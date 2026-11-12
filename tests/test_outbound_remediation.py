"""Regression coverage for the hardened Gmail outbound boundary.

These tests are deliberately transport-mocked: no network, no Gmail call, and
no real message is created. They cover the properties the remediation must
preserve across code paths and process restarts: hard recipient allowlists,
prepared-artifact integrity, the durable fail-closed stop, idempotency and
uncertain outcomes, persistent rate limits, and honest identifiers.
"""
from __future__ import annotations

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from backend.stage_b import create_app
from email_workflow import (
    EmailWorkflowService,
    MockTransport,
    OutgoingDefense,
    Policy,
    RateLimiter,
    TransportError,
    compose_new,
)
from email_workflow.compose import message_from_summary
from email_workflow.outbound_state import (
    ATTEMPT_SIMULATED,
    OutboundStateError,
    OutboundStateStore,
)
from email_workflow.policy import GMAIL_SEND_SCOPE, PolicyError, RecipientNotAllowed
from email_workflow.transport import idempotency_key
from gmail_live import GmailLiveTransport

APPROVED = "owner-approved@example.com"
CC_APPROVED = "cc-approved@example.com"
BCC_APPROVED = "bcc-approved@example.com"
OTHER = "other@example.com"


def make_store(tmp_path) -> OutboundStateStore:
    return OutboundStateStore(tmp_path / "outbound.sqlite3")


def make_service(
    store: OutboundStateStore,
    *,
    mode: str = "authorized_automation",
    transport=None,
    allowed=(APPROVED, CC_APPROVED, BCC_APPROVED),
) -> EmailWorkflowService:
    return EmailWorkflowService(
        policy=Policy(
            mode=mode,
            allowed_recipients=frozenset(allowed),
            send_authorized=True,
            draft_authorized=True,
            granted_scopes=frozenset({GMAIL_SEND_SCOPE}),
        ),
        transport=transport or MockTransport(),
        state_store=store,
        require_prepared_artifacts=True,
    )


def prepared(service: EmailWorkflowService, *, to=APPROVED, cc=(), bcc=()):
    report = service.prepare_new(
        [to] if isinstance(to, str) else list(to),
        "Status update",
        "A short, benign status update.",
        cc=list(cc),
        bcc=list(bcc),
    )
    assert report.status == "prepared"
    return report


# --------------------------------------------------------------- allowlist ---


def test_hard_allowlist_rejects_unlisted_recipient_even_with_confirmation(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    with pytest.raises(RecipientNotAllowed, match="hard allowlist"):
        service.prepare_new([OTHER], "Hello", "Body", confirmed=True)


def test_hard_allowlist_checks_every_to_cc_and_bcc_recipient(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    with pytest.raises(RecipientNotAllowed):
        service.prepare_new([APPROVED], "Hello", "Body", cc=[OTHER], confirmed=True)
    with pytest.raises(RecipientNotAllowed):
        service.prepare_new([APPROVED], "Hello", "Body", bcc=[OTHER], confirmed=True)


def test_allowlisted_recipient_is_accepted_without_confirmation(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    assert prepared(service).status == "prepared"


def test_allowlist_normalizes_case_and_whitespace(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    report = service.prepare_new(["  OWNER-APPROVED@EXAMPLE.COM "], "Hello", "Body")
    assert report.status == "prepared"
    assert report.message["to"] == [APPROVED]


def test_release_never_widens_allowlist(tmp_path):
    store = make_store(tmp_path)
    service = make_service(store, mode="simulation")
    service.release_kill_switch(confirm=True, actor="test")
    with pytest.raises(RecipientNotAllowed):
        service.prepare_new([OTHER], "Hello", "Body", confirmed=True)


# ------------------------------------------------------- prepared integrity ---


def test_prepared_submission_rejects_every_substitutable_field(tmp_path):
    store = make_store(tmp_path)
    service = make_service(store, mode="simulation")
    report = prepared(service, cc=(CC_APPROVED,), bcc=(BCC_APPROVED,))
    prepared_id = report.message["message_id"]
    from email_workflow.compose import message_from_summary

    original = message_from_summary(report.message)
    mutations = [
        replace(original, to=(OTHER,)),
        replace(original, cc=(OTHER,)),
        replace(original, bcc=(OTHER,)),
        replace(original, subject="Substituted subject"),
        replace(original, body="Substituted body"),
        replace(original, kind="reply"),
        replace(original, thread_id="thread-substituted"),
        replace(original, references=("substituted-reference",)),
    ]
    for mutated in mutations:
        denied = service.submit(
            mutated, prepared_id=prepared_id, purpose="send", confirm=True
        )
        assert denied.status == "denied", mutated
        assert "modified" in (denied.reason or "").lower()
        assert denied.transport_called is False


def test_unknown_or_fabricated_prepared_id_is_denied(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    report = service.submit(
        None, prepared_id="fabricated-preparation", purpose="send", confirm=True
    )
    assert report.status == "denied"
    assert report.transport_called is False


def test_prepared_artifact_cannot_be_reused_for_a_different_action(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    report = prepared(service)
    prepared_id = report.message["message_id"]
    first = service.submit(None, prepared_id=prepared_id, purpose="send")
    assert first.status == "simulated_send"
    second = service.submit(None, prepared_id=prepared_id, purpose="draft")
    assert second.status == "denied"
    assert "already used for a send action" in (second.reason or "")


def test_unmodified_allowlisted_prepared_message_reaches_mock_transport(tmp_path):
    store = make_store(tmp_path)
    service = make_service(store)
    service.release_kill_switch(confirm=True, actor="test")
    report = prepared(service)
    prepared_id = report.message["message_id"]
    sent = service.submit(None, prepared_id=prepared_id, purpose="send", confirm=True)
    assert sent.status == "simulated_send"
    assert sent.transport_called is True
    assert sent.executed is False
    assert sent.transport["transport"] == "mock"
    assert sent.transport["message_id"].startswith("mock-send-")
    assert service.transport.sent[0]["gmail_message_id"] == sent.transport["message_id"]


# -------------------------------------------------------------- kill switch ---


def test_new_store_defaults_to_engaged(tmp_path):
    store = make_store(tmp_path)
    assert store.kill_switch_engaged() is True
    record = store.kill_switch_record()
    assert record["engaged"] is True
    assert record["durable"] is True


def test_missing_store_is_initialized_engaged(tmp_path):
    path = tmp_path / "missing" / "state.sqlite3"
    store = OutboundStateStore(path)
    assert path.exists()
    assert store.kill_switch_engaged() is True


def test_corrupt_store_fails_closed_and_refuses_release(tmp_path):
    path = tmp_path / "corrupt.sqlite3"
    path.write_bytes(b"this is not a sqlite database")
    store = OutboundStateStore(path)
    assert store.kill_switch_engaged() is True
    with pytest.raises(OutboundStateError):
        store.set_kill_switch(False, require_confirm=True, actor="test")


def test_stop_engage_and_release_survive_reconstruction(tmp_path):
    path = tmp_path / "persistent.sqlite3"
    store = OutboundStateStore(path)
    service = make_service(store, mode="simulation")
    service.engage_kill_switch(actor="test", reason="persistence check")
    assert OutboundStateStore(path).kill_switch_engaged() is True

    service2 = make_service(OutboundStateStore(path), mode="simulation")
    assert service2.policy.kill_switch is True
    service2.release_kill_switch(confirm=True, actor="test", reason="controlled")
    assert OutboundStateStore(path).kill_switch_engaged() is False
    # Releasing the stop does not arm sending or change the configured mode.
    assert service2.policy.mode.value == "simulation"
    assert service2.transport.name == "mock"


def test_release_without_confirmation_is_refused(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(OutboundStateError):
        store.set_kill_switch(False)
    with pytest.raises(PolicyError):
        make_service(store).release_kill_switch(confirm=False)


def test_persistence_failure_still_leaves_in_memory_stop_engaged(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    service = make_service(store, mode="simulation")
    service.release_kill_switch(confirm=True, actor="test")

    def broken_connect():
        raise OSError("simulated disk failure")

    monkeypatch.setattr(store, "_connect", broken_connect)
    with pytest.raises(OutboundStateError):
        service.engage_kill_switch(actor="test", reason="failure path")
    assert service.policy.kill_switch is True


def test_release_persistence_failure_keeps_stop_engaged(tmp_path, monkeypatch):
    store = make_store(tmp_path)
    service = make_service(store, mode="simulation")
    service.release_kill_switch(confirm=True, actor="test")

    def broken_connect():
        raise OSError("simulated disk failure")

    monkeypatch.setattr(store, "_connect", broken_connect)
    with pytest.raises(OutboundStateError):
        service.release_kill_switch(confirm=True, actor="test")
    assert service.policy.kill_switch is True


def test_stop_blocks_every_non_simulation_action_before_transport(tmp_path):
    store = make_store(tmp_path)
    transport = MockTransport()
    service = make_service(store, transport=transport)
    service.release_kill_switch(confirm=True, actor="test")
    send_report = prepared(service)
    draft_report = service.prepare_new([APPROVED], "Draft subject", "Draft body")
    service.engage_kill_switch(actor="test", reason="hard stop")

    for report, purpose in ((send_report, "send"), (draft_report, "draft")):
        result = service.submit(
            None,
            prepared_id=report.message["message_id"],
            purpose=purpose,
            confirm=True,
        )
        assert result.status == "denied"
        assert "kill switch" in (result.reason or "").lower()
        assert result.transport_called is False
    assert transport.calls == []


def test_stop_still_allows_local_simulation(tmp_path):
    service = make_service(make_store(tmp_path), mode="simulation")
    assert service.kill_switch_status()["engaged"] is True
    report = prepared(service)
    result = service.submit(None, prepared_id=report.message["message_id"])
    assert result.status == "simulated_send"
    assert result.transport_called is False


def test_gmail_transport_independently_refuses_when_stop_is_engaged():
    transport = GmailLiveTransport(kill_switch_check=lambda: True)
    with pytest.raises(TransportError, match="kill switch"):
        transport.send(compose_new([APPROVED], "Hello", "Body"), key="k")


# ------------------------------------------------- idempotency / uncertain ---


def test_idempotency_is_persistent_across_service_reconstruction(tmp_path):
    path = tmp_path / "idempotency.sqlite3"
    store = OutboundStateStore(path)
    service = make_service(store)
    service.release_kill_switch(confirm=True, actor="test")
    report = prepared(service)
    first = service.submit(None, prepared_id=report.message["message_id"])
    assert first.status == "simulated_send"
    assert len(service.transport.sent) == 1

    calls_before = len(service.transport.calls)
    store2 = OutboundStateStore(path)
    service2 = make_service(store2)
    replay = service2.prepare_new(
        [APPROVED], "Status update", "A short, benign status update."
    )
    duplicate = service2.submit(None, prepared_id=replay.message["message_id"])
    assert duplicate.status == "simulated_send"
    assert duplicate.transport["duplicate"] is True
    assert service2.transport.calls == []
    assert calls_before == 1
    assert store2.get_attempt(
        idempotency_key(message_from_summary(replay.message), action="send")
    )["state"] == ATTEMPT_SIMULATED


class _UncertainTransport:
    name = "uncertain-test"
    executes_live_actions = True

    def __init__(self) -> None:
        self.calls = 0

    def send(self, message, *, key):
        self.calls += 1
        raise TransportError("simulated ambiguous Gmail failure", uncertain=True)

    def create_draft(self, message, *, key):
        self.calls += 1
        raise TransportError("simulated ambiguous Gmail failure", uncertain=True)


def test_uncertain_outcome_is_persisted_and_never_auto_retried(tmp_path):
    path = tmp_path / "uncertain.sqlite3"
    store = OutboundStateStore(path)
    transport = _UncertainTransport()
    service = make_service(store, transport=transport)
    service.release_kill_switch(confirm=True, actor="test")
    report = prepared(service)
    first = service.submit(
        None, prepared_id=report.message["message_id"], purpose="send", confirm=True
    )
    assert first.status == "uncertain"
    assert first.executed is False
    assert transport.calls == 1
    assert len(store.uncertain_attempts()) == 1

    service2 = make_service(OutboundStateStore(path), transport=transport)
    replay = service2.prepare_new(
        [APPROVED], "Status update", "A short, benign status update."
    )
    second = service2.submit(
        None, prepared_id=replay.message["message_id"], purpose="send", confirm=True
    )
    assert second.status == "uncertain"
    assert second.transport["duplicate"] is True
    assert transport.calls == 1


def test_persistent_rate_limit_survives_service_reconstruction(tmp_path):
    path = tmp_path / "rate.sqlite3"
    store = OutboundStateStore(path)
    service = make_service(store)
    service.release_kill_switch(confirm=True, actor="test")
    service.rate_limiter = RateLimiter(2, store=store)

    reports = [
        service.prepare_new([APPROVED], f"Subject {i}", f"Body {i}") for i in range(2)
    ]
    for report in reports:
        result = service.submit(None, prepared_id=report.message["message_id"])
        assert result.status == "simulated_send"

    third = service.prepare_new([APPROVED], "Subject third", "Body third")
    denied = service.submit(None, prepared_id=third.message["message_id"])
    assert denied.status == "denied"
    assert "rate limit" in (denied.reason or "").lower()

    # A new process/service sees the same consumed window.
    store2 = OutboundStateStore(path)
    service2 = make_service(store2)
    service2.rate_limiter = RateLimiter(2, store=store2)
    third_again = service2.prepare_new([APPROVED], "Subject third", "Body third")
    denied2 = service2.submit(None, prepared_id=third_again.message["message_id"])
    assert denied2.status == "denied"
    assert "rate limit" in (denied2.reason or "").lower()


def test_rate_limit_failure_is_not_retried_as_a_successful_action(tmp_path):
    store = make_store(tmp_path)
    service = make_service(store)
    service.release_kill_switch(confirm=True, actor="test")
    service.rate_limiter = RateLimiter(1, store=store)
    first = prepared(service)
    assert service.submit(None, prepared_id=first.message["message_id"]).status == (
        "simulated_send"
    )
    second = service.prepare_new([APPROVED], "Second", "Second body")
    denied = service.submit(None, prepared_id=second.message["message_id"])
    assert denied.status == "denied"
    assert denied.transport_called is False
    # The denied attempt is recorded as failed, not as a simulated delivery.
    key = idempotency_key(message_from_summary(second.message), action="send")
    assert store.get_attempt(key)["state"] == "failed"


# --------------------------------------------------------------- analysis ---


def test_reading_and_defense_analysis_do_not_require_releasing_stop(tmp_path):
    # The stop is for outbound actions only; local analysis must keep working.
    message = compose_new([APPROVED], "Routine note", "Nothing unusual here.")
    assert OutgoingDefense().scan(message)["decision"] == "allow"
    assert make_store(tmp_path).kill_switch_engaged() is True


def test_backend_kill_switch_routes_block_then_explicitly_release(tmp_path):
    """The paired API cannot bypass the same durable stop as the service."""
    nonce = "remediation-pairing-nonce"
    origin = "chrome-extension://remediation-test"
    service = make_service(make_store(tmp_path))
    service.release_kill_switch(confirm=True, actor="test")
    app = create_app(
        credentials_path=tmp_path / "credentials.json",
        token_path=tmp_path / "token.json",
        pairing_nonce=nonce,
        workflow_service=service,
        feedback_store=tmp_path / "feedback.json",
        quality_store=tmp_path / "quality.json",
        adaptive_store=tmp_path / "adaptive.json",
    )
    client = TestClient(app, follow_redirects=False)
    base = "/api/v1/stage_b"
    headers = {"origin": origin, "authorization": f"Bearer {nonce}"}
    pair = client.post(
        f"{base}/pair",
        json={"presented_nonce": nonce, "extension_origin": origin},
        headers={"origin": origin},
    )
    assert pair.status_code == 200, pair.text

    prepared = client.post(
        f"{base}/nemesis/prepare/new",
        json={"to": [APPROVED], "subject": "API stop test", "body_text": "Benign."},
        headers=headers,
    )
    assert prepared.status_code == 200, prepared.text
    prepared_id = prepared.json()["report"]["message"]["message_id"]
    activity = client.post(f"{base}/nemesis/activity", json={}, headers=headers)
    assert activity.status_code == 200, activity.text

    assert client.post(f"{base}/nemesis/killswitch", headers=headers).status_code == 200
    status = client.post(f"{base}/workflow/status", headers=headers).json()
    assert status["kill_switch"] is True
    assert status["kill_switch_status"]["durable"] is True
    assert status["transport"] == "mock"
    assert status["display_mode"] == "SIMULATION"

    blocked = client.post(
        f"{base}/workflow/submit",
        json={"prepared_id": prepared_id, "purpose": "send", "confirm": True},
        headers=headers,
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["report"]["status"] == "denied"
    assert "kill switch" in blocked.json()["report"]["reason"].lower()

    # Missing confirmation cannot release the stop.
    refused = client.post(f"{base}/workflow/killswitch/release", json={}, headers=headers)
    assert refused.status_code == 400
    released = client.post(
        f"{base}/workflow/killswitch/release",
        json={"confirm": True, "reason": "test release"},
        headers=headers,
    )
    assert released.status_code == 200, released.text

    allowed = client.post(
        f"{base}/workflow/submit",
        json={"prepared_id": prepared_id, "purpose": "send", "confirm": True},
        headers=headers,
    )
    assert allowed.status_code == 200, allowed.text
    report = allowed.json()["report"]
    assert report["status"] == "simulated_send"
    assert report["executed"] is False
