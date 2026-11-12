# -*- coding: utf-8 -*-
"""Gmail integration tests: unit guards + opt-in REAL Gmail verification.

The unit tests below run everywhere and never touch the network. The live
tests are the acceptance evidence for real Gmail read/draft/send and only run
when ``NEMESIS_LIVE_TESTS=1`` AND the write credential verifies with a real
refresh. They assert on Gmail's own identifiers and re-read the mailbox, so a
locally generated draft can never be mistaken for a delivered object.
"""
from __future__ import annotations

import os
import uuid

import pytest

LIVE = os.environ.get("NEMESIS_LIVE_TESTS", "").strip() == "1"

needs_live = pytest.mark.skipif(
    not LIVE, reason="set NEMESIS_LIVE_TESTS=1 to run real Gmail integration tests"
)


def _write_ready() -> bool:
    try:
        from gmail_live import live_send_status

        return bool(live_send_status(verify_refresh=True).get("live_send_armed"))
    except Exception:  # noqa: BLE001 - not ready, skip
        return False


needs_write = pytest.mark.skipif(
    not LIVE or not _write_ready(),
    reason="write OAuth token is absent/revoked; re-consent with `python -m gmail_live auth`",
)


# --------------------------------------------------------------------- unit ---


def test_send_result_distinguishes_sent_from_drafted(monkeypatch, tmp_path):
    """A draft result must never claim ``sent``; the two capabilities are
    reported separately so the dashboard cannot conflate them."""
    from backend import gmail_agent

    class _Report:
        def to_dict(self):
            return {
                "executed": True,
                "simulated": False,
                "status": "ok",
                "message_id": "gmail-msg-1",
                "thread_id": "gmail-thread-1",
                "transport": {"transport": "gmail-live"},
            }

    class _Service:
        def prepare_message(self, message, confirmed=True):
            class _P:
                prepared_id = "prepared-1"
                message = {"message_id": "prepared-1"}

            return _P()

        def submit(self, _arg, *, purpose, confirm, prepared_id):
            assert purpose in {"send", "draft"}
            return _Report()

    monkeypatch.setattr(gmail_agent, "_build_service", lambda: _Service())
    monkeypatch.setattr(gmail_agent, "_recent_duplicate", lambda _d: None)
    # Keep the real operation history clean: this test never touches Gmail.
    monkeypatch.setattr(gmail_agent, "HISTORY_PATH", tmp_path / "history.json")
    payload = {"to": "anoushkas2006@gmail.com", "subject": "s", "body": "b"}

    sent = gmail_agent.send(dict(payload))
    assert sent["sent"] is True and sent["drafted"] is False
    assert sent["record"]["type"] == "send"

    drafted = gmail_agent.save_draft(dict(payload))
    assert drafted["drafted"] is True and drafted["sent"] is False
    assert drafted["record"]["type"] == "draft"
    assert drafted["status"] == "drafted"


def test_draft_refuses_non_allowlisted_recipient():
    """Draft creation is a real mailbox write: the hard recipient allowlist
    applies exactly as it does to send, before any Gmail request is made."""
    from backend import gmail_agent

    res = gmail_agent.save_draft(
        {
            "to": "someone-else@example.com",
            "subject": "synthetic",
            "body": "synthetic",
        }
    )
    assert res["drafted"] is False
    assert "RecipientNotAllowed" in str(res["reason"])


# --------------------------------------------------------------------- live ---


@pytest.fixture
def real_outbound_state(monkeypatch):
    """Live tests use the owner's real outbound state (the test-isolation
    fixture points at a fresh store whose safe default is kill-switch ON)."""
    monkeypatch.delenv("NEMESIS_OUTBOUND_STATE_PATH", raising=False)
    # Live acceptance runs several real operations in one session; give the
    # test its own bounded allowance so the production default (5/hour) does
    # not reject the suite itself. The limiter is still enforced.
    monkeypatch.setenv("NEMESIS_RATE_LIMIT_PER_HOUR", "20")
    yield


@needs_live
def test_live_read_returns_real_gmail_messages():
    from gmail_auth import build_gmail_service, fetch_nemesis_demo_emails, get_credentials

    creds = get_credentials(open_browser=False)
    assert "gmail.readonly" in " ".join(creds.scopes or [])
    messages = fetch_nemesis_demo_emails(build_gmail_service(creds), max_results=3)
    assert messages, "no NEMESIS_DEMO messages were returned by the real Gmail API"
    for m in messages:
        assert m.id, "every real Gmail message carries a Gmail id"
        assert "@" in (m.sender or "")
        assert "NEMESIS_DEMO" in (m.labels or [])


@needs_live
def test_live_gmail_agent_target_uses_real_messages_and_local_model():
    from adaptive_agent_eval.target.adapter import TargetSession
    from adaptive_agent_eval.target.gmail_agent import GmailReadOnlyTargetAdapter

    adapter = GmailReadOnlyTargetAdapter(target_id="live-test", max_results=2)
    res = adapter.execute_turn(
        TargetSession(session_id="s", correlation_id="c", target_id="live-test"),
        "Summarise the inbox.",
    )
    ev = res.evidence or {}
    assert res.is_technical_failure is False
    assert ev.get("email_count", 0) >= 1
    assert ev.get("model_called") is True
    assert ev.get("model") == "llama3.1:8b"
    assert ev.get("read_only") is True
    assert ev["messages"][0]["message_id"]


@needs_write
def test_live_draft_is_created_and_verified_in_gmail(real_outbound_state):
    from backend import gmail_agent
    from gmail_auth import build_gmail_service, get_credentials

    canary = f"NEMESIS-DRAFT-{uuid.uuid4().hex[:10]}"
    res = gmail_agent.save_draft(
        {
            "action": "compose",
            "to": "anoushkas2006@gmail.com",
            "subject": f"Nemesis live draft test {canary}",
            "body": f"Synthetic draft. {canary}",
        }
    )
    assert res["drafted"] is True, res.get("reason")
    svc = build_gmail_service(get_credentials(open_browser=False))
    found = None
    for ref in svc.users().drafts().list(userId="me", maxResults=50).execute().get(
        "drafts", []
    ):
        got = svc.users().drafts().get(userId="me", id=ref["id"], format="metadata").execute()
        if (got.get("message") or {}).get("id") == res["message_id"]:
            found = got
            break
    assert found is not None, "the draft Gmail confirmed is not readable back"
    headers = {h["name"]: h["value"] for h in found["message"]["payload"]["headers"]}
    assert canary in headers.get("Subject", "")


@needs_write
def test_live_send_lands_in_sent_folder(real_outbound_state):
    from backend import gmail_agent
    from gmail_auth import build_gmail_service, get_credentials

    canary = f"NEMESIS-SEND-{uuid.uuid4().hex[:10]}"
    res = gmail_agent.send(
        {
            "action": "compose",
            "to": "anoushkas2006@gmail.com",
            "subject": f"Nemesis live send test {canary}",
            "body": f"Synthetic acceptance message. {canary}",
        }
    )
    assert res["sent"] is True, res.get("reason")
    assert res["simulated"] is False
    svc = build_gmail_service(get_credentials(open_browser=False))
    got = svc.users().messages().get(
        userId="me", id=res["message_id"], format="metadata",
        metadataHeaders=["Subject", "To"],
    ).execute()
    assert "SENT" in (got.get("labelIds") or [])
    headers = {h["name"]: h["value"] for h in got["payload"]["headers"]}
    assert canary in headers.get("Subject", "")
    assert headers.get("To") == "anoushkas2006@gmail.com"
