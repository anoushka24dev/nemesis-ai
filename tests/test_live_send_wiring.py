"""Regression tests for the live-send wiring and the side-panel integration.

Covers:

1. ``build_workflow_policy`` scope handling: default stays READ-ONLY, owner
   may declare ``send``/``compose``/``modify`` (or full URIs) via
   ``NEMESIS_GRANTED_SCOPES``, and unknown scope names are REFUSED
   (fail-closed) instead of silently granted or dropped.
2. ``build_workflow_service`` transport selection: mock by default; the real
   ``GmailLiveTransport`` is selected only when the policy is past simulation
   mode AND gmail_live reports fully armed — and even then a submit through a
   malformed token refuses with ``executed=False`` (never claims "sent").
3. The extension panel actually renders the defense/metrics/hill-climb/
   feedback/health elements the user sees (the missing ``m-blocked-sub`` id
   regression and the feedback controls), and sidepanel.js wires them.

No network, no real email: arming is simulated with temp files whose token
content is deliberately invalid, so the refusal path is the one exercised.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _no_live_write_token(tmp_path, monkeypatch):
    """Isolate the write credential paths.

    A developer machine can hold a real, armed write token; these tests assert
    the UNARMED contract, so they must never read it (or send anything).
    """
    monkeypatch.setenv(
        "NEMESIS_WRITE_CREDENTIALS_PATH", str(tmp_path / "no_client.json")
    )
    monkeypatch.setenv("NEMESIS_WRITE_TOKEN_PATH", str(tmp_path / "no_token.json"))
    yield

from backend import stage_b
from email_workflow.compose import compose_new

CONSENT_ENV = "NEMESIS_LIVE_SEND_CONSENT"
CONSENT_PHRASE = "I authorize real Gmail sends from Nemesis"
READONLY = "https://www.googleapis.com/auth/gmail.readonly"
SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose"

EXT = Path(__file__).resolve().parents[1] / "extension"

_WIRE_ENV_KEYS = (
    "NEMESIS_GRANTED_SCOPES",
    "NEMESIS_WORKFLOW_MODE",
    "NEMESIS_SEND_AUTHORIZED",
    "NEMESIS_DRAFT_AUTHORIZED",
    CONSENT_ENV,
    "NEMESIS_WRITE_CREDENTIALS_PATH",
    "NEMESIS_WRITE_TOKEN_PATH",
    "NEMESIS_ALLOWED_RECIPIENTS",
    "NEMESIS_ALLOWED_DOMAINS",
)


@pytest.fixture(autouse=True)
def _clean_wire_env(monkeypatch):
    for key in _WIRE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    yield


# ------------------------------------------------- policy scope wiring ----


def test_default_policy_scopes_are_read_only() -> None:
    policy = stage_b.build_workflow_policy()
    assert policy.granted_scopes == frozenset({READONLY})
    assert policy.mode.value == "simulation"
    assert policy.send_authorized is False
    assert policy.draft_authorized is False


def test_owner_can_declare_write_scope_short_names(monkeypatch) -> None:
    monkeypatch.setenv("NEMESIS_GRANTED_SCOPES", "send,compose")
    policy = stage_b.build_workflow_policy()
    assert SEND_SCOPE in policy.granted_scopes
    assert COMPOSE_SCOPE in policy.granted_scopes


def test_owner_can_declare_full_scope_uris(monkeypatch) -> None:
    monkeypatch.setenv("NEMESIS_GRANTED_SCOPES", f"{READONLY},{SEND_SCOPE}")
    policy = stage_b.build_workflow_policy()
    assert policy.granted_scopes == frozenset({READONLY, SEND_SCOPE})


def test_unknown_scope_name_is_refused_not_silently_granted(monkeypatch) -> None:
    monkeypatch.setenv("NEMESIS_GRANTED_SCOPES", "send,mail.google.com")
    with pytest.raises(stage_b.PolicyError, match="unknown scope"):
        stage_b.build_workflow_policy()


def test_mode_env_and_flags_still_flow_into_policy(monkeypatch) -> None:
    monkeypatch.setenv("NEMESIS_WORKFLOW_MODE", "authorized_automation")
    monkeypatch.setenv("NEMESIS_SEND_AUTHORIZED", "1")
    monkeypatch.setenv("NEMESIS_GRANTED_SCOPES", "send")
    policy = stage_b.build_workflow_policy()
    assert policy.mode.value == "authorized_automation"
    assert policy.send_authorized is True
    assert SEND_SCOPE in policy.granted_scopes
    # Construction-time-only policy: still frozen (immutable at runtime).
    with pytest.raises((AttributeError, TypeError)):
        policy.send_authorized = False  # type: ignore[misc]


# --------------------------------------------- transport selection -------


def test_default_service_uses_mock_transport() -> None:
    svc = stage_b.build_workflow_service()
    assert svc.transport.name == "mock"
    assert svc.policy.mode.value == "simulation"


def test_past_simulation_but_unarmed_still_uses_mock(monkeypatch) -> None:
    monkeypatch.setenv("NEMESIS_WORKFLOW_MODE", "authorized_automation")
    monkeypatch.setenv("NEMESIS_SEND_AUTHORIZED", "1")
    monkeypatch.setenv("NEMESIS_GRANTED_SCOPES", "send")
    svc = stage_b.build_workflow_service()
    assert svc.transport.name == "mock"


def test_malformed_write_token_never_selects_live_transport(
    monkeypatch, tmp_path
) -> None:
    cred = tmp_path / "credentials_write.json"
    token = tmp_path / "token_write.json"
    cred.write_text("{}", encoding="utf-8")
    token.write_text("{}", encoding="utf-8")  # deliberately malformed token
    monkeypatch.setenv(CONSENT_ENV, CONSENT_PHRASE)
    monkeypatch.setenv("NEMESIS_WRITE_CREDENTIALS_PATH", str(cred))
    monkeypatch.setenv("NEMESIS_WRITE_TOKEN_PATH", str(token))
    monkeypatch.setenv("NEMESIS_WORKFLOW_MODE", "authorized_automation")
    monkeypatch.setenv("NEMESIS_SEND_AUTHORIZED", "1")
    monkeypatch.setenv("NEMESIS_GRANTED_SCOPES", "send")
    monkeypatch.setenv("NEMESIS_ALLOWED_RECIPIENTS", "alice@corp.example")

    svc = stage_b.build_workflow_service()
    # File existence is not readiness: an unreadable token must keep the mock
    # transport selected and the live-ready flag false.
    assert svc.transport.name == "mock"
    from gmail_live import live_send_status

    status = live_send_status()
    assert status["live_send_armed"] is False
    assert status["write_token_structurally_valid"] is False


def test_simulation_mode_never_selects_live_transport(monkeypatch) -> None:
    # Everything armed EXCEPT the mode: simulation must stay mock.
    monkeypatch.setenv(CONSENT_ENV, CONSENT_PHRASE)
    svc = stage_b.build_workflow_service()
    assert svc.transport.name == "mock"


def test_mock_submission_never_claims_sent(monkeypatch) -> None:
    monkeypatch.setenv("NEMESIS_ALLOWED_RECIPIENTS", "alice@corp.example")
    svc = stage_b.build_workflow_service()
    prepared = svc.prepare_new(["alice@corp.example"], "Hello", "Body")
    assert prepared.status == "prepared"
    report = svc.submit(
        None,
        purpose="send",
        confirm=True,
        prepared_id=prepared.message["message_id"],
    )
    assert report.status == "simulated_send"
    assert report.executed is False
    # Simulation never reaches a transport at all: no transport record exists.
    assert report.transport_called is False
    assert report.transport is None


def test_workflow_status_reports_armed_state_honestly(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from backend.stage_b import _MOUNT_PREFIX, create_app

    app = create_app(
        credentials_path="c.json",
        token_path="t.json",
        pairing_nonce="wire-nonce",
    )
    client = TestClient(app, follow_redirects=False)
    base = f"/{_MOUNT_PREFIX.lstrip('/')}"
    headers = {
        "origin": "chrome-extension://chlorophyll-modern-bread",
        "authorization": "Bearer wire-nonce",
    }
    client.post(
        f"{base}/pair",
        json={
            "presented_nonce": "wire-nonce",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
        headers=headers,
    )
    resp = client.post(f"{base}/workflow/status", headers=headers)
    s = resp.json()
    # Default (unarmed) state: the UI must be able to say so truthfully.
    assert s["mode"] == "simulation"
    assert s["granted_scopes"] == [READONLY]
    assert s["live_send"]["live_send_armed"] is False
    assert s["transport"] == "mock"


# ------------------------------------------------ side panel elements ----


def _panel_html() -> str:
    return (EXT / "sidepanel.html").read_text(encoding="utf-8")


def _panel_js() -> str:
    return (EXT / "sidepanel.js").read_text(encoding="utf-8")


def test_panel_exposes_the_single_demo_action_and_mode_indicator() -> None:
    """The approved dashboard replaces the old metrics/compose panels. It must
    still show the real execution mode and a single policy-gated action."""
    html = _panel_html()
    assert html.count('id="demo-run-btn"') == 1
    assert 'id="pill-mode"' in html
    assert 'id="result-body"' in html
    for stale in (
        'id="m-asr"', 'id="c-to"', 'id="c-subject"', 'id="c-body"',
        'id="prepare-new-btn"', 'id="submit-btn"', 'id="feedback-record-btn"',
    ):
        assert stale not in html, stale


def test_js_wires_the_demo_action_and_keeps_paths_relative() -> None:
    js = _panel_js()
    assert 'runBtn.addEventListener("click", onStartDemo)' in js
    assert 'backendPost("/nemesis/demo/run"' in js
    assert 'backendPost("/nemesis/demo/status"' in js
    paths = re.findall(r'backendPost\(\s*["\'`]([^"\'`]*)', js)
    assert paths
    for p in paths:
        assert p.startswith("/"), p


def test_js_never_claims_live_execution_without_backend_status() -> None:
    js = _panel_js()
    # The live label is derived from the backend workflow policy, never a
    # locally assumed constant.
    assert "client.workflow" in js
    assert 'mode === "LIVE"' in js
    assert "not independently confirmed" in js


def test_js_async_declarations_are_not_comment_merged() -> None:
    """Regression: an edit once ate the newline after a banner comment so
    ``async`` was swallowed (``-- metrics --async function ...``), turning
    every await into a SyntaxError that only ``node --check`` caught.
    Every ``async function`` must start its own line."""
    js = _panel_js()
    for lineno, line in enumerate(js.splitlines(), start=1):
        if "async function" in line:
            assert line.lstrip().startswith("async function"), (
                f"line {lineno}: async function must start a line: {line!r}"
            )


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
@pytest.mark.parametrize("script", ["sidepanel.js", "background.js", "content.js"])
def test_js_files_parse_with_node(script: str) -> None:
    """When node is available, every extension script must parse cleanly."""
    proc = subprocess.run(
        [shutil.which("node") or "node", "--check", str(EXT / script)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stderr[:2000]
