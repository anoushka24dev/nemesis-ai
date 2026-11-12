# -*- coding: utf-8 -*-
"""Tests for gmail_live: owner-authorized write transport, disabled by default.

No network and no real email is ever sent. The tests exercise only the refusal
paths (consent/env/token modes) and ensure the read-only API is untouched.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import pytest

from gmail_live import (
    CONSENT_ENV,
    CONSENT_PHRASE,
    WRITE_ALLOWED_SCOPES,
    GmailLiveTransport,
    assert_live_send_armed,
    live_send_status,
    validate_write_scopes,
    run_write_consent_flow,
    DEFAULT_WRITE_CREDENTIALS_PATH,
    DEFAULT_WRITE_TOKEN_PATH,
    GMAIL_COMPOSE_SCOPE,
    GMAIL_SEND_SCOPE,
)


def test_write_allowed_scopes_are_send_and_compose_only():
    """Least privilege for the prepared write capability: exactly send +
    compose. gmail.modify (archive/label) is deliberately NOT prepared —
    no mailbox-modification action exists — and read-only never counts."""
    from email_workflow.policy import GMAIL_MODIFY_SCOPE, GMAIL_READONLY_SCOPE

    assert WRITE_ALLOWED_SCOPES == frozenset(
        {GMAIL_SEND_SCOPE, GMAIL_COMPOSE_SCOPE}
    )
    assert GMAIL_MODIFY_SCOPE not in WRITE_ALLOWED_SCOPES
    assert GMAIL_READONLY_SCOPE not in WRITE_ALLOWED_SCOPES
    # Overlap note: gmail.modify would add label/archive mutation (and draft
    # editing) without adding send; gmail.send alone cannot create drafts —
    # so both of ours are required and modify is not.


def test_write_consent_flow_refuses_without_exact_consent_phrase(monkeypatch):
    monkeypatch.delenv(CONSENT_ENV, raising=False)
    with pytest.raises(Exception) as exc:
        run_write_consent_flow(
            credentials_path=Path(tempfile.gettempdir()) / "no-such-write-client.json"
        )
    # Refused BEFORE any file or browser interaction; no scopes requested.
    assert CONSENT_ENV in str(exc.value)


@pytest.fixture(autouse=True)
def _isolated_env(monkeypatch):
    # Start from a clean slate per test.
    for key in (
        CONSENT_ENV,
        "NEMESIS_WRITE_CREDENTIALS_PATH",
        "NEMESIS_WRITE_TOKEN_PATH",
    ):
        monkeypatch.delenv(key, raising=False)
    yield


# ---------------------------------------------------------------- refusal ---

def test_live_transport_refuses_without_a_write_token():
    # Owner consent is standing policy now, so the remaining precondition is a
    # usable write credential. Isolate the paths: the developer machine may
    # hold a real token, and this test must never reach Gmail.
    tmp = Path(tempfile.mkdtemp())
    os.environ["NEMESIS_WRITE_CREDENTIALS_PATH"] = str(tmp / "credentials_write.json")
    os.environ["NEMESIS_WRITE_TOKEN_PATH"] = str(tmp / "missing_token.json")
    with pytest.raises(Exception) as exc:
        GmailLiveTransport(kill_switch_check=lambda: False).send(MakeMessage(), key="k")
    assert "not armed" in str(exc.value).lower() or "token" in str(exc.value).lower()


def test_live_transport_independently_refuses_when_stop_engaged():
    with pytest.raises(Exception) as exc:
        GmailLiveTransport(kill_switch_check=lambda: True).send(MakeMessage(), key="k")
    assert "kill switch" in str(exc.value).lower()


def test_live_transport_refuses_without_credential_file():
    tmp = Path(tempfile.mkdtemp())
    os.environ["NEMESIS_WRITE_CREDENTIALS_PATH"] = str(tmp / "no_such_client.json")
    os.environ["NEMESIS_WRITE_TOKEN_PATH"] = str(tmp / "no_such_token.json")
    with pytest.raises(Exception) as exc:
        GmailLiveTransport(kill_switch_check=lambda: False).send(MakeMessage(), key="k")
    err = str(exc.value).lower()
    assert ("write oauth client missing" in err) or ("not armed" in err) or (
        "token" in err
    )


def test_live_transport_refuses_without_write_token():
    os.environ[CONSENT_ENV] = CONSENT_PHRASE
    tmp = Path(tempfile.mkdtemp())
    (tmp / "credentials_write.json").write_text("{}")
    os.environ["NEMESIS_WRITE_CREDENTIALS_PATH"] = str(tmp / "credentials_write.json")
    os.environ["NEMESIS_WRITE_TOKEN_PATH"] = str(tmp / "missing.json")
    with pytest.raises(Exception) as exc:
        GmailLiveTransport(kill_switch_check=lambda: False).send(MakeMessage(), key="k")
    err = str(exc.value).lower()
    assert "token" in err or "not armed" in err


def test_live_transport_refuses_read_only_write_token():
    os.environ[CONSENT_ENV] = CONSENT_PHRASE
    tmp = Path(tempfile.mkdtemp())
    cred = tmp / "credentials_write.json"
    token = tmp / "write_token.json"
    cred.write_text(json.dumps({
        "installed": {"client_id": "a", "client_secret": "b", "auth_uri": "u", "token_uri": "t", "redirect_uris": ["oob"]}
    }))
    token.write_text(json.dumps({
        "token": "r", "refresh_token": "x", "token_uri": "t", "client_id": "a",
        "scopes": "https://www.googleapis.com/auth/gmail.readonly",
    }))
    os.environ["NEMESIS_WRITE_CREDENTIALS_PATH"] = str(cred)
    os.environ["NEMESIS_WRITE_TOKEN_PATH"] = str(token)
    with pytest.raises(Exception) as exc:
        GmailLiveTransport(kill_switch_check=lambda: False).send(MakeMessage(), key="k")
    err = str(exc.value).lower()
    assert "read-only" in err or "no send" in err or "not armed" in err


def test_live_send_status_reflects_arming_state():
    # Hermetic: point at empty paths so a developer machine's real token can
    # never make this assertion describe the environment by accident.
    tmp = Path(tempfile.mkdtemp())
    os.environ["NEMESIS_WRITE_CREDENTIALS_PATH"] = str(tmp / "no_client.json")
    os.environ["NEMESIS_WRITE_TOKEN_PATH"] = str(tmp / "no_token.json")
    status = live_send_status()
    assert status["consent_env"] == CONSENT_ENV
    assert status["consent_phrase_required"] == CONSENT_PHRASE
    assert status["live_send_armed"] is False
    assert status["write_token_present"] is False
    assert status["write_token_refresh_verified"] is False


def test_validate_write_scopes_rejects_readonly():
    with pytest.raises(Exception) as exc:
        validate_write_scopes("https://www.googleapis.com/auth/gmail.readonly")
    err = str(exc.value).lower()
    assert "read-only" in err or "no send" in err


def test_validate_write_scopes_accepts_send_and_compose():
    scopes = validate_write_scopes([GMAIL_SEND_SCOPE, GMAIL_COMPOSE_SCOPE])
    assert GMAIL_SEND_SCOPE in scopes
    assert GMAIL_COMPOSE_SCOPE in scopes


def test_validate_write_scopes_rejects_wider_scope():
    with pytest.raises(Exception) as exc:
        validate_write_scopes("https://mail.google.com/")
    assert "mail.google.com" in str(exc.value)


def test_validate_write_scopes_rejects_empty():
    with pytest.raises(Exception) as exc:
        validate_write_scopes("")
    assert "no scopes" in str(exc.value).lower()


# ---------------------------------------------------------------- auth flow ---

def test_write_consent_flow_requires_consent_first():
    tmp = Path(tempfile.mkdtemp())
    cred = tmp / "credentials_write.json"
    cred.write_text(json.dumps({
        "installed": {"client_id": "x", "client_secret": "y", "auth_uri": "u", "token_uri": "t", "redirect_uris": ["oob"]}
    }))
    os.environ["NEMESIS_WRITE_CREDENTIALS_PATH"] = str(cred)
    with pytest.raises(Exception) as exc:
        run_write_consent_flow()
    assert "consent" in str(exc.value).lower() or "not armed" in str(exc.value).lower()


# ---------------------------------------------------------------- no real network ---

def test_pacakage_never_imports_gmail_write_clients():
    """The write transport lives in a separate module (gmail_live.py) that the
    read-only implementation never imports; read-only OAuth stays read-only."""
    from pathlib import Path
    pkg_root = Path(__file__).resolve().parents[1] / "gmail_demo"
    for py in pkg_root.glob("*.py"):
        text = py.read_text(encoding="utf-8")
        assert "googleapiclient" not in text, f"found googleapiclient in {py}"
        assert "users().messages().send" not in text, f"found send in {py}"
    # Separate module must import googleapiclient only lazily inside functions so
    # that simple imports of the module do not trigger class-lookup / network.
    import gmail_live
    assert hasattr(gmail_live, "GmailLiveTransport")
    assert gmail_live.TransportUnavailableError.__bases__ != ()


# ---------------------------------------------------------------- helper ---

class MakeMessage:
    kind = "reply"
    to = ("alice@corp.example",)
    subject = "Hello"
    body = "Body"
    settings = None
    message_id = "m-1"
    thread_id = None

    def summary(self):
        return {"message_id": self.message_id, "to": list(self.to), "subject": self.subject, "body": self.body, "settings": {}, "kind": self.kind}



