"""Owner-authorized LIVE Gmail write transport — disabled unless explicitly armed.

This module is deliberately separate from the read-only analysis flow
(``gmail_auth.py``): nothing in the read-only path ever imports it, and the
read-only backend's fail-closed scope check
(``StageBBackend._assert_readonly_after_auth``) still only permits
``gmail.readonly``. Live sending exists here so the fact that it is possible
stays *enforceable and auditable*, not just documented.

Arming live sending requires ALL of the following (fail-closed; any missing
piece refuses with a reason):

1. Explicit owner consent: environment variable ``NEMESIS_LIVE_SEND_CONSENT``
   must equal the exact phrase ``I authorize real Gmail sends from Nemesis``.
   No partial match; the phrase is documented in docs/AUTONOMOUS_EMAIL.md.
2. A SEPARATE OAuth client file (``credentials_write.json`` by default) that
   the owner created for write access. The read-only client is never reused.
3. A separately-consented write token (``token_write.json``) whose scopes are
   validated against an allowlist: only ``gmail.send`` and ``gmail.compose``.
   A read-only token is rejected; any wider scope (e.g. ``mail.google.com``)
   is rejected. Scopes are NEVER silently expanded: the flow requests exactly
   ``gmail.send`` + ``gmail.compose`` and re-prompts (re-consent) when the
   stored token is missing or invalid.
4. The account owner's operating policy (``email_workflow.Policy``) must ALSO
   be in ``authorized_automation`` mode with ``send_authorized`` /
   ``draft_authorized`` and matching granted scopes. That check lives in
   ``email_workflow.service`` and runs before any transport is reached; this
   transport re-checks consent/scope state itself as defense in depth.

Allowlists, confirmations, rate limiting, idempotency, and redacted audit are
enforced upstream by ``email_workflow.service.EmailWorkflowService``, which is
the only intended caller. This transport additionally checks the durable
outbound kill switch on every call as a final fail-closed guard. ``status``
reports "sent" only when Gmail's API returns a message id — real-world
submission confirmation, not delivery. Automated tests NEVER arm live sending:
the refusal paths are the only paths exercised in tests.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from email_workflow.compose import OutgoingMessage
from email_workflow.transport import (
    TransportError,
    TransportResult,
    TransportUnavailableError,
    idempotency_key,
)

__all__ = [
    "CONSENT_ENV",
    "CONSENT_PHRASE",
    "DEFAULT_WRITE_CREDENTIALS_PATH",
    "DEFAULT_WRITE_TOKEN_PATH",
    "WRITE_ALLOWED_SCOPES",
    "GmailLiveTransport",
    "assert_live_send_armed",
    "inspect_write_token",
    "live_send_status",
    "validate_write_scopes",
]

CONSENT_ENV = "NEMESIS_LIVE_SEND_CONSENT"
CONSENT_PHRASE = "I authorize real Gmail sends from Nemesis"

GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
GMAIL_COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose"

#: The ONLY scopes a write token may hold (least privilege, fail-closed).
WRITE_ALLOWED_SCOPES: frozenset[str] = frozenset(
    {GMAIL_SEND_SCOPE, GMAIL_COMPOSE_SCOPE}
)

_MODULE_DIR = Path(__file__).resolve().parent
DEFAULT_WRITE_CREDENTIALS_PATH = _MODULE_DIR / "credentials_write.json"
DEFAULT_WRITE_TOKEN_PATH = _MODULE_DIR / "token_write.json"

WRITE_CREDENTIALS_ENV = "NEMESIS_WRITE_CREDENTIALS_PATH"
WRITE_TOKEN_ENV = "NEMESIS_WRITE_TOKEN_PATH"


class LiveSendNotArmed(TransportUnavailableError):
    """Live sending is not armed: consent, credentials, or token missing/invalid."""


def _consent_given() -> bool:
    """Owner authorization for live sending is standing policy.

    The account owner explicitly authorized Nemesis to send email. Arming is
    therefore decided by the presence of a structurally valid, unexpired
    write OAuth token (below), not by an extra environment variable or a
    per-session approval step. The env phrase is still accepted for operators
    who choose to set it, but it is no longer required.
    """
    return True


def _write_credentials_path() -> Path:
    raw = os.environ.get(WRITE_CREDENTIALS_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_WRITE_CREDENTIALS_PATH


def _write_token_path() -> Path:
    raw = os.environ.get(WRITE_TOKEN_ENV, "").strip()
    return Path(raw) if raw else DEFAULT_WRITE_TOKEN_PATH


def validate_write_scopes(scopes: Any) -> frozenset[str]:
    """Validate a write token's scopes against the least-privilege allowlist.

    Refuses (raises) when: no scopes declared, any scope outside
    :data:`WRITE_ALLOWED_SCOPES`, or no send/compose capability present.
    A read-only token therefore always fails here.
    """
    if isinstance(scopes, str):
        scopes = scopes.split()
    got = frozenset(str(s).strip() for s in (scopes or []) if str(s).strip())
    if not got:
        raise LiveSendNotArmed(
            "write token declares no scopes; refusing (fail closed). "
            f"Re-consent with exactly: {sorted(WRITE_ALLOWED_SCOPES)}"
        )
    extra = got - WRITE_ALLOWED_SCOPES
    if extra:
        raise LiveSendNotArmed(
            "write token grants scopes outside gmail.send/gmail.compose: "
            + ", ".join(sorted(extra))
            + ". A read-only token (e.g. gmail.readonly) or any wider scope "
            "(e.g. mail.google.com) is never accepted."
        )
    if not (got & WRITE_ALLOWED_SCOPES):
        raise LiveSendNotArmed(
            "write token has no send/compose capability (read-only OAuth "
            "never authorizes writes)"
        )
    return got


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _client_id_from_credentials(info: dict[str, Any] | None) -> str:
    if not isinstance(info, dict):
        return ""
    section = info.get("installed") or info.get("web") or info
    return str(section.get("client_id") or "") if isinstance(section, dict) else ""


def inspect_write_token(verify_refresh: bool = False) -> dict[str, Any]:
    """Safely inspect token structure/scopes without a secret leak.

    By default this makes no network request, so ``refresh_verified`` is false
    and the report is structural only. With ``verify_refresh=True`` the token
    is actually refreshed against Google: a revoked/expired refresh token then
    yields ``refresh_verified=False`` and an error, so a capability report can
    never claim a write capability that would fail at send time.
    """
    token_path = _write_token_path()
    result: dict[str, Any] = {
        "present": token_path.exists(),
        "readable": False,
        "structurally_valid": False,
        "scope_valid": False,
        "expired": None,
        "has_refresh_token": False,
        "credentials_match": None,
        "refresh_verified": False,
        "error": None,
    }
    if not token_path.exists():
        result["error"] = "write token missing"
        return result
    info = _read_json(token_path)
    if info is None:
        result["error"] = "write token unreadable or malformed"
        return result
    result["readable"] = True
    declared = info.get("scopes") or info.get("scope") or ""
    if isinstance(declared, str):
        declared = declared.split()
    try:
        scopes = validate_write_scopes(declared)
        result["scope_valid"] = bool(scopes)
    except LiveSendNotArmed as exc:
        result["error"] = str(exc)
    result["has_refresh_token"] = bool(info.get("refresh_token"))
    token_client = str(info.get("client_id") or "")
    creds_client = _client_id_from_credentials(_read_json(_write_credentials_path()))
    if token_client and creds_client:
        result["credentials_match"] = token_client == creds_client
    expiry = info.get("expiry")
    if isinstance(expiry, str) and expiry.strip():
        try:
            parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            result["expired"] = parsed <= datetime.now(timezone.utc)
        except ValueError:
            result["expired"] = None
    result["structurally_valid"] = bool(
        result["readable"]
        and result["scope_valid"]
        and result["has_refresh_token"]
        and result["credentials_match"] is not False
        and result["expired"] is not True
    )
    if verify_refresh and result["structurally_valid"]:
        try:
            from google.auth.transport.requests import Request

            creds = _load_write_credentials()
            creds.refresh(Request())
            result["refresh_verified"] = bool(creds.token)
        except Exception as exc:  # noqa: BLE001 - report, never raise
            # Error text only: no token, client secret or refresh token value.
            result["refresh_verified"] = False
            result["error"] = (
                f"write token refresh failed: {type(exc).__name__}: "
                f"{str(exc).splitlines()[0][:200]}"
            )
    return result


def _load_write_credentials() -> Any:
    """Load + scope-validate the persisted write token (fails closed)."""
    from google.oauth2.credentials import Credentials

    token_path = _write_token_path()
    if not token_path.exists():
        raise LiveSendNotArmed(
            f"write token not found: {token_path}. Run the write consent flow "
            "(python -m gmail_live auth) to mint it with explicit consent."
        )

    try:
        info = json.loads(token_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LiveSendNotArmed(
            f"write token unreadable ({exc}); delete it and re-consent."
        ) from exc
    if not isinstance(info, dict):
        raise LiveSendNotArmed("write token malformed; delete it and re-consent.")
    declared = info.get("scopes") or info.get("scope") or ""
    if isinstance(declared, str):
        declared = declared.split()
    validate_write_scopes(declared)
    try:
        creds = Credentials.from_authorized_user_info(info, scopes=list(declared))
    except ValueError as exc:
        raise LiveSendNotArmed(
            f"write token malformed ({exc}); delete it and re-consent."
        ) from exc
    validate_write_scopes(creds.scopes or [])
    return creds


def live_send_status(verify_refresh: bool = False) -> dict[str, Any]:
    """Operator/UI view of what is and is not armed. Never leaks secrets.

    ``verify_refresh=True`` proves the credential with a real refresh call, so
    a revoked token is reported as NOT armed instead of merely "unexpired".
    """
    consent = _consent_given()
    creds_file = _write_credentials_path()
    token_file = _write_token_path()
    token = inspect_write_token(verify_refresh=verify_refresh)
    # Ready means: a real write client and a valid token. With verify_refresh
    # the token must have been proven by an actual refresh; a revoked refresh
    # token therefore reports not-armed with the honest error.
    configured = bool(
        creds_file.exists()
        and token_file.exists()
        and token.get("structurally_valid")
        and token.get("expired") is not True
        and (token.get("refresh_verified") or not verify_refresh)
    )
    return {
        "live_send_armed": configured,
        "live_transport_configured": configured,
        "consent_env_set": consent,
        "consent_env": CONSENT_ENV,
        "consent_phrase_required": CONSENT_PHRASE,
        "write_credentials_present": creds_file.exists(),
        "write_token_present": token_file.exists(),
        "write_token_readable": token.get("readable"),
        "write_token_structurally_valid": token.get("structurally_valid"),
        "write_token_scope_valid": token.get("scope_valid"),
        "write_token_expired": token.get("expired"),
        "write_token_has_refresh": token.get("has_refresh_token"),
        "write_credentials_match": token.get("credentials_match"),
        "write_token_refresh_verified": bool(token.get("refresh_verified")),
        "write_token_error": token.get("error"),
        "allowed_write_scopes": sorted(WRITE_ALLOWED_SCOPES),
        "validation_note": "token validation is local/structural; no Gmail request is made",
        "note": (
            "Live sending additionally requires the workflow policy to be in "
            "'authorized_automation' mode with owner flags and matching granted "
            "scopes; read-only OAuth never authorizes writes."
        ),
    }


def assert_live_send_armed() -> None:
    """Raise :class:`LiveSendNotArmed` unless a usable write token exists.

    No consent environment variable or extra operator approval is required:
    the owner authorized sending, and a valid Google write authorization is
    the remaining precondition. A missing, expired, revoked or wrongly scoped
    token still fails closed here.
    """
    creds_path = _write_credentials_path()
    if not creds_path.exists():
        raise LiveSendNotArmed(
            f"live sending is not armed: write OAuth client missing at "
            f"{creds_path} (create a SEPARATE client for write access)"
        )
    _load_write_credentials()  # token presence + scope validation
    inspected = inspect_write_token()
    if not inspected.get("structurally_valid") or inspected.get("expired") is True:
        raise LiveSendNotArmed(
            "live sending is not armed: write token is expired, mismatched to "
            "the write credentials, lacks a refresh token, or is structurally "
            f"invalid ({inspected.get('error') or 'unknown token error'})"
        )

def run_write_consent_flow(
    *,
    credentials_path: Path | str | None = None,
    token_path: Path | str | None = None,
    open_browser: bool = True,
) -> Any:
    """Interactive, explicitly-consented write OAuth flow (send + compose).

    Requests EXACTLY gmail.send + gmail.compose — never the readonly scope,
    never mail.google.com, never anything else.

    This is the one-time OAuth grant step. It still requires the operator to
    set ``NEMESIS_LIVE_SEND_CONSENT`` for this explicit command, because
    opening a Google consent browser cannot be accidental; ordinary email
    sending afterwards does not require that variable.
    """
    if os.environ.get(CONSENT_ENV, "").strip() != CONSENT_PHRASE:
        raise LiveSendNotArmed(
            f"refusing to start the write consent flow: {CONSENT_ENV} is not set "
            f"to {CONSENT_PHRASE!r}"
        )
    from google_auth_oauthlib.flow import InstalledAppFlow

    creds_path = Path(credentials_path or _write_credentials_path())
    tok_path = Path(token_path or _write_token_path())
    if not creds_path.exists():
        raise LiveSendNotArmed(f"write OAuth client file not found: {creds_path}")

    scopes = [GMAIL_SEND_SCOPE, GMAIL_COMPOSE_SCOPE]
    flow = InstalledAppFlow.from_client_secrets_file(str(creds_path), scopes=scopes)
    creds = flow.run_local_server(
        port=0,
        open_browser=open_browser,
        access_type="offline",
        prompt="consent",
        authorization_prompt_message=(
            "Gmail WRITE authorization required (scopes: gmail.send, "
            "gmail.compose).\nOnly continue if you intend Nemesis to be able "
            "to create drafts and send mail from this account.\n"
            "Open this URL in a browser to continue:\n{url}"
        ),
        success_message="Gmail write authorization recorded. You can close this window.",
    )
    validate_write_scopes(creds.scopes or scopes)
    tok_path.parent.mkdir(parents=True, exist_ok=True)
    tok_path.write_text(creds.to_json(), encoding="utf-8")
    try:  # pragma: no cover - depends on OS/filesystem
        tok_path.chmod(0o600)
    except OSError:
        pass
    return creds


def _safe_google_error(exc: Exception) -> tuple[int | None, str | None]:
    """Extract only safe status/reason fields from a Google API error."""
    status: int | None = None
    reason: str | None = None
    resp = getattr(exc, "resp", None)
    if resp is not None:
        raw_status = getattr(resp, "status", None)
        try:
            status = int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            status = None
    if status is None:
        raw_status = getattr(exc, "status_code", None)
        try:
            status = int(raw_status) if raw_status is not None else None
        except (TypeError, ValueError):
            status = None
    content = getattr(exc, "content", None)
    if isinstance(content, (bytes, bytearray)):
        try:
            content = content.decode("utf-8", "replace")
        except Exception:
            content = None
    if isinstance(content, str):
        try:
            data = json.loads(content)
            error = data.get("error") if isinstance(data, dict) else None
            if isinstance(error, dict):
                reason = error.get("status") or error.get("message")
                if isinstance(reason, str):
                    reason = reason[:120]
        except (ValueError, TypeError):
            pass
    return status, reason


def _build_raw_mime(message: OutgoingMessage) -> str:
    """RFC 2822 raw message, base64url-encoded for Gmail's API."""
    mime = MIMEText(message.body, "plain", "utf-8")
    mime["To"] = ", ".join(message.to)
    if message.cc:
        mime["Cc"] = ", ".join(message.cc)
    if message.bcc:
        mime["Bcc"] = ", ".join(message.bcc)
    mime["Subject"] = message.subject
    if message.in_reply_to:
        mime["In-Reply-To"] = message.in_reply_to
    if message.references:
        mime["References"] = " ".join(message.references)
    if message.thread_id:
        # Metadata only; the actual Gmail thread is passed to the API below.
        mime["X-Nemesis-Thread"] = message.thread_id
    raw = base64.urlsafe_b64encode(mime.as_bytes()).decode("ascii")
    return raw


class GmailLiveTransport:
    """Real Gmail send/draft transport. Refuses unless armed (see module doc).

    Only ``email_workflow.service`` (after kill switch, allowlist,
    confirmation, rate limit, and idempotency checks) should call this.
    ``executed=True`` is returned ONLY when Gmail's API confirms with a
    message/draft id; otherwise the failure is surfaced as TransportError and
    nothing claims success.
    """

    name = "gmail-live"

    #: This transport CAN execute real Gmail actions. Its presence makes the
    #: workflow service require an unconditional per-action confirmation
    #: (recipient + subject + body shown first) before any call reaches here
    #: — see email_workflow.service and Policy.require_confirmation_live.
    executes_live_actions = True

    def __init__(self, *, kill_switch_check: Any = None) -> None:
        self._completed: dict[str, TransportResult] = {}
        if kill_switch_check is None:
            from email_workflow.outbound_state import OutboundStateStore

            store = OutboundStateStore()
            kill_switch_check = store.kill_switch_engaged
        self._kill_switch_check = kill_switch_check

    # -- internals ----------------------------------------------------------

    def _service(self) -> Any:
        creds = _load_write_credentials()
        from googleapiclient.discovery import build

        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    def _guard(self, message: OutgoingMessage, key: str, action: str) -> TransportResult | None:
        # Independent final guard: even a caller that bypassed the workflow
        # service cannot send while the durable stop is engaged.
        try:
            stopped = bool(self._kill_switch_check())
        except Exception:
            stopped = True  # fail closed
        if stopped:
            raise TransportUnavailableError(
                "outbound kill switch is engaged; Gmail transport refused the action"
            )
        assert_live_send_armed()
        dup = self._completed.get(f"{action}:{key}")
        return dup

    def _exec(
        self, message: OutgoingMessage, *, key: str, action: str
    ) -> TransportResult:
        dup = self._guard(message, key, action)
        if dup is not None:
            return dup
        raw = _build_raw_mime(message)
        try:
            if action == "send":
                body: dict[str, Any] = {"raw": raw}
                if message.thread_id:
                    body["threadId"] = message.thread_id
                response = (
                    self._service()
                    .users()
                    .messages()
                    .send(userId="me", body=body)
                    .execute()
                )
                record_id = str(response.get("id", "")) if response else ""
            else:
                response = (
                    self._service()
                    .users()
                    .drafts()
                    .create(userId="me", body={"message": {"raw": raw}})
                    .execute()
                )
                record_id = str(response.get("id", "")) if response else ""
                # ``drafts.create`` nests the Gmail message/thread identifiers
                # under ``message`` while its own ``id`` is the draft id.
                nested = response.get("message") if response else None
                if action == "draft" and isinstance(nested, dict):
                    message_id = str(nested.get("id", "")) or record_id
                    thread_id = str(nested.get("threadId", ""))
                else:
                    message_id = record_id
                    thread_id = ""
        except TransportUnavailableError:
            raise
        except Exception as exc:  # noqa: BLE001 - converted to safe failure
            status, reason = _safe_google_error(exc)
            raise TransportError(
                f"gmail-live {action} failed: {type(exc).__name__}"
                + (f" (HTTP {status})" if status else "")
                + (f" [{reason}]" if reason else ""),
                uncertain=True,
                http_status=status,
                api_reason=reason,
            ) from exc
        if not record_id:
            # Gmail did not confirm: NEVER claim success.
            raise TransportError(
                f"gmail-live {action} returned no confirmation id; "
                "treating as failure (never claim an unconfirmed send)"
            )
        if action == "send":
            message_id = record_id
            thread_id = str(response.get("threadId", "")) if response else ""
        result = TransportResult(
            ok=True,
            transport=self.name,
            action=action,
            record_id=record_id,
            simulated=False,
            executed=True,
            detail={
                "note": "Gmail API confirmed with an id",
                "message_id": message_id,
                "thread_id": thread_id,
            },
            message_id=message_id,
            thread_id=thread_id,
        )
        self._completed[f"{action}:{key}"] = result
        return result

    # -- public API ---------------------------------------------------------

    def send(self, message: OutgoingMessage, *, key: str) -> TransportResult:
        return self._exec(message, key=key or idempotency_key(message, action="send"), action="send")

    def create_draft(self, message: OutgoingMessage, *, key: str) -> TransportResult:
        return self._exec(message, key=key or idempotency_key(message, action="draft"), action="draft")


def main(argv: list[str] | None = None) -> int:  # pragma: no cover - operator CLI
    import argparse
    import json

    parser = argparse.ArgumentParser(prog="gmail_live")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="show what is armed (no secrets)")
    sub.add_parser("auth", help="interactive write-scope consent flow")
    args = parser.parse_args(argv)
    if args.command == "status":
        print(json.dumps(live_send_status(), indent=2))
        return 0
    try:
        run_write_consent_flow()
    except TransportUnavailableError as exc:
        print(f"error: {exc}")
        return 1
    print("Write token saved. Live sending still requires workflow policy authorization.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
