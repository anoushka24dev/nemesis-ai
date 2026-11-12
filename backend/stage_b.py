"""
Stage B: read-only backend for the RealGmail reading pilot.

This is a thin, local-only FastAPI service that sits between the Chrome extension
and the existing read-only Gmail integration in ``gmail_auth.py``.

Responsibilities, all enforced from the start:

* Bind to ``127.0.0.1`` only. It is never exposed publicly in this stage.
* Require a per-install pairing nonce before any RealGmail operation is performed.
* Use only the existing read-only Gmail flow from ``gmail_auth.py``, including the
  ``NEMESIS_DEMO`` label policy and the mutating-verb guard.
* Never return OAuth tokens, refresh material, or token metadata to the extension.
* Fail closed when credentials, scopes, or the read-only policy are not satisfied.

Pairing model
-------------
The extension is issued a per-install pairing nonce out of band (the pairing
page). To pair it posts that nonce plus its own ``extension_origin`` to
``/pair``. Once paired, protected endpoints require a matching ``Origin`` header
and ``Authorization: Bearer <nonce>``. The nonce itself is never echoed back.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import secrets
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

import backend.adaptive_harness as _adaptive
import backend.feedback as _feedback
import backend.integrations as _integrations
import backend.security_metrics as _security_metrics
import email_workflow.quality as _quality
import gmail_auth as _gmail_auth
import threats as _threats
from adaptive_agent_eval.experiment_matrix import (
    build_manifest as _build_experiment_manifest,
)
from adaptive_agent_eval.experiment_matrix import (
    manifest_summary as _experiment_manifest_summary,
)
from backend.local_llm import (
    LocalModelError,
)
from backend.local_llm import (
    analyze_local as _analyze_local,
)
from backend.nemesis_demo import (
    nemesis_demo_run,
    nemesis_demo_status,
    nemesis_demo_stop,
)
from backend.nemesis_workflow import (
    nemesis_activity,
    nemesis_killswitch,
    nemesis_prepare_forward,
    nemesis_prepare_new,
    nemesis_prepare_reply,
    nemesis_submit,
    nemesis_workflow_status,
)
from email_workflow import (
    EmailWorkflowService,
    GenerationSettings,
    OperatingMode,
    Policy,
    message_from_summary,
)
from email_workflow.audit import AuditLog
from email_workflow.policy import (
    GMAIL_COMPOSE_SCOPE as _POLICY_GMAIL_COMPOSE_SCOPE,
)
from email_workflow.policy import (
    GMAIL_MODIFY_SCOPE as _POLICY_GMAIL_MODIFY_SCOPE,
)
from email_workflow.policy import (
    GMAIL_SEND_SCOPE as _POLICY_GMAIL_SEND_SCOPE,
)
from email_workflow.policy import READ_ONLY_GRANT, PolicyError
from gmail_auth import (
    DEMO_LABEL,
    GMAIL_READONLY_SCOPE,
    GeminiAnalysisError,
    ReadOnlyScopeError,
    ReadOnlyViolation,
    build_gmail_service,
    fetch_nemesis_demo_emails,
    get_credentials,
)
from gmail_auth import (
    analyze_emails as _analyze_emails,
)
from gmail_demo.defense import DefenseChecker
from gmail_demo.models import Email as _DemoEmail
from gmail_demo.models import ProposedAction

# Load owner configuration before any policy/service construction. Explicit
# process environment values win; .env only fills unset variables.
try:  # python-dotenv is available in the deployed environment
    from dotenv import load_dotenv as _load_dotenv

    _load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
except Exception:  # pragma: no cover - optional dependency path
    pass

APP_ORIGIN = "http://127.0.0.1:8123"
ALLOWED_EXTENSION_ORIGINS = frozenset({"chrome-extension://"})
_BACKEND_PORT = 8123
_MOUNT_PREFIX = "/api/v1/stage_b"
_EXTERNAL_HOSTS_ENV = "ALLOWED_EXTERNAL_STAGE_B_HOSTS"
# Optional: pin a single extension ID so identity is an exact origin match
# (chrome-extension://<id>) instead of any extension under the scheme prefix.
_PINNED_EXTENSION_ID_ENV = "STAGE_B_EXTENSION_ID"

_MAX_RESULTS_DEFAULT = 25
_MAX_RESULTS_LIMIT = 25

#: /analyze provider allowlist. "gemini" is the pre-existing external path
#: (unchanged default); "local" is loopback Ollama and never reaches Gemini.
_ANALYZE_PROVIDERS = frozenset({"local", "gemini"})

# ---------------------------------------------------------------------------
# Outbound workflow configuration (owner-controlled via environment).
#
# Safety defaults: simulation mode, empty allowlists, 5 actions/hour, and
# granted scopes stay READ-ONLY. The backend NEVER widens OAuth scopes on its
# own. Live sending becomes possible only when the owner arms every gate in
# gmail_live.py (consent phrase + separate write OAuth client + a
# scope-validated write token) AND raises the policy via env (mode, send flag,
# NEMESIS_GRANTED_SCOPES). Even then every policy gate — allowlist,
# confirmation, outgoing defense scan, rate limit, kill switch, idempotency —
# runs before the transport is reached (see docs/AUTONOMOUS_EMAIL.md).
# ---------------------------------------------------------------------------
_WORKFLOW_MODE_ENV = "NEMESIS_WORKFLOW_MODE"
_WORKFLOW_RECIPIENTS_ENV = "NEMESIS_ALLOWED_RECIPIENTS"
_WORKFLOW_DOMAINS_ENV = "NEMESIS_ALLOWED_DOMAINS"
_WORKFLOW_RATE_ENV = "NEMESIS_RATE_LIMIT_PER_HOUR"
_WORKFLOW_DRAFT_AUTH_ENV = "NEMESIS_DRAFT_AUTHORIZED"
_WORKFLOW_SEND_AUTH_ENV = "NEMESIS_SEND_AUTHORIZED"
_WORKFLOW_AUDIT_PATH_ENV = "NEMESIS_WORKFLOW_AUDIT_PATH"
_WORKFLOW_SCOPES_ENV = "NEMESIS_GRANTED_SCOPES"
_FEEDBACK_STORE_ENV = "NEMESIS_FEEDBACK_STORE"
_QUALITY_STORE_ENV = "NEMESIS_QUALITY_STORE"
_ADAPTIVE_STORE_ENV = "NEMESIS_ADAPTIVE_STORE"
_OUTBOUND_STATE_ENV = "NEMESIS_OUTBOUND_STATE_PATH"

#: Owner-declarable scopes: short names (lowercase) or the full URIs.
_SCOPE_ALIASES: dict[str, str] = {
    "readonly": GMAIL_READONLY_SCOPE,
    "send": _POLICY_GMAIL_SEND_SCOPE,
    "compose": _POLICY_GMAIL_COMPOSE_SCOPE,
    "modify": _POLICY_GMAIL_MODIFY_SCOPE,
}
#: The same scopes keyed by their full URI (either form parses identically).
_SCOPE_URIS: dict[str, str] = {
    uri.lower(): uri for uri in _SCOPE_ALIASES.values()
}


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _env_csv(name: str) -> frozenset[str]:
    raw = os.environ.get(name, "")
    return frozenset(
        part.strip().lower() for part in raw.split(",") if part.strip()
    )


def _env_int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        value = int(raw) if raw else default
    except ValueError:
        return default
    return max(lo, min(hi, value))


def _env_scopes(name: str) -> frozenset[str]:
    """Owner-declared granted scopes (fail-closed; default stays READ-ONLY).

    Accepts a CSV of scope short names (``readonly``/``send``/``compose``/
    ``modify``) or the full scope URIs. Unknown values are REFUSED with
    :class:`PolicyError` — never silently granted, never silently dropped —
    and an empty/unset variable keeps the read-only grant. Declaring a scope
    here only states what the owner granted: sending still requires the
    armed write token in ``gmail_live`` plus mode/flag/allowlist/confirmation
    gates before any transport is reached.
    """
    raw = os.environ.get(name, "").strip()
    if not raw:
        return READ_ONLY_GRANT
    out: set[str] = set()
    for part in raw.split(","):
        token = part.strip().lower()
        if not token:
            continue
        scope = _SCOPE_ALIASES.get(token) or _SCOPE_URIS.get(token)
        if scope is None:
            raise PolicyError(
                f"unknown scope {part.strip()!r} in {name}; allowed: "
                f"{sorted(_SCOPE_ALIASES)} or their full URIs"
            )
        out.add(scope)
    return frozenset(out) or READ_ONLY_GRANT


def build_workflow_policy() -> Policy:
    """Outbound policy from owner-controlled env vars (fail-safe defaults)."""
    return Policy(
        mode=os.environ.get(_WORKFLOW_MODE_ENV, "").strip() or "simulation",
        allowed_recipients=_env_csv(_WORKFLOW_RECIPIENTS_ENV),
        allowed_domains=_env_csv(_WORKFLOW_DOMAINS_ENV),
        rate_limit_per_hour=_env_int(_WORKFLOW_RATE_ENV, 5, 1, 100),
        # Flags and granted scopes are BOTH owner-declared (env); even with
        # both raised, assert_send_authorized still needs the armed write
        # token in gmail_live before a real send can happen.
        draft_authorized=_env_flag(_WORKFLOW_DRAFT_AUTH_ENV),
        send_authorized=_env_flag(_WORKFLOW_SEND_AUTH_ENV),
        granted_scopes=_env_scopes(_WORKFLOW_SCOPES_ENV),
    )


def build_workflow_service(
    *,
    audit: AuditLog | None = None,
    policy: Policy | None = None,
    state_path: str | Path | None = None,
) -> EmailWorkflowService:
    """Workflow service with the safest transport that is actually available.

    The in-memory mock transport is the default: it simulates every action
    (executed=False always) and never contacts a network, so the full
    compose/reply/submit chain works with no possibility of real delivery.

    The REAL Gmail transport (``gmail_live.GmailLiveTransport``) is selected
    only when the owner has armed live sending (consent phrase + separate
    write OAuth client + scope-validated write token, per ``gmail_live``)
    AND moved the policy past simulation mode. The transport re-checks
    arming on every call and every policy gate (allowlist, confirmation,
    outgoing defense scan, rate limit, kill switch, idempotency) still runs
    first in ``EmailWorkflowService.submit``. Any doubt falls back to the
    mock, so nothing can leave the process unless every owner gate is up.
    """
    if audit is None:
        audit_path = os.environ.get(_WORKFLOW_AUDIT_PATH_ENV, "").strip()
        audit = AuditLog(audit_path or None)
    resolved = policy or build_workflow_policy()
    configured_state = str(state_path or os.environ.get(_OUTBOUND_STATE_ENV, "")).strip()
    from email_workflow.outbound_state import OutboundStateStore

    state_store = OutboundStateStore(configured_state or None)
    transport: Any = None  # None -> EmailWorkflowService defaults to mock
    if resolved.mode is not OperatingMode.SIMULATION:
        try:
            from gmail_live import GmailLiveTransport, live_send_status

            if live_send_status().get("live_send_armed"):
                transport = GmailLiveTransport(
                    kill_switch_check=state_store.kill_switch_engaged
                )
        except Exception:  # noqa: BLE001 - fail safe to the mock (no delivery)
            transport = None
    return EmailWorkflowService(
        policy=resolved,
        audit=audit,
        transport=transport,
        state_store=state_store,
        require_prepared_artifacts=True,
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _error(code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=code, content={"error": message})


def _header_token(raw: str | None) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    raw = raw.removeprefix("Bearer ")
    return raw.strip() or None


def _origin_matches(request_origin: str | None, allowed_prefixes: frozenset[str]) -> bool:
    if not request_origin:
        return False
    lower = request_origin.lower()
    return any(lower.startswith(prefix.lower()) for prefix in allowed_prefixes)


def _pinned_extension_id() -> str | None:
    """The extension ID we require, if the operator pinned one.

    The scheme prefix ``chrome-extension://`` accepts *any* extension ID, so a
    pinned ID turns origin validation into an exact match against the one
    extension this install is meant to serve.
    """
    raw = os.environ.get(_PINNED_EXTENSION_ID_ENV, "")
    return raw.strip() or None


def _origin_allowed(request_origin: str | None) -> bool:
    """Fail-closed origin check used by every auth path.

    Must be an allowed extension origin; when an extension ID is pinned, the
    origin must additionally be exactly ``chrome-extension://<pinned-id>``.
    """
    if not _origin_matches(request_origin, ALLOWED_EXTENSION_ORIGINS):
        return False
    pinned = _pinned_extension_id()
    if pinned is None:
        return True
    assert request_origin is not None
    return request_origin.strip().lower() == f"chrome-extension://{pinned}".lower()


def _nonce_matches(presented: str, expected: str) -> bool:
    """Constant-time nonce comparison that fails closed on any error.

    ``hmac.compare_digest`` raises on non-ASCII input; treat that as a mismatch
    rather than letting an exception leak timing or reject the request loudly.
    """
    try:
        return hmac.compare_digest(presented, expected)
    except (TypeError, ValueError):
        return False


def _request_origin(request: Request) -> str | None:
    """Best-effort origin header reader. Missing headers and empty strings are
    both treated as missing origins.
    """
    try:
        header = request.headers.get("origin")
    except Exception:
        return None
    if not header or not header.strip():
        return None
    return header.strip()


def _local_request(request: Request) -> bool:
    """True when the peer is the loopback interface on the backend port.

    This is informational (used by the bind/health contract); network exposure
    is prevented by binding the server to ``127.0.0.1`` in the first place.
    """
    remote = request.client
    if remote is None:
        return False
    host, port = remote.host, remote.port
    if host is None or port is None:
        return False
    try:
        return (host == "127.0.0.1" or host == "localhost") and port == _BACKEND_PORT
    except Exception:
        return False


def _allowed_external_pairs() -> list[tuple[str, int]]:
    pairs: list[tuple[str, int]] = []
    raw = os.environ.get(_EXTERNAL_HOSTS_ENV, "")
    if not raw:
        return pairs
    for segment in raw.split(","):
        segment = segment.strip()
        if not segment:
            continue
        if ":" in segment:
            host, port = segment.rsplit(":", 1)
            try:
                pairs.append((host.strip() or "127.0.0.1", int(port.strip())))
            except ValueError:
                continue
        else:
            pairs.append((segment, _BACKEND_PORT))
    return pairs


def _request_is_allowed(request: Request) -> bool:
    """True only for localhost loopback or explicitly opted-in hosts.

    No public or wildcard access is granted by this helper.
    """
    if _local_request(request):
        return True
    remote = request.client
    if remote is None:
        return False
    for host, port in _allowed_external_pairs():
        try:
            if remote.host == host and remote.port == port:
                return True
        except Exception:
            continue
    return False


def _feed_name_from_token(token: str) -> str:
    """Deterministic, non-reversible public label derived from the pairing nonce."""
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return f"stage_b_{digest[:12]}"


class StageBBackend:
    def __init__(
        self,
        *,
        credentials_path: Path | str,
        token_path: Path | str,
        pairing_nonce: str,
        workflow_service: EmailWorkflowService | None = None,
        feedback_store: Path | str | None = None,
        quality_store: Path | str | None = None,
        adaptive_store: Path | str | None = None,
    ) -> None:
        self._credentials_path = Path(credentials_path)
        self._token_path = Path(token_path)
        self._pairing_nonce = pairing_nonce
        self._state: str = "unpaired"
        # The extension origin we are bound to. Retained across ``reset`` so a
        # later reset from a *different* origin is still rejected; only the
        # paired flag (and therefore bearer acceptance) is cleared by reset.
        self._paired_origin: str | None = None
        self._last_ping: str | None = None
        self._nonces_exposed: int = 0
        # Integrated defense/workflow services (pairing-gated like everything
        # else). The workflow service ships with the in-memory mock transport:
        # no code path here can deliver real email.
        self._workflow = workflow_service or build_workflow_service()
        env_feedback = os.environ.get(_FEEDBACK_STORE_ENV, "").strip()
        env_quality = os.environ.get(_QUALITY_STORE_ENV, "").strip()
        env_adaptive = os.environ.get(_ADAPTIVE_STORE_ENV, "").strip()
        self._feedback_store = (
            Path(feedback_store) if feedback_store else (Path(env_feedback) if env_feedback else None)
        )
        self._quality_store = (
            Path(quality_store) if quality_store else (Path(env_quality) if env_quality else None)
        )
        self._adaptive_store = (
            Path(adaptive_store) if adaptive_store else (Path(env_adaptive) if env_adaptive else None)
        )
        # The adaptive evaluation harness (real adaptive_agent_eval controller).
        # Constructed lazily so pairing-gated endpoints never pay the cost until
        # called, and so an import/construct failure can't break the backend.
        self._adaptive_harness = None
        self._adaptive_harness_lock = threading.Lock()

    @property
    def workflow(self) -> EmailWorkflowService:
        """The outbound workflow service (mock transport; simulation default)."""
        return self._workflow

    def _feedback_path(self) -> Path | None:
        return _feedback.store_path(self._feedback_store)

    def _quality_path(self) -> Path | None:
        return _quality.store_path(self._quality_store)

    def _adaptive_path(self) -> Path | None:
        return self._adaptive_store

    @property
    def adaptive_harness(self):
        """Lazily construct the adaptive evaluation harness (thread-safe)."""
        if self._adaptive_harness is None:
            with self._adaptive_harness_lock:
                if self._adaptive_harness is None:
                    self._adaptive_harness = _adaptive.AdaptiveHarness(
                        store_path=self._adaptive_store
                    )
        return self._adaptive_harness

    def _require_auth(self, request: Request) -> JSONResponse | None:
        """Pairing + origin + bearer gate. Returns an error response or None."""
        try:
            self._auth_headers(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
        return None

    @property
    def nonces_exposed(self) -> int:
        """Counter used by safety assertions only; never exposed to the extension."""
        return self._nonces_exposed

    @nonces_exposed.setter
    def nonces_exposed(self, value: int) -> None:
        self._nonces_exposed = value

    @property
    def state(self) -> str:
        return self._state

    @property
    def paired_origin(self) -> str | None:
        return self._paired_origin

    def reset(self, request: Request | None = None) -> JSONResponse:
        """Clear the paired flag so bearer tokens stop being accepted.

        A provided ``Origin`` header must be an allowed extension origin and must
        match the origin this install is bound to; otherwise the reset is refused
        (403). A missing origin header is allowed: reset only de-escalates access,
        it never grants any. Returns a JSON body attesting that the nonce is not
        echoed.
        """
        if request is not None:
            origin = _request_origin(request)
            if origin is not None:
                if not _origin_allowed(origin):
                    raise HTTPException(status_code=403, detail="Extension origin not allowed")
                if self._paired_origin is not None and origin != self._paired_origin:
                    raise HTTPException(status_code=403, detail="Extension origin changed after pairing")
        self._state = "unpaired"
        self._last_ping = None
        return JSONResponse(
            status_code=200,
            content={
                "state": "unpaired",
                "paired": False,
                "pairing_nonce_exposed": False,
                "reset_at": _now_iso(),
            },
        )

    def present_nonce(self, request: Request, presented: str) -> JSONResponse:
        """Low-level pairing primitive used by the pairing page.

        Requires an allowed extension ``Origin`` header and the exact nonce.
        """
        origin = _request_origin(request)
        if not origin or not origin.strip():
            return _error(400, "Missing origin header")

        if not _origin_allowed(origin):
            return _error(403, "Extension origin not allowed")

        if not presented or not presented.strip():
            return _error(400, "Missing or empty nonce")

        if not _nonce_matches(presented, self._pairing_nonce):
            return _error(403, "Pairing nonce rejected")

        return self._bind_pairing(origin)

    def offer_pairing(
        self,
        request: Request,
        *,
        presented_nonce: str | None = None,
        extension_origin: str | None = None,
    ) -> JSONResponse:
        """Pair with an extension that presents the expected nonce.

        The pairing page exposes the nonce exactly once intentionally: only the
        extension that was offered this exact nonce may complete pairing, and the
        nonce is not stored in any frontend or response after that point.

        The bound origin comes from the request body's ``extension_origin`` field
        (the extension declaring itself). A present ``Origin`` header, if any, must
        also be an allowed extension origin.
        """
        # Header origin is optional here; when present it must still be allowed.
        header_origin = _request_origin(request)
        if header_origin is not None and not _origin_allowed(header_origin):
            return _error(403, "Extension origin not allowed")

        ext_origin = (extension_origin or "").strip()
        if not ext_origin:
            return _error(400, "Missing or empty extension_origin")

        if not _origin_allowed(ext_origin):
            return _error(403, "Extension origin not allowed")

        if presented_nonce is None:
            return _error(400, "Missing or empty nonce")
        presented_nonce = presented_nonce.strip()
        if not presented_nonce:
            return _error(400, "Missing or empty nonce")

        if not _nonce_matches(presented_nonce, self._pairing_nonce):
            self._nonces_exposed += 1
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Pairing nonce rejected",
                    "hint": (
                        "PAIRING NONCE EXPOSED: STOP — DO NOT PRESENT THIS NONCE TO ANY EXTENSION "
                        "OR STORE IT ON ANY FRONTEND OR DEVICE. The backend may have already exposed "
                        "the real nonce once; rotate it instead of retrying here."
                    ),
                },
            )

        return self._bind_pairing(ext_origin)

    def _bind_pairing(self, origin: str) -> JSONResponse:
        self._state = "paired"
        self._paired_origin = origin
        self._last_ping = _now_iso()
        return JSONResponse(
            status_code=200,
            content={
                "state": "paired",
                "paired": True,
                "origin_validated": origin,
                "paired_at": _now_iso(),
            },
        )

    def ping(self, request: Request) -> JSONResponse:
        origin = _request_origin(request)
        if not origin or not origin.strip():
            return _error(400, "Missing origin header")

        if not _origin_allowed(origin):
            return _error(403, "Extension origin not allowed")

        if self._state != "paired":
            return _error(403, "Not paired with an extension")

        if origin != self._paired_origin:
            return _error(403, "Extension origin changed after pairing")

        bearer = _header_token(request.headers.get("authorization"))
        if not bearer:
            return _error(401, "Missing bearer token")
        if not _nonce_matches(bearer, self._pairing_nonce):
            return _error(401, "Bearer token rejected")

        self._last_ping = _now_iso()
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "state": self._state,
                "last_ping": self._last_ping,
                "origin_validated": origin,
                "feed_name_prefix": _feed_name_from_token(self._pairing_nonce),
            },
        )

    def _require_paired(self, request: Request) -> str:
        origin = _request_origin(request)
        if not origin or not origin.strip():
            raise HTTPException(status_code=400, detail="Missing origin header")
        if not _origin_allowed(origin):
            raise HTTPException(status_code=403, detail="Extension origin not allowed")
        if self._state != "paired":
            raise HTTPException(status_code=403, detail="Not paired with an extension")
        if origin != self._paired_origin:
            raise HTTPException(status_code=403, detail="Extension origin changed after pairing")
        return origin

    def _auth_headers(self, request: Request) -> dict[str, str]:
        origin = self._require_paired(request)
        bearer = _header_token(request.headers.get("authorization"))
        if not bearer:
            raise HTTPException(status_code=401, detail="Missing bearer token")
        if not _nonce_matches(bearer, self._pairing_nonce):
            raise HTTPException(status_code=401, detail="Bearer token rejected")
        return {"origin": origin, "bearer": bearer}

    def _assert_readonly_after_auth(self) -> None:
        """Fail closed immediately if the scope this backend may ever hold is not readonly.

        This check runs before any Gmail API call, so a corrupted or tampered oauth
        client does not widen access.
        """
        scopes = _gmail_auth.requested_scopes()
        got: frozenset[str] = frozenset(str(s).strip() for s in scopes if str(s).strip())
        if got != frozenset({GMAIL_READONLY_SCOPE}):
            raise ReadOnlyScopeError(
                "Read-only scope contract violated: backend would be allowed to hold "
                f"scopes {sorted(got)}, but only {GMAIL_READONLY_SCOPE} is allowed."
            )

    def fetch_demo_emails(self, request: Request, max_results: int) -> JSONResponse:
        try:
            self._auth_headers(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
        try:
            self._assert_readonly_after_auth()
            creds = get_credentials(
                credentials_path=self._credentials_path,
                token_path=self._token_path,
                open_browser=False,
                timeout_seconds=60,
            )
            service = build_gmail_service(creds)
            emails = fetch_nemesis_demo_emails(service, max_results=max_results)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "label": DEMO_LABEL,
                    "scope": GMAIL_READONLY_SCOPE,
                    "read_only": True,
                    "email_count": len(emails),
                    "emails": [
                        {
                            "id": em.id,
                            "sender": em.sender,
                            "subject": em.subject,
                            "snippet": em.preview(120),
                            "body_text": em.body,
                            "raw_body_chars": len(em.body),
                            "labels": em.labels,
                            "received_at": em.received_at,
                        }
                        for em in emails
                    ],
                    "fetched_at": _now_iso(),
                },
            )
        except ReadOnlyScopeError as exc:
            return _error(403, f"Read-only scope violation: {exc}")
        except ReadOnlyViolation as exc:
            return _error(403, f"Read-only violation blocked: {exc}")
        except GeminiAnalysisError as exc:
            return _error(502, f"Gemini analysis error: {exc}")
        except Exception as exc:
            return _error(500, f"_backend fetch failed: {exc}")

    def analyze_demo_emails(
        self, request: Request, max_results: int, *, provider: str = "gemini"
    ) -> JSONResponse:
        if provider not in _ANALYZE_PROVIDERS:
            return _error(
                400,
                "provider must be one of: "
                + ", ".join(sorted(_ANALYZE_PROVIDERS)),
            )
        try:
            self._auth_headers(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
        try:
            self._assert_readonly_after_auth()
            creds = get_credentials(
                credentials_path=self._credentials_path,
                token_path=self._token_path,
                open_browser=False,
                timeout_seconds=60,
            )
            service = build_gmail_service(creds)
            emails = fetch_nemesis_demo_emails(service, max_results=max_results)
            if provider == "local":
                # Local mode: loopback Ollama only. This branch never builds
                # the Gemini provider config or client (see backend/local_llm),
                # so no email content can reach an external AI from here.
                analysis = _analyze_local(emails)
            else:
                analysis = _analyze_emails(emails)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "provider": provider,
                    "analysis": analysis,
                    "fetched_at": _now_iso(),
                },
            )
        except LocalModelError as exc:
            # analyze_local defaults to rules-only fallback, so this is a
            # defensive mapping (e.g. a refused non-loopback URL config).
            return _error(503, f"Local model error ({exc.category}): {exc}")
        except ReadOnlyScopeError as exc:
            return _error(403, f"Read-only scope violation: {exc}")
        except ReadOnlyViolation as exc:
            return _error(403, f"Read-only violation blocked: {exc}")
        except GeminiAnalysisError as exc:
            return _error(502, f"Gemini analysis error: {exc}")
        except Exception as exc:
            return _error(500, f"_backend analyze failed: {exc}")

    # ------------------------------------------------------------------
    # Integrated defense: metrics, ruleset status, hill climbing, workflow.
    #
    # All endpoints below are pairing-gated exactly like /feed and /analyze,
    # run locally, and use the deterministic ruleset + the versioned
    # feedback/quality stores. No model calls and no Gmail writes happen on
    # any of these paths.
    # ------------------------------------------------------------------

    def defense_status(self, request: Request) -> JSONResponse:
        """Active ruleset version, regression state, quality version, optimizer facts."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            path = self._feedback_path()
            ruleset = _feedback.active_ruleset(path)
            store = _feedback.show(path=path)
            regression = _threats.evaluate_ruleset(ruleset)
            quality = _quality.show(path=self._quality_path())
            parent = ruleset.parent
            versions = _feedback._load(path)["versions"] if path and Path(path).exists() else {}
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "active_ruleset": {
                        "version": ruleset.version,
                        "scores": dict(ruleset.scores),
                        "review_threshold": ruleset.review_threshold,
                        "flag_threshold": ruleset.flag_threshold,
                        "parent": parent,
                    },
                    "regression": regression,
                    "feedback_counts": store["counts"],
                    "feedback_audit": store["recent_audit"],
                    "quality": {
                        "active_version": quality["active_version"],
                        "active_settings": quality["active_settings"],
                        "counts": quality["counts"],
                    },
                    "rollback": {
                        "available": bool(parent and parent in versions),
                        "target": parent,
                    },
                    "optimizer": {
                        "defense_parameters": (
                            "per-rule weights (bounded by FLOORS/CAPS) and the "
                            "review/flag decision thresholds of the deterministic "
                            "classifier, evaluated against the versioned regression "
                            "dataset (threats.REGRESSION_CASES)"
                        ),
                        "generation_parameters": (
                            "reply generation knobs only: tone, length, greeting, "
                            "sign_off (KNOB_SCHEMA)"
                        ),
                        "model_weights": (
                            "hill climbing never trains Gemini and never changes "
                            "model weights; no model call is involved"
                        ),
                    },
                },
            )
        except Exception as exc:
            return _error(500, f"defense status failed: {exc}")

    def metrics_report(self, request: Request) -> JSONResponse:
        """ASR, detection/precision/FPR/FNR, blast radius, categories, blocked actions."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            ruleset = _feedback.active_ruleset(self._feedback_path())
            report = _security_metrics.full_report(
                ruleset,
                audit_records=self._workflow.audit.records,
                rate_limit_per_hour=self._workflow.policy.rate_limit_per_hour,
            )
            report["workflow_mode"] = self._workflow.policy.mode.value
            return JSONResponse(status_code=200, content={"status": "ok", "metrics": report})
        except Exception as exc:
            return _error(500, f"metrics failed: {exc}")

    def assess_text(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Deterministic defense assessment of posted email text (open-email analysis)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            subject = str(body.get("subject") or "")[:1000]
            text = str(body.get("body_text") or body.get("body") or "")[:20000]
            sender = str(body.get("sender") or "unknown@untrusted.invalid")[:500]
            email = _DemoEmail(
                id=str(body.get("email_id") or "posted-text"),
                sender=sender,
                subject=subject,
                body=text,
                labels=[DEMO_LABEL],
            )
            ruleset = _feedback.active_ruleset(self._feedback_path())
            assessment = _threats.assess_email(email, ruleset)
            verdict = DefenseChecker().check(
                email, ProposedAction(action="read", email_id=email.id)
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "assessment": assessment,
                    "action_check": {"decision": verdict.decision, "reasons": verdict.reasons},
                    "note": (
                        "recommendation only; nothing in Gmail is flagged, "
                        "quarantined, or modified by this assessment"
                    ),
                },
            )
        except Exception as exc:
            return _error(400, f"assessment failed: {exc}")

    def hillclimb_status(self, request: Request) -> JSONResponse:
        """Hill-climbing state: baseline vs candidates, decisions, rollback."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            fb_path = self._feedback_path()
            q_path = self._quality_path()
            fb_data = _feedback._load(fb_path) if fb_path and Path(fb_path).exists() else None
            ruleset = _feedback.active_ruleset(fb_path)
            baseline = _threats.evaluate_ruleset(ruleset)
            defense_proposals = (fb_data or {}).get("proposals", [])
            quality_data = _quality._load(q_path) if q_path and Path(q_path).exists() else None
            quality_candidates = (quality_data or {}).get("candidates", [])
            active_quality = _quality.active_settings(q_path)
            quality_baseline = _quality.evaluate_settings(active_quality)
            q_active_version = (quality_data or {}).get("active_version", "email-quality-v1")
            q_parent = (
                (quality_data or {}).get("versions", {}).get(q_active_version, {}).get("parent")
                if quality_data
                else None
            )
            q_versions = (quality_data or {}).get("versions", {}) if quality_data else {}
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "defense": {
                        "active_version": ruleset.version,
                        "baseline": baseline,
                        "proposals": defense_proposals,
                        "accepted": [p for p in defense_proposals if p.get("status") == "applied"],
                        "rejected": [p for p in defense_proposals if p.get("status") == "rejected"],
                        "pending": [p for p in defense_proposals if p.get("status") == "pending"],
                    },
                    "generation": {
                        "active_version": q_active_version,
                        "baseline": {
                            "score": quality_baseline["score"],
                            "metrics": quality_baseline["metrics"],
                        },
                        "candidates": quality_candidates,
                        "accepted": [
                            cd for cd in quality_candidates if cd.get("status") == "applied"
                        ],
                        "rejected": [
                            cd for cd in quality_candidates if cd.get("status") == "rejected"
                        ],
                        "pending": [
                            cd for cd in quality_candidates if cd.get("status") == "pending"
                        ],
                        "rollback": {
                            "available": bool(q_parent and q_parent in q_versions),
                            "target": q_parent,
                        },
                    },
                },
            )
        except Exception as exc:
            return _error(500, f"hill-climb status failed: {exc}")

    def hillclimb_run(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Run the generation-knob hill climber (dry run; persists nothing)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            max_iterations = max(1, min(32, int(body.get("max_iterations") or 16)))
            climb = _quality.hill_climb(max_iterations=max_iterations, path=self._quality_path())
            return JSONResponse(status_code=200, content={"status": "ok", "climb": climb})
        except Exception as exc:
            return _error(400, f"hill climb failed: {exc}")

    def hillclimb_propose(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Propose a bounded candidate: 'quality' knobs or a 'defense' weight."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        kind = str(body.get("kind") or "quality")
        try:
            if kind == "quality":
                settings = body.get("settings")
                if settings is None:
                    climb = _quality.hill_climb(path=self._quality_path())
                    settings = climb["end_settings"]
                candidate = _quality.propose_candidate(
                    GenerationSettings.from_dict(settings),
                    str(body.get("rationale") or "hill-climb proposal"),
                    path=self._quality_path(),
                )
                return JSONResponse(status_code=200, content={"status": "ok", "candidate": candidate})
            if kind == "defense":
                proposal_id = _feedback.propose_adjustment(
                    str(body.get("rule_id") or ""),
                    float(body.get("weight")),
                    [str(f) for f in (body.get("feedback_ids") or [])],
                    str(body.get("rationale") or ""),
                    path=self._feedback_path(),
                )
                return JSONResponse(
                    status_code=200,
                    content={"status": "ok", "proposal_id": proposal_id, "state": "pending"},
                )
            return _error(400, f"unknown proposal kind: {kind!r}")
        except Exception as exc:
            return _error(400, f"propose failed: {exc}")

    def hillclimb_apply(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Explicit approval step: regression-gate a candidate, then activate."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        kind = str(body.get("kind") or "quality")
        try:
            if kind == "quality":
                report = _quality.apply_candidate(
                    str(body.get("candidate_id") or ""), path=self._quality_path()
                )
            elif kind == "defense":
                report = _feedback.apply_proposal(
                    str(body.get("proposal_id") or ""), path=self._feedback_path()
                )
            else:
                return _error(400, f"unknown proposal kind: {kind!r}")
            return JSONResponse(status_code=200, content={"status": "ok", "report": report})
        except Exception as exc:
            return _error(400, f"apply failed: {exc}")

    def hillclimb_revert(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Rollback: reactivate the previous (or a named) version."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        kind = str(body.get("kind") or "quality")
        version = body.get("version") or None
        try:
            if kind == "quality":
                result = _quality.revert(version, path=self._quality_path())
            elif kind == "defense":
                result = _feedback.revert(version, path=self._feedback_path())
            else:
                return _error(400, f"unknown kind: {kind!r}")
            return JSONResponse(status_code=200, content={"status": "ok", "result": result})
        except Exception as exc:
            return _error(400, f"revert failed: {exc}")

    # ------------------------------------------------------------------
    # Adaptive Strategy Engine (real adaptive_agent_eval harness).
    #
    # These endpoints expose the REAL evaluation loop (Controller + Defense
    # Adapter + Diagnoser + Memory + Metrics) via backend/adaptive_harness.py.
    # Attacker strategy evaluation is fully separate from live Gmail: no
    # scope is widened, no policy is bypassed, and no transport is reachable
    # from this code path. All endpoints are pairing-gated like every other
    # Stage B route.
    # ------------------------------------------------------------------

    def adaptive_status(self, request: Request) -> JSONResponse:
        """Active strategy, optimization-loop history, run status, defender metrics."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            state = self.adaptive_harness.status()
            return JSONResponse(status_code=200, content={"status": "ok", "adaptive": state})
        except Exception as exc:
            return _error(500, f"adaptive status failed: {exc}")

    def adaptive_run(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Start an authorized evaluation run (rejects duplicate/concurrent runs)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            # Absent (None) means "use the documented default". A present but
            # invalid value (0, negative, non-numeric) is NOT defaulted or
            # clamped away: it falls through to the budget/parse validation
            # below and is rejected with an explicit reason.
            raw_episodes = body.get("episodes")
            raw_max_rounds = body.get("max_rounds")
            raw_iterations = body.get("iterations")
            episodes = (
                _adaptive.DEFAULT_EPISODES
                if raw_episodes is None
                else int(raw_episodes)
            )
            max_rounds = (
                _adaptive.DEFAULT_MAX_ROUNDS
                if raw_max_rounds is None
                else int(raw_max_rounds)
            )
            iterations = (
                _adaptive.DEFAULT_ITERATIONS
                if raw_iterations is None
                else int(raw_iterations)
            )
            seed = body.get("seed")
            seed = int(seed) if seed is not None else None
            # Optional cumulative episode budget for the WHOLE run (distinct
            # from the per-candidate episodes setting). Absent/null keeps the
            # structural worst-case default; an invalid or out-of-range value
            # is rejected, never clamped.
            raw_total = body.get("total_episode_budget")
            total_episode_budget = (
                None if raw_total is None else int(raw_total)
            )
            # Phase 4 search configuration. Defaults preserve the approved
            # baseline exactly: greedy hill climbing + the marker defense.
            mode = str(body.get("mode") or "greedy")
            defense = str(body.get("defense") or "marker")
            selection_budget = int(
                body.get("selection_budget") or _adaptive.DEFAULT_SELECTION_BUDGET
            )
            # Optional assistant provider selection (Phase 6B). Absent/None
            # keeps the harness default; a value is validated by the harness
            # (unknown provider or missing live credentials → explicit 400,
            # never a silent fallback to the fake provider).
            raw_provider = body.get("provider")
            provider = str(raw_provider) if raw_provider is not None else None
            raw_model_budget = body.get("model_request_budget")
            model_request_budget = (
                None if raw_model_budget is None else int(raw_model_budget)
            )
            # BYOA experiment configuration (Parts 2/4): a target id or an
            # inline adapter spec, and/or the three fixed attack categories.
            # Absent keeps the seeded deterministic stand-in (legacy default).
            target = body.get("target")
            attack_categories = body.get("attack_categories")
        except (TypeError, ValueError):
            return _error(400, "invalid run parameters")
        # Budget validation happens HERE — before the harness is touched and
        # before any run state exists. Over-budget or non-positive requests
        # are rejected with an explicit reason and the violated bound;
        # nothing is clamped into a smaller run. These are the
        # adaptive-harness bounds, deliberately separate from the Phase 3 CLI
        # runner's 50-episode per-invocation cap.
        try:
            _adaptive.validate_run_budget(
                episodes=episodes, max_rounds=max_rounds, iterations=iterations,
                total_episode_budget=total_episode_budget,
            )
        except ValueError as exc:
            return _error(400, str(exc))
        # Runs are synchronous by default so the HTTP response reflects the
        # completed evaluation (the CLI and tests rely on this). The side panel
        # opts into a background run with {"background": true} and polls
        # /adaptive/monitor, keeping its request under the 8s client timeout.
        background = bool(body.get("background", False))
        try:
            result = self.adaptive_harness.start(
                episodes=episodes,
                max_rounds=max_rounds,
                iterations=iterations,
                seed=seed,
                background=background,
                mode=mode,
                defense=defense,
                selection_budget=selection_budget,
                total_episode_budget=total_episode_budget,
                provider=provider,
                model_request_budget=model_request_budget,
                target=target,
                attack_categories=attack_categories,
            )
            return JSONResponse(status_code=200, content={"status": "ok", "run": result["run"]})
        except ValueError as exc:
            # Invalid mode/defense/selection_budget (validated inside start()):
            # an explicit client error with the reason, never a clamped or
            # silently reconfigured run.
            return _error(400, str(exc))
        except RuntimeError as exc:
            # Duplicate/concurrent run guard.
            return _error(409, str(exc))
        except Exception as exc:
            return _error(400, f"adaptive run failed: {exc}")

    def adaptive_resume(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Resume an interrupted run from its local versioned checkpoint.

        The checkpoint path is derived from the server-configured store; the
        client cannot supply filesystem paths. A corrupt, incompatible or
        already-finished checkpoint is refused with an explicit reason — never
        a silent fresh run and never a re-run of a completed one.
        """
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        run_id = str(body.get("run_id") or "") or None
        background = bool(body.get("background", False))
        try:
            result = self.adaptive_harness.resume(
                background=background, run_id=run_id
            )
            return JSONResponse(status_code=200, content={"status": "ok", **result})
        except _adaptive.CheckpointError as exc:
            return _error(getattr(exc, "http_status", 400), str(exc))
        except RuntimeError as exc:
            # Duplicate/concurrent run guard.
            return _error(409, str(exc))
        except Exception as exc:
            return _error(400, f"adaptive resume failed: {exc}")

    def adaptive_monitor(self, request: Request) -> JSONResponse:
        """Current (or last) run progress."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            return JSONResponse(
                status_code=200, content={"status": "ok", "monitor": self.adaptive_harness.monitor()}
            )
        except Exception as exc:
            return _error(500, f"adaptive monitor failed: {exc}")

    def adaptive_stop(self, request: Request) -> JSONResponse:
        """Signal the running evaluation to stop after the current episode."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            return JSONResponse(
                status_code=200, content={"status": "ok", "stop": self.adaptive_harness.stop()}
            )
        except Exception as exc:
            return _error(500, f"adaptive stop failed: {exc}")

    def adaptive_promote(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Explicitly promote a candidate (still regression-gated; never bypassed)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        candidate_id = str(body.get("candidate_id") or "")
        if not candidate_id:
            return _error(400, "candidate_id is required")
        try:
            result = self.adaptive_harness.promote(candidate_id)
            return JSONResponse(status_code=200, content={"status": "ok", "result": result})
        except KeyError as exc:
            return _error(404, str(exc))
        except Exception as exc:
            return _error(400, f"promote failed: {exc}")

    def adaptive_defense_eval(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Replay an attack finding against a selected defense (Phase 5)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        candidate_id = str(body.get("candidate_id") or "")
        if not candidate_id:
            return _error(400, "candidate_id is required")
        against = body.get("against") or None
        seed = body.get("seed")
        seed = int(seed) if seed is not None else None
        run_id = body.get("run_id")
        run_id = str(run_id) if run_id else None
        # Part 6.1: the defense phase may only START from a completed attacker
        # run — refused with 409 and the exact reason, never silently started.
        eligibility = self.adaptive_harness.defense_phase_eligibility(
            candidate_id, run_id=run_id
        )
        if not eligibility.get("eligible"):
            reason = str(eligibility.get("reason") or "")
            if reason.startswith("unknown candidate"):
                return _error(404, reason)
            return _error(
                409,
                "run not eligible for defense evaluation: " + reason,
            )
        try:
            entry = self.adaptive_harness.defense_evaluation(
                candidate_id, against=against, seed=seed, run_id=run_id
            )
            return JSONResponse(status_code=200, content={"status": "ok", "evaluation": entry})
        except KeyError as exc:
            return _error(404, str(exc))
        except ValueError as exc:
            return _error(400, str(exc))
        except Exception as exc:
            return _error(500, f"defense evaluation failed: {exc}")

    def feedback_record(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Record a deterministic prediction (evaluation feedback loop step 1)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            email = _DemoEmail(
                id=str(body.get("email_id") or ""),
                sender="synthetic@test.invalid",
                subject=str(body.get("subject") or ""),
                body=str(body.get("body_text") or ""),
                labels=[DEMO_LABEL],
            )
            ruleset = _feedback.active_ruleset(self._feedback_path())
            assessment = _threats.assess_email(email, ruleset)
            pred_id = _feedback.record_prediction(
                email.id, assessment, path=self._feedback_path()
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "prediction_id": pred_id,
                    "assessment": assessment,
                },
            )
        except Exception as exc:
            return _error(400, f"record failed: {exc}")

    def feedback_correct(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Record a reviewer correction (pending; inert until applied)."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            fb_id = _feedback.submit_correction(
                str(body.get("email_id") or ""),
                str(body.get("expected") or ""),
                str(body.get("reviewer") or ""),
                reason=str(body.get("reason") or ""),
                path=self._feedback_path(),
            )
            return JSONResponse(status_code=200, content={"status": "ok", "feedback_id": fb_id})
        except Exception as exc:
            return _error(400, f"correction failed: {exc}")

    # -- outbound workflow (compose / reply / submit / status / audit) ------

    def workflow_status(self, request: Request) -> JSONResponse:
        """Mode, policy summary, rate-limit state, kill switch, live-send arming."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            from gmail_live import live_send_status

            policy = self._workflow.policy
            live = live_send_status()
            transport = getattr(self._workflow.transport, "name", "?")
            executes = bool(
                getattr(self._workflow.transport, "executes_live_actions", False)
            )
            live_eligible = bool(
                live.get("live_send_armed")
                and policy.mode is OperatingMode.AUTHORIZED_AUTOMATION
                and policy.send_authorized
                and _POLICY_GMAIL_SEND_SCOPE in policy.granted_scopes
                and bool(policy.allowed_recipients or policy.allowed_domains)
                and not self._workflow.policy.kill_switch
            )
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "mode": policy.mode.value,
                    "kill_switch": bool(self._workflow.policy.kill_switch),
                    "kill_switch_status": self._workflow.kill_switch_status(),
                    "send_authorized": policy.send_authorized,
                    "draft_authorized": policy.draft_authorized,
                    "allowed_recipients": sorted(policy.allowed_recipients),
                    "allowed_domains": sorted(policy.allowed_domains),
                    "recipient_policy_configured": bool(
                        policy.allowed_recipients or policy.allowed_domains
                    ),
                    "rate_limit_per_hour": policy.rate_limit_per_hour,
                    "rate_limit_remaining": self._workflow.rate_limiter.remaining(),
                    "granted_scopes": sorted(policy.granted_scopes),
                    "transport": transport,
                    "transport_executes_live_actions": executes,
                    "live_send": live,
                    "live_send_eligible": live_eligible,
                    "display_mode": (
                        "LIVE" if executes else "SIMULATION"
                    ),
                },
            )
        except Exception as exc:
            return _error(500, f"workflow status failed: {exc}")

    def compose_prepare(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Compose + validate + scan a NEW message. Nothing is sent or saved."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            settings = (
                GenerationSettings.from_dict(body["settings"])
                if body.get("settings")
                else _quality.active_settings(self._quality_path())
            )
            report = self._workflow.prepare_new(
                [str(a) for a in (body.get("to") or [])],
                str(body.get("subject") or ""),
                str(body.get("body_text") or body.get("body") or ""),
                settings=settings,
                confirmed=bool(body.get("confirm")),
                cc=[str(a) for a in (body.get("cc") or [])],
                bcc=[str(a) for a in (body.get("bcc") or [])],
            )
            return JSONResponse(status_code=200, content={"status": "ok", "report": report.to_dict()})
        except Exception as exc:
            return _error(400, f"compose failed: {exc}")

    def compose_reply_prepare(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Compose + validate + scan a REPLY to posted thread content."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            incoming = _DemoEmail(
                id=str(body.get("email_id") or "posted-open-email"),
                sender=str(body.get("sender") or ""),
                subject=str(body.get("subject") or ""),
                body=str(body.get("body_text") or body.get("body") or ""),
                labels=[DEMO_LABEL],
            )
            settings = (
                GenerationSettings.from_dict(body["settings"])
                if body.get("settings")
                else _quality.active_settings(self._quality_path())
            )
            report = self._workflow.prepare_reply(
                incoming,
                settings=settings,
                thread_id=str(body.get("thread_id") or "") or None,
                confirmed=bool(body.get("confirm")),
            )
            return JSONResponse(status_code=200, content={"status": "ok", "report": report.to_dict()})
        except Exception as exc:
            return _error(400, f"reply compose failed: {exc}")

    def compose_submit(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Submit a prepared message for 'send' or 'draft' — policy-enforced.

        With the shipped defaults the mode is 'simulation': the transport is
        never called and nothing leaves the process. Purpose lives in the body
        (the extension path is /compose/submit).
        """
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            raw_message = body.get("message")
            message = (
                message_from_summary(raw_message)
                if isinstance(raw_message, dict) and raw_message
                else None
            )
            prepared_id = str(
                body.get("prepared_id")
                or (raw_message or {}).get("message_id")
                or ""
            ).strip() or None
            purpose = str(body.get("purpose") or "send")
            report = self._workflow.submit(
                message,
                purpose=purpose,
                confirm=bool(body.get("confirm")),
                prepared_id=prepared_id,
            )
            return JSONResponse(status_code=200, content={"status": "ok", "report": report.to_dict()})
        except Exception as exc:
            return _error(400, f"submit failed: {exc}")

    def engage_kill_switch(self, request: Request) -> JSONResponse:
        """Owner kill switch: hard-stops every outbound transport action."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            out = self._workflow.engage_kill_switch(
                actor="paired-extension", reason="operator stop request"
            )
            return JSONResponse(
                status_code=200,
                content={"status": "ok", **out},
            )
        except Exception as exc:
            return JSONResponse(
                status_code=500,
                content={
                    "status": "error",
                    "kill_switch": True,
                    "durable": False,
                    "error": f"kill switch engaged in memory but persistence failed: {exc}",
                },
            )

    def release_kill_switch(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Explicit release; never arms or authorizes live sending."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        if body.get("confirm") is not True:
            return _error(400, "release requires explicit confirm=true")
        try:
            out = self._workflow.release_kill_switch(
                confirm=True,
                actor="paired-extension",
                reason=str(body.get("reason") or "operator release request")[:300],
            )
            return JSONResponse(status_code=200, content={"status": "ok", **out})
        except Exception as exc:
            return _error(500, f"kill switch release failed: {exc}")

    def audit_recent(self, request: Request, body: dict[str, Any]) -> JSONResponse:
        """Recent audit events: workflow (append-only, redacted) + store tails."""
        auth_error = self._require_auth(request)
        if auth_error:
            return auth_error
        try:
            limit = max(1, min(200, int(body.get("limit") or 25)))
            fb_path = self._feedback_path()
            fb_data = _feedback._load(fb_path) if fb_path and Path(fb_path).exists() else None
            q_path = self._quality_path()
            q_data = _quality._load(q_path) if q_path and Path(q_path).exists() else None
            return JSONResponse(
                status_code=200,
                content={
                    "status": "ok",
                    "workflow": self._workflow.audit.tail(limit),
                    "feedback_audit": (fb_data or {}).get("audit", [])[-limit:],
                    "quality_audit": (q_data or {}).get("audit", [])[-limit:],
                },
            )
        except Exception as exc:
            return _error(500, f"audit failed: {exc}")

    def fetch_attachment(self, request: Request, filename: str) -> JSONResponse:
        # Defensive filename validation runs first, before any state or auth, so
        # malformed traversal/absolute inputs are rejected outright.
        if not filename or not filename.strip():
            return _error(400, "Missing attachment filename")

        if ".." in filename or filename.startswith("/") or filename.startswith("\\"):
            return _error(400, "Invalid attachment filename")

        if not filename.endswith(".bin"):
            return _error(400, "Only .bin attachments are served by this backend")

        normalized = filename.strip().replace("\\", "/").lstrip("/")

        # Attachment access is gated by pairing + origin + bearer, exactly like
        # the read endpoints. Network exposure is prevented by the loopback bind.
        try:
            self._auth_headers(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})

        payload = self._mock_attachment_metadata(self._pairing_nonce, normalized)
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "filename": normalized,
                "mime": "application/octet-stream",
                "size_bytes": payload["size_bytes"],
                "sha256": payload["sha256"],
                "attachment_id": payload["attachment_id"],
                "read_only": True,
                "fetched_at": _now_iso(),
            },
        )

    @staticmethod
    def _sanitize_attachment(raw: Any) -> dict[str, Any] | list[Any] | None:
        if not isinstance(raw, dict):
            return None
        if "id" not in raw and "attachmentId" not in raw:
            return None
        safe: dict[str, Any] = {}
        for key in ("id", "attachmentId", "size", "mimeType", "filename", "title"):
            value = raw.get(key)
            if value is None:
                continue
            safe[key if key != "attachmentId" else "id"] = value
        return safe if safe else None

    @staticmethod
    def _mock_attachment_metadata(pairing_nonce: str, filename: str) -> dict[str, Any]:
        seed = f"{pairing_nonce}::{filename}".encode()
        digest = hashlib.sha256(seed).digest()
        attachment_id = f"att_{hashlib.sha256(digest).hexdigest()[:16]}"
        body = hashlib.sha256(digest + b"attachment-body").digest()
        return {
            "attachment_id": attachment_id,
            "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body),
        }


def _parse_max_results(body: Any) -> int | JSONResponse:
    if not isinstance(body, dict):
        return _MAX_RESULTS_DEFAULT
    raw = body.get("max_results", _MAX_RESULTS_DEFAULT)
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return _error(400, "max_results must be an integer")
    if value < 1:
        return _error(400, "max_results must be >= 1")
    value = min(value, _MAX_RESULTS_LIMIT)
    return value


def _parse_provider(body: Any) -> str | JSONResponse:
    """Allowlisted analysis provider; absent body keeps the legacy default."""
    if not isinstance(body, dict) or body.get("provider") is None:
        return "gemini"
    provider = str(body.get("provider")).strip().lower()
    if provider not in _ANALYZE_PROVIDERS:
        return _error(
            400,
            "provider must be one of: " + ", ".join(sorted(_ANALYZE_PROVIDERS)),
        )
    return provider


def create_app(
    *,
    credentials_path: Path | str,
    token_path: Path | str,
    pairing_nonce: str,
    workflow_service: EmailWorkflowService | None = None,
    feedback_store: Path | str | None = None,
    quality_store: Path | str | None = None,
    adaptive_store: Path | str | None = None,
) -> FastAPI:
    backend = StageBBackend(
        credentials_path=credentials_path,
        token_path=token_path,
        pairing_nonce=pairing_nonce,
        workflow_service=workflow_service,
        feedback_store=feedback_store,
        quality_store=quality_store,
        adaptive_store=adaptive_store,
    )

    app = FastAPI(title="Stage B read-only backend")

    @app.get("/health")
    async def health() -> JSONResponse:
        integrations = [
            report.to_dict()
            for report in _integrations.collect_integrations(
                token_path=token_path,
                paired_origin=backend.paired_origin,
            )
        ]
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "bind": f"127.0.0.1:{_BACKEND_PORT}",
                "origin": APP_ORIGIN,
                "state": backend.state,
                "integrations": integrations,
                "timestamp": _now_iso(),
            },
        )

    stage_b = FastAPI(
        title="Stage B read-only backend", docs_url=None, openapi_url=None
    )

    async def _read_body(request: Request) -> dict[str, Any]:
        try:
            body = await request.json()
        except Exception:
            return {}
        return body if isinstance(body, dict) else {}

    @stage_b.get("/experiment-manifest")
    async def stage_b_experiment_manifest() -> JSONResponse:
        """Validate the approved experiment manifest (plan only).

        Configuration validation ONLY: this endpoint never executes an
        experiment: the summary always carries execution="not_started"
        and episodes_executed=0, and `valid`/`errors` describe the plan.
        """
        manifest = _build_experiment_manifest()
        summary = _experiment_manifest_summary(manifest)
        return JSONResponse(status_code=200, content={"summary": summary, "manifest": manifest})

    @stage_b.get("/experiment-dry-run")
    async def stage_b_experiment_dry_run(
        configs: str | None = None, episodes: int = 50
    ) -> JSONResponse:
        """Plan a bounded selection — non-executing by construction.

        Planning ONLY: this endpoint never executes an episode and never
        touches the runs directory; the summary always carries
        execution="none" and episodes_executed=0. `configs` is a
        comma-separated list of configuration IDs (default: all 26 —
        planning the whole matrix executes nothing); `episodes` is the
        planned episodes per configuration (1-50). Execution itself is
        CLI-only in Phase 3 (ADR-017): no API route can launch a run.
        """
        from adaptive_agent_eval.runner.plan import (
            SelectionError,
            dry_run_summary,
            resolve_selection,
        )

        manifest = _build_experiment_manifest()
        if configs:
            config_ids = [c.strip() for c in configs.split(",") if c.strip()]
        else:
            config_ids = [e["config_id"] for e in manifest["configurations"]]
        try:
            plan = resolve_selection(
                manifest, config_ids, episodes, enforce_bounded=False
            )
        except SelectionError as exc:
            return JSONResponse(
                status_code=400,
                content={"error": str(exc), "episodes_executed": 0},
            )
        return JSONResponse(
            status_code=200, content={"summary": dry_run_summary(plan, manifest)}
        )

    @stage_b.post("/pair")
    async def stage_b_pair(request: Request) -> JSONResponse:
        body = await _read_body(request)
        return backend.offer_pairing(
            request,
            presented_nonce=body.get("presented_nonce"),
            extension_origin=body.get("extension_origin"),
        )

    @stage_b.post("/ping")
    async def stage_b_ping(request: Request) -> JSONResponse:
        return backend.ping(request)

    @stage_b.post("/feed")
    async def stage_b_feed(request: Request) -> JSONResponse:
        body = await _read_body(request)
        max_results = _parse_max_results(body)
        if isinstance(max_results, JSONResponse):
            return max_results
        return backend.fetch_demo_emails(request, max_results)

    @stage_b.post("/analyze")
    async def stage_b_analyze(request: Request) -> JSONResponse:
        body = await _read_body(request)
        max_results = _parse_max_results(body)
        if isinstance(max_results, JSONResponse):
            return max_results
        provider = _parse_provider(body)
        if isinstance(provider, JSONResponse):
            return provider
        return backend.analyze_demo_emails(request, max_results, provider=provider)

    # Integrated defense endpoints (deterministic, local-only, pairing-gated).

    @stage_b.post("/defense/status")
    async def stage_b_defense_status(request: Request) -> JSONResponse:
        return backend.defense_status(request)

    @stage_b.post("/defense/assess")
    async def stage_b_defense_assess(request: Request) -> JSONResponse:
        return backend.assess_text(request, await _read_body(request))

    @stage_b.post("/metrics")
    async def stage_b_metrics(request: Request) -> JSONResponse:
        return backend.metrics_report(request)

    @stage_b.post("/hillclimb/status")
    async def stage_b_hillclimb_status(request: Request) -> JSONResponse:
        return backend.hillclimb_status(request)

    @stage_b.post("/hillclimb/run")
    async def stage_b_hillclimb_run(request: Request) -> JSONResponse:
        return backend.hillclimb_run(request, await _read_body(request))

    @stage_b.post("/hillclimb/propose")
    async def stage_b_hillclimb_propose(request: Request) -> JSONResponse:
        return backend.hillclimb_propose(request, await _read_body(request))

    @stage_b.post("/hillclimb/apply")
    async def stage_b_hillclimb_apply(request: Request) -> JSONResponse:
        return backend.hillclimb_apply(request, await _read_body(request))

    @stage_b.post("/hillclimb/revert")
    async def stage_b_hillclimb_revert(request: Request) -> JSONResponse:
        return backend.hillclimb_revert(request, await _read_body(request))

    # Adaptive Strategy Engine (real adaptive_agent_eval harness, pairing-gated).

    @stage_b.post("/adaptive/status")
    async def stage_b_adaptive_status(request: Request) -> JSONResponse:
        return backend.adaptive_status(request)

    @stage_b.post("/adaptive/run")
    async def stage_b_adaptive_run(request: Request) -> JSONResponse:
        return backend.adaptive_run(request, await _read_body(request))

    @stage_b.post("/adaptive/monitor")
    async def stage_b_adaptive_monitor(request: Request) -> JSONResponse:
        return backend.adaptive_monitor(request)

    @stage_b.post("/adaptive/stop")
    async def stage_b_adaptive_stop(request: Request) -> JSONResponse:
        return backend.adaptive_stop(request)

    @stage_b.post("/adaptive/resume")
    async def stage_b_adaptive_resume(request: Request) -> JSONResponse:
        return backend.adaptive_resume(request, await _read_body(request))

    @stage_b.post("/adaptive/promote")
    async def stage_b_adaptive_promote(request: Request) -> JSONResponse:
        return backend.adaptive_promote(request, await _read_body(request))

    @stage_b.post("/adaptive/defense_eval")
    async def stage_b_adaptive_defense_eval(request: Request) -> JSONResponse:
        return backend.adaptive_defense_eval(request, await _read_body(request))

    @stage_b.post("/feedback/record")
    async def stage_b_feedback_record(request: Request) -> JSONResponse:
        return backend.feedback_record(request, await _read_body(request))

    @stage_b.post("/feedback/correct")
    async def stage_b_feedback_correct(request: Request) -> JSONResponse:
        return backend.feedback_correct(request, await _read_body(request))

    # Outbound workflow (compose / reply / submit / status / kill switch / audit).

    @stage_b.post("/workflow/status")
    async def stage_b_workflow_status(request: Request) -> JSONResponse:
        return backend.workflow_status(request)

    @stage_b.post("/workflow/prepare")
    async def stage_b_workflow_prepare(request: Request) -> JSONResponse:
        return backend.compose_prepare(request, await _read_body(request))

    @stage_b.post("/workflow/reply")
    async def stage_b_workflow_reply(request: Request) -> JSONResponse:
        return backend.compose_reply_prepare(request, await _read_body(request))

    @stage_b.post("/workflow/submit")
    async def stage_b_workflow_submit(request: Request) -> JSONResponse:
        return backend.compose_submit(request, await _read_body(request))

    @stage_b.post("/workflow/killswitch")
    async def stage_b_workflow_killswitch(request: Request) -> JSONResponse:
        return backend.engage_kill_switch(request)

    @stage_b.post("/workflow/killswitch/release")
    async def stage_b_workflow_killswitch_release(request: Request) -> JSONResponse:
        return backend.release_kill_switch(request, await _read_body(request))

    @stage_b.post("/audit/recent")
    async def stage_b_audit_recent(request: Request) -> JSONResponse:
        return backend.audit_recent(request, await _read_body(request))

    # Two routes so slash-containing filenames still reach the defensive
    # validation in ``fetch_attachment`` (and are rejected with 400) instead of
    # falling through to a 404. The exact ``{filename}``` route is registered
    # first for ordinary names.
    @stage_b.post("/attachments/{filename}")
    async def stage_b_attachments(request: Request, filename: str) -> JSONResponse:
        return backend.fetch_attachment(request, filename)

    @stage_b.post("/attachments/{filename:path}")
    async def stage_b_attachments_path(request: Request, filename: str) -> JSONResponse:
        return backend.fetch_attachment(request, filename)

    # Nemesis autonomous email workflow endpoints.
    # These route to the supplied backend instance so they reuse the same
    # pairing/auth gates, workflow service, and audit log.
    @stage_b.post("/nemesis/workflow/status")
    async def stage_b_nemesis_workflow_status(request: Request) -> JSONResponse:
        return nemesis_workflow_status(request, backend)

    @stage_b.post("/nemesis/prepare/new")
    async def stage_b_nemesis_prepare_new(request: Request) -> JSONResponse:
        return await nemesis_prepare_new(request, backend)

    @stage_b.post("/nemesis/prepare/reply")
    async def stage_b_nemesis_prepare_reply(request: Request) -> JSONResponse:
        return await nemesis_prepare_reply(request, backend)

    @stage_b.post("/nemesis/prepare/forward")
    async def stage_b_nemesis_prepare_forward(request: Request) -> JSONResponse:
        return await nemesis_prepare_forward(request, backend)

    @stage_b.post("/nemesis/submit")
    async def stage_b_nemesis_submit(request: Request) -> JSONResponse:
        return await nemesis_submit(request, backend)

    @stage_b.post("/nemesis/killswitch")
    async def stage_b_nemesis_killswitch(request: Request) -> JSONResponse:
        return await nemesis_killswitch(request, backend)

    @stage_b.post("/nemesis/killswitch/release")
    async def stage_b_nemesis_killswitch_release(request: Request) -> JSONResponse:
        return backend.release_kill_switch(request, await _read_body(request))

    @stage_b.post("/nemesis/activity")
    async def stage_b_nemesis_activity(request: Request) -> JSONResponse:
        return await nemesis_activity(request, backend)

    # The single autonomous demo run behind the side panel's primary action.
    # /run starts it (single-flight), /status polls real stage progress, and
    # /stop signals the running harness. Same pairing/auth gates as above.
    @stage_b.post("/nemesis/demo/run")
    async def stage_b_nemesis_demo_run(request: Request) -> JSONResponse:
        return await nemesis_demo_run(request, backend)

    @stage_b.post("/nemesis/demo/status")
    async def stage_b_nemesis_demo_status(request: Request) -> JSONResponse:
        return await nemesis_demo_status(request, backend)

    @stage_b.post("/nemesis/demo/stop")
    async def stage_b_nemesis_demo_stop(request: Request) -> JSONResponse:
        return await nemesis_demo_stop(request, backend)

    @stage_b.post("/reset")
    async def stage_b_reset(request: Request) -> JSONResponse:
        return backend.reset(request=request)

    app.mount(_MOUNT_PREFIX, app=stage_b)
    app.extra["_stage_b"] = backend

    return app


def create_app_with_defaults() -> FastAPI:
    return create_app(
        credentials_path=Path(__file__).resolve().parent.parent
        / "credentials.json",
        token_path=Path(__file__).resolve().parent.parent / "token.json",
        pairing_nonce=secrets.token_hex(32),
    )


def _info_text() -> str:
    lines: list[str] = []
    lines.append("stage_b")
    lines.append("backend")
    lines.append(f"port={_BACKEND_PORT}")
    lines.append(f"bind=127.0.0.1:{_BACKEND_PORT}")
    lines.append(f"origin={APP_ORIGIN}")
    lines.append("auth=extension + pairing nonce")
    lines.append("origin wildcard=false")
    lines.append("read_only=true")
    lines.append("gmail_scopes=readonly only")
    lines.append("mount_path=/api/v1/stage_b")
    lines.append(
        "endpoints=pair ping feed analyze attachments/ reset health "
        "defense/status defense/assess metrics hillclimb/status hillclimb/run "
        "hillclimb/propose hillclimb/apply hillclimb/revert feedback/record "
        "feedback/correct adaptive/status adaptive/run adaptive/monitor "
        "adaptive/stop adaptive/resume adaptive/promote workflow/status workflow/prepare "
        "workflow/reply workflow/submit workflow/killswitch audit/recent"
    )
    lines.append("workflow_mode=owner-configured (default simulation; mock transport)")
    lines.append(
        "granted_scopes=readonly (default); owner may declare "
        "NEMESIS_GRANTED_SCOPES=send,compose — never auto-granted"
    )
    lines.append(
        "live_send=disabled unless armed in gmail_live (consent phrase + "
        "separate write OAuth client + scope-validated write token) AND "
        "policy moved past simulation"
    )
    return "\n".join(lines)


def _serve(host: str = "127.0.0.1", port: int = _BACKEND_PORT) -> int:
    """Start the read-only backend on loopback and print the pairing nonce once.

    The nonce is written to the operator's terminal only — it is never served
    over HTTP, never placed in a frontend bundle, and never logged to a file.
    The extension's pairing screen asks the operator to paste it.

    Non-loopback hosts are refused: this stage is local-only by contract.
    """
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(
            f"Refusing to bind non-loopback host {host!r}; Stage B is local-only.",
            file=sys.stderr,
        )
        return 2

    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required to serve: pip install uvicorn", file=sys.stderr)
        return 2

    nonce = secrets.token_hex(32)
    app = create_app(
        credentials_path=Path(__file__).resolve().parent.parent / "credentials.json",
        token_path=Path(__file__).resolve().parent.parent / "token.json",
        pairing_nonce=nonce,
    )

    print(f"stage_b read-only backend on http://{host}:{port}", flush=True)
    print("Pairing nonce (operator only — paste into the extension pairing screen):", flush=True)
    print(nonce, flush=True)

    uvicorn.run(app, host=host, port=port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="backend.stage_b")
    parser.add_argument(
        "command",
        nargs="?",
        default="info",
        help="Command to run: 'info' (default) or 'serve'.",
    )
    args = parser.parse_args(argv)

    if args.command == "info":
        print(_info_text())
        return 0

    if args.command == "serve":
        return _serve()

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
