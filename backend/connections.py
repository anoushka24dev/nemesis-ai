"""Target-connection management for the Nemesis research dashboard.

Two connection methods are exposed by the dashboard:

``http_api``
    A user agent reachable at an absolute ``http(s)://`` endpoint using the
    repository's ``ExternalHttpTargetAdapter`` request/response contract.

``agent_framework``
    A REAL LangChain/LangGraph integration backed by
    ``adaptive_agent_eval.target.langchain_agent.LangChainAgentAdapter``. The
    agent is a genuine ReAct agent built with ``langchain.agents.create_agent``
    (falling back to ``langgraph.prebuilt.create_react_agent`` only on older
    installs) over a ``ChatOllama`` model (default ``llama3.1:8b``); readiness
    is only claimed
    after a bounded REAL invocation that reaches the model and returns a
    parsed response. A metadata/import check alone never marks it connected.

``local_python`` was retired from the supported product: the BYOA adapter no
longer appears in the UI, is not enumerated by :func:`CONNECTION_METHODS` and
cannot be connected or selected through this store. A legacy client that still
sends it receives an explicit ``retired`` error instead of a silent fallback.

Honesty rules enforced here:

* A saved connection is never proof of readiness — readiness comes from the
  last recorded validation result, which is produced by an actual probe
  (import + connectivity check for BYOA, one bounded HTTP request for an
  endpoint).
* Nothing falls back to a fixture, fake target or simulated agent. A failed
  probe is stored as a failure with its reason.
* The HTTP ``auth_header`` value is kept **in memory for this process only**;
  it is never written to the connection store, never returned by the API and
  never logged.
* Only local files under ``results/`` are used; no arbitrary path is accepted
  from a client.
"""

from __future__ import annotations

import json
import os
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

__all__ = [
    "CONNECTION_METHODS",
    "METHOD_AGENT_FRAMEWORK",
    "METHOD_GMAIL",
    "METHOD_HTTP_API",
    "RETIRED_METHODS",
    "ConnectionStore",
    "get_store",
    "probe_http_endpoint",
    "probe_langchain_agent",
]

METHOD_HTTP_API = "http_api"
METHOD_AGENT_FRAMEWORK = "agent_framework"
METHOD_GMAIL = "gmail"

#: Retired product integrations. Kept only so a legacy caller can be rejected
#: with a precise, actionable error instead of being silently ignored.
RETIRED_METHODS: dict[str, str] = {
    "local_python": (
        "the Local Python Agent connection method is retired and is not part "
        "of this product; expose the agent behind a JSON HTTP endpoint and "
        "use the HTTP API method"
    ),
}

#: The two methods the dashboard shows. ``status`` is what the CODE actually
#: supports today — the UI renders it verbatim.
CONNECTION_METHODS: list[dict[str, Any]] = [
    {
        "method": METHOD_HTTP_API,
        "display_name": "HTTP API",
        "subtitle": "REST endpoint",
        "status": "available",
        "status_label": "Supported",
        "description": (
            "Connect to an agent running as a local or remote HTTP service."
        ),
        "requires": ["an absolute http(s) endpoint", "JSON responses"],
        "limitations": [
            (
                "the endpoint must accept the documented JSON request body and "
                "return 'output' (and optionally 'tool_calls')"
            ),
            "authentication headers are held in memory for this process only",
            "a non-2xx response is a technical failure, never a blocked attack",
        ],
        "fields": [
            {"name": "endpoint_url", "label": "Endpoint URL", "placeholder": "http://localhost:8000/run"},
            {"name": "auth_header", "label": "Authorization header (optional, not stored)", "placeholder": "Bearer …"},
            {"name": "target_id", "label": "Target id (optional)", "placeholder": "my-http-agent"},
            {"name": "timeout_seconds", "label": "Timeout (seconds)", "placeholder": "15"},
        ],
    },
    {
        "method": METHOD_GMAIL,
        "display_name": "Gmail Agent",
        "subtitle": "Read-only inbox",
        "status": "available",
        "status_label": "Supported",
        "description": (
            "Drive the repository's real Gmail agent: read-only inbox analysis, "
            "or the draft/send workflow through the separate write token. The "
            "selected mode is what the campaign executes."
        ),
        "requires": [
            "a valid gmail.readonly OAuth token (reads and readback)",
            "for draft/send: a valid gmail.compose (+ gmail.send) write token",
            "for draft/send: an allowlisted recipient",
            "local Ollama with llama3.1:8b for generated content",
        ],
        "limitations": [
            (
                "send mode refuses to start unless the write token is valid and "
                "the live send transport is armed; it never downgrades to draft"
            ),
            (
                "an attack payload can never choose the recipient: the configured "
                "allowlisted address is the only authorized destination"
            ),
            "a model, OAuth or Gmail API failure is a technical failure, never a blocked attack",
        ],
        "fields": [
            {
                "name": "mode",
                "label": "Execution mode",
                "type": "select",
                "default": "read_only",
                "options": [
                    {
                        "value": "read_only",
                        "label": "Read-only",
                    },
                    {
                        "value": "draft",
                        "label": "Draft",
                    },
                    {
                        "value": "send",
                        "label": "Send",
                    },
                ],
            },
            {
                "name": "recipient",
                "label": "Allowlisted recipient",
                "placeholder": "you@example.com",
            },
            {"name": "max_results", "label": "Messages per turn", "placeholder": "5"},
            {"name": "target_id", "label": "Target id (optional)", "placeholder": "gmail-agent"},
            {
                "name": "url",
                "label": "Gmail agent URL (optional)",
                "placeholder": "https://gmail.google.com or custom endpoint",
            },
        ],
    },
    {
        "method": METHOD_AGENT_FRAMEWORK,
        "display_name": "Agent Framework (LangChain)",
        "subtitle": "LangGraph ReAct agent",
        "status": "available",
        "status_label": "Supported",
        "description": (
            "Connect a real LangChain agent (langchain.agents.create_agent) on "
            "a local Ollama model. The model is actually invoked at run time."
        ),
        "requires": [
            "a reachable Ollama endpoint",
            "an installed model (default llama3.1:8b)",
            "langchain / langgraph / langchain-ollama installed",
        ],
        "limitations": [
            (
                "the agent's tools are Nemesis-provided stubs; whether the model "
                "calls a tool is decided by the real model, never faked"
            ),
            (
                "only this LangGraph ReAct construction is claimed supported; "
                "arbitrary user LangChain agents are not auto-imported"
            ),
            "a model/transport error is a technical failure, never a blocked attack",
        ],
        "fields": [
            {"name": "model", "label": "Ollama model", "placeholder": "llama3.1:8b"},
            {"name": "base_url", "label": "Ollama endpoint", "placeholder": "http://127.0.0.1:11434"},
            {"name": "target_id", "label": "Target id (optional)", "placeholder": "langchain-agent"},
            {"name": "timeout_seconds", "label": "Timeout (seconds)", "placeholder": "30"},
        ],
    },
]

_METHOD_IDS = {m["method"] for m in CONNECTION_METHODS}

#: In-memory only: never persisted, never returned, never logged.
_SESSION_SECRETS: dict[str, str] = {}
_SECRET_LOCK = threading.Lock()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _method_meta(method: str) -> dict[str, Any]:
    for entry in CONNECTION_METHODS:
        if entry["method"] == method:
            return entry
    raise ValueError(f"unknown connection method {method!r}")


def _clean(value: Any, *, limit: int = 400) -> str:
    text = str(value if value is not None else "").strip()
    return text[:limit]


def probe_http_endpoint(
    endpoint_url: str,
    *,
    auth_header: str | None = None,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    """Make ONE bounded request to the configured endpoint.

    This is the only way the dashboard claims an HTTP connection is reachable.
    A syntactically valid URL is never treated as a healthy connection. The
    probe body is the documented request shape with a benign input; the result
    records the HTTP status and whether the response parsed as JSON — never
    the response body or the auth header.
    """
    if not endpoint_url or not str(endpoint_url).startswith(("http://", "https://")):
        return {
            "ok": False,
            "error": "endpoint_url must be an absolute http:// or https:// URL",
            "error_category": "config",
        }
    body = json.dumps(
        {
            "probe": True,
            "session_id": "nemesis-connectivity-probe",
            "correlation_id": uuid.uuid4().hex,
            "input": "Connection probe from Nemesis. Reply with a short JSON object.",
            "available_tools": [],
            "history": [],
        }
    ).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Nemesis-Evaluator/1.0",
    }
    if auth_header:
        headers["Authorization"] = auth_header
    req = urllib.request.Request(
        str(endpoint_url), data=body, headers=headers, method="POST"
    )
    started = time.time()
    try:
        with urllib.request.urlopen(req, timeout=max(1.0, float(timeout_seconds))) as resp:
            raw = resp.read()
            elapsed = round(time.time() - started, 3)
            parsed: Any = None
            parse_error = None
            try:
                parsed = json.loads(raw.decode("utf-8", errors="replace"))
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                parse_error = f"response was not JSON ({type(exc).__name__})"
            return {
                "ok": parsed is not None,
                "status_code": resp.status,
                "elapsed_seconds": elapsed,
                "json": parsed is not None,
                "error": parse_error,
                "error_category": None if parsed is not None else "invalid_response",
                "endpoint": str(endpoint_url),
            }
    except urllib.error.HTTPError as exc:
        return {
            "ok": False,
            "status_code": exc.code,
            "error": f"HTTP {exc.code}: {exc.reason}",
            "error_category": "http_error",
            "endpoint": str(endpoint_url),
        }
    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "error": f"connection error: {exc.reason}",
            "error_category": "unreachable",
            "endpoint": str(endpoint_url),
        }
    except Exception as exc:  # noqa: BLE001 - reported, never swallowed silently
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "error_category": "transport",
            "endpoint": str(endpoint_url),
        }


#: Gmail agent evaluation modes. ``read_only`` can never write; ``draft`` and
#: ``send`` drive the repository's real ``backend.gmail_agent`` workflow.
GMAIL_MODES: tuple[str, ...] = ("read_only", "draft", "send")

#: Operator-facing adapter names. A mode is never presented as plain
#: "Gmail Agent", and none of them implies a capability the token lacks.
GMAIL_ADAPTER_LABELS: dict[str, str] = {
    "read_only": "Gmail Read-only Inbox",
    "draft": "Gmail Agent — Draft mode",
    "send": "Gmail Agent — Send mode",
}


def gmail_adapter_label(mode: str | None) -> str:
    """The adapter name shown for a Gmail evaluation mode."""
    return GMAIL_ADAPTER_LABELS.get(str(mode or "read_only"), "Gmail Read-only Inbox")


def probe_gmail_readonly() -> dict[str, Any]:
    """Validate the real read-only Gmail connection without writing anything."""
    try:
        from gmail_auth import (
            GMAIL_READONLY_SCOPE,
            build_gmail_service,
            fetch_nemesis_demo_emails,
            get_credentials,
        )

        creds = get_credentials(open_browser=False, timeout_seconds=1)
        scopes = set(getattr(creds, "scopes", None) or [])
        if scopes != {GMAIL_READONLY_SCOPE}:
            return {
                "ok": False,
                "error": f"Gmail token scopes are {sorted(scopes)}, expected only {GMAIL_READONLY_SCOPE}",
                "error_category": "scope",
            }
        emails = fetch_nemesis_demo_emails(
            build_gmail_service(creds), max_results=1
        )
        return {
            "ok": True,
            "scope": GMAIL_READONLY_SCOPE,
            "email_count": len(emails),
            "label": "NEMESIS_DEMO",
            "checks": {"oauth": True, "read_only_scope": True, "gmail_read": True},
        }
    except Exception as exc:  # noqa: BLE001 - real failure is reported honestly
        return {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "error_category": "gmail",
        }


def probe_gmail_agent(mode: str = "read_only", recipient: str = "") -> dict[str, Any]:
    """Verify the REAL capability of the selected Gmail agent mode.

    ``read_only`` only needs the read token. ``draft``/``send`` additionally
    need the separate write token with the right scopes, and the configured
    recipient must be inside the outbound allowlist. Anything missing is
    reported as ``ok: False`` with the actual reason — a mode is never
    silently downgraded to read-only.
    """
    mode = str(mode or "read_only").strip().lower()
    if mode not in GMAIL_MODES:
        return {
            "ok": False,
            "error": f"unknown Gmail mode {mode!r}; expected one of {list(GMAIL_MODES)}",
            "error_category": "config",
        }
    read_probe = probe_gmail_readonly()
    checks: dict[str, Any] = {
        "oauth": bool(read_probe.get("ok")),
        "read_only_scope": bool(read_probe.get("ok")),
        "gmail_read": bool(read_probe.get("ok")),
        "write_token": None,
        "write_scopes": None,
        "recipient_allowlisted": None,
        "live_send_armed": None,
    }
    result: dict[str, Any] = {
        "ok": bool(read_probe.get("ok")),
        "mode": mode,
        "scope": read_probe.get("scope"),
        "email_count": read_probe.get("email_count"),
        "label": read_probe.get("label"),
        "checks": checks,
        "error": read_probe.get("error"),
        "error_category": read_probe.get("error_category"),
    }
    if mode == "read_only":
        return result

    # -- draft / send: the write token is required, never substituted --------
    try:
        from gmail_live import inspect_write_token, live_send_status

        token = inspect_write_token(verify_refresh=True)
        checks["write_token"] = bool(token.get("scope_valid"))
        checks["write_scopes"] = list(token.get("scopes") or [])
        # Prove the credential with a real refresh: a revoked or unusable
        # write token must fail the connect probe, not merely look unexpired.
        armed = live_send_status(verify_refresh=True)
        checks["live_send_armed"] = bool(armed.get("live_send_armed"))
        # The allowlist is the outbound policy's, not the token's: read it from
        # the same resolver the send workflow enforces.
        from backend.gmail_agent import _allowed_recipients

        allow_set, domain_set = _allowed_recipients()
        allowed = {str(a).lower() for a in allow_set}
        domains = {str(d).lower().lstrip("@") for d in domain_set}
        address = str(recipient or "").strip().lower()
        checks["recipient_allowlisted"] = bool(
            address
            and (address in allowed or ("@" in address and address.split("@", 1)[1] in domains))
        )
        checks["allowed_recipients"] = sorted(allowed)
        checks["kill_switch_engaged"] = bool(armed.get("kill_switch_engaged"))
        checks["write_token_expired"] = token.get("expired")
    except Exception as exc:  # noqa: BLE001 - a real failure is reported
        return {
            **result,
            "ok": False,
            "error": f"write authorization check failed: {type(exc).__name__}: {exc}",
            "error_category": "credentials",
        }

    if not checks["write_token"]:
        return {
            **result,
            "ok": False,
            "error": (
                "the write token is missing or its scopes are not "
                "gmail.compose/gmail.send; re-run `python -m gmail_live auth` "
                "(read-only credentials never authorize writes)"
            ),
            "error_category": "credentials",
        }
    if not checks["recipient_allowlisted"]:
        return {
            **result,
            "ok": False,
            "error": (
                f"recipient {recipient!r} is not in the outbound allowlist "
                f"({sorted(checks.get('allowed_recipients') or [])}); draft/send "
                "mode requires an explicitly allowlisted address"
            ),
            "error_category": "allowlist",
        }
    if not checks["live_send_armed"]:
        # Drafts are a real mailbox write too, and both modes need a usable
        # write token. Claiming a mode whose token cannot be refreshed would
        # produce a run that fails at every write, so it is refused here.
        return {
            **result,
            "ok": False,
            "error": (
                f"{mode} mode requires a usable write token; the stored token "
                "could not be proven (expired or revoked). Re-run "
                "`python -m gmail_live auth` in a browser, then reconnect. The "
                "run will NOT downgrade to read-only."
            ),
            "error_category": "credentials",
        }
    result["ok"] = bool(result["ok"])
    return result


def probe_langchain_agent(
    model: str = "llama3.1:8b",
    *,
    base_url: str = "http://127.0.0.1:11434",
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Bounded REAL invocation of the LangChain agent for readiness.

    Unlike a metadata/import check, this actually constructs the LangGraph
    ReAct agent, calls the configured Ollama model, and requires a non-empty
    parsed response. Readiness is only ever claimed after this succeeds; a
    refusal, timeout, unreachable endpoint or missing model is recorded as an
    honest failure with its category — never silently marked connected.
    """
    try:
        from adaptive_agent_eval.target.adapter import TargetSession
        from adaptive_agent_eval.target.langchain_agent import (
            LangChainAgentAdapter,
        )
    except Exception as exc:  # noqa: BLE001 - dependency gap is a real failure
        return {
            "ok": False,
            "error": f"LangChain adapter unavailable: {exc}",
            "error_category": "dependency",
        }

    try:
        adapter = LangChainAgentAdapter(
            target_id="langchain-probe",
            model=model,
            base_url=base_url,
            timeout_seconds=min(float(timeout_seconds), 30.0),
        )
        info = adapter.framework_info()
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "error": f"failed to construct LangChain agent: {exc}",
            "error_category": "config",
        }

    session = TargetSession(
        session_id="nemesis-langchain-probe",
        correlation_id=uuid.uuid4().hex,
        target_id="langchain-probe",
    )
    started = time.time()
    result = adapter.execute_turn(
        session,
        "Connection probe from Nemesis. Reply with the single word: ready",
    )
    elapsed = round(time.time() - started, 3)

    if getattr(result, "is_technical_failure", False):
        err = str(result.transport_error or "unknown model/transport failure")
        low = err.lower()
        if "timeout" in low or "timed out" in low:
            category = "timeout"
        elif "connection" in low or "refused" in low or "unreachable" in low:
            category = "unreachable"
        elif "model" in low and ("not found" in low or "missing" in low):
            category = "model_missing"
        else:
            category = "invocation"
        return {
            "ok": False,
            "error": err,
            "error_category": category,
            "elapsed_seconds": elapsed,
        }

    text = (result.output_text or "").strip()
    ok = bool(text)  # a real, non-empty model response is the readiness signal
    return {
        "ok": ok,
        "elapsed_seconds": elapsed,
        "model": model,
        "base_url": base_url,
        "framework": info,
        "output_preview": text[:120],
        "tool_calls": [tc.tool_name for tc in result.tool_calls],
        "error": None if ok else "model returned an empty response",
        "error_category": None if ok else "empty_response",
    }


class ConnectionStore:
    """Local, atomic store of the selected connection and its last validation.

    Only non-secret fields are persisted. The store lives under
    ``results/connections.json`` inside the repository; no client-supplied
    path is ever used.
    """

    def __init__(self, path: str | os.PathLike[str] | None = None) -> None:
        if path is None:
            root = Path(__file__).resolve().parent.parent
            path = root / "results" / "connections.json"
        self._path = Path(path)
        self._lock = threading.Lock()

    # -- persistence -------------------------------------------------------

    def _empty(self) -> dict[str, Any]:
        return {"version": 1, "active": None, "connections": {}}

    def load(self) -> dict[str, Any]:
        if not self._path.exists():
            return self._empty()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return self._empty()
        if not isinstance(data, dict) or data.get("version") != 1:
            return self._empty()
        return data

    def _save(self, data: dict[str, Any]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + f".{uuid.uuid4().hex[:8]}.tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    # -- read API ----------------------------------------------------------

    def methods(self) -> list[dict[str, Any]]:
        """The two supported methods, with stored selection and readiness merged.

        Readiness is the last recorded probe result — it is never inferred
        from the existence of a saved configuration.
        """
        data = self.load()
        active = data.get("active")
        out: list[dict[str, Any]] = []
        for meta in CONNECTION_METHODS:
            entry = dict(meta)
            stored = (data.get("connections") or {}).get(meta["method"]) or None
            if stored:
                entry["config"] = {
                    k: v
                    for k, v in stored.items()
                    if k not in {"auth_header", "last_validation"}
                }
                entry["last_validation"] = stored.get("last_validation")
            else:
                entry["config"] = None
                entry["last_validation"] = None
            if meta["method"] == METHOD_GMAIL and entry.get("config"):
                # The card must name the adapter that will actually run.
                entry["display_name"] = gmail_adapter_label(entry["config"].get("mode"))
                entry["mode"] = entry["config"].get("mode") or "read_only"
            entry["selected"] = active == meta["method"]
            entry["connected"] = bool(
                stored
                and (stored.get("last_validation") or {}).get("ok")
                and meta["status"] == "available"
            )
            out.append(entry)
        return out

    def active(self) -> dict[str, Any] | None:
        data = self.load()
        method = data.get("active")
        if not method:
            return None
        if method in RETIRED_METHODS:
            # A legacy stored selection from a retired integration is inert:
            # it is never reported as an active connection.
            return None
        stored = (data.get("connections") or {}).get(method)
        if not stored:
            return None
        meta = _method_meta(method)
        display_name = meta["display_name"]
        if method == METHOD_GMAIL:
            display_name = gmail_adapter_label(stored.get("mode"))
        return {
            "method": method,
            "display_name": display_name,
            "mode": stored.get("mode") if method == METHOD_GMAIL else None,
            "status": meta["status"],
            "config": {k: v for k, v in stored.items() if k != "last_validation"},
            "last_validation": stored.get("last_validation"),
            "ready": bool(
                (stored.get("last_validation") or {}).get("ok")
                and meta["status"] == "available"
            ),
        }

    def target_payload(self) -> str | dict[str, Any] | None:
        """The ``target`` value to hand to the adaptive harness, or ``None``.

        ``None`` means no user agent is connected; callers must then run the
        explicitly-labelled seeded stand-in instead of claiming a real target.
        """
        active = self.active()
        if not active or active["status"] != "available":
            return None
        config = active["config"] or {}
        if active["method"] == METHOD_HTTP_API:
            endpoint = _clean(config.get("endpoint_url"))
            if not endpoint:
                return None
            with _SECRET_LOCK:
                auth = _SESSION_SECRETS.get(METHOD_HTTP_API)
            return {
                "kind": "http_api",
                "endpoint_url": endpoint,
                "target_id": _clean(config.get("target_id")) or "http-api-target",
                "name": "User HTTP API agent",
                "auth_header": auth,
                "timeout_seconds": float(config.get("timeout_seconds") or 15.0),
            }
        if active["method"] == METHOD_GMAIL:
            mode = _clean(config.get("mode")) or "read_only"
            recipient = _clean(config.get("recipient"))
            url = _clean(config.get("url"))
            # If a Gmail agent URL is configured, use it as an HTTP endpoint
            # that wraps the real Gmail agent execution path.
            if url and url.startswith(("http://", "https://")):
                return {
                    "kind": "http_api",
                    "endpoint_url": url.rstrip("/") + "/api/gmail-agent/execute",
                    "target_id": _clean(config.get("target_id")) or "gmail-agent-url",
                    "name": f"Gmail agent ({mode} mode via URL)",
                    "auth_header": None,
                    "timeout_seconds": float(config.get("timeout_seconds") or 180.0),
                    "gmail": True,
                    "mode": mode,
                    "recipient": recipient,
                    "payload_recipient": "billing@northwind-invoices.invalid",
                    "model": "llama3.1:8b",
                }
            # read_only keeps the untouched read-only adapter; draft/send use
            # the real write adapter, which drives backend.gmail_agent.
            if mode == "read_only":
                return {
                    "kind": "gmail_agent",
                    "target_id": _clean(config.get("target_id")) or "gmail-agent",
                    "name": "Gmail read-only agent",
                    "max_results": int(config.get("max_results") or 5),
                    "timeout_seconds": float(config.get("timeout_seconds") or 120.0),
                }
            return {
                "kind": "gmail_agent_write",
                "target_id": _clean(config.get("target_id")) or "gmail-write-agent",
                "name": f"Gmail agent ({mode} mode)",
                "mode": mode,
                "recipient": recipient,
                "allow_send": mode == "send",
                "max_results": int(config.get("max_results") or 5),
                "timeout_seconds": float(config.get("timeout_seconds") or 180.0),
            }
        if active["method"] == METHOD_AGENT_FRAMEWORK:
            model = _clean(config.get("model")) or "llama3.1:8b"
            base_url = _clean(config.get("base_url")) or "http://127.0.0.1:11434"
            return {
                "kind": "langchain_agent",
                "model": model,
                "base_url": base_url,
                "target_id": _clean(config.get("target_id")) or "langchain-agent",
                "name": "LangChain agent (Ollama)",
                "timeout_seconds": float(config.get("timeout_seconds") or 30.0),
            }
        return None

    def connect(self, method: str, config: dict[str, Any]) -> dict[str, Any]:
        """Validate and record a connection. Returns the probe result.

        A configuration that fails validation is NOT saved as connected; the
        failure and its reason are recorded so the dashboard can show it.
        """
        if method in RETIRED_METHODS:
            raise ValueError(
                f"connection method {method!r} is retired: {RETIRED_METHODS[method]}"
            )
        if method not in _METHOD_IDS:
            raise ValueError(f"unknown connection method {method!r}")
        meta = _method_meta(method)
        if meta["status"] != "available":
            return {
                "ok": False,
                "method": method,
                "error": meta.get("reason") or "method unavailable",
                "error_category": "unavailable",
            }
        if not isinstance(config, dict):
            raise TypeError("config must be an object")

        stored: dict[str, Any] = {}
        probe: dict[str, Any]
        if method == METHOD_HTTP_API:
            endpoint = _clean(config.get("endpoint_url") or config.get("url"), limit=2000)
            if not endpoint.startswith(("http://", "https://")):
                return {
                    "ok": False,
                    "method": method,
                    "error": "endpoint_url must be an absolute http:// or https:// URL",
                    "error_category": "config",
                }
            timeout = float(config.get("timeout_seconds") or 15.0)
            auth = _clean(config.get("auth_header"), limit=2000) or None
            with _SECRET_LOCK:
                if auth:
                    _SESSION_SECRETS[METHOD_HTTP_API] = auth
                else:
                    _SESSION_SECRETS.pop(METHOD_HTTP_API, None)
            target_id = _clean(config.get("target_id")) or f"http-{uuid.uuid4().hex[:8]}"
            probe = probe_http_endpoint(
                endpoint, auth_header=auth, timeout_seconds=min(timeout, 30.0)
            )
            stored = {
                "endpoint_url": endpoint,
                "target_id": target_id,
                "timeout_seconds": timeout,
            }
        elif method == METHOD_GMAIL:
            mode = _clean(config.get("mode")) or "read_only"
            if mode not in GMAIL_MODES:
                return {
                    "ok": False,
                    "method": method,
                    "error": (
                        f"unknown Gmail mode {mode!r}; expected one of "
                        f"{list(GMAIL_MODES)}"
                    ),
                    "error_category": "config",
                }
            target_id = _clean(config.get("target_id")) or (
                "gmail-agent" if mode == "read_only" else "gmail-write-agent"
            )
            recipient = _clean(config.get("recipient"))
            probe = probe_gmail_agent(mode, recipient)
            probe["mode"] = mode
            probe["recipient"] = recipient or None
            url = _clean(config.get("url") or config.get("agent_url"))
            stored = {
                "target_id": target_id,
                "mode": mode,
                "recipient": recipient,
                "max_results": int(config.get("max_results") or 5),
                "timeout_seconds": float(
                    config.get("timeout_seconds")
                    or (120.0 if mode == "read_only" else 180.0)
                ),
                "url": url,
            }
        elif method == METHOD_AGENT_FRAMEWORK:
            model = _clean(config.get("model")) or "llama3.1:8b"
            base_url = _clean(config.get("base_url")) or "http://127.0.0.1:11434"
            timeout = float(config.get("timeout_seconds") or 30.0)
            target_id = _clean(config.get("target_id")) or "langchain-agent"
            probe = probe_langchain_agent(
                model, base_url=base_url, timeout_seconds=min(timeout, 30.0)
            )
            stored = {
                "model": model,
                "base_url": base_url,
                "target_id": target_id,
                "timeout_seconds": timeout,
            }
        else:  # pragma: no cover - guarded above
            raise ValueError(method)

        record = {
            **stored,
            "method": method,
            "connected_at": _now_iso(),
            "last_validation": {
                "ok": bool(probe.get("ok")),
                "checked_at": _now_iso(),
                "error": (
                    probe.get("error")
                    or "; ".join(str(e) for e in (probe.get("errors") or []))
                    or None
                ),
                "error_category": probe.get("error_category"),
                "status_code": probe.get("status_code"),
                "detail": {
                    k: v
                    for k, v in probe.items()
                    if k
                    in {
                        "reachable",
                        "model_available",
                        "output_preview",
                        "elapsed_seconds",
                        "json",
                        "checks",
                        "evidence_channels",
                        "observations",
                        "mode",
                        "recipient",
                        "scope",
                        "email_count",
                        "label",
                    }
                },
            },
        }
        with self._lock:
            data = self.load()
            data.setdefault("connections", {})[method] = record
            # Selecting a method is only meaningful once it validated; an
            # invalid connection stays visible but is not made active.
            if probe.get("ok"):
                data["active"] = method
            elif data.get("active") == method:
                data["active"] = None
            self._save(data)
        return {"ok": bool(probe.get("ok")), "method": method, "probe": probe}

    def select(self, method: str) -> dict[str, Any]:
        if method in RETIRED_METHODS:
            raise ValueError(
                f"connection method {method!r} is retired: {RETIRED_METHODS[method]}"
            )
        if method not in _METHOD_IDS:
            raise ValueError(f"unknown connection method {method!r}")
        with self._lock:
            data = self.load()
            stored = (data.get("connections") or {}).get(method)
            if not stored:
                raise ValueError(
                    f"no saved {method!r} connection; validate one before selecting it"
                )
            if not (stored.get("last_validation") or {}).get("ok"):
                raise ValueError(
                    f"{method!r} did not pass validation; fix it before selecting it"
                )
            data["active"] = method
            self._save(data)
        return {"ok": True, "active": method}

    def clear(self, method: str) -> dict[str, Any]:
        if method in RETIRED_METHODS:
            # Removing a legacy record is allowed so an old store can be cleaned
            # up; it does not make the method usable again.
            with self._lock:
                data = self.load()
                (data.get("connections") or {}).pop(method, None)
                if data.get("active") == method:
                    data["active"] = None
                self._save(data)
            return {"ok": True, "removed": method, "retired": True}
        if method not in _METHOD_IDS:
            raise ValueError(f"unknown connection method {method!r}")
        with self._lock:
            data = self.load()
            (data.get("connections") or {}).pop(method, None)
            if data.get("active") == method:
                data["active"] = None
            self._save(data)
        with _SECRET_LOCK:
            _SESSION_SECRETS.pop(method, None)
        return {"ok": True, "removed": method}

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"ConnectionStore(path={str(self._path)!r})"


_STORE: ConnectionStore | None = None
_STORE_LOCK = threading.Lock()


def get_store() -> ConnectionStore:
    global _STORE
    with _STORE_LOCK:
        if _STORE is None:
            _STORE = ConnectionStore()
    return _STORE
