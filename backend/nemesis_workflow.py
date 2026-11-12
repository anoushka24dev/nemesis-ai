"""Nemesis autonomous email backend endpoints — Stage B integration layer.

These are the backend routes the Nemesis side panel actually drives:
- workflow status / kill switch
- prepare new, prepare reply, prepare forward
- submit (send / draft)
- adaptive strategy status (attacker/defender generation loop state)
- recent activity (workflow + feedback audit tail)

Everything here is pairing-gated, local-only, and deterministic. No model
call and no real Gmail write happens from these endpoints. Real sending is
only reachable through the owner-armed live transport path already implemented
in `email_workflow.service` + `gmail_live`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

import backend.feedback as _feedback
import email_workflow.quality as _quality
from email_workflow import GenerationSettings
from email_workflow.compose import message_from_summary
from gmail_demo.models import Email as _DemoEmail

NOW = lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")


async def _read_body(request: Request) -> dict[str, Any]:
    """Read a JSON object body; malformed input becomes an empty object."""
    try:
        body = await request.json()
    except (ValueError, UnicodeDecodeError):
        return {}
    return body if isinstance(body, dict) else {}


_read_body_exc = (ValueError, UnicodeDecodeError)

# Nemesis uses two explicit sandbox accounts for sender/recipient identity and
# for adaptive-mutation routing. These are the only identities this backend
# will ever describe; the actual OAuth credentials for each are owned outside
# this file and are not materialized here.


def _sandbox_senders() -> dict[str, dict[str, str]]:
    """Return the two configured sandbox identities (labels, not secrets)."""
    return {
        "sender_a": {
            "label": "Nemesis Sandbox A (sender / attacker context)",
            "address": "nemesis-sandbox-a@proton.me",
        },
        "sender_b": {
            "label": "Nemesis Sandbox B (recipient / defender context)",
            "address": "nemesis-sandbox-b@proton.me",
        },
    }


def _sender_for(role: str) -> dict[str, str]:
    """Pick the explicit sandbox identity for the requested role."""
    pool = _sandbox_senders()
    key = role.lower()
    if key in pool:
        return pool[key]
    # Fail closed: unknown roles do not default to some other identity.
    raise ValueError(f"unknown sandbox identity role: {role!r}")


def _sender_address_for_display(role: str) -> str:
    """Return the labelled sandbox address used in a prepared forward."""
    return _sender_for(role)["address"]


_FEEDBACK_PATH = Path(__file__).resolve().parent.parent / "backend" / "data" / "feedback_store.json"
_QUALITY_PATH = Path(__file__).resolve().parent.parent / "email_workflow" / "data" / "quality_store.json"


def _feedback_path() -> Path:
    env = Path(__file__).resolve().parent.parent.parent / "backend" / "data" / "feedback_store.json"
    return env if env.exists() else _FEEDBACK_PATH


def _quality_path() -> Path:
    env = Path(__file__).resolve().parent.parent.parent / "email_workflow" / "data" / "quality_store.json"
    return env if env.exists() else _QUALITY_PATH


class NemesisWorkflow:
    """Thin wrapper that gives the Nemesis panel a clean autonomous workflow API.

    It composes messages, runs the active outgoing defense scan, enforces policy
    through the existing `email_workflow.service` path, and records activity for
    the recent-activity panel. It never claims success unless the underlying
    workflow service did.
    """

    def __init__(self, workflow_service: Any, kill_switch: bool, policy: Any) -> None:
        self._svc = workflow_service
        self._kill_switch = kill_switch
        self._policy = policy

    def status(self) -> dict[str, Any]:
        return {
            "mode": self._policy.mode.value,
            "kill_switch": bool(self._svc.policy.kill_switch),
            "send_authorized": self._policy.send_authorized,
            "draft_authorized": self._policy.draft_authorized,
            "allowed_recipients": sorted(self._policy.allowed_recipients),
            "allowed_domains": sorted(self._policy.allowed_domains),
            "rate_limit_per_hour": self._policy.rate_limit_per_hour,
            "rate_limit_remaining": (
                self._svc.rate_limiter.remaining()
                if getattr(self._svc, "rate_limiter", None)
                else None
            ),
            "granted_scopes": sorted(self._policy.granted_scopes),
            "transport": getattr(self._svc.transport, "name", "?"),
            "transport_executes_live_actions": bool(
                getattr(self._svc.transport, "executes_live_actions", False)
            ),
            "kill_switch_status": self._svc.kill_switch_status(),
            "sandbox_accounts": _sandbox_senders(),
        }

    def prepare_new(self, *, to: list[str], subject: str, body: str,
                    settings: dict[str, Any] | None, confirm: bool) -> dict[str, Any]:
        settings_obj = GenerationSettings.from_dict(settings) if settings else GenerationSettings()
        report = self._svc.prepare_new(to, subject, body, settings=settings_obj, confirmed=confirm)
        return {"status": report.status, "report": report.to_dict()}

    def prepare_reply(self, *, sender: str, subject: str, body_text: str,
                      email_id: str, thread_id: str | None, settings: dict[str, Any] | None,
                      confirm: bool) -> dict[str, Any]:
        incoming = _DemoEmail(
            id=email_id or "posted-open-email",
            sender=sender or "",
            subject=subject or "",
            body=body_text or "",
            labels=["NEMESIS_DEMO"],
        )
        settings_obj = GenerationSettings.from_dict(settings) if settings else GenerationSettings()
        report = self._svc.prepare_reply(
            incoming,
            settings=settings_obj,
            thread_id=thread_id or None,
            confirmed=confirm,
        )
        return {"status": report.status, "report": report.to_dict()}

    def prepare_forward(self, *, recipient: str, subject: str, body_text: str,
                        source_email_id: str, settings: dict[str, Any] | None,
                        attach_original: bool, confirm: bool,
                        role: str | None = None) -> dict[str, Any]:
        settings_obj = GenerationSettings.from_dict(settings) if settings else GenerationSettings()
        sender_addr = _sender_address_for_display(role or "sender_a")
        # Forward is a new message; the recipient is explicit and validated.
        # Original content is summarized; body quotes only the sanitized subject
        # to avoid forwarding untrusted body instructions verbatim.
        forward_body = (
            f"Forwarding: {subject or '(no subject)'}\n\n"
            f"Original message from: {sender_addr}\n"
            f"Forwarded for review by Nemesis.\n"
        )
        report = self._svc.prepare_new(
            [recipient],
            f"FW: {subject or '(no subject)'}",
            forward_body,
            settings=settings_obj,
            confirmed=confirm,
        )
        return {"status": report.status, "report": report.to_dict(), "sender": sender_addr}

    def submit(
        self,
        *,
        message: dict[str, Any] | None,
        purpose: str,
        confirm: bool,
        prepared_id: str | None = None,
    ) -> dict[str, Any]:
        msg = message_from_summary(message) if message else None
        report = self._svc.submit(
            msg, purpose=purpose, confirm=confirm, prepared_id=prepared_id
        )
        return {"status": report.status, "report": report.to_dict()}

    def engage_kill_switch(self) -> dict[str, Any]:
        out = self._svc.engage_kill_switch(
            actor="paired-extension", reason="nemesis stop request"
        )
        self._kill_switch = True
        return {**out, "mode": self._policy.mode.value}

    def release_kill_switch(
        self, *, confirm: bool, reason: str | None = None
    ) -> dict[str, Any]:
        out = self._svc.release_kill_switch(
            confirm=confirm,
            actor="paired-extension",
            reason=reason or "nemesis release request",
        )
        self._kill_switch = False
        return {**out, "mode": self._policy.mode.value}

    def kill_switch(self) -> bool:
        return bool(self._svc.policy.kill_switch)

    def activity(self, limit: int = 25) -> dict[str, Any]:
        """Recent activity for the Nemesis panel: workflow + feedback audit tail."""
        try:
            wf = self._svc.audit.tail(limit)
        except Exception:
            wf = []
        try:
            fb_path = _feedback_path()
            fb_data = _feedback._load(fb_path) if fb_path.exists() else {}
        except Exception:
            fb_data = {}
        try:
            q_path = _quality_path()
            q_data = _quality._load(q_path) if q_path.exists() else {}
        except Exception:
            q_data = {}
        return {
            "workflow": wf,
            "feedback_audit": fb_data.get("audit", [])[-limit:],
            "quality_audit": q_data.get("audit", [])[-limit:],
            "sandbox_senders": _sandbox_senders(),
        }




def nemesis_workflow_status(request: Request, backend: Any) -> JSONResponse:
    """Nemesis panel: current autonomous workflow + sandbox identity status."""
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        status = wf.status()
        status["kill_switch"] = wf.kill_switch()
        status["sandbox_accounts"] = _sandbox_senders()
        return JSONResponse(status_code=200, content={"status": "ok", "workflow": status})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"nemesis workflow status failed: {exc}"})


async def nemesis_prepare_new(request: Request, backend: Any) -> JSONResponse:
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        body = await _read_body(request)
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        out = wf.prepare_new(
            to=[str(a) for a in (body.get("to") or [])],
            subject=str(body.get("subject") or ""),
            body=str(body.get("body_text") or body.get("body") or ""),
            settings=body.get("settings"),
            confirm=bool(body.get("confirm")),
        )
        return JSONResponse(status_code=200, content={"status": "ok", **out})
    except _read_body_exc as exc:
        return JSONResponse(status_code=400, content={"error": f"nemesis prepare new failed: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"nemesis prepare new failed: {exc}"})


async def nemesis_prepare_reply(request: Request, backend: Any) -> JSONResponse:
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        body = await _read_body(request)
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        out = wf.prepare_reply(
            sender=str(body.get("sender") or ""),
            subject=str(body.get("subject") or ""),
            body_text=str(body.get("body_text") or body.get("body") or ""),
            email_id=str(body.get("email_id") or "posted-open-email"),
            thread_id=(str(body.get("thread_id") or "") or None),
            settings=body.get("settings"),
            confirm=bool(body.get("confirm")),
        )
        return JSONResponse(status_code=200, content={"status": "ok", **out})
    except _read_body_exc as exc:
        return JSONResponse(status_code=400, content={"error": f"nemesis prepare reply failed: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"nemesis prepare reply failed: {exc}"})


async def nemesis_prepare_forward(request: Request, backend: Any) -> JSONResponse:
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        body = await _read_body(request)
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        out = wf.prepare_forward(
            recipient=str(body.get("recipient") or ""),
            subject=str(body.get("subject") or ""),
            body_text=str(body.get("body_text") or body.get("body") or ""),
            source_email_id=str(body.get("source_email_id") or "posted-open-email"),
            settings=body.get("settings"),
            attach_original=bool(body.get("attach_original", False)),
            confirm=bool(body.get("confirm")),
            role=str(body.get("role") or "sender_a"),
        )
        return JSONResponse(status_code=200, content={"status": "ok", **out})
    except _read_body_exc as exc:
        return JSONResponse(status_code=400, content={"error": f"nemesis prepare forward failed: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"nemesis prepare forward failed: {exc}"})


async def nemesis_submit(request: Request, backend: Any) -> JSONResponse:
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        body = await _read_body(request)
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        raw_message = body.get("message")
        prepared_id = str(
            body.get("prepared_id")
            or (raw_message or {}).get("message_id")
            or ""
        ).strip() or None
        out = wf.submit(
            message=raw_message if isinstance(raw_message, dict) and raw_message else None,
            purpose=str(body.get("purpose") or "send"),
            confirm=bool(body.get("confirm")),
            prepared_id=prepared_id,
        )
        return JSONResponse(status_code=200, content={"status": "ok", **out})
    except _read_body_exc as exc:
        return JSONResponse(status_code=400, content={"error": f"nemesis submit failed: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"nemesis submit failed: {exc}"})


async def nemesis_killswitch(request: Request, backend: Any) -> JSONResponse:
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        out = wf.engage_kill_switch()
        return JSONResponse(status_code=200, content={"status": "ok", **out})
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "kill_switch": True,
                "durable": False,
                "error": f"nemesis kill switch failed: {exc}",
            },
        )


async def nemesis_activity(request: Request, backend:Any) -> JSONResponse:
    auth_error = backend._require_auth(request)
    if auth_error:
        return auth_error
    try:
        body = await _read_body(request)
        wf = NemesisWorkflow(
            workflow_service=backend._workflow,
            kill_switch=backend._workflow.policy.kill_switch,
            policy=backend._workflow.policy,
        )
        out = wf.activity(limit=max(1, min(200, int(body.get("limit") or 25))))
        return JSONResponse(status_code=200, content={"status": "ok", **out})
    except _read_body_exc as exc:
        return JSONResponse(status_code=400, content={"error": f"nemesis activity failed: {exc}"})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": f"nemesis activity failed: {exc}"})


