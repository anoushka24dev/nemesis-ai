"""Workflow orchestration: authorize -> compose/validate -> transport -> audit.

Order of enforcement for any outbound action (``submit``):

0. outgoing defense scan with the ACTIVE threat ruleset (``email_workflow.
   outgoing``): flag-level content is refused outright, review-level content
   requires explicit confirmation — the same ruleset version that classifies
   incoming mail,
1. kill switch (hard stop for transport actions),
2. recipient allowlist / explicit-confirmation rules,
3. operating mode (simulation never calls the transport at all),
4. owner authorization flags + granted OAuth scopes,
5. sensitive-content confirmation,
6. hourly rate limit (only immediately before a transport call),
7. idempotency (duplicate-send prevention),
8. transport dispatch, then audit of the outcome.

``WorkflowReport.status`` becomes ``"sent"`` ONLY when a transport result
carries ``executed=True`` (real-world confirmation). The mock transport can
never produce that flag, so no test or demo can ever claim a real send.
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any

from email_workflow.audit import AuditLog, body_fingerprint
from email_workflow.compose import (
    GenerationSettings,
    OutgoingMessage,
    compose_new,
    compose_reply,
)
from email_workflow.modes import OperatingMode  # canonical enum identity (do not alias elsewhere)
from email_workflow.outbound_state import (
    ATTEMPT_CONFIRMED,
    ATTEMPT_FAILED,
    ATTEMPT_SIMULATED,
    ATTEMPT_UNCERTAIN,
    OutboundStateError,
    OutboundStateStore,
)
from email_workflow.outgoing import OutgoingDefense
from email_workflow.policy import (
    ConfirmationRequired,
    Policy,
    PolicyDenied,
    PolicyError,
    RateLimiter,
)
from email_workflow.transport import (
    LiveGmailTransport,
    MockTransport,
    TransportError,
    TransportUnavailableError,
    idempotency_key,
)
from email_workflow.validate import (
    MessageValidationError,
    requires_confirmation,
    validate_recipients,
    validate_reply_target,
    validate_thread_id,
)
from gmail_demo.models import Email

__all__ = [
    "EmailWorkflowService",
    "LiveGmailTransport",
    "WorkflowReport",
]

_STATUS_PREPARED = "prepared"
_STATUS_SIMULATED = "simulated_send"
_STATUS_DRAFT = "draft_saved"
_STATUS_SENT = "sent"
_STATUS_UNCERTAIN = "uncertain"
_STATUS_DENIED = "denied"
_STATUS_ERROR = "error"


@dataclass
class WorkflowReport:
    """Outcome of prepare/submit. ``executed`` is real-world truth; everything
    else (including ``status``) is bookkeeping around it."""

    status: str
    action: str  # "reply" | "new" | "send" | "draft"
    mode: str
    transport_called: bool
    executed: bool
    simulated: bool
    message: dict[str, Any] | None = None
    transport: dict[str, Any] | None = None
    reason: str | None = None
    audit_id: str | None = None
    #: Outgoing defense scan result (same active ruleset as incoming analysis).
    defense: dict[str, Any] | None = None
    #: Present when the submission was bound to a prepared artifact.
    prepared_id: str | None = None

    @property
    def message_id(self) -> str | None:
        if not self.transport:
            return None
        return self.transport.get("message_id") or self.transport.get("record_id") or None

    @property
    def thread_id(self) -> str | None:
        if not self.transport:
            return None
        return self.transport.get("thread_id") or None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "action": self.action,
            "mode": self.mode,
            "transport_called": self.transport_called,
            "executed": self.executed,
            "simulated": self.simulated,
            "message": self.message,
            "transport": self.transport,
            "reason": self.reason,
            "audit_id": self.audit_id,
            "defense": self.defense,
            "prepared_id": self.prepared_id,
            "message_id": self.message_id,
            "thread_id": self.thread_id,
        }


@dataclass
class PreparedArtifact:
    """A canonical message prepared by this service and not yet submitted."""

    message: OutgoingMessage
    fingerprint: str
    consumed_purpose: str | None = None


def canonical_fingerprint(message: OutgoingMessage) -> str:
    raw = json.dumps(
        message.canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _recipient_fingerprint(message: OutgoingMessage) -> str:
    raw = "|".join((*message.to, *message.cc, *message.bcc))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class EmailWorkflowService:
    """Owns policy + transport + audit for one account-owner configuration."""

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        transport: Any = None,
        audit: AuditLog | None = None,
        rate_limiter: RateLimiter | None = None,
        clock: Callable[[], float] = time.time,
        outgoing_defense: OutgoingDefense | None = None,
        state_store: OutboundStateStore | None = None,
        require_prepared_artifacts: bool | None = None,
    ) -> None:
        self.policy = policy or Policy()
        self.state_store = state_store
        # A production service requires a prepared artifact id; unit callers
        # that construct the service directly retain the lower-level contract.
        self.require_prepared_artifacts = (
            state_store is not None
            if require_prepared_artifacts is None
            else bool(require_prepared_artifacts)
        )
        self._prepared: dict[str, PreparedArtifact] = {}
        if state_store is not None:
            engaged = state_store.kill_switch_engaged()
            # A store that says ON always wins. A policy that says ON must also
            # be persisted so a later reconstruction cannot silently release it.
            if engaged or self.policy.kill_switch:
                self.policy = replace(self.policy, kill_switch=True)
                if not engaged:
                    try:
                        state_store.set_kill_switch(
                            True, actor="system", reason="policy required stop"
                        )
                    except OutboundStateError:
                        pass
            else:
                self.policy = replace(self.policy, kill_switch=False)
        self.transport = transport or MockTransport()
        self.audit = audit or AuditLog()
        self._clock = clock
        self.rate_limiter = rate_limiter or RateLimiter(
            self.policy.rate_limit_per_hour, clock=clock, store=state_store
        )
        # Every outgoing message is scanned with the SAME active threat
        # ruleset that incoming analysis uses (requirement 2 integration).
        self.outgoing_defense = outgoing_defense or OutgoingDefense()

    # -- kill switch --------------------------------------------------------

    def engage_kill_switch(
        self, *, actor: str | None = None, reason: str | None = None
    ) -> dict[str, Any]:
        """Persist the hard stop, then update the in-memory policy.

        If persistence fails the in-memory policy remains ON and the error is
        raised to the caller, which must report that the stop may not be
        durable. The stop is never silently reported as saved.
        """
        durable = False
        error: str | None = None
        if self.state_store is not None:
            try:
                self.state_store.set_kill_switch(
                    True, actor=actor, reason=reason
                )
                durable = True
            except OutboundStateError as exc:
                error = str(exc)
        self.policy = replace(self.policy, kill_switch=True)
        self.audit.record(
            "kill_switch_engaged", actor=actor, reason=reason, durable=durable
        )
        if error:
            raise OutboundStateError(
                f"outbound stop engaged in memory but not durably persisted: {error}"
            )
        return {"kill_switch": True, "durable": durable}

    def release_kill_switch(
        self,
        *,
        confirm: bool,
        actor: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Explicitly release the stop. Never arms or authorizes sending."""
        if not confirm:
            raise PolicyError(
                "releasing the outbound stop requires explicit confirm=true"
            )
        if self.state_store is None:
            raise PolicyError(
                "persistent outbound state is not configured; the stop cannot "
                "be released durably"
            )
        try:
            result = self.state_store.set_kill_switch(
                False, actor=actor, reason=reason, require_confirm=True
            )
        except OutboundStateError:
            self.policy = replace(self.policy, kill_switch=True)
            raise
        self.policy = replace(self.policy, kill_switch=False)
        self.audit.record(
            "kill_switch_released", actor=actor, reason=reason, durable=True
        )
        return {
            "kill_switch": False,
            "durable": True,
            "previous_state": result.get("previous_state"),
        }

    def kill_switch_status(self) -> dict[str, Any]:
        if self.state_store is None:
            return {
                "engaged": bool(self.policy.kill_switch),
                "durable": False,
                "source": "process",
            }
        record = self.state_store.kill_switch_record()
        record["source"] = "persistent"
        return record

    # -- preparation (allowed in every mode, no transport involved) ---------

    def prepare_reply(
        self,
        incoming: Email,
        *,
        settings: GenerationSettings | None = None,
        thread_id: str | None = None,
        confirmed: bool = False,
    ) -> WorkflowReport:
        """Compose + validate a reply proposal. Nothing is sent or saved."""
        tid = validate_thread_id(thread_id)
        message = compose_reply(
            incoming,
            settings=settings,
            thread_id=tid,
            created_mode=self.policy.mode,
        )
        validate_reply_target(incoming, message.to, self.policy, confirmed=confirmed)
        self._register_prepared(message)
        return self._report(
            _STATUS_PREPARED,
            "reply",
            transport_called=False,
            message=message,
            defense=self.outgoing_defense.scan(message),
        )

    def prepare_new(
        self,
        to: tuple[str, ...] | list[str],
        subject: str,
        body: str,
        *,
        settings: GenerationSettings | None = None,
        confirmed: bool = False,
        cc: tuple[str, ...] | list[str] = (),
        bcc: tuple[str, ...] | list[str] = (),
    ) -> WorkflowReport:
        """Compose + validate a new (owner-authored) message proposal."""
        message = compose_new(
            to,
            subject,
            body,
            settings=settings,
            created_mode=self.policy.mode,
            cc=cc,
            bcc=bcc,
        )
        validate_recipients(
            (*message.to, *message.cc, *message.bcc),
            self.policy,
            confirmed=confirmed,
        )
        self._register_prepared(message)
        return self._report(
            _STATUS_PREPARED,
            "new",
            transport_called=False,
            message=message,
            defense=self.outgoing_defense.scan(message),
        )

    def prepare_message(
        self, message: OutgoingMessage, *, confirmed: bool = False
    ) -> WorkflowReport:
        """Register an already-composed message as a prepared artifact.

        Used by the Gmail agent so a reply keeps its real Gmail thread
        references. The same recipient validation and outgoing-defense scan
        that ``prepare_new``/``prepare_reply`` apply still run here, and the
        canonical fingerprint binds the exact message to the later submit.
        """
        validate_recipients(
            (*message.to, *message.cc, *message.bcc),
            self.policy,
            confirmed=confirmed,
        )
        self._register_prepared(message)
        return self._report(
            _STATUS_PREPARED,
            message.kind,
            transport_called=False,
            message=message,
            defense=self.outgoing_defense.scan(message),
        )

    def _register_prepared(self, message: OutgoingMessage) -> None:
        self._prepared[message.message_id] = PreparedArtifact(
            message=message, fingerprint=canonical_fingerprint(message)
        )

    # -- submission (the only path that can touch a transport) --------------

    def submit(
        self,
        message: OutgoingMessage | None,
        *,
        purpose: str = "send",
        confirm: bool = False,
        prepared_id: str | None = None,
    ) -> WorkflowReport:
        """Attempt ``purpose`` ("send"|"draft") for a prepared message.

        The prepared artifact is authoritative. When ``prepared_id`` is
        supplied (required by the production backend), every canonical field
        must match the artifact; the caller cannot substitute recipients,
        subject, body, type, CC/BCC, or thread references.
        """
        if purpose not in ("send", "draft"):
            raise PolicyError(f"unknown purpose {purpose!r}")
        resolved: OutgoingMessage | None = message
        artifact: PreparedArtifact | None = None
        defense: dict[str, Any] | None = None
        try:
            resolved, artifact = self._resolve_submission(
                message, prepared_id, purpose=purpose
            )
            # Outgoing defense scan runs FIRST for every submission in every
            # mode. flag -> hard block; review -> explicit confirmation.
            defense = self.outgoing_defense.scan(resolved)
            # The stop protects real Gmail outbound actions. Simulation is a
            # local inspection path and remains useful while the stop is ON;
            # any non-simulation transport path is blocked before dispatch.
            if self.policy.mode is not OperatingMode.SIMULATION:
                self.policy.assert_kill_switch_off()
            self._check_recipients(resolved, confirmed=confirm)
            self.outgoing_defense.enforce(defense, confirm=confirm)
            if purpose == "send":
                report = self._submit_send(resolved, confirm=confirm)
            else:
                report = self._submit_draft(resolved, confirm=confirm)
            report.defense = defense
            report.prepared_id = resolved.message_id
            if artifact is not None and report.status != _STATUS_DENIED:
                artifact.consumed_purpose = purpose
            return report
        except (PolicyDenied, MessageValidationError, OutboundStateError) as exc:
            summary = resolved.summary() if resolved is not None else None
            report = WorkflowReport(
                status=_STATUS_DENIED,
                action=purpose,
                mode=self.policy.mode.value,
                transport_called=False,
                executed=False,
                simulated=True,
                message=summary,
                reason=f"{type(exc).__name__}: {exc}",
                defense=defense,
                prepared_id=prepared_id or (resolved.message_id if resolved else None),
            )
            report.audit_id = self._audit_denied(
                resolved, purpose, exc, prepared_id=prepared_id
            )
            return report

    def _resolve_submission(
        self,
        message: OutgoingMessage | None,
        prepared_id: str | None,
        *,
        purpose: str,
    ) -> tuple[OutgoingMessage, PreparedArtifact | None]:
        if prepared_id is None and self.require_prepared_artifacts:
            raise PolicyDenied(
                "a prepared message id is required; submit the exact artifact "
                "returned by prepare"
            )
        if prepared_id is None:
            if message is None:
                raise PolicyDenied("message is required")
            artifact = self._prepared.get(message.message_id)
            if artifact is None:
                return message, None
            self._verify_prepared(artifact, message, prepared_id=message.message_id)
            return artifact.message, artifact
        artifact = self._prepared.get(str(prepared_id))
        if artifact is None:
            raise PolicyDenied(
                f"unknown prepared message id {prepared_id!r}; prepare the message first"
            )
        if artifact.consumed_purpose is not None:
            # Same-purpose idempotent replay is allowed to reach the ledger;
            # any other reuse is a policy violation.
            if artifact.consumed_purpose != purpose:
                raise PolicyDenied(
                    f"prepared message {prepared_id!r} was already used for a "
                    f"{artifact.consumed_purpose} action; it cannot be reused "
                    f"for {purpose}"
                )
            if message is None:
                return artifact.message, artifact
            if canonical_fingerprint(message) != artifact.fingerprint:
                raise PolicyDenied("prepared message was altered after preparation")
        if message is None:
            return artifact.message, artifact
        if message.message_id != str(prepared_id):
            raise PolicyDenied(
                "message id does not match the prepared artifact id"
            )
        self._verify_prepared(artifact, message, prepared_id=str(prepared_id))
        return artifact.message, artifact

    def _verify_prepared(
        self,
        artifact: PreparedArtifact,
        message: OutgoingMessage,
        *,
        prepared_id: str,
    ) -> None:
        if canonical_fingerprint(message) != artifact.fingerprint:
            raise PolicyDenied(
                f"prepared message {prepared_id!r} was modified; submission must "
                "match the exact prepared recipient, content, and references"
            )

    # -- internals ----------------------------------------------------------

    def _check_recipients(self, message: OutgoingMessage, *, confirmed: bool) -> None:
        # Reply targets were pinned to the source sender at compose time; every
        # To/CC/BCC address still clears the hard allowlist.
        validate_recipients(
            (*message.to, *message.cc, *message.bcc),
            self.policy,
            confirmed=confirmed,
        )

    def _maybe_confirm_sensitive(
        self, message: OutgoingMessage, *, confirm: bool
    ) -> None:
        if not self.policy.require_confirmation_sensitive:
            return
        if requires_confirmation(message.subject, message.body) and not confirm:
            raise ConfirmationRequired(
                "message looks sensitive/high-impact (financial, credential, "
                "payroll, or confidential content); explicit confirmation required"
            )

    def _submit_send(self, message: OutgoingMessage, *, confirm: bool) -> WorkflowReport:
        if self.policy.mode is OperatingMode.SIMULATION:
            # Simulation: document the intent, never touch the transport.
            report = self._report(
                _STATUS_SIMULATED,
                "send",
                transport_called=False,
                message=message,
                reason=(
                    "simulation mode: the send was composed and inspected only; "
                    "no transport was called and nothing was sent"
                ),
            )
            entry = self.audit.record(
                "workflow_simulated",
                workflow_action="send",
                message_id=message.message_id,
                to=list(message.to),
                subject=message.subject,
                body_fingerprint=body_fingerprint(message.body),
            )
            report.audit_id = str(entry.get("at"))
            return report
        self.policy.assert_mode_allows("send")
        self.policy.assert_send_authorized()
        self._maybe_confirm_sensitive(message, confirm=confirm)
        if getattr(self.transport, "executes_live_actions", False):
            # The transport can really deliver: an unconditional, per-action
            # operator confirmation is mandatory (details were shown by the
            # caller before submit). Nothing from the message or a model may
            # stand in for confirm=True.
            self.policy.assert_live_confirmation(confirmed=confirm)
        key = idempotency_key(message, action="send")
        return self._dispatch(message, "send", key=key)

    def _submit_draft(self, message: OutgoingMessage, *, confirm: bool) -> WorkflowReport:
        if self.policy.mode is OperatingMode.SIMULATION:
            # Simulation never claims a draft was saved.
            report = self._report(
                _STATUS_SIMULATED,
                "draft",
                transport_called=False,
                message=message,
                reason=(
                    "simulation mode: the draft was composed and inspected only; "
                    "no transport was called and nothing was saved"
                ),
            )
            entry = self.audit.record(
                "workflow_simulated",
                workflow_action="draft",
                message_id=message.message_id,
                to=list(message.to),
                subject=message.subject,
                body_fingerprint=body_fingerprint(message.body),
            )
            report.audit_id = str(entry.get("at"))
            return report
        self.policy.assert_mode_allows("draft")
        self.policy.assert_draft_authorized()
        self._maybe_confirm_sensitive(message, confirm=confirm)
        if getattr(self.transport, "executes_live_actions", False):
            # Saving a draft is a real mailbox write too: same unconditional
            # per-action confirmation requirement as sending.
            self.policy.assert_live_confirmation(confirmed=confirm)
        key = idempotency_key(message, action="draft")
        return self._dispatch(message, "draft", key=key)

    def _dispatch(
        self, message: OutgoingMessage, action: str, *, key: str
    ) -> WorkflowReport:
        """Rate-limit, persist idempotency state, and dispatch one action."""
        claim: dict[str, Any] | None = None
        if self.state_store is not None:
            claim = self.state_store.begin_attempt(
                key,
                action=action,
                message_fingerprint=canonical_fingerprint(message),
                recipient_fingerprint=_recipient_fingerprint(message),
            )
            if not claim.get("claimed"):
                return self._report_duplicate(message, action, claim)
        try:
            self.rate_limiter.check_and_record()
        except Exception:
            if self.state_store is not None:
                try:
                    self.state_store.finish_attempt(
                        key, state=ATTEMPT_FAILED, error="rate limit or ledger failure"
                    )
                except OutboundStateError:
                    pass
            raise
        try:
            if action == "send":
                result = self.transport.send(message, key=key)
            else:
                result = self.transport.create_draft(message, key=key)
        except TransportError as exc:
            # A live transport may have crossed the Gmail submission boundary
            # unless it refused before requesting (arming/kill/guard errors).
            uncertain = bool(
                getattr(exc, "uncertain", False)
                or (
                    getattr(self.transport, "executes_live_actions", False)
                    and not isinstance(exc, TransportUnavailableError)
                )
            )
            if self.state_store is not None:
                try:
                    self.state_store.finish_attempt(
                        key,
                        state=ATTEMPT_UNCERTAIN if uncertain else ATTEMPT_FAILED,
                        transport=getattr(self.transport, "name", None),
                        error=str(exc),
                        note="transport raised; automatic retry is disabled",
                    )
                except OutboundStateError:
                    pass
            return self._transport_error(
                message, action, exc, uncertain=uncertain, state_key=key
            )
        if self.state_store is not None:
            executed = bool(getattr(result, "executed", False) and result.ok)
            state = (
                ATTEMPT_CONFIRMED
                if executed
                else ATTEMPT_FAILED
                if not getattr(result, "ok", False)
                else ATTEMPT_SIMULATED
            )
            try:
                self.state_store.finish_attempt(
                    key,
                    state=state,
                    transport=getattr(result, "transport", None),
                    record_id=getattr(result, "record_id", None),
                    message_id=(
                        getattr(result, "message_id", None)
                        or getattr(result, "record_id", None)
                    ),
                    thread_id=getattr(result, "thread_id", None) or None,
                    error=getattr(result, "error", None),
                )
            except OutboundStateError as exc:
                report = self._report_from_result(message, action, result)
                report.reason = (
                    f"{report.reason + '; ' if report.reason else ''}"
                    f"ledger update failed ({exc}); delivery state may be uncertain"
                )
                return report
        return self._report_from_result(message, action, result)

    def _report_duplicate(
        self, message: OutgoingMessage, action: str, claim: dict[str, Any]
    ) -> WorkflowReport:
        attempt = claim.get("attempt") or {}
        state = str(claim.get("state") or "unknown")
        record_id = str(attempt.get("record_id") or "")
        message_id = str(attempt.get("message_id") or record_id)
        thread_id = str(attempt.get("thread_id") or "")
        if state == ATTEMPT_CONFIRMED:
            status = _STATUS_SENT if action == "send" else _STATUS_DRAFT
            reason = "idempotent replay of a previously confirmed outbound action"
            executed = True
            simulated = False
        elif state == ATTEMPT_UNCERTAIN:
            status = _STATUS_UNCERTAIN
            reason = (
                "outbound action is uncertain from an earlier attempt; automatic "
                "retry is disabled pending explicit reconciliation"
            )
            executed = False
            simulated = False
        elif state == ATTEMPT_SIMULATED:
            status = _STATUS_SIMULATED if action == "send" else _STATUS_DRAFT
            reason = "idempotent replay of a previously simulated outbound action"
            executed = False
            simulated = True
        elif state == "in_flight":
            status = _STATUS_DENIED
            reason = "the same outbound action is already in flight; not retried"
            executed = False
            simulated = False
        else:
            status = _STATUS_DENIED
            reason = f"outbound action has non-retryable state {state!r}"
            executed = False
            simulated = False
        transport_info = {
            "transport": attempt.get("transport") or getattr(self.transport, "name", "?"),
            "ok": status in (_STATUS_SENT, _STATUS_DRAFT, _STATUS_SIMULATED),
            "record_id": record_id,
            "message_id": message_id,
            "thread_id": thread_id,
            "duplicate": True,
            "error": attempt.get("error"),
            "detail": {"note": reason},
        }
        report = self._report(
            status,
            action,
            transport_called=False,
            message=message,
            transport=transport_info,
            executed=executed,
            simulated=simulated,
            reason=reason,
        )
        report.audit_id = str(
            self.audit.record(
                "workflow_duplicate",
                workflow_action=action,
                message_id=message.message_id,
                to=list(message.to),
                state=state,
                record_id=record_id,
                duplicate=True,
                executed=executed,
            ).get("at")
        )
        return report

    def _report_from_result(
        self, message: OutgoingMessage, action: str, result: Any
    ) -> WorkflowReport:
        transport_info = {
            "transport": getattr(result, "transport", "?"),
            "ok": bool(getattr(result, "ok", False)),
            "record_id": getattr(result, "record_id", ""),
            "message_id": (
                getattr(result, "message_id", "")
                or getattr(result, "record_id", "")
            ),
            "thread_id": getattr(result, "thread_id", ""),
            "duplicate": bool(getattr(result, "duplicate", False)),
            "error": getattr(result, "error", None),
            "detail": getattr(result, "detail", {}),
        }
        executed = bool(getattr(result, "executed", False) and result.ok)
        simulated = bool(getattr(result, "simulated", True))
        if not result.ok:
            status = _STATUS_ERROR
        elif executed:
            # Only a transport that actually performed the action earns "sent".
            status = _STATUS_SENT if action == "send" else _STATUS_DRAFT
        else:
            # Mock / non-executing transport: never claim a real-world effect.
            status = _STATUS_SIMULATED if action == "send" else _STATUS_DRAFT
        report = self._report(
            status,
            action,
            transport_called=True,
            message=message,
            transport=transport_info,
            executed=executed,
            simulated=simulated,
            reason=None
            if result.ok
            else f"transport {action} failed: {getattr(result, 'error', 'unknown')}",
        )
        report.audit_id = str(self.audit.record(
            f"transport_{action}_{'ok' if result.ok else 'failed'}",
            workflow_action=action,
            message_id=message.message_id,
            to=list(message.to),
            subject=message.subject,
            body_fingerprint=body_fingerprint(message.body),
            transport=transport_info["transport"],
            record_id=transport_info["record_id"],
            gmail_message_id=transport_info["message_id"],
            gmail_thread_id=transport_info["thread_id"],
            duplicate=transport_info["duplicate"],
            executed=executed,
            simulated=simulated,
        ).get("at"))
        return report

    def _transport_error(
        self,
        message: OutgoingMessage,
        action: str,
        exc: Exception,
        *,
        uncertain: bool = False,
        state_key: str | None = None,
    ) -> WorkflowReport:
        status = _STATUS_UNCERTAIN if uncertain else _STATUS_ERROR
        reason = f"{type(exc).__name__}: {exc}"
        if uncertain:
            reason += (
                "; Gmail may have accepted the request, so automatic retry is "
                "disabled pending explicit reconciliation"
            )
        report = WorkflowReport(
            status=status,
            action=action,
            mode=self.policy.mode.value,
            transport_called=True,
            executed=False,
            simulated=not uncertain,
            message=message.summary(),
            reason=reason,
        )
        report.audit_id = str(self.audit.record(
            f"transport_{action}_error",
            workflow_action=action,
            message_id=message.message_id,
            to=list(message.to),
            error=str(exc),
            http_status=getattr(exc, "http_status", None),
            api_reason=getattr(exc, "api_reason", None),
            uncertain=uncertain,
            state_key=state_key,
            executed=False,
        ).get("at"))
        return report

    def _audit_denied(
        self,
        message: OutgoingMessage | None,
        purpose: str,
        exc: Exception,
        *,
        prepared_id: str | None = None,
    ) -> str:
        entry = self.audit.record(
            "workflow_denied",
            workflow_action=purpose,
            message_id=message.message_id if message is not None else prepared_id,
            prepared_id=prepared_id,
            to=list(message.to) if message is not None else None,
            subject=message.subject if message is not None else None,
            body_fingerprint=(
                body_fingerprint(message.body) if message is not None else None
            ),
            reason=f"{type(exc).__name__}: {exc}",
            executed=False,
        )
        return str(entry.get("at"))

    def _report(
        self,
        status: str,
        action: str,
        *,
        transport_called: bool,
        message: OutgoingMessage,
        transport: dict[str, Any] | None = None,
        executed: bool = False,
        simulated: bool = True,
        reason: str | None = None,
        defense: dict[str, Any] | None = None,
    ) -> WorkflowReport:
        return WorkflowReport(
            status=status,
            action=action,
            mode=self.policy.mode.value,
            transport_called=transport_called,
            executed=executed,
            simulated=simulated,
            message=message.summary(),
            transport=transport,
            reason=reason,
            defense=defense,
        )

