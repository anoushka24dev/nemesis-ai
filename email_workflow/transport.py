"""Email transports. Mock first; the live Gmail transport intentionally refuses.

Contract: a transport result's ``executed`` flag is the ONLY evidence that a
real-world action happened. Callers must never report "sent" without it.

* :class:`MockTransport` simulates compose/draft/reply/send entirely in
  memory: no network, no real recipients, results always
  ``simulated=True, executed=False``. It supports injected failures (for
  error-path tests) and idempotency keys (duplicate-send prevention).
* :class:`LiveGmailTransport` is a deliberate placeholder. Every method raises
  :class:`TransportUnavailableError`: this phase does NOT implement real
  sending. Wiring it requires the account owner to grant ``gmail.send`` /
  ``gmail.compose`` and to configure policy (docs/AUTONOMOUS_EMAIL.md);
  read-only OAuth never authorizes writes.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any

from email_workflow.compose import OutgoingMessage

__all__ = [
    "LiveGmailTransport",
    "MockTransport",
    "TransportError",
    "TransportResult",
    "TransportUnavailableError",
    "idempotency_key",
]


class TransportError(RuntimeError):
    """A transport failed to perform an action.

    Optional safe diagnostic fields let the service distinguish a definite
    pre-submission failure from an ambiguous one without exposing response
    bodies, credentials, or message content.
    """

    def __init__(
        self,
        message: str,
        *,
        uncertain: bool = False,
        http_status: int | None = None,
        api_reason: str | None = None,
    ) -> None:
        super().__init__(message)
        self.uncertain = bool(uncertain)
        self.http_status = http_status
        self.api_reason = api_reason


class TransportUnavailableError(TransportError):
    """The requested transport is not wired and refuses to act."""


@dataclass(frozen=True)
class TransportResult:
    ok: bool
    transport: str
    action: str  # "send" | "draft"
    record_id: str
    simulated: bool
    executed: bool
    duplicate: bool = False
    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    #: Gmail identifiers, when the transport has them. ``record_id`` remains
    #: the backwards-compatible primary identifier.
    message_id: str = ""
    thread_id: str = ""


def idempotency_key(message: OutgoingMessage, *, action: str) -> str:
    """Content-derived key: same action on identical content dedupes."""
    raw = "|".join(
        [
            action,
            message.kind,
            message.thread_id or "",
            ",".join(message.to),
            ",".join(message.cc),
            ",".join(message.bcc),
            message.in_reply_to or "",
            ",".join(message.references),
            message.subject,
            message.body,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class MockTransport:
    """In-memory transport used by tests and by simulation-adjacent flows.

    It NEVER contacts a network or a real recipient. ``fail_next=True``
    injects one deterministic failure (for error-path coverage).
    """

    name = "mock"
    #: Cannot execute a real action; the per-live-action confirmation gate
    #: (email_workflow.service) does not apply to it.
    executes_live_actions = False

    def __init__(self, *, fail_next: bool = False) -> None:
        self.fail_next = fail_next
        self.sent: list[dict[str, Any]] = []
        self.drafts: list[dict[str, Any]] = []
        self.calls: list[tuple[str, str]] = []  # (action, record_id)
        self._idem: dict[str, str] = {}

    # -- internals ----------------------------------------------------------

    def _record(
        self, message: OutgoingMessage, *, action: str, key: str
    ) -> TransportResult:
        dup = self._idem.get(f"{action}:{key}")
        if dup is not None:
            return TransportResult(
                ok=True,
                transport=self.name,
                action=action,
                record_id=dup,
                simulated=True,
                executed=False,
                duplicate=True,
                detail={
                    "note": "idempotent replay: identical message already "
                    f"{action}ed in this transport; nothing was {action}ed again"
                },
            )
        if self.fail_next:
            self.fail_next = False
            return TransportResult(
                ok=False,
                transport=self.name,
                action=action,
                record_id="",
                simulated=True,
                executed=False,
                error=f"mock {action} failure (injected)",
            )
        record_id = f"mock-{action}-{len(self.sent) + len(self.drafts) + 1:04d}"
        record = {
            "record_id": record_id,
            "action": action,
            "to": list(message.to),
            "subject": message.subject,
            "message_id": message.message_id,
            "thread_id": message.thread_id,
            "gmail_message_id": record_id,
            "gmail_thread_id": message.thread_id or "",
        }
        (self.sent if action == "send" else self.drafts).append(record)
        self.calls.append((action, record_id))
        self._idem[f"{action}:{key}"] = record_id
        return TransportResult(
            ok=True,
            transport=self.name,
            action=action,
            record_id=record_id,
            # A mock delivery is a simulation: nothing left this process.
            simulated=True,
            executed=False,
            detail={"note": f"mock {action} simulated; no real recipient was contacted"},
            message_id=record_id,
            thread_id=message.thread_id or "",
        )

    # -- public API ---------------------------------------------------------

    def send(self, message: OutgoingMessage, *, key: str) -> TransportResult:
        return self._record(message, action="send", key=key)

    def create_draft(self, message: OutgoingMessage, *, key: str) -> TransportResult:
        return self._record(message, action="draft", key=key)

    def reset(self) -> None:
        self.sent.clear()
        self.drafts.clear()
        self.calls.clear()
        self._idem.clear()


class LiveGmailTransport:
    """Real Gmail send/draft transport — deliberately NOT wired in this phase.

    Every method raises. There is no code path in this repository that can
    transmit an email to a real recipient. To ever enable one, the account
    owner must: (1) create a separate OAuth client requesting ``gmail.send``
    (sending) and/or ``gmail.compose`` (drafts) *in addition to* readonly,
    (2) set ``Policy.send_authorized`` / ``Policy.draft_authorized`` and the
    matching mode, (3) configure recipient allowlists and rate limits, and
    (4) implement ``send``/``create_draft`` here against
    ``users.messages.send`` / ``users.drafts.create``. See
    ``docs/AUTONOMOUS_EMAIL.md``. Read-only Gmail OAuth never authorizes
    writes, and this class exists so that fact stays enforceable, not just
    documented.
    """

    name = "gmail-live"
    #: A placeholder cannot execute anything either; the real
    #: ``gmail_live.GmailLiveTransport`` sets this True, which is what makes
    #: the unconditional per-action confirmation gate apply there.
    executes_live_actions = False

    _REFUSAL = (
        "live Gmail transport is not implemented: this repository cannot send "
        "or draft real email. Enabling it requires explicit account-owner "
        "authorization (gmail.send / gmail.compose scopes, mode "
        "'authorized_automation', allowlists, rate limits) per "
        "docs/AUTONOMOUS_EMAIL.md"
    )

    def send(self, message: OutgoingMessage, *, key: str) -> TransportResult:
        raise TransportUnavailableError(self._REFUSAL)

    def create_draft(self, message: OutgoingMessage, *, key: str) -> TransportResult:
        raise TransportUnavailableError(self._REFUSAL)
