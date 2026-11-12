"""Autonomous email workflow (Phase 2, Objective 5) — safe, testable increment.

This package is deliberately separate from the read-only analysis component
(``gmail_auth`` / ``backend/stage_b``). Nothing here imports the Gmail API and
no concrete transport contacts a network: :class:`MockTransport` simulates
draft/send in memory, and :class:`LiveGmailTransport` refuses unconditionally
until the account owner wires it under explicit scopes and policy
(``docs/AUTONOMOUS_EMAIL.md``).

Default operating mode is ``simulation``: messages can be composed and
inspected, but no transport object is called at all. Promotion to ``draft``
or ``authorized_automation`` requires explicit owner configuration of
``Policy`` (flags + OAuth scopes), and every action passes kill switch,
allowlist/confirmation, sensitive-content confirmation, rate limiting,
idempotency, and append-only audit on the way to the transport. "sent" is
reported only when a transport confirms real execution.
"""
from __future__ import annotations

from email_workflow.audit import AuditLog, body_fingerprint
from email_workflow.compose import (
    KNOB_SCHEMA,
    GenerationSettings,
    OutgoingMessage,
    compose_new,
    compose_reply,
    message_from_summary,
)
from email_workflow.modes import DEFAULT_MODE, OperatingMode, resolve_mode  # noqa: F401
from email_workflow.outgoing import (
    DefenseBlocked,
    OutgoingDefense,
    OutgoingReviewRequired,
)
from email_workflow.policy import (
    GMAIL_COMPOSE_SCOPE,
    GMAIL_READONLY_SCOPE,
    GMAIL_SEND_SCOPE,
    IMMUTABLE_POLICY_KEYS,
    AuthorizationMissing,
    ConfirmationRequired,
    KillSwitchEngaged,
    ModeNotAllowed,
    Policy,
    PolicyDenied,
    RateLimiter,
    RateLimitExceeded,
    RecipientNotAllowed,
)
from email_workflow.service import EmailWorkflowService, WorkflowReport
from email_workflow.transport import (
    LiveGmailTransport,
    MockTransport,
    TransportError,
    TransportResult,
    TransportUnavailableError,
)

__all__ = [
    "DEFAULT_MODE",
    "GMAIL_COMPOSE_SCOPE",
    "GMAIL_READONLY_SCOPE",
    "GMAIL_SEND_SCOPE",
    "IMMUTABLE_POLICY_KEYS",
    "KNOB_SCHEMA",
    "AuditLog",
    "AuthorizationMissing",
    "ConfirmationRequired",
    "DefenseBlocked",
    "EmailWorkflowService",
    "GenerationSettings",
    "KillSwitchEngaged",
    "LiveGmailTransport",
    "MockTransport",
    "ModeNotAllowed",
    "OperatingMode",
    "OutgoingDefense",
    "OutgoingMessage",
    "OutgoingReviewRequired",
    "Policy",
    "PolicyDenied",
    "RateLimitExceeded",
    "RateLimiter",
    "RecipientNotAllowed",
    "TransportError",
    "TransportResult",
    "TransportUnavailableError",
    "WorkflowReport",
    "body_fingerprint",
    "compose_new",
    "compose_reply",
    "message_from_summary",
    "resolve_mode",
]
