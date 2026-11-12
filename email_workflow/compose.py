"""Deterministic message composition for replies and new messages.

Thread content is untrusted data. Composed bodies quote only the *subject*
of the incoming message (sanitized, capped) and never interpolate the
incoming body, never follow instructions found in either, and never widen
recipients. Composition is deterministic (templates keyed by
:class:`GenerationSettings`) so quality metrics and tests are reproducible;
no LLM is involved and no network is touched.

The four generation knobs (``tone``, ``length``, ``greeting``, ``sign_off``)
are the ONLY values the quality hill-climber in ``email_workflow.quality``
may adjust. They carry no authority: recipient lists, modes, scopes, and rate
limits live in :mod:`email_workflow.policy` and are unreachable from there.
"""
from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any

from email_workflow.modes import DEFAULT_MODE, OperatingMode
from email_workflow.validate import (
    extract_address,
    sanitize_body,
    sanitize_header,
    validate_address,
    validate_thread_id,
)

__all__ = [
    "KNOB_SCHEMA",
    "MAX_BODY_CHARS",
    "MAX_SUBJECT_CHARS",
    "GenerationSettings",
    "OutgoingMessage",
    "compose_new",
    "compose_reply",
    "message_from_summary",
]


def message_from_summary(data: Mapping[str, Any]) -> OutgoingMessage:
    """Module-level alias for :meth:`OutgoingMessage.from_summary`."""
    return OutgoingMessage.from_summary(data)

MAX_SUBJECT_CHARS = 200
MAX_BODY_CHARS = 5_000
MAX_TO_RECIPIENTS = 10

TONES: tuple[str, ...] = ("neutral", "formal", "friendly")
LENGTHS: tuple[str, ...] = ("concise", "normal")

#: The complete optimizable surface. Anything not in here is not a knob.
KNOB_SCHEMA: dict[str, tuple[Any, ...]] = {
    "tone": TONES,
    "length": LENGTHS,
    "greeting": (True, False),
    "sign_off": (True, False),
}

_GREETINGS: dict[str, str] = {
    "formal": "Dear {name},",
    "neutral": "Hello {name},",
    "friendly": "Hi {name},",
}
_SIGN_OFFS: dict[str, str] = {
    "formal": "Kind regards,",
    "neutral": "Best,",
    "friendly": "Thanks,",
}
#: The agent's own identity in sign-offs (no real person is impersonated).
_AGENT_NAME = "Nemesis assistant"

_RE_PREFIX_RE = re.compile(r"^\s*(?:(?:re|aw|fw)\s*:\s*)+", re.IGNORECASE)


@dataclass(frozen=True)
class GenerationSettings:
    """Bounded, auditable message-generation knobs (the optimizer's universe)."""

    tone: str = "neutral"
    length: str = "normal"
    greeting: bool = True
    sign_off: bool = True

    def __post_init__(self) -> None:
        if self.tone not in TONES:
            raise ValueError(f"tone must be one of {TONES}, got {self.tone!r}")
        if self.length not in LENGTHS:
            raise ValueError(f"length must be one of {LENGTHS}, got {self.length!r}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "tone": self.tone,
            "length": self.length,
            "greeting": bool(self.greeting),
            "sign_off": bool(self.sign_off),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> GenerationSettings:
        unknown = set(data) - set(KNOB_SCHEMA)
        if unknown:
            raise ValueError(
                f"unknown generation knobs: {sorted(unknown)}; only "
                f"{sorted(KNOB_SCHEMA)} may be tuned"
            )
        return cls(**{k: data[k] for k in KNOB_SCHEMA if k in data})

    def with_knob(self, knob: str, value: Any) -> GenerationSettings:
        if knob not in KNOB_SCHEMA:
            raise ValueError(f"{knob!r} is not an optimizable knob")
        if value not in KNOB_SCHEMA[knob]:
            raise ValueError(f"{knob}={value!r} outside {KNOB_SCHEMA[knob]}")
        return replace(self, **{knob: value})


@dataclass(frozen=True)
class OutgoingMessage:
    """A composed, validated message. Still inert: nothing has been sent."""

    message_id: str
    kind: str  # "reply" | "new"
    to: tuple[str, ...]
    subject: str
    body: str
    settings: GenerationSettings
    cc: tuple[str, ...] = ()
    bcc: tuple[str, ...] = ()
    created_mode: OperatingMode = DEFAULT_MODE
    thread_id: str | None = None
    in_reply_to: str | None = None
    references: tuple[str, ...] = ()
    source_email_id: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    @classmethod
    def from_summary(cls, data: Mapping[str, Any]) -> "OutgoingMessage":
        """Rebuild a message from an operator-supplied summary dict.

        The input is UNTRUSTED (it may arrive via the backend API from the
        extension), so every field is re-sanitized with the same controls used
        at compose time: control characters refused, lengths capped, kind
        constrained, settings validated against the knob schema. The
        ``created_mode`` field of the summary is ignored — the workflow
        service's policy decides the mode, never the caller.
        """
        if not isinstance(data, Mapping):
            raise ValueError("message payload must be an object")
        kind = str(data.get("kind") or "")
        if kind not in ("new", "reply"):
            raise ValueError(f"unknown message kind: {kind!r}")
        raw_to = data.get("to") or ()
        if isinstance(raw_to, str):
            raw_to = (raw_to,)
        to = tuple(validate_address(a) for a in raw_to)[:MAX_TO_RECIPIENTS]
        if not to:
            raise ValueError("message requires at least one recipient")
        raw_cc = data.get("cc") or ()
        if isinstance(raw_cc, str):
            raw_cc = (raw_cc,)
        raw_bcc = data.get("bcc") or ()
        if isinstance(raw_bcc, str):
            raw_bcc = (raw_bcc,)
        cc = tuple(validate_address(a) for a in raw_cc)[:MAX_TO_RECIPIENTS]
        bcc = tuple(validate_address(a) for a in raw_bcc)[:MAX_TO_RECIPIENTS]
        subject = sanitize_header(
            str(data.get("subject") or ""),
            field_name="subject",
            max_len=MAX_SUBJECT_CHARS,
        )
        body = sanitize_body(
            str(data.get("body") or ""), max_len=MAX_BODY_CHARS
        )
        if not body:
            raise ValueError("message requires a non-empty body")
        settings = GenerationSettings.from_dict(data.get("settings") or {})
        thread_id = data.get("thread_id")
        if thread_id is not None:
            thread_id = validate_thread_id(str(thread_id))
        raw_refs = data.get("references") or ()
        if isinstance(raw_refs, str):
            raw_refs = (raw_refs,)
        references = tuple(validate_thread_id(str(r)) for r in raw_refs if r)
        return cls(
            message_id=str(data.get("message_id") or uuid.uuid4().hex),
            kind=kind,
            to=to,
            cc=cc,
            bcc=bcc,
            subject=subject,
            body=body,
            settings=settings,
            thread_id=thread_id,
            in_reply_to=str(data["in_reply_to"]) if data.get("in_reply_to") else None,
            references=references,
            source_email_id=(
                str(data["source_email_id"]) if data.get("source_email_id") else None
            ),
        )

    def summary(self) -> dict[str, Any]:
        """Operator-facing summary (includes the body: this IS the artifact
        being inspected in simulation mode; the audit log never stores it)."""
        return {
            "message_id": self.message_id,
            "kind": self.kind,
            "to": list(self.to),
            "cc": list(self.cc),
            "bcc": list(self.bcc),
            "subject": self.subject,
            "body": self.body,
            "thread_id": self.thread_id,
            "in_reply_to": self.in_reply_to,
            "references": list(self.references),
            "source_email_id": self.source_email_id,
            "settings": self.settings.as_dict(),
            "created_mode": self.created_mode.value,
        }

    def canonical_dict(self) -> dict[str, Any]:
        """All fields that determine the outgoing message, for integrity binding.

        ``created_at`` is local bookkeeping and does not affect what leaves the
        process, so it is excluded; every recipient, header, thread reference,
        body, and generation setting is included.
        """
        return {
            "message_id": self.message_id,
            "kind": self.kind,
            "to": list(self.to),
            "cc": list(self.cc),
            "bcc": list(self.bcc),
            "subject": self.subject,
            "body": self.body,
            "thread_id": self.thread_id,
            "in_reply_to": self.in_reply_to,
            "references": list(self.references),
            "source_email_id": self.source_email_id,
            "settings": self.settings.as_dict(),
        }


def _display_name(sender: str) -> str:
    raw = str(sender or "").strip()
    if "<" in raw:
        raw = raw.split("<", 1)[0]
    raw = raw.strip().strip('"').strip()
    if not raw or "@" in raw:
        local = extract_address(sender).split("@", 1)[0] if "@" in sender else "there"
        raw = local or "there"
    cleaned = re.sub(r"[^\w .'-]", "", raw).strip()
    return (cleaned or "there")[:40]


def _reply_subject(subject: str) -> str:
    base = _RE_PREFIX_RE.sub("", str(subject or "")).strip() or "(no subject)"
    # Control characters (CRLF header-injection vectors) are refused outright,
    # BEFORE any whitespace normalization could hide them.
    base = sanitize_header(base, field_name="subject", max_len=MAX_SUBJECT_CHARS)
    base = re.sub(r"\s+", " ", base)
    return sanitize_header(
        f"Re: {base}", field_name="subject", max_len=MAX_SUBJECT_CHARS
    )


def _render_body(settings: GenerationSettings, name: str, subject: str) -> str:
    """Template render. Quotes only the (sanitized) subject as data."""
    lines: list[str] = []
    if settings.greeting:
        lines.append(_GREETINGS[settings.tone].format(name=name))
        lines.append("")
    if settings.length == "concise":
        lines.append(f"Thank you for your message about: {subject}.")
    else:
        lines.append(f"Thank you for your message about: {subject}.")
        lines.append("")
        lines.append(
            "I am writing to confirm receipt and will follow up with details if needed."
        )
    if settings.sign_off:
        lines.append("")
        lines.append(_SIGN_OFFS[settings.tone])
        lines.append(_AGENT_NAME)
    return sanitize_body("\n".join(lines), max_len=MAX_BODY_CHARS)


def compose_reply(
    incoming,
    *,
    settings: GenerationSettings | None = None,
    thread_id: str | None = None,
    created_mode: OperatingMode = DEFAULT_MODE,
    message_id: str | None = None,
) -> OutgoingMessage:
    """Compose a deterministic reply to ``incoming`` (a ``gmail_demo.models.Email``).

    The recipient is derived from the source message's sender; the subject is
    the source subject with reply prefixes collapsed; the body quotes only the
    subject line. Instructions inside the incoming body are never followed and
    never copied into the reply.
    """
    settings = settings or GenerationSettings()
    sender = extract_address(getattr(incoming, "sender", ""))
    name = _display_name(getattr(incoming, "sender", ""))
    subject = _reply_subject(getattr(incoming, "subject", ""))
    body = _render_body(settings, name, subject)
    msg_id = message_id or uuid.uuid4().hex
    return OutgoingMessage(
        message_id=msg_id,
        kind="reply",
        to=(sender,),
        subject=subject,
        body=body,
        settings=settings,
        created_mode=created_mode,
        thread_id=thread_id,
        in_reply_to=str(getattr(incoming, "id", "") or "") or None,
        references=(str(getattr(incoming, "id", "") or ""),)
        if getattr(incoming, "id", None)
        else (),
        source_email_id=str(getattr(incoming, "id", "") or "") or None,
    )


def compose_new(
    to: tuple[str, ...] | list[str],
    subject: str,
    body: str,
    *,
    settings: GenerationSettings | None = None,
    created_mode: OperatingMode = DEFAULT_MODE,
    message_id: str | None = None,
    cc: tuple[str, ...] | list[str] = (),
    bcc: tuple[str, ...] | list[str] = (),
) -> OutgoingMessage:
    """Compose a brand-new (owner-authored content) message.

    ``subject``/``body`` come from the account owner, not from email content,
    but are still sanitized: no control characters, capped length.
    """
    settings = settings or GenerationSettings()
    norm_to = tuple(str(a).strip().lower() for a in to)[:MAX_TO_RECIPIENTS]
    if not norm_to:
        raise ValueError("compose_new requires at least one recipient")
    norm_cc = tuple(validate_address(a) for a in cc)[:MAX_TO_RECIPIENTS]
    norm_bcc = tuple(validate_address(a) for a in bcc)[:MAX_TO_RECIPIENTS]
    subj = sanitize_header(subject, field_name="subject", max_len=MAX_SUBJECT_CHARS)
    clean = sanitize_body(body, max_len=MAX_BODY_CHARS)
    if not clean:
        raise ValueError("compose_new requires a non-empty body")
    return OutgoingMessage(
        message_id=message_id or uuid.uuid4().hex,
        kind="new",
        to=norm_to,
        cc=norm_cc,
        bcc=norm_bcc,
        subject=subj,
        body=clean,
        settings=settings,
        created_mode=created_mode,
    )
