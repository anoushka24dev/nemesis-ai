"""Recipient, thread, and header validation for outbound messages.

All inputs here are untrusted (they originate from email content or user
fields). Nothing in this module executes instructions found in that content:
it only checks shapes, allowlists, and confirmation state.

Reply integrity: a reply's recipient must be exactly the sender of the source
thread message, and must additionally pass the policy allowlist (or carry an
explicit confirmation). Thread ids must look like Gmail ids and nothing else.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from email_workflow.policy import (
    Policy,
    RecipientNotAllowed,
)

__all__ = [
    "MessageValidationError",
    "extract_address",
    "requires_confirmation",
    "sanitize_body",
    "sanitize_header",
    "thread_participants",
    "validate_address",
    "validate_recipients",
    "validate_reply_target",
    "validate_thread_id",
]

_ADDRESS_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[A-Za-z]{2,}$")
_ANGLE_RE = re.compile(r"<([^<>]+)>")
#: CR, LF, NUL and other control characters: header-injection vectors.
_CONTROL_RE = re.compile(r"[\r\x00-\x1f\x7f]")
THREAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")

#: Content whose presence makes a message high-impact: explicit confirmation
#: required even for allowlisted recipients (policy.require_confirmation_sensitive).
_SENSITIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(wire|wiring|wire transfer|bank account|account number|routing number|iban|swift)\b", re.IGNORECASE),
    re.compile(r"\b(password|passphrase|credentials|secret key|api key)\b", re.IGNORECASE),
    re.compile(r"\b(salary|payroll|severance|bonus amount)\b", re.IGNORECASE),
    re.compile(r"\b(ssn|social security|aadhaar|aadhar|passport number|pan number|date of birth)\b", re.IGNORECASE),
    re.compile(r"\b(confidential|settlement|non-disclosure|nda)\b", re.IGNORECASE),
)


class MessageValidationError(RuntimeError):
    """A message field failed shape/safety validation."""


def extract_address(display: str) -> str:
    """Pull the bare address out of ``Name <addr@x>`` or a plain address."""
    raw = str(display or "")
    m = _ANGLE_RE.search(raw)
    addr = m.group(1) if m else raw
    return addr.strip().strip('"').lower()


def validate_address(addr: str) -> str:
    """Normalize and shape-check one address; refuse control characters."""
    if addr is None:
        raise MessageValidationError("address is required")
    raw = str(addr)
    if _CONTROL_RE.search(raw):
        raise MessageValidationError(
            "control characters (CR/LF/NUL) refused in address"
        )
    norm = raw.strip().lower()
    if not _ADDRESS_RE.match(norm):
        raise MessageValidationError(f"invalid email address: {addr!r}")
    return norm


def validate_recipients(
    addrs: Iterable[str],
    policy: Policy,
    *,
    confirmed: bool = False,
) -> tuple[str, ...]:
    """Hard allowlist/domain check for every outbound recipient.

    * In ``allowed_recipients`` or ``allowed_domains``: allowed.
    * Otherwise: always refused with :class:`RecipientNotAllowed`.

    ``confirmed`` is retained for call-site compatibility, but confirmation
    never widens this boundary. Confirmation can satisfy separate sensitive or
    live-action requirements; it cannot authorize a recipient.
    """
    normalized = tuple(validate_address(a) for a in addrs)
    if not normalized:
        raise MessageValidationError("at least one recipient is required")
    out: list[str] = []
    for addr in normalized:
        domain = addr.rsplit("@", 1)[1]
        if addr in policy.allowed_recipients or domain in policy.allowed_domains:
            out.append(addr)
            continue
        raise RecipientNotAllowed(
            f"recipient {addr} is outside the hard allowlist; confirmation "
            "does not authorize recipients"
        )
    return tuple(out)


def validate_thread_id(thread_id: str | None) -> str | None:
    """Thread ids must be opaque Gmail-style tokens (no paths, no CRLF)."""
    if thread_id is None:
        return None
    tid = str(thread_id)
    if not THREAD_ID_RE.match(tid):
        raise MessageValidationError(
            "invalid thread id: expected 1-128 chars of [A-Za-z0-9_-]"
        )
    return tid


def sanitize_header(value: str, *, field_name: str, max_len: int) -> str:
    """Headers must not contain control characters (header injection)."""
    raw = str(value or "")
    if _CONTROL_RE.search(raw):
        raise MessageValidationError(
            f"control characters (CR/LF/NUL) refused in {field_name}"
        )
    norm = raw.strip()
    if len(norm) > max_len:
        raise MessageValidationError(f"{field_name} exceeds {max_len} chars")
    return norm


def sanitize_body(value: str, *, max_len: int) -> str:
    """Bodies may contain newlines, but never CR/NUL/control chars; capped."""
    raw = str(value or "").replace("\r", "").replace("\x00", "")
    cleaned = "".join(ch for ch in raw if ch == "\n" or ch == "\t" or not _CONTROL_RE.match(ch))
    if len(cleaned) > max_len:
        raise MessageValidationError(f"body exceeds {max_len} chars")
    return cleaned.strip()


def thread_participants(incoming) -> frozenset[str]:
    """The addresses a reply to ``incoming`` may target (currently: sender)."""
    return frozenset({extract_address(getattr(incoming, "sender", ""))})


def validate_reply_target(
    incoming,
    to_addrs: Iterable[str],
    policy: Policy,
    *,
    confirmed: bool = False,
) -> tuple[str, ...]:
    """A reply may only go to the sender of the source thread message.

    The reply target is derived from the thread itself, then checked against
    the policy allowlist. Re-targeting a reply at some other address is not a
    reply and is refused before any transport is involved.
    """
    normalized = tuple(validate_address(a) for a in to_addrs)
    participants = {a for a in thread_participants(incoming) if a}
    if not participants:
        raise MessageValidationError("source message has no parseable sender")
    if set(normalized) != participants:
        raise MessageValidationError(
            "reply recipient(s) must match the source thread sender exactly"
        )
    return validate_recipients(normalized, policy, confirmed=confirmed)


def requires_confirmation(subject: str, body: str) -> bool:
    """True when a message is sensitive/high-impact (owner confirmation)."""
    text = f"{subject or ''}\n{body or ''}"
    return any(p.search(text) for p in _SENSITIVE_PATTERNS)

