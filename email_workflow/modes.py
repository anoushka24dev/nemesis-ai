"""Operating modes for the autonomous email workflow (Phase 2, Objective 5).

The workflow never sends live email by default. Three explicit modes:

* ``simulation`` (default) — compose and inspect proposed messages. Nothing is
  saved to a draft folder, nothing is sent, and no transport object is called
  at all.
* ``draft`` — save a draft, but only when the account owner explicitly
  authorized drafts (``Policy.draft_authorized``) *and* granted the matching
  OAuth scope. Sending is still refused in this mode.
* ``authorized_automation`` — sending is possible only after the account owner
  both sets this mode and flips ``Policy.send_authorized`` AND granted the
  ``gmail.send`` scope. Every other safeguard (allowlist, confirmation, rate
  limit, kill switch, idempotency, audit) still applies.

Changing the mode is an account-owner action. It is deliberately not reachable
by any optimizer in this codebase: see ``policy.IMMUTABLE_POLICY_KEYS`` and
``email_workflow.quality`` (the quality hill-climber may only touch generation
settings).
"""
from __future__ import annotations

from enum import Enum

__all__ = ["DEFAULT_MODE", "ModeError", "OperatingMode", "resolve_mode"]

#: Canonical export: this is the ONLY place the enum class object is created.
#: Every other module in this package must import ``OperatingMode`` from here
#: (``from email_workflow.modes import OperatingMode``) so that identity
#: comparisons (``is`` / ``is not``) across modules stay stable. Do NOT
#: re-create or re-export this enum from any other module.

__all__ = [
    "DEFAULT_MODE",
    "ModeError",
    "OperatingMode",
    "resolve_mode",
]


class OperatingMode(str, Enum):
    """Explicit, owner-controlled operating modes. ``str`` mixin so comparisons
    with plain strings ("simulation") work in configs and tests."""

    SIMULATION = "simulation"
    DRAFT = "draft"
    AUTHORIZED_AUTOMATION = "authorized_automation"


#: Safe default: inspect-only. Never upgraded implicitly anywhere in this package.
DEFAULT_MODE = OperatingMode.SIMULATION


class ModeError(ValueError):
    """Unknown or invalid operating-mode string."""


def resolve_mode(value: object) -> OperatingMode:
    """Resolve ``None``/string/OperatingMode into a concrete mode.

    ``None`` or "" -> DEFAULT_MODE (simulation). Unknown values raise
    :class:`ModeError`; they never silently become a more permissive mode.
    """
    if value is None or value == "":
        return DEFAULT_MODE
    if isinstance(value, OperatingMode):
        return value
    try:
        return OperatingMode(str(value).strip().lower())
    except ValueError as exc:
        allowed = ", ".join(m.value for m in OperatingMode)
        raise ModeError(
            f"unknown operating mode {value!r}; expected one of: {allowed}"
        ) from exc
