"""Authorization and policy enforcement for outbound email actions.

Single server-side decision point for whether an outbound action (send or
draft) may proceed. The extension/UI never decides, and no optimizer can edit
any of these fields: see :data:`IMMUTABLE_POLICY_KEYS` (enforced by
``email_workflow.quality``).

Safety defaults:
* mode = ``simulation`` (nothing leaves the process),
* empty allowlists (no recipient is permitted without owner configuration),
* rate limit 5 outbound actions per hour,
* this in-memory policy stop is OFF, but every authorization flag is OFF and
  the durable global outbound stop defaults ON in the service state store,
* granted scopes = read-only Gmail. Read-only OAuth never authorizes writes;
  live sending requires the owner to grant ``gmail.send`` explicitly
  (documented in ``docs/AUTONOMOUS_EMAIL.md``).
"""
from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from email_workflow.modes import DEFAULT_MODE, OperatingMode, resolve_mode  # noqa: F401

__all__ = [
    "GMAIL_COMPOSE_SCOPE",
    "GMAIL_MODIFY_SCOPE",
    "GMAIL_READONLY_SCOPE",
    "GMAIL_SEND_SCOPE",
    "IMMUTABLE_POLICY_KEYS",
    "AuthorizationMissing",
    "ConfirmationRequired",
    "KillSwitchEngaged",
    "ModeNotAllowed",
    "Policy",
    "PolicyDenied",
    "PolicyError",
    "RateLimitExceeded",
    "RateLimiter",
    "RecipientNotAllowed",
]

# OAuth scopes. gmail_auth requests ONLY the readonly scope (fail-closed, see
# requested_scopes()); the write scopes below are documented requirements for
# a future owner-authorized transport and are NEVER requested by this repo.
GMAIL_READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
GMAIL_COMPOSE_SCOPE = "https://www.googleapis.com/auth/gmail.compose"
GMAIL_MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"

#: What the read-only analysis component may hold. Nothing else, ever.
READ_ONLY_GRANT: frozenset[str] = frozenset({GMAIL_READONLY_SCOPE})

#: Policy keys no optimizer, feedback loop, or CLI may ever change. Changing
#: any of these is an explicit account-owner action (construction-time only).
IMMUTABLE_POLICY_KEYS: frozenset[str] = frozenset(
    {
        "mode",
        "allowed_recipients",
        "allowed_domains",
        "rate_limit_per_hour",
        "kill_switch",
        "send_authorized",
        "draft_authorized",
        "granted_scopes",
        "require_confirmation_outside_allowlist",
        "require_confirmation_sensitive",
        "require_confirmation_live",
    }
)


class PolicyError(RuntimeError):
    """Base class for policy/authorization failures."""


class PolicyDenied(PolicyError):
    """An outbound action was refused by policy."""


class KillSwitchEngaged(PolicyDenied):
    """The kill switch is engaged: every outbound transport action is refused."""


class ModeNotAllowed(PolicyDenied):
    """The current operating mode does not allow this action."""


class AuthorizationMissing(PolicyDenied):
    """The account owner has not authorized this capability (flags/scopes)."""


class RecipientNotAllowed(PolicyDenied):
    """Recipient is outside the hard allowlist (confirmation never widens it)."""


class ConfirmationRequired(PolicyDenied):
    """Action touches an outside-allowlist recipient or sensitive content."""


class RateLimitExceeded(PolicyDenied):
    """Per-hour outbound rate limit reached."""


def _norm_addresses(values: Iterable[str]) -> frozenset[str]:
    return frozenset(str(v).strip().lower() for v in values if str(v).strip())


def _norm_domains(values: Iterable[str]) -> frozenset[str]:
    return frozenset(
        str(v).strip().lower().lstrip("@").rstrip(".") for v in values if str(v).strip()
    )


@dataclass(frozen=True)
class Policy:
    """Immutable snapshot of the outbound-email authorization policy.

    Construct a new instance (``dataclasses.replace``) to change anything;
    there are no setters, so a policy object can never mutate underneath the
    enforcement points.
    """

    mode: OperatingMode = DEFAULT_MODE
    allowed_recipients: frozenset[str] = frozenset()
    allowed_domains: frozenset[str] = frozenset()
    rate_limit_per_hour: int = 5
    kill_switch: bool = False
    #: Owner explicitly enabled live sending (mode must ALSO be authorized_automation).
    send_authorized: bool = False
    #: Owner explicitly enabled draft saving (mode must be draft/authorized_automation).
    draft_authorized: bool = False
    #: Scopes actually granted. Defaults to read-only; writes need owner action.
    granted_scopes: frozenset[str] = READ_ONLY_GRANT
    #: Retained for API compatibility. The recipient allowlist is a HARD
    #: boundary; confirmation never authorizes an outside recipient.
    require_confirmation_outside_allowlist: bool = True
    #: Sensitive/high-impact content requires an explicit per-call confirmation.
    require_confirmation_sensitive: bool = True
    #: EVERY live (real) action requires explicit per-call confirmation,
    #: regardless of allowlist or sensitivity tier. Enforced by the workflow
    #: service only when the transport can execute real actions; mock and
    #: simulation paths are unaffected (they can never act). Owner-level key:
    #: no optimizer or feedback loop may change it.
    require_confirmation_live: bool = True

    def __post_init__(self) -> None:
        object.__setattr__(self, "mode", resolve_mode(self.mode))
        object.__setattr__(self, "allowed_recipients", _norm_addresses(self.allowed_recipients))
        object.__setattr__(self, "allowed_domains", _norm_domains(self.allowed_domains))
        object.__setattr__(
            self,
            "granted_scopes",
            frozenset(str(s).strip() for s in self.granted_scopes if str(s).strip()),
        )
        if self.rate_limit_per_hour < 1:
            raise PolicyError("rate_limit_per_hour must be >= 1")

    # -- enforcement points (each raises a specific PolicyDenied subclass) ----

    def assert_kill_switch_off(self) -> None:
        if self.kill_switch:
            raise KillSwitchEngaged(
                "kill switch engaged: all outbound email actions are refused"
            )

    def assert_mode_allows(self, action: str) -> None:
        if action == "send":
            if self.mode is not OperatingMode.AUTHORIZED_AUTOMATION:
                raise ModeNotAllowed(
                    f"mode {self.mode.value!r} cannot send; sending requires "
                    "mode 'authorized_automation' set by the account owner"
                )
        elif action == "draft":
            if self.mode is OperatingMode.SIMULATION:
                raise ModeNotAllowed(
                    "mode 'simulation' does not save drafts; use mode 'draft'"
                )
        else:  # pragma: no cover - defensive
            raise PolicyError(f"unknown action {action!r}")

    def assert_send_authorized(self) -> None:
        if not self.send_authorized:
            raise AuthorizationMissing(
                "live sending is not authorized by the account owner "
                "(Policy.send_authorized=False)"
            )
        if GMAIL_SEND_SCOPE not in self.granted_scopes:
            raise AuthorizationMissing(
                "gmail.send scope is not granted; read-only OAuth never "
                "authorizes writes (see docs/AUTONOMOUS_EMAIL.md)"
            )

    def assert_draft_authorized(self) -> None:
        if not self.draft_authorized:
            raise AuthorizationMissing(
                "draft saving is not authorized by the account owner "
                "(Policy.draft_authorized=False)"
            )
        if not {GMAIL_COMPOSE_SCOPE, GMAIL_MODIFY_SCOPE} & self.granted_scopes:
            raise AuthorizationMissing(
                "gmail.compose (or gmail.modify) scope is not granted; "
                "read-only OAuth never authorizes drafts"
            )

    def assert_live_confirmation(self, *, confirmed: bool) -> None:
        """Every LIVE (real) action needs explicit per-action confirmation.

        Called by the workflow service only when the configured transport can
        execute real actions. The confirmation itself must come from the
        operator (the confirm flag after reviewing recipient, subject, and
        body) — never from an email or a model output.
        """
        if self.require_confirmation_live and not confirmed:
            raise ConfirmationRequired(
                "explicit confirmation is required for every live action; "
                "review the recipient, subject, and message body in the "
                "confirmation panel and submit with confirm=true"
            )


class RateLimiter:
    """Sliding-window per-hour limiter for outbound transport actions.

    With a persistent ``store`` the window is shared across service instances
    and backend restarts; without one this is an in-memory limiter for unit
    tests and isolated callers.
    """

    def __init__(
        self,
        limit_per_hour: int,
        *,
        clock: Callable[[], float] = time.time,
        store: object | None = None,
    ) -> None:
        if limit_per_hour < 1:
            raise PolicyError("limit_per_hour must be >= 1")
        self.limit = limit_per_hour
        self._clock = clock
        self._store = store
        self._events: list[float] = []

    def check_and_record(self) -> None:
        """Record one outbound action now, or raise :class:`RateLimitExceeded`."""
        if self._store is not None:
            self._store.record_rate_event(  # type: ignore[attr-defined]
                self.limit, action="outbound", clock=self._clock()
            )
            return
        now = self._clock()
        cutoff = now - 3600.0
        self._events = [t for t in self._events if t > cutoff]
        if len(self._events) >= self.limit:
            raise RateLimitExceeded(
                f"rate limit reached: {self.limit} outbound actions per hour"
            )
        self._events.append(now)

    def remaining(self) -> int:
        """Read-only view of the remaining slots in the current window."""
        if self._store is not None:
            return int(  # type: ignore[attr-defined]
                self._store.rate_remaining(self.limit, clock=self._clock())
            )
        now = self._clock()
        cutoff = now - 3600.0
        self._events = [t for t in self._events if t > cutoff]
        return max(0, self.limit - len(self._events))
