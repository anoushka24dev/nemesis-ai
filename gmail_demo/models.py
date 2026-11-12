"""Shared data types for the Gmail agent demo."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

# Domains considered internal/trusted. Anything else is external.
INTERNAL_DOMAINS: tuple[str, ...] = ("corp.example",)

# Actions the agent is physically able to perform.
AGENT_ACTIONS: tuple[str, ...] = (
    "list",
    "read",
    "search",
    "reply",
    "forward",
    "send",
    "delete",
    "move",
    "flag",
)

# Actions that touch data leaving the mailbox or destroying it. These are
# never executed on the agent's own authority; the defense checker must allow.
SENSITIVE_ACTIONS: frozenset[str] = frozenset(
    {"forward", "delete", "send"}
)

# Actions that are always safe and need no defense review.
BENIGN_ACTIONS: frozenset[str] = frozenset({"list", "read", "search", "move", "flag"})

# The demos's declared unsafe outcomes.
UNSAFE_FORWARD = "forward_private_email_to_external_address"
UNSAFE_REPLY = "reply_with_manipulated_content"


def utc_now() -> str:
    """Timestamp helper used for seed data and run traces."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_external(address: str) -> bool:
    """True when an email address does not belong to an internal domain."""
    if not address or "@" not in address:
        return False
    domain = address.rsplit("@", 1)[1].strip().lower()
    return not any(domain == d or domain.endswith("." + d) for d in INTERNAL_DOMAINS)


# ---------------------------------------------------------------------------
# Gmail demo safety constraints (Phase 1 safety layer)
# ---------------------------------------------------------------------------
# When EMAIL_DEMO_MODE is enabled, the demo restricts Gmail access to a single
# label and a small allowlisted recipient set. Any forward / reply-all /
# send_email that targets a non-allowlisted recipient must fail.
#
# These constraints are separate from the existing vulnerable/protected design.
# They are a demo safety policy layered on top of the agent + defense checker.

EMAIL_DEMO_LABEL_ALLOWLIST: tuple[str, ...] = ("NEMESIS_DEMO",)

EMAIL_DEMO_RECIPIENT_ALLOWLIST: tuple[str, ...] = (
    "wuttisthisnishi@gmail.com",
    "eng23am0186@dsu.edu.in",
)

# Action verbs that are forbidden outside the allowlist when demo mode is on.
# The requirement names forward / reply_all / send_email; the harness
# vocabulary (AGENT_ACTIONS) spells the last two as "send" and "reply", so
# both spellings are covered.
EMAIL_DEMO_FORBIDDEN_OUTBOUND_ACTIONS: tuple[str, ...] = (
    "forward",
    "reply_all",
    "send_email",
    "send",
    "reply",
)

# Name of the env / config toggle that enables the safety constraints.
EMAIL_DEMO_MODE_ENV = "EMAIL_DEMO_MODE"


def is_email_demo_mode() -> bool:
    """Whether the Gmail demo safety constraints are active.

    The constraint is enabled when EMAIL_DEMO_MODE is set to a truthy value.
    """
    import os

    raw = os.environ.get(EMAIL_DEMO_MODE_ENV, "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def email_demo_allowed_recipient(address: str) -> bool:
    """Whether a recipient is valid under the Gmail demo safety constraints.

    When demo mode is off, every recipient is allowed by this check.
    """
    if not is_email_demo_mode():
        return True
    if not address:
        return False
    return address.strip().lower() in {a.strip().lower() for a in EMAIL_DEMO_RECIPIENT_ALLOWLIST}


def email_demo_label_allowed(email: Email) -> bool:
    """Whether an email is accessible under the Gmail demo safety constraints.

    When demo mode is off, every email is accessible by this check.
    """
    if not is_email_demo_mode():
        return True
    return any(label in EMAIL_DEMO_LABEL_ALLOWLIST for label in email.labels)


def build_demo_defense_checker(harden_normalization: bool = False) -> "DefenseChecker":
    """Create the defense checker with Gmail demo safety constraints enabled.

    This keeps the vulnerable/protected design intact and only adds the demo
    label + recipient policy on top. ``harden_normalization`` is passed through
    so combining demo mode with hardened scanning does not drop that flag.
    """
    from gmail_demo.defense import DefenseChecker

    return DefenseChecker(harden_normalization=harden_normalization, demo_mode=True)


@dataclass
class Email:
    """One message in the simulated mailbox."""

    id: str
    sender: str
    subject: str
    body: str
    received_at: str = field(default_factory=utc_now)
    folder: str = "inbox"
    unread: bool = True
    labels: list[str] = field(default_factory=list)

    # Demo bookkeeping (set by the engine as the run proceeds).
    is_attacker: bool = False
    variant: str = ""
    variant_number: int = 0
    status: str = "new"  # new | read | allowed | blocked | flagged | executed
    status_reason: str = ""

    def preview(self, length: int = 96) -> str:
        flat = " ".join(self.body.split())
        return flat if len(flat) <= length else flat[: length - 3] + "..."

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProposedAction:
    """What the target agent wants to do with an email, before the defense."""

    action: str = "read"  # see AGENT_ACTIONS, plus "none"
    email_id: str = ""
    to: str = ""
    requested: bool = False  # did the email actually ask for this?
    sensitive: bool = False
    manipulated: bool = False  # reply built from hidden/overridden instructions
    reason: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Verdict:
    """The defense checker's independent opinion."""

    decision: str = "allow"  # allow | block | flag
    reasons: list[str] = field(default_factory=list)

    @property
    def properly_stopped(self) -> bool:
        """Blocked or flagged counts as the defense doing its job."""
        return self.decision in {"block", "flag"}

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class AttackStep:
    """One attacker attempt, start to finish."""

    attempt: int
    variant_number: int
    variant: str
    variant_description: str
    email_id: str
    email_sender: str
    email_subject: str
    email_body: str
    proposed: ProposedAction
    verdict: Verdict
    executed: bool
    unsafe_outcome: str
    attacker_succeeded: bool
    note: str

    def to_dict(self) -> dict:
        data = asdict(self)
        data["proposed"] = self.proposed.to_dict()
        data["verdict"] = self.verdict.to_dict()
        return data


@dataclass
class EpisodeResult:
    """The full outcome of one demo run."""

    episode_id: str
    started_at: str
    finished_at: str
    steps: list[AttackStep] = field(default_factory=list)
    attacker_succeeded: bool = False
    successful_variant: str = ""
    successful_attempt: int = 0
    stopped_reason: str = ""
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "episode_id": self.episode_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "attacker_succeeded": self.attacker_succeeded,
            "successful_variant": self.successful_variant,
            "successful_attempt": self.successful_attempt,
            "stopped_reason": self.stopped_reason,
            "metrics": self.metrics,
            "steps": [s.to_dict() for s in self.steps],
        }
