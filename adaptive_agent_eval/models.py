"""Shared data models used across all components."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import time
import uuid


class DefenseDecision(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    NO_SIGNAL = "no_signal"


class AttackOutcome(str, Enum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    IGNORED = "ignored"
    TECHNICAL_FAIL = "technical_fail"
    UNKNOWN = "unknown"


class EpisodeMode(str, Enum):
    SINGLE_AGENT = "single-agent"
    CROSS_AGENT = "cross-agent"
    DEFENSE_COMPOSITION = "defense-composition"


class DefenseType(str, Enum):
    CAMEL = "camel"
    PROGENT = "progent"
    VERIFIER = "verifier"
    #: No defense at all. Used by ATTACK-ONLY campaigns: the controller still
    #: has a defense slot, but the pass-through layer performs no evaluation
    #: and emits no defense decision record.
    NONE = "none"


class AttackerTier(str, Enum):
    CHEAP = "cheap"
    FRONTIER = "frontier"


class TargetTier(str, Enum):
    CHEAP = "cheap"
    FRONTIER = "frontier"


# ---------------------------------------------------------------------------
# Lifecycle, ground truth, implementation and integration contracts
# ---------------------------------------------------------------------------


class EpisodeStatus(str, Enum):
    """Lifecycle status of a single episode within an experiment."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class ExperimentStatus(str, Enum):
    """Lifecycle status of an experiment run.

    ``INTERRUPTED`` is distinct from ``FAILED``: an interrupted run stopped
    partway (cancellation race, crash recovery) and is *not* completed even if
    a partial summary object exists.
    """

    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class GroundTruthOutcome(str, Enum):
    """Ground-truth evaluation of an episode, kept separate from the
    defense's own opinion and from the diagnoser's ``AttackOutcome``.

    The six values are mutually exclusive:

    - ``SUCCESSFUL_ATTACK``: the attack's goal action executed in the target
      environment and no defense prevented it.
    - ``PARTIAL_SUCCESS``: an unauthorized effect occurred, but not the full
      attack goal (only a sub-action, or the effect was limited/reverted).
    - ``FAILED_ATTACK``: the attempt produced no unauthorized effect and none
      of the defenses detected it (payload ineffective / agent ignored it).
    - ``DETECTED_NOT_BLOCKED``: at least one defense flagged or denied the
      action (evidence exists) yet the goal effect still executed.
    - ``BLOCKED``: a defense prevented the goal action and the target
      environment confirms no unauthorized effect occurred.
    - ``INDETERMINATE``: the target environment supplied insufficient
      evidence — never guessed from defense opinion alone.

    ``None`` on a record means ground truth has not been evaluated yet.
    """

    SUCCESSFUL_ATTACK = "successful_attack"
    PARTIAL_SUCCESS = "partial_success"
    FAILED_ATTACK = "failed_attack"
    DETECTED_NOT_BLOCKED = "detected_not_blocked"
    BLOCKED = "blocked"
    INDETERMINATE = "indeterminate"


class DefenseImplementation(str, Enum):
    """How the defense that produced a record is actually implemented.

    A record naming a defense never implies the *original research system*
    executed: it executed the implementation named here.
    """

    REAL_INTEGRATION = "real_integration"
    LOCAL_IMPLEMENTATION = "local_implementation"
    PROXY = "proxy"
    MOCK = "mock"
    UNAVAILABLE = "unavailable"
    OTHER = "other"


class IntegrationStatus(str, Enum):
    """Honest status vocabulary for integration/system-health reporting.

    ``CONNECTED`` must only be used after a successful live interaction —
    never merely because a config file names a provider or an API key
    variable exists.
    """

    CONNECTED = "connected"
    AVAILABLE = "available"
    PROXY_IMPLEMENTATION = "proxy_implementation"
    NOT_INSTALLED = "not_installed"
    NOT_CONFIGURED = "not_configured"
    FAILED = "failed"


class ContractViolation(ValueError):
    """A record or state transition violated a shared contract.

    Malformed input is rejected loudly — never silently coerced into a
    misleading value.
    """


@dataclass
class AttackPayload:
    """Output of the attacker LLM for one round.

    ``metadata`` is optional structured provenance. Email targets use it to
    carry the generated email's fields (persona, subject, body, requested
    action, injection token) so the target receives them verbatim instead of
    re-parsing prose. It is empty for every non-email payload, preserving the
    original contract.
    """
    text: str
    category: str  # one of 5 attack categories
    sophistication_level: int  # 1-5
    a5_category_flag: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DefenseEvent:
    """Normalized output from any defense mechanism.

    Contract (validated in ``__post_init__``):

    - ``decision``: the normalized decision of a defense that actually ran —
      the record's existence implies execution; a defense that did not run
      produces *no* record (see the aggregation policy's ``missing_defenses``
      / ``fail_closed`` fields for absent or failed defenses).
    - ``confidence``: ``None`` unless the defense genuinely calculates a
      confidence; otherwise 0.0–1.0.
    - ``implementation_type``: how that defense is implemented *here*
      (this repo's defenses are local rule-based implementations, not the
      original research systems).
    - ``experiment_id`` / ``episode_id`` / ``round_num`` / ``timestamp``:
      traceability back to the experiment, episode and round that produced
      the record; ``None`` when not bound to one.
    """

    decision: DefenseDecision
    confidence: float | None  # 0.0–1.0, or None when not genuinely calculated
    evidence: str  # explanation of decision
    source: DefenseType | None  # None only for the adapter's no-signal record
    latency_ms: float = 0.0
    implementation_type: DefenseImplementation = (
        DefenseImplementation.LOCAL_IMPLEMENTATION
    )
    experiment_id: str | None = None
    episode_id: str | None = None
    round_num: int | None = None
    timestamp: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, DefenseDecision):
            raise ContractViolation(f"invalid decision: {self.decision!r}")
        if self.source is not None and not isinstance(self.source, DefenseType):
            raise ContractViolation(f"invalid source: {self.source!r}")
        if not isinstance(self.implementation_type, DefenseImplementation):
            raise ContractViolation(
                f"invalid implementation_type: {self.implementation_type!r}"
            )
        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(
                self.confidence, (int, float)
            ):
                raise ContractViolation(
                    f"confidence must be a number or None: {self.confidence!r}"
                )
            if not 0.0 <= float(self.confidence) <= 1.0:
                raise ContractViolation(
                    f"confidence out of range [0.0, 1.0]: {self.confidence!r}"
                )
            self.confidence = float(self.confidence)
        if not isinstance(self.evidence, str):
            raise ContractViolation(f"evidence must be a string: {self.evidence!r}")


@dataclass
class ToolCallRequest:
    """A tool call the target agent wants to make."""
    tool_name: str
    arguments: dict[str, Any]
    raw_text: str = ""


@dataclass
class EpisodeConfig:
    """Configuration for a single evaluation episode."""
    episode_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    mode: EpisodeMode = EpisodeMode.SINGLE_AGENT
    defense: DefenseType = DefenseType.CAMEL
    attacker_tier: AttackerTier = AttackerTier.CHEAP
    target_tier: TargetTier = TargetTier.CHEAP
    max_rounds: int = 5
    task_description: str = ""
    attack_goal: str = ""  # what the attacker is trying to achieve


@dataclass
class EpisodeResult:
    """Result of a completed episode."""
    config: EpisodeConfig
    outcome: AttackOutcome
    rounds_used: int = 0
    defense_events: list[DefenseEvent] = field(default_factory=list)
    payloads: list[AttackPayload] = field(default_factory=list)
    tool_calls: list[ToolCallRequest] = field(default_factory=list)
    #: Rounds until recovery after a compromise. ``None`` means NOT MEASURED —
    #: only episodes where recovery was actually observed may carry an int.
    #: (An unset ``0`` used to be silently reported as a measured 0.0 rounds.)
    recovery_rounds: int | None = None
    total_cost_usd: float = 0.0
    elapsed_seconds: float = 0.0
    diagnostics: dict[str, Any] = field(default_factory=dict)
    #: Lifecycle status of this episode (default: the episode produced a
    #: result, so it ran to completion; runners override on failure/cancel).
    status: EpisodeStatus = EpisodeStatus.COMPLETED
    #: Ground truth as evaluated against the target environment — ``None``
    #: means *not evaluated yet*, never a default guess.
    ground_truth: GroundTruthOutcome | None = None

    @property
    def attack_succeeded(self) -> bool:
        return self.outcome == AttackOutcome.SUCCESS


@dataclass
class EpisodeLog:
    """Append-only log entry for episodic memory."""
    round_num: int
    payload: AttackPayload
    defense_event: DefenseEvent | None
    outcome: AttackOutcome
    tool_call: ToolCallRequest | None
    cost_usd: float
    timestamp: float = field(default_factory=time.time)
