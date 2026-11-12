"""Shared, validated contracts for experiments, episodes, defenses, and
integrations (Phase 2).

Design rules
------------
* Reuse the enums and record shapes in :mod:`adaptive_agent_eval.models`;
  this module adds the composed contracts (lifecycle, aggregation, experiment
  configuration/identity) and their validation.
* Malformed input raises :class:`~adaptive_agent_eval.models.ContractViolation`
  (or :class:`ContractValidationError` listing every error) — values are
  rejected, never silently coerced into misleading records.
* Metrics with no evidence stay ``None`` (see Phase 1's availability contract
  in ``docs/METRICS_DEFINITIONS.md`` §1.5); this module never invents values
  for absent data either.

Aggregation policy (verified against the implementation
-------------------------------------------------------
``adaptive_agent_eval.defense.adapter.DefenseAdapter.normalize`` and pinned by
``tests/test_phase2_regression.py::test_defense_majority_deny_wins``,
``test_defense_majority_allow_wins`` and ``test_defense_tie_breaks_to_denied``:

* Majority of *recorded* decisions wins: more DENIED than ALLOWED → DENIED
  (the highest-confidence denial is kept); more ALLOWED than DENIED → ALLOWED
  (the highest-confidence allow is kept).
* **Deny-on-tie**: equal counts (including 2+ all-NO_SIGNAL events, which
  count as 0–0) → DENIED.
* A single recorded event is returned unchanged (so a lone NO_SIGNAL stays
  NO_SIGNAL); zero recorded events → NO_SIGNAL, meaning *no defense ran* —
  an absence of signal, not an approval.
* NO_SIGNAL never casts a vote in the majority count.
* **Fail-closed**: when ``expected_defenses`` names a defense that produced no
  record, or the caller reports defense errors (exception/timeout), the
  aggregate is forced to DENIED with ``fail_closed=True`` and the absent
  sources listed — a missing, timed-out or errored defense can never silently
  become an approval.

Decision vocabulary mapping (dashboard wording → contract values):
allow → ``ALLOWED``; deny/block → ``DENIED``; flag → ``NO_SIGNAL`` (flagged,
no decisive allow/deny); error → *no event is produced* — represented at the
aggregation level via ``errors`` + ``fail_closed``, never as a fabricated
per-defense decision.
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from adaptive_agent_eval.defense.adapter import DefenseAdapter
from adaptive_agent_eval.models import (
    AttackerTier,
    ContractViolation,
    DefenseDecision,
    DefenseEvent,
    DefenseImplementation,
    DefenseType,
    EpisodeMode,
    EpisodeStatus,
    ExperimentStatus,
    GroundTruthOutcome,
    IntegrationStatus,
    TargetTier,
)

# Re-exported for callers that import contracts as the contract façade.
__all__ = [
    "AGGREGATION_POLICY",
    "ALLOWED_AGENT_SETUPS",
    "ALLOWED_ATTACKER_TYPES",
    "STRATEGY_DIMENSIONS",
    "STRATEGY_DIMENSION_IDS",
    "TOP_LEVEL_ATTACK_CATEGORIES",
    "TOP_LEVEL_ATTACK_CATEGORY_IDS",
    "TACTIC_TO_DIMENSION",
    "DIMENSION_TO_TACTIC",
    "dimension_display_name",
    "dimension_id_for_tactic",
    "dimensions_for_ladder",
    "AggregatedDecision",
    "ContractValidationError",
    "ContractViolation",
    "ExperimentConfig",
    "ExperimentRecord",
    "IntegrationReport",
    "aggregate_defense_decisions",
    "assert_episode_transition",
    "assert_experiment_transition",
    "defense_event_from_dict",
    "is_valid_episode_transition",
    "is_valid_experiment_transition",
    "parse_episode_status",
    "parse_experiment_status",
    "parse_ground_truth",
]

# ---------------------------------------------------------------------------
# Constants describing the implemented surface
# ---------------------------------------------------------------------------

#: Agent setups the repository can actually execute. Multi-agent is only
#: defined for the cross-agent mode (EXPERIMENT_PLAN.md §2.2 matrix).
ALLOWED_AGENT_SETUPS = ("single-agent", "multi-agent")

#: Attacker implementations with a real execution path today. A static
#: baseline attacker lands in Phase 4 and will be added to this set then —
#: configs naming it are rejected until it exists.
ALLOWED_ATTACKER_TYPES = ("adaptive-hill-climbing",)

#: Providers with a real configuration path. ``gemini`` binds to Gemini's
#: OpenAI-compatible endpoint (ADR-016; key/model names are metadata only —
#: credentials never enter a config or manifest).
ALLOWED_PROVIDERS = ("gemini", "openai", "anthropic")

DEFAULT_CHEAP_MODEL = "gemini-2.5-flash"
DEFAULT_FRONTIER_MODEL = "gemini-2.5-pro"

#: The three fixed top-level attack categories of the BYOA experiment, with
#: their exact display names (README / PRD §1.8). Every baseline case and
#: every evaluated candidate carries exactly one of these. They are the
#: experiment's *objectives* and are deliberately distinct from the five
#: strategy dimensions the hill-climber explores.
#:
#:
TOP_LEVEL_ATTACK_CATEGORIES = (
    "Unauthorized data access",
    "Sensitive-data exfiltration",
    "Sensitive-data disclosure",
)

#: Stable machine ids for :data:`TOP_LEVEL_ATTACK_CATEGORIES` (order matches).
TOP_LEVEL_ATTACK_CATEGORY_IDS = (
    "unauthorized_data_access",
    "sensitive_data_exfiltration",
    "sensitive_data_disclosure",
)

#: The five fixed strategy dimensions the adaptive search explores, with their
#: exact display names. A candidate records the dimension(s) it exercises;
#: these are *how* the attack is constructed, not *which objective* it targets.
STRATEGY_DIMENSIONS = (
    "Prompt injection",
    "Obfuscation and evasion",
    "Sensitive-data disclosure",
    "Tool misuse and unauthorized actions",
    "Multi-turn and chained attacks",
)

#: Stable machine ids for :data:`STRATEGY_DIMENSIONS` (order matches).
STRATEGY_DIMENSION_IDS = (
    "prompt_injection",
    "obfuscation_and_evasion",
    "sensitive_data_disclosure",
    "tool_misuse_and_unauthorized_actions",
    "multi_turn_and_chained_attacks",
)

#: Maps the harness's internal ladder *tactic* keys onto strategy dimensions
#: (both directions are total and one-to-one, so the search always covers all
#: five dimensions). The tactic key is an implementation detail of payload
#: generation; the dimension is what candidates and artifacts record. Payload
#: text generation (``backend/adaptive_harness.StrategyAttacker``) produces
#: material that actually exercises the mapped dimension, so the label is
#: connected to execution rather than decorative.
TACTIC_TO_DIMENSION = {
    "direct_injection": "prompt_injection",
    "obfuscation": "obfuscation_and_evasion",
    "social_engineering": "sensitive_data_disclosure",
    "context_manipulation": "tool_misuse_and_unauthorized_actions",
    "advanced_persistent": "multi_turn_and_chained_attacks",
}

#: Reverse mapping: strategy dimension id -> ladder tactic key.
DIMENSION_TO_TACTIC = {v: k for k, v in TACTIC_TO_DIMENSION.items()}


def dimension_id_for_tactic(tactic: str) -> str | None:
    """Strategy-dimension id exercised by a ladder tactic (``None`` if unknown)."""
    return TACTIC_TO_DIMENSION.get(tactic)


def dimension_display_name(dimension_id: str) -> str | None:
    """Exact display name for a strategy-dimension id (``None`` if unknown)."""
    try:
        return STRATEGY_DIMENSIONS[STRATEGY_DIMENSION_IDS.index(dimension_id)]
    except ValueError:
        return None


def dimensions_for_ladder(ladder: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Distinct strategy dimensions a ladder exercises, with display names.

    Preserves first-exercise order and keeps unknown tactics visible as
    ``dimension_id: None`` instead of silently dropping them.
    """
    seen: dict[str, dict[str, Any]] = {}
    for step in ladder:
        tactic = str((step or {}).get("category", ""))
        dim_id = TACTIC_TO_DIMENSION.get(tactic)
        key = dim_id or f"unmapped:{tactic}"
        if key not in seen:
            seen[key] = {
                "dimension_id": dim_id,
                "display_name": (
                    dimension_display_name(dim_id) if dim_id else None
                ),
                "tactic": tactic,
            }
    return list(seen.values())

#: Values that look like credentials must never appear in saved configs or
#: manifests (defense-in-depth on top of the manifest key-name scan).
_SECRET_VALUE_RE = re.compile(
    r"(AIza[0-9A-Za-z_\-]{20,}|sk-[0-9A-Za-z_\-]{16,}|ghp_[0-9A-Za-z]{20,}"
    r"|Bearer\s+[0-9A-Za-z]|api[_\-]?key\s*[:=])",
    re.IGNORECASE,
)

_SECRET_KEY_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "api_secret",
        "token",
        "access_token",
        "refresh_token",
        "secret",
        "password",
        "passwd",
        "authorization",
        "credential",
        "credentials",
        "private_key",
        "client_secret",
        "bearer",
    }
)

AGGREGATION_POLICY = (
    "majority-of-recorded-decisions (DefenseAdapter.normalize): more DENIED "
    "than ALLOWED -> DENIED (highest-confidence denial kept); more ALLOWED -> "
    "ALLOWED (highest-confidence allow kept); equal counts (including 2+ "
    "all-NO_SIGNAL events) -> tie -> DENIED (deny-on-tie); a single recorded "
    "event passes through unchanged; zero recorded events -> NO_SIGNAL (no "
    "defense ran - absence of signal, not an approval). NO_SIGNAL never "
    "votes. When expected_defenses has gaps or the caller reports defense "
    "errors/timeouts, the aggregate fails closed to DENIED with "
    "fail_closed=True and the absent sources listed - a failed defense never "
    "silently becomes an approval."
)


class ContractValidationError(ContractViolation):
    """Raised when validation found one or more problems; ``errors`` lists
    every one of them (validation never stops at the first error)."""

    def __init__(self, errors: list[str]):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


# ---------------------------------------------------------------------------
# Lifecycle transitions
# ---------------------------------------------------------------------------

EXPERIMENT_TRANSITIONS: dict[ExperimentStatus, frozenset[ExperimentStatus]] = {
    ExperimentStatus.CREATED: frozenset(
        {ExperimentStatus.RUNNING, ExperimentStatus.FAILED, ExperimentStatus.CANCELLED}
    ),
    ExperimentStatus.RUNNING: frozenset(
        {
            ExperimentStatus.COMPLETED,
            ExperimentStatus.FAILED,
            ExperimentStatus.CANCELLED,
            ExperimentStatus.INTERRUPTED,
        }
    ),
    # Terminal — except that an interrupted run may be resumed (Phase 3+).
    ExperimentStatus.COMPLETED: frozenset(),
    ExperimentStatus.FAILED: frozenset(),
    ExperimentStatus.CANCELLED: frozenset(),
    ExperimentStatus.INTERRUPTED: frozenset({ExperimentStatus.RUNNING}),
}

EPISODE_TRANSITIONS: dict[EpisodeStatus, frozenset[EpisodeStatus]] = {
    EpisodeStatus.PENDING: frozenset(
        {EpisodeStatus.RUNNING, EpisodeStatus.CANCELLED, EpisodeStatus.SKIPPED}
    ),
    EpisodeStatus.RUNNING: frozenset(
        {EpisodeStatus.COMPLETED, EpisodeStatus.FAILED, EpisodeStatus.CANCELLED}
    ),
    EpisodeStatus.COMPLETED: frozenset(),
    EpisodeStatus.FAILED: frozenset(),
    EpisodeStatus.CANCELLED: frozenset(),
    EpisodeStatus.SKIPPED: frozenset(),
}


def _parse_enum(enum_cls: type[Enum], value: Any, label: str) -> Enum:
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(value)
    except (ValueError, TypeError) as exc:
        allowed = ", ".join(repr(m.value) for m in enum_cls)
        raise ContractViolation(
            f"invalid {label}: {value!r} (allowed: {allowed})"
        ) from exc


def parse_experiment_status(value: Any) -> ExperimentStatus:
    return _parse_enum(ExperimentStatus, value, "experiment status")  # type: ignore[return-value]


def parse_episode_status(value: Any) -> EpisodeStatus:
    return _parse_enum(EpisodeStatus, value, "episode status")  # type: ignore[return-value]


def parse_ground_truth(value: Any) -> GroundTruthOutcome:
    return _parse_enum(GroundTruthOutcome, value, "ground truth outcome")  # type: ignore[return-value]


def is_valid_experiment_transition(
    current: ExperimentStatus, target: ExperimentStatus
) -> bool:
    return target in EXPERIMENT_TRANSITIONS.get(current, frozenset())


def is_valid_episode_transition(current: EpisodeStatus, target: EpisodeStatus) -> bool:
    return target in EPISODE_TRANSITIONS.get(current, frozenset())


def assert_experiment_transition(
    current: ExperimentStatus, target: ExperimentStatus
) -> None:
    if not is_valid_experiment_transition(current, target):
        allowed = ", ".join(
            sorted(s.value for s in EXPERIMENT_TRANSITIONS.get(current, frozenset()))
        )
        raise ContractViolation(
            f"invalid experiment transition {current.value} -> {target.value} "
            f"(allowed from {current.value}: {allowed or 'none'})"
        )


def assert_episode_transition(current: EpisodeStatus, target: EpisodeStatus) -> None:
    if not is_valid_episode_transition(current, target):
        allowed = ", ".join(
            sorted(s.value for s in EPISODE_TRANSITIONS.get(current, frozenset()))
        )
        raise ContractViolation(
            f"invalid episode transition {current.value} -> {target.value} "
            f"(allowed from {current.value}: {allowed or 'none'})"
        )


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Defense aggregation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AggregatedDecision:
    """The overall decision, kept strictly separate from the individual
    defense records (``events``) that produced it."""

    decision: DefenseDecision
    policy: str
    events: tuple[DefenseEvent, ...]
    #: (source label or "unknown", decision value) per recorded defense.
    votes: tuple[tuple[str, str], ...]
    allowed_count: int
    denied_count: int
    no_signal_count: int
    #: True when denied == allowed among 2+ records (deny-on-tie applied).
    tie: bool
    #: True when the result was forced to DENIED because expected defenses
    #: produced no record or the caller reported defense errors.
    fail_closed: bool
    #: Expected defenses that produced no record (source values).
    missing_defenses: tuple[str, ...]
    #: Caller-reported defense failures (exceptions, timeouts).
    errors: tuple[str, ...]
    evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "policy": self.policy,
            "votes": [list(v) for v in self.votes],
            "allowed_count": self.allowed_count,
            "denied_count": self.denied_count,
            "no_signal_count": self.no_signal_count,
            "tie": self.tie,
            "fail_closed": self.fail_closed,
            "missing_defenses": list(self.missing_defenses),
            "errors": list(self.errors),
            "evidence": self.evidence,
        }


def aggregate_defense_decisions(
    events: Iterable[DefenseEvent],
    *,
    expected_defenses: Iterable[DefenseType] | None = None,
    errors: Iterable[str] = (),
) -> AggregatedDecision:
    """Aggregate per-defense events into one overall decision.

    The *decision value* always comes from the real
    ``DefenseAdapter.normalize`` (single source of truth); this wrapper adds
    the auditable detail — votes, tie flag, missing defenses, fail-closed
    flag — and enforces the fail-closed rule for absent/failed defenses.
    """
    event_list = tuple(events)
    for ev in event_list:
        if not isinstance(ev, DefenseEvent):
            raise ContractViolation(
                f"aggregate expects DefenseEvent records, got {type(ev).__name__}"
            )

    error_list = tuple(str(e) for e in errors)
    seen_sources = {ev.source for ev in event_list if ev.source is not None}
    missing: list[str] = []
    if expected_defenses is not None:
        for expected in expected_defenses:
            if not isinstance(expected, DefenseType):
                raise ContractViolation(
                    f"expected_defenses must contain DefenseType, got {expected!r}"
                )
            if expected not in seen_sources:
                missing.append(expected.value)

    allowed = sum(1 for e in event_list if e.decision == DefenseDecision.ALLOWED)
    denied = sum(1 for e in event_list if e.decision == DefenseDecision.DENIED)
    no_signal = sum(
        1 for e in event_list if e.decision == DefenseDecision.NO_SIGNAL
    )
    tie = len(event_list) > 1 and denied == allowed
    votes = tuple(
        (ev.source.value if ev.source is not None else "unknown", ev.decision.value)
        for ev in event_list
    )

    if missing or error_list:
        parts = []
        if missing:
            parts.append(f"no record from: {', '.join(missing)}")
        if error_list:
            parts.append(f"defense errors: {'; '.join(error_list)}")
        evidence = "fail-closed DENIED — " + "; ".join(parts)
        decision = DefenseDecision.DENIED
        fail_closed = True
    else:
        normalized = DefenseAdapter().normalize(list(event_list))
        decision = normalized.decision
        evidence = normalized.evidence
        fail_closed = False

    return AggregatedDecision(
        decision=decision,
        policy=AGGREGATION_POLICY,
        events=event_list,
        votes=votes,
        allowed_count=allowed,
        denied_count=denied,
        no_signal_count=no_signal,
        tie=tie,
        fail_closed=fail_closed,
        missing_defenses=tuple(missing),
        errors=error_list,
        evidence=evidence,
    )


def defense_event_from_dict(data: Mapping[str, Any]) -> DefenseEvent:
    """Strict deserialization of a defense event.

    Missing/unknown fields and invalid decision values are rejected with
    :class:`ContractViolation` instead of being coerced.
    """
    if not isinstance(data, Mapping):
        raise ContractViolation(f"defense event must be an object, got {type(data).__name__}")
    known = {
        "decision",
        "confidence",
        "evidence",
        "source",
        "latency_ms",
        "implementation_type",
        "experiment_id",
        "episode_id",
        "round_num",
        "timestamp",
    }
    unknown = sorted(set(data) - known)
    if unknown:
        raise ContractViolation(f"unknown defense event field(s): {', '.join(unknown)}")
    missing = sorted({"decision", "confidence", "evidence", "source"} - set(data))
    if missing:
        raise ContractViolation(
            f"missing required defense event field(s): {', '.join(missing)}"
        )
    try:
        decision = DefenseDecision(data["decision"])
    except (ValueError, TypeError) as exc:
        allowed = ", ".join(repr(d.value) for d in DefenseDecision)
        raise ContractViolation(
            f"invalid decision: {data['decision']!r} (allowed: {allowed})"
        ) from exc
    source = data["source"]
    if source is not None:
        try:
            source = DefenseType(source)
        except (ValueError, TypeError) as exc:
            raise ContractViolation(f"invalid source: {source!r}") from exc
    impl = data.get("implementation_type", DefenseImplementation.LOCAL_IMPLEMENTATION)
    if not isinstance(impl, DefenseImplementation):
        try:
            impl = DefenseImplementation(impl)
        except (ValueError, TypeError) as exc:
            raise ContractViolation(
                f"invalid implementation_type: {impl!r}"
            ) from exc
    return DefenseEvent(
        decision=decision,
        confidence=data["confidence"],
        evidence=data["evidence"],
        source=source,
        latency_ms=data.get("latency_ms", 0.0),
        implementation_type=impl,
        experiment_id=data.get("experiment_id"),
        episode_id=data.get("episode_id"),
        round_num=data.get("round_num"),
        timestamp=data.get("timestamp"),
    )


# ---------------------------------------------------------------------------
# Experiment configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExperimentConfig:
    """Validated, serializable configuration for one experiment (one matrix
    configuration × its episodes). Credentials never appear here."""

    # Required factors — no defaults, so a missing field is an error, not a
    # silently substituted guess.
    mode: EpisodeMode
    defenses: tuple[DefenseType, ...]
    episodes: int
    seed: int
    max_rounds: int

    attacker_tier: AttackerTier = AttackerTier.CHEAP
    target_tier: TargetTier = TargetTier.CHEAP
    agent_setup: str = "single-agent"
    attacker_type: str = "adaptive-hill-climbing"
    provider: str = "gemini"
    cheap_model: str = DEFAULT_CHEAP_MODEL
    frontier_model: str = DEFAULT_FRONTIER_MODEL
    max_technical_failures: int = 3
    label: str = ""

    def __post_init__(self) -> None:
        # Normalize sequences to an immutable tuple (list input allowed, but
        # validation still rejects non-DefenseType members).
        if isinstance(self.defenses, list):
            object.__setattr__(self, "defenses", tuple(self.defenses))

    # -- validation ---------------------------------------------------------

    def validation_errors(self) -> list[str]:
        errors: list[str] = []

        if not isinstance(self.mode, EpisodeMode):
            errors.append(f"mode: invalid value {self.mode!r}")
            mode = None
        else:
            mode = self.mode

        if isinstance(self.episodes, bool) or not isinstance(self.episodes, int):
            errors.append(f"episodes: must be an integer, got {self.episodes!r}")
        elif self.episodes < 1:
            errors.append(f"episodes: must be positive, got {self.episodes}")

        if isinstance(self.max_rounds, bool) or not isinstance(self.max_rounds, int):
            errors.append(f"max_rounds: must be an integer, got {self.max_rounds!r}")
        elif self.max_rounds < 1:
            errors.append(f"max_rounds: must be positive, got {self.max_rounds}")

        if isinstance(self.seed, bool) or not isinstance(self.seed, int):
            errors.append(f"seed: must be an integer, got {self.seed!r}")
        elif self.seed < 0:
            errors.append(f"seed: must be non-negative, got {self.seed}")

        if not isinstance(self.defenses, (tuple, list)) or not self.defenses:
            errors.append(
                f"defenses: at least one defense required, got {self.defenses!r}"
            )
        else:
            invalid = [d for d in self.defenses if not isinstance(d, DefenseType)]
            if invalid:
                errors.append(f"defenses: invalid value(s) {invalid!r}")
            if len(set(self.defenses)) != len(self.defenses):
                errors.append(f"defenses: duplicates not allowed {self.defenses!r}")
            if mode is not None and not invalid:
                if mode in (
                    EpisodeMode.SINGLE_AGENT,
                    EpisodeMode.CROSS_AGENT,
                ) and len(self.defenses) != 1:
                    errors.append(
                        f"defenses: {mode.value} mode requires exactly one "
                        f"defense, got {len(self.defenses)}"
                    )
                if mode == EpisodeMode.DEFENSE_COMPOSITION and len(
                    self.defenses
                ) not in (2, 3):
                    errors.append(
                        "defenses: defense-composition mode requires 2 or 3 "
                        f"stacked defenses, got {len(self.defenses)}"
                    )

        if self.agent_setup not in ALLOWED_AGENT_SETUPS:
            errors.append(
                f"agent_setup: invalid value {self.agent_setup!r} "
                f"(allowed: {', '.join(ALLOWED_AGENT_SETUPS)})"
            )
        elif mode == EpisodeMode.CROSS_AGENT and self.agent_setup not in (
            "single-agent",
            "multi-agent",
        ):  # pragma: no cover - unreachable via the tuple check above
            errors.append("agent_setup: invalid value for cross-agent mode")
        elif mode is not None and mode != EpisodeMode.CROSS_AGENT and (
            self.agent_setup != "single-agent"
        ):
            errors.append(
                f"agent_setup: multi-agent is only defined for cross-agent "
                f"mode, got {self.agent_setup!r} with mode {mode.value!r}"
            )

        if self.attacker_type not in ALLOWED_ATTACKER_TYPES:
            errors.append(
                f"attacker_type: unsupported {self.attacker_type!r} "
                f"(implemented: {', '.join(ALLOWED_ATTACKER_TYPES)})"
            )

        if not isinstance(self.attacker_tier, AttackerTier):
            errors.append(f"attacker_tier: invalid value {self.attacker_tier!r}")
        if not isinstance(self.target_tier, TargetTier):
            errors.append(f"target_tier: invalid value {self.target_tier!r}")

        if self.provider not in ALLOWED_PROVIDERS:
            errors.append(
                f"provider: unsupported {self.provider!r} "
                f"(supported: {', '.join(ALLOWED_PROVIDERS)})"
            )
        for field_name in ("cheap_model", "frontier_model"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{field_name}: must be a non-empty string")
            elif _SECRET_VALUE_RE.search(value):
                errors.append(f"{field_name}: looks like a credential — refused")

        if (
            isinstance(self.max_technical_failures, bool)
            or not isinstance(self.max_technical_failures, int)
            or self.max_technical_failures < 1
        ):
            errors.append(
                "max_technical_failures: must be an integer >= 1, "
                f"got {self.max_technical_failures!r}"
            )

        if not isinstance(self.label, str):
            errors.append(f"label: must be a string, got {self.label!r}")
        elif _SECRET_VALUE_RE.search(self.label):
            errors.append("label: looks like a credential — refused")

        return errors

    def validate(self) -> ExperimentConfig:
        """Raise :class:`ContractValidationError` listing every problem."""
        errors = self.validation_errors()
        if errors:
            raise ContractValidationError(errors)
        return self

    # -- serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "defenses": [d.value for d in self.defenses],
            "episodes": self.episodes,
            "seed": self.seed,
            "max_rounds": self.max_rounds,
            "attacker_tier": self.attacker_tier.value,
            "target_tier": self.target_tier.value,
            "agent_setup": self.agent_setup,
            "attacker_type": self.attacker_type,
            "provider": self.provider,
            "cheap_model": self.cheap_model,
            "frontier_model": self.frontier_model,
            "max_technical_failures": self.max_technical_failures,
            "label": self.label,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExperimentConfig:
        """Strict deserialization: unknown keys, missing required fields and
        invalid values are collected and rejected together."""
        if not isinstance(data, Mapping):
            raise ContractValidationError(
                [f"configuration must be an object, got {type(data).__name__}"]
            )
        errors: list[str] = []

        known = {
            "mode",
            "defenses",
            "episodes",
            "seed",
            "max_rounds",
            "attacker_tier",
            "target_tier",
            "agent_setup",
            "attacker_type",
            "provider",
            "cheap_model",
            "frontier_model",
            "max_technical_failures",
            "label",
        }
        for key in sorted(set(data) - known):
            errors.append(f"unknown field: {key}")

        required = ("mode", "defenses", "episodes", "seed", "max_rounds")
        missing = [k for k in required if k not in data]
        for key in missing:
            errors.append(f"missing required field: {key}")

        def _enum(enum_cls, key, default=None, *, required=False):
            if key in data:
                try:
                    return enum_cls(data[key])
                except (ValueError, TypeError):
                    allowed = ", ".join(repr(m.value) for m in enum_cls)
                    errors.append(
                        f"{key}: invalid value {data[key]!r} (allowed: {allowed})"
                    )
                    return default
            if required:
                return default
            return default

        mode = _enum(EpisodeMode, "mode")
        attacker_tier = _enum(
            AttackerTier, "attacker_tier", AttackerTier.CHEAP
        )
        target_tier = _enum(TargetTier, "target_tier", TargetTier.CHEAP)

        defenses: tuple[DefenseType, ...] = ()
        if "defenses" in data:
            raw = data["defenses"]
            if not isinstance(raw, (list, tuple)):
                errors.append(f"defenses: must be a list, got {type(raw).__name__}")
            else:
                parsed: list[DefenseType] = []
                for item in raw:
                    try:
                        parsed.append(DefenseType(item))
                    except (ValueError, TypeError):
                        allowed = ", ".join(repr(d.value) for d in DefenseType)
                        errors.append(
                            f"defenses: invalid value {item!r} (allowed: {allowed})"
                        )
                defenses = tuple(parsed)

        if errors:
            raise ContractValidationError(errors)

        config = cls(
            mode=mode,  # type: ignore[arg-type]
            defenses=defenses,
            episodes=data["episodes"],
            seed=data["seed"],
            max_rounds=data["max_rounds"],
            attacker_tier=attacker_tier,  # type: ignore[arg-type]
            target_tier=target_tier,  # type: ignore[arg-type]
            agent_setup=data.get("agent_setup", "single-agent"),
            attacker_type=data.get("attacker_type", "adaptive-hill-climbing"),
            provider=data.get("provider", "gemini"),
            cheap_model=data.get("cheap_model", DEFAULT_CHEAP_MODEL),
            frontier_model=data.get("frontier_model", DEFAULT_FRONTIER_MODEL),
            max_technical_failures=data.get("max_technical_failures", 3),
            label=data.get("label", ""),
        )
        return config.validate()


# ---------------------------------------------------------------------------
# Experiment identity + lifecycle record
# ---------------------------------------------------------------------------


@dataclass
class ExperimentRecord:
    """Identity, lifecycle state and progress for one experiment run.

    The lifecycle is enforced by :meth:`transition`: a FAILED or INTERRUPTED
    run can never become COMPLETED, and COMPLETED additionally requires every
    episode to have actually completed — a summary object alone cannot mark a
    partial run as complete.
    """

    config: ExperimentConfig
    config_id: str = ""  # manifest configuration ID, or "" for ad-hoc runs
    experiment_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: ExperimentStatus = ExperimentStatus.CREATED
    created_at: str = field(default_factory=_utc_now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    episodes_completed: int = 0
    episodes_failed: int = 0
    episodes_skipped: int = 0
    episodes_cancelled: int = 0
    error: str | None = None

    def note_episode(self, status: EpisodeStatus | str) -> None:
        """Count one terminal episode outcome."""
        parsed = parse_episode_status(status)
        if parsed == EpisodeStatus.COMPLETED:
            self.episodes_completed += 1
        elif parsed == EpisodeStatus.FAILED:
            self.episodes_failed += 1
        elif parsed == EpisodeStatus.SKIPPED:
            self.episodes_skipped += 1
        elif parsed == EpisodeStatus.CANCELLED:
            self.episodes_cancelled += 1
        else:
            raise ContractViolation(
                f"episode must have a terminal status to be counted, got "
                f"{parsed.value!r}"
            )

    def transition(
        self, target: ExperimentStatus | str, *, error: str | None = None
    ) -> None:
        target = parse_experiment_status(target)
        assert_experiment_transition(self.status, target)

        if target == ExperimentStatus.COMPLETED:
            total = self.config.episodes
            if self.episodes_completed != total:
                raise ContractViolation(
                    "cannot mark experiment completed: "
                    f"{self.episodes_completed}/{total} episodes completed"
                )

        self.status = target
        if target == ExperimentStatus.RUNNING and self.started_at is None:
            self.started_at = _utc_now_iso()
        if target in (
            ExperimentStatus.COMPLETED,
            ExperimentStatus.FAILED,
            ExperimentStatus.CANCELLED,
            ExperimentStatus.INTERRUPTED,
        ):
            self.finished_at = _utc_now_iso()
        if error is not None:
            self.error = error

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["config"] = self.config.to_dict()
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ExperimentRecord:
        if not isinstance(data, Mapping):
            raise ContractViolation(
                f"experiment record must be an object, got {type(data).__name__}"
            )
        if "config" not in data:
            raise ContractViolation("experiment record missing 'config'")
        config = ExperimentConfig.from_dict(data["config"])
        record = cls(
            config=config,
            config_id=data.get("config_id", ""),
            experiment_id=data.get("experiment_id") or uuid.uuid4().hex,
            status=parse_experiment_status(data.get("status", "created")),
            created_at=data.get("created_at") or _utc_now_iso(),
            started_at=data.get("started_at"),
            finished_at=data.get("finished_at"),
            episodes_completed=int(data.get("episodes_completed", 0)),
            episodes_failed=int(data.get("episodes_failed", 0)),
            episodes_skipped=int(data.get("episodes_skipped", 0)),
            episodes_cancelled=int(data.get("episodes_cancelled", 0)),
            error=data.get("error"),
        )
        return record


# ---------------------------------------------------------------------------
# Integration status
# ---------------------------------------------------------------------------


@dataclass
class IntegrationReport:
    """One honest integration/system-health entry (never claims CONNECTED
    without a live interaction)."""

    name: str
    status: IntegrationStatus
    detail: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ContractViolation(f"integration name must be non-empty: {self.name!r}")
        if not isinstance(self.status, IntegrationStatus):
            raise ContractViolation(f"invalid integration status: {self.status!r}")
        if not isinstance(self.detail, str):
            raise ContractViolation(f"integration detail must be a string: {self.detail!r}")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IntegrationReport:
        if not isinstance(data, Mapping):
            raise ContractViolation("integration report must be an object")
        if "name" not in data or "status" not in data:
            raise ContractViolation("integration report requires 'name' and 'status'")
        return cls(
            name=data["name"],
            status=_parse_enum(IntegrationStatus, data["status"], "integration status"),  # type: ignore[arg-type]
            detail=data.get("detail", ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "status": self.status.value, "detail": self.detail}
