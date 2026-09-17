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


class AttackerTier(str, Enum):
    CHEAP = "cheap"
    FRONTIER = "frontier"


class TargetTier(str, Enum):
    CHEAP = "cheap"
    FRONTIER = "frontier"


@dataclass
class AttackPayload:
    """Output of the attacker LLM for one round."""
    text: str
    category: str  # one of 5 attack categories
    sophistication_level: int  # 1-5
    a5_category_flag: bool = False


@dataclass
class DefenseEvent:
    """Normalized output from any defense mechanism."""
    decision: DefenseDecision
    confidence: float  # 0.0 - 1.0
    evidence: str  # explanation of decision
    source: DefenseType
    latency_ms: float = 0.0


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
    recovery_rounds: int = 0
    total_cost_usd: float = 0.0
    elapsed_seconds: float = 0.0
    diagnostics: dict[str, Any] = field(default_factory=dict)

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
