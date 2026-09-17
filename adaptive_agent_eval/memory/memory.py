"""Memory System — episodic, procedural, working, semantic, and prospective memory.

Feedback loop:
- Attacker reads episodic + procedural → revises strategy
- Controller checks prospective → decides continue/stop
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

from adaptive_agent_eval.models import (
    AttackOutcome,
    EpisodeConfig,
    EpisodeLog,
    EpisodeResult,
)

logger = logging.getLogger(__name__)


class MemorySystem:
    """Manages all memory types for the evaluation framework.

    Memory types:
    - Working: current payload + defense decision (ephemeral per round)
    - Episodic: history of attempts in this episode
    - Procedural: success rates per attack category (persistent across episodes)
    - Semantic: tool schemas, defense rules, task definitions (static)
    - Prospective: controller obligations (stop conditions, round budgets)
    """

    def __init__(self, persist_dir: str | None = None):
        self.persist_dir = persist_dir
        self._episodic: dict[str, list[EpisodeLog]] = {}
        self._procedural: dict[str, list[float]] = {
            cat: [] for cat in [
                "direct_injection", "obfuscation", "context_manipulation",
                "social_engineering", "advanced_persistent"
            ]
        }
        self._working: dict[str, Any] = {}
        self._prospective: dict[str, Any] = {}

        if persist_dir:
            os.makedirs(persist_dir, exist_ok=True)

    def start_episode(self, config: EpisodeConfig) -> None:
        """Initialize memory for a new episode."""
        self._episodic[config.episode_id] = []
        self._working = {}
        self._prospective = {
            "max_rounds": config.max_rounds,
            "current_round": 0,
            "stop_conditions": [],
        }

    def append_log(self, episode_id: str, log: EpisodeLog) -> None:
        """Append a log entry to episodic memory."""
        if episode_id not in self._episodic:
            self._episodic[episode_id] = []
        self._episodic[episode_id].append(log)

        # Update working memory
        self._working = {
            "current_payload": log.payload,
            "defense_decision": log.defense_event.decision.value if log.defense_event else None,
        }

    def get_episodic_history(self, episode_id: str) -> list[EpisodeLog]:
        """Get the full history of attempts for an episode."""
        return self._episodic.get(episode_id, [])

    def get_procedural_rates(self) -> dict[str, float]:
        """Get success rates per attack category across all episodes."""
        rates = {}
        for category, outcomes in self._procedural.items():
            if outcomes:
                rates[category] = sum(outcomes) / len(outcomes)
            else:
                rates[category] = 0.0
        return rates

    def update_procedural(self, category: str, success: bool) -> None:
        """Update procedural memory with a new outcome."""
        if category in self._procedural:
            self._procedural[category].append(1.0 if success else 0.0)

    def finalize_episode(self, episode_id: str, result: EpisodeResult) -> None:
        """Finalize an episode and update procedural memory."""
        # Update procedural memory based on final outcome
        for log_entry in self._episodic.get(episode_id, []):
            self.update_procedural(
                log_entry.payload.category,
                log_entry.outcome == AttackOutcome.SUCCESS,
            )

        # Persist if configured
        if self.persist_dir:
            self._persist_episode(episode_id, result)

        # Clean up working memory
        self._working = {}
        self._prospective = {}

    def _persist_episode(self, episode_id: str, result: EpisodeResult) -> None:
        """Persist episode results to disk."""
        filepath = os.path.join(self.persist_dir, f"{episode_id}.json")
        data = {
            "episode_id": episode_id,
            "config": {
                "mode": result.config.mode.value,
                "defense": result.config.defense.value,
                "attacker_tier": result.config.attacker_tier.value,
                "target_tier": result.config.target_tier.value,
            },
            "outcome": result.outcome.value,
            "rounds_used": result.rounds_used,
            "total_cost_usd": result.total_cost_usd,
            "elapsed_seconds": result.elapsed_seconds,
            "diagnostics": result.diagnostics,
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

    def get_working_memory(self) -> dict[str, Any]:
        return self._working.copy()

    def get_prospective_memory(self) -> dict[str, Any]:
        return self._prospective.copy()

    def update_prospective(self, **kwargs) -> None:
        self._prospective.update(kwargs)
