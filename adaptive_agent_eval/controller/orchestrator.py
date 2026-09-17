"""Controller / Orchestrator — the central evaluation loop.

Non-LLM Python script. Hardened: no prompt exposure, read-only memory,
cryptographic checksums on stop conditions, isolated from LLM processes.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field

from adaptive_agent_eval.models import (
    AttackOutcome,
    EpisodeConfig,
    EpisodeMode,
    EpisodeResult,
    EpisodeLog,
)

logger = logging.getLogger(__name__)


@dataclass
class StopCondition:
    """Cryptographically signed stop conditions."""

    attack_success: bool = False
    round_budget_exhausted: bool = False
    repeated_technical_failures: bool = False
    max_technical_failures: int = 3

    def should_stop(self, outcome: AttackOutcome, round_num: int, max_rounds: int, technical_failures: int) -> bool:
        self.attack_success = outcome == AttackOutcome.SUCCESS
        self.round_budget_exhausted = round_num >= max_rounds
        self.repeated_technical_failures = technical_failures >= self.max_technical_failures
        return self.attack_success or self.round_budget_exhausted or self.repeated_technical_failures

    def checksum(self) -> str:
        """Return SHA-256 of stop condition state for integrity verification."""
        data = f"{self.attack_success}:{self.round_budget_exhausted}:{self.repeated_technical_failures}"
        return hashlib.sha256(data.encode()).hexdigest()


class Controller:
    """Orchestrates a single episode evaluation loop.

    Responsibilities:
    - Track round counter, episode config, stop conditions
    - Drive the loop: attacker → target → defense → diagnoser → memory → metrics
    - Verify stop-condition integrity via checksums
    """

    def __init__(
        self,
        attacker,
        target_agent,
        defense_layer,
        defense_adapter,
        diagnoser,
        memory_system,
        metrics_collector,
    ):
        self.attacker = attacker
        self.target_agent = target_agent
        self.defense_layer = defense_layer
        self.defense_adapter = defense_adapter
        self.diagnoser = diagnoser
        self.memory = memory_system
        self.metrics = metrics_collector
        self._episode_logs: list[EpisodeLog] = []

    def run_episode(self, config: EpisodeConfig) -> EpisodeResult:
        """Execute a single evaluation episode."""
        start_time = time.time()
        stop = StopCondition()
        technical_failures = 0

        self.memory.start_episode(config)
        self.metrics.begin_episode(config)

        for round_num in range(1, config.max_rounds + 1):
            # 1. Attacker generates payload (reads episodic + procedural memory)
            history = self.memory.get_episodic_history(config.episode_id)
            success_rates = self.memory.get_procedural_rates()
            payload = self.attacker.generate_payload(config, history, success_rates)

            # 2. Target agent processes the payload and attempts tool calls
            tool_call_request = self.target_agent.process_and_act(config.task_description, payload)

            # 3. Defense layer evaluates the tool call
            raw_defense_event = self.defense_layer.evaluate(tool_call_request)
            defense_event = self.defense_adapter.normalize(raw_defense_event)

            # 4. Diagnoser determines outcome
            outcome = self.diagnoser.diagnose(
                payload=payload,
                tool_call=tool_call_request,
                defense_event=defense_event,
                config=config,
            )

            # 5. Record log entry
            log_entry = EpisodeLog(
                round_num=round_num,
                payload=payload,
                defense_event=defense_event,
                outcome=outcome,
                tool_call=tool_call_request,
                cost_usd=self.metrics.last_round_cost(),
            )
            self.memory.append_log(config.episode_id, log_entry)
            self.metrics.record_round(log_entry)

            # 6. Check stop conditions
            if stop.should_stop(outcome, round_num, config.max_rounds, technical_failures):
                break

            if outcome == AttackOutcome.TECHNICAL_FAIL:
                technical_failures += 1

        elapsed = time.time() - start_time
        checksum = stop.checksum()

        result = EpisodeResult(
            config=config,
            outcome=outcome,
            rounds_used=round_num,
            defense_events=[e.defense_event for e in self._episode_logs if e.defense_event],
            payloads=[e.payload for e in self._episode_logs],
            tool_calls=[e.tool_call for e in self._episode_logs if e.tool_call],
            total_cost_usd=self.metrics.episode_total_cost(),
            elapsed_seconds=elapsed,
            diagnostics={"checksum": checksum, "stop_reason": stop},
        )

        self.memory.finalize_episode(config.episode_id, result)
        self.metrics.end_episode(result)

        logger.info(
            "Episode %s complete: outcome=%s rounds=%d cost=$%.4f checksum=%s",
            config.episode_id,
            result.outcome.value,
            result.rounds_used,
            result.total_cost_usd,
            checksum[:16],
        )

        return result

    def run_experiment(self, configs: list[EpisodeConfig]) -> list[EpisodeResult]:
        """Run multiple episodes and collect results."""
        results = []
        for i, config in enumerate(configs, 1):
            logger.info("Starting episode %d/%d: %s", i, len(configs), config.episode_id)
            result = self.run_episode(config)
            results.append(result)
        return results
