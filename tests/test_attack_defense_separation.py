"""Regression tests: Run Experiment must execute ZERO Nemesis defense logic.

The attack campaign is attack-only. A separate, explicitly requested defense
evaluation is the only path that may construct or run a defense. These tests
fail loudly if the campaign path ever consults a defense builder again.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend import adaptive_harness as ah
from adaptive_agent_eval.models import DefenseType


def _explode(*_args, **_kwargs):
    raise AssertionError(
        "defense builder must not be called during an attack campaign"
    )


def test_campaign_evaluation_never_calls_build_defense(monkeypatch):
    monkeypatch.setattr(ah, "_build_defense", _explode)

    ladder = [{"category": "direct_injection", "sophistication_level": 1}]
    ev = ah.evaluate_strategy(
        ladder, episodes=2, max_rounds=1, seed=7, defense=ah.CAMPAIGN_DEFENSE
    )

    assert ev.total_episodes == 2
    assert ev.defense == "none"
    # No defense decision may exist anywhere in the episode evidence.
    assert ev.defense_denied == 0
    assert ev.defense_allowed == 0
    for trace in ev.episode_trace:
        assert trace["defense_decision"] is None
    # Utility stays unmeasured: no defense ran the benign probes.
    assert ev.utility_score is None


def test_campaign_records_no_defense_events(monkeypatch):
    """A campaign episode must not produce a defense event record at all."""

    seen_events: list[object] = []
    original = ah._NoDefenseAdapter.normalize

    def _spy(self, raw_events):
        seen_events.append(list(raw_events))
        return original(self, raw_events)

    monkeypatch.setattr(ah._NoDefenseAdapter, "normalize", _spy)

    ladder = [{"category": "social_engineering", "sophistication_level": 2}]
    ev = ah.evaluate_strategy(
        ladder, episodes=1, max_rounds=2, seed=3, defense=ah.CAMPAIGN_DEFENSE
    )
    assert seen_events, "the no-defense adapter must have been used"
    assert all(events == [] for events in seen_events)
    assert ev.defense_denied == 0 and ev.defense_allowed == 0


def test_harness_run_is_attack_only(tmp_path, monkeypatch):
    """A full harness run (baseline + candidates) never builds a defense."""
    monkeypatch.setattr(ah, "_build_defense", _explode)

    h = ah.AdaptiveHarness(
        store_path=str(Path(tmp_path) / "sep.json"),
        mode="greedy",
        defense="marker",  # a stale/legacy label must not re-enable defense
        iterations=1,
    )
    h._run(run_id="sep-run", episodes=1, max_rounds=1, iterations=1, seed=11)
    run = h._current_run

    assert run["history"], "the campaign must have evaluated candidates"
    for record in run["history"]:
        assert record["asr"] is not None

    # Every persisted per-episode trace is defense-free.
    for candidate_eval in run["history"]:
        for trace in candidate_eval.get("episode_trace") or []:
            assert trace.get("defense_decision") is None


def test_defense_type_none_is_additive():
    assert DefenseType.NONE.value == "none"
    assert DefenseType.CAMEL.value == "camel"
