"""Phase 2 behavioral regression tests.

Purpose
-------
Pin the behavioral promises that Phase 2 is meant to preserve, in one place,
so later cleanup passes cannot silently change them.

Right now this covers:

1. Provider precedence (Phase 1 contract, re-asserted as regression)
   - explicit provider argument wins over LLM_PROVIDER env var
   - LLM_PROVIDER env var is a fallback, not an override
   - no arg and no env -> OpenAI default
   - unknown provider, as arg or via env, raises ValueError

2. Defense adapter majority voting
   - deny majority -> DENIED
   - allow majority -> ALLOWED
   - tie -> DENIED (safer default)

3. Pipeline stop-condition checksums (stub pipeline, C1)
   - C1 StopCondition.checksum() is deterministic for a given state
   - C1 StopCondition.checksum() changes when its own state changes
   - C1 StopCondition is NOT the same class as the controller's StopCondition
   - C1 StopCondition includes technical_failures in its checksum

4. Stub pipeline artifact shape (Mode 2, Config C1)
   - the self-contained stub pipeline writes results/mode2_c1/*.csv, *.json,
     and config_summary.json
   - the CSV has the expected per-episode metric columns
   - the config summary includes the expected top-level keys

Scope notes
-----------
- These tests assert what is true on disk now. They are not promises about
  features not yet wired, such as the real CLI path using from_env at runtime.
- If any of these behaviors are intentionally changed later, update this file
  with the reason before changing the implementation.
"""
from __future__ import annotations

import csv
import json

import pytest

from adaptive_agent_eval.defense.adapter import DefenseAdapter
from adaptive_agent_eval.defense.defenses import DefenseDecision, DefenseEvent, DefenseType
from adaptive_agent_eval.llm.provider import ProviderConfig, ProviderType


@pytest.fixture
def clean_env_provider(monkeypatch):
    """Remove LLM_PROVIDER from the environment for the duration of a test."""
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    yield
    monkeypatch.delenv("LLM_PROVIDER", raising=False)


# ---------------------------------------------------------------------------
# 1. Provider precedence
# ---------------------------------------------------------------------------


def test_explicit_arg_wins_over_env(clean_env_provider, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    cfg = ProviderConfig.from_env(provider=ProviderType.OPENAI)
    assert cfg.provider == ProviderType.OPENAI


def test_env_is_fallback_not_override(clean_env_provider, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    cfg = ProviderConfig.from_env()
    assert cfg.provider == ProviderType.ANTHROPIC


def test_no_arg_no_env_defaults_to_openai(clean_env_provider):
    cfg = ProviderConfig.from_env()
    assert cfg.provider == ProviderType.OPENAI


def test_unknown_provider_as_arg_raises():
    with pytest.raises(ValueError, match="Unknown provider"):
        ProviderConfig.from_env(provider="bad")


def test_unknown_provider_via_env_raises(clean_env_provider, monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "bad")
    with pytest.raises(ValueError, match="Unknown provider"):
        ProviderConfig.from_env()


# ---------------------------------------------------------------------------
# 2. Defense adapter majority voting
# ---------------------------------------------------------------------------


def test_defense_majority_deny_wins():
    adapter = DefenseAdapter()
    events = [
        DefenseEvent(
            decision=DefenseDecision.DENIED,
            confidence=0.8,
            evidence="a",
            source=DefenseType.CAMEL,
        ),
        DefenseEvent(
            decision=DefenseDecision.DENIED,
            confidence=0.7,
            evidence="b",
            source=DefenseType.PROGENT,
        ),
        DefenseEvent(
            decision=DefenseDecision.ALLOWED,
            confidence=0.9,
            evidence="c",
            source=DefenseType.VERIFIER,
        ),
    ]
    result = adapter.normalize(events)
    assert result.decision == DefenseDecision.DENIED


def test_defense_majority_allow_wins():
    adapter = DefenseAdapter()
    events = [
        DefenseEvent(
            decision=DefenseDecision.ALLOWED,
            confidence=0.8,
            evidence="a",
            source=DefenseType.CAMEL,
        ),
        DefenseEvent(
            decision=DefenseDecision.ALLOWED,
            confidence=0.7,
            evidence="b",
            source=DefenseType.PROGENT,
        ),
        DefenseEvent(
            decision=DefenseDecision.DENIED,
            confidence=0.9,
            evidence="c",
            source=DefenseType.VERIFIER,
        ),
    ]
    result = adapter.normalize(events)
    assert result.decision == DefenseDecision.ALLOWED


def test_defense_tie_breaks_to_denied():
    adapter = DefenseAdapter()
    events = [
        DefenseEvent(
            decision=DefenseDecision.DENIED,
            confidence=0.8,
            evidence="a",
            source=DefenseType.CAMEL,
        ),
        DefenseEvent(
            decision=DefenseDecision.ALLOWED,
            confidence=0.7,
            evidence="b",
            source=DefenseType.PROGENT,
        ),
    ]
    result = adapter.normalize(events)
    assert result.decision == DefenseDecision.DENIED


# ---------------------------------------------------------------------------
# 3. Pipeline stop-condition checksums (stub pipeline, C1)
# ---------------------------------------------------------------------------


def test_c1_stop_condition_is_deterministic():
    from adaptive_agent_eval.pipelines.mode2_c1 import StopCondition

    stop = StopCondition()
    first = stop.checksum()
    second = stop.checksum()
    assert first == second
    assert len(first) == 64


def test_c1_stop_condition_checksum_changes_with_state():
    from adaptive_agent_eval.pipelines.mode2_c1 import StopCondition

    stop = StopCondition()
    before = stop.checksum()
    stop.attack_success = True
    after = stop.checksum()
    assert before != after


def test_c1_stop_condition_is_not_controller_stop_condition():
    from adaptive_agent_eval.controller.orchestrator import StopCondition as CtrlStop
    from adaptive_agent_eval.pipelines.mode2_c1 import StopCondition as C1Stop

    assert C1Stop is not CtrlStop


def test_c1_stop_condition_includes_technical_failures_in_checksum():
    from adaptive_agent_eval.pipelines.mode2_c1 import StopCondition

    stop = StopCondition()
    base = stop.checksum()
    stop.technical_failures = 1
    changed = stop.checksum()
    assert base != changed


# ---------------------------------------------------------------------------
# 4. Stub pipeline artifact shape
# ---------------------------------------------------------------------------


def test_mode2_c1_stub_writes_expected_artifacts(tmp_path, monkeypatch):
    from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

    results_dir = tmp_path / "results" / "mode2_c1"
    monkeypatch.setattr(
        "adaptive_agent_eval.pipelines.mode2_c1.RESULTS_DIR", results_dir
    )

    episode = run_mode2_c1(max_rounds=2, seed=42, results_dir=results_dir)

    assert (results_dir / "episodes.csv").exists()
    assert (results_dir / "episodes.json").exists()
    assert (results_dir / "config_summary.json").exists

    # Episode-level artifact shape.
    episodes = json.loads((results_dir / "episodes.json").read_text(encoding="utf-8"))
    assert len(episodes) >= 1
    ep = episodes[-1]
    assert ep["episode_id"] == episode.episode_id
    assert ep["outcome"] == episode.outcome

    # Config summary shape.
    summary = json.loads(
        (results_dir / "config_summary.json").read_text(encoding="utf-8")
    )
    assert summary["config_id"] == "M2-C1-stub"
    assert "metrics" in summary
    metrics = summary["metrics"]
    for key in ("asr", "utility_score", "propagation_rate", "blast_radius"):
        assert key in metrics


def test_mode2_c1_csv_has_expected_columns(tmp_path, monkeypatch):
    from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

    results_dir = tmp_path / "results" / "mode2_c1"
    monkeypatch.setattr(
        "adaptive_agent_eval.pipelines.mode2_c1.RESULTS_DIR", results_dir
    )

    run_mode2_c1(max_rounds=2, seed=42, results_dir=results_dir)

    with (results_dir / "episodes.csv").open(
        encoding="utf-8",
    ) as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames
        assert columns is not None
        expected = {
            "episode_id",
            "mode",
            "defense",
            "agent_setup",
            "attacker_tier",
            "outcome",
            "rounds_used",
            "total_cost_usd",
            "elapsed_seconds",
            "bypass_triggered",
            "checksum",
            "agents_compromised",
            "total_agents",
            "utility_score",
            "propagation_happened",
        }
        assert expected.issubset(set(columns))


def test_stubs_module_imports_and_demo_episode_runs(tmp_path):
    """Regression: mode2_c1_stubs must be importable standalone.

    ``PipelineController.__init__`` annotates with classes defined later in
    the same file, so the module requires ``from __future__ import
    annotations``. Without it, importing the module raises NameError and the
    frontend's ``/api/run_c1`` path (``load_run_stubs``) crashes.
    """
    import importlib

    stubs = importlib.import_module("adaptive_agent_eval.pipelines.mode2_c1_stubs")
    assert callable(stubs.run_demo_episode)
    assert "AttackerStub" in vars(stubs)

    results_dir = tmp_path / "results" / "mode2_c1"
    out = stubs.run_demo_episode(results_dir=results_dir)

    assert isinstance(out, dict)
    for key in (
        "episode_id",
        "rounds_used",
        "ASR",
        "utility",
        "propagation_rate",
        "blast_radius",
        "checksum",
    ):
        assert key in out
    assert (results_dir / "episodes.json").exists()
    assert (results_dir / "config_summary.json").exists()
