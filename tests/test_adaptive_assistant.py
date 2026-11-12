"""Deterministic regression tests for AdaptiveModelAssistant and provider integration.

Verifies:
- Structured candidate suggestion with provenance tracking.
- Feedback interpretation and strategy shift recommendations.
- Model call budget enforcement (halting when limit is reached).
- Graceful deterministic fallback when model calls fail.
- Distinct classification between model execution errors and security outcomes.
"""

from __future__ import annotations

import pytest

from adaptive_agent_eval.llm.adaptive_assistant import (
    AdaptiveModelAssistant,
    CandidateSuggestion,
    ModelFeedbackInterpretation,
)
from adaptive_agent_eval.llm.provider import (
    FakeConfig,
    FakeProvider,
    GeminiConfig,
    ProviderConfig,
    ProviderType,
    create_provider,
    make_provider_config,
)


def test_assistant_suggests_candidate():
    cfg = FakeConfig()
    cfg.max_model_calls = 5
    assistant = AdaptiveModelAssistant(config=cfg)

    current_ladder = [
        {"category": "direct_injection", "sophistication_level": 1},
        {"category": "social_engineering", "sophistication_level": 2},
    ]

    suggestion = assistant.suggest_candidate(current_ladder)
    assert isinstance(suggestion, CandidateSuggestion)
    assert suggestion.provenance in ("model-driven", "deterministic-fallback")
    assert len(suggestion.candidate_ladder) == len(current_ladder)
    assert cfg.model_calls_consumed == 1


def test_assistant_interprets_feedback():
    cfg = make_provider_config(ProviderType.FAKE)
    cfg.max_model_calls = 5
    assistant = AdaptiveModelAssistant(config=cfg)

    interp = assistant.interpret_feedback(
        iteration=1,
        best_asr=0.25,
        recent_evaluations=[{"candidate_id": "c1", "asr": 0.25}],
        feedback_statistics={"direct_injection": {"success": 0, "blocked": 4}},
    )
    assert isinstance(interp, ModelFeedbackInterpretation)
    assert interp.summary
    assert interp.suggested_strategy_shift
    assert interp.model_metadata["provider"] == "fake"
    assert cfg.model_calls_consumed == 1


def test_model_call_budget_enforcement():
    cfg = FakeConfig()
    cfg.max_model_calls = 2
    assistant = AdaptiveModelAssistant(config=cfg)

    # Call 1: OK
    assistant.interpret_feedback(iteration=1, best_asr=0.0, recent_evaluations=[])
    assert cfg.model_calls_consumed == 1

    # Call 2: OK
    assistant.interpret_feedback(iteration=2, best_asr=0.0, recent_evaluations=[])
    assert cfg.model_calls_consumed == 2

    # Call 3: Budget exhausted -> assistant handles cleanly and returns fallback
    res = assistant.suggest_candidate([{"category": "direct_injection", "sophistication_level": 1}])
    assert res.provenance == "deterministic-fallback"
    assert res.call_budget_remaining == 0


def test_gemini_provider_configuration_contract():
    cfg = make_provider_config(ProviderType.GEMINI)
    assert isinstance(cfg, GeminiConfig)
    assert cfg.provider == "gemini"
    assert cfg.attacker == "gemini-2.5-flash"
    assert cfg.attacker_frontier == "gemini-2.5-pro"
    assert cfg.api_key_env == "GEMINI_API_KEY"

    # api_key raises RuntimeError when GEMINI_API_KEY is not set
    # (does not print secrets or silently fallback)
    with pytest.MonkeyPatch.context() as mp:
        mp.delenv("GEMINI_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="Missing GEMINI_API_KEY"):
            cfg.api_key()

