"""Tests for shared data models."""

from adaptive_agent_eval.models import (
    AttackOutcome,
    AttackPayload,
    DefenseDecision,
    DefenseEvent,
    DefenseType,
    EpisodeConfig,
    EpisodeLog,
    EpisodeMode,
    EpisodeResult,
    ToolCallRequest,
)


def test_episode_config_defaults():
    config = EpisodeConfig()
    assert config.mode == EpisodeMode.SINGLE_AGENT
    assert config.defense == DefenseType.CAMEL
    assert config.max_rounds == 5
    assert len(config.episode_id) == 12


def test_attack_payload():
    payload = AttackPayload(
        text="test payload",
        category="direct_injection",
        sophistication_level=1,
    )
    assert payload.text == "test payload"
    assert payload.a5_category_flag is False


def test_defense_event():
    event = DefenseEvent(
        decision=DefenseDecision.DENIED,
        confidence=0.9,
        evidence="Tainted data",
        source=DefenseType.CAMEL,
    )
    assert event.decision == DefenseDecision.DENIED
    assert event.confidence == 0.9


def test_episode_result_attack_succeeded():
    config = EpisodeConfig()
    result = EpisodeResult(
        config=config,
        outcome=AttackOutcome.SUCCESS,
    )
    assert result.attack_succeeded is True

    result_fail = EpisodeResult(
        config=config,
        outcome=AttackOutcome.BLOCKED,
    )
    assert result_fail.attack_succeeded is False


def test_stop_condition_checksum():
    from adaptive_agent_eval.controller.orchestrator import StopCondition

    stop = StopCondition()
    checksum1 = stop.checksum()

    stop.attack_success = True
    checksum2 = stop.checksum()

    assert checksum1 != checksum2


def test_defense_adapter_majority_voting():
    from adaptive_agent_eval.defense.adapter import DefenseAdapter

    adapter = DefenseAdapter()

    # Two denies, one allow -> majority deny
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
