"""Phase 2 — shared contracts: lifecycle, defense events, aggregation,
ground truth, experiment configuration and integration reports.

All fixtures are small and deterministic: no LLM calls, no Gmail, no
experiment execution.
"""

from __future__ import annotations

import json

import pytest

from adaptive_agent_eval.contracts import (
    AGGREGATION_POLICY,
    ALLOWED_ATTACKER_TYPES,
    ContractValidationError,
    ContractViolation,
    ExperimentConfig,
    ExperimentRecord,
    IntegrationReport,
    aggregate_defense_decisions,
    assert_episode_transition,
    assert_experiment_transition,
    defense_event_from_dict,
    is_valid_episode_transition,
    is_valid_experiment_transition,
    parse_ground_truth,
)
from adaptive_agent_eval.models import (
    AttackerTier,
    AttackOutcome,
    DefenseDecision,
    DefenseEvent,
    DefenseImplementation,
    DefenseType,
    EpisodeConfig,
    EpisodeMode,
    EpisodeResult,
    EpisodeStatus,
    ExperimentStatus,
    GroundTruthOutcome,
    IntegrationStatus,
)


def _event(
    decision: DefenseDecision = DefenseDecision.DENIED,
    confidence: float | None = 0.8,
    source: DefenseType | None = DefenseType.CAMEL,
    evidence: str = "evidence",
) -> DefenseEvent:
    return DefenseEvent(
        decision=decision,
        confidence=confidence,
        evidence=evidence,
        source=source,
    )


def _config(**overrides) -> ExperimentConfig:
    base = {
        "mode": EpisodeMode.SINGLE_AGENT,
        "defenses": (DefenseType.CAMEL,),
        "episodes": 50,
        "seed": 42,
        "max_rounds": 5,
    }
    base.update(overrides)
    return ExperimentConfig(**base)


# ------------------------------------------------------------- lifecycle ----


def test_valid_experiment_transitions():
    assert is_valid_experiment_transition(
        ExperimentStatus.CREATED, ExperimentStatus.RUNNING
    )
    assert is_valid_experiment_transition(
        ExperimentStatus.RUNNING, ExperimentStatus.COMPLETED
    )
    assert is_valid_experiment_transition(
        ExperimentStatus.RUNNING, ExperimentStatus.INTERRUPTED
    )
    # An interrupted run may be resumed.
    assert is_valid_experiment_transition(
        ExperimentStatus.INTERRUPTED, ExperimentStatus.RUNNING
    )
    for current, target in [
        (ExperimentStatus.CREATED, ExperimentStatus.RUNNING),
        (ExperimentStatus.CREATED, ExperimentStatus.CANCELLED),
        (ExperimentStatus.CREATED, ExperimentStatus.FAILED),
        (ExperimentStatus.RUNNING, ExperimentStatus.FAILED),
        (ExperimentStatus.RUNNING, ExperimentStatus.CANCELLED),
    ]:
        assert_experiment_transition(current, target)  # must not raise


@pytest.mark.parametrize(
    "current,target",
    [
        (ExperimentStatus.CREATED, ExperimentStatus.COMPLETED),
        (ExperimentStatus.CREATED, ExperimentStatus.INTERRUPTED),
        (ExperimentStatus.RUNNING, ExperimentStatus.CREATED),
        (ExperimentStatus.COMPLETED, ExperimentStatus.RUNNING),
        (ExperimentStatus.COMPLETED, ExperimentStatus.FAILED),
        (ExperimentStatus.FAILED, ExperimentStatus.COMPLETED),
        (ExperimentStatus.CANCELLED, ExperimentStatus.RUNNING),
        (ExperimentStatus.INTERRUPTED, ExperimentStatus.COMPLETED),
    ],
)
def test_invalid_experiment_transitions_rejected(current, target):
    with pytest.raises(ContractViolation) as exc:
        assert_experiment_transition(current, target)
    # Exception messages stay ASCII so they print on any console (cp1252).
    str(exc.value).encode("ascii")


def test_failed_run_cannot_become_completed():
    record = ExperimentRecord(config=_config())
    record.transition(ExperimentStatus.RUNNING)
    record.transition(ExperimentStatus.FAILED, error="boom")
    for _ in range(50):
        record.note_episode(EpisodeStatus.COMPLETED)
    with pytest.raises(ContractViolation) as exc:
        record.transition(ExperimentStatus.COMPLETED)
    assert "failed -> completed" in str(exc.value)


def test_completed_requires_every_episode():
    record = ExperimentRecord(config=_config(episodes=50))
    record.transition(ExperimentStatus.RUNNING)
    record.note_episode(EpisodeStatus.COMPLETED)
    with pytest.raises(ContractViolation) as exc:
        record.transition(ExperimentStatus.COMPLETED)
    assert "1/50" in str(exc.value)
    # A summary object alone must not complete a partial run.
    assert record.status == ExperimentStatus.RUNNING

    for _ in range(49):
        record.note_episode(EpisodeStatus.COMPLETED)
    record.transition(ExperimentStatus.COMPLETED)
    assert record.started_at is not None
    assert record.finished_at is not None


def test_partially_failed_run_cannot_complete():
    record = ExperimentRecord(config=_config(episodes=3))
    record.transition(ExperimentStatus.RUNNING)
    record.note_episode(EpisodeStatus.COMPLETED)
    record.note_episode(EpisodeStatus.FAILED)
    record.note_episode(EpisodeStatus.COMPLETED)
    with pytest.raises(ContractViolation):
        record.transition(ExperimentStatus.COMPLETED)


def test_episode_transitions_and_counters():
    assert is_valid_episode_transition(
        EpisodeStatus.PENDING, EpisodeStatus.RUNNING
    )
    assert is_valid_episode_transition(
        EpisodeStatus.RUNNING, EpisodeStatus.COMPLETED
    )
    with pytest.raises(ContractViolation):
        assert_episode_transition(EpisodeStatus.COMPLETED, EpisodeStatus.RUNNING)
    with pytest.raises(ContractViolation):
        assert_episode_transition(EpisodeStatus.SKIPPED, EpisodeStatus.RUNNING)

    record = ExperimentRecord(config=_config(episodes=4))
    record.note_episode(EpisodeStatus.COMPLETED)
    record.note_episode(EpisodeStatus.FAILED)
    record.note_episode(EpisodeStatus.SKIPPED)
    record.note_episode(EpisodeStatus.CANCELLED)
    assert record.episodes_completed == 1
    assert record.episodes_failed == 1
    assert record.episodes_skipped == 1
    assert record.episodes_cancelled == 1
    with pytest.raises(ContractViolation):
        record.note_episode(EpisodeStatus.RUNNING)  # not terminal


def test_experiment_record_roundtrip():
    record = ExperimentRecord(config=_config(), config_id="M1-01")
    record.transition(ExperimentStatus.RUNNING)
    record.note_episode(EpisodeStatus.COMPLETED)
    payload = json.dumps(record.to_dict())
    restored = ExperimentRecord.from_dict(json.loads(payload))
    assert restored.experiment_id == record.experiment_id
    assert restored.config_id == "M1-01"
    assert restored.status == ExperimentStatus.RUNNING
    assert restored.episodes_completed == 1
    assert restored.config == record.config


# ------------------------------------------------------- defense events -----


def test_defense_event_valid_values():
    ev = _event(confidence=0.95)
    assert ev.implementation_type == DefenseImplementation.LOCAL_IMPLEMENTATION
    assert ev.experiment_id is None and ev.round_num is None
    no_calc = _event(decision=DefenseDecision.NO_SIGNAL, confidence=None, source=None)
    assert no_calc.confidence is None
    assert no_calc.source is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"decision": "denied"},  # raw string is not a DefenseDecision instance
        {"confidence": 1.5},
        {"confidence": -0.1},
        {"confidence": True},
        {"confidence": "high"},
        {"source": "camel"},
        {"implementation_type": "mock"},
        {"evidence": None},
    ],
)
def test_defense_event_rejects_invalid_records(kwargs):
    base = {
        "decision": DefenseDecision.DENIED,
        "confidence": 0.5,
        "evidence": "e",
        "source": DefenseType.CAMEL,
    }
    base.update(kwargs)
    with pytest.raises(ContractViolation):
        DefenseEvent(**base)


def test_defense_event_from_dict_contract():
    legacy = {
        "decision": "denied",
        "confidence": 0.9,
        "evidence": "marker matched",
        "source": "camel",
    }
    ev = defense_event_from_dict(legacy)  # legacy 4-field payloads still load
    assert ev.decision == DefenseDecision.DENIED
    assert ev.source == DefenseType.CAMEL
    assert ev.implementation_type == DefenseImplementation.LOCAL_IMPLEMENTATION

    enriched = dict(
        legacy,
        implementation_type="proxy",
        experiment_id="exp1",
        episode_id="ep1",
        round_num=2,
        timestamp=123.0,
        latency_ms=4.5,
    )
    ev2 = defense_event_from_dict(enriched)
    assert ev2.implementation_type == DefenseImplementation.PROXY
    assert ev2.episode_id == "ep1" and ev2.round_num == 2

    with pytest.raises(ContractViolation) as exc:
        defense_event_from_dict({"decision": "block", "confidence": 0.5, "evidence": "x", "source": "camel"})
    assert "invalid decision" in str(exc.value)
    with pytest.raises(ContractViolation) as exc:
        defense_event_from_dict({"decision": "denied"})
    assert "missing required" in str(exc.value)
    with pytest.raises(ContractViolation) as exc:
        defense_event_from_dict(dict(legacy, sneaky=1))
    assert "unknown defense event field" in str(exc.value)


# ----------------------------------------------------------- aggregation ----


def test_aggregation_majority_and_fields():
    events = [
        _event(DefenseDecision.DENIED, 0.8, DefenseType.CAMEL),
        _event(DefenseDecision.DENIED, 0.7, DefenseType.PROGENT),
        _event(DefenseDecision.ALLOWED, 0.9, DefenseType.VERIFIER),
    ]
    # "none" means no defense ran; it can never be a missing voting source.
    voting = [d for d in DefenseType if d is not DefenseType.NONE]
    agg = aggregate_defense_decisions(events, expected_defenses=voting)
    assert agg.decision == DefenseDecision.DENIED
    assert agg.denied_count == 2 and agg.allowed_count == 1
    assert agg.tie is False and agg.fail_closed is False
    assert agg.missing_defenses == ()
    assert len(agg.events) == 3  # individual records stay separate
    assert ("camel", "denied") in agg.votes
    assert agg.policy == AGGREGATION_POLICY
    payload = json.dumps(agg.to_dict())
    assert '"decision": "denied"' in payload


def test_aggregation_tie_breaks_to_denied():
    events = [
        _event(DefenseDecision.DENIED, 0.8, DefenseType.CAMEL),
        _event(DefenseDecision.ALLOWED, 0.7, DefenseType.PROGENT),
    ]
    agg = aggregate_defense_decisions(events)
    assert agg.decision == DefenseDecision.DENIED
    assert agg.tie is True
    assert agg.fail_closed is False  # the deny-on-tie rule is not fail-closed


def test_aggregation_empty_events_is_no_signal_not_approval():
    agg = aggregate_defense_decisions([])
    assert agg.decision == DefenseDecision.NO_SIGNAL
    assert agg.fail_closed is False
    assert agg.tie is False


def test_aggregation_no_signal_does_not_vote():
    agg = aggregate_defense_decisions(
        [
            _event(DefenseDecision.ALLOWED, 0.7, DefenseType.CAMEL),
            _event(DefenseDecision.NO_SIGNAL, None, DefenseType.PROGENT),
        ]
    )
    assert agg.decision == DefenseDecision.ALLOWED
    assert agg.allowed_count == 1 and agg.no_signal_count == 1


def test_aggregation_single_no_signal_passes_through():
    agg = aggregate_defense_decisions(
        [_event(DefenseDecision.NO_SIGNAL, None, None)]
    )
    assert agg.decision == DefenseDecision.NO_SIGNAL


def test_aggregation_missing_expected_defense_fails_closed():
    agg = aggregate_defense_decisions(
        [_event(DefenseDecision.ALLOWED, 0.9, DefenseType.CAMEL)],
        expected_defenses=[DefenseType.CAMEL, DefenseType.VERIFIER],
    )
    # An allow must NOT survive when an expected defense never reported.
    assert agg.decision == DefenseDecision.DENIED
    assert agg.fail_closed is True
    assert agg.missing_defenses == ("verifier",)
    assert "fail-closed" in agg.evidence


def test_aggregation_defense_errors_fail_closed():
    agg = aggregate_defense_decisions(
        [_event(DefenseDecision.ALLOWED, 0.9, DefenseType.CAMEL)],
        errors=["progent raised TimeoutError after 3 retries"],
    )
    assert agg.decision == DefenseDecision.DENIED
    assert agg.fail_closed is True
    assert agg.errors and "TimeoutError" in agg.errors[0]
    assert "defense errors" in agg.evidence


def test_aggregation_no_events_but_expected_fails_closed():
    agg = aggregate_defense_decisions(
        [], expected_defenses=[DefenseType.CAMEL]
    )
    assert agg.decision == DefenseDecision.DENIED
    assert agg.fail_closed is True
    assert agg.missing_defenses == ("camel",)


def test_aggregation_rejects_non_events():
    with pytest.raises(ContractViolation):
        aggregate_defense_decisions([{"decision": "denied"}])  # type: ignore[list-item]


def test_aggregation_policy_documents_key_rules():
    for phrase in (
        "deny-on-tie",
        "fails closed",
        "NO_SIGNAL never votes",
        "absence of signal, not an approval",
    ):
        assert phrase in AGGREGATION_POLICY
    # Policy text must print on any console.
    AGGREGATION_POLICY.encode("ascii")


# ------------------------------------------------------------ ground truth --


def test_ground_truth_values_and_parse():
    assert {v.value for v in GroundTruthOutcome} == {
        "successful_attack",
        "partial_success",
        "failed_attack",
        "detected_not_blocked",
        "blocked",
        "indeterminate",
    }
    assert (
        parse_ground_truth("detected_not_blocked")
        == GroundTruthOutcome.DETECTED_NOT_BLOCKED
    )
    assert parse_ground_truth(GroundTruthOutcome.BLOCKED) == GroundTruthOutcome.BLOCKED
    with pytest.raises(ContractViolation):
        parse_ground_truth("kinda_blocked")


def test_episode_result_defaults_are_honest():
    result = EpisodeResult(config=EpisodeConfig(), outcome=AttackOutcome.BLOCKED)
    assert result.status == EpisodeStatus.COMPLETED
    assert result.ground_truth is None  # not evaluated -> no guess
    # backward-compatible field names still present
    for key in (
        "config",
        "outcome",
        "rounds_used",
        "total_cost_usd",
        "diagnostics",
        "recovery_rounds",
    ):
        assert key in result.__dict__
    assert result.__dict__["recovery_rounds"] is None


# ---------------------------------------------- experiment configuration ----


def test_valid_config_roundtrip():
    cfg = _config(attacker_tier=AttackerTier.FRONTIER)
    cfg.validate()
    restored = ExperimentConfig.from_dict(cfg.to_dict())
    assert restored == cfg
    payload = json.dumps(cfg.to_dict())
    assert restored == ExperimentConfig.from_dict(json.loads(payload))
    # required factors have no silent defaults
    assert cfg.episodes == 50 and cfg.seed == 42 and cfg.max_rounds == 5
    assert cfg.defenses == (DefenseType.CAMEL,)


def test_config_collects_all_errors():
    # Structurally valid config, many value errors: all collected at once.
    cfg = ExperimentConfig(
        mode=EpisodeMode.SINGLE_AGENT,
        defenses=(DefenseType.CAMEL, DefenseType.CAMEL),
        episodes=0,
        seed=-1,
        max_rounds=0,
        agent_setup="multi-agent",
    )
    with pytest.raises(ContractValidationError) as exc:
        cfg.validate()
    errors = exc.value.errors
    assert len(errors) >= 6
    joined = "; ".join(errors)
    assert "episodes" in joined
    assert "max_rounds" in joined
    assert "seed" in joined
    assert "duplicates" in joined
    assert "exactly one defense" in joined
    assert "multi-agent is only defined for cross-agent" in joined

    # An invalid mode is itself reported (reasoning about mode-specific
    # combinations requires a valid mode, so it is checked separately).
    bad_mode = ExperimentConfig(
        mode="bogus",  # type: ignore[arg-type]
        defenses=(DefenseType.CAMEL,),
        episodes=1,
        seed=1,
        max_rounds=1,
    )
    with pytest.raises(ContractValidationError) as exc2:
        bad_mode.validate()
    assert "mode" in "; ".join(exc2.value.errors)


def test_config_from_dict_missing_required_fields():
    with pytest.raises(ContractValidationError) as exc:
        ExperimentConfig.from_dict({})
    joined = "; ".join(exc.value.errors)
    for key in ("mode", "defenses", "episodes", "seed", "max_rounds"):
        assert f"missing required field: {key}" in joined


def test_config_from_dict_unknown_and_invalid_values():
    with pytest.raises(ContractValidationError) as exc:
        ExperimentConfig.from_dict(
            {
                "mode": "free-for-all",
                "defenses": ["camel", "shields-up"],
                "episodes": 10,
                "seed": 1,
                "max_rounds": 2,
                "surprise": True,
            }
        )
    joined = "; ".join(exc.value.errors)
    assert "unknown field: surprise" in joined
    assert "invalid value 'free-for-all'" in joined
    assert "invalid value 'shields-up'" in joined


@pytest.mark.parametrize(
    "overrides,needle",
    [
        (
            {
                "mode": EpisodeMode.DEFENSE_COMPOSITION,
                "defenses": (DefenseType.CAMEL,),
            },
            "2 or 3 stacked defenses",
        ),
        (
            {
                "mode": EpisodeMode.SINGLE_AGENT,
                "defenses": (DefenseType.CAMEL, DefenseType.PROGENT),
            },
            "exactly one defense",
        ),
        ({"agent_setup": "multi-agent"}, "multi-agent is only defined"),
        ({"episodes": 0}, "must be positive"),
        ({"episodes": -5}, "must be positive"),
        ({"max_rounds": 0}, "max_rounds"),
        ({"seed": -1}, "seed"),
        (
            {"attacker_type": "static-baseline"},
            "attacker_type: unsupported",
        ),
        ({"provider": "cohere"}, "provider: unsupported"),
        ({"cheap_model": ""}, "cheap_model"),
        ({"cheap_model": "AIza" + "x" * 40}, "credential"),
        ({"label": "sk-" + "a" * 24}, "credential"),
        ({"max_technical_failures": 0}, "max_technical_failures"),
    ],
)
def test_config_unsupported_or_invalid_combinations(overrides, needle):
    cfg = _config(**overrides)
    with pytest.raises(ContractValidationError) as exc:
        cfg.validate()
    assert needle in "; ".join(exc.value.errors)


def test_cross_agent_and_composition_shapes_accepted():
    cross = _config(
        mode=EpisodeMode.CROSS_AGENT,
        agent_setup="multi-agent",
    )
    cross.validate()
    stacked = _config(
        mode=EpisodeMode.DEFENSE_COMPOSITION,
        defenses=(DefenseType.CAMEL, DefenseType.PROGENT, DefenseType.VERIFIER),
    )
    stacked.validate()
    single_cross = _config(mode=EpisodeMode.CROSS_AGENT, agent_setup="single-agent")
    single_cross.validate()


def test_allowed_attacker_types_reflect_implemented_surface():
    assert ALLOWED_ATTACKER_TYPES == ("adaptive-hill-climbing",)


# ------------------------------------------------------ integration report --


def test_integration_report_contract():
    report = IntegrationReport(
        "agentdojo", IntegrationStatus.NOT_INSTALLED, "not installed"
    )
    assert report.to_dict() == {
        "name": "agentdojo",
        "status": "not_installed",
        "detail": "not installed",
    }
    restored = IntegrationReport.from_dict(report.to_dict())
    assert restored == report
    with pytest.raises(ContractViolation):
        IntegrationReport("", IntegrationStatus.AVAILABLE)
    with pytest.raises(ContractViolation):
        IntegrationReport("x", "connected")  # type: ignore[arg-type]
    with pytest.raises(ContractViolation):
        IntegrationReport.from_dict({"name": "x"})
