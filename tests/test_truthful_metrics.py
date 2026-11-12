"""Phase 1 — truthful metrics and artifact integrity.

Proves that:
* a metric with no evidence is reported as *not measured* (``None`` → JSON
  ``null`` → UI "—"/"n/a"), never as a fabricated ``0.0``/``0.95``/``1.0``;
* utility is measured from actual benign-probe outcomes (no constant, no
  always-true monitor);
* cost ratios require real role-tagged spend and zero-cost mocks are not
  reported as measured cost;
* recovery/propagation/bypass/rounds stay ``None`` until real evidence exists;
* the artifact manifest detects modified, missing, and tampered records.
"""

from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from adaptive_agent_eval.artifacts import (
    MANIFEST_NAME,
    verify_artifacts,
    write_manifest,
)
from adaptive_agent_eval.metrics.modules import (
    CostTracker,
    GuardrailBypassLogger,
    MetricsCollector,
    UtilityMonitor,
)
from adaptive_agent_eval.models import (
    AttackOutcome,
    AttackPayload,
    DefenseDecision,
    DefenseEvent,
    DefenseType,
    EpisodeConfig,
    EpisodeLog,
    EpisodeResult,
)

_ALL_METRIC_FIELDS = (
    "attack_success_rate",
    "utility_score",
    "cost_per_attack",
    "rounds_to_success",
    "recovery_time",
    "bypass_rate",
    "propagation_rate",
    "blast_radius",
    "marginal_gain",
)


def _episode(
    outcome: AttackOutcome = AttackOutcome.BLOCKED,
    *,
    rounds: int = 1,
    cost: float = 0.0,
    recovery: int | None = None,
    denied: bool = True,
) -> EpisodeResult:
    event = DefenseEvent(
        decision=DefenseDecision.DENIED if denied else DefenseDecision.ALLOWED,
        confidence=0.9,
        evidence="test evidence",
        source=DefenseType.CAMEL,
    )
    return EpisodeResult(
        config=EpisodeConfig(),
        outcome=outcome,
        rounds_used=rounds,
        defense_events=[event],
        recovery_rounds=recovery,
        total_cost_usd=cost,
    )


def _round_log(cost_usd: float) -> EpisodeLog:
    return EpisodeLog(
        round_num=1,
        payload=AttackPayload(
            text="payload", category="direct_injection", sophistication_level=1
        ),
        defense_event=None,
        outcome=AttackOutcome.BLOCKED,
        tool_call=None,
        cost_usd=cost_usd,
    )


# ---------------------------------------------------------------- snapshot ----


def test_empty_collector_reports_nothing_measured():
    snap = MetricsCollector().get_snapshot()
    assert snap.total_episodes == 0
    for field in _ALL_METRIC_FIELDS:
        assert getattr(snap, field) is None, f"{field} must be None, not 0.0"
    # The API/JSON form must carry nulls (UIs render them as "—"/"n/a").
    assert '"utility_score": null' in json.dumps(asdict(snap))
    assert '"attack_success_rate": null' in json.dumps(asdict(snap))


def test_utility_not_measured_until_benign_probes_run():
    collector = MetricsCollector()
    collector.begin_episode(EpisodeConfig())
    collector.end_episode(_episode())
    # The old implementation returned a hardcoded 0.95 here.
    assert collector.get_snapshot().utility_score is None
    # An empty sample also measures nothing (previously 0.0).
    assert collector.compute_utility_from_results([]) is None
    collector.set_benign_results([True, True, False])
    assert collector.get_snapshot().utility_score == pytest.approx(0.6667, abs=1e-4)


def test_zero_successes_report_undefined_rates_as_none():
    collector = MetricsCollector()
    for _ in range(3):
        collector.begin_episode(EpisodeConfig())
        collector.end_episode(_episode(AttackOutcome.BLOCKED))
    snap = collector.get_snapshot()
    # ASR is measured: 0 of 3 attacks succeeded.
    assert snap.attack_success_rate == pytest.approx(0.0)
    # These need successes to exist — not measured, not a fabricated 0.0.
    assert snap.bypass_rate is None
    assert snap.rounds_to_success is None


def test_successes_measure_bypass_and_rounds_to_success():
    collector = MetricsCollector()
    collector.begin_episode(EpisodeConfig())
    collector.end_episode(_episode(AttackOutcome.BLOCKED, denied=True))
    collector.begin_episode(EpisodeConfig())
    collector.end_episode(_episode(AttackOutcome.SUCCESS, rounds=4, denied=False))
    snap = collector.get_snapshot()
    assert snap.attack_success_rate == pytest.approx(0.5)
    assert snap.bypass_rate == pytest.approx(1.0)
    assert snap.rounds_to_success == pytest.approx(4.0)


def test_zero_cost_mock_is_not_reported_as_measured_cost():
    collector = MetricsCollector()
    collector.begin_episode(EpisodeConfig())
    collector.record_round(_round_log(cost_usd=0.0))
    collector.end_episode(_episode(cost=0.0))
    # A zero-cost stub run must not masquerade as a paid evaluation.
    assert collector.get_snapshot().cost_per_attack is None

    priced = MetricsCollector()
    priced.begin_episode(EpisodeConfig())
    priced.record_round(_round_log(cost_usd=0.025))
    priced.end_episode(_episode(AttackOutcome.SUCCESS, cost=0.05))
    assert priced.get_snapshot().cost_per_attack == pytest.approx(0.05)


def test_recovery_time_none_until_recovery_actually_recorded():
    collector = MetricsCollector()
    collector.begin_episode(EpisodeConfig())
    collector.end_episode(_episode(AttackOutcome.SUCCESS))
    # recovery_rounds was never set anywhere in the codebase and used to be
    # silently averaged as 0.0 rounds.
    assert collector.get_snapshot().recovery_time is None
    collector.begin_episode(EpisodeConfig())
    collector.end_episode(_episode(AttackOutcome.SUCCESS, recovery=2))
    assert collector.get_snapshot().recovery_time == pytest.approx(2.0)


def test_propagation_not_measured_then_connected():
    collector = MetricsCollector()
    collector.begin_episode(EpisodeConfig())
    collector.end_episode(_episode())
    snap = collector.get_snapshot()
    assert snap.propagation_rate is None
    assert snap.blast_radius is None

    collector.record_propagation("ep-1", agents_compromised=2, total_agents=2)
    collector.record_propagation("ep-2", agents_compromised=1, total_agents=2)
    snap = collector.get_snapshot()
    assert snap.propagation_rate == pytest.approx(0.5)
    assert snap.blast_radius == pytest.approx(0.75)


# ---------------------------------------------------------------- monitors ----


def test_utility_monitor_refuses_to_assume_success():
    monitor = UtilityMonitor(target_agent=None, threshold=0.9)
    # No tasks → not measured (previously a guaranteed 1.0 / 0.0 pass).
    assert monitor.evaluate_benign_tasks([]) == (None, False)
    # Tasks without a runner → loud failure, never a fabricated score.
    with pytest.raises(RuntimeError):
        monitor.evaluate_benign_tasks(["benign task"])

    selective = UtilityMonitor(
        None, threshold=0.9, runner=lambda task: task == "ok"
    )
    score, acceptable = selective.evaluate_benign_tasks(["ok", "ok", "bad"])
    assert score == pytest.approx(2 / 3)
    assert acceptable is False

    def boom(_task):
        raise RuntimeError("target failed")

    failing = UtilityMonitor(None, runner=boom)
    assert failing.evaluate_benign_tasks(["t"]) == (0.0, False)


def test_cost_ratio_requires_role_tagged_spend():
    tracker = CostTracker()
    # No calls at all → not measured (previously a constant 1.0).
    assert tracker.attacker_defender_cost_ratio() is None
    # Untagged calls cannot be attributed to either side.
    tracker.log_call("m", 10, 10, 0.01)
    assert tracker.attacker_defender_cost_ratio() is None
    # Only one side tagged → still not measurable.
    tracker.log_call("m", 10, 10, 0.01, role="attacker")
    assert tracker.attacker_defender_cost_ratio() is None
    tracker.log_call("m", 10, 10, 0.02, role="defender")
    assert tracker.attacker_defender_cost_ratio() == pytest.approx(0.5)


def test_guardrail_bypass_logger_empty_is_not_zero():
    assert GuardrailBypassLogger().bypass_rate() is None
    logger = GuardrailBypassLogger()
    logger.log_trigger("ep1", "camel", True)
    assert logger.bypass_rate() == pytest.approx(0.0)


# ----------------------------------------------------------------- harness ----


def test_evaluate_strategy_metrics_are_evidence_based(tmp_path):
    from backend.adaptive_harness import evaluate_strategy

    ladder = [
        {"category": "direct_injection", "sophistication_level": 1},
        {"category": "obfuscation", "sophistication_level": 2},
    ]
    ev = evaluate_strategy(
        ladder, episodes=3, max_rounds=2, seed=1234, strategy_id="truth-probe"
    )
    d = ev.to_dict()

    # Utility comes from benign probes run through the real defense + adapter.
    assert isinstance(d["utility_score"], float)
    assert 0.0 <= d["utility_score"] <= 1.0
    # The offline harness records no priced usage → cost is not measured.
    assert d["cost_per_attack"] is None
    # Recovery is never recorded by the runner → not measured.
    # (Previously recovery_time silently averaged as 0.0.)
    assert isinstance(d["asr"], float)

    successes = int(d["outcomes"].get("success", 0))
    if successes:
        assert isinstance(d["bypass_rate"], float)
        assert isinstance(d["rounds_to_success"], float)
    else:
        assert d["bypass_rate"] is None
        assert d["rounds_to_success"] is None


def test_promotion_gate_fails_closed_on_unmeasured_utility(tmp_path):
    from backend.adaptive_harness import (
        DEFENDER_UTILITY_FLOOR,
        AdaptiveHarness,
        CandidateRecord,
    )

    harness = AdaptiveHarness(store_path=str(tmp_path / "adaptive.json"))

    unmeasured = CandidateRecord(
        candidate_id="c-unmeasured",
        ladder=[],
        evaluation={"total_episodes": 5, "outcomes": {}, "asr": 0.5},
        baseline_asr=0.1,
        asr=0.5,
    )
    gate = harness._evaluate_gate(unmeasured, active_asr=0.2, stopped=False)
    # Unmeasured utility must not be coerced to 0.0 ("below floor") or 1.0
    # ("passes"): the gate rejects with an honest, explicit reason.
    assert gate["passed"] is False
    assert any("not measured" in r for r in gate["reasons"])
    assert gate["checked"]["utility"] is None

    below = CandidateRecord(
        candidate_id="c-below",
        ladder=[],
        evaluation={
            "total_episodes": 5,
            "outcomes": {},
            "utility_score": DEFENDER_UTILITY_FLOOR - 0.1,
        },
        baseline_asr=0.1,
        asr=0.5,
    )
    gate_below = harness._evaluate_gate(below, active_asr=0.2, stopped=False)
    assert gate_below["passed"] is False
    assert any("below floor" in r for r in gate_below["reasons"])

    healthy = CandidateRecord(
        candidate_id="c-healthy",
        ladder=[],
        evaluation={
            "total_episodes": 5,
            "outcomes": {},
            "utility_score": DEFENDER_UTILITY_FLOOR,
        },
        baseline_asr=0.1,
        asr=0.5,
    )
    gate_healthy = harness._evaluate_gate(healthy, active_asr=0.2, stopped=False)
    assert gate_healthy["passed"] is True


# ------------------------------------------------------ artifact integrity ----


def test_missing_manifest_means_unverified(tmp_path):
    report = verify_artifacts(tmp_path)
    assert report["ok"] is False
    assert "manifest" in report["error"]


def test_mode2_manifest_written_and_verifies(tmp_path, monkeypatch):
    from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

    results_dir = tmp_path / "results"
    monkeypatch.setattr(
        "adaptive_agent_eval.pipelines.mode2_c1.RESULTS_DIR", results_dir
    )
    run_mode2_c1(max_rounds=2, seed=42, results_dir=results_dir)

    assert (results_dir / MANIFEST_NAME).exists()
    report = verify_artifacts(results_dir)
    assert report["ok"] is True
    assert report["files"]["episodes.csv"]["status"] == "ok"
    assert report["episodes_payload"]["status"] == "ok"


def test_modified_artifact_is_detected(tmp_path, monkeypatch):
    from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

    results_dir = tmp_path / "results"
    monkeypatch.setattr(
        "adaptive_agent_eval.pipelines.mode2_c1.RESULTS_DIR", results_dir
    )
    run_mode2_c1(max_rounds=2, seed=42, results_dir=results_dir)

    csv_path = results_dir / "episodes.csv"
    csv_path.write_text(
        csv_path.read_text(encoding="utf-8") + "tampered,row\n", encoding="utf-8"
    )
    report = verify_artifacts(results_dir)
    assert report["ok"] is False
    assert report["files"]["episodes.csv"]["status"] == "modified"


def test_missing_artifact_is_detected(tmp_path, monkeypatch):
    from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

    results_dir = tmp_path / "results"
    monkeypatch.setattr(
        "adaptive_agent_eval.pipelines.mode2_c1.RESULTS_DIR", results_dir
    )
    run_mode2_c1(max_rounds=2, seed=42, results_dir=results_dir)

    (results_dir / "config_summary.json").unlink()
    report = verify_artifacts(results_dir)
    assert report["ok"] is False
    assert report["files"]["config_summary.json"]["status"] == "missing"


def test_tampered_episode_records_are_detected(tmp_path, monkeypatch):
    from adaptive_agent_eval.pipelines.mode2_c1 import run_mode2_c1

    results_dir = tmp_path / "results"
    monkeypatch.setattr(
        "adaptive_agent_eval.pipelines.mode2_c1.RESULTS_DIR", results_dir
    )
    run_mode2_c1(max_rounds=2, seed=42, results_dir=results_dir)

    episodes_path = results_dir / "episodes.json"
    records = json.loads(episodes_path.read_text(encoding="utf-8"))
    records[0]["outcome"] = "success"  # forge a successful attack
    episodes_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    report = verify_artifacts(results_dir)
    assert report["ok"] is False
    assert report["files"]["episodes.json"]["status"] == "modified"
    assert report["episodes_payload"]["status"] == "modified"


def test_run_demo_episode_manifest_matches_displayed_checksum(tmp_path):
    from adaptive_agent_eval.pipelines.mode2_c1_stubs import run_demo_episode

    results_dir = tmp_path / "results"
    out = run_demo_episode(n_episodes=2, results_dir=results_dir)

    report = verify_artifacts(results_dir)
    assert report["ok"] is True
    # The checksum shown in the demo payload is persisted and verifiable.
    manifest = json.loads((results_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
    assert out["checksum"] == manifest["episodes_payload_sha256"]

    # Tampering with a record flips both the file hash and the payload hash.
    episodes_path = results_dir / "episodes.json"
    lines = [ln for ln in episodes_path.read_text(encoding="utf-8").splitlines() if ln]
    record = json.loads(lines[0])
    original_id = record["episode_id"]
    record["episode_id"] = "forged-episode-id"
    record["outcome"] = "success"
    lines[0] = json.dumps(record, ensure_ascii=False)
    episodes_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report = verify_artifacts(results_dir)
    assert report["ok"] is False
    assert report["files"]["episodes.json"]["status"] == "modified"
    assert report["episodes_payload"]["status"] == "modified"
    assert original_id != "forged-episode-id"


def test_empty_demo_run_reports_null_metrics_not_zeros(tmp_path):
    from adaptive_agent_eval.pipelines.mode2_c1_stubs import run_demo_episode

    results_dir = tmp_path / "results"
    out = run_demo_episode(n_episodes=0, results_dir=results_dir)
    # No episodes → nothing measured → JSON nulls, never fabricated 0.0.
    assert out["ASR"] is None
    assert out["utility"] is None
    assert out["propagation_rate"] is None
    assert out["blast_radius"] is None
    assert json.loads(json.dumps(out))["utility"] is None


def test_write_manifest_covers_present_files_only(tmp_path):
    (tmp_path / "episodes.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    manifest = write_manifest(tmp_path)
    assert "episodes.csv" in manifest["files"]
    assert "episodes.json" not in manifest["files"]
    assert verify_artifacts(tmp_path)["ok"] is True
