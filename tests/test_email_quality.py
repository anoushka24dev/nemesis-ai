"""Tests for message-quality evaluation and the settings hill-climber
(Phase 2, Objective 6).

The optimizer may only touch GenerationSettings knobs, is gated by a fixed
synthetic dataset plus explicit reviewer verdicts, is versioned/auditable/
reversible, and can never alter permission/policy settings.
"""
from __future__ import annotations

import json

import pytest

from email_workflow import quality as q
from email_workflow.compose import KNOB_SCHEMA, GenerationSettings
from email_workflow.policy import IMMUTABLE_POLICY_KEYS

BEST = GenerationSettings(tone="formal", length="concise", greeting=True, sign_off=True)


@pytest.fixture()
def store(tmp_path):
    return tmp_path / "quality_store.json"


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def test_concise_has_full_support_and_normal_has_unsupported_claim():
    concise = q.evaluate_settings(GenerationSettings(length="concise"))
    normal = q.evaluate_settings(GenerationSettings(length="normal"))
    assert concise["metrics"]["unsupported_claim_rate"] == 0.0
    assert concise["metrics"]["factual_support"] == 1.0
    # The extra template sentence in "normal" makes an unverifiable claim.
    assert normal["metrics"]["unsupported_claim_rate"] > 0.0
    assert normal["metrics"]["factual_support"] < 1.0


def test_tone_metric_tracks_expected_tone():
    formal = q.evaluate_settings(GenerationSettings(tone="formal"))
    friendly = q.evaluate_settings(GenerationSettings(tone="friendly"))
    # The fixed dataset expects "formal" for a plurality of cases.
    assert formal["metrics"]["tone_appropriateness"] > friendly["metrics"]["tone_appropriateness"]


def test_evaluation_is_deterministic():
    a = q.evaluate_settings(BEST)
    b = q.evaluate_settings(BEST)
    assert a == b


def test_dataset_is_fixed_and_synthetic():
    import re

    assert len(q.DEFAULT_QUALITY_DATASET) >= 6
    for case in q.DEFAULT_QUALITY_DATASET:
        assert case.case_id and case.sender and case.subject
        assert case.expected_tone in ("neutral", "formal", "friendly")
        # No long real-identifier-like digit runs in the synthetic dataset.
        assert not re.search(r"\b(?:\d[\s-]?){7,}\d\b", case.body)


def test_knobs_are_generation_only():
    assert not (set(KNOB_SCHEMA) & IMMUTABLE_POLICY_KEYS)


# ---------------------------------------------------------------------------
# Hill-climbing
# ---------------------------------------------------------------------------


def test_hill_climb_improves_from_shipped_defaults_and_stops():
    start = GenerationSettings()
    before = q.evaluate_settings(start)
    climb = q.hill_climb(start=start, max_iterations=16)
    assert climb["improved"] is True
    assert climb["end_score"] > climb["start_score"] == before["score"]
    assert climb["stopped_because"] == "no improving neighbor"
    assert climb["iterations"] < 16
    assert climb["history"]
    # Accepted steps are strictly improving and eligible at every point.
    previous = climb["start_score"]
    for step in climb["history"]:
        assert step["score_after"] > step["score_before"] == previous
        previous = step["score_after"]
    assert climb["end_score"] == previous


def test_hill_climb_only_produces_generation_settings():
    climb = q.hill_climb(max_iterations=16)
    assert set(climb["end_settings"]) == set(KNOB_SCHEMA)
    GenerationSettings.from_dict(climb["end_settings"])  # validates bounds


def test_hill_climb_converges_at_local_optimum_not_budget():
    climb = q.hill_climb(max_iterations=16)
    assert climb["stopped_because"] == "no improving neighbor"


def test_hill_climb_persists_nothing(store):
    climb = q.hill_climb(path=store, max_iterations=16)
    assert climb["improved"]
    assert not store.exists()


# ---------------------------------------------------------------------------
# Versioned, reviewer-gated promotion
# ---------------------------------------------------------------------------


def test_promotion_requires_reviewer_gate_then_applies(store):
    climb = q.hill_climb(path=store, max_iterations=16)
    best = GenerationSettings.from_dict(climb["end_settings"])
    candidate = q.propose_candidate(best, "climb result", path=store)
    assert candidate["eligible"] and candidate["score"] > candidate["before_score"]

    deferred = q.apply_candidate(candidate["candidate_id"], path=store)
    assert deferred["applied"] is False
    assert "reviewer gate" in deferred["rejected_reason"]
    # Deferred is readiness, not rejection: candidate stays pending.
    data = q._load(store)
    assert data["candidates"][0]["status"] == "pending"
    assert data["active_version"] == "email-quality-v1"

    for i in range(q.MIN_REVIEWS):
        q.record_review("q-formal-contract", best, accepted=True,
                        reviewer=f"rev-{i}", path=store)
    applied = q.apply_candidate(candidate["candidate_id"], path=store)
    assert applied["applied"] is True
    assert applied["version"] == "email-quality-v2"
    assert applied["verdict"] == "improved"
    assert q.active_settings(store) == best


def test_rejected_reviewer_verdicts_block_promotion(store):
    climb = q.hill_climb(path=store, max_iterations=16)
    best = GenerationSettings.from_dict(climb["end_settings"])
    candidate = q.propose_candidate(best, "climb result", path=store)
    for i in range(q.MIN_REVIEWS):
        q.record_review("q-formal-contract", best, accepted=False,
                        reviewer=f"rev-{i}", path=store)
    report = q.apply_candidate(candidate["candidate_id"], path=store)
    assert report["applied"] is False
    assert report["reviewer_gate"]["acceptance_rate"] < q.MIN_ACCEPTANCE
    assert q._load(store)["active_version"] == "email-quality-v1"


def test_regression_is_hard_rejected_and_status_sticky(store):
    for i in range(q.MIN_REVIEWS):
        q.record_review("q-formal-contract", BEST, accepted=True,
                        reviewer=f"rev-{i}", path=store)
    good = q.propose_candidate(BEST, "best settings", path=store)
    assert q.apply_candidate(good["candidate_id"], path=store)["applied"] is True

    # A friendly/normal candidate is eligible but scores lower: regression.
    worse = GenerationSettings(tone="friendly", length="concise")
    assert q.evaluate_settings(worse)["eligible"] is True
    bad = q.propose_candidate(worse, "deliberately worse", path=store)
    assert q.evaluate_settings(BEST)["score"] > bad["score"]
    report = q.apply_candidate(bad["candidate_id"], path=store)
    assert report["applied"] is False
    assert "regressed" in report["rejected_reason"]
    assert q._load(store)["candidates"][-1]["status"] == "rejected"
    # Sticky: cannot be revived later.
    with pytest.raises(q.QualityError):
        q.apply_candidate(bad["candidate_id"], path=store)


def test_ineligible_candidate_is_rejected(store):
    # tone wrong + normal length: ineligible through unsupported claims.
    ineligible = GenerationSettings(tone="friendly", length="normal")
    assert q.evaluate_settings(ineligible)["eligible"] is False
    candidate = q.propose_candidate(ineligible, "bad", path=store)
    assert candidate["eligible"] is False
    report = q.apply_candidate(candidate["candidate_id"], path=store)
    assert report["applied"] is False
    assert "ineligible" in report["rejected_reason"]


def test_candidate_equals_active_is_rejected(store):
    for i in range(q.MIN_REVIEWS):
        q.record_review("c", GenerationSettings(), accepted=True,
                        reviewer=f"rev-{i}", path=store)
    candidate = q.propose_candidate(GenerationSettings(), "no-op", path=store)
    report = q.apply_candidate(candidate["candidate_id"], path=store)
    assert report["applied"] is False
    assert "equals the active" in report["rejected_reason"]


def test_revert_returns_to_previous_version(store):
    climb = q.hill_climb(path=store, max_iterations=16)
    best = GenerationSettings.from_dict(climb["end_settings"])
    candidate = q.propose_candidate(best, "climb result", path=store)
    for i in range(q.MIN_REVIEWS):
        q.record_review("c", best, accepted=True, reviewer=f"rev-{i}", path=store)
    q.apply_candidate(candidate["candidate_id"], path=store)
    assert q.active_settings(store) == best
    out = q.revert(path=store)
    assert out["reverted"] is True and out["to"] == "email-quality-v1"
    assert q.active_settings(store) == GenerationSettings()


def test_rationale_required_and_audit_trail(store):
    with pytest.raises(q.QualityError):
        q.propose_candidate(BEST, "  ", path=store)
    q.propose_candidate(BEST, "testing audit", path=store)
    data = q._load(store)
    actions = [entry["action"] for entry in data["audit"]]
    assert "propose_candidate" in actions


# ---------------------------------------------------------------------------
# Permissions are unreachable for the optimizer
# ---------------------------------------------------------------------------


def test_policy_keys_rejected_everywhere(store):
    poisoned = {"tone": "formal", "kill_switch": False}
    with pytest.raises(q.QualityError):
        q.propose_candidate(poisoned, "sneaky", path=store)
    with pytest.raises(q.QualityError):
        q.record_review("c", poisoned, accepted=True, reviewer="r", path=store)
    with pytest.raises(q.QualityError):
        q.propose_candidate({"send_authorized": True}, "sneaky", path=store)
    # Nothing was written by the refused proposals.
    assert not store.exists()


def test_cli_refuses_policy_knobs(store, capsys):
    rc = q.main(["--store", str(store), "evaluate", "--set", "kill_switch=True"])
    assert rc == 1
    err = capsys.readouterr().err
    assert "not a generation knob" in err


def test_cli_full_flow(store, capsys):
    rc = q.main(["--store", str(store), "optimize", "--max-iterations", "16"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    candidate_id = payload["candidate"]["candidate_id"]
    assert payload["climb"]["improved"] is True
    assert payload["climb"]["end_score"] > payload["climb"]["start_score"]

    best = GenerationSettings.from_dict(payload["climb"]["end_settings"])
    for i in range(q.MIN_REVIEWS):
        rc = q.main([
            "--store", str(store), "review", "--case-id", "q-formal-contract",
            "--set", f"tone={best.tone}", "--set", f"length={best.length}",
            "--accepted", "--reviewer", f"rev-{i}",
        ])
        assert rc == 0
        capsys.readouterr()

    rc = q.main(["--store", str(store), "apply", "--candidate", candidate_id])
    assert rc == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["applied"] is True
    assert applied["version"] == "email-quality-v2"

    rc = q.main(["--store", str(store), "show"])
    assert rc == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["active_version"] == "email-quality-v2"
    assert shown["counts"]["candidates_applied"] == 1

    rc = q.main(["--store", str(store), "revert"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out)["to"] == "email-quality-v1"


def test_optimize_reports_before_and_after_metrics(store, capsys):
    rc = q.main(["--store", str(store), "optimize"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    before = payload["climb"]["start_metrics"]
    after = payload["climb"]["end_metrics"]
    assert before["unsupported_claim_rate"] > after["unsupported_claim_rate"]
    assert after["unsupported_claim_rate"] == 0.0
    assert after["tone_appropriateness"] >= before["tone_appropriateness"]
