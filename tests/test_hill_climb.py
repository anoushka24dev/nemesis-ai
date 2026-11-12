"""Assertion-based tests for the adaptive hill-climbing loop in
``backend/adaptive_harness.py``, plus the supporting ``evaluate_strategy`` and
``neighbours`` helpers.

These deliberately do not launch the Phase 3 experiment runner, do not touch live
Gmail/LLM, and are deterministic enough to assert the actual selected candidate
and recorded state rather than merely that "something ran".

Sections follow the Phase 3A audit checklist:
  A. Strict-improvement acceptance (through the real ``_run`` loop)
  B. Convergence and iteration limits
  C. Promotion gate rejection conditions
  D. Explicit promotion revalidation
  E. Persistence and status
  F. Technical failures and incomplete evaluations
  G. Candidate generation (``neighbours``)
"""
from __future__ import annotations

import json

from backend.adaptive_harness import (
    ATTACK_CATEGORIES,
    DEFENDER_UTILITY_FLOOR,
    MIN_EPISODES_FOR_PROMOTION,
    AdaptiveHarness,
    CandidateRecord,
    StrategyEvaluation,
    neighbours,
)

# ---------------------------------------------------------------------------
# Deterministic evaluation double.
#
# ``_run`` calls the module-level ``evaluate_strategy`` for the baseline, every
# neighbour candidate, and the final "best" evaluation. Replacing it lets the
# tests drive the real greedy-acceptance loop with pinned ASR values instead of
# hoping the seeded simulator produces a particular landscape.
# ---------------------------------------------------------------------------


def _fixed_eval(*, asr, ladder, strategy_id="fixed", utility=1.0, total_episodes=1,
                tech_fails=0, outcomes=None):
    merged = {"success": 1}
    if tech_fails:
        merged["technical_fail"] = tech_fails
    if outcomes:
        merged.update(outcomes)
    return StrategyEvaluation(
        strategy_id=strategy_id,
        ladder=[dict(s) for s in ladder],
        asr=asr,
        bypass_rate=None,
        rounds_to_success=None,
        utility_score=utility,
        cost_per_attack=None,
        total_episodes=total_episodes,
        defense_denied=0,
        defense_allowed=0,
        outcomes=merged,
        checksums=[],
        elapsed_seconds=0.0,
    )


class _EvalScript:
    """A callable stand-in for ``evaluate_strategy`` with pinned ASR values.

    ``asr_for(ladder)`` decides the ASR of any evaluated ladder; every call is
    recorded in ``calls`` so tests can assert how many evaluations happened
    (iteration budget, no burn after convergence, etc.).
    """

    def __init__(self, asr_for):
        self._asr_for = asr_for
        self.calls: list[list[dict]] = []

    def __call__(self, ladder, *, episodes, max_rounds, seed, strategy_id="",
                 stop_event=None):
        self.calls.append([dict(s) for s in ladder])
        asr = self._asr_for([dict(s) for s in ladder])
        return _fixed_eval(
            asr=asr,
            ladder=ladder,
            strategy_id=strategy_id or "scripted",
            total_episodes=episodes,
        )


def _asr_by_category(mapping, default=0.10):
    """ASR keyed on the ladder's last rung category (ladders are per-round)."""

    def _asr(ladder):
        cat = ladder[-1]["category"] if ladder else "direct_injection"
        return mapping.get(cat, default)

    return _asr


def _install_script(monkeypatch, asr_for) -> _EvalScript:
    script = _EvalScript(asr_for)
    monkeypatch.setattr("backend.adaptive_harness.evaluate_strategy", script)
    return script


def _run_one(h, *, run_id, episodes=1, max_rounds=1, iterations=1, seed=1):
    h._run(
        run_id=run_id,
        episodes=episodes,
        max_rounds=max_rounds,
        iterations=iterations,
        seed=seed,
    )
    run = h._current_run
    assert run is not None
    return run


def _candidate_record(asr=0.99, utility=1.0, total_episodes=MIN_EPISODES_FOR_PROMOTION,
                      tech_fails=0, outcomes=None):
    if outcomes is None:
        outcomes = {}
    return CandidateRecord(
        candidate_id="probe-candidate",
        ladder=[{"category": "direct_injection", "sophistication_level": 1}],
        evaluation=_fixed_eval(
            asr=asr,
            ladder=[{"category": "direct_injection", "sophistication_level": 1}],
            utility=utility,
            total_episodes=total_episodes,
            tech_fails=tech_fails,
            outcomes=outcomes,
        ).to_dict(),
        baseline_asr=0.0,
        asr=asr,
    )


# ---------------------------------------------------------------------------
# A1. Strict-improvement acceptance (through the real loop)
# ---------------------------------------------------------------------------


def test_strict_improvement_accepts_higher_asr(monkeypatch):
    # Only the "obfuscation" neighbour measures higher ASR than the baseline;
    # the loop must select exactly that ladder as the new best.
    _install_script(monkeypatch, _asr_by_category({"obfuscation": 0.40}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=2)
    run = _run_one(h, run_id="a1-higher", seed=1)

    assert run["improved"] is True
    assert run["converged"] is False
    assert run["status"] == "completed"
    assert run["best_asr"] == 0.40

    # Exactly one history entry improved, and it is the selected ladder.
    winners = [e for e in run["history"] if e["improved"]]
    assert len(winners) == 1
    assert winners[0]["candidate_ladder"] == [
        {"category": "obfuscation", "sophistication_level": 1}
    ]
    assert winners[0]["asr"] == 0.40

    # The recorded candidate state agrees with the run result.
    cand = h.status()["candidates"][-1]
    assert cand["ladder"] == winners[0]["candidate_ladder"]
    assert cand["asr"] == 0.40
    assert run["best_asr"] == cand["asr"]


def test_equal_asr_not_accepted(monkeypatch):
    # Every neighbour measures the same ASR as the baseline: nothing may be
    # accepted, and the best ladder stays the baseline ladder.
    _install_script(monkeypatch, _asr_by_category({}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=4)
    run = _run_one(h, run_id="a1-equal", seed=1)

    assert run["improved"] is False
    assert run["converged"] is True
    assert run["status"] == "completed"
    assert run["best_asr"] == 0.10
    assert not [e for e in run["history"] if e["improved"]]
    cand = h.status()["candidates"][-1]
    assert cand["ladder"] == [{"category": "direct_injection", "sophistication_level": 1}]
    assert cand["asr"] == 0.10


def test_lower_asr_not_accepted(monkeypatch):
    # Neighbours measure lower ASR than the baseline: none may be accepted.
    _install_script(monkeypatch, _asr_by_category({"obfuscation": 0.05}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=4)
    run = _run_one(h, run_id="a1-lower", seed=1)

    assert run["improved"] is False
    assert run["converged"] is True
    assert run["best_asr"] == 0.10
    assert not [e for e in run["history"] if e["improved"]]
    cand = h.status()["candidates"][-1]
    assert cand["ladder"] == [{"category": "direct_injection", "sophistication_level": 1}]


def test_best_asr_and_best_ladder_stay_consistent(monkeypatch):
    _install_script(monkeypatch, _asr_by_category({"obfuscation": 0.55}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=2)
    run = _run_one(h, run_id="a1-consistency", seed=1)
    cand = h.status()["candidates"][-1]
    # best_asr in the run record must equal the selected candidate's measured
    # ASR, and the candidate ladder must be the one the loop recorded as best.
    assert run["best_asr"] == cand["asr"] == 0.55
    assert cand["ladder"] == [{"category": "obfuscation", "sophistication_level": 1}]
    assert run["baseline_asr"] == 0.10


# ---------------------------------------------------------------------------
# B. Convergence and iteration limits
# ---------------------------------------------------------------------------


def test_convergence_breaks_and_does_not_burn_iteration_budget(monkeypatch):
    # No neighbour ever improves: the loop must stop after the first iteration
    # and must not consume the remaining budget (iterations=4 configured).
    script = _install_script(monkeypatch, _asr_by_category({}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=4)
    run = _run_one(h, run_id="b-converge", seed=1)

    assert run["improved"] is False
    assert run["converged"] is True
    assert run["status"] == "completed"
    assert run["iteration"] == 1, "converged run must not report extra iterations"
    # init baseline (1) + run baseline (1) + one iteration of neighbours (5)
    # + final evaluation of the best ladder (1). Crucially NOT 4 iterations.
    n_neighbours = len(neighbours([{"category": "direct_injection",
                                    "sophistication_level": 1}]))
    assert len(script.calls) == 1 + 1 + n_neighbours + 1


def test_iteration_limit_is_respected(monkeypatch):
    # Strictly increasing ASR with every evaluation: the loop keeps accepting
    # and must stop exactly at the configured iteration limit.
    counter = {"k": 0}

    def _increasing(ladder):
        counter["k"] += 1
        return round(0.10 + 0.01 * counter["k"], 4)

    script = _install_script(monkeypatch, _increasing)
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=2)
    run = _run_one(h, run_id="b-limit", iterations=2, seed=1)

    assert run["iteration"] == 2
    assert run["improved"] is True
    assert run["converged"] is False
    # init baseline + run baseline + one evaluation per history entry (the
    # candidates actually tried) + final evaluation of the best ladder.
    assert len(script.calls) == 1 + 1 + len(run["history"]) + 1
    # The limit was respected: exactly two iterations' worth of history.
    iters = {e["iteration"] for e in run["history"]}
    assert iters == {1, 2}


def test_stop_event_is_honored_and_reported_as_stopped(monkeypatch):
    _install_script(monkeypatch, _asr_by_category({}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=4)
    h._stop_event.set()
    try:
        run = _run_one(h, run_id="b-stop", seed=1)
    finally:
        h._stop_event.clear()

    # Cancellation is distinct from convergence: status is "stopped" and the
    # promotion gate records the stop as an explicit rejection reason.
    assert run["status"] == "stopped"
    assert run["gate"]["passed"] is False
    assert any("stopped" in r.lower() for r in run["gate"]["reasons"])


def test_converged_run_gate_has_no_stop_reason(monkeypatch):
    _install_script(monkeypatch, _asr_by_category({}, default=0.10))
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=1)
    run = _run_one(h, run_id="b-distinct", seed=1)
    assert run["status"] == "completed"
    assert not any("stopped" in r.lower() for r in run["gate"]["reasons"])


# ---------------------------------------------------------------------------
# C. Promotion gate: each rejection condition independently
# ---------------------------------------------------------------------------


def test_gate_rejects_when_stopped():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(asr=0.99, utility=1.0)
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=True)
    assert gate["passed"] is False
    assert any("stopped" in r.lower() for r in gate["reasons"])


def test_gate_rejects_below_min_episodes():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(
        asr=0.99, utility=1.0,
        total_episodes=MIN_EPISODES_FOR_PROMOTION - 1,
    )
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is False
    assert any("episode" in r.lower() for r in gate["reasons"])


def test_gate_rejects_with_technical_failures():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(asr=0.99, utility=1.0, tech_fails=1)
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is False
    assert any("technical" in r.lower() for r in gate["reasons"])


def test_gate_rejects_when_not_strictly_better_than_active():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(asr=0.50, utility=1.0)
    # An equal ASR must not pass; a higher active ASR must also fail.
    for active_asr in (0.50, 0.80):
        gate = h._evaluate_gate(cand, active_asr=active_asr, stopped=False)
        assert gate["passed"] is False, (active_asr, gate["reasons"])
        assert any("regress" in r.lower() or "beat the active" in r.lower()
                   for r in gate["reasons"]), gate["reasons"]


def test_gate_rejects_when_utility_unmeasured():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(asr=0.99, utility=None)
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is False
    assert any("utility" in r.lower() and "measured" in r.lower()
               for r in gate["reasons"])


def test_gate_rejects_when_utility_below_floor():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(asr=0.99, utility=DEFENDER_UTILITY_FLOOR - 0.05)
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is False
    assert any("utility" in r.lower() and "floor" in r.lower()
               for r in gate["reasons"])


def test_gate_passes_when_every_requirement_is_met():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(
        asr=0.99,
        utility=DEFENDER_UTILITY_FLOOR,
        total_episodes=MIN_EPISODES_FOR_PROMOTION,
        outcomes={"success": 1},
    )
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is True, gate["reasons"]
    assert cand.status == "candidate"  # gate alone does not mutate status


# ---------------------------------------------------------------------------
# D. Explicit promotion revalidation
# ---------------------------------------------------------------------------


def _seed_candidate(h, *, cid="seed-cand", asr=0.40, utility=1.0,
                    total_episodes=MIN_EPISODES_FOR_PROMOTION, tech_fails=0):
    """Insert a stored candidate record so ``promote()`` can be tested on its
    own, independent of whether a run's in-loop gate already promoted it."""
    rec = _candidate_record(asr=asr, utility=utility,
                            total_episodes=total_episodes, tech_fails=tech_fails)
    rec.candidate_id = cid
    h._state["candidates"].append(rec.to_dict())
    return cid


def test_promote_revalidates_against_current_active():
    # Attack-only campaigns run no defense, so the seeded baseline is measured
    # without one. A stored candidate that beats the CURRENT active ASR on every
    # gate condition must become the active strategy.
    h = AdaptiveHarness(store_path=None, episodes=MIN_EPISODES_FOR_PROMOTION)
    # Pin a realistic measured baseline: attack-only campaigns run no defense,
    # so the seeded stand-in always succeeds (ASR 1.0) and offers no gradient.
    # This test exercises the gate, so give the active strategy a measured ASR
    # that a candidate can actually beat.
    h._state["active"]["evaluation"]["asr"] = 0.2
    better = 0.4
    cid = _seed_candidate(h, asr=better)

    result = h.promote(candidate_id=cid)
    assert result["promoted"] is True, result["gate"]["reasons"]
    assert result["candidate"]["status"] == "active"
    active = h.status()["strategy_engine"]["active"]
    assert active["strategy_id"] == cid
    assert active["evaluation"]["asr"] == 0.4


def test_promote_fails_when_active_changes_after_evaluation():
    # Regression case: the candidate was evaluated against a weak active
    # strategy (ASR 0.0), but by promotion time a stronger active strategy is
    # in place. promote() must re-evaluate the gate against the *current*
    # active ASR and refuse, leaving the active strategy untouched.
    h = AdaptiveHarness(store_path=None, episodes=MIN_EPISODES_FOR_PROMOTION)
    cid = _seed_candidate(h, asr=0.40)

    # The active strategy improved after the candidate was evaluated.
    h._state["active"]["evaluation"]["asr"] = 0.90

    result = h.promote(candidate_id=cid)
    assert result["promoted"] is False
    assert any("regress" in r.lower() for r in result["gate"]["reasons"])
    assert result["candidate"]["status"] == "rejected"
    active = h.status()["strategy_engine"]["active"]
    assert active["strategy_id"] == "baseline"
    assert h.status()["strategy_engine"]["active_asr"] == 0.90


def test_promoting_already_active_candidate_keeps_it_active():
    # Re-promoting the already-active candidate cannot beat its own ASR, so
    # the gate fails - but the record must stay "active" (it *is* the active
    # strategy), never be relabelled "rejected".
    h = AdaptiveHarness(store_path=None, episodes=MIN_EPISODES_FOR_PROMOTION)
    h._state["active"]["evaluation"]["asr"] = 0.2
    cid = _seed_candidate(h, asr=0.4)
    assert h.promote(candidate_id=cid)["promoted"] is True

    again = h.promote(candidate_id=cid)
    assert again["promoted"] is False
    assert again["candidate"]["status"] == "active"
    assert h.status()["strategy_engine"]["active"]["strategy_id"] == cid


# ---------------------------------------------------------------------------
# E. Persistence and status
# ---------------------------------------------------------------------------


def test_bounded_run_persists_state_and_status_matches(tmp_path, monkeypatch):
    _install_script(monkeypatch, _asr_by_category({"obfuscation": 0.40}, default=0.10))
    tmp = tmp_path / "persist.json"
    h = AdaptiveHarness(store_path=str(tmp))
    run = _run_one(h, run_id="e-persist", episodes=2, max_rounds=1,
                   iterations=2, seed=7)

    # The supported status interface agrees with the returned run result.
    status = h.status()
    assert status["runs"], "expected at least one persisted run"
    last = status["runs"][-1]
    assert last["run_id"] == run["run_id"]
    assert last["status"] == "completed"
    assert last["best_asr"] == run["best_asr"]

    # The store on disk matches what status() reports (the harness uses its own
    # JSON store, NOT the Phase 3 runner's RunStore).
    reloaded = json.loads(tmp.read_text(encoding="utf-8"))
    assert reloaded.get("baseline"), "persisted store must retain the baseline"
    assert reloaded.get("active"), "persisted store must retain the active strategy"
    assert reloaded.get("candidates"), "persisted store must retain candidates"
    assert reloaded["runs"][-1]["run_id"] == run["run_id"]
    assert reloaded["runs"][-1]["status"] == "completed"
    assert reloaded["runs"][-1]["best_asr"] == run["best_asr"]

    # A fresh harness over the same store reloads that state.
    h2 = AdaptiveHarness(store_path=str(tmp))
    assert h2.status()["runs"][-1]["run_id"] == run["run_id"]


# ---------------------------------------------------------------------------
# F. Technical failures and incomplete evaluations
# ---------------------------------------------------------------------------


def test_candidate_with_technical_failures_cannot_pass_gate():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(asr=0.99, utility=1.0, tech_fails=1)
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is False, "a candidate with technical failures must not pass"
    assert any("technical" in r.lower() for r in gate["reasons"])


def test_partially_completed_evaluation_still_subject_to_min_episodes_gate():
    h = AdaptiveHarness(store_path=None, episodes=1)
    cand = _candidate_record(
        asr=0.99, utility=1.0,
        total_episodes=MIN_EPISODES_FOR_PROMOTION - 1,
    )
    gate = h._evaluate_gate(cand, active_asr=0.10, stopped=False)
    assert gate["passed"] is False
    assert any("episode" in r.lower() for r in gate["reasons"])


def test_partial_evaluation_high_asr_cannot_be_promoted_over_full_evaluation():
    # Documented behavior: the greedy ASR acceptance inside ``_run`` compares
    # measured ASR only, so a partial (interrupted) evaluation with a higher
    # measured ASR *would* win the internal search. It can never be promoted,
    # however, because the promotion gate independently requires the minimum
    # episode count. This test pins that separation.
    h = AdaptiveHarness(store_path=None, episodes=1)
    partial_asr = 0.40   # higher, but only 2 episodes
    full_asr = 0.35      # lower, but fully evaluated

    assert partial_asr > full_asr > 0.0
    for active_asr in (0.0, full_asr, partial_asr - 0.01):
        cand = _candidate_record(
            asr=partial_asr,
            utility=1.0,
            total_episodes=MIN_EPISODES_FOR_PROMOTION - 1,
            outcomes={"success": 1},
        )
        gate = h._evaluate_gate(cand, active_asr=active_asr, stopped=False)
        assert gate["passed"] is False, "partial evaluation must not pass the gate"
        assert any("episode" in r.lower() for r in gate["reasons"])


# ---------------------------------------------------------------------------
# G. Candidate generation
# ---------------------------------------------------------------------------


def test_neighbours_produces_valid_ladders():
    ladder = [
        {"category": "direct_injection", "sophistication_level": 2},
        {"category": "obfuscation", "sophistication_level": 3},
    ]
    cands = neighbours(ladder)
    assert cands, "expected at least one neighbor"
    for cand in cands:
        assert len(cand) == len(ladder)
        for step in cand:
            assert step["category"] in ATTACK_CATEGORIES
            assert isinstance(step["sophistication_level"], int)
            assert 1 <= step["sophistication_level"] <= 5


def test_neighbours_does_not_mutate_input():
    ladder = [
        {"category": "direct_injection", "sophistication_level": 2},
    ]
    before = [dict(s) for s in ladder]
    neighbours(ladder)
    assert ladder == before


def test_neighbours_dimensionality_is_bounded():
    ladder = [
        {"category": "direct_injection", "sophistication_level": 3},
        {"category": "obfuscation", "sophistication_level": 3},
    ]
    cands = neighbours(ladder)
    # Each rung can yield up to (num_categories - 1) category swaps plus up to 2
    # sophistication bumps (one down, one up, each clamped to 1..5).
    max_per_rung = (len(ATTACK_CATEGORIES) - 1) + 2
    assert len(cands) <= max_per_rung * len(ladder)


def test_neighbours_varies_exactly_one_rung():
    ladder = [
        {"category": "direct_injection", "sophistication_level": 3},
        {"category": "obfuscation", "sophistication_level": 3},
    ]
    for cand in neighbours(ladder):
        diffs = [
            i for i, (a, b) in enumerate(zip(ladder, cand))
            if a != b
        ]
        assert len(diffs) == 1, f"neighbour changed {len(diffs)} rungs: {cand}"
        i = diffs[0]
        # Either the category swapped or the sophistication moved by one.
        if ladder[i]["category"] != cand[i]["category"]:
            assert cand[i]["sophistication_level"] == ladder[i]["sophistication_level"]
        else:
            assert abs(cand[i]["sophistication_level"]
                       - ladder[i]["sophistication_level"]) == 1
