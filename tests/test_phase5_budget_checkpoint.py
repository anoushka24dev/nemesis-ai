"""Phase 5 regression tests: cumulative budgets, checkpoint/resume, truthful
outcome vocabulary, and the defense-evaluation foundation contract.

Covers the §7 acceptance list:

**Budget enforcement**
1. invalid/over-budget parameters rejected before harness resolution or state
   mutation,
2. cumulative episode consumption enforced across candidates and iterations,
3. exhaustion occurs before starting an additional candidate evaluation,
4. exhaustion produces a truthful status (never success/blocked/normal
   completion),
5. existing defaults and limits remain unchanged.

**Checkpoint/resume**
6. a valid checkpoint restores the actual search state,
7. corrupt and incompatible checkpoints are rejected (no silent fresh run),
8. atomic persistence never exposes a partially written checkpoint,
9. resumption does not duplicate outcomes or budget accounting,
10. completed runs are not executed again,
11. interrupted and exhausted runs remain distinguishable.

**Outcome and defense reporting**
12. ``ignored`` and ``technical_fail`` remain distinct from ``blocked``,
13. missing evidence yields inconclusive/unavailable rather than fabricated
    success,
14. an attack finding alone cannot establish that a defense blocked it,
15. unobservable security boundaries cannot produce a confirmed verdict.

Everything is deterministic and offline: no network, no model calls, no Gmail.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import backend.adaptive_harness as ah
from backend import defense_eval
from backend.adaptive_harness import (
    CHECKPOINT_VERSION,
    DEFAULT_EPISODES,
    DEFAULT_ITERATIONS,
    DEFAULT_MAX_ROUNDS,
    DEFENDER_UTILITY_FLOOR,
    MAX_EPISODES,
    MAX_ITERATIONS,
    MAX_MAX_ROUNDS,
    MAX_TOTAL_EPISODE_BUDGET,
    MIN_EPISODES_FOR_PROMOTION,
    AdaptiveHarness,
    CheckpointError,
    RunBudgetError,
    StrategyEvaluation,
    resolve_total_episode_budget,
    structural_episode_ceiling,
    validate_run_budget,
)
from backend.stage_b import (
    _MOUNT_PREFIX,
    create_app,
)

_NONC2 = "test-pairing-nonce"


def _headers(origin="chrome-extension://chlorophyll-modern-bread"):
    return {
        "origin": origin,
        "authorization": "Bearer test-pairing-nonce",
    }


# ---------------------------------------------------------------------------
# Deterministic doubles
# ---------------------------------------------------------------------------


def _fixed_eval(
    asr=0.0,
    *,
    total_episodes=2,
    outcomes=None,
    trace=None,
    utility=1.0,
):
    """A scripted ``StrategyEvaluation`` (same shape the real engine returns)."""
    return StrategyEvaluation(
        strategy_id="scripted",
        ladder=[],
        asr=asr,
        bypass_rate=0.0,
        rounds_to_success=None,
        utility_score=utility,
        cost_per_attack=None,
        total_episodes=total_episodes,
        defense_denied=0,
        defense_allowed=0,
        outcomes=dict(outcomes or {}),
        checksums=[],
        elapsed_seconds=0.01,
        defense="marker",
        episode_trace=[dict(t) for t in (trace or [])],
    )


class _Script:
    """Callable double recording every invocation (mirrors the Phase 3A
    scripted-eval pattern used by ``tests/test_hill_climb.py``)."""

    def __init__(self, fn):
        self.calls = []
        self._fn = fn

    def __call__(self, ladder, **kwargs):
        self.calls.append([dict(s) for s in ladder])
        return self._fn([dict(s) for s in ladder], **kwargs)


def _step_trace(outcome, decision, *, episode=0, category="obfuscation"):
    return {
        "episode": episode,
        "outcome": outcome,
        "defense_decision": decision,
        "rounds_used": 1,
        "steps": [{"category": category, "sophistication_level": 1}],
    }


# ---------------------------------------------------------------------------
# 1. Rejection before harness resolution / state mutation
# ---------------------------------------------------------------------------


def test_invalid_and_over_budget_requests_rejected_before_any_state(
    tmp_path, monkeypatch
):
    store = str(tmp_path / "s.json")
    h = AdaptiveHarness(store_path=store)
    # If validation happens after harness work, this fails the test loudly.
    monkeypatch.setattr(
        ah,
        "evaluate_strategy",
        lambda *a, **k: pytest.fail("no evaluation may run for a rejected request"),
    )
    bad_requests = (
        {"episodes": MAX_EPISODES + 1},
        {"episodes": 0},
        {"iterations": 0},
        {"total_episode_budget": 0},
        {"total_episode_budget": "abc"},
        {"total_episode_budget": MAX_TOTAL_EPISODE_BUDGET + 1},
    )
    for kwargs in bad_requests:
        with pytest.raises(ValueError):  # RunBudgetError is a ValueError
            h.start(background=False, seed=1, **kwargs)
    # No run state was created, no store written, no checkpoint written.
    assert h._current_run is None
    assert not Path(store).exists()
    assert not Path(store + ".checkpoint.json").exists()


# ---------------------------------------------------------------------------
# 2 + 3 + 4. Cumulative enforcement, exhaustion boundary, truthful status
# ---------------------------------------------------------------------------


def test_plan_limits_candidate_fan_out_and_never_exceeds_budget(monkeypatch):
    # Construct BEFORE patching: the harness's own init-baseline evaluation is
    # not part of the run under test.
    h = AdaptiveHarness(store_path=None, episodes=2, max_rounds=1, iterations=5)
    script = _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="ex-mid", episodes=2, max_rounds=1, iterations=5, seed=3,
        total_episode_budget=6,
    )
    run = h._current_run
    # Plan for 6 episodes @ 2 each: baseline (2) + one comparison (2) +
    # confirmation (2). The structural neighbour set (5 ladders) is NOT
    # scheduled, because that would make completion impossible.
    plan = run["budget_plan"]
    assert plan["baseline"]["episodes"] == 2
    assert plan["candidates"]["max_evaluations"] == 1
    assert plan["confirmation"]["budgeted"] is True
    assert run["candidate_evaluations"] == 1
    assert run["episodes_consumed"] == 6
    assert run["episodes_consumed"] <= run["total_episode_budget"] == 6
    # baseline + one candidate + the reserved final evaluation.
    assert len(script.calls) == 3
    assert run["final_evaluation_reused"] is False
    assert run["status"] == "completed"
    assert run["budget_exhausted"] is False
    assert run["stop_reason"] == "plan_complete_search_truncated_by_budget"
    # Truncated fan-out is disclosed as no convergence (the full
    # neighbourhood was never measured), and the promotion gate rejected the
    # candidate because it did not genuinely improve on the active strategy.
    assert run["search_truncated_by_budget"] is True
    assert run["converged"] is False
    assert run["gate"]["passed"] is False
    assert run["episode_accounting"]["consumed_total"] == 6
    assert run["episode_accounting"]["within_budget"] is True
    cand = h.status()["candidates"][-1]
    assert cand["status"] == "rejected"


def test_cumulative_budget_enforced_at_iteration_boundary(monkeypatch):
    # Strictly increasing ASR: every candidate is accepted, so iteration 1
    # runs to its end and the budget is checked at the ITERATION ADVANCE.
    counter = {"k": 0}

    def _increasing(ladder, **kw):
        counter["k"] += 1
        return _fixed_eval(
            asr=round(0.10 + 0.01 * counter["k"], 4),
            total_episodes=int(kw["episodes"]),
        )

    h = AdaptiveHarness(store_path=None, episodes=2, max_rounds=1, iterations=5)
    script = _Script(_increasing)
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="ex-boundary", episodes=2, max_rounds=1, iterations=5, seed=4,
        total_episode_budget=12,
    )
    run = h._current_run
    # Plan for 12 episodes @ 2 each: baseline (2) + confirmation (2) leaves 8
    # episodes = 4 candidate comparisons, although the ladder has 5 structural
    # neighbours. Fan-out is capped at 4 and the fifth is never started, so
    # the iteration-boundary check can still fund the reserved final run.
    plan = run["budget_plan"]
    assert plan["candidates"]["max_evaluations"] == 4
    assert run["candidate_evaluations"] == 4
    assert run["episodes_consumed"] == 12
    assert len(script.calls) == 6  # baseline + 4 candidates + final
    assert run["iteration"] == 1  # iteration 2 never started
    assert run["search_truncated_by_budget"] is True
    assert run["status"] == "completed"
    assert run["budget_exhausted"] is False
    assert run["episodes_consumed"] <= run["total_episode_budget"]
    assert run["converged"] is False
    # Four improving candidates are still not promoted: promotion is gated on
    # final-evaluation evidence and the promotion floor, never on fan-out.
    assert run["gate"]["passed"] is False


def test_feedback_mode_budget_enforced_too(tmp_path, monkeypatch):
    h = AdaptiveHarness(
        store_path=str(tmp_path / "fb.json"),
        episodes=1, max_rounds=1, iterations=3, mode="feedback",
        selection_budget=2,
    )
    script = _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="ex-fb", episodes=1, max_rounds=1, iterations=3, seed=6,
        total_episode_budget=3,
    )
    run = h._current_run
    # Plan for 3 episodes @ 1 each: baseline (1) + one comparison (1) +
    # confirmation (1). The selection budget (2) is capped by the plan.
    assert run["budget_plan"]["candidates"]["max_evaluations"] == 1
    assert run["episodes_consumed"] == 3
    assert run["candidate_evaluations"] == 1
    assert run["status"] == "completed"
    assert run["episodes_consumed"] <= run["total_episode_budget"]
    assert len(script.calls) == 3


# ---------------------------------------------------------------------------
# 5. Defaults and limits unchanged; default budget never binds
# ---------------------------------------------------------------------------


def test_defaults_and_limits_unchanged_and_default_budget_never_binds(
    monkeypatch,
):
    assert (DEFAULT_EPISODES, DEFAULT_MAX_ROUNDS, DEFAULT_ITERATIONS) == (8, 3, 8)
    assert (MAX_EPISODES, MAX_MAX_ROUNDS, MAX_ITERATIONS) == (64, 8, 32)
    assert MIN_EPISODES_FOR_PROMOTION == 3
    assert DEFENDER_UTILITY_FLOOR == 0.90

    # Structural ceiling for the approved defaults (greedy: max_rounds x 6
    # neighbours per iteration + baseline + final).
    ceiling = structural_episode_ceiling(
        episodes=8, max_rounds=3, iterations=8, mode="greedy",
        selection_budget=3,
    )
    assert ceiling == 8 * (2 + 8 * 18)
    assert (
        resolve_total_episode_budget(
            None, episodes=8, max_rounds=3, iterations=8, mode="greedy",
            selection_budget=3,
        )
        == ceiling
    )
    # Feedback-mode ceiling uses the selection budget, not the neighbour set.
    assert (
        resolve_total_episode_budget(
            None, episodes=4, max_rounds=2, iterations=3, mode="feedback",
            selection_budget=2,
        )
        == 4 * (2 + 3 * 2)
    )
    with pytest.raises(RunBudgetError):
        validate_run_budget(episodes=1, max_rounds=1, iterations=1,
                            total_episode_budget=0)
    with pytest.raises(RunBudgetError):
        validate_run_budget(episodes=1, max_rounds=1, iterations=1,
                            total_episode_budget=MAX_TOTAL_EPISODE_BUDGET + 1)

    # A default-budget run completes normally: the ceiling never binds.
    script = _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h = AdaptiveHarness(store_path=None)
    h._run(run_id="defaults", episodes=1, max_rounds=1, iterations=2, seed=1)
    run = h._current_run
    assert run["status"] == "completed"
    assert run["budget_exhausted"] is False
    assert run["total_episode_budget"] == 1 * (2 + 2 * 6)
    assert run["episodes_consumed"] <= run["total_episode_budget"]
    assert run["unsupported_budgets"] == ["wall_clock", "tokens", "cost"]


# ---------------------------------------------------------------------------
# 6 + 9. Crash -> resume restores search state, no duplicated accounting
# ---------------------------------------------------------------------------


def _crash_on_call(monkeypatch, call_number):
    real = ah.evaluate_strategy
    state = {"n": 0}

    def flaky(ladder, **kwargs):
        state["n"] += 1
        if state["n"] == call_number:
            raise RuntimeError("simulated crash mid-evaluation")
        return real(ladder, **kwargs)

    monkeypatch.setattr(ah, "evaluate_strategy", flaky)
    return state


def test_crash_resume_restores_state_without_duplicate_accounting(
    tmp_path, monkeypatch
):
    store = str(tmp_path / "crash.json")
    h = AdaptiveHarness(store_path=store)
    _crash_on_call(monkeypatch, 4)  # baseline + 2 candidates committed, 3rd in flight
    with pytest.raises(RuntimeError):
        h._run(run_id="crash-1", episodes=2, max_rounds=1, iterations=3, seed=5)
    monkeypatch.undo()

    # --- checkpoint survives the crash with the real search position ------
    ck = json.loads(Path(store + ".checkpoint.json").read_text(encoding="utf-8"))
    assert ck["checkpoint_version"] == CHECKPOINT_VERSION
    assert ck["run"]["run_id"] == "crash-1"
    assert ck["run"]["status"] == "running"  # interrupted, not finished
    progress = ck["progress"]
    assert progress["inflight"] is not None
    assert progress["inflight"]["stage"] == "candidate"
    assert progress["pending"], "remaining candidates must be persisted"
    assert progress["episodes_committed"] == 6  # baseline + 2 candidates x 2
    assert progress["candidate_evaluations"] == 2
    assert progress["search_done"] is False

    # --- resume on a fresh instance (like a process restart) --------------
    h2 = AdaptiveHarness(store_path=store)
    result = h2.resume(background=False)
    assert result["resumed"] is True
    assert result["checkpoint"]["run_id"] == "crash-1"
    runs = h2._state["runs"]
    assert len(runs) == 1
    resumed_run = runs[0]
    assert resumed_run["run_id"] == "crash-1"
    assert resumed_run["status"] == "completed"
    assert resumed_run["resumed_from_checkpoint"] is True
    # The interrupted evaluation is counted exactly once.
    assert resumed_run["episodes_consumed"] == resumed_run["total_evaluations"] * 2
    assert resumed_run["episodes_consumed"] <= resumed_run["total_episode_budget"]

    # --- an identical uninterrupted run produces identical evidence --------
    clean = AdaptiveHarness(store_path=str(tmp_path / "clean.json"))
    clean._run(run_id="clean-1", episodes=2, max_rounds=1, iterations=3, seed=5)
    clean_run = clean._state["runs"][0]
    assert clean_run["status"] == "completed"
    assert resumed_run["history"] == clean_run["history"]
    assert resumed_run["episodes_consumed"] == clean_run["episodes_consumed"]
    assert resumed_run["candidate_evaluations"] == clean_run["candidate_evaluations"]
    assert resumed_run["best_asr"] == clean_run["best_asr"]


# ---------------------------------------------------------------------------
# 7. Corrupt / incompatible checkpoints rejected — never a silent fresh run
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "not json at all {{{",
        json.dumps({"checkpoint_version": 999, "run": {"run_id": "x"}}),
        json.dumps({"checkpoint_version": CHECKPOINT_VERSION, "run": {}, "progress": {}}),
        json.dumps({"checkpoint_version": CHECKPOINT_VERSION, "progress": {}}),
        json.dumps([1, 2, 3]),
    ],
    ids=["garbage", "wrong-version", "no-run-identity", "no-progress", "not-object"],
)
def test_corrupt_and_incompatible_checkpoints_rejected(tmp_path, monkeypatch, payload):
    store = str(tmp_path / "bad.json")
    Path(store + ".checkpoint.json").write_text(payload, encoding="utf-8")
    h = AdaptiveHarness(store_path=store)
    monkeypatch.setattr(
        ah,
        "evaluate_strategy",
        lambda *a, **k: pytest.fail("an invalid checkpoint must never run anything"),
    )
    with pytest.raises(CheckpointError):
        h.resume(background=False)
    # Nothing ran, no fresh run was created, state untouched.
    assert h._running is False
    assert h._current_run is None
    assert h._state["runs"] == []


def test_missing_checkpoint_is_an_explicit_not_found(tmp_path):
    h = AdaptiveHarness(store_path=str(tmp_path / "none.json"))
    with pytest.raises(CheckpointError) as excinfo:
        h.resume(background=False)
    assert excinfo.value.http_status == 404


def test_resume_after_converged_iteration_boundary_does_not_rerun(
    tmp_path, monkeypatch
):
    """A crash between the last candidate commit of a converged iteration and
    the convergence write must not re-run that iteration on resume."""
    store = str(tmp_path / "boundary.json")
    h = AdaptiveHarness(store_path=store)
    script = _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(run_id="bd-1", episodes=1, max_rounds=1, iterations=3, seed=2)
    assert h._current_run["status"] == "completed"
    completed_history = list(h._current_run["history"])
    # 5 structural neighbours of the 1-step ladder, none accepted (flat ASR).
    assert len(completed_history) == 5

    # Rewind the terminal checkpoint to the exact interrupted state such a
    # crash leaves: all iteration-1 candidates committed (baseline 1 + 5
    # candidates = 6 episodes), search_done not yet written, no final eval.
    p = Path(store + ".checkpoint.json")
    ck = json.loads(p.read_text(encoding="utf-8"))
    assert ck["progress"]["search_done"] is True
    assert ck["progress"]["episodes_committed"] == 7  # includes the final eval
    ck["run"]["status"] = "running"
    ck["progress"].update(
        {"search_done": False, "phase": "search", "episodes_committed": 6}
    )
    p.write_text(json.dumps(ck), encoding="utf-8")

    h2 = AdaptiveHarness(store_path=store)
    calls_before = len(script.calls)
    result = h2.resume(background=False)
    assert result["resumed"] is True
    # ONLY the final evaluation runs — no candidate may be re-evaluated.
    assert len(script.calls) == calls_before + 1
    # runs[0] is the pre-crash record persisted by the first attempt; the
    # resumed pass appends its own record.
    run = h2._state["runs"][-1]
    assert run["run_id"] == "bd-1"
    assert run["status"] == "completed"
    assert run["resumed_from_checkpoint"] is True
    assert run["history"] == completed_history  # no duplicate iteration
    assert run["candidate_evaluations"] == 5
    assert run["episodes_consumed"] == 7 == run["total_evaluations"] * 1


def test_finished_checkpoint_is_refused_instead_of_rerun(tmp_path, monkeypatch):
    store = str(tmp_path / "done.json")
    h = AdaptiveHarness(store_path=store)
    script = _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(run_id="done-1", episodes=1, max_rounds=1, iterations=1, seed=1)
    assert h._state["runs"][0]["status"] == "completed"

    h2 = AdaptiveHarness(store_path=store)
    calls_before = len(script.calls)
    with pytest.raises(CheckpointError) as excinfo:
        h2.resume(background=False)
    assert "already finished" in str(excinfo.value)
    # Zero evaluations were executed by the refused resume.
    assert len(script.calls) == calls_before
    assert h2._state["runs"][0]["status"] == "completed"
    assert len(h2._state["runs"]) == 1


# ---------------------------------------------------------------------------
# 8. Atomic persistence: no partially written checkpoint is ever exposed
# ---------------------------------------------------------------------------


def test_checkpoint_writes_are_atomic(tmp_path, monkeypatch):
    h = AdaptiveHarness(store_path=str(tmp_path / "atomic.json"))
    payload = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "run": {"run_id": "a1", "status": "running", "episodes": 1,
                 "max_rounds": 1, "iterations": 1, "seed": 1,
                 "mode": "greedy", "defense": "marker",
                 "selection_budget": 3, "total_episode_budget": 10},
        "progress": {"phase": "baseline", "iteration": 0},
        "written_at": "now",
    }
    h._write_checkpoint(payload)
    path = Path(str(tmp_path / "atomic.json") + ".checkpoint.json")
    before = path.read_text(encoding="utf-8")
    assert json.loads(before)["run"]["status"] == "running"

    # A crash during replace leaves the previous complete checkpoint intact.
    import pathlib

    def _boom(self, target):
        raise OSError("simulated disk failure during atomic replace")

    monkeypatch.setattr(pathlib.Path, "replace", _boom)
    with pytest.raises(OSError):
        h._write_checkpoint({**payload, "run": {**payload["run"], "status": "failed"}})
    monkeypatch.undo()
    after = path.read_text(encoding="utf-8")
    assert after == before  # readers still see the complete old checkpoint
    assert json.loads(after)["run"]["status"] == "running"

    # After recovery, writes succeed again and leave no reader-visible partial.
    h._write_checkpoint(payload)
    assert json.loads(path.read_text(encoding="utf-8"))["checkpoint_version"] == (
        CHECKPOINT_VERSION
    )


# ---------------------------------------------------------------------------
# 11. Interrupted / exhausted / completed / stopped are distinguishable
# ---------------------------------------------------------------------------


def test_interrupted_exhausted_and_completed_statuses_are_distinct(
    tmp_path, monkeypatch
):
    statuses = {}

    # Interrupted: crash mid-eval leaves a RUNNING checkpoint.
    store_i = str(tmp_path / "int.json")
    hi = AdaptiveHarness(store_path=store_i)
    _crash_on_call(monkeypatch, 4)
    with pytest.raises(RuntimeError):
        hi._run(run_id="int-1", episodes=2, max_rounds=1, iterations=3, seed=9)
    monkeypatch.undo()
    ck = json.loads(Path(store_i + ".checkpoint.json").read_text(encoding="utf-8"))
    statuses["interrupted_checkpoint"] = ck["run"]["status"]

    # Exhausted.
    script = _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    # Genuine runtime shortfall: the target reports 3 executed episodes for a
    # 1-episode reservation, so the reserved confirmation no longer fits. The
    # run must report ``budget_exhausted``, never completion.
    store_e = str(tmp_path / "exh.json")
    he = AdaptiveHarness(store_path=store_e)
    overrun = _Script(lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=3))
    monkeypatch.setattr(ah, "evaluate_strategy", overrun)
    he._run(
        run_id="exh-1", episodes=1, max_rounds=1, iterations=2, seed=1,
        total_episode_budget=3,
    )
    monkeypatch.setattr(ah, "evaluate_strategy", _Script(
        lambda ladder, **kw: _fixed_eval(asr=0.10, total_episodes=int(kw["episodes"]))
    ))
    assert he._state["runs"][0]["budget_exhausted"] is True
    statuses["exhausted"] = he._state["runs"][0]["status"]
    ck_e = json.loads(Path(store_e + ".checkpoint.json").read_text(encoding="utf-8"))
    statuses["exhausted_checkpoint"] = ck_e["run"]["status"]

    # Completed.
    store_c = str(tmp_path / "comp.json")
    hc = AdaptiveHarness(store_path=store_c)
    hc._run(run_id="comp-1", episodes=1, max_rounds=1, iterations=1, seed=1)
    statuses["completed"] = hc._state["runs"][0]["status"]

    # Stopped (external stop signal).
    store_s = str(tmp_path / "stop.json")
    hs = AdaptiveHarness(store_path=store_s)
    hs._stop_event.set()
    try:
        hs._run(run_id="stop-1", episodes=1, max_rounds=1, iterations=1, seed=1)
    finally:
        hs._stop_event.clear()
    statuses["stopped"] = hs._state["runs"][0]["status"]

    assert statuses == {
        "interrupted_checkpoint": "running",
        "exhausted": "budget_exhausted",
        "exhausted_checkpoint": "budget_exhausted",
        "completed": "completed",
        "stopped": "stopped",
    }
    # And status() reports the checkpoint honestly.
    summary = hi.status()["checkpoint"]
    assert summary["available"] is True
    assert summary["run_status"] == "running"
    assert summary["run_id"] == "int-1"


# ---------------------------------------------------------------------------
# 12. ignored / technical_fail never rolled into blocked
# ---------------------------------------------------------------------------


def test_ignored_and_technical_fail_never_rolled_into_blocked(monkeypatch):
    outcomes = {"success": 1, "blocked": 1, "ignored": 2, "technical_fail": 1}
    script = _Script(
        lambda ladder, **kw: _fixed_eval(
            asr=0.0, total_episodes=int(kw["episodes"]), outcomes=dict(outcomes)
        )
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h = AdaptiveHarness(store_path=None, episodes=3, max_rounds=1, iterations=1)
    h._run(run_id="outcomes-1", episodes=3, max_rounds=1, iterations=1, seed=1)
    cand = h.status()["candidates"][-1]
    ev_outcomes = cand["evaluation"]["outcomes"]
    assert ev_outcomes["ignored"] == 2
    assert ev_outcomes["blocked"] == 1  # exactly 1 — never 1 + 2 ignored
    assert ev_outcomes["technical_fail"] == 1
    # Technical failures are not a security outcome: the gate rejects.
    assert cand["status"] == "rejected"
    assert any("technical failure" in r for r in cand["gate"]["reasons"])


@pytest.mark.parametrize(
    "outcome,decision,expected_state",
    [
        ("ignored", None, defense_eval.INCONCLUSIVE),
        ("ignored", "denied", defense_eval.INCONCLUSIVE),
        ("ignored", "allowed", defense_eval.INCONCLUSIVE),
        ("technical_fail", None, defense_eval.TECHNICAL_FAILURE),
        ("technical_fail", "denied", defense_eval.TECHNICAL_FAILURE),
        ("blocked", None, defense_eval.INCONCLUSIVE),
        ("blocked", "allowed", defense_eval.INCONCLUSIVE),
        ("blocked", "denied", defense_eval.CONFIRMED_BLOCKED),
        ("success", None, defense_eval.CONFIRMED_SUCCESS),
        ("success", "allowed", defense_eval.CONFIRMED_SUCCESS),
        ("success", "denied", defense_eval.CONFIRMED_SUCCESS),
    ],
)
def test_classify_episode_vocabulary(outcome, decision, expected_state):
    state, evidence = defense_eval.classify_episode(outcome, decision)
    assert state == expected_state
    assert evidence


def _replay(trace, *, asr=0.5, defense="marker"):
    ev = _fixed_eval(
        asr=asr, total_episodes=max(1, len(trace)),
        outcomes={}, trace=trace,
    )
    return defense_eval.replay_attack_against_defense(
        [{"category": "obfuscation", "sophistication_level": 1}],
        defense=defense, episodes=2, max_rounds=1, seed=1,
        evaluate=lambda ladder, **kw: ev,
    )


# ---------------------------------------------------------------------------
# 13. Missing evidence -> inconclusive/unavailable, nothing fabricated
# ---------------------------------------------------------------------------


def test_finding_without_episode_evidence_is_unavailable(tmp_path):
    h = AdaptiveHarness(store_path=str(tmp_path / "ev.json"))
    h._state["candidates"].append(
        {
            "candidate_id": "cand-notrace",
            "ladder": [{"category": "direct_injection",
                        "sophistication_level": 1}],
            "evaluation": {"total_episodes": 3, "asr": 0.0},
            "baseline_asr": 0.0,
            "asr": 0.0,
            "status": "rejected",
            "gate": {},
            "created_at": "",
        }
    )
    entry = h.defense_evaluation("cand-notrace", against="marker")
    result = entry["result"]
    assert result["unavailable"] is True
    assert result["verdict"] == defense_eval.INCONCLUSIVE
    assert result["episodes_evaluated"] == 0
    assert all(n == 0 for n in result["states"].values())
    assert any("no per-episode evidence" in lim for lim in result["limitations"])
    assert result["ground_truth"] == "not_evaluated"


def test_finding_without_success_evidence_cannot_be_evaluated(tmp_path):
    h = AdaptiveHarness(store_path=str(tmp_path / "ev2.json"))
    h._state["candidates"].append(
        {
            "candidate_id": "cand-nosuccess",
            "ladder": [{"category": "direct_injection",
                        "sophistication_level": 1}],
            "evaluation": {
                "total_episodes": 3,
                "asr": 0.0,
                "episode_trace": [
                    _step_trace("ignored", None),
                    _step_trace("ignored", "denied", episode=1),
                ],
            },
            "baseline_asr": 0.0,
            "asr": 0.0,
            "status": "rejected",
            "gate": {},
            "created_at": "",
        }
    )
    entry = h.defense_evaluation("cand-nosuccess", against="marker")
    result = entry["result"]
    assert result["unavailable"] is True
    assert result["verdict"] == defense_eval.INCONCLUSIVE
    assert any(
        "no confirmed successful episode" in lim for lim in result["limitations"]
    )


# ---------------------------------------------------------------------------
# 14 + 15. A finding alone never confirms a block; unobservable boundary
#          never confirms a verdict
# ---------------------------------------------------------------------------


def _completed_run_for(h, candidate_id, **overrides):
    """Record the completed attacker run the defense phase now requires.

    Part 6.1 / ADR-020: defense evaluation may only start from a completed
    attacker run, so every finding fixture must carry its source run.
    """
    run = {
        "run_id": f"run-{candidate_id}",
        "candidate_id": candidate_id,
        "status": "completed",
        "seed": 7,
        "defense": "marker",
        "mode": "greedy",
        # Current run records persist the exact target snapshot; the defense
        # phase refuses to replay without it (legacy records are unavailable).
        "target_snapshot": h.target_snapshot(),
    }
    run.update(overrides)
    h._state["runs"].append(run)
    return run["run_id"]


def test_attack_finding_alone_cannot_confirm_a_block(tmp_path, monkeypatch):
    h = AdaptiveHarness(store_path=str(tmp_path / "blk.json"))
    # The finding itself shows a CONFIRMED successful attack (evidence exists).
    _completed_run_for(h, "cand-finding")
    h._state["candidates"].append(
        {
            "candidate_id": "cand-finding",
            "ladder": [{"category": "obfuscation", "sophistication_level": 1}],
            "evaluation": {
                "total_episodes": 4,
                "asr": 0.5,
                "episode_trace": [_step_trace("success", "allowed")],
            },
            "baseline_asr": 0.0,
            "asr": 0.5,
            "status": "rejected",
            "gate": {},
            "created_at": "",
        }
    )
    # Replay evidence: outcome "blocked" but NO defense telemetry — the
    # boundary is unobservable, so the defense cannot be credited.
    replay_trace = [_step_trace("blocked", None, episode=i) for i in range(2)]
    monkeypatch.setattr(
        ah,
        "evaluate_strategy",
        lambda ladder, **kw: _fixed_eval(
            asr=0.0, total_episodes=2, trace=replay_trace
        ),
    )
    entry = h.defense_evaluation("cand-finding", against="marker")
    result = entry["result"]
    assert result["unavailable"] is not True
    assert result["states"]["confirmed_blocked"] == 0
    assert result["verdict"] == defense_eval.INCONCLUSIVE
    assert result["states"]["inconclusive"] == 2
    for ep in result["episodes"]:
        assert ep["state"] != defense_eval.CONFIRMED_BLOCKED
        assert "unobservable" in ep["evidence"]
    # Ground truth is never manufactured.
    assert result["ground_truth"] == "not_evaluated"


def test_unobservable_boundary_never_produces_a_confirmed_verdict():
    # All episodes blocked without denial telemetry, plus ignored episodes:
    # no confirmed verdict may be produced in either direction.
    result = _replay(
        [_step_trace("blocked", None, episode=i) for i in range(2)]
        + [_step_trace("ignored", None, episode=2)]
    )
    assert result["states"]["confirmed_blocked"] == 0
    assert result["states"]["confirmed_success"] == 0
    assert result["verdict"] == defense_eval.INCONCLUSIVE
    assert result["states"]["inconclusive"] == 3


def test_confirmed_states_require_positive_evidence():
    blocked = _replay([_step_trace("blocked", "denied", episode=i)
                       for i in range(3)])
    assert blocked["states"]["confirmed_blocked"] == 3
    assert blocked["verdict"] == defense_eval.CONFIRMED_BLOCKED

    allowed = _replay([_step_trace("success", "allowed", episode=i)
                       for i in range(3)])
    assert allowed["states"]["confirmed_success"] == 3
    assert allowed["verdict"] == defense_eval.CONFIRMED_SUCCESS

    technical = _replay([_step_trace("technical_fail", None)])
    assert technical["states"]["technical_failure"] == 1
    assert technical["states"]["confirmed_blocked"] == 0
    assert technical["states"]["confirmed_success"] == 0

    # Every replayed episode's state is backed by matching evidence.
    for result in (blocked, allowed, technical):
        assert sum(result["states"].values()) == result["episodes_evaluated"]
        for ep in result["episodes"]:
            if ep["state"] == defense_eval.CONFIRMED_BLOCKED:
                assert ep["defense_decision"] == "denied"
            if ep["state"] == defense_eval.TECHNICAL_FAILURE:
                assert ep["outcome"] == "technical_fail"
        assert result["ground_truth"] == "not_evaluated"
        assert result["limitations"]


# ---------------------------------------------------------------------------
# Defense evaluation end-to-end on the real engine (evidence-driven)
# ---------------------------------------------------------------------------


def test_defense_evaluation_end_to_end_real_engine(tmp_path):
    # Build a finding from the REAL engine: an evasive ladder that actually
    # produced successful episodes under the marker defense.
    ladder = [{"category": "obfuscation", "sophistication_level": 1}]
    ev = None
    for seed in range(1, 11):
        candidate_ev = ah.evaluate_strategy(
            ladder, episodes=4, max_rounds=1, seed=seed, strategy_id="finding"
        )
        if (candidate_ev.asr or 0.0) > 0.0:
            ev = candidate_ev
            break
    assert ev is not None, "expected a successful attack within 10 seeds"

    h = AdaptiveHarness(store_path=str(tmp_path / "e2e.json"))
    _completed_run_for(h, "cand-real", seed=seed)
    h._state["candidates"].append(
        {
            "candidate_id": "cand-real",
            "ladder": [dict(s) for s in ladder],
            "evaluation": ev.to_dict(),
            "baseline_asr": 0.0,
            "asr": ev.asr,
            "status": "rejected",
            "gate": {},
            "created_at": "",
        }
    )
    entry = h.defense_evaluation(
        "cand-real", against="marker", seed=seed  # same seed as the finding
    )
    result = entry["result"]
    assert result["unavailable"] is not True
    # Only CONFIRMED saved cases are replayed (one episode per case); an
    # ignored/inconclusive attempt is not a replayable attack case.
    success_cases = [
        t for t in ev.episode_trace if t.get("outcome") == "success"
    ]
    assert result["episodes_evaluated"] == len(success_cases)
    assert sum(result["states"].values()) == result["episodes_evaluated"]
    assert result["replay_basis"] == "exact_saved_cases"
    assert result["verdict"] in (*defense_eval.STATES, "mixed")
    # The replay reproduced the finding's successes (same seed, same engine):
    # at least one confirmed success, and no fabricated blocks.
    assert result["states"]["confirmed_success"] >= 1
    assert result["ground_truth"] == "not_evaluated"
    # Persisted as evidence, surfaced through status().
    assert h.status()["defense_evaluations"][-1]["candidate_id"] == "cand-real"
    # Defense evaluation never mutated search state.
    assert h.status()["candidates"][-1]["candidate_id"] == "cand-real"
    assert h.status()["strategy_engine"]["active"]["strategy_id"] == "baseline"


# ---------------------------------------------------------------------------
# HTTP surface: /adaptive/resume and budget rejection on /adaptive/run
# ---------------------------------------------------------------------------


@pytest.fixture
def paired_client(tmp_path):
    app = create_app(
        credentials_path=tmp_path / "c.json",
        token_path=tmp_path / "t.json",
        pairing_nonce=_NONC2,
        feedback_store=tmp_path / "fb.json",
        quality_store=tmp_path / "q.json",
        adaptive_store=str(tmp_path / "adaptive.json"),
    )
    client = TestClient(app, follow_redirects=False)
    base = f"/{_MOUNT_PREFIX.lstrip('/')}"
    client.post(
        f"{base}/pair",
        json={
            "presented_nonce": _NONC2,
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
        headers=_headers(),
    )
    return client, base


def test_resume_route_requires_pairing(tmp_path):
    app = create_app(
        credentials_path=tmp_path / "c.json",
        token_path=tmp_path / "t.json",
        pairing_nonce=_NONC2,
        feedback_store=tmp_path / "fb.json",
        quality_store=tmp_path / "q.json",
        adaptive_store=str(tmp_path / "adaptive.json"),
    )
    client = TestClient(app, follow_redirects=False)
    base = f"/{_MOUNT_PREFIX.lstrip('/')}"
    # Origin + bearer presented, but the app was never paired.
    resp = client.post(f"{base}/adaptive/resume", json={}, headers=_headers())
    assert resp.status_code in (401, 403), resp.status_code


def test_resume_route_without_checkpoint_is_explicit_404(paired_client):
    client, base = paired_client
    resp = client.post(f"{base}/adaptive/resume", json={}, headers=_headers())
    assert resp.status_code == 404
    assert "no checkpoint" in resp.json()["error"]


def test_run_route_rejects_invalid_total_budget_without_starting(paired_client):
    client, base = paired_client
    resp = client.post(
        f"{base}/adaptive/run",
        json={
            "episodes": 1, "max_rounds": 1, "iterations": 1,
            "total_episode_budget": 0, "background": True,
        },
        headers=_headers(),
    )
    assert resp.status_code == 400
    assert "total_episode_budget" in resp.json()["error"]
    # The rejected request started no experiment and mutated no run state.
    status = client.post(
        f"{base}/adaptive/status", json={}, headers=_headers()
    ).json()["adaptive"]
    assert status["running"] is False
    assert status["current_run"] is None
    assert status["runs"] == []


def test_defense_eval_route_requires_candidate_id(paired_client):
    client, base = paired_client
    resp = client.post(f"{base}/adaptive/defense_eval", json={}, headers=_headers())
    assert resp.status_code == 400
    assert "candidate_id is required" in resp.json()["error"]


def test_defense_eval_route_with_unknown_candidate_is_404(paired_client):
    client, base = paired_client
    resp = client.post(
        f"{base}/adaptive/defense_eval",
        json={"candidate_id": "cand-nonexistent"},
        headers=_headers(),
    )
    assert resp.status_code == 404
    assert "unknown candidate" in resp.json()["error"]


def test_defense_eval_route_replays_candidate(paired_client):
    client, base = paired_client
    # Start a 1-episode offline run so we get a candidate record
    run_resp = client.post(
        f"{base}/adaptive/run",
        json={
            "episodes": 3,
            "max_rounds": 1,
            "iterations": 1,
            "background": False,
        },
        headers=_headers(),
    )
    assert run_resp.status_code == 200
    status = client.post(f"{base}/adaptive/status", json={}, headers=_headers()).json()["adaptive"]
    candidates = status["candidates"]
    assert len(candidates) > 0
    cand_id = candidates[0]["candidate_id"]

    eval_resp = client.post(
        f"{base}/adaptive/defense_eval",
        json={"candidate_id": cand_id, "against": "marker"},
        headers=_headers(),
    )
    assert eval_resp.status_code == 200
    res = eval_resp.json()["evaluation"]["result"]
    assert "verdict" in res
    assert "states" in res
    assert "limitations" in res
