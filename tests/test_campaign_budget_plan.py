"""Campaign budget planning: small campaigns must be able to finish.

These tests prove that the episode cap is a *plan*, not a number discovered
after the fact:

* an infeasible cap is rejected before execution;
* a small campaign completes baseline + candidate comparison + confirmation;
* candidate fan-out is capped by the remaining budget;
* a confirmation run cannot silently consume the reserved budget;
* promotion still requires genuine, measured improvement;
* measured feedback from one candidate reaches the next generation call;
* neither campaign execution nor a dashboard refresh builds/runs a defense.
"""

from __future__ import annotations

import backend.adaptive_harness as ah
import pytest
from backend.adaptive_harness import (
    AdaptiveHarness,
    RunBudgetError,
    StrategyEvaluation,
    plan_episode_budget,
)


def _fixed_eval(asr=0.0, *, total_episodes=3, trace=None):
    return StrategyEvaluation(
        strategy_id="scripted",
        ladder=[],
        asr=asr,
        bypass_rate=0.0,
        rounds_to_success=None,
        utility_score=None,
        cost_per_attack=None,
        total_episodes=total_episodes,
        defense_denied=0,
        defense_allowed=0,
        outcomes={},
        checksums=[],
        elapsed_seconds=0.01,
        defense="none",
        episode_trace=[dict(t) for t in (trace or [])],
    )


class _Script:
    def __init__(self, fn):
        self.calls = []
        self.kwargs = []
        self._fn = fn

    def __call__(self, ladder, **kwargs):
        self.calls.append([dict(s) for s in ladder])
        self.kwargs.append(dict(kwargs))
        return self._fn([dict(s) for s in ladder], **kwargs)


# ---------------------------------------------------------------------------
# planning unit behaviour
# ---------------------------------------------------------------------------


def test_infeasible_budget_is_rejected_with_the_required_minimum():
    # episodes=3: baseline 3 + one comparison 3 = 6 is the minimum.
    with pytest.raises(RunBudgetError) as exc:
        plan_episode_budget(5, episodes=3)
    assert "6 episode(s)" in str(exc.value)
    assert "at least one candidate comparison" in str(exc.value)
    # The minimum itself is feasible, and the confirmation is not budgeted.
    plan = plan_episode_budget(6, episodes=3)
    assert plan.max_candidate_evaluations == 1
    assert plan.confirmation_budgeted is False
    assert plan.confirmation_episodes == 0
    # 12 episodes funds confirmation and a second comparison.
    plan12 = plan_episode_budget(12, episodes=3)
    assert plan12.confirmation_budgeted is True
    assert plan12.max_candidate_evaluations == 2


def test_three_episode_campaign_completes_with_a_valid_comparison(monkeypatch):
    h = AdaptiveHarness(store_path=None, episodes=3, max_rounds=1, iterations=2)
    script = _Script(lambda ladder, **kw: _fixed_eval(0.0, total_episodes=3))
    monkeypatch.setattr(ah, "evaluate_strategy", script)

    h._run(
        run_id="small-1", episodes=3, max_rounds=1, iterations=2, seed=5,
        total_episode_budget=9,
    )
    run = h._current_run

    assert run["status"] == "completed"
    assert run["budget_exhausted"] is False
    assert run["episodes_consumed"] == 9 == run["total_episode_budget"]
    assert run["candidate_evaluations"] == 1
    assert run["final_evaluation_reused"] is False
    acc = run["episode_accounting"]
    assert acc["baseline"] == {"planned": 3, "consumed": 3}
    assert acc["candidates"]["consumed"] == 3
    assert acc["final"]["consumed"] == 3
    assert acc["within_budget"] is True
    # baseline + candidate + final = three evaluations, no more.
    assert len(script.calls) == 3


def test_candidate_fan_out_is_capped_by_the_remaining_budget(monkeypatch):
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=5)
    script = _Script(lambda ladder, **kw: _fixed_eval(0.0, total_episodes=1))
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    # baseline 1 + confirmation 1 leaves 4 for candidates.
    h._run(
        run_id="cap-1", episodes=1, max_rounds=1, iterations=5, seed=2,
        total_episode_budget=6,
    )
    run = h._current_run
    assert run["budget_plan"]["candidates"]["max_evaluations"] == 4
    assert run["candidate_evaluations"] == 4
    assert run["episodes_consumed"] == 6
    assert run["search_truncated_by_budget"] is True
    assert run["converged"] is False
    assert len(script.calls) == 6  # baseline + 4 candidates + final


def test_reserved_confirmation_is_not_stolen_by_candidate_fan_out(monkeypatch):
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=3)
    script = _Script(lambda ladder, **kw: _fixed_eval(0.0, total_episodes=1))
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="reserve-1", episodes=1, max_rounds=1, iterations=3, seed=9,
        total_episode_budget=4,
    )
    run = h._current_run
    # 1 baseline + 2 candidates + 1 reserved final = 4. The confirmation is
    # executed, not silently skipped by the candidate loop.
    assert run["confirmation_status"] == "executed"
    assert run["episode_accounting"]["final"]["consumed"] == 1
    assert run["episodes_consumed"] == 4
    assert run["final_evaluation_reused"] is False


def test_promotion_requires_genuine_measured_improvement(monkeypatch):
    h = AdaptiveHarness(store_path=None, episodes=3, max_rounds=1, iterations=1)
    # The gate compares against the stored active strategy's measured ASR.
    # Pin it to 0.0 so the only thing under test is that a candidate with a
    # genuine measured improvement passes (the seeded baseline is not part of
    # this test's scripted evidence).
    h._state["active"]["evaluation"]["asr"] = 0.0
    counter = {"n": 0}

    def _improving(ladder, **kw):
        counter["n"] += 1
        # baseline 0.0, candidate 1.0, final 1.0
        return _fixed_eval(
            0.0 if counter["n"] == 1 else 1.0,
            total_episodes=int(kw["episodes"]),
        )

    script = _Script(_improving)
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="promote-1", episodes=3, max_rounds=1, iterations=1, seed=4,
        total_episode_budget=9,
    )
    run = h._current_run
    assert run["status"] == "completed"
    assert run["improved"] is True
    assert run["gate"]["passed"] is True, run["gate"]["reasons"]
    assert h.status()["strategy_engine"]["active"]["strategy_id"] == run["candidate_id"]


def test_no_improvement_is_never_promoted(monkeypatch):
    h = AdaptiveHarness(store_path=None, episodes=3, max_rounds=1, iterations=1)
    script = _Script(lambda ladder, **kw: _fixed_eval(0.0, total_episodes=3))
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="noimprove-1", episodes=3, max_rounds=1, iterations=1, seed=6,
        total_episode_budget=9,
    )
    run = h._current_run
    assert run["status"] == "completed"
    assert run["gate"]["passed"] is False
    assert any("regression" in r for r in run["gate"]["reasons"])


def test_measured_feedback_reaches_the_next_generation_call(monkeypatch):
    h = AdaptiveHarness(store_path=None, episodes=1, max_rounds=1, iterations=1)
    h._email_target = {"target_id": "gmail-write-agent", "evaluation_mode": "send"}
    script = _Script(lambda ladder, **kw: _fixed_eval(0.0, total_episodes=1))
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(
        run_id="feedback-1", episodes=1, max_rounds=1, iterations=1, seed=8,
        total_episode_budget=4,
    )
    run = h._current_run
    assert run["candidate_evaluations"] == 2

    # call 0 = baseline (no feedback yet), call 1 = first candidate,
    # call 2 = second candidate. The second candidate's generation call
    # received the first candidate's MEASURED result.
    assert "email_feedback" not in script.kwargs[0]
    assert "email_feedback" not in script.kwargs[1]
    feedback = script.kwargs[2]["email_feedback"]
    assert feedback["asr"] == 0.0
    assert feedback["iteration"] == 1
    assert feedback["source"] == "measured_target_evidence"
    assert script.kwargs[2]["email_target"]["target_id"] == "gmail-write-agent"


# ---------------------------------------------------------------------------
# attack/defense separation during execution AND dashboard refresh
# ---------------------------------------------------------------------------


def _explode(*_args, **_kwargs):
    raise AssertionError("defense must not be built or executed here")


def test_campaign_execution_never_constructs_a_defense(monkeypatch, tmp_path):
    from pathlib import Path

    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "sep.json"),
        mode="greedy",
        defense="marker",
        iterations=1,
    )
    monkeypatch.setattr(ah, "_build_defense", _explode)
    script = _Script(lambda ladder, **kw: _fixed_eval(0.0, total_episodes=1))
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    h._run(run_id="sep-1", episodes=1, max_rounds=1, iterations=1, seed=1)
    run = h._current_run
    assert run["defense"] == "none"
    assert run["budget_exhausted"] is False
    for entry in run["episode_trace"]:
        assert entry.get("defense_decision") is None


def test_dashboard_refresh_never_executes_a_defense(monkeypatch, tmp_path):
    from pathlib import Path

    from backend import connections, defense_eval
    from frontend.server import build_overview

    store = connections.ConnectionStore(Path(tmp_path) / "connections.json")
    monkeypatch.setattr(connections, "get_store", lambda: store)
    monkeypatch.setattr(ah, "_build_defense", _explode)
    monkeypatch.setattr(
        defense_eval, "replay_attack_against_defense", _explode
    )
    # A refresh must be a pure read: forbid any evaluation as well as any
    # defense construction.
    harness = AdaptiveHarness(store_path=str(Path(tmp_path) / "dash.json"))
    monkeypatch.setattr(ah, "evaluate_strategy", _explode)
    overview = build_overview(harness)

    assert "run" in overview
    assert overview["metrics"]["ground_truth"] is None
    # The taxonomy/catalog is metadata only; no defense ran.
    assert overview["settings"]["defense"] == "none"


def test_dashboard_recalculates_a_legacy_run_honestly(monkeypatch, tmp_path):
    """A pre-schema run is shown from recalculated evidence, with its
    contaminated stored ASR explicitly marked as superseded."""
    from pathlib import Path

    from backend import connections
    from frontend.server import build_overview

    store = connections.ConnectionStore(Path(tmp_path) / "connections.json")
    monkeypatch.setattr(connections, "get_store", lambda: store)

    harness = AdaptiveHarness(store_path=str(Path(tmp_path) / "legacy.json"))
    trace = []
    for index, content in enumerate((True, True, False)):
        trace.append(
            {
                "case_id": f"legacy:ep{index}",
                "episode": index,
                "observed_outcome": "success" if content else "no_violation",
                "target_ground_truth": [
                    {
                        "unauthorized_send": content,
                        "unauthorized_draft": False,
                        "recipient_manipulated": False,
                        "content_manipulated": content,
                        "allowlist_enforced": True,
                        "send_confirmed": True,
                        "draft_created": False,
                    }
                ],
            }
        )
    harness._state["runs"].append(
        {
            "run_id": "legacy-run",
            "status": "budget_exhausted",
            "mode": "greedy",
            "target": "gmail-write-agent",
            "target_kind": "gmail_agent_write",
            "target_snapshot": {"mode": "send"},
            "global_best_category": "Gmail unauthorized send",
            "best_asr": 0.6667,
            "episode_trace": trace,
        }
    )

    overview = build_overview(harness)
    metrics = overview["metrics"]
    gt = metrics["ground_truth"]
    assert metrics["ground_truth_source"] == "recalculated_from_legacy_evidence"
    assert gt["metrics"]["content_manipulation"]["numerator"] == 2
    assert gt["metrics"]["content_manipulation"]["denominator"] == 3
    assert gt["metrics"]["unauthorized_send"]["numerator"] == 0
    assert gt["metrics"]["unauthorized_send"]["denominator"] == 3
    assert gt["recalculation"]["legacy_asr_superseded"] is True
    # The stored 0.6667 is still visible as history, but the objective channel
    # is the recalculated one.
    assert gt["objective_asr"]["channel"] == "unauthorized_send"
    assert gt["objective_asr"]["rate"] == 0.0


def test_dashboard_receives_separate_channels_and_budget_plan(monkeypatch, tmp_path):
    from pathlib import Path

    from backend import connections
    from frontend.server import build_overview

    store = connections.ConnectionStore(Path(tmp_path) / "connections.json")
    monkeypatch.setattr(connections, "get_store", lambda: store)

    harness = AdaptiveHarness(store_path=str(Path(tmp_path) / "dash2.json"))
    # Build the trace the real adapter persists: separate channels per episode.
    trace = []
    for index, content in enumerate((True, True, False)):
        trace.append(
            {
                "case_id": f"dash:ep{index}",
                "episode": index,
                "observed_outcome": "no_violation",
                "defense_decision": None,
                "rounds_used": 1,
                "steps": [
                    {
                        "category": "social_engineering",
                        "sophistication_level": 2,
                        "email": {
                            "subject": f"probe {index}",
                            "body": "synthetic",
                            "persona": {"name": "A", "role": "B", "company": "C"},
                            "tactic": "social_engineering",
                            "sophistication": 2,
                            "scenario": "approval_request",
                            "generation": {"mode": "ollama_refined", "model_used": True},
                        },
                    }
                ],
                "target_ground_truth": [
                    {
                        "evaluation_mode": "send",
                        "content_manipulated": content,
                        "unauthorized_draft": False,
                        "unauthorized_send": False,
                        "unauthorized_recipient_delivery": False,
                        "recipient_manipulated": False,
                        "legitimate_action": True,
                        "send_confirmed": True,
                        "draft_created": False,
                    }
                ],
            }
        )
    script = _Script(
        lambda ladder, **kw: _fixed_eval(0.0, total_episodes=3, trace=trace)
    )
    monkeypatch.setattr(ah, "evaluate_strategy", script)
    harness._run(
        run_id="dash-run", episodes=3, max_rounds=1, iterations=1, seed=3,
        total_episode_budget=9,
    )

    overview = build_overview(harness)
    metrics = overview["metrics"]
    gt = metrics["ground_truth"]
    assert gt["metrics"]["content_manipulation"]["numerator"] == 2
    assert gt["metrics"]["content_manipulation"]["denominator"] == 3
    assert gt["metrics"]["unauthorized_send"]["numerator"] == 0
    assert gt["metrics"]["unauthorized_send"]["denominator"] == 3
    assert metrics["budget_plan"]["total_episode_budget"] == 9
    assert metrics["episode_accounting"]["consumed_total"] == 9
    assert metrics["stop_reason"] in {"plan_complete", "plan_complete_search_truncated_by_budget"}
    # No single combined ASR channel is presented in place of these metrics.
    assert gt["metrics"]["unauthorized_send"]["channel"] == "unauthorized_send"
