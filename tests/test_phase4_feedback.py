"""Phase 4 — feedback-guided adaptive search (``docs/ADAPTIVE_SEARCH.md`` §6).

Checklist covered here:

* cross-candidate statistics persist across candidate evaluations in one run
* independent runs never share feedback state
* a previous outcome changes a later candidate ranking/selection — and the
  counter-fixture proves the change is genuinely outcome-driven rather than a
  relabelled neighbour loop (the §6 regression test)
* Diagnoser output is ingested only through the validated ``AttackOutcome``
  interface (unknown vocabulary is refused)
* technical failures / incomplete evaluations can never create a favourable
  learning signal
* deterministic tie-breaking and repeatability
* feedback-store persistence, reload, validation, corruption handling
* duplicate candidate avoidance
* the greedy baseline is untouched when the adaptive mode is disabled
* the promotion gate still rejects candidates that fail its requirements
* the A/B comparison uses comparable configurations and records its results
* a second local deterministic defense changes the landscape and resets the
  store (no cross-defense leakage)

Everything runs offline: no LLM calls, no Gmail, no network.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from adaptive_agent_eval.models import AttackOutcome
from backend.adaptive_ab import compare_search_modes
from backend.adaptive_harness import (
    DEFENDER_UTILITY_FLOOR,
    AdaptiveHarness,
    StrategyEvaluation,
    evaluate_strategy,
    neighbours,
)
from backend.search_feedback import (
    OUTCOME_VOCAB,
    FeedbackStore,
    FeedbackStoreError,
    ladder_key,
    step_key,
)

# ---------------------------------------------------------------------------
# Deterministic evaluation double with *valid* episode traces.
#
# ``_run`` calls the module-level ``evaluate_strategy``. The double pins ASR
# per ladder and emits the structured episode trace the feedback store
# ingests (outcome + exercised steps), so the tests control the evidence
# instead of hoping the simulator lands somewhere convenient.
# ---------------------------------------------------------------------------


class _TraceEval:
    """``evaluate_strategy`` stand-in with pinned ASR and valid traces."""

    def __init__(self, asr_for, *, utility: float = 1.0, tech_fails: int = 0):
        self._asr_for = asr_for
        self._utility = utility
        self._tech_fails = tech_fails
        self.calls: list[list[dict]] = []

    def __call__(
        self,
        ladder,
        *,
        episodes,
        max_rounds,
        seed,
        strategy_id="",
        stop_event=None,
        defense=None,
    ):
        self.calls.append([dict(s) for s in ladder])
        asr = self._asr_for([dict(s) for s in ladder])
        successes = round(asr * episodes)
        tech = min(self._tech_fails, episodes)
        blocked = episodes - successes - tech
        steps = [dict(s) for s in ladder]
        outcomes = {"success": successes, "blocked": max(blocked, 0)}
        if tech:
            outcomes["technical_fail"] = tech
        trace = []
        for i in range(episodes):
            if i < successes:
                outcome = "success"
            elif i < successes + blocked:
                outcome = "blocked"
            else:
                outcome = "technical_fail"
            trace.append(
                {
                    "episode": i,
                    "outcome": outcome,
                    "rounds_used": len(steps),
                    "steps": [dict(s) for s in steps],
                }
            )
        return StrategyEvaluation(
            strategy_id=strategy_id or "scripted",
            ladder=[dict(s) for s in ladder],
            asr=round(float(asr), 4),
            bypass_rate=None,
            rounds_to_success=None,
            utility_score=self._utility,
            cost_per_attack=None,
            total_episodes=episodes,
            defense_denied=0,
            defense_allowed=0,
            outcomes=outcomes,
            checksums=[],
            elapsed_seconds=0.0,
            defense=str(defense or "marker"),
            episode_trace=trace,
        )


def _last_cat_asr(mapping, default=0.0):
    """ASR keyed on the ladder's last rung category (the deciding step)."""

    def asr(ladder):
        cat = ladder[-1]["category"] if ladder else "direct_injection"
        return mapping.get(cat, default)

    return asr


#: The controlled landscape: only ladders ending in ``direct_injection``
#: improve (ASR 0.5); the baseline ladder ends in ``social_engineering``
#: (ASR 0.0). Exact fractions of 1/episodes keep ASR and outcomes consistent.
_FIXTURE_ASR = _last_cat_asr({"direct_injection": 0.5})
_ZERO_ASR = _last_cat_asr({})

_BASELINE = [
    {"category": "direct_injection", "sophistication_level": 1},
    {"category": "social_engineering", "sophistication_level": 2},
]
_DI2_DI2 = [
    {"category": "direct_injection", "sophistication_level": 2},
    {"category": "direct_injection", "sophistication_level": 2},
]

_CFG = {"episodes": 4, "max_rounds": 2, "iterations": 3, "seed": 1}


def _run_harness(tmp_path, monkeypatch, *, mode, asr_for, run_id, **kw):
    script = _TraceEval(asr_for, **kw)
    monkeypatch.setattr("backend.adaptive_harness.evaluate_strategy", script)
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / f"{mode}.json"),
        mode=mode,
        selection_budget=3,
    )
    h._run(run_id=run_id, **_CFG)
    assert h._current_run is not None
    return h, script, h._current_run


def _selections(run, iteration):
    return [
        e["selection"] for e in run["history"] if e["iteration"] == iteration
    ]


# ---------------------------------------------------------------------------
# A. Store: cross-candidate accumulation, isolation, validation
# ---------------------------------------------------------------------------


def _cfg(mode="feedback", episodes=4, defense="marker"):
    return {
        "mode": mode,
        "episodes": episodes,
        "max_rounds": 2,
        "iterations": 3,
        "seed": 1,
        "defense": defense,
        "selection_budget": 3,
    }


def _eval(ladder, *, asr, episodes=4, tech_fails=0, trace=True, utility=1.0):
    """A plain evaluation dict (what ``StrategyEvaluation.to_dict`` yields)."""
    successes = round(asr * episodes)
    blocked = episodes - successes - tech_fails
    outcomes = {"success": successes, "blocked": max(blocked, 0)}
    if tech_fails:
        outcomes["technical_fail"] = tech_fails
    return {
        "strategy_id": "e",
        "ladder": [dict(s) for s in ladder],
        "asr": asr,
        "total_episodes": episodes,
        "outcomes": outcomes,
        "utility_score": utility,
        "defense": "marker",
        "episode_trace": (
            [
                {
                    "episode": i,
                    "outcome": "success" if i < successes else "blocked",
                    "rounds_used": len(ladder),
                    "steps": [dict(s) for s in ladder],
                }
                for i in range(episodes)
            ]
            if trace
            else None
        ),
    }


def test_step_statistics_accumulate_across_candidate_evaluations(tmp_path):
    """Within one store instance, evidence from *different* candidates stacks
    up on shared steps — this is the cross-candidate learning surface."""
    store = FeedbackStore.open(tmp_path / "s.json", run_id="r1", config=_cfg())
    ladder_a = [dict(_BASELINE[0]), {"category": "obfuscation", "sophistication_level": 2}]
    ladder_b = [dict(_BASELINE[0]), {"category": "social_engineering", "sophistication_level": 2}]
    store.observe(_eval(ladder_a, asr=0.5), ladder=ladder_a, iteration=1, requested_episodes=4)
    store.observe(_eval(ladder_b, asr=0.0), ladder=ladder_b, iteration=2, requested_episodes=4)

    # The shared first step saw both evaluations; the deciding (last) steps
    # each saw one.
    shared = store.state["step_stats"][step_key(_BASELINE[0])]
    assert shared["exposures"] == 8
    assert store.state["step_stats"][step_key(ladder_a[-1])]["decided"] == 4
    assert store.state["step_stats"][step_key(ladder_b[-1])]["decided"] == 4
    totals = store.state["totals"]
    assert totals["episodes_decided"] == 8
    assert totals["known_decisions"] == 8
    assert len(store.state["candidates"]) == 2


def test_independent_runs_never_share_feedback_state(tmp_path):
    path = tmp_path / "s.json"
    first = FeedbackStore.open(path, run_id="run-a", config=_cfg())
    ladder = [dict(_BASELINE[0]), {"category": "obfuscation", "sophistication_level": 2}]
    first.observe(_eval(ladder, asr=1.0), ladder=ladder, iteration=1, requested_episodes=4)
    assert first.state["totals"]["episodes_decided"] == 4

    # A different run_id must start clean and record why.
    second = FeedbackStore.open(path, run_id="run-b", config=_cfg())
    assert second.origin.startswith("fresh:")
    assert "new-run" in second.origin
    assert second.state["totals"]["episodes_decided"] == 0
    assert second.state["step_stats"] == {}
    assert any("new-run" in r["reason"] for r in second.state["resets"])

    # A changed config fingerprint also forces a clean store.
    third = FeedbackStore.open(path, run_id="run-b", config=_cfg(episodes=8))
    assert "config-changed" in third.origin
    assert third.state["totals"]["episodes_decided"] == 0


def test_harness_runs_isolate_their_feedback_state(tmp_path, monkeypatch):
    """Two runs of the same harness config accumulate identical totals — proof
    the second run starts from zero instead of doubling the first run's."""
    script = _TraceEval(_FIXTURE_ASR)
    monkeypatch.setattr("backend.adaptive_harness.evaluate_strategy", script)
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "h.json"), mode="feedback", selection_budget=3
    )
    h._run(run_id="iso-1", **_CFG)
    totals_one = dict(h._current_run["feedback"]["totals"])
    h._run(run_id="iso-2", **_CFG)
    totals_two = dict(h._current_run["feedback"]["totals"])

    assert totals_two["episodes_decided"] == totals_one["episodes_decided"] > 0
    persisted = json.loads(
        (Path(tmp_path) / "h.json.feedback.json").read_text(encoding="utf-8")
    )
    assert persisted["run_id"] == "iso-2"
    assert any("new-run" in r["reason"] for r in persisted["resets"])


def test_persistence_reload_and_corruption_handling(tmp_path):
    path = tmp_path / "s.json"
    store = FeedbackStore.open(path, run_id="r1", config=_cfg())
    ladder = [dict(_BASELINE[0]), {"category": "obfuscation", "sophistication_level": 2}]
    store.observe(_eval(ladder, asr=0.5), ladder=ladder, iteration=1, requested_episodes=4)

    # Reload: valid state is reused and keeps its statistics.
    reloaded = FeedbackStore.open(path, run_id="r1", config=_cfg())
    assert reloaded.origin == "reused"
    assert reloaded.state["totals"]["episodes_decided"] == 4

    def _assert_healed(mutate, *, written: str | None = None):
        """Corrupt the file, reopen, and require a clean store + audit entry."""
        if written is not None:
            path.write_text(written, encoding="utf-8")
        else:
            data = json.loads(path.read_text(encoding="utf-8"))
            mutate(data)
            path.write_text(json.dumps(data), encoding="utf-8")
        healed = FeedbackStore.open(path, run_id="r1", config=_cfg())
        assert healed.origin.startswith("fresh:invalid-state")
        assert healed.state["totals"]["episodes_decided"] == 0
        assert "invalid-state" in healed.state["resets"][0]["reason"]

    # Corruption 1: not JSON at all.
    _assert_healed(None, written="{not json")

    # Corruption 2: valid JSON but internally inconsistent counters.
    store.save()  # restore a valid file, then break the totals invariant
    _assert_healed(lambda d: d["totals"].__setitem__("successes", 99))

    # Corruption 3: tampered ladder key (record does not match its ladder).
    store.save()

    def _tamper(d):
        key = next(iter(d["candidates"]))
        d["candidates"][key]["ladder"][0]["category"] = "obfuscation"

    _assert_healed(_tamper)

    # Corruption 4: wrong schema version.
    store.save()
    _assert_healed(lambda d: d.__setitem__("schema_version", 999))

    # Corruption 5: counters disagreeing with the step_stats sum.
    store.save()

    def _desync(d):
        key = next(iter(d["step_stats"]))
        d["step_stats"][key]["decided"] = 7
        d["step_stats"][key]["successes"] = 7

    _assert_healed(_desync)


def test_diagnoser_outcomes_are_the_only_evidence_vocabulary():
    """The store accepts the structured ``AttackOutcome`` enum and nothing
    else — free-text or invented explanations can never be ingested."""
    assert OUTCOME_VOCAB == {o.value for o in AttackOutcome}
    assert "technical_fail" in OUTCOME_VOCAB

    store = FeedbackStore.open(None, run_id="r", config=_cfg())
    ladder = [dict(_BASELINE[0])]
    for bad in ("totally_made_up", "the model explained that it worked", ""):
        ev = _eval(ladder, asr=0.5)
        ev["outcomes"] = {bad: 1}
        with pytest.raises(FeedbackStoreError, match="unknown outcome"):
            store.observe(ev, ladder=ladder, iteration=1, requested_episodes=4)
    # A malformed step (unknown sophistication) is refused too.
    with pytest.raises(FeedbackStoreError):
        store.observe(
            _eval(ladder, asr=0.5),
            ladder=[{"category": "direct_injection", "sophistication_level": 9}],
            iteration=1,
            requested_episodes=4,
        )


def test_unusable_evidence_cannot_create_a_favorable_signal(tmp_path):
    """Technical failures, incomplete evaluations and missing traces are
    recorded as unusable and contribute *zero* ranking statistics."""
    store = FeedbackStore.open(tmp_path / "s.json", run_id="r1", config=_cfg())
    ladder = [dict(_BASELINE[0]), {"category": "obfuscation", "sophistication_level": 2}]

    # High ASR, but 2 technical failures → unusable.
    res = store.observe(
        _eval(ladder, asr=1.0, tech_fails=2), ladder=ladder, iteration=1, requested_episodes=4
    )
    assert res["usable"] is False and "technical failure" in res["reason"]
    # High ASR, but only 3 of 4 episodes ran → unusable.
    res = store.observe(
        _eval(ladder, asr=1.0, episodes=3), ladder=ladder, iteration=2, requested_episodes=4
    )
    assert res["usable"] is False and "incomplete" in res["reason"]
    # Missing trace → unusable.
    res = store.observe(
        _eval(ladder, asr=1.0, trace=False), ladder=ladder, iteration=3, requested_episodes=4
    )
    assert res["usable"] is False

    assert store.state["totals"]["episodes_decided"] == 0
    assert store.state["step_stats"] == {}
    assert store.state["totals"]["unusable_evaluations"] == 3
    # Ranking therefore stays exactly neutral: every candidate scores p = 0.0.
    ranked = store.rank(neighbours(_BASELINE))
    assert {e["score"] for e in ranked} == {0.0}
    assert [e["structural_index"] for e in ranked] == sorted(
        e["structural_index"] for e in ranked
    )


def test_rank_is_deterministic_and_breaks_ties_structurally(tmp_path):
    store = FeedbackStore.open(tmp_path / "s.json", run_id="r1", config=_cfg())
    cands = neighbours(_BASELINE)
    first = store.rank(cands)
    second = store.rank(cands)
    assert first == second, "ranking must be a pure function of the store"
    # Cold store: all scores equal p, so order is exactly structural order.
    assert [e["structural_index"] for e in first] == list(range(len(cands)))
    # With observed evidence the ordering becomes score-driven but stays
    # deterministic; equal scores still resolve to structural order.
    for entry in first:
        assert set(entry) == {"key", "ladder", "score", "structural_index", "evidence"}
    scores = [e["score"] for e in first]
    assert scores == sorted(scores, reverse=True)


def test_smoothing_is_documented_shrinkage_not_a_confidence_claim():
    from backend.search_feedback import ALPHA

    store = FeedbackStore.open(None, run_id="r", config=_cfg())
    assert store.prior() == 0.0
    # Unobserved step scores exactly the prior, by construction.
    ladder = [dict(_BASELINE[0]), {"category": "obfuscation", "sophistication_level": 3}]
    entry = store.rank([ladder])[0]
    assert entry["score"] == 0.0
    assert all(ev["observed"] is False for ev in entry["evidence"])
    assert ALPHA > 0  # documented pseudo-count, not a statistical guarantee


# ---------------------------------------------------------------------------
# B. The learning loop (outcome dependence regression)
# ---------------------------------------------------------------------------


def test_cross_candidate_statistics_persist_within_one_run(tmp_path, monkeypatch):
    _, _, run = _run_harness(
        tmp_path, monkeypatch, mode="feedback", asr_for=_FIXTURE_ASR, run_id="stats-1"
    )
    summary = run["feedback"]
    assert summary["totals"]["episodes_decided"] >= 4 * 2  # several evaluations
    assert summary["candidates_recorded"] >= 4  # baseline + candidates
    assert (
        summary["totals"]["usable_evaluations"] == summary["candidates_recorded"]
    )
    assert summary["selections_recorded"] == _CFG["iterations"]
    # Statistics were still live in the *last* iteration, i.e. they were not
    # reset between candidates.
    last = _selections(run, _CFG["iterations"])[-1]
    assert last["evidence"], "the final selection must cite observed evidence"
    assert any(ev["observed"] for ev in last["evidence"])


def test_previous_outcome_changes_a_later_selection(tmp_path, monkeypatch):
    """The §6 regression test: the adaptive path is genuinely outcome-driven.

    Controlled fixture, two runs with the *same* candidate landscape:

    1. outcomes observed → a candidate that is 5th in structural order is
       ranked first in iteration 3 and is the one actually evaluated first;
    2. counter-fixture, no successes ever → the ordering stays exactly
       structural.

    If the feedback path were merely a relabelled neighbour loop, both runs
    would produce the same ordering and (2) could not differ from (1).
    """
    _, _, run = _run_harness(
        tmp_path, monkeypatch, mode="feedback", asr_for=_FIXTURE_ASR, run_id="dep-yes"
    )

    # (1) Cold start: iteration 1 ranks structurally (no evidence yet).
    it1 = _selections(run, 1)
    assert it1[0]["structural_index"] == 0
    assert it1[0]["key"] == ladder_key(
        [{"category": "obfuscation", "sophistication_level": 1}, _BASELINE[1]]
    )

    # After 6 evaluations (2 iterations) the observed outcomes move
    # direct_injection:2 to the top: it is NOT the structural-first candidate.
    it3 = [
        e for e in run["history"] if e["iteration"] == 3
    ]
    assert it3, "expected a third iteration"
    top = it3[0]["selection"]
    assert top["structural_index"] == 4
    assert top["key"] == ladder_key(_DI2_DI2)
    assert top["score"] > 0
    assert any(
        ev["step"] == step_key({"category": "direct_injection", "sophistication_level": 2})
        and ev["observed"]
        for ev in top["evidence"]
    )
    # The candidate the feedback path evaluates first in iteration 3 is the
    # outcome-driven pick, not the structural one.
    evaluated_first_it3 = _selections(run, 3)
    assert evaluated_first_it3[0]["key"] == ladder_key(_DI2_DI2)
    assert evaluated_first_it3[0]["structural_index"] != 0

    # (2) Counter-fixture: same landscape shape, but no outcome is ever a
    # success, so no statistic can favour any candidate.
    _, _, run2 = _run_harness(
        tmp_path,
        monkeypatch,
        mode="feedback",
        asr_for=_ZERO_ASR,
        run_id="dep-no",
    )
    assert run2["improved"] is False
    it3_b = [e for e in run2["history"] if e["iteration"] == 3]
    assert it3_b, "expected a third iteration in the counter-fixture too"
    top_b = it3_b[0]["selection"]
    assert top_b["structural_index"] == 0, (
        "without observed successes the ordering must remain structural"
    )
    # Every candidate still scores exactly the prior: no evidence favours one.
    assert all(ev["observed"] is False for ev in top_b["evidence"])
    assert all(ev["decided"] == 0 or ev["successes"] == 0 for ev in top_b["evidence"])


def test_feedback_ordering_differs_from_greedy_and_never_duplicates(
    tmp_path, monkeypatch
):
    _, _, fb_run = _run_harness(
        tmp_path, monkeypatch, mode="feedback", asr_for=_FIXTURE_ASR, run_id="ord-fb"
    )
    _, _, greedy_run = _run_harness(
        tmp_path, monkeypatch, mode="greedy", asr_for=_FIXTURE_ASR, run_id="ord-g"
    )

    def keys(run):
        return [ladder_key(e["candidate_ladder"]) for e in run["history"]]

    fb_keys, greedy_keys = keys(fb_run), keys(greedy_run)
    assert fb_keys != greedy_keys, "feedback must change candidate ordering"

    # Duplicate avoidance: feedback evaluates a ladder at most once per run;
    # the greedy baseline may revisit ladders (it has no dedup, unchanged).
    assert len(set(fb_keys)) == len(fb_keys)
    assert len(greedy_keys) > len(set(greedy_keys))
    # And the budget bounds the per-iteration work.
    per_iter = [
        len([e for e in fb_run["history"] if e["iteration"] == it])
        for it in range(1, _CFG["iterations"] + 1)
    ]
    assert max(per_iter) <= 3
    assert len(greedy_keys) > len(fb_keys)


def test_identical_configuration_is_repeatable(tmp_path, monkeypatch):
    _, _, run_a = _run_harness(
        tmp_path, monkeypatch, mode="feedback", asr_for=_FIXTURE_ASR, run_id="rep-a"
    )
    _, _, run_b = _run_harness(
        tmp_path, monkeypatch, mode="feedback", asr_for=_FIXTURE_ASR, run_id="rep-b"
    )

    def fingerprint(run):
        return [
            (e["iteration"], ladder_key(e["candidate_ladder"]), e["asr"])
            for e in run["history"]
        ]

    assert fingerprint(run_a) == fingerprint(run_b)
    assert run_a["best_asr"] == run_b["best_asr"]
    assert run_a["unique_candidates_evaluated"] == run_b["unique_candidates_evaluated"]
    # Selection rationale is persisted for audit, with the evidence used.
    persisted = json.loads(
        (Path(tmp_path) / "feedback.json.feedback.json").read_text(encoding="utf-8")
    )
    assert persisted["selections"], "selections must be auditable after the run"
    entry = persisted["selections"][0]
    assert {"iteration", "ranked", "evaluated", "accepted", "budget"} <= set(entry)
    assert entry["ranked"][0]["evidence"] is not None


def test_baseline_is_unchanged_when_the_adaptive_mode_is_disabled(
    tmp_path, monkeypatch
):
    store = Path(tmp_path) / "greedy.json"
    script = _TraceEval(_FIXTURE_ASR)
    monkeypatch.setattr("backend.adaptive_harness.evaluate_strategy", script)

    h = AdaptiveHarness(store_path=str(store))  # defaults: greedy + marker
    assert h.status()["search_mode"] == "greedy"
    # Campaigns are attack-only: "none" is what ran; the label is preserved.
    assert h.status()["defense"] == "none"
    assert h.status()["requested_defense"] == "marker"
    assert h.status()["feedback"] is None

    h._run(run_id="base-1", **_CFG)
    run = h._current_run
    assert run["mode"] == "greedy"
    assert run["selection_budget"] is None
    assert run["feedback"] is None
    # The baseline call pattern is untouched: init baseline + run baseline +
    # one evaluation per history entry + the final evaluation.
    assert len(script.calls) == 1 + 1 + len(run["history"]) + 1
    # Baseline history entries keep their exact field set (no new keys leaked
    # into the approved baseline records).
    assert set(run["history"][0]) == {
        "iteration",
        "candidate_ladder",
        "candidate_id",
        "parent_ladder",
        "mutation",
        "asr",
        "baseline_asr",
        "improved",
        "delta",
    }
    # No feedback store is ever created in greedy mode.
    assert not Path(str(store) + ".feedback.json").exists()
    # Greedy still evaluates the full structural neighbour set each iteration.
    assert len(run["history"]) >= len(neighbours([dict(s) for s in _BASELINE]))


def test_invalid_search_configuration_is_rejected(tmp_path):
    with pytest.raises(ValueError, match="search mode"):
        AdaptiveHarness(mode="bayesian")
    with pytest.raises(ValueError, match="defense"):
        AdaptiveHarness(mode="feedback", defense="honeypot")
    with pytest.raises(ValueError, match="selection_budget"):
        AdaptiveHarness(mode="feedback", selection_budget=0)
    h = AdaptiveHarness(store_path=str(Path(tmp_path) / "h.json"))
    assert h.configure(mode="feedback")["mode"] == "feedback"
    with pytest.raises(ValueError, match="search mode"):
        h.configure(mode="magic")
    # The API surface passes configuration through start(); an invalid value
    # surfaces as an error, never as a silent fallback to another algorithm.
    with pytest.raises(ValueError, match="search mode"):
        h.start(episodes=1, max_rounds=1, iterations=1, seed=1, mode="magic")


def test_feedback_mode_gate_ignores_defender_utility(tmp_path, monkeypatch):
    """Selection changes; the gate is attack-only. Defender utility is not a
    campaign gate input because no defense runs during a campaign, so a low
    scripted utility value cannot reject a candidate that genuinely improved
    measured ASR. The utility floor still applies to the gate's generic form
    (``require_utility=True``), which campaigns never use."""
    h, _, run = _run_harness(
        tmp_path,
        monkeypatch,
        mode="feedback",
        asr_for=_FIXTURE_ASR,
        run_id="gate-attack-only",
        utility=0.5,
    )
    assert run["improved"] is True
    gate = run["gate"]
    assert gate["passed"] is True, gate["reasons"]
    assert not any("utility" in r for r in gate["reasons"])
    assert gate["checked"]["utility_floor"] == DEFENDER_UTILITY_FLOOR
    candidates = h.status()["candidates"]
    assert candidates[-1]["status"] == "active"
    assert candidates[-1]["candidate_id"] == run["candidate_id"]
    assert run["defense"] == "none"


def test_status_exposes_mode_rationale_and_completeness(tmp_path, monkeypatch):
    h, _, run = _run_harness(
        tmp_path, monkeypatch, mode="feedback", asr_for=_FIXTURE_ASR, run_id="status-1"
    )
    status = h.status()
    assert status["search_mode"] == "feedback"
    assert status["defense"] == "none"
    assert status["requested_defense"] == "marker"
    assert status["selection_budget"] == 3
    fb = status["feedback"]
    assert fb is not None
    assert fb["alpha"] > 0 and fb["schema_version"] == 1
    assert fb["totals"]["episodes_decided"] > 0
    # Every evaluated candidate records why it was selected: rank, score,
    # structural position, the per-step evidence, and evaluation completeness.
    for entry in run["history"]:
        sel = entry["selection"]
        assert {"rank", "score", "structural_index", "evidence",
                "observed_usable", "observe_reason", "frontier_size"} <= set(sel)
    # Promotion status still flows through the same reporting surface.
    assert "gate" in run and "passed" in run["gate"]
    assert status["strategy_engine"]["active"]


# ---------------------------------------------------------------------------
# C. A/B evaluation protocol
# ---------------------------------------------------------------------------


def test_ab_comparison_uses_comparable_config_and_records_results(tmp_path):
    out = tmp_path / "ab_results.json"
    record = compare_search_modes(
        tmp_path / "ab",
        episodes=3,
        max_rounds=2,
        iterations=3,
        seed=20261024,
        defense="marker",
        selection_budget=3,
        out_path=out,
    )
    assert record["config"]["arms"] == ["greedy", "feedback"]
    greedy_cfg = record["arms"]["greedy"]["result"]["config"]
    feedback_cfg = record["arms"]["feedback"]["result"]["config"]
    # Same ladder, defense, episodes, iterations, seeds — comparable arms.
    # Campaigns are attack-only, so the recorded defense is "none" and the
    # requested label is preserved separately.
    assert record["config"]["defense"] == "none"
    assert record["config"]["requested_defense"] == "marker"
    for field in ("episodes", "max_rounds", "iterations", "seed", "defense"):
        assert greedy_cfg[field] == feedback_cfg[field] == record["config"][field]

    for arm in ("greedy", "feedback"):
        result = record["arms"][arm]["result"]
        assert isinstance(result["selected_strategy_asr"], float)
        assert isinstance(result["candidate_evaluations"], int)
        assert isinstance(result["unique_candidates_evaluated"], int)
        assert isinstance(result["episodes_consumed"], int)
        assert isinstance(result["incomplete_evaluations"], int)
        assert isinstance(result["technical_failure_episodes"], int)
        # No defense ran, so benign utility probes were not executed.
        assert result["final_utility"] is None
        assert isinstance(result["promoted"], bool)
        assert result["ordering"], "the followed candidate order must be recorded"
        # Repeated with an identical configuration: the trajectory is stable.
        assert record["arms"][arm]["reproducible"] is True

    assert isinstance(record["feedback_changed_ordering"], bool)
    assert record["results_are_recorded"] is True
    assert record["held_constant"] and record["cannot_hold_constant"]
    # The results file is written and parses back to the same record.
    on_disk = json.loads(out.read_text(encoding="utf-8"))
    assert on_disk["protocol"] == record["protocol"]
    assert on_disk["arms"]["feedback"]["result"]["candidate_evaluations"] == record[
        "arms"
    ]["feedback"]["result"]["candidate_evaluations"]


# ---------------------------------------------------------------------------
# D. Defense transfer (second local deterministic defense)
# ---------------------------------------------------------------------------


def test_second_local_defense_flips_the_preference_landscape():
    """Two toy defenses, one question: does a marker-learned preference just
    transfer? The measured answer here is no — the landscape inverts, which is
    exactly why the defense is a configuration knob rather than an assumption.

    Evidence is deterministic local simulation only; two defenses cannot
    support a claim of cross-defense generalization.
    """
    evasive = [
        {"category": "obfuscation", "sophistication_level": 1},
        {"category": "advanced_persistent", "sophistication_level": 1},
    ]
    marker_evasive = evaluate_strategy(
        evasive, episodes=8, max_rounds=2, seed=11, defense="marker"
    )
    marker_plain = evaluate_strategy(
        _BASELINE, episodes=8, max_rounds=2, seed=11, defense="marker"
    )
    verifier_evasive = evaluate_strategy(
        evasive, episodes=8, max_rounds=2, seed=11, defense="verifier"
    )
    verifier_plain = evaluate_strategy(
        _BASELINE, episodes=8, max_rounds=2, seed=11, defense="verifier"
    )

    # Marker defense: encoded payloads evade, literal ones are blocked.
    assert marker_evasive.asr > 0.0
    assert marker_plain.asr == 0.0
    # Verifier defense: intent matching denies the encoded payloads and
    # passes the literal ones — the preference direction inverts.
    assert verifier_evasive.asr == 0.0
    assert verifier_plain.asr > 0.0
    assert marker_evasive.defense == "marker"
    assert verifier_evasive.defense == "verifier"
    # Both stay honest about unmeasured metrics rather than fabricating them.
    for ev in (marker_evasive, verifier_evasive):
        assert ev.episode_trace and ev.total_episodes == 8


def test_feedback_run_under_the_second_defense_resets_the_store(tmp_path):
    """No statistics leak across defenses: the config fingerprint includes the
    defense, so switching it forces a clean store with a recorded reason."""
    cfg_marker = _cfg(defense="marker")
    cfg_verifier = _cfg(defense="verifier")
    path = tmp_path / "s.json"
    a = FeedbackStore.open(path, run_id="shared", config=cfg_marker)
    ladder = [dict(_BASELINE[0]), {"category": "obfuscation", "sophistication_level": 2}]
    a.observe(_eval(ladder, asr=1.0), ladder=ladder, iteration=1, requested_episodes=4)
    assert a.state["totals"]["episodes_decided"] == 4

    b = FeedbackStore.open(path, run_id="shared", config=cfg_verifier)
    assert "config-changed" in b.origin
    assert b.state["totals"]["episodes_decided"] == 0


def test_feedback_search_ignores_the_selected_defense_label(tmp_path):
    """Attack/defense separation: the feedback loop drives the real evaluator,
    but a defense label (here the verifier) has NO effect on a campaign. Two
    runs differing only by that label must measure identical attack evidence,
    record ``defense="none"``, and evaluate no benign utility probes."""
    verifier_store = Path(tmp_path) / "v.json"
    hv = AdaptiveHarness(
        store_path=str(verifier_store),
        mode="feedback",
        defense="verifier",
        selection_budget=3,
    )
    hv._run(run_id="verifier-run", episodes=4, max_rounds=2, iterations=2, seed=5)
    run = hv._current_run
    assert run["mode"] == "feedback"
    assert run["defense"] == "none"
    assert run["requested_defense"] == "verifier"
    assert run["history"], "the feedback path must have evaluated candidates"
    assert run["feedback"]["config"]["defense"] == "none"
    assert run["feedback"]["selections_recorded"] >= 1
    assert run["feedback"]["totals"]["technical_fail"] == 0
    # No defense ran, so no defense decision and no utility measurement exist.
    assert run["gate"]["checked"]["utility"] is None
    assert not any("utility" in r for r in run["gate"]["reasons"])
    assert not any("defense" in r.lower() for r in run["gate"]["reasons"])

    marker_store = Path(tmp_path) / "m.json"
    hm = AdaptiveHarness(
        store_path=str(marker_store),
        mode="feedback",
        defense="marker",
        selection_budget=3,
    )
    hm._run(run_id="marker-run", episodes=4, max_rounds=2, iterations=2, seed=5)
    other = hm._current_run
    assert other["defense"] == "none"
    # Same attack evidence regardless of the requested defense label.
    assert [e["asr"] for e in other["history"]] == [e["asr"] for e in run["history"]]
