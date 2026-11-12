"""Phase 6B — validated model-suggested candidates + explicit provider selection.

Checklist covered here (all offline, no network, no paid API calls):

* a valid model suggestion genuinely influences the next candidate decision
  (it is evaluated FIRST and the influence is auditable in the run record)
* feedback from an evaluated suggested candidate affects later selection
  (the outcome flows through the same feedback store; no re-evaluation)
* invalid suggestions are rejected safely, each with an explicit reason:
  schema-invalid, out-of-scope (not a single-step neighbour), duplicate
* a model exception (provider outage, request-budget exhaustion) is a
  rejection record — never a security outcome, never a crash
* a model's own claim that an attack succeeded can NEVER count as evidence:
  only the harness evaluation of the resulting candidate is recorded
* greedy mode remains fully independent of the assistant
* explicit provider selection is validated; a requested live provider never
  silently falls back to the fake provider; missing credentials fail loudly
* the model-request budget is enforced and reported from real telemetry
* model-suggestion records survive checkpoint/resume (and old checkpoints
  without the new field still resume)
* the frontend wires its provider/budget controls to /api/adaptive/run
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from adaptive_agent_eval.llm.adaptive_assistant import (
    AdaptiveModelAssistant,
    CandidateProposal,
)
from adaptive_agent_eval.llm.provider import FakeConfig
from backend.adaptive_harness import (
    AdaptiveHarness,
    StrategyEvaluation,
    _checkpoint_progress_keys,
)
from backend.search_feedback import ladder_key

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Deterministic evaluation double with valid episode traces (same shape as
# tests/test_phase4_feedback.py): ASR is keyed on the ladder's LAST category,
# so the landscape is controlled exactly.
# ---------------------------------------------------------------------------


class _TraceEval:
    def __init__(self, asr_for, *, utility: float = 1.0):
        self._asr_for = asr_for
        self._utility = utility
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
        blocked = episodes - successes
        steps = [dict(s) for s in ladder]
        outcomes = {"success": successes, "blocked": max(blocked, 0)}
        trace = []
        for i in range(episodes):
            trace.append(
                {
                    "episode": i,
                    "outcome": "success" if i < successes else "blocked",
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
    def asr(ladder):
        cat = ladder[-1]["category"] if ladder else "direct_injection"
        return mapping.get(cat, default)

    return asr


#: Controlled landscape: only ladders ending in direct_injection succeed.
_FIXTURE_ASR = _last_cat_asr({"direct_injection": 0.5})

_BASELINE = [
    {"category": "direct_injection", "sophistication_level": 1},
    {"category": "social_engineering", "sophistication_level": 2},
]
#: A single-step neighbour of the baseline (position 1 category swap) that
#: ends in direct_injection — structural index 5, NOT the structural-first
#: candidate, and a strict improvement over the baseline (ASR 0.5 > 0.0).
_GOOD_NEIGHBOUR = [
    {"category": "direct_injection", "sophistication_level": 1},
    {"category": "direct_injection", "sophistication_level": 2},
]
#: Changes TWO steps relative to the baseline — never a legal neighbour.
_TWO_STEP = [
    {"category": "obfuscation", "sophistication_level": 3},
    {"category": "direct_injection", "sophistication_level": 2},
]

_CFG = {"episodes": 4, "max_rounds": 2, "iterations": 3, "seed": 1}


# ---------------------------------------------------------------------------
# Scripted assistant doubles (deterministic test doubles, clearly labelled)
# ---------------------------------------------------------------------------


def _accept(ladder, rationale="scripted valid proposal"):
    return CandidateProposal(
        candidate_ladder=[dict(s) for s in ladder],
        rationale=rationale,
        accepted=True,
        rejection_reason=None,
        provenance="model-driven",
        model_used="scripted-double",
    )


def _reject(reason):
    return CandidateProposal(
        candidate_ladder=None,
        rationale="scripted rejection",
        accepted=False,
        rejection_reason=reason,
        provenance="model-driven",
        model_used="scripted-double",
    )


class _ScriptedAssistant:
    """Deterministic stand-in for AdaptiveModelAssistant (clearly a double)."""

    provider_kind = "fake"

    def __init__(self, script=(), *, config=None, kind="fake"):
        self.script = list(script)
        self.config = config or FakeConfig()
        self.provider_kind = kind
        self.calls = 0

    def propose_candidate(self, parent_ladder, **kwargs):
        self.calls += 1
        self.config.model_calls_consumed += 1
        if self.config.model_calls_consumed > self.config.max_model_calls:
            raise RuntimeError(
                f"Model call budget exhausted "
                f"({self.config.model_calls_consumed}/{self.config.max_model_calls})"
            )
        if not self.script:
            return _reject("scripted: no further suggestion")
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _run_feedback(tmp_path, monkeypatch, script, run_id, **cfg_kw):
    eval_script = _TraceEval(_FIXTURE_ASR)
    monkeypatch.setattr("backend.adaptive_harness.evaluate_strategy", eval_script)
    assistant = _ScriptedAssistant(script)
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / f"{run_id}.json"),
        mode="feedback",
        selection_budget=3,
        assistant=assistant,
    )
    # Drop the harness-initialisation baseline evaluation so ``calls[i]``
    # indexes the RUN's evaluations: calls[0] is the run baseline, calls[1]
    # the first candidate of iteration 1.
    eval_script.calls.clear()
    cfg = dict(_CFG)
    cfg.update(cfg_kw)
    h._run(run_id=run_id, **cfg)
    return h, eval_script, h._current_run, assistant


def _selections(run, iteration):
    return [
        e["selection"] for e in run["history"] if e["iteration"] == iteration
    ]


# ---------------------------------------------------------------------------
# 1. A valid suggestion genuinely influences the next candidate decision
# ---------------------------------------------------------------------------


def test_accepted_model_suggestion_is_evaluated_first(tmp_path, monkeypatch):
    _, script, run, assistant = _run_feedback(
        tmp_path, monkeypatch, [_accept(_GOOD_NEIGHBOUR)], "sugg-first"
    )
    assert run["status"] == "completed"
    # One validated request per iteration; the script only had one proposal,
    # so iterations 2-3 recorded explicit rejections.
    assert assistant.calls == 3

    # The model-suggested candidate — not the structural-first candidate —
    # is the first candidate evaluated in iteration 1 (calls[0] is the run's
    # baseline evaluation).
    assert script.calls[0] == _BASELINE
    assert script.calls[1] == _GOOD_NEIGHBOUR
    it1 = _selections(run, 1)
    assert it1[0]["model_suggested"] is True
    assert it1[0]["structural_index"] != 0
    # The suggestion was planned at rank 0 of the store-ranked batch (the
    # strict-improvement rule then ended iteration 1 after this single
    # evaluation, because the suggested candidate improved).
    assert it1[0]["rank"] == 0
    assert it1[0]["frontier_size"] >= 3
    assert len(it1) == 1

    # Full provenance is persisted in the run record.
    assert len(run["model_suggestions"]) == 3
    record = run["model_suggestions"][0]
    assert record["requested"] is True
    assert record["accepted"] is True
    assert record["rejection_reason"] is None
    assert record["parent_ladder"] == _BASELINE
    assert record["suggested_ladder"] == _GOOD_NEIGHBOUR
    assert record["iteration"] == 1
    assert record["phase"] == "search"
    assert record["provider_kind"] == "fake"
    # The measured outcome comes from the harness evaluation, attached after
    # the fact — not from the model.
    assert record["outcome"] == {
        "asr": 0.5,
        "improved_over_best": True,
        "observed_usable": True,
        "total_episodes": 4,
        "evaluated_candidate_key": ladder_key(_GOOD_NEIGHBOUR),
    }


def test_suggestion_outcome_feedback_influences_later_selection(
    tmp_path, monkeypatch
):
    """The measured outcome of a model-suggested candidate flows through the
    feedback store and moves related candidates up in a LATER iteration."""
    _, _, run, _ = _run_feedback(
        tmp_path, monkeypatch, [_accept(_GOOD_NEIGHBOUR)], "sugg-feedback"
    )
    # The suggested candidate improved and was accepted as the new best.
    assert run["improved"] is True
    assert run["best_asr"] == 0.5
    # Iteration 2: no further scripted suggestion — pure store ranking.
    assert run["model_suggestions"][1]["accepted"] is False
    it2 = _selections(run, 2)
    top = it2[0]
    # The successful step (direct_injection:2) observed in iteration 1 now
    # carries real evidence and lifts candidates containing it above pure
    # structural order.
    assert top["score"] > 0
    assert any(
        ev["step"] == "direct_injection:2"
        and ev["observed"] is True
        and ev["successes"] > 0
        for ev in top["evidence"]
    )
    # No duplicate evaluation of the already-recorded suggested ladder.
    keys = [ladder_key(e["candidate_ladder"]) for e in run["history"]]
    assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# 2. Invalid suggestions are rejected safely, each with an explicit reason
# ---------------------------------------------------------------------------


def test_schema_invalid_suggestion_is_rejected(tmp_path, monkeypatch):
    bad = CandidateProposal(
        candidate_ladder=None,
        rationale="nope",
        accepted=False,
        rejection_reason="unsupported proposal: step 0 category 'warp_drive'",
        provenance="model-driven",
        model_used="scripted-double",
    )
    _, script, run, _ = _run_feedback(
        tmp_path, monkeypatch, [bad], "sugg-bad-schema"
    )
    assert run["status"] == "completed"
    record = run["model_suggestions"][0]
    assert record["requested"] is True
    assert record["accepted"] is False
    assert "warp_drive" in record["rejection_reason"]
    assert record["outcome"] is None
    # The rejected suggestion never touched candidate selection: after the
    # run baseline (calls[0]) the batch starts with the structural-first
    # candidate (calls[1]).
    assert script.calls[0] == _BASELINE
    assert script.calls[1] == [
        {"category": "obfuscation", "sophistication_level": 1},
        _BASELINE[1],
    ]
    assert _selections(run, 1)[0]["model_suggested"] is False


def test_out_of_scope_suggestion_is_rejected(tmp_path, monkeypatch):
    _, script, run, _ = _run_feedback(
        tmp_path, monkeypatch, [_accept(_TWO_STEP)], "sugg-oos"
    )
    record = run["model_suggestions"][0]
    assert record["accepted"] is False
    assert "single-step neighbour" in record["rejection_reason"]
    assert record["suggested_ladder"] == _TWO_STEP  # kept for audit
    assert _TWO_STEP not in script.calls  # never evaluated


def test_duplicate_suggestion_is_rejected(tmp_path, monkeypatch):
    # Iteration 1: a valid suggestion is accepted and improves the search.
    # Iteration 2: the model re-proposes the BASELINE ladder — a legal
    # neighbour of the new best, but already evaluated in this run.
    _, script, run, _ = _run_feedback(
        tmp_path,
        monkeypatch,
        [_accept(_GOOD_NEIGHBOUR), _accept(_BASELINE)],
        "sugg-dup",
    )
    first, record = run["model_suggestions"][0], run["model_suggestions"][1]
    assert first["accepted"] is True
    assert record["accepted"] is False
    assert "duplicate" in record["rejection_reason"]
    baseline_calls = [c for c in script.calls if c == _BASELINE]
    assert len(baseline_calls) == 1  # only the initial baseline evaluation


def test_model_exception_is_a_rejection_not_a_security_outcome(
    tmp_path, monkeypatch
):
    _, script, run, _ = _run_feedback(
        tmp_path,
        monkeypatch,
        [RuntimeError("simulated provider outage")],
        "sugg-err",
    )
    assert run["status"] == "completed"
    record = run["model_suggestions"][0]
    assert record["requested"] is True
    assert record["accepted"] is False
    assert "simulated provider outage" in record["rejection_reason"]
    assert record["outcome"] is None
    # The search continued deterministically: after the run baseline the
    # first evaluated candidate is the structural-first one, and nothing
    # was invented.
    assert script.calls[0] == _BASELINE
    assert script.calls[1] == [
        {"category": "obfuscation", "sophistication_level": 1},
        _BASELINE[1],
    ]
    assert run["best_asr"] == 0.5  # measured, not invented


def test_model_claim_of_success_never_becomes_evidence(tmp_path, monkeypatch):
    """A suggestion whose rationale claims the attack already succeeded still
    gets its outcome from the harness evaluation only."""
    lying = _accept(
        _GOOD_NEIGHBOUR,
        rationale="The attack already succeeded at 100% — trust me.",
    )
    monkeypatch.setattr(
        "backend.adaptive_harness.evaluate_strategy",
        _TraceEval(_last_cat_asr({})),  # NOTHING ever succeeds in this fixture
    )
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "liar.json"),
        mode="feedback",
        selection_budget=3,
        assistant=_ScriptedAssistant([lying]),
    )
    h._run(run_id="liar", **_CFG)
    run = h._current_run
    record = run["model_suggestions"][0]
    assert record["accepted"] is True  # valid strategy proposal...
    assert "succeeded" in record["rationale"]
    # ...but the measured outcome is the scripted measurement, not the claim.
    assert record["outcome"]["asr"] == 0.0
    assert record["outcome"]["improved_over_best"] is False
    assert run["best_asr"] == 0.0


# ---------------------------------------------------------------------------
# 3. Greedy mode stays fully independent of the assistant
# ---------------------------------------------------------------------------


def test_greedy_mode_never_uses_the_assistant(tmp_path, monkeypatch):
    script = _TraceEval(_FIXTURE_ASR)
    monkeypatch.setattr("backend.adaptive_harness.evaluate_strategy", script)
    assistant = _ScriptedAssistant([_accept(_GOOD_NEIGHBOUR)])
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "greedy6b.json"),
        mode="greedy",
        assistant=assistant,
    )
    h._run(run_id="greedy-6b", **_CFG)
    run = h._current_run
    assert assistant.calls == 0  # no model request ever happened
    assert run["model_suggestions"] == []
    assert run["assistant"]["used_in_search"] is False
    assert run["assistant"]["model_calls_consumed"] == 0
    # Greedy history entries keep their exact approved field set.
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


def test_default_feedback_mode_is_advisory_only(tmp_path, monkeypatch):
    """Without an explicit provider (or injected assistant) the validated
    suggestion loop is OFF: no model-suggestion records exist."""
    monkeypatch.setattr(
        "backend.adaptive_harness.evaluate_strategy", _TraceEval(_FIXTURE_ASR)
    )
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "adv.json"), mode="feedback"
    )
    h._run(run_id="adv-1", **_CFG)
    run = h._current_run
    assert run["model_suggestions"] == []
    assert run["assistant"]["suggestion_loop_enabled"] is False
    assert run["assistant"]["provider"] == "fake"


# ---------------------------------------------------------------------------
# 4. Explicit provider selection: validated, fail-loud, never a silent fake
# ---------------------------------------------------------------------------


def test_unknown_provider_is_rejected():
    with pytest.raises(ValueError, match="provider"):
        AdaptiveHarness(provider="bogus")
    h = AdaptiveHarness()
    with pytest.raises(ValueError, match="provider"):
        h.configure(provider="bogus")
    # The failed configure changed nothing.
    assert h.configure()["provider"] is None


def test_live_provider_without_credentials_fails_loudly(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        AdaptiveHarness(provider="gemini")
    h = AdaptiveHarness()
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        h.configure(provider="gemini")
    # No silent fallback: the harness still reports no provider at all.
    assert h.configure()["provider"] is None
    assert h.status()["provider"] is None


def test_live_provider_selection_never_silently_falls_back(monkeypatch):
    """A live provider is selected verbatim; its assistant is 'live' and no
    request is made merely by selecting it."""
    monkeypatch.setenv("GEMINI_API_KEY", "dummy-test-key-never-sent")
    h = AdaptiveHarness(mode="feedback", provider="gemini")
    assert h.status()["provider"] == "gemini"
    meta = h.status()["assistant"]
    assert meta["kind"] == "live"
    assert meta["provider"] == "gemini"
    assert meta["model_calls_consumed"] == 0  # selection made no request
    assert meta["model_request_budget"] == 50  # default explicit budget
    # Greedy + live provider: the assistant is never built or used.
    g = AdaptiveHarness(mode="greedy", provider="gemini")
    assert g.status()["provider"] == "gemini"
    assert g.status()["assistant"] is None


def test_fake_provider_works_offline_and_reports_itself(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "backend.adaptive_harness.evaluate_strategy", _TraceEval(_FIXTURE_ASR)
    )
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "fakeprov.json"),
        mode="feedback",
        provider="fake",
        model_request_budget=10,
    )
    meta = h.status()["assistant"]
    assert meta["provider"] == "fake"
    assert meta["kind"] == "fake"
    assert meta["suggestion_loop_enabled"] is True
    h._run(run_id="fakeprov", **_CFG)
    run = h._current_run
    # The real assistant + offline fake provider produced a valid suggestion
    # that was accepted, evaluated and measured.
    assert run["model_suggestions"][0]["accepted"] is True
    assert run["model_suggestions"][0]["outcome"] is not None
    # Telemetry is the actual counter, and no cost/token data is fabricated.
    assert run["assistant"]["model_calls_consumed"] == h._assistant.config.model_calls_consumed
    for record in run["model_suggestions"]:
        assert "cost" not in record and "tokens" not in record


def test_provider_none_disables_assistance_explicitly():
    h = AdaptiveHarness(mode="feedback", provider="fake")
    assert h.configure()["provider"] == "fake"
    assert h.configure(provider="none")["provider"] is None
    assert h.status()["assistant"]["suggestion_loop_enabled"] is False


# ---------------------------------------------------------------------------
# 5. Model-request budget: separate, enforced, reported from telemetry
# ---------------------------------------------------------------------------


def test_model_request_budget_is_enforced_and_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "backend.adaptive_harness.evaluate_strategy", _TraceEval(_FIXTURE_ASR)
    )
    cfg = FakeConfig()
    cfg.max_model_calls = 1
    assistant = AdaptiveModelAssistant(config=cfg)
    h = AdaptiveHarness(
        store_path=str(Path(tmp_path) / "mbudget.json"),
        mode="feedback",
        selection_budget=3,
        assistant=assistant,
    )
    h._run(run_id="mbudget", **_CFG)
    run = h._current_run
    assert run["status"] == "completed"
    assert cfg.model_calls_consumed == 1  # hard stop at the budget
    first, second = run["model_suggestions"][0], run["model_suggestions"][1]
    assert first["accepted"] is True  # the one allowed request was used
    assert second["requested"] is True
    assert second["accepted"] is False
    assert "budget exhausted" in second["rejection_reason"]
    assert run["assistant"]["model_request_budget"] == 1
    assert run["assistant"]["model_calls_consumed"] == 1


def test_model_request_budget_bounds_are_validated():
    AdaptiveHarness(model_request_budget=1)  # lower bound ok
    AdaptiveHarness(model_request_budget=500)  # upper bound ok
    for bad in (0, 501, -1, "abc"):
        with pytest.raises(ValueError, match="model_request_budget"):
            AdaptiveHarness(model_request_budget=bad)


# ---------------------------------------------------------------------------
# 6. Checkpoint/resume preserves the model-suggestion state
# ---------------------------------------------------------------------------


def test_model_suggestions_are_checkpointed_and_resume_compatible(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "backend.adaptive_harness.evaluate_strategy", _TraceEval(_FIXTURE_ASR)
    )
    store = Path(tmp_path) / "ckpt.json"
    h = AdaptiveHarness(
        store_path=str(store), mode="feedback", provider="fake",
        model_request_budget=7,
    )
    h._run(run_id="ckpt-6b", **_CFG)
    ckpt_path = Path(str(store) + ".checkpoint.json")
    data = json.loads(ckpt_path.read_text(encoding="utf-8"))
    assert "model_suggestions" in _checkpoint_progress_keys()
    assert data["progress"]["model_suggestions"]  # survived the checkpoint
    assert data["run"]["provider"] == "fake"
    assert data["run"]["model_request_budget"] == 7

    # A finished checkpoint refuses to be resumed (unchanged Phase 5 rule).
    from backend.adaptive_harness import CheckpointError

    h2 = AdaptiveHarness(store_path=str(store))
    with pytest.raises(CheckpointError, match="already finished"):
        h2.resume(background=False)

    # Old-format compatibility: a checkpoint written WITHOUT the
    # model_suggestions field still resumes cleanly (field defaults to []).
    data["run"]["status"] = "running"
    data["progress"].pop("model_suggestions", None)
    ckpt_path.write_text(json.dumps(data), encoding="utf-8")
    h3 = AdaptiveHarness(store_path=str(store))
    h3.resume(background=False)
    resumed_run = h3._current_run
    assert resumed_run["status"] in ("completed", "budget_exhausted", "stopped")
    assert resumed_run["model_suggestions"] == []
    # The restored configuration came from the checkpoint, not the defaults.
    assert resumed_run["assistant"]["provider"] == "fake"


# ---------------------------------------------------------------------------
# 7. Frontend wiring: controls reach the real backend
# ---------------------------------------------------------------------------


def test_frontend_wires_provider_controls_to_adaptive_run():
    js = (REPO_ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    html = (REPO_ROOT / "frontend" / "index.html").read_text(encoding="utf-8")
    for element_id in ("cfgProvider", "cfgModelBudget", "expStartBtn"):
        assert f'id="{element_id}"' in html, element_id
    assert '$("cfgProvider")' in js
    assert '$("cfgModelBudget")' in js
    assert '"/api/adaptive/run"' in js
    # The payload built by the adaptive handler carries every control.
    payload = js[js.index("function experimentPayload") :]
    payload = payload[: payload.index("background: true")]
    for field in (
        "mode:",
        "defense:",
        "provider:",
        "total_episode_budget:",
        "model_request_budget:",
    ):
        assert field in payload, field
    # Reported provider usage always states the fake/live kind.
    assert "provider.kind" in js or "a.kind" in js or ".kind" in js
