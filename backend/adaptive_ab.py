"""Reproducible A/B comparison: greedy hill climbing vs feedback-guided search.

Phase 4 evaluation protocol (see ``docs/ADAPTIVE_SEARCH.md`` §2.8). Both arms
run through the *same* :class:`backend.adaptive_harness.AdaptiveHarness` code
paths — the only difference is the ``mode`` (candidate selection):

* ``greedy``    — the untouched baseline: every neighbour, structural order.
* ``feedback``  — neighbours ranked from statistics accumulated by previous
  evaluations in the same run, evaluated within ``selection_budget``.

Everything that can be held constant *is* held constant and asserted: the
starting (baseline) ladder, defense, episodes, max_rounds, iterations, seed,
and the ``seed + iteration`` evaluation-seed policy. Each arm is run twice and
the trajectories are fingerprint-compared for reproducibility.

Instrumentation: :func:`compare_search_modes` temporarily wraps the module-level
``evaluate_strategy`` in :mod:`backend.adaptive_harness` (restored in a
``finally``) to count every evaluation — total episodes consumed, incomplete
evaluations (fewer episodes than requested), and technical failures. This is
measurement only; it does not alter any evaluation result. Run the comparison
offline (it is synchronous and takes over the module global for its duration).

Honesty: this compares two *deterministic local simulations*. It is evidence
about the search mechanism on this fixture, not about real-world attack
effectiveness, not statistically significant, and not a live red-team result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Self

from backend import adaptive_harness as _h
from backend.adaptive_harness import (
    DEFAULT_SELECTION_BUDGET,
    DEFENSE_CHOICES,
    SEARCH_MODES,
    AdaptiveHarness,
)

#: Every field the two arms are compared on with an identical value.
HELD_CONSTANT = (
    "episodes",
    "max_rounds",
    "iterations",
    "seed",
    "defense",
    "starting_ladder",
)

_ARMS = ("greedy", "feedback")


class _EvaluationCounter:
    """Counts and records every ``evaluate_strategy`` call (measurement only)."""

    def __init__(self) -> None:
        self._real = None
        self.evaluations: list[dict[str, Any]] = []

    def __enter__(self) -> Self:
        self._real = _h.evaluate_strategy
        _h.evaluate_strategy = self  # type: ignore[assignment]
        return self

    def __exit__(self, *exc) -> None:
        _h.evaluate_strategy = self._real  # type: ignore[assignment]
        self._real = None

    def __call__(self, ladder, **kwargs):
        ev = self._real(ladder, **kwargs)
        self.evaluations.append(
            {
                "strategy_id": ev.strategy_id,
                "ladder": [dict(s) for s in ev.ladder],
                "asr": ev.asr,
                "requested_episodes": int(kwargs.get("episodes") or 0),
                "total_episodes": int(ev.total_episodes),
                "outcomes": dict(ev.outcomes),
                "utility_score": ev.utility_score,
            }
        )
        return ev


def _run_arm(
    mode: str,
    *,
    episodes: int,
    max_rounds: int,
    iterations: int,
    seed: int,
    defense: str,
    selection_budget: int,
    work_dir: Path,
    rep: int,
) -> dict[str, Any]:
    """Run one arm once and return its recorded, comparable metrics."""
    if mode not in SEARCH_MODES:
        raise ValueError(f"unknown mode {mode!r}; choices are {SEARCH_MODES}")
    if defense not in DEFENSE_CHOICES:
        raise ValueError(f"unknown defense {defense!r}; choices are {DEFENSE_CHOICES}")

    work_dir.mkdir(parents=True, exist_ok=True)
    store = work_dir / f"ab_{mode}_rep{rep}.json"
    for stale in (store, Path(str(store) + ".feedback.json")):
        stale.unlink(missing_ok=True)

    harness = AdaptiveHarness(
        store_path=str(store),
        mode=mode,
        defense=defense,
        selection_budget=selection_budget,
    )
    with _EvaluationCounter() as counter:
        harness.start(
            episodes=episodes,
            max_rounds=max_rounds,
            iterations=iterations,
            seed=seed,
            background=False,
        )
    run = dict(harness._current_run or {})
    status = harness.status()
    history = list(run.get("history") or [])

    candidate = next(
        (c for c in status["candidates"] if c["candidate_id"] == run.get("candidate_id")),
        None,
    )
    evaluations = counter.evaluations
    candidate_evals = [
        e
        for e in evaluations
        if not e["strategy_id"].endswith("-base")
        and not e["strategy_id"].endswith("-best")
    ]
    incomplete = [
        e
        for e in candidate_evals
        if e["total_episodes"] < e["requested_episodes"]
    ]
    technical_failure_episodes = sum(
        int(e["outcomes"].get("technical_fail", 0)) for e in candidate_evals
    )
    episodes_consumed = sum(e["total_episodes"] for e in evaluations)
    ordering = [
        {
            "iteration": e.get("iteration"),
            "ladder_key": _ladder_key(e["candidate_ladder"]),
        }
        for e in history
        if e.get("candidate_ladder")
    ]

    return {
        "mode": mode,
        "config": {
            "episodes": episodes,
            "max_rounds": max_rounds,
            "iterations": iterations,
            "seed": seed,
            # Attack-only campaign: "none" is what actually ran.
            "defense": "none",
            "requested_defense": defense,
            "selection_budget": selection_budget if mode == "feedback" else None,
        },
        "status": run.get("status"),
        "selected_strategy_asr": (candidate or {}).get("asr"),
        "selected_ladder": (candidate or {}).get("ladder"),
        "best_asr": run.get("best_asr"),
        "baseline_asr": run.get("baseline_asr"),
        "final_utility": ((candidate or {}).get("evaluation") or {}).get("utility_score"),
        "gate": run.get("gate"),
        "promoted": bool((run.get("gate") or {}).get("passed")),
        "iterations_run": run.get("iteration"),
        "improved": run.get("improved"),
        "converged": run.get("converged"),
        "candidate_evaluations": len(candidate_evals),
        "unique_candidates_evaluated": run.get("unique_candidates_evaluated"),
        "episodes_consumed": episodes_consumed,
        "incomplete_evaluations": len(incomplete),
        "technical_failure_episodes": technical_failure_episodes,
        "technical_failure_rate": (
            round(technical_failure_episodes / episodes_consumed, 6)
            if episodes_consumed
            else None
        ),
        "ordering": ordering,
        "ordering_keys": [o["ladder_key"] for o in ordering],
        "fingerprint": {
            "best_asr": run.get("best_asr"),
            "improved": run.get("improved"),
            "converged": run.get("converged"),
            "status": run.get("status"),
            "selected_ladder": (candidate or {}).get("ladder"),
            "gate_passed": bool((run.get("gate") or {}).get("passed")),
            "trajectory": [
                (e.get("iteration"), _ladder_key(e["candidate_ladder"]), e.get("asr"))
                for e in history
                if e.get("candidate_ladder")
            ],
        },
        "feedback_summary": run.get("feedback"),
    }


def _ladder_key(ladder: list[dict[str, Any]]) -> str:
    from backend.search_feedback import ladder_key

    return ladder_key(ladder)


def compare_search_modes(
    work_dir: str | Path,
    *,
    episodes: int = 4,
    max_rounds: int = 2,
    iterations: int = 3,
    seed: int = 20261024,
    defense: str = "marker",
    selection_budget: int = DEFAULT_SELECTION_BUDGET,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Run both arms twice under an identical configuration and compare.

    Returns a JSON-serializable record containing, per arm: selected-strategy
    ASR, candidate evaluations and unique candidates consumed, episodes
    consumed, incomplete/technical-failure counts, final candidate utility,
    gate verdict, and the candidate ordering actually followed. Plus:
    ``held_constant``/``cannot_hold_constant`` explanations, a
    ``reproducible`` flag per arm (two identical runs), and
    ``feedback_changed_ordering`` (does the feedback arm follow a different
    candidate order than the greedy arm?).

    ``out_path`` optionally persists the full record as JSON.
    """
    work_dir = Path(work_dir)
    arms: dict[str, Any] = {}
    for mode in _ARMS:
        first = _run_arm(
            mode,
            episodes=episodes,
            max_rounds=max_rounds,
            iterations=iterations,
            seed=seed,
            defense=defense,
            selection_budget=selection_budget,
            work_dir=work_dir,
            rep=0,
        )
        second = _run_arm(
            mode,
            episodes=episodes,
            max_rounds=max_rounds,
            iterations=iterations,
            seed=seed,
            defense=defense,
            selection_budget=selection_budget,
            work_dir=work_dir,
            rep=1,
        )
        arms[mode] = {
            "result": first,
            "repeat_fingerprint": second["fingerprint"],
            "reproducible": first["fingerprint"] == second["fingerprint"],
        }

    greedy_keys = arms["greedy"]["result"]["ordering_keys"]
    feedback_keys = arms["feedback"]["result"]["ordering_keys"]
    record: dict[str, Any] = {
        "protocol": "phase4-ab-v1",
        "config": {
            "episodes": episodes,
            "max_rounds": max_rounds,
            "iterations": iterations,
            "seed": seed,
            # Both arms are attack-only campaigns: no defense runs, so the
            # recorded defense is "none" and the caller's label is kept only as
            # the (unused) request.
            "defense": "none",
            "requested_defense": defense,
            "selection_budget": selection_budget,
            "arms": list(_ARMS),
        },
        "held_constant": list(HELD_CONSTANT),
        "cannot_hold_constant": [
            (
                "The two arms consume different numbers of evaluations, so "
                "they exercise different numbers of episodes (cost is not "
                "equal and is reported per arm rather than normalized away)."
            ),
            (
                "Greedy may re-evaluate a ladder it has already scored; "
                "feedback skips recorded ladders, so the sets of evaluated "
                "ladders differ by design."
            ),
            (
                "selection_budget only constrains the feedback arm; the "
                "greedy arm evaluates its whole neighbourhood by construction."
            ),
            (
                "Candidate ids and timestamps are random/unique per run and "
                "are excluded from the reproducibility fingerprint."
            ),
        ],
        "arms": arms,
        "feedback_changed_ordering": greedy_keys != feedback_keys,
        "results_are_recorded": True,
        "evidence_class": (
            "deterministic local simulation (fixed seeds, offline stand-in "
            "target/attacker, local defenses) — mechanism evidence only, not a "
            "real-world attack result and not a statistical significance claim"
        ),
    }
    if out_path is not None:
        out = Path(out_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    return record


if __name__ == "__main__":  # pragma: no cover - manual experiment entry point
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", default="results/adaptive_ab")
    parser.add_argument("--out", default="results/adaptive_ab/ab_results.json")
    parser.add_argument("--episodes", type=int, default=4)
    parser.add_argument("--max-rounds", type=int, default=2)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--seed", type=int, default=20261024)
    parser.add_argument("--defense", default="marker", choices=DEFENSE_CHOICES)
    parser.add_argument("--selection-budget", type=int, default=DEFAULT_SELECTION_BUDGET)
    args = parser.parse_args()
    result = compare_search_modes(
        args.work_dir,
        episodes=args.episodes,
        max_rounds=args.max_rounds,
        iterations=args.iterations,
        seed=args.seed,
        defense=args.defense,
        selection_budget=args.selection_budget,
        out_path=args.out,
    )
    for arm in _ARMS:
        r = result["arms"][arm]["result"]
        print(
            f"{arm:9s} asr={r['selected_strategy_asr']} "
            f"cands={r['candidate_evaluations']} "
            f"unique={r['unique_candidates_evaluated']} "
            f"eps={r['episodes_consumed']} "
            f"reproducible={result['arms'][arm]['reproducible']}"
        )
    print("ordering changed by feedback:", result["feedback_changed_ordering"])
    print("recorded:", args.out)