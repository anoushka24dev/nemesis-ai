"""Cross-candidate feedback store for the Phase 4 feedback-guided search.

Scope — what this adapts
------------------------
Only the **candidate ordering** of the strategy search in
:mod:`backend.adaptive_harness` (``mode="feedback"``). It never changes the
acceptance rule (strict measured-ASR improvement) or the promotion gate, it
never touches Gmail/LLM/provider code, and it is *not* used at all by the
greedy baseline mode.

Evidence — what is retained between candidate evaluations
---------------------------------------------------------
Structured, validated episode outcomes only:

* ``AttackOutcome`` enum values produced by the real Controller + Diagnoser
  (rule-based stage A offline) — the entire evidence vocabulary. Raw
  model-generated explanations, free-text diagnostics, and unstructured
  strings are never ingested: unknown outcome keys are rejected with
  :class:`FeedbackStoreError`.
* Per-episode trace from ``StrategyEvaluation.to_dict()["episode_trace"]``:
  the episode's final outcome and the exact ``(category, sophistication)``
  steps it exercised (read from the real ``AttackPayload`` objects). By the
  Controller's stop-on-success / round-budget construction the episode's final
  outcome equals the outcome of its **last exercised round**, so each episode
  attributes its outcome to that *deciding* step and counts as an *exposure*
  for every step it exercised.
* Ladder-level record per candidate: measured ASR, requested vs actual episode
  counts, technical failures, and whether the evaluation was usable evidence.

Per-step statistics are **correlational** (which steps co-occurred with
decisive outcomes), not causal attribution.

Ranking rule — how the next neighbour is chosen
-----------------------------------------------
Deterministic, count-based, interpretable (no RL, no embeddings, no invented
confidence numbers)::

    p           = global success rate over known decisions so far (0.0 if none)
    estimate(k) = (successes(k) + ALPHA * p) / (decided(k) + ALPHA)
    score(C)    = mean over the steps of candidate C of estimate(k)
    order       = sort by (-score, structural_index)

``ALPHA`` is a documented smoothing pseudo-count (shrinkage toward the
run-wide rate) — **not** a confidence interval, significance test, or
statistical guarantee. A step with zero observations scores exactly ``p``, so
a cold store ranks candidates exactly like the structural
``neighbours()`` order; such steps are flagged ``observed: false`` in the
recorded evidence. Ties always resolve to structural order, never to hash or
insertion order.

Handling of bad evidence
------------------------
Evaluations that are missing (no outcomes / no trace / ``asr is None``),
incomplete (fewer episodes than requested), technically failed, or carrying
invalid data are recorded as **unusable** and contribute *nothing* to the
ranking statistics — a partial or broken run can never create a favorable
learning signal. Structurally invalid data (wrong types, unknown outcome
vocabulary, tampered ladder keys) raises :class:`FeedbackStoreError` instead
of being silently absorbed.

Persistence — versioning, validation, reset
-------------------------------------------
* One JSON file next to the harness store (``<store>.feedback.json``); purely
  in-memory when no path is configured.
* ``schema_version: 1``; state is bound to the ``run_id`` **and** a config
  fingerprint (mode, episodes, max_rounds, iterations, seed, defense,
  selection_budget). Independent runs therefore never share statistics;
  within one run the store is *never* reset between candidates.
* On open: missing file -> fresh; different run/config -> fresh with a recorded
  reset reason; corrupt / inconsistent / wrong-schema state -> fresh with a
  recorded ``invalid-state`` reason (corrupt state can never bias a search).
* Writes are atomic (tmp file + ``replace``) and happen after every
  observation, so an interrupted run leaves a consistent store.

CLI-less by design: the store is driven by the harness; ``summary()`` is the
read-only surface exposed through ``AdaptiveHarness.status()``.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any

from adaptive_agent_eval.models import AttackOutcome

#: Store format version. A load with a different version is treated as
#: invalid state (fresh start with a recorded reset reason).
SCHEMA_VERSION = 1

#: Smoothing pseudo-count: how much a step's estimate is shrunk toward the
#: run-wide prior rate. Documented shrinkage, NOT a confidence claim.
ALPHA = 4.0

#: Bounded audit trail (mirrors the harness history cap).
MAX_RECORDED_SELECTIONS = 40
MAX_RECORDED_CANDIDATES = 2000

#: The entire evidence vocabulary: structured Diagnoser/Controller outcomes.
OUTCOME_VOCAB: frozenset[str] = frozenset(o.value for o in AttackOutcome)

#: Outcomes that count toward the success-rate denominator at a step.
_KNOWN_DECIDED = frozenset({"success", "blocked", "ignored"})

#: Vocabulary value -> counter field name (the enum says ``success``, the
#: counters say ``successes``).
_OUTCOME_TO_COUNTER = {"success": "successes", "blocked": "blocked", "ignored": "ignored"}

_STEP_RE = re.compile(r"^[A-Za-z0-9_]+:[1-5]$")

#: Config fields bound to a store instance (a change forces a fresh store).
CONFIG_FIELDS = (
    "mode",
    "episodes",
    "max_rounds",
    "iterations",
    "seed",
    "defense",
    "selection_budget",
)

_STEP_COUNTERS = (
    "exposures",
    "decided",
    "successes",
    "blocked",
    "ignored",
    "unknown",
    "technical_fail",
)
_TOTAL_COUNTERS = (
    "episodes_decided",
    "known_decisions",
    "successes",
    "blocked",
    "ignored",
    "unknown",
    "technical_fail",
    "usable_evaluations",
    "unusable_evaluations",
)


class FeedbackStoreError(RuntimeError):
    """Invalid input, invalid persisted state, or a failed store write."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def ladder_key(ladder: list[dict[str, Any]]) -> str:
    """Stable 12-hex key for a ladder (same algorithm as the harness)."""
    blob = "|".join(f"{s['category']}:{s['sophistication_level']}" for s in ladder)
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def step_key(step: dict[str, Any]) -> str:
    """``"<category>:<sophistication_level>"`` — the statistics key."""
    return f"{step['category']}:{int(step['sophistication_level'])}"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_step(step: Any, where: str) -> dict[str, Any]:
    if not isinstance(step, dict):
        raise FeedbackStoreError(f"{where}: step is not an object")
    category = step.get("category")
    level = step.get("sophistication_level")
    if not isinstance(category, str) or not category:
        raise FeedbackStoreError(f"{where}: step category must be a non-empty string")
    if not _is_int(level) or not 1 <= level <= 5:
        raise FeedbackStoreError(f"{where}: sophistication_level must be an int in 1..5")
    if not _STEP_RE.match(step_key(step)):
        raise FeedbackStoreError(f"{where}: malformed step key {step_key(step)!r}")
    return {"category": category, "sophistication_level": level}


def _validate_ladder(ladder: Any, where: str) -> list[dict[str, Any]]:
    if not isinstance(ladder, list) or not ladder:
        raise FeedbackStoreError(f"{where}: ladder must be a non-empty list")
    return [_validate_step(s, where) for s in ladder]


# ---------------------------------------------------------------------------
# State construction and validation
# ---------------------------------------------------------------------------


def normalize_config(config: dict[str, Any]) -> dict[str, Any]:
    """Extract and coerce the config fingerprint fields (stable comparison)."""
    normalized: dict[str, Any] = {}
    for field in CONFIG_FIELDS:
        value = (config or {}).get(field)
        if field in ("episodes", "max_rounds", "iterations", "seed", "selection_budget"):
            if value is not None and not _is_int(value):
                raise FeedbackStoreError(f"config.{field} must be an int")
        elif not isinstance(value, str):
            raise FeedbackStoreError(f"config.{field} must be a string")
        normalized[field] = value
    return normalized


def _empty_state(run_id: str, config: dict[str, Any]) -> dict[str, Any]:
    now = _now()
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "config": dict(config),
        "created_at": now,
        "updated_at": now,
        "totals": {name: 0 for name in _TOTAL_COUNTERS},
        "step_stats": {},
        "candidates": {},
        "selections": [],
        "resets": [],
    }


def _validate_state(data: Any) -> dict[str, Any]:
    """Validate a persisted state. Raises FeedbackStoreError on any problem."""
    if not isinstance(data, dict):
        raise FeedbackStoreError("feedback store is not a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise FeedbackStoreError(
            f"unsupported schema_version {data.get('schema_version')!r} "
            f"(expected {SCHEMA_VERSION})"
        )
    if not isinstance(data.get("run_id"), str) or not data.get("run_id"):
        raise FeedbackStoreError("feedback store has no run_id")
    if not isinstance(data.get("config"), dict):
        raise FeedbackStoreError("feedback store has no config fingerprint")

    totals = data.get("totals")
    if not isinstance(totals, dict):
        raise FeedbackStoreError("feedback store has no totals block")
    for name in _TOTAL_COUNTERS:
        if not _is_int(totals.get(name)) or totals[name] < 0:
            raise FeedbackStoreError(f"totals.{name} must be a non-negative int")
    if totals["known_decisions"] != totals["successes"] + totals["blocked"] + totals["ignored"]:
        raise FeedbackStoreError("totals known_decisions inconsistent with outcome counts")
    if (
        totals["known_decisions"] + totals["unknown"] + totals["technical_fail"]
        != totals["episodes_decided"]
    ):
        raise FeedbackStoreError("totals episodes_decided inconsistent with outcome counts")

    step_stats = data.get("step_stats")
    if not isinstance(step_stats, dict):
        raise FeedbackStoreError("feedback store has no step_stats block")
    summed = {name: 0 for name in _TOTAL_COUNTERS}
    for key, counters in step_stats.items():
        if not isinstance(key, str) or not _STEP_RE.match(key):
            raise FeedbackStoreError(f"malformed step_stats key {key!r}")
        if not isinstance(counters, dict):
            raise FeedbackStoreError(f"step_stats[{key!r}] is not an object")
        for name in _STEP_COUNTERS:
            if not _is_int(counters.get(name)) or counters[name] < 0:
                raise FeedbackStoreError(f"step_stats[{key!r}].{name} must be a non-negative int")
        if counters["decided"] != counters["successes"] + counters["blocked"] + counters["ignored"]:
            raise FeedbackStoreError(f"step_stats[{key!r}] decided inconsistent with outcomes")
        summed["episodes_decided"] += (
            counters["decided"] + counters["unknown"] + counters["technical_fail"]
        )
        summed["known_decisions"] += counters["decided"]
        summed["successes"] += counters["successes"]
        summed["blocked"] += counters["blocked"]
        summed["ignored"] += counters["ignored"]
        summed["unknown"] += counters["unknown"]
        summed["technical_fail"] += counters["technical_fail"]
    summed["usable_evaluations"] = totals["usable_evaluations"]
    summed["unusable_evaluations"] = totals["unusable_evaluations"]
    for name in _TOTAL_COUNTERS:
        if summed[name] != totals[name]:
            raise FeedbackStoreError(
                f"totals.{name} ({totals[name]}) does not match step_stats sum ({summed[name]})"
            )

    candidates = data.get("candidates")
    if not isinstance(candidates, dict):
        raise FeedbackStoreError("feedback store has no candidates block")
    for key, record in candidates.items():
        if not isinstance(key, str) or not isinstance(record, dict):
            raise FeedbackStoreError("candidate record is malformed")
        ladder = _validate_ladder(record.get("ladder"), f"candidates[{key!r}]")
        if ladder_key(ladder) != key:
            raise FeedbackStoreError(
                f"candidate key {key!r} does not match its ladder (tampered or corrupt state)"
            )
        asr = record.get("asr")
        if asr is not None and not _is_number(asr):
            raise FeedbackStoreError(f"candidates[{key!r}].asr must be a number or null")
        if not _is_bool(record.get("usable")):
            raise FeedbackStoreError(f"candidates[{key!r}].usable must be a bool")
        if not isinstance(record.get("reason"), str):
            raise FeedbackStoreError(f"candidates[{key!r}].reason must be a string")
        if not _is_int(record.get("requested_episodes")) or not _is_int(
            record.get("total_episodes")
        ):
            raise FeedbackStoreError(f"candidates[{key!r}] episode counts must be ints")

    selections = data.get("selections")
    if not isinstance(selections, list) or not all(isinstance(s, dict) for s in selections):
        raise FeedbackStoreError("feedback store selections block is malformed")
    resets = data.get("resets")
    if not isinstance(resets, list) or not all(isinstance(r, dict) for r in resets):
        raise FeedbackStoreError("feedback store resets block is malformed")
    return data


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------


class FeedbackStore:
    """Per-run outcome statistics + deterministic candidate ranking."""

    def __init__(
        self,
        state: dict[str, Any],
        *,
        path: Path | None = None,
        origin: str = "fresh:new-store",
    ) -> None:
        self._state = state
        self._path = path
        #: How this instance came to exist: ``reused`` or ``fresh:<reason>``.
        self.origin = origin

    # -- lifecycle ---------------------------------------------------------

    @classmethod
    def open(
        cls,
        path: str | Path | None,
        *,
        run_id: str,
        config: dict[str, Any],
    ) -> FeedbackStore:
        """Load the store for this run, or start a fresh one.

        Fresh (with the reason recorded in ``resets``) when: the file is
        missing (``new-store``), the run_id differs (``new-run``), the config
        fingerprint differs (``config-changed``), or the state is
        unreadable/inconsistent (``invalid-state``). Corrupt state is
        overwritten with a clean empty state so it can never bias a search.
        """
        if not run_id or not isinstance(run_id, str):
            raise FeedbackStoreError("run_id must be a non-empty string")
        cfg = normalize_config(config)
        p = Path(path) if path else None

        if p is None or not p.exists():
            store = cls(_empty_state(run_id, cfg), path=p, origin="fresh:new-store")
            store.save()
            return store

        reason: str | None = None
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            data = _validate_state(raw)
            if data["run_id"] != run_id:
                reason = f"new-run (store bound to run {data['run_id']})"
            elif data["config"] != cfg:
                reason = "config-changed (store bound to a different configuration)"
            else:
                store = cls(data, path=p, origin="reused")
                return store
        except FeedbackStoreError as exc:
            reason = f"invalid-state ({exc})"
        except (OSError, json.JSONDecodeError) as exc:
            reason = f"invalid-state (unreadable: {exc})"

        state = _empty_state(run_id, cfg)
        state["resets"].append({"at": _now(), "reason": reason})
        store = cls(state, path=p, origin=f"fresh:{reason}")
        store.save()
        return store

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def run_id(self) -> str:
        return self._state["run_id"]

    @property
    def state(self) -> dict[str, Any]:
        """The raw state (read-mostly; used for audits and tests)."""
        return self._state

    def save(self) -> None:
        """Atomic write (tmp file + replace). Raises on IO failure."""
        if self._path is None:
            return
        self._state["updated_at"] = _now()
        payload = json.dumps(self._state, indent=2, ensure_ascii=False)
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(payload, encoding="utf-8")
            tmp.replace(self._path)
        except OSError as exc:
            raise FeedbackStoreError(
                f"failed to persist feedback store to {self._path}: {exc}"
            ) from exc

    # -- recording evidence ------------------------------------------------

    def observe(
        self,
        evaluation: dict[str, Any],
        *,
        ladder: list[dict[str, Any]],
        iteration: int,
        requested_episodes: int,
    ) -> dict[str, Any]:
        """Record one candidate evaluation.

        Structurally invalid evidence raises :class:`FeedbackStoreError`.
        Valid-but-unusable evidence (missing outcomes/trace/asr, incomplete,
        technical failures) is recorded without contributing any statistics.
        Returns ``{"key", "usable", "reason", "attributed_steps"}``.
        """
        steps = _validate_ladder(ladder, "observe")
        if not isinstance(evaluation, dict):
            raise FeedbackStoreError("evaluation must be a dict (StrategyEvaluation.to_dict())")
        if not _is_int(iteration) or iteration < 0:
            raise FeedbackStoreError("iteration must be a non-negative int")
        if not _is_int(requested_episodes) or requested_episodes < 0:
            raise FeedbackStoreError("requested_episodes must be a non-negative int")

        asr = evaluation.get("asr")
        if asr is not None and (not _is_number(asr) or not 0.0 <= float(asr) <= 1.0):
            raise FeedbackStoreError("asr must be a number in [0, 1] or null")
        total = evaluation.get("total_episodes")
        if not _is_int(total) or total < 0:
            raise FeedbackStoreError("total_episodes must be a non-negative int")

        outcomes = evaluation.get("outcomes")
        if not isinstance(outcomes, dict):
            raise FeedbackStoreError("outcomes block is required (structured episode outcomes)")
        counts: dict[str, int] = {}
        for name, value in outcomes.items():
            if name not in OUTCOME_VOCAB:
                raise FeedbackStoreError(
                    f"unknown outcome {name!r}; evidence vocabulary is {sorted(OUTCOME_VOCAB)}"
                )
            if not _is_int(value) or value < 0:
                raise FeedbackStoreError(f"outcome count for {name!r} must be a non-negative int")
            counts[name] = value

        trace = evaluation.get("episode_trace")
        if trace is not None and not isinstance(trace, list):
            raise FeedbackStoreError("episode_trace must be a list or null")

        key = ladder_key(steps)
        usable = True
        reasons: list[str] = []
        if asr is None:
            usable = False
            reasons.append("asr was not measured")
        if total == 0:
            usable = False
            reasons.append("no episodes evaluated")
        elif requested_episodes and total < requested_episodes:
            usable = False
            reasons.append(
                f"incomplete evaluation ({total}/{requested_episodes} episodes)"
            )
        if counts.get("technical_fail", 0) > 0:
            usable = False
            reasons.append(
                f"{counts['technical_fail']} technical failure(s) in evaluation"
            )
        if trace is None:
            usable = False
            reasons.append("no episode trace")
        elif len(trace) != total:
            usable = False
            reasons.append(f"episode trace count {len(trace)} != total_episodes {total}")

        attributed = 0
        if usable and trace is not None:
            attributed = self._attribute(steps, trace, counts)

        reason = "; ".join(reasons) if reasons else "usable structured evidence"
        record = {
            "ladder": steps,
            "iteration": iteration,
            "asr": None if asr is None else round(float(asr), 6),
            "usable": usable,
            "reason": reason,
            "requested_episodes": requested_episodes,
            "total_episodes": total,
            "outcomes": counts,
        }
        self._state["candidates"][key] = record
        self._state["totals"]["usable_evaluations" if usable else "unusable_evaluations"] += 1
        if len(self._state["candidates"]) > MAX_RECORDED_CANDIDATES:
            # Bounded store: drop the oldest recorded candidate (insertion
            # order is preserved by dicts); it simply becomes eligible for
            # re-evaluation, never for a statistical rewrite.
            oldest = next(iter(self._state["candidates"]))
            del self._state["candidates"][oldest]
        self.save()
        return {
            "key": key,
            "usable": usable,
            "reason": reason,
            "attributed_steps": attributed,
        }

    def _attribute(
        self,
        ladder: list[dict[str, Any]],
        trace: list[Any],
        fallback_outcomes: dict[str, int],
    ) -> int:
        """Attribute each traced episode's outcome to its deciding step."""
        step_stats = self._state["step_stats"]
        totals = self._state["totals"]
        exercised: set[str] = set()

        for index, entry in enumerate(trace):
            if not isinstance(entry, dict):
                raise FeedbackStoreError(f"episode_trace[{index}] is not an object")
            outcome = entry.get("outcome")
            if outcome not in OUTCOME_VOCAB:
                raise FeedbackStoreError(
                    f"episode_trace[{index}].outcome {outcome!r} is outside the "
                    f"evidence vocabulary {sorted(OUTCOME_VOCAB)}"
                )
            ep_steps = entry.get("steps")
            if not isinstance(ep_steps, list) or not ep_steps:
                raise FeedbackStoreError(
                    f"episode_trace[{index}].steps must be a non-empty list"
                )
            validated = [
                _validate_step(s, f"episode_trace[{index}].steps") for s in ep_steps
            ]
            rounds_used = entry.get("rounds_used")
            if rounds_used is not None and (
                not _is_int(rounds_used) or rounds_used != len(validated)
            ):
                raise FeedbackStoreError(
                    f"episode_trace[{index}].rounds_used disagrees with its steps"
                )

            for s in validated:
                k = step_key(s)
                counters = step_stats.setdefault(
                    k, {name: 0 for name in _STEP_COUNTERS}
                )
                counters["exposures"] += 1
                exercised.add(k)
            deciding = step_key(validated[-1])
            counters = step_stats[deciding]
            totals["episodes_decided"] += 1
            if outcome in _KNOWN_DECIDED:
                field = _OUTCOME_TO_COUNTER[outcome]
                counters["decided"] += 1
                counters[field] += 1
                totals["known_decisions"] += 1
                totals[field] += 1
            elif outcome == "unknown":
                counters["unknown"] += 1
                totals["unknown"] += 1
            else:  # technical_fail
                counters["technical_fail"] += 1
                totals["technical_fail"] += 1

        # A usable evaluation's outcome block must agree with its trace; a
        # disagreement would mean the two evidence views are inconsistent.
        traced = {name: 0 for name in OUTCOME_VOCAB}
        for entry in trace:
            traced[entry["outcome"]] += 1
        for name in OUTCOME_VOCAB:
            if traced[name] != fallback_outcomes.get(name, 0):
                raise FeedbackStoreError(
                    f"outcomes[{name!r}]={fallback_outcomes.get(name, 0)} disagrees "
                    f"with the episode trace ({traced[name]})"
                )
        return len(exercised)

    # -- ranking -----------------------------------------------------------

    def prior(self) -> float:
        """Run-wide success rate over known decisions (0.0 when none)."""
        totals = self._state["totals"]
        known = totals["known_decisions"]
        return (totals["successes"] / known) if known else 0.0

    def rank(self, candidates: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
        """Order candidates by feedback score, structural order as tie-break."""
        p = self.prior()
        ranked: list[dict[str, Any]] = []
        for index, ladder in enumerate(candidates):
            steps = _validate_ladder(ladder, "rank")
            evidence: list[dict[str, Any]] = []
            estimates: list[float] = []
            for s in steps:
                k = step_key(s)
                counters = self._state["step_stats"].get(k)
                decided = counters["decided"] if counters else 0
                successes = counters["successes"] if counters else 0
                estimate = (successes + ALPHA * p) / (decided + ALPHA)
                estimates.append(estimate)
                evidence.append(
                    {
                        "step": k,
                        "decided": decided,
                        "successes": successes,
                        "observed": decided > 0,
                    }
                )
            score = round(sum(estimates) / len(estimates), 6) if estimates else 0.0
            ranked.append(
                {
                    "key": ladder_key(steps),
                    "ladder": steps,
                    "score": score,
                    "structural_index": index,
                    "evidence": evidence,
                }
            )
        ranked.sort(key=lambda e: (-e["score"], e["structural_index"]))
        return ranked

    # -- audit trail -------------------------------------------------------

    def record_selection(
        self,
        *,
        iteration: int,
        ranked: list[dict[str, Any]],
        evaluated: list[str],
        accepted: str | None,
        budget: int,
    ) -> None:
        """Persist why candidates were picked: scores + evidence + outcome."""
        entry = {
            "at": _now(),
            "iteration": iteration,
            "budget": budget,
            "ranked": [
                {
                    "key": e["key"],
                    "score": e["score"],
                    "structural_index": e["structural_index"],
                    "evidence": e["evidence"],
                }
                for e in ranked
            ],
            "evaluated": list(evaluated),
            "accepted": accepted,
        }
        selections = self._state["selections"]
        selections.append(entry)
        if len(selections) > MAX_RECORDED_SELECTIONS:
            del selections[: len(selections) - MAX_RECORDED_SELECTIONS]
        self.save()

    # -- read surfaces -----------------------------------------------------

    def recorded_keys(self) -> set[str]:
        return set(self._state["candidates"].keys())

    def is_usable(self, key: str) -> bool:
        record = self._state["candidates"].get(key)
        return bool(record and record.get("usable"))

    def summary(self) -> dict[str, Any]:
        """Small, honest summary for status/reporting surfaces."""
        totals = dict(self._state["totals"])
        totals["prior_success_rate"] = round(self.prior(), 6)
        return {
            "path": str(self._path) if self._path else None,
            "origin": self.origin,
            "schema_version": self._state["schema_version"],
            "run_id": self._state["run_id"],
            "config": dict(self._state["config"]),
            "totals": totals,
            "steps_tracked": len(self._state["step_stats"]),
            "candidates_recorded": len(self._state["candidates"]),
            "selections_recorded": len(self._state["selections"]),
            "resets": list(self._state["resets"]),
        }