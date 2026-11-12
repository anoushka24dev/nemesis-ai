# Feedback-Guided Adaptive Search (Phase 4)

> **Project:** Adaptive AI Agent Defense Evaluation Framework (Nemesis)
> **Status:** Design + bounded first implementation
> **Last Updated:** 2026-10-25

This document is the Phase 4 design proposal and its implementation notes. It
describes two *different* candidate-search algorithms that live side by side in
`backend/adaptive_harness.py`, the evidence store that makes the second one
feedback-guided, and the A/B protocol used to compare them honestly.

---

## 1. Glossary — what is what

| Term | Meaning | Where |
|------|---------|-------|
| **Greedy hill climbing** (baseline) | Existing search: every iteration evaluates **all** `neighbours()` of the current best ladder in structural order and keeps any neighbour whose *measured* ASR is strictly higher. Unchanged, still the default. | `AdaptiveHarness._run` → `_run_greedy_search` |
| **Feedback-guided candidate selection** (new, opt-in) | New search: candidate neighbours are **ranked from statistics accumulated by previous evaluations** in the same run, evaluated within a per-iteration budget, first strict improvement accepted. | `_run_feedback_search` + `backend/search_feedback.py` |
| **Within-episode / within-candidate memory** | The real `MemorySystem` (episodic history of the current episode, procedural rates across the episodes of *one* candidate evaluation). Created fresh inside every `evaluate_strategy` call. Never crosses candidates. | `adaptive_agent_eval/memory` |
| **Cross-candidate learning** | The Phase 4 `FeedbackStore`: per-run statistics accumulated **across** candidate evaluations; the only thing that changes candidate ordering. | `backend/search_feedback.py` |
| **Acceptance rule** | Strict measured-ASR improvement over the current best ladder. Identical in both modes; never changed by feedback. | `_run_*_search` |
| **Promotion gate** | Separate regression gate (completed run, >= `MIN_EPISODES_FOR_PROMOTION` episodes, zero technical failures, strict ASR improvement over the *active* strategy, defender utility >= floor). Unchanged by Phase 4. | `_evaluate_gate` |
| **Deterministic local simulation** | Seeded stand-in attacker/target + marker/verifier/progent defenses driving the real Controller/Diagnoser/Memory/Metrics. Reproducible, offline, no Gmail. | this module |
| **Live LLM-target evaluation** | *Not implemented in Phase 4.* Nothing here is evidence of adaptive red-teaming against a real model. | deferred (ADR-016/017) |

---

## 2. Design (the 8 questions)

### 2.1 Which observed episode outcomes are retained between candidate evaluations

Only **structured, validated episode outcomes** — never model-generated text:

* per candidate evaluation: the ladder key, measured ASR, requested vs actual
  episode counts, technical-failure count, and the per-episode trace produced by
  the real `Controller` (`outcome`, `rounds_used`, and the exact
  `(category, sophistication)` steps the episode exercised, read from the real
  `AttackPayload`s);
* per step `(category, sophistication)`: how many episodes that step
  **decided** (the last round exercised determines the episode outcome by the
  Controller's stop-on-success/budget construction), and the outcome counts
  among those decisions (`success` / `blocked` / `ignored`, with `unknown` and
  `technical_fail` counted separately);
* per step: `exposures` — episodes in which the step was exercised at all
  (audit only, not used in ranking).

Free-text diagnostics, LLM classifier output, and raw explanations are **not**
ingested: `AttackOutcome` enum values are the entire evidence vocabulary.

### 2.2 How category and sophistication are represented in persistent statistics

A flat map keyed by `"<category>:<sophistication_level>"` (at most 5 x 5 = 25
keys). Each key holds integer counters only. The ladder-level map is keyed by
the existing 12-hex `ladder_key` and links a ladder to its recorded evaluation.

### 2.3 How the Diagnoser's output is incorporated

The offline path runs rule-based stage A (`Diagnoser.diagnose` →
`AttackOutcome`), aggregated by the real `Controller` into `EpisodeResult`,
counted into `StrategyEvaluation.outcomes`, and traced per episode. That enum
is the *only* Diagnoser surface the feedback store accepts, and it is validated
on ingestion (unknown keys are rejected with `FeedbackStoreError`). Stage B
(LLM classifier) has no client offline, so no model-generated explanation
exists on this path, and no store field would accept one.

### 2.4 How the next neighbour is ranked

Deterministic, interpretable, count-based (no RL, no embeddings):

```
p            = global success rate over known decisions so far (0.0 if none)
estimate(k)  = (successes(k) + ALPHA * p) / (decided(k) + ALPHA)   # ALPHA = 4
score(C)     = mean over steps s of C of estimate(s)
order        = sort by (-score, structural_index in neighbours())
```

`ALPHA` is a documented smoothing pseudo-count toward the run-wide rate — a
shrinkage estimator, **not** a confidence interval or significance claim.
Unobserved steps (`decided == 0`) score exactly `p`, so a cold candidate set
ranks exactly like the structural (greedy) order.

### 2.5 Uncertainty / insufficient observations

No invented confidence numbers. Every ranked candidate carries its evidence
(`decided`, `successes`, `observed` per step); steps with zero observations are
flagged `observed: false` and treated as neutral (score `p`). Evaluations that
are incomplete, stopped, technically failed, missing a trace, or carry invalid
outcome keys are recorded as **unusable** and contribute *nothing* to the
ranking statistics, so a partial or broken run cannot create a favorable
learning signal.

### 2.6 Determinism

* seed: same `seed + iteration` policy as the baseline;
* candidate order: `neighbours()` output order is the structural tie-break;
* score ties resolve to `structural_index` (ascending), never to dict/hash
  order;
* fresh feedback state per run (see 2.7), so identical configuration ⇒
  identical trajectory (verified by fingerprint comparison in the A/B).

### 2.7 Feedback-store persistence, versioning, validation, reset

* One JSON file next to the harness store: `<store>.feedback.json`
  (in-memory only when the harness has no store path).
* `schema_version: 1`; the state carries `run_id` **and** a config fingerprint
  (`mode, episodes, max_rounds, iterations, seed, defense, selection_budget`).
* On open: missing file → fresh (`new-store`); different `run_id` or config →
  fresh (reset reason recorded); unreadable / wrong schema / inconsistent
  counters → `FeedbackStoreError`, and the harness starts from an **empty**
  store with reason `invalid-state` (corrupt state can never bias the search).
* Written atomically (tmp + replace) after every observation.
* Reset semantics: independent runs never share statistics; within one run the
  store is *never* reset between candidates.

### 2.8 Fair comparison against the greedy baseline

`compare_search_modes()` runs both arms with the same starting ladder,
defense, target process, episodes, iterations, seed, and `seed + iteration`
evaluation-seed policy, twice each (reproducibility check), and records per arm:
selected-strategy ASR, candidate evaluations consumed, unique candidates,
episodes consumed, incomplete evaluations, technical-failure episodes, final
candidate utility, gate verdict, and whether feedback changed candidate
ordering. Limitations that cannot be held constant (arms consume different
numbers of evaluations, so per-candidate iteration seeds differ) are recorded
in the returned `limitations` list rather than hidden.

---

## 3. Search algorithm (feedback mode)

```
baseline_eval <- evaluate(default ladder); store.observe(baseline)
frontier      <- neighbours(baseline)                      # unexamined candidates
for iteration in 1..iterations:
    if stop signalled: break
    if frontier empty: record neighbourhood exhausted; break
    ranked    <- store.rank(frontier)                      # -score, structural index
    batch     <- ranked[:selection_budget]
    record selection (ranked scores + evidence + evaluated keys)
    for cand in batch:
        ev <- evaluate(cand, seed + iteration)
        store.observe(ev)                                  # cross-candidate update
        if ev.asr is strictly greater than best: accept; break   # first improvement
    if accepted:
        frontier <- neighbours(new best) minus already-recorded keys   # dedup
    else:
        frontier <- frontier minus evaluated keys
final evaluation of best ladder -> unchanged promotion gate
```

Key properties:

* the ordering of `batch` is a function of previously observed outcomes, so the
  feedback genuinely steers the search (regression-tested against the greedy
  order under controlled fixtures);
* acceptance and promotion rules are untouched;
* a ladder is evaluated at most once per run (recorded keys are skipped);
* every selection is persisted with the evidence used, so decisions are
  auditable after the run.

---

## 4. Defense transfer (second local deterministic defense)

`evaluate_strategy(..., defense=...)` supports the three search-time defense
choices exposed by the dashboard (`DEFENSE_CHOICES`):

* `"marker"` — the existing CaMeL-style literal-taint stand-in (default,
  unchanged);
* `"verifier"` — the package's `VerifierDefense` (rule-based schema + intent
  match) behind the same `evaluate() -> list[DefenseEvent]` interface;
* `"progent"` — the package's `ProgentDefense` **proxy**: a static privilege
  table plus literal argument checks. It contains **no SMT solver** and no
  formal/constraint solving, and must not be described as Progent.

Same safety contract: deterministic, offline, no LLM/Gmail/network. The three
are local proxies; none reproduces the published CaMeL / Progent / Verifier
systems. The verifier's landscape differs from the marker defense (intent matching denies
the *encoded* payloads that evade the marker defense, and it over-blocks the
benign utility probes), so it is used only to ask whether a preference learned
on one defense reappears on the other. **Two toy defenses cannot support a
claim of cross-defense generalization**; results are reported as observations
about these two defenses only.

---

## 5. Honest limits

* Deterministic local simulation only — not evidence of real-world attack
  effectiveness, not a live red-team result.
* Step statistics are **correlational** (which steps co-occurred with
  decisive outcomes), not causal attribution.
* `ALPHA` smoothing is shrinkage, not a statistical guarantee; no significance
  test is performed or claimed.
* The A/B fixture is small and deterministic; it demonstrates mechanism, not
  population-level improvement.
* Live LLM-target evaluation remains blocked on the Phase 4 provider binding
  work (ADR-016) and a separately approved full-matrix procedure (ADR-017).

---

## 6. Product framing (dashboard requirements)

Both algorithms are **separately selectable strategies** in the product
(PRD §1.6/§1.10):

| Requirement | Meaning |
|-------------|---------|
| Explicit selection | The user chooses `greedy` (default, unchanged) or `feedback` before an experiment; the choice is recorded with the run. Unknown modes are rejected, never silently coerced (`backend/adaptive_harness.py`, `search_mode` in `status()`). |
| Both preserved | Greedy search may not be removed or demoted while feedback-guided search exists; feedback is opt-in. |
| Honest "level" display | A strategy **level** shown in the dashboard must be the actual search progression — the ladder steps and measured ASR of recorded candidates — not a fabricated or cosmetic narrative. Levels render from persisted candidate records only. |
| Shared execution shape | The attacker executes **bounded** tests, collects **structured outcomes** (`AttackOutcome` enum only), and the *selected* algorithm decides what to test next. Selection feedback never writes into defense decisions or post-run AI analysis (PRD §1.13.E). |

**Research question (unresolved):** does feedback-guided search find
successful strategies, or reach comparable results more efficiently, than
greedy search under comparable conditions? The A/B protocol in §2.8 is the
design for answering it. **No superiority claim is made** — until controlled
experiments are run and recorded, neither algorithm may be described as
better in product copy, dashboards, or analyses.

---

## 7. Model assistance — actual scope (Phase 6B)

When a provider is explicitly selected for a `feedback` run, the model
assistant (`adaptive_agent_eval/llm/adaptive_assistant.py`) proposes a
candidate ladder at each iteration boundary. Its real scope:

| Property | Reality |
|----------|---------|
| Provider | `ollama` is the default (loopback `http://127.0.0.1:11434`, model `llama3.1:8b`); hosted providers require explicit credentials. No silent fallback exists in either direction. |
| Request accounting | The assistant has its own request budget (`model_request_budget`, default 50, capped at 500). Every request is counted; `0` means no request was made — never an estimate. |
| Failure handling | Connection errors, timeouts (120 s default), malformed JSON and schema violations are recorded as **rejections with a reason**. They never become security outcomes and never stall the search. |
| Proposal validation | A proposal must match the parent ladder length, use allowed tactic categories and sophistication 1–5, and be a single-step neighbour that has not been evaluated in this run. Invalid proposals are rejected verbatim — never repaired into something the model did not say. |
| Authority | Advisory only. The model orders/suggests candidates; **it cannot declare an attack successful, blocked, or safe**. Promotion still requires a strictly higher measured ASR. |
| Greedy mode | Never consults the assistant (no implicit model use). |
| Convergence boundary | The proposal is requested when a new iteration begins. A run that converges or hits its iteration limit before that boundary makes **zero** model requests and reports exactly that. |

A smoke test that shows `model_calls_consumed = 0` therefore means “the model
was configured but not needed for this bounded run”, not “the model was used
and produced nothing”. Readiness and usage are separate fields in
`/api/overview` and in the persisted run record.

Existing candidate-selection rules (strict ASR improvement), the promotion
gate, and metrics semantics are unchanged by this document; see
[ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) ADR-002/ADR-018 and
[PRD.md](PRD.md).
