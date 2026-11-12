# Experiment Runner (Phase 3)

Bounded, resumable execution of the validated experiment manifest
(`adaptive_agent_eval/experiment_matrix.py`, ADR-016/ADR-017). The runner
drives the **existing** controller lifecycle — attacker → target → defense
layer → adapter → diagnoser → memory → metrics — and never re-implements the
attack/defense pipeline.

> **Product context:** this runner is step 3–4 of the eight-step experiment
> workflow in [PRD.md §1.10](PRD.md) (bounded adaptive episodes → evidence
> and artifacts). The target connectivity check (step 1), the dashboard UX, the
> AI attack/defense analyses (steps 5 and 8), and the separate defense
> evaluation (steps 6–7) are **not** part of this runner. **1,000 episodes**
> is the *desired supported* budget for the eventual product runner — today's
> hard cap is 50 episodes per invocation and the 26-config/1,300-episode
> matrix is refused (see below). Safe initial defaults (PRD §1.11) match the
> safety invariants at the bottom of this document.

> **Scope:** The Phase 3 runner is a deterministic *experiment executor*, not
> an adaptive attack optimizer. It does not perform the hill-climbing
> candidate-search loop; that lives in the backend adaptive harness
> (`backend/adaptive_harness.py`, see ADR-002's terminology note). A manifest
> or contract field labelled `adaptive-hill-climbing` names the attacker type
> only — it does not mean this runner adapts strategies between episodes.

## Operations

All operations are CLI subcommands (`python -m adaptive_agent_eval.cli
<command>` or `adaptive-eval <command>`); the pre-Phase-3 flat flags
(`--mode`, `--defenses`, `--validate-manifest`, …) still work unchanged.

| Command | Executes episodes? | Writes anything? | Purpose |
|---------|--------------------|------------------|---------|
| `validate` | **No** | No | Validate the manifest; exit 1 when invalid |
| `dry-run` | **No** | No | Plan configuration IDs, episode IDs, seeds, integrations, resource bounds |
| `run` | Only with `--execute` | Yes | Execute an explicitly selected, bounded subset |
| `resume` | Only with `--execute` | Yes | Continue an interrupted run; completed episodes never re-run |
| `status` | No | No | Persisted run state, counts, artifact locations + integrity |
| `aggregate` | No | No | Aggregate persisted, valid episode records only |

**Default behavior is non-executing everywhere.** A missing or ambiguous
execution option never starts an experiment; `run`/`resume` without
`--execute` print the plan and exit with status 2.

## Execution boundaries

* `run` requires explicit `--configs` IDs (empty, malformed, unknown, or
  duplicate selections are rejected with an explanation).
* Hard per-invocation episode limit: default **10**, absolute cap **50**.
  Selections above the limit are refused; the cap cannot be raised.
* The full 26-configuration / 1,300-episode matrix is **always refused** by
  `run` — a future, separately approved full-evaluation procedure must
  explicitly enable it. `dry-run` may *plan* the full matrix (planning
  executes nothing).
* Execution mode, configuration IDs, episode count, provider mode, and the
  manifest hash are printed **before** any execution begins.
* Execution is **CLI-only** in Phase 3: no API route can launch, resume, or
  aggregate a run (`GET /stage-b/experiment-dry-run` is planning-only and
  non-executing).

### Engines

* `--provider-mode deterministic` (default): real local defenses and
  diagnoser execute; attacker/target are seed-driven deterministic doubles
  (`adaptive_agent_eval/runner/doubles.py`). **Zero LLM calls, zero network,
  zero cost.** Every record is labeled `engine: deterministic-local` with per
  component implementations — these results are *not* research results.
* `--provider-mode llm`: preflighted before any episode. It currently **fails
  closed**: the approved manifest binds provider `gemini`, which
  `adaptive_agent_eval.llm.provider` does not implement (`openai`/`anthropic`
  only — the Phase 2 finding, ADR-016 consequence). The runner never silently
  switches providers, never reinterprets environment variables, and never
  falls back to the doubles when real execution was requested. Credential
  checks report environment variable *names*, never values.

## Seeds (canonical Phase 2 policy)

```
config_seed  = global_config_index * 1000        # 1..26 across the manifest
episode_seed = config_seed + episode_index       # episode_index is 1-based
episode_id   = <config_id>-E<index:03d>          # e.g. M1-01-E001
```

Same manifest + same selection + same seeds ⇒ same episode identities, and
with the deterministic engine, identical results (asserted by tests).

## On-disk layout (`results/runs/<run_id>/` by default)

| File | Content | Write style |
|------|---------|-------------|
| `run.json` | Checkpoint: run ID, manifest hash, selection, per-episode statuses, counts, timestamps | Atomic (temp + `os.replace`, fsynced) |
| `episodes.json` | Episode records, one JSON object per line (JSON Lines) | Append-only, fsynced per record |
| `manifest.json` | Existing artifact manifest (`adaptive_agent_eval.artifacts`) covering `episodes.json` by SHA-256 + canonical episode-payload hash | Written at finalization |

No new database was introduced: this continues ADR-008 (JSON persistence).
PostgreSQL/SQLite would only be justified if run counts or concurrency
outgrew filesystem storage; nothing in the 26-configuration plan does.

### Episode statuses

`pending` (not started) → `running` → `completed` | `failed`.
An episode that was mid-execution when the process died stays `running`
(= *interrupted*) and is re-executed on resume; run-level status distinguishes
`interrupted` (stopped partway) from `failed` (finished with failed episodes)
and `completed` (every episode completed). Skipped = manifest-planned
episodes intentionally excluded by the bounded selection.

### Integrity vs authenticity

Hashes here (and in `artifacts.py`) **detect** modification, truncation, or
deletion after the fact; they are *not* signatures — anyone who can rewrite
the run directory can rewrite the hashes with it (same documented limit as
ADR-007). Resume fails closed on: corrupt checkpoints, manifest-identity
change, artifact modification since finalization, a `completed` checkpoint
without a matching record, duplicate records, or mid-file corruption. A torn
**trailing** record line (interrupted append) is repaired on resume; that
episode is never treated as completed.

### Resume reconciliation

The appended episode **record** is authoritative: if the process died between
record append and checkpoint save, resume adopts the record's terminal status
instead of re-executing. Completed episodes are never re-executed; failed
episodes are not auto-retried (start a new run to retry). Duplicate resume
requests are idempotent.

## Aggregation

`aggregate` reads **only persisted, valid episode records**. Metrics reuse the
Phase 1 availability contract (`docs/METRICS_DEFINITIONS.md` §1.5): metrics
with no evidence are `null` / `not_measured` — never fabricated `0.0` (e.g. a
zero-cost stub run reports `cost_per_attack: null`, not `0.0`). Reported:
planned/completed/failed/interrupted/pending/skipped counts, per-configuration
and overall metrics with availability and sample counts, run duration,
reproducibility metadata (manifest hash, seed policy, engine), and artifact
integrity. A configuration is `complete` only when every planned episode has
a valid persisted result. Statistical confidence/significance is **not
reported** because it is not implemented (`confidence: null`).

## Safety invariants (tested)

* Gmail stays read-only; the runner never imports Gmail modules and performs
  no mailbox mutations; email operations remain simulation-only.
* Chrome extension pairing protections and existing API routes are unchanged.
* No paid LLM calls occur in tests or dry runs.
* Failure diagnostics are redacted (secret-looking values → `[REDACTED]`)
  before persistence.

## Quick reference

```bash
# Validate the plan (runs nothing)
python -m adaptive_agent_eval.cli validate

# Plan a bounded experiment (runs nothing)
python -m adaptive_agent_eval.cli dry-run --configs M1-01 M2-03 --episodes-per-config 2

# Execute 4 deterministic episodes (refuses without --execute)
python -m adaptive_agent_eval.cli run --configs M1-01 M1-02 --episodes-per-config 2 \
    --run-id smoke1 --execute

# Continue after an interruption
python -m adaptive_agent_eval.cli resume --run-id smoke1 --execute

# Inspect and aggregate
python -m adaptive_agent_eval.cli status --run-id smoke1
python -m adaptive_agent_eval.cli aggregate --run-id smoke1 --json
```

Tests: `tests/test_phase3_runner.py` (selection bounds, zero execution,
seeds, interruption/resume, corruption, aggregation availability, preflight,
CLI exit codes, API non-execution, Gmail preservation).
