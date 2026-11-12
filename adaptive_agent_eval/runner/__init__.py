"""Phase 3 experiment runner: bounded, resumable execution of the validated
experiment manifest.

Operations (CLI subcommands, see ``docs/EXPERIMENT_RUNNER.md``):

* ``validate``  — manifest validation only; executes zero episodes.
* ``dry-run``   — plan configurations/episode IDs/seeds and estimate cost;
  executes zero episodes and writes nothing.
* ``run``       — execute an explicitly selected, bounded subset (requires
  ``--execute``; the full 26-config/1,300-episode matrix is refused).
* ``resume``    — continue an interrupted run without duplicating episodes.
* ``status``    — persisted run state, counts, artifact locations + integrity.
* ``aggregate`` — aggregate persisted, valid episode records only.

The runner drives the existing controller lifecycle; it never re-implements
the attack/defense pipeline, never executes LLM calls in deterministic mode,
and never mutates Gmail (read-only behavior preserved).
"""

from adaptive_agent_eval.runner.doubles import (
    DeterministicAttacker,
    DeterministicTarget,
    build_components,
)
from adaptive_agent_eval.runner.executor import (
    ENGINE_DETERMINISTIC,
    ENGINE_LLM,
    PreflightError,
    execute_run,
    preflight,
    resume_run,
    run_status,
)
from adaptive_agent_eval.runner.plan import (
    DEFAULT_MAX_EPISODES_PER_RUN,
    DEFAULT_RUNS_DIR,
    HARD_CAP_EPISODES_PER_RUN,
    EpisodePlan,
    RunnerError,
    RunPlan,
    SelectionError,
    aggregate_run,
    dry_run_summary,
    episode_id_for,
    episode_seed,
    manifest_identity,
    resolve_selection,
)
from adaptive_agent_eval.runner.store import (
    EPISODE_RECORD_SCHEMA,
    RUN_CHECKPOINT_SCHEMA,
    RunStore,
    RunStoreError,
    episode_result_from_dict,
    episode_result_to_dict,
)

__all__ = [
    "DEFAULT_MAX_EPISODES_PER_RUN",
    "DEFAULT_RUNS_DIR",
    "ENGINE_DETERMINISTIC",
    "ENGINE_LLM",
    "EPISODE_RECORD_SCHEMA",
    "HARD_CAP_EPISODES_PER_RUN",
    "RUN_CHECKPOINT_SCHEMA",
    "DeterministicAttacker",
    "DeterministicTarget",
    "EpisodePlan",
    "PreflightError",
    "RunPlan",
    "RunStore",
    "RunStoreError",
    "RunnerError",
    "SelectionError",
    "aggregate_run",
    "build_components",
    "dry_run_summary",
    "episode_id_for",
    "episode_result_from_dict",
    "episode_result_to_dict",
    "episode_seed",
    "execute_run",
    "manifest_identity",
    "preflight",
    "resolve_selection",
    "resume_run",
    "run_status",
]
