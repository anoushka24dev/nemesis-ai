"""Run planning, bounded selection, and result aggregation (Phase 3).

Selection is resolved against the validated manifest only — unknown, empty,
malformed, duplicate, or unexpectedly broad selections are rejected with an
explanation, never coerced. ``resolve_selection`` never executes anything.

Aggregation reads **only persisted, valid episode records**. Metrics reuse
Phase 1's availability contract (``docs/METRICS_DEFINITIONS.md`` §1.5): a
metric with no evidence stays ``None`` and is reported as "not measured" —
never fabricated as ``0.0``. No statistical confidence or significance is
reported, because none is implemented.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from adaptive_agent_eval.experiment_matrix import (
    EPISODES_PER_CONFIG,
    validate_manifest,
)
from adaptive_agent_eval.metrics.modules import MetricsCollector
from adaptive_agent_eval.runner.store import (
    RunStore,
    RunStoreError,
    episode_result_from_dict,
)

#: Conservative default for one `run` invocation (local testing).
DEFAULT_MAX_EPISODES_PER_RUN = 10
#: Absolute per-invocation ceiling; a run may never exceed it this phase.
HARD_CAP_EPISODES_PER_RUN = 50

DEFAULT_RUNS_DIR = "results/runs"

CONFIG_ID_RE = re.compile(r"^M[123]-\d{2}$")


class RunnerError(RuntimeError):
    """A run-level operation failed with an explanation."""


class SelectionError(RunnerError):
    """The requested selection is invalid, too broad, or unsupported."""


@dataclass(frozen=True)
class EpisodePlan:
    """One planned episode: identity plus its reproducible seed."""

    episode_id: str
    config_id: str
    index: int
    seed: int


@dataclass
class RunPlan:
    """A fully resolved, bounded plan for a (possibly resumed) run."""

    manifest_sha256: str
    engine: str
    provider_mode: str
    episodes_per_config: int
    selection: list[str]
    config_entries: list[dict[str, Any]] = field(default_factory=list)
    episodes: list[EpisodePlan] = field(default_factory=list)
    #: Manifest-planned episodes intentionally NOT part of this run
    #: (bounded selection within 50-episode configurations).
    excluded_episodes: int = 0

    @property
    def total_episodes(self) -> int:
        return len(self.episodes)


def manifest_identity(manifest: dict[str, Any]) -> str:
    """Canonical SHA-256 of the manifest (sorted keys, stable encoding).

    Integrity bookkeeping, not authenticity — same documented limit as
    ``artifacts.py``.
    """
    blob = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def episode_id_for(config_id: str, index: int) -> str:
    return f"{config_id}-E{index:03d}"


def episode_seed(entry: dict[str, Any], index: int) -> int:
    """Canonical Phase 2 seed policy: ``episode_seed = config_seed + index``."""
    return int(entry["seed"]) + index


def resolve_selection(
    manifest: dict[str, Any],
    config_ids: list[str],
    episodes_per_config: int = EPISODES_PER_CONFIG,
    *,
    provider_mode: str = "deterministic",
    max_episodes: int = DEFAULT_MAX_EPISODES_PER_RUN,
    enforce_bounded: bool = True,
) -> RunPlan:
    """Resolve an explicit selection into a bounded ``RunPlan``.

    ``enforce_bounded=True`` (used by ``run``/``resume``) additionally
    enforces the per-invocation episode limit and refuses the full matrix.
    Dry-run planning sets it to ``False`` — planning the whole matrix executes
    nothing.
    """
    errors = validate_manifest(manifest)
    if errors:
        raise SelectionError(
            "manifest is invalid; refusing to plan against it:\n  - "
            + "\n  - ".join(errors)
        )

    if not isinstance(config_ids, list) or not config_ids:
        raise SelectionError(
            "selection is empty: name one or more configuration IDs "
            "(e.g. --configs M1-01)"
        )

    known = [entry["config_id"] for entry in manifest["configurations"]]
    known_set = set(known)
    seen: set[str] = set()
    problems: list[str] = []
    for cid in config_ids:
        if not isinstance(cid, str) or not cid:
            problems.append(f"malformed configuration id: {cid!r}")
            continue
        if not CONFIG_ID_RE.match(cid):
            problems.append(
                f"malformed configuration id {cid!r} (expected e.g. M1-01)"
            )
            continue
        if cid not in known_set:
            problems.append(f"unknown configuration id {cid!r} (not in the manifest)")
            continue
        if cid in seen:
            problems.append(f"duplicate configuration id {cid!r}")
            continue
        seen.add(cid)
    if problems:
        raise SelectionError("invalid selection:\n  - " + "\n  - ".join(problems))

    if (
        isinstance(episodes_per_config, bool)
        or not isinstance(episodes_per_config, int)
        or episodes_per_config < 1
    ):
        raise SelectionError(
            f"episodes_per_config must be an integer >= 1, got {episodes_per_config!r}"
        )
    if episodes_per_config > EPISODES_PER_CONFIG:
        raise SelectionError(
            f"episodes_per_config {episodes_per_config} exceeds the manifest's "
            f"approved {EPISODES_PER_CONFIG} episodes per configuration"
        )

    if provider_mode not in ("deterministic", "llm"):
        raise SelectionError(
            f"unknown provider mode {provider_mode!r} "
            "(expected 'deterministic' or 'llm')"
        )

    entries_by_id = {e["config_id"]: e for e in manifest["configurations"]}
    # Canonical order = manifest order, independent of argument order.
    selection = [cid for cid in known if cid in seen]

    if enforce_bounded:
        if len(seen) == len(known):
            raise SelectionError(
                "the full 26-configuration / 1,300-episode matrix is refused: "
                "a future, separately approved full-evaluation procedure must "
                "explicitly enable it. Select a bounded subset (or use "
                "`dry-run` to plan without executing)."
            )
        if max_episodes > HARD_CAP_EPISODES_PER_RUN:
            raise SelectionError(
                f"max_episodes {max_episodes} exceeds the hard per-invocation "
                f"cap of {HARD_CAP_EPISODES_PER_RUN}"
            )
        total = len(selection) * episodes_per_config
        if total > max_episodes:
            raise SelectionError(
                f"selection would execute {total} episodes "
                f"({len(selection)} configurations x {episodes_per_config} "
                f"episodes), above the per-invocation limit of {max_episodes}. "
                "Narrow the selection, lower --episodes-per-config, or use "
                "dry-run to plan without executing."
            )

    entries = [entries_by_id[cid] for cid in selection]
    episodes: list[EpisodePlan] = []
    for entry in entries:
        for index in range(1, episodes_per_config + 1):
            episodes.append(
                EpisodePlan(
                    episode_id=episode_id_for(entry["config_id"], index),
                    config_id=entry["config_id"],
                    index=index,
                    seed=episode_seed(entry, index),
                )
            )
    excluded = len(selection) * (EPISODES_PER_CONFIG - episodes_per_config)

    return RunPlan(
        manifest_sha256=manifest_identity(manifest),
        engine="deterministic-local" if provider_mode == "deterministic" else "llm",
        provider_mode=provider_mode,
        episodes_per_config=episodes_per_config,
        selection=selection,
        config_entries=entries,
        episodes=episodes,
        excluded_episodes=excluded,
    )


def dry_run_summary(plan: RunPlan, manifest: dict[str, Any]) -> dict[str, Any]:
    """Planning-only summary. Executes nothing, writes nothing."""
    integrations: list[str] = []
    for entry in plan.config_entries:
        for item in entry.get("required_integrations", ()):
            if item not in integrations:
                integrations.append(item)
    seeds = [ep.seed for ep in plan.episodes]
    return {
        "kind": "experiment_dry_run",
        "execution": "none",
        "episodes_executed": 0,
        "engine": plan.engine,
        "provider_mode": plan.provider_mode,
        "manifest_sha256": plan.manifest_sha256,
        "selection": plan.selection,
        "configurations": len(plan.selection),
        "episodes_per_config": plan.episodes_per_config,
        "planned_episodes": plan.total_episodes,
        "excluded_episodes": plan.excluded_episodes,
        "episode_id_first": plan.episodes[0].episode_id if plan.episodes else None,
        "episode_id_last": plan.episodes[-1].episode_id if plan.episodes else None,
        "seed_min": min(seeds) if seeds else None,
        "seed_max": max(seeds) if seeds else None,
        "required_integrations": integrations,
        "provider_binding": manifest.get("provider_binding"),
        "resource_estimate": {
            "total_rounds_upper_bound": plan.total_episodes
            * (plan.config_entries[0]["max_rounds"] if plan.config_entries else 0),
            "llm_calls": (
                0
                if plan.provider_mode == "deterministic"
                else "unknown: llm mode requires a supported provider binding"
            ),
        },
        "note": (
            "planning only — zero episodes were executed; nothing was written "
            "to disk"
        ),
    }


# ---------------------------------------------------------------------------
# Aggregation (persisted records only)
# ---------------------------------------------------------------------------

_METRIC_FIELDS = (
    "attack_success_rate",
    "utility_score",
    "cost_per_attack",
    "rounds_to_success",
    "recovery_time",
    "bypass_rate",
    "propagation_rate",
    "blast_radius",
    "marginal_gain",
)


def _snapshot_block(results: list) -> dict[str, Any]:
    collector = MetricsCollector()
    for result in results:
        collector.end_episode(result)
    snapshot = collector.get_snapshot()
    metrics = {name: getattr(snapshot, name) for name in _METRIC_FIELDS}
    return {
        "episodes_with_results": len(results),
        "metrics": metrics,
        "availability": {
            name: ("measured" if value is not None else "not_measured")
            for name, value in metrics.items()
        },
    }


def aggregate_run(store: RunStore) -> dict[str, Any]:
    """Aggregate a run from its persisted, valid episode records only."""
    meta = store.load()
    try:
        records_by_id = store.read_records()
    except RunStoreError as exc:
        raise RunnerError(f"cannot aggregate: {exc}") from exc

    episodes_meta = meta.get("episodes") or []
    counts = {"completed": 0, "failed": 0, "interrupted": 0, "pending": 0}
    for ep in episodes_meta:
        status = ep.get("status")
        if status in ("completed", "failed"):
            counts[status] += 1
        elif status == "running":
            counts["interrupted"] += 1
        else:
            counts["pending"] += 1

    per_config: dict[str, Any] = {}
    overall_results = []
    integrity_problems: list[str] = []

    snapshots = meta.get("config_snapshots") or []
    entries = (
        snapshots
        if isinstance(snapshots, list)
        else [snapshots[k] for k in sorted(snapshots)]
    )
    for entry in entries:
        cid = entry["config_id"]
        planned_ids = [
            ep["episode_id"]
            for ep in episodes_meta
            if ep.get("config_id") == cid
        ]
        results = []
        failed = pending = 0
        for episode_id in planned_ids:
            ep_meta = next(
                e for e in episodes_meta if e.get("episode_id") == episode_id
            )
            record = records_by_id.get(episode_id)
            if ep_meta.get("status") == "completed":
                if record is None or not record.get("result"):
                    integrity_problems.append(
                        f"{episode_id}: checkpoint says completed but no valid "
                        "record exists"
                    )
                    pending += 1
                    continue
                try:
                    results.append(episode_result_from_dict(record["result"]))
                except (KeyError, ValueError, TypeError) as exc:
                    integrity_problems.append(
                        f"{episode_id}: persisted result failed strict "
                        f"deserialization ({exc})"
                    )
                    pending += 1
            elif ep_meta.get("status") == "failed":
                failed += 1
            else:
                pending += 1
        overall_results.extend(results)
        block = _snapshot_block(results)
        per_config[cid] = {
            "planned": len(planned_ids),
            "completed": len(results),
            "failed": failed,
            "pending": pending,
            "complete": len(results) == len(planned_ids) and failed == 0 and pending == 0,
            **block,
        }

    integrity = store.integrity()
    duration = {
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
    }
    # "completed" means a *valid persisted result* — a checkpoint claim whose
    # record is missing or invalid is counted as pending, never as completed.
    checkpoint_claimed_completed = counts["completed"]
    completed = sum(b["completed"] for b in per_config.values())
    failed = sum(b["failed"] for b in per_config.values())
    interrupted = counts["interrupted"]
    planned = len(episodes_meta)
    pending = max(0, planned - completed - failed - interrupted)
    return {
        "kind": "experiment_aggregation",
        "run_id": meta.get("run_id"),
        "run_status": meta.get("status"),
        "manifest_sha256": meta.get("manifest_sha256"),
        "engine": meta.get("engine"),
        "provider_mode": meta.get("provider_mode"),
        "counts": {
            "planned": planned,
            "completed": completed,
            "failed": failed,
            "interrupted": interrupted,
            "pending": pending,
            "skipped": int(meta.get("excluded_episodes") or 0),
            "checkpoint_claimed_completed": checkpoint_claimed_completed,
        },
        "per_config": per_config,
        "overall": _snapshot_block(overall_results),
        "complete": all(b["complete"] for b in per_config.values()) if per_config else False,
        "duration": duration,
        "reproducibility": {
            "manifest_sha256": meta.get("manifest_sha256"),
            "seed_policy": meta.get("seed_policy"),
            "episodes_per_config": meta.get("episodes_per_config"),
            "engine": meta.get("engine"),
        },
        "artifact_integrity": integrity,
        "integrity_problems": integrity_problems,
        "confidence": None,  # not implemented — never fabricated
        "note": (
            "aggregation covers persisted, valid episode records only; "
            "undefined metrics are reported as not_measured, never 0.0"
        ),
    }
