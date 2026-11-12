"""Bounded execution, resume, status, and provider preflight (Phase 3).

The executor drives the **existing** controller lifecycle
(``Controller.run_episode``) — attacker → target → defense layer → adapter →
diagnoser → memory → metrics — and persists each episode through
:class:`~adaptive_agent_eval.runner.store.RunStore`. It never duplicates the
attack/defense pipeline.

Execution boundaries
--------------------
* Episodes execute only from an explicit, bounded ``RunPlan`` (see
  :mod:`adaptive_agent_eval.runner.plan`); this module executes exactly the
  plan it is given and never widens it.
* ``provider_mode="llm"`` is preflighted and currently **fails closed**: the
  approved manifest binds provider ``gemini``, which the provider layer does
  not implement (``openai``/``anthropic`` only — the Phase 2 finding). The
  runner never silently switches providers or falls back to the doubles when
  real execution was requested.
* Failures are recorded per episode (status ``failed`` with a redacted
  diagnostic) — a partial failure never becomes a silent success.
"""

from __future__ import annotations

import os
import re
import traceback
from datetime import datetime, timezone
from typing import Any

from adaptive_agent_eval.controller.orchestrator import Controller
from adaptive_agent_eval.memory.memory import MemorySystem
from adaptive_agent_eval.models import (
    AttackerTier,
    DefenseType,
    EpisodeConfig,
    EpisodeMode,
    EpisodeStatus,
    TargetTier,
)
from adaptive_agent_eval.runner.doubles import (
    DEFAULT_ATTACK_GOAL,
    DEFAULT_TASK_DESCRIPTION,
    build_components,
)
from adaptive_agent_eval.runner.plan import (
    RunnerError,
    RunPlan,
    manifest_identity,
)
from adaptive_agent_eval.runner.store import (
    RunStore,
    RunStoreError,
    episode_result_to_dict,
)

ENGINE_DETERMINISTIC = "deterministic-local"
ENGINE_LLM = "llm"

#: Any value that *looks* like a credential is redacted from failure
#: diagnostics before persistence. Integrity bookkeeping only — the runner
#: never logs key values in the first place.
_SECRET_RE = re.compile(
    r"(AIza[0-9A-Za-z_\-]{20,}|sk-[0-9A-Za-z_\-]{16,}|ghp_[0-9A-Za-z]{20,}"
    r"|Bearer\s+[0-9A-Za-z]+|api[_\-]?key\s*[:=]\s*\S+)",
    re.IGNORECASE,
)


class PreflightError(RunnerError):
    """A required provider/dependency is unavailable; execution refused."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _redact(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


def preflight(provider_mode: str, manifest: dict[str, Any]) -> dict[str, Any]:
    """Verify execution prerequisites BEFORE any episode runs.

    Never prints credential values; only the *names* of missing environment
    variables are reported.
    """
    checks: list[dict[str, Any]] = [
        {
            "check": "local-components",
            "status": "available",
            "detail": "controller, defenses, adapter, diagnoser, memory, metrics",
        }
    ]
    if provider_mode == ENGINE_DETERMINISTIC or provider_mode == "deterministic":
        checks.append(
            {
                "check": "llm-provider",
                "status": "not_required",
                "detail": "deterministic engine executes zero LLM calls",
            }
        )
        return {
            "ok": True,
            "engine": ENGINE_DETERMINISTIC,
            "provider_mode": "deterministic",
            "checks": checks,
        }
    if provider_mode != "llm":
        raise PreflightError(
            f"unknown provider mode {provider_mode!r} "
            "(expected 'deterministic' or 'llm')"
        )

    # -- llm mode: the manifest's explicit binding must be supported ---------
    binding = (manifest.get("provider_binding") or {}).get("provider")
    from adaptive_agent_eval.llm.provider import ProviderConfig

    try:
        # Explicit provider argument — never inferred from the environment.
        cfg = ProviderConfig(binding)  # type: ignore[arg-type]
    except ValueError as exc:
        raise PreflightError(
            f"provider preflight failed: the approved manifest binds provider "
            f"{binding!r}, which the provider layer does not implement "
            f"(supported: openai, anthropic). Options: (a) implement a "
            f"{binding!r} provider path under an approved decision, (b) rebind "
            "the manifest via a new ADR, or (c) execute with "
            "--provider-mode deterministic. The runner will not silently "
            "switch providers or reinterpret environment variables."
        ) from exc
    key_env = cfg.api_key_env
    if not os.getenv(key_env):
        raise PreflightError(
            f"provider preflight failed: credential environment variable "
            f"{key_env} is not set (set it in .env; the runner never prints "
            "credential values)"
        )
    checks.append(
        {
            "check": "llm-provider",
            "status": "configured",
            "detail": f"provider={cfg.provider} credential_env={key_env} present",
        }
    )
    return {
        "ok": True,
        "engine": ENGINE_LLM,
        "provider_mode": "llm",
        "checks": checks,
    }


def _new_checkpoint(plan: RunPlan) -> dict[str, Any]:
    now = _utcnow()
    return {
        "manifest_sha256": plan.manifest_sha256,
        "engine": plan.engine,
        "provider_mode": plan.provider_mode,
        "episodes_per_config": plan.episodes_per_config,
        "selection": list(plan.selection),
        "config_snapshots": [dict(e) for e in plan.config_entries],
        "seed_policy": {
            "episode_seed_formula": "episode_seed = config_seed + episode_index",
            "config_seed_scope": "global-1-based-position-in-manifest",
        },
        "excluded_episodes": plan.excluded_episodes,
        "status": "created",
        "created_at": now,
        "updated_at": now,
        "artifact_manifest_written": False,
        "failure": None,
        "episodes": [
            {
                "episode_id": ep.episode_id,
                "config_id": ep.config_id,
                "index": ep.index,
                "seed": ep.seed,
                "status": "pending",
            }
            for ep in plan.episodes
        ],
    }


def _episode_config(entry: dict[str, Any], episode_id: str) -> EpisodeConfig:
    return EpisodeConfig(
        episode_id=episode_id,
        mode=EpisodeMode(entry["mode"]),
        defense=DefenseType(entry["defenses"][0]),
        attacker_tier=AttackerTier(entry["attacker_tier"]),
        target_tier=TargetTier(entry["target_tier"]),
        max_rounds=entry["max_rounds"],
        task_description=(
            f"[{entry['config_id']}] {DEFAULT_TASK_DESCRIPTION}"
        ),
        attack_goal=DEFAULT_ATTACK_GOAL,
    )


def _reconcile_with_records(
    meta: dict[str, Any], records_by_id: dict[str, dict[str, Any]]
) -> None:
    """Trust terminal records over checkpoint statuses (crash window).

    A checkpoint claiming ``completed`` without a matching terminal record is
    corruption and fails closed — an incomplete episode is never treated as
    completed.
    """
    for ep in meta["episodes"]:
        record = records_by_id.get(ep["episode_id"])
        if record is not None:
            ep["status"] = record.get("status", ep["status"])
        elif ep.get("status") == "completed":
            raise RunStoreError(
                f"episode {ep['episode_id']} is marked completed in the "
                "checkpoint but has no persisted record — refusing to treat "
                "an incomplete episode as completed"
            )
    _recount(meta)


def _recount(meta: dict[str, Any]) -> None:
    counts = {"completed": 0, "failed": 0, "interrupted": 0, "pending": 0}
    for ep in meta["episodes"]:
        status = ep.get("status")
        if status in ("completed", "failed"):
            counts[status] += 1
        elif status == "running":
            counts["interrupted"] += 1
        else:
            counts["pending"] += 1
    meta["counts"] = {
        "planned": len(meta["episodes"]),
        **counts,
        "skipped": int(meta.get("excluded_episodes") or 0),
    }


def execute_run(
    store: RunStore,
    plan: RunPlan,
    *,
    component_factory=None,
    on_event=None,
) -> dict[str, Any]:
    """Execute (or continue) a bounded run exactly as planned.

    ``component_factory(entry, episode_config, seed)`` returns the component
    bundle; tests inject deterministic failures/interruptions through it. The
    default is the deterministic double bundle.
    """
    factory = component_factory or build_components

    if store.exists():
        meta = store.load()
        if meta.get("manifest_sha256") != plan.manifest_sha256:
            raise RunnerError(
                "manifest identity mismatch: this run was created against "
                f"manifest {meta.get('manifest_sha256')}, the current manifest "
                f"hashes to {plan.manifest_sha256}. Refusing to continue "
                "against a changed manifest — start a new run instead."
            )
        planned = [
            (ep["episode_id"], ep["config_id"], ep["seed"]) for ep in meta["episodes"]
        ]
        expected = [
            (ep.episode_id, ep.config_id, ep.seed) for ep in plan.episodes
        ]
        if planned != expected:
            raise RunnerError(
                "selection mismatch: the persisted run's planned episodes do "
                "not match the requested selection/seeds — refusing to "
                "continue (resume with the same selection that created the run)"
            )
        records_by_id = store.read_records()
        _reconcile_with_records(meta, records_by_id)
        store.repair_torn_trailing_record()
        if meta.get("status") == "completed":
            if on_event:
                on_event({"event": "already_completed", "run_id": store.run_id})
            return meta
    else:
        meta = store.create(_new_checkpoint(plan))

    entries = {e["config_id"]: e for e in plan.config_entries}
    # One in-memory MemorySystem per run: procedural success rates accumulate
    # across episodes of this run (adaptive feedback), while episodic memory
    # stays keyed per episode. Persisted state is owned by the RunStore only.
    shared_memory = MemorySystem()

    meta["status"] = "running"
    meta["updated_at"] = _utcnow()
    store.save(meta)

    try:
        for ep in meta["episodes"]:
            if ep["status"] in ("completed", "failed"):
                continue  # never rerun terminal episodes
            entry = entries[ep["config_id"]]
            episode_config = _episode_config(entry, ep["episode_id"])
            ep["status"] = "running"
            meta["updated_at"] = _utcnow()
            store.save(meta)
            if on_event:
                on_event({"event": "episode_started", "episode_id": ep["episode_id"]})

            started_at = _utcnow()
            try:
                components = factory(entry, episode_config, ep["seed"])
                controller = Controller(
                    attacker=components["attacker"],
                    target_agent=components["target"],
                    defense_layer=components["defense_layer"],
                    defense_adapter=components["defense_adapter"],
                    diagnoser=components["diagnoser"],
                    memory_system=components.get("memory") or shared_memory,
                    metrics_collector=components["metrics"],
                )
                result = controller.run_episode(episode_config)
                result.diagnostics = {
                    **(result.diagnostics or {}),
                    "engine": plan.engine,
                    "config_id": ep["config_id"],
                    "episode_index": ep["index"],
                    "seed": ep["seed"],
                    "implementations": components.get("implementations", {}),
                }
                record = {
                    "episode_id": ep["episode_id"],
                    "config_id": ep["config_id"],
                    "episode_index": ep["index"],
                    "seed": ep["seed"],
                    "status": EpisodeStatus.COMPLETED.value,
                    "engine": plan.engine,
                    "started_at": started_at,
                    "finished_at": _utcnow(),
                    "result": episode_result_to_dict(result),
                    "failure": None,
                }
                store.append_episode(record)
                ep["status"] = EpisodeStatus.COMPLETED.value
                if on_event:
                    on_event(
                        {
                            "event": "episode_finished",
                            "episode_id": ep["episode_id"],
                            "status": EpisodeStatus.COMPLETED.value,
                            "outcome": result.outcome.value,
                        }
                    )
            except Exception as exc:  # noqa: BLE001 - failure IS the recorded outcome
                record = {
                    "episode_id": ep["episode_id"],
                    "config_id": ep["config_id"],
                    "episode_index": ep["index"],
                    "seed": ep["seed"],
                    "status": EpisodeStatus.FAILED.value,
                    "engine": plan.engine,
                    "started_at": started_at,
                    "finished_at": _utcnow(),
                    "result": None,
                    "failure": {
                        "type": type(exc).__name__,
                        "message": _redact(str(exc))[:2000],
                        "traceback": _redact(
                            traceback.format_exc(limit=8)
                        )[:4000],
                    },
                }
                store.append_episode(record)
                ep["status"] = EpisodeStatus.FAILED.value
                if on_event:
                    on_event(
                        {
                            "event": "episode_finished",
                            "episode_id": ep["episode_id"],
                            "status": EpisodeStatus.FAILED.value,
                            "failure": record["failure"]["type"],
                        }
                    )
            _recount(meta)
            meta["updated_at"] = _utcnow()
            store.save(meta)
    except BaseException as exc:  # KeyboardInterrupt/crash path
        meta["status"] = "interrupted"
        meta["failure"] = {
            "type": type(exc).__name__,
            "message": _redact(str(exc))[:500],
        }
        meta["updated_at"] = _utcnow()
        _recount(meta)
        store.save(meta)
        raise

    failed = meta["counts"]["failed"]
    meta["status"] = "completed" if failed == 0 else "failed"
    store.write_artifact_manifest(meta)
    meta["artifact_manifest_written"] = True
    meta["updated_at"] = _utcnow()
    _recount(meta)
    store.save(meta)
    return meta


def resume_run(
    store: RunStore,
    plan: RunPlan,
    *,
    component_factory=None,
    on_event=None,
) -> dict[str, Any]:
    """Continue an interrupted run; completed episodes are never re-run.

    Fails closed on: corrupt checkpoint, manifest identity change, artifact
    modification since finalization, or selection mismatch.
    """
    meta = store.load()  # raises RunStoreError on corrupt/missing
    if meta.get("manifest_sha256") != plan.manifest_sha256:
        raise RunnerError(
            "manifest changed since this run was created "
            f"(recorded {meta.get('manifest_sha256')}, current "
            f"{plan.manifest_sha256}) — refusing to resume. Restore the "
            "original manifest or start a new run."
        )
    integrity = store.integrity()
    if integrity.get("status") == "modified":
        raise RunnerError(
            "persisted artifacts were modified since finalization — refusing "
            "to resume (integrity is hash-based bookkeeping, see ADR-017)"
        )
    return execute_run(store, plan, component_factory=component_factory, on_event=on_event)


def run_status(store: RunStore) -> dict[str, Any]:
    """Persisted run state: counts, status, artifact locations + integrity."""
    meta = store.load()
    _recount(meta)
    return {
        "kind": "experiment_run_status",
        "run_id": meta.get("run_id"),
        "status": meta.get("status"),
        "engine": meta.get("engine"),
        "provider_mode": meta.get("provider_mode"),
        "manifest_sha256": meta.get("manifest_sha256"),
        "selection": meta.get("selection"),
        "counts": meta["counts"],
        "created_at": meta.get("created_at"),
        "updated_at": meta.get("updated_at"),
        "failure": meta.get("failure"),
        "artifacts": {
            "run_dir": str(store.run_dir),
            "checkpoint": str(store.checkpoint_path),
            "episode_records": str(store.episodes_path),
            "artifact_manifest": str(store.artifact_manifest_path),
        },
        "artifact_integrity": store.integrity(),
    }


__all__ = [
    "ENGINE_DETERMINISTIC",
    "ENGINE_LLM",
    "PreflightError",
    "execute_run",
    "manifest_identity",
    "preflight",
    "resume_run",
    "run_status",
]
