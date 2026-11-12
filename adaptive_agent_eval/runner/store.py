"""Durable run checkpoints, episode records, and artifact integrity (Phase 3).

On-disk layout for one run (under ``<runs_dir>/<run_id>/``):

* ``run.json``      — the checkpoint: run identity, manifest hash, selection,
  per-episode statuses, counts. Written **atomically** (temp file + ``os.replace``
  with fsync) so an interrupted write can never leave a truncated checkpoint.
* ``episodes.json`` — append-only episode records, one JSON object per line
  (JSON Lines), each self-contained. Named ``episodes.json`` (not ``.jsonl``)
  so the existing artifact manifest functions cover it unchanged —
  ``adaptive_agent_eval.artifacts`` already reads either shape.
* ``manifest.json`` — the existing artifact manifest
  (:func:`adaptive_agent_eval.artifacts.write_manifest`) written at
  finalization, covering ``episodes.json`` by SHA-256 plus a canonical
  episode-payload hash.

Integrity vs authenticity (same documented limit as ``artifacts.py`` and
ADR-007): hashes here detect later modification, truncation, or deletion;
they are **not** signatures. Anyone who can rewrite the run directory can
rewrite the hashes with it.

Resume reconciliation rule (crash window between record append and checkpoint
save): the appended episode **record** is authoritative — an episode with a
terminal record is never re-executed, and a checkpoint claiming ``completed``
without a matching record is corruption and fails closed.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from adaptive_agent_eval import artifacts
from adaptive_agent_eval.contracts import defense_event_from_dict
from adaptive_agent_eval.models import (
    AttackerTier,
    AttackOutcome,
    AttackPayload,
    DefenseEvent,
    DefenseType,
    EpisodeConfig,
    EpisodeMode,
    EpisodeResult,
    EpisodeStatus,
    GroundTruthOutcome,
    TargetTier,
    ToolCallRequest,
)

RUN_CHECKPOINT_SCHEMA = "nemesis-run-checkpoint/1"
EPISODE_RECORD_SCHEMA = "nemesis-episode-record/1"
CHECKPOINT_NAME = "run.json"
EPISODES_NAME = "episodes.json"

#: Run IDs must be filesystem-safe slugs (no path separators, no surprises).
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class RunStoreError(RuntimeError):
    """The persisted run state is missing, corrupt, or inconsistent."""


def _json_safe(obj: Any) -> Any:
    """Recursively convert dataclasses/enums into JSON-serializable values.

    The controller stores a ``StopCondition`` dataclass in diagnostics; this
    keeps record writing robust without pretending the object was JSON-native.
    """
    from dataclasses import asdict, is_dataclass
    from enum import Enum

    if is_dataclass(obj) and not isinstance(obj, type):
        return _json_safe(asdict(obj))
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# ---------------------------------------------------------------------------
# EpisodeResult serialization (strict deserialization — bad values rejected)
# ---------------------------------------------------------------------------


def episode_config_to_dict(config: EpisodeConfig) -> dict[str, Any]:
    return {
        "episode_id": config.episode_id,
        "mode": config.mode.value,
        "defense": config.defense.value,
        "attacker_tier": config.attacker_tier.value,
        "target_tier": config.target_tier.value,
        "max_rounds": config.max_rounds,
        "task_description": config.task_description,
        "attack_goal": config.attack_goal,
    }


def episode_config_from_dict(data: dict[str, Any]) -> EpisodeConfig:
    return EpisodeConfig(
        episode_id=data["episode_id"],
        mode=EpisodeMode(data["mode"]),
        defense=DefenseType(data["defense"]),
        attacker_tier=AttackerTier(data["attacker_tier"]),
        target_tier=TargetTier(data["target_tier"]),
        max_rounds=data["max_rounds"],
        task_description=data.get("task_description", ""),
        attack_goal=data.get("attack_goal", ""),
    )


def _defense_event_to_dict(event: DefenseEvent) -> dict[str, Any]:
    return {
        "decision": event.decision.value,
        "confidence": event.confidence,
        "evidence": event.evidence,
        "source": event.source.value if event.source is not None else None,
        "latency_ms": event.latency_ms,
        "implementation_type": event.implementation_type.value,
        "experiment_id": event.experiment_id,
        "episode_id": event.episode_id,
        "round_num": event.round_num,
        "timestamp": event.timestamp,
    }


def episode_result_to_dict(result: EpisodeResult) -> dict[str, Any]:
    return {
        "config": episode_config_to_dict(result.config),
        "outcome": result.outcome.value,
        "rounds_used": result.rounds_used,
        "defense_events": [_defense_event_to_dict(e) for e in result.defense_events],
        "payloads": [_json_safe(vars(p)) for p in result.payloads],
        "tool_calls": [_json_safe(vars(t)) for t in result.tool_calls],
        "recovery_rounds": result.recovery_rounds,
        "total_cost_usd": result.total_cost_usd,
        "elapsed_seconds": result.elapsed_seconds,
        "diagnostics": _json_safe(result.diagnostics),
        "status": result.status.value,
        "ground_truth": result.ground_truth.value if result.ground_truth else None,
    }


def episode_result_from_dict(data: dict[str, Any]) -> EpisodeResult:
    """Strict deserialization: invalid enum values raise, never coerce."""
    defense_events = [defense_event_from_dict(e) for e in data.get("defense_events", ())]
    payloads = [
        AttackPayload(
            text=p["text"],
            category=p["category"],
            sophistication_level=p["sophistication_level"],
            a5_category_flag=p.get("a5_category_flag", False),
        )
        for p in data.get("payloads", ())
    ]
    tool_calls = [
        ToolCallRequest(
            tool_name=t["tool_name"],
            arguments=dict(t.get("arguments") or {}),
            raw_text=t.get("raw_text", ""),
        )
        for t in data.get("tool_calls", ())
    ]
    ground_truth = data.get("ground_truth")
    return EpisodeResult(
        config=episode_config_from_dict(data["config"]),
        outcome=AttackOutcome(data["outcome"]),
        rounds_used=data.get("rounds_used", 0),
        defense_events=defense_events,
        payloads=payloads,
        tool_calls=tool_calls,
        recovery_rounds=data.get("recovery_rounds"),
        total_cost_usd=data.get("total_cost_usd", 0.0),
        elapsed_seconds=data.get("elapsed_seconds", 0.0),
        diagnostics=dict(data.get("diagnostics") or {}),
        status=EpisodeStatus(data.get("status", EpisodeStatus.COMPLETED.value)),
        ground_truth=(
            GroundTruthOutcome(ground_truth) if ground_truth is not None else None
        ),
    )


# ---------------------------------------------------------------------------
# RunStore
# ---------------------------------------------------------------------------


class RunStore:
    """Filesystem persistence for one experiment run."""

    def __init__(self, runs_dir: Path | str, run_id: str):
        if not RUN_ID_RE.match(run_id or ""):
            raise RunStoreError(
                f"invalid run id {run_id!r}: must match {RUN_ID_RE.pattern}"
            )
        self.run_id = run_id
        self.run_dir = Path(runs_dir) / run_id
        self.checkpoint_path = self.run_dir / CHECKPOINT_NAME
        self.episodes_path = self.run_dir / EPISODES_NAME
        self.artifact_manifest_path = self.run_dir / artifacts.MANIFEST_NAME

    # -- checkpoint ---------------------------------------------------------

    def exists(self) -> bool:
        return self.checkpoint_path.exists()

    def create(self, meta: dict[str, Any]) -> dict[str, Any]:
        """Create a new run directory; refuses to clobber an existing run."""
        if self.exists():
            raise RunStoreError(
                f"run {self.run_id!r} already exists at {self.run_dir} — duplicate "
                "runs are refused; use `resume` to continue it or choose a new "
                "run id"
            )
        self.run_dir.mkdir(parents=True, exist_ok=True)
        meta = dict(meta)
        meta.setdefault("schema", RUN_CHECKPOINT_SCHEMA)
        meta.setdefault("run_id", self.run_id)
        meta.setdefault("records", {})
        self.save(meta)
        return meta

    def load(self) -> dict[str, Any]:
        """Load and sanity-check the checkpoint; corruption fails closed."""
        if not self.exists():
            raise RunStoreError(
                f"no checkpoint for run {self.run_id!r} at {self.run_dir}"
            )
        try:
            meta = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            raise RunStoreError(
                f"checkpoint for run {self.run_id!r} is unreadable or corrupt "
                f"({exc}); refusing to resume — restore the file or start a new run"
            ) from exc
        if not isinstance(meta, dict) or meta.get("schema") != RUN_CHECKPOINT_SCHEMA:
            got = (
                meta.get("schema")
                if isinstance(meta, dict)
                else type(meta).__name__
            )
            raise RunStoreError(
                f"checkpoint for run {self.run_id!r} has an unexpected "
                f"schema ({got!r}); refusing to continue"
            )
        if meta.get("run_id") != self.run_id:
            raise RunStoreError(
                f"checkpoint run_id {meta.get('run_id')!r} does not match "
                f"directory {self.run_id!r}"
            )
        return meta

    def save(self, meta: dict[str, Any]) -> None:
        """Atomically write the checkpoint (temp file + os.replace, fsynced)."""
        meta = dict(meta)
        meta["schema"] = RUN_CHECKPOINT_SCHEMA
        meta["run_id"] = self.run_id
        payload = json.dumps(meta, indent=2, ensure_ascii=False)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.run_dir / (CHECKPOINT_NAME + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        try:
            os.write(fd, payload.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.checkpoint_path)

    # -- episode records ----------------------------------------------------

    def append_episode(self, record: dict[str, Any]) -> None:
        """Append one self-contained episode record (line + fsync)."""
        record = dict(record)
        record.setdefault("schema", EPISODE_RECORD_SCHEMA)
        record.setdefault("run_id", self.run_id)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        with self.episodes_path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def read_records(self) -> dict[str, dict[str, Any]]:
        """Load records keyed by episode_id.

        A torn **final** line (interrupted append) is ignored with the episode
        treated as *not completed*; corruption anywhere else, or duplicate
        records for one episode, raises — an inconsistent log can never be
        mistaken for completed work.
        """
        if not self.episodes_path.exists():
            return {}
        text = self.episodes_path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        records: dict[str, dict[str, Any]] = {}
        for position, line in enumerate(lines):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                if position == len(lines) - 1:
                    # Torn trailing write from an interrupted append: the
                    # episode it describes is NOT completed.
                    continue
                raise RunStoreError(
                    f"episode log for run {self.run_id!r} is corrupt at line "
                    f"{position + 1}; refusing to continue"
                ) from None
            if not isinstance(parsed, dict):
                raise RunStoreError(
                    f"episode log for run {self.run_id!r} has a non-object "
                    f"record at line {position + 1}"
                )
            episode_id = parsed.get("episode_id")
            if not episode_id:
                raise RunStoreError(
                    f"episode record at line {position + 1} has no episode_id"
                )
            if episode_id in records:
                raise RunStoreError(
                    f"duplicate episode record for {episode_id!r} in run "
                    f"{self.run_id!r}; refusing to treat duplicates as completed"
                )
            records[episode_id] = parsed
        return records

    def repair_torn_trailing_record(self) -> bool:
        """Remove a torn final line left by an interrupted append.

        Called on resume before new records are appended, so recovery from an
        interruption mid-write is possible. Returns ``True`` when a torn tail
        was removed. Mid-file corruption is NEVER repaired — that fails
        closed in :meth:`read_records`.
        """
        if not self.episodes_path.exists():
            return False
        text = self.episodes_path.read_text(encoding="utf-8")
        lines = text.splitlines(keepends=True)
        idx = len(lines) - 1
        while idx >= 0 and not lines[idx].strip():
            idx -= 1
        if idx < 0:
            return False
        try:
            json.loads(lines[idx])
        except json.JSONDecodeError:
            kept = "".join(lines[:idx])
            tmp = self.episodes_path.with_suffix(".json.tmp")
            tmp.write_text(kept, encoding="utf-8", newline="\n")
            os.replace(tmp, self.episodes_path)
            return True
        return False

    # -- integrity ----------------------------------------------------------

    def write_artifact_manifest(self, meta: dict[str, Any]) -> dict[str, Any]:
        """Cover persisted artifacts with the existing artifact manifest."""
        return artifacts.write_manifest(
            self.run_dir,
            extra={
                "run_id": self.run_id,
                "manifest_sha256": meta.get("manifest_sha256"),
                "run_status": meta.get("status"),
            },
        )

    def integrity(self) -> dict[str, Any]:
        """Artifact integrity status (hash-based; see module docstring)."""
        if not self.artifact_manifest_path.exists():
            return {
                "status": "not_finalized",
                "detail": "no artifact manifest yet — run has not been finalized",
            }
        report = artifacts.verify_artifacts(self.run_dir)
        return {
            "status": "ok" if report.get("ok") else "modified",
            "report": report,
        }
