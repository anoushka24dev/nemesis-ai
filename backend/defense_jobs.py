"""Background defense-evaluation jobs.

An attacker campaign and a defense evaluation are INDEPENDENT operations. This
module only manages the defense side once an operator explicitly starts one:
it runs the replay in a worker thread, returns a job id immediately, persists
lifecycle state and per-case progress, and deduplicates retried requests.

It never generates attacks, never chooses a campaign, and is never called by
attacker completion. It does not decide verdicts either: the harness and
``backend.defense_eval`` do. Failure and interruption are explicit states,
never a fabricated result.

A job records the selected attacker run, the selected saved case ids, the
original target identity, and the selected defense so a restart can report
exactly what was (or was not) evaluated.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

__all__ = ["DefenseJobManager", "get_manager", "JOB_STATES"]

JOB_STATES = (
    "queued",
    "running",
    "completed",
    "inconclusive",
    "unavailable",
    "technical_failure",
    "interrupted",
)

_ACTIVE_STATES = {"queued", "running"}
_TERMINAL_STATES = set(JOB_STATES) - _ACTIVE_STATES

#: ``defense_eval`` lifecycle states mapped onto the job vocabulary. A defense
#: result with evidence is a *completed* job; an inconclusive replay is still a
#: finished job, not a success.
_RESULT_STATE_MAP = {
    "completed_with_evidence": "completed",
    "completed": "completed",
    "inconclusive": "inconclusive",
    "unavailable": "unavailable",
    "technical_failure": "technical_failure",
    "interrupted": "interrupted",
}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item) for item in value if item is not None and str(item)]


class DefenseJobManager:
    """Thread-backed job runner with a small atomic JSON store."""

    def __init__(self, path: str | Path | None = None) -> None:
        if path is None:
            root = Path(__file__).resolve().parent.parent
            path = root / "results" / "defense_jobs.json"
        self._path = Path(path)
        self._lock = threading.RLock()
        self._jobs: dict[str, dict[str, Any]] = {}
        self._load()
        self._sweep_interrupted()

    # -- persistence ----------------------------------------------------
    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        jobs = data.get("jobs") if isinstance(data, dict) else None
        if not isinstance(jobs, list):
            return
        loaded: dict[str, dict[str, Any]] = {}
        for raw in jobs:
            if not isinstance(raw, dict) or not raw.get("evaluation_id"):
                continue
            job = dict(raw)
            # Backward-compatible normalisation for jobs written before the
            # campaign/case metadata existed.
            job.setdefault("job_id", job["evaluation_id"])
            job.setdefault("warnings", [])
            job.setdefault("errors", [])
            job.setdefault("case_ids", _str_list((job.get("request") or {}).get("case_ids")))
            job.setdefault(
                "source_run_id",
                (job.get("request") or {}).get("run_id")
                or (job.get("request") or {}).get("source_run_id"),
            )
            job.setdefault(
                "defense",
                (job.get("request") or {}).get("defense")
                or (job.get("request") or {}).get("against"),
            )
            loaded[str(job["evaluation_id"])] = job
        self._jobs = loaded

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        payload = {"version": 2, "jobs": list(self._jobs.values())[-50:]}
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(self._path)

    def _sweep_interrupted(self) -> None:
        """A job that was running when the process died cannot still be running.

        Any partial progress is preserved; only the lifecycle state changes and
        an explicit error is written. A restart never turns an unfinished job
        into a completed one.
        """
        changed = False
        for job in self._jobs.values():
            if job.get("state") in _ACTIVE_STATES:
                job["state"] = "interrupted"
                job["error"] = (
                    "the dashboard process stopped while this evaluation was "
                    "running; no verdict was produced"
                )
                job["errors"] = list(job.get("errors") or []) + [job["error"]]
                job["finished_at"] = _now()
                job.setdefault("progress", {})["phase"] = "interrupted"
                changed = True
        if changed:
            self._save()

    # -- API ------------------------------------------------------------
    def get(self, evaluation_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(str(evaluation_id))
            return dict(job) if job else None

    def list(self, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(j) for j in list(self._jobs.values())[-limit:]][::-1]

    def find_active(self, key: str) -> dict[str, Any] | None:
        with self._lock:
            for job in self._jobs.values():
                if job.get("key") == key and job.get("state") in _ACTIVE_STATES:
                    return dict(job)
        return None

    @staticmethod
    def _request_key(request: dict[str, Any]) -> str:
        """Stable identity for duplicate-active suppression.

        The selected saved cases are part of the identity: the same campaign
        and defense with a different case selection is a different request.
        """
        case_ids = _str_list(request.get("case_ids"))
        return "|".join(
            [
                str(request.get("run_id") or request.get("source_run_id") or ""),
                str(request.get("candidate_id") or ""),
                str(request.get("defense") or request.get("against") or ""),
                str(request.get("seed") if request.get("seed") is not None else ""),
                ",".join(sorted(case_ids)) if case_ids else "*",
            ]
        )

    def start(
        self,
        *,
        request: dict[str, Any],
        work: Callable[[dict[str, Any], Callable[[dict[str, Any]], None]], dict[str, Any]],
    ) -> dict[str, Any]:
        """Start a job and return immediately.

        ``work(job, progress)`` runs in the worker; ``progress`` appends real
        per-case information to the persisted job. Duplicate active requests
        return the existing job instead of re-running the evaluation.
        """
        request = dict(request or {})
        key = self._request_key(request)
        case_ids = _str_list(request.get("case_ids"))
        with self._lock:
            active = self.find_active(key)
            if active is not None:
                return active
            evaluation_id = f"deval-{uuid.uuid4().hex[:10]}"
            job = {
                "evaluation_id": evaluation_id,
                "job_id": evaluation_id,
                "key": key,
                "state": "queued",
                "request": dict(request),
                "source_run_id": request.get("run_id") or request.get("source_run_id"),
                "candidate_id": request.get("candidate_id"),
                "defense": request.get("defense") or request.get("against"),
                "case_ids": case_ids,
                "target_identity": request.get("target_identity"),
                "selected_cases": request.get("selected_cases") or [],
                "excluded_cases": request.get("excluded_cases") or [],
                "warnings": _str_list(request.get("warnings")),
                "errors": [],
                "progress": {
                    "phase": "queued",
                    "cases_total": len(case_ids) or request.get("cases_total"),
                    "cases_replayed": 0,
                },
                "result": None,
                "error": None,
                "queued_at": _now(),
                "created_at": _now(),
                "started_at": None,
                "finished_at": None,
            }
            self._jobs[evaluation_id] = job
            self._save()

        def progress(update: dict[str, Any]) -> None:
            if not isinstance(update, dict):
                return
            with self._lock:
                current = self._jobs.get(evaluation_id)
                if current is None:
                    return
                current.setdefault("progress", {}).update(update)
                self._save()

        def runner() -> None:
            with self._lock:
                job = self._jobs.get(evaluation_id)
                if job is None:
                    return
                job["state"] = "running"
                job["started_at"] = _now()
                job["progress"] = {
                    **(job.get("progress") or {}),
                    "phase": "running",
                }
                self._save()
            try:
                result = work(job, progress)
                with self._lock:
                    job = self._jobs[evaluation_id]
                    job["result"] = result
                    state = str(
                        result.get("evaluation_state")
                        or result.get("state")
                        or "completed"
                    )
                    job["state"] = _RESULT_STATE_MAP.get(state, "completed")
                    if state == "completed_with_evidence":
                        job["state"] = "completed"
                    # Selection/target provenance is written by the backend
                    # result; the request metadata is the pre-replay record.
                    if result.get("target_identity"):
                        job["target_identity"] = result["target_identity"]
                    if result.get("selected_case_ids"):
                        job["case_ids"] = _str_list(result.get("selected_case_ids"))
                    if result.get("excluded_cases"):
                        job["excluded_cases"] = list(result.get("excluded_cases") or [])
                    warnings = _str_list(result.get("warnings"))
                    if warnings:
                        job["warnings"] = list(dict.fromkeys(
                            list(job.get("warnings") or []) + warnings
                        ))
                    if result.get("result", {}).get("limitations"):
                        # Limitations are evidence caveats, not errors. Keep
                        # them visible on the job without inflating "warnings".
                        job["limitations"] = list(
                            result["result"].get("limitations") or []
                        )
                    job["finished_at"] = _now()
                    job.setdefault("progress", {})["phase"] = "finished"
                    self._save()
            except Exception as exc:  # noqa: BLE001 - explicit failed state
                with self._lock:
                    job = self._jobs.get(evaluation_id) or {}
                    job["state"] = "technical_failure"
                    job["error"] = f"{type(exc).__name__}: {exc}"
                    job["errors"] = list(job.get("errors") or []) + [job["error"]]
                    job["finished_at"] = _now()
                    job.setdefault("progress", {})["phase"] = "failed"
                    self._save()

        threading.Thread(
            target=runner, name=f"defense-{evaluation_id}", daemon=True
        ).start()
        with self._lock:
            return dict(self._jobs[evaluation_id])


_MANAGER: DefenseJobManager | None = None
_MANAGER_LOCK = threading.Lock()


def get_manager() -> DefenseJobManager:
    global _MANAGER
    with _MANAGER_LOCK:
        if _MANAGER is None:
            _MANAGER = DefenseJobManager()
    return _MANAGER
