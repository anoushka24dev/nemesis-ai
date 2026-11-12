"""Background defense-evaluation job lifecycle."""

from __future__ import annotations

import json
import threading
import time

from backend.defense_jobs import DefenseJobManager


def _wait(manager, evaluation_id, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = manager.get(evaluation_id)
        if job and job["state"] not in {"queued", "running"}:
            return job
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_start_returns_immediately_and_persists_progress(tmp_path):
    manager = DefenseJobManager(tmp_path / "jobs.json")
    release = threading.Event()

    def work(job, progress):
        progress({"phase": "replaying", "cases_replayed": 1, "cases_total": 2})
        release.wait(2)
        return {"evaluation_state": "completed", "verdict": "confirmed_blocked"}

    started = manager.start(request={"candidate_id": "c1", "against": "marker"}, work=work)
    # The caller gets control back before the work finishes.
    assert started["state"] in {"queued", "running"}
    assert started["evaluation_id"].startswith("deval-")

    # A retried request with the same key reuses the active job.
    duplicate = manager.start(request={"candidate_id": "c1", "against": "marker"}, work=work)
    assert duplicate["evaluation_id"] == started["evaluation_id"]

    # Progress observed while running is real, persisted state.
    deadline = time.time() + 2
    while time.time() < deadline:
        job = manager.get(started["evaluation_id"])
        if (job.get("progress") or {}).get("cases_replayed") == 1:
            break
        time.sleep(0.02)
    assert job["progress"]["cases_total"] == 2

    release.set()
    finished = _wait(manager, started["evaluation_id"])
    assert finished["state"] == "completed"
    assert finished["result"]["verdict"] == "confirmed_blocked"

    # Persisted across a manager reload.
    reloaded = DefenseJobManager(tmp_path / "jobs.json")
    saved = reloaded.get(started["evaluation_id"])
    assert saved is not None and saved["state"] == "completed"


def test_worker_failure_is_explicit(tmp_path):
    manager = DefenseJobManager(tmp_path / "jobs.json")

    def work(job, progress):
        raise RuntimeError("replay exploded")

    job = manager.start(request={"candidate_id": "c2", "against": "marker"}, work=work)
    finished = _wait(manager, job["evaluation_id"])
    assert finished["state"] == "technical_failure"
    assert "replay exploded" in finished["error"]


def test_stale_running_job_is_swept_to_interrupted(tmp_path):
    path = tmp_path / "jobs.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "jobs": [
                    {
                        "evaluation_id": "deval-stale",
                        "key": "k",
                        "state": "running",
                        "request": {},
                        "progress": {},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    manager = DefenseJobManager(path)
    job = manager.get("deval-stale")
    assert job["state"] == "interrupted"
    assert "no verdict was produced" in job["error"]
