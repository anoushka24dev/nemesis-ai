"""Independent attacker and defense operations.

The attacker must never create or start a defense job. Defense is a separate,
manual operation over cases already persisted by a completed attacker run, and
it replays exactly the cases the operator selected against the recorded target.
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from backend import defense_jobs
from backend.adaptive_harness import AdaptiveHarness
from backend.defense_jobs import DefenseJobManager


# ---------------------------------------------------------------- helpers ----


def _seed_campaign(
    harness: AdaptiveHarness,
    *,
    candidate_id: str = "cand-campaign",
    run_id: str = "run-campaign",
    seed: int = 5,
    snapshot: dict | None = None,
) -> dict:
    """Persist a completed campaign with two usable and one unusable case."""
    trace = [
        {
            "case_id": f"{candidate_id}:ep0",
            "episode": 0,
            "outcome": "success",
            "observed_outcome": "success",
            "defense_decision": "allowed",
            "steps": [{"category": "obfuscation", "sophistication_level": 1}],
        },
        {
            "case_id": f"{candidate_id}:ep1",
            "episode": 1,
            "outcome": "blocked",
            "observed_outcome": "blocked",
            "defense_decision": "denied",
            "steps": [{"category": "direct_injection", "sophistication_level": 1}],
        },
        {
            "case_id": f"{candidate_id}:ep2",
            "episode": 2,
            "outcome": "success",
            "observed_outcome": "success",
            "defense_decision": "allowed",
            "steps": [{"category": "social_engineering", "sophistication_level": 1}],
        },
    ]
    harness._state["candidates"].append(
        {
            "candidate_id": candidate_id,
            "ladder": [
                {"category": "obfuscation", "sophistication_level": 1}
            ],
            "evaluation": {
                "total_episodes": len(trace),
                "asr": 2 / 3,
                "episode_trace": trace,
            },
            "baseline_asr": 0.0,
            "asr": 2 / 3,
            "status": "accepted",
            "gate": {},
            "created_at": "2026-01-01T00:00:00Z",
        }
    )
    harness._state["runs"].append(
        {
            "run_id": run_id,
            "candidate_id": candidate_id,
            "status": "completed",
            "seed": seed,
            "defense": "marker",
            "mode": "greedy",
            "target": (snapshot or {}).get("target_id"),
            "target_snapshot": snapshot,
            "finished_at": "2026-01-01T00:01:00Z",
        }
    )
    return {
        "run_id": run_id,
        "candidate_id": candidate_id,
        "usable": [f"{candidate_id}:ep0", f"{candidate_id}:ep2"],
        "unusable": f"{candidate_id}:ep1",
        "steps": {f"{candidate_id}:ep0": trace[0]["steps"], f"{candidate_id}:ep2": trace[2]["steps"]},
    }


def _wait(manager, evaluation_id, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = manager.get(evaluation_id)
        if job and job["state"] not in {"queued", "running"}:
            return job
        time.sleep(0.02)
    raise AssertionError("defense job did not finish")


# ------------------------------------------------- harness / manager tests ----


def test_attacker_completion_creates_no_defense_job(tmp_path, monkeypatch):
    manager = DefenseJobManager(tmp_path / "jobs.json")
    monkeypatch.setattr(defense_jobs, "_MANAGER", manager)
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "adaptive.json"), target="local-byoa-fixture"
    )

    result = harness.start(
        episodes=2,
        max_rounds=1,
        iterations=1,
        seed=1,
        total_episode_budget=20,
        provider="rules_only",
        target="local-byoa-fixture",
        background=False,
    )
    run = result["run"]
    # The campaign really completed; no job was created by start or completion.
    assert run["status"] == "completed"
    assert manager.list() == []
    assert harness.completed_attack_runs()  # read-only view is available
    assert manager.list() == []  # building the view does not start anything


def test_defense_replays_exactly_the_selected_case(tmp_path):
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "adaptive.json"), target="local-byoa-fixture"
    )
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())

    entry = harness.defense_evaluation(
        campaign["candidate_id"],
        against="marker",
        run_id=campaign["run_id"],
        case_ids=[campaign["usable"][0]],
    )
    result = entry["result"]

    assert entry["selected_case_ids"] == [campaign["usable"][0]]
    assert entry["replayable_cases"] == 1
    assert result["episodes_evaluated"] == 1
    assert result["replay_basis"] == "exact_saved_cases"
    assert [e["source_case_id"] for e in result["episodes"]] == [campaign["usable"][0]]
    # The unselected usable case and the unusable case are both reported.
    reasons = {c["case_id"]: c["exclusion_reason"] for c in result["excluded_cases"]}
    assert reasons[campaign["usable"][1]] == "not selected by operator"
    assert "confirmed attack" in reasons[campaign["unusable"]]
    # The exact saved steps were replayed, not a regenerated ladder.
    assert result["episodes"][0]["steps"] == campaign["steps"][campaign["usable"][0]]


def test_partial_selection_reports_all_exclusions(tmp_path):
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "adaptive.json"), target="local-byoa-fixture"
    )
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())

    entry = harness.defense_evaluation(
        campaign["candidate_id"],
        against="marker",
        run_id=campaign["run_id"],
        case_ids=[campaign["usable"][1]],
    )
    result = entry["result"]
    assert entry["selected_case_ids"] == [campaign["usable"][1]]
    assert result["episodes_evaluated"] == 1
    assert result["source_cases_available"] == 3
    assert result["source_cases_selected"] == 1
    excluded = {c["case_id"]: c for c in result["excluded_cases"]}
    assert excluded[campaign["usable"][0]]["exclusion_reason"] == "not selected by operator"
    assert excluded[campaign["unusable"]]["usable"] is False


def test_empty_or_unknown_selection_is_unavailable_without_replay(tmp_path):
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "adaptive.json"), target="local-byoa-fixture"
    )
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())

    for selection in ([], ["no-such-case"]):
        entry = harness.defense_evaluation(
            campaign["candidate_id"],
            against="marker",
            run_id=campaign["run_id"],
            case_ids=selection,
        )
        result = entry["result"]
        assert result["unavailable"] is True
        assert result["episodes_evaluated"] == 0
        assert result["states"]["confirmed_blocked"] == 0
        assert entry["selection_error"]
        assert any(
            c.get("exclusion_reason") in {
                "not selected by operator",
                "no such saved case in this run",
            }
            for c in entry["excluded_cases"]
        )


def test_job_metadata_records_campaign_cases_target_and_defense(tmp_path):
    manager = DefenseJobManager(tmp_path / "jobs.json")
    release = threading.Event()

    def work(job, progress):
        progress({"cases_replayed": 1, "cases_total": 2})
        release.wait(2)
        return {
            "evaluation_state": "completed_with_evidence",
            "verdict": "confirmed_blocked",
            "selected_case_ids": ["c:ep0"],
            "target_identity": {"target_id": "local-byoa-fixture", "kind": "fixture"},
            "warnings": ["operator selected one of two eligible cases"],
            "result": {"limitations": ["test limitation"]},
        }

    request = {
        "candidate_id": "cand-c",
        "run_id": "run-c",
        "defense": "camel_real",
        "case_ids": ["c:ep0"],
        "target_identity": {"target_id": "local-byoa-fixture", "kind": "fixture"},
        "excluded_cases": [{"case_id": "c:ep1", "exclusion_reason": "not selected by operator"}],
    }
    job = manager.start(request=request, work=work)
    assert job["source_run_id"] == "run-c"
    assert job["case_ids"] == ["c:ep0"]
    assert job["defense"] == "camel_real"
    assert job["target_identity"]["target_id"] == "local-byoa-fixture"
    assert job["excluded_cases"][0]["case_id"] == "c:ep1"
    assert job["job_id"] == job["evaluation_id"]

    # Same campaign/defense but a different case selection is a different job.
    other = manager.start(
        request={**request, "case_ids": ["c:ep2"]}, work=lambda job, progress: {}
    )
    assert other["evaluation_id"] != job["evaluation_id"]

    release.set()
    finished = _wait(manager, job["evaluation_id"])
    assert finished["state"] == "completed"
    assert finished["warnings"]
    assert finished["result"]["selected_case_ids"] == ["c:ep0"]

    reloaded = DefenseJobManager(tmp_path / "jobs.json")
    saved = reloaded.get(job["evaluation_id"])
    assert saved["source_run_id"] == "run-c"
    assert saved["case_ids"] == ["c:ep0"]
    assert saved["warnings"]


def test_interrupted_job_preserves_partial_metadata_and_never_completes(tmp_path):
    path = tmp_path / "jobs.json"
    path.write_text(
        json.dumps(
            {
                "version": 2,
                "jobs": [
                    {
                        "evaluation_id": "deval-stale",
                        "job_id": "deval-stale",
                        "key": "k",
                        "state": "running",
                        "request": {},
                        "progress": {"cases_replayed": 1, "cases_total": 3},
                        "source_run_id": "run-stale",
                        "case_ids": ["c:ep0", "c:ep1"],
                        "result": None,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    manager = DefenseJobManager(path)
    job = manager.get("deval-stale")
    assert job["state"] == "interrupted"
    assert job["source_run_id"] == "run-stale"
    assert job["case_ids"] == ["c:ep0", "c:ep1"]
    assert job["progress"]["cases_replayed"] == 1
    assert job["result"] is None
    assert "no verdict was produced" in job["error"]


# ------------------------------------------------------------ HTTP surface ----


def _get(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "Nemesis-Test"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _post(url: str, body: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "Nemesis-Test"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


@pytest.fixture
def api(tmp_path, monkeypatch):
    from frontend import server as frontend_server

    harness = AdaptiveHarness(
        store_path=str(tmp_path / "adaptive.json"), target="local-byoa-fixture"
    )
    manager = DefenseJobManager(tmp_path / "jobs.json")
    monkeypatch.setattr(frontend_server, "get_harness", lambda: harness)
    monkeypatch.setattr(defense_jobs, "_MANAGER", manager)

    server = ThreadingHTTPServer(("127.0.0.1", 0), frontend_server.DemoHandler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", harness, manager
    finally:
        server.shutdown()
        server.server_close()


def test_http_attacker_run_never_creates_a_defense_job(api):
    base, harness, manager = api
    status, body = _post(
        f"{base}/api/adaptive/run",
        {
            "target": "local-byoa-fixture",
            "provider": "rules_only",
            "episodes": 2,
            "max_rounds": 1,
            "iterations": 1,
            "seed": 1,
            "total_episode_budget": 20,
            "background": False,
        },
    )
    assert status == 200, body
    assert body["run"]["status"] == "completed"
    assert manager.list() == []
    _, jobs = _get(f"{base}/api/adaptive/defense_eval/jobs")
    assert jobs["jobs"] == []


def test_http_campaigns_are_read_only_and_show_case_eligibility(api):
    base, harness, manager = api
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())

    status, body = _get(f"{base}/api/adaptive/defense_campaigns")
    assert status == 200
    entry = next(c for c in body["campaigns"] if c["run_id"] == campaign["run_id"])
    assert entry["eligible"] is True
    assert entry["usable_cases"] == 2
    assert entry["target_identity"]["target_id"] == "local-byoa-fixture"
    by_id = {c["case_id"]: c for c in entry["cases"]}
    assert by_id[campaign["unusable"]]["usable"] is False
    assert manager.list() == []  # reading campaigns starts nothing


def test_http_manual_defense_uses_exact_cases_and_separate_job(api):
    base, harness, manager = api
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())

    status, start = _post(
        f"{base}/api/adaptive/defense_eval",
        {
            "run_id": campaign["run_id"],
            "case_ids": [campaign["usable"][0], campaign["usable"][1]],
            "defense": "marker",
        },
    )
    assert status == 202, start
    evaluation_id = start["evaluation_id"]
    assert evaluation_id.startswith("deval-")
    job = start["job"]
    assert job["source_run_id"] == campaign["run_id"]
    assert job["case_ids"] == [campaign["usable"][0], campaign["usable"][1]]
    assert job["defense"] == "marker"
    assert job["target_identity"]["target_id"] == "local-byoa-fixture"

    finished = _wait(manager, evaluation_id)
    assert finished["state"] in {"completed", "inconclusive"}
    entry = finished["result"]
    assert entry["source_run_id"] == campaign["run_id"]
    assert entry["selected_case_ids"] == [
        campaign["usable"][0],
        campaign["usable"][1],
    ]
    assert entry["result"]["episodes_evaluated"] == 2
    assert {
        e["source_case_id"] for e in entry["result"]["episodes"]
    } == set(campaign["usable"])

    # Refresh/status reads must not start another job.
    _, status_body = _get(
        f"{base}/api/adaptive/defense_eval/status?evaluation_id={evaluation_id}"
    )
    assert status_body["job"]["evaluation_id"] == evaluation_id
    _, jobs = _get(f"{base}/api/adaptive/defense_eval/jobs")
    assert len(jobs["jobs"]) == 1


def test_http_empty_and_foreign_case_selections_are_refused(api):
    base, harness, manager = api
    first = _seed_campaign(
        harness, candidate_id="cand-a", run_id="run-a",
        snapshot=harness.target_snapshot(),
    )
    _seed_campaign(
        harness, candidate_id="cand-b", run_id="run-b",
        snapshot=harness.target_snapshot(),
    )

    status, body = _post(
        f"{base}/api/adaptive/defense_eval",
        {"run_id": first["run_id"], "case_ids": [], "defense": "marker"},
    )
    assert status == 400
    assert "empty selection" in body["error"] or "non-empty" in body["error"]

    # A case id from another campaign can never be substituted.
    status, body = _post(
        f"{base}/api/adaptive/defense_eval",
        {
            "run_id": first["run_id"],
            "case_ids": ["cand-b:ep0"],
            "defense": "marker",
        },
    )
    assert status == 409
    assert body["eligible_case_ids"] == first["usable"]
    foreign = next(
        c for c in body["excluded_cases"] if c["case_id"] == "cand-b:ep0"
    )
    assert foreign["exclusion_reason"] == "no such saved case in this run"
    assert manager.list() == []


def test_http_failed_defense_preserves_attacker_campaign(api, monkeypatch):
    base, harness, manager = api
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())

    def _explode(*args, **kwargs):
        raise RuntimeError("replay exploded")

    monkeypatch.setattr(harness, "defense_evaluation", _explode)
    status, start = _post(
        f"{base}/api/adaptive/defense_eval",
        {
            "run_id": campaign["run_id"],
            "case_ids": [campaign["usable"][0]],
            "defense": "marker",
        },
    )
    assert status == 202
    finished = _wait(manager, start["evaluation_id"])
    assert finished["state"] == "technical_failure"
    assert "replay exploded" in finished["error"]

    # The attacker campaign and its saved cases are untouched.
    run = harness.attack_run(campaign["run_id"])
    assert run is not None and run["status"] == "completed"
    status, body = _get(f"{base}/api/adaptive/defense_campaigns")
    again = next(c for c in body["campaigns"] if c["run_id"] == campaign["run_id"])
    assert again["usable_cases"] == 2


def test_http_dashboard_refresh_never_builds_or_runs_a_defense(api, monkeypatch):
    """Dashboard loading/polling/history is attack-only.

    Every read endpoint is hit repeatedly with the defense builder booby-
    trapped: a single call would raise and fail the request. No job may be
    created and the campaign evidence must stay intact.
    """
    base, harness, manager = api
    campaign = _seed_campaign(harness, snapshot=harness.target_snapshot())
    before = harness.attack_run(campaign["run_id"])
    assert before is not None

    def _explode(*_args, **_kwargs):
        raise AssertionError("dashboards must never build a defense")

    backend_harness = sys.modules["backend.adaptive_harness"]
    monkeypatch.setattr(backend_harness, "_build_defense", _explode)

    for _ in range(3):
        for path in (
            "/api/adaptive/status",
            "/api/adaptive/defense_campaigns",
            "/api/adaptive/defense_eval/jobs",
            "/api/adaptive/defenses",
        ):
            status, body = _get(f"{base}{path}")
            assert status == 200, (path, body)

    assert manager.list() == []
    assert harness.status()["defense_evaluations"] == []
    after = harness.attack_run(campaign["run_id"])
    assert after["status"] == before["status"]
    assert after["candidate_id"] == before["candidate_id"]
