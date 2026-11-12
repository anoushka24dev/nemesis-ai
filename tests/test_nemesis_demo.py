# -*- coding: utf-8 -*-
"""End-to-end tests for the single ``Start Nemesis Demo`` backend run.

These drive the real orchestrator (architecture documents, adaptive harness,
regression gate, workflow service) through the mounted Stage B routes. They use
the in-memory mock transport only, so no email can leave the process.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.stage_b import create_app
from email_workflow.policy import Policy
from email_workflow.service import EmailWorkflowService

NONCE = "demo-pairing-nonce"
ORIGIN = "chrome-extension://nemesis-demo-test"
SANDBOX = "nemesis-sandbox-b@proton.me"
REPO = Path(__file__).resolve().parents[1]


def _headers():
    return {"origin": ORIGIN, "authorization": f"Bearer {NONCE}"}


def _app(tmp_path, *, recipients=(SANDBOX,)):
    service = EmailWorkflowService(
        policy=Policy(mode="simulation", allowed_recipients=frozenset(recipients))
    )
    return create_app(
        credentials_path=tmp_path / "c.json",
        token_path=tmp_path / "t.json",
        pairing_nonce=NONCE,
        workflow_service=service,
        feedback_store=tmp_path / "fb.json",
        quality_store=tmp_path / "q.json",
        adaptive_store=tmp_path / "adaptive.json",
    )


def _paired_client(tmp_path, **kwargs):
    client = TestClient(_app(tmp_path, **kwargs), follow_redirects=False)
    pair = client.post(
        "/api/v1/stage_b/pair",
        json={"presented_nonce": NONCE, "extension_origin": ORIGIN},
        headers={"origin": ORIGIN},
    )
    assert pair.status_code == 200, pair.text
    return client


def _start(client, body=None):
    resp = client.post(
        "/api/v1/stage_b/nemesis/demo/run", json=body or {}, headers=_headers()
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()["demo"]
    assert payload["run"] is not None
    assert payload["stages"]
    return payload


def _wait(client, timeout=20.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = client.post(
            "/api/v1/stage_b/nemesis/demo/status", headers=_headers()
        )
        assert status.status_code == 200, status.text
        demo = status.json()["demo"]
        if not demo["running"]:
            return demo
        time.sleep(0.05)
    raise AssertionError("demo run did not finish within the timeout")


def test_unpaired_demo_routes_are_rejected(tmp_path):
    client = TestClient(_app(tmp_path), follow_redirects=False)
    for path in ("/run", "/status", "/stop"):
        resp = client.post(f"/api/v1/stage_b/nemesis/demo{path}", headers=_headers())
        assert resp.status_code in (401, 403), (path, resp.status_code)


def test_demo_run_completes_with_real_stages(tmp_path):
    client = _paired_client(tmp_path)
    started = _start(client, {"episodes": 5, "max_rounds": 3, "iterations": 3})
    run = started["run"]
    assert run["run_id"].startswith("demo-")
    assert run["state"] == "running"
    assert len(run["stages"]) == 8

    demo = _wait(client)
    run = demo["run"]
    assert run["state"] == "completed", run.get("error")
    assert run["error"] is None
    assert [s["id"] for s in run["stages"]] == [
        "architecture",
        "scenario",
        "attack_email",
        "evaluation",
        "hillclimb",
        "decision",
        "email",
        "audit",
    ]
    for stage in run["stages"]:
        assert stage["state"] == "done", stage
        assert stage["started_at"] and stage["finished_at"]
        assert stage["detail"]


def test_architecture_documents_are_actually_read(tmp_path):
    client = _paired_client(tmp_path)
    _start(client)
    demo = _wait(client)
    run = demo["run"]
    docs = run["architecture"]["documents"]
    assert docs, "expected at least one architecture document"
    paths = {doc["path"] for doc in docs}
    assert "docs/ARCHITECTURE_DECISIONS.md" in paths
    assert "docs/ARCHITECTURE_PROMPT.md" in paths
    for doc in docs:
        assert doc["bytes"] > 0
        assert len(doc["sha256"]) == 64
        # Only real, existing files are claimed as read.
        assert (REPO / doc["path"]).is_file(), doc["path"]
    rules = run["architecture"]["rules"]
    assert rules
    for rule in rules:
        assert rule["source"] in paths
        assert rule["text"]


def test_hillclimb_metrics_come_from_the_harness(tmp_path):
    client = _paired_client(tmp_path)
    _start(client, {"episodes": 6, "max_rounds": 3, "iterations": 3, "seed": 7})
    demo = _wait(client)
    run = demo["run"]

    hill = run["hillclimb"]
    assert hill["run_id"]
    assert hill["history"], "expected measured candidate evaluations"
    assert hill["baseline_asr"] == pytest.approx(run["evaluation"]["baseline"]["asr"])
    assert hill["candidate_evaluation"]["total_episodes"] >= 6
    assert 0.0 <= hill["baseline_asr"] <= 1.0
    assert 0.0 <= hill["best_asr"] <= 1.0
    assert hill["candidate_asr"] == pytest.approx(
        hill["candidate_evaluation"]["asr"]
    )

    gate = hill["gate"]
    assert isinstance(gate["passed"], bool)
    assert "checked" in gate
    decision = run["decision"]
    assert decision["outcome"] == ("retained" if gate["passed"] else "rejected")
    assert decision["candidate_id"] == hill["candidate_id"]
    if gate["passed"]:
        assert decision["strategy_id"] == hill["candidate_id"]
        assert hill["active_strategy_id"] == hill["candidate_id"]
    else:
        assert decision["strategy_id"] == "baseline"
        assert gate["reasons"]


def test_email_step_is_simulated_and_never_executed(tmp_path):
    client = _paired_client(tmp_path)
    _start(client)
    demo = _wait(client)
    run = demo["run"]

    email = run["email"]
    assert email["status"] == "simulated"
    assert email["simulated"] is True
    assert email["executed"] is False
    assert email["transport_called"] is False
    assert email["recipient"] == SANDBOX
    assert run["mode"] == "SIMULATION"
    assert run["audit"]["workflow_entries"], "expected an audit entry"


def test_email_step_reports_blocked_without_allowlist(tmp_path):
    client = _paired_client(tmp_path, recipients=())
    _start(client)
    run = _wait(client)["run"]

    email = run["email"]
    assert email["status"] == "blocked"
    assert email["executed"] is False
    assert "NEMESIS_ALLOWED_RECIPIENTS" in email["detail"]


def test_duplicate_start_is_refused(tmp_path):
    client = _paired_client(tmp_path)
    first = _start(client)
    second = client.post(
        "/api/v1/stage_b/nemesis/demo/run", json={}, headers=_headers()
    )
    assert second.status_code == 409
    assert "already" in second.json()["error"].lower()
    _wait(client)
    assert first["run"]["run_id"]


def test_status_before_any_run_reports_pending_stages(tmp_path):
    client = _paired_client(tmp_path)
    resp = client.post("/api/v1/stage_b/nemesis/demo/status", headers=_headers())
    demo = resp.json()["demo"]
    assert demo["run"] is None
    assert len(demo["stages"]) == 8
    assert all(stage["state"] == "pending" for stage in demo["stages"])
