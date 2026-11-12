"""Tests for frontend server adaptive endpoints and target discovery."""

from __future__ import annotations

import json
from http.server import HTTPServer
from threading import Thread
import urllib.request
import urllib.error
import pytest

from frontend.server import DemoHandler


@pytest.fixture(autouse=True)
def _isolated_connection_store(monkeypatch, tmp_path):
    """No test may inherit the developer's active dashboard connection.

    The run endpoint intentionally uses the active connection when no target is
    supplied; without isolation these tests would invoke a real model.
    """
    from backend import connections
    from backend.adaptive_harness import AdaptiveHarness
    from frontend import server as frontend_server

    store = connections.ConnectionStore(tmp_path / "connections.json")
    monkeypatch.setattr(connections, "get_store", lambda: store)
    harness = AdaptiveHarness(store_path=str(tmp_path / "adaptive.json"))
    monkeypatch.setattr(frontend_server, "get_harness", lambda: harness)
    return store


@pytest.fixture(scope="module")
def frontend_test_server():
    server = HTTPServer(("127.0.0.1", 0), DemoHandler)
    port = server.server_port
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "Nemesis-Test"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post(url: str, body: dict) -> tuple[int, dict]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Nemesis-Test"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_frontend_server_targets_endpoint(frontend_test_server):
    data = _get(f"{frontend_test_server}/api/targets")
    assert isinstance(data, list)
    target_ids = [t["target_id"] for t in data]
    assert "fake-target" in target_ids
    assert "email-demo-target" in target_ids


def test_frontend_server_adaptive_status(frontend_test_server):
    data = _get(f"{frontend_test_server}/api/adaptive/status")
    assert "running" in data
    assert "search_mode" in data
    assert "candidates" in data


def test_frontend_server_adaptive_run_synchronous(frontend_test_server):
    status_code, body = _post(
        f"{frontend_test_server}/api/adaptive/run",
        {
            "episodes": 2,
            "max_rounds": 1,
            "iterations": 1,
            "mode": "greedy",
            "defense": "marker",
            "background": False,
        },
    )
    assert status_code == 200
    assert body.get("started") is True
    assert body["run"]["status"] in ("completed", "converged", "running")

    # Verify status now contains candidates
    status = _get(f"{frontend_test_server}/api/adaptive/status")
    candidates = status["candidates"]
    assert len(candidates) > 0
    cand_id = candidates[0]["candidate_id"]

    # Replay defense evaluation through the frontend server. The honest
    # contract: a finding WITH a confirmed successful case replays (200 with a
    # linked, evidence-backed result); a finding with no replayable case is
    # refused (409 with an accurate reason) — never an empty 200 that could
    # look like a completed comparison.
    eval_code, eval_body = _post(
        f"{frontend_test_server}/api/adaptive/defense_eval",
        # Inline mode is exercised here; the default is a background job.
        {"candidate_id": cand_id, "against": "marker", "sync": True},
    )
    if eval_code == 200:
        assert eval_body["candidate_id"] == cand_id
        assert "verdict" in eval_body["result"]
        # A 200 must carry a real replay, not an empty shell.
        assert eval_body["result"]["episodes_evaluated"] >= 1
    else:
        assert eval_code == 409
        assert "error" in eval_body


def test_frontend_server_resume_no_checkpoint_is_400_or_404(frontend_test_server):
    status_code, body = _post(
        f"{frontend_test_server}/api/adaptive/resume",
        {"run_id": "nonexistent-run-id", "background": False},
    )
    assert status_code in (400, 404)
    assert "error" in body


# --- Phase 6B: explicit provider selection through the HTTP surface --------


def test_frontend_server_status_exposes_provider_and_assistant(frontend_test_server):
    data = _get(f"{frontend_test_server}/api/adaptive/status")
    # Provider selection and assistant provenance are first-class status
    # fields — the dashboard can always state fake vs live honestly.
    assert "provider" in data
    assert "model_request_budget" in data
    assert "assistant" in data


def test_frontend_server_rejects_unknown_provider(frontend_test_server):
    """An unknown provider is an explicit 400 — never a silent fallback."""
    status_code, body = _post(
        f"{frontend_test_server}/api/adaptive/run",
        {
            "episodes": 2,
            "max_rounds": 1,
            "iterations": 1,
            "mode": "greedy",
            "background": False,
            "provider": "bogus-provider",
        },
    )
    assert status_code == 400
    assert "provider" in body["error"]
    # The rejected request started nothing.
    data = _get(f"{frontend_test_server}/api/adaptive/status")
    assert data["provider"] is None


def test_frontend_server_rejects_live_provider_without_credentials(
    frontend_test_server, monkeypatch
):
    """A requested live provider with missing credentials fails loudly with
    the env var named — no key material, no fake fallback, no run."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    status_code, body = _post(
        f"{frontend_test_server}/api/adaptive/run",
        {
            "episodes": 2,
            "max_rounds": 1,
            "iterations": 1,
            "mode": "greedy",
            "background": False,
            "provider": "gemini",
        },
    )
    assert status_code == 400
    assert "GEMINI_API_KEY" in body["error"]
    data = _get(f"{frontend_test_server}/api/adaptive/status")
    assert data["provider"] is None  # selection was refused, not downgraded


def test_frontend_server_fake_provider_run_reports_fake_kind(
    frontend_test_server,
):
    """A run started with the offline fake provider reports kind='fake' and
    its actual model-request telemetry in the persisted run record."""
    status_code, body = _post(
        f"{frontend_test_server}/api/adaptive/run",
        {
            "episodes": 2,
            "max_rounds": 1,
            "iterations": 1,
            "mode": "feedback",
            "defense": "marker",
            "provider": "fake",
            "model_request_budget": 5,
            "background": False,
        },
    )
    assert status_code == 200
    run = body["run"]
    assert run["mode"] == "feedback"  # frontend selection == backend execution
    assert run["assistant"]["provider"] == "fake"
    assert run["assistant"]["kind"] == "fake"
    assert run["assistant"]["model_request_budget"] == 5
    assert isinstance(run["assistant"]["model_calls_consumed"], int)
    assert "model_suggestions" in run
    # Reset the shared harness to the default configuration so later tests
    # see the unconfigured state.
    from frontend.server import get_harness

    get_harness().configure(provider="none")
