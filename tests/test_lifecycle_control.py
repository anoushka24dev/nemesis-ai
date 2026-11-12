"""Lifecycle and single-connection-UI regression tests.

These tests exercise the real AdaptiveHarness pause gate (not a status-only
toggle): while paused no new candidate evaluation may start, resume continues
the same run, and Stop while paused terminates it.
"""

from __future__ import annotations

import time
from pathlib import Path

from backend.adaptive_harness import AdaptiveHarness


def _wait_until(predicate, *, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("condition was not met before timeout")


def _slow_harness(tmp_path: Path) -> AdaptiveHarness:
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "state.json"),
        episodes=2,
        max_rounds=1,
        iterations=4,
        mode="greedy",
        defense="marker",
    )
    original = harness._evaluate

    def slow_evaluate(*args, **kwargs):
        time.sleep(0.6)
        return original(*args, **kwargs)

    harness._evaluate = slow_evaluate  # type: ignore[method-assign]
    return harness


def test_pause_blocks_new_candidates_and_resume_continues_same_run(tmp_path):
    harness = _slow_harness(tmp_path)
    started = harness.start(
        episodes=2,
        max_rounds=1,
        iterations=4,
        mode="greedy",
        defense="marker",
        background=True,
        target="fake-target",
    )
    run_id = started["run"]["run_id"]
    _wait_until(lambda: harness.running)

    paused = harness.pause()
    assert paused["paused"] is True
    before = harness.status(with_candidates=False)["current_run"]["candidate_evaluations"]
    time.sleep(1.8)
    after = harness.status(with_candidates=False)["current_run"]["candidate_evaluations"]
    assert after == before, (before, after)

    resumed = harness.resume_paused()
    assert resumed["resumed"] is True
    assert resumed["run_id"] == run_id
    _wait_until(lambda: not harness.running)
    final = harness.status(with_candidates=False)["current_run"]
    assert final["run_id"] == run_id
    assert final["status"] == "completed"
    assert final["candidate_evaluations"] > before


def test_stop_while_paused_terminates_without_starting_more_candidates(tmp_path):
    harness = _slow_harness(tmp_path)
    started = harness.start(
        episodes=2,
        max_rounds=1,
        iterations=4,
        mode="greedy",
        defense="marker",
        background=True,
        target="fake-target",
    )
    run_id = started["run"]["run_id"]
    _wait_until(lambda: harness.running)
    assert harness.pause()["paused"] is True

    stopped = harness.stop()
    assert stopped["stop_signalled"] is True
    _wait_until(lambda: not harness.running)
    final = harness.status(with_candidates=False)["current_run"]
    assert final["run_id"] == run_id
    assert final["status"] == "stopped"
    assert final["episodes_consumed"] == 0


def test_experiments_page_has_no_duplicate_connection_management():
    text = (Path(__file__).resolve().parents[1] / "frontend" / "index.html").read_text(
        encoding="utf-8"
    )
    experiments = text.split('id="page-experiments"', 1)[1].split(
        'id="page-agents"', 1
    )[0]
    assert "Selected Agent" in experiments
    assert "Manage Connections" in experiments
    assert "Connect Your Agent" not in experiments
    assert "data-connect=" not in experiments
    assert 'id="methodGrid"' not in experiments
    # Gmail connection management is rendered from the backend connection
    # catalog on Agents; no separate hardcoded connector is needed there.
    agents = text.split('id="page-agents"', 1)[1]
    assert "Agents" in agents
    app_js = (Path(__file__).resolve().parents[1] / "frontend" / "app.js").read_text(
        encoding="utf-8"
    )
    assert "data-agent-connect" in app_js
    from backend.connections import CONNECTION_METHODS

    assert "gmail" in {m["method"] for m in CONNECTION_METHODS}
