"""Lifecycle and single-connection-UI regression tests.

These tests exercise the real AdaptiveHarness pause gate (not a status-only
toggle): while paused no new candidate evaluation may start, resume continues
the same run, and Stop while paused terminates it.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest

from backend.adaptive_harness import (
    AdaptiveHarness,
    CheckpointError,
    evaluate_strategy,
)
from frontend.server import build_overview


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


def test_pause_gate_blocks_new_episodes_inside_one_evaluation():
    """The pause gate must hold between episodes, not only between candidates.

    Without this, Pause pressed during a multi-episode evaluation kept starting
    that evaluation's remaining episodes and the control looked unresponsive.
    """
    pause_event = threading.Event()
    resume_event = threading.Event()
    stop_event = threading.Event()
    pause_event.set()
    finished = threading.Event()
    holder: dict = {}

    def run() -> None:
        holder["eval"] = evaluate_strategy(
            [{"category": "direct_injection", "sophistication_level": 1}],
            episodes=2,
            max_rounds=1,
            seed=3,
            stop_event=stop_event,
            pause_event=pause_event,
            resume_event=resume_event,
        )
        finished.set()

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    try:
        assert not finished.wait(0.5), "a paused gate must not start an episode"
        pause_event.clear()
        resume_event.set()
        assert finished.wait(30), "the evaluation did not resume"
        assert holder["eval"].total_episodes == 2
    finally:
        stop_event.set()
        resume_event.set()
        worker.join(timeout=5)


def test_harness_passes_the_pause_gate_to_the_real_evaluation_loop():
    harness = AdaptiveHarness(store_path=None)
    assert harness._pause_gate_kwargs(evaluate_strategy) == {
        "pause_event": harness._pause_event,
        "resume_event": harness._resume_event,
    }

    def pinned_double(ladder, *, episodes, max_rounds, seed, strategy_id="", stop_event=None):
        raise AssertionError("not called")

    # A scripted double with a pinned signature keeps working unchanged.
    assert harness._pause_gate_kwargs(pinned_double) == {}


def _finished_harness(tmp_path: Path) -> AdaptiveHarness:
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "state.json"),
        episodes=2,
        max_rounds=1,
        iterations=1,
        mode="greedy",
        defense="marker",
    )
    started = harness.start(
        episodes=2,
        max_rounds=1,
        iterations=1,
        background=False,
        target="fake-target",
    )
    assert started["started"] is True
    assert harness.running is False
    return harness


def test_control_state_explains_a_terminal_run_instead_of_silently_disabling(tmp_path):
    harness = _finished_harness(tmp_path)
    run = harness.status(with_candidates=False)["current_run"]
    assert run["status"] in {"completed", "budget_exhausted", "stopped"}

    control = harness.control_state()
    assert control["can_pause"] is False
    assert control["can_stop"] is False
    # The checkpoint of a finished run is never resumable.
    assert control["can_resume"] is False
    assert control["resume_source"] is None
    assert control["checkpoint"]["resumable"] is False
    assert run["run_id"] in control["reason"]
    assert "already finished" in control["reason"]

    overview = build_overview(harness)
    lifecycle = overview["lifecycle"]
    assert lifecycle["running"] is False
    assert lifecycle["control"]["can_pause"] is False
    assert lifecycle["control"]["reason"] == control["reason"]


def test_control_state_offers_checkpoint_resume_for_an_interrupted_run(tmp_path):
    harness = _finished_harness(tmp_path)
    checkpoint_path = Path(str(tmp_path / "state.json") + ".checkpoint.json")
    data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    interrupted_id = data["run"]["run_id"]
    # What a killed dashboard process leaves behind: a checkpoint whose run is
    # still marked running, and no in-memory worker in the new process.
    data["run"]["status"] = "running"
    checkpoint_path.write_text(json.dumps(data), encoding="utf-8")

    fresh = AdaptiveHarness(
        store_path=str(tmp_path / "state.json"),
        episodes=2,
        max_rounds=1,
        iterations=1,
        mode="greedy",
        defense="marker",
    )
    control = fresh.control_state()
    assert control["can_pause"] is False
    assert control["can_stop"] is False
    assert control["can_resume"] is True
    assert control["resume_source"] == "checkpoint"
    assert control["checkpoint"]["run_id"] == interrupted_id
    assert control["checkpoint"]["resumable"] is True
    assert interrupted_id in control["reason"]


@pytest.mark.parametrize("status", ["completed", "stopped", "failed", "budget_exhausted"])
def test_resume_refuses_every_finished_checkpoint(tmp_path, status):
    harness = _finished_harness(tmp_path)
    checkpoint_path = Path(str(tmp_path / "state.json") + ".checkpoint.json")
    data = json.loads(checkpoint_path.read_text(encoding="utf-8"))
    data["run"]["status"] = status
    checkpoint_path.write_text(json.dumps(data), encoding="utf-8")

    fresh = AdaptiveHarness(
        store_path=str(tmp_path / "state.json"),
        episodes=2,
        max_rounds=1,
        iterations=1,
        mode="greedy",
        defense="marker",
    )
    with pytest.raises(CheckpointError):
        fresh.resume(background=False)
    assert fresh.control_state()["can_resume"] is False


def test_stop_of_a_terminal_run_reports_the_real_reason(tmp_path):
    harness = _finished_harness(tmp_path)
    result = harness.stop()
    assert result["stop_signalled"] is False
    assert result["running"] is False
    assert "already finished" in result["reason"]
    assert harness.pause()["paused"] is False
    assert harness.resume_paused()["resumed"] is False


def test_paused_active_run_reports_resume_not_checkpoint_recovery(tmp_path):
    harness = _slow_harness(tmp_path)
    harness.start(
        episodes=2,
        max_rounds=1,
        iterations=4,
        background=True,
        target="fake-target",
    )
    _wait_until(lambda: harness.running)
    assert harness.pause()["paused"] is True
    control = harness.control_state()
    assert control["can_pause"] is False
    assert control["can_resume"] is True
    assert control["can_stop"] is True
    assert control["resume_source"] == "active_pause"

    assert harness.stop()["stop_signalled"] is True
    _wait_until(lambda: not harness.running)
    stopped = harness.control_state()
    assert stopped["can_resume"] is False
    assert stopped["can_stop"] is False


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
