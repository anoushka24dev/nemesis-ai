"""Pre-execution gateway tests: deny never invokes the executor."""
from __future__ import annotations

import pytest

from backend.pre_execution import (
    AUTHORIZATION_FAILED,
    BENIGN_ALLOWED,
    PREVENTED,
    REPLAY_REJECTED,
    run_suite,
)

DEFENSES = ("camel_real", "progent_real", "verifier")


def _run():
    return {
        "run_id": "prex-test-campaign",
        "candidate_id": "cand-test",
        "status": "completed",
        "global_best_category": "Unauthorized data access",
        "target_snapshot": {"kind": "cooperative_local"},
        "episode_trace": [
            {
                "case_id": "prex-test-campaign:ep0",
                "outcome": "success",
                "observed_outcome": "success",
                "steps": [{"category": "direct_injection", "sophistication_level": 5}],
            },
            {
                "case_id": "prex-test-campaign:ep1",
                "outcome": "success",
                "observed_outcome": "success",
                "steps": [{"category": "direct_injection", "sophistication_level": 5}],
            },
        ],
    }


@pytest.mark.parametrize("defense", DEFENSES)
def test_malicious_is_denied_before_executor(defense):
    suite = run_suite(_run(), defense, persist=False)
    prevented = [r for r in suite["records"] if r["verdict"] == PREVENTED]
    assert len(prevented) == 2
    for record in prevented:
        assert record["decision"] == "deny"
        assert record["executor_invoked"] is False
        assert record["executor_invocations_before"] == record["executor_invocations_after"]
        assert record["action_result"] is None
        assert record["enforcement_boundary"] == "before_execution"
    assert suite["prevention_rate"] == 1.0


@pytest.mark.parametrize("defense", DEFENSES)
def test_benign_is_allowed_and_executor_called(defense):
    suite = run_suite(_run(), defense, persist=False)
    benign = [r for r in suite["records"] if r["verdict"] == BENIGN_ALLOWED]
    assert len(benign) == 1
    assert benign[0]["decision"] == "allow"
    assert benign[0]["executor_invoked"] is True
    assert benign[0]["action_result"]["tool_name"] == "read email"
    assert suite["false_positive_rate"] == 0.0


@pytest.mark.parametrize("defense", DEFENSES)
def test_tampered_and_replayed_authorization_never_execute(defense):
    suite = run_suite(_run(), defense, persist=False)
    verdicts = {r["verdict"] for r in suite["records"]}
    assert AUTHORIZATION_FAILED in verdicts
    assert REPLAY_REJECTED in verdicts
    for record in suite["records"]:
        if record["verdict"] in (AUTHORIZATION_FAILED, REPLAY_REJECTED):
            assert record["executor_invoked"] is False
            assert record["action_result"] is None


def test_http_target_is_classified_unsupported_for_pre_execution():
    run = _run()
    run["target_snapshot"] = {"kind": "http_api"}
    suite = run_suite(run, "verifier", persist=False)
    assert suite["original_target_supports_pre_execution"] is False
    assert "cooperative local target" in suite["original_target_note"]
