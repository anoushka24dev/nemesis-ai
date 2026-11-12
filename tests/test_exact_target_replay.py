"""Exact-target defense replay.

The defense phase must replay a saved case against the target recorded in the
source run, never the target currently selected in the dashboard. A case whose
target cannot be restored is ``unavailable`` — never a confirmed verdict.
"""

from __future__ import annotations

from backend.adaptive_harness import AdaptiveHarness


def _candidate(harness: AdaptiveHarness, candidate_id: str, *, trace):
    harness._state["candidates"].append(
        {
            "candidate_id": candidate_id,
            "ladder": [{"category": "obfuscation", "sophistication_level": 1}],
            "evaluation": {
                "total_episodes": len(trace),
                "asr": 0.5,
                "episode_trace": trace,
            },
            "baseline_asr": 0.0,
            "asr": 0.5,
            "status": "rejected",
            "gate": {},
            "created_at": "",
        }
    )


def _run(harness: AdaptiveHarness, candidate_id: str, *, snapshot):
    harness._state["runs"].append(
        {
            "run_id": f"run-{candidate_id}",
            "candidate_id": candidate_id,
            "status": "completed",
            "seed": 7,
            "defense": "marker",
            "mode": "greedy",
            "target_snapshot": snapshot,
        }
    )


def test_replay_uses_recorded_target_after_dashboard_target_changes(tmp_path):
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "exact.json"), target="local-byoa-fixture"
    )
    snapshot = harness.target_snapshot()
    assert snapshot["target_id"] == "local-byoa-fixture"

    _candidate(
        harness,
        "cand-exact",
        trace=[
            {
                "case_id": "cand-exact:ep0",
                "episode": 0,
                "outcome": "success",
                "observed_outcome": "success",
                "defense_decision": "allowed",
                "steps": [{"category": "obfuscation", "sophistication_level": 1}],
            }
        ],
    )
    _run(harness, "cand-exact", snapshot=snapshot)

    # The dashboard now selects a DIFFERENT target.
    harness.configure(target="fake-target")
    assert harness.target_identity()["target_id"] == "fake-target"

    entry = harness.defense_evaluation("cand-exact", against="marker")
    result = entry["result"]

    assert result["unavailable"] is not True
    assert entry["target_available"] is True
    assert entry["replay_target"]["target_id"] == "local-byoa-fixture"
    assert entry["target_identity"]["target_id"] == "local-byoa-fixture"
    assert result["replay_basis"] == "exact_saved_cases"
    # The replayed episode itself reports the recorded target, not the
    # dashboard's current selection.
    for episode in result["episodes"]:
        assert episode["target_identity"]["target_id"] == "local-byoa-fixture"


def test_legacy_run_without_snapshot_is_unavailable_not_replayed(tmp_path):
    harness = AdaptiveHarness(store_path=str(tmp_path / "legacy.json"))
    _candidate(
        harness,
        "cand-legacy",
        trace=[
            {
                "case_id": "cand-legacy:ep0",
                "episode": 0,
                "outcome": "success",
                "observed_outcome": "success",
                "defense_decision": "allowed",
                "steps": [{"category": "obfuscation", "sophistication_level": 1}],
            }
        ],
    )
    _run(harness, "cand-legacy", snapshot=None)

    entry = harness.defense_evaluation("cand-legacy", against="marker")
    result = entry["result"]

    assert result["unavailable"] is True
    assert result["episodes_evaluated"] == 0
    assert result["states"]["confirmed_blocked"] == 0
    assert entry["target_available"] is False
    assert any("no persisted target snapshot" in lim for lim in result["limitations"])


def test_fingerprint_mismatch_is_unavailable(tmp_path):
    harness = AdaptiveHarness(
        store_path=str(tmp_path / "fp.json"), target="local-byoa-fixture"
    )
    snapshot = dict(harness.target_snapshot())
    snapshot["fingerprint"] = "0" * 64
    _candidate(
        harness,
        "cand-fp",
        trace=[
            {
                "case_id": "cand-fp:ep0",
                "episode": 0,
                "outcome": "success",
                "observed_outcome": "success",
                "defense_decision": "allowed",
                "steps": [{"category": "obfuscation", "sophistication_level": 1}],
            }
        ],
    )
    _run(harness, "cand-fp", snapshot=snapshot)

    entry = harness.defense_evaluation("cand-fp", against="marker")
    assert entry["result"]["unavailable"] is True
    assert entry["target_available"] is False
    assert "fingerprint" in (entry["result"].get("reason") or "")
