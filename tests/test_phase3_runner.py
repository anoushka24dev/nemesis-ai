"""Phase 3 runner tests: bounded execution, checkpoints/resume, aggregation.

All execution in this file uses the deterministic engine (real local
defenses + stub attacker/target): zero LLM calls, zero network, zero paid
API usage. The full 26-configuration / 1,300-episode matrix is never launched
here or anywhere else in Phase 3.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from adaptive_agent_eval.experiment_matrix import (
    EPISODES_PER_CONFIG,
    build_manifest,
)
from adaptive_agent_eval.runner import (
    DEFAULT_MAX_EPISODES_PER_RUN,
    HARD_CAP_EPISODES_PER_RUN,
    RunnerError,
    RunStore,
    RunStoreError,
    SelectionError,
    aggregate_run,
    build_components,
    dry_run_summary,
    episode_result_from_dict,
    episode_result_to_dict,
    execute_run,
    preflight,
    resolve_selection,
    resume_run,
    run_status,
)
from adaptive_agent_eval.runner.executor import PreflightError

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def manifest():
    return build_manifest()


@pytest.fixture
def runs_dir(tmp_path):
    d = tmp_path / "runs"
    d.mkdir()
    return str(d)


def _cli(*args, cwd=None):
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, "-m", "adaptive_agent_eval.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(cwd or REPO_ROOT),
        env=env,
        timeout=300,
        check=False,
    )


def _interrupt_at(episode_id: str):
    """Component factory that simulates a crash (Ctrl-C) mid-run."""

    def factory(entry, episode_config, seed):
        if episode_config.episode_id == episode_id:
            raise KeyboardInterrupt(f"simulated interruption at {episode_id}")
        return build_components(entry, episode_config, seed)

    return factory


def _fail_at(episode_id: str, exc: Exception):
    """Component factory where one episode's execution raises ``exc``."""

    def factory(entry, episode_config, seed):
        if episode_config.episode_id == episode_id:
            raise exc
        return build_components(entry, episode_config, seed)

    return factory


# ---------------------------------------------------------------------------
# Selection: valid and invalid
# ---------------------------------------------------------------------------


def test_resolve_selection_valid(manifest):
    plan = resolve_selection(manifest, ["M1-01", "M1-02"], episodes_per_config=2)
    assert [e.episode_id for e in plan.episodes] == [
        "M1-01-E001", "M1-01-E002", "M1-02-E001", "M1-02-E002",
    ]
    assert plan.total_episodes == 4
    assert plan.excluded_episodes == 2 * (EPISODES_PER_CONFIG - 2)


def test_reject_empty_selection(manifest):
    with pytest.raises(SelectionError, match="empty"):
        resolve_selection(manifest, [], episodes_per_config=1)


def test_reject_unknown_id(manifest):
    with pytest.raises(SelectionError, match="unknown configuration id 'M1-99'"):
        resolve_selection(manifest, ["M1-01", "M1-99"], episodes_per_config=1)


def test_reject_malformed_id(manifest):
    with pytest.raises(SelectionError, match="malformed configuration id 'drop-table'"):
        resolve_selection(manifest, ["drop-table"], episodes_per_config=1)


def test_reject_path_traversal_id(manifest):
    with pytest.raises(SelectionError, match="malformed"):
        resolve_selection(manifest, ["../../etc"], episodes_per_config=1)


def test_reject_duplicate_id(manifest):
    with pytest.raises(SelectionError, match="duplicate configuration id"):
        resolve_selection(manifest, ["M1-01", "M1-01"], episodes_per_config=1)


def test_reject_zero_episodes(manifest):
    with pytest.raises(SelectionError, match="episodes_per_config"):
        resolve_selection(manifest, ["M1-01"], episodes_per_config=0)


def test_reject_episodes_above_manifest(manifest):
    with pytest.raises(SelectionError, match="exceeds the manifest"):
        resolve_selection(manifest, ["M1-01"], episodes_per_config=EPISODES_PER_CONFIG + 1)


def test_reject_unknown_provider_mode(manifest):
    with pytest.raises(SelectionError, match="provider mode"):
        resolve_selection(manifest, ["M1-01"], 1, provider_mode="gemini-cloud")


def test_selection_uses_canonical_manifest_order(manifest):
    plan = resolve_selection(manifest, ["M2-01", "M1-05"], episodes_per_config=1)
    assert plan.selection == ["M1-05", "M2-01"]


def test_seed_policy_formula(manifest):
    """episode_seed = config_seed + episode_index, config_seed = index*1000."""
    plan = resolve_selection(
        manifest, ["M1-01", "M2-01"], episodes_per_config=3
    )
    seeds = {(e.config_id, e.index): e.seed for e in plan.episodes}
    assert seeds[("M1-01", 1)] == 1000 + 1  # global index 1
    assert seeds[("M1-01", 3)] == 1000 + 3
    assert seeds[("M2-01", 1)] == 13000 + 1  # global index 13
    # No collisions across configs.
    assert len(set(seeds.values())) == len(seeds)


# ---------------------------------------------------------------------------
# Bounded execution limits and full-matrix refusal
# ---------------------------------------------------------------------------


def test_per_invocation_limit(manifest):
    with pytest.raises(SelectionError, match="per-invocation limit of 10"):
        resolve_selection(
            manifest, ["M1-01", "M1-02", "M1-03"], episodes_per_config=5
        )


def test_hard_cap_cannot_be_raised(manifest):
    with pytest.raises(SelectionError, match="hard per-invocation cap"):
        resolve_selection(
            manifest, ["M1-01"], 1, max_episodes=HARD_CAP_EPISODES_PER_RUN + 1
        )


def test_full_matrix_refused_even_within_limits(manifest):
    all_ids = [e["config_id"] for e in manifest["configurations"]]
    with pytest.raises(SelectionError, match="full 26-configuration"):
        resolve_selection(manifest, all_ids, episodes_per_config=1)


def test_dry_run_may_plan_full_matrix_but_executes_nothing(manifest):
    all_ids = [e["config_id"] for e in manifest["configurations"]]
    plan = resolve_selection(
        manifest, all_ids, EPISODES_PER_CONFIG, enforce_bounded=False
    )
    assert plan.total_episodes == 26 * EPISODES_PER_CONFIG == 1300
    summary = dry_run_summary(plan, manifest)
    assert summary["execution"] == "none"
    assert summary["episodes_executed"] == 0


def test_default_limit_is_conservative():
    assert DEFAULT_MAX_EPISODES_PER_RUN <= 10
    assert DEFAULT_MAX_EPISODES_PER_RUN < 1300


# ---------------------------------------------------------------------------
# Execution: success, determinism, seeds
# ---------------------------------------------------------------------------


def test_execute_completes_bounded_run(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01", "M1-02"], episodes_per_config=2)
    store = RunStore(runs_dir, "run-ok")
    meta = execute_run(store, plan)
    assert meta["status"] == "completed"
    assert meta["counts"] == {
        "planned": 4, "completed": 4, "failed": 0,
        "interrupted": 0, "pending": 0, "skipped": 96,
    }
    records = store.read_records()
    assert len(records) == 4
    for record in records.values():
        assert record["status"] == "completed"
        assert record["engine"] == "deterministic-local"
        assert record["result"]["diagnostics"]["implementations"] == {
            "attacker": "deterministic-double",
            "target": "deterministic-double",
            "defenses": "local-implementation",
            "diagnoser": "local-rule-based",
        }
    status = run_status(store)
    assert status["artifact_integrity"]["status"] == "ok"
    assert (store.run_dir / "manifest.json").exists()


def test_same_seed_reproduces_same_results(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=3)
    store_a = RunStore(runs_dir, "repro-a")
    store_b = RunStore(runs_dir, "repro-b")
    execute_run(store_a, plan)
    execute_run(store_b, plan)

    def fingerprint(store):
        return sorted(
            (
                r["episode_id"],
                r["seed"],
                r["result"]["outcome"],
                r["result"]["rounds_used"],
                [p["text"] for p in r["result"]["payloads"]],
            )
            for r in store.read_records().values()
        )

    assert fingerprint(store_a) == fingerprint(store_b)


def test_records_carry_policy_seeds(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    store = RunStore(runs_dir, "seeds")
    execute_run(store, plan)
    records = store.read_records()
    assert records["M1-01-E001"]["seed"] == 1001
    assert records["M1-01-E002"]["seed"] == 1002
    assert records["M1-01-E002"]["result"]["diagnostics"]["seed"] == 1002


def test_episode_result_roundtrip(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "roundtrip")
    execute_run(store, plan)
    record = next(iter(store.read_records().values()))
    result = episode_result_from_dict(record["result"])
    assert episode_result_to_dict(result) == record["result"]


# ---------------------------------------------------------------------------
# Failure and interruption
# ---------------------------------------------------------------------------


def test_episode_failure_is_recorded_not_silently_success(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=3)
    store = RunStore(runs_dir, "fail")
    meta = execute_run(
        store,
        plan,
        component_factory=_fail_at("M1-01-E002", ValueError("boom in component")),
    )
    assert meta["status"] == "failed"  # run not "completed" with failures present
    assert meta["counts"]["completed"] == 2
    assert meta["counts"]["failed"] == 1
    records = store.read_records()
    failed = records["M1-01-E002"]
    assert failed["status"] == "failed"
    assert failed["result"] is None
    assert failed["failure"]["type"] == "ValueError"
    assert "boom in component" in failed["failure"]["message"]


def test_failure_diagnostics_redact_secret_looking_values(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "redact")
    secret = "AIzaSyFakeKey01234567890123456789012345"
    execute_run(
        store, plan, component_factory=_fail_at("M1-01-E001", RuntimeError(secret))
    )
    record = store.read_records()["M1-01-E001"]
    assert secret not in json.dumps(record)
    assert "[REDACTED]" in record["failure"]["message"]


def test_interruption_then_resume_completes_exactly_once(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=4)
    store = RunStore(runs_dir, "interrupt")

    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E003"))

    meta = store.load()
    assert meta["status"] == "interrupted"
    statuses = {e["episode_id"]: e["status"] for e in meta["episodes"]}
    assert statuses["M1-01-E001"] == "completed"
    assert statuses["M1-01-E002"] == "completed"
    assert statuses["M1-01-E003"] == "running"   # interrupted mid-episode
    assert statuses["M1-01-E004"] == "pending"
    assert len(store.read_records()) == 2

    resumed = resume_run(store, plan)
    assert resumed["status"] == "completed"
    records = store.read_records()
    assert len(records) == 4
    # Each episode recorded exactly once; the two completed before the
    # interruption were not re-executed.
    ids = [r["episode_id"] for r in records.values()]
    assert sorted(ids) == sorted(set(ids)) == [
        "M1-01-E001", "M1-01-E002", "M1-01-E003", "M1-01-E004",
    ]


def test_resume_never_duplicates_records(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    store = RunStore(runs_dir, "dup-resume")
    execute_run(store, plan)
    before = store.episodes_path.read_text(encoding="utf-8")
    resume_run(store, plan)
    resume_run(store, plan)
    assert store.episodes_path.read_text(encoding="utf-8") == before


def test_duplicate_run_creation_refused(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "dupe")
    execute_run(store, plan)
    with pytest.raises(RunStoreError, match="already exists"):
        RunStore(runs_dir, "dupe").create({"status": "created"})


def test_resume_with_different_selection_refused(manifest, runs_dir):
    plan_a = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    plan_b = resolve_selection(manifest, ["M1-01"], episodes_per_config=3)
    store = RunStore(runs_dir, "mismatch")
    execute_run(store, plan_a)
    with pytest.raises(RunnerError, match="selection mismatch"):
        execute_run(store, plan_b)


# ---------------------------------------------------------------------------
# Checkpoint integrity: manifest mismatch, corruption, torn writes
# ---------------------------------------------------------------------------


def test_manifest_hash_mismatch_fails_closed(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "hash")
    execute_run(store, plan)
    meta = store.load()
    meta["manifest_sha256"] = "0" * 64
    store.save(meta)
    with pytest.raises(RunnerError, match="manifest"):
        resume_run(store, plan)


def test_corrupt_checkpoint_fails_closed(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "corrupt")
    execute_run(store, plan)
    store.checkpoint_path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RunStoreError, match="corrupt|unreadable"):
        store.load()


def test_completed_without_record_fails_closed(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    store = RunStore(runs_dir, "ghost")
    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E002"))
    meta = store.load()
    meta["episodes"][1]["status"] = "completed"  # forged: no record exists
    store.save(meta)
    with pytest.raises(RunStoreError, match="no persisted record"):
        resume_run(store, plan)


def test_torn_trailing_record_is_repaired_on_resume(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=3)
    store = RunStore(runs_dir, "torn")
    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E002"))
    # Simulate an append torn mid-write (no newline, partial JSON).
    with store.episodes_path.open("a", encoding="utf-8") as fh:
        fh.write('{"episode_id": "M1-01-E002", "status": "comp')
    # Aggregation still tolerates the torn tail (that episode is NOT completed).
    assert "M1-01-E002" not in store.read_records()
    resumed = resume_run(store, plan)
    assert resumed["status"] == "completed"
    records = store.read_records()
    assert sorted(records) == ["M1-01-E001", "M1-01-E002", "M1-01-E003"]


def test_mid_file_corruption_fails_closed(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    store = RunStore(runs_dir, "midcorrupt")
    execute_run(store, plan)
    lines = store.episodes_path.read_text(encoding="utf-8").splitlines()
    lines[0] = "{{garbage"
    store.episodes_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(RunStoreError, match="corrupt"):
        store.read_records()


def test_duplicate_records_fail_closed(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "duprec")
    execute_run(store, plan)
    record = next(iter(store.read_records().values()))
    store.append_episode(record)
    with pytest.raises(RunStoreError, match="duplicate episode record"):
        store.read_records()


def test_invalid_run_id_rejected(runs_dir):
    for bad in ("../escape", "a/b", "", ".hidden", "x" * 80):
        with pytest.raises(RunStoreError, match="invalid run id"):
            RunStore(runs_dir, bad)


def test_checkpoint_write_is_atomic(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "atomic")
    execute_run(store, plan)
    assert not (store.run_dir / "run.json.tmp").exists()
    json.loads(store.checkpoint_path.read_text(encoding="utf-8"))  # parses


def test_artifact_corruption_detected_and_blocks_resume(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    store = RunStore(runs_dir, "tamper")
    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E002"))
    # Finalize manually, then tamper with the artifact the manifest covers.
    meta = store.load()
    store.write_artifact_manifest(meta)
    text = store.episodes_path.read_text(encoding="utf-8")
    store.episodes_path.write_text(text.replace("completed", "completed "), encoding="utf-8")
    integrity = store.integrity()
    assert integrity["status"] == "modified"
    with pytest.raises(RunnerError, match="modified"):
        resume_run(store, plan)


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def test_aggregation_unavailable_metrics_stay_none(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01", "M1-02"], episodes_per_config=2)
    store = RunStore(runs_dir, "agg")
    execute_run(store, plan)
    summary = aggregate_run(store)
    metrics = summary["overall"]["metrics"]
    # Measured: ASR is a real 0.0 here (denominator exists).
    assert metrics["attack_success_rate"] == 0.0
    assert summary["overall"]["availability"]["attack_success_rate"] == "measured"
    # Not measured: never fabricated as 0.0.
    assert metrics["cost_per_attack"] is None
    assert metrics["utility_score"] is None
    assert metrics["recovery_time"] is None
    assert metrics["rounds_to_success"] is None
    assert metrics["propagation_rate"] is None
    assert metrics["blast_radius"] is None
    for name in ("cost_per_attack", "utility_score", "recovery_time"):
        assert summary["overall"]["availability"][name] == "not_measured"
    assert summary["confidence"] is None
    assert summary["complete"] is True
    assert summary["artifact_integrity"]["status"] == "ok"


def test_aggregation_of_partial_run_is_marked_incomplete(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=4)
    store = RunStore(runs_dir, "partial")
    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E003"))
    summary = aggregate_run(store)
    assert summary["run_status"] == "interrupted"
    assert summary["counts"]["completed"] == 2
    assert summary["counts"]["interrupted"] == 1
    assert summary["counts"]["pending"] == 1
    block = summary["per_config"]["M1-01"]
    assert block["complete"] is False
    assert summary["complete"] is False


def test_aggregation_reports_invalid_persisted_result_honestly(manifest, runs_dir):
    plan = resolve_selection(manifest, ["M1-01"], episodes_per_config=2)
    store = RunStore(runs_dir, "badresult")
    execute_run(store, plan)
    text = store.episodes_path.read_text(encoding="utf-8")
    store.episodes_path.write_text(
        text.replace('"outcome": "', '"outcome": "bogus-', 1),
        encoding="utf-8",
    )
    summary = aggregate_run(store)
    assert summary["integrity_problems"]
    assert summary["per_config"]["M1-01"]["complete"] is False
    assert summary["counts"]["completed"] == 1  # only the valid record counts


def test_aggregation_of_missing_run_fails_closed(runs_dir):
    store = RunStore(runs_dir, "nope")
    with pytest.raises(RunStoreError, match="no checkpoint"):
        aggregate_run(store)


# ---------------------------------------------------------------------------
# Provider / dependency preflight
# ---------------------------------------------------------------------------


def test_preflight_deterministic_ok(manifest):
    report = preflight("deterministic", manifest)
    assert report["ok"] is True
    assert report["engine"] == "deterministic-local"
    assert any(c["check"] == "llm-provider" and c["status"] == "not_required"
               for c in report["checks"])


def test_preflight_llm_fails_early_on_manifest_binding(manifest, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-supersecretvalue123456789")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-antsecretvalue123456789")
    with pytest.raises(PreflightError) as excinfo:
        preflight("llm", manifest)
    message = str(excinfo.value)
    assert "gemini" in message
    assert "openai, anthropic" in message
    # The diagnostic never leaks credential values.
    assert "sk-supersecretvalue123456789" not in message
    assert "sk-antsecretvalue123456789" not in message


def test_preflight_llm_credential_env_check(manifest, monkeypatch):
    manifest = json.loads(json.dumps(manifest))
    manifest["provider_binding"]["provider"] = "openai"
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(PreflightError, match="OPENAI_API_KEY"):
        preflight("llm", manifest)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-present-but-never-printed")
    report = preflight("llm", manifest)
    assert report["ok"] is True
    assert "sk-present-but-never-printed" not in json.dumps(report)


def test_llm_mode_plans_are_labeled_and_never_claim_execution(manifest):
    """llm-mode planning exists but claims zero executed episodes and never
    pretends LLM calls are free-or-absent: the count is unknown, not 0."""
    plan = resolve_selection(manifest, ["M1-01"], 1, provider_mode="llm")
    summary = dry_run_summary(plan, manifest)
    assert summary["engine"] == "llm"
    assert summary["episodes_executed"] == 0
    assert summary["execution"] == "none"
    assert summary["resource_estimate"]["llm_calls"] != 0


# ---------------------------------------------------------------------------
# Gmail read-only / simulation-only preservation
# ---------------------------------------------------------------------------


def test_runner_package_never_touches_gmail():
    runner_dir = REPO_ROOT / "adaptive_agent_eval" / "runner"
    forbidden = (
        "gmail_live", "gmail_auth", "send_message", "delete_message",
        "gmail_send", "modify_message", "add_label", "OAuth2",
    )
    for path in runner_dir.glob("*.py"):
        source = path.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in source, f"{path.name} references {token!r}"


def test_importing_runner_does_not_import_gmail_modules():
    code = (
        "import sys\n"
        "import adaptive_agent_eval.runner\n"
        "leaked = [m for m in sys.modules if m.startswith('gmail')]\n"
        "assert not leaked, leaked\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True,
        encoding="utf-8", errors="replace", cwd=str(REPO_ROOT), timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr


# ---------------------------------------------------------------------------
# CLI: exit codes and behavior (subprocess)
# ---------------------------------------------------------------------------


def test_cli_validate_subcommand_runs_nothing():
    result = _cli("validate")
    assert result.returncode == 0
    assert "Result: VALID" in result.stdout
    assert "no experiment was executed" in result.stdout


def test_cli_dry_run_executes_zero(runs_dir):
    result = _cli("dry-run", "--configs", "M1-01", "M1-02", "--episodes-per-config", "3")
    assert result.returncode == 0
    assert "DRY-RUN OK (episodes_executed=0)" in result.stdout
    assert "zero episodes executed" in result.stdout
    assert os.listdir(runs_dir) == []  # nothing written anywhere for this run dir


def test_cli_run_without_execute_refuses(runs_dir):
    result = _cli(
        "run", "--configs", "M1-01", "--run-id", "noexec",
        "--runs-dir", runs_dir,
    )
    assert result.returncode == 2
    assert "REFUSED" in result.stderr
    assert os.listdir(runs_dir) == []  # zero episodes, zero artifacts


def test_cli_run_with_execute(runs_dir):
    result = _cli(
        "run", "--configs", "M1-01", "M1-02", "--episodes-per-config", "2",
        "--run-id", "clirun", "--runs-dir", runs_dir, "--execute",
    )
    assert result.returncode == 0, result.stderr
    assert "status=completed" in result.stdout
    run_dir = Path(runs_dir) / "clirun"
    assert (run_dir / "run.json").exists()
    assert (run_dir / "episodes.json").exists()
    assert (run_dir / "manifest.json").exists()
    lines = [
        ln for ln in (run_dir / "episodes.json").read_text(encoding="utf-8").splitlines()
        if ln.strip()
    ]
    assert len(lines) == 4


def test_cli_run_rejects_over_limit(runs_dir):
    result = _cli(
        "run", "--configs", "M1-01", "M1-02", "M1-03", "--episodes-per-config", "5",
        "--run-id", "big", "--runs-dir", runs_dir, "--execute",
    )
    assert result.returncode == 1
    assert "per-invocation limit" in result.stderr


def test_cli_run_rejects_raised_cap(runs_dir):
    result = _cli(
        "run", "--configs", "M1-01", "--max-episodes", "1000",
        "--run-id", "cap", "--runs-dir", runs_dir, "--execute",
    )
    assert result.returncode == 1
    assert "hard per-invocation cap" in result.stderr


def test_cli_run_rejects_full_matrix(runs_dir):
    all_ids = [e["config_id"] for e in build_manifest()["configurations"]]
    result = _cli(
        "run", "--configs", *all_ids, "--run-id", "matrix",
        "--runs-dir", runs_dir, "--execute",
    )
    assert result.returncode == 1
    assert "full 26-configuration" in result.stderr
    assert os.listdir(runs_dir) == []


def test_cli_duplicate_run_id_with_different_selection_refused(runs_dir):
    first = _cli(
        "run", "--configs", "M1-01", "--episodes-per-config", "2",
        "--run-id", "same", "--runs-dir", runs_dir, "--execute",
    )
    assert first.returncode == 0
    second = _cli(
        "run", "--configs", "M1-01", "--episodes-per-config", "3",
        "--run-id", "same", "--runs-dir", runs_dir, "--execute",
    )
    assert second.returncode == 1
    assert "selection mismatch" in second.stderr


def test_cli_resume_interrupted_run(runs_dir):
    plan = resolve_selection(build_manifest(), ["M1-01"], episodes_per_config=3)
    store = RunStore(runs_dir, "int-cli")
    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E002"))

    refused = _cli("resume", "--run-id", "int-cli", "--runs-dir", runs_dir)
    assert refused.returncode == 2
    assert "REFUSED" in refused.stderr

    result = _cli("resume", "--run-id", "int-cli", "--runs-dir", runs_dir, "--execute")
    assert result.returncode == 0, result.stderr
    assert "status=completed" in result.stdout or "Resumed: status=completed" in result.stdout
    assert len(store.read_records()) == 3


def test_cli_status_and_aggregate(runs_dir):
    _cli("run", "--configs", "M1-01", "--episodes-per-config", "2",
         "--run-id", "st", "--runs-dir", runs_dir, "--execute")
    status = _cli("status", "--run-id", "st", "--runs-dir", runs_dir)
    assert status.returncode == 0
    payload = json.loads(status.stdout)
    assert payload["status"] == "completed"
    assert payload["counts"]["completed"] == 2

    listing = _cli("status", "--runs-dir", runs_dir)
    assert listing.returncode == 0
    assert "st: status=completed" in listing.stdout

    agg = _cli("aggregate", "--run-id", "st", "--runs-dir", runs_dir, "--json")
    assert agg.returncode == 0
    summary = json.loads(agg.stdout)
    assert summary["counts"]["completed"] == 2
    assert summary["overall"]["metrics"]["cost_per_attack"] is None


def test_cli_llm_mode_fails_preflight_without_creating_run(runs_dir, monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    result = _cli(
        "run", "--configs", "M1-01", "--provider-mode", "llm",
        "--run-id", "llmrun", "--runs-dir", runs_dir, "--execute",
    )
    assert result.returncode == 1
    assert "provider preflight failed" in result.stderr
    assert os.listdir(runs_dir) == []


def test_cli_resume_corrupt_checkpoint_exits_nonzero(runs_dir):
    plan = resolve_selection(build_manifest(), ["M1-01"], episodes_per_config=1)
    store = RunStore(runs_dir, "corrupt-cli")
    with pytest.raises(KeyboardInterrupt):
        execute_run(store, plan, component_factory=_interrupt_at("M1-01-E001"))
    store.checkpoint_path.write_text("{broken", encoding="utf-8")
    result = _cli("resume", "--run-id", "corrupt-cli", "--runs-dir", runs_dir, "--execute")
    assert result.returncode == 1
    assert "corrupt" in result.stderr or "unreadable" in result.stderr


def test_cli_legacy_flags_still_work():
    result = _cli("--validate-manifest")
    assert result.returncode == 0
    assert "Result: VALID" in result.stdout


# ---------------------------------------------------------------------------
# API: non-executing endpoints only
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client(tmp_path):
    from backend.stage_b import create_app

    app = create_app(
        credentials_path=tmp_path / "c.json",
        token_path=tmp_path / "t.json",
        pairing_nonce="test-pairing-nonce",
    )
    return TestClient(app, follow_redirects=False)


def _base():
    from backend.stage_b import _MOUNT_PREFIX

    return f"/{_MOUNT_PREFIX.lstrip('/')}"


def test_api_dry_run_zero_execution(api_client):
    response = api_client.get(
        f"{_base()}/experiment-dry-run?configs=M1-01,M1-02&episodes=3"
    )
    assert response.status_code == 200
    summary = response.json()["summary"]
    assert summary["execution"] == "none"
    assert summary["episodes_executed"] == 0
    assert summary["planned_episodes"] == 6
    assert summary["selection"] == ["M1-01", "M1-02"]


def test_api_dry_run_default_plans_all_without_executing(api_client):
    response = api_client.get(f"{_base()}/experiment-dry-run")
    assert response.status_code == 200
    summary = response.json()["summary"]
    assert summary["planned_episodes"] == 1300
    assert summary["episodes_executed"] == 0
    assert summary["execution"] == "none"


def test_api_dry_run_invalid_selection_is_400(api_client):
    response = api_client.get(f"{_base()}/experiment-dry-run?configs=NOT-A-ID")
    assert response.status_code == 400
    body = response.json()
    assert body["episodes_executed"] == 0
    assert "malformed" in body["error"]


def test_api_has_no_execution_routes(api_client):
    """No API route can launch, resume, or aggregate an experiment run."""
    for path in (
        f"{_base()}/experiment-run",
        f"{_base()}/experiment-resume",
        f"{_base()}/experiment-status",
        f"{_base()}/experiment-aggregate",
    ):
        assert api_client.get(path).status_code in (404, 405)
        assert api_client.post(path).status_code in (404, 405)
    # The dry-run endpoint is GET-only (no mutation surface).
    assert api_client.post(f"{_base()}/experiment-dry-run").status_code == 405


def test_api_existing_routes_still_compatible(api_client):
    from backend.stage_b import _MOUNT_PREFIX

    base = f"/{_MOUNT_PREFIX.lstrip('/')}"
    headers = {
        "origin": "chrome-extension://chlorophyll-modern-bread",
        "authorization": "Bearer test-pairing-nonce",
    }
    pair = api_client.post(
        f"{base}/pair",
        json={
            "presented_nonce": "test-pairing-nonce",
            "extension_origin": "chrome-extension://chlorophyll-modern-bread",
        },
        headers=headers,
    )
    assert pair.status_code != 404  # pairing route preserved and reachable
    manifest_route = api_client.get(f"{base}/experiment-manifest")
    assert manifest_route.status_code == 200
    assert manifest_route.json()["summary"]["episodes_executed"] == 0
