"""CLI entry point for running adaptive evaluation experiments.

Two surfaces, one entry point:

* **Runner subcommands** (Phase 3) — ``validate``, ``dry-run``, ``run``,
  ``resume``, ``status``, ``aggregate``. Default behavior is non-executing;
  ``run``/``resume`` refuse to execute without an explicit ``--execute`` and
  enforce a hard per-invocation episode limit. The full 26-configuration /
  1,300-episode matrix is refused by design (see ADR-017).
* **Legacy flat flags** — everything before Phase 3 (``--mode``,
  ``--defenses``, …, ``--validate-manifest``) keeps working unchanged: when
  the first argument is not a runner subcommand, the legacy parser runs.

Usage: ``python -m adaptive_agent_eval.cli <subcommand> [options]`` or
``adaptive-eval <subcommand> [options]``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from adaptive_agent_eval.models import (
    AttackerTier,
    DefenseType,
    EpisodeConfig,
    EpisodeMode,
    TargetTier,
)

RUNNER_SUBCOMMANDS = (
    "validate",
    "dry-run",
    "run",
    "resume",
    "status",
    "aggregate",
)


def build_configs(args) -> list[EpisodeConfig]:
    """Build episode configurations from CLI arguments."""
    configs = []

    defenses = [DefenseType(d) for d in args.defenses]
    attacker_tiers = [AttackerTier(t) for t in args.attacker_tiers]
    target_tiers = [TargetTier(t) for t in args.target_tiers]

    for defense in defenses:
        for att_tier in attacker_tiers:
            for tgt_tier in target_tiers:
                for i in range(args.episodes_per_config):
                    configs.append(
                        EpisodeConfig(
                            mode=EpisodeMode(args.mode),
                            defense=defense,
                            attacker_tier=att_tier,
                            target_tier=tgt_tier,
                            max_rounds=args.max_rounds,
                            task_description=args.task or "Process the following content",
                            attack_goal=args.attack_goal or "Execute unauthorized tool call",
                        )
                    )

    return configs


def run_manifest_validation(args) -> None:
    """Build + validate the approved experiment manifest and print a summary.

    Validation only — no experiment is executed here. Exits with status 1
    when the manifest is invalid (for CI use).
    """
    from pathlib import Path

    from adaptive_agent_eval.experiment_matrix import (
        build_manifest,
        manifest_summary,
        manifest_to_json,
        validate_manifest,
    )

    manifest = build_manifest()
    errors = validate_manifest(manifest)
    summary = manifest_summary(manifest)

    print("Experiment manifest validation (configuration only - runs nothing)")
    print("=" * 60)
    print(f"Schema version:   {manifest['schema_version']}")
    print(f"Plan source:      {manifest['plan_source']}")
    for mode, count in sorted(summary["mode_counts"].items()):
        print(f"  {mode}: {count} configurations")
    print(f"Configurations:   {summary['configurations']}")
    print(f"Episodes/config:  {manifest['plan']['episodes_per_config']}")
    print(f"Planned episodes: {summary['planned_episodes']}")
    print(f"Provider binding: {manifest['provider_binding']['provider']}"
          f" ({manifest['provider_binding']['cheap_model']} / "
          f"{manifest['provider_binding']['frontier_model']})")

    if args.manifest_out:
        out = Path(args.manifest_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(manifest_to_json(manifest), encoding="utf-8")
        print(f"Manifest written: {out}")

    if errors:
        print(f"Result: INVALID - {len(errors)} error(s)")
        for err in errors:
            print(f"  - {err}")
        raise SystemExit(1)

    print("Result: VALID")
    print("Note: configuration validation only - no experiment was executed.")


def legacy_main(argv: list[str] | None = None) -> None:
    """Pre-Phase-3 CLI behavior, preserved verbatim (flat flags)."""
    parser = argparse.ArgumentParser(
        description="Adaptive AI Agent Defense Evaluation Framework",
    )
    parser.add_argument(
        "--mode",
        choices=["single-agent", "cross-agent", "defense-composition"],
        default="single-agent",
        help="Evaluation mode",
    )
    parser.add_argument(
        "--defenses",
        nargs="+",
        choices=["camel", "progent", "verifier"],
        default=["camel"],
        help="Defenses to evaluate",
    )
    parser.add_argument(
        "--attacker-tiers",
        nargs="+",
        choices=["cheap", "frontier"],
        default=["cheap"],
        help="Attacker model tiers",
    )
    parser.add_argument(
        "--target-tiers",
        nargs="+",
        choices=["cheap", "frontier"],
        default=["cheap"],
        help="Target model tiers",
    )
    parser.add_argument(
        "--episodes-per-config",
        type=int,
        default=50,
        help="Number of episodes per configuration",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=5,
        help="Maximum rounds per episode",
    )
    parser.add_argument(
        "--task",
        type=str,
        default="Process the following content",
        help="Task description for target agent",
    )
    parser.add_argument(
        "--attack-goal",
        type=str,
        default="Execute unauthorized tool call",
        help="Goal for the attacker",
    )
    parser.add_argument(
        "--persist-dir",
        type=str,
        default="data/episodes",
        help="Directory to persist episode results",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )
    parser.add_argument(
        "--validate-manifest",
        action="store_true",
        help=(
            "Build and validate the approved experiment manifest "
            "(26 configurations / 1,300 episodes plan). This checks the "
            "configuration grid ONLY and executes nothing. Exits 1 when "
            "the manifest is invalid."
        ),
    )
    parser.add_argument(
        "--manifest-out",
        type=str,
        default=None,
        help="With --validate-manifest: also write the manifest JSON to this path",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.validate_manifest:
        run_manifest_validation(args)
        return

    configs = build_configs(args)
    total_episodes = len(configs)
    total_configs = total_episodes // args.episodes_per_config

    print("Adaptive Agent Defense Evaluation Framework")
    print("=" * 50)
    print(f"Mode: {args.mode}")
    print(f"Defenses: {args.defenses}")
    print(f"Attacker tiers: {args.attacker_tiers}")
    print(f"Target tiers: {args.target_tiers}")
    print(f"Configs: {total_configs}")
    print(f"Episodes per config: {args.episodes_per_config}")
    print(f"Total episodes: {total_episodes}")
    print(f"Max rounds per episode: {args.max_rounds}")
    print("=" * 50)
    print()
    print("Note: Full implementation requires LLM API clients.")
    print("This scaffold provides the structure and interfaces.")
    print("See EXPERIMENT_PLAN.md for the complete architecture.")
    print("Runner subcommands (validate/dry-run/run/resume/status/aggregate)")
    print("are available: python -m adaptive_agent_eval.cli <subcommand> --help")


# ---------------------------------------------------------------------------
# Runner subcommands (Phase 3)
# ---------------------------------------------------------------------------


def _auto_run_id(selection: list[str], manifest_sha256: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"r{stamp}-{manifest_sha256[:8]}-{'-'.join(selection[:2])}"[:64]


def _print_plan_banner(plan, run_id: str | None = None) -> None:
    print("Execution plan (visible BEFORE any execution):")
    print("-" * 60)
    if run_id:
        print(f"  run_id:         {run_id}")
    print(f"  engine:         {plan.engine}")
    print(f"  provider mode:  {plan.provider_mode}")
    print(f"  configurations: {len(plan.selection)} ({', '.join(plan.selection)})")
    print(f"  episodes/config:{plan.episodes_per_config}")
    print(f"  total episodes: {plan.total_episodes}")
    print(f"  manifest hash:  {plan.manifest_sha256[:16]}…")
    print("-" * 60)


def _runner_dry_run(args) -> int:
    from adaptive_agent_eval.experiment_matrix import (
        EPISODES_PER_CONFIG,
        build_manifest,
    )
    from adaptive_agent_eval.runner.plan import (
        SelectionError,
        dry_run_summary,
        resolve_selection,
    )

    manifest = build_manifest()
    if args.configs:
        config_ids = args.configs
    else:
        config_ids = [e["config_id"] for e in manifest["configurations"]]
    try:
        plan = resolve_selection(
            manifest,
            config_ids,
            args.episodes_per_config or EPISODES_PER_CONFIG,
            provider_mode=args.provider_mode,
            enforce_bounded=False,
        )
    except SelectionError as exc:
        print(f"dry-run: selection rejected:\n{exc}", file=sys.stderr)
        return 1
    summary = dry_run_summary(plan, manifest)
    print("DRY RUN — planning only; zero episodes executed, nothing written.")
    _print_plan_banner(plan)
    print(f"  episode ids:    {summary['episode_id_first']} … {summary['episode_id_last']}")
    print(f"  seed range:     {summary['seed_min']} … {summary['seed_max']}")
    print(f"  rounds upper:   {summary['resource_estimate']['total_rounds_upper_bound']}")
    print(f"  llm calls:      {summary['resource_estimate']['llm_calls']}")
    print(f"  integrations:   {', '.join(summary['required_integrations'])}")
    if summary["excluded_episodes"]:
        print(
            f"  excluded:       {summary['excluded_episodes']} manifest-planned "
            "episodes not part of this bounded selection"
        )
    print("Result: DRY-RUN OK (episodes_executed=0)")
    return 0


def _runner_run(args) -> int:
    from adaptive_agent_eval.experiment_matrix import build_manifest
    from adaptive_agent_eval.runner.executor import (
        PreflightError,
        execute_run,
        preflight,
    )
    from adaptive_agent_eval.runner.plan import (
        DEFAULT_MAX_EPISODES_PER_RUN,
        RunnerError,
        SelectionError,
        resolve_selection,
    )
    from adaptive_agent_eval.runner.store import RunStore, RunStoreError

    manifest = build_manifest()
    try:
        plan = resolve_selection(
            manifest,
            args.configs,
            args.episodes_per_config,
            provider_mode=args.provider_mode,
            max_episodes=args.max_episodes or DEFAULT_MAX_EPISODES_PER_RUN,
            enforce_bounded=True,
        )
    except SelectionError as exc:
        print(f"run: selection rejected:\n{exc}", file=sys.stderr)
        return 1

    try:
        preflight_report = preflight(args.provider_mode, manifest)
    except PreflightError as exc:
        print(f"run: {exc}", file=sys.stderr)
        return 1

    run_id = args.run_id or _auto_run_id(plan.selection, plan.manifest_sha256)
    _print_plan_banner(plan, run_id=run_id)
    print(f"  preflight:      ok ({preflight_report['engine']})")
    print(f"  runs dir:       {args.runs_dir}")

    if not args.execute:
        print(
            "REFUSED: no episodes were executed. Pass --execute to run this "
            "bounded selection (the full matrix can never be executed this way).",
            file=sys.stderr,
        )
        return 2

    def _event(event: dict) -> None:
        if event.get("event") == "episode_finished":
            detail = event.get("outcome") or event.get("failure") or ""
            print(f"  [{event['status']}] {event['episode_id']} {detail}")

    store = RunStore(args.runs_dir, run_id)
    try:
        meta = execute_run(store, plan, on_event=_event)
    except (RunnerError, RunStoreError) as exc:
        print(f"run: {exc}", file=sys.stderr)
        return 1

    counts = meta["counts"]
    print("Run finished:")
    print(
        f"  status={meta['status']} planned={counts['planned']} "
        f"completed={counts['completed']} failed={counts['failed']} "
        f"interrupted={counts['interrupted']} pending={counts['pending']} "
        f"skipped={counts['skipped']}"
    )
    print(f"  artifacts: {store.run_dir}")
    if plan.engine == "deterministic-local":
        print(
            "  note: deterministic local engine — real local defenses, stub "
            "attacker/target, zero LLM calls; results are not research results."
        )
    return 0 if meta["status"] == "completed" else 1


def _runner_resume(args) -> int:
    from adaptive_agent_eval.experiment_matrix import build_manifest
    from adaptive_agent_eval.runner.executor import (
        PreflightError,
        preflight,
        resume_run,
    )
    from adaptive_agent_eval.runner.plan import (
        HARD_CAP_EPISODES_PER_RUN,
        RunnerError,
        resolve_selection,
    )
    from adaptive_agent_eval.runner.store import RunStore, RunStoreError

    manifest = build_manifest()
    store = RunStore(args.runs_dir, args.run_id)
    try:
        meta = store.load()
    except RunStoreError as exc:
        print(f"resume: {exc}", file=sys.stderr)
        return 1

    pending = [
        ep
        for ep in meta.get("episodes", [])
        if ep.get("status") not in ("completed", "failed")
    ]
    print("Resume plan (visible BEFORE any execution):")
    print("-" * 60)
    print(f"  run_id:     {args.run_id}")
    print(f"  run status: {meta.get('status')}")
    print(f"  engine:     {meta.get('engine')}")
    print(f"  pending:    {len(pending)} episode(s) would execute")
    print("-" * 60)

    if not args.execute:
        print(
            "REFUSED: no episodes were executed. Pass --execute to continue "
            "this run.",
            file=sys.stderr,
        )
        return 2
    if meta.get("status") == "completed":
        print("Nothing to resume: the run is already completed.")
        return 0

    try:
        plan = resolve_selection(
            manifest,
            list(meta.get("selection") or []),
            int(meta.get("episodes_per_config") or 1),
            provider_mode=meta.get("provider_mode", "deterministic"),
            max_episodes=HARD_CAP_EPISODES_PER_RUN,
            enforce_bounded=True,
        )
        preflight(meta.get("provider_mode", "deterministic"), manifest)
        meta = resume_run(store, plan)
    except (RunnerError, RunStoreError, PreflightError, ValueError, TypeError) as exc:
        print(f"resume: {exc}", file=sys.stderr)
        return 1

    counts = meta["counts"]
    print(
        f"Resumed: status={meta['status']} completed={counts['completed']} "
        f"failed={counts['failed']} pending={counts['pending']}"
    )
    return 0 if meta["status"] == "completed" else 1


def _runner_status(args) -> int:
    import json

    from adaptive_agent_eval.runner.plan import DEFAULT_RUNS_DIR
    from adaptive_agent_eval.runner.store import RunStore, RunStoreError

    runs_dir = args.runs_dir or DEFAULT_RUNS_DIR
    if not args.run_id:
        from pathlib import Path

        base = Path(runs_dir)
        if not base.exists():
            print(f"No runs directory at {base} — no runs yet.")
            return 0
        for entry in sorted(base.iterdir()):
            if not entry.is_dir():
                continue
            try:
                store = RunStore(runs_dir, entry.name)
                meta = store.load()
                print(
                    f"{entry.name}: status={meta.get('status')} "
                    f"updated={meta.get('updated_at')}"
                )
            except RunStoreError as exc:
                print(f"{entry.name}: UNREADABLE ({exc})")
        return 0

    store = RunStore(args.runs_dir, args.run_id)
    try:
        status = _runner_status_payload(store)
    except RunStoreError as exc:
        print(f"status: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(status, indent=2, ensure_ascii=False))
    return 0


def _runner_status_payload(store) -> dict:
    from adaptive_agent_eval.runner.executor import run_status

    return run_status(store)


def _runner_aggregate(args) -> int:
    import json

    from adaptive_agent_eval.runner.plan import (
        RunnerError,
        aggregate_run,
    )
    from adaptive_agent_eval.runner.store import RunStore, RunStoreError

    store = RunStore(args.runs_dir, args.run_id)
    try:
        summary = aggregate_run(store)
    except (RunnerError, RunStoreError) as exc:
        print(f"aggregate: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    counts = summary["counts"]
    print(f"Aggregation for run {summary['run_id']} (status={summary['run_status']})")
    print("-" * 60)
    print(
        f"  planned={counts['planned']} completed={counts['completed']} "
        f"failed={counts['failed']} interrupted={counts['interrupted']} "
        f"pending={counts['pending']} skipped={counts['skipped']}"
    )
    for cid, block in summary["per_config"].items():
        flag = "complete" if block["complete"] else "INCOMPLETE"
        asr = block["metrics"]["attack_success_rate"]
        print(
            f"  {cid}: {block['completed']}/{block['planned']} completed "
            f"({flag}) asr={'n/a' if asr is None else f'{asr:.3f}'}"
        )
    measured = [
        name
        for name, state in summary["overall"]["availability"].items()
        if state == "measured"
    ]
    print(f"  overall metrics measured: {', '.join(measured) or 'none'}")
    print(f"  artifact integrity: {summary['artifact_integrity']['status']}")
    if summary["integrity_problems"]:
        print(f"  INTEGRITY PROBLEMS: {summary['integrity_problems']}")
    print("  confidence/significance: not reported (not implemented)")
    if summary["run_status"] != "completed" or not summary["complete"]:
        print("  NOTE: run is not complete — these are partial results.")
    return 0


def _build_runner_parser() -> argparse.ArgumentParser:
    from adaptive_agent_eval.runner.plan import (
        DEFAULT_MAX_EPISODES_PER_RUN,
        DEFAULT_RUNS_DIR,
        EPISODES_PER_CONFIG,
    )

    parser = argparse.ArgumentParser(
        prog="adaptive-eval",
        description="Nemesis AI experiment runner (bounded, resumable)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Logging level (default WARNING: progress is printed directly)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="Validate the manifest; executes nothing")

    p_dry = sub.add_parser(
        "dry-run", help="Plan configs/episodes/seeds; executes nothing"
    )
    p_dry.add_argument("--configs", nargs="+", default=None,
                       help="Configuration IDs (default: all 26, planning only)")
    p_dry.add_argument("--episodes-per-config", type=int, default=EPISODES_PER_CONFIG)
    p_dry.add_argument("--provider-mode", choices=["deterministic", "llm"],
                       default="deterministic")

    p_run = sub.add_parser("run", help="Execute a bounded selection (--execute required)")
    p_run.add_argument("--configs", nargs="+", required=True,
                       help="Explicit configuration IDs (e.g. M1-01 M2-03)")
    p_run.add_argument("--episodes-per-config", type=int, default=1,
                       help="Episodes per selected config (default 1; max "
                            f"{EPISODES_PER_CONFIG})")
    p_run.add_argument("--max-episodes", type=int,
                       default=DEFAULT_MAX_EPISODES_PER_RUN,
                       help="Hard per-invocation episode limit")
    p_run.add_argument("--run-id", default=None,
                       help="Run identifier (default: generated)")
    p_run.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR)
    p_run.add_argument("--provider-mode", choices=["deterministic", "llm"],
                       default="deterministic")
    p_run.add_argument("--execute", action="store_true",
                       help="Actually execute (without it: plan only, exit 2)")

    p_res = sub.add_parser("resume", help="Continue an interrupted run")
    p_res.add_argument("--run-id", required=True)
    p_res.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR)
    p_res.add_argument("--execute", action="store_true",
                       help="Actually execute pending episodes")

    p_st = sub.add_parser("status", help="Persisted run state + artifact integrity")
    p_st.add_argument("--run-id", default=None,
                      help="Omit to list all runs in --runs-dir")
    p_st.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR)

    p_agg = sub.add_parser(
        "aggregate", help="Aggregate persisted, valid episode records only"
    )
    p_agg.add_argument("--run-id", required=True)
    p_agg.add_argument("--runs-dir", default=DEFAULT_RUNS_DIR)
    p_agg.add_argument("--json", action="store_true",
                       help="Print the full aggregation JSON")

    return parser


def runner_cli(argv: list[str]) -> int:
    parser = _build_runner_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if args.command == "validate":
        run_manifest_validation(argparse.Namespace(manifest_out=None))
        return 0
    if args.command == "dry-run":
        return _runner_dry_run(args)
    if args.command == "run":
        return _runner_run(args)
    if args.command == "resume":
        return _runner_resume(args)
    if args.command == "status":
        return _runner_status(args)
    if args.command == "aggregate":
        return _runner_aggregate(args)
    parser.error(f"unknown command {args.command!r}")  # pragma: no cover
    return 2  # pragma: no cover


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in RUNNER_SUBCOMMANDS:
        raise SystemExit(runner_cli(argv))
    legacy_main(argv)


if __name__ == "__main__":
    main()
