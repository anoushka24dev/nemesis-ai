# -*- coding: utf-8 -*-
"""CLI smoke checks for the Stage B backend package."""
from __future__ import annotations

import pytest
from pathlib import Path
from subprocess import run
from sys import executable

from backend.stage_b import APP_ORIGIN, ALLOWED_EXTENSION_ORIGINS, create_app_with_defaults


def test_app_origin_is_loopback() -> None:
    assert APP_ORIGIN == "http://127.0.0.1:8123"


def test_allowed_origins_are_extension_schemes() -> None:
    assert "chrome-extension://" in ALLOWED_EXTENSION_ORIGINS


def test_create_app_with_defaults_returns_app() -> None:
    app = create_app_with_defaults()
    assert app is not None


def run_cli_pkg(args: list[str]) -> str:
    """Run ``python -m backend.stage_b <args>`` from the repository root and
    return its stdout. Non-zero exit codes are treated as test failures."""
    root = Path(__file__).resolve().parents[1]
    completed = run(
        [executable, "-m", "backend.stage_b"] + args,
        cwd=root,
        text=True,
        capture_output=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "backend CLI failed on args %r:\n%s"
            % (args, completed.stdout + completed.stderr)
        )
    return completed.stdout


def test_cli_info_targets_the_stage_b_readonly_backend() -> None:
    output = run_cli_pkg(["info"])
    lowered = output.lower()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    assert any("stage_b" in line for line in lines)
    assert any("backend" in line for line in lines)
    assert any(line.startswith("port=") for line in lines)
    assert any("8123" in line for line in lines)
    assert any("bind=127.0.0.1:8123" in line for line in lines)
    assert any("origin=" in line and "127.0.0.1:8123" in line for line in lines)
    assert any("read_only=true" in line for line in lines)
    assert any("gmail_scopes=readonly only" in line for line in lines)
    assert any("auth=extension" in line for line in lines)
    assert any("pairing" in line or "nonce" in line for line in lines)
    assert any("mount_path=/api/v1/stage_b" in line for line in lines)
    assert any("endpoints=" in line for line in lines)


def test_cli_info_has_no_staging_or_webhook_noise() -> None:
    output = run_cli_pkg(["info"])
    lowered = output.lower()
    for forbidden in ("webhook", "staging", "production", "public"):
        assert forbidden not in lowered, (
            "unexpected %r in backend info output:\n%s" % (forbidden, output)
        )


def test_cli_unknown_command_returns_non_zero() -> None:
    root = Path(__file__).resolve().parents[1]
    completed = run(
        [executable, "-m", "backend.stage_b", "does-not-exist"],
        cwd=root,
        text=True,
        capture_output=True,
        timeout=60,
    )
    assert completed.returncode != 0
    assert "Unknown command" in completed.stderr or "does-not-exist" in completed.stderr


if __name__ == "__main__":
    raise SystemExit("backend tests must be run with pytest, not executed directly.")
