"""Root-level pytest helpers.

This repo has two independent test domains:

- gmail_demo / tests/test_gmail_demo*.py
- adaptive_agent_eval / tests/test_*.py

Their packages use absolute imports and do not share a package namespace, so
running all tests from a single root can make one package shadow the other
depending on sys.path order. This conftest keeps collection explicit by
choosing a default test directory.

Usage:
- From the repo root, run only one domain at a time, for example:
    pytest tests/test_gmail_demo_execution.py -q --import-mode=importlib
    pytest tests/test_gmail_demo_safety.py -q --import-mode=importlib
    pytest tests/test_email_demo.py -q --import-mode=importlib
    pytest tests/test_phase2_regression.py -q --import-mode=importlib
    pytest adaptive_agent_eval -q --import-mode=importlib
- To run everything, use the folders explicitly:
    pytest tests -q --import-mode=importlib
    pytest adaptive_agent_eval -q --import-mode=importlib
"""

from __future__ import annotations

import sys
from pathlib import Path


def _ensure_both_package_roots_on_path() -> None:
    repo_root = Path(__file__).resolve().parent
    roots = [
        str(repo_root),
        str(repo_root / "gmail_demo"),
        str(repo_root / "adaptive_agent_eval"),
    ]
    for root in roots:
        if root not in sys.path:
            sys.path.insert(0, root)


def pytest_configure(config: object) -> None:
    _ensure_both_package_roots_on_path()
