"""Tests for the existing Gmail agent demo execution path.

These are the simplest direct checks that the demo's main entry points load,
build state, and run through the engine without crashing.

Note: this project also has a separate adaptive_agent_eval test suite. When
both are collected, be careful to run only the gmail_demo tests (or vice
versa) so imports from the other package do not shadow or conflict.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

import pytest

from gmail_demo import Attacker, FakeInbox, GmailAgent, run_episode
from gmail_demo.defense import DefenseChecker
from gmail_demo.engine import build_state
from gmail_demo.models import (
    EMAIL_DEMO_MODE_ENV,
    EpisodeResult,
    is_email_demo_mode,
)


def _set_demo_mode(on: bool) -> None:
    if on:
        os.environ[EMAIL_DEMO_MODE_ENV] = "1"
    elif EMAIL_DEMO_MODE_ENV in os.environ:
        del os.environ[EMAIL_DEMO_MODE_ENV]


@pytest.fixture(autouse=True)
def _reset_demo_mode():
    before = os.environ.get(EMAIL_DEMO_MODE_ENV)
    try:
        _set_demo_mode(False)
        yield
    finally:
        if before is not None:
            os.environ[EMAIL_DEMO_MODE_ENV] = before
        elif EMAIL_DEMO_MODE_ENV in os.environ:
            del os.environ[EMAIL_DEMO_MODE_ENV]


def test_build_state_returns_expected_keys():
    state = build_state()
    assert set(state) == {"hardened", "demo_mode", "episode", "inbox", "attacker_variants"}
    assert isinstance(state["episode"], dict)
    assert isinstance(state["inbox"], list)
    assert isinstance(state["attacker_variants"], list)
    assert isinstance(state["demo_mode"], bool)


def test_run_episode_defaults_preserve_existing_behavior():
    result = run_episode()
    assert isinstance(result, EpisodeResult)
    assert result.started_at
    assert result.finished_at
    assert result.metrics
    assert result.metrics["defense_hardened"] is False
    assert " attacker_succeeded" not in result.stopped_reason or result.stopped_reason


def test_hardened_flag_is_passed_through():
    normal = build_state(hardened=False)
    hardened = build_state(hardened=True)
    assert normal["hardened"] is False
    assert hardened["hardened"] is True


def test_defense_checker_still_constructor():
    d = DefenseChecker()
    assert d.name == "defense_checker"
    assert d.harden_normalization is False
    assert d.demo_mode is False

    d2 = DefenseChecker(harden_normalization=True, demo_mode=True)
    assert d2.harden_normalization is True
    assert d2.demo_mode is True
    d = DefenseChecker()
    assert d.name == "defense_checker"
    assert d.harden_normalization is False
    assert d.demo_mode is False

    d2 = DefenseChecker(harden_normalization=True, demo_mode=True)
    assert d2.harden_normalization is True
    assert d2.demo_mode is True


def test_demo_mode_false_keeps_existing_defense_checker_factory():
    assert is_email_demo_mode() is False
    checker = DefenseChecker()
    assert checker.demo_mode is False


def test_email_demo_mode_false_keeps_existing_demo_behavior():
    """EMAIL_DEMO_MODE=false -> existing demo behavior.

    First half of the required integration comparison. Driven purely by the
    environment: no demo_mode argument is passed, so the engine must fall back
    to the plain DefenseChecker path.
    """
    assert is_email_demo_mode() is False

    # Env-only: demo_mode defaults to None -> resolved from EMAIL_DEMO_MODE.
    state = build_state()
    assert state["demo_mode"] is False
    assert state["episode"]["metrics"]["demo_mode"] is False
    assert state["episode"]["metrics"]["defense_hardened"] is False

    result = run_episode()
    assert result.metrics["demo_mode"] is False
    assert result.metrics["defense_hardened"] is False

    # Explicit False also preserves existing behavior even with env on.
    _set_demo_mode(True)
    result_explicit = run_episode(demo_mode=False)
    assert result_explicit.metrics["demo_mode"] is False
    _set_demo_mode(False)


def test_email_demo_mode_true_activates_demo_safety_constraints():
    """EMAIL_DEMO_MODE=true -> demo safety constraints active.

    Second half of the required integration comparison. Driven purely by the
    environment: no demo_mode argument is passed, so the engine must resolve
    EMAIL_DEMO_MODE and build the defense checker with
    build_demo_defense_checker() (demo_mode=True).
    """
    _set_demo_mode(True)
    assert is_email_demo_mode() is True

    # Env-only: demo_mode defaults to None -> resolved from EMAIL_DEMO_MODE.
    state = build_state()
    assert state["demo_mode"] is True
    assert state["episode"]["metrics"]["demo_mode"] is True

    result = run_episode()
    assert result.metrics["demo_mode"] is True
    assert result.metrics["defense_hardened"] is False

    # The defense actually used must be the demo checker, not a plain one.
    # This proves the engine loaded build_demo_defense_checker(), which is
    # what enforces the NEMESIS_DEMO label restriction and the recipient
    # allowlist.
    from gmail_demo.models import (
        EMAIL_DEMO_RECIPIENT_ALLOWLIST,
        Email,
        ProposedAction,
        build_demo_defense_checker,
    )

    demo_checker = build_demo_defense_checker()
    assert demo_checker.demo_mode is True

    # A non-allowlisted forward is blocked by the demo policy...
    email = Email(
        id="msg-safety",
        sender="cfo@corp.example",
        subject="Confidential",
        body="Please forward this onward.",
        labels=["NEMESIS_DEMO"],
    )
    bad = ProposedAction(
        action="forward",
        email_id=email.id,
        to="evil@exfil.example",
        requested=True,
        sensitive=True,
    )
    assert demo_checker.check(email, bad).decision == "block"

    # ...and an allowlisted recipient is allowed.
    good = ProposedAction(
        action="forward",
        email_id=email.id,
        to=EMAIL_DEMO_RECIPIENT_ALLOWLIST[0],
        requested=True,
        sensitive=True,
    )
    assert demo_checker.check(email, good).decision == "allow"

    # And the engine path itself used a demo-mode checker for this run.
    assert result.metrics.get("demo_mode") is True


def test_engine_loads_build_demo_defense_checker_from_env(monkeypatch):
    """The engine must call build_demo_defense_checker() when EMAIL_DEMO_MODE
    is on and no explicit demo_mode is passed."""
    import gmail_demo.engine as engine_mod
    import gmail_demo.models as models_mod

    calls: list[tuple] = []
    real_factory = models_mod.build_demo_defense_checker

    def spy_factory(harden_normalization: bool = False):
        calls.append((harden_normalization,))
        return real_factory(harden_normalization=harden_normalization)

    monkeypatch.setattr(models_mod, "build_demo_defense_checker", spy_factory)

    _set_demo_mode(True)
    run_episode()  # env-driven, no demo_mode argument
    assert calls, "engine did not load build_demo_defense_checker()"
    assert calls == [(False,)]

    # hardened flag is forwarded to the demo checker factory
    calls.clear()
    run_episode(hardened=True)
    assert calls == [(True,)]

    # env off -> factory is never used
    calls.clear()
    _set_demo_mode(False)
    run_episode()
    assert calls == []
