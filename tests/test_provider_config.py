"""Tests for the LLM provider configuration precedence rules.

These tests cover the Option-2 contract for ProviderConfig.from_env():

- An explicit argument wins over the LLM_PROVIDER environment variable.
- The environment variable is used only when no explicit argument is given.
- The hardcoded default is used only when neither the argument nor the env is
  set.
- An invalid provider value (from argument or env) is rejected, not silently
  replaced by the default.
"""

from __future__ import annotations

import importlib
import sys

import pytest

from adaptive_agent_eval.llm.provider import ProviderConfig, ProviderType


def _clear_llm_modules() -> None:
    for mod in list(sys.modules):
        if mod.startswith("adaptive_agent_eval.llm"):
            del sys.modules[mod]


def test_explicit_argument_wins_over_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)

    cfg = _p.ProviderConfig.from_env(provider=ProviderType.OPENAI)
    assert cfg.provider == ProviderType.OPENAI


def test_env_var_used_when_no_argument_given(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)

    cfg = _p.ProviderConfig.from_env()
    assert cfg.provider == ProviderType.ANTHROPIC


def test_env_var_falls_back_to_default_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)
    # load_dotenv() at module import re-reads the project .env (which a real
    # setup defines); the contract under test is "env unset at call time",
    # so drop it again after the reload.
    monkeypatch.delenv("LLM_PROVIDER", raising=False)

    cfg = _p.ProviderConfig.from_env()
    assert cfg.provider == ProviderType.OPENAI


def test_empty_string_argument_triggers_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)

    cfg = _p.ProviderConfig.from_env(provider="")
    assert cfg.provider == ProviderType.ANTHROPIC


def test_none_argument_triggers_env_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)

    cfg = _p.ProviderConfig.from_env(provider=None)  # type: ignore[arg-type]
    assert cfg.provider == ProviderType.ANTHROPIC


def test_invalid_env_var_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "foo")
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)

    with pytest.raises(ValueError, match="Unknown provider"):
        _p.ProviderConfig.from_env()


def test_invalid_explicit_argument_is_rejected() -> None:
    with pytest.raises(ValueError, match="Unknown provider"):
        ProviderConfig.from_env(provider="foo")


def test_case_insensitive_env_var_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ANTHROPIC")
    _clear_llm_modules()
    import adaptive_agent_eval.llm.provider as _p
    importlib.reload(_p)

    cfg = _p.ProviderConfig.from_env()
    assert cfg.provider == ProviderType.ANTHROPIC
