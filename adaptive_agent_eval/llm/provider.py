"""LLM provider abstraction — the only LLM-adjacent layer in the project.

This module is deliberately thin: it owns SDK client construction, retries/backoff,
and a shared `messages.create(...)` interface. Nothing here decides semantics
(how an attacker is shaped, how a target acts, or what counts as a block).
Those decisions live in `adaptive_agent_eval.attacker`, `.target`, and `.diagnoser`,
each of which accepts a `client` object with a `messages.create(...)` contract.

The controller stays LLM-free (ADR-001): it never imports this module.

SDK imports are deferred into provider methods so the package can be imported
without pulling in `openai` or `anthropic` at module load time.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING, Any, cast

from dotenv import load_dotenv

load_dotenv(override=False)

__all__ = [
    "ProviderConfig",
    "ProviderType",
    "OpenAIProvider",
    "AnthropicProvider",
    "create_provider",
    "get_default_provider",
]

_MISSING: object = object()
# Private sentinel to mark "no argument provided"

_PRIMARY_MODEL_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}

_ROLE_MODEL_ENV: dict[str, dict[str, str]] = {
    "openai": {
        "attacker": "OPENAI_MODEL_ATTACKER",
        "attacker_frontier": "OPENAI_MODEL_ATTACKER_FRONTIER",
        "target": "OPENAI_MODEL_TARGET",
        "target_frontier": "OPENAI_MODEL_TARGET_FRONTIER",
        "classifier": "OPENAI_MODEL_CLASSIFIER",
    },
    "anthropic": {
        "attacker": "ANTHROPIC_MODEL_ATTACKER",
        "attacker_frontier": "ANTHROPIC_MODEL_ATTACKER_FRONTIER",
        "target": "ANTHROPIC_MODEL_TARGET",
        "target_frontier": "ANTHROPIC_MODEL_TARGET_FRONTIER",
        "classifier": "ANTHROPIC_MODEL_CLASSIFIER",
    },
}

# Provider-native defaults for each role. Anthropic uses Claude models in the same
# capability band as the OpenAI defaults; the provider translation table below is
# used only when a caller explicitly supplies a model from the *other* provider's
# family. Default-family values are identity-mapped by design.
_DEFAULT_MODEL_FAMILY: dict[str, dict[str, str]] = {
    "openai": {
        "attacker": "gpt-3.5-turbo",
        "attacker_frontier": "gpt-4o",
        "target": "gpt-3.5-turbo",
        "target_frontier": "gpt-4o",
        "classifier": "gpt-4o-mini",
    },
    "anthropic": {
        "attacker": "claude-3-5-haiku-20241026",
        "attacker_frontier": "claude-opus-4-6",
        "target": "claude-3-5-haiku-20241026",
        "target_frontier": "claude-opus-4-6",
        "classifier": "claude-3-5-haiku-20241026",
    },
}

# Provider-native model translation. Use this only when switching providers and you
# want the closest equivalent from the other provider's family. If a model is not
# listed here, it is passed through unchanged.
_PROVIDER_MODEL_MAP: dict[str, dict[str, str]] = {
    "openai": {
        "claude-3-5-haiku-20241026": "gpt-4o-mini",
        "claude-opus-4-6": "gpt-4o",
    },
    "anthropic": {
        "gpt-3.5-turbo": "claude-3-5-haiku-20241026",
        "gpt-4o-mini": "claude-3-5-haiku-20241026",
        "gpt-4o": "claude-opus-4-6",
    },
}

if TYPE_CHECKING:
    # At type-check time, validate that the translation table does not silently
    # remap a provider's own default-family model onto a different model. At
    # runtime this check is intentionally skipped because the installed stubs for
    # this project can make the literal values look incompatible.
    for _provider, _family in _DEFAULT_MODEL_FAMILY.items():
        for _role, _default_model in _family.items():
            _translated = _PROVIDER_MODEL_MAP[_provider].get(_default_model)
            if _translated is not None and _translated != _default_model:
                raise RuntimeError(
                    f"Provider config error: {_provider} role {_role} default {_default_model} "
                    f"is mapped to {_translated}, which is a different model. Update the default "
                    f"family or the translation table deliberately."
                )


class ProviderType:
    OPENAI = "openai"
    ANTHROPIC = "anthropic"


_VALID_PROVIDERS = frozenset((ProviderType.OPENAI, ProviderType.ANTHROPIC))


class ProviderConfig:
    """Resolved LLM provider configuration (no secrets in code, reads env)."""

    def __init__(self, provider: str = ProviderType.OPENAI) -> None:
        self.provider = provider.lower()
        if self.provider not in _VALID_PROVIDERS:
            raise ValueError(f"Unknown provider: {self.provider}")

        family = _DEFAULT_MODEL_FAMILY[self.provider]
        self.attacker = family["attacker"]
        self.attacker_frontier = family["attacker_frontier"]
        self.target = family["target"]
        self.target_frontier = family["target_frontier"]
        self.classifier = family["classifier"]

        self.api_key_env = _PRIMARY_MODEL_ENV[self.provider]
        self.api_base_override: str | None = None
        self.timeout_seconds = 60.0
        self.retries = 3
        self.retry_base_delay = 1.0  # seconds, exponential backoff

    @classmethod
    def from_env(cls, provider: str | object = _MISSING) -> ProviderConfig:
        """Build a config resolved from environment variables (no secrets in code).

        Precedence (highest to lowest):

        1. An explicit ``provider`` argument passed by the caller. Any non-empty
           string value — including ``"openai"`` — wins outright and the
           environment variable is never consulted.
        2. The ``LLM_PROVIDER`` environment variable, used only when no explicit
           argument was provided.
        3. The hardcoded default, :data:`ProviderType.OPENAI`.

        The environment variable is a fallback, not an override. Calling
        ``from_env()`` with no argument means "no argument provided" and falls
        through to the environment variable, then the default.

        An explicitly passed empty string (``""``) or ``None`` is also treated
        as "no argument provided" and follows the same env → default fallback.
        The sentinel default for this parameter is a private ``object()``, so an
        omitted argument is distinguishable from an explicit ``""`` at the
        implementation level even though both share the same fallback behavior.

        Both the explicit argument and the environment variable are validated
        against the same allowlist (:data:`_VALID_PROVIDERS`). An invalid value
        raises :class:`ValueError` so a bad ``.env`` is caught early rather than
        silently falling back.
        """
        resolved: str
        if provider is _MISSING or not provider:
            resolved = os.getenv("LLM_PROVIDER", ProviderType.OPENAI)
        else:
            resolved = cast(str, provider)
        cfg = cls(resolved)
        role_env = _ROLE_MODEL_ENV[cfg.provider]

        primary = os.getenv(_PRIMARY_MODEL_ENV[cfg.provider])
        cfg.attacker = os.getenv(role_env["attacker"], primary or cfg.attacker)
        cfg.attacker_frontier = os.getenv(role_env["attacker_frontier"], cfg.attacker_frontier)
        cfg.target = os.getenv(role_env["target"], primary or cfg.target)
        cfg.target_frontier = os.getenv(role_env["target_frontier"], cfg.target_frontier)
        cfg.classifier = os.getenv(role_env["classifier"], primary or cfg.classifier)

        cfg.api_base_override = os.getenv("LLM_API_BASE")
        cfg.timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", cfg.timeout_seconds))
        cfg.retries = int(os.getenv("LLM_RETRIES", cfg.retries))
        cfg.retry_base_delay = float(os.getenv("LLM_RETRY_BASE_DELAY", cfg.retry_base_delay))
        return cfg

    def api_key(self) -> str:
        """Resolve the provider API key from the environment."""
        key = os.getenv(self.api_key_env)
        if not key:
            raise RuntimeError(
                f"Missing {self.api_key_env}. Create a .env file (see .env.example)"
            )
        return key

    def api_base(self) -> str | None:
        """Return an optional base URL override for the provider client."""
        return self.api_base_override

    def model_for_role(self, role: str) -> str:
        """Return the effective model for a config role, translated to the active provider."""
        value = getattr(self, role, None)
        if value is None:
            raise ValueError(f"Unknown config role: {role}")
        mapped = _PROVIDER_MODEL_MAP[self.provider].get(value)
        return mapped if mapped is not None else value


class BaseProvider:
    """Abstract provider: builds a client with a typed `messages.create` interface."""

    def __init__(self, config: ProviderConfig) -> None:
        self.config = config

    def messages(self) -> Any:
        """Return a client with a `messages.create(model, messages, ...)` call."""
        raise NotImplementedError


class OpenAIProvider(BaseProvider):
    def messages(self) -> Any:
        import openai

        client = openai.OpenAI(
            api_key=self.config.api_key(),
            base_url=self.config.api_base() or None,
        )
        return OpenAIMessagesClient(client)


class AnthropicProvider(BaseProvider):
    def messages(self) -> Any:
        import anthropic

        client = anthropic.Anthropic(
            api_key=self.config.api_key(),
            base_url=self.config.api_base() or None,
        )
        return AnthropicMessagesClient(client)


class OpenAIMessagesClient:
    """Forward `messages.create(model, max_tokens, system, messages)` for OpenAI.

    Uses the standard synchronous chat completion path, not the beta Messages API.
    Callers pass `system`; it is forwarded as the standard system message in the
    `messages` array so both providers honor it the same way.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def create(self, model: str, max_tokens: int, system: str, messages: list[dict[str, Any]]) -> Any:
        # Forward `system` the same way Anthropic does: as a real system message.
        merged: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            *messages,
        ]
        return self._client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=merged,
        )


class AnthropicMessagesClient:
    """Forward `messages.create(model, max_tokens, system, messages)` for Anthropic.

    Anthropic's SDK accepts `system` as a top-level parameter; we forward it
    directly so the shared contract stays simple for callers.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def create(self, model: str, max_tokens: int, system: str, messages: list[dict[str, Any]]) -> Any:
        return self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
        )


def _with_retry(
    retries: int,
    base_delay: float,
    func: Any,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Call `func` with exponential backoff and jitter, then re-raise on exhaustion.

    Transient failures are retried. On the last attempt the most recent error is
    re-raised cleanly so callers see a normal exception, not a retry-policy leak.
    """
    import random

    last_error: BaseException | None = None
    for attempt in range(retries):
        try:
            return func(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - retry any transient failure
            last_error = exc
            if attempt == retries - 1:
                break
            jitter = random.random() * base_delay
            delay = base_delay * (2 ** attempt) + jitter
            time.sleep(delay)
    assert last_error is not None  # pragma: no cover - always raises when exhausted
    raise last_error


def create_provider(config: ProviderConfig) -> BaseProvider:
    """Factory: resolve the configured provider type."""
    if config.provider == ProviderType.OPENAI:
        return OpenAIProvider(config)
    if config.provider == ProviderType.ANTHROPIC:
        return AnthropicProvider(config)
    raise ValueError(f"Unsupported LLM provider: {config.provider}")


def get_default_provider() -> BaseProvider:
    """Convenience: build and return the default provider from env."""
    return create_provider(ProviderConfig.from_env())
