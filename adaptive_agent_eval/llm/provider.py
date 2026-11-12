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

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from dotenv import load_dotenv

load_dotenv(override=False)

logger = logging.getLogger(__name__)

__all__ = [
    "ProviderConfig",
    "ProviderType",
    "OpenAIProvider",
    "AnthropicProvider",
    "GeminiProvider",
    "OllamaConfig",
    "OllamaProvider",
    "OllamaMessagesClient",
    "ollama_health_check",
    "FakeProvider",
    "create_provider",
    "get_default_provider",
    "make_provider_config",
]

_MISSING: object = object()
# Private sentinel to mark "no argument provided"

_PRIMARY_MODEL_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "ollama": "OLLAMA_API_KEY",
    "fake": "FAKE_API_KEY",
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
    "gemini": {
        "attacker": "GEMINI_MODEL_ATTACKER",
        "attacker_frontier": "GEMINI_MODEL_ATTACKER_FRONTIER",
        "target": "GEMINI_MODEL_TARGET",
        "target_frontier": "GEMINI_MODEL_TARGET_FRONTIER",
        "classifier": "GEMINI_MODEL_CLASSIFIER",
    },
    "fake": {
        "attacker": "FAKE_MODEL_ATTACKER",
        "attacker_frontier": "FAKE_MODEL_ATTACKER_FRONTIER",
        "target": "FAKE_MODEL_TARGET",
        "target_frontier": "FAKE_MODEL_TARGET_FRONTIER",
        "classifier": "FAKE_MODEL_CLASSIFIER",
    },
    "ollama": {
        "attacker": "OLLAMA_MODEL_ATTACKER",
        "attacker_frontier": "OLLAMA_MODEL_ATTACKER_FRONTIER",
        "target": "OLLAMA_MODEL_TARGET",
        "target_frontier": "OLLAMA_MODEL_TARGET_FRONTIER",
        "classifier": "OLLAMA_MODEL_CLASSIFIER",
    },
}

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
    "gemini": {
        "attacker": "gemini-2.5-flash",
        "attacker_frontier": "gemini-2.5-pro",
        "target": "gemini-2.5-flash",
        "target_frontier": "gemini-2.5-pro",
        "classifier": "gemini-2.5-flash",
    },
    "fake": {
        "attacker": "fake-deterministic",
        "attacker_frontier": "fake-deterministic-frontier",
        "target": "fake-target",
        "target_frontier": "fake-target-frontier",
        "classifier": "fake-classifier",
    },
    # Ollama is the default proposal provider for adaptive search (local,
    # no credentials). Endpoint: OLLAMA_HOST (default 127.0.0.1:11434).
    "ollama": {
        "attacker": "llama3.1:8b",
        "attacker_frontier": "llama3.1:8b",
        "target": "llama3.1:8b",
        "target_frontier": "llama3.1:8b",
        "classifier": "llama3.1:8b",
    },
}

_PROVIDER_MODEL_MAP: dict[str, dict[str, str]] = {
    "openai": {
        "claude-3-5-haiku-20241026": "gpt-4o-mini",
        "claude-opus-4-6": "gpt-4o",
        "gemini-2.5-flash": "gpt-4o-mini",
        "gemini-2.5-pro": "gpt-4o",
    },
    "anthropic": {
        "gpt-3.5-turbo": "claude-3-5-haiku-20241026",
        "gpt-4o-mini": "claude-3-5-haiku-20241026",
        "gpt-4o": "claude-opus-4-6",
        "gemini-2.5-flash": "claude-3-5-haiku-20241026",
        "gemini-2.5-pro": "claude-opus-4-6",
    },
    "gemini": {
        "gpt-3.5-turbo": "gemini-2.5-flash",
        "gpt-4o-mini": "gemini-2.5-flash",
        "gpt-4o": "gemini-2.5-pro",
        "claude-3-5-haiku-20241026": "gemini-2.5-flash",
        "claude-opus-4-6": "gemini-2.5-pro",
    },
    "fake": {
        "gpt-3.5-turbo": "fake-deterministic",
        "claude-3-5-haiku-20241026": "fake-deterministic",
        "gemini-2.5-flash": "fake-deterministic",
    },
    # Cloud model names requested under the local provider collapse to the
    # single configured local model — never the other way around.
    "ollama": {
        "gpt-3.5-turbo": "llama3.1:8b",
        "gpt-4o-mini": "llama3.1:8b",
        "gpt-4o": "llama3.1:8b",
        "gemini-2.5-flash": "llama3.1:8b",
        "gemini-2.5-pro": "llama3.1:8b",
        "claude-3-5-haiku-20241026": "llama3.1:8b",
        "claude-opus-4-6": "llama3.1:8b",
    },
}


class ProviderType:
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    FAKE = "fake"


_VALID_PROVIDERS = frozenset((ProviderType.OPENAI, ProviderType.ANTHROPIC))


class GeminiConfig:
    """Configuration for Google Gemini provider (ADR-016)."""

    def __init__(self) -> None:
        self.provider = ProviderType.GEMINI
        family = _DEFAULT_MODEL_FAMILY["gemini"]
        self.attacker = family["attacker"]
        self.attacker_frontier = family["attacker_frontier"]
        self.target = family["target"]
        self.target_frontier = family["target_frontier"]
        self.classifier = family["classifier"]

        self.api_key_env = _PRIMARY_MODEL_ENV["gemini"]
        self.api_base_override = os.getenv("LLM_API_BASE")
        self.timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", 60.0))
        self.retries = int(os.getenv("LLM_RETRIES", 3))
        self.retry_base_delay = float(os.getenv("LLM_RETRY_BASE_DELAY", 1.0))
        self.max_model_calls = int(os.getenv("LLM_MAX_MODEL_CALLS", 100))
        self.model_calls_consumed = 0

    def api_key(self) -> str:
        key = os.getenv(self.api_key_env)
        if not key:
            raise RuntimeError(
                f"Missing {self.api_key_env}. Create a .env file (see .env.example)"
            )
        return key

    def api_base(self) -> str | None:
        return self.api_base_override

    def model_for_role(self, role: str) -> str:
        value = getattr(self, role, None)
        if value is None:
            raise ValueError(f"Unknown config role: {role}")
        mapped = _PROVIDER_MODEL_MAP[self.provider].get(value)
        return mapped if mapped is not None else value

    def check_and_increment_call(self) -> None:
        if self.model_calls_consumed >= self.max_model_calls:
            raise RuntimeError(
                f"Model call budget exhausted ({self.model_calls_consumed}/{self.max_model_calls}). "
                "Halting further model requests safely."
            )
        self.model_calls_consumed += 1


class OllamaConfig:
    """Configuration for the local Ollama provider (default proposal provider).

    No credentials: the local endpoint is trusted by loopback binding. The
    endpoint and model are explicit and never silently replaced by a hosted
    provider or a fake.
    """

    #: Default local endpoint (Part 3 requirement).
    DEFAULT_ENDPOINT = "http://127.0.0.1:11434"
    DEFAULT_MODEL = "llama3.1:8b"

    def __init__(self) -> None:
        self.provider = ProviderType.OLLAMA
        model = self.DEFAULT_MODEL
        self.attacker = model
        self.attacker_frontier = model
        self.target = model
        self.target_frontier = model
        self.classifier = model

        self.api_key_env = _PRIMARY_MODEL_ENV["ollama"]
        self.api_base_override = (
            os.getenv("OLLAMA_HOST")
            or os.getenv("OLLAMA_URL")
            or self.DEFAULT_ENDPOINT
        )
        # Local models can be slow; the default timeout is generous but still
        # bounded, and it is overridable via the standard env var.
        self.timeout_seconds = float(os.getenv("LLM_TIMEOUT_SECONDS", 120.0))
        self.retries = int(os.getenv("LLM_RETRIES", 2))
        self.retry_base_delay = float(os.getenv("LLM_RETRY_BASE_DELAY", 1.0))
        self.max_model_calls = int(os.getenv("LLM_MAX_MODEL_CALLS", 100))
        self.model_calls_consumed = 0
        # Honest request telemetry (Part 3.2).
        self.successful_requests = 0
        self.failed_requests = 0
        self.total_elapsed_seconds = 0.0
        self.last_error_category: str | None = None

    @property
    def endpoint(self) -> str:
        return (self.api_base_override or self.DEFAULT_ENDPOINT).rstrip("/")

    def api_key(self) -> str:
        # Ollama is a local, credential-less endpoint. This is a fixed
        # non-secret sentinel so callers that expect a key never see a
        # fabricated secret and never read one from the environment.
        return "local-ollama-no-credential"

    def api_base(self) -> str | None:
        return self.endpoint

    def model_for_role(self, role: str) -> str:
        value = getattr(self, role, None)
        if value is None:
            raise ValueError(f"Unknown config role: {role}")
        return value

    def check_and_increment_call(self) -> None:
        if self.model_calls_consumed >= self.max_model_calls:
            raise RuntimeError(
                f"Model call budget exhausted ({self.model_calls_consumed}/{self.max_model_calls}). "
                "Halting further model requests safely."
            )
        self.model_calls_consumed += 1

    def telemetry(self) -> dict[str, Any]:
        """Request counters and timing — real runtime data only."""
        return {
            "provider": self.provider,
            "endpoint": self.endpoint,
            "model": self.attacker,
            "successful_requests": self.successful_requests,
            "failed_requests": self.failed_requests,
            "total_elapsed_seconds": round(self.total_elapsed_seconds, 4),
            "last_error_category": self.last_error_category,
            "model_calls_consumed": self.model_calls_consumed,
            "model_call_budget": self.max_model_calls,
        }


def ollama_health_check(
    endpoint: str | None = None, *, timeout: float = 5.0
) -> dict[str, Any]:
    """Reachability + model-availability check for the local Ollama endpoint.

    Returns a structured, never-raising diagnostic so the UI can distinguish
    "Ollama is down" from "Ollama answered but the model is missing" from
    "the model is ready". Only reachability data is returned — no prompt
    content ever leaves this function.
    """
    import urllib.error
    import urllib.request

    url = (endpoint or OllamaConfig.DEFAULT_ENDPOINT).rstrip("/")
    result: dict[str, Any] = {
        "endpoint": url,
        "reachable": False,
        "model": OllamaConfig.DEFAULT_MODEL,
        "model_available": False,
        "error_category": None,
        "error": None,
    }
    try:
        req = urllib.request.Request(f"{url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        result["error_category"] = "unavailable"
        result["error"] = f"Ollama endpoint unreachable at {url}: {exc.reason}"
        return result
    except (ValueError, OSError) as exc:
        result["error_category"] = "invalid_response"
        result["error"] = f"Ollama endpoint at {url} returned an unreadable response: {exc}"
        return result
    result["reachable"] = True
    models = [
        str(m.get("name", "")) for m in payload.get("models", []) if isinstance(m, dict)
    ]
    wanted = os.getenv("OLLAMA_MODEL_ATTACKER") or OllamaConfig.DEFAULT_MODEL
    result["model"] = wanted
    # ``llama3.1:8b`` is usually listed as ``llama3.1:8b``; accept a bare
    # name match as well (``llama3.1`` implies the default tag).
    result["model_available"] = wanted in models or wanted.split(":")[0] in {
        m.split(":")[0] for m in models
    }
    if not result["model_available"]:
        result["error_category"] = "model_not_found"
        result["error"] = (
            f"model {wanted!r} is not available at {url}; "
            f"installed models: {models or 'none'}"
        )
    return result


class OllamaMessagesClient:
    """Messages client for Ollama's local ``/api/chat`` endpoint.

    Implements the same ``create(model, max_tokens, system, messages,
    temperature)`` contract the attacker/assistant components use for every
    other provider, so no second LLM subsystem is introduced.

    Failure semantics (Part 3.2 / 3.4): connection errors, timeouts, HTTP
    errors and malformed responses raise :class:`OllamaProviderError` with an
    explicit ``category`` — they are never converted into a fake answer, a
    scripted proposal, or a hosted-model call.
    """

    def __init__(self, config: OllamaConfig) -> None:
        self._config = config
        #: Number of HTTP attempts used by the most recent create() call.
        #: Read by the assistant telemetry; never estimated.
        self.last_attempts = 0

    def create(
        self,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
    ) -> NormalizedResponse:
        import urllib.error
        import urllib.request

        self._config.check_and_increment_call()
        url = f"{self._config.endpoint}/api/chat"
        body = {
            "model": model,
            "stream": False,
            "format": "json",
            "options": {"temperature": temperature, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system},
                *[
                    {"role": m.get("role", "user"), "content": m.get("content", "")}
                    for m in messages
                ],
            ],
        }
        data = json.dumps(body).encode("utf-8")
        started = time.time()
        last_error: str | None = None
        category = "unknown"
        attempts = max(1, int(self._config.retries))
        for attempt in range(1, attempts + 1):
            self.last_attempts = attempt
            req = urllib.request.Request(
                url, data=data, method="POST",
                headers={"Content-Type": "application/json"},
            )
            try:
                with urllib.request.urlopen(
                    req, timeout=self._config.timeout_seconds
                ) as resp:
                    raw = json.loads(resp.read().decode("utf-8"))
                text = raw.get("message", {}).get("content", "") if isinstance(raw, dict) else ""
                if not isinstance(text, str) or not text.strip():
                    raise OllamaProviderError(
                        "Ollama returned an empty completion",
                        category="invalid_response",
                    )
                self._config.successful_requests += 1
                self._config.total_elapsed_seconds += time.time() - started
                self._config.last_error_category = None
                # Keep the raw Ollama payload so callers can record real
                # token counts (prompt_eval_count / eval_count), if supplied.
                return NormalizedResponse.from_text(text, raw=raw)
            except OllamaProviderError as exc:
                self._config.failed_requests += 1
                self._config.total_elapsed_seconds += time.time() - started
                self._config.last_error_category = exc.category
                raise
            except urllib.error.HTTPError as exc:
                last_error = f"HTTP {exc.code}: {exc.reason}"
                category = "http_error" if exc.code < 500 else "server_error"
            except TimeoutError as exc:
                # A read timeout can surface as a bare socket TimeoutError
                # (it is OSError, so it must be caught before the OSError
                # fallback and does not match URLError on all platforms).
                last_error = (
                    f"request to {url} timed out after "
                    f"{self._config.timeout_seconds}s"
                )
                category = "timeout"
                del exc
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", exc)
                if isinstance(reason, TimeoutError) or "timed out" in str(reason).lower():
                    last_error = f"request to {url} timed out after {self._config.timeout_seconds}s"
                    category = "timeout"
                else:
                    last_error = f"Ollama endpoint unreachable at {url}: {reason}"
                    category = "unavailable"
            except (ValueError, KeyError, TypeError) as exc:
                last_error = f"unreadable response from {url}: {exc}"
                category = "invalid_response"
            except OSError as exc:
                # Residual transport failures (reset, broken pipe, ...): still
                # an explicit provider failure, never a fabricated answer.
                last_error = f"transport failure talking to {url}: {exc}"
                category = "unavailable"
            if attempt < attempts:
                time.sleep(self._config.retry_base_delay * attempt)
        self._config.failed_requests += 1
        self._config.total_elapsed_seconds += time.time() - started
        self._config.last_error_category = category
        raise OllamaProviderError(
            last_error or "Ollama request failed", category=category
        )


class OllamaProviderError(RuntimeError):
    """A real Ollama request failed. ``category`` is a public, machine-readable
    label ('timeout' | 'unavailable' | 'model_not_found' | 'http_error' |
    'server_error' | 'invalid_response' | 'budget')."""

    def __init__(self, message: str, *, category: str) -> None:
        super().__init__(message)
        self.category = category


class FakeConfig:
    """Configuration for offline fake model provider."""

    def __init__(self) -> None:
        self.provider = ProviderType.FAKE
        family = _DEFAULT_MODEL_FAMILY["fake"]
        self.attacker = family["attacker"]
        self.attacker_frontier = family["attacker_frontier"]
        self.target = family["target"]
        self.target_frontier = family["target_frontier"]
        self.classifier = family["classifier"]

        self.api_key_env = _PRIMARY_MODEL_ENV["fake"]
        self.api_base_override = None
        self.timeout_seconds = 5.0
        self.retries = 1
        self.retry_base_delay = 0.1
        self.max_model_calls = int(os.getenv("LLM_MAX_MODEL_CALLS", 100))
        self.model_calls_consumed = 0

    def api_key(self) -> str:
        return "fake-api-key"

    def api_base(self) -> str | None:
        return None

    def model_for_role(self, role: str) -> str:
        value = getattr(self, role, None)
        if value is None:
            raise ValueError(f"Unknown config role: {role}")
        return value

    def check_and_increment_call(self) -> None:
        if self.model_calls_consumed >= self.max_model_calls:
            raise RuntimeError(
                f"Model call budget exhausted ({self.model_calls_consumed}/{self.max_model_calls}). "
                "Halting further model requests safely."
            )
        self.model_calls_consumed += 1


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
        self.max_model_calls: int = 100
        self.model_calls_consumed: int = 0

    @classmethod
    def from_env(cls, provider: str | object = _MISSING) -> ProviderConfig:
        """Build a config resolved from environment variables (no secrets in code)."""
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
        cfg.max_model_calls = int(os.getenv("LLM_MAX_MODEL_CALLS", cfg.max_model_calls))
        return cfg

    def api_key(self) -> str:
        """Resolve the provider API key from the environment."""
        if self.provider == ProviderType.FAKE:
            return "fake-api-key"
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

    def check_and_increment_call(self) -> None:
        """Enforce model call budget."""
        if self.model_calls_consumed >= self.max_model_calls:
            raise RuntimeError(
                f"Model call budget exhausted ({self.model_calls_consumed}/{self.max_model_calls}). "
                "Halting further model requests safely."
            )
        self.model_calls_consumed += 1


# ---------------------------------------------------------------------------
# Normalized response objects so callers access .content[0].text uniformly
# ---------------------------------------------------------------------------


@dataclass
class TextBlock:
    text: str


@dataclass
class ChatMessage:
    content: str


@dataclass
class ChatChoice:
    message: ChatMessage


@dataclass
class NormalizedResponse:
    content: list[TextBlock]
    choices: list[ChatChoice] = field(default_factory=list)
    raw: Any = None

    @classmethod
    def from_text(cls, text: str, raw: Any = None) -> NormalizedResponse:
        return cls(
            content=[TextBlock(text=text)],
            choices=[ChatChoice(message=ChatMessage(content=text))],
            raw=raw,
        )


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
            timeout=self.config.timeout_seconds,
        )
        return OpenAIMessagesClient(client, self.config)


class GeminiProvider(BaseProvider):
    """Google Gemini Provider using its official OpenAI-compatible endpoint (ADR-016)."""

    DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"

    def messages(self) -> Any:
        import openai

        base_url = self.config.api_base() or self.DEFAULT_BASE_URL
        client = openai.OpenAI(
            api_key=self.config.api_key(),
            base_url=base_url,
            timeout=self.config.timeout_seconds,
        )
        return OpenAIMessagesClient(client, self.config)


class AnthropicProvider(BaseProvider):
    def messages(self) -> Any:
        import anthropic

        client = anthropic.Anthropic(
            api_key=self.config.api_key(),
            base_url=self.config.api_base() or None,
            timeout=self.config.timeout_seconds,
        )
        return AnthropicMessagesClient(client, self.config)


class FakeProvider(BaseProvider):
    """Offline, deterministic model provider for tests without external network or API keys."""

    def messages(self) -> Any:
        return FakeMessagesClient(self.config)


class OllamaProvider(BaseProvider):
    """Local Ollama provider implementing the standard messages contract.

    This is a REAL provider: every ``create`` issues an HTTP request to the
    configured local endpoint. If the endpoint is unreachable the call raises
    ``OllamaProviderError`` — it never falls back to the fake provider or to a
    hosted model.
    """

    def messages(self) -> Any:
        return OllamaMessagesClient(self.config)


class OpenAIMessagesClient:
    """Forward `messages.create(model, max_tokens, system, messages)` for OpenAI/Gemini."""

    def __init__(self, client: Any, config: ProviderConfig | None = None) -> None:
        self._client = client
        self._config = config

    def create(
        self,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
    ) -> NormalizedResponse:
        if self._config is not None:
            self._config.check_and_increment_call()

        merged: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            *messages,
        ]
        resp = self._client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            messages=merged,
            temperature=temperature,
        )
        text = resp.choices[0].message.content or ""
        return NormalizedResponse.from_text(text, raw=resp)


class AnthropicMessagesClient:
    """Forward `messages.create(model, max_tokens, system, messages)` for Anthropic."""

    def __init__(self, client: Any, config: ProviderConfig | None = None) -> None:
        self._client = client
        self._config = config

    def create(
        self,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
    ) -> NormalizedResponse:
        if self._config is not None:
            self._config.check_and_increment_call()

        resp = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            system=system,
            messages=messages,
            temperature=temperature,
        )
        text = resp.content[0].text if resp.content else ""
        return NormalizedResponse.from_text(text, raw=resp)


class FakeMessagesClient:
    """Returns deterministic mock responses for testing model-driven candidate generation."""

    def __init__(self, config: ProviderConfig) -> None:
        self._config = config
        self._call_count = 0

    def create(
        self,
        model: str,
        max_tokens: int,
        system: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.7,
    ) -> NormalizedResponse:
        self._config.check_and_increment_call()
        self._call_count += 1

        prompt = (system + " " + " ".join(m.get("content", "") for m in messages)).lower()

        # Phase 6B: validated candidate-proposal requests carry an explicit
        # marker (no prompt heuristics). The fake provider derives a
        # deterministic single-step mutation from the parent ladder in the
        # request context, so offline runs exercise the real accept/reject
        # path end to end.
        if "nemesis_candidate_proposal" in prompt:
            parent: list[dict[str, Any]] = []
            try:
                user_text = messages[-1].get("content", "")
                blob = json.loads(user_text.split("\n", 1)[1])
                parent = list(blob.get("parent_ladder") or [])
            except (ValueError, IndexError, KeyError, TypeError, AttributeError):
                parent = []
            ladder = [dict(s) for s in parent] if parent else [
                {"category": "direct_injection", "sophistication_level": 1}
            ]
            first = ladder[0]
            if first.get("category") != "obfuscation":
                first["category"] = "obfuscation"
            else:
                first["category"] = "direct_injection"
            mock_payload = {
                "candidate_ladder": ladder,
                "rationale": (
                    "Offline fake-provider suggestion (deterministic double, "
                    "not a real model): single-step category mutation."
                ),
            }
            return NormalizedResponse.from_text(json.dumps(mock_payload))

        # Generate structured candidate ladder if requested
        if "escalation" in prompt or "ladder" in prompt or "candidate" in prompt:
            mock_payload = {
                "category": "obfuscation",
                "sophistication_level": 3,
                "text": "IMPORTANT: malicious_email_payload decoded instructions",
                "a5_category_flag": False,
                "rationale": "Escalate to obfuscation based on previous blocked direct_injection",
            }
        elif "feedback" in prompt or "diagnose" in prompt or "analyze" in prompt:
            mock_payload = {
                "interpretation": "Direct injection was blocked by marker defense; evasive encoding recommended.",
                "recommended_category": "obfuscation",
                "confidence": 0.85,
            }
        else:
            mock_payload = {
                "text": "Fake generated test content",
                "category": "direct_injection",
                "sophistication_level": 1,
                "a5_category_flag": False,
            }

        return NormalizedResponse.from_text(json.dumps(mock_payload))


def make_provider_config(provider: str = ProviderType.OPENAI) -> Any:
    """Build configuration for any supported provider including Gemini, Ollama and Fake."""
    p = provider.lower()
    if p == ProviderType.GEMINI:
        return GeminiConfig()
    if p == ProviderType.OLLAMA:
        return OllamaConfig()
    if p == ProviderType.FAKE:
        return FakeConfig()
    return ProviderConfig(p)


def create_provider(config: Any) -> BaseProvider:
    """Factory: resolve the configured provider type."""
    if config.provider == ProviderType.OPENAI:
        return OpenAIProvider(config)
    if config.provider == ProviderType.ANTHROPIC:
        return AnthropicProvider(config)
    if config.provider == ProviderType.GEMINI:
        return GeminiProvider(config)
    if config.provider == ProviderType.OLLAMA:
        return OllamaProvider(config)
    if config.provider == ProviderType.FAKE:
        return FakeProvider(config)
    raise ValueError(f"Unsupported LLM provider: {config.provider}")


def get_default_provider() -> BaseProvider:
    """Convenience: build and return the default provider from env."""
    return create_provider(ProviderConfig.from_env())
