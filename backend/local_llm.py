"""Local, offline LLM analysis for Nemesis via Ollama (loopback only).

This is the ONLY module in the repository that talks to Ollama. It exists so
that "local mode" is a hard property, not a convention:

* **Loopback only.** The Ollama URL defaults to ``http://127.0.0.1:11434``
  and a non-loopback ``NEMESIS_OLLAMA_URL`` is refused at construction time
  (fail closed) — email content can never be shipped to another host from
  this path.
* **No external AI provider is reachable.** This module never imports or
  constructs the Gemini/OpenAI provider machinery; :func:`analyze_local`
  drives the project's real analysis entry point
  (``gmail_auth.analyze_emails``) with *this* client injected, so the Gemini
  config path is never read, let alone called. Nothing falls back to Gemini
  when the local model fails: a failure yields the deterministic ruleset
  verdicts (status ``fallback``) with a machine-readable
  ``model_error_category``.
* **Bounded everything.** One HTTP request per attempt, socket timeout
  enforced, at most ``retries`` attempts (default 2, hard ceiling 4 via the
  shared retry wrapper) — never an unbounded loop.
* **Untrusted input.** Email bodies travel only inside the request payload
  as prompt *data* for the shared ``ANALYSIS_SYSTEM_PROMPT``, which directs
  the model to treat them as content to analyze, never as instructions.
  Model output is schema-validated by ``gmail_auth`` before it is trusted
  and can only ever influence recommendations — it never authorizes or
  performs an action. No exception or log printed by this module ever
  contains email content, prompt text, or model output.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from gmail_auth import analyze_emails

__all__ = [
    "DEFAULT_LOCAL_MODEL",
    "DEFAULT_OLLAMA_URL",
    "LocalConfigError",
    "LocalModelError",
    "LocalNotFoundError",
    "LocalProviderConfig",
    "LocalTimeoutError",
    "LocalUnavailableError",
    "LocalInvalidResponseError",
    "OllamaClient",
    "analyze_local",
]

OLLAMA_URL_ENV = "NEMESIS_OLLAMA_URL"
OLLAMA_MODEL_ENV = "NEMESIS_OLLAMA_MODEL"
OLLAMA_TIMEOUT_ENV = "NEMESIS_OLLAMA_TIMEOUT"
OLLAMA_RETRIES_ENV = "NEMESIS_OLLAMA_RETRIES"

DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_LOCAL_MODEL = "llama3.1:8b"
DEFAULT_TIMEOUT_SECONDS = 120.0
#: Analysis JSON plus a little slack; local hardware must not be asked to
#: generate the full Gemini budget.
LOCAL_MAX_TOKENS_CAP = 768
DEFAULT_RETRIES = 2
DEFAULT_RETRY_BASE_DELAY = 0.5

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

#: Result metadata used in place of the core's hardcoded Gemini labels.
LOCAL_PROVIDER_LABEL = "ollama-local"
LOCAL_TRANSPORT_LABEL = "ollama-local"


class LocalModelError(RuntimeError):
    """A local-model failure. ``category`` is a short, public-only label.

    The message is intentionally content-free: it may carry the URL host,
    HTTP status, or exception type — never email bodies or model output.
    """

    def __init__(self, message: str, *, category: str) -> None:
        super().__init__(message)
        self.category = category


class LocalTimeoutError(LocalModelError, TimeoutError):
    def __init__(self, message: str) -> None:
        super().__init__(message, category="timeout")


class LocalUnavailableError(LocalModelError, ConnectionError):
    def __init__(self, message: str) -> None:
        super().__init__(message, category="model_unavailable")


class LocalNotFoundError(LocalModelError):
    def __init__(self, message: str) -> None:
        super().__init__(message, category="model_not_found")
        #: Surfaces as "HTTP 404" in the shared wrapper's bounded message and
        #: marks the failure non-retryable (a missing model won't appear by
        #: trying again).
        self.status_code = 404


class LocalInvalidResponseError(LocalModelError):
    def __init__(self, message: str) -> None:
        super().__init__(message, category="invalid_response")


class LocalConfigError(LocalModelError):
    """Local-mode configuration is refused (e.g. a non-loopback Ollama URL)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, category="config")


def _env_number(env: str, default: float, *, lo: float, hi: float) -> float:
    raw = os.environ.get(env, "").strip()
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return max(lo, min(hi, value))


def _env_int(env: str, default: int, *, lo: int, hi: int) -> int:
    return int(_env_number(env, float(default), lo=float(lo), hi=float(hi)))


def ollama_url() -> str:
    """Resolved Ollama base URL; refused unless it is loopback (fail closed)."""
    url = (os.environ.get(OLLAMA_URL_ENV, "").strip() or DEFAULT_OLLAMA_URL).rstrip("/")
    host = urlparse(url).hostname or ""
    if host not in _LOOPBACK_HOSTS:
        raise LocalConfigError(
            f"refusing non-loopback Ollama URL host {host!r}: local mode keeps "
            "email content on this machine (set "
            f"{OLLAMA_URL_ENV} to a 127.0.0.1/localhost URL or unset it)"
        )
    return url


def local_model_name() -> str:
    return os.environ.get(OLLAMA_MODEL_ENV, "").strip() or DEFAULT_LOCAL_MODEL


class LocalProviderConfig:
    """Duck-typed config for ``gmail_auth``'s bounded retry machinery.

    Provides exactly what the analysis path reads (``api_base()``,
    ``retries``, ``retry_base_delay``) with local defaults. It carries no
    API key and never consults Gemini/OpenAI environment variables.
    """

    def __init__(self) -> None:
        self.model = local_model_name()
        self.api_key_env = ""  # no key: loopback Ollama needs none
        self.retries = _env_int(OLLAMA_RETRIES_ENV, DEFAULT_RETRIES, lo=1, hi=4)
        self.retry_base_delay = _env_number(
            "NEMESIS_OLLAMA_RETRY_BASE_DELAY", DEFAULT_RETRY_BASE_DELAY, lo=0.0, hi=5.0
        )
        self.timeout_seconds = _env_number(
            OLLAMA_TIMEOUT_ENV, DEFAULT_TIMEOUT_SECONDS, lo=1.0, hi=600.0
        )
        self._url = ollama_url()

    def api_base(self) -> str:
        return self._url


class OllamaClient:
    """The shared ``create(model, max_tokens, system, messages)`` contract,
    served by Ollama's loopback ``/api/chat`` endpoint.

    ``last_error_category`` records why the most recent call failed so the
    caller can surface an honest machine-readable category after the shared
    wrapper has converted the exception.
    """

    def __init__(
        self,
        *,
        model: str | None = None,
        url: str | None = None,
        timeout: float | None = None,
    ) -> None:
        self.model = model or local_model_name()
        self.url = url or ollama_url()
        self.timeout = timeout if timeout is not None else _env_number(
            OLLAMA_TIMEOUT_ENV, DEFAULT_TIMEOUT_SECONDS, lo=1.0, hi=600.0
        )
        self.last_error_category: str | None = None

    # -- internals ----------------------------------------------------------

    def _fail(self, exc: LocalModelError) -> None:
        self.last_error_category = exc.category
        raise exc

    def _read(self, payload: dict[str, Any]) -> bytes:
        request = urllib.request.Request(
            f"{self.url}/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            # HTTPError is a URLError subclass: catch it first.
            body = ""
            try:
                body = exc.read().decode("utf-8", "replace")[:300]
            except Exception:  # noqa: BLE001 - diagnostics only
                body = ""
            if exc.code == 404 or "not found" in body.lower():
                self._fail(
                    LocalNotFoundError(
                        f"ollama model {self.model!r} not available at "
                        f"{self.url} (HTTP {exc.code}); pull it with "
                        f"`ollama pull {self.model}`"
                    )
                )
            self._fail(
                LocalUnavailableError(
                    f"ollama returned HTTP {exc.code} at {self.url}"
                )
            )
        except (TimeoutError, socket.timeout) as exc:
            self._fail(
                LocalTimeoutError(
                    f"ollama did not answer within {self.timeout:.0f}s "
                    f"({type(exc).__name__})"
                )
            )
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, (TimeoutError, socket.timeout)):
                self._fail(
                    LocalTimeoutError(
                        f"ollama did not answer within {self.timeout:.0f}s"
                    )
                )
            self._fail(
                LocalUnavailableError(
                    f"ollama unreachable at {self.url} "
                    f"({type(reason).__name__ if reason is not None else 'no reason'})"
                )
            )
        except OSError as exc:
            # Connection resets mid-read and friends.
            self._fail(
                LocalUnavailableError(
                    f"ollama connection failed ({type(exc).__name__})"
                )
            )
        raise AssertionError("unreachable: _fail always raises")  # pragma: no cover

    # -- public API ---------------------------------------------------------

    def create(
        self, *, model: str, max_tokens: int, system: str, messages: list[dict[str, Any]]
    ) -> Any:
        """One bounded chat request; returns an OpenAI-shaped response dict.

        The shape matches what ``gmail_auth._response_text`` consumes, so the
        real analysis path (parsing, schema validation, aggregation) runs
        unchanged on local output.
        """
        self.last_error_category = None
        num_predict = int(min(max(1, max_tokens), LOCAL_MAX_TOKENS_CAP))
        payload: dict[str, Any] = {
            "model": model or self.model,
            "messages": [
                {"role": "system", "content": system},
                *messages,
            ],
            "stream": False,
            # Server-side JSON mode: guarantees parseable output; the shared
            # schema validator still decides whether to trust it.
            "format": "json",
            "options": {"num_predict": num_predict},
        }
        raw = self._read(payload)
        try:
            data = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            self._fail(LocalInvalidResponseError("ollama returned non-JSON output"))
            raise AssertionError  # pragma: no cover
        if not isinstance(data, dict):
            self._fail(
                LocalInvalidResponseError(
                    f"ollama returned unexpected JSON shape {type(data).__name__}"
                )
            )
        if data.get("error"):
            text = str(data["error"])[:200]
            if "not found" in text.lower():
                self._fail(LocalNotFoundError(f"ollama model error: {text}"))
            self._fail(LocalUnavailableError(f"ollama error: {text}"))
        message = data.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            self._fail(LocalInvalidResponseError("ollama returned no message content"))
        return {
            "choices": [
                {"message": {"content": content}, "finish_reason": "stop"}
            ],
            "model": str(data.get("model") or model or self.model),
        }


def analyze_local(
    emails: list[Any],
    *,
    demo_mode: bool | None = None,
    client: Any = None,
    on_model_failure: str = "fallback",
) -> dict[str, Any]:
    """Run the project's REAL analysis path against the local Ollama model.

    Deterministic threat scoring, label policy, JSON schema validation, and
    max-pooled aggregation all run in ``gmail_auth.analyze_emails``; only the
    HTTP client at the far end is this module's loopback Ollama client.

    Local failures never escalate to an external provider: with the default
    ``on_model_failure="fallback"`` the result carries deterministic rule
    verdicts with ``status="fallback"`` plus ``model_error_category``.

    After the call, the result's provider metadata (which the core hardcodes
    to Gemini) is corrected to honestly say where the findings came from.
    """
    cfg = LocalProviderConfig()
    client = client or OllamaClient(
        model=cfg.model, url=cfg.api_base(), timeout=cfg.timeout_seconds
    )
    analysis = analyze_emails(
        emails,
        provider_config=cfg,
        model=cfg.model,
        client=client,
        demo_mode=demo_mode,
        on_model_failure=on_model_failure,
    )
    # Honest metadata: this run's model findings came from the local model.
    analysis["provider"] = LOCAL_PROVIDER_LABEL
    analysis["model"] = cfg.model
    analysis["transport"] = LOCAL_TRANSPORT_LABEL
    analysis["endpoint"] = cfg.api_base()
    findings_source = analysis.get("findings_source")
    if isinstance(findings_source, dict):
        if findings_source.get("summary_recommendation_indicators") == "gemini":
            findings_source["summary_recommendation_indicators"] = (
                LOCAL_PROVIDER_LABEL
            )
    if analysis.get("status") == "fallback":
        category = getattr(client, "last_error_category", None)
        if not category:
            # The HTTP edge succeeded but the SHARED schema validator rejected
            # the model's answer: that is an invalid response, not a transport
            # problem. (Messages come from gmail_auth's validator/parser.)
            error_text = str(analysis.get("model_error") or "")
            schema_markers = (
                "did not return JSON",
                "malformed JSON",
                "not an object",
                "missing required field",
                "is not numeric",
                "Unexpected model response shape",
            )
            category = (
                "invalid_response"
                if any(marker in error_text for marker in schema_markers)
                else "other"
            )
        analysis["model_error_category"] = category
    return analysis
