"""Honest integration / system-health probes (Phase 2).

Every entry uses :class:`adaptive_agent_eval.models.IntegrationStatus`:

* ``CONNECTED`` — only after a real established interaction (e.g. a completed
  extension pairing). Never merely because a config names a provider or an
  API-key variable exists.
* ``AVAILABLE`` — capability present but not verified live in this check.
* ``PROXY_IMPLEMENTATION`` — local stand-in for an external/research system
  (the repo's CaMeL/Progent/Verifier are local rule-based proxies).
* ``NOT_INSTALLED`` / ``NOT_CONFIGURED`` / ``FAILED`` — absent or broken.

No probe returns, logs, or stores a credential *value* — only environment
variable *names* and presence booleans.
"""

from __future__ import annotations

import importlib.util
import os
from collections.abc import Mapping
from pathlib import Path

from dotenv import load_dotenv

from adaptive_agent_eval.contracts import IntegrationReport
from adaptive_agent_eval.models import IntegrationStatus

_REPO_ROOT = Path(__file__).resolve().parent.parent

_GEMINI_KEY_ENVS = ("GEMINI_API_KEY", "GOOGLE_API_KEY")


def _resolve_env(env: Mapping[str, str] | None) -> Mapping[str, str]:
    """Environment seen by the probes.

    ``None`` (runtime) mirrors :mod:`adaptive_agent_eval.llm.provider`:
    load the project ``.env`` without overriding already-set variables, then
    read ``os.environ``. Tests pass an explicit mapping for determinism.
    """
    if env is not None:
        return env
    load_dotenv(override=False)
    return os.environ


def _llm_provider_report(env: Mapping[str, str]) -> IntegrationReport:
    provider = (env.get("LLM_PROVIDER") or "").strip()
    if not provider:
        return IntegrationReport(
            "llm-provider",
            IntegrationStatus.NOT_CONFIGURED,
            "LLM_PROVIDER not set",
        )
    if provider == "gemini":
        key_present = any((env.get(name) or "").strip() for name in _GEMINI_KEY_ENVS)
        detail = (
            "provider=gemini (OpenAI-compatible endpoint, ADR-016); "
            + (
                "credential env var present — not verified live"
                if key_present
                else "no GEMINI_API_KEY/GOOGLE_API_KEY env var set"
            )
        )
        return IntegrationReport(
            "llm-provider",
            IntegrationStatus.AVAILABLE if key_present else IntegrationStatus.NOT_CONFIGURED,
            detail,
        )
    if provider in ("openai", "anthropic"):
        key_env = f"{provider.upper()}_API_KEY"
        key_present = bool((env.get(key_env) or "").strip())
        detail = (
            f"provider={provider}; "
            + (
                f"{key_env} present — not verified live"
                if key_present
                else f"{key_env} not set"
            )
        )
        return IntegrationReport(
            "llm-provider",
            IntegrationStatus.AVAILABLE if key_present else IntegrationStatus.NOT_CONFIGURED,
            detail,
        )
    return IntegrationReport(
        "llm-provider",
        IntegrationStatus.FAILED,
        f"unknown provider {provider!r} (allowed: gemini, openai, anthropic)",
    )


def _llm_wiring_report() -> IntegrationReport:
    """Does the framework's default provider resolution actually work with the
    current environment? Checked by resolving it, not by reading a name."""
    try:
        from adaptive_agent_eval.llm.provider import ProviderConfig

        cfg = ProviderConfig.from_env()
    except (
        ValueError,
        RuntimeError,
        KeyError,
        TypeError,
        AttributeError,
        OSError,
    ) as exc:
        # from_env's failure modes: unknown provider, missing API key, bad
        # env value. Anything else propagates as a genuine bug instead of
        # being masked as an integration finding.
        return IntegrationReport(
            "llm-provider-wiring",
            IntegrationStatus.FAILED,
            f"ProviderConfig.from_env() raised {type(exc).__name__}: {exc}",
        )
    return IntegrationReport(
        "llm-provider-wiring",
        IntegrationStatus.AVAILABLE,
        f"ProviderConfig.from_env() resolves provider={cfg.provider}",
    )


def _agentdojo_report() -> IntegrationReport:
    if importlib.util.find_spec("agentdojo") is None:
        return IntegrationReport(
            "agentdojo",
            IntegrationStatus.NOT_INSTALLED,
            "real AgentDojo package not installed; local target implementation "
            "is used and results must never be labeled as real AgentDojo",
        )
    return IntegrationReport(
        "agentdojo",
        IntegrationStatus.AVAILABLE,
        "agentdojo package installed — interface verification still pending",
    )


def _defense_report(name: str) -> IntegrationReport:
    # All three defenses live in one module (adaptive_agent_eval.defense.defenses).
    spec = importlib.util.find_spec("adaptive_agent_eval.defense.defenses")
    if spec is None:  # pragma: no cover - package layout change would surface
        return IntegrationReport(
            f"defense:{name}",
            IntegrationStatus.NOT_INSTALLED,
            "module adaptive_agent_eval.defense.defenses not found",
        )
    return IntegrationReport(
        f"defense:{name}",
        IntegrationStatus.PROXY_IMPLEMENTATION,
        f"local rule-based {name} implementation — proxy for the research "
        "defense, not the original system",
    )


def _gmail_report(token_path: Path) -> IntegrationReport:
    if token_path.exists():
        return IntegrationReport(
            "gmail-readonly",
            IntegrationStatus.AVAILABLE,
            "read-only OAuth token file present (gmail_auth refuses any scope "
            "beyond gmail.readonly) — not verified live",
        )
    return IntegrationReport(
        "gmail-readonly",
        IntegrationStatus.NOT_CONFIGURED,
        f"no OAuth token at {token_path.name} — run: python gmail_auth.py --auth-only",
    )


def _artifact_storage_report(results_dir: Path) -> IntegrationReport:
    if not results_dir.exists():
        return IntegrationReport(
            "artifact-storage",
            IntegrationStatus.NOT_CONFIGURED,
            f"results directory {results_dir.name}/ does not exist yet",
        )
    if os.access(results_dir, os.W_OK):
        return IntegrationReport(
            "artifact-storage",
            IntegrationStatus.AVAILABLE,
            f"results directory {results_dir.name}/ is writable",
        )
    return IntegrationReport(
        "artifact-storage",
        IntegrationStatus.FAILED,
        f"results directory {results_dir.name}/ is not writable",
    )


def _pairing_report(paired_origin: str | None) -> IntegrationReport:
    if paired_origin:
        # A completed pairing is a real established interaction.
        return IntegrationReport(
            "extension-pairing",
            IntegrationStatus.CONNECTED,
            "a paired extension origin is established for this backend",
        )
    return IntegrationReport(
        "extension-pairing",
        IntegrationStatus.NOT_CONFIGURED,
        "no paired extension origin (complete pairing via POST /pair)",
    )


def collect_integrations(
    *,
    token_path: Path | str | None = None,
    results_dir: Path | str | None = None,
    paired_origin: str | None = None,
    env: Mapping[str, str] | None = None,
) -> list[IntegrationReport]:
    """Collect honest integration statuses for system-health reporting."""
    environment = _resolve_env(env)
    token = Path(token_path) if token_path is not None else (
        _REPO_ROOT / "token.json"
    )
    results = Path(results_dir) if results_dir is not None else (_REPO_ROOT / "results")

    return [
        _llm_provider_report(environment),
        _llm_wiring_report(),
        _agentdojo_report(),
        _defense_report("camel"),
        _defense_report("progent"),
        _defense_report("verifier"),
        _gmail_report(token),
        _artifact_storage_report(results),
        _pairing_report(paired_origin),
    ]
