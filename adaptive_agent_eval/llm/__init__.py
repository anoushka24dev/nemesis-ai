"""LLM layer for the adaptive agent defense evaluation framework.

This package is the only place in the codebase that touches an LLM provider
(OpenAI or Anthropic). It owns:

- Building a typed provider/client from environment configuration.
- Retries and backoff on transient API failures.
- The minimal `messages.create` interface expected by the attacker,
  target, and diagnoser components.

The controller stays LLM-free (ADR-001). It never imports this package.
"""

from adaptive_agent_eval.llm.provider import (
    AnthropicProvider,
    OpenAIProvider,
    ProviderConfig,
    ProviderType,
    create_provider,
    get_default_provider,
)

__all__ = [
    "ProviderConfig",
    "ProviderType",
    "OpenAIProvider",
    "AnthropicProvider",
    "create_provider",
    "get_default_provider",
]

__version__ = "0.1.0"
