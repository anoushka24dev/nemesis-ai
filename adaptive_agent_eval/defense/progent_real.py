"""Bounded adapter for the authentic Progent paper artifact (``secagent``).

Paper/reference source: https://github.com/sunblaze-ucb/progent
Pinned revision: b02783b896d4bf01a2adf24738015e258db8d35b (MIT; vendored).

This calls upstream ``secagent.tool.check_tool_call`` before the sandbox tool
callback executes. The research artifact here is its rule-priority and JSON
Schema policy checker; the vendored full package also contains optional Z3
policy-analysis code, but that path is not used by this runtime. No LLM,
network, or Gmail access is performed by this adapter.

IMPORTANT PROVENANCE NOTE: this is a VENDORED SOURCE integration, not the
unrelated ``progent`` distribution published on PyPI (a different project with
a different repository). The adapter loads the pinned upstream file
``vendor/progent-paper/secagent/tool.py`` directly and never imports the PyPI
package. The allow/deny decision is made by upstream
``secagent.tool.check_tool_call`` against the policy installed with
``update_security_policy``; Nemesis supplies only the policy document and
records the resulting decision.
"""
from __future__ import annotations

import logging
import sys
import threading
import types
from pathlib import Path
from typing import Any

from adaptive_agent_eval.models import (
    DefenseDecision,
    DefenseEvent,
    DefenseImplementation,
    DefenseType,
    ToolCallRequest,
)

logger = logging.getLogger(__name__)
IMPLEMENTATION = "progent-paper-secagent"
SOURCE_REPO = "https://github.com/sunblaze-ucb/progent"
SOURCE_REVISION = "b02783b896d4bf01a2adf24738015e258db8d35b"
SOURCE_LICENSE = "MIT"
_POLICY_LOCK = threading.RLock()


class ProgentUnavailable(RuntimeError):
    """The vendored paper-reference checker could not be imported."""


def _load_sdk():
    root = Path(__file__).resolve().parents[2] / "vendor" / "progent-paper"
    if not (root / "secagent" / "tool.py").is_file():
        raise ProgentUnavailable(f"paper-reference Progent source missing under {root}")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    try:
        # Load by file location rather than importing top-level `secagent`:
        # an unrelated pip package named secagent may be installed and shadow
        # this repo's actual paper implementation.
        import importlib.util

        package = root / "secagent"
        # Import only the upstream checker module. The package __init__ eagerly
        # imports policy_analysis (Z3); Z3 is not used by check_tool_call and is
        # not required to execute the reference runtime's allow/deny path.
        name = "nemesis_vendored_progent.tool"
        spec = importlib.util.spec_from_file_location(name, package / "tool.py")
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load tool module from {package / 'tool.py'}")
        module = importlib.util.module_from_spec(spec)
        module.__package__ = "nemesis_vendored_progent"
        parent = types.ModuleType("nemesis_vendored_progent")
        parent.__path__ = [str(package)]
        sys.modules[parent.__name__] = parent
        sys.modules[name] = module
        spec.loader.exec_module(module)
        return module, module, module.ValidationError
    except Exception as exc:
        raise ProgentUnavailable(f"paper-reference secagent import failed: {exc}") from exc


class RealProgentDefense:
    """Apply Progent's actual checker and then execute only the sandbox stub."""

    defense_type = DefenseType.PROGENT

    def __init__(self, policy: dict[str, Any] | None = None):
        self._secagent, self._tool, self._validation_error = _load_sdk()
        self._policy = policy
        self._configured = policy is not None
        self.decisions: list[dict[str, Any]] = []
        self.executed_calls: list[dict[str, Any]] = []

    def load_policy(self, policy: dict[str, Any]) -> None:
        self._policy = policy
        self._configured = True

    @property
    def configured(self) -> bool:
        return self._configured

    @staticmethod
    def _policy_value(policy: dict[str, Any]) -> dict[str, list[tuple]]:
        """Normalize upstream tuple policy and SDK README rule dictionaries."""
        normalized: dict[str, list[tuple]] = {}
        for tool, rules in policy.items():
            normalized[tool] = []
            for rule in rules:
                if isinstance(rule, tuple):
                    if len(rule) not in (4, 5):
                        raise ValueError(f"invalid Progent rule tuple for {tool!r}")
                    normalized[tool].append(rule)
                elif isinstance(rule, dict):
                    # The reference checker feeds these conditions to
                    # jsonschema.validate(instance=arg, schema=restriction).
                    # A property schema must therefore be translated into the
                    # enclosing argument-schema shape; the legacy max_value
                    # keyword is not JSON Schema's `maximum`.
                    conditions = {}
                    for arg_name, schema in (rule.get("conditions") or {}).items():
                        schema = dict(schema) if isinstance(schema, dict) else schema
                        if isinstance(schema, dict) and "max_value" in schema:
                            schema["maximum"] = schema.pop("max_value")
                        conditions[arg_name] = schema
                    normalized[tool].append((
                        int(rule.get("priority", 1)),
                        int(rule.get("effect", 0)),
                        conditions,
                        int(rule.get("fallback", 0)),
                    ))
                else:
                    raise ValueError(f"invalid Progent rule for {tool!r}: {type(rule).__name__}")
        return normalized

    def evaluate(self, tool_call: ToolCallRequest | None) -> list[DefenseEvent]:
        if tool_call is None:
            return [DefenseEvent(
                decision=DefenseDecision.ALLOWED,
                confidence=1.0,
                evidence="No tool call to evaluate",
                source=self.defense_type,
                implementation_type=DefenseImplementation.REAL_INTEGRATION,
            )]
        if not self._configured:
            return [DefenseEvent(
                decision=DefenseDecision.NO_SIGNAL,
                confidence=None,
                evidence="Progent policy not configured; no enforcement decision was made",
                source=self.defense_type,
                implementation_type=DefenseImplementation.UNAVAILABLE,
            )]

        name = str(tool_call.tool_name)
        args = dict(tool_call.arguments or {})
        executed: list[dict[str, Any]] = []
        reason: str | None = None
        with _POLICY_LOCK:
            old_policy = self._tool.get_current_config()
            try:
                # The authentic reference implementation uses a module global.
                # Serialize access and restore the host's exact prior state.
                self._tool.update_security_policy(self._policy_value(self._policy or {}))
                # Upstream check_tool_call(None policy) warns and RETURNS;
                # prevent that upstream fail-open edge by installing an
                # explicit empty policy before invoking it.
                if self._tool.get_current_config() is None:
                    raise self._validation_error("Progent policy is not configured (fail-closed)")
                self._secagent.check_tool_call(name, args)
                # The sandbox callback is the only execution point and is
                # unreachable until the actual upstream checker returns.
                executed.append({"tool_name": name, "arguments": args})
            except self._validation_error as exc:
                reason = str(exc)
            except Exception as exc:
                reason = f"Progent enforcement failure (fail-closed): {exc}"
                logger.warning("Progent checker failed for %s: %s", name, exc)
            finally:
                self._tool.update_security_policy(old_policy)

        allowed = reason is None and bool(executed)
        if allowed:
            self.executed_calls.extend(executed)
        self.decisions.append({"tool_name": name, "allowed": allowed, "reason": reason})
        return [DefenseEvent(
            decision=DefenseDecision.ALLOWED if allowed else DefenseDecision.DENIED,
            confidence=None,
            evidence=(
                f"Progent paper checker allowed and sandbox executed '{name}'"
                if allowed else f"Progent paper checker blocked before execution: {reason}"
            ),
            source=self.defense_type,
            implementation_type=DefenseImplementation.REAL_INTEGRATION,
        )]
