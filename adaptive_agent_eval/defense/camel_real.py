"""Bounded Nemesis adapter for the vendored Google Research CaMeL core.

Upstream source: https://github.com/google-research/camel-prompt-injection
Revision: f083b6b396399d3b3c7f2ddaf613a5945eaf32d8 (Apache-2.0; see vendor/.../LICENSE).

This adapter uses the actual CaMeL value wrappers, AST interpreter,
SecurityPolicyEngine and pre-call policy boundary. It supplies a small,
sandboxed tool namespace rather than claiming to reproduce the upstream
AgentDojo model pipeline.

HONEST SCOPE (partial CaMeL integration): the restricted interpreter,
capability/provenance values and SecurityPolicyEngine are the real vendored
Google code and the enforcement happens inside them. NOT reproduced here: the
quarantined/privileged LLM pipeline that *generates* CaMeL code from untrusted
content, the AgentDojo task/environment integration, and CaMeL's original
tool library. Nemesis supplies the code to execute, the tool namespace and the
policy. Provenance for arguments is likewise constructed by this adapter from
the payload boundary (raw_text present => untrusted source), not tracked from
a live dual-LLM data flow. Do not describe this as the full CaMeL system.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Any

from adaptive_agent_eval.models import (
    DefenseDecision,
    DefenseEvent,
    DefenseImplementation,
    DefenseType,
    ToolCallRequest,
)

logger = logging.getLogger(__name__)
IMPLEMENTATION = "camel-upstream-interpreter"
SOURCE_REPO = "https://github.com/google-research/camel-prompt-injection"
SOURCE_REVISION = "f083b6b396399d3b3c7f2ddaf613a5945eaf32d8"
SOURCE_LICENSE = "Apache-2.0"
PRIVILEGED_TOOLS = {
    "send_email", "send message", "transfer_funds", "transfer funds",
    "disclose sensitive record", "edit_file", "execute_command",
    "read restricted file",
}


def _vendor_src_path() -> str:
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(here, "vendor", "camel-prompt-injection", "src")


def _load_camel():
    src = _vendor_src_path()
    if not os.path.isdir(src):
        raise RuntimeError(f"vendored CaMeL core not found at {src}")
    if src not in sys.path:
        sys.path.insert(0, src)
    try:
        from camel import security_policy
        from camel.capabilities import Capabilities
        from camel.capabilities import utils as cap_utils
        from camel.capabilities.readers import Public
        from camel.capabilities.sources import Tool
        from camel.interpreter import interpreter, namespace, result, value
    except Exception as exc:
        raise RuntimeError(f"vendored CaMeL core not importable: {exc}") from exc
    return {
        "security_policy": security_policy,
        "Capabilities": Capabilities,
        "utils": cap_utils,
        "Public": Public,
        "Tool": Tool,
        "interpreter": interpreter,
        "namespace": namespace,
        "result": result,
        "value": value,
    }


def _make_policy_engine(camel: dict[str, Any], privileged_tools: set[str]):
    """Build an upstream SecurityPolicyEngine with a bounded Nemesis policy.

    The reference engine's concrete check_policy implementation enforces
    private dependencies, applies policies in order and defaults to denial.
    Its base_security_policy adds the upstream public-reader check for tool
    arguments. The only adaptation is the explicit set of sandbox tool names.
    """
    SP = camel["security_policy"]
    CAP = camel["utils"]

    def trusted_recipient_policy(recipient_key: str, content_keys: tuple[str, ...] = ()):
        def policy(tool_name, kwargs):
            recipient = kwargs.get(recipient_key)
            if recipient is None or not CAP.is_trusted(recipient):
                return SP.Denied("recipient is not directly authorized by a trusted source")
            for key in content_keys:
                content = kwargs.get(key)
                if content is not None and not CAP.can_readers_read_value({recipient.raw}, content):
                    return SP.Denied("recipient cannot read the supplied content")
            return SP.Allowed()
        return policy

    def trusted_fields_policy(*field_names: str):
        def policy(tool_name, kwargs):
            if any(name not in kwargs or not CAP.is_trusted(kwargs[name]) for name in field_names):
                return SP.Denied("required argument is not directly authorized by a trusted source")
            return SP.Allowed()
        return policy

    policies = {
        "send message": trusted_recipient_policy("recipient", ("body",)),
        "send_email": trusted_recipient_policy("to", ("body",)),
        "transfer funds": trusted_recipient_policy("recipient"),
        "transfer_funds": trusted_recipient_policy("recipient"),
        "disclose sensitive record": trusted_recipient_policy("recipient", ("record",)),
        "read restricted file": trusted_fields_policy("path"),
        "read email": trusted_fields_policy("message_id"),
        "list events": trusted_fields_policy("day"),
        "create event": trusted_fields_policy("title", "when"),
    }

    class NemesisPolicyEngine(SP.SecurityPolicyEngine):
        def __init__(self):
            self.policies = [(name, policy) for name, policy in policies.items()]
            # These read-only operations do not mutate the environment. CaMeL's
            # upstream engine permits them without requiring every input value
            # to be public; output provenance remains attached by the interpreter.
            self.no_side_effect_tools: set[str] = {"read email", "list events"}
            self.decisions: list[dict[str, Any]] = []

        def check_policy(self, tool_name, kwargs, dependencies):
            result = super().check_policy(tool_name, kwargs, dependencies)
            self.decisions.append({
                "tool_name": tool_name,
                "allowed": isinstance(result, SP.Allowed),
                "reason": getattr(result, "reason", None),
                "argument_provenance": {
                    key: _capability_labels(camel, item)
                    for key, item in kwargs.items()
                },
                "dependency_provenance": [
                    _capability_labels(camel, item) for item in dependencies
                ],
            })
            return result

    return NemesisPolicyEngine()


def _capability_labels(camel: dict[str, Any], value: Any) -> dict[str, Any]:
    """Describe source/reader labels only; never include the wrapped value."""
    metadata = getattr(value, "metadata", None)
    if metadata is None:
        return {"sources": [], "readers": "unknown"}
    readers = metadata.readers_set
    return {
        "sources": sorted(repr(source) for source in metadata.sources_set),
        "readers": "public" if isinstance(readers, camel["Public"]) else sorted(map(str, readers)),
    }


class _PolicyCheckedSandboxCallable:
    """CaMeL callable value for externally checked tools.

    CaMeL's interpreter exempts its own CaMeLFunction helper objects from
    denied-policy exceptions (they are treated as pure builtins). This
    subclasses the real CaMeL callable value protocol, not CaMeLFunction, and
    follows the upstream AgentDojoFunction execution boundary instead.
    """

    def __new__(cls, camel: dict[str, Any], name: str, callback):
        base = camel["value"].CaMeLCallable

        class PolicyCheckedCallable(base):
            is_builtin = False
            is_class_method = False
            _bound_python_value = None

            def __init__(self):
                self._camel = camel
                self._python_value = callback
                self._metadata = camel["Capabilities"].camel()
                self._dependencies = ()
                self._name = name
                self._recv = None

            @property
            def raw(self):
                return self._python_value

            @property
            def raw_type(self):
                return type(self._python_value).__name__

            def get_dependencies(self, visited_objects=frozenset()):
                return self._dependencies, frozenset({id(self)})

            def name(self):
                return camel["value"].CaMeLStr.from_raw(
                    self._name, camel["Capabilities"].camel(), (self,)
                )

            def freeze(self):
                return camel["value"].CaMeLNone(camel["Capabilities"].camel(), (self,))

            def string(self):
                return self.name().add(camel["value"].CaMeLStr.from_raw(
                    "()", camel["Capabilities"].camel(), (self,)
                ))

            def wrap_output(self, output, args, kwargs, namespace):
                return camel["value"].value_from_raw(
                    output,
                    camel["Capabilities"](
                        frozenset({camel["Tool"](name)}), camel["Public"]()
                    ),
                    namespace,
                    (self, args, kwargs),
                )

            def call(self, args, kwargs, namespace):
                output = callback(*args.raw, **kwargs.raw)
                args_by_keyword = self.make_args_by_keyword_preserve_values(args, kwargs)
                return self.wrap_output(output, args, kwargs, namespace), {
                    key: item.raw for key, item in args_by_keyword.items()
                }

            def bind_recv(self, recv):
                self._recv = recv

            def receiver(self):
                return self._recv

            def make_args_by_keyword_preserve_values(self, args, kwargs):
                return {str(i): item for i, item in enumerate(args.iterate_python())} | {
                    key.raw: item for key, item in kwargs._python_value.items()
                }

        return PolicyCheckedCallable()


class RealCamelDefense:
    """Run each ToolCallRequest through CaMeL's actual restricted interpreter."""

    defense_type = DefenseType.CAMEL

    def __init__(self, private_tools: set[str] | None = None):
        self._camel = _load_camel()
        self._private_tools = set(private_tools or PRIVILEGED_TOOLS)
        self._engine = _make_policy_engine(self._camel, self._private_tools)
        self.decisions: list[dict[str, Any]] = []
        self.executed_calls: list[dict[str, Any]] = []

    def _argument_value(self, raw: Any, untrusted: bool):
        C = self._camel
        if untrusted:
            capabilities = C["Capabilities"](
                sources_set=frozenset({C["Tool"]("untrusted_input", frozenset())}),
                readers_set=frozenset(),
            )
        else:
            capabilities = C["Capabilities"].default()
        return C["value"].value_from_raw(raw, capabilities, C["namespace"].Namespace(), ())

    def evaluate(self, tool_call: ToolCallRequest | None) -> list[DefenseEvent]:
        if tool_call is None:
            return [DefenseEvent(
                decision=DefenseDecision.ALLOWED,
                confidence=1.0,
                evidence="No tool call to evaluate",
                source=self.defense_type,
                implementation_type=DefenseImplementation.REAL_INTEGRATION,
            )]

        C = self._camel
        name = str(tool_call.tool_name)
        args = dict(tool_call.arguments or {})
        raw_text = str(tool_call.raw_text or "")
        untrusted_context = bool(raw_text)
        wrapped_args = {
            key: self._argument_value(value, untrusted_context)
            for key, value in args.items()
        }
        trusted_intent = None
        if name in self._private_tools:
            # Preserve source/provenance for the task input itself, in addition
            # to the explicit values that form the arguments. The upstream
            # interpreter's STRICT mode passes this dependency to policy.
            intent_text = raw_text or "no trusted user instruction provided"
            trusted_intent = self._argument_value(
                intent_text,
                untrusted=bool(raw_text),
            )
        recorded: list[dict[str, Any]] = []

        def _sandbox_tool(**kwargs):
            # The upstream interpreter calls this only after the configured
            # SecurityPolicyEngine returns Allowed. Preserve plain values as
            # sandbox execution evidence, not as actual external side effects.
            recorded.append({"tool_name": name, "arguments": dict(kwargs)})
            return "sandbox tool executed"

        # No builtins/imports are exposed. The sole function is the proposed
        # operation, and the upstream interpreter checks policy immediately
        # before calling it in _eval_call.
        callable_value = _PolicyCheckedSandboxCallable(
            C, name=name, callback=_sandbox_tool
        )
        if any(not str(key).isidentifier() for key in wrapped_args):
            self.decisions.append({
                "tool_name": name,
                "allowed": False,
                "reason": "tool argument name is not a valid CaMeL identifier",
            })
            return [DefenseEvent(
                decision=DefenseDecision.DENIED,
                confidence=None,
                evidence="CaMeL interpreter blocked before tool execution: invalid argument identifier",
                source=self.defense_type,
                implementation_type=DefenseImplementation.REAL_INTEGRATION,
            )]
        tool_namespace = C["namespace"].Namespace(
            variables={"nemesis_tool": callable_value, **wrapped_args}
        )
        call_args = ", ".join(f"{key}={key}" for key in wrapped_args)
        code = f"nemesis_tool({call_args})"
        try:
            interpreted, _, _, _ = C["interpreter"].parse_and_interpret_code(
                f"```python\n{code}\n```",
                tool_namespace,
                [],
                (*wrapped_args.values(), *(() if trusted_intent is None else (trusted_intent,))),
                C["interpreter"].EvalArgs(
                    self._engine,
                    C["interpreter"].MetadataEvalMode.STRICT,
                ),
            )
            if isinstance(interpreted, C["result"].Error):
                raise interpreted.error.exception
            allowed = bool(recorded)
            reason = "upstream CaMeL interpreter executed the policy-approved sandbox call"
        except Exception as exc:
            allowed = False
            reason = f"CaMeL interpreter/policy failure (fail-closed): {exc}"
            logger.warning("CaMeL interpreter rejected %s: %s", name, exc)

        if allowed:
            self.executed_calls.extend(recorded)
        self.decisions.append({"tool_name": name, "allowed": allowed, "reason": reason})
        return [DefenseEvent(
            decision=DefenseDecision.ALLOWED if allowed else DefenseDecision.DENIED,
            confidence=None,
            evidence=(
                f"CaMeL interpreter allowed and executed '{name}'"
                if allowed
                else f"CaMeL interpreter blocked before tool execution: {reason}"
            ),
            source=self.defense_type,
            implementation_type=DefenseImplementation.REAL_INTEGRATION,
        )]
