"""Real read-only Gmail target adapter.

This adapter does not fabricate inbox data. On every turn it:

1. reads ``NEMESIS_DEMO``-labelled messages through ``gmail_auth`` with the
   existing ``gmail.readonly`` OAuth scope;
2. runs the repository's real local Ollama analysis path
   (``backend.local_llm.analyze_local``), which is the same analysis engine
   used by the Stage B backend; and
3. returns the message identity, classifier decision, proposed action and
   read-only security observations to the harness.

No Gmail write is attempted or possible through this adapter.
"""

from __future__ import annotations

import time
from typing import Any

from adaptive_agent_eval.models import AttackPayload, ToolCallRequest
from adaptive_agent_eval.target.adapter import (
    BaseTargetAdapter,
    TargetCapability,
    TargetDeclaration,
    TargetExecutionResult,
    TargetSession,
)

READ_ONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


class GmailReadOnlyTargetAdapter(BaseTargetAdapter):
    """Evaluate the real Gmail analysis agent over real labelled messages."""

    def __init__(
        self,
        target_id: str = "gmail-agent",
        *,
        max_results: int = 5,
        model: str = "llama3.1:8b",
        timeout_seconds: float = 120.0,
    ) -> None:
        self._target_id = target_id
        self._max_results = max(1, min(int(max_results), 20))
        self._model = model
        self._timeout_seconds = float(timeout_seconds)

    def declaration(self) -> TargetDeclaration:
        return TargetDeclaration(
            target_id=self._target_id,
            name="Gmail read-only agent",
            description=(
                "Real NEMESIS_DEMO Gmail messages analyzed by the local "
                "Ollama-backed Stage B analysis engine; gmail.readonly only"
            ),
            capabilities=frozenset(
                {
                    TargetCapability.SINGLE_TURN,
                    TargetCapability.EVIDENCE_COLLECTION,
                }
            ),
            execution_mode="real",
            timeout_seconds=self._timeout_seconds,
            supported_tools=("read email",),
        )

    def execute_turn(
        self,
        session: TargetSession,
        prompt_or_payload: str | AttackPayload,
        available_tools: list[str] | None = None,
    ) -> TargetExecutionResult:
        started = time.time()
        request_text = (
            prompt_or_payload.text
            if isinstance(prompt_or_payload, AttackPayload)
            else str(prompt_or_payload)
        )
        try:
            from gmail_auth import (
                build_gmail_service,
                fetch_nemesis_demo_emails,
                get_credentials,
            )

            creds = get_credentials(open_browser=False, timeout_seconds=1)
            scopes = set(getattr(creds, "scopes", None) or [])
            if scopes != {READ_ONLY_SCOPE}:
                raise RuntimeError(
                    "Gmail credentials do not have exactly the read-only scope"
                )
            emails = fetch_nemesis_demo_emails(
                build_gmail_service(creds), max_results=self._max_results
            )
            if not emails:
                return self._result(
                    session,
                    started,
                    output_text="No NEMESIS_DEMO Gmail messages are available.",
                    evidence={
                        "provider": "gmail",
                        "scope": READ_ONLY_SCOPE,
                        "read_only": True,
                        "email_count": 0,
                    },
                    observations={},
                )

            from backend.local_llm import analyze_local

            analysis = analyze_local(
                emails,
                demo_mode=True,
                on_model_failure="error",
            )
            decisions = list(analysis.get("defense") or [])
            by_id = {str(row.get("email_id")): row for row in decisions}
            tool_calls: list[ToolCallRequest] = []
            messages: list[dict[str, Any]] = []
            for email in emails:
                row = by_id.get(str(email.id), {})
                decision = str(row.get("decision") or "unavailable")
                threat_types = list(row.get("threat_types") or [])
                action_check = row.get("action_check") or {}
                tool_calls.append(
                    ToolCallRequest(
                        tool_name="read email",
                        arguments={
                            "message_id": str(email.id),
                            "decision": decision,
                            "read_only": True,
                        },
                        raw_text=request_text,
                    )
                )
                messages.append(
                    {
                        "message_id": str(email.id),
                        "sender": str(email.sender),
                        "subject": str(email.subject),
                        "labels": list(email.labels),
                        "threat_types": threat_types,
                        "risk_level": row.get("risk_level"),
                        "risk_score": row.get("risk_score"),
                        "decision": decision,
                        "action_check": action_check,
                        "proposed_action": "read",
                        "action_executed": False,
                        "read_only": True,
                    }
                )

            prompt_injection = any(
                "prompt_injection" in (m["threat_types"] or []) for m in messages
            )
            sensitive = any(
                "sensitive_pii" in (m["threat_types"] or []) for m in messages
            )
            blocked = any(m["decision"] in {"flag", "block"} for m in messages)
            evidence = {
                "provider": "gmail",
                "scope": READ_ONLY_SCOPE,
                "read_only": True,
                "label": analysis.get("label"),
                "email_count": len(messages),
                "messages": messages,
                "prompt_injection_detected": prompt_injection,
                "sensitive_data_detected": sensitive,
                "threat_classifications": [
                    {"message_id": m["message_id"], "threat_types": m["threat_types"]}
                    for m in messages
                ],
                "agent_decision": {
                    "decisions": {m["message_id"]: m["decision"] for m in messages},
                    "blocked_or_flagged": blocked,
                },
                "proposed_action": "read",
                "actual_action": "read",
                "action_executed": False,
                "unauthorized_action_attempted": False,
                "unauthorized_disclosure": False,
                # Required by the evaluator's evidence path. These are
                # observations from a read-only analysis run, not model claims.
                "ground_truth": {
                    "unauthorized_access": False,
                    "exfiltrated": False,
                    "disclosed": False,
                },
                "model": analysis.get("model"),
                "model_called": analysis.get("model_called"),
                "analysis_status": analysis.get("status"),
                "analysis_summary": analysis.get("summary"),
            }
            observations = {
                "unauthorized_access": False,
                "exfiltrated": False,
                "disclosed": False,
                "action_attempted": False,
                "action_executed": False,
                "read_only": True,
            }
            output = (
                f"Analyzed {len(messages)} real Gmail message(s); "
                f"prompt_injection={prompt_injection}; "
                f"sensitive_data={sensitive}; decisions="
                + ", ".join(f"{m['message_id']}:{m['decision']}" for m in messages)
            )
            return self._result(
                session,
                started,
                output_text=output,
                tool_calls=tool_calls,
                evidence=evidence,
                observations=observations,
                raw_response={"analysis": analysis},
            )
        except Exception as exc:  # noqa: BLE001 - must become a technical failure
            return self._result(
                session,
                started,
                output_text="",
                evidence={"provider": "gmail", "scope": READ_ONLY_SCOPE},
                observations={},
                transport_error=f"Gmail target error: {type(exc).__name__}: {exc}",
                is_technical_failure=True,
            )

    def _result(
        self,
        session: TargetSession,
        started: float,
        *,
        output_text: str,
        evidence: dict[str, Any],
        observations: dict[str, Any],
        tool_calls: list[ToolCallRequest] | None = None,
        raw_response: Any = None,
        transport_error: str | None = None,
        is_technical_failure: bool = False,
    ) -> TargetExecutionResult:
        duration = time.time() - started
        result = TargetExecutionResult(
            target_id=self._target_id,
            session_id=session.session_id,
            correlation_id=session.correlation_id,
            execution_mode="real",
            output_text=output_text,
            tool_calls=list(tool_calls or []),
            raw_response=raw_response,
            evidence=evidence,
            duration_seconds=duration,
            transport_error=transport_error,
            is_technical_failure=is_technical_failure,
            observations=observations,
        )
        session.turns.append({"input": "gmail-readonly-turn", "output": output_text})
        return result
