"""Outgoing defense scan: the SAME active threat ruleset guards every send.

Requirement: the active defense ruleset used for incoming analysis
(``gmail_auth.analyze_emails`` resolves it from ``backend.feedback.active_ruleset``)
must also gate outgoing composition, replies, and send authorization. This
module provides that scan; ``EmailWorkflowService`` runs it on every
``prepare_*`` (reported, not enforced — preparation is inspection) and every
``submit`` (enforced) message.

Enforcement semantics (decision comes from the ACTIVE ruleset version):

* ``allow`` — proceed with the normal policy checks.
* ``review`` — the message resembles risky content; an explicit per-call
  ``confirm=True`` is required (same confirmation surface as sensitive-content
  and outside-allowlist recipients).
* ``flag`` — the outgoing content matches high-risk threat patterns; the
  action is refused outright and confirmation cannot override it.

The scan is deterministic, local, and uses no model. Its result (including the
ruleset version) is attached to every workflow report and audit entry, so the
active ruleset is provably the same one used for incoming analysis, outgoing
composition, replies, and send authorization.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import threats
from email_workflow.compose import OutgoingMessage
from email_workflow.policy import ConfirmationRequired, PolicyDenied

__all__ = [
    "DefenseBlocked",
    "OutgoingDefense",
    "OutgoingReviewRequired",
]


class DefenseBlocked(PolicyDenied):
    """Outgoing content matched a flag-level threat pattern; never overridable."""


class OutgoingReviewRequired(ConfirmationRequired):
    """Outgoing content needs review-level confirmation before proceeding."""


def _default_rules_provider() -> Callable[[], threats.RuleSet]:
    """Resolve the SAME active ruleset incoming analysis uses.

    ``backend.feedback.active_ruleset`` reads the local feedback store
    (``NEMESIS_FEEDBACK_STORE`` override) and fails safe to the shipped
    defaults on any read/parse error, so classification can never crash or run
    on corrupt data. The import is lazy: ``backend.feedback`` imports
    ``threats`` only, but keeping it lazy mirrors ``gmail_auth.analyze_emails``
    and avoids an import cycle through ``backend.__init__``.
    """

    def provider() -> threats.RuleSet:
        try:
            from backend.feedback import active_ruleset

            return active_ruleset()
        except Exception:  # noqa: BLE001 - fail safe to shipped defaults
            return threats.DEFAULT_RULESET

    return provider


class OutgoingDefense:
    """Scans an outgoing message with the active threat ruleset."""

    def __init__(
        self, rules_provider: Callable[[], threats.RuleSet] | None = None
    ) -> None:
        self._rules_provider = rules_provider or _default_rules_provider()

    def rules(self) -> threats.RuleSet:
        return self._rules_provider()

    def scan(self, message: OutgoingMessage) -> dict[str, Any]:
        """Deterministic threat assessment of an outgoing message.

        Returns the assessment dict plus ``action`` ("send"/"draft") and the
        ``rule_version`` that produced the decision. The message body is
        treated as untrusted data (it quotes a sanitized subject line).
        """
        rules = self.rules()
        # Outgoing messages are our own artifacts; they carry the demo label
        # only so the shared classifier treats them uniformly.
        email = Email_outgoing(message)
        assessment = threats.assess_email(email, rules)
        return {
            "message_id": message.message_id,
            "kind": message.kind,
            "decision": assessment["decision"],
            "risk_level": assessment["risk_level"],
            "risk_score": assessment["risk_score"],
            "threat_types": assessment["threat_types"],
            "indicators": assessment["indicators"],
            "reasons": assessment["reasons"],
            "rule_version": assessment["rule_version"],
            "source": assessment["source"],
        }

    def enforce(self, scan: dict[str, Any], *, confirm: bool) -> None:
        """Apply the scan decision to a submit. Raises on refusal."""
        decision = scan.get("decision")
        if decision == "flag":
            raise DefenseBlocked(
                "outgoing defense scan flagged this message; it will not be "
                "sent or saved even with confirmation "
                f"(rule_version={scan.get('rule_version')})"
            )
        if decision == "review" and not confirm:
            raise OutgoingReviewRequired(
                "outgoing defense scan recommends review of this message; "
                "explicit confirmation is required to proceed "
                f"(rule_version={scan.get('rule_version')})"
            )


def Email_outgoing(message: OutgoingMessage):
    """Build the Email record the shared classifier scans for one message."""
    from gmail_demo.models import Email

    return Email(
        id=message.message_id,
        sender="nemesis-assistant <agent@localhost>",
        subject=message.subject,
        body=message.body,
        labels=["NEMESIS_OUTGOING"],
    )
