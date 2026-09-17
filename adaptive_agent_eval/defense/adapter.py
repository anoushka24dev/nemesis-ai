"""Defense Adapter — normalizes defense outputs into a unified schema."""

from __future__ import annotations

from adaptive_agent_eval.models import (
    DefenseDecision,
    DefenseEvent,
)


class DefenseAdapter:
    """Normalizes raw defense events into a unified format.

    Handles differences between CaMeL, Progent, and Verifier outputs.
    Extracts confidence scores and standardizes decision labels.
    """

    def normalize(self, raw_events: list[DefenseEvent]) -> DefenseEvent:
        """Normalize a list of defense events into a single combined event.

        If multiple defenses disagree, use majority voting.
        If all agree, return the highest-confidence event.
        """
        if not raw_events:
            return DefenseEvent(
                decision=DefenseDecision.NO_SIGNAL,
                confidence=0.0,
                evidence="No defense events to normalize",
                source=None,
            )

        if len(raw_events) == 1:
            return raw_events[0]

        # Majority voting on decision
        decisions = [e.decision for e in raw_events]
        denied_count = decisions.count(DefenseDecision.DENIED)
        allowed_count = decisions.count(DefenseDecision.ALLOWED)

        if denied_count > allowed_count:
            # Majority says denied — return highest-confidence denial
            best = max(
                (e for e in raw_events if e.decision == DefenseDecision.DENIED),
                key=lambda e: e.confidence,
            )
            sources = [e.source.value for e in raw_events if e.decision == DefenseDecision.DENIED]
            best.evidence = f"Majority denied ({sources}): {best.evidence}"
            return best
        elif allowed_count > denied_count:
            # Majority says allowed — return highest-confidence allow
            best = max(
                (e for e in raw_events if e.decision == DefenseDecision.ALLOWED),
                key=lambda e: e.confidence,
            )
            return best
        else:
            # Tie — default to denied (safer)
            best = max(raw_events, key=lambda e: e.confidence)
            best.decision = DefenseDecision.DENIED
            best.evidence = f"Tie-breaking to DENIED: {best.evidence}"
            return best
