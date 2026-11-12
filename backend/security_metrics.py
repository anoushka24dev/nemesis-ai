# -*- coding: utf-8 -*-
"""Security metrics computed from REAL evaluation results and audit events.

Every number this module produces is derived from two concrete sources:

1. The fixed, versioned threat-regression dataset (:data:`threats.REGRESSION_CASES`)
   evaluated against a specific :class:`threats.RuleSet` version.
2. The append-only workflow audit log (``email_workflow.audit.AuditLog``
   records) describing what the outbound workflow actually attempted, denied,
   simulated, or executed.

Nothing here is hardcoded or fabricated; when a denominator is zero the value
is ``None`` (the API/UI renders that as "N/A").

Documented definitions
----------------------
For a ruleset evaluated over the labeled regression dataset:

* **Case labels.** ``expected`` is the trusted ground-truth decision
  (``allow``/``review``/``flag``). ``actual`` is the active ruleset's decision.
* **Eligible attack.** A case whose expected decision is ``review`` or
  ``flag`` — i.e. ground truth says this message is threatening.
* **Successful attack (ASR numerator).** An eligible attack the active
  ruleset decided to ``allow`` — a missed threat, i.e. the "attack" of
  slipping past detection succeeded.
* **Attack Success Rate (ASR)** = successful attacks / eligible attacks.
  ``None`` when there are no eligible attacks.
* **Detection rate (recall)** = detected attacks / eligible attacks, where a
  detected attack has decision ``review`` or ``flag``.
* **Precision** = detected attacks / (all cases decided review/flag).
* **False-positive rate** = benign cases (expected ``allow``) decided
  review/flag / all benign cases.
* **False-negative rate** = missed attacks / eligible attacks. Under this
  protocol FNR and ASR coincide; both are reported because operators look
  for them by different names.

Blast radius (estimated vs confirmed)
-------------------------------------
* **Confirmed impact** counts audit events where a transport reported
  ``executed=True`` — a real-world effect that actually happened. In the
  shipped configuration (simulation mode, mock transport) this is always 0.
* **Estimated potential impact** is a worst-case bound under documented
  assumptions (also returned in the payload):

  - each missed attack is assumed capable of motivating ONE outbound action
    (the reply-to-sender workflow never forwards or reply-alls);
  - outbound actions are capped by the workflow rate limit
    (``rate_limit_per_hour``), so at most that many can leave in an hour;
  - no automatic propagation: the propagation factor is 1.0 (no code path
    forwards a received message onward on its own).

  ``estimated_blast_radius = min(missed_attacks, rate_limit_per_hour) *
  propagation_factor``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

import threats
from gmail_demo.models import Email

__all__ = [
    "ASR_DEFINITION",
    "PROPAGATION_FACTOR",
    "assess_cases",
    "audit_summary",
    "category_breakdown",
    "classification_metrics",
    "full_report",
    "insufficient",
]

ASR_DEFINITION = (
    "ASR = successful attacks / eligible attacks, where an eligible attack is a "
    "labeled regression case whose ground-truth decision is review or flag, and a "
    "successful attack is one the active ruleset decided to 'allow' (missed)."
)

#: No automatic propagation exists in this workflow; documented assumption.
PROPAGATION_FACTOR = 1.0

_INSUFFICIENT = "insufficient_data"


def insufficient(reason: str) -> dict[str, Any]:
    """A structured N/A marker (rendered as 'N/A' by the UI)."""
    return {"value": None, "display": "N/A", "reason": reason}


def _rate(numerator: int, denominator: int) -> dict[str, Any]:
    """A ratio that is honest about zero denominators."""
    if denominator <= 0:
        return insufficient(f"denominator is zero (numerator={numerator})")
    return {
        "value": round(numerator / denominator, 4),
        "numerator": numerator,
        "denominator": denominator,
    }


def _case_email(case: Mapping[str, str]) -> Email:
    return Email(
        id=case["case_id"],
        sender="synthetic@test.invalid",
        subject=case["subject"],
        body=case["body"],
        labels=["NEMESIS_DEMO"],
    )


def assess_cases(
    rules: threats.RuleSet | None = None,
    cases: Sequence[Mapping[str, str]] = threats.REGRESSION_CASES,
) -> list[dict[str, Any]]:
    """Assess every labeled case with one ruleset; return per-case results."""
    rs = rules or threats.DEFAULT_RULESET
    out: list[dict[str, Any]] = []
    for case in cases:
        assessment = threats.assess_email(_case_email(case), rs)
        expected = case.get("expected", "allow")
        actual = assessment["decision"]
        is_attack = expected in ("review", "flag")
        detected = is_attack and actual in ("review", "flag")
        out.append(
            {
                "case_id": case.get("case_id", "?"),
                "expected": expected,
                "actual": actual,
                "is_attack": is_attack,
                "detected": detected,
                "missed": is_attack and actual == "allow",
                "false_alarm": (not is_attack) and actual in ("review", "flag"),
                "risk_score": assessment["risk_score"],
                "risk_level": assessment["risk_level"],
                "threat_types": list(assessment.get("threat_types", [])),
            }
        )
    return out


def classification_metrics(per_case: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Detection rate/recall, precision, FPR, FNR (N/A on zero denominators)."""
    eligible = [c for c in per_case if c["is_attack"]]
    benign = [c for c in per_case if not c["is_attack"]]
    detected = sum(1 for c in eligible if c["detected"])
    missed = sum(1 for c in eligible if c["missed"])
    false_alarms = sum(1 for c in benign if c["false_alarm"])
    correct_benign = len(benign) - false_alarms
    return {
        "eligible_attacks": len(eligible),
        "benign_cases": len(benign),
        "detected_attacks": detected,
        "missed_attacks": missed,
        "false_alarms": false_alarms,
        "correct_benign": correct_benign,
        "detection_rate_recall": _rate(detected, len(eligible)),
        "precision": _rate(detected, detected + false_alarms),
        "false_positive_rate": _rate(false_alarms, len(benign)),
        "false_negative_rate": _rate(missed, len(eligible)),
    }


def asr(per_case: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Attack Success Rate with its eligible/successful counts (see module doc)."""
    eligible = sum(1 for c in per_case if c["is_attack"])
    successful = sum(1 for c in per_case if c["missed"])
    result = _rate(successful, eligible)
    result.update(
        {
            "definition": ASR_DEFINITION,
            "eligible_attacks": eligible,
            "successful_attacks": successful,
        }
    )
    return result


def category_breakdown(
    per_case: Sequence[Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Per threat-category counts, from actual assessments (not estimates)."""
    out: dict[str, dict[str, Any]] = {}
    for case in per_case:
        for category in case.get("threat_types", []):
            entry = out.setdefault(
                str(category),
                {"cases": 0, "attacks": 0, "detected": 0, "missed": 0},
            )
            entry["cases"] += 1
            if case["is_attack"]:
                entry["attacks"] += 1
                if case["detected"]:
                    entry["detected"] += 1
                if case["missed"]:
                    entry["missed"] += 1
    for entry in out.values():
        entry["detection_rate"] = _rate(entry["detected"], entry["attacks"])
    return dict(sorted(out.items()))


def audit_summary(records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Summarize real workflow audit events (append-only, redacted)."""
    records = list(records)
    denied = [r for r in records if r.get("action") == "workflow_denied"]
    simulated = [r for r in records if r.get("action") == "workflow_simulated"]
    transport_ok = [
        r
        for r in records
        if str(r.get("action", "")).startswith("transport_")
        and str(r.get("action", "")).endswith("_ok")
    ]
    executed = [
        r
        for r in records
        if r.get("executed") is True
        and str(r.get("action", "")).startswith("transport_")
    ]
    kill_switch = [r for r in records if r.get("action") == "kill_switch_engaged"]
    defense_blocked = [
        r for r in records if str(r.get("action", "")).startswith("defense_")
    ]
    return {
        "total_events": len(records),
        "unauthorized_actions_blocked": len(denied),
        "defense_events": len(defense_blocked),
        "simulated_actions": len(simulated),
        "transport_ok": len(transport_ok),
        "executed_actions_confirmed": len(executed),
        "kill_switch_events": len(kill_switch),
        "denied_reasons": [str(r.get("reason", ""))[:200] for r in denied[-10:]],
    }


def blast_radius(
    *,
    missed_attacks: int,
    rate_limit_per_hour: int,
    audit: Mapping[str, Any],
) -> dict[str, Any]:
    """Estimated potential impact vs confirmed impact (see module doc)."""
    cap = max(1, int(rate_limit_per_hour))
    estimated = min(missed_attacks, cap) * PROPAGATION_FACTOR
    confirmed = int(audit.get("executed_actions_confirmed", 0))
    return {
        "estimated": {
            "value": round(estimated, 2),
            "basis": (
                "worst-case bound: min(missed_attacks, rate_limit_per_hour) "
                "* propagation_factor"
            ),
            "assumptions": [
                "each missed attack motivates at most one outbound action "
                "(reply-to-sender only; never forward/reply-all)",
                f"outbound actions capped at {cap} per hour by the workflow rate limit",
                f"propagation factor {PROPAGATION_FACTOR}: no automatic "
                "forwarding/propagation code path exists",
            ],
        },
        "confirmed": {
            "value": confirmed,
            "basis": "audit events where a transport reported executed=True",
        },
        "observed_factors": {
            "unauthorized_actions_blocked": audit.get(
                "unauthorized_actions_blocked", 0
            ),
            "simulated_actions": audit.get("simulated_actions", 0),
            "kill_switch_events": audit.get("kill_switch_events", 0),
        },
    }


def full_report(
    rules: threats.RuleSet | None = None,
    *,
    audit_records: Sequence[Mapping[str, Any]] = (),
    rate_limit_per_hour: int = 5,
    cases: Sequence[Mapping[str, str]] = threats.REGRESSION_CASES,
    evaluated_at: str | None = None,
) -> dict[str, Any]:
    """The complete metrics payload surfaced by the backend and extension."""
    rs = rules or threats.DEFAULT_RULESET
    per_case = assess_cases(rs, cases)
    audit = audit_summary(audit_records)
    classification = classification_metrics(per_case)
    return {
        "ruleset_version": rs.version,
        "evaluated_at": evaluated_at
        or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sample_size": len(per_case),
        "dataset": "threats.REGRESSION_CASES (fixed synthetic regression set)",
        "asr": asr(per_case),
        "classification": classification,
        "attack_categories": category_breakdown(per_case),
        "audit": audit,
        "blast_radius": blast_radius(
            missed_attacks=classification["missed_attacks"],
            rate_limit_per_hour=rate_limit_per_hour,
            audit=audit,
        ),
        "per_case": per_case,
    }
