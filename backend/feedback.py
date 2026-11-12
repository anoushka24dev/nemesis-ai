"""Local, versioned, auditable feedback loop for the deterministic threat rules.

Scope — what this actually adapts
---------------------------------
ONLY the per-rule weights and the review/flag decision thresholds of the
*deterministic* classifier in :mod:`threats`. It never touches Gemini, and no
ordinary API call trains anything: model outputs are findings, never ground
truth. The system is only "adaptive" in the narrow sense below, and even then
every change is a **new immutable version** of the ruleset.

The controlled loop (7 steps)
-----------------------------
1. ``record_prediction`` — a labeled test email is assessed; the prediction,
   evidence labels, rule version and outcome are stored (no bodies, no PII).
2. ``submit_correction`` — an explicit reviewer correction or trusted test
   label (``expected`` decision) is recorded as *pending*. Nothing changes yet.
3. ``propose_adjustment`` — an operator proposes a weight/threshold change
   citing at least ``MIN_CONFIRMATIONS`` pending corrections that describe a
   real prediction mismatch. Values outside ``FLOORS``/``CAPS`` are refused,
   so feedback can never weaken a rule below its security floor.
4. ``apply_proposal`` — the candidate ruleset is evaluated on the FIXED
   regression dataset (:data:`threats.REGRESSION_CASES`) *before* activation;
   verdict = improved / unchanged / regressed. A regressed candidate is
   REJECTED and nothing changes.
5. Approved changes become a new version ``threat-rules-vN`` (parent recorded),
   the referenced corrections flip to ``applied``, everything lands in an
   append-only audit log.
6. ``revert`` activates a prior version again — updates are reversible.
7. ``evaluate`` re-runs the fixed dataset against any version and reports
   improved / regressed / unchanged vs the parent version.

Guarantees and limits
---------------------
- A single feedback item can never alter the active rules (``MIN_CONFIRMATIONS``
  + explicit ``apply`` + regression gate + floors).
- Persistence is one local JSON file (default ``backend/data/feedback_store.json``,
  override with ``NEMESIS_FEEDBACK_STORE``). Written atomically.
- Stored records carry email_ids, labels, scores and evidence *labels* only —
  never email bodies or raw sensitive identifiers.
- Trust boundary: whoever can run the CLI is a trusted local reviewer;
  this is not multi-user and does not verify reviewer identity.
- Not online learning, not model fine-tuning, no cross-run personalization.

CLI
---
::

    python -m backend.feedback show
    python -m backend.feedback evaluate [--version threat-rules-v1]
    python -m backend.feedback submit --email-id ID --expected review \
        --reviewer alice --reason "should have been reviewed"
    python -m backend.feedback propose --rule urgency --weight 0.25 \
        --feedback ID1 --feedback ID2 --rationale "..."
    python -m backend.feedback apply --proposal PID
    python -m backend.feedback revert [--version threat-rules-v2]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

import threats

DEFAULT_STORE_PATH = Path(__file__).resolve().parent / "data" / "feedback_store.json"

# How many independent confirmed corrections must exist before a weight change
# may even be proposed, let alone applied.
MIN_CONFIRMATIONS = 2

CORRECTION_SOURCES = ("reviewer", "trusted_test_label")
DECISIONS = threats.DECISIONS

__all__ = [
    "DEFAULT_STORE_PATH",
    "MIN_CONFIRMATIONS",
    "FeedbackError",
    "active_ruleset",
    "apply_proposal",
    "evaluate",
    "propose_adjustment",
    "record_prediction",
    "revert",
    "show",
    "store_path",
    "submit_correction",
]


class FeedbackError(RuntimeError):
    """A refused feedback operation (invalid input, guard triggered, etc.)."""


# --------------------------------------------------------------------------
# Store plumbing
# --------------------------------------------------------------------------


def store_path(path: str | Path | None = None) -> Path:
    if path:
        return Path(path)
    env = os.getenv("NEMESIS_FEEDBACK_STORE", "").strip()
    return Path(env) if env else DEFAULT_STORE_PATH


def _empty_data() -> dict:
    v = threats.DEFAULT_RULESET
    return {
        "schema": 1,
        "active_version": v.version,
        "versions": {
            v.version: {
                "scores": dict(v.scores),
                "review_threshold": v.review_threshold,
                "flag_threshold": v.flag_threshold,
                "parent": None,
                "created_at": _now(),
                "note": "shipped defaults",
            }
        },
        "predictions": [],
        "corrections": [],
        "proposals": [],
        "audit": [],
    }


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _load(path: Path) -> dict:
    if not path.exists():
        return _empty_data()
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        # Fail safe: a corrupt store never disables classification; it falls
        # back to the shipped ruleset and makes the problem visible.
        raise FeedbackError(f"feedback store unreadable ({path}): {exc}") from exc
    if not isinstance(raw, dict) or "active_version" not in raw:
        raise FeedbackError(f"feedback store has unexpected shape: {path}")
    return raw


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)


def _ruleset_from(data: dict, version: str | None = None) -> threats.RuleSet:
    version = version or data["active_version"]
    entry = data["versions"].get(version)
    if entry is None:
        raise FeedbackError(f"unknown rule version: {version}")
    return threats.RuleSet(
        version=version,
        scores=dict(entry["scores"]),
        review_threshold=float(entry["review_threshold"]),
        flag_threshold=float(entry["flag_threshold"]),
        parent=entry.get("parent"),
        note=entry.get("note", ""),
    )


def active_ruleset(path: str | Path | None = None) -> threats.RuleSet:
    """Resolve the active ruleset for classification.

    Missing store -> shipped defaults (this is the normal state before first
    use; no file is created by reading). Unreadable store -> shipped defaults
    + no crash classification (failure-raising variant for operators is
    ``show``/``evaluate``).
    """
    p = store_path(path)
    if not p.exists():
        return threats.DEFAULT_RULESET
    try:
        data = _load(p)
        return _ruleset_from(data)
    except FeedbackError:
        return threats.DEFAULT_RULESET


def _audit(data: dict, action: str, detail: dict) -> None:
    data.setdefault("audit", []).append({"at": _now(), "action": action, **detail})


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------
# Step 1 + 2: predictions and corrections
# --------------------------------------------------------------------------


def record_prediction(
    email_id: str,
    assessment: dict,
    *,
    path: str | Path | None = None,
) -> str:
    """Store one deterministic prediction (evidence labels only, no bodies).

    NOTE: the live ``analyze_emails`` API path does not auto-record; recording
    is an explicit, operator-driven step so production traffic never silently
    grows the feedback store. The CLI ``predict`` subcommand records as part
    of the documented evaluation loop.
    """
    if not email_id or not isinstance(email_id, str):
        raise FeedbackError("email_id must be a non-empty string")
    decision = assessment.get("decision")
    if decision not in DECISIONS:
        raise FeedbackError(f"assessment decision must be one of {DECISIONS}")
    # Ground-truth discipline: only the deterministic ruleset may be stored
    # as a prediction. Model outputs are findings, never labels.
    source = str(assessment.get("source") or "deterministic_rules")
    if source != "deterministic_rules":
        raise FeedbackError(
            f"refusing to record a {source!r} assessment as ground truth; "
            "only 'deterministic_rules' predictions are recordable"
        )
    p = store_path(path)
    data = _load(p)
    pred_id = _new_id("pred")
    data["predictions"].append(
        {
            "prediction_id": pred_id,
            "email_id": email_id,
            "decision": decision,
            "risk_level": assessment.get("risk_level"),
            "risk_score": assessment.get("risk_score"),
            # Evidence as *labels* (rule ids / threat types) only — never the
            # matched text, never anything from the email body.
            "evidence_labels": list(assessment.get("threat_types", [])),
            "rule_version": assessment.get("rule_version", data["active_version"]),
            "source": assessment.get("source", "deterministic_rules"),
            # Model output is explicitly NOT ground truth: only predictions
            # from the deterministic ruleset are recorded here.
            "predicted_at": _now(),
        }
    )
    _audit(data, "record_prediction", {"prediction_id": pred_id, "email_id": email_id})
    _save(p, data)
    return pred_id


def submit_correction(
    email_id: str,
    expected: str,
    reviewer: str,
    *,
    reason: str = "",
    source: str = "reviewer",
    path: str | Path | None = None,
) -> str:
    """Record an explicit human/trusted-test correction (pending; inert until applied)."""
    if expected not in DECISIONS:
        raise FeedbackError(f"expected must be one of {DECISIONS}, got {expected!r}")
    if source not in CORRECTION_SOURCES:
        raise FeedbackError(f"source must be one of {CORRECTION_SOURCES}")
    if not reviewer or not reviewer.strip():
        raise FeedbackError("reviewer is required")
    p = store_path(path)
    data = _load(p)
    fb_id = _new_id("fb")
    data["corrections"].append(
        {
            "feedback_id": fb_id,
            "email_id": email_id,
            "expected": expected,
            "reviewer": reviewer.strip(),
            "reason": reason.strip()[:500],
            "source": source,
            "status": "pending",
            "active_version_at_submit": data["active_version"],
            "submitted_at": _now(),
        }
    )
    _audit(
        data,
        "submit_correction",
        {"feedback_id": fb_id, "email_id": email_id, "expected": expected},
    )
    _save(p, data)
    return fb_id


def _is_mismatched(data: dict, feedback_id: str) -> dict | None:
    """Corroborated mismatch: correction expected != recorded prediction decision."""
    fb = next(
        (f for f in data["corrections"] if f["feedback_id"] == feedback_id), None
    )
    if fb is None:
        raise FeedbackError(f"unknown feedback id: {feedback_id}")
    if fb["status"] != "pending":
        raise FeedbackError(f"feedback {feedback_id} is not pending")
    pred = next(
        (
            pr
            for pr in reversed(data["predictions"])
            if pr["email_id"] == fb["email_id"]
        ),
        None,
    )
    if pred is None:
        raise FeedbackError(
            f"feedback {feedback_id} has no recorded prediction for "
            f"email {fb['email_id']!r}; predictions must exist first"
        )
    if pred["decision"] == fb["expected"]:
        return None  # correction agrees with the prediction -> no mismatch
    return fb


# --------------------------------------------------------------------------
# Step 3: proposals
# --------------------------------------------------------------------------


def propose_adjustment(
    rule_id: str,
    new_weight: float,
    feedback_ids: list[str],
    rationale: str,
    *,
    path: str | Path | None = None,
) -> str:
    """Propose a rule-weight change corroborated by >= MIN_CONFIRMATIONS mismatches."""
    if rule_id not in threats.DEFAULT_SCORES and rule_id not in (
        "review_threshold",
        "flag_threshold",
    ):
        raise FeedbackError(f"unknown rule: {rule_id}")
    try:
        new_weight = float(new_weight)
    except (TypeError, ValueError) as exc:
        raise FeedbackError("weight must be numeric") from exc
    if rule_id in threats.FLOORS:
        lo, hi = threats.FLOORS[rule_id], threats.CAPS[rule_id]
        if not (lo <= new_weight <= hi):
            raise FeedbackError(
                f"weight {new_weight} outside admissible range [{lo}, {hi}] "
                "for this rule (security floor/cap)"
            )
    if rule_id == "review_threshold":
        lo, hi = threats.REVIEW_THRESHOLD_RANGE
        if not lo <= new_weight <= hi:
            raise FeedbackError(
                f"weight {new_weight} outside admissible range [{lo}, {hi}] "
                "for review_threshold"
            )
    elif rule_id == "flag_threshold":
        lo, hi = threats.FLAG_THRESHOLD_RANGE
        if not lo <= new_weight <= hi:
            raise FeedbackError(
                f"weight {new_weight} outside admissible range [{lo}, {hi}] "
                "for flag_threshold"
            )
    if len(feedback_ids) < MIN_CONFIRMATIONS:
        raise FeedbackError(
            f"at least {MIN_CONFIRMATIONS} corroborating corrections required, "
            f"got {len(feedback_ids)}"
        )
    if not rationale or not rationale.strip():
        raise FeedbackError("rationale is required for auditability")

    p = store_path(path)
    data = _load(p)
    mismatches = [fb for fb in (_is_mismatched(data, fid) for fid in feedback_ids) if fb]
    if len(mismatches) < MIN_CONFIRMATIONS:
        raise FeedbackError(
            f"only {len(mismatches)} of the supplied corrections describe a real "
            f"prediction mismatch; {MIN_CONFIRMATIONS} required"
        )

    if rule_id in threats.DEFAULT_SCORES:
        old_weight = _ruleset_from(data).weight(rule_id)
    else:
        old_weight = float(
            getattr(_ruleset_from(data), rule_id)
        )

    proposal_id = _new_id("prop")
    data["proposals"].append(
        {
            "proposal_id": proposal_id,
            "rule_id": rule_id,
            "old_weight": old_weight,
            "new_weight": new_weight,
            "feedback_ids": [f["feedback_id"] for f in mismatches],
            "rationale": rationale.strip()[:500],
            "base_version": data["active_version"],
            "status": "pending",
            "created_at": _now(),
        }
    )
    _audit(
        data,
        "propose_adjustment",
        {"proposal_id": proposal_id, "rule_id": rule_id, "new_weight": new_weight},
    )
    _save(p, data)
    return proposal_id


def _candidate_ruleset(
    base: threats.RuleSet, rule_id: str | None, new_weight: float | None
) -> threats.RuleSet:
    scores = dict(base.scores)
    rv, ft = base.review_threshold, base.flag_threshold
    if rule_id is not None and new_weight is not None:
        if rule_id in threats.DEFAULT_SCORES:
            scores[rule_id] = new_weight
        elif rule_id == "review_threshold":
            lo, hi = threats.REVIEW_THRESHOLD_RANGE
            if not lo <= new_weight <= hi:
                raise FeedbackError(f"review_threshold {new_weight} outside [{lo}, {hi}]")
            rv = new_weight
        elif rule_id == "flag_threshold":
            lo, hi = threats.FLAG_THRESHOLD_RANGE
            if not lo <= new_weight <= hi:
                raise FeedbackError(f"flag_threshold {new_weight} outside [{lo}, {hi}]")
            ft = new_weight
        else:
            raise FeedbackError(f"unknown adjustable parameter: {rule_id}")
    return threats.RuleSet(
        version=base.version + "-candidate",
        scores=scores,
        review_threshold=rv,
        flag_threshold=ft,
        parent=base.version,
    )


def _compare(before: dict, after: dict) -> str:
    if after["accuracy"] > before["accuracy"]:
        return "improved"
    if after["accuracy"] < before["accuracy"]:
        return "regressed"
    return "unchanged"


# --------------------------------------------------------------------------
# Steps 4-5: apply with regression gate; Step 6: revert; Step 7: evaluate
# --------------------------------------------------------------------------


def apply_proposal(
    proposal_id: str,
    *,
    path: str | Path | None = None,
) -> dict:
    """Evaluate a pending proposal on the fixed regression gate, then activate
    ONLY if performance did not regress. Fully recorded and reversible."""
    p = store_path(path)
    data = _load(p)
    prop = next(
        (x for x in data["proposals"] if x["proposal_id"] == proposal_id), None
    )
    if prop is None:
        raise FeedbackError(f"unknown proposal: {proposal_id}")
    if prop["status"] != "pending":
        raise FeedbackError(f"proposal {proposal_id} is {prop['status']}, not pending")

    base = _ruleset_from(data, prop["base_version"])
    candidate = _candidate_ruleset(base, prop["rule_id"], prop["new_weight"])

    before = threats.evaluate_ruleset(base)
    after = threats.evaluate_ruleset(candidate)
    verdict = _compare(before, after)

    report = {
        "proposal_id": proposal_id,
        "rule_id": prop["rule_id"],
        "old_weight": prop["old_weight"],
        "new_weight": prop["new_weight"],
        "base_version": prop["base_version"],
        "before": before,
        "after": after,
        "verdict": verdict,
        "applied": False,
        "version": None,
    }

    if verdict == "regressed":
        prop["status"] = "rejected"
        prop["regression"] = report
        prop["rejected_at"] = _now()
        _audit(data, "apply_rejected", report)
        _save(p, data)
        return report

    # Next version id: threat-rules-vN where N = existing materialized count.
    existing = [v for v in data["versions"] if v.startswith("threat-rules-v")]
    next_num = max((int(v.rsplit("-v", 1)[1]) for v in existing if v.rsplit("-v", 1)[1].isdigit()), default=0) + 1
    new_version = f"threat-rules-v{next_num}"
    data["versions"][new_version] = {
        "scores": dict(candidate.scores),
        "review_threshold": candidate.review_threshold,
        "flag_threshold": candidate.flag_threshold,
        "parent": base.version,
        "created_at": _now(),
        "note": f"apply {proposal_id}: {prop['rationale']}",
    }
    data["active_version"] = new_version
    prop["status"] = "applied"
    prop["applied_at"] = _now()
    prop["version"] = new_version
    prop["regression"] = report
    for fid in prop["feedback_ids"]:
        for fb in data["corrections"]:
            if fb["feedback_id"] == fid:
                fb["status"] = "applied"
    report["applied"] = True
    report["version"] = new_version
    _audit(data, "apply_proposal", report)
    _save(p, data)
    return report


def revert(
    version: str | None = None,
    *,
    path: str | Path | None = None,
) -> dict:
    """Activate a previous ruleset version (default: the active version's parent).

    To undo everything back to the shipped rules, revert to ``threat-rules-v1``.
    """
    p = store_path(path)
    data = _load(p)
    active = _ruleset_from(data)
    target = version or active.parent
    if target is None:
        raise FeedbackError(f"version {active.version} has no parent to revert to")
    if target not in data["versions"]:
        raise FeedbackError(f"unknown version: {target}")
    previous = active.version
    data["active_version"] = target
    _audit(data, "revert", {"from": previous, "to": target})
    _save(p, data)
    return {
        "reverted": True,
        "from": previous,
        "to": target,
        "scores": dict(data["versions"][target]["scores"]),
    }


def evaluate(
    *,
    version: str | None = None,
    path: str | Path | None = None,
) -> dict:
    """Report accuracy of a (default: active) version on the fixed regression set."""
    p = store_path(path)
    data = _load(p)
    rs = _ruleset_from(data, version)
    result = threats.evaluate_ruleset(rs)
    parent = rs.parent
    if parent and parent in data["versions"]:
        base = threats.evaluate_ruleset(_ruleset_from(data, parent))
        result["vs_parent"] = _compare(base, result)
    else:
        result["vs_parent"] = "no-parent"
    return result


def show(*, path: str | Path | None = None) -> dict:
    """Operator view: active version, weights, thresholds, counts, audit tail."""
    p = store_path(path)
    data = _load(p)
    rs = _ruleset_from(data)
    return {
        "store": str(p),
        "active_version": rs.version,
        "scores": dict(rs.scores),
        "review_threshold": rs.review_threshold,
        "flag_threshold": rs.flag_threshold,
        "counts": {
            "versions": len(data["versions"]),
            "predictions": len(data["predictions"]),
            "corrections": len(data["corrections"]),
            "corrections_pending": sum(
                1 for f in data["corrections"] if f["status"] == "pending"
            ),
            "proposals": len(data["proposals"]),
            "proposals_applied": sum(
                1 for x in data["proposals"] if x["status"] == "applied"
            ),
        },
        "regression": threats.evaluate_ruleset(rs),
        "recent_audit": data["audit"][-10:],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m backend.feedback",
        description="Versioned, auditable feedback loop for the threat rules.",
    )
    parser.add_argument("--store", help="override the feedback store path")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("show", help="active ruleset, counts, latest audit entries")

    p_eval = sub.add_parser("evaluate", help="run the fixed regression dataset")
    p_eval.add_argument("--version", help="version to evaluate (default: active)")

    p_pred = sub.add_parser(
        "predict",
        help="assess synthetic/subject text with the active ruleset and RECORD the prediction",
    )
    p_pred.add_argument("--email-id", required=True)
    p_pred.add_argument("--subject", default="")
    p_pred.add_argument("--body", default="")
    p_pred.add_argument("--body-file", help="read the body from a UTF-8 file")

    p_submit = sub.add_parser("submit", help="record a reviewer correction (pending)")
    p_submit.add_argument("--email-id", required=True)
    p_submit.add_argument("--expected", required=True, choices=list(DECISIONS))
    p_submit.add_argument("--reviewer", required=True)
    p_submit.add_argument("--reason", default="")
    p_submit.add_argument("--source", default="reviewer", choices=list(CORRECTION_SOURCES))

    p_prop = sub.add_parser("propose", help="propose a rule weight change")
    p_prop.add_argument("--rule", required=True)
    p_prop.add_argument("--weight", type=float, required=True)
    p_prop.add_argument(
        "--feedback", action="append", required=True, dest="feedback",
        help="corroborating feedback id (repeat; min 2)",
    )
    p_prop.add_argument("--rationale", required=True)

    p_apply = sub.add_parser("apply", help="regression-gate a proposal and activate it")
    p_apply.add_argument("--proposal", required=True)

    p_revert = sub.add_parser("revert", help="activate a previous ruleset version")
    p_revert.add_argument("--version", help="target version (default: parent)")

    args = parser.parse_args(argv)
    path = store_path(args.store)
    try:
        if args.command == "predict":
            if args.body_file:
                body = Path(args.body_file).read_text(encoding="utf-8")
            else:
                body = args.body
            from gmail_demo.models import Email

            email = Email(
                id=args.email_id,
                sender="synthetic@test.invalid",
                subject=args.subject,
                body=body,
                # Synthetic fixture labeling, same as threats._case_email.
                labels=["NEMESIS_DEMO"],
            )
            rs = active_ruleset(path)
            assessment = threats.assess_email(email, rs)
            pred_id = record_prediction(args.email_id, assessment, path=path)
            out = {"prediction_id": pred_id, "assessment": assessment}
        elif args.command == "show":
            out = show(path=path)
        elif args.command == "evaluate":
            out = evaluate(version=args.version, path=path)
        elif args.command == "submit":
            fid = submit_correction(
                args.email_id,
                args.expected,
                args.reviewer,
                reason=args.reason,
                source=args.source,
                path=path,
            )
            out = {"feedback_id": fid, "status": "pending"}
        elif args.command == "propose":
            pid = propose_adjustment(
                args.rule, args.weight, args.feedback, args.rationale, path=path
            )
            out = {"proposal_id": pid, "status": "pending"}
        elif args.command == "apply":
            out = apply_proposal(args.proposal, path=path)
        else:  # revert
            out = revert(args.version, path=path)
    except FeedbackError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())