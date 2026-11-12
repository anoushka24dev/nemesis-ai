"""Message-quality evaluation and a hill-climbing optimizer for generation settings.

Scope (Phase 2, Objective 6): this optimizer tunes ONLY the bounded
``GenerationSettings`` knobs (tone, length, greeting, sign_off). It can never
touch recipient allowlists, modes, OAuth scopes, rate limits, or the kill
switch — :data:`IMMUTABLE_POLICY_KEYS` is checked on every proposal, and the
knob schema itself has no authority. It is also explicitly NOT optimizing for
recipient manipulation, spam-filter evasion, bulk outreach, or bypassing
provider protections: no such knob exists, and the fixed dataset rewards
grounded, relevant, appropriately toned replies to the actual sender.

Method (the same hill-climbing shape as ADR-002's attacker climber in
``adaptive_agent_eval/attacker/attacker_llm.py``: iterate a candidate,
measure, keep it only if the measured objective improves, stop when it does
not):

* State: the active ``GenerationSettings`` (versioned in a JSON store).
* Objective: weighted score on a FIXED synthetic dataset —
  0.35*factual_support + 0.25*relevance + 0.20*tone + 0.20*(1-unsupported_rate).
* Neighborhood: single-knob alternatives from :data:`KNOB_SCHEMA`.
* Acceptance: candidate must be *eligible* (no malformed or duplicate drafts,
  unsupported-claim rate <= 0) and strictly improve the score.
* Stopping: no improving neighbor, or the iteration budget.
* Promotion (``apply_candidate``) additionally requires an explicit reviewer
  gate: >= MIN_REVIEWS recorded reviews for the exact candidate settings with
  acceptance >= MIN_ACCEPTANCE, and a fresh regression check against the
  active version. Every transition is versioned (``email-quality-vN``),
  audited, and reversible (``revert``).

The dataset is synthetic and fixed; no email content and no model output is
stored anywhere in the quality store.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from email_workflow.compose import (
    KNOB_SCHEMA,
    MAX_BODY_CHARS,
    GenerationSettings,
    compose_reply,
)
from email_workflow.policy import IMMUTABLE_POLICY_KEYS
from gmail_demo.models import Email

__all__ = [
    "DEFAULT_QUALITY_DATASET",
    "MAX_UNSUPPORTED_CLAIM_RATE",
    "MIN_ACCEPTANCE",
    "MIN_REVIEWS",
    "QualityCase",
    "QualityError",
    "active_settings",
    "apply_candidate",
    "evaluate_settings",
    "hill_climb",
    "propose_candidate",
    "record_review",
    "revert",
    "show",
    "store_path",
]

DEFAULT_STORE_PATH = Path(__file__).resolve().parent / "data" / "quality_store.json"
ACTIVE_VERSION_PREFIX = "email-quality-v"
MIN_REVIEWS = 2
MIN_ACCEPTANCE = 0.5
MAX_UNSUPPORTED_CLAIM_RATE = 0.0

_WORD_RE = re.compile(r"[a-z][a-z0-9'-]{2,}")
_GREETING_RE = re.compile(r"^(dear|hello|hi)\b.+$", re.IGNORECASE)
_SIGNOFF_RE = re.compile(r"^(kind regards|best|thanks)[,]?$", re.IGNORECASE)
_AGENT_LINE = "nemesis assistant"
_STOPWORDS = frozenset(
    ["the", "and", "for", "you", "your", "are", "this", "that", "with", "from", "have", "will", "would", "can", "could", "about", "into", "onto", "their", "there", "here", "when", "what", "which", "while", "who", "whom", "why", "how", "not", "but", "any", "all", "some", "more", "most", "other", "than", "then", "them", "they", "these", "those", "a", "an", "of", "to", "in", "on", "at", "by", "is", "am", "are", "was", "were", "be", "been", "being", "it", "its", "as", "if", "or"]
)


class QualityError(RuntimeError):
    """Quality-optimizer failure (gate rejection, store error, bad settings)."""


# ---------------------------------------------------------------------------
# Fixed synthetic evaluation dataset (no real email, no PII)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QualityCase:
    case_id: str
    sender: str
    subject: str
    body: str
    source_texts: tuple[str, ...]
    expected_tone: str


def _case(
    case_id: str, sender: str, subject: str, body: str,
    sources: tuple[str, ...], tone: str,
) -> QualityCase:
    return QualityCase(case_id, sender, subject, body, sources, tone)


#: Fixed validation examples. ``source_texts`` are earlier messages in the
#: thread (the "grounding" a factual reply may draw on). ``expected_tone`` is
#: the explicit reviewer expectation for that thread. Balanced so shipped
#: defaults (neutral/normal) are measurably improvable, not saturated.
DEFAULT_QUALITY_DATASET: tuple[QualityCase, ...] = (
    _case(
        "q-formal-contract",
        "Legal Dept <legal@corp.example>",
        "MSA renewal for signature",
        "Please review the attached MSA renewal and confirm the indemnity clause.",
        ("We circulate the MSA renewal for legal review.", "Indemnity clause is clause 8.2."),
        "formal",
    ),
    _case(
        "q-formal-payroll",
        "HR Records <hr@corp.example>",
        "Payroll cutoff confirmation",
        "Confirming the payroll cutoff for this month is the 28th.",
        ("Payroll cutoff is the 28th each month.", "Finance signed off on the cutoff."),
        "formal",
    ),
    _case(
        "q-formal-audit",
        "Compliance <compliance@corp.example>",
        "Audit evidence request",
        "Please provide the access-review evidence for the Q3 audit.",
        ("The Q3 audit needs access-review evidence.", "Evidence is due Friday."),
        "formal",
    ),
    _case(
        "q-neutral-standup",
        "Team Lead <lead@corp.example>",
        "Standup moved to 09:30",
        "Standup moves to 09:30 starting tomorrow.",
        ("Standup moves to 09:30 from tomorrow.",),
        "neutral",
    ),
    _case(
        "q-neutral-deploy",
        "CI Bot <ci@corp.example>",
        "Deployment finished",
        "The staging deployment finished and the tests are green.",
        ("Staging deployment completed.", "All tests passed on staging."),
        "neutral",
    ),
    _case(
        "q-friendly-lunch",
        "Priya <priya@corp.example>",
        "Lunch tomorrow?",
        "Fancy grabbing lunch tomorrow around noon?",
        ("I am free for lunch tomorrow.",),
        "friendly",
    ),
)


# ---------------------------------------------------------------------------
# Deterministic metrics
# ---------------------------------------------------------------------------


def content_tokens(text: str) -> set[str]:
    """Lowercased content words (len >= 3) minus stopwords."""
    return {w for w in _WORD_RE.findall((text or "").lower()) if w not in _STOPWORDS}


def _sentences(body: str) -> list[str]:
    parts = re.split(r"\n+|(?<=[.!?])\s+", str(body or ""))
    return [p.strip() for p in parts if p.strip()]


def _is_structural(sentence: str) -> bool:
    s = sentence.strip()
    return bool(
        _GREETING_RE.match(s)
        or _SIGNOFF_RE.match(s)
        or s.lower() == _AGENT_LINE
    )


def factual_support(draft: str, grounded: set[str]) -> tuple[float, float, int]:
    """(support, unsupported_rate, content_sentence_count) for one draft.

    A content sentence is *supported* when at least one of its content words
    also appears in the source thread or the incoming message. Structural
    lines (greeting/sign-off) are excluded: they make no factual claims.
    """
    content = [s for s in _sentences(draft) if not _is_structural(s)]
    if not content:
        return 1.0, 0.0, 0
    supported = 0
    for sentence in content:
        if content_tokens(sentence) & grounded:
            supported += 1
    total = len(content)
    return supported / total, 1.0 - (supported / total), total


def relevance(draft: str, incoming_tokens: set[str]) -> float:
    """Share of the draft's non-greeting tokens that relate to the incoming mail."""
    tokens: set[str] = set()
    for sentence in _sentences(draft):
        if _GREETING_RE.match(sentence.strip()) or sentence.strip().lower() == _AGENT_LINE:
            continue
        tokens |= content_tokens(sentence)
    if not tokens:
        return 0.0
    return len(tokens & incoming_tokens) / len(tokens)


def tone_appropriateness(settings: GenerationSettings, expected_tone: str) -> float:
    """1.0 tone+greeting+sign-off correct; 0.5 tone correct only; else 0."""
    if settings.tone != expected_tone:
        return 0.0
    if settings.greeting and settings.sign_off:
        return 1.0
    return 0.5


def _malformed_reasons(draft: str, settings: GenerationSettings) -> list[str]:
    reasons: list[str] = []
    body = str(draft or "")
    if not body.strip():
        reasons.append("empty body")
    if "\r" in body:
        reasons.append("CR character in body")
    if len(body) > MAX_BODY_CHARS:
        reasons.append("body exceeds max length")
    sentences = _sentences(body)
    if settings.greeting and not any(_GREETING_RE.match(s) for s in sentences):
        reasons.append("greeting enabled but missing")
    if settings.sign_off and not any(_SIGNOFF_RE.match(s) for s in sentences):
        reasons.append("sign-off enabled but missing")
    return reasons


def evaluate_settings(
    settings: GenerationSettings,
    dataset: Sequence[QualityCase] = DEFAULT_QUALITY_DATASET,
) -> dict[str, Any]:
    """Score one settings object on the fixed dataset (deterministic)."""
    grounded_extra: set[str] = set()
    per_case: list[dict[str, Any]] = []
    supports: list[float] = []
    unrates: list[float] = []
    rels: list[float] = []
    tones: list[float] = []
    malformed = 0
    bodies: dict[str, str] = {}

    for case in dataset:
        incoming = Email(
            id=case.case_id,
            sender=case.sender,
            subject=case.subject,
            body=case.body,
            labels=["NEMESIS_DEMO"],
        )
        draft = compose_reply(incoming, settings=settings).body
        bodies[case.case_id] = draft
        grounded = (
            content_tokens(case.subject)
            | content_tokens(case.body)
            | set().union(*(content_tokens(t) for t in case.source_texts))
            | grounded_extra
        )
        support, unsupported_rate, _n_content = factual_support(draft, grounded)
        rel = relevance(draft, content_tokens(case.subject) | content_tokens(case.body))
        tone = tone_appropriateness(settings, case.expected_tone)
        reasons = _malformed_reasons(draft, settings)
        malformed += 1 if reasons else 0
        supports.append(support)
        unrates.append(unsupported_rate)
        rels.append(rel)
        tones.append(tone)
        per_case.append(
            {
                "case_id": case.case_id,
                "expected_tone": case.expected_tone,
                "factual_support": round(support, 4),
                "unsupported_claim_rate": round(unsupported_rate, 4),
                "relevance": round(rel, 4),
                "tone": round(tone, 4),
                "malformed": reasons,
            }
        )

    n = max(1, len(dataset))
    dup_pairs = 0
    seen: dict[str, str] = {}
    for cid, body in bodies.items():
        key = re.sub(r"\s+", " ", body).strip().lower()
        if key in seen:
            dup_pairs += 1
        seen[key] = cid
    duplicate_rate = dup_pairs / n

    avg_support = sum(supports) / n
    avg_unrate = sum(unrates) / n
    avg_rel = sum(rels) / n
    avg_tone = sum(tones) / n
    score = (
        0.35 * avg_support
        + 0.25 * avg_rel
        + 0.20 * avg_tone
        + 0.20 * (1.0 - avg_unrate)
    )
    eligible = (
        malformed == 0
        and duplicate_rate == 0.0
        and avg_unrate <= MAX_UNSUPPORTED_CLAIM_RATE
    )
    return {
        "settings": settings.as_dict(),
        "dataset_size": len(dataset),
        "metrics": {
            "factual_support": round(avg_support, 4),
            "unsupported_claim_rate": round(avg_unrate, 4),
            "relevance": round(avg_rel, 4),
            "tone_appropriateness": round(avg_tone, 4),
            "duplicate_rate": round(duplicate_rate, 4),
            "malformed_count": malformed,
        },
        "score": round(score, 4),
        "eligible": eligible,
        "ineligible_reasons": [] if eligible else _ineligible_reasons(
            malformed, duplicate_rate, avg_unrate
        ),
        "per_case": per_case,
    }


def _ineligible_reasons(malformed: int, duplicate_rate: float, unrate: float) -> list[str]:
    reasons: list[str] = []
    if malformed:
        reasons.append(f"{malformed} malformed draft(s)")
    if duplicate_rate:
        reasons.append("duplicate drafts across cases")
    if unrate > MAX_UNSUPPORTED_CLAIM_RATE:
        reasons.append(
            f"unsupported_claim_rate {unrate:.3f} > {MAX_UNSUPPORTED_CLAIM_RATE}"
        )
    return reasons


# ---------------------------------------------------------------------------
# Versioned store (propose -> reviewer gate -> apply -> revert), audited
# ---------------------------------------------------------------------------


def store_path(path: str | Path | None = None) -> Path:
    return Path(path) if path else DEFAULT_STORE_PATH


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _empty_data() -> dict[str, Any]:
    defaults = GenerationSettings().as_dict()
    return {
        "active_version": f"{ACTIVE_VERSION_PREFIX}1",
        "versions": {
            f"{ACTIVE_VERSION_PREFIX}1": {
                "settings": defaults,
                "parent": None,
                "created_at": _now(),
                "note": "shipped defaults",
            }
        },
        "reviews": [],
        "candidates": [],
        "audit": [],
    }


def _load(path: Path) -> dict[str, Any]:
    if not path.exists():
        return _empty_data()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualityError(f"quality store unreadable: {path} ({exc})") from exc
    if not isinstance(data, dict) or "active_version" not in data:
        raise QualityError(f"quality store corrupt (missing keys): {path}")
    return data


def _save(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def _audit(data: dict[str, Any], action: str, detail: Mapping[str, Any]) -> None:
    data["audit"].append({"at": _now(), "action": action, "detail": dict(detail)})


def active_settings(path: str | Path | None = None) -> GenerationSettings:
    data = _load(store_path(path))
    return GenerationSettings.from_dict(data["versions"][data["active_version"]]["settings"])


def _settings_fingerprint(settings: Mapping[str, Any]) -> str:
    return json.dumps(settings, sort_keys=True)


def _check_knobs_only(settings: Mapping[str, Any]) -> None:
    unknown = set(settings) - set(KNOB_SCHEMA)
    if unknown & IMMUTABLE_POLICY_KEYS or unknown - set(KNOB_SCHEMA):
        raise QualityError(
            f"refusing to optimize non-generation keys {sorted(unknown)}: "
            "policy/permission settings are immutable to this optimizer"
        )


def record_review(
    case_id: str,
    settings: GenerationSettings | Mapping[str, Any],
    *,
    accepted: bool,
    reviewer: str,
    reason: str = "",
    path: str | Path | None = None,
) -> str:
    """Record an explicit reviewer accept/reject for the exact settings."""
    if not reviewer or not str(reviewer).strip():
        raise QualityError("reviewer is required")
    settings_dict = (
        settings.as_dict() if isinstance(settings, GenerationSettings) else dict(settings)
    )
    _check_knobs_only(settings_dict)
    p = store_path(path)
    data = _load(p)
    review_id = f"rev-{len(data['reviews']) + 1:04d}"
    data["reviews"].append(
        {
            "review_id": review_id,
            "case_id": str(case_id),
            "settings": settings_dict,
            "accepted": bool(accepted),
            "reviewer": str(reviewer).strip(),
            "reason": str(reason).strip()[:500],
            "at": _now(),
        }
    )
    _audit(data, "record_review", {"review_id": review_id, "accepted": bool(accepted)})
    _save(p, data)
    return review_id


def _reviewer_gate(
    data: dict[str, Any], settings_dict: Mapping[str, Any]
) -> dict[str, Any]:
    fp = _settings_fingerprint(settings_dict)
    reviews = [
        r for r in data["reviews"] if _settings_fingerprint(r["settings"]) == fp
    ]
    accepted = sum(1 for r in reviews if r["accepted"])
    rate = accepted / len(reviews) if reviews else 0.0
    passed = len(reviews) >= MIN_REVIEWS and rate >= MIN_ACCEPTANCE
    return {
        "reviews": len(reviews),
        "accepted": accepted,
        "acceptance_rate": round(rate, 4),
        "min_reviews": MIN_REVIEWS,
        "min_acceptance": MIN_ACCEPTANCE,
        "passed": passed,
    }


def propose_candidate(
    settings: GenerationSettings | Mapping[str, Any],
    rationale: str,
    *,
    path: str | Path | None = None,
    dataset: Sequence[QualityCase] = DEFAULT_QUALITY_DATASET,
) -> dict[str, Any]:
    """Evaluate + gate a candidate (promotion happens only in ``apply_candidate``)."""
    if not rationale or not str(rationale).strip():
        raise QualityError("rationale is required for auditability")
    settings_dict = (
        settings.as_dict() if isinstance(settings, GenerationSettings) else dict(settings)
    )
    _check_knobs_only(settings_dict)
    p = store_path(path)
    data = _load(p)
    active = active_settings(p)
    report = evaluate_settings(GenerationSettings.from_dict(settings_dict), dataset)
    candidate_id = f"qc-{len(data['candidates']) + 1:04d}"
    candidate = {
        "candidate_id": candidate_id,
        "settings": settings_dict,
        "rationale": str(rationale).strip()[:500],
        "base_version": data["active_version"],
        "metrics": report["metrics"],
        "score": report["score"],
        "eligible": report["eligible"],
        "ineligible_reasons": report["ineligible_reasons"],
        "status": "pending",
        "created_at": _now(),
    }
    data["candidates"].append(candidate)
    _audit(
        data,
        "propose_candidate",
        {"candidate_id": candidate_id, "score": report["score"], "eligible": report["eligible"]},
    )
    _save(p, data)
    return {
        **candidate,
        "before": evaluate_settings(active, dataset)["metrics"],
        "before_score": evaluate_settings(active, dataset)["score"],
    }


def apply_candidate(
    candidate_id: str,
    *,
    path: str | Path | None = None,
    dataset: Sequence[QualityCase] = DEFAULT_QUALITY_DATASET,
) -> dict[str, Any]:
    """Regression-gate + reviewer-gate a candidate, then activate it."""
    p = store_path(path)
    data = _load(p)
    cand = next(
        (c for c in data["candidates"] if c["candidate_id"] == candidate_id), None
    )
    if cand is None:
        raise QualityError(f"unknown candidate: {candidate_id}")
    if cand["status"] != "pending":
        raise QualityError(f"candidate {candidate_id} is {cand['status']}, not pending")

    active_version = data["active_version"]
    active = GenerationSettings.from_dict(data["versions"][active_version]["settings"])
    candidate_settings = GenerationSettings.from_dict(cand["settings"])
    before = evaluate_settings(active, dataset)
    after = evaluate_settings(candidate_settings, dataset)
    reviewer = _reviewer_gate(data, cand["settings"])

    verdict = "unchanged"
    if after["score"] > before["score"]:
        verdict = "improved"
    elif after["score"] < before["score"]:
        verdict = "regressed"

    hard_rejection: str | None = None
    if candidate_settings.as_dict() == active.as_dict():
        hard_rejection = "candidate equals the active settings"
    elif not after["eligible"]:
        hard_rejection = "candidate is ineligible: " + "; ".join(after["ineligible_reasons"])
    elif verdict == "regressed":
        hard_rejection = f"score regressed ({before['score']} -> {after['score']})"

    report = {
        "candidate_id": candidate_id,
        "verdict": verdict,
        "before": before["metrics"],
        "before_score": before["score"],
        "after": after["metrics"],
        "after_score": after["score"],
        "reviewer_gate": reviewer,
        "applied": False,
        "rejected_reason": hard_rejection,
        "version": None,
    }

    if hard_rejection is not None:
        cand["status"] = "rejected"
        cand["rejected_reason"] = hard_rejection
        cand["rejected_at"] = _now()
        cand["report"] = report
        _audit(data, "apply_rejected", {"candidate_id": candidate_id, "reason": hard_rejection})
        _save(p, data)
        return report

    if not reviewer["passed"]:
        # Readiness, not a verdict: the candidate stays pending so the
        # operator can record reviewer verdicts and retry. Nothing changes.
        reason = (
            f"reviewer gate not met yet: {reviewer['reviews']} review(s), "
            f"acceptance {reviewer['acceptance_rate']} "
            f"(need >= {MIN_REVIEWS} reviews and >= {MIN_ACCEPTANCE} acceptance)"
        )
        report["rejected_reason"] = reason
        _audit(data, "apply_deferred", {"candidate_id": candidate_id, "reason": reason})
        _save(p, data)
        return report

    existing = [
        v for v in data["versions"] if v.startswith(ACTIVE_VERSION_PREFIX)
    ]
    next_num = (
        max(
            (int(v.rsplit("-v", 1)[1]) for v in existing if v.rsplit("-v", 1)[1].isdigit()),
            default=0,
        )
        + 1
    )
    new_version = f"{ACTIVE_VERSION_PREFIX}{next_num}"
    data["versions"][new_version] = {
        "settings": cand["settings"],
        "parent": active_version,
        "created_at": _now(),
        "note": f"apply {candidate_id}: {cand['rationale']}",
    }
    data["active_version"] = new_version
    cand["status"] = "applied"
    cand["applied_at"] = _now()
    cand["version"] = new_version
    cand["report"] = report
    report["applied"] = True
    report["version"] = new_version
    _audit(
        data,
        "apply_candidate",
        {"candidate_id": candidate_id, "version": new_version, "score": after["score"]},
    )
    _save(p, data)
    return report


def revert(
    version: str | None = None, *, path: str | Path | None = None
) -> dict[str, Any]:
    """Activate a previous quality version (default: the active version's parent)."""
    p = store_path(path)
    data = _load(p)
    active_version = data["active_version"]
    target = version or data["versions"][active_version].get("parent")
    if target is None:
        raise QualityError(f"version {active_version} has no parent to revert to")
    if target not in data["versions"]:
        raise QualityError(f"unknown version: {target}")
    data["active_version"] = target
    _audit(data, "revert", {"from": active_version, "to": target})
    _save(p, data)
    return {
        "reverted": True,
        "from": active_version,
        "to": target,
        "settings": data["versions"][target]["settings"],
    }


def show(*, path: str | Path | None = None) -> dict[str, Any]:
    """Operator view: active settings, counts, audit tail."""
    p = store_path(path)
    data = _load(p)
    return {
        "store": str(p),
        "active_version": data["active_version"],
        "active_settings": data["versions"][data["active_version"]]["settings"],
        "counts": {
            "versions": len(data["versions"]),
            "reviews": len(data["reviews"]),
            "candidates": len(data["candidates"]),
            "candidates_applied": sum(
                1 for c in data["candidates"] if c["status"] == "applied"
            ),
        },
        "regression": evaluate_settings(
            GenerationSettings.from_dict(
                data["versions"][data["active_version"]]["settings"]
            )
        )["metrics"],
        "recent_audit": data["audit"][-10:],
    }


# ---------------------------------------------------------------------------
# Hill-climbing (greedy, deterministic, never auto-applies)
# ---------------------------------------------------------------------------


def hill_climb(
    *,
    start: GenerationSettings | None = None,
    dataset: Sequence[QualityCase] = DEFAULT_QUALITY_DATASET,
    max_iterations: int = 16,
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Greedy hill-climb over the knob neighborhood; returns the trajectory.

    Acceptance: a neighbor is accepted only when it is *eligible* and strictly
    improves the score. Stopping: no improving neighbor or the budget. Nothing
    is persisted here — promotion goes through propose/apply + the reviewer
    gate, so an optimizer run can never silently change what messages say.
    """
    current = start or active_settings(path)
    current_eval = evaluate_settings(current, dataset)
    history: list[dict[str, Any]] = []
    for iteration in range(1, max_iterations + 1):
        best: tuple[float, GenerationSettings, dict[str, Any], str] | None = None
        for knob, values in KNOB_SCHEMA.items():
            for value in values:
                if value == getattr(current, knob):
                    continue
                neighbor = current.with_knob(knob, value)
                report = evaluate_settings(neighbor, dataset)
                if not report["eligible"]:
                    continue
                if (
                    report["score"] > current_eval["score"] + 1e-9
                    and (best is None or report["score"] > best[0])
                ):
                    best = (report["score"], neighbor, report, f"{knob}: {getattr(current, knob)!r} -> {value!r}")
        if best is None:
            return {
                "improved": bool(history),
                "iterations": iteration - 1,
                "start_settings": start.as_dict() if start else None,
                "end_settings": current.as_dict(),
                "start_score": history[0]["score_before"] if history else current_eval["score"],
                "end_score": current_eval["score"],
                "start_metrics": history[0]["metrics_before"] if history else current_eval["metrics"],
                "end_metrics": current_eval["metrics"],
                "history": history,
                "stopped_because": "no improving neighbor",
            }
        _, neighbor, report, change = best
        history.append(
            {
                "iteration": iteration,
                "change": change,
                "score_before": current_eval["score"],
                "score_after": report["score"],
                "metrics_before": current_eval["metrics"],
                "metrics_after": report["metrics"],
            }
        )
        current, current_eval = neighbor, report
    return {
        "improved": bool(history),
        "iterations": max_iterations,
        "start_settings": start.as_dict() if start else None,
        "end_settings": current.as_dict(),
        "start_score": history[0]["score_before"] if history else current_eval["score"],
        "end_score": current_eval["score"],
        "start_metrics": history[0]["metrics_before"] if history else current_eval["metrics"],
        "end_metrics": current_eval["metrics"],
        "history": history,
        "stopped_because": "iteration budget",
    }


# ---------------------------------------------------------------------------
# CLI: python -m email_workflow.quality
# ---------------------------------------------------------------------------


def _parse_settings(pairs: Iterable[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for pair in pairs:
        if "=" not in pair:
            raise QualityError(f"--set expects key=value, got {pair!r}")
        key, _, value = pair.partition("=")
        key = key.strip()
        value = value.strip()
        if key not in KNOB_SCHEMA:
            raise QualityError(
                f"{key!r} is not a generation knob; policy keys are immutable"
            )
        parsed: Any = value
        if value in ("True", "False"):
            parsed = value == "True"
        if parsed not in KNOB_SCHEMA[key]:
            raise QualityError(f"{key}={value!r} outside {KNOB_SCHEMA[key]}")
        out[key] = parsed
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m email_workflow.quality",
        description="Versioned, reviewer-gated quality tuning for reply generation.",
    )
    parser.add_argument("--store", help="override the quality store path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_eval = sub.add_parser("evaluate", help="score settings on the fixed dataset")
    p_eval.add_argument("--set", action="append", default=[], dest="settings")

    p_opt = sub.add_parser(
        "optimize", help="hill-climb from the active settings and propose the result"
    )
    p_opt.add_argument("--max-iterations", type=int, default=16)
    p_opt.add_argument("--rationale", default="hill-climb from active settings")

    p_review = sub.add_parser("review", help="record an explicit reviewer verdict")
    p_review.add_argument("--case-id", required=True)
    p_review.add_argument("--set", action="append", default=[], dest="settings")
    verdict = p_review.add_mutually_exclusive_group(required=True)
    verdict.add_argument("--accepted", action="store_true")
    verdict.add_argument("--rejected", action="store_true")
    p_review.add_argument("--reviewer", required=True)
    p_review.add_argument("--reason", default="")

    p_apply = sub.add_parser("apply", help="regression + reviewer gate a candidate")
    p_apply.add_argument("--candidate", required=True)

    p_revert = sub.add_parser("revert", help="activate a previous quality version")
    p_revert.add_argument("--version")

    sub.add_parser("show", help="active settings, counts, audit tail")

    args = parser.parse_args(argv)
    try:
        if args.command == "evaluate":
            settings = GenerationSettings.from_dict(
                {**active_settings(args.store).as_dict(), **_parse_settings(args.settings)}
            )
            out = evaluate_settings(settings)
        elif args.command == "optimize":
            climb = hill_climb(max_iterations=args.max_iterations, path=args.store)
            candidate = propose_candidate(
                GenerationSettings.from_dict(climb["end_settings"]),
                args.rationale,
                path=args.store,
            )
            out = {"climb": climb, "candidate": candidate}
        elif args.command == "review":
            settings = GenerationSettings.from_dict(
                {**active_settings(args.store).as_dict(), **_parse_settings(args.settings)}
            )
            out = {
                "review_id": record_review(
                    args.case_id,
                    settings,
                    accepted=args.accepted,
                    reviewer=args.reviewer,
                    reason=args.reason,
                    path=args.store,
                )
            }
        elif args.command == "apply":
            out = apply_candidate(args.candidate, path=args.store)
        elif args.command == "revert":
            out = revert(args.version, path=args.store)
        else:  # show
            out = show(path=args.store)
    except QualityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
