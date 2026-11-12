# NEMESIS threat classification, decisions, and the feedback loop

> **Experience:** this document covers the **Nemesis Gmail Security Side
> Panel** — the separate, read-only Gmail experience. It is *not* the target
> connection of the Research Dashboard; the side panel reads a real mailbox
> under a fixed `gmail.readonly` scope, while the dashboard connects a user
> agent over a JSON HTTP endpoint before any experiment can run (see
> `README.md`, `docs/PRD.md` §1.6–1.7).

This document is the contract for how Nemesis turns email content into a
risk verdict, and what that verdict does - and does not - authorize.

## 1. Two layers that never mix

| Layer | Question | Where | Output |
|---|---|---|---|
| **A. Threat assessment** | What risks does this email present? | `threats.py` (`assess_email`) | per-email `risk_level`, `risk_score`, `threat_types`, `indicators`, `decision`, `reasons` in the `defense` array |
| **B. Action authorization** | What may the system do? | `gmail_demo.defense` checker + `action_authorization` in every `/analyze` result | `action_check` per email, top-level `gmail_writes: "not_permitted"`, `performed_actions: []` |

An `allow` in layer A means "no meaningful threatening indicator found"
(NOT "we lacked permission to act"). Layer B under the read-only policy
always permits reading NEMESIS_DEMO messages and never permits a write:
Gmail OAuth scope is `gmail.readonly`, and no code path sends, modifies,
labels, deletes, or quarantines anything. All `flag`/`review` wording in
outputs is a **recommendation** ("recommend flagging for review"), never a
claim that an action was executed.

## 2. Decision semantics

| decision | condition (defaults) | meaning |
|---|---|---|
| `allow` | score < 0.15 | No meaningful threatening indicator; handle under normal read-only processing. |
| `review` | 0.15 <= score < 0.50 | **Recommend** human review before a human acts on this email. |
| `flag` | score >= 0.50 | **Recommend** flagging for review; do not act on links/requests inside it. |

Score = `benign_floor` (0.05) + each distinct matching rule's weight
(fired at most once per email) + link weights + a multi-signal escalation
when >= 3 distinct threat types are present, clamped to [0, 1]. Rule
weights, thresholds and their feedback bounds (`FLOORS`/`CAPS`) live in
`threats.py`; the shipped version is `threat-rules-v1`.

Context matters: the phrase "ignore previous instructions" alone scores
0.40 -> `review`, not `flag`. Compounding indicators (urgency +
authority-claim + credential asks) escalate to `flag`. Email content is
untrusted data: regexes only count matches and never obey instructions
found in messages.

Threat taxonomy: `phishing`, `credential_theft`, `prompt_injection`,
`suspicious_links`, `malware_indicators`, `sensitive_pii`.

## 3. Aggregation

`threats.aggregate_scores` **max-pools**:

```
risk_score = clamp(max(per-email scores..., model aggregate), 0, 1)
risk_level = derive_level(risk_score)   # <0.25 low, <0.5 medium, <0.75 high, else critical
```

The aggregate can therefore never be lower than the highest individual
email or the model's own aggregate - aggregation cannot conceal a
high-risk email, and the model cannot downgrade a rule-based verdict.
The response's `risk_aggregation` block documents the method, the
per-level `risk_distribution`, and `decision_counts`.

PII handling: digit runs (Aadhaar/card-like numbers) are never echoed
into indicators, reasons, results or tests - they are replaced with
`[number redacted]`; quoted URLs keep scheme + host only.

## 4. Model provider, validation, and failure behavior

- Provider: **Gemini** (`gemini-2.5-flash` by default, `GEMINI_MODEL`
  override) reached through Gemini's OpenAI-compatible endpoint
  `https://generativelanguage.googleapis.com/v1beta/openai/`, keyed by
  `GEMINI_API_KEY` (or `GOOGLE_API_KEY`). Responses report
  `provider: "gemini"` with `transport: "openai-compatible"` and the real
  `endpoint`/`model` - the internal `ProviderConfig.provider == "openai"`
  value only names the SDK compatibility layer and is never surfaced.
- Retries: bounded exponential backoff (default 3 attempts, ceiling 4,
  0.5s base doubling) **for transient failures only** - timeouts,
  connection errors, HTTP 408/409/425/429/5xx. Status 400/401/403/404/etc
  fail on the first attempt. See `gmail_auth._is_retryable`.
- Output validation: model JSON must contain a numeric `risk_score`
  (0..1 or percent-style) and string `summary`/`recommendation` fields;
  anything else raises `GeminiAnalysisError` - a model failure is never
  converted into a fabricated successful assessment.
- Failure surfacing: `/analyze` returns structured HTTP 502
  (`{"error": "Gemini analysis error: model call failed after N attempt(s)
  (HTTP 503): ..."}`) with bounded messages containing no email content.
  Callers may opt into `analyze_emails(..., on_model_failure="fallback")`
  to receive the deterministic rule assessment marked
  `status: "fallback"`, `fallback: true` and `model_error`.
- Model findings (summary / recommendation / prompt_injection_indicators)
  are labeled via `findings_source` and are findings, never ground truth.

## 5. The feedback loop (what it actually adapts)

Implemented in `backend/feedback.py`. It adapts **only** the deterministic
rule weights and the two decision thresholds - it does not train, tune or
change Gemini in any way, and no ordinary model call alters anything.

Loop (CLI: `python -m backend.feedback --help`):

1. `predict` - assess a labeled synthetic email with the active ruleset
   and **record** the prediction (evidence labels + rule version only, no
   bodies, no PII).
2. `submit` - record an explicit reviewer correction (`pending`; inert).
3. `propose` - operator proposes a weight/threshold change citing >= 2
   corrections that describe a *real* prediction mismatch. Values outside
   `FLOORS`/`CAPS`/threshold ranges are refused outright.
4. `apply` - the candidate ruleset is evaluated on the fixed regression
   dataset (`threats.REGRESSION_CASES`, 9 synthetic cases). Verdict =
   `improved` / `unchanged` / `regressed`. **Regressed candidates are
   rejected and nothing changes.**
5. Approved changes become a new immutable version `threat-rules-vN`
   with `parent`, rationale, proposal id, and audit entries; the
   referenced corrections flip to `applied`.
6. `revert` - activate any prior version (e.g. back to
   `threat-rules-v1`), audited.
7. `evaluate [--version]` - report accuracy + `vs_parent` verdict
   (improved / regressed / unchanged).

Guarantees and limits:

- The **active** version is what `analyze_emails` uses for per-email
  verdicts (via `backend.feedback.active_ruleset()`, fail-safe to the
  shipped ruleset on an unreadable store), so an applied `threat-rules-vN`
  changes live classification while an unreadable or missing store never
  crashes it.
- One feedback item can never change active rules: it needs >= 2
  corroborating mismatches, an explicit `apply`, a passing regression
  gate, and security floors.
- Only `deterministic_rules` assessments may be recorded as predictions;
  model-sourced labels are refused (model output is not ground truth).
- Persistence: single local JSON store
  (`backend/data/feedback_store.json`, `NEMESIS_FEEDBACK_STORE` override),
  written atomically; append-only `audit` array; corrupt stores fail safe
  to the shipped ruleset.
- Stored records carry ids, labels, scores and evidence *labels* only -
  never email bodies or raw identifiers.
- Trust boundary: whoever can run the local CLI is a trusted reviewer;
  this is not multi-user and verifies no identities. It is a minimal
  versioned rule/threshold loop, **not** online learning, not fine-tuning,
  and has no cross-run personalization. The system should be called
  "adaptive" only in this narrow, auditable sense.

## 6. Read-only guarantees (unchanged, hard requirements)

- Scope: `https://www.googleapis.com/auth/gmail.readonly` only; token
  guard fails closed on anything broader; `ReadOnlyGmailService` blocks
  mutating verbs; label policy limits reads to `NEMESIS_DEMO`.
- Pairing/nonce validation and origin pinning in the backend are intact;
  nonces never appear in analysis responses, logs, or the sidebar.
- The sidebar shows per-email verdict cards with digit redaction and
  states explicitly that nothing was flagged, isolated, or modified.