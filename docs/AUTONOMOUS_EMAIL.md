# Autonomous Email Workflow — Modes, Guarantees, and Owner Authorization

Phase 2, Objectives 5–7. Code: `email_workflow/`. Tests:
`tests/test_email_workflow.py`, `tests/test_email_quality.py`.

This component is **separate from the read-only analysis** (`gmail_auth` /
`backend/stage_b`). The read-only component continues to request exactly
`gmail.readonly` (fail-closed check in
`StageBBackend._assert_readonly_after_auth`). The write transport is shipped
disarmed and refuses unless every owner gate below is satisfied; the durable
outbound stop is ON at first use and simulation still works while it is ON.

## Operating modes

| Mode | What happens | Default? |
|---|---|---|
| `simulation` | Messages are composed and inspected. **No transport object is called at all** (spy-verified in tests). Nothing is saved or sent. | **Yes** |
| `draft` | Drafts are saved only when the owner set `Policy.draft_authorized=True` *and* granted `gmail.compose` (or `gmail.modify`). Sending is still refused. | No |
| `authorized_automation` | Sending only when `Policy.send_authorized=True` *and* `gmail.send` is granted *and* this mode is set explicitly. Every safeguard below still applies. | No |

Mode is resolved with `resolve_mode()`: unknown values **raise**; nothing
silently escalates. Changing mode/flags is a construction-time (owner) action;
`dataclasses.FrozenError` enforces immutability at runtime.

## Server-side safeguards (enforced in `service.submit`, in order)

1. **Prepared artifact binding** — the backend requires a `prepared_id` and
   the submitted message must match the exact prepared recipient, subject,
   body, CC/BCC, kind, thread, and references. Any substitution or unknown id
   is denied before any transport can be reached. A preparation can be replayed
   for the same action only; it cannot be reused for a different action.
2. **Outgoing defense scan** — every submission is scanned with the active
   ruleset; `flag` refuses outright, `review` requires explicit confirmation.
3. **Durable kill switch** — the SQLite-backed global stop is **ON by
   default**, survives restarts, and fail-closes if its store is missing,
   corrupt, or unwritable. Every non-simulation send/draft is refused while it
   is ON. Preparation, analysis, and local simulation remain available.
   Releasing it requires an explicit `confirm=true`; release does not arm or
   authorize sending.
4. **Mode gate** — simulation never touches the transport; drafts and sends
   require their own mode.
5. **Owner authorization + scopes** — flags AND matching granted OAuth scopes
   are both required; read-only scope alone never authorizes writes
   (`AuthorizationMissing`).
6. **Recipient allowlist** — `allowed_recipients` / `allowed_domains` is a
   **hard boundary** for every To, CC, and BCC address. Confirmation never
   authorizes an outside recipient. Reply recipients must equal the source
   thread's sender exactly.
7. **Sensitive-content confirmation** — financial/credential/payroll/confidential
   phrasing (`requires_confirmation`) requires `confirm=True`
   (`ConfirmationRequired`).
8. **Live-action confirmation** — when the selected transport can execute
   real Gmail actions, every `send` and `draft` additionally requires
   `confirm=True`.
9. **Persistent rate limit** — an atomic SQLite sliding window (default
   5/hour) is shared across service instances and restarts.
10. **Persistent idempotency and uncertain outcomes** — a content-derived key
    makes duplicate sends return the original record with `duplicate=True`.
    A live transport failure that may have crossed the Gmail submission
    boundary is persisted as `uncertain`; it is **never automatically
    retried** and must be reconciled explicitly.
11. **Transport + audit** — the result is recorded append-only with a body
    fingerprint (SHA-256), never the body; string fields pass
    `threats.redact_digits`. Confirmed Gmail message and thread ids are
    preserved in the report and audit; a Gmail draft also preserves the nested
    message/thread ids.

**`status: "sent"` is only possible when a transport result carries
`executed=True`.** The mock transport always returns `simulated=True,
executed=False`, so even a fully authorized configuration reports
`simulated_send` unless the live transport confirms a Gmail message id.
`status: "uncertain"` explicitly means Gmail may have accepted the request;
it is never presented as sent, delivered, or retryable.

## Arming live sending through the backend (implemented)

`gmail_live.py` implements the real write transport
(`GmailLiveTransport`) and `backend/stage_b.build_workflow_service()`
selects it — everything else stays off by default. To ever send or draft for
real, the owner must raise **all** of these (fail-closed; any missing piece
refuses with a reason):

1. **Consent env:** `NEMESIS_LIVE_SEND_CONSENT` must equal exactly
   `I authorize real Gmail sends from Nemesis`.
2. **Separate write OAuth client** (default `credentials_write.json`,
   overridable via `NEMESIS_WRITE_CREDENTIALS_PATH`) — never reused from the
   read-only flow.
3. **Scope-validated write token** (default `token_write.json`) minted by
   `python -m gmail_live auth`, holding ONLY `gmail.send` and
   `gmail.compose`. Read-only or wider scopes (e.g. `mail.google.com`) are
   rejected by `validate_write_scopes`.
4. **Policy env:** `NEMESIS_WORKFLOW_MODE=draft|authorized_automation`,
   `NEMESIS_SEND_AUTHORIZED=1` (and/or `NEMESIS_DRAFT_AUTHORIZED=1`),
   `NEMESIS_GRANTED_SCOPES=send,compose` (short names or full URIs; unknown
   names are refused), plus allowlists
   (`NEMESIS_ALLOWED_RECIPIENTS` / `NEMESIS_ALLOWED_DOMAINS`) and
   `NEMESIS_RATE_LIMIT_PER_HOUR`.

Only when 1–3 hold **and** the mode is past `simulation` does the backend
attach `GmailLiveTransport`; otherwise it ships the in-memory mock. Even
armed, every gate still runs first, in order: prepared-artifact integrity →
outgoing defense scan → durable kill switch → mode/authorization/scopes →
hard recipient allowlist → confirmations → persistent rate limit →
idempotency → transport. `WorkflowReport.status` becomes `"sent"` only when
Gmail's API returns a message id (`executed=True`); a malformed or expired
token surfaces as an error with `executed=False`. A request that may have
been accepted is `uncertain` and is not retried automatically.

Defaults remain fail-closed: no consent env, no write files, empty
allowlists, simulation mode, read-only scopes, and the durable stop ON — so
out of the box **nothing can leave the process**
(`tests/test_live_send_wiring.py` and
`tests/test_outbound_remediation.py` regression-cover every rung of this
ladder). The configured mode, selected transport, live eligibility, and
readiness are reported separately; a mock transport is never labelled LIVE.

## Quality tuning (`email_workflow/quality.py`, Objective 6)

The hill-climber tunes **only** `GenerationSettings` (tone, length, greeting,
sign_off) on a fixed synthetic dataset: factual support, unsupported-claim
rate, relevance, tone, duplicate/malformed rates. `IMMUTABLE_POLICY_KEYS` is
checked on every proposal — the optimizer cannot change permissions, allowlists,
or the kill switch. Promotion requires: eligible candidate + non-regressed
score + ≥2 explicit reviewer acceptances (≥50% acceptance) + fresh regression
check; everything is versioned (`email-quality-vN`), audited, and reversible.
