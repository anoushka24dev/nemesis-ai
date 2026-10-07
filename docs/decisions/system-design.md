**Version:** 1.0
**Status:** Draft (requirements confirmed)
**Last updated:** 2026-10-04

## 1. Problem Statement

Modern AI agents are trusted with real permissions: sending emails, editing files, running commands, moving funds. That autonomy is a new attack surface — agents can be manipulated by poisoned content (e.g., a malicious email) rather than only by direct user input.

Most defenses are validated against static attacks. Real adversaries **adapt**: they observe outcomes, revise strategies, and retry. Whether current defenses withstand adaptive pressure remains untested. This framework provides a reproducible, controllable way to measure defense robustness and attack adaptation under pressure.

## 2. Product Overview

### What it does
A framework for evaluating how well defense strategies (CaMeL, Progent, Verifier) protect LLM-based agents from **adaptive adversarial attacks**. Users run experiments where an attacker tries to force a target agent into an unauthorized tool call. A defense layer evaluates each tool call. A controller drives the loop. Results are logged with metrics.

### Who it's for
- Solo developers who want to test and harden their own agent systems
- Security teams in companies who need evidence that their defenses hold up under adaptive pressure

### What users expect
- Find vulnerabilities in their own agent systems
- See how strong their defenses are (ASR, bypass rate, propagation)
- Modify defense configs and attack strategies
- Iterate to make their system stronger

## 3. User Roles & Tenancy

### Roles
- **Sole developer** — runs personal experiments, tunes defenses, exports results
- **Security engineer** — runs structured campaigns, compares defenses, shares reports with leadership

### Tenancy (one user = one tenant)
Each account is isolated by:
- email
- account_id
- organization name
- workspace_id

All data for a tenant is scoped to `organization_id` in every query, even though it's one-tenant-per-user. This keeps the design auditable for multi-agent/multi-org runs and simplifies future team features.

## 4. Core User Flows

### Flow 1: Run an experiment
1. User configures an experiment: target agent, attack strategy, defense(s), number of episodes, max rounds.
2. Controller runs episodes: attacker → target agent → defense evaluation → diagnoser → metrics.
3. Results (metrics, episodes, artifacts) are written to disk.

### Flow 2: Get results
1. User reviews aggregated metrics (ASR, utility, bypass rate, propagation, cost, rounds-to-success).
2. User inspects per-episode logs and artifacts for debugging.

### Flow 3: Modify defense config
1. User edits defense parameters (e.g., sensitive tools, privilege cap, schema rules).
2. Re-run experiment. New results show whether changes improved defense.

### Flow 4: Modify attack strategy
1. User adjusts or switches attack category / sophistication / adaptation strategy.
2. Re-run experiment. New results show attacker adaptation vs defense.

## 5. Functional Requirements

| ID | Requirement |
|----|-------------|
| FR-1 | Run an experiment with configurable defenses (CaMeL, Progent, Verifier) |
| FR-2 | Run episodes with adaptive attacker (hill-climbing over 5 categories, sophistication escalation) |
| FR-3 | Evaluate each tool call via defense layer, normalized via majority voting |
| FR-4 | Classify outcome per episode (success, blocked, ignored, technical_fail) |
| FR-5 | Collect metrics: ASR, utility, bypass rate, propagation, cost per attack, rounds-to-success |
| FR-6 | Save results to disk (CSV, JSON, config summary) for analysis |
| FR-7 | Support multiple tenants with isolation |
| FR-8 | Support offline stub pipeline (no API keys needed) for demonstration/testing |
| FR-9 | Provide CLI entry point with configurable episodes, defenses, tiers, max rounds |
| FR-10 | Provide audit trail: per-episode logs, checksummed stop conditions, config snapshots |

## 6. Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| **Performance** | Controller loop runs in-process (non-LLM, fast). Per-episode runtime dominated by LLM API latency. Peak ~100 concurrent runs → design output writes to be non-blocking (stream to disk). |
| **Availability** | Framework itself should not be a single point of failure. Run experiments via CLI or CI. Graceful shutdown for long evaluations. |
| **Security** | No secrets committed. Defense events always include confidence + evidence. Stop conditions checksummed (SHA-256). No LLM calls in controller. |
| **Scalability** | ~1,000 users, 50 experiments/user/week, 500 episodes/experiment, ~100 peak concurrent runs. Large log outputs → stream to disk, aggregate to JSON/CSV, no in-memory passes. |
| **Reproducibility** | Random seeds per config. Pinned model IDs in config. Results written with checksums. Configs version-controlled. |
| **Reliability** | Graceful handling of LLM API failures (retry or fail clearly). No silent skipping of tests. |
| **Observability** | Structured logs with request IDs. Error tracking for crashes. Alerts on failure. |

## 7. Data Storage & Retention

### What we store
- Experiment configs
- Attack payloads
- Defense events
- Metrics
- Credentials (encrypted)
- Logs

### Sensitivity
Internal security data only. No PII or compliance-regulated data assumed.

### Retention & Deletion
- Logs: keep for **90 days**, then delete
- Account removal: delete everything for that tenant

## 8. Integrations

### LLM Provider
- **Configurable**, not a hard dependency (avoids vendor lock-in and GPU requirement)
- Default: hosted API provider (e.g., OpenAI, Anthropic)
- Local/self-hosted LLMs are supported only if the user provides a compatible client interface
- Explicit note: **no GPU assumption** — self-hosted LLM is optional, not the default

### Database
- PostgreSQL (tenant-scoped, migrations, indexes, soft deletes)
- ORM: SQLAlchemy 2.0

### Object Storage
- For large log output (e.g., S3, R2, Supabase Storage)
- Files private by default, signed URLs for downloads

### Alerting (optional)
- Not required in v1

## 9. Out of Scope (v1)

- Payment/billing tiers
- Compliance certification (GDPR, SOC 2, etc.)
- Real-time concurrent orchestration UI
- Multi-tenant team management
- External LLM vendor lock-in
- Native GPU/self-hosted LLM as default
- CI/CD/CD pipeline for the framework itself

## 10. Open Questions

| # | Question | Priority |
|---|----------|----------|
| OQ-1 | What compliance/regulatory requirements apply? | Medium |
| OQ-2 | What is the preferred LLM provider/endpoint? | High |
| OQ-3 | Do users need to call external APIs during experiments? | Medium |
| OQ-4 | What is the support channel for security teams? | Low |
| OQ-5 | Do we need API access for the target agent to call during an experiment? | Medium |
