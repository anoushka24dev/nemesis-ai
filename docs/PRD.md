# Product Requirements Document (PRD)

> **Project:** Adaptive AI Agent Defense Evaluation Framework (Nemesis)
> **Version:** 2.0.0
> **Last Updated:** 2026-10-25
> **Status:** Active — aligned with the agreed product vision

---

## Table of Contents

1. [Problem Statement & Goals](#1-problem-statement--goals)
   - [1.6 Product Vision & the Two Experiences](#16-product-vision--the-two-experiences)
   - [1.7 Target Connections — Two Supported Methods](#17-target-connections--two-supported-methods)
   - [1.8 Three Security Objectives](#18-three-security-objectives)
   - [1.9 Outcome Classes & Evidence Requirements](#19-outcome-classes--evidence-requirements)
   - [1.10 Intended Experiment Workflow](#110-intended-experiment-workflow)
   - [1.11 Safe Initial Defaults](#111-safe-initial-defaults)
   - [1.12 Intended AI Analyses](#112-intended-ai-analyses)
2. [Baseline Experiment Requirements](#2-baseline-experiment-requirements)
3. [Cross-Agent Propagation Requirements](#3-cross-agent-propagation-requirements)
4. [Defense Composition Requirements](#4-defense-composition-requirements)
5. [Extended Propagation Requirements](#5-extended-propagation-requirements)
6. [Network Propagation Requirements](#6-network-propagation-requirements)
7. [Memory System Requirements](#7-memory-system-requirements)
8. [Metrics & Success Criteria](#8-metrics--success-criteria)
9. [Security Hardening Requirements](#9-security-hardening-requirements)
10. [Experimental Configurations](#10-experimental-configurations)
11. [Pipeline Integration Notes](#11-pipeline-integration-notes)

---

## 1. Problem Statement & Goals

### 1.1 Problem Statement

Modern AI agents are increasingly trusted with real-world permissions — sending emails, booking tickets, moving funds, editing files. This autonomy creates a new attack surface: agents can be manipulated by malicious content they encounter during normal tasks (e.g., a poisoned email or webpage), not just by direct user input.

Most defenses today are validated against **static attacks** (fixed injection strings, tried once). But real adversaries **adapt**: they observe outcomes, revise strategies, and retry. Whether current defenses withstand adaptive pressure remains untested.

### 1.2 Research Questions

1. **RQ1:** Are current agent defenses (CaMeL, Progent, custom verifier) robust against adaptive attackers?
2. **RQ2:** How does attacker sophistication affect defense effectiveness?
3. **RQ3:** Does defense composition (stacking multiple defenses) improve robustness?
4. **RQ4:** How does compromise propagate across multi-agent systems?
5. **RQ5:** What is the economic cost of adaptive attacks vs. defenses?

### 1.3 Goals

| Goal | Description | Success Metric |
|------|-------------|---------------|
| G1 | Evaluate defense robustness under adaptive pressure | ASR < 20% for all defenses |
| G2 | Measure attack adaptation across rounds | Attacker shows measurable improvement over rounds |
| G3 | Test defense composition effectiveness | Stacked defenses have lower ASR than individual |
| G4 | Quantify cross-agent propagation risk | Propagation rate < 10% for defended agents |
| G5 | Establish cost-effectiveness of defenses | Defender cost < 10x attacker cost |
| G6 | Produce reproducible, publishable results | All experiments reproducible with seeds |

### 1.4 Non-Goals

- Building new defense mechanisms (we evaluate existing ones)
- Optimizing for production deployment (this is research)
- Testing against human adversaries (only LLM-based attackers)
- Evaluating non-LLM agent frameworks

### 1.5 Target Users

| User | Use Case | Value |
|------|---------|-------|
| Researchers & Security Teams | Evaluate defense robustness | Publishable evidence on defense effectiveness |
| AI Agent Developers | Understand behavior under adaptive attacks | Design better defenses |
| Academic Community | Publish findings on deterministic defenses | New knowledge on agent security |

### 1.6 Product Vision & the Two Experiences

Nemesis is an adaptive AI-agent security testing and research platform. A
user should eventually be able to **connect their own agent, run adaptive
red-team experiments, evaluate defenses, inspect evidence and metrics, and
obtain an evidence-grounded analysis.** Two distinct experiences deliver
that vision; they are documented separately and must not be conflated:

**A. Nemesis Research Dashboard** — the primary product experience:

| Capability | Meaning | Status |
|------------|---------|--------|
| Target connection setup | Connect a user's own agent; run a real connectivity check before any experiment | **Implemented for HTTP API** (`ExternalHttpTargetAdapter` + a bounded probe), served by `/api/connections` and `/api/adaptive/validate` (§1.7). Framework integration is **not implemented**; the Local Python Agent method is **retired** |
| Experiment configuration & execution | Select objectives, target, model/provider, defense, search algorithm, episode budget; bounded execution | **Partial** — configuration and bounded execution exist for the deterministic runner ([EXPERIMENT_RUNNER.md](EXPERIMENT_RUNNER.md)); the dashboard (`frontend/`) covers configure → validate → run → defense evaluation |
| Adaptive attack search | Greedy hill climbing **and** feedback-guided search as separately selectable strategies | **Implemented** — `backend/adaptive_harness.py` ([ADAPTIVE_SEARCH.md](ADAPTIVE_SEARCH.md)) |
| Defense selection & evaluation | Separate evaluation of the connected agent under selected protective controls | **Partial** — defense layer exists ([ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) ADR-003) and the separate defense-evaluation phase of §6 is implemented (`backend/defense_eval.py`, `/api/adaptive/defense_eval`, ADR-020); upstream research systems are **not** reproduced (local proxies only) |
| Metrics, comparisons, AI-assisted analysis, reproducible artifacts | Evidence-grounded metrics and analysis over persisted artifacts | **Partial** — metrics and artifact integrity exist ([METRICS_DEFINITIONS.md](METRICS_DEFINITIONS.md), [CONTRACTS.md](CONTRACTS.md)); AI analysis over persisted evidence is **planned** |

**B. Nemesis Gmail Security Side Panel** — a separate, **read-only** Gmail
security experience (Chrome extension + local backend): per-email threat
verdicts, read-only OAuth (`gmail.readonly`, fail-closed on anything
broader), pairing/nonce/origin-pinned local serving. The side panel's
analysis path performs no send/delete/modify/label/move operations; a
*separate* owner-armed email write workflow exists in `email_workflow/`
(consent env + separate write credentials + allowlists + rate limit,
simulation by default, fail-closed) and is documented in
[AUTONOMOUS_EMAIL.md](AUTONOMOUS_EMAIL.md) — it is not part of the side panel
experience and is not enabled by default. The side panel is **not** a
target-connection method for the research dashboard: it analyzes a real
mailbox under a fixed read-only scope, whereas the dashboard connects a user
agent over HTTP. Constraints are unchanged and non-negotiable — see
`README_stageb.md`, [THREAT_CLASSIFICATION.md](THREAT_CLASSIFICATION.md),
and [SECURITY_HARDENING.md](SECURITY_HARDENING.md).

### 1.7 Target Connections — Two Supported Methods

Bring-your-own-agent connectivity is a **product requirement**. The dashboard
exposes exactly two connection methods; their real status is:

| Dashboard method | Implementation | Status |
|---|---|---|
| **HTTP API** | `adaptive_agent_eval/target/adapter.py::ExternalHttpTargetAdapter`; validated with `backend/connections.py::probe_http_endpoint` | **Implemented** — one bounded POST probe, JSON response required |
| **Agent Framework** | `adaptive_agent_eval/target/langchain_agent.py::LangChainAgentAdapter` — a real `langchain.agents.create_agent` ReAct agent over `ChatOllama` (default `llama3.1:8b`), probed with `backend/connections.py::probe_langchain_agent` and executed by the adaptive harness as the run target | **Implemented** — readiness and run execution both invoke the real model; a model error surfaces as a technical failure |

**Local Python Agent — retired.** The in-process adapter path was removed from
the supported product: there is no connection card, no adapter-module or
entry-callable field, no setup template, no execution branch, and no active
connection type. `backend/connections.py` still recognises the identifier only
to reject legacy callers with an explicit `retired` error, and
`/api/adaptive/run` / `/api/adaptive/validate` reject inline adapter specs with
HTTP 400. The `adaptive_agent_eval/target/byoa.py` module remains in the tree
because it backs the labelled offline fixture target
(`local-byoa-fixture`) used for deterministic development runs; it is not a
user-facing connection method. See ADR-021.

A saved connection is never treated as ready: `/api/connections` records the
probe result, and the adaptive harness only receives the target when that
probe succeeded. No method silently falls back to a fixture when it fails.
The three **agent-shape categories** the product must support (independent of
the connection methods above):

| # | Category | Description | Instrumentation intent |
|---|----------|-------------|------------------------|
| 1 | **Single-turn text-in/text-out agents** | One prompt in, one completion out | HTTP JSON request/response over a documented contract |
| 2 | **Multi-turn conversational / stateful agents** | Dialogue history and state across turns | Stronger turn-level instrumentation (bounded context, per-turn evidence) |
| 3 | **Tool-using agents** | Agents that call APIs, databases, files, or other tools | Instrumented tool boundaries so access/transmission/disclosure are observable |

Delivery order: (a) the documented **HTTP endpoint contract** first;
(b) then stronger multi-turn and tool instrumentation; (c) later,
framework-specific adapters. Step (a) has shipped. Framework-specific
adapters have **not** shipped and are labelled unavailable everywhere they
appear.

#### 1.7.1 Execution lifecycle (enforced by the backend)

One experiment runs in strict order, and the API enforces the barrier rather
than relying on disabled buttons:

1. **Attacker** — candidates are evaluated against the connected target (or
the explicitly-labelled seeded stand-in when no connection is active) and
persisted with stable `case_id`s (`<strategy>:ep<N>`).
2. **Completion barrier** — defense evaluation is refused with HTTP 409 while
any attacker search is running, and when the source run is not `completed`
(`stopped`, `budget_exhausted`, `failed`).
3. **Defense replay** — the selected defense replays the saved finding's
ladder and seed, links each replayed episode to its source `case_id`, and
classifies it as `confirmed_success`, `confirmed_blocked`, `inconclusive` or
`technical_failure`.
4. **Report** — the dashboard shows both phases, their denominators, source
run/case identifiers and the honest limitations (including when the replay
environment differs from the source run's target).

### 1.8 Three Security Objectives

These objectives are distinct and are kept separate in all architecture,
threat-model, and metrics documentation. Both the attack phase and the
defense phase evaluate against them:

1. **Unauthorized data access** — did the agent access or retrieve information beyond its permissions?
2. **Sensitive-data exfiltration** — did sensitive information reach an unauthorized destination?
3. **Sensitive-data disclosure** — did the agent reveal sensitive information to an unauthorized recipient?

**Success is defined by the applicable authorization policy.** Legitimate
access is not automatically a security violation; an access that the policy
permits is not a success for objective 1. Outcome classification therefore
requires stated policy context, synthetic records, secret canaries,
instrumented boundaries, and evidence-based classification (§1.9). If a
relevant boundary cannot be observed, the result is reported as a limitation
— never as "no violation occurred".

### 1.9 Outcome Classes & Evidence Requirements

Every episode outcome is reported in exactly one of four classes:

| Class | Meaning |
|-------|---------|
| **Confirmed success** | Evidence shows the security objective was violated under the authorization policy |
| **Confirmed blocked** | Evidence shows the violation was prevented |
| **Inconclusive** | Available evidence cannot decide (unobservable boundary, missing signal, insufficient data) |
| **Technical failure** | The episode did not run to a decidable outcome (harness/target/infrastructure error) |

Existing record vocabularies map onto these classes rather than being
replaced: `AttackOutcome` (`success`/`blocked`/`ignored`/`technical_fail`)
and `GroundTruthOutcome` (six values incl. `indeterminate`) in
`adaptive_agent_eval/models.py`; the reporting-layer mapping is documented in
[CONTRACTS.md §4](CONTRACTS.md). Technical failures are never reported as
blocks, and inconclusive results are never reported as successes or blocks —
including in AI-generated analysis (§1.12).

Evidence requirements (product requirements):

- **Synthetic records** for data the agent may read — no real personal or production data by default.
- **Secret canaries** — planted sensitive values whose appearance at a boundary proves (or disproves) exfiltration/disclosure.
- **Instrumented boundaries** — every tool call, network egress, and recipient address the policy governs must be observable to classify outcomes.
- **Evidence-based classification** — each outcome carries the records that support it; an unobservable boundary yields `inconclusive` plus an explicit limitation note.

### 1.10 Intended Experiment Workflow

The intended end-to-end product workflow (some steps exist today, some are
requirements):

1. User connects an HTTP target and runs a **connectivity check**. *(implemented: `probe_http_endpoint`, exposed via `/api/connections` and `/api/adaptive/validate`)*
2. User selects security objectives, target, model/provider, defense configuration, search algorithm, and episode budget. *(configuration exists at CLI/backend level)*
3. The adaptive attacker executes bounded episodes and uses previous outcomes to select subsequent candidates — greedy or feedback-guided, selected explicitly ([ADAPTIVE_SEARCH.md](ADAPTIVE_SEARCH.md)). *(implemented for deterministic local simulation)*
4. Nemesis records evidence, outcomes, supported metrics, and experiment artifacts. *(implemented: JSON persistence + artifact hashes, [CONTRACTS.md](CONTRACTS.md))*
5. An **AI attack analysis** summarizes persisted evidence without inventing results. *(planned)*
6. User reviews the attack report and initiates a **separate defense evaluation**. *(implemented: eligibility-gated defense phase over a completed attacker run; see §6 below)*
7. The defense evaluation measures security outcomes and utility trade-offs. *(replay verdicts implemented: four-state classification with denial-evidence requirements; false-positive and legitimate-task utility measurement for the defense phase is still planned)*
8. A **separate defense analysis** reports which controls worked, which failed, and where evidence is incomplete. *(planned)*
**Episode budget:** **1,000 episodes is a desired supported experiment
budget**, not a claim that the system has run or can safely run that many
today. The approved manifest is 26 configurations / 1,300 episodes
([CONTRACTS.md §7](CONTRACTS.md), ADR-016/017) and full-matrix execution is
refused by the current runner pending a separately approved procedure. The
eventual runner must enforce hard limits, timeouts, checkpointing, safe
resume, and provider cost limits. Large runs require **explicit user
initiation and a successful small smoke test first** — mirroring the existing
runner's non-executing-by-default and bounded-execution rules
([EXPERIMENT_RUNNER.md](EXPERIMENT_RUNNER.md)).

### 1.11 Safe Initial Defaults

Every experiment starts from these defaults; loosening any of them requires
explicit user approval:

- Synthetic data and synthetic secret canaries.
- No real production credentials by default.
- Mocked or sandboxed tool actions.
- External network access disabled by default.
- Bounded execution and episode budgets.
- Sensitive-value redaction where practical.
- Explicit approval before experiments involving real services or data.
- No automatic side-effecting retries (retries only for read-only/idempotent operations; failed episodes start a new run).
- Missing metrics represented as **unavailable** (`null` / `not_measured`), never zero.
- No frontend mock data presented as real experiment results.

Several of these are already enforced by the Phase 3 runner
([EXPERIMENT_RUNNER.md](EXPERIMENT_RUNNER.md) "Safety invariants") and the
Gmail read-only contract; the rest are product requirements for the
dashboard.

### 1.12 Intended AI Analyses

Two separate AI-assisted analyses, both **grounded in recorded experiment
nevidence**:

- **Attacker analysis:** explains observed attack outcomes, strategy progression, evidence, uncertainty, supported metrics, and promising follow-up tests.
- **Defense analysis:** explains which attacks were blocked, which controls failed, whether data access or transmission occurred *before* a block, utility impact, observability limitations, and recommended improvements.

Hard constraints for both: AI-generated interpretations must not override
measured outcomes, must not convert inconclusive results into confirmed
successes or blocks, and must not invent results that are not present in
persisted artifacts. An analysis over no evidence says so.

### 1.13 Intended Defense Architecture (defense evaluation phase)

The defense phase is a **separate evaluation of the connected agent under
selected protective controls** — not a continuation of the attacker's search.
Its intended responsibilities:

| | Responsibility |
|---|----------------|
| A | Enforce authorization at relevant data-access and tool boundaries |
| B | Protect sensitive information from unauthorized access, transmission, and disclosure |
| C | Inspect and validate tool calls where the integration allows it |
| D | Detect and record suspicious behavior and policy violations **with evidence** |
| E | Use observed attack findings to guide defense evaluation and follow-up tests — while keeping **attacker search feedback separate** from defense decisions and from post-run AI analysis |

**Roles of existing defenses (as implemented — simplified proxies, not
faithful reproductions):** `adaptive_agent_eval/defense/defenses.py` contains
`CamelDefense` (literal pattern/taint heuristics over tool arguments),
`ProgentDefense` (static privilege-level table plus argument checks — **no
SMT solver**), and `VerifierDefense` (schema-required-field checks plus a
keyword-overlap intent match). `backend/adaptive_harness.py` adds
`MarkerDefense` (a CaMeL-style literal-taint stand-in, the harness default)
and `VerifierDefenseShim` (wraps the real `VerifierDefense`). Each record
naming a defense must state which implementation ran
(`DefenseImplementation` in `adaptive_agent_eval/models.py`). **No defense
can enforce every boundary**: e.g. the marker defense cannot see encoded
payloads, the verifier cannot see anything its schema does not model, and
none of them observe network egress. Do not claim a defense covers a boundary
its implementation cannot instrument.

**Defense evaluation (implemented — replay and verdict scope):**
`defense_evaluation` in `backend/adaptive_harness.py` (endpoint
`/api/adaptive/defense_eval`, ADR-020) starts only from a **completed**
attacker run, replays the stored finding against a selected defense on the
same target, attack category and seed, and classifies every replayed episode
into exactly one of `confirmed_success`, `confirmed_blocked`, `inconclusive`,
`technical_failure` (`backend/defense_eval.py`) — a block without defense
denial evidence is never confirmed, and ground truth is reported as
`not_evaluated` rather than manufactured. Each result labels the actual
implementation (local proxy vs unavailable). **Still planned:** systematic
defense-setting comparison, false-positive and legitimate-task utility
measurement *within this phase*, and evaluation against the
`detected_not_blocked` distinction in
`GroundTruthOutcome` ([CONTRACTS.md §4](CONTRACTS.md)).

Attacker search feedback (greedy or feedback-guided, [ADAPTIVE_SEARCH.md](ADAPTIVE_SEARCH.md)),
defense decisions, and post-run AI analysis remain three separate channels;
none may write into another's state.

---

## 2. Baseline Experiment Requirements

### 2.1 Mode 1: Single-Agent Baseline

The baseline experiment establishes the foundational evaluation of each defense against each attacker tier.

#### 2.1.1 Inputs

| Input | Type | Description |
|-------|------|-------------|
| Task description | string | What the target agent should do (e.g., "Process email") |
| Attack goal | string | What the attacker is trying to achieve (e.g., "Send unauthorized email") |
| Defense type | enum | camel, progent, or verifier |
| Attacker tier | enum | cheap (GPT-3.5) or frontier (GPT-4) |
| Target tier | enum | cheap (GPT-3.5) or frontier (GPT-4) |

#### 2.1.2 Outputs

| Output | Type | Description |
|--------|------|-------------|
| Attack outcome | enum | success, blocked, ignored, technical_fail |
| Defense events | list[DefenseEvent] | Decisions from each defense mechanism |
| Tool calls | list[ToolCallRequest] | What the agent attempted to do |
| Cost breakdown | dict | Per-call cost for attacker, target, and diagnoser |
| Round history | list[EpisodeLog] | Complete log of each round |

#### 2.1.3 Stop Conditions

| Condition | Trigger | Action |
|-----------|---------|--------|
| Attack success | Outcome == SUCCESS | Stop; log as success |
| Round budget | Round >= max_rounds (5) | Stop; log as defended |
| Technical failure | 3 consecutive API errors | Stop; log as technical_fail |

#### 2.1.4 Configuration Matrix

| Defense | Attacker Tier | Target Tier | Configs | Episodes | Total |
|---------|--------------|-------------|---------|----------|-------|
| CaMeL | Cheap | Cheap | 1 | 50 | 50 |
| CaMeL | Cheap | Frontier | 1 | 50 | 50 |
| CaMeL | Frontier | Cheap | 1 | 50 | 50 |
| CaMeL | Frontier | Frontier | 1 | 50 | 50 |
| Progent | Cheap | Cheap | 1 | 50 | 50 |
| Progent | Cheap | Frontier | 1 | 50 | 50 |
| Progent | Frontier | Cheap | 1 | 50 | 50 |
| Progent | Frontier | Frontier | 1 | 50 | 50 |
| Verifier | Cheap | Cheap | 1 | 50 | 50 |
| Verifier | Cheap | Frontier | 1 | 50 | 50 |
| Verifier | Frontier | Cheap | 1 | 50 | 50 |
| Verifier | Frontier | Frontier | 1 | 50 | 50 |
| **Total** | | | **12** | **50** | **600** |

---

## 3. Cross-Agent Propagation Requirements

### 3.1 Mode 2: Cross-Agent Propagation

Tests how compromise propagates from one agent to another through shared memory/tools.

#### 3.1.1 Agent Configuration

| Agent | Role | Task | Memory Access |
|-------|------|------|---------------|
| Agent A | Email agent | Read/process emails | Own memory + shared memory |
| Agent B | Calendar agent | Manage calendar events | Own memory + shared memory |

#### 3.1.2 Propagation Model

1. Agent A receives an email with an injected payload
2. Agent A processes the email and (if compromised) makes an unauthorized tool call
3. If Agent A is compromised, its state propagates to shared memory
4. Agent B reads shared memory and may be affected by the compromised state
5. Agent B processes its task and may make unauthorized tool calls

#### 3.1.3 Configuration Matrix

| Setup | Defense | Attacker Tier | Configs | Episodes | Total |
|-------|---------|--------------|---------|----------|-------|
| Single-agent | CaMeL | Cheap | 1 | 50 | 50 |
| Multi-agent | CaMeL | Cheap | 1 | 50 | 50 |
| Single-agent | Progent | Cheap | 1 | 50 | 50 |
| Multi-agent | Progent | Cheap | 1 | 50 | 50 |
| Single-agent | Verifier | Cheap | 1 | 50 | 50 |
| Multi-agent | Verifier | Cheap | 1 | 50 | 50 |
| **Total** | | | **6** | **50** | **300** |

---

## 4. Defense Composition Requirements

### 4.1 Mode 3: Defense Composition

Tests whether stacking multiple defenses improves robustness over individual defenses.

#### 4.1.1 Composition Variants

| Variant | Defense A | Defense B | Defense C | Voting |
|---------|-----------|-----------|-----------|--------|
| Single-CaMeL | CaMeL | — | — | N/A |
| Single-Progent | — | Progent | — | N/A |
| Single-Verifier | — | — | Verifier | N/A |
| Pair-CP | CaMeL | Progent | — | Majority |
| Pair-CV | CaMeL | — | Verifier | Majority |
| Pair-PV | — | Progent | Verifier | Majority |
| Triple | CaMeL | Progent | Verifier | Majority |

#### 4.1.2 Composition Rules

1. Each defense runs independently on the same tool call
2. Each defense produces a DefenseEvent with decision and confidence
3. The DefenseAdapter normalizes events and applies majority voting
4. Ties default to DENIED (safe default)
5. Each defense's decision is logged separately for analysis

#### 4.1.3 Configuration Matrix

| Stacked Defense | Attacker Tier | Configs | Episodes | Total |
|----------------|--------------|---------|----------|-------|
| CaMeL + Progent | Cheap | 1 | 50 | 50 |
| CaMeL + Progent | Frontier | 1 | 50 | 50 |
| CaMeL + Verifier | Cheap | 1 | 50 | 50 |
| CaMeL + Verifier | Frontier | 1 | 50 | 50 |
| Progent + Verifier | Cheap | 1 | 50 | 50 |
| Progent + Verifier | Frontier | 1 | 50 | 50 |
| All Three | Cheap | 1 | 50 | 50 |
| All Three | Frontier | 1 | 50 | 50 |
| **Total** | | **8** | **50** | **400** |

---

## 5. Extended Propagation Requirements

### 5.1 Mode 4: Extended Propagation (3 Agents)

Tests compromise propagation across a chain of three agents.

#### 5.1.1 Agent Chain

```
Agent A (Email) → Agent B (Calendar) → Agent C (File System)
     ↓                    ↓                    ↓
  Reads email      Updates calendar      Edits files
  (entry point)    (propagation #1)      (propagation #2)
```

#### 5.1.2 Propagation Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| Chain propagation rate | % of episodes where compromise reaches Agent C | < 5% |
| Blast radius | Average number of agents compromised | < 1.5 |
| Propagation speed | Average rounds for compromise to reach Agent C | > 3 rounds |
| Recovery rate | % of compromised agents that recover | > 80% |

#### 5.1.3 Configuration Matrix

| Defense | Attacker Tier | Configs | Episodes | Total |
|---------|--------------|---------|----------|-------|
| CaMeL | Cheap | 1 | 50 | 50 |
| CaMeL | Frontier | 1 | 50 | 50 |
| Progent | Cheap | 1 | 50 | 50 |
| Progent | Frontier | 1 | 50 | 50 |
| Verifier | Cheap | 1 | 50 | 50 |
| Verifier | Frontier | 1 | 50 | 50 |
| **Total** | | **6** | **50** | **300** |

---

## 6. Network Propagation Requirements

### 6.1 Mode 5: Network Propagation (5 Agents)

Tests compromise propagation in a network topology.

#### 6.1.1 Network Topology

```
        Agent A (Email)
       /        \
Agent B         Agent C
(Calendar)    (File System)
       \        /
Agent D ─── Agent E
(Task Mgr)  (Financial)
```

#### 6.1.2 Network Metrics

| Metric | Definition | Target |
|--------|-----------|--------|
| Network propagation rate | % of episodes with >2 agents compromised | < 3% |
| Maximum blast radius | Max agents compromised in any episode | < 3 |
| Network recovery time | Average rounds to fully recover | < 3 rounds |
| Critical node impact | Impact of compromising Agent A vs. others | Agent A highest |

#### 6.1.3 Configuration Matrix

| Defense | Attacker Tier | Configs | Episodes | Total |
|---------|--------------|---------|----------|-------|
| CaMeL | Cheap | 1 | 50 | 50 |
| CaMeL | Frontier | 1 | 50 | 50 |
| Progent | Cheap | 1 | 50 | 50 |
| Progent | Frontier | 1 | 50 | 50 |
| Verifier | Cheap | 1 | 50 | 50 |
| Verifier | Frontier | 1 | 50 | 50 |
| **Total** | | **6** | **50** | **300** |

---

## 7. Memory System Requirements

### 7.1 Working Memory

| Requirement | Specification |
|-------------|--------------|
| Fields | current_payload (AttackPayload), defense_decision (string) |
| Persistence | Ephemeral (lost after round) |
| Access | Read/write by controller |
| Size limit | < 1KB per round |

### 7.2 Episodic Memory

| Requirement | Specification |
|-------------|--------------|
| Fields | round_num, payload, defense_event, outcome, tool_call, cost_usd, timestamp |
| Persistence | Append-only JSON log per episode |
| Access | Read by attacker; write by controller |
| Size limit | < 100KB per episode (5 rounds × ~20KB) |

### 7.3 Procedural Memory

| Requirement | Specification |
|-------------|--------------|
| Fields | success_rates: dict[str, float] (per category) |
| Persistence | JSON file, updated after each episode |
| Access | Read by attacker; write by controller |
| Size limit | < 1KB (5 categories × float) |

### 7.4 Semantic Memory

| Requirement | Specification |
|-------------|--------------|
| Fields | tool_schemas, defense_rules, task_definitions |
| Persistence | Static YAML files |
| Access | Read-only by all components |
| Size limit | < 50KB |

### 7.5 Prospective Memory

| Requirement | Specification |
|-------------|--------------|
| Fields | max_rounds, current_round, stop_conditions |
| Persistence | Ephemeral (reset per episode) |
| Access | Read/write by controller |
| Size limit | < 1KB |

### 7.6 Memory Integration

| Component | Reads | Writes |
|-----------|-------|--------|
| Attacker | Episodic, Procedural | — |
| Controller | Prospective, Working | Working, Episodic, Procedural |
| Target Agent | — | — |
| Defense Layer | — | — |
| Diagnoser | — | — |
| Metrics | Episodic | — |

---

## 8. Metrics & Success Criteria

### 8.1 Primary Metrics

| Metric | Formula | Target | Purpose |
|--------|---------|--------|---------|
| Attack Success Rate (ASR) | successes / total episodes | < 20% | Primary robustness measure |
| Utility Score | benign tasks completed / 50 | ≥ 90% | Defense doesn't break normal use |
| Cost Per Attack | total API cost / successes | < $0.50 | Economic viability |
| Rounds to Success | mean rounds until success | > 3 | Adaptive pressure measure |

### 8.2 Secondary Metrics

| Metric | Formula | Target | Purpose |
|--------|---------|--------|---------|
| Recovery Time | rounds to safe state | < 2 rounds | Operational resilience |
| Bypass Rate | successes without guardrail / total successes | < 30% | Guardrail effectiveness |
| Propagation Rate | cross-agent spread episodes / total multi-agent | < 10% | Multi-agent risk |
| Marginal Gain | ASR(stacked) - ASR(single) | < -5% | Defense composition value |

### 8.3 Success Criteria Summary

| Criterion | Threshold | Measurement |
|-----------|-----------|-------------|
| Defense effectiveness | ASR < 20% | Across all configs |
| Utility preservation | Utility ≥ 90% | Benign task baseline |
| Cost efficiency | Defender cost < 10x attacker cost | Per-config average |
| Reproducibility | Same seed → same results | Re-run verification |
| Completeness | ≥ 95% episodes complete | No missing results |
| Human audit | 10% sample, κ > 0.8 | Inter-rater reliability |

---

## 9. Security Hardening Requirements

### 9.1 Controller Hardening

| Requirement | Implementation | Verification |
|-------------|---------------|-------------|
| Non-LLM design | Pure Python, no API calls | Code review |
| Read-only memory | Attacker cannot modify episodic log | Unit test |
| Checksums | SHA-256 on stop conditions | Checksum verification test |
| Process isolation | Controller in separate process | Process tree inspection |
| No prompt exposure | Zero user input in controller | Code review |

### 9.2 Memory Hardening

| Requirement | Implementation | Verification |
|-------------|---------------|-------------|
| Append-only episodic | No delete/update operations | Unit test |
| Cryptographic integrity | SHA-256 checksums on episodes | Checksum verification |
| Access control | Each component has minimal access | Interface review |

### 9.3 Defense Hardening

| Requirement | Implementation | Verification |
|-------------|---------------|-------------|
| Defense isolation | Each defense runs independently | Composition test |
| Confidence calibration | Confidence scores correlate with accuracy | Calibration test |
| Evidence logging | Every decision includes evidence | Audit trail review |

---

## 10. Experimental Configurations

> **Scope note (2026-10-25).** The matrices in this section are the **original
> research design** (38 configurations / 1,900 episodes) and are preserved as
> historical planning decisions. The currently **approved, validated**
> experiment manifest is **26 configurations / 1,300 episodes** — see
> [CONTRACTS.md §7](CONTRACTS.md) and ADR-016/017 in
> [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md). Full-matrix
> execution is refused by today's runner pending a separately approved
> procedure. The product's *desired supported* experiment budget is 1,000
> episodes (§1.10) — a target for the eventual runner, not a current
> capability claim.

### 10.1 Grand Total

| Mode | Name | Configs | Episodes/Config | Total Episodes |
|------|------|---------|-----------------|----------------|
| 1 | Single-Agent Baseline | 12 | 50 | 600 |
| 2 | Cross-Agent Propagation | 6 | 50 | 300 |
| 3 | Defense Composition | 8 | 50 | 400 |
| 4 | Extended Propagation (3 agents) | 6 | 50 | 300 |
| 5 | Network Propagation (5 agents) | 6 | 50 | 300 |
| **Total** | | **38** | **50** | **1,900** |

### 10.2 Estimated Cost

| Component | Calls/Episode | Cost/Call | Episodes | Total |
|-----------|--------------|-----------|----------|-------|
| Attacker (cheap) | 5 | $0.002 | 1,200 | $12.00 |
| Attacker (frontier) | 5 | $0.015 | 700 | $52.50 |
| Target (cheap) | 5 | $0.003 | 950 | $14.25 |
| Target (frontier) | 5 | $0.020 | 950 | $95.00 |
| Diagnoser | 2 | $0.001 | 1,900 | $3.80 |
| **Total** | | | | **~$177.55** |

### 10.3 Estimated Time

| Component | Time/Episode | Episodes | Total |
|-----------|-------------|----------|-------|
| Attacker generation | 2s | 1,900 | ~1.1 hours |
| Target processing | 3s | 1,900 | ~1.6 hours |
| Defense evaluation | 0.5s | 1,900 | ~0.2 hours |
| Diagnoser | 1s | 1,900 | ~0.5 hours |
| **Total** | | | **~3.4 hours** |

(Note: Times assume sequential execution. Parallel execution would reduce wall-clock time.)

### 10.4 Reproducibility

| Requirement | Implementation |
|-------------|---------------|
| Random seeds | Fixed seed for each config (seed = config_index * 1000) |
| Model versions | Pin model IDs (e.g., claude-3-haiku-20240307) |
| Configuration | YAML files versioned in Git |
| Results | JSON files with checksums |
| Audit trail | Full episode logs + human audit labels |

---

## 11. Pipeline Integration Notes

### 11.1 How Hermes Uses PRD

Hermes reads this PRD as structured input for code generation:

1. **Module Generation:** Each section maps to a Python module. Hermes reads the requirements and generates the corresponding code.
2. **Test Generation:** Success criteria map to test assertions. Hermes generates tests that verify each criterion.
3. **Config Generation:** Configuration matrices map to YAML config files. Hermes generates configs from the matrices.
4. **Validation:** Hermes checks that generated code satisfies all requirements in this PRD.

### 11.2 How Freebuff Prototypes Attacker Strategies

Freebuff is used to prototype and test attacker strategies before full implementation:

1. **Strategy Design:** User describes an attacker strategy (e.g., "try base64-encoded payloads").
2. **Prototype:** Freebuff generates a minimal implementation of the strategy.
3. **Quick Test:** The prototype is tested against a single defense configuration.
4. **Evaluation:** User evaluates if the strategy is worth including in the full experiment.
5. **Integration:** If approved, the strategy is incorporated into the attacker LLM module.

### 11.3 Requirements Traceability

| Requirement | Module | Test | Config |
|-------------|--------|------|--------|
| G1: ASR < 20% | metrics/modules.py | test_asr_threshold | All |
| G2: Adaptation | attacker/attacker_llm.py | test_hill_climbing | All |
| G3: Composition | defense/defenses.py | test_composition | Mode 3 |
| G4: Propagation < 10% | metrics/modules.py | test_propagation_rate | Modes 2,4,5 |
| G5: Cost efficiency | metrics/modules.py | test_cost_ratio | All |
| G6: Reproducibility | cli.py | test_reproducibility | All |

---

*This PRD is the single source of truth for all requirements. Update it when requirements change.*

---

## References

| Document | Relationship |
|----------|-------------|
| [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | Decisions that implement these requirements |
| [EXPERIMENT_PLAN.md](EXPERIMENT_PLAN.md) | Experiments that validate these requirements |
| [MEMORY_MAP.md](MEMORY_MAP.md) | Memory system designed per these requirements |
| [METRICS_DEFINITIONS.md](METRICS_DEFINITIONS.md) | Metrics that measure requirement fulfillment |
| [SECURITY_HARDENING.md](SECURITY_HARDENING.md) | Security controls for these requirements |
