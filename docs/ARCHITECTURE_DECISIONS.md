# Architecture Decisions Record (ADR)

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Version:** 1.0.0
> **Last Updated:** 2026-09-16
> **Status:** Active

---

## Table of Contents

1. [Tech Stack Matrix](#1-tech-stack-matrix)
2. [Alternatives & Tradeoffs](#2-alternatives--tradeoffs)
3. [Architecture Decision Records](#3-architecture-decision-records)
4. [Interconnection Map](#4-interconnection-map)
5. [Reversibility Guide](#5-reversibility-guide)
6. [Pipeline Integration Notes](#6-pipeline-integration-notes)

---

## 1. Tech Stack Matrix

| Component | Chosen Technology | Rationale | Alternatives Considered |
|-----------|------------------|-----------|------------------------|
| **Language** | Python 3.10+ | Dominant in AI research; rich ecosystem for LLM clients, data processing, and async | TypeScript (better for web-based agents), Rust (performance but slower prototyping) |
| **Controller** | Pure Python (non-LLM) | No prompt exposure; deterministic; auditable; fast | LLM-based controller (rejected: attack surface), Go (unnecessary complexity) |
| **Attacker LLM** | Anthropic Claude API | Strong reasoning; tool-use support; cost-effective for cheap tier | OpenAI GPT-4 (alternative frontier), Llama (self-hosted, latency concerns) |
| **Target Agent** | AgentDojo framework | 97 established tasks; known benchmarks; academic credibility | Custom task suite (no baseline), LangChain agents (less standardized) |
| **Defense: CaMeL** | Custom implementation | Control/data flow separation; taint tracking; research-backed | Reimplementing from paper (reference: ICML 2024) |
| **Defense: Progent** | SMT-based privilege control | Formal verification; least privilege enforcement | Rule-based only (less rigorous), ML-based (too complex for determinism) |
| **Defense: Verifier** | Rule-based schema + intent match | Simple baseline; fast; explainable | LLM-based verifier (circular dependency), static analysis only (too narrow) |
| **Memory System** | In-memory + JSON persistence | Fast for episodes; JSON for auditability | SQLite (overkill for <2000 episodes), Redis (unnecessary for single-machine) |
| **Metrics** | Python dataclasses + pandas | Structured; queryable; exportable | Prometheus (overkill), custom CSV (less flexible) |
| **Config** | YAML | Human-readable; version-controllable; nested support | JSON (less readable), TOML (limited nesting), env vars (not versioned) |
| **Testing** | pytest + pytest-asyncio | Standard; good async support; rich plugin ecosystem | unittest (verbose), hypothesis (property-based, add later) |
| **Linting** | Ruff | Fast; comprehensive; replaces flake8+isort+black | Black+flake8 (slower), pylint (heavy) |
| **Containerization** | Docker (planned) | Reproducible environments; isolation for security | Nix (steeper learning curve), venv (not hermetic) |
| **CI/CD** | GitHub Actions (planned) | Free for public repos; good Python support | GitLab CI (self-hosting overhead), Jenkins (legacy) |
| **Documentation** | Markdown | Universal; Git-friendly; renders everywhere | RST (Sphinx overhead), Wiki (not versioned) |
| **CLI** | argparse | Built-in; no dependencies; sufficient for 15 options | Click (more features but dependency), Typer (CLI framework overhead) |
| **LLM Client** | anthropic SDK | Direct API; well-documented; async support | litellm (multi-provider but abstraction layer), openai SDK (for GPT models only) |
| **Cost Tracking** | Custom CostTracker class | Per-call logging; model-specific rates; attacker/defender separation | LangSmith (vendor lock-in), W&B (unnecessary for cost tracking) |
| **Logging** | Python logging + rich | Structured; colorful; file + console output | loguru (less standard), structlog (more complexity) |

---

## 2. Alternatives & Tradeoffs

### 2.1 Language Choice: Python vs. TypeScript vs. Rust

| Criterion | Python | TypeScript | Rust |
|-----------|--------|-----------|------|
| LLM ecosystem | ★★★★★ | ★★★☆☆ | ★★☆☆☆ |
| Research familiarity | ★★★★★ | ★★★☆☆ | ★★☆☆☆ |
| Performance | ★★★☆☆ | ★★★★☆ | ★★★★★ |
| Async support | ★★★★☆ | ★★★★★ | ★★★★☆ |
| Type safety | ★★★☆☆ | ★★★★☆ | ★★★★★ |
| Prototyping speed | ★★★★★ | ★★★★☆ | ★★☆☆☆ |
| **Decision** | **Chosen** | Alternative | Too heavy |

**Why Python won:** The project is research-oriented. Researchers read and modify Python code daily. The LLM ecosystem (anthropic, openai, litellm) is Python-first. Performance is not critical — each episode takes seconds to minutes, not milliseconds. The 1,900-episode budget is bounded.

**Reversibility:** MODERATE. Rewriting in TypeScript would require re-implementing all LLM clients and defense logic. However, the architecture is module-separated, so a port is feasible.

---

### 2.2 Controller Design: Non-LLM vs. LLM-Based

| Criterion | Non-LLM Python | LLM-Based Controller |
|-----------|---------------|---------------------|
| Prompt exposure risk | ★★★★★ (none) | ★☆☆☆☆ (high) |
| Determinism | ★★★★★ | ★★☆☆☆ |
| Auditability | ★★★★★ | ★★★☆☆ |
| Adaptability | ★★☆☆☆ | ★★★★★ |
| Cost | ★★★★★ (zero) | ★☆☆☆☆ (API calls) |

**Why non-LLM won:** The controller is the security boundary. If the attacker can influence the controller, the entire experiment is compromised. A pure Python script has no prompt exposure — it cannot be injected. Determinism is essential for reproducibility.

**Reversibility:** EASY. An LLM-based controller could be added as an optional mode without changing existing code.

---

### 2.3 Defense Composition: Sequential vs. Parallel

| Criterion | Sequential (pipeline) | Parallel (fan-out) | Voting (ensemble) |
|-----------|----------------------|--------------------|--------------------|
| Latency | O(n) per defense | O(1) (parallel) | O(1) (parallel) |
| Correctness | Depends on order | Majority vote | Weighted vote |
| Complexity | Low | Medium | High |
| Debuggability | High | Medium | Low |

**Chosen: Sequential with majority vote adapter.** Each defense runs in sequence. The DefenseAdapter normalizes outputs and applies majority voting for disagreements. This is simple, debuggable, and sufficient for 3 defenses.

**Reversibility:** EASY. The adapter pattern means switching to parallel or voting requires only changing `DefenseAdapter.normalize()`.

---

### 2.4 Memory Persistence: JSON vs. SQLite vs. Redis

| Criterion | JSON files | SQLite | Redis |
|-----------|-----------|--------|-------|
| Setup complexity | ★★★★★ | ★★★★☆ | ★★☆☆☆ |
| Query capability | ★☆☆☆☆ | ★★★★★ | ★★★★☆ |
| Auditability | ★★★★★ | ★★★☆☆ | ★☆☆☆☆ |
| Performance | ★★★☆☆ | ★★★★☆ | ★★★★★ |
| Portability | ★★★★★ | ★★★★☆ | ★☆☆☆☆ |

**Why JSON won:** With ~1,900 episodes and ~9,500 total rounds, JSON files are sufficient. Each episode is one file. Git can version-control them. Researchers can read them directly. No database server needed.

**Reversibility:** EASY. Adding a SQLite backend requires only implementing a `PersistenceBackend` interface.

---

### 2.5 Attacker Adaptation: Hill-Climbing vs. RL vs. Bayesian Optimization

| Criterion | Hill-Climbing | RL (PPO/DQN) | Bayesian Optimization |
|-----------|--------------|--------------|----------------------|
| Implementation complexity | ★★★★★ | ★☆☆☆☆ | ★★☆☆☆ |
| Sample efficiency | ★★★☆☆ | ★★★★☆ | ★★★★★ |
| Explainability | ★★★★★ | ★★☆☆☆ | ★★★☆☆ |
| Research clarity | ★★★★★ | ★★★☆☆ | ★★★★☆ |

**Why hill-climbing won:** It's the simplest adaptation strategy that still demonstrates iterative improvement. The attacker observes outcomes, increases sophistication, and switches categories. This is interpretable for examiners and sufficient to test defense robustness.

**Reversibility:** EASY. The `AttackerLLM` class interface is fixed. Swapping the adaptation strategy only changes the `generate_payload` method internals.

---

## 3. Architecture Decision Records

### ADR-001: Controller is Non-LLM Python

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** The controller orchestrates the entire evaluation loop. It must be resistant to attacker manipulation. An LLM-based controller could be tricked by sophisticated payloads.

**Decision:** The controller is a pure Python script with no LLM calls. It reads configuration, drives the loop, checks stop conditions, and logs results. No user-facing prompts. No LLM API calls.

**Consequences:**
- ✅ No prompt exposure — attacker cannot influence controller
- ✅ Fully deterministic — reproducible results
- ✅ Zero API cost for orchestration
- ❌ Cannot adapt its own strategy (fixed loop logic)
- ❌ Cannot reason about edge cases (e.g., unusual defense outputs)

**Alternatives Rejected:**
- LLM-based controller: Too risky for security boundary
- Go/Rust: Unnecessary performance gain; loses research familiarity

---

### ADR-002: Attacker Uses Hill-Climbing Adaptation

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** The attacker must adapt across rounds. Static attacks don't test defense robustness under pressure. We need a simple, explainable adaptation strategy.

**Decision:** The attacker uses hill-climbing: it tracks success rates per category (procedural memory), increases sophistication when failing, and switches categories when hitting a ceiling. One LLM call per round.

**Consequences:**
- ✅ Simple to implement and explain
- ✅ Demonstrates iterative improvement
- ✅ Compatible with memory feedback loop
- ❌ May get stuck in local optima (acceptable for evaluation)
- ❌ Single-LLM-call-per-round limits complexity of adaptation

**Alternatives Rejected:**
- Reinforcement learning: Too complex; too many episodes needed for convergence
- Bayesian optimization: Overkill for 5 categories × 5 sophistication levels
- Genetic algorithms: No clear "genome" for attack payloads

---

### ADR-003: Three-Defense Architecture (CaMeL + Progent + Verifier)

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** We need at least two defenses to test composition. Three gives us 7 composition variants (3 singles + 3 pairs + 1 triple). Each defense must have a different mechanism to test orthogonal protection.

**Decision:** Three defenses with orthogonal mechanisms:
1. **CaMeL:** Control/data flow separation + taint tracking (dynamic analysis)
2. **Progent:** SMT-based privilege control + least privilege (formal verification)
3. **Custom Verifier:** Rule-based schema check + intent matching (static analysis)

**Consequences:**
- ✅ Three orthogonal mechanisms test different attack surfaces
- ✅ 7 composition variants provide rich data
- ✅ Each defense has a clear, publishable mechanism
- ❌ Implementing all three is significant effort
- ❌ SMT solver integration (Progent) adds dependency complexity

**Alternatives Rejected:**
- Two defenses: Insufficient composition variants
- Four+ defenses: Diminishing returns; implementation overhead

---

### ADR-004: Memory System Uses Five Memory Types

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** The attacker needs memory to adapt. But different memory types serve different purposes. Conflating them makes the system harder to reason about.

**Decision:** Five distinct memory types:
1. **Working Memory:** Current payload + defense decision (ephemeral per round)
2. **Episodic Memory:** History of attempts in this episode (append-only log)
3. **Procedural Memory:** Success rates per category across episodes (persistent)
4. **Semantic Memory:** Tool schemas, defense rules, task definitions (static)
5. **Prospective Memory:** Controller obligations (stop conditions, round budgets)

**Consequences:**
- ✅ Clear separation of concerns
- ✅ Attacker reads episodic + procedural for adaptation
- ✅ Controller reads prospective for stop decisions
- ❌ More complex than a single memory store
- ❌ Procedural memory persistence requires careful synchronization

---

### ADR-005: Defense Adapter Uses Majority Voting

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** In composition mode, multiple defenses produce separate DefenseEvents. The target agent needs a single allow/deny decision.

**Decision:** The DefenseAdapter normalizes all defense events and applies majority voting. Ties default to DENIED (safe). The adapter also logs the full evidence chain for auditability.

**Consequences:**
- ✅ Simple, explainable aggregation
- ✅ Safe default (deny on tie)
- ✅ Full evidence chain preserved
- ❌ Equal-weight voting doesn't account for defense reliability
- ❌ A single high-confidence denial can be outvoted

**Alternatives Rejected:**
- Weighted voting: Would require calibration data we don't have yet
- AND-gate (all must allow): Too conservative; blocks evaluation of defense weaknesses
- OR-gate (any can deny): Too aggressive; prevents testing bypass scenarios

---

### ADR-006: Diagnoser Uses Two-Stage Classification

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Determining whether an attack succeeded is non-trivial. The tool call might look legitimate but accomplish the attacker's goal. We need both deterministic and LLM-based classification.

**Decision:** Stage A uses rule-based checks (tool call match, defense decision, argument analysis). Stage B uses an LLM classifier on a different model family to avoid bias. Human audit of 10% of episodes provides ground truth.

**Consequences:**
- ✅ Most cases resolved deterministically (Stage A)
- ✅ Ambiguous cases get expert LLM judgment (Stage B)
- ✅ Human audit provides ground truth for calibration
- ❌ LLM classifier adds API cost
- ❌ Cross-family requirement adds model management complexity

---

### ADR-007: Stop Conditions Use Cryptographic Checksums

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Stop conditions are critical for experiment integrity. If an attacker could modify stop conditions, they could force premature termination or infinite loops.

**Decision:** Stop conditions are cryptographically signed using SHA-256. The checksum is computed after each round and logged. Any tampering would produce a different checksum, detectable during audit.

**Consequences:**
- ✅ Tamper-evident stop conditions
- ✅ Simple to implement (hashlib)
- ✅ Detectable during post-hoc audit
- ❌ Not truly signed (no key pair) — only integrity, not authenticity
- ❌ Checksum can be recomputed by attacker if they know the algorithm

---

### ADR-008: Episodes Persist as JSON Files

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Each episode produces structured data. Researchers need to inspect, query, and version-control this data.

**Decision:** Each episode persists as a single JSON file in `data/episodes/`. The filename is the episode ID. The file contains config, results, and diagnostics. JSON is human-readable and Git-friendly.

**Consequences:**
- ✅ Human-readable; Git-friendly
- ✅ No database server needed
- ✅ Each episode is self-contained
- ❌ No efficient querying across episodes (use pandas for analysis)
- ❌ File count grows (1,900 files maximum — acceptable)

---

### ADR-009: Metrics Modules Run in Parallel

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Six metric modules compute different statistics. Running them sequentially wastes time, especially across 1,900 episodes.

**Decision:** All six metrics modules (Utility, Cost, Recovery, Attack Taxonomy, Guardrail Bypass, Propagation) compute independently and in parallel using Python threading. Results are aggregated at episode end.

**Consequences:**
- ✅ Faster computation
- ✅ Independent modules can be developed/tested separately
- ❌ Thread safety requires careful state management
- ❌ GIL limits true parallelism (acceptable for I/O-bound metric computation)

---

### ADR-010: Experimental Modes Are Separated

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** The framework supports 5 experimental modes. Running them all together complicates configuration and analysis.

**Decision:** Each mode is a separate configuration. The CLI accepts `--mode` flag. Modes share the same code but use different configs. Results are stored in mode-specific directories.

**Consequences:**
- ✅ Clean separation of experimental concerns
- ✅ Same codebase, different configs
- ✅ Results are easily attributable to specific modes
- ❌ Requires careful config management
- ❌ Cross-mode comparisons need post-processing

---

### ADR-011: Target Agent Uses AgentDojo Framework

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** We need a standardized target agent with known tasks and baseline performance.

**Decision:** Target agent wraps AgentDojo, which provides 97 standardized tasks across email, booking, and file operations. This gives us an established baseline for utility measurement.

**Consequences:**
- ✅ 97 established tasks with known baselines
- ✅ Academic credibility (published benchmark)
- ✅ Utility measurement against known baseline
- ❌ Dependency on AgentDojo's task definitions
- ❌ May not cover all attack surfaces we want to test

---

### ADR-012: Cross-Agent Bridge for Multi-Agent Mode

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Cross-agent propagation mode requires two agents sharing state. Compromised state in Agent A can propagate to Agent B.

**Decision:** `CrossAgentBridge` class manages shared memory between two `TargetAgent` instances. Agent A runs first; if compromised, its state propagates to Agent B via shared memory. Propagation rate and blast radius are measured.

**Consequences:**
- ✅ Tests real-world multi-agent scenarios
- ✅ Measures propagation and blast radius
- ✅ Simple shared-memory model
- ❌ Simplified propagation model (real systems have more complex state)
- ❌ Only tests sequential propagation (not concurrent)

---

### ADR-013: LLM Client Abstraction

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Different components use different LLM models (attacker, target, diagnoser). We need a unified client interface.

**Decision:** Use the Anthropic SDK directly with a simple client wrapper. Each component receives the client at initialization. Model names are passed as strings.

**Consequences:**
- ✅ Direct API access; no abstraction overhead
- ✅ Model selection is flexible (any Anthropic model)
- ❌ Vendor lock-in to Anthropic (mitigated by model-agnostic interface)
- ❌ No multi-provider fallback (could add litellm later)

---

### ADR-014: CLI Uses argparse

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** The CLI needs to accept ~15 configuration options for experimental setup.

**Decision:** Use Python's built-in `argparse` with subcommands for each mode. No external CLI framework.

**Consequences:**
- ✅ Zero dependencies
- ✅ Built-in; well-documented
- ✅ Sufficient for 15 options
- ❌ No auto-generated help formatting (mitigated by rich)
- ❌ No type validation beyond basic argparse (mitigated by pydantic models)

---

### ADR-015: Cost Tracking Per-Call

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** Cost is a key metric. We need per-call tracking to compute cost-per-attack and attacker/defender cost ratios.

**Decision:** `CostTracker` logs every LLM API call with model name, input/output tokens, and computed cost. Rates are stored as constants. attacker vs. defender calls are tagged.

**Consequences:**
- ✅ Precise per-call cost tracking
- ✅ Enables attacker/defender cost ratio
- ✅ Model-specific rate application
- ❌ Cost rates must be manually updated when pricing changes
- ❌ Does not track caching or batch discounts

---

## 4. Interconnection Map

```
ADR-001 (Controller=Non-LLM)
  ├── ADR-007 (Checksums) — Controller integrity
  ├── ADR-014 (CLI=argparse) — Controller entry point
  └── ADR-010 (Modes Separated) — Controller configuration

ADR-002 (Hill-Climbing)
  ├── ADR-004 (5 Memory Types) — Attacker reads episodic+procedural
  └── ADR-013 (LLM Client) — Attacker API calls

ADR-003 (3 Defenses)
  ├── ADR-005 (Majority Voting) — Defense composition
  └── ADR-009 (Parallel Metrics) — Defense event logging

ADR-006 (2-Stage Diagnoser)
  ├── ADR-003 (Defenses) — Diagnoser reads defense events
  └── ADR-013 (LLM Client) — Diagnoser API calls

ADR-008 (JSON Persistence)
  ├── ADR-004 (Memory) — Episode persistence
  └── ADR-011 (AgentDojo) — Task definitions

ADR-012 (Cross-Agent Bridge)
  ├── ADR-003 (Defenses) — Multi-agent defense testing
  └── ADR-011 (AgentDojo) — Target agent instances

ADR-015 (Cost Tracking)
  ├── ADR-002 (Attacker) — Attacker cost tracking
  ├── ADR-006 (Diagnoser) — Diagnoser cost tracking
  └── ADR-009 (Metrics) — Cost metric computation
```

---

## 5. Reversibility Guide

### Easy to Change (Low risk, quick pivot)

| Decision | Change Required | Effort | Risk |
|----------|----------------|--------|------|
| ADR-002: Hill-climbing strategy | Modify `generate_payload` internals | 1-2 days | Low |
| ADR-005: Majority voting | Modify `DefenseAdapter.normalize` | 0.5 days | Low |
| ADR-008: JSON persistence | Add SQLite backend class | 1 day | Low |
| ADR-010: Mode separation | Add new mode config | 0.5 days | Low |
| ADR-014: CLI framework | Switch to Click/Typer | 1 day | Low |
| ADR-015: Cost tracking rates | Update rate constants | 0.5 days | Low |

### Moderate to Change (Some refactoring needed)

| Decision | Change Required | Effort | Risk |
|----------|----------------|--------|------|
| ADR-001: Non-LLM controller | Add optional LLM mode | 2-3 days | Medium |
| ADR-003: 3 defenses | Add/remove defense module | 2-3 days | Medium |
| ADR-006: 2-stage diagnoser | Adjust stage logic | 1-2 days | Medium |
| ADR-009: Parallel metrics | Add async/threading | 2-3 days | Medium |
| ADR-012: Cross-Agent Bridge | Extend to N agents | 3-4 days | Medium |
| ADR-013: LLM client | Switch to litellm | 1-2 days | Medium |

### Hard to Change (Significant rewrite)

| Decision | Change Required | Effort | Risk |
|----------|----------------|--------|------|
| ADR-004: 5 memory types | Merge/split memory classes | 1-2 weeks | High |
| ADR-007: Checksums | Replace with proper signing | 1 week | High |
| ADR-011: AgentDojo | Replace target agent framework | 2-3 weeks | High |
| Language choice (Python) | Full rewrite in another language | 4-6 weeks | Very High |

---

## 6. Pipeline Integration Notes

### How Hermes Consumes ADRs

Hermes is the orchestration layer that enforces architectural decisions before coding begins. The pipeline works as follows:

1. **Prompt Phase:** Hermes reads `ARCHITECTURE_PROMPT.md` to understand what decisions are needed.
2. **Decision Phase:** For each scenario, Hermes loads the relevant ADR from `ARCHITECTURE_DECISIONS.md`.
3. **Validation Phase:** Hermes checks that new code doesn't violate any accepted ADR.
4. **Coding Phase:** Code is generated/modified according to the ADR constraints.
5. **Audit Phase:** After coding, Hermes verifies ADR compliance and updates the interconnection map.

### How Freebuff Prototypes ADRs

Freebuff serves as a rapid prototyping environment. When a new ADR is proposed:

1. **Prompt Entry:** The ADR prompt is entered into Freebuff.
2. **Prototype Generation:** Freebuff generates a minimal implementation.
3. **Evaluation:** The prototype is tested against existing tests.
4. **ADR Update:** If the prototype succeeds, the ADR is updated with implementation details.
5. **Handoff:** The working prototype is ported to Hermes for production integration.

### ADR Lifecycle in the Pipeline

```
Propose ADR → Freebuff Prototype → Validate Tests → Accept ADR → Hermes Enforces → Code Generated
     ↑                                                                        │
     └──────────────────── Revisit ADR (if new evidence) ←───────────────────┘
```

---

*This document is living. Update it whenever a new decision is made or an existing one is revisited.*

---

## References

| Document | Relationship |
|----------|-------------|
| [ARCHITECTURE_PROMPT.md](ARCHITECTURE_PROMPT.md) | Prompts that enforce these decisions during code generation |
| [DECISION_WORKFLOW_GUIDE.md](DECISION_WORKFLOW_GUIDE.md) | How to make, document, and revisit these decisions |
| [PRD.md](PRD.md) | Requirements that drove these decisions |
| [MEMORY_MAP.md](MEMORY_MAP.md) | Memory schemas resulting from ADR-004 |
| [SECURITY_HARDENING.md](SECURITY_HARDENING.md) | Security controls implementing ADR-001, ADR-007 |
| [TESTING.md](TESTING.md) | Tests verifying these decisions |
| [EXPERIMENT_PLAN.md](EXPERIMENT_PLAN.md) | Experiments designed around these decisions |
