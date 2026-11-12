# Architecture Decisions Record (ADR)

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Version:** 1.2.0
> **Last Updated:** 2026-10-26
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
| **Defense: Progent** | Privilege-table proxy (no SMT solver) | Deterministic least-privilege checks without a solver dependency; upstream Progent is SMT-based but is NOT reproduced here | SMT solver (rejected: dependency complexity; no solver shipped), ML-based (too complex for determinism) |
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

**Terminology note (two distinct hill-climbing implementations):** ADR-002
describes the *LLM attacker's* per-round adaptation (inside
`attacker/attacker_llm.py`). Two other components also hill-climb and must not
be conflated with it or with each other:

1. **Backend adaptive harness** (`backend/adaptive_harness.py`, exposed via
   `backend/stage_b.py`): greedy local search over *strategy ladders* (ordered
   (category, sophistication) steps). A candidate neighbour is accepted only
   when its **measured ASR strictly improves** on the current best — acceptance
   is ASR-only. Promotion to the active strategy is a **separate,
   utility-aware regression gate** (enough episodes, zero technical failures,
   strict ASR improvement over the active strategy, defender-utility floor).
   The current implementation runs a deterministic simulated attacker/target
   and a marker-based (CaMeL-style) defense: it drives the real
   Controller/Diagnoser/MemorySystem/MetricsCollector pipeline, but diagnoses
   and memory do **not** steer cross-candidate selection, and results are **not**
   evidence of adaptive red-teaming against a live LLM target.
2. **Phase 3 experiment runner** (`adaptive_agent_eval/runner/`): a bounded,
   resumable executor for the approved experiment manifest (checkpointing,
   resume, integrity verification, aggregation). It executes configurations
   and episodes with deterministic doubles; it does **not** perform any
   hill-climbing candidate search. A contract or configuration labelled
   `adaptive-hill-climbing` names the attacker *type* (ADR-002); it does not
   make the runner an adaptive attack optimizer.

---

### ADR-003: Three-Defense Architecture (CaMeL + Progent + Verifier)

**Status:** Accepted
**Date:** 2026-09-16
**Decision Maker:** Research team

**Context:** We need at least two defenses to test composition. Three gives us 7 composition variants (3 singles + 3 pairs + 1 triple). Each defense must have a different mechanism to test orthogonal protection.

**Decision:** Three defenses with orthogonal mechanisms:
1. **CaMeL:** Control/data flow separation + taint tracking (dynamic analysis)
2. **Progent:** privilege-table + argument checks (local proxy — **no SMT solver**; upstream Progent's formal verification is NOT reproduced)
3. **Custom Verifier:** Rule-based schema check + intent matching (static analysis)

**Consequences:**
- ✅ Three orthogonal mechanisms test different attack surfaces
- ✅ 7 composition variants provide rich data
- ✅ Each defense has a clear, publishable mechanism
- ❌ Implementing all three is significant effort
- ❌ No SMT solver ships: `ProgentDefense` is a privilege table plus pattern checks, so results must never be described as formal verification

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

### ADR-016: Experiment Provider Binding = Gemini

**Status:** Accepted
**Date:** 2026-10-24
**Decision Maker:** Project owner (explicit Phase 2 decision)

**Context:** Provider sources conflicted: ADR-013 and EXPERIMENT_PLAN.md §8.2 pin Anthropic models (Claude 3 Haiku/Sonnet), `config/default.yaml` and `.env.example` assume OpenAI (gpt-3.5-turbo / gpt-4o), while the working `.env` configures `LLM_PROVIDER=gemini` with `GEMINI_API_KEY` and attacker/target/diagnoser = `gemini-2.5-flash`. The framework's `ProviderConfig` implements only the `openai`/`anthropic` provider values; Gemini is already reached through its OpenAI-compatible endpoint (`gmail_auth.gemini_provider_config()`). A live models-list probe on 2026-10-24 confirmed `gemini-2.5-flash` and `gemini-2.5-pro` are available to the configured key.

**Decision:** Bind experiment tiers to Gemini via the OpenAI-compatible endpoint: cheap tier = `gemini-2.5-flash`, frontier tier = `gemini-2.5-pro`. These are recorded as provider *binding metadata* only — credentials never enter experiment configurations or manifests. The tier factors in all contracts remain provider-neutral (`cheap`/`frontier`).

**Consequences:**
- ✅ Uses the only provider with a configured key; no new credentials required
- ✅ Model IDs verified against the live models list, not guessed
- ✅ Manifest records the binding plus its provenance (`provider_binding` block)
- ❌ Supersedes ADR-013's Anthropic-only choice *for experiments* (ADR-013's client-wrapper design is unchanged)
- ❌ EXPERIMENT_PLAN.md §8.2's Claude model pins no longer describe the active binding (scope note lives in `docs/CONTRACTS.md`)
- ❌ `ProviderConfig.from_env()` must learn the `gemini` provider value in Phase 4 before any live LLM run; until then the system-health probe honestly reports `llm-provider-wiring: failed`

---

### ADR-017: Experiment Runner — Bounded, Resumable Execution (Phase 3)

**Status:** Accepted
**Date:** 2026-10-24
**Decision Maker:** Project owner (approved Phase 3 plan)

**Context:** Phase 2 delivered validated contracts and the 26-configuration / 1,300-episode manifest, but nothing could execute it safely: an unbounded runner could burn 1,300 paid episodes, interruptions lose work, and the ADR-016 provider binding (`gemini`) is not yet executable (`llm-provider-wiring: failed`).

**Decision:** A filesystem-backed runner (`adaptive_agent_eval/runner/`) with six operations — `validate`, `dry-run`, `run`, `resume`, `status`, `aggregate` — built on these boundaries:

1. **Non-executing by default.** Only `run`/`resume` execute, and only with an explicit `--execute` flag; the plan (mode, configs, episode count, provider mode, manifest hash) is printed before execution begins.
2. **Hard bounds.** `run` requires explicit configuration IDs; per-invocation episode limit defaults to 10 with an absolute cap of 50; the full 26-config/1,300-episode matrix is always refused pending a separately approved full-evaluation procedure.
3. **Deterministic engine by default.** Real local defenses + rule-based diagnoser execute against seed-driven attacker/target doubles — zero LLM calls, zero network; every record is labeled with its engine and component implementations. `--provider-mode llm` is preflighted and currently fails closed on the gemini binding; the runner never silently switches providers or falls back to doubles when real execution was requested.
4. **Durable checkpoints (ADR-008 continuity).** Atomic `run.json` checkpoint + append-only `episodes.json` (JSON Lines) + the existing `artifacts.py` manifest at finalization. No new database. Resume reconciles via terminal records (records are authoritative over checkpoint claims), fails closed on manifest-identity change, corruption, or artifact tampering, and never re-runs completed episodes.
5. **CLI-only execution.** The API exposes only non-executing planning (`GET /stage-b/experiment-dry-run`, `GET /stage-b/experiment-manifest`); no HTTP route can launch or resume a run.
6. **Honest aggregation.** Only persisted, valid records are aggregated; unavailable metrics stay `null`/`not_measured`; confidence/significance is not reported because it is not implemented; incomplete configurations are never presented as complete.

**Consequences:**
- ✅ A bounded smoke run (e.g. 2 configs × 2 episodes) is executable today with zero cost and full reproducibility
- ✅ Interruption, crash, corruption, and tampering paths are tested and fail closed
- ✅ Full-matrix execution is structurally impossible without a future approved procedure
- ❌ `--provider-mode llm` cannot run until Phase 4 implements the gemini provider path or a new ADR rebinds the manifest
- ❌ Deterministic-engine results are labeled local evaluations, never research results
- ❌ Failed episodes are not auto-retried on resume (deliberate: prevents double-spend); a new run retries

---

### ADR-018: Feedback-Guided Candidate Selection (Phase 4)

**Status:** Accepted (bounded first version)
**Date:** 2026-10-24
**Decision Maker:** Project owner (approved Phase 4 plan)

**Context:** The backend adaptive harness (`backend/adaptive_harness.py`)
searches strategy ladders greedily: each iteration measures *every* neighbour
and keeps strict ASR improvements. Nothing learned from earlier evaluations
influences which candidates are tried next, so a run repeats measurements it
already made and cannot prioritise promising regions of the ladder space.

**Decision:** Add a second, opt-in search mode (`mode="feedback"`) that ranks
neighbours from a per-run `FeedbackStore` (`backend/search_feedback.py`):

1. **Evidence = structured episode outcomes only.** Per-episode traces from the
   real Controller (outcome enum + exercised ladder steps); each episode's
   outcome is attributed to the step of its deciding (last) round. The
   Diagnoser's `AttackOutcome` enum is the entire vocabulary; no model text,
   explanation, or free-text diagnostic is ingested.
2. **Ranking rule:** smoothed empirical success rate per
   `(category, sophistication)` key, `estimate = (successes + ALPHA * p) /
   (decided + ALPHA)` with `ALPHA = 4` shrinkage toward the run-wide rate `p`;
   candidate score = mean over its steps; ties break on structural
   `neighbours()` order. Unobserved steps score exactly `p` (neutral). No
   confidence intervals or significance claims are made.
3. **Budgeted first-improvement:** evaluate the top `selection_budget`
   (default 3) ranked neighbours per iteration; accept the first strict ASR
   improvement (acceptance rule unchanged); regenerate the frontier from the
   new best minus already-recorded keys (duplicate avoidance).
4. **Store lifecycle:** versioned JSON (`schema_version: 1`) beside the harness
   store, bound to `run_id` + config fingerprint; corrupt/mismatched state is
   discarded with a recorded reset reason; atomic writes; never reset between
   candidates within a run, always fresh across independent runs.
5. **Quality gates untouched:** `_evaluate_gate` and `promote()` are unchanged;
   mode defaults to `greedy`, so existing behavior is byte-for-byte preserved
   when the adaptive mode is disabled.
6. **A/B protocol:** `compare_search_modes()` runs both arms with identical
   ladder, defense, episode budget, seed, and `seed + iteration` evaluation-seed
   policy, repeated runs for reproducibility, recording consumed evaluations,
   unique candidates, incomplete evaluations, utility, gate verdict, and
   whether ordering changed — with unavoidable asymmetries listed as
   limitations.
7. **Defense transfer probe:** `evaluate_strategy(..., defense="verifier")`
   runs the package's real `VerifierDefense` behind the same interface to
   observe whether a learned preference reappears under a second deterministic
   local defense. Two toy defenses support no generalization claim.

**Consequences:**
- ✅ Feedback demonstrably changes candidate ordering under controlled fixtures
  (regression-tested against the greedy order)
- ✅ Baseline greedy search, its acceptance rule, and the promotion gate are
  unchanged and still the default
- ✅ Every selection decision persists its evidence and is auditable
- ✅ Corrupt/partial/failed evaluations cannot create favorable signals
- ❌ Step statistics are correlational, not causal attribution
- ❌ `ALPHA` smoothing is not a statistical guarantee; no significance test
- ❌ Results remain deterministic local simulation — not adaptive red-teaming
  against a live LLM target (blocked on ADR-016/017)

**Alternatives Rejected:** reinforcement learning / Bayesian optimization /
embeddings (no evidence of necessity for a 5x5 ladder space), Thompson sampling
or Wilson intervals (would imply statistical guarantees the deterministic
fixture cannot support), resetting per candidate (would destroy the cross-
candidate signal), reusing greedy's exhaustive scan with only a re-labeling
(ordering would have no effect on the search — explicitly regression-tested).

---

### ADR-019: BYOA Integration — Local Python Adapter First (product requirement)

**Status:** Partially superseded by ADR-022 — the three agent-shape categories
remain the requirement, but the **Local Python Agent connection method was
retired**.
**Date:** 2026-10-25
**Decision Maker:** Project owner (product vision)

**Context:** The product vision requires users to connect their own agent to
the Research Dashboard. A local Python adapter now exists
(`adaptive_agent_eval/target/byoa.py`: `ByoaAdapterSpec`, `validate_byoa_spec`,
`connectivity_check`, `BringYourOwnAgentAdapter`, with
`adaptive_agent_eval/target/example_adapter.py` as the documented example).
The **HTTP API** connection shipped later through
`ExternalHttpTargetAdapter` + `backend/connections.py` (ADR-021). A
framework-specific adapter still does not exist and is labelled unavailable.
The Gmail Security Side Panel's read-only integration is a *different*
integration and must not be presented as BYOA.

**Decision:** Support exactly three BYOA agent categories, delivered through
a **local Python adapter behind a documented interface**:

1. **Single-turn text-in/text-out agents.**
2. **Multi-turn conversational / stateful agents** (history/state across turns).
3. **Tool-using agents** that call APIs, databases, files, or other tools.

Delivery order: local Python adapter + documented interface → stronger
multi-turn and tool instrumentation (instrumented boundaries so the three
security objectives are observable) → hosted-endpoint and
framework-specific adapters.

**Consequences:**
- ✅ One interface covers all three categories; no per-framework fork early
- ✅ Tool-boundary instrumentation is tied to outcome observability (ADR-020)
- ✅ Gmail side panel stays a separate, read-only experience with its own contract
- ⚠️ **Superseded in part by ADR-022:** the local Python *connection method* was retired from the product; only the HTTP API connection is supported today. The three agent-shape categories above remain the requirement.
- ❌ Tool-using agents are the hardest category to instrument honestly; some boundaries may stay unobservable (→ `inconclusive`, never "safe")

**Alternatives Rejected:** starting with hosted-endpoint adapters (no local
debugging loop, credentials handling before any evidence exists), treating
the Gmail integration as BYOA (conflates a fixed read-only scope with
arbitrary user agents).

---

### ADR-020: Defense Evaluation Phase Is Separate from Attacker Search

**Status:** Accepted (defense-evaluation phase implemented: `backend/defense_eval.py` + `AdaptiveHarness.defense_evaluation`)
**Date:** 2026-10-25
**Decision Maker:** Project owner (product vision)

**Context:** The product must evaluate defenses as a distinct experience:
replay selected attack scenarios under protective controls, compare defense
settings, measure false positives and legitimate-task utility, and report
whether a violation was prevented or merely detected. Attacker search,
defense decisions, and post-run AI analysis all consume experiment evidence
and could silently contaminate each other.

**Decision:**

1. The defense phase is a **separate evaluation** of the connected agent
   under selected protective controls, with its own configuration,
   execution, and analysis (PRD §1.13 A–E).
2. **Three channels never write into each other:** attacker search feedback
   (greedy or feedback-guided, ADR-018), defense decisions (enforcement at
   data-access/tool boundaries), and post-run AI analysis (attack and
   defense analyses over persisted evidence).
3. Outcome reporting uses the four product classes (confirmed success,
   confirmed blocked, inconclusive, technical failure) as a **view over**
   `AttackOutcome` / `GroundTruthOutcome` (CONTRACTS §4.1); detect ≠ prevent
   (`detected_not_blocked` stays distinct).
4. Each defense record names its actual implementation
   (`DefenseImplementation`): the shipped CaMeL/Progent/Verifier components
   are simplified proxies (no SMT solver in Progent, pattern heuristics in
   CaMeL/Marker), and no defense may be credited with a boundary it cannot
   observe.

**Consequences:**
- ✅ A blocked *and detected* effect is never reported as prevented without evidence
- ✅ Feedback loops stay auditable: each channel has its own persisted state
- ✅ False positives and legitimate-task utility are measured in the defense phase, not assumed from ASR
- ✅ Defense phase replays a finding with the source run's ladder and seed, gated on a completed attacker run with persisted linkage (eligibility + replay, `defense_evaluation`); the replay executes through the currently configured target, so a differing target identity is recorded as an explicit limitation rather than presented as an identical environment
- ❌ Proxy defenses limit how far results generalize to the published systems

**Alternatives Rejected:** folding defense decisions into the attacker's
feedback store (would let attack outcomes tune enforcement), a single
combined analysis pass (would mix measured outcomes with interpretation),
reporting per-defense results without implementation labels (overstates what
ran).

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
  ├── ADR-011 (AgentDojo) — Task definitions
  └── ADR-017 (Runner) — Run checkpoints, episode records, artifact integrity

ADR-016 (Provider Binding)
  ├── ADR-017 (Runner) — llm-mode preflight enforces the binding; fails closed today
  └── Phase 4: gemini provider implementation unblocks live LLM runs

ADR-018 (Feedback-Guided Search)
  ├── ADR-002 (Hill-Climbing) — greedy baseline preserved as default mode
  ├── ADR-006 (Diagnoser) — AttackOutcome enum is the evidence vocabulary
  └── ADR-017 (Runner) — same bounded, deterministic evaluation discipline

ADR-019 (BYOA Adapter First)
  ├── ADR-013 (LLM Client) — provider-neutral agent invocation
  └── ADR-020 (Defense Phase) — instrumented tool boundaries make BYOA outcomes classifiable

ADR-020 (Defense Phase Separation)
  ├── ADR-018 (Feedback Search) — search feedback never writes into defense decisions
  ├── ADR-003 (3 Defenses) — proxy status labeled via DefenseImplementation
  ├── CONTRACTS §4.1 — four outcome classes as the reporting layer
  └── ADR-021 (Dashboard Connections + Barrier) — API-enforced ordering, case-level linkage

ADR-021 (Dashboard Connections + Barrier)
  ├── ADR-019 (BYOA Adapter First) — local Python method uses the same adapter contract
  └── ADR-020 (Defense Phase) — replay is only reachable after the completion barrier

ADR-012 (Cross-Agent Bridge)
  ├── ADR-003 (Defenses) — Multi-agent defense testing
  └── ADR-011 (AgentDojo) — Target agent instances

ADR-015 (Cost Tracking)
  ├── ADR-002 (Attacker) — Attacker cost tracking
  ├── ADR-006 (Diagnoser) — Diagnoser cost tracking
  └── ADR-009 (Metrics) — Cost metric computation
```

---

### ADR-021: Research Dashboard Connections, Real Probes, and API-Enforced Phase Ordering

**Status:** Accepted (dashboard rebuilt in `frontend/`; connections in `backend/connections.py`)
**Date:** 2026-10-26
**Decision Maker:** Project owner (product directive)

**Context:** The research dashboard needed to expose target-connection
methods without pretending unsupported integrations work (it originally
showed three; ADR-022 reduced the supported set to two), render only real
persisted state, and guarantee that defense evaluation never runs while the
attacker search is active. The previous UI exposed controls that were not
bound to the backend (a scripted timeline, a fabricated completion summary)
and an HTTP target adapter existed in code but was unreachable from run
configuration.

**Decision:**

1. **Connections are probed, never inferred.** `/api/connections` stores the
   selected method and the last probe result. HTTP API performs one bounded
   POST and requires a JSON response. The Agent Framework method has no
   implementation and is reported as unavailable with its prerequisite. The
   Local Python Agent method has since been retired (ADR-022). No method falls
   back to a fixture on failure.
2. **The HTTP adapter is wired to execution.** `_set_target_config` accepts
   `{kind: "http_api", endpoint_url, ...}` and registers an
   `ExternalHttpTargetAdapter`, so a validated HTTP connection can actually
   be attacked — it is not a UI label.
3. **The barrier is backend state, not a disabled button.**
   `defense_phase_eligibility` refuses every defense request while an attacker
   search is running, and for source runs whose status is not `completed`.
   `/api/adaptive/defense_eval` returns 409 with the exact reason.
4. **Case-level linkage.** Every evaluated episode persists a stable
   `case_id` (`<strategy>:ep<N>`); each replayed defense episode carries
   `source_case_id` pointing back to it. Replay uses the source ladder and
   seed; conflicting target identity is reported, not hidden.
5. **Dashboard data comes from one read-only aggregate** (`GET /api/overview`)
   computed from the harness store, connection store, and a live Ollama
   readiness check. Missing values stay `null` and render as "Unavailable";
   `ignored`/inconclusive and technical failures have their own display
   buckets and are never rolled into "blocked".

**Consequences:**
- ✅ A user can connect a real HTTP endpoint and see the probe result that
  justifies the "ready" state
- ✅ Defense evaluation cannot race an attacker run or start from an
  incomplete run, regardless of what the UI sends
- ✅ A defended case can be traced to the exact attack case that produced it
- ✅ The dashboard stops claiming capabilities it lacks (framework connection,
  pause, 1,000-episode runs)
- ❌ The Agent Framework path remains a visible gap rather than a feature
- ❌ The HTTP probe is a synthetic request; it proves reachability and the
  response contract, not the quality of the user's agent

**Alternatives Rejected:** shipping a LangChain shim without an adapter (would
be a fake integration), treating a syntactically valid URL as connected
(no evidence), allowing defense evaluation from any run (violates strict
sequencing), and deriving dashboard metrics from request responses instead of
persisted artifacts (fabricates progress).

---

### ADR-022: Retire the Local Python Agent Connection Method

**Status:** Accepted (retired in `backend/connections.py`, `frontend/`, `/api/adaptive/run`)
**Date:** 2026-10-26
**Decision Maker:** Project owner (product directive)

**Context:** The dashboard exposed a *Local Python Agent* connection that
imported `<module>:<entry>` in-process and called `run_turn(request)`. It
required users to write and maintain an adapter, offered no process isolation
(a wall-clock timeout is not a sandbox), and could not be validated beyond a
single synthetic ping turn. The product decision is to support exactly two
connection methods — **HTTP API** (implemented) and **Agent Framework**
(unavailable) — and to stop advertising the Python path.

**Decision:**

1. Remove the method from the product surface: no connection card, no adapter
   module / entry-callable fields, no setup template, no validation branch, no
   active-connection type.
2. `backend/connections.py` keeps the legacy identifier **only** in
   `RETIRED_METHODS`, so `connect`/`select` reject it with an explicit
   `retired` message and `active()` ignores a stale stored selection (an old
   `results/connections.json` cannot resurrect it or crash the overview).
3. `/api/adaptive/run` and `/api/adaptive/validate` reject an inline
   `user_byoa` target spec with HTTP 400 and the same guidance.
4. The internal module `adaptive_agent_eval/target/byoa.py` and its
   `local-byoa-fixture` target remain, because the harness's **labelled
   offline fixture** is implemented through them. That fixture is a
   deterministic development stand-in, never presented as a user's agent.
5. The HTTP JSON contract is documented in the dashboard (Agents page) and in
   PRD §1.7, so "connect your agent" has one supported answer.

**Consequences:**
- ✅ One supported connection path with a real probe, documented request and
  response shape, and no user-written adapter code
- ✅ A legacy client cannot silently re-enable in-process Python execution
- ✅ Existing persisted runs and defense evaluations stay readable (target
  kind is stored per run; legacy records are not rewritten)
- ❌ Users with Python-only agents must expose an HTTP endpoint; that is a
  real prerequisite, and it is stated in the UI
- ❌ The framework integration remains a visible gap

**Alternatives Rejected:** hiding the card while leaving the endpoint live
(would keep an undocumented in-process execution surface), deleting the BYOA
module outright (would break the labelled fixture and its deterministic
tests), and keeping the method as "deprecated but usable" (the directive is
that it is not a supported connection method).

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
