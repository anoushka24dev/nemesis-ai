# Architecture Prompt Reference

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Version:** 1.0.0
> **Last Updated:** 2026-09-16
> **Status:** Active

---

## Table of Contents

1. [Master Prompt](#1-master-prompt)
2. [Scenario-Specific Prompts](#2-scenario-specific-prompts)
3. [Prompt → ADR → Code Workflow](#3-prompt--adr--code-workflow)
4. [Red Flags Requiring ADR](#4-red-flags-requiring-adr)
5. [Pipeline Integration Notes](#5-pipeline-integration-notes)

---

## 1. Master Prompt

This master prompt **MUST** be used before any code change in the project. It ensures all decisions are documented, reversible where possible, and traceable.

```
MASTER ARCHITECTURE PROMPT — ADAPTIVE AI AGENT DEFENSE EVALUATION FRAMEWORK

Before making any code change, you MUST:

1. IDENTIFY which component is affected:
   - Controller (orchestrator.py)
   - Attacker (attacker_llm.py)
   - Target Agent (agent_dojo.py)
   - Defense Layer (defenses.py, adapter.py)
   - Diagnoser (diagnoser.py)
   - Memory System (memory.py)
   - Metrics Modules (modules.py)
   - CLI (cli.py)
   - Configuration (config/*.yaml)

2. CHECK if an existing ADR covers this change:
   - Read ARCHITECTURE_DECISIONS.md
   - If the change violates an accepted ADR, STOP and propose an ADR revision
   - If the change is covered by an ADR, proceed within its constraints

3. DETERMINE if a new ADR is needed:
   - Is this a new component or interface?
   - Does this change affect multiple components?
   - Does this change the security model?
   - Does this change the experimental design?
   If YES to any, create a new ADR before coding.

4. DOCUMENT the change:
   - Update the interconnection map if components are affected
   - Update the reversibility guide if a decision becomes harder to change
   - Log the change in Git with ADR reference

5. VERIFY the change:
   - Run type checks (mypy/ruff)
   - Run unit tests
   - Check that existing tests still pass
   - Verify no ADR violations

CONSTRAINTS:
- Controller MUST remain non-LLM (ADR-001)
- Stop conditions MUST have checksums (ADR-007)
- Memory MUST be append-only for episodic (ADR-004)
- Defense events MUST include confidence scores (ADR-005)
- All API calls MUST be logged for cost tracking (ADR-015)
- Episodes MUST persist as JSON (ADR-008)
```

---

## 2. Scenario-Specific Prompts

### Prompt 1: Framework Choice

```
FRAMEWORK CHOICE PROMPT

When selecting or changing a framework/library:

1. CHECK if the project already uses this type of dependency:
   - LLM clients: anthropic SDK (ADR-013)
   - Testing: pytest (ADR-010)
   - CLI: argparse (ADR-014)
   - Config: YAML + pydantic (ADR-004)

2. EVALUATE alternatives using this matrix:
   | Criterion | Current | Alternative | Score |
   |-----------|---------|-------------|-------|
   | Ecosystem fit | | | /5 |
   | Learning curve | | | /5 |
   | Maintenance burden | | | /5 |
   | Reversibility | | | /5 |
   | Community support | | | /5 |

3. If switching, document WHY in a new ADR (minimum 3 reasons).

4. If adding NEW framework, check:
   - Is there an existing framework that does this?
   - Can it be implemented in <50 lines without a framework?
   - Does it introduce a transitive dependency chain?

5. REVERSIBILITY: Any new framework must be behind an interface so it can be swapped.
```

### Prompt 2: Data Pipeline Design

```
DATA PIPELINE DESIGN PROMPT

When designing data flow between components:

1. IDENTIFY the data contract:
   - Input type (e.g., AttackPayload)
   - Output type (e.g., DefenseEvent)
   - Side effects (e.g., memory updates, cost logging)

2. VERIFY the data flows in ONE direction:
   Controller → Attacker → Target → Defense → Adapter → Diagnoser → Memory → Metrics
   Never: Diagnoser → Attacker (would leak defense info to attacker)

3. CHECK for data leakage:
   - Attacker MUST NOT see defense confidence scores
   - Target MUST NOT see attacker's goal
   - Diagnoser MUST NOT see defense internal state (only normalized events)

4. DEFINE the schema using pydantic models in models.py.

5. LOG the data flow in the interconnection map.
```

### Prompt 3: Model Architecture

```
MODEL ARCHITECTURE PROMPT

When designing or modifying data models:

1. USE existing models from models.py:
   - AttackPayload, DefenseEvent, EpisodeConfig, EpisodeResult
   - DefenseDecision, AttackOutcome, EpisodeMode enums
   - ToolCallRequest, EpisodeLog dataclasses

2. EXTEND, don't replace:
   - Add new fields with defaults (backward compatible)
   - Don't remove fields (would break serialization)
   - Don't change field types (would break type checking)

3. VALIDATE:
   - All models use @dataclass or pydantic BaseModel
   - All enums inherit from str (for JSON serialization)
   - All optional fields have defaults

4. SERIALIZE:
   - All models must be JSON-serializable (for persistence)
   - Test serialization roundtrip: model → JSON → model
```

### Prompt 4: API Design

```
API DESIGN PROMPT

When designing interfaces between components:

1. FOLLOW the existing pattern:
   - Each component is a class with __init__(dependencies) and a main method
   - Dependencies are injected, not imported globally
   - Methods return typed results (no raw dicts)

2. DEFINE the interface contract:
   - Input types (what goes in)
   - Output types (what comes out)
   - Error conditions (what can fail)
   - Side effects (what changes externally)

3. KEEP interfaces narrow:
   - Each class should have 2-4 public methods max
   - Private methods prefixed with _
   - No God objects (if a class has >10 methods, split it)

4. TEST the interface:
   - Mock external dependencies (LLM clients)
   - Test with valid and invalid inputs
   - Test error handling paths
```

### Prompt 5: Deployment

```
DEPLOYMENT PROMPT

When preparing for deployment:

1. CHECKLIST:
   - [ ] All environment variables documented
   - [ ] API keys never hardcoded (use env vars or .env)
   - [ ] Dockerfile created (when ready)
   - [ ] Dependencies pinned in pyproject.toml
   - [ ] Logging configured (not print statements)
   - [ ] Error handling in place (no bare except)

2. SECURITY:
   - [ ] Controller runs in isolated process
   - [ ] Memory is read-only (attacker can't modify)
   - [ ] Stop conditions have checksums
   - [ ] No user input reaches LLM prompts unsanitized

3. REPRODUCIBILITY:
   - [ ] Random seeds documented
   - [ ] Model versions pinned
   - [ ] Configuration versioned in Git
   - [ ] Results stored with checksums
```

### Prompt 6: Performance Optimization

```
PERFORMANCE OPTIMIZATION PROMPT

When optimizing performance:

1. MEASURE first:
   - Profile the bottleneck (usually LLM API calls)
   - Measure latency per component
   - Identify the critical path

2. OPTIMIZE the right thing:
   - LLM API calls: Use async, batch requests, cache repeated prompts
   - Memory operations: Batch writes, use append-only patterns
   - Metrics: Compute lazily, cache intermediate results

3. DON'T optimize prematurely:
   - Python speed is rarely the bottleneck (LLM latency dominates)
   - Each episode takes seconds to minutes — milliseconds don't matter
   - Code clarity > micro-optimization

4. VERIFY optimization didn't break correctness:
   - Run full test suite
   - Compare results with pre-optimization baseline
```

### Prompt 7: Scaling

```
SCALING PROMPT

When scaling from 1,900 to more episodes:

1. HORIZONTAL SCALING:
   - Episodes are independent → trivially parallelizable
   - Use multiprocessing for episode-level parallelism
   - Each process gets its own memory instance

2. VERTICAL SCALING:
   - Within an episode, rounds are sequential (attacker depends on history)
   - Parallelize defense evaluations (CaMeL, Progent, Verifier are independent)
   - Parallelize metrics modules (they compute independently)

3. RESOURCE LIMITS:
   - LLM API rate limits: Implement retry with backoff (tenacity)
   - Memory: JSON files are fine up to ~10,000 episodes
   - Disk: ~1,900 episodes × ~10KB = ~19MB (negligible)

4. MONITORING:
   - Track API calls per minute
   - Track memory usage per episode
   - Track disk usage for persistence
```

### Prompt 8: Security

```
SECURITY PROMPT

When making security-related changes:

1. THREAT MODEL:
   - Attacker can: craft arbitrary payloads, observe outcomes, retry
   - Attacker cannot: modify controller, access memory, change stop conditions
   - Attacker may: find bypasses in defense logic

2. DEFENSE IN DEPTH:
   - Layer 1: Defense mechanism (CaMeL/Progent/Verifier)
   - Layer 2: Defense adapter (majority voting)
   - Layer 3: Diagnoser (outcome classification)
   - Layer 4: Controller (stop conditions, checksums)

3. PRINCIPLE OF LEAST PRIVILEGE:
   - Each component has minimal required access
   - Attacker never sees defense internals
   - Target never sees attack goals

4. AUDIT TRAIL:
   - Every decision is logged with evidence
   - Checksums on critical state
   - Human audit of 10% of episodes
```

### Prompt 9: Logging

```
LOGGING PROMPT

When adding or modifying logging:

1. USE Python logging module (not print):
   - logger.info() for normal operations
   - logger.warning() for recoverable errors
   - logger.error() for failures
   - logger.debug() for detailed debugging

2. LOG FORMAT:
   - Timestamp, level, component, message
   - Include episode ID for traceability
   - Include relevant IDs (round, defense type)

3. DON'T log:
   - API keys or secrets
   - Full LLM prompts (too verbose; use summaries)
   - User PII

4. STRUCTURED LOGGING:
   - Use key=value pairs for machine-parseable logs
   - Consider JSON logging for production
```

### Prompt 10: Testing

```
TESTING PROMPT

When writing or modifying tests:

1. TEST PYRAMID:
   - Unit tests: Each class in isolation (mock dependencies)
   - Integration tests: Full pipeline with mocked LLMs
   - Regression tests: Known attack/defense scenarios

2. COVERAGE TARGETS:
   - Models: 100% (dataclasses are simple)
   - Controller: 90% (critical path)
   - Defenses: 80% (core logic)
   - Diagnoser: 80% (decision logic)
   - Memory: 85% (persistence paths)

3. TEST NAMING:
   - test_<component>_<method>_<scenario>
   - Example: test_defense_camel_detects_taint_in_email_arg

4. MOCK EXTERNAL DEPENDENCIES:
   - LLM clients: Return canned responses
   - File system: Use tmpdir
   - API calls: Mock HTTP responses
```

### Prompt 11: Cost Tracking

```
COST TRACKING PROMPT

When modifying LLM API calls:

1. LOG EVERY CALL:
   - Model name
   - Input tokens
   - Output tokens
   - Cost (computed from rates)

2. TAG CALLS:
   - "attacker" — attacker LLM generating payloads
   - "target" — target agent processing payloads
   - "diagnoser" — LLM classifier for outcome classification

3. RATE TABLE:
   | Model | Input $/1M tokens | Output $/1M tokens |
   |-------|-------------------|---------------------|
   | claude-3-haiku | $0.25 | $1.25 |
   | claude-3-sonnet | $3.00 | $15.00 |
   | claude-3-opus | $15.00 | $75.00 |
   | gpt-3.5-turbo | $0.50 | $1.50 |
   | gpt-4o | $2.50 | $10.00 |

4. COMPUTE:
   - Cost per attack (total / successes)
   - Attacker/defender cost ratio
   - Cost per defense mechanism
```

### Prompt 12: Utility Monitoring

```
UTILITY MONITORING PROMPT

When testing defense impact on normal operation:

1. BASELINE: Run 50 benign AgentDojo tasks without any attacks
2. THRESHOLD: Utility must remain ≥ 90% with defenses active
3. MEASURE: Task completion rate, response quality, latency
4. ALERT: If utility drops below 85%, flag for investigation
5. LOG: Each benign task result for audit trail
```

### Prompt 13: Propagation Tracking

```
PROPAGATION TRACKING PROMPT

When testing cross-agent scenarios:

1. SETUP: Two or more agents with shared memory/tools
2. MEASURE:
   - Propagation rate: % of episodes where compromise spreads
   - Blast radius: Number of agents compromised per episode
   - Propagation speed: Rounds needed for cross-agent spread
3. TRACK: Which agent was first compromised, which were secondary
4. LOG: Full propagation chain for each episode
5. ANALYZE: Which attack categories propagate most effectively
```

### Prompt 14: Defense Composition

```
DEFENSE COMPOSITION PROMPT

When testing stacked defenses:

1. CONFIGURATIONS:
   - CaMeL + Progent
   - CaMeL + Verifier
   - Progent + Verifier
   - CaMeL + Progent + Verifier
2. MEASURE: Marginal gain = ASR(stacked) - ASR(single)
3. ANALYZE: Which combinations provide the best protection
4. LOG: Defense decisions from each layer separately
5. NOTE: Defenses may conflict (one allows, another denies)
```

### Prompt 15: Recovery Monitoring

```
RECOVERY MONITORING PROMPT

When an attack succeeds and the agent is compromised:

1. MEASURE: Time to safe state (in rounds)
2. CHECK: Can the agent still perform benign tasks?
3. DETERMINE: Does the agent need a full reset?
4. LOG: Recovery steps taken and their effectiveness
5. ANALYZE: Which attack categories cause the most damage
```

---

## 3. Prompt → ADR → Code Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    PROMPT PHASE                                 │
│  1. Identify the scenario (which of the 15 prompts applies)    │
│  2. Load the master prompt + scenario prompt                    │
│  3. Generate the ADR draft                                     │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ADR PHASE                                    │
│  1. Check existing ADRs for conflicts                          │
│  2. Document decision, rationale, consequences                  │
│  3. Update interconnection map                                  │
│  4. Categorize reversibility (easy/moderate/hard)               │
│  5. Get approval (or self-approve for minor decisions)          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CODE PHASE                                   │
│  1. Implement within ADR constraints                            │
│  2. Follow existing patterns (models, interfaces)               │
│  3. Write tests for new code                                    │
│  4. Update documentation                                        │
│  5. Run type checks + tests                                     │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    VERIFY PHASE                                 │
│  1. Check ADR compliance                                        │
│  2. Update interconnection map if needed                        │
│  3. Log change in Git with ADR reference                        │
│  4. Update reversibility guide                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Red Flags Requiring ADR

The following situations **MUST** trigger an ADR before any code is written:

| # | Red Flag | Why It Needs an ADR |
|---|----------|-------------------|
| 1 | Adding a new external dependency | Changes the tech stack; may conflict with existing choices |
| 2 | Changing a component's interface | Affects all consumers; may break existing code |
| 3 | Modifying the security model | Attacker capabilities or defense boundaries change |
| 4 | Changing the experimental design | Metrics, configurations, or episode structure changes |
| 5 | Adding a new component | New integration points; new failure modes |
| 6 | Changing data models | Serialization; backward compatibility; downstream effects |
| 7 | Modifying stop conditions | Experiment integrity; reproducibility |
| 8 | Changing the LLM client | API compatibility; cost model; rate limits |
| 9 | Adding a new defense mechanism | Composition variants; voting logic; testing overhead |
| 10 | Modifying memory persistence | Data format; query patterns; audit trail |
| 11 | Changing the CLI interface | User-facing; configuration management |
| 12 | Modifying the attacker strategy | Core experimental variable; must be documented |
| 13 | Adding async/concurrent execution | Thread safety; resource management; debugging |
| 14 | Changing the target agent | Baseline comparison; task coverage; utility measurement |
| 15 | Modifying metrics computation | Definitions; comparability; visualization |

### How to Handle Red Flags

1. **STOP** — Do not write code until the ADR is resolved
2. **DRAFT** — Write the ADR using the template in ARCHITECTURE_DECISIONS.md
3. **REVIEW** — Check for conflicts with existing ADRs
4. **DECIDE** — Accept, reject, or defer the decision
5. **CODE** — Implement within the accepted ADR constraints
6. **VERIFY** — Confirm the implementation matches the ADR

---

## 5. Pipeline Integration Notes

### How Hermes Enforces Prompts

Hermes is the code-generation orchestrator. It enforces the prompt system as follows:

1. **Pre-flight Check:** Before any code generation, Hermes loads the master prompt and verifies no red flags are present.
2. **Scenario Detection:** Hermes analyzes the user's request and maps it to one of the 15 scenario prompts.
3. **ADR Validation:** Hermes reads existing ADRs and ensures the proposed change doesn't violate any accepted decision.
4. **Code Generation:** Hermes generates code within ADR constraints, following existing patterns.
5. **Post-flight Check:** After generation, Hermes runs type checks, tests, and ADR compliance verification.
6. **Documentation Update:** Hermes updates the interconnection map and reversibility guide if needed.

### How Freebuff Prototypes Prompts

Freebuff serves as the rapid prototyping environment:

1. **Prompt Entry:** User enters a scenario-specific prompt into Freebuff.
2. **Prototype Generation:** Freebuff generates a minimal, working implementation.
3. **Testing:** The prototype is tested against existing test suites.
4. **Evaluation:** User evaluates if the prototype meets requirements.
5. **ADR Creation:** If approved, the prototype informs the ADR.
6. **Handoff:** Working code is ported to Hermes for production integration.

### Prompt Enforcement Rules

| Rule | Enforced By | Action on Violation |
|------|------------|-------------------|
| Master prompt before code | Hermes | Block code generation |
| ADR check for new deps | Hermes | Require ADR draft |
| Interface contracts | Type checker (mypy) | Error on type mismatch |
| Security constraints | Manual review | Reject code |
| Test coverage | pytest + coverage | Warn on coverage drop |
| Cost logging | Code review | Require logging |

---

*This document is the authoritative reference for all prompts in the project. Update it when new scenarios emerge.*

---

## References

| Document | Relationship |
|----------|-------------|
| [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | ADRs that these prompts enforce |
| [DECISION_WORKFLOW_GUIDE.md](DECISION_WORKFLOW_GUIDE.md) | Decision lifecycle these prompts support |
| [MEMORY_MAP.md](MEMORY_MAP.md) | Memory schemas referenced in prompt scenarios |
| [TESTING.md](TESTING.md) | Test prompts for verification |
| [PRD.md](PRD.md) | Requirements that generate these prompts |
