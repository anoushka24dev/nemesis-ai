# Decision Workflow Guide

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Version:** 1.0.0
> **Last Updated:** 2026-09-16
> **Status:** Active

---

## Table of Contents

1. [When to Make Decisions](#1-when-to-make-decisions)
2. [How to Evaluate Tradeoffs](#2-how-to-evaluate-tradeoffs)
3. [How to Document Decisions](#3-how-to-document-decisions)
4. [How to Explain Decisions to Examiners](#4-how-to-explain-decisions-to-examiners)
5. [How to Revisit Decisions](#5-how-to-revisit-decisions)
6. [Common Pitfalls](#6-common-pitfalls)
7. [Pipeline Integration Notes](#7-pipeline-integration-notes)

---

## 1. When to Make Decisions

Architectural decisions fall into three categories based on timing.

### 1.1 Upfront Decisions (Before Coding)

These decisions are made before any implementation begins. They define the boundaries within which all code operates.

| Decision Type | Examples | Why Upfront |
|--------------|---------|-------------|
| Language & framework | Python, anthropic SDK, pytest | Everything depends on these |
| Core architecture | Non-LLM controller, 3-defense system | Defines module boundaries |
| Security model | Read-only memory, checksums | Changes later are risky |
| Data models | EpisodeConfig, DefenseEvent, etc. | Serialization; backward compat |
| Experimental design | 5 modes, 1,900 episodes | Defines what we're measuring |

**When:** Project kickoff, before Sprint 1.
**Who:** Research team (all members).
**Output:** ADR-001 through ADR-015 in `ARCHITECTURE_DECISIONS.md`.

### 1.2 Emergent Decisions (During Coding)

These decisions arise during implementation when unexpected challenges or opportunities appear.

| Decision Type | Examples | Why Emergent |
|--------------|---------|-------------|
| Interface refinement | Adding optional fields to models | Discovered during integration |
| Error handling strategy | Retry vs. fail-fast for API calls | Discovered during testing |
| Performance optimization | Caching repeated prompts | Discovered during profiling |
| Edge case handling | What to do when defense returns None | Discovered during unit testing |

**When:** During development sprints.
**Who:** Developer making the change.
**Output:** Updated ADR or new ADR-016+ as needed.

### 1.3 Deferred Decisions (After MVP)

These decisions are intentionally postponed because they don't affect the MVP and waiting provides more information.

| Decision Type | Examples | Why Deferred |
|--------------|---------|-------------|
| Multi-provider support | litellm integration | Anthropic SDK works for now |
| Database persistence | SQLite/PostgreSQL | JSON files are sufficient |
| Web dashboard | Flask/FastAPI frontend | CLI is sufficient for MVP |
| Advanced RL attacker | PPO/DQN adaptation | Hill-climbing is sufficient |
| Container orchestration | Kubernetes deployment | Single-machine is sufficient |

**When:** After MVP is validated.
**Who:** Research team (at sprint review).
**Output:** Deferred decision log in `ARCHITECTURE_DECISIONS.md` appendix.

### Decision Timing Decision Tree

```
Is this change...
├── Related to security, data models, or core architecture?
│   └── YES → Make decision UPFRONT (ADR required)
├── Discovered during coding?
│   └── YES → Make decision EMERGENT (update ADR if needed)
├── Nice-to-have but not blocking MVP?
│   └── YES → DEFER the decision
└── Not sure?
    └── DEFER by default (safe choice)
```

---

## 2. How to Evaluate Tradeoffs

### 2.1 Tradeoff Evaluation Matrix

For every decision, evaluate alternatives using this matrix. Score each criterion 1-5 (1=worst, 5=best).

| Criterion | Weight | Alternative A | Alternative B | Alternative C |
|-----------|--------|---------------|---------------|---------------|
| **Correctness** | 30% | | | |
| **Performance** | 15% | | | |
| **Cost** | 15% | | | |
| **Reversibility** | 20% | | | |
| **Complexity** | 10% | | | |
| **Maintainability** | 10% | | | |
| **Weighted Total** | 100% | | | |

### 2.2 Criterion Definitions

**Correctness (30%):**
- Does the alternative produce correct results?
- How confident are we in its correctness?
- What are the failure modes?

**Performance (15%):**
- How fast is it? (latency, throughput)
- Does it scale to 1,900 episodes?
- What are the resource requirements?

**Cost (15%):**
- API costs (for LLM-based alternatives)
- Development time (for new implementations)
- Maintenance burden (for new dependencies)

**Reversibility (20%):**
- How hard is it to change later?
- What's the blast radius of a wrong choice?
- Can we prototype without committing?

**Complexity (10%):**
- How many lines of code?
- How many new concepts?
- How steep is the learning curve?

**Maintainability (10%):**
- How easy is it to debug?
- How easy is it to test?
- How well-documented is it?

### 2.3 Worked Example: Language Choice

| Criterion | Weight | Python | TypeScript | Rust |
|-----------|--------|--------|-----------|------|
| Correctness | 30% | 4 (1.2) | 4 (1.2) | 5 (1.5) |
| Performance | 15% | 3 (0.45) | 4 (0.6) | 5 (0.75) |
| Cost | 15% | 5 (0.75) | 4 (0.6) | 3 (0.45) |
| Reversibility | 20% | 3 (0.6) | 3 (0.6) | 2 (0.4) |
| Complexity | 10% | 5 (0.5) | 4 (0.4) | 2 (0.2) |
| Maintainability | 10% | 5 (0.5) | 4 (0.4) | 3 (0.3) |
| **Weighted Total** | | **4.0** | **3.8** | **3.6** |

**Winner: Python** — Highest weighted score. Ecosystem fit and simplicity outweigh performance concerns.

### 2.4 When the Matrix Isn't Enough

Sometimes the matrix produces a tie or the decision hinges on a factor not captured by the criteria. In these cases:

1. **Gut check:** Which option would you regret least if wrong?
2. **Reversibility wins:** If tied, choose the more reversible option.
3. **Default to existing:** If tied, choose what the project already uses.
4. **Ask the team:** If still tied, escalate to the research team.

---

## 3. How to Document Decisions

### 3.1 ADR Template

Every decision MUST be documented using this template:

```markdown
### ADR-XXX: <Decision Title>

**Status:** Proposed | Accepted | Deprecated | Superseded by ADR-YYY
**Date:** YYYY-MM-DD
**Decision Maker:** <Name or team>

**Context:**
<What situation prompted this decision? What constraints exist?>

**Decision:**
<What was decided? Be specific and unambiguous.>

**Consequences:**
- ✅ <Positive consequence 1>
- ✅ <Positive consequence 2>
- ❌ <Negative consequence 1>
- ❌ <Negative consequence 2>

**Alternatives Rejected:**
- <Alternative 1>: <Why rejected>
- <Alternative 2>: <Why rejected>

**Interconnection Impact:**
<Which other ADRs are affected? Update the interconnection map.>

**Reversibility:**
<Easy | Moderate | Hard> — <What would it take to change this?>
```

### 3.2 Git Log Format

Every commit that implements or changes an ADR should reference it:

```
feat(component): brief description

Implements ADR-XXX: <Decision Title>

Details:
- What changed
- Why it changed
- How it was verified

Related: ADR-XXX, ADR-YYY
```

### 3.3 Interconnection Updates

When a new ADR is added or an existing one is modified:

1. Update the interconnection map in `ARCHITECTURE_DECISIONS.md`
2. Check all connected ADRs for conflicts
3. If conflicts found, resolve before accepting the new ADR
4. Update the reversibility guide if the change affects difficulty

### 3.4 Documentation Checklist

Before accepting any ADR, verify:

- [ ] Context is clear and specific
- [ ] Decision is unambiguous
- [ ] Consequences list both positive and negative
- [ ] At least one alternative was considered and rejected
- [ ] Interconnection map is updated
- [ ] Reversibility is categorized
- [ ] No conflicts with existing ADRs

---

## 4. How to Explain Decisions to Examiners

### 4.1 Explanation Structure

When presenting architectural decisions to examiners, use this structure:

1. **Problem Statement** (1-2 sentences)
   - What problem does this decision solve?
   - Why is it important for the project?

2. **Options Considered** (3-5 options)
   - List each option with a one-line description
   - Show the evaluation matrix

3. **Chosen Solution** (2-3 sentences)
   - What was chosen and why
   - Reference the ADR number

4. **Tradeoffs Admitted** (1-2 sentences)
   - What was sacrificed
   - Why the tradeoff is acceptable

5. **Evidence** (if available)
   - Prototype results
   - Benchmark data
   - Related work citations

### 4.2 Example Explanation

> **Decision: Non-LLM Controller (ADR-001)**
>
> **Problem:** The controller orchestrates the evaluation loop and must be resistant to attacker manipulation. An LLM-based controller could be tricked by sophisticated payloads injected through the evaluation process.
>
> **Options:** (1) Pure Python script, (2) LLM-based controller, (3) Go microservice, (4) Rust binary.
>
> **Choice:** Pure Python script. The controller has no prompt exposure, is fully deterministic, and has zero API cost. This is critical for a security evaluation framework where the controller is the trust boundary.
>
> **Tradeoffs:** We sacrifice adaptability — the controller cannot reason about edge cases or change its strategy. This is acceptable because the controller's logic is simple (loop + stop conditions) and doesn't need reasoning.
>
> **Evidence:** The controller has ~200 lines of code. It runs 1,900 episodes without issues. No attacker payload has influenced its behavior (because it has no LLM calls to influence).

### 4.3 Common Examiner Questions

| Question | How to Answer |
|----------|--------------|
| "Why didn't you use X?" | Reference the alternatives rejected section in the ADR |
| "What if this doesn't scale?" | Reference the deferred decisions section |
| "How do you know this is correct?" | Reference test results and the evaluation matrix |
| "What are the risks?" | Reference the negative consequences in the ADR |
| "Can you change this later?" | Reference the reversibility guide |
| "How does this connect to other decisions?" | Reference the interconnection map |

### 4.4 Presentation Tips

1. **Lead with the problem, not the solution.** Examiners want to understand why, not just what.
2. **Show the work.** The evaluation matrix demonstrates rigorous analysis.
3. **Admit tradeoffs.** Every decision has costs. Acknowledging them shows maturity.
4. **Reference evidence.** Prototype results, benchmarks, and literature citations strengthen your case.
5. **Connect to the bigger picture.** Show how this decision enables the overall research goals.

---

## 5. How to Revisit Decisions

### 5.1 Revisit Triggers

Decisions should be revisited when:

| Trigger | Example | Action |
|---------|---------|--------|
| **New evidence** | Prototype shows hill-climbing is too weak | Revisit ADR-002 |
| **Changed requirements** | Need to support 10,000+ episodes | Revisit ADR-008 (persistence) |
| **Failure in production** | Checksum bypass found | Revisit ADR-007 |
| **New technology** | litellm becomes standard | Revisit ADR-013 |
| **Team feedback** | Developer finds interface confusing | Revisit relevant interface ADR |
| **Cost overrun** | API costs exceed budget | Revisit ADR-015 (cost tracking) |

### 5.2 Revisit Process

```
1. IDENTIFY the trigger
   └── What changed? Why does it matter?

2. ASSESS impact
   ├── Which ADRs are affected?
   ├── What's the blast radius?
   └── What's the reversibility category?

3. DRAFT revision
   ├── Update the ADR with new context
   ├── Document what changed and why
   ├── Update the interconnection map
   └── Update the reversibility guide

4. COMPARE old vs. new
   ├── Run evaluation matrix with new information
   ├── Check for conflicts with other ADRs
   └── Verify tests still pass

5. DECIDE
   ├── ACCEPT revision (update status)
   ├── REJECT revision (document why)
   └── DEFER (need more evidence)

6. IMPLEMENT
   ├── Update code to match new ADR
   ├── Update tests
   └── Update documentation
```

### 5.3 Superseding ADRs

When a revision is significant enough, create a new ADR that supersedes the old one:

```markdown
### ADR-016: Replaced by ADR-002 (Superseded)

**Status:** Superseded by ADR-017
**Date:** 2026-09-20
**Superseded By:** ADR-017

**Reason:** <Why the original decision no longer applies>
```

### 5.4 Revisit Schedule

| ADR | Review Frequency | Next Review | Reason |
|-----|-----------------|-------------|--------|
| ADR-001 (Controller) | Never (core constraint) | N/A | Security boundary |
| ADR-002 (Hill-climbing) | After 100 episodes | TBD | Adaptation effectiveness |
| ADR-003 (3 defenses) | After Mode 1 complete | TBD | Defense adequacy |
| ADR-005 (Majority voting) | After composition tests | TBD | Voting correctness |
| ADR-008 (JSON persistence) | After 1,000 episodes | TBD | Performance at scale |
| ADR-015 (Cost tracking) | Monthly | TBD | Pricing changes |

---

## 6. Common Pitfalls

### Pitfall 1: Decision Paralysis

**Symptom:** Spending too long evaluating alternatives without deciding.

**Fix:** Set a time limit. If the decision isn't critical (reversibility = easy), decide in <1 hour. If critical, decide in <1 day. Imperfect decisions that are reversible are better than perfect decisions made too late.

### Pitfall 2: HIPPO Effect (Highest Paid Person's Opinion)

**Symptom:** The most senior person's preference overrides the evaluation matrix.

**Fix:** Use the matrix objectively. Score independently before discussing. Let the numbers guide the decision, not authority.

### Pitfall 3: Analysis Paralysis by Proxy

**Symptom:** Creating more ADRs than necessary to avoid making decisions.

**Fix:** Only create ADRs for decisions that meet the red flag criteria (Section 4 of ARCHITECTURE_PROMPT.md). Small decisions can be documented in Git commits.

### Pitfall 4: Forgetting to Update the Interconnection Map

**Symptom:** ADRs are added but the map doesn't reflect new dependencies.

**Fix:** Make interconnection map update part of the ADR acceptance checklist. Review it quarterly.

### Pitfall 5: Not Revisiting Decisions

**Symptom:** Decisions are made once and never reconsidered, even when evidence contradicts them.

**Fix:** Follow the revisit schedule (Section 5.4). Assign a "decision owner" for each ADR who is responsible for monitoring triggers.

### Pitfall 6: Conflating "Accepted" with "Perfect"

**Symptom:** Refusing to revisit a decision because it was "accepted."

**Fix:** Accepted means "best available choice at the time." New evidence should trigger revision. Document that the original decision was correct given当时的 information.

### Pitfall 7: Not Documenting Rejected Alternatives

**Symptom:** ADRs only document the chosen option, not what was considered.

**Fix:** Always document at least 2 alternatives that were rejected, with reasons. This prevents "why didn't you use X?" questions from examiners.

---

## 7. Pipeline Integration Notes

### How Hermes Enforces Decision Lifecycle

Hermes is the code-generation orchestrator that enforces the decision lifecycle:

1. **Pre-commit:** Hermes checks that all new code references an ADR. If no ADR exists, it blocks the commit and prompts the developer to create one.

2. **ADR Validation:** Hermes reads the ADR and verifies:
   - Status is "Accepted" (not "Proposed" or "Deprecated")
   - No conflicts with other accepted ADRs
   - Interconnection map is up to date
   - Reversibility is categorized

3. **Code Compliance:** Hermes verifies that generated code:
   - Follows the ADR's constraints
   - Doesn't violate any other ADR
   - Includes tests
   - References the ADR in commit messages

4. **Post-commit:** Hermes updates the project's decision log and notifies the decision owner if the ADR should be reviewed.

### How Freebuff Prototypes Decisions

Freebuff serves as the rapid prototyping environment for decision evaluation:

1. **Prompt:** User enters a decision scenario into Freebuff.
2. **Prototype:** Freebuff generates a minimal implementation of each alternative.
3. **Evaluate:** User runs the prototypes against existing tests.
4. **Compare:** Results are compared using the evaluation matrix.
5. **Decide:** User accepts one alternative and creates the ADR.
6. **Handoff:** Working code is ported to Hermes for production integration.

### Decision Enforcement Rules

| Rule | Enforced By | Action on Violation |
|------|------------|-------------------|
| ADR before code | Hermes pre-commit | Block commit |
| Interconnection map update | ADR checklist | Warn (review required) |
| Reversibility categorization | ADR template | Reject ADR draft |
| Alternative documentation | ADR template | Reject ADR draft |
| Revisit schedule | Decision owner | Quarterly review |
| Conflict detection | Hermes ADR validation | Block conflicting code |

### Decision Metrics

Track these metrics to measure decision quality:

| Metric | Target | Measured By |
|--------|--------|------------|
| ADR coverage | 100% of major decisions | Hermes audit |
| Decision latency | <1 day for critical, <1 hour for easy | Timestamp tracking |
| Revisit rate | At least 1 revisit per 10 ADRs | Decision log |
| Conflict rate | 0 unresolved conflicts | Hermes validation |
| Examiner satisfaction | No "why didn't you..." questions | Post-defense feedback |

---

*This document is the authoritative reference for decision-making in the project. All team members must follow this workflow.*

---

## References

| Document | Relationship |
|----------|-------------|
| [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | The ADRs produced by this workflow |
| [ARCHITECTURE_PROMPT.md](ARCHITECTURE_PROMPT.md) | Prompts that trigger decision-making |
| [PRD.md](PRD.md) | Requirements that drive decisions |
| [TESTING.md](TESTING.md) | Tests that verify decisions |
