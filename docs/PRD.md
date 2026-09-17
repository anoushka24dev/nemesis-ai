# Product Requirements Document (PRD)

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Version:** 1.0.0
> **Last Updated:** 2026-09-16
> **Status:** Active

---

## Table of Contents

1. [Problem Statement & Goals](#1-problem-statement--goals)
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
