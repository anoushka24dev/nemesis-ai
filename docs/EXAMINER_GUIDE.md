# Examiner Guide

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Purpose:** Quick navigation for examiners reviewing this project
> **Last Updated:** 2026-09-16

---

## Welcome

This guide helps examiners quickly navigate the project documentation, verify claims, and assess the quality of architectural decisions, experimental design, and results.

---

## 1. Project Overview (2 minutes)

**What is this project?**

A framework that tests whether AI agent defenses (CaMeL, Progent, custom verifier) are robust against **adaptive** attackers — not just static injection strings. The attacker learns from failures and retries with different strategies.

**Why does it matter?**

AI agents are increasingly trusted with real-world permissions (email, payments, files). Most defenses are tested against fixed attacks. This project evaluates them under realistic, adaptive pressure.

**Key numbers:**
- 5 experimental modes
- 38 configurations
- 1,900 episodes
- 3 defense mechanisms
- 5 memory types
- 8 primary metrics

---

## 2. Where to Find What

### 2.1 Architectural Decisions

**Document:** [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md)

**What to check:**
- ADR-001: Controller is non-LLM (security boundary)
- ADR-002: Attacker uses hill-climbing adaptation
- ADR-003: Three defenses with orthogonal mechanisms
- ADR-004: Five memory types with clear separation
- ADR-007: Stop conditions use SHA-256 checksums

**Key questions to ask:**
1. Why was Python chosen over other languages? → Section 2.1 (tradeoff matrix)
2. Why is the controller non-LLM? → ADR-001 (security rationale)
3. How are defense disagreements resolved? → ADR-005 (majority voting)

### 2.2 Requirements

**Document:** [PRD.md](PRD.md)

**What to check:**
- 5 research questions (RQ1-RQ5)
- 6 goals with success metrics
- Memory system requirements (5 types)
- Security hardening requirements
- 1,900 episode total

**Key questions to ask:**
1. What are the success criteria? → Section 8 (metrics & success criteria)
2. How many episodes per configuration? → Section 10 (experimental configurations)
3. What is the estimated cost? → Section 10.2 (resource estimates)

### 2.3 Experimental Design

**Document:** [EXPERIMENT_PLAN.md](EXPERIMENT_PLAN.md)

**What to check:**
- Mode 1: 12 configs × 50 episodes = 600 (baseline)
- Mode 2: 6 configs × 50 episodes = 300 (cross-agent)
- Mode 3: 8 configs × 50 episodes = 400 (composition)
- Mode 4: 6 configs × 50 episodes = 300 (extended)
- Mode 5: 6 configs × 50 episodes = 300 (network)

**Key questions to ask:**
1. How are episodes structured? → Section 6 (episode structure)
2. What are the stop conditions? → Section 6.3 (stop conditions detail)
3. How is reproducibility ensured? → Section 8 (reproducibility plan)

### 2.4 Metrics

**Document:** [METRICS_DEFINITIONS.md](METRICS_DEFINITIONS.md)

**What to check:**
- ASR formula and threshold (< 20%)
- Utility score formula and threshold (≥ 90%)
- Cost per attack formula and threshold (> $0.50)
- All 8 metrics with interpretations

**Key questions to ask:**
1. How is ASR computed? → Section 1.1 (formula + example)
2. What does "utility" measure? → Section 1.2 (benign task completion)
3. How are confidence intervals computed? → Section 5.1 (bootstrap CI)

### 2.5 Security

**Document:** [SECURITY_HARDENING.md](SECURITY_HARDENING.md)

**What to check:**
- Non-LLM controller (Section 1)
- Read-only memory (Section 2)
- Checksums on stop conditions (Section 3)
- Process isolation (Section 4)
- Threat model (Section 5)

**Key questions to ask:**
1. How is the controller protected? → Section 1 (non-LLM design)
2. Can the attacker modify memory? → Section 2 (append-only enforcement)
3. What is the threat model? → Section 5 (attacker capabilities/limitations)

### 2.6 Results

**Document:** [RESULTS_TEMPLATE.md](RESULTS_TEMPLATE.md)

**What to check:**
- Table format for all 5 modes
- Example rows with interpretation
- Human audit plan (10% sampling)
- Visualization plan (7 charts)

**Key questions to ask:**
1. How are results presented? → Section 1 (table formats)
2. How is human audit conducted? → Section 3 (audit plan)
3. What statistical tests are used? → Section 5 (statistical analysis)

### 2.7 Testing

**Document:** [TESTING.md](TESTING.md)

**What to check:**
- Test pyramid (unit → integration → performance → security → human audit)
- 30+ unit test cases
- Security test cases (no LLM in controller, memory read-only, checksums)
- Coverage targets (90% controller, 85% defenses)

**Key questions to ask:**
1. What tests verify the controller is non-LLM? → Section 5.1 (AST analysis)
2. How is memory integrity tested? → Section 5.2 (tamper detection)
3. How are experiments validated? → Section 3 (integration tests)

---

## 3. Verification Checklist

Use this checklist to verify the project's claims:

### Architecture
- [ ] Controller has no LLM imports (verified by AST analysis in test suite)
- [ ] Memory is append-only (verified by unit tests)
- [ ] Stop conditions have checksums (verified by checksum tests)
- [ ] Three defenses with different mechanisms (CaMeL=dynamic, Progent=formal, Verifier=static)
- [ ] Majority voting for defense composition (verified by adapter tests)

### Experiments
- [ ] 1,900 total episodes across 5 modes
- [ ] 50 episodes per configuration (statistical power)
- [ ] Random seeds documented (base 42, config×1000)
- [ ] Model versions pinned (claude-3-haiku-20240307, etc.)
- [ ] Stop conditions are deterministic

### Metrics
- [ ] ASR formula: successes / total episodes
- [ ] Utility formula: benign tasks completed / 50
- [ ] 95% bootstrap confidence intervals
- [ ] Cost tracking per API call
- [ ] Human audit of 10% episodes (κ ≥ 0.80)

### Security
- [ ] Controller runs in separate process
- [ ] No user input reaches LLM prompts unsanitized
- [ ] API keys in environment variables (not code)
- [ ] All episode results have checksums
- [ ] Attacker cannot modify controller or memory

### Reproducibility
- [ ] All configurations in YAML files
- [ ] All results in JSON/JSONL format
- [ ] All code version-controlled in Git
- [ ] All experiments can be re-run from documentation alone
- [ ] Human audit provides ground truth labels

---

## 4. Suggested Review Order

For a thorough review, follow this order:

### First Pass (30 minutes)
1. Read EXAMINER_GUIDE.md (this document)
2. Skim PRD.md (understand what the project does)
3. Review ARCHITECTURE_DECISIONS.md (understand why decisions were made)

### Second Pass (1 hour)
4. Review EXPERIMENT_PLAN.md (understand how experiments are designed)
5. Review METRICS_DEFINITIONS.md (understand what is measured)
6. Review SECURITY_HARDENING.md (understand security model)

### Third Pass (1 hour)
7. Review MEMORY_MAP.md (understand memory system)
8. Review TESTING.md (understand test coverage)
9. Review RESULTS_TEMPLATE.md (understand how results are presented)

### Deep Dive (as needed)
10. Review ARCHITECTURE_PROMPT.md (understand code generation prompts)
11. Review DECISION_WORKFLOW_GUIDE.md (understand decision lifecycle)
12. Run test suite to verify claims

---

## 5. Key Claims to Verify

| Claim | Where to Verify | How to Verify |
|-------|----------------|---------------|
| Controller is non-LLM | SECURITY_HARDENING.md §1 | Run: `grep -r "import openai\|import anthropic" adaptive_agent_eval/controller/` |
| Memory is append-only | MEMORY_MAP.md §2 | Run: `pytest tests/test_memory.py -k "append_only"` |
| Checksums are computed | SECURITY_HARDENING.md §3 | Run: `pytest tests/test_security.py -k "checksum"` |
| ASR < 20% target | METRICS_DEFINITIONS.md §1.1 | Review experiment results when available |
| Utility ≥ 90% target | METRICS_DEFINITIONS.md §1.2 | Review benign task results |
| 1,900 episodes planned | EXPERIMENT_PLAN.md §9 | Count configs × episodes in all 5 modes |
| 30+ unit tests exist | TESTING.md §2 | Run: `pytest tests/ --collect-only` |
| Human audit at 10% | RESULTS_TEMPLATE.md §3 | Review audit sampling plan |

---

## 6. Common Examiner Questions

| Question | Answer Location |
|----------|----------------|
| Why Python? | ARCHITECTURE_DECISIONS.md §2.1 (tradeoff matrix) |
| Why not use an LLM for the controller? | ARCHITECTURE_DECISIONS.md ADR-001 (security boundary) |
| How does the attacker adapt? | MEMORY_MAP.md §3 (procedural memory), ARCHITECTURE_DECISIONS.md ADR-002 |
| How are defense disagreements resolved? | ARCHITECTURE_DECISIONS.md ADR-005 (majority voting) |
| What if the attacker modifies memory? | SECURITY_HARDENING.md §2 (append-only enforcement) |
| How is reproducibility ensured? | EXPERIMENT_PLAN.md §8 (seeds, versions, configs) |
| What is the cost? | EXPERIMENT_PLAN.md §9.2 (resource estimates) |
| How many tests exist? | TESTING.md (40+ test cases) |
| What are the limitations? | EXPERIMENT_PLAN.md §13.2 (5 acknowledged limitations) |
| What is the statistical power? | EXPERIMENT_PLAN.md §8.5 (50 episodes, bootstrap CIs) |

---

## 7. Contact

For questions about this project, contact the research team.

---

*This guide is the entry point for all examiners. Update it when the project structure changes.*
