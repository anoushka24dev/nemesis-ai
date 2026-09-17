# Adaptive AI Agent Defense Evaluation Framework — Documentation

> **Version:** 1.0.0
> **Last Updated:** 2026-09-16
> **Status:** Baseline Documentation Release

---

## Purpose

This directory contains all architectural, operational, and experimental documentation for the Adaptive AI Agent Defense Evaluation Framework. These documents are designed to be:

1. **Exam-ready** — Every decision is documented with rationale, alternatives, and tradeoffs.
2. **Pipeline-compatible** — Hermes reads ADRs before coding; Freebuff uses prompts for prototyping.
3. **Reproducible** — Every experiment can be re-run from these documents alone.
4. **Auditable** — Every metric, threshold, and test is defined unambiguously.

---

## Document Map

| # | Document | Lines | Purpose | Start Here If... |
|---|----------|-------|---------|-----------------|
| 1 | [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | 543 | All architectural decisions (15 ADRs), tech stack, tradeoffs | You want to understand WHY things are built this way |
| 2 | [ARCHITECTURE_PROMPT.md](ARCHITECTURE_PROMPT.md) | 569 | Master prompt + 15 scenario prompts for code generation | You want to generate or modify code |
| 3 | [DECISION_WORKFLOW_GUIDE.md](DECISION_WORKFLOW_GUIDE.md) | 479 | How to make, document, and revisit decisions | You need to make a new architectural decision |
| 4 | [PRD.md](PRD.md) | 485 | Product requirements — what the system must do | You want to understand all requirements |
| 5 | [MEMORY_MAP.md](MEMORY_MAP.md) | 593 | Complete memory system schemas and behavior | You're working on memory, attacker, or controller |
| 6 | [METRICS_DEFINITIONS.md](METRICS_DEFINITIONS.md) | 561 | All metrics with formulas, logging, visualization | You're implementing or analyzing metrics |
| 7 | [EXPERIMENT_PLAN.md](EXPERIMENT_PLAN.md) | 719 | Complete experiment plan for 1,900 episodes | You're running or reviewing experiments |
| 8 | [SECURITY_HARDENING.md](SECURITY_HARDENING.md) | 579 | Security model, threat model, test cases | You're implementing security controls |
| 9 | [RESULTS_TEMPLATE.md](RESULTS_TEMPLATE.md) | 377 | Result table formats, examples, audit notes | You're presenting or reviewing results |
| 10 | [TESTING.md](TESTING.md) | 879 | Testing strategy, 40+ test cases, CI/CD | You're writing or running tests |
| 11 | [EXAMINER_GUIDE.md](EXAMINER_GUIDE.md) | — | Quick navigation for examiners | You're an examiner reviewing the project |

**Total:** ~5,784 lines of documentation

---

## Quick Navigation

### By Role

| Role | Read These First |
|------|-----------------|
| **Examiner** | EXAMINER_GUIDE.md → ARCHITECTURE_DECISIONS.md → PRD.md → RESULTS_TEMPLATE.md |
| **Developer** | ARCHITECTURE_PROMPT.md → ARCHITECTURE_DECISIONS.md → MEMORY_MAP.md → TESTING.md |
| **Researcher** | PRD.md → EXPERIMENT_PLAN.md → METRICS_DEFINITIONS.md → RESULTS_TEMPLATE.md |
| **Security Reviewer** | SECURITY_HARDENING.md → ARCHITECTURE_DECISIONS.md → TESTING.md |
| **Operations** | EXPERIMENT_PLAN.md → TESTING.md → RESULTS_TEMPLATE.md |

### By Task

| Task | Document |
|------|----------|
| Understand the system | PRD.md → ARCHITECTURE_DECISIONS.md |
| Make a new decision | DECISION_WORKFLOW_GUIDE.md → ARCHITECTURE_DECISIONS.md |
| Write code | ARCHITECTURE_PROMPT.md → MEMORY_MAP.md |
| Run experiments | EXPERIMENT_PLAN.md → TESTING.md |
| Analyze results | METRICS_DEFINITIONS.md → RESULTS_TEMPLATE.md |
| Verify security | SECURITY_HARDENING.md → TESTING.md |
| Prepare for review | EXAMINER_GUIDE.md → RESULTS_TEMPLATE.md |

---

## Document Dependencies

```
EXAMINER_GUIDE.md (entry point)
    ├── ARCHITECTURE_DECISIONS.md (decisions)
    │   ├── DECISION_WORKFLOW_GUIDE.md (how decisions are made)
    │   └── ARCHITECTURE_PROMPT.md (prompts for code generation)
    ├── PRD.md (requirements)
    │   ├── EXPERIMENT_PLAN.md (experiment design)
    │   └── MEMORY_MAP.md (memory system)
    ├── METRICS_DEFINITIONS.md (metric formulas)
    │   └── RESULTS_TEMPLATE.md (result formats)
    ├── SECURITY_HARDENING.md (security model)
    │   └── TESTING.md (test cases)
    └── TESTING.md (testing strategy)
```

---

## How These Docs Connect to the Code

| Document | Code Module | Key Interface |
|----------|------------|---------------|
| ARCHITECTURE_DECISIONS.md | All modules | ADR constraints |
| MEMORY_MAP.md | adaptive_agent_eval/memory/memory.py | MemorySystem class |
| METRICS_DEFINITIONS.md | adaptive_agent_eval/metrics/modules.py | MetricsCollector class |
| SECURITY_HARDENING.md | adaptive_agent_eval/controller/orchestrator.py | Controller class |
| TESTING.md | tests/*.py | pytest test files |
| EXPERIMENT_PLAN.md | adaptive_agent_eval/cli.py | CLI arguments |
| RESULTS_TEMPLATE.md | data/metrics/*.json | Output files |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-09-16 | Baseline documentation release — all 10 documents |

---

*This README is the top-level entry point for all documentation. Update it when documents are added, removed, or reorganized.*
