# Adaptive AI Agent Defense Evaluation Framework — Documentation

> **Version:** 1.1.0
> **Last Updated:** 2026-10-25
> **Status:** Baseline Documentation Release + product-vision alignment

---

## Product vision (what these documents describe)

Nemesis is an adaptive AI-agent security testing and research platform. Two
distinct experiences are documented across this directory — they are **not**
the same integration:

1. **Nemesis Research Dashboard** — target connection (HTTP API), experiment
   configuration and execution, adaptive attack search (greedy and
   feedback-guided), defense selection and evaluation,
   metrics/comparisons, AI-assisted analysis, and reproducible artifacts.
   Most of this is a **product requirement**; what exists today is described
   honestly in [PRD.md](PRD.md) and
   [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md).
2. **Nemesis Gmail Security Side Panel** — a separate, read-only Gmail
   security experience ([THREAT_CLASSIFICATION.md](THREAT_CLASSIFICATION.md),
   [AUTONOMOUS_EMAIL.md](AUTONOMOUS_EMAIL.md), `README_stageb.md`).

Product-level requirements — target connection methods and agent-shape
categories, the three security objectives, the four outcome classes, the
experiment workflow, safe defaults, and the intended AI analyses — live in
[PRD.md](PRD.md). Threat-model and
metrics consequences live in [SECURITY_HARDENING.md](SECURITY_HARDENING.md)
and [METRICS_DEFINITIONS.md](METRICS_DEFINITIONS.md).

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
| 1 | [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | — | All architectural decisions (21 ADRs), tech stack, tradeoffs | You want to understand WHY things are built this way |
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
| 12 | [CONTRACTS.md](CONTRACTS.md) | — | Shared data contracts, lifecycle, aggregation policy, validated 26-config matrix | You're implementing experiments, APIs or dashboards |
| 13 | [ADAPTIVE_SEARCH.md](ADAPTIVE_SEARCH.md) | — | Greedy hill climbing vs. feedback-guided candidate selection (Phase 4) | You're comparing or changing the search algorithms |
| 14 | [EXPERIMENT_RUNNER.md](EXPERIMENT_RUNNER.md) | — | Bounded, resumable Phase 3 execution (CLI-only, non-executing by default) | You're executing or resuming bounded runs |
| 15 | [THREAT_CLASSIFICATION.md](THREAT_CLASSIFICATION.md) | — | Gmail side panel threat verdicts, read-only guarantees, rule feedback loop | You're working on the Gmail Security Side Panel |
| 16 | [GROUND_TRUTH_METRICS.md](GROUND_TRUTH_METRICS.md) | — | Separated content/draft/send/recipient metrics, episode budget planning, outbound rate limits | You're reading or changing campaign measurements |

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
| Run experiments | EXPERIMENT_PLAN.md → EXPERIMENT_RUNNER.md → TESTING.md |
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
| 1.1.0 | 2026-10-25 | Product-vision alignment: two experiences (Research Dashboard + read-only Gmail side panel), target-connection categories, three security objectives, four outcome classes, experiment workflow and safe defaults documented in PRD/SECURITY_HARDENING/METRICS_DEFINITIONS; ADAPTIVE_SEARCH.md and EXPERIMENT_RUNNER.md added to the map |
| 1.2.0 | 2026-10-26 | Local Python Agent connection method retired (ADR-022): PRD §1.7 now documents the two supported methods (HTTP API implemented, Agent Framework unavailable), CONTRACTS/README/EXAMINER_GUIDE/EXPERIMENT_PLAN/EXPERIMENT_RUNNER/THREAT_CLASSIFICATION updated to match. Defense implementations are documented as local proxies (no SMT solver, no upstream CaMeL/Progent code) |

---

*This README is the top-level entry point for all documentation. Update it when documents are added, removed, or reorganized.*
