# Adaptive AI Agent Defense Evaluation Framework

A framework for evaluating how well different defense strategies (CaMeL, Progent, Verifier) protect LLM-based agents from adaptive adversarial attacks.

**Status:** Scaffold with working stub pipeline. Full LLM-based execution requires API clients (Anthropic / OpenAI) wired in.

## What it does

- Runs episodes where an **attacker** (LLM or stub) tries to force a **target agent** into making an unauthorized tool call.
- A **defense layer** (CaMeL / Progent / Verifier) evaluates each tool call.
- A **diagnoser** classifies the outcome: success, blocked, ignored, or technical fail.
- A **controller/orchestrator** drives the loop with cryptographic checksums on stop conditions.
- **Memory** (episodic + procedural) lets the attacker adapt across rounds via hill-climbing over 5 attack categories.

## Modes

| Mode | What happens |
|------|--------------|
| `single-agent` | One target agent, one attacker, one defense. |
| `cross-agent` | Multi-agent propagation (e.g. Email → Calendar sharing memory). |
| `defense-composition` | Multiple defenses run in parallel; events from all are collected. |

Attacker/target tiers: `cheap` and `frontier`. Defenses: `camel`, `progent`, `verifier`.

## Quick start

### Install

```bash
pip install -r requirements.txt
```

### Run the stub pipeline (no API keys needed)

The stub pipeline (`Mode 2, Config C1`) is a fully self-contained, deterministic demo: Email agent → shared memory → Calendar agent, defended by CaMeL, 2 rounds. All LLM components are stubs so it runs offline.

```bash
python -m adaptive_agent_eval.pipelines.mode2_c1
```

Output goes to `results/mode2_c1/` (CSV, JSON, config summary).

### Run the CLI

```bash
# Show help
adaptive-eval --help

# Default run (single-agent, CaMeL, cheap attacker + target, 50 episodes)
adaptive-eval

# Customize
adaptive-eval \
  --mode cross-agent \
  --defenses camel progent \
  --attacker-tiers cheap frontier \
  --target-tiers cheap frontier \
  --episodes-per-config 10 \
  --max-rounds 3
```

### Run the tests

```bash
pip install -r requirements.txt pytest pytest-asyncio ruff
pytest
ruff check adaptive_agent_eval/ tests/
```

## Configuration

`config/default.yaml` controls experiment mode, models, defense parameters, diagnoser settings, and memory persist dir. Edit it or supply your own via the CLI's `--persist-dir`.

## Architecture

The framework is split into modules under `adaptive_agent_eval/`:

- **`models.py`** — shared dataclasses and enums (`EpisodeConfig`, `EpisodeResult`, `AttackPayload`, `DefenseEvent`, tiers, outcomes).
- **`cli.py`** — argparse entry point; builds config grids from CLI args.
- **`controller/orchestrator.py`** — the hardened evaluation loop (non-LLM, checksum-verified stop conditions).
- **`attacker/attacker_llm.py`** — LLM-based attacker with hill-climbing over 5 categories.
- **`defense/defenses.py`** — CaMeL, Progent, Verifier implementations.
- **`diagnoser/`** — outcome classification.
- **`memory/`** — episodic + procedural memory.
- **`metrics/`** — metrics collection (ASR, utility, propagation, blast radius).
- **`pipelines/`** — self-contained stub pipelines (offline demos).

Full documentation is in `docs/`:

| Document | Read it when... |
|----------|-----------------|
| `docs/PRD.md` | You want to understand all requirements |
| `docs/ARCHITECTURE_DECISIONS.md` | You want to know why things are built this way (15 ADRs) |
| `docs/MEMORY_MAP.md` | You're working on memory, attacker, or controller |
| `docs/EXPERIMENT_PLAN.md` | You're running or reviewing experiments |
| `docs/METRICS_DEFINITIONS.md` | You're implementing or analyzing metrics |
| `docs/SECURITY_HARDENING.md` | You're reviewing the security model |
| `docs/RESULTS_TEMPLATE.md` | You're presenting or reviewing results |
| `docs/TESTING.md` | You're writing or running tests |

## Requirements

- Python ≥ 3.10
- Runtime deps: openai, anthropic, pydantic, tenacity, rich, numpy, pandas, pyyaml
- Dev deps (optional): pytest, pytest-asyncio, ruff

## License

MIT. See `LICENSE`.
