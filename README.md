# Nemesis — Adaptive AI-Agent Security Testing & Research Platform

Nemesis is an adaptive AI-agent security testing and research platform. The
product vision is that a user can eventually connect their own agent, run
adaptive red-team experiments, evaluate defenses, inspect evidence and
metrics, and obtain an evidence-grounded analysis.

The platform has **two distinct experiences** — they are not the same
integration and must not be conflated:

| Experience | What it is | Status today |
|------------|-----------|--------------|
| **Nemesis Research Dashboard** | Target connection setup, experiment configuration and execution, adaptive attack search, defense selection and evaluation, metrics/comparisons, AI-assisted analysis, reproducible artifacts. | Backend harness, search strategies, defense layer, metrics, the bounded Phase 3 runner, the **HTTP API** target connection (real connectivity probe), the reference-matched dashboard (`frontend/`) and the sequential attacker → defender workflow exist. The **Local Python Agent** method has been **retired**; the **Agent Framework** connection and AI analysis over persisted evidence are **not implemented** (see [docs/PRD.md](docs/PRD.md) §1.7). |
| **Nemesis Gmail Security Side Panel** | A separate, **read-only** Gmail security experience (Chrome extension + local backend). | Implemented and guarded: `gmail.readonly` scope (fail-closed), pairing/nonce/origin protections (see [README_stageb.md](README_stageb.md), [docs/THREAT_CLASSIFICATION.md](docs/THREAT_CLASSIFICATION.md)). A *separate* owner-armed, fail-closed email write workflow exists in `email_workflow/` — simulation by default, never enabled by default ([docs/AUTONOMOUS_EMAIL.md](docs/AUTONOMOUS_EMAIL.md)); it is not part of the side panel. |

Gmail integration is **not** a research-dashboard target connection: the side
panel analyzes a real mailbox under a read-only OAuth scope, whereas the
research dashboard connects a user agent over **HTTP** (`POST` JSON contract,
bounded probe) before any experiment can run.

## Core security objectives (kept separate throughout the docs)

1. **Unauthorized data access** — did the agent access or retrieve information beyond its permissions?
2. **Sensitive-data exfiltration** — did sensitive information reach an unauthorized destination?
3. **Sensitive-data disclosure** — did the agent reveal sensitive information to an unauthorized recipient?

Success is defined by the applicable **authorization policy**; legitimate
access is not automatically a security violation. Outcomes are classified as
**confirmed success**, **confirmed blocked**, **inconclusive**, or **technical
failure**, based on recorded evidence — an unobservable boundary is reported
as inconclusive, never as "no violation occurred". Details:
[docs/SECURITY_HARDENING.md](docs/SECURITY_HARDENING.md),
[docs/METRICS_DEFINITIONS.md](docs/METRICS_DEFINITIONS.md),
[docs/CONTRACTS.md](docs/CONTRACTS.md).

## What it does (implemented today)

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

### Run the Research Dashboard (local)

```bash
python -m frontend.server 8000
# → http://127.0.0.1:8000
```

The dashboard is server-rendered from `frontend/` and bound to loopback. It
reads only persisted state through `/api/overview` (runs, candidates,
per-episode evidence, defense evaluations, checkpoint) plus a live Ollama
readiness check; it never invents numbers. Missing data renders as
“Unavailable”, never as zero or as success.

**Target connections** (`/api/connections`) — a saved connection is never
proof of readiness; readiness comes from a real probe:

| Method | What actually happens | Status |
|--------|----------------------|--------|
| **HTTP API** | `ExternalHttpTargetAdapter` posts the documented JSON body to your absolute `http(s)://` endpoint with a bounded timeout and validates a JSON response; the `Authorization` value is held in memory only and never persisted or logged | Implemented and verified |
| **Agent Framework** | `adaptive_agent_eval/target/langchain_agent.py::LangChainAgentAdapter` builds a real `langchain.agents.create_agent` ReAct agent over `ChatOllama` (default `llama3.1:8b`); readiness comes from `probe_langchain_agent` (a bounded real invocation), and experiment runs execute the same adapter end to end | Implemented and verified |
| ~~**Local Python Agent**~~ | retired from the product: no connection card, no adapter fields, no server entry point. A legacy API call is rejected with an explicit `retired` error. The internal `adaptive_agent_eval/target/byoa.py` module now only backs the labelled offline fixture target | Retired |

**Sequential lifecycle** — the attacker runs first; the defense phase is
refused (HTTP 409 with the reason) while an attacker search is running or when
the source run is not `completed`. A defense evaluation replays the saved
case ladder/seed, links each replayed episode to its source `case_id`, and
reports `confirmed_success` / `confirmed_blocked` / `inconclusive` /
`technical_failure`. `ignored` and technical failures are never counted as a
blocked attack.

**Local model** — the default assistant provider is Ollama
(`http://127.0.0.1:11434`, `llama3.1:8b`). Proposals are advisory strategy
suggestions validated by schema and search policy; they can never assert an
outcome and never replace a measured result. If Ollama is unreachable or the
model is missing, the run reports the failure instead of silently falling back
to a hosted model or a fake double.

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

Full documentation is in `docs/` (see [docs/README.md](docs/README.md) for
the full map):

| Document | Read it when... |
|----------|-----------------|
| `docs/PRD.md` | You want to understand all requirements, including the product vision, target-connection methods, and the experiment workflow |
| `docs/ARCHITECTURE_DECISIONS.md` | You want to know why things are built this way (22 ADRs) |
| `docs/ADAPTIVE_SEARCH.md` | You're comparing greedy hill climbing vs. feedback-guided search |
| `docs/EXPERIMENT_RUNNER.md` | You're running the bounded Phase 3 experiment runner |
| `docs/MEMORY_MAP.md` | You're working on memory, attacker, or controller |
| `docs/EXPERIMENT_PLAN.md` | You're running or reviewing experiments |
| `docs/METRICS_DEFINITIONS.md` | You're implementing or analyzing metrics |
| `docs/GROUND_TRUTH_METRICS.md` | You're reading or changing the separated Gmail campaign metrics, episode budget plan, or outbound rate limits |
| `docs/SECURITY_HARDENING.md` | You're reviewing the threat model and security objectives |
| `docs/THREAT_CLASSIFICATION.md` | You're working on the Gmail side panel's read-only verdicts |
| `docs/RESULTS_TEMPLATE.md` | You're presenting or reviewing results |
| `docs/TESTING.md` | You're writing or running tests |

### Product workflow (intended, partially implemented)

The intended end-to-end workflow is documented in
[docs/PRD.md §Product Experience & Workflow](docs/PRD.md): connect a target
over HTTP and run a connectivity check → select security objectives, target, defense,
search algorithm and episode budget → run bounded adaptive episodes → record
evidence and artifacts → AI analysis over persisted evidence → review the
attack report → run a **separate** defense evaluation → defense analysis.
Safe initial defaults (synthetic data, canaries, mocked/sandboxed tools,
no external network, bounded budgets, no automatic side-effecting retries,
missing metrics as unavailable rather than zero) apply to every experiment;
see [docs/PRD.md](docs/PRD.md) and [docs/EXPERIMENT_RUNNER.md](docs/EXPERIMENT_RUNNER.md).

## Requirements

- Python ≥ 3.10
- Runtime deps: openai, anthropic, pydantic, tenacity, rich, numpy, pandas, pyyaml
- Dev deps (optional): pytest, pytest-asyncio, ruff

## License

MIT. See `LICENSE`.
