# Project: Adaptive AI Agent Defense Evaluation Framework

## What this product does
Evaluates how well defense strategies (CaMeL, Progent, Verifier) protect LLM-based
agents from adaptive adversarial attacks. Runs episodes where an attacker tries to
force a target agent into an unauthorized tool call; a defense layer evaluates
each call; a controller drives the loop with cryptographic stop-condition checksums.

## Stack (do not change without asking)
- Python 3.10+
- Frontend: static dashboard served by `frontend/server.py` (stdlib HTTP server, no framework)
- Database: Postgres (planned for tenant-scoped data + auth)
- ORM: SQLAlchemy 2.0
- Auth: Auth.js + session model
- Hosting: Vercel/Railway + Neon/Supabase (planned)
- Testing: pytest + pytest-asyncio
- Linting: ruff

## Rules
- Never commit secrets. All secrets go in environment variables, documented in `.env.example`.
- Every new API endpoint needs: input validation, auth check, authorization check, tests.
- Every database change goes through a migration file. Never edit the DB by hand.
- Run lint, typecheck and tests before saying a task is done.
- Ask before adding a new dependency.
- Prefer small, reviewable changes. One feature per branch.
- Run the controller loop end-to-end before calling a defense "tested."
- Record decisions in `docs/decisions/` (see below).

## Commands
- Dev: `python -m adaptive_agent_eval.cli --help`
- Run stub pipeline: `python -m adaptive_agent_eval.pipelines.mode2_c1`
- Run demo pipeline: `python -m adaptive_agent_eval.pipelines.mode2_c1_stubs`
- Lint/typecheck: `ruff check adaptive_agent_eval/ tests/`
- Test: `pytest`

## Architecture decisions
See `docs/decisions/` for the log of decisions and why they were made.
Update this file every time you make a decision. It's the single highest-leverage habit in agentic coding.