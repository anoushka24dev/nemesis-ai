# Nemesis demo runbook

One panel, one action: pair with the local backend, press **Start Nemesis Demo**,
and watch the autonomous run. Everything is executed on this machine; Gmail is
read-only by default and live sending is a separate, owner-armed capability.

> **Experience scope:** this runbook drives the **Nemesis Gmail Security Side
> Panel** demo (read-only analysis; `docs/THREAT_CLASSIFICATION.md`). It is
> not the Research Dashboard's BYOA experiment workflow (`docs/PRD.md` §1.6),
> and the hill climb shown here is the backend adaptive harness's
> deterministic local search (`docs/ADAPTIVE_SEARCH.md`) — not a live
> red-team run against a real model. Live sending stays a separate,
> fail-closed, owner-armed capability that is off by default
> (`docs/AUTONOMOUS_EMAIL.md`).

---

## 1. Prerequisites

- Python 3.11+ with the project dependencies installed.
- Google Chrome with `extension/` loaded via `chrome://extensions` →
  Developer mode → **Load unpacked**.
- No API key is required: the demo's defense verdict, strategy evaluation and
  hill climb run deterministically offline.

## 2. Start the backend

```bash
python -m backend.stage_b serve
```

It binds `http://127.0.0.1:8123`, mounts the API at `/api/v1/stage_b`, and
prints a **pairing nonce** in the terminal. Confirm it is reachable:

```bash
curl http://127.0.0.1:8123/health
```

`state` is `unpaired` until the panel pairs, then `paired`.

## 3. Open and pair the panel

1. Click the Nemesis icon (or open the side panel on a Gmail tab).
2. Paste the nonce into **Backend pairing nonce** and press **Pair**.
3. The header shows **Backend connected · Paired · Mode: SIMULATION** (or
   **LIVE** when the owner has armed live sending).

The nonce is stored only in `chrome.storage.local`; it is never rendered or
logged.

## 4. Run the demo

Press **Start Nemesis Demo**. The button is disabled while the backend is
unreachable, while the panel is unpaired, and while a run is active, so a double
click cannot start two runs.

The execution timeline advances from the backend's real run state:

1. Load architecture and strategy sources.
2. Initialize the demo scenario and sandbox identities.
3. Generate the attack / demo email.
4. Evaluate the target and the defense.
5. Run the Hill Climber candidate evaluation.
6. Strategy decision and regression checks.
7. Authorized sandbox email execution.
8. Record the final outcome and audit trail.

A failed stage is shown as failed (with the real error) and the remaining
stages are marked skipped. **Stop** sends a real stop signal to the running
harness.

## 5. What the Hill Climbing Strategy Engine shows

- Every Markdown source actually read (`docs/ARCHITECTURE_DECISIONS.md`,
  `docs/ARCHITECTURE_PROMPT.md`, `docs/decisions/phase1_architecture.md`,
  `docs/AUTONOMOUS_EMAIL.md`, `docs/THREAT_CLASSIFICATION.md`,
  `docs/METRICS_DEFINITIONS.md`, `docs/stage_b_contract.md`, plus
  `architecture.md` at the repo root when present) with size and SHA-256.
- Quoted strategy/evaluation rules from those files.
- Baseline vs candidate ASR measured by the real adaptive harness.
- Candidate utility, bypass rate, rounds to success, episode count and gate
  result.
- The candidate evaluations: accepted improvements and the latest rows, with
  ASR, delta and decision.
- The regression-gate decision and its reasons. A candidate is only retained
  when the gate passes; otherwise the baseline remains active and the panel says
  so.

Nothing in this section is fabricated: it is a projection of the harness run
record and the persisted candidate evaluation.

## 6. Email execution and honesty

The email step calls the same policy-gated workflow service as the rest of the
backend (prepared-artifact integrity, outgoing defense scan, hard allowlist,
durable kill switch, rate limit, idempotency). It prepares a message, then
submits that exact prepared id; the demo cannot substitute recipients or
content afterward. Its outcome is shown as one of:

- **SIMULATED** — no live transport was selected; nothing left the process.
  This includes simulation mode and any fallback to the in-memory mock.
- **BLOCKED** — policy refused (no allowlisted recipient, durable stop, scan,
  stale/fabricated preparation).
- **ACCEPTED** — the Gmail API accepted the send request; delivery is *not*
  independently confirmed.
- **DELIVERED** — only when the transport reports delivery explicitly.
- **UNCERTAIN** — Gmail may have accepted the request but no confirmation was
  returned. It is never retried automatically and must be reconciled.
- **FAILED** — the workflow reported a definite error.

An accepted API response is never labelled as delivered, and simulation/mock
is never labelled LIVE. The run record shows the configured mode, selected
transport, and whether a live transport is selected separately. The durable
outbound stop is ON at first use; preparation and local simulation still run
while it is ON.

Relevant owner configuration (environment, not the panel):

| Variable | Meaning | Default |
| --- | --- | --- |
| `NEMESIS_WORKFLOW_MODE` | `simulation`, `draft`, or `authorized_automation` | `simulation` |
| `NEMESIS_ALLOWED_RECIPIENTS` | comma-separated hard-allowlist recipients | empty |
| `NEMESIS_ALLOWED_DOMAINS` | comma-separated hard-allowlist domains | empty |
| `NEMESIS_SEND_AUTHORIZED` | owner send flag | off |
| `NEMESIS_DRAFT_AUTHORIZED` | owner draft flag | off |
| `NEMESIS_GRANTED_SCOPES` | declared OAuth scopes | read-only |
| `NEMESIS_RATE_LIMIT_PER_HOUR` | persistent workflow rate limit | 5 |
| `NEMESIS_OUTBOUND_STATE_PATH` | durable stop/idempotency/rate SQLite path | `results/nemesis_outbound_state.sqlite3` |

Live delivery additionally needs the armed write OAuth client and the exact
consent phrase in `gmail_live.py`, and the durable outbound stop must be
explicitly released (`POST .../workflow/killswitch/release` with
`confirm: true`) or every real send/draft remains refused. The panel cannot
enable, widen, or silently release any of this.

## 7. Routes the panel uses

```
POST /api/v1/stage_b/pair
POST /api/v1/stage_b/ping
POST /api/v1/stage_b/reset
POST /api/v1/stage_b/nemesis/demo/run
POST /api/v1/stage_b/nemesis/demo/status
POST /api/v1/stage_b/nemesis/demo/stop
POST /api/v1/stage_b/nemesis/workflow/status
POST /api/v1/stage_b/nemesis/killswitch
POST /api/v1/stage_b/nemesis/killswitch/release
POST /api/v1/stage_b/workflow/killswitch/release
GET  /health
```

## 8. Troubleshooting

- **Backend offline** — start it with `python -m backend.stage_b serve`; the
  panel retries the health check every 5 seconds.
- **Unpaired / pairing rejected** — restarting the backend rotates the nonce.
  Paste the new one.
- **Email action BLOCKED** — the result row states the exact reason
  (`NEMESIS_ALLOWED_RECIPIENTS` empty, durable kill switch, outgoing scan,
  rate limit, or a missing/modified prepared artifact).
- **Everything is BLOCKED but mode looks configured** — the durable outbound
  stop defaults ON and survives restarts. Release it explicitly only after
  reviewing recipient, mode, and scopes; releasing it does not itself send.
- **Hill climb rejected** — read the gate reasons. A candidate that does not
  beat the currently active strategy is rejected by design.

## 9. Tests

```bash
python -m pytest tests -q
```

The demo tests (`tests/test_nemesis_demo.py`) drive the real orchestrator
through the mounted routes with the in-memory mock transport; they cannot send
real email.
