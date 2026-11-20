# NEMESIS Defense System Audit (inspection only)

Prepared: 2026-11-12. Read-only audit; no repo files changed, no campaign executed, no Gmail sends.

## 1. Architecture and execution flow

### Defense stack
- `adaptive_agent_eval/defense/defenses.py` — local deterministic proxies (`CamelDefense`, `ProgentDefense`, `VerifierDefense`), plus `DefenseLayer`/`BaseDefense` and the majority-vote `DefenseAdapter.normalize`.
- `adaptive_agent_eval/defense/camel_real.py` — real Google CaMeL core (`vendor/camel-prompt-injection@f083b6b…`, Apache-2.0): real `SecurityPolicyEngine`, capability/provenance values, AST interpreter, `RealCamelDefense`. **Partial integration only** — the quarantined/privileged LLM planner and AgentDojo pipeline are not reproduced; provenance is adapter-constructed from the payload boundary.
- `adaptive_agent_eval/defense/progent_real.py` — real vendored SunBlaze Progent `secagent` paper artifact (`vendor/progent-paper@b02783b…`, MIT): `RealProgentDefense` wraps upstream `secagent.tool.check_tool_call` against an installed policy. **Z3 is not used** (the vendored `__init__` eagerly imports `policy_analysis`, but the checker path does not require it).
- `backend/defense_eval.py` — Phase 5 contract: four-state classification (`confirmed_success` / `confirmed_blocked` / `inconclusive` / `technical_failure`), `saved_attack_cases`, `select_saved_cases`, `replay_attack_against_defense`, `defense_catalog`, `evaluation_state`.
- `backend/defense_jobs.py` — background `DefenseJobManager` (JSON store): queued/running/completed/inconclusive/unavailable/technical_failure/interrupted; retries dedupe by request key; no verdict created by the job manager.
- `backend/adaptive_harness.py` — `DEFENSE_CHOICES = ("none","marker","verifier","progent","camel_real","progent_real")`; `MarkerDefense`, `VerifierDefenseShim`, `ProgentDefenseShim`, `RealProgentShim`, `RealCamelShim`, `_NoDefenseLayer`, `_NoDefenseAdapter`, `_build_defense`; `attack_run`/`completed_attack_runs` are read-only views; `defense_evaluation` replay; `defense_phase_eligibility`.
- `backend/pre_execution.py` — separate two-phase pre-execution gateway (`EnforcementGateway` with one-time tokens, `CooperativeLocalTarget`, `LocalToolExecutor`), lives only under the Defenses page (`/api/adaptive/defense_execute`).
- `backend/stage_b.py` — Stage B HTTP handlers: `adaptive_defense_eval` (POST `/adaptive/defense_eval`) and `adaptive_defense_execute` (POST `/adaptive/defense_execute`), plus read-only `completed_attack_runs`/`defense_catalog`/`pre_execution suites`.
- `frontend/server.py` — routes: `/api/adaptive/defenses`, `/api/adaptive/defense_campaigns`, `/api/adaptive/defense_eval/jobs`, `/api/adaptive/defense_eval/status`, `/api/adaptive/defense_eval` (start only), `/api/adaptive/defense_execute`. `_api_adaptive_defense_eval` is the **only** start point.
- `frontend/app.js` — Defenses page: reads `defense_campaigns`, builds selection, `runDefenseBtn` → POST `/api/adaptive/defense_eval` (separate job, `DEFENSE_JOB_KEY` persistence, 1200 ms polling), pre-execution suites from `defense.pre_execution.suites`.

### Execution flow
1. `Run Experiment` (`/api/adaptive/run`) hardcodes `defense="none"` (`DEFENSE_CHOICES` + `CAMPAIGN_DEFENSE`), `_build_defense` is never consulted; `_NoDefenseLayer`/`_NoDefenseAdapter` make the controller record no defense event/decision.
2. `/api/adaptive/defense_campaigns` returns `completed_attack_runs()` — read-only, no job start.
3. User selects a completed campaign + saved cases + defense → `Run Defense` → `POST /api/adaptive/defense_eval` → `_api_adaptive_defense_eval` → `defense_phase_eligibility` (completed run mandatory, 409 otherwise) → background `DefenseJobManager.start` → `h.defense_evaluation` → `defense_eval.replay_attack_against_defense` → four-state verdict persisted as `deval-<10 hex>` evaluation id.
4. `/api/adaptive/defense_eval/status` polls job state; page restores the job from `localStorage` on refresh (no restart).
5. `/api/adaptive/defense_execute` (pre-execution) is a separate Defenses action: cooperative local target proposes, defense authorizes, executor executes only after ALLOW. It is never part of an attacker run.
6. Results never feed attack-search scoring, acceptance, or the promotion gate.

## 2. File-by-file inventory

| File | Role | Status |
|---|---|---|
| `adaptive_agent_eval/defense/__init__.py` | package marker | present |
| `adaptive_agent_eval/defense/adapter.py` | `DefenseAdapter.normalize` majority vote | implemented |
| `adaptive_agent_eval/defense/defenses.py` | `CamelDefense`, `ProgentDefense`, `VerifierDefense` | implemented |
| `adaptive_agent_eval/defense/camel_real.py` | real CaMeL core adapter | implemented (partial integration) |
| `adaptive_agent_eval/defense/progent_real.py` | real secagent checker adapter | implemented |
| `backend/defense_eval.py` | Phase 5 contract | implemented |
| `backend/defense_jobs.py` | background job manager | implemented |
| `backend/pre_execution.py` | pre-execution gateway | implemented |
| `backend/adaptive_harness.py` | `DEFENSE_CHOICES`, `_build_defense`, shims, replay | implemented |
| `backend/stage_b.py` | Stage B defense HTTP handlers | implemented |
| `frontend/server.py` | defense routes | implemented |
| `frontend/app.js` | defenses page, job polling | implemented |
| tests | `test_real_defenses.py`, `test_outgoing_defense.py`, `test_attack_defense_separation.py`, `test_defense_independence.py`, `test_defense_jobs.py`, `test_pre_execution.py`, `test_frontend_server.py` | passing |

## 3. Ollama usage per defense (verified by inspection)

No defense calls an LLM. All three real defenses consume `ToolCallRequest.arguments` / `raw_text` and return `DefenseEvent`.

| Defense | Ollama | Model / endpoint evidence | Verdict source |
|---|---|---|---|
| `marker` (`MarkerDefense`, harness) | none | data = `raw_text`/`arguments` | local literal-marker taint |
| `verifier` (`VerifierDefenseShim` → `VerifierDefense`) | none | n/a — project-local rule-based | local schema+intent rules |
| `progent` (`ProgentDefenseShim` → `ProgentDefense`) | none | n/a — privilege table + string checks, no solver | local deterministic proxy |
| `camel_real` (`RealCamelShim` → `RealCamelDefense`) | none | no model calls anywhere in `camel_real.py`; upstream repo `google-research/camel-prompt-injection` f083b6b Apache-2.0 | real CaMeL interpreter policy engine |
| `progent_real` (`RealProgentShim` → `RealProgentDefense`) | none | no Ollama; upstream `sunblaze-ucb/progent` b02783b MIT `secagent.tool.check_tool_call`, pinned vendor file | vendored paper checker |

Attacker generation does use Ollama (`gmail_agent.py::_generate_with_ollama`, `gmail_attack_content.py::refine_with_ollama`), but only for the attacker side. The live Ollama target is a separate consumer, not a defense.

## 4. Defense button trace

- `POST /api/adaptive/defense_eval` (server.py 990/1518+) is the only path that starts a defense evaluation.
- `defense_campaigns` (line 924) is read-only; `defense_eval/jobs` and `defense_eval/status` are read-only lists/status.
- `run` endpoint hardcodes `defense="none"` (adaptive_harness.py 1848-1855); campaign uses `_NoDefenseLayer`, never `_build_defense`.
- `defense_phase_eligibility` requires a completed run with confirmed successful saved cases; ineligible findings return explicit `unavailable`/`inconclusive` — never a manufactured verdict.
- `defense_evaluation` replays exact saved cases with a separate `deval-<10 hex>` evaluation id, linked to `source_run_id`/`source_run_status`, and never shares IDs with attack campaigns.
- Background job manager (`defense_jobs`) persists lifecycle, progress, terminal state, and deduplicates retried requests; the HTTP handler returns 202 immediately and polls `/api/adaptive/defense_eval/status`.
- Result display: dashboard `defense_evaluations` (20 entries), defense page `evals` table, job panel via `renderDefenseJob`.
- Pre-execution (`/api/adaptive/defense_execute`) is a separate Defenses action; two-phase local gateway only.

## 5. Attack/defense sep
