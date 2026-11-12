# Manus Dashboard Handoff — Nemesis Adaptive Security Evaluation

**Purpose**: This document provides the backend data contract, evidence sources, and state semantics required by the Manus frontend team to implement dashboard panels. All example values are derived from actual persisted runtime data. No invented or mock values are included.

---

## 1. Campaign Overview Panel

The campaign overview displays the top-level state of the adaptive evaluation lifecycle. All values are read from the adaptive harness store (`results/adaptive_store.json`) and the checkpoint file.

| State Key | Type | Source | Description |
|-----------|------|--------|-------------|
| `generated_at` | `str` (ISO 8601) | `build_overview()` | Timestamp of last overview generation |
| `connection` | `dict \| None` | `get_store().active()` | Active connection status; `null` when no connection |
| `connections` | `list` | `get_store().methods()` | List of supported connection methods |
| `provider` | `dict` | `_provider_health()` | Ollama health: `reachable`, `model_available`, `ready`, `error`, `error_category`, `default_model` |
| `assistant` | `str` | `status.get("assistant")` | Assistant provider kind (`"fake"`, `"ollama"`, etc.) |
| `taxonomy.objectives` | `list[{id, name}]` | Contract constants | Fixed attack categories (Part 10.1) |
| `taxonomy.dimensions` | `list[{id, name}]` | Contract constants | Fixed strategy dimensions (Part 10.1) |
| `lifecycle.phase` | `str` | `build_overview()` | One of: `"idle"`, `"attacker"`, `"defense_ready"`, `"incomplete"`, `"defense_unavailable"` |
| `lifecycle.running` | `bool` | `status.get("running")` | Whether a run is currently in flight |
| `lifecycle.attacker_complete` | `bool` | `run_dict and run_dict.status == "completed"` | True when attacker run finished |
| `lifecycle.barrier_reason` | `str \| None` | `build_overview()` | Why defense cannot start (e.g., "an attacker search is running") |
| `lifecycle.eligibility` | `dict` | `build_overview()` | `{"eligible": bool, "reason": str, "source_run_id": str \| None, "run_status": str}` |
| `settings.search_mode` | `str` | `status.get("search_mode")` | `"greedy"` or `"feedback"` |
| `settings.defense` | `str \| None` | `status.get("defense")` | Currently selected defense kind |
| `settings.target` | `str \| dict \| None` | `status.get("target")` | Target identity or `null` |
| `settings.target_kind` | `str \| None` | `status.get("target_kind")` | e.g. `"remote"`, `"http_api"`, `"user_byoa"` |
| `settings.assistant_provider` | `str \| None` | `status.get("provider")` | Assistant provider name |
| `settings.model_request_budget` | `int \| None` | `status.get("model_request_budget")` | Model request budget limit |
| `settings.limits` | `dict` | `build_overview()` | Fixed limits: episodes_per_candidate, max_rounds, iterations, total_episode_budget, model_requests |
| `run` | `dict \| None` | `status.get("current_run")` | Current run record (or `null`) |
| `active_run` | `dict \| None` | `build_overview()` | The in-flight run dict (same as `run` when running) |
| `candidates` | `list[dict]` | `build_overview()` | List of candidate summaries (last 12) |
| `history` | `list[dict]` | `run_dict.get("history") or []` | Full iteration history; empty list when no run |
| `metrics` | `dict` | `build_overview()` | Measured metrics (see Section 4) |
| `defense` | `dict` | `build_overview()` | Defense panel data (catalog, evaluations, state, eligible_cases) |
| `activity` | `list[dict]` | `build_overview()` | Recent activity feed (last 6 events, sorted by timestamp descending) |
| `reports.runs` | `list[dict]` | `build_overview()` | Last 10 run summaries (run_id, status, timestamps, mode, defense, target, best_asr, baseline_asr, episodes_consumed, candidate_id, improved, converged, global_best_category, assistant) |
| `reports.checkpoint` | `dict \| None` | `status.get("checkpoint")` | Checkpoint state (`available: bool`) |

### Loading State
- Dashboard shows "Loading..." when `connection` is `None` or `provider` health check is in progress.

### Empty State
- When no run has ever been started: `running: false`, `attacker_complete: false`, `candidates: []`, `history: []`, `metrics: {all_None}`, `defense.evaluations: []`.

### Unavailable State
- When `lifecycle.phase == "defense_unavailable"`: defense evaluation is not eligible until the attacker run completes and its cases persist.

### Partial State
- When a run is in progress (`lifecycle.running == true`): live counters come from the current run, but measured evaluations are `null` until the run terminates.

### Completed State
- When `lifecycle.attacker_complete == true` and `lifecycle.phase == "defense_ready"`: the dashboard shows the final evaluation, candidate data, and enables defense evaluation initiation.

### API Mapping
| Endpoint | Method | Purpose | States Covered |
|----------|--------|---------|----------------|
| `/api/overview` | `GET` | Campaign overview data | All states (loading, empty, unavailable, partial, completed) |
| `/api/adaptive/status` | `GET` | Harness status (running, candidates, etc.) | All states |
| `/api/adaptive/monitor` | `GET` | Real-time progress monitor | Only when `running == true` |
| `/api/adaptive/run` | `POST` | Launch adaptive evaluation | Transitions from `idle` → `attacker` |
| `/api/adaptive/stop` | `POST` | Signal running evaluation to stop | Transitions from `attacker` → `completed`/`incomplete` |
| `/api/adaptive/defense_eval` | `POST` | Start defense replay against saved cases | Transitions from `defense_ready` → `defense_running`/`defense_completed` |
| `/api/adaptive/defense_eval/jobs` | `GET` | List defense jobs | Shows job state: queued/running/progress/terminal |
| `/api/adaptive/defense_eval/status` | `GET` | Get defense job status by evaluation_id | Shows detailed state |
| `/api/adaptive/defenses` | `GET` | List selectable defenses | Catalog of defense kinds |
| `/api/connections` | `GET/POST` | Connect/select/clear target connection | Methods: connect, select, clear |

---

## 2. Attacker Strategies and Proposals Panel

This panel displays the adaptive search state: active strategy (the "baseline" or current best candidate), proposal history, and candidate evaluations.

### Data Structure
The `strategy_engine` section of the overview dict contains:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `strategy_engine.active.strategy_id` | `str` | `run_dict.strategy_engine.active.strategy_id` | Current active strategy ID (e.g. `"baseline"`, `"7e6275b0ff5f-best"`) |
| `strategy_engine.active.ladder` | `list[{category, sophistication_level}]` | `run_dict.strategy_engine.active.ladder` | The current best strategy ladder (ordered categories) |
| `strategy_engine.active.evaluation.asr` | `float \| None` | `run_dict.strategy_engine.active.evaluation.asr` | Attack success rate of active strategy; `None` when unmeasured |
| `strategy_engine.active.evaluation.ladder` | `list` | Same as above | Ladder evaluation details |
| `strategy_engine.active.evaluation.utility_score` | `float \| None` | `run_dict.strategy_engine.active.evaluation.utility_score` | Defense utility score; `None` when unmeasured |
| `strategy_engine.active.evaluation.outcomes` | `dict` | `run_dict.strategy_engine.active.evaluation.outcomes` | Outcome counts: `{blocked, success, ignored, technical_fail, inconclusive, unclassified}` |
| `strategy_engine.active.episode_trace` | `list[dict]` | `run_dict.strategy_engine.active.episode_trace` | Per-episode trace with case_id, episode, outcome, defense_decision, rounds_used, steps, observed_outcome, observation, target_identity |
| `strategy_engine.baseline.strategy_id` | `str` | `run_dict.strategy_engine.baseline.strategy_id` | Baseline strategy ID |
| `strategy_engine.baseline.ladder` | `list` | `run_dict.strategy_engine.baseline.ladder` | Baseline ladder |
| `strategy_engine.baseline.evaluation.asr` | `float \| None` | `run_dict.strategy_engine.baseline.evaluation.asr` | Baseline ASR; `None` when unmeasured |
| `strategy_engine.baseline.evaluation.utility_score` | `float \| None` | `run_dict.strategy_engine.baseline.evaluation.utility_score` | Baseline utility; `None` when unmeasured |
| `strategy_engine.baseline.evaluation.outcomes` | `dict` | `run_dict.strategy_engine.baseline.evaluation.outcomes` | Baseline outcome counts |
| `strategy_engine.baseline.episode_trace` | `list` | `run_dict.strategy_engine.baseline.episode_trace` | Baseline per-episode trace |

### Candidate List
The `candidates` array in the overview contains per-candidate summaries:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `candidate_id` | `str` | Candidate record | Unique candidate identifier |
| `ladder` | `list[{category, sophistication_level}]` | Candidate record | Proposed attack strategy ladder |
| `evaluation.asr` | `float \| None` | Candidate evaluation | ASR for this candidate; `None` when unmeasured |
| `evaluation.utility_score` | `float \| None` | Candidate evaluation | Utility score; `None` when unmeasured |
| `evaluation.outcomes` | `dict` | Candidate evaluation | Outcome counts |
| `evaluation.episode_trace` | `list` | Candidate evaluation | Per-episode trace |
| `baseline_asr` | `float \| None` | Candidate record | Baseline ASR referenced by this candidate |
| `status` | `str` | Candidate record | One of: `"active"`, `"promoted"`, `"rejected"`, `"pending"` |
| `gate.passed` | `bool` | Candidate gate result | Whether the promotion gate passed |
| `gate.reasons` | `list[str]` | Candidate gate result | Honest reasons if gate failed (never fabricated) |
| `created_at` | `str` (ISO 8601) | Candidate record | When the candidate was created |
| `asr` | `float \| None` | Top-level candidate field | Convenience alias for `evaluation.asr` |

### States
- **Loading**: Candidate list is fetched via `/api/adaptive/status`; may show skeleton rows.
- **Empty**: No candidates have been evaluated yet (`candidates: []`).
- **Unavailable**: When no run has been started, the strategy engine shows `"baseline"` as active with `asr: 0.0` (deterministic baseline).
- **Partial**: When a run is in progress, the active strategy is updated live but `asr` values remain `None` until evaluation completes.
- **Completed**: All candidates have final `asr` and `utility_score` values; `gate.reasons` are honest and documented.

### API Mapping
| Endpoint | Method | Response Schema Highlights |
|----------|--------|---------------------------|
| `/api/adaptive/status` | `GET` | `status.running`, `status.candidates`, `status.strategy_engine.active`, `status.strategy_engine.baseline` |
| `/api/adaptive/run` | `POST` | Return dict with `run_id`, `status`, `current_run` fields |
| `/api/adaptive/defense_eval` | `POST` | Returns `evaluation_id`, `job_id`, `state`, `selected_case_ids`, `excluded_cases` |

---

## 3. Hill-Climber Iterations and Scores Panel

This panel shows the iteration history, per-iteration ASR/utility progress, and the hill-climbing loop dynamics.

### Iteration History
The `run.history` array contains per-iteration records:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `iteration` | `int` | History entry | Iteration number (1-indexed) |
| `attack_category` | `str` | History entry | The attack category being targeted |
| `candidate_id` | `str` | History entry | The candidate ID evaluated in this iteration |
| `candidate_ladder` | `list[{category, sophistication_level}]` | History entry | The strategy ladder proposed in this iteration |
| `strategy_dimensions` | `list[str]` | History entry | Strategy dimensions exercised in this iteration |
| `asr` | `float \| None` | History entry | Measured ASR for this candidate; `None` when unmeasured |
| `asr_denominator` | `int` | History entry | Number of episodes used to compute ASR |
| `baseline_asr` | `float \| None` | History entry | Baseline ASR at the time of this iteration |
| `improved` | `bool` | History entry | Whether this candidate improved upon the then-active strategy |
| `delta` | `float \| None` | History entry | `candidate_asr - baseline_asr`; `None` when either is `None` |
| `technical_failures` | `int` | History entry | Count of technical failures observed |
| `inconclusive_episodes` | `int` | History entry | Number of episodes with inconclusive outcomes |

### Score Summary
The `strategy_engine` section provides cross-iteration score comparison:

| Metric | Type | Description |
|--------|------|-------------|
| `global_best_category` | `str \| None` | The category with the best observed ASR across all iterations |
| `best_asr` | `float \| None` | The highest ASR ever measured in this run; `None` if never measured |
| `baseline_asr` | `float \| None` | The baseline ASR (from the initial strategy) |
| `improved` | `bool` | Whether any candidate surpassed the baseline ASR |
| `converged` | `bool` | Whether the hill-climber converged (no further improvement possible within budget) |
| `unique_candidates_evaluated` | `int` | Count of distinct candidates evaluated |
| `candidate_evaluations` | `int` | Total candidate evaluations (may count re-evaluations) |
| `episodes_consumed` | `int` | Total episodes consumed across all iterations |
| `total_episode_budget` | `int` | The maximum episode budget for the run |
| `budget_exhausted` | `bool` | Whether the episode budget was fully consumed |

### States
- **Loading**: History is fetched via `/api/adaptive/status`; may show placeholder "—" for missing iteration data.
- **Empty**: `history: []` when no iterations have been completed.
- **Partial**: When a run is in progress, the latest iteration may be incomplete (some episodes still running).
- **Completed**: All iterations have final `asr`, `delta`, `improved` values; `converged` is accurately reported.

### API Mapping
| Endpoint | Method | Response |
|----------|--------|----------|
| `/api/adaptive/status` | `GET` | `run.history`, `strategy_engine`, `candidates` |
| `/api/overview` | `GET` | Full overview with `strategy_engine` and `run` data |

---

## 4. Feedback and Lineage Panel

This panel shows the feedback store, cross-run isolation, and strategy lineage across iterations.

### Feedback Store
The feedback is stored in `results/adaptive_*.json.feedback.json` files. Key fields:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `run_id` | `str` | Feedback file | Unique run identifier (e.g. `"7e6275b0ff5f"`) |
| `origin` | `str` | Feedback file | `"fresh:new-store"` or `"feedback:previous-run"` |
| `config.mode` | `str` | Feedback file | `"greedy"` or `"feedback"` |
| `config.episodes` | `int` | Feedback file | Number of episodes per candidate |
| `config.iterations` | `int` | Feedback file | Number of adaptive iterations |
| `config.defense` | `str` | Feedback file | Defense kind used (e.g. `"marker"`) |
| `totals.episodes_decided` | `int` | Feedback file | Count of episodes where a decision (allowed/blocked) was made |
| `totals.known_decisions` | `int` | Feedback file | Episodes with a confirmed decision |
| `totals.successes` | `int` | Feedback file | Count of `success` outcomes |
| `totals.blocked` | `int` | Feedback file | Count of `blocked` outcomes |
| `totals.ignored` | `int` | Feedback file | Count of `ignored` outcomes |
| `totals.technical_fail` | `int` | Feedback file | Count of technical failures |
| `totals.unknown` | `int` | Feedback file | Unknown outcomes |
| `totals.unusable_evaluations` | `int` | Feedback file | Evaluations that could not produce a favorable signal |
| `steps_tracked` | `int` | Feedback file | Number of feedback store steps tracked |
| `candidates_recorded` | `int` | Feedback file | Number of candidates evaluated |
| `selections_recorded` | `int` | Feedback file | Number of selections made |
| `resets` | `list` | Feedback file | List of store resets (config fingerprints that triggered a reset) |
| `alpha` | `float` | Feedback store parameter | Temperature/ranking parameter |
| `model_suggestion_records` | `int` | Feedback file | Number of model suggestion records stored |

### Cross-Run Isolation
- Each run's feedback store is independent (`test_phase4_feedback.py::test_independent_runs_never_share_feedback_state` passes).
- A new/changed config fingerprint starts from a clean store (`test_phase4_feedback.py::test_baseline_is_unchanged_when_the_adaptive_mode_is_disabled` passes).

### Strategy Lineage
Lineage is tracked through the run records:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `history[i].iteration` | `int` | Run history | Iteration number |
| `history[i].candidate_id` | `str` | Run history | Candidate evaluated in this iteration |
| `history[i].parent_category_best_asr` | `float \| None` | Run history | Best ASR from parent iteration |
| `history[i].delta` | `float \| None` | Run history | `candidate_asr - parent_best_asr`; `None` when unknown |
| `model_suggestions` | `list` | Run record | Each suggestion record includes: request shape, accepted/rejected tag, reason, measured outcome (once evaluated) |
| `candidate_id` (top-level) | `str` | Run record | The currently active candidate ID |
| `iteration` (top-level) | `int` | Run record | Current iteration number |
| `iterations_completed` | `int` | Run record | How many iterations completed |
| `budget_exhausted` | `bool` | Run record | Whether budget was exhausted |
| `final_evaluation_reused` | `bool` | Run record | Whether a final evaluation was reused from a checkpoint |

### States
- **Loading**: Feedback data is fetched from the persisted `.feedback.json` file; may show "No feedback data" when no run has completed.
- **Empty**: When no run has been started, all feedback totals are `0` and `candidates_recorded: 0`.
- **Partial**: When a run is in progress, `steps_tracked` reflects live progress; `candidates_recorded` may be incomplete.
- **Completed**: All feedback totals are final; `alpha` value is stable; `resets` count reflects any config changes that triggered store resets.

### API Mapping
| Endpoint | Method | Notes |
|----------|--------|-------|
| `/api/overview` | `GET` | Includes `feedback`-derived data in `metrics` and `activity` sections |
| `/api/adaptive/defense_eval` | `POST` | May reference saved cases from the feedback store's eligible candidates |

---

## 5. Defense Evaluation Panel

This panel shows defense evaluation state, per-case outcomes, and aggregate metrics. Defense is independent from the attacker lifecycle.

### Defense Job Lifecycle
Defense evaluations are started explicitly via `/api/adaptive/defense_eval`. They do NOT auto-start on attacker campaign completion.

| State | Description |
|-------|-------------|
| `queued` | Defense job has been submitted; not yet started |
| `running` | Defense replay is in progress |
| `progress` | Worker is reporting progress (phase, cases_total) |
| `terminal` | Defense evaluation completed (success/failure/unavailable) |

### Per-Case Outcomes (Four-State Contract)
Each episode is classified as one of:
- `allowed` — the defense permitted the attack
- `blocked` — the defense stopped the attack
- `inconclusive` — insufficient evidence to classify
- `error` — a technical failure occurred

### Defense Evaluation Record
When a defense evaluation completes, the following data is persisted:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `evaluation_id` | `str` | Defense job output | Unique evaluation identifier |
| `job_id` | `str` | Defense job output | Job identifier (may be same as evaluation_id) |
| `state` | `str` | Defense job output | One of: `"completed_with_evidence"`, `"inconclusive"`, `"unavailable"`, `"technical_failure"` |
| `against` | `str` | Defense payload | The defense kind being replayed (e.g. `"marker"`) |
| `source_run_id` | `str` | Defense payload | The attacker run ID this defense evaluates against |
| `case_ids` | `list[str]` | Defense payload | The saved case IDs selected for replay |
| `selected_cases` | `list[dict]` | Defense eligibility | The actual cases selected, each with `case_id`, `bucket`, `usable` |
| `excluded_cases` | `list[dict]` | Defense eligibility | Cases that were eligible but not selected |
| `eligibility` | `dict` | Defense eligibility check | `{"eligible": bool, "reason": str, "cases": list, "source_run_id": str}` |
| `result.verdict` | `str` | Evaluation result | The final verdict (e.g. `"confirmed_blocked"`, `"unavailable"`) |
| `result.unavailable` | `bool` | Evaluation result | True when evaluation could not replay anything |
| `result.episodes_evaluated` | `int` | Evaluation result | Number of cases actually evaluated |
| `result.states.confirmed_success` | `int` | Evaluation result | Count of episodes classified as `success` |
| `result.states.confirmed_blocked` | `int` | Evaluation result | Count of episodes classified as `blocked` |
| `activity entries` | `list[dict]` | `build_overview()` | Defense events added to the overview activity feed |

### Eligibility
A defense evaluation is only eligible when:
1. A completed attacker run exists (`run.status == "completed"`)
2. The run has eligible saved cases (cases with `bucket == "success"` and `usable == true`)
3. The candidate ID matches the run's candidate ID

If not eligible, the API returns `409` with `error` explaining the reason (e.g. `"run not eligible for defense evaluation: no eligible saved cases"`).

### States
- **Loading**: Defense job status is fetched via `/api/defense_jobs` or `/api/defense_job_status`; shows "Starting defense..." until the worker reports progress.
- **Empty**: When no defense evaluation has ever been started; `defense.evaluations: []`.
- **Unavailable**: When the attacker run is not completed, or the run has no eligible cases. The dashboard shows `phase: "defense_unavailable"` and `eligibility: {"eligible": false, "reason": "..."}`.
- **Partial**: During replay, the activity feed shows progress events; `result.states` may be partially populated.
- **Completed**: Defense evaluation finished with `state: "completed_with_evidence"` and `result.states.confirmed_blocked`/`confirmed_success` populated.

### API Mapping
| Endpoint | Method | Response Highlights |
|----------|--------|---------------------|
| `/api/adaptive/defense_eval` | `POST` | `202` with `evaluation_id`, `job_id`, `state`, `selected_case_ids`, `excluded_cases` (when `sync: false`); inline result when `sync: true` |
| `/api/adaptive/defense_eval/jobs` | `GET` | `{"jobs": [job_summary]}` — list of defense jobs with state |
| `/api/adaptive/defense_eval/status` | `GET` | `{"job": detailed_job_state}` — status by evaluation_id |
| `/api/adaptive/defenses` | `GET` | `{"defenses": [defense_kind, ...]}` — list of selectable defense names |
| `/api/overview` | `GET` | `defense.catalog`, `defense.evaluations`, `defense.latest`, `defense.state`, `defense.eligible_cases` |

---

## 6. ASR and Blast Radius Panel

This panel displays the security metrics: Attack Success Rate (ASR), blast radius, and utility. All metrics follow the `float \| None` contract — unknown values are `None`, never `0.0`.

### ASR (Attack Success Rate)
- **Formula**: `ASR = successes / asr_denominator`, where `successes` is the count of episodes with `outcome == "success"` and `asr_denominator` is the number of eligible episodes.
- **Eligible observation population**: Episodes where the outcome is measurable and not filtered out as technical failure or ignored.
- **Actual source records**: Derived from `run.candidates[].evaluation.episode_trace` and `run.strategy_engine.active.evaluation.outcomes`.
- **Missing-data behavior**: `None` when no eligible episodes exist (denominator is 0); never fabricated as `0.0`.
- **Example from persisted data**: In `results/adaptive_iter2_fresh.json`, `global_best_category: null`, `best_asr: null`, `baseline_asr: null` — all ASR values are `None` because only 2 episodes were evaluated (below `MIN_EPISODES_FOR_PROMOTION = 3`).

### Blast Radius
- **Formula**: Count of episodes with confirmed security outcomes (success + blocked) divided by total evaluated episodes, or a count of unique affected dimensions.
- **Eligible observation population**: All episodes that received a confirmed decision (allowed/blocked), excluding inconclusive/technical_fail/unknown.
- **Actual source records**: `run.strategy_engine.active.evaluation.outcomes`, per-candidate `evaluation.outcomes`, dimension breakdown `_dimension_breakdown()`.
- **Missing-data behavior**: `None` when no blast radius can be computed; the dashboard shows `"no data"` rather than zeros.
- **Example**: `_dimension_breakdown(history)` returns `[{id, name, count, share: float\|None, denominator: int}]` — when `total` is 0, `share` is `None`.

### Utility
- **Formula**: Measured from benign probe tool calls in the target execution. Reported as `float \| None`.
- **Eligible observation population**: Benign tool calls that successfully execute without error or authorization denial.
- **Actual source records**: `run.strategy_engine.active.evaluation.utility_score`, candidate evaluation records.
- **Missing-data behavior**: `None` when utility cannot be measured (e.g. too few episodes, all technical failures).
- **Example from persisted data**: `utility_floor: 0.9` (the minimum acceptable utility), `utility_score: 1.0` (baseline baseline utility).

### Metrics Payload (from `build_overview()`)
The overview `metrics` dict contains:

```json
{
  "candidates_evaluated": int \| null,
  "episodes_consumed": int \| null,
  "episode_budget": int \| null,
  "success": float \| None,     // from final evaluation
  "blocked": float \| None,     // from final evaluation (plus inconclusive)
  "ignored": float \| None,     // from final evaluation
  "technical_fail": float \| None, // from final evaluation
  "inconclusive": float \| None, // from final evaluation (plus ignored)
  "unclassified": float \| None, // from final evaluation
  "episodes_measured": int \| None, // from final evaluation
  "asr": float \| None,         // best ASR from run or candidate
  "baseline_asr": float \| None, // baseline ASR
  "source": "in flight: outcome counts are published when the run terminates" // when running
  // or null when no run
}
```

### States
- **Loading**: Metrics are fetched via `/api/overview`; may show skeleton numbers.
- **Empty**: When no run has started: all metric values are `None`; the dashboard shows `"unavailable"`.
- **Unavailable**: When `lifecycle.phase == "defense_unavailable"` or no completed run exists.
- **Partial**: When a run is in progress: live counters from current run, but `asr` and `utility` are `None` until termination.
- **Completed**: All metrics have final `float \| None` values; `source` explains whether values are from the final evaluation or are unavailable.

### API Mapping
| Endpoint | Method | Key Response Fields |
|----------|--------|--------------------|
| `/api/overview` | `GET` | Full `metrics` dict (see above) |
| `/api/adaptive/status` | `GET` | `best_asr`, `baseline_asr`, `episodes_consumed`, `total_episode_budget` |
| `/api/adaptive/run` | `POST` | Return dict with `best_asr`, `baseline_asr`, `episodes_consumed` |

---

## 7. BYOA Execution Panel

This panel shows the Bring-Your-Own-Agent execution details, including target kind, execution mode, and evidence channels.

### Target Configuration
The currently active target is displayed in the overview `settings` and `run.target_identity`:

| Field | Type | Source | Example Value |
|-------|------|--------|---------------|
| `target_kind` | `str` | `status.get("target_kind")` | `"remote"`, `"http_api"`, `"user_byoa"` |
| `target_identity.target_id` | `str` | `run.target_identity.target_id` | `"http-api-target"` |
| `target_identity.name` | `str` | `run.target_identity.name` | `"HTTP API agent"` |
| `target_identity.description` | `str` | `run.target_identity.description` | `"External AI agent at http://127.0.0.1:11643/execute"` |
| `target_identity.execution_mode` | `str` | `run.target_identity.execution_mode` | `"remote"`, `"real"`, `"fixture"` |
| `target_identity.timeout_seconds` | `float` | `run.target_identity.timeout_seconds` | `15.0` |
| `target_identity.capabilities` | `list[str]` | `run.target_identity.capabilities` | `["evidence_collection", "tool_calling", ...]` |
| `target_identity.adapter_version` | `str` | `run.target_identity.adapter_version` | `"built-in"` |
| `target_identity.contract_version` | `str` | `run.target_identity.contract_version` | `"1.0"` |

### Execution Mode Distinctions
- `execution_mode == "real"`: Genuine Python target code executes (reports `execution_mode='real'` in `boya_target_module.py`). Evidence channels (`tool_invocations`, `authorization_decisions`, `state_observations`, `ground_truth`) are truthfully reported.
- `execution_mode == "fixture"`: `LocalFixtureTargetAdapter` reports `execution_mode='fixture'` — never `real`. Synthetic data only.
- `execution_mode == "remote"`: `ExternalHttpTargetAdapter` sends requests to a JSON HTTP endpoint; execution happens outside the process.

### Evidence Channels (from BYOA target module)
When a target executes with `execution_mode == "real"`:
- `tool_invocations`: `True` when tool calls are made (boolean, never fabricated)
- `authorization_decisions`: `True` when an authorization decision exists (boolean)
- `state_observations`: `True` when synthetic state changes are observed (always `True` when observable; `None` when unknown, never `0.0` or `False`)
- `ground_truth`: `None` when unknown, never fabricated as `False` or `0.0`

### States
- **Loading**: Target identity is fetched via `/api/adaptive/status` or `/api/overview`; may show "Connecting target...".
- **Empty**: When no connection has been established; `target_kind: null`, `execution_mode: null`.
- **Unavailable**: When `target_kind == "user_byoa"` and the harness `start()` raises `ValueError` (ADR-022 blockade). The dashboard shows an error banner: `"Local Python Agent targets are retired; expose the agent behind a JSON HTTP endpoint and use the HTTP API method"`.
- **Partial**: When a run is in progress, the target identity is live but may be the seeded stand-in if no active connection exists.
- **Completed**: Target identity is finalized; `execution_mode` is recorded in the run manifest; adapter version and contract version are persisted.

### API Mapping
| Endpoint | Method | Response |
|----------|--------|----------|
| `/api/adaptive/status` | `GET` | `target`, `target_kind`, `target_identity` |
| `/api/connections` | `GET/POST` | Connect, select, clear a target method; records probe outcomes |
| `/api/targets` | `GET` | List of supported target declarations from the adapter registry |
| `/api/overview` | `GET` | `settings.target`, `settings.target_kind`, `run.target_identity` |

---

## 8. Experiment History Panel

This panel records the full experiment configuration and outcomes across runs, enabling reproducibility and comparison.

### Run Records
The `reports.runs` array in the overview contains the last 10 completed runs:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `run_id` | `str` | Run record | Unique identifier (UUID-like string) |
| `status` | `str` | Run record | `"completed"`, `"incomplete"`, `"running"`, `"stopped"` |
| `started_at` | `str` (ISO 8601) | Run record | When the run started |
| `finished_at` | `str` (ISO 8601) | Run record | When the run finished ( `null` when still running) |
| `mode` | `str` | Run record | `"greedy"` or `"feedback"` |
| `defense` | `str \| None` | Run record | Defense kind used (e.g. `"marker"`, `null` when none) |
| `target` | `str` | Run record | Target ID (e.g. `"http-api-target"`) |
| `target_kind` | `str` | Run record | `"remote"`, `"http_api"`, etc. |
| `best_asr` | `float \| None` | Run record | Best ASR measured in this run; `None` when unmeasured |
| `baseline_asr` | `float \| None` | Run record | Baseline ASR |
| `episodes_consumed` | `int` | Run record | Total episodes consumed |
| `total_episode_budget` | `int` | Run record | Maximum episode budget |
| `candidate_id` | `str \| None` | Run record | The candidate ID that produced the best result |
| `improved` | `bool` | Run record | Whether the run improved upon the previous best |
| `converged` | `bool` | Run record | Whether the hill-climber converged |
| `global_best_category` | `str \| None` | Run record | The category with the best ASR |
| `assistant` | `str` | Run record | Assistant provider kind (`"fake"`, `"ollama"`, etc.) |

### Experiment Configuration
Each run record stores the configuration that was used:

| Field | Type | Source | Description |
|-------|------|--------|-------------|
| `episodes` | `int` | Run record | Episodes per candidate |
| `max_rounds` | `int` | Run record | Maximum rounds per iteration |
| `iterations` | `int` | Run record | Number of adaptive iterations |
| `seed` | `int \| null` | Run record | Random seed (may be `null`) |
| `selection_budget` | `int` | Run record | Neighbours evaluated per iteration (feedback mode) |
| `total_episode_budget` | `int \| null` | Run record | Total episode budget across all candidates |
| `provider` | `str \| null` | Run record | Assistant provider name (may be `null`) |
| `model_request_budget` | `int \| null` | Run record | Model request budget limit |
| `attack_categories` | `list[str]` | Run record | Selected attack categories |
| `defense` | `str \| null` | Run record | Defense kind (may be `null`) |

### States
- **Loading**: Experiment history is fetched via `/api/overview`; shows skeleton table.
- **Empty**: No runs have been started; `reports.runs: []`.
- **Partial**: When a run is in progress, it appears in `reports.runs` with `status: "running"` and `finished_at: null`.
- **Completed**: All runs have final status, metrics, and configuration persisted; `reports.checkpoint` indicates whether a checkpoint is available.

### API Mapping
| Endpoint | Method | Response |
|----------|--------|----------|
| `/api/overview` | `GET` | `reports.runs` (last 10), `reports.checkpoint` |
| `/api/adaptive/status` | `GET` | Current run state (active_run, running) |
| `/api/adaptive/defense_eval` | `POST` | May reference a `run_id` from the experiment history |

---

## Summary of States Across all Panels

| State Key | Empty | Loading | Partial | Unavailable | Completed |
|-----------|-------|---------|---------|-------------|-----------|
| `lifecycle.running` | `false` | `true/false` (detecting) | `true` (in progress) | `false` (not eligible) | `false` (finished) |
| `lifecycle.phase` | `"idle"` | `"attacker"` / `"defense_ready"` | `"attacker"` | `"defense_unavailable"` | `"defense_completed"` / `"idle"` |
| All metric `float` values | `None` | `None` (in flight) | `None` (in flight) | `None` / error reason | Final `float \| None` |
| `candidates` | `[]` | Live updates | Live updates (may be incomplete) | `[]` / ineligibility reason | Final candidates with evaluations |
| `history` | `[]` | Live iteration may be incomplete | Incomplete (latest iteration still running) | `[]` | Full iteration history |
| `defense.evaluations` | `[]` | No defense started | Progress events appearing | `[]` (eligibility blocked) | `[{verdict, result}]` |
| `activity` | `[]` | Live events appended | Progress events | `[]` | Full activity feed |

---

## Evidence Integrity Rules (Frontend Guidelines)

1. **Never fabricate `0.0` or `false` for unknown metrics**: If a value is `None`/`null` in the persisted data, the frontend must display `"unavailable"` or `"—"`, never dress up a zero as a measurement.

2. **ASR denominator must match episode count**: The `asr_denominator` field must equal the number of episodes actually used to compute ASR. If `asr_denominator == 0`, ASR must be `None`.

3. **Defense eligibility is gated**: The defense panel must not show "Run defense" button when `lifecycle.phase != "defense_ready"` or `eligibility.eligible == false`. The button label should change to `"Defense unavailable: <reason>"`.

4. **Strategy lineage is parent-child**: When displaying iteration history, always show `history[i].parent_category_best_asr` and `history[i].delta` — these are the canonical evidence of how iteration feedback influenced the next strategy.

5. **BYOA execution_mode is authoritative**: The `target_identity.execution_mode` field is the source of truth for whether the target executed as `real`, `fixture`, or `remote`. Do not infer from candidate IDs or parent references.

6. **Feedback from iteration 1 must appear in iteration 2's Ollama context**: When showing the two-linked adaptive iteration, the system must display the exact iteration 1 feedback (ASR delta, outcomes) that was passed to the second Ollama request. If the feedback is missing, report `"feedback not passed to iteration 2"` rather than hiding the gap.

7. **Error states are honest**: When an API returns an error (4xx/5xx), the frontend must display the exact error message returned by the server, never a generic "something went wrong" mask.

8. **Checkpoint availability is separate from run status**: `reports.checkpoint.available` can be `true` even when `run.status == "incomplete"`, and vice versa. The frontend must show both independently.

9. **Empty states show "no data", never zeros**: When a count or metric is `0` because no data exists (not because the value was measured as zero), the dashboard must show `"no data"` or `"—"`, not `0`.

10. **Per-case defense outcomes follow the four-state contract**: Each episode's defense verdict must be one of `allowed`, `blocked`, `inconclusive`, `error`. Never display a fifth state or mix in unrelated classifications.

---