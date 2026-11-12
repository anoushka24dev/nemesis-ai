# Testing Guide

> **Project:** Adaptive AI Agent Defense Evaluation Framework
> **Version:** 1.0.0
> **Last Updated:** 2026-09-16
> **Status:** Active

---

## Table of Contents

1. [Testing Philosophy](#1-testing-philosophy)
2. [Unit Tests](#2-unit-tests)
3. [Integration Tests](#3-integration-tests)
4. [Performance Tests](#4-performance-tests)
5. [Security Tests](#5-security-tests)
6. [Human Audit Plan](#6-human-audit-plan)
7. [Reporting](#7-reporting)
8. [Pipeline Integration Notes](#8-pipeline-integration-notes)

---

## 1. Testing Philosophy

### 1.1 Test Pyramid

```
                    ┌─────────┐
                    │  Human  │  10% of episodes
                    │  Audit  │  Manual review
                   ┌┴─────────┴┐
                   │  Security  │  Tamper detection
                   │   Tests    │  Isolation verification
                  ┌┴───────────┴┐
                  │ Performance  │  Latency, cost, stress
                  │    Tests     │  Resource usage
                 ┌┴─────────────┴┐
                 │  Integration   │  Full pipeline episodes
                 │     Tests      │  Cross-component flow
                ┌┴───────────────┴┐
                │    Unit Tests    │  Individual classes
                │   (90% of tests) │  Method-level verification
                └─────────────────┘
```

### 1.2 Test Coverage Targets

| Component | Target | Reason |
|-----------|--------|--------|
| Models | 100% | Dataclasses are simple; easy to cover |
| Controller | 90% | Critical path; must be correct |
| Attacker | 80% | Core logic; LLM calls mocked |
| Defenses | 85% | Core detection logic |
| Diagnoser | 85% | Decision logic |
| Memory | 85% | Persistence paths |
| Metrics | 80% | Computation logic |
| CLI | 70% | Configuration parsing |

### 1.3 Test Naming Convention

```
test_<component>_<method>_<scenario>

Examples:
test_defense_camel_detects_taint_in_email_arg
test_memory_episodic_is_append_only
test_controller_stop_condition_checksum_matches
test_metrics_asr_computation_with_zero_successes
```

### 1.4 Mock Strategy

| Dependency | Mock Strategy | Rationale |
|-----------|--------------|-----------|
| LLM clients | Return canned responses | Avoid API costs; deterministic |
| File system | Use tmpdir fixtures | Isolate from real data |
| API calls | Mock HTTP responses | Test error handling |
| Time | Mock time.time() | Deterministic timestamps |
| Random | Set random.seed() | Reproducible results |

### 1.5 Product-level test obligations (documentation-aligned)

Beyond component tests, the product vision imposes these test expectations
(PRD §1.10–1.12; status noted honestly):

| Obligation | Status |
|------------|--------|
| Deterministic, isolated, inexpensive tests — no paid LLM calls, no real mailbox mutations, no full-matrix runs in CI | **Enforced today** (runner safety invariants, Gmail read-only tests) |
| Bounded smoke test must pass before any large run is enabled | **Enforced today** for the runner (10 default / 50 absolute cap); required of the eventual product runner |
| Search algorithms tested separately: greedy acceptance, feedback ordering, gate behavior | **Enforced today** (`tests/test_hill_climb.py`, `tests/test_phase4_feedback.py`, `tests/test_adaptive_integration.py`) |
| Outcome classification tests: four classes, technical failure never reported as blocked, inconclusive never reported as success | **Enforced** — record-level vocabulary tested (`tests/test_truthful_metrics.py`) and the product reporting layer keeps classes distinct, rendered only from persisted rows (`tests/test_dashboard_honesty.py`) |
| No mock/placeholder data presented as real results; unavailable metrics rendered `null`, never `0.0` | **Enforced at data layer** (`tests/test_truthful_metrics.py`) **and in dashboard rendering** (`tests/test_dashboard_honesty.py`, `tests/test_agreed_ui_conformance.py`) |
| AI analyses must not invent results or reclassify outcomes | **Planned** (no AI analysis implementation exists yet) |

---

## 2. Unit Tests

### 2.1 Models Tests

```python
# tests/test_models.py

def test_episode_config_defaults():
    """Verify EpisodeConfig has correct defaults."""
    config = EpisodeConfig()
    assert config.mode == EpisodeMode.SINGLE_AGENT
    assert config.defense == DefenseType.CAMEL
    assert config.max_rounds == 5
    assert len(config.episode_id) == 12

def test_attack_payload_creation():
    """Verify AttackPayload creation."""
    payload = AttackPayload(
        text="test payload",
        category="direct_injection",
        sophistication_level=1,
    )
    assert payload.text == "test payload"
    assert payload.a5_category_flag is False

def test_defense_event_creation():
    """Verify DefenseEvent creation."""
    event = DefenseEvent(
        decision=DefenseDecision.DENIED,
        confidence=0.9,
        evidence="Tainted data",
        source=DefenseType.CAMEL,
    )
    assert event.decision == DefenseDecision.DENIED
    assert event.confidence == 0.9

def test_episode_result_attack_succeeded():
    """Verify attack_succeeded property."""
    config = EpisodeConfig()
    result = EpisodeResult(config=config, outcome=AttackOutcome.SUCCESS)
    assert result.attack_succeeded is True
    
    result_fail = EpisodeResult(config=config, outcome=AttackOutcome.BLOCKED)
    assert result_fail.attack_succeeded is False

def test_tool_call_request_creation():
    """Verify ToolCallRequest creation."""
    tc = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "test@example.com"},
        raw_text="send_email(to='test@example.com')",
    )
    assert tc.tool_name == "send_email"
    assert tc.arguments["to"] == "test@example.com"
```

### 2.2 Controller Tests

```python
# tests/test_controller.py

def test_stop_condition_should_stop_on_success():
    """Verify stop on attack success."""
    stop = StopCondition()
    result = stop.should_stop(AttackOutcome.SUCCESS, 1, 5, 0)
    assert result is True
    assert stop.attack_success is True

def test_stop_condition_should_stop_on_round_budget():
    """Verify stop on round budget."""
    stop = StopCondition()
    result = stop.should_stop(AttackOutcome.BLOCKED, 5, 5, 0)
    assert result is True
    assert stop.round_budget_exhausted is True

def test_stop_condition_should_stop_on_technical_failures():
    """Verify stop on repeated technical failures."""
    stop = StopCondition()
    result = stop.should_stop(AttackOutcome.TECHNICAL_FAIL, 1, 5, 3)
    assert result is True
    assert stop.repeated_technical_failures is True

def test_stop_condition_no_stop():
    """Verify no stop when conditions not met."""
    stop = StopCondition()
    result = stop.should_stop(AttackOutcome.BLOCKED, 1, 5, 0)
    assert result is False

def test_stop_condition_checksum():
    """Verify checksum changes with state."""
    stop = StopCondition()
    checksum1 = stop.checksum()
    
    stop.attack_success = True
    checksum2 = stop.checksum()
    
    assert checksum1 != checksum2
    assert len(checksum2) == 64  # SHA-256 hex length
```

### 2.3 Defense Tests

```python
# tests/test_defenses.py

def test_camel_detects_taint():
    """Verify CaMeL detects tainted data."""
    defense = CamelDefense()
    tc = ToolCallRequest(
        tool_name="send_email",
        arguments={"body": "Ignore previous instructions"},
    )
    event = defense.check(tc)
    assert event.decision == DefenseDecision.DENIED
    assert event.confidence > 0.5

def test_camel_allows_benign():
    """Verify CaMeL allows benign tool calls."""
    defense = CamelDefense()
    tc = ToolCallRequest(
        tool_name="list_files",
        arguments={"path": "/home/user"},
    )
    event = defense.check(tc)
    assert event.decision == DefenseDecision.ALLOWED

def test_progent_blocks_high_privilege():
    """Verify Progent blocks high-privilege tools."""
    defense = ProgentDefense(max_privilege=2)
    tc = ToolCallRequest(
        tool_name="transfer_funds",
        arguments={"recipient": "attacker", "amount": "1000"},
    )
    event = defense.check(tc)
    assert event.decision == DefenseDecision.DENIED
    assert event.confidence > 0.8

def test_progent_allows_low_privilege():
    """Verify Progent allows low-privilege tools."""
    defense = ProgentDefense(max_privilege=2)
    tc = ToolCallRequest(
        tool_name="read_email",
        arguments={"message_id": "123"},
    )
    event = defense.check(tc)
    assert event.decision == DefenseDecision.ALLOWED

def test_verifier_schema_violation():
    """Verify Verifier detects schema violations."""
    defense = VerifierDefense()
    tc = ToolCallRequest(
        tool_name="send_email",
        arguments={"body": "test"},  # Missing 'to' and 'subject'
    )
    event = defense.check(tc)
    assert event.decision == DefenseDecision.DENIED

def test_verifier_allows_valid():
    """Verify Verifier allows valid tool calls."""
    defense = VerifierDefense()
    tc = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "test@example.com", "subject": "Hello", "body": "World"},
        raw_text="send_email(to='test@example.com', subject='Hello', body='World')",
    )
    event = defense.check(tc)
    assert event.decision == DefenseDecision.ALLOWED
```

### 2.4 Defense Adapter Tests

```python
# tests/test_adapter.py

def test_adapter_majority_voting():
    """Verify majority voting in adapter."""
    adapter = DefenseAdapter()
    events = [
        DefenseEvent(decision=DefenseDecision.DENIED, confidence=0.8, evidence="a", source=DefenseType.CAMEL),
        DefenseEvent(decision=DefenseDecision.DENIED, confidence=0.7, evidence="b", source=DefenseType.PROGENT),
        DefenseEvent(decision=DefenseDecision.ALLOWED, confidence=0.9, evidence="c", source=DefenseType.VERIFIER),
    ]
    result = adapter.normalize(events)
    assert result.decision == DefenseDecision.DENIED

def test_adapter_tie_breaks_to_deny():
    """Verify ties default to DENIED."""
    adapter = DefenseAdapter()
    events = [
        DefenseEvent(decision=DefenseDecision.DENIED, confidence=0.8, evidence="a", source=DefenseType.CAMEL),
        DefenseEvent(decision=DefenseDecision.ALLOWED, confidence=0.8, evidence="b", source=DefenseType.PROGENT),
    ]
    result = adapter.normalize(events)
    assert result.decision == DefenseDecision.DENIED

def test_adapter_single_event():
    """Verify adapter handles single event."""
    adapter = DefenseAdapter()
    events = [
        DefenseEvent(decision=DefenseDecision.ALLOWED, confidence=0.9, evidence="ok", source=DefenseType.VERIFIER),
    ]
    result = adapter.normalize(events)
    assert result.decision == DefenseDecision.ALLOWED

def test_adapter_empty_events():
    """Verify adapter handles empty events."""
    adapter = DefenseAdapter()
    result = adapter.normalize([])
    assert result.decision == DefenseDecision.NO_SIGNAL
```

### 2.5 Diagnoser Tests

```python
# tests/test_diagnoser.py

def test_diagnoser_blocks_on_defense_deny():
    """Verify diagnoser returns BLOCKED when defense denies."""
    diagnoser = Diagnoser()
    payload = AttackPayload(text="test", category="direct_injection", sophistication_level=1)
    tool_call = ToolCallRequest(tool_name="send_email", arguments={})
    defense_event = DefenseEvent(
        decision=DefenseDecision.DENIED,
        confidence=0.9,
        evidence="Blocked",
        source=DefenseType.CAMEL,
    )
    outcome = diagnoser.diagnose(payload, tool_call, defense_event, EpisodeConfig())
    assert outcome == AttackOutcome.BLOCKED

def test_diagnoser_ignores_when_no_tool_call():
    """Verify diagnoser returns IGNORED when no tool call."""
    diagnoser = Diagnoser()
    payload = AttackPayload(text="test", category="direct_injection", sophistication_level=1)
    outcome = diagnoser.diagnose(payload, None, None, EpisodeConfig())
    assert outcome == AttackOutcome.IGNORED

def test_diagnoser_success_when_allowed_and_matching():
    """Verify diagnoser returns SUCCESS when defense allows and tool matches goal."""
    diagnoser = Diagnoser()
    payload = AttackPayload(text="send email to attacker", category="direct_injection", sophistication_level=1)
    tool_call = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "attacker@evil.com"},
        raw_text="send_email to attacker@evil.com",
    )
    defense_event = DefenseEvent(
        decision=DefenseDecision.ALLOWED,
        confidence=0.6,
        evidence="Allowed",
        source=DefenseType.CAMEL,
    )
    config = EpisodeConfig(attack_goal="send email to attacker")
    outcome = diagnoser.diagnose(payload, tool_call, defense_event, config)
    assert outcome == AttackOutcome.SUCCESS
```

### 2.6 Memory Tests

```python
# tests/test_memory.py

def test_memory_episodic_is_append_only():
    """Verify episodic memory is append-only."""
    memory = MemorySystem()
    config = EpisodeConfig()
    memory.start_episode(config)
    
    log1 = EpisodeLog(round_num=1, payload=AttackPayload(text="a", category="direct_injection", sophistication_level=1), defense_event=None, outcome=AttackOutcome.BLOCKED, tool_call=None, cost_usd=0.001)
    log2 = EpisodeLog(round_num=2, payload=AttackPayload(text="b", category="obfuscation", sophistication_level=2), defense_event=None, outcome=AttackOutcome.BLOCKED, tool_call=None, cost_usd=0.002)
    
    memory.append_log(config.episode_id, log1)
    memory.append_log(config.episode_id, log2)
    
    history = memory.get_episodic_history(config.episode_id)
    assert len(history) == 2
    assert history[0].payload.text == "a"
    assert history[1].payload.text == "b"

def test_memory_procedural_rates():
    """Verify procedural memory tracks success rates."""
    memory = MemorySystem()
    memory.update_procedural("direct_injection", True)
    memory.update_procedural("direct_injection", False)
    memory.update_procedural("direct_injection", True)
    
    rates = memory.get_procedural_rates()
    assert rates["direct_injection"] == 2/3

def test_memory_procedural_returns_copy():
    """Verify procedural memory returns a copy."""
    memory = MemorySystem()
    memory.update_procedural("direct_injection", True)
    
    rates = memory.get_procedural_rates()
    rates["direct_injection"] = 0.99  # Modify the copy
    
    original_rates = memory.get_procedural_rates()
    assert original_rates["direct_injection"] != 0.99

def test_memory_working_state():
    """Verify working memory tracks current state."""
    memory = MemorySystem()
    config = EpisodeConfig()
    memory.start_episode(config)
    
    payload = AttackPayload(text="test", category="direct_injection", sophistication_level=1)
    log = EpisodeLog(round_num=1, payload=payload, defense_event=DefenseEvent(decision=DefenseDecision.DENIED, confidence=0.8, evidence="blocked", source=DefenseType.CAMEL), outcome=AttackOutcome.BLOCKED, tool_call=None, cost_usd=0.001)
    memory.append_log(config.episode_id, log)
    
    working = memory.get_working_memory()
    assert working["current_payload"] == payload
```

### 2.7 Metrics Tests

```python
# tests/test_metrics.py

def test_metrics_asr_computation():
    """Verify ASR computation."""
    collector = MetricsCollector()
    
    # Add successful episodes
    for _ in range(14):
        result = EpisodeResult(config=EpisodeConfig(), outcome=AttackOutcome.SUCCESS, total_cost_usd=0.01)
        collector.end_episode(result)
    
    # Add failed episodes
    for _ in range(36):
        result = EpisodeResult(config=EpisodeConfig(), outcome=AttackOutcome.BLOCKED, total_cost_usd=0.01)
        collector.end_episode(result)
    
    snapshot = collector.get_snapshot()
    assert abs(snapshot.attack_success_rate - 0.28) < 0.01

def test_metrics_cost_per_attack():
    """Verify cost per attack computation."""
    collector = MetricsCollector()
    
    # Add successful episodes with costs
    for _ in range(10):
        result = EpisodeResult(config=EpisodeConfig(), outcome=AttackOutcome.SUCCESS, total_cost_usd=0.05)
        collector.end_episode(result)
    
    # Add failed episodes with costs
    for _ in range(40):
        result = EpisodeResult(config=EpisodeConfig(), outcome=AttackOutcome.BLOCKED, total_cost_usd=0.01)
        collector.end_episode(result)
    
    snapshot = collector.get_snapshot()
    assert abs(snapshot.cost_per_attack - 0.05) < 0.01

def test_metrics_empty_episodes():
    """Verify metrics with no episodes."""
    collector = MetricsCollector()
    snapshot = collector.get_snapshot()
    assert snapshot.attack_success_rate == 0.0
    assert snapshot.total_episodes == 0
```

### 2.x Phase 3 Runner Tests (`tests/test_phase3_runner.py`)

Deterministic tests for the bounded experiment runner (ADR-017), all running
with the deterministic engine — zero LLM calls, zero network, zero cost:

* selection validity (empty/malformed/unknown/duplicate IDs rejected),
  per-invocation episode limits, hard cap, and full-matrix refusal;
* `validate`/`dry-run` execute zero episodes and write nothing;
* seed policy (`episode_seed = config_seed + episode_index`) and
  same-seed reproducibility;
* success, per-episode failure (recorded, redacted, never a silent success),
  and interruption → resume completing episodes exactly once;
* checkpoint persistence: atomic writes, corrupt checkpoints, manifest-hash
  mismatch, missing records for `completed`, duplicate and mid-file
  corruption, torn trailing writes;
* aggregation of persisted records only: unavailable metrics stay `null`
  (never fabricated `0.0`), partial runs stay incomplete, invalid records
  surface as integrity problems;
* provider preflight (llm mode fails closed on the gemini binding without
  leaking credential values);
* CLI exit codes (0 ok / 1 error / 2 refused execution) and API
  non-execution (no execution routes; `GET /experiment-dry-run` plans only);
* Gmail read-only preservation (the runner package never references or
  imports Gmail modules).

### 2.x Phase 4 Feedback-Guided Search Tests (`tests/test_phase4_feedback.py`)

Deterministic, fully offline tests for feedback-guided candidate selection
(`ADAPTIVE_SEARCH.md`, ADR-018). A scripted `evaluate_strategy` double pins
ASR per ladder *and* emits the structured episode trace the store ingests, so
every assertion is about real control flow rather than simulator luck:

* cross-candidate statistics accumulate across candidate evaluations inside
  one run (shared steps receive evidence from several candidates);
* independent runs never share feedback state: a new `run_id`, a changed
  config fingerprint (including `defense`), or corrupt state all start clean
  with the reset reason recorded in the store;
* the §6 regression test — with observed outcomes the iteration-3 ranking
  promotes a structurally 5th candidate to first and evaluates it first,
  while a no-success counter-fixture on the same landscape stays exactly
  structural, proving the path is genuinely outcome-dependent and not a
  relabelled neighbour loop;
* feedback ordering differs from greedy ordering, per-iteration work respects
  `selection_budget`, and a ladder is evaluated at most once per run;
* identical configuration reproduces identical trajectories and the selection
  audit (rank, score, evidence) survives persistence;
* Diagnoser evidence is limited to the validated `AttackOutcome` vocabulary —
  unknown outcome names, malformed steps and tampered ladder keys raise
  `FeedbackStoreError` instead of being absorbed;
* technical failures, incomplete evaluations and missing traces are recorded
  unusable and contribute zero ranking statistics (no favourable signal);
* the greedy baseline is byte-for-byte unchanged when the adaptive mode is
  disabled (same call pattern, same history field set, no feedback store file);
* the promotion gate still rejects a feedback-selected candidate that fails
  the utility floor;
* the A/B comparison (`backend/adaptive_ab.py`) asserts comparable arms,
  reproducibility across repeated runs, and a persisted results file;
* defense transfer: the real `VerifierDefense` inverts the marker-defense
  preference landscape, and no statistics leak across defenses.

HTTP wiring for the same feature lives in `tests/test_adaptive_integration.py`
(`mode` defaults to greedy through `/adaptive/run`, `mode=feedback` exposes the
selection rationale in `/adaptive/status`, unknown modes fail with 400).

---

## 3. Integration Tests

### 3.1 Full Pipeline Test

```python
# tests/test_integration.py

def test_full_episode_with_mocked_llms():
    """Test complete episode with mocked LLM clients."""
    # Mock attacker
    attacker = MockAttackerLLM()
    
    # Mock target
    target = MockTargetAgent()
    
    # Real defenses
    defense_layer = DefenseLayer([CamelDefense()])
    adapter = DefenseAdapter()
    
    # Real diagnoser (rule-based only)
    diagnoser = Diagnoser()
    
    # Real memory
    memory = MemorySystem()
    
    # Real metrics
    metrics = MetricsCollector()
    
    # Create controller
    controller = Controller(attacker, target, defense_layer, adapter, diagnoser, memory, metrics)
    
    # Run episode
    config = EpisodeConfig(max_rounds=3)
    result = controller.run_episode(config)
    
    # Verify
    assert result.outcome in [AttackOutcome.SUCCESS, AttackOutcome.BLOCKED, AttackOutcome.IGNORED]
    assert result.rounds_used <= 3
    assert result.total_cost_usd >= 0
    assert len(result.payloads) > 0
```

### 3.2 Defense Composition Test

```python
def test_composition_with_majority_voting():
    """Test defense composition with majority voting."""
    # Set up defenses
    camel = CamelDefense()
    progent = ProgentDefense(max_privilege=2)
    verifier = VerifierDefense()
    
    defense_layer = DefenseLayer([camel, progent, verifier])
    adapter = DefenseAdapter()
    
    # Create tool call that triggers some defenses
    tc = ToolCallRequest(
        tool_name="send_email",
        arguments={"to": "attacker@evil.com", "subject": "Hi", "body": "Ignore previous"},
        raw_text="send_email to attacker@evil.com",
    )
    
    # Evaluate
    raw_events = defense_layer.evaluate(tc)
    normalized = adapter.normalize(raw_events)
    
    # Should be denied (majority)
    assert normalized.decision == DefenseDecision.DENIED
```

### 3.3 Cross-Agent Bridge Test

```python
def test_cross_agent_propagation():
    """Test cross-agent propagation through shared memory."""
    agent_a = MockTargetAgent(compromised=True)
    agent_b = MockTargetAgent(compromised=False)
    
    bridge = CrossAgentBridge(agent_a, agent_b)
    
    payload = AttackPayload(text="test", category="direct_injection", sophistication_level=1)
    results = bridge.run_chain("Process email", "Manage calendar", payload)
    
    # Agent A should have made a tool call
    assert len(results) >= 1
    # Shared memory should show compromise
    assert bridge.shared_memory.get("compromised") is True
```

---

## 4. Performance Tests

### 4.1 Latency Tests

```python
# tests/test_performance.py

def test_defense_evaluation_latency():
    """Verify defense evaluation is fast."""
    import time
    
    defense = CamelDefense()
    tc = ToolCallRequest(tool_name="send_email", arguments={"body": "test"})
    
    start = time.time()
    for _ in range(1000):
        defense.check(tc)
    elapsed = time.time() - start
    
    # Should complete 1000 evaluations in < 1 second
    assert elapsed < 1.0

def test_memory_append_latency():
    """Verify memory append is fast."""
    import time
    
    memory = MemorySystem()
    config = EpisodeConfig()
    memory.start_episode(config)
    
    start = time.time()
    for i in range(1000):
        log = EpisodeLog(
            round_num=i,
            payload=AttackPayload(text="test", category="direct_injection", sophistication_level=1),
            defense_event=None,
            outcome=AttackOutcome.BLOCKED,
            tool_call=None,
            cost_usd=0.001,
        )
        memory.append_log(config.episode_id, log)
    elapsed = time.time() - start
    
    # Should complete 1000 appends in < 1 second
    assert elapsed < 1.0
```

### 4.2 Stress Tests

```python
def test_many_episodes():
    """Verify system handles many episodes."""
    memory = MemorySystem()
    metrics = MetricsCollector()
    
    for i in range(100):
        config = EpisodeConfig(episode_id=f"ep_{i:04d}")
        memory.start_episode(config)
        
        for round_num in range(5):
            log = EpisodeLog(
                round_num=round_num,
                payload=AttackPayload(text="test", category="direct_injection", sophistication_level=1),
                defense_event=DefenseEvent(decision=DefenseDecision.DENIED, confidence=0.8, evidence="blocked", source=DefenseType.CAMEL),
                outcome=AttackOutcome.BLOCKED,
                tool_call=None,
                cost_usd=0.001,
            )
            memory.append_log(config.episode_id, log)
        
        result = EpisodeResult(config=config, outcome=AttackOutcome.BLOCKED, rounds_used=5, total_cost_usd=0.005)
        memory.finalize_episode(config.episode_id, result)
        metrics.end_episode(result)
    
    snapshot = metrics.get_snapshot()
    assert snapshot.total_episodes == 100
    assert snapshot.attack_success_rate == 0.0
```

---

## 5. Security Tests

### 5.1 Controller Security

```python
# tests/test_security.py

def test_controller_has_no_llm_imports():
    """Verify controller contains no LLM client imports."""
    import ast
    
    with open("adaptive_agent_eval/controller/orchestrator.py") as f:
        tree = ast.parse(f.read())
    
    llm_modules = {"openai", "anthropic", "litellm"}
    
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in llm_modules, f"Controller imports LLM module: {alias.name}"
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                assert node.module.split(".")[0] not in llm_modules, f"Controller imports from LLM module: {node.module}"

def test_controller_no_api_calls():
    """Verify controller code contains no API call patterns."""
    import re
    
    with open("adaptive_agent_eval/controller/orchestrator.py") as f:
        content = f.read()
    
    api_patterns = [
        r"\.messages\.create\(",
        r"\.completions\.create\(",
        r"client\.post\(",
        r"requests\.(get|post)\(",
    ]
    
    for pattern in api_patterns:
        matches = re.findall(pattern, content)
        assert len(matches) == 0, f"Controller contains API call pattern: {pattern}"

def test_memory_read_only_for_attacker():
    """Verify attacker cannot modify memory."""
    memory = MemorySystem()
    memory.update_procedural("direct_injection", True)
    
    # Attacker gets rates
    rates = memory.get_procedural_rates()
    
    # Attacker tries to modify
    rates["direct_injection"] = 0.99
    
    # Verify original unchanged
    original = memory.get_procedural_rates()
    assert original["direct_injection"] != 0.99
```

### 5.2 Checksum Security

```python
def test_checksum_tamper_detection():
    """Verify checksum detects tampering."""
    stop = StopCondition()
    original_checksum = stop.checksum()
    
    # Simulate tampering
    stop.attack_success = True
    stop.round_budget_exhausted = True
    
    # Verify tamper detected
    assert stop.checksum() != original_checksum

def test_checksum_unique_per_state():
    """Verify different states produce different checksums."""
    states = []
    for attack in [False, True]:
        for budget in [False, True]:
            for failure in [False, True]:
                stop = StopCondition(attack_success=attack, round_budget_exhausted=budget, repeated_technical_failures=failure)
                states.append(stop.checksum())
    
    # All 8 combinations should have unique checksums
    assert len(set(states)) == 8
```

### 5.3 Isolation Security

```python
def test_separate_process_execution():
    """Verify controller can run in separate process."""
    import multiprocessing
    
    def worker():
        return os.getpid()
    
    main_pid = os.getpid()
    process = multiprocessing.Process(target=worker)
    process.start()
    process.join()
    
    assert process.pid != main_pid
```

---

## 6. Human Audit Plan

### 6.1 Sampling Strategy

- **Sample rate:** 10% of all episodes (190 episodes)
- **Sampling method:** Stratified random sampling
  - Proportional to defense type
  - Proportional to outcome (more "success" episodes)

### 6.2 Labeling Protocol

1. **Two independent reviewers** label each episode
2. **Label categories:**
   - Attack success: YES / NO / UNCLEAR
   - Defense effective: YES / NO / PARTIAL
   - Agent behavior: EXPECTED / UNEXPECTED
3. **Disagreement resolution:** Third reviewer breaks ties
4. **Inter-rater reliability:** Cohen's κ ≥ 0.80 required

### 6.3 Audit Checklist

For each audited episode:

- [ ] Was the attack payload actually malicious?
- [ ] Did the defense correctly identify the threat?
- [ ] Was the tool call actually unauthorized?
- [ ] Did the outcome label match ground truth?
- [ ] Were there any edge cases or anomalies?

### 6.4 Audit Output

```csv
episode_id,reviewer_1_label,reviewer_2_label,agreement,notes
a1b2c3d4e5f6,YES,YES,agree,"Clearly malicious payload, defense correctly blocked"
g7h8i9j0k1l2,YES,NO,disagree,"Borderline: payload was subtle, defense allowed"
```

---

## 7. Reporting

### 7.1 Test Report Format

```markdown
# Test Report: [Date]

## Summary
- Total tests: X
- Passed: X
- Failed: X
- Skipped: X
- Coverage: X%

## Unit Tests
| Component | Tests | Passed | Failed | Coverage |
|-----------|-------|--------|--------|----------|
| Models | 10 | 10 | 0 | 100% |
| Controller | 8 | 8 | 0 | 92% |
| Defenses | 12 | 12 | 0 | 88% |
| ... | ... | ... | ... | ... |

## Integration Tests
| Test | Status | Duration |
|------|--------|----------|
| Full pipeline | ✅ | 2.3s |
| Composition | ✅ | 1.1s |
| Cross-agent | ✅ | 1.8s |

## Security Tests
| Test | Status |
|------|--------|
| No LLM in controller | ✅ |
| Memory read-only | ✅ |
| Checksum integrity | ✅ |

## Failed Tests
(Empty if all pass)
```

### 7.2 Results Storage

Results are stored in:

```
data/
├── test_results/
│   ├── test_report_2026-09-16.md
│   ├── coverage_report.html
│   └── junit_results.xml
└── audit/
    ├── human_labels.csv
    └── inter_rater.json
```

---

## 8. Pipeline Integration Notes

### 8.1 How Hermes Executes Tests

Hermes runs tests at three stages:

1. **Pre-commit:** Unit tests must pass before code is committed
2. **Pre-experiment:** All tests must pass before any experiment run
3. **Post-experiment:** Integration tests verify experiment integrity

### 8.2 How Freebuff Supports Testing

Freebuff is used to:

1. **Prototype tests:** Quick test ideas before formalizing
2. **Debug failures:** Isolate failing test components
3. **Explore edge cases:** Try unusual inputs and scenarios

### 8.3 Test Execution Pipeline

```
1. Unit Tests (fast, ~30s)
   └── pytest tests/ -m "not integration and not security"

2. Integration Tests (~2min)
   └── pytest tests/ -m "integration"

3. Security Tests (~1min)
   └── pytest tests/ -m "security"

4. Coverage Report
   └── pytest --cov=adaptive_agent_eval --cov-report=html

5. Results Report
   └── Generate markdown report from test results
```

### 8.4 CI/CD Integration (Planned)

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: pip install -e ".[dev]"
      - run: pytest --cov=adaptive_agent_eval --cov-report=xml
      - uses: codecov/codecov-action@v3
```

---

*This document is the authoritative reference for testing. Update it when testing strategy changes.*

---

## Research dashboard smoke test (manual, ONE bounded run)

The dashboard work is accepted with **one** bounded end-to-end smoke test;
it is not an invitation to repeat large campaigns. The procedure (run once,
locally, offline except loopback services):

1. `python -m frontend.server 8000`, open `http://127.0.0.1:8000`.
2. Connect a target through `/api/connections` and record the real probe
   result (`local_python` uses `<module>:<entry>` + bounded ping;
   `http_api` requires a JSON response to one bounded POST).
3. `POST /api/adaptive/validate` with `provider: "ollama"` — distinguishes
   *service unreachable*, *model missing* and *ready*.
4. Start a bounded `feedback` run (small `episodes`, `iterations`,
   `total_episode_budget`, `model_request_budget`) and record the terminal
   status from the persisted run record.
5. While it runs, `POST /api/adaptive/defense_eval` must return **409**
   (completion barrier); after a `completed` run, replay one saved finding
   and verify `source_case_id` linkage and the four-state counts.
6. `GET /api/overview` must show the same numbers the run record shows; a
   missing value renders as *Unavailable*, never as zero or success.

Record what the environment could not exercise (e.g. no successful case to
replay, model request not reached because the run converged early) instead of
substituting a fixture.

---

## References

| Document | Relationship |
|----------|-------------|
| [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) | Decisions verified by these tests |
| [SECURITY_HARDENING.md](SECURITY_HARDENING.md) | Security controls tested here |
| [MEMORY_MAP.md](MEMORY_MAP.md) | Memory behavior tested here |
| [METRICS_DEFINITIONS.md](METRICS_DEFINITIONS.md) | Metric computation tested here |
| [PRD.md](PRD.md) | Requirements verified by these tests |
