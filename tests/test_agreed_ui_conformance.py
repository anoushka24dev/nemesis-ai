"""Conformance tests for the agreed NEMESIS dashboard side panel.

The approved interface is one autonomous-agent dashboard:

  1. header with backend / pairing / mode status and the nonce input,
  2. a single ``Start Nemesis Demo`` action,
  3. an execution timeline fed by real backend stage state,
  4. the Hill Climbing Strategy Engine with documented inputs, baseline vs
     candidate measurements, candidate iterations and the gate decision,
  5. final results (threat verdict, strategy outcome, email action).

The legacy manual-email workflow (compose fields, per-email Forward/Reply/Send
buttons, numbered sections) must be absent.
"""
from __future__ import annotations

import re
from pathlib import Path

EXT = Path(__file__).resolve().parent.parent / "extension"
HTML = (EXT / "sidepanel.html").read_text(encoding="utf-8")
CSS = (EXT / "sidepanel.css").read_text(encoding="utf-8")
SRC = (EXT / "sidepanel.js").read_text(encoding="utf-8")


def fn(signature):
    """Extract a top-level function body by name (column-0 anchored)."""
    name = signature.split("(", 1)[0].split()[-1]
    m = re.search(r"^(?:async )?function " + re.escape(name) + r"\(", SRC, re.M)
    assert m, name
    tail = SRC[m.end():]
    nxt = re.search(r"^(?:async )?function ", tail, re.M)
    return tail[: nxt.start()] if nxt else tail


def wireup():
    assert 'document.addEventListener("DOMContentLoaded", wire)' in SRC
    return fn("function wire")


# --------------------------------------------------------------- header ----

def test_header_has_connection_pairing_and_mode_status():
    for element_id in (
        "pill-backend", "pill-backend-text", "pill-pairing", "pill-mode",
        "conn-banner", "nonce", "pair-btn", "pair-status",
    ):
        assert f'id="{element_id}"' in HTML, element_id
    # The nonce stays a password field; it is never rendered as text.
    nonce_input = re.search(r"<input[^>]*id=\"nonce\"[^>]*>", HTML)
    assert nonce_input is not None
    assert 'type="password"' in nonce_input.group(0)

    conn = fn("function renderConnection")
    assert "client.online" in conn
    assert "client.paired" in conn
    assert "modeFromWorkflow()" in conn
    assert "client.workflow.kill_switch" in fn("function updateAvailability")


def test_no_undefined_placeholder_values_are_rendered():
    assert "fmtNum(" in SRC and '"n/a"' in fn("function fmtNum")
    assert "fmtPct(" in SRC and '"n/a"' in fn("function fmtPct")
    # Every rendered run field falls back through a helper or String(...).
    results = fn("function renderResults")
    assert "String(" in results
    assert "n/a" in results


# ---------------------------------------------------------- primary action --

def test_single_primary_start_button_exists():
    assert HTML.count('id="demo-run-btn"') == 1
    assert "Start Nemesis Demo" in HTML
    # Exactly one primary action; no competing demo/evaluation launch buttons.
    for stale in (
        "adaptive-run-btn", "hill-run-btn", "hill-propose-btn", "metrics-btn",
        "defense-btn", "feed-btn", "analyze-btn", "audit-btn",
    ):
        assert f'id="{stale}"' not in HTML, stale


def test_start_button_wiring_and_duplicate_guard():
    wire = wireup()
    assert 'el("demo-run-btn")' in wire
    assert 'runBtn.addEventListener("click", onStartDemo)' in wire
    assert 'el("demo-stop-btn")' in wire
    assert 'stopBtn.addEventListener("click", onStopDemo)' in wire
    start = fn("async function onStartDemo")
    assert 'backendPost("/nemesis/demo/run"' in start
    assert "runIsActive(client.run)" in start  # duplicate launch guard
    assert "client.busy" in start
    availability = fn("function updateAvailability")
    assert "!client.online" in availability
    assert "!client.paired" in availability
    assert "runIsActive(client.run)" in availability


def test_stop_uses_the_backend_stop_route():
    stop = fn("async function onStopDemo")
    assert 'backendPost("/nemesis/demo/stop"' in stop
    poll = fn("function schedulePoll")
    assert "/nemesis/demo/status" in SRC
    assert "refreshDemoStatus" in poll


# --------------------------------------------------------------- timeline ---

def test_timeline_comes_from_backend_stage_state():
    assert 'id="stage-list"' in HTML
    timeline = fn("function renderTimeline")
    assert "stage.state" in timeline
    assert "stage.detail" in timeline
    assert "stageGlyph(stage.state)" in timeline
    duration = fn("function stageDuration")
    assert "stage.started_at" in duration
    assert "stage.finished_at" in duration
    assert "replaceChildren" in timeline
    assert 'id="run-state-badge"' in HTML
    badge = fn("function setRunBadge")
    assert 'String(state || "idle")' in badge


def test_failed_stages_are_not_drawn_as_progress():
    assert '"failed"' in SRC
    assert '"skipped"' in SRC
    assert 'stageGlyph(stage.state)' in SRC


# -------------------------------------------------------------- hill climb --

def test_hillclimber_section_is_substantial_and_wired():
    section = HTML.split('<section class="card climber"', 1)[1].split("</section>", 1)[0]
    for element_id in (
        "doc-list", "compare", "cmp-base-asr", "cmp-cand-asr", "cmp-delta",
        "metric-grid", "adaptive-engine-box", "adaptive-engine",
        "adaptive-loops-box", "adaptive-loops", "adaptive-activity-box",
        "adaptive-activity",
    ):
        assert f'id="{element_id}"' in section, element_id
    assert "Baseline vs candidate" in section
    assert "Hill Climbing Strategy Engine" in section
    assert "Adaptive Strategy Engine" in section


def test_architecture_documents_and_rules_are_rendered():
    docs = fn("function renderDocs")
    assert "architecture.documents" in docs
    assert "doc.path" in docs
    assert "doc.sha256" in docs
    assert "architecture.rules" in docs
    assert "rule.source" in docs


def test_baseline_and_candidate_scores_are_measured_values():
    compare = fn("function renderCompare")
    assert "hillclimb.baseline_asr" in compare
    assert "hillclimb.best_asr" in compare
    assert "evaluation.baseline" in compare
    # No hardcoded score literals in the comparison renderer.
    assert not re.search(r'"[0-9]+\.[0-9]+"', compare), "hardcoded score in compare"


def test_iteration_table_and_gate_reason_rendering():
    loops = fn("function renderIterations")
    for header in ("iter", "candidate ladder", "ASR", "delta", "decision"):
        assert f'"{header}"' in loops, header
    assert "iter-table" in loops
    assert "entry.improved" in loops
    decision = fn("function renderDecision")
    assert "gate.reasons" in decision
    assert "gate.passed" in decision
    assert "Candidate retained" in decision
    assert "Candidate rejected" in decision


# --------------------------------------------------------------- results ----

def test_final_results_cover_verdict_strategy_and_email():
    results = fn("function renderResults")
    assert "run.evaluation" in results and "verdict.decision" in results
    assert "run.decision" in results and "outcome" in results
    assert "run.email" in results and "email.status" in results
    assert "run.mode" in results
    assert "run.audit" in results
    assert "run.error" in results
    for element_id in ("result-badge", "result-body"):
        assert f'id="{element_id}"' in HTML


def test_email_outcome_labels_are_honest():
    delivery = fn("function deliveryText")
    # An accepted API call is never described as delivered.
    assert "not independently confirmed" in delivery
    assert "simulation mode" in delivery.lower()
    assert "policy blocked" in delivery.lower()
    assert "email.status === \"delivered\"" in delivery
    tag = fn("function emailTag")
    for status in ("simulated", "blocked", "accepted", "delivered", "failed"):
        assert status in tag


# ------------------------------------------------------- removed legacy UI --

def test_manual_compose_and_per_email_actions_are_gone():
    for stale in (
        'id="c-to"', 'id="c-subject"', 'id="c-body"', 'id="compose"',
        'id="prepare-new-btn"', 'id="prepare-reply-btn"', 'id="submit-btn"',
        'id="agent-box"', 'id="agent-reply-btn"', 'id="agent-forward-btn"',
        'id="agent-send-btn"', 'id="nemesis-actions"', 'id="read-email-btn"',
        'id="analyze-provider"', 'id="feedback-record-btn"',
    ):
        assert stale not in HTML, stale
    assert "<textarea" not in HTML
    # No numbered legacy workflow headings.
    assert not re.search(r"<h2>\s*[1-9]\.", HTML)


def test_js_does_not_reference_legacy_controls():
    for stale in (
        "prepare-new-btn", "prepare-reply-btn", "submit-btn", "agent-send-btn",
        "agent-reply-btn", "agent-forward-btn", "analyze-provider",
        "feedback-record-btn", "compose-status",
    ):
        assert stale not in SRC, stale


# ------------------------------------------------------------ security ------

def test_only_loopback_backend_paths_are_called():
    assert 'const API_BASE = "http://127.0.0.1:8123/api/v1/stage_b";' in SRC
    for capture in re.findall(r"fetch\(([^)]*)\)", SRC):
        assert "API_BASE" in capture, capture
    paths = re.findall(r'backendPost\(\s*"([^"]+)"', SRC)
    assert paths
    for path in paths:
        assert path.startswith("/"), path
        for forbidden in ("send", "modify", "trash", "drafts", "batchModify"):
            assert forbidden not in path, (forbidden, path)


def test_nonce_is_never_logged_and_no_dom_injection():
    assert "console.log" not in SRC
    assert "console.debug" not in SRC
    assert "console.info" not in SRC
    assert "innerHTML" not in SRC
    assert "eval(" not in SRC


def test_no_literal_arrow_chars_in_js():
    assert "\u2192" not in SRC


# ---------------------------------------------------------------- styling ---

def test_css_supports_dashboard_layout_and_side_panel_width():
    for selector in (
        ".timeline", ".stage.running", ".stage.done", ".stage.failed",
        ".compare", ".compare-delta.up", ".metrics", ".iter-table",
        ".badge.running", ".btn.primary", ".pairing-row", ".result-row",
    ):
        assert selector in CSS, selector
    assert "@media (max-width: 360px)" in CSS
