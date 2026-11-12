// Nemesis side panel — autonomous demo dashboard.
//
// One primary action (Start Nemesis Demo) drives the real backend orchestrator
// at /nemesis/demo/run. The panel renders only what the backend reports: stage
// state, measured strategy metrics, the regression-gate decision, and the real
// email action outcome. It never fakes progress or success.
//
// Security contract (unchanged from the Stage C panel):
//   * The pairing nonce lives only in chrome.storage.local. It is never logged,
//     never rendered as text, and only ever sent as a Bearer token to the
//     loopback backend.
//   * The only host fetched is the loopback API base; the health check derives
//     its URL from the same constant.
//   * No Gmail write endpoint is referenced here. The backend owns policy,
//     allowlist, rate limit, kill switch, and transport arming.

const API_BASE = "http://127.0.0.1:8123/api/v1/stage_b";

const client = {
  nonce: "",
  paired: false,
  online: false,
  health: null,
  workflow: null,
  run: null,
  busy: false,
  statusTimer: null,
  pollInFlight: false,
};

// ---------------------------------------------------------------- helpers --

function el(id) {
  return document.getElementById(id);
}

function make(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function setText(id, text) {
  const node = el(id);
  if (node) node.textContent = text === undefined || text === null ? "" : String(text);
}

function setBanner(text, kind) {
  const banner = el("conn-banner");
  if (!banner) return;
  if (!text) {
    banner.hidden = true;
    banner.textContent = "";
    banner.className = "banner";
    return;
  }
  banner.hidden = false;
  banner.textContent = text;
  banner.className = "banner " + (kind || "");
}

function setStatus(node, text, kind) {
  if (!node) return;
  node.textContent = text;
  node.classList.remove("ok", "err");
  if (kind) node.classList.add(kind);
}

function redactDigits(text) {
  return String(text).replace(/\b(?:\d[\s-]?){7,}\d\b/g, "[number redacted]");
}

function fmtNum(value, digits) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "n/a";
  }
  return Number(value).toFixed(digits === undefined ? 2 : digits);
}

function fmtPct(value) {
  if (value === null || value === undefined || Number.isNaN(Number(value))) {
    return "n/a";
  }
  return Math.round(Number(value) * 100) + "%";
}

function fmtBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(1) + " MB";
}

function fmtDuration(ms) {
  if (!Number.isFinite(ms) || ms < 0) return "";
  if (ms < 1000) return Math.round(ms) + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(1) + " s";
  const min = Math.floor(ms / 60000);
  const sec = Math.round((ms % 60000) / 1000);
  return min + "m " + sec + "s";
}

function parseTime(value) {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
}

function shortHash(value) {
  return String(value || "").slice(0, 10);
}

// Storage is chrome.storage.local inside the extension and localStorage when
// the same page is opened directly for layout review. Both paths are guarded.
function hasChromeStorage() {
  return (
    typeof chrome !== "undefined" &&
    chrome !== null &&
    chrome.storage &&
    chrome.storage.local
  );
}

async function loadNonce() {
  try {
    if (hasChromeStorage()) {
      const stored = await chrome.storage.local.get("pairingNonce");
      return stored.pairingNonce || "";
    }
    return window.localStorage.getItem("pairingNonce") || "";
  } catch (err) {
    return "";
  }
}

async function saveNonce(nonce) {
  try {
    if (hasChromeStorage()) {
      await chrome.storage.local.set({ pairingNonce: nonce });
    } else {
      window.localStorage.setItem("pairingNonce", nonce);
    }
  } catch (err) {
    /* storage unavailable: pairing still works for this page session */
  }
}

async function clearNonce() {
  try {
    if (hasChromeStorage()) {
      await chrome.storage.local.remove("pairingNonce");
    } else {
      window.localStorage.removeItem("pairingNonce");
    }
  } catch (err) {
    /* ignore */
  }
}

function extensionOrigin() {
  if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.getURL) {
    return chrome.runtime.getURL("").replace(/\/$/, "");
  }
  return "chrome-extension://nemesis-layout-preview";
}

// --------------------------------------------------------------- backend ---

async function backendPost(path, body, nonce) {
  const headers = { "Content-Type": "application/json" };
  if (nonce) headers.Authorization = "Bearer " + nonce;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  let resp;
  try {
    resp = await fetch(API_BASE + path, {
      method: "POST",
      headers,
      body: body ? JSON.stringify(body) : "{}",
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    return {
      ok: false,
      status: 0,
      data: { error: "Backend unreachable (offline or not started)" },
      offline: true,
    };
  }
  clearTimeout(timer);
  let data = null;
  try {
    data = await resp.json();
  } catch (err) {
    data = { error: "Non-JSON response from the backend" };
  }
  return { ok: resp.ok, status: resp.status, data, offline: false };
}

async function fetchHealth() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 3000);
  try {
    const resp = await fetch(
      API_BASE.split("/api/v1/stage_b")[0] + "/health",
      { method: "GET", signal: controller.signal }
    );
    clearTimeout(timer);
    if (!resp.ok) return null;
    return await resp.json();
  } catch (err) {
    clearTimeout(timer);
    return null;
  }
}

// ----------------------------------------------------------- presentation --

function setPill(id, text, className) {
  const pill = el(id);
  if (!pill) return;
  pill.classList.remove("online", "offline", "live", "muted");
  if (className) pill.className = "pill " + className;
  const label = pill.querySelector("span:last-child");
  if (label) {
    label.textContent = text;
  } else {
    pill.textContent = text;
  }
}

function renderConnection() {
  if (client.online) {
    setPill("pill-backend", "Backend connected", "online");
    const bind = (client.health && client.health.bind) || "127.0.0.1:8123";
    const pill = el("pill-backend");
    if (pill) pill.title = bind;
  } else {
    setPill("pill-backend", "Backend offline", "offline");
  }
  setPill(
    "pill-pairing",
    client.paired ? "Paired" : "Unpaired",
    client.paired ? "online" : "muted"
  );
  const policyMode = modeFromWorkflow();
  const mode = policyMode !== "--" ? policyMode : client.run && client.run.mode ? client.run.mode : "--";
  setPill(
    "pill-mode",
    "Mode: " + (mode || "--"),
    mode === "LIVE" ? "live" : "muted"
  );

  const pairing = document.querySelector(".pairing");
  if (pairing) pairing.hidden = client.paired;

  setText(
    "pair-status",
    client.paired
      ? "Paired with the local backend. The nonce is stored only in this extension."
      : client.nonce
      ? "Stored nonce was not accepted. Paste the current nonce from the backend terminal."
      : "Not paired with the local backend."
  );

  el("reset-btn").disabled = !client.paired;
  el("killswitch-btn").disabled = !client.paired;

  if (!client.online) {
    setBanner(
      "Backend unreachable at 127.0.0.1:8123. Start it with: python -m backend.stage_b serve",
      "err"
    );
  } else if (!client.paired) {
    setBanner("Backend is reachable. Paste its pairing nonce to enable the demo.", "");
  } else {
    setBanner("", "");
  }
  updateAvailability();
}

function modeFromWorkflow() {
  if (!client.workflow) return "--";
  const policyMode = String(client.workflow.mode || "").toLowerCase();
  return policyMode && policyMode !== "simulation" ? "LIVE" : "SIMULATION";
}

function runIsActive(run) {
  return Boolean(run) && (run.state === "running" || run.state === "starting");
}

function updateAvailability() {
  const running = runIsActive(client.run);
  const blockers = [];
  if (!client.online) blockers.push("Backend offline");
  if (!client.paired) blockers.push("Not paired");
  const runBtn = el("demo-run-btn");
  const stopBtn = el("demo-stop-btn");
  if (runBtn) {
    runBtn.disabled = blockers.length > 0 || running || client.busy;
    runBtn.textContent = running ? "Run in progress" : "Start Nemesis Demo";
  }
  if (stopBtn) stopBtn.hidden = !running;

  const blocker = el("run-blocker");
  if (!blocker) return;
  let message = "";
  if (!client.online) {
    message = "The demo needs the loopback backend on 127.0.0.1:8123.";
  } else if (!client.paired) {
    message = "Pair this panel with the backend nonce to enable the run.";
  } else if (client.workflow && client.workflow.kill_switch) {
    message = "Kill switch is engaged: the backend will block the email action.";
  } else if (
    client.workflow &&
    Array.isArray(client.workflow.allowed_recipients) &&
    client.workflow.allowed_recipients.length === 0
  ) {
    message =
      "No allowlisted sandbox recipient (NEMESIS_ALLOWED_RECIPIENTS): the email step will be BLOCKED.";
  }
  blocker.hidden = !message;
  blocker.textContent = message;
}

function setRunBadge(state) {
  const badge = el("run-state-badge");
  if (!badge) return;
  const label = String(state || "idle").toUpperCase();
  badge.className = "badge " + String(state || "idle");
  badge.textContent = label;
}

function setRunStatusLine() {
  const node = el("run-status-line");
  if (!node) return;
  const run = client.run;
  if (!client.online) {
    setStatus(node, "Backend unreachable. Start the local backend, then reload the panel.", "err");
    return;
  }
  if (!client.paired) {
    setStatus(node, "Ready to pair. Paste the nonce printed by the backend terminal.", "");
    return;
  }
  if (!run) {
    setStatus(node, "Ready. One run executes the full autonomous workflow.", "ok");
    return;
  }
  if (run.state === "running") {
    const stage = currentStage(run);
    const started = parseTime(run.started_at);
    const spent = started ? fmtDuration(Date.now() - started) : "";
    setStatus(
      node,
      "Running" + (stage ? ": " + stage.label : "") + (spent ? " (" + spent + ")" : ""),
      ""
    );
    return;
  }
  const started = parseTime(run.started_at);
  const finished = parseTime(run.finished_at);
  const took = started && finished ? fmtDuration(finished - started) : "";
  if (run.state === "completed") {
    setStatus(node, "Run completed" + (took ? " in " + took : "") + ".", "ok");
  } else if (run.state === "stopped") {
    setStatus(node, "Run stopped by operator" + (took ? " after " + took : "") + ".", "");
  } else if (run.state === "failed") {
    setStatus(node, "Run failed: " + (run.error || "unknown backend error"), "err");
  } else {
    setStatus(node, "Run state: " + String(run.state), "");
  }
}

function currentStage(run) {
  if (!run || !Array.isArray(run.stages)) return null;
  for (let i = 0; i < run.stages.length; i += 1) {
    if (run.stages[i].state === "running") return run.stages[i];
  }
  return null;
}

// -------------------------------------------------------------- timeline ---

function stageGlyph(state) {
  if (state === "done") return "\u2713";
  if (state === "failed") return "\u2715";
  if (state === "running") return "\u2022";
  if (state === "skipped") return "\u2013";
  return "";
}

function stageDuration(stage) {
  const started = parseTime(stage.started_at);
  if (!started) return "";
  const finished = parseTime(stage.finished_at) || Date.now();
  return fmtDuration(finished - started);
}

function renderTimeline(stages, run) {
  const list = el("stage-list");
  if (!list) return;
  const clean = Array.isArray(stages) ? stages : [];
  const nodes = clean.map((stage) => {
    const item = make("li", "stage " + String(stage.state || "pending"));
    const dot = make("span", "stage-dot", stageGlyph(stage.state));
    dot.setAttribute("aria-hidden", "true");
    const body = make("div", "stage-body");
    body.appendChild(make("span", "stage-label", stage.label || stage.id || "stage"));
    if (stage.detail) {
      body.appendChild(make("span", "stage-detail", redactDigits(stage.detail)));
    }
    const time = make("span", "stage-time", stageDuration(stage));
    item.appendChild(dot);
    item.appendChild(body);
    item.appendChild(time);
    return item;
  });
  list.replaceChildren(...nodes);

  const chip = el("timeline-state");
  if (chip) {
    const state = run && run.state ? run.state : "waiting";
    chip.textContent =
      state === "running"
        ? "stage " + clean.filter((s) => s.state === "done").length + "/" + clean.length
        : state;
  }
}

// --------------------------------------------------------------- climber ---

function ladderSummary(ladder) {
  if (!Array.isArray(ladder) || !ladder.length) return "n/a";
  return ladder
    .map((step) => {
      const category = String(step.category || "?");
      const level = step.sophistication_level === undefined ? "?" : step.sophistication_level;
      return category + ":" + level;
    })
    .join(" \u00b7 ");
}

function metricCell(label, value, sub) {
  const cell = make("div", "metric");
  cell.appendChild(make("span", "metric-k", label));
  cell.appendChild(make("span", "metric-v", value));
  if (sub) cell.appendChild(make("span", "metric-sub", sub));
  return cell;
}

function renderDocs(architecture) {
  const list = el("doc-list");
  if (!list) return;
  const documents = (architecture && architecture.documents) || [];
  if (!documents.length) {
    list.replaceChildren(make("li", "empty", "No architecture documents were read."));
    return;
  }
  const nodes = documents.map((doc) => {
    const item = make("li", "doc");
    item.appendChild(make("span", "doc-name", doc.path));
    item.appendChild(
      make(
        "span",
        "doc-meta",
        fmtBytes(doc.bytes) +
          " \u00b7 " +
          String(doc.sections || 0) +
          " headings \u00b7 sha " +
          shortHash(doc.sha256)
      )
    );
    return item;
  });
  const rules = (architecture && architecture.rules) || [];
  if (rules.length) {
    const wrap = make("li", "doc");
    const details = make("details", "rules");
    details.appendChild(
      make("summary", null, String(rules.length) + " strategy rules quoted from the sources")
    );
    const ul = document.createElement("ul");
    rules.forEach((rule) => {
      const li = make("li", null, redactDigits(rule.text));
      li.appendChild(make("span", "src", rule.source));
      ul.appendChild(li);
    });
    details.appendChild(ul);
    wrap.appendChild(details);
    nodes.push(wrap);
  }
  list.replaceChildren(...nodes);
}

function renderCompare(hillclimb, evaluation) {
  const baseline =
    hillclimb && hillclimb.baseline_asr !== undefined && hillclimb.baseline_asr !== null
      ? hillclimb.baseline_asr
      : evaluation && evaluation.baseline
      ? evaluation.baseline.asr
      : null;
  const candidate =
    hillclimb && hillclimb.candidate_asr !== undefined && hillclimb.candidate_asr !== null
      ? hillclimb.candidate_asr
      : hillclimb && hillclimb.best_asr !== undefined && hillclimb.best_asr !== null
      ? hillclimb.best_asr
      : null;
  setText("cmp-base-asr", fmtPct(baseline));
  setText("cmp-cand-asr", fmtPct(candidate));
  const deltaNode = el("cmp-delta");
  if (!deltaNode) return;
  deltaNode.classList.remove("up", "down");
  if (baseline === null || candidate === null) {
    deltaNode.textContent = "--";
    return;
  }
  const delta = Number(candidate) - Number(baseline);
  const points = Math.round(delta * 100);
  deltaNode.textContent = (points > 0 ? "+" : "") + points + " pts";
  if (points > 0) deltaNode.classList.add("up");
  if (points < 0) deltaNode.classList.add("down");
}

function renderMetrics(run) {
  const grid = el("metric-grid");
  if (!grid) return;
  const hillclimb = run.hillclimb;
  const evaluation = run.evaluation || {};
  if (!hillclimb) {
    grid.replaceChildren();
    const engineBox = el("adaptive-engine-box");
    if (engineBox) engineBox.hidden = true;
    return;
  }
  const candidateEval = hillclimb.candidate_evaluation || {};
  const gate = hillclimb.gate || {};
  const checked = gate.checked || {};
  const cells = [
    metricCell(
      "Candidate utility",
      candidateEval.utility_score === undefined ? fmtNum(checked.utility) : fmtNum(candidateEval.utility_score),
      "floor " + fmtNum(hillclimb.utility_floor)
    ),
    metricCell(
      "Bypass rate",
      candidateEval.bypass_rate === undefined ? "n/a" : fmtPct(candidateEval.bypass_rate),
      "measured by the harness"
    ),
    metricCell(
      "Rounds to success",
      candidateEval.rounds_to_success === undefined ? "n/a" : fmtNum(candidateEval.rounds_to_success),
      "candidate strategy"
    ),
    metricCell(
      "Episodes evaluated",
      String(candidateEval.total_episodes || checked.episodes || hillclimb.episodes || 0),
      "min for gate " + String(hillclimb.min_episodes_for_promotion || 0)
    ),
    metricCell(
      "Gate",
      gate.passed ? "PASSED" : "REJECTED",
      gate.passed ? "candidate retained" : "baseline stays active"
    ),
    metricCell(
      "Baseline utility",
      evaluation.baseline ? fmtNum(evaluation.baseline.utility_score) : "n/a",
      "pre-climb measurement"
    ),
    metricCell(
      "Best observed ASR",
      fmtPct(hillclimb.best_asr),
      "max over " + String((hillclimb.history || []).length) + " evaluations"
    ),
  ];
  grid.replaceChildren(...cells);

  const engineBox = el("adaptive-engine-box");
  const engine = el("adaptive-engine");
  if (engineBox && engine) {
    const activeEval = hillclimb.active_evaluation || {};
    if (hillclimb.active_strategy_id) {
      engineBox.hidden = false;
      const activeCells = [
        metricCell("Active strategy", hillclimb.active_strategy_id, "post-gate state"),
        metricCell("Active ASR", fmtPct(activeEval.asr), "measured"),
        metricCell("Active utility", fmtNum(activeEval.utility_score), "defender"),
        metricCell(
          "Evaluation run",
          String(hillclimb.run_id || "n/a"),
          "backend harness run"
        ),
      ];
      engine.replaceChildren(...activeCells);
    } else {
      engineBox.hidden = true;
    }
  }
}

function renderIterations(hillclimb) {
  const host = el("adaptive-loops");
  if (!host) return;
  if (!hillclimb) {
    host.replaceChildren(make("p", "empty", "No candidate evaluations yet."));
    return;
  }
  const history = Array.isArray(hillclimb.history) ? hillclimb.history : [];
  if (!history.length) {
    host.replaceChildren(make("p", "empty", "The hill climber produced no candidate evaluations."));
    return;
  }
  const table = make("table", "iter-table");
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  ["iter", "candidate ladder", "ASR", "delta", "decision"].forEach((label) => {
    headRow.appendChild(make("th", null, label));
  });
  thead.appendChild(headRow);
  table.appendChild(thead);
  const tbody = document.createElement("tbody");
  // Keep the accepted improvements plus the latest evaluations; the full
  // history stays on the backend for audit.
  const tailStart = Math.max(0, history.length - 6);
  const shown = history.filter((entry, index) => index >= tailStart || entry.improved);
  shown.forEach((entry) => {
    const row = document.createElement("tr");
    row.appendChild(make("td", null, String(entry.iteration === undefined ? "-" : entry.iteration)));
    row.appendChild(make("td", "ladder", ladderSummary(entry.candidate_ladder)));
    row.appendChild(make("td", null, fmtPct(entry.asr)));
    const delta = Number(entry.delta || 0) * 100;
    row.appendChild(make("td", null, (delta > 0 ? "+" : "") + Math.round(delta) + " pts"));
    row.appendChild(make("td", null, entry.improved ? "accepted" : "rejected"));
    tbody.appendChild(row);
  });
  table.appendChild(tbody);
  const caption = make(
    "p",
    "micro",
    "showing accepted improvements and the latest evaluations (" +
      String(shown.length) +
      " of " +
      String(history.length) +
      ")"
  );
  host.replaceChildren(table, caption);
}

function renderDecision(hillclimb) {
  const host = el("adaptive-activity");
  if (!host) return;
  if (!hillclimb) {
    host.replaceChildren(make("p", "empty", "The regression gate result appears after a run."));
    return;
  }
  const gate = hillclimb.gate || {};
  const decision = host;
  decision.className = "decision " + (gate.passed ? "retained" : "rejected");
  const head = make("div", "decision-head");
  head.appendChild(make("span", "dot"));
  head.appendChild(
    make("span", null, gate.passed ? "Candidate retained" : "Candidate rejected")
  );
  const reasons = make("ul");
  const list = Array.isArray(gate.reasons) ? gate.reasons : [];
  if (list.length) {
    list.forEach((reason) => reasons.appendChild(make("li", null, redactDigits(reason))));
  } else if (gate.passed) {
    reasons.appendChild(
      make("li", null, "All regression checks passed: completed run, enough episodes, no technical failures, ASR improvement, utility above floor.")
    );
  } else {
    reasons.appendChild(make("li", null, "The gate did not pass; the baseline strategy remains active."));
  }
  decision.replaceChildren(
    head,
    reasons,
    make(
      "p",
      "decision-meta",
      "candidate " +
        String(hillclimb.candidate_id || "n/a") +
        " \u00b7 evaluation run " +
        String(hillclimb.run_id || "n/a") +
        " \u00b7 baseline " +
        fmtPct(hillclimb.baseline_asr) +
        " to candidate " +
        fmtPct(
          hillclimb.candidate_asr === undefined || hillclimb.candidate_asr === null
            ? hillclimb.best_asr
            : hillclimb.candidate_asr
        )
    )
  );
}

function renderClimber(run) {
  const chip = el("climber-state");
  if (!run) {
    renderDocs(null);
    renderCompare(null, null);
    const grid = el("metric-grid");
    if (grid) grid.replaceChildren();
    renderIterations(null);
    renderDecision(null);
    if (chip) chip.textContent = "no run yet";
    return;
  }
  renderDocs(run.architecture);
  renderCompare(run.hillclimb, run.evaluation);
  renderMetrics(run);
  renderIterations(run.hillclimb);
  renderDecision(run.hillclimb);
  if (chip) {
    if (run.hillclimb && run.hillclimb.gate) {
      chip.textContent = run.hillclimb.gate.passed ? "retained" : "rejected";
    } else {
      chip.textContent = run.state === "running" ? "evaluating" : "no evaluation";
    }
  }
}

// --------------------------------------------------------------- results ---

function resultRow(key, valueNodes) {
  const row = make("div", "result-row");
  row.appendChild(make("span", "result-key", key));
  const value = make("div", "result-value");
  if (Array.isArray(valueNodes)) {
    valueNodes.forEach((node) => value.appendChild(node));
  } else {
    value.textContent = String(valueNodes === undefined || valueNodes === null ? "n/a" : valueNodes);
  }
  row.appendChild(value);
  return row;
}

function emailTag(status) {
  const known = ["simulated", "blocked", "accepted", "delivered", "failed"];
  const className = known.indexOf(status) >= 0 ? status : "blocked";
  return make("span", "tag " + className, String(status || "unknown").toUpperCase());
}

function deliveryText(email) {
  if (!email) return "No email action reported.";
  if (email.status === "delivered") {
    return "Confirmed by the transport.";
  }
  if (email.status === "accepted") {
    return "Gmail API accepted the request; delivery to the mailbox is not independently confirmed.";
  }
  if (email.status === "simulated") {
    return "Not sent: simulation mode. The message was composed and inspected only.";
  }
  if (email.status === "blocked") {
    return "Not sent: the backend policy blocked the action.";
  }
  if (email.status === "failed") {
    return "Not sent: the workflow reported an error.";
  }
  return "No delivery confirmation.";
}

function renderResults(run) {
  const body = el("result-body");
  const badge = el("result-badge");
  if (!body) return;
  if (!run) {
    body.replaceChildren(
      make(
        "p",
        "empty",
        "Run the demo to see the threat verdict, strategy outcome, and the email execution status."
      )
    );
    if (badge) {
      badge.className = "badge idle";
      badge.textContent = "PENDING";
    }
    return;
  }
  if (badge) {
    const state = run.state || "idle";
    badge.className = "badge " + state;
    if (state === "completed") {
      badge.textContent = run.decision && run.decision.outcome === "rejected"
        ? "COMPLETED / REJECTED"
        : "COMPLETED";
    } else {
      badge.textContent = String(state).toUpperCase();
    }
  }

  const rows = [];
  const verdict = run.evaluation && run.evaluation.verdict;
  if (verdict) {
    const value = document.createElement("div");
    value.appendChild(make("strong", null, String(verdict.decision || "unknown").toUpperCase()));
    value.appendChild(
      make(
        "span",
        "sub",
        "risk " +
          String(verdict.risk_level || "n/a") +
          " \u00b7 score " +
          fmtNum(verdict.risk_score) +
          " \u00b7 rules " +
          String(verdict.rule_version || "n/a")
      )
    );
    rows.push(resultRow("Threat verdict", [value]));
  }

  const hillclimb = run.hillclimb;
  if (hillclimb && run.decision) {
    const value = document.createElement("div");
    value.appendChild(
      make("strong", null, run.decision.outcome === "retained" ? "Retained" : "Rejected")
    );
    value.appendChild(
      make(
        "span",
        "sub",
        "candidate " +
          String(run.decision.candidate_id || "n/a") +
          " \u00b7 active " +
          String(run.decision.strategy_id || "n/a") +
          " \u00b7 ASR " +
          fmtPct(run.decision.baseline_asr) +
          " to " +
          fmtPct(run.decision.candidate_asr)
      )
    );
    rows.push(resultRow("Strategy outcome", [value]));
  }

  const email = run.email;
  if (email) {
    const value = document.createElement("div");
    value.appendChild(emailTag(email.status));
    value.appendChild(make("span", "sub", redactDigits(email.detail || "")));
    rows.push(resultRow("Email action", [value]));
    rows.push(resultRow("Delivery", deliveryText(email)));
    rows.push(
      resultRow(
        "Recipient",
        email.recipient ? redactDigits(String(email.recipient)) : "none configured"
      )
    );
  } else if (run.state === "running") {
    rows.push(resultRow("Email action", "pending"));
  }

  rows.push(resultRow("Execution mode", run.mode || "SIMULATION"));
  if (run.attack_email) {
    rows.push(
      resultRow(
        "Demo attack",
        String(run.attack_email.variant_name || "n/a") +
          " \u00b7 from " +
          String(run.attack_email.sender || "n/a")
      )
    );
  }
  if (run.audit && run.audit.event_id) {
    rows.push(resultRow("Audit run id", String(run.audit.event_id)));
  }
  if (email && email.audit_id) {
    rows.push(resultRow("Workflow audit recorded at", String(email.audit_id)));
  }
  if (run.error) {
    const note = make("p", "note-block err", "Failure: " + redactDigits(run.error));
    rows.push(note);
  } else if (run.state === "running") {
    rows.push(
      make("p", "note-block", "The run is still executing; this section fills in as stages report.")
    );
  }
  body.replaceChildren(...rows);
}

// ----------------------------------------------------------------- wiring --

function applyRun(payload) {
  if (!payload) return;
  const run = payload.run || null;
  client.run = run;
  renderTimeline(run ? run.stages : payload.stages, run);
  renderClimber(run);
  renderResults(run);
  setRunBadge(run ? run.state : "idle");
  setRunStatusLine();
  renderConnection();
}

async function refreshDemoStatus(silent) {
  if (!client.paired || client.pollInFlight) return;
  client.pollInFlight = true;
  const res = await backendPost("/nemesis/demo/status", null, client.nonce);
  client.pollInFlight = false;
  if (res.ok && res.data && res.data.demo) {
    applyRun(res.data.demo);
    return;
  }
  if (res.status === 401 || res.status === 403) {
    await handleAuthFailure();
    return;
  }
  if (!silent && el("run-status-line")) {
    setStatus(
      el("run-status-line"),
      "Status request failed: " +
        String((res.data && (res.data.error || res.data.detail)) || "HTTP " + res.status),
      "err"
    );
  }
}

function schedulePoll() {
  if (client.statusTimer) clearTimeout(client.statusTimer);
  client.statusTimer = setTimeout(async () => {
    client.statusTimer = null;
    await refreshDemoStatus(true);
    if (runIsActive(client.run)) schedulePoll();
  }, 900);
}

async function handleAuthFailure() {
  client.paired = false;
  await clearNonce();
  client.nonce = "";
  renderConnection();
  setRunStatusLine();
  setBanner("Pairing was rejected by the backend. Paste the current nonce to re-pair.", "err");
}

async function refreshConnection() {
  const health = await fetchHealth();
  client.health = health;
  client.online = Boolean(health);
  if (client.online && !client.nonce) {
    client.nonce = await loadNonce();
  }
  if (client.online && client.nonce) {
    const ping = await backendPost("/ping", null, client.nonce);
    if (ping.ok && ping.data && ping.data.state === "paired") {
      client.paired = true;
    } else if (ping.status === 401 || ping.status === 403) {
      client.paired = false;
    }
  } else {
    client.paired = false;
  }
  renderConnection();
  if (client.paired) {
    await loadWorkflowStatus();
    if (!client.run) await refreshDemoStatus(true);
  }
}

async function loadWorkflowStatus() {
  if (!client.paired) return;
  const res = await backendPost("/nemesis/workflow/status", null, client.nonce);
  if (!res.ok) {
    if (res.status === 401 || res.status === 403) {
      await handleAuthFailure();
    }
    return;
  }
  client.workflow = (res.data && res.data.workflow) || null;
  const kill = el("killswitch-btn");
  if (kill && client.workflow) {
    kill.disabled = Boolean(client.workflow.kill_switch);
    kill.textContent = client.workflow.kill_switch
      ? "Kill switch engaged"
      : "Engage kill switch";
  }
  renderConnection();
}

async function onPair() {
  const input = el("nonce");
  const nonce = input ? input.value.trim() : "";
  const status = el("pair-status");
  if (!nonce) {
    setStatus(status, "Paste the nonce printed by the backend terminal.", "err");
    return;
  }
  const res = await backendPost("/pair", {
    presented_nonce: nonce,
    extension_origin: extensionOrigin(),
  });
  if (res.ok && res.data && res.data.state === "paired") {
    await saveNonce(nonce);
    client.nonce = nonce;
    client.paired = true;
    if (input) input.value = "";
    setBanner("", "");
    renderConnection();
    await loadWorkflowStatus();
    await refreshDemoStatus(true);
    setStatus(status, "Paired with the local backend.", "ok");
    return;
  }
  setStatus(
    status,
    "Pairing failed: " +
      String((res.data && (res.data.error || res.data.hint)) || "HTTP " + res.status),
    "err"
  );
}

async function onUnpair() {
  if (!client.paired) return;
  await backendPost("/reset", null, client.nonce);
  await clearNonce();
  client.nonce = "";
  client.paired = false;
  client.workflow = null;
  renderConnection();
  setRunStatusLine();
  setBanner("Unpaired. Paste a fresh nonce to re-enable the demo.", "");
}

async function onKillSwitch() {
  if (!client.paired) return;
  const res = await backendPost("/nemesis/killswitch", null, client.nonce);
  if (res.ok) {
    setBanner("Kill switch engaged on the backend. The email action will be blocked.", "err");
    await loadWorkflowStatus();
  } else {
    setBanner(
      "Kill switch failed: " +
        String((res.data && res.data.error) || "HTTP " + res.status),
      "err"
    );
  }
}

async function onStartDemo() {
  if (client.busy || runIsActive(client.run)) return;
  client.busy = true;
  updateAvailability();
  const status = el("run-status-line");
  setStatus(status, "Starting the autonomous run...", "");
  const res = await backendPost("/nemesis/demo/run", {}, client.nonce);
  client.busy = false;
  if (!res.ok) {
    if (res.status === 409) {
      setStatus(status, "A run is already active; showing its progress.", "");
      await refreshDemoStatus(true);
      schedulePoll();
      updateAvailability();
      return;
    }
    if (res.status === 401 || res.status === 403) {
      await handleAuthFailure();
      updateAvailability();
      return;
    }
    setStatus(
      status,
      "Start failed: " +
        String((res.data && res.data.error) || "HTTP " + res.status || "unknown error"),
      "err"
    );
    updateAvailability();
    return;
  }
  applyRun(res.data.demo);
  schedulePoll();
}

async function onStopDemo() {
  if (!runIsActive(client.run)) return;
  const res = await backendPost("/nemesis/demo/stop", null, client.nonce);
  if (res.ok) {
    setStatus(el("run-status-line"), "Stop signalled; waiting for the run to halt.", "");
    await refreshDemoStatus(true);
    schedulePoll();
  } else {
    setStatus(
      el("run-status-line"),
      "Stop failed: " + String((res.data && res.data.error) || "HTTP " + res.status),
      "err"
    );
  }
}

function wire() {
  const pairBtn = el("pair-btn");
  if (pairBtn) pairBtn.addEventListener("click", onPair);
  const nonce = el("nonce");
  if (nonce) {
    nonce.addEventListener("keydown", (event) => {
      if (event.key === "Enter") onPair();
    });
  }
  const runBtn = el("demo-run-btn");
  if (runBtn) runBtn.addEventListener("click", onStartDemo);
  const stopBtn = el("demo-stop-btn");
  if (stopBtn) stopBtn.addEventListener("click", onStopDemo);
  const reset = el("reset-btn");
  if (reset) reset.addEventListener("click", onUnpair);
  const kill = el("killswitch-btn");
  if (kill) kill.addEventListener("click", onKillSwitch);

  renderTimeline([], null);
  renderClimber(null);
  renderResults(null);
  setRunBadge("idle");
  refreshConnection().then(() => {
    if (client.paired && !client.run) refreshDemoStatus(true);
  });
  setInterval(() => {
    refreshConnection();
  }, 5000);
}

document.addEventListener("DOMContentLoaded", wire);
