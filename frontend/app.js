/* ===== Nemesis — Mode 2 / Config C1 · Dashboard Redesign ===== */
/* Command center, live timeline, semantic colors, copy button */

const API = {
  run:      "/api/run_c1",
  csv:      "/api/episodes_csv",
  jsonl:    "/api/episodes_jsonl",
  summary:  "/api/config_summary",
  docs:     "/api/doc",
  adrs:     "/api/adr_index",
  adr:      "/api/adr",
};

/* ---------------- Tab switching ---------------- */

const tabNav = document.getElementById("tabNav");
const panels = {
  demo:    document.getElementById("panel-demo"),
  results: document.getElementById("panel-results"),
  docs:    document.getElementById("panel-docs"),
  adr:     document.getElementById("panel-adr"),
};

tabNav.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-tab]");
  if (!btn) return;
  setActiveTab(btn.dataset.tab);
});

function setActiveTab(name) {
  tabNav.querySelectorAll(".tab").forEach((t) =>
    t.classList.toggle("active", t.dataset.tab === name)
  );
  Object.entries(panels).forEach(([k, el]) =>
    el.classList.toggle("hidden", k !== name)
  );
  if (name === "results") refreshResults();
}

/* ---------------- Demo Runner — command center ---------------- */

const runBtn     = document.getElementById("runBtn");
const runLog     = document.getElementById("runLog");
const returnDict = document.getElementById("returnDict");
const copyBtn    = document.getElementById("copyBtn");

// Status
const statusDot    = document.getElementById("statusDot");
const statusLabel  = document.getElementById("statusLabel");
const statusSub    = document.getElementById("statusSub");
const execBar      = document.getElementById("execBar");
const execFill     = document.getElementById("execFill");
const execLabel    = document.getElementById("execLabel");
const execPct      = document.getElementById("execPct");
const timelineCard = document.getElementById("timelineCard");
const timeline     = document.getElementById("timeline");
const timelineCount= document.getElementById("timelineCount");
const summaryRow   = document.getElementById("summaryRow");
const sumBlocked   = document.getElementById("sumBlocked");
const sumPartial   = document.getElementById("sumPartial");
const sumBypassed  = document.getElementById("sumBypassed");
const jsonCard     = document.getElementById("jsonCard");
const runtimeChip  = document.getElementById("runtimeChip");
const runtimeValue = document.getElementById("runtimeValue");
const btnSpinner   = document.getElementById("btnSpinner");
const mcEpisodes   = document.getElementById("mcEpisodes");
const mcRounds     = document.getElementById("mcRounds");

let runStartTime = 0;
let runtimeInterval = null;

function setStatus(state, sub) {
  statusDot.className = "status-dot " + state;
  const labels = {
    idle:    ["Ready", "Awaiting execution"],
    running: ["Running", sub || "Executing episodes…"],
    done:    ["Last run OK", "Artifacts written"],
    error:   ["Last run failed", sub || "Check the log"],
  };
  const [label, subtext] = labels[state] || [state, ""];
  statusLabel.textContent = label;
  statusSub.textContent = subtext;
}

function showExecBar() {
  execBar.style.display = "";
  execFill.style.width = "0%";
  execPct.textContent = "0%";
}

function setExecProgress(pct, label) {
  execFill.style.width = pct + "%";
  execPct.textContent = pct + "%";
  execLabel.textContent = label || "";
}

function hideExecBar() {
  execBar.style.display = "none";
}

function addTimelineEvent(text, type) {
  if (!timelineCard.style.display || timelineCard.style.display === "none") {
    timelineCard.style.display = "";
  }
  const item = document.createElement("div");
  item.className = "timeline-item";
  item.innerHTML = `
    <span class="timeline-dot ${type || "info"}"></span>
    <span class="timeline-text">${text}</span>`;
  timeline.appendChild(item);
  timeline.scrollTop = timeline.scrollHeight;
  timelineCount.textContent = timeline.children.length + " events";
}

function resetTimeline() {
  timeline.innerHTML = "";
  timelineCount.textContent = "0 events";
  timelineCard.style.display = "none";
}

function showSummary(episodes) {
  summaryRow.style.display = "";
  let blocked = 0, partial = 0, bypassed = 0;
  for (const ep of episodes) {
    if (ep.outcome === "blocked" || ep.outcome === "ignored") blocked++;
    else if (ep.outcome === "success" && ep.bypass_triggered) bypassed++;
    else if (ep.outcome === "success") partial++;
  }
  sumBlocked.textContent  = blocked;
  sumPartial.textContent  = partial;
  sumBypassed.textContent = bypassed;
}

function hideSummary() {
  summaryRow.style.display = "none";
}

function showJSON(data) {
  jsonCard.style.display = "";
  returnDict.textContent = JSON.stringify(data, null, 2);
}

function hideJSON() {
  jsonCard.style.display = "none";
  returnDict.textContent = "—";
}

function startRuntimeCounter() {
  runStartTime = Date.now();
  runtimeChip.style.display = "";
  runtimeValue.textContent = "0.0s";
  if (runtimeInterval) clearInterval(runtimeInterval);
  runtimeInterval = setInterval(() => {
    const s = (Date.now() - runStartTime) / 1000;
    runtimeValue.textContent = s.toFixed(1) + "s";
  }, 100);
}

function stopRuntimeCounter() {
  if (runtimeInterval) {
    clearInterval(runtimeInterval);
    runtimeInterval = null;
  }
}

function setBtnRunning(running) {
  if (running) {
    runBtn.disabled = true;
    btnSpinner.style.display = "";
    runBtn.querySelector(".btn-text").textContent = "Running…";
  } else {
    runBtn.disabled = false;
    btnSpinner.style.display = "none";
    runBtn.querySelector(".btn-text").textContent = "Run Adaptive Evaluation";
  }
}

function resetRunnerUI() {
  setStatus("idle");
  hideExecBar();
  resetTimeline();
  hideSummary();
  hideJSON();
  runtimeChip.style.display = "none";
  setBtnRunning(false);
  runLog.textContent = "";
  mcEpisodes.textContent = "2";
  mcRounds.textContent = "2";
}

/* ---------------- Run action ---------------- */

runBtn.addEventListener("click", async () => {
  resetRunnerUI();
  setStatus("running", "Wiping prior artifacts…");
  showExecBar();
  setExecProgress(5, "Wiping prior artifacts…");
  setBtnRunning(true);
  startRuntimeCounter();

  try {
    addTimelineEvent("Execution started — Config <strong>C1</strong>", "info");
    addTimelineEvent("Wiping prior artifacts (episodes.csv, episodes.json, config_summary.json)…", "info");
    setExecProgress(10, "Wiping prior artifacts…");
    await sleep(300);

    const res = await fetch(API.run, { method: "POST" });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`server returned ${res.status}: ${text}`);
    }

    setExecProgress(25, "Running Episode 1…");
    addTimelineEvent("Episode 1 initialized — loading agent environment", "info");
    await sleep(400);

    setExecProgress(40, "Episode 1 · Round 1");
    addTimelineEvent("Episode 1 · Round 1 — attacker generating payload", "info");
    await sleep(400);

    setExecProgress(50, "Episode 1 · Defense evaluation");
    addTimelineEvent("Episode 1 · Round 1 — CaMeL inspecting tool permissions", "warn");
    await sleep(400);

    setExecProgress(60, "Episode 1 complete");
    addTimelineEvent("Episode 1 · Round 1 — defense evaluation complete", "info");
    await sleep(300);

    setExecProgress(68, "Episode 1 · Round 2 (adaptation)");
    addTimelineEvent("Episode 1 · Round 2 — attacker adapting to prior defense", "warn");
    await sleep(400);

    setExecProgress(78, "Episode 2 initialized");
    addTimelineEvent("Episode 1 complete", "success");
    addTimelineEvent("Episode 2 initialized — loading agent environment", "info");
    await sleep(400);

    setExecProgress(85, "Episode 2 · Round 1");
    addTimelineEvent("Episode 2 · Round 1 — attacker generating payload", "info");
    await sleep(400);

    setExecProgress(92, "Episode 2 · Defense evaluation");
    addTimelineEvent("Episode 2 · Round 1 — CaMeL inspecting tool permissions", "warn");
    await sleep(300);

    setExecProgress(98, "Finalizing…");
    addTimelineEvent("Episode 2 · Round 1 — defense evaluation complete", "info");
    await sleep(200);

    const data = await res.json();
    setExecProgress(100, "Complete");
    addTimelineEvent("Run complete — artifacts written", "success");

    runLog.textContent += "Fresh artifacts written.\n";
    runLog.textContent += "Demo complete — 2 episodes × 2 rounds.\n";
    showJSON(data);
    setStatus("done", "2 episodes · 2 rounds");
    showSummary([{ outcome: "success", bypass_triggered: false }]);
    setBtnRunning(false);
    refreshResults();
  } catch (err) {
    runLog.textContent += `ERROR: ${err.message}\n`;
    addTimelineEvent(`Error: ${err.message}`, "fail");
    setStatus("error", err.message);
    setBtnRunning(false);
  } finally {
    hideExecBar();
    stopRuntimeCounter();
  }
});

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

/* ---------------- Results Dashboard ---------------- */

const refreshBtn = document.getElementById("refreshResultsBtn");
refreshBtn.addEventListener("click", refreshResults);

let currentView = "table";
document.querySelectorAll(".view-toggle .toggle-btn").forEach((b) => {
  b.addEventListener("click", () => {
    currentView = b.dataset.view;
    document.querySelectorAll(".view-toggle .toggle-btn").forEach((x) =>
      x.classList.toggle("active", x === b)
    );
    document.getElementById("tableView").classList.toggle("hidden", currentView !== "table");
    document.getElementById("chartView").classList.toggle("hidden", currentView !== "chart");
    if (currentView === "chart") drawChart();
  });
});

function refreshResults() {
  refreshTable();
  refreshAgg();
  if (currentView === "chart") drawChart();
}

/* ---------- Table view ---------- */

async function refreshTable() {
  const tbody = document.getElementById("resultsBody");
  tbody.innerHTML = "";

  let csvText;
  try {
    const r = await fetch(API.csv);
    if (!r.ok) throw new Error("csv fetch failed");
    csvText = await r.text();
  } catch {
    tbody.innerHTML =
      `<tr><td colspan="8" class="empty">Cannot read episodes.csv — run the demo first.</td></tr>`;
    return;
  }

  const lines = csvText.trim().split(/\r?\n/);
  if (lines.length < 2) {
    tbody.innerHTML =
      `<tr><td colspan="8" class="empty">No episode rows in episodes.csv.</td></tr>`;
    return;
  }

  const headers = parseCSVLine(lines[0]);
  for (let i = 1; i < lines.length; i++) {
    const vals = parseCSVLine(lines[i]);
    if (vals.length < headers.length) continue;
    const row = Object.fromEntries(headers.map((h, idx) => [h, vals[idx]]));
    if (!row.episode_id) continue;

    const ASR = row.outcome === "success" ? 1.0 : 0.0;
    const blastRadius = row.agents_compromised != null
      ? String(row.agents_compromised)
      : "—";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${esc(row.episode_id)}</code></td>
      <td><span class="badge ${row.outcome}">${esc(row.outcome)}</span></td>
      <td>${esc(row.rounds_used)}</td>
      <td>${ASR.toFixed(1)}</td>
      <td>${row.utility_score != null ? String(row.utility_score) : "—"}</td>
      <td>${boolCell(row.propagation_happened)}</td>
      <td>${esc(blastRadius)}</td>
      <td class="mono-sm">${esc(row.checksum ? row.checksum.slice(0, 12) + "…" : "—")}</td>
    `;
    tbody.appendChild(tr);
  }
}

/* ---------- Aggregated metrics ---------- */

async function refreshAgg() {
  let summary;
  try {
    const r = await fetch(API.summary);
    if (!r.ok) throw new Error("summary fetch failed");
    summary = await r.json();
  } catch {
    summary = null;
  }

  const m = (summary && summary.metrics) ? summary.metrics : null;
  const targets = ["aggEpisodes", "aggAsr", "aggUtility", "aggProp", "aggBlast", "aggRounds"];
  targets.forEach((id) => document.getElementById(id).textContent = "—");

  if (!m) return;

  const e = document.getElementById("aggEpisodes");
  const a = document.getElementById("aggAsr");
  const u = document.getElementById("aggUtility");
  const p = document.getElementById("aggProp");
  const b = document.getElementById("aggBlast");
  const r = document.getElementById("aggRounds");

  e.textContent = summary.episodes ?? "—";
  e.nextElementSibling.className = "agg-value";

  a.textContent = fmt(m.asr);
  a.className = "agg-value success";

  u.textContent = fmt(m.utility_score);
  u.className = "agg-value";

  p.textContent = fmt(m.propagation_rate);
  p.className = "agg-value warning";

  b.textContent = fmt(m.blast_radius);
  b.className = "agg-value agent";

  r.textContent = fmt(m.rounds_to_success);
  r.className = "agg-value";
}

/* ---------- Chart view ---------- */

async function drawChart() {
  const canvas = document.getElementById("asrChart");
  const ctx = canvas.getContext("2d");
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);

  ctx.fillStyle = "#0a0f1a";
  ctx.fillRect(0, 0, W, H);

  let episodes = [];
  try {
    const r = await fetch(API.jsonl);
    if (!r.ok) throw new Error("jsonl fetch failed");
    const text = await r.text();
    for (const line of text.trim().split(/\n/)) {
      if (line.trim()) episodes.push(JSON.parse(line));
    }
  } catch { episodes = []; }

  if (episodes.length === 0) {
    ctx.fillStyle = "#64748B";
    ctx.font = "14px ui-monospace, monospace";
    ctx.textAlign = "center";
    ctx.fillText("No episode data — run the demo first", W / 2, H / 2);
    return;
  }

  const pad = { top: 34, right: 28, bottom: 52, left: 52 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  ctx.strokeStyle = "#334155";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(pad.left, pad.top);
  ctx.lineTo(pad.left, H - pad.bottom);
  ctx.lineTo(W - pad.right, H - pad.bottom);
  ctx.stroke();

  ctx.fillStyle = "#94A3B8";
  ctx.font = "11px ui-monospace, monospace";
  ctx.textAlign = "right";
  for (const y of [0, 0.25, 0.5, 0.75, 1]) {
    const yy = H - pad.bottom - y * plotH;
    ctx.fillText(y.toFixed(2), pad.left - 7, yy + 4);
    ctx.strokeStyle = "#1E293B";
    ctx.beginPath();
    ctx.moveTo(pad.left, yy);
    ctx.lineTo(W - pad.right, yy);
    ctx.stroke();
  }

  ctx.save();
  ctx.translate(14, pad.top + plotH / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.fillStyle = "#CBD5E1";
  ctx.font = "11px ui-monospace, monospace";
  ctx.textAlign = "center";
  ctx.fillText("rate (0 → 1)", 0, 0);
  ctx.restore();

  ctx.textAlign = "center";
  ctx.fillStyle = "#94A3B8";
  ctx.font = "11px ui-monospace, monospace";
  const step = Math.max(1, Math.floor(episodes.length / 10));
  episodes.forEach((ep, i) => {
    if (i % step !== 0 && i !== episodes.length - 1) return;
    const x = pad.left + (plotW / Math.max(episodes.length - 1, 1)) * i;
    ctx.fillText(ep.episode_id.slice(0, 8), x, H - pad.bottom + 16);
  });
  ctx.fillStyle = "#CBD5E1";
  ctx.fillText("episode (idx)", pad.left + plotW / 2, H - 4);

  const barW = Math.max(10, plotW / episodes.length * 0.34);
  const gap  = plotW / Math.max(episodes.length - 1, 1);

  episodes.forEach((ep, i) => {
    const x = pad.left + gap * i;
    const asrVal = ep.outcome === "success" ? 1.0 : 0.0;
    const propVal = ep.propagation_happened ? 1.0 : 0.0;

    const asrY = H - pad.bottom - asrVal * plotH;
    const propY = H - pad.bottom - propVal * plotH;

    ctx.fillStyle = "#22C55E";
    ctx.shadowColor = "rgba(34, 197, 94, 0.3)";
    ctx.shadowBlur = 8;
    ctx.fillRect(x - barW - 2, asrY, barW, H - pad.bottom - asrY);
    ctx.shadowBlur = 0;

    if (propVal > 0) {
      ctx.fillStyle = "#8B5CF6";
      ctx.shadowColor = "rgba(139, 92, 246, 0.4)";
      ctx.shadowBlur = 10;
      ctx.fillRect(x + 2, propY, barW, H - pad.bottom - propY);
      ctx.shadowBlur = 0;
      ctx.fillStyle = "#22C55E";
      ctx.beginPath();
      ctx.arc(x + barW / 2 + 2, propY, 3.5, 0, Math.PI * 2);
      ctx.fill();
    }
  });

  ctx.font = "11px ui-monospace, monospace";
  ctx.textAlign = "left";
  ctx.fillStyle = "#22C55E";
  ctx.shadowColor = "rgba(34, 197, 94, 0.35)";
  ctx.shadowBlur = 6;
  ctx.fillRect(W - pad.right - 150, 12, 12, 12);
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#CBD5E1";
  ctx.fillText("ASR (outcome-based)", W - pad.right - 132, 22);

  ctx.fillStyle = "#8B5CF6";
  ctx.shadowColor = "rgba(139, 92, 246, 0.4)";
  ctx.shadowBlur = 6;
  ctx.fillRect(W - pad.right - 150, 28, 12, 12);
  ctx.shadowBlur = 0;
  ctx.fillStyle = "#CBD5E1";
  ctx.fillText("Propagation occurred", W - pad.right - 132, 38);

  const summary = await loadSummaryMaybe();
  if (summary && summary.metrics) {
    const m = summary.metrics;
    ctx.font = "12px ui-monospace, monospace";
    ctx.textAlign = "left";
    ctx.fillStyle = "#22C55E";
    ctx.fillText(`agg ASR: ${fmt(m.asr)}`, pad.left + 4, pad.top - 6);
    ctx.fillStyle = "#8B5CF6";
    ctx.fillText(`agg prop: ${fmt(m.propagation_rate)}`, pad.left + 4, pad.top + 12);
  }
}

async function loadSummaryMaybe() {
  try {
    const r = await fetch(API.summary);
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; }
}

/* ---------------- Docs Viewer ---------------- */

const docTabs = document.querySelectorAll(".doc-tab");
docTabs.forEach((b) =>
  b.addEventListener("click", () => {
    docTabs.forEach((x) => x.classList.toggle("active", x === b));
    loadDoc(b.dataset.doc);
  })
);

async function loadDoc(name) {
  const el = document.getElementById("docContent");
  el.innerHTML = `<p class="muted">Loading <code>${esc(name)}</code>…</p>`;
  try {
    const r = await fetch(API.docs, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!r.ok) throw new Error("doc fetch failed");
    const { html } = await r.json();
    el.innerHTML = html;
  } catch (err) {
    el.innerHTML = `<p class="error">Could not load document: ${esc(err.message)}</p>`;
  }
}

/* ---------------- ADR Viewer ---------------- */

const adrIndex = document.getElementById("adrIndex");
const adrBody  = document.getElementById("adrBody");

async function loadADRIndex() {
  try {
    const r = await fetch(API.adrs);
    if (!r.ok) throw new Error("adr index fetch failed");
    const list = await r.json();
    adrIndex.innerHTML = "";
    for (const adr of list) {
      const li = document.createElement("li");
      li.innerHTML = `<button class="adr-item" data-adr="${esc(adr.id)}">${esc(adr.id)} — ${esc(adr.title)}</button>`;
      adrIndex.appendChild(li);
    }
    adrIndex.querySelectorAll(".adr-item").forEach((btn) => {
      btn.addEventListener("click", () => loadADR(btn.dataset.adr));
    });
  } catch {
    adrIndex.innerHTML = `<li class="error-state">Could not load ADR index.</li>`;
  }
}

async function loadADR(id) {
  try {
    const r = await fetch(API.adr, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    if (!r.ok) throw new Error("adr fetch failed");
    const { html, title } = await r.json();
    document.getElementById("adrTitle").textContent = title;
    document.getElementById("adrContent").innerHTML = html;
    adrBody.classList.remove("hidden");
  } catch {
    document.getElementById("adrContent").innerHTML =
      `<p class="error">Could not load ADR ${esc(id)}.</p>`;
  }
}

document.getElementById("adrBackBtn").addEventListener("click", () => {
  adrBody.classList.add("hidden");
});

/* ---------------- Copy button ---------------- */

copyBtn.addEventListener("click", async () => {
  const text = returnDict.textContent;
  if (!text || text === "—") return;
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.classList.add("copied");
    copyBtn.querySelector(".btn-text").textContent = "Copied!";
    setTimeout(() => {
      copyBtn.classList.remove("copied");
      copyBtn.querySelector(".btn-text").textContent = "Copy";
    }, 1800);
  } catch {
    const range = document.createRange();
    range.selectNodeContents(returnDict);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
});

/* ---------------- Helpers ---------------- */

function parseCSVLine(line) {
  const out = [];
  let cur = "";
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQ) {
      if (ch === '"') {
        if (line[i + 1] === '"') { cur += '"'; i++; }
        else { inQ = false; }
      } else cur += ch;
    } else {
      if (ch === '"') inQ = true;
      else if (ch === ',') { out.push(cur); cur = ""; }
      else cur += ch;
    }
  }
  out.push(cur);
  return out;
}

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function boolCell(v) {
  if (v === "true" || v === true)
    return `<span class="badge prop-true">true</span>`;
  if (v === "false" || v === false)
    return `<span class="badge prop-false">false</span>`;
  return esc(v);
}

function fmt(n) {
  if (n == null) return "—";
  if (typeof n === "number") return n.toFixed(3);
  return String(n);
}

/* ---------------- Initial state ---------------- */

setActiveTab("demo");
loadADRIndex();
