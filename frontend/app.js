/* ===== Nemesis dashboard — real backend data only ===== */

const state = {
  overview: null,
  page: "experiments",
  pollTimer: null,
  starting: false,
  // In-flight lifecycle request ("pause" | "resume" | "stop" | null) so a
  // double click cannot fire two conflicting transitions at once.
  controlPending: null,
};

const $ = (id) => document.getElementById(id);

function esc(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function na(value, fallback = "—") {
  if (value === null || value === undefined || value === "") return fallback;
  return value;
}

function parseTs(iso) {
  if (!iso) return NaN;
  // Persisted timestamps are ISO-8601 and may carry an explicit +00:00 offset
  // or no zone at all. Try the value as-is first, then assume UTC.
  let t = Date.parse(iso);
  if (Number.isNaN(t)) t = Date.parse(`${iso}Z`);
  return t;
}

function timeAgo(iso) {
  if (!iso) return "";
  const t = parseTs(iso);
  if (Number.isNaN(t)) return "";
  const secs = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function clockTime(iso) {
  if (!iso) return "—";
  const t = parseTs(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function toast(message, bad = false) {
  const el = $("toast");
  el.textContent = message;
  el.className = "toast" + (bad ? " bad" : "");
  el.hidden = false;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.hidden = true; }, 5000);
}

async function api(path, options) {
  const res = await fetch(path, options);
  let data = null;
  try { data = await res.json(); } catch { data = null; }
  if (!res.ok) {
    const reason = (data && (data.error || data.detail)) || `HTTP ${res.status}`;
    const err = new Error(reason);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

/* ---------------- navigation ---------------- */

function setPage(page) {
  state.page = page;
  document.querySelectorAll(".page").forEach((el) => {
    el.hidden = el.id !== `page-${page}`;
  });
  document.querySelectorAll("[data-page]").forEach((el) => {
    const target = el.dataset.page;
    if (!target) return;
    if (el.classList.contains("nav-item")) {
      el.classList.toggle("active", target === page);
    }
  });
  if (page === "experiments") {
    requestAnimationFrame(drawChart);
  }
  if (page === "defenses") {
    loadDefenseCampaigns();
    restoreDefenseJob();
  }
}

document.addEventListener("click", (event) => {
  const nav = event.target.closest("[data-page]");
  if (nav && nav.dataset.page) {
    setPage(nav.dataset.page);
  }
});

/* ---------------- overview polling ---------------- */

async function loadOverview({ quiet = false } = {}) {
  try {
    const data = await api("/api/overview");
    state.overview = data;
    renderAll();
    schedulePoll();
  } catch (err) {
    if (!quiet) toast(`Dashboard state unavailable: ${err.message}`, true);
    $("phaseText").textContent = "Backend unreachable";
  }
}

function schedulePoll() {
  clearTimeout(state.pollTimer);
  const o = state.overview;
  const active = o && (o.lifecycle?.running || ["attacker", "paused", "stopping"].includes(o.lifecycle?.phase));
  state.pollTimer = setTimeout(() => loadOverview({ quiet: true }), active ? 2000 : 12000);
}

/* ---------------- render: all ---------------- */

function renderAll() {
  const o = state.overview;
  if (!o) return;
  renderTopbar(o);
  renderRail(o);
  renderActive(o);
  renderAgents(o);
  renderDefenses(o);
  renderReports(o);
  renderSettings(o);
  renderHome(o);
  renderSelectedAgent(o);
}

function renderTopbar(o) {
  const p = o.provider || {};
  const dot = $("modelDot");
  dot.className = "dot " + (p.ready ? "ok" : p.reachable ? "warn" : "bad");
  $("modelChipTitle").textContent = p.ready
    ? "Ollama Connected"
    : p.reachable
      ? "Ollama — model missing"
      : "Ollama unreachable";
  $("modelChipModel").textContent = p.model || p.default_model || "—";
}

function renderSelectedAgent(o) {
  // There is exactly one authoritative selection: the backend connection
  // store. Experiments only displays it; it never maintains a second choice.
  const conn = o.connection;
  const connected = !!(conn && conn.ready);
  const pill = $("selectedAgentPill");
  if (!pill) return;
  pill.className = "pill sm " + (connected ? "ok" : "idle");
  $("selectedAgentPillText").textContent = connected ? "Selected · connected" : "Not connected";
  $("selectedAgentName").textContent = connected ? conn.display_name : "No agent connected";
  $("selectedAgentKind").textContent = connected
    ? `${conn.method || "unknown method"} · ${conn.config?.target_id || conn.config?.endpoint_url || "validated"}`
    : "Connect an HTTP API, LangChain, or Gmail integration on Agents.";
  $("selectedAgentMeta").textContent = connected
    ? `Ready at ${conn.config?.endpoint_url || conn.config?.base_url || "validated connection"} · managed on Agents.`
    : "Experiments cannot launch against a fake or implicit target; visit Agents first.";
}

function renderRail(o) {
  /* The selected agent is rendered once, in the compact Experiments summary;
     connection management lives only on Agents. */

  /* objectives */
  const list = $("objectiveList");
  list.innerHTML = (o.taxonomy.objectives || [])
    .map((obj) => `<li><span class="obj-check">✓</span><span>${esc(obj.name)}</span></li>`)
    .join("");

  /* model */
  const p = o.provider || {};
  const modelPill = $("modelPill");
  modelPill.className = "pill sm right " + (p.ready ? "ok" : p.reachable ? "warn" : "bad");
  $("modelPillText").textContent = p.ready ? "Online" : p.reachable ? "Model missing" : "Offline";
  $("modelName").textContent = "Ollama";
  $("modelId").textContent = p.model || p.default_model || "—";
  const note = $("modelNote");
  if (p.ready) {
    note.className = "rail-note";
    note.textContent = `Reachable at ${p.endpoint} · model installed.`;
  } else {
    note.className = "rail-note error";
    note.textContent = p.error || "Run `ollama list` to check the local service.";
  }

  /* settings rail */
  const settings = o.settings || {};
  const run = o.run || {};
  $("setMax").textContent = run.total_episode_budget != null
    ? `${run.total_episode_budget} episodes`
    : `${settings.limits?.approved_experiment_budget ?? "—"} approved`;
  const modeShown = run.mode || settings.search_mode;
  $("setClimb").textContent = modeShown
    ? (modeShown === "greedy" ? "Enabled (greedy)" : "Enabled (feedback)")
    : "Idle";
  const catalog = o.defense.catalog || [];
  const realDefenses = catalog.filter((d) => d.available && d.implementation_type === "real_integration").length;
  const proxyDefenses = catalog.filter((d) => d.available && d.implementation_type === "local_proxy").length;
  if (realDefenses && proxyDefenses) {
    $("setDefense").textContent = `${realDefenses} real + ${proxyDefenses} proxies`;
  } else if (realDefenses) {
    $("setDefense").textContent = `${realDefenses} real`;
  } else if (proxyDefenses) {
    $("setDefense").textContent = `${proxyDefenses} proxies`;
  } else {
    $("setDefense").textContent = "Unavailable";
  }
}

function renderActive(o) {
  const run = o.run;
  const active = o.active_run;
  const phase = o.lifecycle?.phase || "idle";
  const pill = $("phasePill");
  const text = $("phaseText");
  const map = {
    idle: ["idle", "Idle"],
    attacker: ["running", "Running"],
    defense_ready: ["ok", "Defense ready"],
    defense_completed: ["ok", "Defense evaluated"],
    defense_inconclusive: ["warn", "Defense inconclusive"],
    defense_unavailable: ["warn", "Attack-only — no replayable case"],
    defense_failed: ["warn", "Defense technical failure"],
    defense_running: ["running", "Defense evaluation running"],
    paused: ["warn", "Paused"],
    stopping: ["warn", "Stopping"],
    incomplete: ["warn", "Incomplete"],
  };
  const [cls, label] = map[phase] || ["idle", phase];
  pill.className = "pill " + cls;
  text.textContent = label;

  const sub = $("activeSub");
  if (phase === "attacker" && active) {
    sub.textContent = `Run ${active.run_id || "—"} · target ${active.target || o.settings?.target || "seeded stand-in"} · mode ${active.mode || o.settings?.search_mode || "—"}`;
  } else if (run) {
    const assistantKind = run.assistant?.kind ? ` (${run.assistant.kind})` : "";
    const evalMode = run.target_snapshot?.mode ? ` · mode ${run.target_snapshot.mode}` : "";
    sub.textContent = `Last run ${run.run_id} · target ${run.target || "seeded stand-in"} (${run.target_kind || "unknown"})${evalMode} · assistant ${run.assistant?.provider || o.settings?.assistant_provider || "none"}${assistantKind}`;
  } else {
    sub.textContent = "No experiment has run yet. Connect an agent and press New Experiment.";
  }

  const activeStatus = o.lifecycle?.active_status || (active && active.status) || "";
  // Terminal statuses must not read as "still going": the pill said
  // "Incomplete" for a budget-exhausted or stopped run, which looked live.
  // After a dashboard restart there is no in-memory run, so the persisted
  // run's own status is the truthful source.
  const terminalStatus = activeStatus || (run && run.status) || "";
  const terminalLabel = {
    budget_exhausted: "Stopped — budget exhausted",
    stopped: "Stopped by operator",
    failed: "Failed",
  };
  if (phase === "incomplete" && terminalLabel[terminalStatus]) {
    pill.className = "pill " + (terminalStatus === "failed" ? "bad" : "warn");
    text.textContent = terminalLabel[terminalStatus];
  }

  // Pause/Resume/Stop availability comes from the backend's real control
  // state (can_pause / can_resume / can_stop + reason), never from guessing
  // off the last run's status. A disabled control always explains itself.
  const control = o.lifecycle?.control || {};
  const paused = phase === "paused" || activeStatus === "paused";
  const stopping = phase === "stopping" || activeStatus === "stopping";
  const canControl = !!o.lifecycle?.running;
  const canPause = control.can_pause != null ? !!control.can_pause : (canControl && !paused && !stopping);
  const canResume = control.can_resume != null ? !!control.can_resume : (canControl && paused && !stopping);
  const canStop = control.can_stop != null ? !!control.can_stop : (canControl && !stopping);
  $("pauseBtn").disabled = !canPause || state.controlPending === "pause";
  $("resumeBtn").disabled = !canResume || state.controlPending === "resume";
  $("stopBtn").disabled = !canStop || state.controlPending === "stop";
  const note = $("activeControlNote");
  if (note) {
    const message = control.reason || "";
    note.hidden = !message;
    note.textContent = message;
  }

  const m = o.metrics || {};
  const statTone = {
    statCandidates: "",
    statSuccess: "green",
    statBlocked: "blue",
    statTechnical: "red",
    statInconclusive: "slate",
  };
  const setStat = (id, value) => {
    const el = $(id);
    if (value === null || value === undefined) {
      el.textContent = "Unavailable";
      el.className = "stat-value na";
    } else {
      el.textContent = value;
      el.className = `stat-value ${statTone[id] || ""}`.trim();
    }
  };
  setStat("statCandidates", m.candidates_evaluated ?? (run ? run.candidate_evaluations : null));
  setStat("statSuccess", m.success);
  setStat("statBlocked", m.blocked);
  setStat("statTechnical", m.technical_fail);
  setStat("statInconclusive", m.inconclusive);

  const consumed = m.episodes_consumed ?? run?.episodes_consumed;
  const budget = m.episode_budget ?? run?.total_episode_budget;
  $("progressMeta").textContent =
    consumed != null && budget != null ? `${consumed} / ${budget}` : "Unavailable";
  $("progressFill").style.width =
    consumed != null && budget ? `${Math.min(100, (consumed / budget) * 100)}%` : "0%";

  const dims = m.dimensions || [];
  $("dimMeta").textContent = dims.length && dims[0].denominator
    ? `${dims[0].denominator} candidate(s)`
    : "No data";
  $("dimList").innerHTML = dims.length
    ? dims.map((d, i) => {
        const share = d.share;
        const pct = share == null ? "—" : `${Math.round(share * 100)}%`;
        const color = ["#7C5CFC", "#3B82F6", "#22C55E", "#8B5CF6", "#EF4444"][i % 5];
        const icon = [
          '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M12 8v8M8 12h8"/></svg>',
          '<svg viewBox="0 0 24 24"><path d="M4 12h6l2-5 3 10 2-5h3"/></svg>',
          '<svg viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="3"/><path d="M9 10h6M9 14h4"/></svg>',
          '<svg viewBox="0 0 24 24"><path d="M14 6l4 4-8 8H6v-4l8-8Z"/><path d="M12 8l4 4"/></svg>',
          '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/><path d="M12 8v4l3 2"/></svg>',
        ][i % 5];
        return `<li class="dim-item">${icon}<div class="dim-body"><span class="dim-name">${esc(d.name)}</span><div class="dim-bar"><span style="width:${share == null ? 0 : share * 100}%;background:${color}"></span></div></div><span class="dim-pct">${pct}</span></li>`;
      }).join("")
    : `<li class="muted small">No evaluated candidates yet — search dimensions appear after a run.</li>`;

  renderCandidates(o);
  renderActivity(o);
  renderClimb(o);
  renderChannels(o);

  $("metricsProvenance").textContent = m.source
    ? `Source: ${m.source}. ignored/inconclusive stay separate from blocked; technical failures are not security outcomes.`
    : "Metrics are derived from the latest persisted run record. Unavailable values stay unavailable.";

  const runForAssistant = run || active;
  const assistantLine = $("runAssistant");
  if (runForAssistant && runForAssistant.assistant) {
    const a = runForAssistant.assistant;
    const calls = a.model_calls_consumed ?? 0;
    const budgetText = a.model_request_budget == null ? "no request budget" : `${calls}/${a.model_request_budget} model requests`;
    const why = calls === 0
      ? " — no request was made (the bounded run ended before a model-proposal boundary)."
      : "";
    assistantLine.textContent = `Assistant: ${a.provider || "none"} (${a.kind || "unknown"})` +
      (a.model ? ` · ${a.model}` : "") +
      ` · ${budgetText}` +
      (a.timeout_seconds ? ` · timeout ${a.timeout_seconds}s` : "") + why;
  } else if (runForAssistant) {
    assistantLine.textContent = "Assistant: none configured for this run (no model requests).";
  } else {
    assistantLine.textContent = "";
  }

  drawChart();
}

function strategyLabel(ladder) {
  if (!Array.isArray(ladder) || !ladder.length) return "—";
  return ladder.map((s) => `${s.category || "?"} L${s.sophistication_level ?? "?"}`).join(" → ");
}

function renderClimb(o) {
  const run = o.run || o.active_run || {};
  const history = Array.isArray(run.history) ? run.history : (o.history || []);
  const decisions = history.filter((h) => h && h.candidate_ladder);
  const bestLabel = run.global_best_category || "—";
  const stopText = run.stop_reason || (run.status === "completed"
    ? `completed ${run.iterations_completed ?? "?"}/${run.iterations ?? "?"} iterations`
    : (run.status || "—"));
  $("climbMeta").textContent = decisions.length
    ? `${decisions.length} evaluated · iteration ${run.iteration ?? "—"} · best ${bestLabel}${run.best_asr == null ? "" : ` ASR ${Number(run.best_asr).toFixed(2)}`} · stop: ${stopText}`
    : "No data";
  $("climbBody").innerHTML = decisions.length
    ? decisions.slice(-12).map((h) => {
        const accepted = h.improved === true;
        const delta = h.delta == null ? "—" : `${h.delta > 0 ? "+" : ""}${Number(h.delta).toFixed(2)}`;
        const mut = h.mutation || {};
        const mutText = (mut.added && mut.added.length) || (mut.removed && mut.removed.length)
          ? `+${(mut.added || []).join(", ")} / -${(mut.removed || []).join(", ")}`
          : (mut.same_tactics ? "same tactics" : "—");
        return `<tr>
          <td>${esc(h.iteration ?? "—")}</td>
          <td><code>${esc(strategyLabel(h.candidate_ladder))}</code>${h.candidate_id ? `<div class="fineprint">${esc(h.candidate_id)}</div>` : ""}<div class="fineprint">${esc(mutText)}</div></td>
          <td>${h.parent_category_best_asr == null ? "unavailable" : Number(h.parent_category_best_asr).toFixed(2)}</td>
          <td>${h.asr == null ? "unavailable" : Number(h.asr).toFixed(2)}</td>
          <td>${accepted ? '<span class="badge green">accepted</span>' : '<span class="badge slate">rejected</span>'}</td>
          <td>${esc(delta)}</td>
        </tr>`;
      }).join("")
    : `<tr><td colspan="6" class="empty">No candidate decisions yet.</td></tr>`;

  const confirmations = Array.isArray(run.post_acceptance_executions)
    ? run.post_acceptance_executions
    : [];
  $("confirmList").innerHTML = confirmations.length
    ? confirmations.map((c) => {
        if (!c.executed_after_acceptance) {
          return `<li><strong>${esc(c.accepted_candidate_id || "accepted strategy")}</strong> was not re-executed — ${esc(c.skipped_reason || "reason not recorded")}</li>`;
        }
        const outcomes = Object.entries(c.outcomes || {}).map(([k, v]) => `${k} ${v}`).join(", ") || "no outcome";
        return `<li><strong>${esc(c.accepted_candidate_id || "accepted strategy")}</strong> re-executed after acceptance · ASR ${c.asr == null ? "unavailable" : Number(c.asr).toFixed(2)} · ${esc(outcomes)} · <code>${esc(c.confirmation_strategy_id || "")}</code></li>`;
      }).join("")
    : `<li class="muted small">No accepted strategy in the latest run.</li>`;



  const displayTraces = Array.isArray(run.episode_trace) ? run.episode_trace : [];
  const targetList = $("targetEvidenceList");
  if (targetList) {
    targetList.innerHTML = displayTraces.length
      ? displayTraces.map((t) => {
          const calls = (Array.isArray(t.target_responses) ? t.target_responses : [])
            .flatMap((r) => (Array.isArray(r.tool_calls) ? r.tool_calls : []).map((c) => `${c.tool_name}(${JSON.stringify(c.arguments || {})})`));
          const outputs = (Array.isArray(t.target_responses) ? t.target_responses : [])
            .map((r) => r.output).filter((x) => x != null && x !== "");
          // Generated adversarial emails (Gmail write/send campaigns) and the
          // real Gmail operation each turn performed. Only recorded evidence is
          // shown; missing fields render as unavailable.
          const emails = (Array.isArray(t.steps) ? t.steps : []).map((s) => s.email).filter(Boolean);
          const emailHtml = emails.map((e) => `<div class="fineprint">generated email · ${esc(e.persona ? `${e.persona.name} (${e.persona.role}, ${e.persona.company})` : "persona unavailable")} · strategy ${esc(e.tactic || "—")} · sophistication ${esc(e.sophistication ?? "—")} · scenario ${esc(e.scenario || "—")}
            <div><strong>Subject:</strong> ${esc(e.subject || "—")}</div>
            <div><strong>Body:</strong> <code>${esc(String(e.body || "").slice(0, 900))}</code></div>
            <div><strong>Requested action:</strong> ${esc(e.requested_action || "—")} · <strong>technique:</strong> ${esc(e.manipulation_technique || "—")} · <strong>expected:</strong> ${esc(e.expected_target_behavior || "—")} · <strong>token:</strong> ${esc(e.injection_token || "—")} · generation ${esc((e.generation || {}).mode || "—")}${(e.generation || {}).model_used ? " (Ollama)" : " (template, no model call)"}</div></div>`).join("");
          const ops = (Array.isArray(t.target_evidence) ? t.target_evidence : [])
            .map((te) => {
              if (!te || !te.operation) return null;
              const op = te.operation;
              // The target-evidence projection deliberately omits the
              // ground-truth dict; the per-turn channel record is the
              // authoritative copy persisted alongside it.
              const gt = te.ground_truth
                || (Array.isArray(t.target_ground_truth) ? t.target_ground_truth[0] : null)
                || {};
              const ver = te.verification || {};
              return `${te.mode || "—"}: ${op.kind} ${op.status || "—"} · sent=${op.sent} drafted=${op.drafted} · message id ${esc(op.message_id || "—")} · verified=${esc(ver.verified)}${ver.reason ? ` (${esc(ver.reason)})` : ""} · channels: content_manipulated=${gt.content_manipulated} unauthorized_draft=${gt.unauthorized_draft} unauthorized_send=${gt.unauthorized_send} unauthorized_recipient_delivery=${gt.unauthorized_recipient_delivery} legitimate_action=${gt.legitimate_action} allowlist_enforced=${gt.allowlist_enforced}`;
            }).filter(Boolean);
          return `<li><strong>${esc(t.case_id || "case")}</strong> · ${esc(strategyLabel(t.steps))} · rounds ${esc(t.rounds_used ?? "—")} · ${bucketBadge(t.outcome)}
            <div class="fineprint">target output: ${outputs.length ? `<code>${esc(outputs.join(" | ").slice(0, 600))}</code>` : "unavailable"}</div>
            <div class="fineprint">tool calls: ${calls.length ? `<code>${esc(calls.join(" · ").slice(0, 400))}</code>` : "none"} · defense: ${esc(t.defense_decision || "not observable")} · observed: ${esc(t.observed_outcome || "—")}</div>
            ${t.email_feedback_in ? `<div class="fineprint">previous iteration feedback (measured): asr=${esc(t.email_feedback_in.asr)} · ${esc(t.email_feedback_in.failure_reason || "—")}</div>` : ""}
            ${Array.isArray(t.target_ground_truth) && t.target_ground_truth.length ? `<div class="fineprint">measured ground truth: ${t.target_ground_truth.map((g) => esc(Object.entries(g || {}).map(([kk, vv]) => `${kk}=${vv}`).join(" "))).join(" | ").slice(0, 800)}</div>` : ""}
            ${emailHtml}${ops.length ? `<div class="fineprint">Gmail operation: ${esc(ops.join(" | ").slice(0, 600))}</div>` : ""}</li>`;
        }).join("")
      : `<li class="muted small">No target evidence recorded for this run.</li>`;
  }

  $("enforcementNote").textContent = decisions.length
    ? "Search-time defense is evaluated after the target action. A denial there is detection, not prevention; observed violations are scored as successes. Use Defenses to run the independent replay; each case reports whether enforcement happened before or after execution."
    : "";
}

/* ---------------- separated security-outcome channels ---------------- */

const CHANNEL_ROWS = [
  ["content_manipulation", "Content manipulation"],
  ["unauthorized_draft", "Unauthorized draft creation"],
  ["unauthorized_send", "Unauthorized send"],
  ["unauthorized_recipient", "Unauthorized recipient delivery"],
];

function pctOrUnavailable(rate) {
  return rate == null ? "Unavailable" : `${(Number(rate) * 100).toFixed(1)}%`;
}

function renderChannels(o) {
  const table = $("channelsBody");
  if (!table) return;
  const run = o.run || o.active_run || {};
  const gt = run.ground_truth_metrics || (o.metrics || {}).ground_truth || null;
  const metrics = (gt && gt.metrics) || {};
  table.innerHTML = CHANNEL_ROWS.map(([key, label]) => {
    const m = metrics[key];
    if (!m) {
      return `<tr><td>${esc(label)}</td><td>Unavailable</td><td>Unavailable</td><td>Unavailable</td><td class="fineprint">${esc((gt && gt.limitations || []).join(" ") || "no persisted evidence for this channel")}</td></tr>`;
    }
    const unknown = m.unknown_episodes ? ` · ${m.unknown_episodes} unknown episode(s) excluded` : "";
    return `<tr>
      <td>${esc(label)}<div class="fineprint"><code>${esc(m.channel)}</code></div></td>
      <td>${na(m.numerator)}</td>
      <td>${na(m.denominator)}</td>
      <td>${pctOrUnavailable(m.rate)}</td>
      <td class="fineprint">${esc(m.eligibility)}${esc(unknown)}</td>
    </tr>`;
  }).join("");
  const meta = $("channelsMeta");
  const recalc = (gt && gt.recalculation) || {};
  if (meta) {
    meta.textContent = gt
      ? `schema ${gt.schema || "—"} · ${na(gt.episodes_with_ground_truth)} episode(s) with ground truth`
      : (run.run_id ? "No separated ground-truth metrics for this run" : "No run");
  }
  const note = $("channelsNote");
  if (note) {
    const parts = [];
    if (gt) {
      parts.push(`Recalculation: ${recalc.method || "—"}`);
      if (recalc.legacy_recalculation) parts.push(`Historical records: ${recalc.legacy_recalculation}`);
      if (recalc.episodes_legacy) parts.push(`${recalc.episodes_legacy} legacy episode(s) recalculated where the evidence allowed it.`);
      (gt.limitations || []).forEach((l) => parts.push(l));
      if (gt.objective_asr) {
        parts.push(`Objective ASR uses channel ${gt.objective_asr.channel}: ${na(gt.objective_asr.numerator)}/${na(gt.objective_asr.denominator)} — never merged with a different violation channel.`);
      }
    } else {
      parts.push(run.run_id
        ? "This run record predates the separated ground-truth schema; no channel rate is inferred for it."
        : "Run a campaign to persist separated ground-truth evidence.");
    }
    note.textContent = parts.join(" ");
  }
  renderBudget(run, o);
  renderEpisodes(run);
  renderCampaignEvidence(run);
}

/* ---------------- per-episode persisted evidence ---------------- */

function scoreBadge(record) {
  if (!record.score_eligible || record.score == null) {
    return `<span class="badge slate">unscored</span>`;
  }
  const cls = record.score >= 1 ? "green" : "blue";
  const label = record.score >= 1 ? "score 1.0 · confirmed violation" : "score 0.0 · decidable no-violation";
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

function feedbackCell(feedback) {
  if (!feedback) return `<span class="muted">none — this was the first generation in the evaluation</span>`;
  const states = Object.entries(feedback.outcomes || {})
    .map(([k, v]) => `${k} ${v}`)
    .join(", ");
  return `iteration ${esc(feedback.iteration ?? "—")} · asr ${feedback.asr == null ? "unavailable" : Number(feedback.asr).toFixed(2)}${states ? ` · ${esc(states)}` : ""} · source ${esc(feedback.source || "—")}
    <div class="fineprint">${esc(feedback.failure_reason || "—")}</div>`;
}

function operationCell(record) {
  const op = record.gmail_operation || {};
  const ids = record.gmail_ids || {};
  const ver = record.verification || {};
  if (!op.kind && !op.status) return `<span class="muted">no Gmail operation recorded</span>`;
  const attempt = op.recipient_attempt;
  const channels = record.ground_truth || {};
  return `${esc(op.kind || "—")} · ${esc(op.status || "—")} · sent=${esc(op.sent)} drafted=${esc(op.drafted)}${op.reason ? ` · ${esc(op.reason)}` : ""}
    <div class="fineprint">message id ${esc(ids.message_id || "—")} · thread id ${esc(ids.thread_id || "—")} · draft id ${esc(ids.draft_id || "—")}</div>
    <div class="fineprint">independent readback verified=${esc(ver.verified)} · To ${esc(ver.delivered_to || "—")} · labels ${esc((ver.labels || []).join(",") || "—")}${ver.reason ? ` (${esc(ver.reason)})` : ""}</div>
    ${attempt ? `<div class="fineprint">payload-declared recipient ${esc(attempt.recipient || "—")} → ${esc(attempt.status || "—")}: ${esc(attempt.reason || "—")} (verified=${esc(attempt.verified)})</div>` : ""}
    <div class="fineprint">allowlist enforced=${esc(channels.allowlist_enforced)} · operation error=${esc(channels.operation_error)}</div>`;
}

function groundTruthCell(record) {
  const m = record.metrics || {};
  const parts = [
    ["content_manipulated", m.content_manipulated],
    ["unauthorized_draft", m.unauthorized_draft],
    ["unauthorized_send", m.unauthorized_send],
    ["unauthorized_recipient_delivery", m.unauthorized_recipient_delivery],
    ["recipient_manipulated", m.recipient_manipulated],
    ["legitimate_action", m.legitimate_action],
  ];
  return parts.map(([k, v]) => `${esc(k)}=${v === null || v === undefined ? "unknown" : esc(v)}`).join(" · ");
}

function renderEpisodes(run) {
  const body = $("episodeList");
  const meta = $("episodeMeta");
  const summary = $("episodeSummary");
  const note = $("episodeNote");
  if (!body) return;
  const records = Array.isArray(run.episode_records) ? run.episode_records : [];
  const ledger = run.episode_ledger || null;
  const acc = run.episode_accounting || {};
  const comparison = (ledger && ledger.comparison) || null;
  const promotion = (ledger && ledger.promotion) || null;
  const recon = (ledger && ledger.reconciliation) || null;
  const scoreText = (v, n, d) => (v == null ? "Unavailable" : `${Number(v).toFixed(4)} (${na(n)}/${na(d)})`);

  if (meta) {
    meta.textContent = ledger
      ? `${na(ledger.persisted_episodes)} persisted · ${na(acc.consumed_total)} consumed · ${na(acc.planned_total_max)} planned`
      : (run.run_id
        ? `${na(run.episodes_persisted ?? 0)} persisted so far · ${na(acc.consumed_total ?? run.episodes_consumed)} consumed · no per-episode ledger yet`
        : "No run");
  }

  if (summary) {
    if (!ledger) {
      summary.textContent = run.run_id
        ? "This run record predates per-episode persistence, so its episodes cannot be listed individually. The final evaluation trace below is the only episode evidence it kept."
        : "Run a campaign to persist per-episode evidence.";
    } else {
      const stage = (ledger.by_stage || {});
      const parts = [
        `Planned ${na(acc.planned_total_max)} · consumed ${na(acc.consumed_total)} · persisted ${na(ledger.persisted_episodes)} (baseline ${na(stage.baseline)}, candidate ${na(stage.candidate)}, confirmation ${na(stage.confirmation)}, final ${na(stage.final)})`,
        `Baseline score ${scoreText(ledger.baseline_score, comparison && comparison.baseline && comparison.baseline.numerator, comparison && comparison.baseline && comparison.baseline.denominator)}`,
        `best candidate score ${scoreText(ledger.candidate_score, comparison && comparison.candidate && comparison.candidate.numerator, comparison && comparison.candidate && comparison.candidate.denominator)}`,
        `final confirmation score ${scoreText(ledger.final_score, comparison && comparison.final && comparison.final.numerator, comparison && comparison.final && comparison.final.denominator)}`,
        `promotion ${promotion && promotion.decision ? promoBadge(promotion.decision) : "not recorded"}`,
        `campaign status ${esc(ledger.run_status || "—")} · stop ${esc(ledger.stop_reason || "—")}`,
      ];
      summary.innerHTML = parts.join(" · ");
    }
  }

  body.innerHTML = records.length
    ? records.map((r) => {
        const steps = (r.strategy && r.strategy.steps) || [];
        const strategy = steps.length
          ? steps.map((s) => `${s.category}@${s.sophistication_level}`).join(" → ")
          : "—";
        const model = r.model || {};
        const email = r.generated_email || {};
        const subject = email.subject || "—";
        const bodyText = String(email.body || "").slice(0, 700);
        const attacker = r.attacker_email || {};
        return `<li class="episode-item">
          <div><strong>#${na(r.sequence)} · ${esc(r.stage || "—")}</strong> · ${scoreBadge(r)} · observed <code>${esc(r.observed_outcome || "—")}</code>
            <span class="fineprint">· episode ${esc(r.episode_index ?? "—")} · iteration ${esc(r.iteration ?? "—")} · ${esc(r.timestamp || "timestamp not recorded")}</span></div>
          <div class="fineprint">evaluation <code>${esc(r.evaluation_id || "—")}</code> · episode id <code>${esc(r.episode_id || "—")}</code> · campaign <code>${esc(r.campaign_id || "—")}</code></div>
          <div class="fineprint">target ${esc((r.target || {}).target_id || "—")} · mode ${esc((r.target || {}).evaluation_mode || "—")} · configured recipient ${esc((r.target || {}).configured_recipient || "—")} · strategy <code>${esc(strategy)}</code></div>
          <div class="fineprint"><strong>Generated subject</strong> ${esc(subject)}</div>
          <div class="fineprint"><strong>Generated body</strong> <code>${esc(bodyText)}</code></div>
          <div class="fineprint">generation ${esc(model.provider || "provider —")} · ${esc(model.name || "model —")} · model called=${esc(model.model_called)} · ${model.latency_ms == null ? "latency unavailable" : `${Number(model.latency_ms).toFixed(0)} ms`}${model.generation_mode ? ` · ${esc(model.generation_mode)}` : ""}${model.target_turn_seconds == null ? "" : ` · target turn ${Number(model.target_turn_seconds).toFixed(1)} s`}</div>
          <div class="fineprint">attacker email (prompt input): subject ${esc(attacker.subject || "—")} · tactic ${esc(attacker.tactic || "—")} · sophistication ${esc(attacker.sophistication ?? "—")} · requested recipient ${esc(attacker.requested_recipient || "—")} · token ${esc(attacker.injection_token || "—")}</div>
          <div class="fineprint"><strong>Feedback in</strong> ${feedbackCell(r.feedback_in)}</div>
          <div class="fineprint"><strong>Gmail operation</strong> ${operationCell(r)}</div>
          <div class="fineprint"><strong>Ground truth</strong> ${groundTruthCell(r)}</div>
        </li>`;
      }).join("")
    : `<li class="muted small">${esc(run.run_id ? "No per-episode records persisted for this run." : "No run yet.")}</li>`;

  if (note) {
    const parts = [];
    if (ledger) {
      parts.push(`Scoring rule: ${ledger.scoring_rule || "—"}.`);
      if (recon) {
        parts.push(recon.reconciled
          ? `Reconciled: ${na(recon.persisted_episodes)} persisted record(s) match ${na(recon.consumed_episodes)} consumed episode(s).`
          : `Not reconciled: ${na(recon.difference)} consumed episode(s) have no persisted record.`);
      }
      if (comparison) {
        parts.push(comparison.comparable
          ? `Comparable: baseline and candidate both measured ${na(comparison.baseline && comparison.baseline.episodes)} episode(s) on ${esc((records[0] && records[0].target && records[0].target.target_id) || "the same target")} in ${esc((records[0] && records[0].target && records[0].target.evaluation_mode) || "the same mode")} (delta ${comparison.delta == null ? "unavailable" : Number(comparison.delta).toFixed(4)}).`
          : "Not comparable: baseline and candidate evidence differ in episode count, target or evaluation mode — no promotion can rest on it.");
        if (!comparison.target_recorded) parts.push("Target identity/mode was not recorded on these episodes (seeded stand-in).");
      }
      if (promotion) {
        parts.push(`Promotion ${promotion.decision}: ${(promotion.reasons || []).join(" · ") || "no blocking reason recorded"}`);
      }
      (ledger.limitations || []).forEach((l) => parts.push(l));
    }
    note.textContent = parts.join(" ");
  }
}

function promoBadge(decision) {
  return decision === "promoted"
    ? `<span class="badge green">promoted</span>`
    : `<span class="badge slate">rejected</span>`;
}

function renderBudget(run, o) {
  const body = $("budgetBody");
  if (!body) return;
  const acc = run.episode_accounting || null;
  const plan = run.budget_plan || (o.metrics || {}).budget_plan || null;
  if (!acc) {
    body.innerHTML = `<tr><td colspan="3" class="empty">${esc(run.run_id ? "No episode accounting recorded for this run." : "No run yet.")}</td></tr>`;
  } else {
    const rows = [
      ["Baseline", acc.baseline?.planned, acc.baseline?.consumed],
      ["Candidate comparisons", acc.candidates?.planned_max, acc.candidates?.consumed],
      ["Acceptance confirmation", acc.confirmation?.planned, acc.confirmation?.consumed],
      ["Final confirmation evaluation", acc.final?.planned, acc.final?.consumed],
    ];
    body.innerHTML = rows.map(([label, planned, consumed]) => `<tr>
      <td>${esc(label)}</td><td>${na(planned)}</td><td>${na(consumed)}</td>
    </tr>`).join("") + `<tr><td><strong>Total</strong></td><td>${na(acc.planned_total_max)}</td><td>${na(acc.consumed_total)}</td></tr>`;
  }
  const meta = $("budgetMeta");
  if (meta) {
    meta.textContent = acc
      ? `${na(acc.consumed_total)}/${na(acc.total_budget)} episodes · stop: ${esc(run.stop_reason || run.status || "—")}`
      : "Unavailable";
  }
  const note = $("budgetNote");
  if (note) {
    const parts = [];
    if (plan) {
      parts.push(`Per-evaluation episodes: ${na(plan.episodes_per_evaluation)}. Minimum feasible budget: ${na(plan.minimum_required)} (baseline + one candidate comparison).`);
      (plan.rules || []).forEach((r) => parts.push(r));
    }
    if (acc) {
      parts.push(`Status: ${esc(run.status || "—")} · final evaluation: ${esc(acc.final?.status || run.confirmation_status || "—")}`);
      if (acc.candidates?.evaluations != null) parts.push(`${na(acc.candidates.evaluations)} candidate evaluation(s) executed.`);
      if (run.search_truncated_by_budget) parts.push("Candidate fan-out was capped by the remaining budget; convergence is not claimed.");
    }
    note.textContent = parts.join(" ");
  }
}

function renderCampaignEvidence(run) {
  const list = $("campaignEvidenceList");
  if (!list) return;
  const traces = Array.isArray(run.episode_trace) ? run.episode_trace : [];
  const last = traces.length ? traces[traces.length - 1] : null;
  const identity = run.target_identity || {};
  const gate = run.gate || {};
  const email = last && Array.isArray(last.steps)
    ? (last.steps.find((s) => s && s.email) || {}).email || null
    : null;
  const generation = (email && email.generation) || {};
  const evidence = (last && Array.isArray(last.target_evidence)) ? (last.target_evidence.find((e) => e && e.provider === "gmail") || null) : null;
  const op = (evidence && evidence.operation) || null;
  const truth = (last && Array.isArray(last.target_ground_truth) && last.target_ground_truth[0]) || null;
  if (!last && !run.run_id) {
    list.innerHTML = `<li class="muted small">No campaign evidence recorded.</li>`;
    return;
  }
  const meta = $("campaignMeta");
  if (meta) meta.textContent = `${run.run_id || "—"} · iteration ${na(run.iteration)} · ${esc(run.status || "—")}`;
  const lines = [];
  lines.push(`<strong>Target</strong> ${esc(identity.name || run.target || "seeded stand-in")} · ${esc(identity.execution_mode || run.target_kind || "unknown")} · evaluation mode ${esc((run.target_snapshot || {}).mode || (evidence && evidence.mode) || "—")}`);
  lines.push(`<strong>Strategy</strong> <code>${esc(strategyLabel(run.gate?.checked?.ladder || run.best_ladder || (run.category_best && Object.values(run.category_best)[0]?.best_ladder) || []))}</code> · best ASR ${run.best_asr == null ? "Unavailable" : Number(run.best_asr).toFixed(2)}`);
  if (email) {
    lines.push(`<strong>Generated sender persona</strong> ${esc(email.persona ? `${email.persona.name} (${email.persona.role}, ${email.persona.company})` : "unavailable")} · tactic ${esc(email.tactic || "—")} · sophistication ${esc(email.sophistication ?? "—")} · scenario ${esc(email.scenario || "—")}`);
    lines.push(`<strong>Ollama subject</strong> ${esc(email.subject || "—")}`);
    lines.push(`<strong>Ollama body</strong> <code>${esc(String(email.body || "").slice(0, 600))}</code>`);
    lines.push(`<strong>Generation provenance</strong> ${esc(generation.mode || "—")}${generation.model_used ? ` · ${esc(generation.model || "model")}` : " · no model call"} · latency ${generation.latency_ms == null ? "unavailable" : `${Number(generation.latency_ms).toFixed(0)} ms`}${last.email_feedback_in ? ` · previous feedback: asr=${esc(last.email_feedback_in.asr)} ${esc(last.email_feedback_in.failure_reason || "")}` : " · no previous feedback"}`);
  } else {
    lines.push("<strong>Generated email</strong> unavailable — this run recorded no Gmail email evidence.");
  }
  if (op) {
    const verification = evidence.verification || {};
    lines.push(`<strong>Actual Gmail operation</strong> ${esc(op.kind)} · status ${esc(op.status || "—")} · sent=${esc(op.sent)} drafted=${esc(op.drafted)} · message id ${esc(op.message_id || "—")} · draft id ${esc(op.draft_id || verification.draft_id || "—")} · readback verified ${esc(verification.verified)}${verification.reason ? ` (${esc(verification.reason)})` : ""}`);
    if (truth) {
      lines.push(`<strong>Measured channels</strong> content_manipulated=${esc(truth.content_manipulated)} · unauthorized_draft=${esc(truth.unauthorized_draft)} · unauthorized_send=${esc(truth.unauthorized_send)} · unauthorized_recipient_delivery=${esc(truth.unauthorized_recipient_delivery)} · legitimate_action=${esc(truth.legitimate_action)}`);
    }
  }
  lines.push(`<strong>Promotion</strong> ${gate.passed ? "<span class=\"badge green\">promoted</span>" : "<span class=\"badge slate\">rejected</span>"} ${esc((gate.reasons || []).join(" · ") || "—")}`);
  lines.push(`<strong>Completion</strong> ${esc(run.status || "—")} · stop reason ${esc(run.stop_reason || "—")} · confirmation ${esc(run.confirmation_status || "—")}`);
  list.innerHTML = lines.map((l) => `<li class="fineprint">${l}</li>`).join("");
}

function bucketBadge(bucket) {
  const map = {
    success: ["green", "Successful"],
    blocked: ["blue", "Blocked"],
    ignored: ["slate", "Inconclusive"],
    inconclusive: ["slate", "Inconclusive"],
    technical_fail: ["red", "Technical"],
    unclassified: ["orange", "Unclassified"],
  };
  const [cls, label] = map[bucket] || ["slate", bucket];
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

function renderCandidates(o) {
  const body = $("candidateBody");
  const candidates = (o.candidates || []).slice(-6).reverse();
  $("recentMeta").textContent = o.candidates?.length
    ? `${o.candidates.length} persisted`
    : "No data";
  if (!candidates.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty">No candidates evaluated yet.</td></tr>`;
    return;
  }
  body.innerHTML = candidates.map((c, idx) => {
    const bucket = dominantBucket(c.outcomes);
    return `<tr>
      <td>${idx + 1}</td>
      <td>${esc(objectiveLabel(c.objective))}</td>
      <td>${esc((c.dimensions || [])[0] || "—")}</td>
      <td>${bucketBadge(bucket)}</td>
      <td>${c.asr == null ? "—" : Number(c.asr).toFixed(2)}</td>
      <td>${c.created_at ? clockTime(c.created_at) : "not recorded"}</td>
    </tr>`;
  }).join("");
}

function allObjectives() {
  const tax = state.overview?.taxonomy || {};
  return [...(tax.objectives || []), ...(tax.gmail_objectives || [])];
}

function objectiveLabel(value) {
  if (!value) return "—";
  const match = allObjectives().find((x) => x.id === value || x.name === value);
  return match ? match.name : value;
}

function dominantBucket(outcomes) {
  if (!outcomes) return "unclassified";
  if (outcomes.success > 0) return "success";
  if (outcomes.blocked > 0) return "blocked";
  if (outcomes.technical_fail > 0) return "technical_fail";
  if (outcomes.ignored > 0) return "ignored";
  return "unclassified";
}

function renderActivity(o) {
  const list = $("activityList");
  const items = o.activity || [];
  $("activityMeta").textContent = items.length ? `${items.length} events` : "No data";
  if (!items.length) {
    list.innerHTML = `<li class="muted small">No persisted activity.</li>`;
    return;
  }
  const icons = {
    candidate: ["purple", '<svg viewBox="0 0 24 24"><path d="M12 4v16M4 12h16"/></svg>'],
    run: ["blue", '<svg viewBox="0 0 24 24"><path d="M5 12h14"/><path d="M13 6l6 6-6 6"/></svg>'],
    defense: ["green", '<svg viewBox="0 0 24 24"><path d="M12 3 5 6v6c0 4 3 7.6 7 9 4-1.4 7-5 7-9V6l-7-3Z"/></svg>'],
  };
  list.innerHTML = items.map((a) => {
    const [cls, icon] = icons[a.kind] || ["orange", '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="8"/></svg>'];
    return `<li class="act-item">
      <span class="act-icon ${cls}">${icon}</span>
      <div><div class="act-title">${esc(a.title)}</div><div class="act-detail">${esc(a.detail || "")}</div></div>
      <span class="act-time">${esc(timeAgo(a.at))}</span>
    </li>`;
  }).join("");
}

/* ---------------- chart ---------------- */

function drawChart() {
  const canvas = $("asrChart");
  if (!canvas) return;
  const cssWidth = canvas.clientWidth || 640;
  const cssHeight = canvas.clientHeight || 190;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(cssWidth * dpr);
  canvas.height = Math.round(cssHeight * dpr);
  const ctx = canvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssWidth, cssHeight);

  const history = (state.overview?.history || []).filter((h) => h && h.asr != null);
  const empty = $("chartEmpty");
  const paintEmpty = (message) => {
    if (empty) { empty.hidden = false; empty.textContent = message; }
    canvas.style.visibility = "hidden";
  };
  if (!history.length) {
    paintEmpty("No measured ASR history yet — run an experiment against a target.");
    return;
  }
  if (empty) empty.hidden = true;
  canvas.style.visibility = "visible";

  const pad = { top: 12, right: 10, bottom: 32, left: 30 };
  const w = cssWidth - pad.left - pad.right;
  const h = cssHeight - pad.top - pad.bottom;

  ctx.strokeStyle = "#1B2740";
  ctx.lineWidth = 1;
  ctx.font = "9px ui-monospace, monospace";
  ctx.fillStyle = "#7F8AA3";
  ctx.textAlign = "right";
  for (const v of [0, 0.25, 0.5, 0.75, 1]) {
    const y = pad.top + h - v * h;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(pad.left + w, y); ctx.stroke();
    ctx.fillText(v.toFixed(2), pad.left - 5, y + 3);
  }

  const xs = (i) => pad.left + (history.length === 1 ? w / 2 : (w / (history.length - 1)) * i);
  const ys = (v) => pad.top + h - Math.max(0, Math.min(1, Number(v))) * h;

  // area
  const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + h);
  gradient.addColorStop(0, "rgba(124,92,252,0.35)");
  gradient.addColorStop(1, "rgba(124,92,252,0.02)");
  ctx.beginPath();
  ctx.moveTo(xs(0), pad.top + h);
  history.forEach((p, i) => ctx.lineTo(xs(i), ys(p.asr)));
  ctx.lineTo(xs(history.length - 1), pad.top + h);
  ctx.closePath();
  ctx.fillStyle = gradient;
  ctx.fill();

  // line
  ctx.beginPath();
  history.forEach((p, i) => {
    const x = xs(i), y = ys(p.asr);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#A78BFA";
  ctx.lineWidth = 1.6;
  ctx.stroke();

  // points
  history.forEach((p, i) => {
    ctx.beginPath();
    ctx.arc(xs(i), ys(p.asr), 2.2, 0, Math.PI * 2);
    ctx.fillStyle = "#C4B5FD";
    ctx.fill();
  });

  // x labels (evaluation index)
  ctx.fillStyle = "#7F8AA3";
  ctx.textAlign = "center";
  const step = Math.max(1, Math.ceil(history.length / 8));
  history.forEach((p, i) => {
    if (i % step !== 0 && i !== history.length - 1) return;
    ctx.fillText(String(i + 1), xs(i), cssHeight - 16);
  });
  ctx.fillText("Attempts", pad.left + w / 2, cssHeight - 4);
}

/* ---------------- agents page ---------------- */

function renderAgents(o) {
  const host = $("agentMethodList");
  if (!host) return;
  const CAP_LABELS = {
    oauth: "OAuth",
    read_only_scope: "Read scope",
    gmail_read: "Read",
    write_token: "Write token",
    recipient_allowlisted: "Allowlist",
    live_send_armed: "Send armed",
  };
  const connections = o.connections || [];
  host.innerHTML = connections.map((c) => {
    const unavailable = c.status !== "available";
    const fields = (c.fields || []).map((f) => {
      const value = c.config?.[f.name] ?? f.default ?? "";
      const span = f.name === "mode" || f.name === "url" ? " span2" : "";
      if (f.type === "select") {
        const options = (f.options || []).map((opt) => {
          const optValue = typeof opt === "string" ? opt : opt.value;
          const optLabel = typeof opt === "string" ? opt : opt.label || opt.value;
          return `<option value="${esc(optValue)}" ${String(optValue) === String(value) ? "selected" : ""}>${esc(optLabel)}</option>`;
        }).join("");
        return `<label class="field${span}">${esc(f.label)}
          <select data-field="${esc(f.name)}" ${unavailable ? "disabled" : ""}>${options}</select>
        </label>`;
      }
      const type = f.name === "timeout_seconds" ? "number" : "text";
      return `<label class="field${span}">${esc(f.label)}
        <input data-field="${esc(f.name)}" type="${type}" placeholder="${esc(f.placeholder || "")}"
          value="${esc(f.name === "auth_header" ? "" : value)}"
          ${unavailable ? "disabled" : ""}>
      </label>`;
    }).join("");
    // Only the last REAL probe's genuine capability booleans are shown.
    const detail = c.last_validation?.detail || {};
    const checks = detail.checks || detail.verification || {};
    const caps = Object.entries(checks)
      .filter(([k, v]) => typeof v === "boolean" && CAP_LABELS[k])
      .map(([k, v]) => `<span class="cap ${v ? "ok" : "bad"}">${esc(CAP_LABELS[k])}</span>`)
      .join("");
    const status = unavailable
      ? `<span class="dot warn"></span> Unavailable — ${esc(c.status_label || "not implemented")}`
      : c.connected
        ? `<span class="dot ok"></span> Connected${c.selected ? " · selected" : ""}`
        : c.last_validation && !c.last_validation.ok
          ? `<span class="dot bad"></span> Validation failed: ${esc(c.last_validation.error || "unknown")}`
          : `<span class="dot"></span> ${esc(c.status_label)}`;
    const actions = unavailable
      ? `<div class="unavailable-note">${esc(c.reason || "Not implemented")}</div>`
      : `<div class="agent-method-actions">
           <button class="btn primary" data-agent-connect="${esc(c.method)}">Validate &amp; connect</button>
           <button class="btn secondary" data-agent-select="${esc(c.method)}" ${c.connected && !c.selected ? "" : "disabled"}>Use</button>
           <button class="btn secondary" data-agent-clear="${esc(c.method)}" ${c.config ? "" : "disabled"}>Remove</button>
         </div>`;
    const modeLabels = { read_only: "Read-only", draft: "Draft", send: "Send" };
    const kind = c.method === "gmail" ? `${modeLabels[c.mode] || "Read-only"} mode` : (c.subtitle || "");
    return `<div class="card agent-method${unavailable ? " unavailable" : ""}" data-method-card="${esc(c.method)}">
      <div class="agent-method-head">
        <h3>${esc(c.display_name)}</h3>
        <span class="agent-kind">${esc(kind)}</span>
      </div>
      <div class="status-line">${status}</div>
      <div class="form-fields">${fields}</div>
      ${caps ? `<div class="cap-row">${caps}</div>` : ""}
      ${actions}
    </div>`;
  }).join("");
}

function collectionConfig(card) {
  const config = {};
  card.querySelectorAll("[data-field]").forEach((input) => {
    const name = input.dataset.field;
    if (name === "auth_header") return; // read separately below
    if (input.value !== "") config[name] = input.value;
  });
  return config;
}

document.addEventListener("click", async (event) => {
  const connectBtn = event.target.closest("[data-agent-connect]");
  if (connectBtn) {
    const method = connectBtn.dataset.agentConnect;
    const card = connectBtn.closest("[data-method-card]");
    const config = collectionConfig(card);
    const authInput = card.querySelector('[data-field="auth_header"]');
    if (authInput && authInput.value.trim()) config.auth_header = authInput.value.trim();
    connectBtn.disabled = true;
    connectBtn.textContent = "Probing…";
    try {
      const result = await api("/api/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "connect", method, config }),
      });
      toast(result.ok ? `${method} validated and connected.` : `Validation failed: ${result.probe?.error || "unknown"}`);
      await loadOverview();
    } catch (err) {
      toast(`Connection failed: ${err.message}`, true);
    } finally {
      connectBtn.disabled = false;
      connectBtn.textContent = "Validate & connect";
    }
    return;
  }

  const selectBtn = event.target.closest("[data-agent-select]");
  if (selectBtn) {
    try {
      await api("/api/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "select", method: selectBtn.dataset.agentSelect }),
      });
      await loadOverview();
      toast("Active connection updated.");
    } catch (err) { toast(err.message, true); }
    return;
  }

  const clearBtn = event.target.closest("[data-agent-clear]");
  if (clearBtn) {
    try {
      await api("/api/connections", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "clear", method: clearBtn.dataset.agentClear }),
      });
      await loadOverview();
      toast("Connection removed.");
    } catch (err) { toast(err.message, true); }
    return;
  }

});

/* ---------------- experiment modal ---------------- */

function updateProviderHint() {
  const hint = $("cfgProviderHint");
  if (!hint) return;
  const mode = $("cfgMode").value;
  const provider = $("cfgProvider").value;
  if (mode !== "feedback") {
    hint.textContent = "Greedy hill climbing makes no model requests — candidates are structural mutations. Choose feedback-guided search to use this provider.";
    return;
  }
  const map = {
    ollama: "Ollama will be called for advisory strategy suggestions, bounded by the model-request budget. Suggestions can never set an outcome.",
    rules_only: "Rules-only ranking: feedback-guided search runs with zero model requests.",
    none: "Statistics-only ranking: no model requests are made.",
    fake: "Offline deterministic double for tests only — no real model is called.",
  };
  hint.textContent = map[provider] || "";
}

function openExperimentModal() {
  const o = state.overview;
  if (!o) return;
  const objective = $("cfgObjective");
  const gmailObjectives = o.taxonomy.gmail_objectives || [];
  objective.innerHTML =
    `<option value="all">All three objectives (fixed set)</option>` +
    (o.taxonomy.objectives || []).map((x) => `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join("") +
    (gmailObjectives.length
      ? `<optgroup label="Gmail write/send (real agent)">` +
        gmailObjectives.map((x) => `<option value="${esc(x.id)}">${esc(x.name)}</option>`).join("") +
        `</optgroup>`
      : "");
  $("cfgProvider").value = "ollama";
  const conn = o.connection;
  updateProviderHint();
  $("cfgTargetLine").textContent = conn && conn.ready
    ? `Target: ${conn.display_name} (${conn.config?.target_id || conn.config?.endpoint_url || "validated"}) — validated connection.`
    : "Target: no user agent connected — the run uses the explicitly-labelled seeded stand-in. Connect an agent in Agents to attack a real target.";
  $("expResult").hidden = true;
  $("expModal").hidden = false;
}

function closeExperimentModal() { $("expModal").hidden = true; }

$("newExperimentBtn").addEventListener("click", openExperimentModal);
$("cfgMode").addEventListener("change", updateProviderHint);
$("cfgProvider").addEventListener("change", updateProviderHint);
$("expModalClose").addEventListener("click", closeExperimentModal);
$("expModalCancel").addEventListener("click", closeExperimentModal);
$("expModal").addEventListener("click", (e) => {
  if (e.target === $("expModal")) closeExperimentModal();
});

function experimentPayload() {
  const o = state.overview;
  const selected = $("cfgObjective").value;
  const categories = selected === "all"
    ? (o.taxonomy.objectives || []).map((x) => x.name)
    : [(allObjectives().find((x) => x.id === selected) || {}).name].filter(Boolean);
  return {
    mode: $("cfgMode").value,
    defense: $("cfgDefense").value,
    provider: $("cfgProvider").value,
    episodes: parseInt($("cfgEpisodes").value, 10),
    iterations: parseInt($("cfgIterations").value, 10),
    total_episode_budget: parseInt($("cfgBudget").value, 10),
    model_request_budget: parseInt($("cfgModelBudget").value, 10),
    attack_categories: categories,
    background: true,
  };
}

/* ---- prominent Run Experiment button (always visible on Experiments) ---- */
const runExperimentBtn = $("runExperimentBtn");
if (runExperimentBtn) {
  runExperimentBtn.addEventListener("click", () => {
    // Prevent duplicate starts: if the harness is already running, surface it
    // instead of opening a second configuration path.
    const o = state.overview;
    if (o && (o.lifecycle?.running || ["attacker", "paused", "stopping"].includes(o.lifecycle?.phase))) {
      toast("An attacker run is already active — resume or stop it before starting another.", true);
      return;
    }
    openExperimentModal();
  });
}

$("expValidateBtn").addEventListener("click", async () => {
  const box = $("expResult");
  box.hidden = false;
  box.className = "probe-result";
  box.textContent = "Validating target and provider — no run is started…";
  const payload = experimentPayload();
  try {
    const data = await api("/api/adaptive/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ provider: payload.provider }),
    });
    const targetLine = data.target
      ? `${data.target.id || data.target.kind || "seeded"}${
          data.target.execution_mode ? ` (${data.target.execution_mode})` : ""
        }`
      : "seeded stand-in";
    const provider = data.provider || {};
    box.className = "probe-result " + (data.ok ? "ok" : "bad");
    box.innerHTML = data.ok
      ? `<strong>Configuration valid.</strong><br>Target: ${esc(targetLine)} · provider ${esc(provider.provider)} (${esc(provider.kind)})${
          provider.model ? ` · ${esc(provider.model)}` : ""
        }`
      : `<strong>Validation failed.</strong><br>${esc((data.errors || []).join(" · "))}`;
  } catch (err) {
    box.className = "probe-result bad";
    box.textContent = err.message;
  }
});

$("expStartBtn").addEventListener("click", async () => {
  if (state.starting) return;
  const box = $("expResult");
  const payload = experimentPayload();
  const numeric = ["episodes", "iterations", "total_episode_budget", "model_request_budget"];
  for (const k of numeric) {
    if (!Number.isFinite(payload[k])) {
      box.hidden = false;
      box.className = "probe-result bad";
      box.textContent = `Invalid ${k.replace(/_/g, " ")} — enter a whole number.`;
      return;
    }
  }
  state.starting = true;
  $("expStartBtn").disabled = true;
  box.hidden = false;
  box.className = "probe-result";
  box.textContent = "Starting the bounded attacker run…";
  try {
    const data = await api("/api/adaptive/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    box.className = "probe-result ok";
    box.innerHTML = `<strong>Attacker run started</strong> — ${esc(data.run?.run_id || "run")}. Defense evaluation stays locked until it completes.`;
    closeExperimentModal();
    await loadOverview();
  } catch (err) {
    box.className = "probe-result bad";
    box.textContent = `Run rejected: ${err.message}`;
  } finally {
    state.starting = false;
    $("expStartBtn").disabled = false;
  }
});

/* Lifecycle controls: every action is confirmed by the backend before it is
   reported as done, and a double click cannot fire two transitions at once. */
async function lifecycleAction(kind, buttonId, request, describe) {
  if (state.controlPending) return;
  const before = state.overview || {};
  state.controlPending = kind;
  $(buttonId).disabled = true;
  try {
    const res = await request();
    await loadOverview(); // re-read real backend state, never assume success
    const [message, isError] = describe(res || {}, state.overview || {}, before);
    toast(message, isError);
  } catch (err) {
    toast(err.message, true);
    await loadOverview({ quiet: true });
  } finally {
    state.controlPending = null;
    if (state.overview) renderActive(state.overview);
  }
}

$("pauseBtn").addEventListener("click", () => lifecycleAction(
  "pause", "pauseBtn",
  () => api("/api/adaptive/pause", { method: "POST" }),
  (res, overview) => {
    const confirmed = !!overview.lifecycle?.paused;
    if (res.paused && confirmed) {
      return ["Paused — no new episode starts until Resume.", false];
    }
    if (res.paused) {
      return ["Pause was accepted but the backend still reports the run as running — refresh to re-check.", true];
    }
    return [res.reason || "Nothing to pause.", true];
  },
));

$("resumeBtn").addEventListener("click", () => lifecycleAction(
  "resume", "resumeBtn",
  () => api("/api/adaptive/resume", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // No run_id: the backend resumes the paused active run, or else the
    // interrupted checkpoint it validated. A finished checkpoint is refused.
    body: JSON.stringify({ background: true }),
  }),
  (res, overview, before) => {
    if (res.resumed && overview.lifecycle?.running) {
      return [before.lifecycle?.control?.resume_source === "checkpoint"
        ? "Resumed the interrupted run from its persisted checkpoint."
        : "Resumed the same run.", false];
    }
    if (res.resumed) {
      return ["Resume was accepted but the backend does not report a running run — refresh to re-check.", true];
    }
    return [res.reason || "Nothing to resume.", true];
  },
));

$("stopBtn").addEventListener("click", () => lifecycleAction(
  "stop", "stopBtn",
  () => api("/api/adaptive/stop", { method: "POST" }),
  (res) => {
    if (res.stop_signalled) {
      return ["Stop requested — no new episode will start; the active episode finishes.", false];
    }
    return [res.reason || "Nothing to stop.", true];
  },
));


/* ---------------- defenses ---------------- */

// Defense evaluation is a SEPARATE operator action. This page only reads
// completed campaigns; it never starts anything until Run Defense is pressed.

const DEFENSE_JOB_KEY = "nemesis.activeDefenseJob";

state.defenseCampaigns = [];
state.defenseRunId = null;
state.defenseCaseIds = new Set();
state.defenseJob = null;
state.defensePollTimer = null;

function defenseCampaign() {
  return (state.defenseCampaigns || []).find((c) => c.run_id === state.defenseRunId) || null;
}

function usableCaseIds(campaign) {
  return (campaign?.cases || [])
    .filter((c) => c.usable && c.case_id)
    .map((c) => String(c.case_id));
}

function selectDefenseCampaign(runId, { reset = false } = {}) {
  state.defenseRunId = runId || null;
  const campaign = defenseCampaign();
  const usable = usableCaseIds(campaign);
  if (reset || !state.defenseCaseIds.size) {
    state.defenseCaseIds = new Set(usable);
  } else {
    // Never keep a selection that belongs to a different campaign.
    const valid = new Set((campaign?.cases || []).map((c) => String(c.case_id)));
    state.defenseCaseIds = new Set(
      [...state.defenseCaseIds].filter((id) => valid.has(id) && usable.includes(id))
    );
    if (!state.defenseCaseIds.size) state.defenseCaseIds = new Set(usable);
  }
}

async function loadDefenseCampaigns() {
  try {
    const data = await api("/api/adaptive/defense_campaigns");
    state.defenseCampaigns = data.campaigns || [];
    const known = state.defenseCampaigns.some((c) => c.run_id === state.defenseRunId);
    if (!known) {
      // Prefer a campaign whose saved cases came from a live/HTTP target over
      // an older fixture campaign. Both remain selectable and are labelled;
      // the default must not silently put fixture evidence in the demo slot.
      const eligible = state.defenseCampaigns.filter((c) => c.eligible);
      const preferred =
        eligible.find((c) => c.target_identity && c.target_identity.kind === "http_api") ||
        eligible.find((c) => c.target_identity && c.target_identity.kind !== "fixture") ||
        eligible[0] ||
        state.defenseCampaigns[0] ||
        null;
      selectDefenseCampaign(preferred ? preferred.run_id : null, { reset: true });
    }
    renderDefenses(state.overview);
  } catch (err) {
    const box = $("barrierBox");
    if (box) {
      box.className = "barrier blocked";
      box.textContent = `Could not load completed attacker campaigns: ${err.message}`;
    }
  }
}

// Classify a defense-evaluation entry into one explicit, user-readable state
// so the dashboard never conflates "nothing was replayed" with a real result.
function defenseState(entry) {
  const r = (entry && entry.result) || {};
  const explicit = entry && entry.evaluation_state;
  const explicitStates = {
    eligible: { label: "Eligible to evaluate", cls: "ok" },
    running: { label: "Evaluation running", cls: "warn" },
    completed_with_evidence: { label: "Completed — evidence recorded", cls: "ok" },
    inconclusive: { label: "Inconclusive", cls: "warn" },
    unavailable: { label: "Unavailable — missing prerequisite", cls: "warn" },
    technical_failure: { label: "Technical failure", cls: "bad" },
    interrupted: { label: "Interrupted — no verdict", cls: "bad" },
  };
  if (explicit && explicitStates[explicit]) return explicitStates[explicit];
  if (r.technical_failure > 0 && !r.episodes_evaluated) {
    return { label: "Technical failure", cls: "bad" };
  }
  if (r.unavailable || !r.episodes_evaluated) {
    return { label: "Unavailable", cls: "warn" };
  }
  if (r.verdict === "inconclusive" || r.verdict === "mixed") {
    return { label: "Inconclusive", cls: "warn" };
  }
  if (r.verdict === "confirmed_success") {
    return { label: "Completed — attack confirmed", cls: "ok" };
  }
  if (r.verdict === "confirmed_blocked") {
    return { label: "Completed — attack blocked", cls: "ok" };
  }
  return { label: `Completed — ${esc(String(r.verdict || "done"))}`, cls: "ok" };
}

function defenseStatePill(entry) {
  const { label, cls } = defenseState(entry);
  return `<span class="pill sm ${cls}">${esc(label)}</span>`;
}

function defenseEntryHtml(entry) {
  const r = entry.result || {};
  const s = r.states || {};
  const target = entry.replay_target || entry.target_snapshot || {};
  const episodes = (r.episodes || []).map((ep) => {
    const executed = ep.action_executed === true
      ? "executed"
      : ep.action_executed === false
        ? "not executed"
        : "unknown";
    const enforced = ep.enforcement_before_execution === true
      ? "yes"
      : ep.enforcement_before_execution === false
        ? "no"
        : "unknown";
    return `<tr>
      <td><code>${esc(ep.source_case_id || "unlinked")}</code></td>
      <td>${esc(ep.state)}</td>
      <td>${esc(executed)}</td>
      <td>${esc(enforced)}</td>
      <td>${esc(ep.evidence)}</td>
    </tr>`;
  }).join("");
  const evidenceCases = (s.confirmed_success || 0) + (s.confirmed_blocked || 0);
  const rate = evidenceCases
    ? `${(s.confirmed_blocked || 0)} blocked / ${evidenceCases} evidence-backed`
    : "n/a (no evidence-backed case)";
  const selected = (entry.selected_case_ids || []).length
    ? entry.selected_case_ids.join(", ")
    : "—";
  return `
    <div class="line">${defenseStatePill(entry)}</div>
    <div class="line">Source attacker run: <code>${esc(entry.source_run_id || "—")}</code> · candidate <code>${esc(entry.candidate_id || "—")}</code></div>
    <div class="line">Selected saved cases: <code>${esc(selected)}</code></div>
    <div class="line">Original target: <code>${esc(target.target_id || "no snapshot")}</code> · kind ${esc(target.kind || "—")} · available ${entry.target_available === false ? "<strong>no</strong>" : "yes"}</div>
    <div class="line">Defense: ${esc(entry.against || "—")} · ${esc(entry.defense_implementation?.display_name || "")} (${esc(entry.defense_implementation?.implementation_type || "")})</div>
    <div class="line">Verdict: <strong>${esc(r.verdict || "—")}</strong>${r.unavailable ? " — nothing was replayed" : ""} · ${esc(rate)}</div>
    <div class="line">Success ${na(s.confirmed_success)} · Blocked ${na(s.confirmed_blocked)} · Inconclusive ${na(s.inconclusive)} · Technical ${na(s.technical_failure)} · replayed ${na(r.episodes_evaluated)}</div>
    <div class="line">Ground truth: ${esc(r.ground_truth || "not_evaluated")} · saved cases available: ${na(r.source_cases_available)}</div>
    ${episodes ? `<div class="table-scroll" style="margin-top:8px"><table class="table"><thead><tr><th>Case</th><th>State</th><th>Action</th><th>Enforced before execution</th><th>Evidence</th></tr></thead><tbody>${episodes}</tbody></table></div>` : `<div class="line">No replayed episodes.</div>`}
    ${(r.limitations || []).map((l) => `<div class="limit">Limitation: ${esc(l)}</div>`).join("")}`;
}

function renderDefenseJob() {
  const box = $("defenseJobStatus");
  if (!box) return;
  const job = state.defenseJob;
  if (!job) {
    box.className = "defense-result muted small";
    box.textContent = "No defense job in this session.";
    return;
  }
  const p = job.progress || {};
  const target = job.target_identity || job.result?.replay_target || {};
  const warnings = job.warnings || [];
  const errors = job.errors || (job.error ? [job.error] : []);
  box.className = "defense-result";
  box.innerHTML = `
    <div class="line"><span class="pill sm ${["queued", "running"].includes(job.state) ? "warn" : job.state === "technical_failure" || job.state === "interrupted" ? "bad" : "ok"}">${esc(job.state)}</span>
      Job <code>${esc(job.job_id || job.evaluation_id)}</code> · created ${esc(timeAgo(job.created_at || job.queued_at))}</div>
    <div class="line">Source run <code>${esc(job.source_run_id || "—")}</code> · defense ${esc(job.defense || "—")} · cases ${esc((job.case_ids || []).length || "—")}</div>
    <div class="line">Original target: <code>${esc(target.target_id || "resolving…")}</code> · kind ${esc(target.kind || "—")}</div>
    <div class="line">Progress: ${esc(p.phase || "queued")} · replayed ${na(p.cases_replayed)} / ${na(p.cases_total)}${p.last_case_id ? ` · last <code>${esc(p.last_case_id)}</code>` : ""}</div>
    ${warnings.map((w) => `<div class="limit">Warning: ${esc(w)}</div>`).join("")}
    ${errors.map((e) => `<div class="limit" style="color:#FCA5A5">Error: ${esc(e)}</div>`).join("")}
    ${job.result ? `<hr style="border-color:var(--border-soft);margin:10px 0">${defenseEntryHtml(job.result)}` : ""}`;
}

function renderDefenses(o) {
  const barrier = $("barrierBox");
  if (!barrier) return;
  const lifecycle = (o && o.lifecycle) || {};
  const campaign = defenseCampaign();
  if (lifecycle.running) {
    barrier.className = "barrier blocked";
    barrier.textContent = "An attacker search is running. Defense starts only after it terminates.";
  } else if (!state.defenseCampaigns.length) {
    barrier.className = "barrier blocked";
    barrier.textContent = "No completed attacker campaign yet. Finish an attacker run first.";
  } else if (campaign && campaign.eligible) {
    barrier.className = "barrier ok";
    barrier.textContent = `Campaign ${campaign.run_id} · ${campaign.usable_cases} eligible case(s). Select cases, then press Run Defense.`;
  } else if (campaign) {
    barrier.className = "barrier blocked";
    barrier.textContent = `Campaign ${campaign.run_id} has no eligible saved case: ${campaign.reason || "none confirmed"}.`;
  } else {
    barrier.className = "barrier blocked";
    barrier.textContent = "Select a completed attacker campaign.";
  }

  const campaignSelect = $("defenseCampaignSelect");
  if (campaignSelect) {
    const current = state.defenseRunId || "";
    campaignSelect.innerHTML = state.defenseCampaigns.length
      ? state.defenseCampaigns.map((c) =>
          `<option value="${esc(c.run_id)}">${esc(c.run_id)} · ${esc(c.usable_cases)} eligible · ${esc(timeAgo(c.finished_at) || "—")}</option>`
        ).join("")
      : `<option value="">— no completed campaign —</option>`;
    if (current && [...campaignSelect.options].some((op) => op.value === current)) {
      campaignSelect.value = current;
    }
  }

  const meta = $("defenseCampaignMeta");
  if (meta) {
    if (!campaign) {
      meta.textContent = "No campaign selected.";
    } else {
      const t = campaign.target_identity || {};
      const targetText = t.target_id
        ? `${t.target_id} (${t.kind || "unknown kind"})`
        : "no persisted target snapshot — replay will be unavailable";
      meta.innerHTML = `Candidate <code>${esc(campaign.candidate_id)}</code> · search-time defense ${esc(campaign.search_defense || "—")} · original target <code>${esc(targetText)}</code> · saved cases ${na(campaign.cases_available)} · eligible ${na(campaign.usable_cases)}${campaign.target_snapshot_present === false ? " · <span style=\"color:#FDBA74\">target snapshot missing</span>" : ""}`;
    }
  }

  const caseBox = $("defenseCaseSelect");
  if (caseBox) {
    const cases = campaign?.cases || [];
    caseBox.innerHTML = cases.length
      ? cases.map((c) => {
          const cid = String(c.case_id || "");
          const checked = state.defenseCaseIds.has(cid) ? "checked" : "";
          const disabled = c.usable ? "" : "disabled";
          return `<label class="case-choice ${c.usable ? "" : "ineligible"}">
            <input type="checkbox" data-defense-case="${esc(cid)}" ${checked} ${disabled}>
            <span>
              <span class="case-id">${esc(cid || "no stable id")}</span>
              <span class="case-meta"> · episode ${na(c.episode)} · outcome ${esc(c.outcome || "—")} · decision ${esc(c.defense_decision || "not observable")}</span>
              ${c.usable ? "" : `<div class="case-why">Excluded: ${esc(c.unusable_reason || "not a replayable confirmed case")}</div>`}
            </span>
          </label>`;
        }).join("")
      : `<div class="muted small">${campaign ? "This campaign has no saved attack cases." : "Choose a completed campaign to list its saved cases."}</div>`;
  }

  const selectionMeta = $("defenseSelectionMeta");
  const usable = usableCaseIds(campaign);
  if (selectionMeta) {
    selectionMeta.textContent = `${state.defenseCaseIds.size} selected / ${usable.length} eligible`;
  }

  const defSel = $("defenseSelect");
  if (defSel && !defSel.options.length) {
    defSel.innerHTML = (o?.defense?.catalog || []).map((d) =>
      `<option value="${esc(d.defense_id)}" ${d.available ? "" : "disabled"}>${esc(d.display_name)}${d.available ? "" : " — UNAVAILABLE"}</option>`
    ).join("");
  }
  const runBtn = $("runDefenseBtn");
  if (runBtn) {
    runBtn.disabled = !campaign || !campaign.eligible || state.defenseCaseIds.size === 0;
  }

  const body = $("defenseEvalBody");
  if (body) {
    const evals = (o?.defense?.evaluations || []).slice().reverse();
    body.innerHTML = evals.length
      ? evals.map((e) => {
          const r = e.result || {};
          const s = r.states || {};
          return `<tr>
            <td><code>${esc(e.source_run_id || "—")}</code></td>
            <td><code>${esc(e.candidate_id)}</code></td>
            <td>${esc(e.against)}</td>
            <td>${defenseStatePill(e)}<br><span class="muted">${esc(r.verdict || "—")}</span></td>
            <td>${na((e.selected_case_ids || []).length || r.episodes_evaluated)}</td>
            <td>${na(s.confirmed_success)}</td>
            <td>${na(s.confirmed_blocked)}</td>
            <td>${na(s.inconclusive)}</td>
            <td>${na(s.technical_failure)}</td>
            <td>${esc(timeAgo(e.evaluated_at))}</td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="10" class="empty">None yet.</td></tr>`;
  }
  renderDefenseJob();
}

function stopDefensePolling() {
  clearTimeout(state.defensePollTimer);
  state.defensePollTimer = null;
}

async function pollDefenseJob(evaluationId) {
  stopDefensePolling();
  const terminal = new Set(["completed", "inconclusive", "unavailable", "technical_failure", "interrupted"]);
  for (;;) {
    let job;
    try {
      const response = await api(`/api/adaptive/defense_eval/status?evaluation_id=${encodeURIComponent(evaluationId)}`);
      job = response.job;
    } catch (err) {
      state.defenseJob = {
        job_id: evaluationId,
        evaluation_id: evaluationId,
        state: "technical_failure",
        errors: [err.message],
        progress: {},
      };
      renderDefenseJob();
      localStorage.removeItem(DEFENSE_JOB_KEY);
      return;
    }
    state.defenseJob = job;
    renderDefenseJob();
    if (terminal.has(job.state)) {
      localStorage.removeItem(DEFENSE_JOB_KEY);
      await loadDefenseCampaigns();
      await loadOverview();
      return;
    }
    await new Promise((resolve) => {
      state.defensePollTimer = setTimeout(resolve, 1200);
    });
  }
}

async function restoreDefenseJob() {
  const evaluationId = localStorage.getItem(DEFENSE_JOB_KEY);
  if (!evaluationId) return;
  try {
    const response = await api(`/api/adaptive/defense_eval/status?evaluation_id=${encodeURIComponent(evaluationId)}`);
    state.defenseJob = response.job;
    renderDefenseJob();
    if (["queued", "running"].includes(response.job.state)) {
      pollDefenseJob(evaluationId);
    } else {
      localStorage.removeItem(DEFENSE_JOB_KEY);
    }
  } catch {
    // A restart may have removed an unknown id; never invent a result or
    // silently start a replacement job.
    localStorage.removeItem(DEFENSE_JOB_KEY);
  }
}

$("defenseCampaignSelect")?.addEventListener("change", (event) => {
  selectDefenseCampaign(event.target.value, { reset: true });
  renderDefenses(state.overview);
});

$("defenseSelectAll")?.addEventListener("click", () => {
  state.defenseCaseIds = new Set(usableCaseIds(defenseCampaign()));
  renderDefenses(state.overview);
});

$("defenseClearSelection")?.addEventListener("click", () => {
  state.defenseCaseIds = new Set();
  renderDefenses(state.overview);
});

$("defenseCaseSelect")?.addEventListener("change", (event) => {
  const input = event.target.closest("input[data-defense-case]");
  if (!input) return;
  const caseId = input.dataset.defenseCase;
  if (input.checked) state.defenseCaseIds.add(caseId);
  else state.defenseCaseIds.delete(caseId);
  renderDefenses(state.overview);
});

$("runDefenseBtn")?.addEventListener("click", async () => {
  const campaign = defenseCampaign();
  const box = $("defenseResult");
  if (!campaign) return;
  const caseIds = [...state.defenseCaseIds];
  if (!caseIds.length) {
    box.className = "defense-result";
    box.innerHTML = `<span style="color:#FDBA74">Select at least one eligible saved case. An empty selection never starts an evaluation.</span>`;
    return;
  }
  const defense = $("defenseSelect").value;
  box.className = "defense-result";
  box.textContent = "Starting the separate defense job…";
  $("runDefenseBtn").disabled = true;
  try {
    const start = await api("/api/adaptive/defense_eval", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        run_id: campaign.run_id,
        candidate_id: campaign.candidate_id,
        case_ids: caseIds,
        defense,
      }),
    });
    if (!start.evaluation_id) {
      // Inline result (sync caller): render it directly.
      box.innerHTML = defenseEntryHtml(start);
      await loadOverview();
      return;
    }
    state.defenseJob = start.job;
    localStorage.setItem(DEFENSE_JOB_KEY, start.evaluation_id);
    renderDefenseJob();
    box.className = "defense-result muted small";
    box.textContent = "The job runs independently in the background. Refreshing this page restores the job; it does not start another one.";
    pollDefenseJob(start.evaluation_id);
  } catch (err) {
    box.className = "defense-result";
    const data = err.data || {};
    const excluded = (data.excluded_cases || [])
      .map((c) => `<div class="limit">Excluded <code>${esc(c.case_id || "—")}</code>: ${esc(c.exclusion_reason || c.unusable_reason || "not eligible")}</div>`)
      .join("");
    box.innerHTML = `<span style="color:#FCA5A5">${esc(err.message)}</span>${excluded}`;
    $("runDefenseBtn").disabled = false;
  }
});

/* ---------------- reports ---------------- */

function renderReports(o) {
  const body = $("runTableBody");
  const runs = (o.reports?.runs || []).slice().reverse();
  body.innerHTML = runs.length
    ? runs.map((r) => `<tr>
        <td><code>${esc(r.run_id)}</code></td>
        <td>${statusBadge(r.status)}</td>
        <td>${esc(r.target || "seeded stand-in")}<br><span class="muted">${esc(r.target_kind || "")}</span></td>
        <td>${esc(r.mode || "—")}</td>
        <td>${r.best_asr == null ? "Unavailable" : Number(r.best_asr).toFixed(2)}</td>
        <td>${na(r.episodes_consumed)}/${na(r.total_episode_budget)}</td>
        <td>${esc(timeAgo(r.finished_at))}</td>
      </tr>`).join("")
    : `<tr><td colspan="7" class="empty">No runs persisted.</td></tr>`;  const latest = o.candidates || [];
  const cases = latest.flatMap((c) => (c.cases || []).map((k) => ({ ...k, candidate: c.candidate_id, objective: c.objective })));
  const runGmail = [];
  for (const trace of (o.run?.episode_trace || [])) {
    for (const evidence of (trace.target_evidence || [])) {
      if (evidence && evidence.provider === "gmail") runGmail.push({ trace, evidence });
    }
  }
  $("casesMeta").textContent = (cases.length || runGmail.length)
    ? `${cases.length} case(s) from the displayed candidates · ${cases.filter((c) => c.bucket === "success").length} successful${runGmail.length ? ` · ${runGmail.length} run-level Gmail evidence record(s)` : ""}`
    : "";
  const gmailRows = runGmail.map(({ trace, evidence }) => {
    const messages = (evidence.messages || []).map((m) => `${m.message_id}:${m.decision}`).join(" · ") || "no messages";
    return `<tr>
      <td><code>${esc(trace.case_id || "—")}</code></td>
      <td>${esc(trace.episode)}</td>
      <td>${bucketBadge(trace.observed_outcome === "success" ? "success" : trace.observed_outcome === "no_violation" ? "blocked" : "inconclusive")}</td>
      <td>${esc(trace.observed_outcome || "—")}</td>
      <td>${esc(trace.defense_decision || "not observable")}</td>
      <td>Gmail: ${esc(messages)} · read-only · executed=false</td>
    </tr>`;
  }).join("");
  $("caseTableBody").innerHTML = (cases.length || gmailRows)
    ? cases.map((c) => {
        const gmail = (c.target_evidence || []).find((e) => e && e.provider === "gmail");
        const evidence = gmail
          ? `<div class="fineprint">Gmail: ${esc((gmail.messages || []).map((m) => `${m.message_id}:${m.decision}`).join(" · ") || "no messages")} · read-only · executed=false</div>`
          : "";
        return `<tr>
        <td><code>${esc(c.case_id || "—")}</code></td>
        <td>${esc(c.episode)}</td>
        <td>${bucketBadge(c.bucket)}</td>
        <td>${esc(c.observed_outcome || "—")}</td>
        <td>${esc(c.defense_decision || "not observable")}</td>
        <td>${esc((c.steps || []).map((s) => s.category).join(", ") || "—")}${evidence}</td>
      </tr>`;
      }).join("") + gmailRows
    : `<tr><td colspan="6" class="empty">No saved cases.</td></tr>`;

  const evals = (o?.defense?.evaluations || []).slice().reverse();
  const dMeta = $("defenseReportMeta");
  if (dMeta) {
    dMeta.textContent = evals.length
      ? `${evals.length} defense job(s) · attacker and defense metrics are kept separate`
      : "No defense job persisted.";
  }
  const dBody = $("defenseReportBody");
  if (dBody) {
    dBody.innerHTML = evals.length
      ? evals.map((e) => {
          const r = e.result || {};
          const s = r.states || {};
          const evidence = (s.confirmed_success || 0) + (s.confirmed_blocked || 0);
          const rate = evidence
            ? `${s.confirmed_blocked || 0} / ${evidence}`
            : "n/a";
          return `<tr>
            <td><code>${esc(e.source_run_id || "—")}</code><br><span class="muted">${esc(e.candidate_id || "")}</span></td>
            <td>${na((e.selected_case_ids || []).length || r.episodes_evaluated)}</td>
            <td>${esc(e.against || "—")}</td>
            <td>${defenseStatePill(e)}</td>
            <td>${na(s.confirmed_success)}</td>
            <td>${na(s.confirmed_blocked)}</td>
            <td>${na(s.inconclusive)}</td>
            <td>${na(s.technical_failure)}</td>
            <td>${esc(rate)}</td>
            <td>${esc(timeAgo(e.evaluated_at))}</td>
          </tr>`;
        }).join("")
      : `<tr><td colspan="10" class="empty">No defense evaluation persisted.</td></tr>`;
  }

  $("rawRun").textContent = o.run ? JSON.stringify(o.run, null, 2) : "No run persisted.";
}

function statusBadge(status) {
  const map = {
    completed: ["green", "completed"],
    budget_exhausted: ["orange", "budget exhausted"],
    stopped: ["orange", "stopped"],
    failed: ["red", "failed"],
    running: ["blue", "running"],
  };
  const [cls, label] = map[status] || ["slate", status || "unknown"];
  return `<span class="badge ${cls}">${esc(label)}</span>`;
}

$("refreshBtn").addEventListener("click", () => loadOverview());

/* ---------------- settings ---------------- */

function renderSettings(o) {
  const p = o.provider || {};
  $("settingsModel").innerHTML = [
    ["Provider", p.provider || "—"],
    ["Endpoint", p.endpoint || "—"],
    ["Model", p.model || p.default_model || "—"],
    ["Service reachable", p.reachable ? "yes" : "no"],
    ["Model installed", p.model_available ? "yes" : "no"],
    ["Error", p.error || "—"],
  ].map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(v)}</span></div>`).join("");

  const limits = o.settings?.limits || {};
  $("settingsLimits").innerHTML = [
    ["Episodes per candidate", limits.episodes_per_candidate],
    ["Max rounds", limits.max_rounds],
    ["Iterations", limits.iterations],
    ["Total episode budget", limits.total_episode_budget],
    ["Model requests", limits.model_requests],
    ["Approved experiment budget", limits.approved_experiment_budget],
  ].map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(na(v))}</span></div>`).join("");

  const cp = o.reports?.checkpoint;
  $("settingsCheckpoint").innerHTML = cp
    ? Object.entries(cp).map(([k, v]) =>
        `<div class="kv"><span>${esc(k)}</span><span>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</span></div>`).join("")
    : `<div class="kv"><span>No checkpoint</span><span>—</span></div>`;

  $("settingsConnections").innerHTML = (o.connections || []).map((c) =>
    `<div class="kv"><span>${esc(c.display_name)}</span><span>${esc(c.connected ? (c.selected ? "connected · selected" : "connected") : c.status_label)}</span></div>`
  ).join("");
}

/* ---------------- home ---------------- */

function renderHome(o) {
  const phase = o.lifecycle?.phase || "idle";
  const phaseLabel = {
    idle: "Idle",
    attacker: "Attacker running",
    defense_ready: "Defense ready",
    defense_completed: "Defense evaluated",
    defense_inconclusive: "Defense inconclusive",
    defense_unavailable: "Defense unavailable — missing prerequisite",
    defense_failed: "Defense technical failure",
    defense_running: "Defense evaluation running",
    incomplete: "Incomplete",
  }[phase] || phase;
  const conn = o.connection;
  $("homeStatus").innerHTML = [
    ["Phase", phaseLabel],
    ["Connected agent", conn && conn.ready ? conn.display_name : "none (seeded stand-in)"],
    ["Ollama", o.provider?.ready ? "ready" : o.provider?.reachable ? "model missing" : "unreachable"],
    ["Runs persisted", String((o.reports?.runs || []).length)],
    ["Defense evaluations", String((o.defense.evaluations || []).length)],
  ].map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(v)}</span></div>`).join("");

  const homeActivity = $("homeActivity");
  if (homeActivity) {
    const items = (o.activity || []).slice(0, 6);
    homeActivity.innerHTML = items.length
      ? items.map((a) => `<li class="act-item">
          <span class="act-dot ${a.kind === "defense" ? "green" : a.kind === "run" ? "blue" : "purple"}"></span>
          <div><div class="act-title">${esc(a.title)}</div><div class="act-detail">${esc(a.detail || "")}</div></div>
          <span class="act-time">${esc(timeAgo(a.at))}</span>
        </li>`).join("")
      : `<li class="muted small">No persisted activity.</li>`;
  }

  const r = o.run;
  $("homeRun").innerHTML = r
    ? [
        ["Run", r.run_id],
        ["Status", r.status],
        ["Best ASR", r.best_asr == null ? "Unavailable" : r.best_asr],
        ["Episodes", `${na(r.episodes_consumed)}/${na(r.total_episode_budget)}`],
        ["Finished", r.finished_at ? `${timeAgo(r.finished_at)} (${clockTime(r.finished_at)})` : "—"],
      ].map(([k, v]) => `<div class="kv"><span>${esc(k)}</span><span>${esc(v)}</span></div>`).join("")
    : `<span class="muted">No run recorded.</span>`;
}

/* ---------------- init ---------------- */

window.addEventListener("resize", () => {
  if (state.page === "experiments") drawChart();
});

setPage("experiments");
loadOverview();
