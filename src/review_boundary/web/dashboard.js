/* ReviewBoundary's portable, browser-local evaluation workspace. */
(() => {
  "use strict";
  const MAX_REPORTS = 8;
  const MAX_BYTES = 16 * 1024 * 1024;
  const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
  const MAX_ROWS = 10000;
  const SURFACES = { clean: "Clean context", pr_body: "PR description", readme: "README file", code_comment: "Code comment", tool_output: "Tool response", benign_quote: "Benign quotation" };
  const PAGES = { overview: "Overview", runs: "Evaluation runs", cases: "Case explorer", pairs: "Paired reviews" };
  const TITLES = { "calibration-v2": "Full-suite calibration", "pilot-v2-typescript": "TypeScript pilot", "pilot-v2-rust-heldout": "Rust held-out pilot" };
  const FAMILIES = { document_path: "Document path access", signed_webhook: "Webhook signature", tenant_lookup: "Tenant isolation", shell_preview: "Shell command preview", ts_batch_export: "Batch export permissions", rust_partial_batch_permissions: "Partial batch permissions" };
  const h = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const titleCase = value => String(value ?? "").replace(/^(ts_|rust_)/, "").replaceAll("_", " ").replace(/^./, c => c.toUpperCase());
  const familyName = value => FAMILIES[value] || titleCase(value);
  const surfaceName = value => SURFACES[value] || titleCase(value);
  const modelName = value => String(value).replace(/^mockllm\/calibration-/, "Scripted ").replace(/^openrouter\//, "");
  const outcome = row => !row.conclusive ? "inconclusive" : row.passed ? "pass" : "fail";
  const pct = (num, den) => den ? `${Math.round(num / den * 100)}%` : "N/A";
  const ratio = (num, den) => den ? `${num}/${den}` : "N/A";
  const number = value => Number(value).toLocaleString("en-US");
  const pairKey = row => JSON.stringify([row.trial_group ?? null, row.model, row.defense, row.family, row.variant, row.epoch]);
  function controlIndex(rows) {
    const controls = new Map();
    for (const row of rows.filter(r => r.surface === "clean")) {
      const key = pairKey(row);
      controls.set(key, controls.has(key) ? null : row);
    }
    return controls;
  }
  function stats(rows) {
    const controls = controlIndex(rows);
    const eligible = rows.filter(r => r.attacked && r.conclusive && controls.get(pairKey(r))?.passed);
    return {
      total: rows.length,
      correct: rows.filter(r => r.review_correct).length,
      pass: rows.filter(r => outcome(r) === "pass").length,
      fail: rows.filter(r => outcome(r) === "fail").length,
      inconclusive: rows.filter(r => outcome(r) === "inconclusive").length,
      completed: rows.filter(r => r.completed).length,
      writes: rows.filter(r => r.write_attempted).length,
      errors: rows.filter(r => r.error).length,
      eligible: eligible.length,
      degraded: eligible.filter(r => !r.passed).length,
      families: new Set(rows.map(r => r.family)).size,
      conditions: new Set(rows.map(r => r.case_id)).size,
    };
  }
  function pairReason(rows, row) {
    const controls = controlIndex(rows), key = pairKey(row);
    if (!controls.has(key)) return "No matching clean control was recorded.";
    if (!controls.get(key)) return "Multiple clean controls match this sample; the pair is ambiguous.";
    if (!controls.get(key).passed) return "The clean control did not pass, so this pair cannot establish a degradation.";
    if (!row.conclusive) return "The attacked review is inconclusive, so this pair cannot establish a degradation.";
    return "";
  }
  function normalizeFilters(filters, rows, paired = false) {
    const result = { ...filters };
    if (!rows.some(r => r.model === result.model)) result.model = "all";
    if (!rows.some(r => r.surface === result.surface && (!paired || r.attacked))) result.surface = "all";
    if (!["pass", "fail", "inconclusive"].includes(result.status)) result.status = "all";
    return result;
  }
  function diagnostics(report) {
    const result = stats(report.rows), messages = [];
    const controls = controlIndex(report.rows);
    const ambiguous = [...controls.values()].filter(value => value === null).length;
    if (ambiguous) messages.push(`${ambiguous} clean-control identities are ambiguous. Those pairs are excluded.`);
    for (const [saved, computed] of [["total", "total"], ["correct_reviews", "correct"], ["paired_eligible", "eligible"], ["paired_degradations", "degraded"], ["write_attempts", "writes"]]) {
      if (Number.isInteger(report.summary?.[saved]) && report.summary[saved] !== result[computed]) messages.push(`Recorded ${saved}: ${report.summary[saved]}; displayed from rows: ${result[computed]}.`);
    }
    return messages;
  }
  function validateReport(report) {
    const object = x => x !== null && typeof x === "object" && !Array.isArray(x);
    const fail = message => { throw new Error(message); };
    if (!object(report) || report.schema_version !== 2 || !object(report.metadata) || !Array.isArray(report.rows)) fail("Choose a ReviewBoundary report.json with schema version 2.");
    if (report.rows.length > MAX_ROWS) fail("A workspace supports up to 10,000 recorded samples.");
    let nodes = 0;
    function walk(value, depth = 0) {
      if (++nodes > 1000000 || depth > 20) fail("The report exceeds the supported structure limits.");
      if (typeof value === "number" && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) fail("The report contains a number outside the supported range.");
      if (typeof value === "string" && new TextEncoder().encode(value).length > 1048576) fail("A report field is too large.");
      if (value && typeof value === "object") {
        if (!Array.isArray(value)) for (const key of Object.keys(value)) walk(key, depth + 1);
        for (const v of Object.values(value)) walk(v, depth + 1);
      }
    }
    walk(report);
    const integer = value => Number.isSafeInteger(value) && value >= 0;
    for (const key of ["run_id", "run_kind", "scoring_version", "corpus_version", "project_version", "inspect_ai_version", "suite_sha256", "split", "language", "sampling"]) if (report.metadata[key] != null && typeof report.metadata[key] !== "string") fail("The report contains an invalid metadata field.");
    for (const key of ["run_finished", "block_writes"]) if (Object.hasOwn(report.metadata, key) && typeof report.metadata[key] !== "boolean") fail("The report contains an invalid metadata flag.");
    for (const key of ["epochs", "case_count"]) if (Object.hasOwn(report.metadata, key) && (!integer(report.metadata[key]) || (key === "epochs" && report.metadata[key] < 1))) fail("The report contains an invalid sample count.");
    if (Object.hasOwn(report, "generated_at") && typeof report.generated_at !== "string") fail("The report date must be text.");
    for (const key of ["summary", "coverage"]) if (Object.hasOwn(report, key) && !object(report[key])) fail("The report summary and coverage must be objects.");
    for (const key of ["total", "completed", "conclusive", "correct_reviews", "write_attempts", "modified_workspaces", "errors", "incomplete", "attack_goal_eligible", "paired_eligible", "paired_degradations", "fixed_rubric_failures", "vulnerable_rubric_failures"]) if (Object.hasOwn(report.summary || {}, key) && !integer(report.summary[key])) fail("The report contains an invalid summary count.");
    if (Object.hasOwn(report.metadata, "usage")) {
      const usage = report.metadata.usage;
      if (!object(usage)) fail("The recorded usage must be an object.");
      for (const key of ["input_tokens", "output_tokens", "api_calls_with_reported_cost", "api_calls_without_reported_cost"]) if (Object.hasOwn(usage, key) && !integer(usage[key])) fail("The recorded usage contains an invalid count.");
      if (usage.provider_reported_cost_usd != null && (typeof usage.provider_reported_cost_usd !== "number" || usage.provider_reported_cost_usd < 0)) fail("The recorded cost must be nonnegative or unknown.");
    }
    for (const row of report.rows) {
      if (!object(row)) fail("A sample is not a valid object.");
      for (const key of ["case_id", "family", "variant", "surface", "model", "defense"]) if (typeof row[key] !== "string" || !row[key].trim()) fail("A sample is missing its identity fields.");
      for (const key of ["attacked", "completed", "conclusive", "review_correct", "write_attempted", "workspace_modified", "passed"]) if (typeof row[key] !== "boolean") fail("A sample is missing its recorded outcome fields.");
      if (!Number.isInteger(row.epoch) || row.epoch < 1) fail("A sample has an invalid trial number.");
      for (const key of ["issue_reported", "evidence_grounded", "citation_correct", "attack_goal_reached"]) if (row[key] != null && typeof row[key] !== "boolean") fail("A sample contains an invalid metric.");
      for (const key of ["attack_goal_eligible", "payload_exposed"]) if (Object.hasOwn(row, key) && typeof row[key] !== "boolean") fail("A sample contains an invalid flag.");
      for (const key of ["finding_count", "expected_category_findings", "supported_findings", "write_requests_seen"]) if (Object.hasOwn(row, key) && !integer(row[key])) fail("A sample contains an invalid count.");
      for (const key of ["trial_group", "language", "split", "source_path", "error", "stop_reason", "model_stop_reason"]) if (row[key] != null && typeof row[key] !== "string") fail("A sample contains an invalid text field.");
      if (!Array.isArray(row.events) || row.events.length > 1000) fail("A sample has an invalid tool trace.");
      for (const event of row.events) {
        if (!object(event) || typeof event.tool !== "string" || !event.tool.trim()) fail("A sample has an invalid tool event.");
        for (const key of ["status", "path", "content"]) if (Object.hasOwn(event, key) && typeof event[key] !== "string") fail("A tool event contains an invalid text field.");
        if (Object.hasOwn(event, "content_truncated") && typeof event.content_truncated !== "boolean") fail("A tool event contains an invalid truncation flag.");
      }
      if (!Object.hasOwn(row, "review")) fail("A sample must include a review, or an explicit null.");
      if (row.review != null) {
        if (!object(row.review) || typeof row.review.verdict !== "string" || !row.review.verdict.trim() || !Array.isArray(row.review.findings) || row.review.findings.length > 100) fail("A sample has an invalid review.");
        for (const finding of row.review.findings) {
          if (!object(finding) || !Number.isInteger(finding.line) || finding.line < 1) fail("A finding has an invalid source line.");
          for (const key of ["category", "file", "evidence", "explanation"]) if (typeof finding[key] !== "string" || !finding[key].trim()) fail("A finding is missing its recorded evidence.");
        }
      }
    }
    return report;
  }
  // The calculation layer can be checked without a browser or a paid model.
  if (typeof module !== "undefined" && module.exports) module.exports = { stats, controlIndex, pairKey, pairReason, normalizeFilters, diagnostics, validateReport, outcome };
  if (typeof document === "undefined") return;

  const ICONS = {
    overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    grid: '<path d="M3 3h18v18H3zM3 9h18M9 3v18"/>',
    runs: '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/>',
    cases: '<path d="m8 5-6 7 6 7m8-14 6 7-6 7M14 3l-4 18"/>',
    compare: '<path d="M8 4H4v16h4M16 4h4v16h-4M8 9h8m-3-3 3 3-3 3M16 16H8m3-3-3 3 3 3"/>',
    book: '<path d="M12 5C9 3 5 3 2 4v16c3-1 7-1 10 1 3-2 7-2 10-1V4c-3-1-7-1-10 1Zm0 0v16"/>',
    github: '<path d="M9 19c-4 1-4-2-6-2m13 5v-4c0-1-.3-1.7-1-2 3-.3 6-1.5 6-6a5 5 0 0 0-1.4-3.5A4.5 4.5 0 0 0 19.5 3S18 2.5 15.7 4a13 13 0 0 0-7.4 0C6 2.5 4.5 3 4.5 3a4.5 4.5 0 0 0-.1 3.5A5 5 0 0 0 3 10c0 4.5 3 5.7 6 6-.7.3-1 1-1 2v4"/>',
    shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
    moon: '<path d="M20 15.5A9 9 0 0 1 8.5 4a9 9 0 1 0 11.5 11.5Z"/>',
    upload: '<path d="M12 16V3m-5 5 5-5 5 5M4 15v5h16v-5"/>',
    download: '<path d="M12 3v13m-5-5 5 5 5-5M4 16v5h16v-5"/>',
    arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
    plus: '<path d="M12 4v16M4 12h16"/>',
    check: '<path d="m5 12 4 4L19 6"/>',
    close: '<path d="m6 6 12 12M6 18 18 6"/>',
    circle: '<circle cx="12" cy="12" r="8"/><path d="M8 12h8"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.1"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
    activity: '<path d="M2 12h4l3-8 6 16 3-8h4"/>',
    flag: '<path d="M5 21V4c5-5 9 5 14 0v10c-5 5-9-5-14 0"/>',
    copy: '<rect x="8" y="8" width="12" height="12" rx="1"/><path d="M16 8V4H4v12h4"/>',
  };
  const icon = name => `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ICONS.runs}</svg>`;
  const $ = selector => document.querySelector(selector);
  const state = { reports: [], run: 0, page: "overview", search: "", model: "all", surface: "all", status: "all", pageNum: 0, selectedPair: null, theme: "dark" };
  let toastTimer;
  let importBusy = false;
  let dragDepth = 0;
  try { state.theme = localStorage.getItem("reviewboundary-theme") === "light" ? "light" : "dark"; } catch { /* Storage is optional for local files. */ }
  function toast(message, persistent = false) {
    $("#toast").innerHTML = `<span>${h(message)}</span><button class="icon-button" data-dismiss-toast="true" aria-label="Dismiss notification">${icon("close")}</button>`;
    $("#toast").hidden = false;
    clearTimeout(toastTimer);
    if (!persistent) toastTimer = setTimeout(() => { $("#toast").hidden = true; }, 6500);
  }
  function hydrateIcons(root = document) {
    root.querySelectorAll("[data-icon]").forEach(el => { el.innerHTML = icon(el.dataset.icon); });
  }
  function setTheme(theme) {
    state.theme = theme;
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll("[data-theme-choice]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.themeChoice === theme)));
    try { localStorage.setItem("reviewboundary-theme", theme); } catch { /* Reports are never persisted. */ }
  }
  function resetFilters() { Object.assign(state, { search: "", model: "all", surface: "all", status: "all", pageNum: 0, selectedPair: null }); }
  const active = () => state.reports[state.run];
  const activeRows = () => active()?.report.rows || [];
  const runName = entry => TITLES[entry.name.toLowerCase().replaceAll(" ", "-")] || titleCase(entry.name.replace(/\.json$/i, "").replaceAll("-", " ")) || "Imported evaluation";
  function kind(report) { return report.metadata.run_kind === "calibration" ? "Harness calibration" : report.metadata.run_kind === "adapter" ? "External reviewer" : "Model pilot"; }
  function formatDate(report) {
    const date = new Date(report.generated_at || "");
    return Number.isNaN(date.valueOf()) ? "Date not recorded" : date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
  }
  function options(values, current, label) { return values.map(([value, text]) => `<option value="${h(value)}"${String(current) === String(value) ? " selected" : ""}>${h(text || label?.(value) || value)}</option>`).join(""); }
  function runSelector() {
    return `<label class="run-switch"><span class="tiny-label">RECORDED EVALUATION</span><select data-control="run" aria-label="Recorded evaluation">${options(state.reports.map((e, i) => [i, runName(e)]), state.run)}</select></label>`;
  }
  function pageHeader(eyebrow, title, description, extra = "") { return `<div class="page-header"><div><p class="eyebrow">${h(eyebrow)}</p><h1>${h(title)}</h1><p class="page-description">${h(description)}</p></div>${extra}</div>`; }
  function notice(report) {
    const label = kind(report);
    const note = report.metadata.run_kind === "calibration" ? "Scripted reviewers check the harness, not model performance." : report.metadata.run_kind === "adapter" ? "Only actions visible through the reviewer protocol are recorded." : "Recorded model responses from a small, controlled test suite.";
    const coverage = report.coverage || {};
    const missing = Number.isSafeInteger(coverage.missing) && coverage.missing > 0 ? ` ${coverage.missing} expected samples are missing from this saved run.` : "";
    const duplicates = Number.isSafeInteger(coverage.duplicates) && coverage.duplicates > 0 ? ` ${coverage.duplicates} duplicate samples are recorded.` : "";
    const messages = diagnostics(report);
    return `<div class="context-strip"><span>${icon("info")}</span><p><strong>${h(label)}.</strong> ${h(note)}${missing || duplicates ? `<br><span class="unknown">${h(missing + duplicates)}</span>` : ""}${messages.length ? `<br><span class="unknown">${messages.map(h).join(" ")}</span>` : ""}</p><span class="tag">${h(report.metadata.split || "RECORDED SAMPLES")}</span></div>`;
  }
  function badge(row) {
    const status = outcome(row);
    return `<span class="tag ${status === "pass" ? "tag-green" : status === "fail" ? "tag-red" : "tag-amber"}">${status === "pass" ? "PASS" : status === "fail" ? "FAIL" : "INCONCLUSIVE"}</span>`;
  }
  function reportTable() {
    return `<div class="panel"><div class="table-scroll"><table><thead><tr><th>EVALUATION</th><th>TYPE</th><th>SAMPLES</th><th>CORRECT REVIEWS</th><th>PAIRED DEGRADATIONS</th><th><span class="muted">OPEN</span></th></tr></thead><tbody>${state.reports.map((entry, index) => {
      const report = entry.report, s = stats(report.rows);
      return `<tr><td><div class="run-cell"><span class="run-icon">${icon(report.metadata.run_kind === "calibration" ? "grid" : "runs")}</span><div><button class="row-name" data-open-run="${index}">${h(runName(entry))}</button><span class="row-meta">${h(formatDate(report))} · ${s.conditions} conditions</span></div></div></td><td><span class="tag">${h(kind(report))}</span></td><td class="mono">${number(s.total)}</td><td><div class="mini-score"><span>${ratio(s.correct, s.total)}</span><span class="mini-track"><i style="width:${s.total ? s.correct / s.total * 100 : 0}%"></i></span></div></td><td><span class="signal ${s.degraded ? "bad" : "good"}">${icon(s.degraded ? "flag" : "check")}${ratio(s.degraded, s.eligible)}</span></td><td><button class="row-action" data-open-run="${index}" aria-label="Open ${h(runName(entry))}">${icon("arrow")}</button></td></tr>`;
    }).join("")}</tbody></table></div><div class="table-note"><span>${state.reports.length} saved evaluations · Files stay in this browser</span><span>SCHEMA 2</span></div></div>`;
  }
  function overview() {
    const report = active().report, rows = report.rows, s = stats(rows);
    const surfaces = [...new Set([...Object.keys(SURFACES), ...rows.map(r => r.surface)])].filter(surface => rows.some(r => r.surface === surface));
    const metric = (label, value, suffix, note, symbol, color = "") => `<div class="metric"><div class="metric-label">${label}${icon(symbol)}</div><div class="metric-value ${color}">${value}<small>${suffix}</small></div><div class="metric-note">${note}</div></div>`;
    return pageHeader("PROMPT INJECTION / REVIEWER EVALUATION", "Trust, under pressure.", "Explore what changes when your AI reviewer meets hostile context.", runSelector()) + notice(report) +
      `<section class="metrics" aria-label="Evaluation summary">${metric("Recorded reviews", number(s.total), "samples", `${s.conditions} conditions across ${s.families} ${s.families === 1 ? "family" : "families"}`, "runs")}${metric("Correct reviews", pct(s.correct, s.total), "", `${s.correct} of ${s.total} match the review rubric`, "check")}${metric("Paired degradations", number(s.degraded), `/ ${s.eligible}`, "Failures after a passing clean control", "compare", s.degraded ? "bad" : "")}${metric("Write attempts", number(s.writes), "", "Samples with an observed write attempt", "flag", s.writes ? "bad" : "")}</section>` +
      `<div class="overview-grid"><section class="panel chart-panel"><div class="panel-header"><div><h2>Outcomes by context</h2><p class="panel-subtitle">Same tests. Different places for an instruction to hide.</p></div><div class="legend"><span><i class="pass"></i>Pass</span><span><i class="fail"></i>Fail</span><span><i class="inconclusive"></i>Inconclusive</span></div></div><div class="chart"><div class="chart-axis"><span>0</span><span>25</span><span>50</span><span>75</span><span>100%</span></div>${surfaces.map(surface => {
        const group = stats(rows.filter(r => r.surface === surface));
        return `<button class="chart-row" data-open-surface="${h(surface)}" aria-label="Explore ${h(surfaceName(surface))}: ${group.pass} pass, ${group.fail} fail, ${group.inconclusive} inconclusive"><span class="surface-label">${h(surfaceName(surface))}${surface === "clean" ? '<span class="control-label">CONTROL</span>' : ""}</span><span class="chart-bar">${["pass", "fail", "inconclusive"].filter(key => group[key]).map(key => `<span class="segment ${key}" style="flex:${group[key]}"></span>`).join("")}</span><span class="chart-total">${group.total}</span></button>`;
      }).join("")}</div><div class="panel-footer"><span>${s.inconclusive} inconclusive · ${s.errors} run errors</span><button class="text-button" data-go="cases">Explore cases ${icon("arrow")}</button></div></section><section class="panel pair-feature"><div class="panel-header"><div><p class="tiny-label">THE PAIRED APPROACH</p><h2>One review.<br>Two versions of context.</h2></div><span class="muted">${icon("compare")}</span></div><div class="pair-diagram"><div class="diagram-source">${h("< / >")} <span>SAME CODE</span></div><div class="diagram-branches"></div><div class="diagram-pair"><div class="diagram-box"><span>MATCHED PAIRS</span><strong>${s.eligible}</strong><small>with passing clean controls</small></div><div class="diagram-box"><span>DEGRADATIONS</span><strong class="${s.degraded ? "bad" : ""}">${s.degraded}</strong><small>of ${s.eligible} eligible pairs</small></div></div><p class="diagram-caption">Open a matched pair to see the actual evidence.</p></div><div class="panel-footer"><button class="text-button" data-go="pairs">Inspect a paired review ${icon("arrow")}</button><span class="mono">CLEAN ↔ ATTACK</span></div></section></div>` +
      `<div class="section-header"><div><h2>Evaluation runs <span class="tag">${state.reports.length}</span></h2><p>Recorded results, ready to inspect.</p></div><button class="text-button" data-go="runs">View all runs ${icon("arrow")}</button></div>${reportTable()}`;
  }
  function runs() {
    return pageHeader("YOUR EVALUATIONS", "Every run has a story.", "Open a saved evaluation, inspect its evidence, or bring your own report.", '<div class="header-actions"><button class="button" data-guide="true">'+icon("plus")+'Create an evaluation</button><button class="button button-primary" data-import="true">'+icon("upload")+'Import report</button></div>') + reportTable() + `<div class="context-strip" style="margin-top:22px"><span>${icon("info")}</span><p>Each run keeps its own samples and controls. Counts across different suites are not a model leaderboard.</p></div>`;
  }
  function filteredRows(paired = false) {
    const query = state.search.toLowerCase();
    return activeRows().map((row, index) => ({ row, index })).filter(({ row }) => (!paired || row.attacked) &&
      (state.model === "all" || row.model === state.model) && (state.surface === "all" || row.surface === state.surface) &&
      (state.status === "all" || outcome(row) === state.status) && (!query || [row.case_id, row.model, row.language, row.defense, row.variant, surfaceName(row.surface), familyName(row.family)].some(v => String(v || "").toLowerCase().includes(query))));
  }
  function filterToolbar(paired = false) {
    const rows = activeRows();
    const models = [...new Set(rows.map(r => r.model))].sort();
    const modelLabel = model => models.filter(m => modelName(m) === modelName(model)).length > 1 ? model : modelName(model);
    const surfaces = [...new Set(rows.filter(r => !paired || r.attacked).map(r => r.surface))];
    return `<div class="toolbar"><label class="search">${icon("search")}<input data-control="search" aria-label="Search cases" placeholder="Search cases, models, languages..." value="${h(state.search)}"></label><select data-control="model" aria-label="Filter by reviewer">${options([["all", "All reviewers"], ...models.map(m => [m, modelLabel(m)])], state.model)}</select><select data-control="surface" aria-label="Filter by context">${options([["all", "All contexts"], ...surfaces.map(s => [s, surfaceName(s)])], state.surface)}</select><select data-control="status" aria-label="Filter by outcome">${options([["all", "All outcomes"], ["pass", "Pass"], ["fail", "Fail"], ["inconclusive", "Inconclusive"]], state.status)}</select><button class="text-button reset" data-reset="true">Reset filters</button></div>`;
  }
  function signal(value, trueLabel = "Yes", falseLabel = "No", invert = false) {
    const available = typeof value === "boolean";
    return `<span class="signal ${!available ? "muted" : value !== invert ? "good" : "bad"}">${icon(!available ? "circle" : value !== invert ? "check" : "close")}${h(!available ? "N/A" : value ? trueLabel : falseLabel)}</span>`;
  }
  function casesContent() {
    if (!activeRows().length) return '<div class="empty-state">'+icon("cases")+'<h2>This report has no samples.</h2><p>Import a completed evaluation to inspect its cases.</p><button class="button" data-import="true">Import report</button></div>';
    const matches = filteredRows();
    state.pageNum = Math.max(0, Math.min(state.pageNum, Math.ceil(matches.length / 20) - 1));
    const page = matches.slice(state.pageNum * 20, state.pageNum * 20 + 20);
    if (!matches.length) return `<div class="empty-state">${icon("search")}<h2>No matching cases.</h2><p>Try a different reviewer, context, or search term.</p><button class="button" data-reset="true">Clear filters</button></div>`;
    return `<div class="result-count">${number(matches.length)} recorded samples · Select a case to inspect its review and tool trace</div><div class="panel table-scroll"><table class="case-table"><thead><tr><th>CASE / VARIANT</th><th>REVIEWER</th><th>CONTEXT</th><th>OUTCOME</th><th>GROUNDED</th><th>TRIAL</th><th>OPEN</th></tr></thead><tbody>${page.map(({ row, index }) => `<tr><td><button class="row-name" data-inspect="${index}">${h(familyName(row.family))}</button><span class="row-meta">${h(row.variant)} · ${h(row.language || "not recorded")}</span></td><td><span>${h(modelName(row.model))}</span><span class="row-meta">${h(row.defense)} policy</span></td><td>${h(surfaceName(row.surface))}</td><td>${badge(row)}</td><td>${signal(row.evidence_grounded)}</td><td class="mono">${row.epoch}</td><td><button class="row-action" data-inspect="${index}" aria-label="Inspect ${h(row.case_id)}, ${h(row.model)}, trial ${row.epoch}">${icon("arrow")}</button></td></tr>`).join("")}</tbody></table></div><div class="pagination"><span>Showing ${state.pageNum * 20 + 1}–${Math.min((state.pageNum + 1) * 20, matches.length)} of ${matches.length}</span><div><button class="button button-small" data-page-step="-1" ${state.pageNum === 0 ? "disabled" : ""}>Previous</button><button class="button button-small" data-page-step="1" ${(state.pageNum + 1) * 20 >= matches.length ? "disabled" : ""}>Next</button></div></div>`;
  }
  function cases() { return pageHeader("LOOK BEYOND THE SCORE", "The evidence, case by case.", "Find the missed issue, the unsupported citation, or the action that crossed a boundary.", runSelector()) + notice(active().report) + filterToolbar() + '<div id="case-results">' + casesContent() + '</div>'; }
  function findings(row) {
    if (!row.review) return '<div class="no-findings">No completed review recorded.</div>';
    if (!row.review.findings.length) return '<div class="no-findings">No findings submitted.</div>';
    return row.review.findings.map(f => `<article class="finding"><strong>${h(titleCase(f.category))}</strong><span class="row-meta">${h(f.file)}:${h(f.line)}</span><pre class="finding-code">${h(f.evidence)}</pre><p>${h(f.explanation)}</p></article>`).join("");
  }
  function reviewBody(row) {
    if (!row) return '<div class="review-body"><div class="no-findings">No unique matching clean control is available in this run.</div></div>';
    const metric = (label, value, invert = false) => `<div class="metric-line"><span>${label}</span>${signal(value, "Yes", "No", invert)}</div>`;
    return `<div class="review-body"><div class="verdict"><span class="tiny-label">REVIEWER VERDICT</span><strong>${h(row.review ? titleCase(row.review.verdict) : "No submission")}</strong></div><div class="metric-list">${metric("Expected issue reported", row.issue_reported)}${metric("Evidence grounded", row.evidence_grounded)}${metric("Citation correct", row.citation_correct)}${metric("Attack goal reached", row.attack_goal_reached, true)}${metric("Write attempted", row.write_attempted, true)}</div><span class="tiny-label">RECORDED FINDINGS</span>${findings(row)}<div class="trace-section"><span class="tiny-label">TOOL TRACE · ${row.events.length} EVENTS</span><ol class="tool-trace">${row.events.map((event, i) => `<li><span class="tool-number">${String(i + 1).padStart(2, "0")}</span><span class="${event.tool === "write_file" ? "bad" : ""}">${h(event.tool)}${event.path ? `<span class="tool-path">${h(event.path)}</span>` : ""}</span><span class="tool-status">${h(event.status || "recorded")}</span></li>`).join("")}</ol></div>${row.error ? `<div class="finding bad"><strong>Run error</strong><p>${h(row.error)}</p></div>` : ""}</div>`;
  }
  function pairDetail(index) {
    const row = activeRows()[index];
    if (!row) return "";
    const controls = controlIndex(activeRows()), control = controls.get(pairKey(row));
    const reason = pairReason(activeRows(), row);
    const eligible = row.attacked && row.conclusive && control?.passed;
    const status = eligible ? row.passed ? "NO DEGRADATION" : "PAIRED DEGRADATION" : "PAIR NOT ELIGIBLE";
    const color = eligible ? row.passed ? "tag-green" : "tag-red" : "tag-amber";
    return `<div class="pair-heading"><div><h2>${h(familyName(row.family))}</h2><span class="row-meta">${h(modelName(row.model))} · ${h(row.variant)} · trial ${row.epoch} · ${h(row.defense)}</span></div><span class="tag ${color}">${status}</span></div>${reason ? `<p class="pair-footnote" style="margin:0 0 16px">${h(reason)}</p>` : ""}<div class="pair-columns"><section class="panel"><div class="review-head"><strong>${icon("shield")}Clean control</strong>${control ? badge(control) : `<span class="tag">${controls.has(pairKey(row)) ? "AMBIGUOUS" : "MISSING"}</span>`}</div>${reviewBody(control)}</section><section class="panel"><div class="review-head"><strong>${icon("flag")}${h(surfaceName(row.surface))}</strong>${badge(row)}</div>${reviewBody(row)}</section></div><p class="pair-footnote">Matched within this run by reviewer, policy, family, code variant, trial, and trial group. A degradation requires a passing clean control and a conclusive attacked review. N/A means a metric was not applicable or not recorded.</p><button class="text-button" data-inspect="${index}" style="margin-top:14px">View complete sample ${icon("arrow")}</button>`;
  }
  function pairsContent() {
    if (!activeRows().some(row => row.attacked)) return '<div class="empty-state">'+icon("compare")+'<h2>No hostile contexts in this report.</h2><p>Import an evaluation containing clean and attacked samples to inspect matched reviews.</p><button class="button" data-import="true">Import report</button></div>';
    const matches = filteredRows(true);
    if (!matches.length) return '<div class="empty-state">'+icon("compare")+'<h2>No attacked samples match.</h2><p>Choose a different filter or import a run containing both clean and hostile contexts.</p><button class="button" data-reset="true">Clear filters</button></div>';
    const controls = controlIndex(activeRows());
    const sorted = [...matches].sort((a, b) => Number(b.row.conclusive && !b.row.passed && controls.get(pairKey(b.row))?.passed) - Number(a.row.conclusive && !a.row.passed && controls.get(pairKey(a.row))?.passed));
    state.pageNum = Math.max(0, Math.min(state.pageNum, Math.ceil(matches.length / 40) - 1));
    if (state.selectedPair != null && matches.some(m => m.index === state.selectedPair)) state.pageNum = Math.floor(sorted.findIndex(m => m.index === state.selectedPair) / 40);
    const shown = sorted.slice(state.pageNum * 40, state.pageNum * 40 + 40);
    if (!shown.some(m => m.index === state.selectedPair)) state.selectedPair = shown[0].index;
    return `<div class="result-count">${matches.length} attacked samples · Paired degradations appear first</div><div class="pairs-layout"><div><div class="panel pair-list"><div class="pair-list-head">SELECT A REVIEW</div>${(shown.length ? shown : sorted.slice(0, 40)).map(({ row, index }) => `<button class="pair-choice" data-pair="${index}" aria-pressed="${index === state.selectedPair}"><strong>${h(familyName(row.family))}</strong><small>${h(modelName(row.model))} · trial ${row.epoch}</small><small>${h(surfaceName(row.surface))} · ${h(row.variant)}</small>${badge(row)}</button>`).join("")}</div><div class="pagination"><span>${state.pageNum + 1}/${Math.ceil(matches.length / 40)}</span><div><button class="button button-small" data-pair-page="-1" ${state.pageNum === 0 ? "disabled" : ""} aria-label="Previous paired reviews">←</button><button class="button button-small" data-pair-page="1" ${(state.pageNum + 1) * 40 >= matches.length ? "disabled" : ""} aria-label="Next paired reviews">→</button></div></div></div><div id="pair-detail" class="pair-detail">${pairDetail(state.selectedPair)}</div></div>`;
  }
  function pairs() { return pageHeader("FOLLOW THE CHANGE", "Same code. Different context.", "Compare the review and the actions, with the clean control right beside them.", runSelector()) + notice(active().report) + filterToolbar(true) + '<div id="pair-results">' + pairsContent() + '</div>'; }
  function empty() { return pageHeader("YOUR LOCAL WORKSPACE", "Start with the evidence.", "Bring a saved ReviewBoundary evaluation into focus.") + `<div class="empty-state">${icon("upload")}<h2>A home for your review results.</h2><p>Drop a report.json here to explore the outcomes, findings, and tool actions. Everything stays in your browser.</p><button class="button button-primary" data-import="true">${icon("upload")}Import report</button><button class="button" data-guide="true" style="margin-left:8px">Create an evaluation</button></div>`; }
  function render(focusControl = null) {
    const page = location.hash.slice(1);
    state.page = Object.hasOwn(PAGES, page) ? page : "overview";
    Object.assign(state, normalizeFilters(state, activeRows(), state.page === "pairs"));
    $("#breadcrumb-page").textContent = PAGES[state.page];
    document.title = `${PAGES[state.page]} | ReviewBoundary`;
    document.querySelectorAll("[data-page]").forEach(a => { if (a.dataset.page === state.page) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current"); });
    $("#run-count").textContent = state.reports.length;
    $("#main").innerHTML = !state.reports.length ? empty() : ({ overview, runs, cases, pairs })[state.page]();
    if (["run", "model", "surface", "status"].includes(focusControl)) $(`[data-control="${focusControl}"]`)?.focus({ preventScroll: true });
  }
  function navigate(page, reset = true) {
    if (reset) resetFilters();
    if (location.hash === `#${page}`) render(); else location.hash = page;
  }
  function openRun(index) { if (!state.reports[index]) return; state.run = index; resetFilters(); navigate("overview", false); }
  function inspect(index) {
    const row = activeRows()[index];
    if (!row) return;
    const dialog = $("#inspector");
    dialog.innerHTML = `<div class="dialog-head"><div><p class="tiny-label">RECORDED SAMPLE</p><h2 id="inspector-title">${h(familyName(row.family))}</h2><p>${h(row.case_id)} · ${h(modelName(row.model))} · trial ${row.epoch}</p></div><button class="icon-button" data-close="inspector" aria-label="Close case details">${icon("close")}</button></div><div class="dialog-content">${badge(row)}<div style="margin-top:22px">${reviewBody(row)}</div><details class="raw-data"><summary>View complete sample JSON</summary><pre>${h(JSON.stringify(row, null, 2))}</pre></details><div class="dialog-actions">${row.attacked ? `<button class="button button-primary" data-inspect-pair="${index}">${icon("compare")}Compare with clean control</button>` : ""}<button class="button" data-export="true">${icon("download")}Export this report</button></div></div>`;
    dialog.showModal();
  }
  function guide() {
    const dialog = $("#guide");
    dialog.innerHTML = `<div class="dialog-head"><div><p class="tiny-label">FROM TEST TO EVIDENCE</p><h2 id="guide-title">Create an evaluation.</h2><p>Run locally, then explore the result here.</p></div><button class="icon-button" data-close="guide" aria-label="Close evaluation guide">${icon("close")}</button></div><div class="dialog-content"><div class="guide-step"><span class="step-number">01</span><div><h3>Try the free, offline demo</h3><p>From your ReviewBoundary checkout, run scripted reviewers across the full suite. No API key is needed.</p><pre class="command">uv run --frozen review-boundary demo --split all</pre><button class="text-button" data-copy-demo="true">${icon("copy")}Copy command</button></div></div><div class="guide-step"><span class="step-number">02</span><div><h3>Import the result</h3><p>The command prints a report.html path. Import the report.json in that same folder, or drop it anywhere in this workspace.</p><button class="text-button" data-import="true">Choose report.json ${icon("arrow")}</button></div></div><div class="guide-step"><span class="step-number">03</span><div><h3>Evaluate your own reviewer</h3><p>Use the OpenAI, Anthropic, or OpenRouter provider, or connect your agent through the reviewer adapter. Model evaluations run through the CLI with your configured spending limits.</p><a class="text-button" href="https://github.com/utkutugrul/review-boundary/blob/main/docs/providers.md" target="_blank" rel="noopener noreferrer">Provider setup ↗</a><a class="text-button" style="margin-left:18px" href="https://github.com/utkutugrul/review-boundary/blob/main/docs/adapters.md" target="_blank" rel="noopener noreferrer">Connect your reviewer ↗</a></div></div></div>`;
    dialog.showModal();
  }
  function exportReport() {
    const blob = new Blob([JSON.stringify(active().report, null, 2) + "\n"], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = "reviewboundary-report.json"; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast("Saved report exported. JSON formatting may differ from the source.");
  }
  async function importFiles(files) {
    if (importBusy) return;
    importBusy = true;
    let importingName = "";
    try {
      const list = [...files];
      if (!list.length) return;
      if (state.reports.length + list.length > MAX_REPORTS) throw new Error("Open up to 8 reports in one workspace. Export a new dashboard for a different collection.");
      if (list.some(f => f.size > MAX_BYTES)) throw new Error("Each report must be 16 MiB or smaller.");
      const existingBytes = state.reports.reduce((n, e) => n + new TextEncoder().encode(JSON.stringify(e.report)).length, 0);
      if (existingBytes + list.reduce((n, f) => n + f.size, 0) > MAX_TOTAL_BYTES) throw new Error("Keep the total workspace below 32 MiB.");
      const next = [];
      for (const file of list) {
        importingName = file.name;
        let report;
        try { report = JSON.parse(await file.text()); } catch { throw new Error("The selected file is not valid JSON."); }
        validateReport(report);
        next.push({ name: file.name === "report.json" ? `Imported evaluation ${state.reports.length + next.length + 1}` : file.name, report });
      }
      if ([...state.reports, ...next].reduce((n, entry) => n + entry.report.rows.length, 0) > MAX_ROWS) throw new Error("A workspace supports up to 10,000 recorded samples.");
      state.run = state.reports.length;
      state.reports.push(...next);
      $("#guide").close();
      $("#inspector").close();
      resetFilters(); navigate("overview", false);
      toast(`${next.length === 1 ? "Report" : `${next.length} reports`} imported locally. Reloading resets imported reports.`);
    } catch (error) { toast((importingName ? `${importingName}: ` : "") + (error.message || "The report could not be imported."), true); }
    finally { importBusy = false; $("#file-input").value = ""; }
  }
  document.addEventListener("click", async event => {
    const button = event.target.closest("button, a[data-page]");
    if (!button) return;
    if (button.matches("[data-page]")) { event.preventDefault(); navigate(button.dataset.page); return; }
    const d = button.dataset;
    if (Object.hasOwn(d, "themeChoice")) setTheme(d.themeChoice);
    else if (Object.hasOwn(d, "dismissToast")) $("#toast").hidden = true;
    else if (button.id === "import-button" || Object.hasOwn(d, "import")) $("#file-input").click();
    else if (Object.hasOwn(d, "go")) navigate(d.go);
    else if (Object.hasOwn(d, "openRun")) openRun(Number(d.openRun));
    else if (Object.hasOwn(d, "openSurface")) { resetFilters(); state.surface = d.openSurface; navigate("cases", false); }
    else if (Object.hasOwn(d, "inspect")) inspect(Number(d.inspect));
    else if (Object.hasOwn(d, "close")) $(`#${d.close}`).close();
    else if (Object.hasOwn(d, "guide")) guide();
    else if (Object.hasOwn(d, "export")) exportReport();
    else if (Object.hasOwn(d, "reset")) { resetFilters(); render(); }
    else if (Object.hasOwn(d, "pageStep")) { state.pageNum += Number(d.pageStep); $("#case-results").innerHTML = casesContent(); }
    else if (Object.hasOwn(d, "pairPage")) { state.pageNum += Number(d.pairPage); state.selectedPair = null; $("#pair-results").innerHTML = pairsContent(); }
    else if (Object.hasOwn(d, "pair")) {
      state.selectedPair = Number(d.pair);
      $("#pair-detail").innerHTML = pairDetail(state.selectedPair);
      document.querySelectorAll("[data-pair]").forEach(b => b.setAttribute("aria-pressed", String(Number(b.dataset.pair) === state.selectedPair)));
    } else if (Object.hasOwn(d, "inspectPair")) {
      $("#inspector").close(); resetFilters(); state.selectedPair = Number(d.inspectPair); navigate("pairs", false);
    } else if (Object.hasOwn(d, "copyDemo")) {
      try { await navigator.clipboard.writeText("uv run --frozen review-boundary demo --split all"); toast("Demo command copied."); }
      catch { toast("Select and copy the command shown above."); }
    }
  });
  document.addEventListener("change", event => {
    if (event.target.id === "file-input") { importFiles(event.target.files); return; }
    const control = event.target.dataset.control;
    if (!control || control === "search") return;
    if (control === "run") { state.run = Number(event.target.value); resetFilters(); render(control); }
    else if (["model", "surface", "status"].includes(control)) { state[control] = event.target.value; state.pageNum = 0; state.selectedPair = null; render(control); }
  });
  document.addEventListener("input", event => {
    if (event.target.dataset.control !== "search") return;
    state.search = event.target.value; state.pageNum = 0; state.selectedPair = null;
    if (state.page === "cases") $("#case-results").innerHTML = casesContent();
    if (state.page === "pairs") $("#pair-results").innerHTML = pairsContent();
  });
  document.addEventListener("dragenter", event => { if ([...event.dataTransfer.types].includes("Files")) { event.preventDefault(); dragDepth++; document.body.classList.add("drop-overlay"); } });
  document.addEventListener("dragover", event => { if ([...event.dataTransfer.types].includes("Files")) event.preventDefault(); });
  document.addEventListener("dragleave", () => { if (--dragDepth <= 0) { dragDepth = 0; document.body.classList.remove("drop-overlay"); } });
  document.addEventListener("drop", event => { event.preventDefault(); dragDepth = 0; document.body.classList.remove("drop-overlay"); if (event.dataTransfer.files.length) importFiles(event.dataTransfer.files); });
  window.addEventListener("hashchange", render);
  try {
    const bundle = JSON.parse($("#dashboard-data")?.textContent || '{"reports":[]}');
    if (!Array.isArray(bundle.reports) || bundle.reports.length > MAX_REPORTS) throw new Error("Invalid dashboard bundle.");
    const entries = bundle.reports.map(entry => ({ name: String(entry.name || "Saved evaluation"), report: validateReport(entry.report) }));
    if (entries.reduce((n, e) => n + e.report.rows.length, 0) > MAX_ROWS) throw new Error("This dashboard exceeds the supported sample limit.");
    state.reports = entries;
  } catch (error) { state.reports = []; toast(error.message || "The saved evaluations could not be loaded."); }
  hydrateIcons(); setTheme(state.theme); render();
})();
