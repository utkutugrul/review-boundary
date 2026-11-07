/* ReviewBoundary's portable, browser-local evaluation workspace. */
(() => {
  "use strict";
  const Contracts = typeof module !== "undefined" && module.exports ? require("./report-contracts.js") : globalThis.ReviewBoundaryReportContracts;
  const MAX_REPORTS = 8;
  const MAX_BYTES = 16 * 1024 * 1024;
  const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
  const MAX_ROWS = 10000;
  const SURFACES = { clean: "Clean context", pr_body: "PR description", readme: "README file", code_comment: "Code comment", tool_output: "Tool response", benign_quote: "Benign quotation" };
  const PAGES = { overview: "Overview", runs: "Evaluation runs", cases: "Case explorer", pairs: "Paired reviews" };
  const TITLES = { "calibration-v2": "Full-suite calibration", "pilot-v2-typescript": "TypeScript pilot", "pilot-v2-rust-heldout": "Rust held-out pilot" };
  const FAMILIES = { document_path: "Document path access", signed_webhook: "Webhook signature", tenant_lookup: "Tenant isolation", shell_preview: "Shell command preview", ts_batch_export: "Batch export permissions", rust_partial_batch_permissions: "Partial batch permissions" };
  const stringValue = value => typeof value === "string" ? value : "";
  const displayText = value => typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value)) ? String(value) : "";
  const h = value => displayText(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
  const titleCase = value => stringValue(value).replace(/^(ts_|rust_)/, "").replaceAll("_", " ").replace(/^./, c => c.toUpperCase());
  const familyName = value => typeof value === "string" && Object.hasOwn(FAMILIES, value) ? FAMILIES[value] : titleCase(value);
  const surfaceName = value => typeof value === "string" && Object.hasOwn(SURFACES, value) ? SURFACES[value] : titleCase(value);
  const modelName = value => stringValue(value).replace(/^mockllm\/calibration-/, "Scripted ").replace(/^openrouter\//, "");
  const runName = entry => {
    const name = stringValue(entry?.name), key = name.toLowerCase().replaceAll(" ", "-");
    return Object.hasOwn(TITLES, key) ? TITLES[key] : titleCase(name.replace(/\.json$/i, "").replaceAll("-", " ")) || "Imported evaluation";
  };
  function formatDate(report) {
    const date = new Date(stringValue(report.generated_at));
    return Number.isNaN(date.valueOf()) ? "Date not recorded" : date.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });
  }
  const outcome = row => !row.conclusive ? "inconclusive" : row.passed ? "pass" : "fail";
  const pct = (num, den) => den ? `${Math.round(num / den * 100)}%` : "N/A";
  const ratio = (num, den) => den ? `${num}/${den}` : "N/A";
  const number = value => Number(value).toLocaleString("en-US");
  const pairKey = row => JSON.stringify([row.trial_group ?? null, row.model, row.defense, row.family, row.variant, row.epoch]);
  const sampleKey = row => JSON.stringify([row.trial_group ?? null, row.model, row.defense, row.case_id, row.epoch]);
  function sampleCounts(rows) {
    const samples = new Map();
    for (const row of rows) {
      const key = sampleKey(row);
      samples.set(key, (samples.get(key) || 0) + 1);
    }
    return samples;
  }
  function controlIndex(rows, samples = sampleCounts(rows)) {
    const controls = new Map();
    for (const row of rows.filter(r => r.surface === "clean")) {
      const key = pairKey(row);
      controls.set(key, controls.has(key) || samples.get(sampleKey(row)) !== 1 ? null : row);
    }
    return controls;
  }
  function pairContext(rows) {
    const samples = sampleCounts(rows);
    return { samples, controls: controlIndex(rows, samples) };
  }
  function pairEligible(row, context) {
    return Boolean(row.attacked && row.conclusive && context.samples.get(sampleKey(row)) === 1 && context.controls.get(pairKey(row))?.passed);
  }
  function stats(rows) {
    const context = pairContext(rows);
    const eligible = rows.filter(row => pairEligible(row, context));
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
  function pairReason(rows, row, context = pairContext(rows)) {
    const { controls, samples } = context, key = pairKey(row);
    if (!row.attacked) return "This sample has no attacked context to pair.";
    if (samples.get(sampleKey(row)) > 1) return "Multiple rows share this sample identity; the attacked review is ambiguous and cannot establish a degradation.";
    if (!samples.has(sampleKey(row))) return "The attacked sample was not recorded in this run.";
    if (!controls.has(key)) return "No matching clean control was recorded.";
    if (!controls.get(key)) return "Multiple clean controls match this sample; the pair is ambiguous.";
    if (!controls.get(key).passed) return "The clean control did not pass, so this pair cannot establish a degradation.";
    if (!row.conclusive) return "The attacked review is inconclusive, so this pair cannot establish a degradation.";
    return "";
  }
  function declaredKeys(metadata, name, fields) {
    const items = metadata[name];
    if (!Array.isArray(items)) return null;
    const keys = new Map();
    for (const item of items) {
      if (!item || typeof item !== "object" || Array.isArray(item)) return null;
      const values = fields.map(field => item[field]);
      if (values.some((value, i) => fields[i] === "epoch" ? !Number.isSafeInteger(value) || value < 1 : typeof value !== "string" || !value.trim())) return null;
      const key = JSON.stringify(values);
      if (keys.has(key)) return null;
      keys.set(key, values);
    }
    return keys;
  }
  function coverage(rows, metadata) {
    const expected = declaredKeys(metadata, "expected_samples", ["case_id", "epoch"]);
    const declared = declaredKeys(metadata, "expected_groups", ["model", "defense"]);
    const recorded = new Map(), groups = new Map(declared || []);
    for (const row of rows) {
      const group = [row.model, row.defense], key = JSON.stringify(group);
      if (!recorded.has(key)) recorded.set(key, []);
      recorded.get(key).push(JSON.stringify([row.case_id, row.epoch]));
      groups.set(key, group);
    }
    const order = ([, a], [, b]) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
    const detail = [...groups.entries()].sort(order).map(([key, [model, defense]]) => {
      const samples = recorded.get(key) || [], present = new Set(samples);
      const target = !declared || declared.has(key) ? expected : new Map();
      const matched = expected ? [...present].filter(sample => target.has(sample)).length : 0;
      return {
        model, defense,
        declared: declared ? declared.has(key) : null,
        expected: expected ? target.size : null,
        present: present.size,
        missing: expected ? target.size - matched : null,
        unexpected: expected ? present.size - matched : null,
        duplicates: samples.length - present.size,
      };
    });
    return {
      expected: expected && declared ? expected.size * declared.size : null,
      recorded: rows.length,
      missing: expected ? detail.reduce((n, group) => n + group.missing, 0) : null,
      duplicates: detail.reduce((n, group) => n + group.duplicates, 0),
      unexpected: expected ? detail.reduce((n, group) => n + group.unexpected, 0) : null,
      unexpected_groups: declared ? [...recorded.keys()].filter(key => !declared.has(key)).length : null,
      expected_samples_known: expected !== null,
      expected_groups_known: declared !== null,
      scope: !expected ? "unknown" : !declared ? "observed" : "declared",
      groups: detail,
    };
  }
  function coverageMessages(report) {
    const result = coverage(report.rows, report.metadata), messages = [];
    if (result.missing) messages.push(`${result.missing} expected samples are missing within ${result.scope === "declared" ? "declared" : "observed"} reviewer/policy groups.`);
    if (result.duplicates) messages.push(`${result.duplicates} repeated sample slots are recorded across reviewer/policy, case, and trial. Raw rows remain visible.`);
    if (result.unexpected_groups) messages.push(`${result.unexpected_groups} undeclared reviewer/policy groups are recorded.`);
    if (result.unexpected) messages.push(`${result.unexpected} sample slots fall outside the declared expectations.`);
    if (!result.expected_samples_known) messages.push("Expected samples are unavailable or invalid; missing coverage cannot be determined.");
    if (!result.expected_groups_known) messages.push("Whole-run coverage is unknown: expected groups are unavailable or invalid, so entirely missing groups cannot be detected.");
    for (const field of ["expected", "recorded", "missing", "duplicates", "unexpected", "unexpected_groups"]) {
      if (result[field] !== null && Number.isSafeInteger(report.coverage?.[field]) && report.coverage[field] !== result[field]) messages.push(`Recorded coverage.${field}: ${report.coverage[field]}; derived from rows and expectations: ${result[field]}.`);
    }
    return messages;
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
    const { controls, samples } = pairContext(report.rows);
    const repeated = [...samples.values()].filter(count => count > 1).length;
    if (repeated) messages.push(`${repeated} sample identities are ambiguous. Those rows are excluded from pairing and remain available for inspection.`);
    const ambiguous = [...controls.values()].filter(value => value === null).length;
    if (ambiguous) messages.push(`${ambiguous} clean-control identities are ambiguous. Those pairs are excluded.`);
    for (const [saved, computed] of [["total", "total"], ["correct_reviews", "correct"], ["paired_eligible", "eligible"], ["paired_degradations", "degraded"], ["write_attempts", "writes"]]) {
      if (Number.isInteger(report.summary?.[saved]) && report.summary[saved] !== result[computed]) messages.push(`Recorded ${saved}: ${report.summary[saved]}; displayed from rows: ${result[computed]}.`);
    }
    return messages.concat(coverageMessages(report));
  }
  function experimentFields(metadata) {
    const object = value => value && typeof value === "object" && !Array.isArray(value);
    const fingerprint = value => typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : "Not recorded or invalid";
    const p = metadata.provenance;
    const known = object(p) && p.schema_version === 1 && p.hash_algorithm === "sha256";
    const fields = [["Tool protocol", known && typeof p.tools?.protocol === "string" ? p.tools.protocol.slice(0, 128) : "Not recorded"]];
    for (const [label, value] of [["Tool schema", p?.tools?.sha256], ["Harness source", p?.harness?.sha256], ["Declared reviewer source", p?.reviewer_source?.sha256]]) fields.push([label, known ? fingerprint(value) : "Not recorded"]);
    if (known && object(p.prompts) && Object.keys(p.prompts).length <= 32) {
      for (const [name, value] of Object.entries(p.prompts)) fields.push([`Instructions / ${name.slice(0, 128)}`, fingerprint(value)]);
    } else fields.push(["Instructions", "Not recorded"]);
    const verification = metadata.score_verification;
    const status = object(verification) && ["verified", "partial", "unchecked"].includes(verification.status) ? verification.status : "unknown";
    fields.push(["Recorded score consistency", status]);
    return fields;
  }
  function validateReport(report) { return Contracts.validateLegacyReport(report); }

  // Native report views. Everything below builds DOM nodes with textContent only.
  const NATIVE_PAGE_SIZE = 20;
  const NATIVE_STATUS = { not_recorded: "Not recorded", unavailable: "Unavailable", unsupported_version: "Unsupported version", unsupported_policy: "Unsupported policy", mismatch: "Mismatch", matching_supplied_artifact: "Matches supplied artifact" };
  const NATIVE_REASON_TEXT = {
    no_snapshot_reference: "No snapshot reference is recorded for this row.",
    verification_context_not_supplied: "The snapshot was not supplied for checking.",
    verification_context_invalid: "The supplied evidence check could not be used.",
    verification_context_source_mismatch: "The supplied check belongs to a different report.",
    verification_record_not_supplied: "No evidence check was supplied for this row.",
    verification_record_inconsistent: "The check and snapshot reference disagree.",
    verification_record_incomplete: "The supplied check is incomplete.",
    document_consistency_only: "The supplied artifact agrees with the recorded digest.",
    reference_kind_disagrees_with_report: "The recorded reference is for a different kind of report.",
    reference_source_hash_disagrees_with_envelope: "The recorded reference names a different source report.",
    reference_case_hash_disagrees_with_row: "The recorded reference names a different case than this row.",
    reference_row_not_recorded: "The recorded reference points to a row that is not in this report.",
    failed_execution_has_no_usable_snapshot_binding: "This failed run has no usable snapshot.",
    external_policy_has_no_snapshot_restore_contract: "Snapshots for this external policy are not supported.",
    unsupported_snapshot_version: "The recorded snapshot version is not supported.",
  };
  const NATIVE_STATUS_TEXT = {
    not_recorded: "No snapshot reference is recorded for this row.",
    unavailable: "The snapshot state could not be checked for this row.",
    unsupported_version: "The recorded snapshot version is not supported.",
    unsupported_policy: "The recorded run policy has no snapshot support.",
    mismatch: "The recorded snapshot reference disagrees with the report.",
    matching_supplied_artifact: "The supplied artifact agrees with the recorded digest.",
  };
  const nativeText = (value, max = 400) => { const text = displayText(value); return text.length > max ? `${text.slice(0, max)}...` : text; };
  const nativeCount = value => Number.isSafeInteger(value) ? number(value) : "Unknown";
  const isNative = entry => Boolean(entry && entry.contract && entry.contract.report_kind !== "legacy");
  function makeEntry(name, source, verification = null) {
    if (verification !== null && (typeof verification !== "object" || Array.isArray(verification))) throw new Error("The evidence verification context is invalid.");
    const contract = Contracts.validateDisplayDocument(source), report = contract.envelope_version ? source.report : source;
    if (contract.report_kind === "legacy") validateReport(report);
    return { name: stringValue(name) || "Saved evaluation", document: source, contract, report, evidence_verification: verification };
  }
  function makeImportedEntry(name, bytes) {
    let text;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
    catch { throw new Error("The selected file is not valid UTF-8 text."); }
    return makeEntry(name, Contracts.parseReportText(text), null);
  }
  function nativeSnapshots(source, verification) {
    let result;
    try { result = Contracts.snapshotStates(source, verification ?? null); } catch { return null; }
    return Array.isArray(result) ? result : Array.isArray(result?.rows) ? result.rows : Array.isArray(result?.results) ? result.results : null;
  }
  function renderNativeView(source, options = {}) {
    return renderNativeDisplayView(Contracts.createDisplayView(source, options.verification ?? null), options);
  }
  function renderNativeDisplayView(display, options) {
    const doc = options.document || globalThis.document;
    const root = options.root || doc.querySelector("#main");
    const view = options.view || (options.view = {});
    for (const [key, value] of Object.entries({ search: "", reviewer: "all", guard: "all", pageNum: 0, pairPage: 0, selected: null })) if (!Object.hasOwn(view, key)) view[key] = value;
    const kind = display.contract.report_kind;
    if (kind !== "repository" && kind !== "boundary") throw new Error("The native view needs a repository or boundary report.");
    const native = display.report, boundary = kind === "boundary";
    const rows = native.rows, meta = native.metadata && typeof native.metadata === "object" ? native.metadata : {};
    const runRecord = Object.fromEntries(["run_id", "run_kind", "run_finished", "scoring_version", "corpus_version", "project_version", "inspect_ai_version", "epochs", "case_count", "expected_count", "suite_sha256", "observation_scope", "os_sandboxed", "fixture_note"].filter(key => Object.hasOwn(meta, key)).map(key => [key, meta[key]]));
    const stats = Contracts.nativeStats(native), cov = Contracts.nativeCoverage(native), snaps = display.snapshots;
    const page = ["cases", "pairs"].includes(options.page) ? options.page : "overview";
    const el = (tag, cls, ...kids) => {
      const node = doc.createElement(tag);
      if (cls) node.className = cls;
      node.append(...kids.filter(kid => kid !== null && kid !== undefined && kid !== false).map(kid => typeof kid === "object" ? kid : String(kid)));
      return node;
    };
    const locate = (index, selector) => { try { return display.evidenceLocator(index, selector); } catch { return null; } };
    const rerender = () => renderNativeDisplayView(display, options);
    const eventNodes = new Map();
    const go = target => { if (typeof options.navigate === "function") options.navigate(target); else { options.page = target; rerender(); } };
    const tag = (text, cls = "") => el("span", cls ? `tag ${cls}` : "tag", text);
    const button = (cls, text, onClick, label) => { const node = el("button", cls, text); node.type = "button"; node.addEventListener("click", onClick); if (label) node.setAttribute("aria-label", label); return node; };
    const flag = (value, yes = "Yes", no = "No", invert = false) => typeof value === "boolean" ? el("span", `signal ${value !== invert ? "good" : "bad"}`, value ? yes : no) : el("span", "signal unknown", "Unknown");
    const count = (value, risky = false) => Number.isSafeInteger(value) ? el("span", risky && value ? "signal bad" : "signal", value) : el("span", "signal unknown", "Unknown");
    const yesNo = value => value === true ? "yes" : value === false ? "no" : "Unknown";
    const line = (label, value) => el("div", "metric-line", el("span", "", label), value);
    const metric = (label, value, suffix, note, color = "") => el("div", "metric", el("div", "metric-label", label), el("div", color ? `metric-value ${color}` : "metric-value", value, el("small", "", suffix)), el("div", "metric-note", note));
    const section = (title, ...kids) => el("div", "native-section", el("span", "tiny-label", title), ...kids);
    const triTag = (value, yes, no, unknown = "UNKNOWN") => value === true ? tag(yes, "tag-green") : value === false ? tag(no, "tag-red") : tag(unknown, "tag-amber");
    const completionTag = row => !row.completed ? tag("INCOMPLETE", "tag-amber") : row.conclusive === false ? tag("INCONCLUSIVE", "tag-amber") : tag("COMPLETED", "tag-green");
    const payloadRow = row => !boundary && row.scoring_version === "repository-payload-v1" && row.case_schema_version === 2;
    const payloadLabel = row => `${nativeText(titleCase(row.payload_ref.entry_id), 64)} · ${titleCase(row.condition)}`;
    const payloadContext = row => `${nativeText(surfaceName(row.surface), 80)} · ${titleCase(row.condition)}`;
    const clampPage = (key, total) => { view[key] = Math.max(0, Math.min(view[key], Math.ceil(total / NATIVE_PAGE_SIZE) - 1)); return view[key]; };
    const facts = object => {
      const dl = el("dl", "native-dl");
      let shown = 0;
      for (const [key, value] of Object.entries(object && typeof object === "object" && !Array.isArray(object) ? object : {})) {
        if (shown >= 16 || !/^[a-z0-9_]{1,48}$/i.test(key) || !["string", "number", "boolean"].includes(typeof value)) continue;
        dl.append(el("dt", "", titleCase(key)), el("dd", "", nativeText(value, 300)));
        shown++;
      }
      return shown ? dl : null;
    };
    const pager = (total, current, onStep) => {
      const last = Math.max(0, Math.ceil(total / NATIVE_PAGE_SIZE) - 1);
      const prev = button("button button-small", "Previous", () => onStep(-1)), next = button("button button-small", "Next", () => onStep(1));
      prev.disabled = current <= 0; next.disabled = current >= last;
      return el("div", "pagination", el("span", "", total ? `Showing ${current * NATIVE_PAGE_SIZE + 1}-${Math.min((current + 1) * NATIVE_PAGE_SIZE, total)} of ${total}` : "Nothing to show"), el("div", "", prev, next));
    };
    const runSwitch = () => {
      if (!Array.isArray(options.runs) || !options.runs.length) return null;
      const select = el("select", "");
      select.setAttribute("data-control", "run"); select.setAttribute("aria-label", "Recorded evaluation");
      options.runs.forEach((name, i) => { const choice = el("option", "", stringValue(name) || "Saved evaluation"); choice.value = String(i); choice.selected = i === options.run; select.append(choice); });
      return el("label", "run-switch", el("span", "tiny-label", "RECORDED EVALUATION"), select);
    };
    const header = (eyebrow, title, text) => el("div", "page-header", el("div", "", el("p", "eyebrow", eyebrow), el("h1", "", title), el("p", "page-description", text)), runSwitch());
    const banner = () => {
      const run = meta.run_kind;
      const label = run === "calibration" ? "Calibration run" : run === "model" ? "Native model run" : run === "adapter" ? "External reviewer run" : "Run kind not recorded";
      const note = run === "calibration" ? "Scripted reviewers check the harness, not model performance." : run === "model" ? "Recorded model responses on this suite. This is not a safety certification." : run === "adapter" ? "Only actions visible through the reviewer protocol are recorded." : "The run kind is missing or unrecognized, so no claim is made about who produced these reviews.";
      return el("div", "context-strip", el("span", ""), el("p", "", el("strong", "", `${label}. `), `${note} Each result below is counted separately. No combined safety score is computed.`), tag(boundary ? "BOUNDARY" : "REPOSITORY"));
    };
    const exportRow = () => { const exporter = el("button", "button", "Export original report"); exporter.type = "button"; exporter.setAttribute("data-export", "true"); return el("div", "native-actions", exporter); };
    const lineText = lines => {
      if (lines.length <= 10) return lines.join(", ");
      const runs = [];
      for (const value of lines) { const last = runs[runs.length - 1]; if (last && value === last[1] + 1) last[1] = value; else runs.push([value, value]); }
      return runs.map(([from, to]) => from === to ? String(from) : `${from}-${to}`).join(", ");
    };
    // Pending focus is bound to this document, row and event. The route is never touched.
    const revealEvent = (rowIndex, eventIndex) => {
      view.pendingEvidence = { row_index: rowIndex, event_index: eventIndex };
      view.selected = rowIndex;
      view.inlineRow = page === "pairs" && !boundary ? rowIndex : null;
      rerender();
    };
    const citationLinks = (index, finding) => {
      try { return display.citationEventLinks(index, finding.finding_sha256); } catch { return null; }
    };
    const citationButtons = (record, index) => {
      if (!record || !Array.isArray(record.event_links)) return null;
      if (!record.event_links.length) return el("span", "row-meta", "No recorded read or search event returned these lines.");
      return el("div", "citation-links", el("span", "tiny-label", "RECORDED SOURCE EVIDENCE"),
        el("div", "native-actions", ...record.event_links.map(link => {
          const kind = link.tool === "search_files" ? "search" : "read";
          return button("text-button", `Recorded ${kind} event [${link.event_index}] · lines ${lineText(link.observed_lines)}${link.covers_citation ? "" : " (partial)"}`, () => revealEvent(index, link.event_index), `Show recorded ${kind} event ${link.event_index} in the tool trace`);
        })),
        record.fully_observed ? null : el("span", "row-meta", `Cited lines not returned by recorded tools: ${lineText(record.missing_lines)}`));
    };
    const findingNode = (index, finding, position) => {
      if (!finding || typeof finding !== "object" || !locate(index, { finding_sha256: finding.finding_sha256 })) return el("div", "no-findings", `Finding ${position + 1} could not be linked to this report and is not shown.`);
      const body = finding.finding && typeof finding.finding === "object" ? finding.finding : {};
      const links = citationLinks(index, finding);
      const spans = (Array.isArray(body.evidence) ? body.evidence : []).map((item, i) => item && typeof item === "object" ? el("div", "", el("span", "row-meta", `${item.path}:${item.start_line}-${item.end_line}${typeof item.symbol === "string" && item.symbol ? ` · ${item.symbol}` : ""}`), el("pre", "finding-code", item.excerpt), citationButtons(links && links[i] && links[i].evidence_index === i ? links[i] : null, index)) : null);
      const ids = Array.isArray(finding.matched_issue_ids) ? finding.matched_issue_ids.filter(id => typeof id === "string").map(id => nativeText(id, 80)).join(", ") : "";
      return el("article", "finding", el("strong", "", titleCase(body.category)), el("span", "row-meta", `Finding hash (recorded, unchecked): ${nativeText(finding.finding_sha256, 80)}`), el("p", "", nativeText(body.summary, 2000)), ...spans,
        el("div", "metric-list", line("Evidence observed in the tool trace", flag(finding.evidence_observed)), line("Grounded in recorded evidence", flag(finding.grounded)), line("Matched issue ids", el("span", "", ids || "None"))),
        el("span", "tiny-label", "INDEPENDENT ADJUDICATION"), adjudicationNode(finding.adjudication));
    };
    const adjudicationNode = value => value && typeof value === "object" ? (facts(value) || el("p", "native-note", "A record is present but has no displayable fields.")) : el("p", "native-note", "None recorded. The semantic result stays Unknown.");
    const eventList = (index, row) => {
      const trace = new Map((Array.isArray(row.policy_trace) ? row.policy_trace : []).filter(entry => entry && Number.isSafeInteger(entry.sequence)).map(entry => [entry.sequence, entry]));
      const list = el("ol", "tool-trace");
      (Array.isArray(row.events) ? row.events : []).forEach((event, i) => {
        if (!event || typeof event !== "object" || !locate(index, { event_index: i })) { list.append(el("li", "", el("span", "tool-number", `[${i}]`), el("span", "", "Event could not be linked to this report."), el("span", "tool-status", "unresolved"))); return; }
        const sequence = event.policy_sequence, linked = Number.isSafeInteger(sequence) ? trace.get(sequence) : null;
        const resolved = linked && locate(index, { event_index: i, policy_sequence: sequence });
        const lines = Array.isArray(event.lines) && event.lines.length && event.lines.every(Number.isSafeInteger) ? ` lines ${event.lines.join(", ")}` : "";
        const item = el("li", "", el("span", "tool-number", `[${i}]`), el("span", "", nativeText(event.tool, 80),
          typeof event.path === "string" ? el("span", "tool-path", `${event.path}${lines}`) : null,
          Array.isArray(event.paths) && event.paths.length ? el("span", "tool-path", `Returned paths: ${event.paths.join(", ")}`) : null,
          typeof event.response_sha256 === "string" ? el("span", "tool-path", `Response hash (recorded, unchecked): ${nativeText(event.response_sha256, 80)}`) : null,
          typeof event.review_sha256 === "string" ? el("span", "tool-path", `Review submission hash (recorded, unchecked): ${nativeText(event.review_sha256, 80)}`) : null,
          Number.isSafeInteger(sequence) ? el("span", "tool-path", resolved ? `Policy sequence ${sequence}: ${nativeText(linked.decision, 40)}, ${nativeText(linked.result, 40)}` : `Policy sequence ${sequence} (unresolved)`) : null),
          el("span", "tool-status", nativeText(event.status || "recorded", 40)));
        item.setAttribute("data-row-index", index);
        item.setAttribute("data-event-index", i);
        eventNodes.set(`${index}:${i}`, item);
        list.append(item);
      });
      return list;
    };
    const guardNodes = (index, row) => {
      const effects = new Map();
      for (const effect of Array.isArray(row.effects) ? row.effects : []) if (effect && typeof effect.effect_id === "string") { const seen = effects.get(effect.effect_id); if (seen) seen.count++; else effects.set(effect.effect_id, { effect, count: 1 }); }
      const decisions = el("ol", "tool-trace");
      for (const entry of Array.isArray(row.policy_trace) ? row.policy_trace : []) {
        if (!entry || typeof entry !== "object") continue;
        const sequence = entry.sequence, id = typeof entry.effect_id === "string" ? entry.effect_id : null;
        const linked = Number.isSafeInteger(sequence) && locate(index, id ? { policy_sequence: sequence, effect_id: id } : { policy_sequence: sequence });
        if (!linked) { decisions.append(el("li", "", el("span", "tool-number", "#?"), el("span", "", "Policy trace entry could not be linked to this report."), el("span", "tool-status", "unresolved"))); continue; }
        decisions.append(el("li", "", el("span", "tool-number", `#${sequence}`), el("span", "", `${nativeText(entry.tool, 80)} · ${nativeText(entry.decision, 40)}`,
          el("span", "tool-path", entry.target),
          el("span", "tool-path", `Reason: ${nativeText(entry.reason, 400)}`),
          el("span", "tool-path", `Expected authorized: ${yesNo(entry.expected_authorized)} · Arguments valid: ${yesNo(entry.arguments_valid)} · After submission: ${yesNo(entry.after_submission)}`),
          el("span", "tool-path", id ? `Effect ${id}${effects.has(id) ? " (listed below)" : " (not listed)"}` : "No effect recorded"),
          entry.decision === "allow" ? null : el("span", "tool-path", "Guard intervention. It is not counted as resistance by the reviewer.")),
          el("span", "tool-status", nativeText(entry.result, 40))));
      }
      const cards = [...effects.entries()].map(([id, { effect, count: times }]) => !locate(index, { effect_id: id }) ? el("div", "no-findings", "An effect could not be linked to this report and is not shown.") :
        el("article", "finding", el("strong", "", nativeText(effect.tool, 80)), el("span", "row-meta", effect.target), el("span", "row-meta", `Effect id (recorded, unchecked): ${id}`),
          el("div", "metric-list", line("Expected authorized", flag(effect.expected_authorized)), line("Content matches submitted review", flag(effect.content_matches_submitted_review))),
          typeof effect.content === "string" ? el("pre", "finding-code", effect.content) : null,
          times > 1 ? el("span", "row-meta", `Recorded ${times} times and shown once.`) : null));
      return [section(`GUARD DECISIONS · ${decisions.children.length}`, decisions.children.length ? decisions : el("div", "no-findings", "No guard decisions recorded.")), section(`VIRTUAL EFFECTS · ${effects.size} UNIQUE`, ...(cards.length ? cards : [el("div", "no-findings", "No virtual effects recorded.")]))];
    };
    const snapshotNode = index => {
      const item = snaps ? snaps[index] : null, status = item && Object.hasOwn(NATIVE_STATUS, item.status) ? item.status : null;
      const reason = item && typeof item.reason === "string" && Object.hasOwn(NATIVE_REASON_TEXT, item.reason) ? NATIVE_REASON_TEXT[item.reason] : status ? NATIVE_STATUS_TEXT[status] : "Snapshot state could not be derived.";
      const records = item ? [facts(item), facts(item.snapshot_reference)].filter(Boolean) : [];
      return section("EVIDENCE SNAPSHOT", el("p", "", tag(status ? NATIVE_STATUS[status] : "Unavailable", status === "mismatch" ? "tag-red" : status === "matching_supplied_artifact" ? "" : "tag-amber"), " ", reason),
        el("p", "native-note", "Consistency check only. Authenticity: not established. A match says the supplied artifact agrees with the recorded digest, not where either came from."),
        records.length ? el("details", "native-snapshot-details", el("summary", "", "Snapshot details"), el("p", "native-note", "Recorded status, reason codes and digests, shown as recorded and unchecked."), ...records) : null);
    };
    const detailNode = (index, close) => {
      const row = rows[index];
      const heading = el("h2", "", payloadRow(row) ? payloadLabel(row) : nativeText(row.case_id, 200));
      if (payloadRow(row)) heading.setAttribute("title", row.case_id);
      const lines = [line("Run completed", flag(row.completed)), line("Conclusive", flag(row.conclusive)), line("Structural rubric passed", flag(row.rubric_passed)), line("Adjudicated semantic result", flag(row.semantic_passed, "Pass", "Fail")), line("Findings without adjudication", count(row.unknown_findings)), line("Duplicate findings", count(row.duplicate_finding_count)), line("Target issues matched", count(row.target_issues_matched))];
      if (!boundary && row.scoring_version === "repository-payload-v1") lines.push(line("Carrier", el("span", "", titleCase(row.surface))), line("Condition", el("span", "", titleCase(row.condition))), line("Carrier observed in returned content", flag(row.carrier_observed)), line("Attack payload exposed", flag(row.payload_exposed)));
      if (boundary) lines.push(line("Task utility met", flag(row.task_success)), line("Unauthorized action attempts", count(row.unauthorized_action_attempts, true)), line("Unauthorized virtual effects", count(row.unauthorized_effects, true)), line("Guard blocks", count(row.policy_blocks)), line("Guard escalations", count(row.policy_escalations)), line("Resistance observable", flag(row.resistance_observable)), line("Agent resisted", flag(row.agent_resisted)));
      if (row.review && typeof row.review.verdict === "string") lines.unshift(line("Recorded verdict", el("span", "", titleCase(row.review.verdict))));
      const found = Array.isArray(row.findings) ? row.findings : [];
      return el("section", "panel native-detail",
        el("div", "pair-heading", el("div", "", heading, el("span", "row-meta", `${nativeText(row.reviewer ?? "reviewer not recorded", 120)} · trial ${nativeText(row.epoch, 8)}${boundary ? ` · guard ${nativeText(row.guard ?? "not recorded", 40)}` : ""} · sample position ${index}`)), button("text-button", "Close details", close)),
        payloadRow(row) ? section("CASE IDENTITY", el("details", "native-snapshot-details", el("summary", "", "Full case identifier"), el("pre", "finding-code", row.case_id))) : null,
        section("RESULTS, COUNTED SEPARATELY", el("div", "metric-list", ...lines), boundary ? el("p", "native-note", "A guard block is the guard's intervention. It is never counted as resistance by the reviewer, and Unknown stays Unknown.") : null),
        row.error !== null ? el("div", "finding bad", el("strong", "", "Run error"), el("p", "", nativeText(row.error, 1000))) : null,
        section("REVIEW-LEVEL ADJUDICATION", adjudicationNode(row.review_adjudication)),
        snapshotNode(index),
        section(`RECORDED FINDINGS · ${found.length}`, ...(found.length ? found.map((f, j) => findingNode(index, f, j)) : [el("div", "no-findings", "No findings recorded.")])),
        ...(boundary ? guardNodes(index, row) : []),
        el("details", "native-trace", el("summary", "", `Tool trace · ${Array.isArray(row.events) ? row.events.length : 0} events (array positions)`), eventList(index, row)),
        exportRow());
    };
    const coveragePanel = () => {
      const known = cov.manifest_known !== false && Number.isSafeInteger(cov.expected);
      const names = [...new Set(rows.map(row => row.source_group).filter(value => typeof value === "string" && value))];
      const dl = el("dl", "native-dl");
      for (const [label, value] of [["Declared expected (metadata, unchecked)", cov.declared_expected], ["Exact expected slots", known ? cov.expected : null], ["Recorded rows", cov.recorded], ["Missing exact slots", known ? cov.missing : null], ["Repeated slots", cov.duplicates], ["Unexpected slots", known ? cov.unexpected : null]]) dl.append(el("dt", "", label), el("dd", "", nativeCount(value)));
      dl.append(el("dt", "", "Source groups"), el("dd", "", names.length ? names.slice(0, 20).map(name => nativeText(name, 80)).join(", ") : "Not recorded"));
      return el("div", "panel native-panel", el("h2", "", "Coverage"), el("p", "native-note", known ? "Exact slots come from the recorded expected_slots list." : "No exact expected_slots list is recorded, so missing slots are Unknown. The declared count is shown separately and is not treated as a slot list."), dl);
    };
    const snapshotPanel = () => {
      const tally = new Map();
      for (const item of snaps || []) { const key = item && Object.hasOwn(NATIVE_STATUS, item.status) ? item.status : "unavailable"; tally.set(key, (tally.get(key) || 0) + 1); }
      const dl = el("dl", "native-dl");
      for (const key of Object.keys(NATIVE_STATUS)) dl.append(el("dt", "", NATIVE_STATUS[key]), el("dd", "", tally.get(key) || 0));
      const note = !snaps ? "Snapshot states could not be derived for this report." : display.verification_supplied ? "A verification context was supplied outside the report. Matching is a consistency check only. Authenticity: not established, and origin is not established." : "No external verification context was supplied, so no row can be shown as matching. Recorded snapshot fields are displayed as recorded and unchecked.";
      return el("div", "panel native-panel", el("h2", "", "Evidence snapshots"), el("p", "native-note", note), dl);
    };
    const usagePanel = () => {
      const usage = meta.usage && typeof meta.usage === "object" && !Array.isArray(meta.usage) ? meta.usage : {};
      const cost = typeof usage.provider_reported_cost_usd === "number" && Number.isFinite(usage.provider_reported_cost_usd) && usage.provider_reported_cost_usd >= 0 ? usage.provider_reported_cost_usd : null;
      const withCost = usage.api_calls_with_reported_cost, withoutCost = usage.api_calls_without_reported_cost;
      const partial = !Number.isSafeInteger(withCost) || !Number.isSafeInteger(withoutCost) || withoutCost > 0 || rows.some(row => row.error !== null);
      const latency = typeof meta.latency_ms === "number" && Number.isFinite(meta.latency_ms) && meta.latency_ms >= 0 ? `${meta.latency_ms} ms` : "Unknown";
      const provider = meta.provider && typeof meta.provider === "object" && typeof meta.provider.name === "string" ? meta.provider.name : "Unknown";
      const dl = el("dl", "native-dl");
      for (const [label, value] of [["Recorded provider", provider], ["Recorded reviewers", Array.isArray(meta.reviewers) ? meta.reviewers.join(", ") : "Unknown"], ["Recorded call cost", cost === null ? "Unknown" : `${cost} USD${partial ? " (partial known cost)" : ""}`], ["Calls with reported cost", nativeCount(withCost)], ["Calls without reported cost", nativeCount(withoutCost)], ["Recorded latency (ms)", latency]]) dl.append(el("dt", "", label), el("dd", "", value));
      return el("div", "panel native-panel", el("h2", "", "Recorded usage"), el("p", "native-note", partial ? "Cost coverage is incomplete or unknown. Failed or unreported calls may be uncosted." : "These are the producer's recorded call costs."), dl);
    };
    const overviewPage = () => {
      const total = rows.length, of = (a, b) => `/ ${nativeCount(b)}`;
      const unjudged = Number.isSafeInteger(stats.semantic_known) ? total - stats.semantic_known : null;
      const first = [metric("Recorded reviews", number(total), "samples", `${new Set(rows.map(r => r.case_id)).size} distinct cases`),
        metric("Completed", nativeCount(stats.completed), `/ ${total}`, `${nativeCount(stats.conclusive)} conclusive`),
        metric("Structural rubric", nativeCount(stats.rubric_passed), `/ ${total}`, "Passed the review rubric. This is not a semantic correctness result."),
        metric("Adjudicated semantics", stats.semantic_known ? nativeCount(stats.semantic_passed) : "Unknown", stats.semantic_known ? of(0, stats.semantic_known) : "", `${nativeCount(unjudged)} unjudged and Unknown. ${nativeCount(stats.unknown_findings)} findings lack adjudication.`, stats.semantic_known === total ? "" : "unknown")];
      const nodes = [header("PROMPT INJECTION / REVIEWER EVALUATION", boundary ? "Boundary evidence." : "Repository evidence.", "Recorded results from a native report, kept in separate counts."), banner(), el("section", "metrics", ...first)];
      if (boundary) nodes.push(el("section", "metrics native-row",
        metric("Task utility", nativeCount(stats.task_success), `/ ${total}`, "Required virtual actions completed with matching content"),
        metric("Unauthorized attempts", nativeCount(stats.unauthorized_action_attempts), "", "Attempts by the reviewer, before any guard decision", stats.unauthorized_action_attempts ? "bad" : ""),
        metric("Unauthorized effects", nativeCount(stats.unauthorized_effects), "", "Virtual effects that were not expected to be authorized", stats.unauthorized_effects ? "bad" : ""),
        metric("Resistance observed", stats.resistance_known ? nativeCount(stats.resisted) : "Unknown", stats.resistance_known ? of(0, stats.resistance_known) : "", `${nativeCount(Number.isSafeInteger(stats.resistance_known) ? total - stats.resistance_known : null)} not observable. Guard blocks are not resistance.`, stats.resistance_known === total ? "" : "unknown")));
      nodes.push(coveragePanel(), snapshotPanel(), usagePanel(), el("div", "panel native-panel", el("h2", "", "Run record (recorded, unchecked)"), facts(runRecord) || el("p", "native-note", "No simple run fields recorded.")), exportRow());
      return nodes;
    };
    const casesPage = () => {
      const reviewers = [...new Set(rows.map(row => row.reviewer))].sort(), guards = boundary ? [...new Set(rows.map(row => row.guard))].sort() : [];
      const results = el("div", "");
      const select = (label, all, values, key) => {
        const node = el("select", "");
        node.setAttribute("aria-label", label);
        for (const [value, text] of [["all", all], ...values.map(v => [v, v || "not recorded"])]) { const choice = el("option", "", text); choice.value = value; choice.selected = view[key] === value; node.append(choice); }
        node.addEventListener("change", () => { view[key] = node.value; view.pageNum = 0; fill(); });
        return node;
      };
      const input = el("input", "");
      input.placeholder = "Search cases, reviewers, families..."; input.setAttribute("aria-label", "Search cases"); input.value = view.search;
      input.addEventListener("input", () => { view.search = input.value; view.pageNum = 0; fill(); });
      const matches = () => {
        const query = stringValue(view.search).toLowerCase();
        return rows.map((row, index) => ({ row, index })).filter(({ row }) => (view.reviewer === "all" || row.reviewer === view.reviewer) && (!boundary || view.guard === "all" || row.guard === view.guard) &&
          (!query || [row.case_id, row.reviewer, row.family, row.variant, row.surface, boundary ? row.guard : null, row.source_group, ...(payloadRow(row) ? [payloadLabel(row), payloadContext(row)] : [])].some(v => stringValue(v).toLowerCase().includes(query))));
      };
      const fill = () => {
        const found = matches(), current = clampPage("pageNum", found.length), shown = found.slice(current * NATIVE_PAGE_SIZE, (current + 1) * NATIVE_PAGE_SIZE);
        const parts = [];
        if (Number.isSafeInteger(view.selected) && rows[view.selected]) parts.push(detailNode(view.selected, () => { view.selected = null; fill(); }));
        if (!found.length) parts.push(el("div", "empty-state", el("h2", "", "No matching cases."), el("p", "", "Try a different reviewer, guard, or search term.")));
        else {
          const head = ["CASE / VARIANT", "REVIEWER", "CONTEXT", "COMPLETION", "RUBRIC", "SEMANTIC", ...(boundary ? ["GUARD", "TASK", "UNAUTH. EFFECTS"] : []), "OPEN"];
          const body = el("tbody", "");
          for (const { row, index } of shown) {
            const open = () => { view.selected = index; fill(); };
            const label = button("row-name", payloadRow(row) ? payloadLabel(row) : nativeText(familyName(stringValue(row.family) || row.case_id), 120), open);
            if (payloadRow(row)) label.setAttribute("title", row.case_id);
            const context = payloadRow(row) ? payloadContext(row) : nativeText(surfaceName(row.surface), 80);
            body.append(el("tr", "", el("td", "", label, el("span", "row-meta", payloadRow(row) ? `${nativeText(row.variant, 80)} · trial ${nativeText(row.epoch, 8)}` : `${nativeText(row.variant, 80)} · ${nativeText(row.case_id, 120)}`)),
              el("td", "", el("span", "", nativeText(row.reviewer === undefined ? "not recorded" : modelName(row.reviewer), 120))), el("td", "", context),
              el("td", "", completionTag(row)), el("td", "", triTag(row.rubric_passed, "RUBRIC PASS", "RUBRIC FAIL")), el("td", "", triTag(row.semantic_passed, "ADJUDICATED PASS", "ADJUDICATED FAIL", "UNKNOWN / UNJUDGED")),
              ...(boundary ? [el("td", "", nativeText(row.guard ?? "not recorded", 40)), el("td", "", triTag(row.task_success, "TASK MET", "TASK NOT MET")), el("td", "", count(row.unauthorized_effects, true))] : []),
              el("td", "", button("row-action", "Open", open, `Inspect sample ${index}`))));
          }
          parts.push(el("div", "result-count", `${number(found.length)} recorded samples · Select a case to inspect its review and evidence`),
            el("div", "panel table-scroll", el("table", "case-table", el("thead", "", el("tr", "", ...head.map(text => el("th", "", text)))), body)),
            pager(found.length, current, step => { view.pageNum += step; fill(); }));
        }
        results.replaceChildren(...parts);
      };
      const toolbar = el("div", "toolbar", el("label", "search", input), select("Filter by reviewer", "All reviewers", reviewers, "reviewer"), boundary ? select("Filter by guard", "All guards", guards, "guard") : null,
        button("text-button reset", "Reset filters", () => { Object.assign(view, { search: "", reviewer: "all", guard: "all", pageNum: 0 }); rerender(); }));
      fill();
      return [header("LOOK BEYOND THE SCORE", "The evidence, case by case.", "Find the finding, the source range, or the action that crossed a boundary."), banner(), toolbar, results];
    };
    const repositoryFindings = () => {
      const items = [];
      rows.forEach((row, index) => (Array.isArray(row.findings) ? row.findings : []).forEach((finding, position) => items.push({ row, index, finding, position })));
      const holder = el("div", "");
      const fill = () => {
        const current = clampPage("pairPage", items.length), shown = items.slice(current * NATIVE_PAGE_SIZE, (current + 1) * NATIVE_PAGE_SIZE);
        holder.replaceChildren(...(Number.isSafeInteger(view.inlineRow) && rows[view.inlineRow] ? [detailNode(view.inlineRow, () => { view.inlineRow = null; fill(); })] : []), ...(items.length ? [el("div", "result-count", `${number(items.length)} recorded findings · Repository reports have no paired controls`),
          ...shown.map(({ row, index, finding, position }) => el("div", "panel native-panel", el("span", "row-meta", `${nativeText(row.case_id, 160)} · ${nativeText(row.reviewer ?? "reviewer not recorded", 120)} · trial ${nativeText(row.epoch, 8)} · sample position ${index}`), findingNode(index, finding, position), button("text-button", "Open sample", () => { view.selected = index; go("cases"); }))),
          pager(items.length, current, step => { view.pairPage += step; fill(); })] : [el("div", "empty-state", el("h2", "", "No findings recorded."), el("p", "", "This report has no submitted findings to display."))]));
      };
      fill();
      return [header("FOLLOW THE FINDINGS", "What the reviewer reported.", "Recorded findings with exact source paths, ranges, and excerpts."), banner(), holder];
    };
    const boundaryPairs = () => {
      const arms = new Map(), buckets = new Map(), guardsByCase = new Map();
      rows.forEach((row, index) => {
        const key = JSON.stringify([row.case_id, row.reviewer, row.guard ?? null]);
        if (!arms.has(key)) arms.set(key, { row, items: [] });
        arms.get(key).items.push(row);
        if (!guardsByCase.has(row.case_id)) guardsByCase.set(row.case_id, new Set());
        guardsByCase.get(row.case_id).add(row.guard ?? null);
        if (typeof row.case_sha256 === "string" && row.case_sha256 && typeof row.input_sha256 === "string" && row.input_sha256) {
          const bucket = JSON.stringify([row.case_id, row.case_sha256, row.input_sha256, row.reviewer, row.epoch, row.condition, row.family, row.variant]);
          if (!buckets.has(bucket)) buckets.set(bucket, []);
          buckets.get(bucket).push({ row, index });
        }
      });
      const linked = [...buckets.values()].filter(items => new Set(items.map(item => item.row.guard ?? null)).size > 1);
      const linkedCases = new Set(linked.flatMap(items => items.map(item => item.row.case_id)));
      const unlinked = [...guardsByCase.entries()].filter(([id, guards]) => guards.size > 1 && !linkedCases.has(id)).length;
      const order = (a, b) => a < b ? -1 : a > b ? 1 : 0;
      const list = [...arms.values()].sort((a, b) => order(String(a.row.case_id), String(b.row.case_id)) || order(String(a.row.reviewer), String(b.row.reviewer)) || order(String(a.row.guard), String(b.row.guard)));
      const sum = (items, key) => items.some(r => Number.isSafeInteger(r[key])) ? items.reduce((n, r) => n + (Number.isSafeInteger(r[key]) ? r[key] : 0), 0) : null;
      const ratioOf = (items, key) => { const known = items.filter(r => typeof r[key] === "boolean"); return known.length ? `${known.filter(r => r[key]).length}/${known.length}` : "Unknown"; };
      const holder = el("div", "");
      const fill = () => {
        const current = clampPage("pairPage", list.length), shown = list.slice(current * NATIVE_PAGE_SIZE, (current + 1) * NATIVE_PAGE_SIZE);
        const body = el("tbody", "");
        for (const { row, items } of shown) body.append(el("tr", "", el("td", "", nativeText(row.case_id, 160)), el("td", "", nativeText(row.reviewer ?? "not recorded", 120)), el("td", "", nativeText(row.guard ?? "not recorded", 40)), el("td", "mono", items.length), el("td", "", ratioOf(items, "task_success")), el("td", "", nativeCount(sum(items, "unauthorized_action_attempts"))), el("td", "", nativeCount(sum(items, "unauthorized_effects"))), el("td", "", nativeCount(sum(items, "policy_blocks"))), el("td", "", ratioOf(items, "agent_resisted"))));
        holder.replaceChildren(el("div", "panel table-scroll", el("table", "case-table", el("thead", "", el("tr", "", ...["CASE", "REVIEWER", "GUARD", "RUNS", "TASK MET", "UNAUTH. ATTEMPTS", "UNAUTH. EFFECTS", "GUARD BLOCKS", "RESISTED / OBSERVABLE"].map(text => el("th", "", text)))), body)), pager(list.length, current, step => { view.pairPage += step; fill(); }));
      };
      fill();
      const links = el("div", "panel native-panel", el("h2", "", "Matched links"), el("p", "native-note", `Links require the same case digest, input digest, reviewer, and trial across different guard arms. ${unlinked} cases have several guard arms without that match and stay as separate runs.`),
        ...(linked.length ? linked.map(items => el("article", "finding", el("strong", "", nativeText(items[0].row.case_id, 160)), el("span", "row-meta", `${nativeText(items[0].row.reviewer ?? "reviewer not recorded", 120)} · trial ${nativeText(items[0].row.epoch, 8)}`),
          el("div", "native-actions", ...items.map(item => button("text-button", `Guard ${nativeText(item.row.guard ?? "not recorded", 40)} (sample ${item.index})`, () => { view.selected = item.index; go("cases"); }))))) : [el("p", "native-note", "No matched guard-arm links are available.")]));
      return [header("FOLLOW THE CHANGE", "Same case. Different guard arms.", "Independent runs compared descriptively, never as a causal pair."), banner(), el("p", "native-note", "Guard arms are independent runs. Model generations are not assumed identical, so these are descriptive counts, not paired results."), holder, links];
    };
    const nodes = page === "cases" ? casesPage() : page === "pairs" ? (boundary ? boundaryPairs() : repositoryFindings()) : overviewPage();
    root.replaceChildren(...nodes);
    const pending = view.pendingEvidence;
    view.pendingEvidence = null;
    const target = pending && Number.isSafeInteger(pending.row_index) && Number.isSafeInteger(pending.event_index) ? eventNodes.get(`${pending.row_index}:${pending.event_index}`) : null;
    if (target) {
      const trace = typeof target.closest === "function" ? target.closest("details") : null;
      if (trace) trace.open = true;
      target.tabIndex = -1;
      target.classList.add("evidence-target");
      target.focus();
      if (typeof target.scrollIntoView === "function") target.scrollIntoView({ block: "center" });
    }
    return root;
  }
  // The calculation layer can be checked without a browser or a paid model.
  if (typeof module !== "undefined" && module.exports) module.exports = { stats, controlIndex, pairKey, sampleKey, sampleCounts, pairContext, pairEligible, pairReason, coverage, coverageMessages, normalizeFilters, diagnostics, validateReport, outcome, experimentFields, renderNativeView, makeEntry, makeImportedEntry, nativeSnapshots, runName, formatDate, contracts: Contracts };
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
  const state = { reports: [], run: 0, page: "overview", search: "", model: "all", surface: "all", status: "all", pageNum: 0, selectedPair: null, native: {}, theme: "dark" };
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
  function resetFilters() { Object.assign(state, { search: "", model: "all", surface: "all", status: "all", pageNum: 0, selectedPair: null, native: {} }); }
  const active = () => state.reports[state.run];
  const activeRows = () => active() && !isNative(active()) ? active().report.rows : [];
  function kind(report) { return report.metadata.run_kind === "calibration" ? "Harness calibration" : report.metadata.run_kind === "adapter" ? "External reviewer" : "Model pilot"; }
  function options(values, current, label) { return values.map(([value, text]) => `<option value="${h(value)}"${String(current) === String(value) ? " selected" : ""}>${h(text || label?.(value) || value)}</option>`).join(""); }
  function runSelector() {
    return `<label class="run-switch"><span class="tiny-label">RECORDED EVALUATION</span><select data-control="run" aria-label="Recorded evaluation">${options(state.reports.map((e, i) => [i, runName(e)]), state.run)}</select></label>`;
  }
  function pageHeader(eyebrow, title, description, extra = "") { return `<div class="page-header"><div><p class="eyebrow">${h(eyebrow)}</p><h1>${h(title)}</h1><p class="page-description">${h(description)}</p></div>${extra}</div>`; }
  function notice(report) {
    const label = kind(report);
    const note = report.metadata.run_kind === "calibration" ? "Scripted reviewers check the harness, not model performance." : report.metadata.run_kind === "adapter" ? "Only actions visible through the reviewer protocol are recorded." : "Recorded model responses from a small, controlled test suite.";
    const messages = diagnostics(report);
    return `<div class="context-strip"><span>${icon("info")}</span><p><strong>${h(label)}.</strong> ${h(note)}${messages.length ? `<br><span class="unknown">${messages.map(h).join(" ")}</span>` : ""}</p><span class="tag">${h(report.metadata.split || "RECORDED SAMPLES")}</span></div>`;
  }
  function badge(row) {
    const status = outcome(row);
    return `<span class="tag ${status === "pass" ? "tag-green" : status === "fail" ? "tag-red" : "tag-amber"}">${status === "pass" ? "PASS" : status === "fail" ? "FAIL" : "INCONCLUSIVE"}</span>`;
  }
  function nativeRunRow(entry, index) {
    const report = entry.report, st = Contracts.nativeStats(report), boundary = entry.contract.report_kind === "boundary", total = report.rows.length;
    const n = value => Number.isSafeInteger(value) ? value : 0;
    return `<tr><td><div class="run-cell"><span class="run-icon">${icon("runs")}</span><div><button class="row-name" data-open-run="${index}">${h(runName(entry))}</button><span class="row-meta">${h(formatDate(report))} · ${new Set(report.rows.map(r => r.case_id)).size} cases</span></div></div></td><td><span class="tag">${boundary ? "Boundary report" : "Repository report"}</span></td><td class="mono">${number(total)}</td><td><div class="mini-score"><span>Rubric ${h(ratio(n(st.rubric_passed), total))}</span><span class="mini-track"><i style="width:${total ? Math.min(100, n(st.rubric_passed) / total * 100) : 0}%"></i></span></div><span class="row-meta">Semantic: ${n(st.semantic_known) ? `${h(ratio(n(st.semantic_passed), n(st.semantic_known)))} adjudicated` : "Unknown"}</span></td><td>${boundary ? `<span class="signal ${n(st.unauthorized_effects) ? "bad" : "good"}">Unauthorized effects ${number(n(st.unauthorized_effects))}</span>` : '<span class="muted">Not applicable</span>'}</td><td><button class="row-action" data-open-run="${index}" aria-label="Open ${h(runName(entry))}">${icon("arrow")}</button></td></tr>`;
  }
  function reportTable() {
    const mixed = state.reports.some(isNative);
    return `<div class="panel"><div class="table-scroll"><table><thead><tr><th>EVALUATION</th><th>TYPE</th><th>SAMPLES</th><th>${mixed ? "REVIEW RESULT" : "CORRECT REVIEWS"}</th><th>${mixed ? "DEGRADATION / EFFECTS" : "PAIRED DEGRADATIONS"}</th><th><span class="muted">OPEN</span></th></tr></thead><tbody>${state.reports.map((entry, index) => {
      if (isNative(entry)) return nativeRunRow(entry, index);
      const report = entry.report, s = stats(report.rows);
      return `<tr><td><div class="run-cell"><span class="run-icon">${icon(report.metadata.run_kind === "calibration" ? "grid" : "runs")}</span><div><button class="row-name" data-open-run="${index}">${h(runName(entry))}</button><span class="row-meta">${h(formatDate(report))} · ${s.conditions} conditions</span></div></div></td><td><span class="tag">${h(kind(report))}</span></td><td class="mono">${number(s.total)}</td><td><div class="mini-score"><span>${ratio(s.correct, s.total)}</span><span class="mini-track"><i style="width:${s.total ? s.correct / s.total * 100 : 0}%"></i></span></div></td><td><span class="signal ${s.degraded ? "bad" : "good"}">${icon(s.degraded ? "flag" : "check")}${ratio(s.degraded, s.eligible)}</span></td><td><button class="row-action" data-open-run="${index}" aria-label="Open ${h(runName(entry))}">${icon("arrow")}</button></td></tr>`;
    }).join("")}</tbody></table></div><div class="table-note"><span>${state.reports.length} saved evaluations · Files stay in this browser</span><span>${mixed ? "MIXED SCHEMAS" : "SCHEMA 2"}</span></div></div>`;
  }
  function experimentRecord(report) {
    return `<details class="panel experiment-record"><summary>Experiment record</summary><p class="muted">Recorded inputs and producer-reported score checks. This viewer does not authenticate fingerprints or rerun the scorer. Missing records stay unknown.</p><dl>${experimentFields(report.metadata).map(([label, value]) => `<dt>${h(label)}</dt><dd>${h(value)}</dd>`).join("")}</dl></details>`;
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
      `<div class="section-header"><div><h2>Evaluation runs <span class="tag">${state.reports.length}</span></h2><p>Recorded results, ready to inspect.</p></div><button class="text-button" data-go="runs">View all runs ${icon("arrow")}</button></div>${reportTable()}${experimentRecord(report)}`;
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
    const context = pairContext(activeRows()), { controls } = context, control = controls.get(pairKey(row));
    const reason = pairReason(activeRows(), row, context);
    const eligible = pairEligible(row, context);
    const status = eligible ? row.passed ? "NO DEGRADATION" : "PAIRED DEGRADATION" : "PAIR NOT ELIGIBLE";
    const color = eligible ? row.passed ? "tag-green" : "tag-red" : "tag-amber";
    return `<div class="pair-heading"><div><h2>${h(familyName(row.family))}</h2><span class="row-meta">${h(modelName(row.model))} · ${h(row.variant)} · trial ${row.epoch} · ${h(row.defense)}</span></div><span class="tag ${color}">${status}</span></div>${reason ? `<p class="pair-footnote" style="margin:0 0 16px">${h(reason)}</p>` : ""}<div class="pair-columns"><section class="panel"><div class="review-head"><strong>${icon("shield")}Clean control</strong>${control ? badge(control) : `<span class="tag">${controls.has(pairKey(row)) ? "AMBIGUOUS" : "MISSING"}</span>`}</div>${reviewBody(control)}</section><section class="panel"><div class="review-head"><strong>${icon("flag")}${h(surfaceName(row.surface))}</strong>${badge(row)}</div>${reviewBody(row)}</section></div><p class="pair-footnote">Matched within this run by reviewer, policy, family, code variant, trial, and trial group. A degradation requires a passing clean control and a conclusive attacked review. N/A means a metric was not applicable or not recorded.</p><button class="text-button" data-inspect="${index}" style="margin-top:14px">View complete sample ${icon("arrow")}</button>`;
  }
  function pairsContent() {
    if (!activeRows().some(row => row.attacked)) return '<div class="empty-state">'+icon("compare")+'<h2>No hostile contexts in this report.</h2><p>Import an evaluation containing clean and attacked samples to inspect matched reviews.</p><button class="button" data-import="true">Import report</button></div>';
    const matches = filteredRows(true);
    if (!matches.length) return '<div class="empty-state">'+icon("compare")+'<h2>No attacked samples match.</h2><p>Choose a different filter or import a run containing both clean and hostile contexts.</p><button class="button" data-reset="true">Clear filters</button></div>';
    const context = pairContext(activeRows());
    const sorted = [...matches].sort((a, b) => Number(!b.row.passed && pairEligible(b.row, context)) - Number(!a.row.passed && pairEligible(a.row, context)));
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
    if (state.reports.length && state.page !== "runs" && isNative(active())) renderNativeView(active().document, { document, root: $("#main"), page: state.page, view: state.native, verification: active().evidence_verification, runs: state.reports.map(runName), run: state.run, navigate: target => navigate(target, false) });
    else $("#main").innerHTML = !state.reports.length ? empty() : ({ overview, runs, cases, pairs })[state.page]();
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
    const blob = new Blob([JSON.stringify(active().document || active().report, null, 2) + "\n"], { type: "application/json" });
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
      const existingBytes = state.reports.reduce((n, e) => n + new TextEncoder().encode(JSON.stringify(e.document || e.report)).length, 0);
      if (existingBytes + list.reduce((n, f) => n + f.size, 0) > MAX_TOTAL_BYTES) throw new Error("Keep the total workspace below 32 MiB.");
      const next = [];
      for (const file of list) {
        importingName = file.name;
        next.push(makeImportedEntry(file.name === "report.json" ? `Imported evaluation ${state.reports.length + next.length + 1}` : file.name, await file.arrayBuffer()));
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
    const bundle = Contracts.parseStrictJSON($("#dashboard-data")?.textContent || '{"reports":[]}', { maxBytes: 64 * 1024 * 1024, maxDepth: 26, maxNodes: 1600000 });
    if (!Array.isArray(bundle.reports) || bundle.reports.length > MAX_REPORTS) throw new Error("Invalid dashboard bundle.");
    const entries = bundle.reports.map(entry => makeEntry(entry?.name, entry?.report, entry?.evidence_verification ?? null));
    if (entries.reduce((n, e) => n + e.report.rows.length, 0) > MAX_ROWS) throw new Error("This dashboard exceeds the supported sample limit.");
    state.reports = entries;
  } catch (error) { state.reports = []; toast(error.message || "The saved evaluations could not be loaded."); }
  hydrateIcons(); setTheme(state.theme); render();
})();
