/* ReviewBoundary repository adjudication labeler. Offline; the page is built from text nodes only. */
(() => {
  "use strict";
  const MAX_ARTIFACT_BYTES = 16 * 1024 * 1024;
  const MAX_FINDING_DECISIONS = 32768;
  const MAX_REVIEW_DECISIONS = 4096;
  const MAX_DEPTH = 64;
  const MAX_REASON = 2000;
  const MAX_ISSUE_ID = 256;
  const PAGE_SIZE = 20;
  const DECISIONS = ["unknown", "supported", "rejected"];
  const DIGEST = /^[0-9a-f]{64}$/;
  const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
  const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
  const codePoints = text => { let count = 0; for (const _ of text) count++; return count; };

  // JSON.parse silently keeps the last duplicate key and accepts 1.0 for 1, so parse strictly.
  function parseStrictJson(text) {
    if (typeof text !== "string") throw new Error("JSON input must be text.");
    let i = 0;
    const fail = message => { throw new Error(`Invalid JSON: ${message}.`); };
    const space = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
    function string() {
      i++;
      let out = "";
      for (;;) {
        if (i >= text.length) fail("unterminated string");
        const c = text[i++];
        if (c === '"') break;
        if (c < " ") fail("control character in string");
        if (c !== "\\") { out += c; continue; }
        const e = text[i++];
        const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
        if (e !== undefined && hasOwn(simple, e)) out += simple[e];
        else if (e === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i, i + 4))) { out += String.fromCharCode(parseInt(text.slice(i, i + 4), 16)); i += 4; }
        else fail("invalid escape");
      }
      if (LONE_SURROGATE.test(out)) fail("string is not valid Unicode");
      return out;
    }
    function value(depth) {
      if (depth > MAX_DEPTH) fail("nesting is too deep");
      space();
      const c = text[i];
      if (c === "{") {
        i++;
        const object = Object.create(null);
        space();
        if (text[i] === "}") { i++; return object; }
        for (;;) {
          space();
          if (text[i] !== '"') fail("expected a string key");
          const key = string();
          if (hasOwn(object, key)) fail("duplicate object key");
          space();
          if (text[i++] !== ":") fail("expected a colon");
          object[key] = value(depth + 1);
          space();
          const next = text[i++];
          if (next === "}") return object;
          if (next !== ",") fail("expected a comma or closing brace");
        }
      }
      if (c === "[") {
        i++;
        const array = [];
        space();
        if (text[i] === "]") { i++; return array; }
        for (;;) {
          array.push(value(depth + 1));
          space();
          const next = text[i++];
          if (next === "]") return array;
          if (next !== ",") fail("expected a comma or closing bracket");
        }
      }
      if (c === '"') return string();
      for (const [word, result] of [["true", true], ["false", false], ["null", null]]) {
        if (text.startsWith(word, i)) { i += word.length; return result; }
      }
      const number = /-?(?:0|[1-9][0-9]*)/y;
      number.lastIndex = i;
      const match = number.exec(text);
      if (!match) fail("unexpected token");
      i += match[0].length;
      if (/[.eE0-9]/.test(text[i] ?? "")) fail("only integer numbers are allowed");
      return Number(match[0]);
    }
    const result = value(0);
    space();
    if (i !== text.length) fail("unexpected trailing content");
    if (!isObject(result)) throw new Error("JSON input must be an object.");
    return result;
  }

  function exactKeys(object, required, optional, label) {
    if (!isObject(object)) throw new Error(`${label} must be an object.`);
    for (const key of Object.keys(object)) {
      if (!required.includes(key) && !optional.includes(key)) throw new Error(`${label} has an unexpected field.`);
    }
    for (const key of required) {
      if (!hasOwn(object, key)) throw new Error(`${label}.${key} is required.`);
    }
  }

  function boundedText(value, label, maximum) {
    if (typeof value !== "string") throw new Error(`${label} must be a string.`);
    const length = codePoints(value);
    if (length < 1 || length > maximum) throw new Error(`${label} must be 1 to ${maximum} characters.`);
    if (LONE_SURROGATE.test(value)) throw new Error(`${label} is not valid Unicode.`);
  }

  const pairKey = (first, second) => `${first}:${second}`;

  function contextIndex(context) {
    return {
      findings: new Map(context.findings.map((item, index) => [pairKey(item.case_sha256, item.finding_sha256), index])),
      reviews: new Map(context.reviews.map((item, index) => [pairKey(item.case_sha256, item.review_sha256), index])),
    };
  }

  // Mirrors repository_adjudication.validate_adjudication for a partial artifact.
  function validateArtifact(value, context) {
    exactKeys(value, ["schema_version", "adjudication_kind", "source_report_sha256", "finding_decisions", "review_decisions"], [], "Artifact");
    if (typeof value.schema_version !== "number" || value.schema_version !== 1) throw new Error("schema_version must be the integer 1.");
    if (value.adjudication_kind !== "repository") throw new Error('adjudication_kind must be "repository".');
    if (typeof value.source_report_sha256 !== "string" || !DIGEST.test(value.source_report_sha256)) throw new Error("source_report_sha256 must be a SHA-256 digest.");
    if (value.source_report_sha256 !== context.source_report_sha256) throw new Error("Adjudication binds to a different or modified source report.");
    const lists = [["finding_decisions", MAX_FINDING_DECISIONS], ["review_decisions", MAX_REVIEW_DECISIONS]];
    for (const [name, maximum] of lists) {
      if (!Array.isArray(value[name])) throw new Error(`${name} must be a list.`);
      if (value[name].length > maximum) throw new Error(`${name} has more than ${maximum} entries.`);
    }
    const index = contextIndex(context);
    const issues = new Map(Object.entries(context.cases).map(([digest, item]) => [digest, new Map(item.issues.map(issue => [issue.issue_id, issue]))]));
    const finding_decisions = [], review_decisions = [];
    const seen = [new Set(), new Set()];
    value.finding_decisions.forEach((raw, position) => {
      const label = `finding_decisions[${position}]`;
      exactKeys(raw, ["case_sha256", "finding_sha256", "decision", "reason"], ["issue_id"], label);
      for (const field of ["case_sha256", "finding_sha256"]) {
        if (typeof raw[field] !== "string" || !DIGEST.test(raw[field])) throw new Error(`${label}.${field} must be a SHA-256 digest.`);
      }
      if (!DECISIONS.includes(raw.decision)) throw new Error(`${label}.decision must be supported, rejected or unknown.`);
      const issueId = hasOwn(raw, "issue_id") ? raw.issue_id : null;
      if (issueId !== null) boundedText(issueId, `${label}.issue_id`, MAX_ISSUE_ID);
      boundedText(raw.reason, `${label}.reason`, MAX_REASON);
      const key = pairKey(raw.case_sha256, raw.finding_sha256);
      if (seen[0].has(key)) throw new Error("Duplicate or conflicting adjudication decisions for one digest.");
      seen[0].add(key);
      if (!hasOwn(context.cases, raw.case_sha256)) throw new Error("Adjudication refers to an unknown case digest.");
      if (!index.findings.has(key)) throw new Error("Adjudication refers to a finding digest absent from the report.");
      if (issueId !== null) {
        if (raw.decision === "unknown") throw new Error("Unknown finding decisions cannot carry an issue mapping.");
        const issue = issues.get(raw.case_sha256).get(issueId);
        if (!issue) throw new Error("Adjudication maps a finding to an unknown issue.");
        if (raw.decision === "supported" && issue.expectation !== "present") throw new Error("A supported finding cannot map to an absent issue.");
      }
      finding_decisions.push({ case_sha256: raw.case_sha256, finding_sha256: raw.finding_sha256, decision: raw.decision, issue_id: issueId, reason: raw.reason });
    });
    value.review_decisions.forEach((raw, position) => {
      const label = `review_decisions[${position}]`;
      exactKeys(raw, ["case_sha256", "review_sha256", "decision", "reason"], [], label);
      for (const field of ["case_sha256", "review_sha256"]) {
        if (typeof raw[field] !== "string" || !DIGEST.test(raw[field])) throw new Error(`${label}.${field} must be a SHA-256 digest.`);
      }
      if (!DECISIONS.includes(raw.decision)) throw new Error(`${label}.decision must be supported, rejected or unknown.`);
      boundedText(raw.reason, `${label}.reason`, MAX_REASON);
      const key = pairKey(raw.case_sha256, raw.review_sha256);
      if (seen[1].has(key)) throw new Error("Duplicate or conflicting adjudication decisions for one digest.");
      seen[1].add(key);
      if (!hasOwn(context.cases, raw.case_sha256)) throw new Error("Adjudication refers to an unknown case digest.");
      if (!index.reviews.has(key)) throw new Error("Adjudication refers to a review digest absent from the report.");
      review_decisions.push({ case_sha256: raw.case_sha256, review_sha256: raw.review_sha256, decision: raw.decision, reason: raw.reason });
    });
    return { schema_version: value.schema_version, adjudication_kind: value.adjudication_kind, source_report_sha256: value.source_report_sha256, finding_decisions, review_decisions };
  }

  const blank = context => ({ decision: "unknown", issue_id: null, reason: context.template_reason });
  const startState = context => ({ findings: context.findings.map(() => blank(context)), reviews: context.reviews.map(() => blank(context)) });

  function artifactFromState(context, state) {
    return {
      schema_version: 1,
      adjudication_kind: "repository",
      source_report_sha256: context.source_report_sha256,
      finding_decisions: context.findings.map((item, i) => ({ case_sha256: item.case_sha256, finding_sha256: item.finding_sha256, decision: state.findings[i].decision, issue_id: state.findings[i].issue_id, reason: state.findings[i].reason })),
      review_decisions: context.reviews.map((item, i) => ({ case_sha256: item.case_sha256, review_sha256: item.review_sha256, decision: state.reviews[i].decision, reason: state.reviews[i].reason })),
    };
  }

  // Listed decisions replace the unknown template; anything unlisted stays unknown.
  function stateFromArtifact(context, artifact) {
    const state = startState(context);
    const index = contextIndex(context);
    for (const item of artifact.finding_decisions) {
      state.findings[index.findings.get(pairKey(item.case_sha256, item.finding_sha256))] = { decision: item.decision, issue_id: item.issue_id, reason: item.reason };
    }
    for (const item of artifact.review_decisions) {
      state.reviews[index.reviews.get(pairKey(item.case_sha256, item.review_sha256))] = { decision: item.decision, issue_id: null, reason: item.reason };
    }
    return state;
  }

  // Moving to or from unknown never invents a judgment: it only clears the mapping
  // and swaps the placeholder reason so a real one has to be written.
  function setDecision(context, label, decision) {
    if (!DECISIONS.includes(decision) || label.decision === decision) return label;
    const reason = decision === "unknown"
      ? (label.reason === "" ? context.template_reason : label.reason)
      : (label.reason === context.template_reason ? "" : label.reason);
    return { decision, issue_id: decision === "unknown" ? null : label.issue_id, reason };
  }

  function serializeArtifact(artifact) {
    const text = JSON.stringify(artifact, null, 2) + "\n";
    if (new TextEncoder().encode(text).length > MAX_ARTIFACT_BYTES) throw new Error("The artifact exceeds the 16 MiB limit.");
    return text;
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { parseStrictJson, validateArtifact, startState, artifactFromState, stateFromArtifact, setDecision, serializeArtifact, MAX_ARTIFACT_BYTES };
  }
  if (typeof document === "undefined") return;

  const $ = selector => document.querySelector(selector);
  let context;
  const view = { kind: "findings", caseFilter: "all", status: "all", page: 0, state: null, loaded: false };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function option(value, text) { const node = el("option", "", text); node.value = value; return node; }
  function setStatus(message, tone) {
    const node = $("#status-line");
    node.textContent = message;
    node.className = tone || "";
  }
  const items = () => context[view.kind];
  const labels = () => view.state[view.kind];
  const judged = label => label.decision !== "unknown";
  const shortDigest = digest => digest.slice(0, 12);
  const trial = slot => `${slot.reviewer} · trial ${slot.epoch}`;

  function visibleIndexes() {
    const result = [];
    items().forEach((item, index) => {
      if (view.caseFilter !== "all" && item.case_sha256 !== view.caseFilter) return;
      const label = labels()[index];
      if (view.status === "unknown" && judged(label)) return;
      if (view.status === "judged" && !judged(label)) return;
      result.push(index);
    });
    return result;
  }

  function slotsLine(slots) {
    const shown = slots.slice(0, 4).map(trial).join("; ");
    return slots.length > 4 ? `${shown}; +${slots.length - 4} more` : shown;
  }

  function rubric(caseItem) {
    const details = el("details");
    details.append(el("summary", "", "Evaluator rubric issues for this case"));
    const list = el("ul");
    for (const issue of caseItem.issues) {
      list.append(el("li", "", `${issue.issue_id} (${issue.category}, ${issue.expectation} issue) ${issue.ranges.join(", ")}`));
    }
    details.append(list);
    return details;
  }

  function controls(item, label, index) {
    const box = el("div", "fields");
    const decision = el("label", "", "Decision");
    const select = el("select");
    select.id = `decision-${view.kind}-${index}`;
    select.dataset.field = "decision";
    select.dataset.index = String(index);
    for (const value of DECISIONS) select.append(option(value, value[0].toUpperCase() + value.slice(1)));
    select.value = label.decision;
    decision.append(select);
    box.append(decision);
    if (view.kind === "findings") {
      const mapping = el("label", "", "Issue mapping (optional)");
      const issue = el("select");
      issue.id = `issue-${index}`;
      issue.dataset.field = "issue";
      issue.dataset.index = String(index);
      issue.append(option("", "No mapping"));
      for (const entry of context.cases[item.case_sha256].issues) issue.append(option(entry.issue_id, `${entry.issue_id} (${entry.category}, ${entry.expectation})`));
      issue.value = label.issue_id ?? "";
      issue.disabled = label.decision === "unknown";
      mapping.append(issue);
      box.append(mapping);
    } else {
      box.append(el("span"));
    }
    const reason = el("label", "wide", "Reason");
    const area = el("textarea");
    area.id = `reason-${view.kind}-${index}`;
    area.dataset.field = "reason";
    area.dataset.index = String(index);
    area.maxLength = MAX_REASON;
    area.value = label.reason;
    reason.append(area);
    const error = el("p", "field-error");
    error.id = `error-${view.kind}-${index}`;
    error.textContent = label.reason === "" ? "A reason is required before export." : "";
    reason.append(error);
    box.append(reason);
    return box;
  }

  function card(index) {
    const item = items()[index], label = labels()[index];
    const article = el("article", "item");
    article.dataset.index = String(index);
    const head = el("div", "item-head");
    const title = el("h2", "", `${context.cases[item.case_sha256].case_id} · ${view.kind === "findings" ? item.category : item.verdict}`);
    const tag = el("span", `tag ${judged(label) ? "judged" : "unknown"}`, judged(label) ? label.decision : "unknown");
    tag.dataset.role = "state";
    head.append(title, tag);
    article.append(head);
    article.append(el("p", "meta mono", `${view.kind === "findings" ? "finding" : "review"} ${shortDigest(view.kind === "findings" ? item.finding_sha256 : item.review_sha256)} · ${slotsLine(item.slots)}`));
    if (view.kind === "findings") {
      article.append(el("p", "summary-text", item.summary));
      for (const evidence of item.evidence) {
        const block = el("div", "evidence");
        block.append(el("p", "meta mono", `${evidence.path}:${evidence.start_line}-${evidence.end_line}${evidence.symbol ? ` · ${evidence.symbol}` : ""}`));
        block.append(el("pre", "", evidence.excerpt));
        article.append(block);
      }
    } else {
      article.append(el("p", "summary-text", `Verdict ${item.verdict} with ${item.finding_sha256s.length} unique finding${item.finding_sha256s.length === 1 ? "" : "s"}. Judge the whole review, for example an approval that reports nothing.`));
    }
    article.append(rubric(context.cases[item.case_sha256]));
    article.append(controls(item, label, index));
    return article;
  }

  function summary() {
    const total = context.findings.length + context.reviews.length;
    const done = view.state.findings.filter(judged).length + view.state.reviews.filter(judged).length;
    $("#progress-line").textContent = `${done} of ${total} decisions judged. ${total - done} remain unknown and count as neither passes nor failures.`;
  }

  function render() {
    const indexes = visibleIndexes();
    const pages = Math.max(1, Math.ceil(indexes.length / PAGE_SIZE));
    view.page = Math.min(view.page, pages - 1);
    const container = $("#items");
    container.replaceChildren();
    if (!indexes.length) container.append(el("p", "empty", "No items match these filters."));
    for (const index of indexes.slice(view.page * PAGE_SIZE, (view.page + 1) * PAGE_SIZE)) container.append(card(index));
    $("#page-line").textContent = `Page ${view.page + 1} of ${pages} · ${indexes.length} items`;
    $("#prev-page").disabled = view.page === 0;
    $("#next-page").disabled = view.page >= pages - 1;
    for (const button of document.querySelectorAll("[data-kind]")) button.setAttribute("aria-pressed", String(button.dataset.kind === view.kind));
    summary();
  }

  function download(text) {
    const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = "repository-adjudication.json";
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function exportArtifact() {
    try {
      const artifact = validateArtifact(artifactFromState(context, view.state), context);
      download(serializeArtifact(artifact));
      setStatus("Exported repository-adjudication.json. The source report was not changed.", "good");
    } catch (error) {
      setStatus(`Not exported: ${error.message}`, "bad");
    }
  }

  async function importFile(file) {
    try {
      if (file.size > MAX_ARTIFACT_BYTES) throw new Error("The artifact exceeds the 16 MiB limit.");
      const buffer = await file.arrayBuffer();
      if (buffer.byteLength > MAX_ARTIFACT_BYTES) throw new Error("The artifact exceeds the 16 MiB limit.");
      const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
      const artifact = validateArtifact(parseStrictJson(text), context);
      view.state = stateFromArtifact(context, artifact);
      view.page = 0;
      render();
      setStatus(`Imported ${artifact.finding_decisions.length + artifact.review_decisions.length} decisions. Items not listed stay unknown.`, "good");
    } catch (error) {
      setStatus(`Import rejected: ${error.message}`, "bad");
    }
  }

  function bind() {
    $("#items").addEventListener("change", event => {
      const target = event.target, kind = view.kind;
      const index = Number(target.dataset.index);
      if (!Number.isInteger(index) || !target.dataset.field) return;
      const label = view.state[kind][index];
      if (target.dataset.field === "decision") {
        view.state[kind][index] = setDecision(context, label, target.value);
        const next = card(index);
        target.closest("article").replaceWith(next);
        next.querySelector("select").focus();
        summary();
      } else if (target.dataset.field === "issue") {
        label.issue_id = target.value === "" ? null : target.value;
      }
    });
    $("#items").addEventListener("input", event => {
      const target = event.target;
      if (target.dataset.field !== "reason") return;
      view.state[view.kind][Number(target.dataset.index)].reason = target.value;
      const error = $(`#error-${view.kind}-${target.dataset.index}`);
      if (error) error.textContent = target.value === "" ? "A reason is required before export." : "";
    });
    document.addEventListener("click", event => {
      const button = event.target.closest("button");
      if (!button || !view.loaded) return;
      if (button.dataset.kind) { view.kind = button.dataset.kind; view.page = 0; render(); }
      else if (button.id === "prev-page") { view.page--; render(); }
      else if (button.id === "next-page") { view.page++; render(); }
      else if (button.id === "export-button") exportArtifact();
      else if (button.id === "import-button") $("#file-input").click();
      else if (button.id === "reset-button") {
        const edited = view.state.findings.concat(view.state.reviews).some(judged);
        if (edited && !window.confirm("Reset every decision to unknown?")) return;
        view.state = startState(context); render(); setStatus("Every decision is unknown.", "");
      }
    });
    $("#case-filter").addEventListener("change", event => { view.caseFilter = event.target.value; view.page = 0; render(); });
    $("#status-filter").addEventListener("change", event => { view.status = event.target.value; view.page = 0; render(); });
    $("#file-input").addEventListener("change", event => {
      const file = event.target.files[0];
      event.target.value = "";
      if (file) importFile(file);
    });
  }

  function start() {
    try {
      context = JSON.parse($("#adjudication-data").textContent);
      if (!isObject(context) || context.schema_version !== 1 || !Array.isArray(context.findings) || !Array.isArray(context.reviews) || !isObject(context.cases)) throw new Error("The embedded adjudication data is invalid.");
    } catch (error) {
      setStatus(error.message || "The embedded adjudication data is invalid.", "bad");
      for (const button of document.querySelectorAll("button")) button.disabled = true;
      return;
    }
    view.state = startState(context);
    view.loaded = true;
    $("#report-line").textContent = `Source report digest ${context.source_report_sha256} · ${context.run.rows} samples · ${context.run.reviewers.length} reviewer${context.run.reviewers.length === 1 ? "" : "s"} · ${context.run.epochs} trial${context.run.epochs === 1 ? "" : "s"}`;
    $("#finding-count").textContent = `(${context.findings.length})`;
    $("#review-count").textContent = `(${context.reviews.length})`;
    const filter = $("#case-filter");
    filter.append(option("all", "All cases"));
    for (const [digest, item] of Object.entries(context.cases).sort((a, b) => a[1].case_id.localeCompare(b[1].case_id) || a[0].localeCompare(b[0]))) filter.append(option(digest, `${item.case_id} (${shortDigest(digest)})`));
    bind();
    render();
    setStatus("Ready. Every item is unknown until you label it.", "");
  }
  start();
})();
