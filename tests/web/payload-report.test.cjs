"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const contracts = require("../../src/review_boundary/web/report-contracts.js");
const dashboard = require("../../src/review_boundary/web/dashboard.js");

// This minimal DOM refuses HTML sinks and records exact evidence focus.
class TextNode {
  constructor(text) { this.textContent = String(text); }
}
let focused = null;
class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.childNodes = []; this.attributes = {}; this.listeners = {};
    this.open = false;
    const classes = new Set();
    this.classList = { add: name => classes.add(name), contains: name => classes.has(name) };
  }
  append(...items) {
    for (const item of items) {
      const child = item instanceof Element || item instanceof TextNode ? item : new TextNode(item);
      child.parentNode = this; this.childNodes.push(child);
    }
  }
  replaceChildren(...items) { this.childNodes = []; this.append(...items); }
  get children() { return this.childNodes.filter(item => item instanceof Element); }
  get textContent() { return this.childNodes.map(item => item.textContent).join(""); }
  set innerHTML(_) { throw new Error("Payload labels must remain inert text"); }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  addEventListener(type, callback) { this.listeners[type] = callback; }
  dispatch(type) { this.listeners[type]?.({ target: this }); }
  click() { this.dispatch("click"); }
  focus() { focused = this; }
  scrollIntoView(options) { this.scrolled = options || true; }
  closest(tag) {
    for (let node = this; node; node = node.parentNode) if (node.tagName === tag.toUpperCase()) return node;
    return null;
  }
}
const dom = { createElement: tag => new Element(tag) };
const nodes = root => [root, ...root.children.flatMap(nodes)];
function renderCases(report, view = {}) {
  const root = new Element("main");
  dashboard.renderNativeView(report, { document: dom, root, page: "cases", view });
  return root;
}

// Display examples carry recorded hashes only. These are not replay evidence.
const canonical = value => Array.isArray(value) ? `[${value.map(canonical).join(",")}]` : value && typeof value === "object" ? `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}` : JSON.stringify(value);
function payloadReport(condition = "benign_quote") {
  const report = JSON.parse(readFileSync(resolve(__dirname, "../fixtures/report_contracts/native-repository.json"), "utf8"));
  report.metadata.scoring_version = "repository-payload-v1";
  const row = report.rows[0];
  Object.assign(row, {
    scoring_version: "repository-payload-v1", case_schema_version: 2, surface: "readme", condition,
    carrier_observed: true, payload_exposed: condition === "attack",
    payload_ref: { pack_id: "original", pack_version: 1, pack_digest: "a".repeat(64), entry_id: "review_note", carrier: "readme", condition },
  });
  row.events = row.events.map(event => {
    let args = {};
    if (event.tool === "list_files") args = { prefix: "", cursor: 0, limit: 20 };
    if (event.tool === "read_file") args = { path: event.path, start_line: 1, end_line: Math.max(...event.lines) };
    if (event.tool === "submit_review") args = { verdict: row.review.verdict, findings: row.review.findings.map(finding => ({ ...finding, evidence: finding.evidence.map(span => ({ ...span, symbol: span.symbol ?? null })) })) };
    return { ...event, requested_tool: event.tool, arguments_json: canonical(args), response_sha256: "b".repeat(64), ...(event.tool === "list_files" ? { paths: ["README.md", "src/policy.py", "src/route.py", "src/service.py"] } : {}) };
  });
  return report;
}
const validateRaw = text => contracts.validateDisplayDocument(contracts.parseReportText(text));

test("payload display keeps clean, attack and quotation delivery separate", () => {
  for (const condition of ["clean", "attack", "benign_quote"]) {
    const report = payloadReport(condition);
    assert.equal(contracts.validateDisplayDocument(report).report_kind, "repository");
    assert.equal(report.rows[0].payload_exposed, condition === "attack");
    assert.equal(report.rows[0].semantic_passed, null);
    assert.equal(contracts.nativeStats(report).source_groups, 1);
    assert.equal(contracts.evidenceLocator(report, 0, { event_index: 1 }).event_index, 1);
  }
});

test("payload fields are required only under the explicit payload scoring version", () => {
  for (const field of ["case_schema_version", "condition", "carrier_observed", "payload_ref"]) {
    const report = payloadReport(); delete report.rows[0][field];
    assert.throws(() => contracts.validateDisplayDocument(report));
  }
  const legacy = JSON.parse(readFileSync(resolve(__dirname, "../fixtures/report_contracts/native-repository.json"), "utf8"));
  assert.doesNotThrow(() => contracts.validateDisplayDocument(legacy));
});

test("raw payload integer fields reject float, exponent and boolean spellings", () => {
  const text = JSON.stringify(payloadReport());
  for (const [key, integer] of [["case_schema_version", 2], ["pack_version", 1]]) {
    for (const spelling of [`${integer}.0`, `${integer}e0`, "true"]) {
      const altered = text.replace(`"${key}":${integer}`, `"${key}":${spelling}`);
      assert.throws(() => validateRaw(altered), `${key}=${spelling}`);
    }
  }
});

test("payload events require canonical validated arguments and response identity", () => {
  for (const mutate of [
    report => { report.rows[0].events[0].arguments_json = "{ }"; },
    report => { report.rows[0].events[1].arguments_json = "{}"; },
    report => { report.rows[0].events[1].arguments_json = '{"cursor":0.0,"limit":20,"prefix":""}'; },
    report => { report.rows[0].events[0].arguments_json = null; },
    report => { delete report.rows[0].events[0].requested_tool; },
    report => { delete report.rows[0].events[0].response_sha256; },
    report => { report.rows[0].events[0].requested_tool = "read_file"; },
    report => { report.rows[0].events[0].paths = ["README.md"]; },
    report => { report.rows[0].events[1].paths = ["README.md", "README.md"]; },
  ]) {
    const report = payloadReport(); mutate(report);
    assert.throws(() => validateRaw(JSON.stringify(report)));
  }
});

test("payload reference and delivery contradictions reject", () => {
  for (const mutate of [
    report => { report.rows[0].payload_ref.carrier = "pr"; },
    report => { report.rows[0].payload_ref.condition = "attack"; },
    report => { report.rows[0].payload_exposed = true; },
    report => { report.rows[0].carrier_observed = false; },
    report => { report.rows[0].payload_ref.pack_id = "original\n"; },
  ]) {
    const report = payloadReport(); mutate(report);
    assert.throws(() => contracts.validateDisplayDocument(report));
  }
});

test("aggregate payload trace allows one bounded overflow event and no later delivery", () => {
  const report = payloadReport();
  const args = canonical({ path: "notes/draft.txt", content: "x".repeat(65536) });
  const ordinary = { tool: "write_file", requested_tool: "write_file", status: "blocked", response_bytes: 4, response_sha256: "c".repeat(64), arguments_json: args };
  const terminal = { tool: "limits", requested_tool: "write_file", status: "trace_bytes", response_bytes: 0, arguments_json: args };
  const row = report.rows[0];
  row.events = [...Array.from({ length: 15 }, () => ({ ...ordinary })), terminal];
  Object.assign(row, { completed: false, conclusive: false, rubric_passed: false, write_attempted: true, write_requests_seen: 16, tool_calls: 16, output_bytes: 60 });
  assert.doesNotThrow(() => validateRaw(JSON.stringify(report)));
  const after = structuredClone(report); after.rows[0].events.push(ordinary); after.rows[0].tool_calls++; after.rows[0].output_bytes += 4; after.rows[0].write_requests_seen++;
  assert.throws(() => validateRaw(JSON.stringify(after)));
  const fake = payloadReport();
  fake.rows[0].events.push({ ...terminal, arguments_json: canonical({ path: "notes/draft.txt", content: "small" }) });
  fake.rows[0].tool_calls++;
  assert.throws(() => validateRaw(JSON.stringify(fake)));
});

test("snapshot display accepts supplied V2 consistency context without claiming authenticity", () => {
  const report = payloadReport();
  const context = { source_report_sha256: "d".repeat(64), rows: [{ row_index: 0, status: "matching_supplied_artifact", reason: "document_consistency_only", case_validation: "restored_and_observations_match", authenticity: "not_established", snapshot_kind: "repository", snapshot_version: 2, snapshot_sha256: "e".repeat(64) }] };
  const state = contracts.snapshotStates(report, context)[0];
  assert.equal(state.status, "matching_supplied_artifact");
  assert.equal(state.authenticity, "not_established");
  context.rows[0].snapshot_version = 1;
  assert.equal(contracts.snapshotStates(report, context)[0].status, "unsupported_version");
});

test("long payload case IDs retain distinct conditions in the list and exact evidence navigation", () => {
  const conditions = ["clean", "attack", "benign_quote"];
  const report = payloadReport("clean");
  report.rows = conditions.map((condition, index) => {
    const row = payloadReport(condition).rows[0];
    row.case_id = `rp2:${"a".repeat(64)}:${"b".repeat(64)}:v1:review_note:tool_output:${condition}`;
    row.case_sha256 = String(index + 1).repeat(64);
    row.surface = row.payload_ref.carrier = "tool_output";
    return row;
  });
  Object.assign(report.metadata, {
    case_count: 3, expected_count: 3,
    expected_slots: report.rows.map(row => ({ case_sha256: row.case_sha256, reviewer: row.reviewer, epoch: row.epoch })),
  });
  const original = JSON.stringify(report), ids = report.rows.map(row => row.case_id), view = {};
  assert.equal(new Set(ids.map(id => id.slice(0, 120))).size, 1);
  const root = renderCases(report, view);
  const labels = nodes(root).filter(node => node.className === "row-name");
  assert.deepEqual(labels.map(node => node.textContent), ["Review note · Clean", "Review note · Attack", "Review note · Benign quote"]);
  assert(labels.every(node => node.textContent.length < 64));
  assert.deepEqual(labels.map(node => node.attributes.title), ids);
  const rows = nodes(root).filter(node => node.tagName === "TR" && node.children[0]?.tagName === "TD");
  assert.deepEqual(rows.map(node => node.children[2].textContent), ["Tool response · Clean", "Tool response · Attack", "Tool response · Benign quote"]);
  assert(rows.every(node => !node.children[0].textContent.includes("rp2:")));
  assert.equal(nodes(root).some(node => node.className === "panel native-detail"), false);
  assert.equal(JSON.stringify(report), original);

  labels[1].click();
  const detail = nodes(root).find(node => node.className === "panel native-detail");
  assert.equal(nodes(detail).find(node => node.tagName === "H2").textContent, "Review note · Attack");
  const canonicalId = nodes(detail).find(node => node.tagName === "PRE" && node.textContent === ids[1]);
  assert(canonicalId && canonicalId.closest("details"));
  assert.equal(canonicalId.closest("details").open, false);
  const citation = nodes(detail).find(node => node.tagName === "BUTTON" && node.attributes["aria-label"]?.startsWith("Show recorded read event"));
  assert(citation);
  const selectedEvent = citation.attributes["aria-label"].match(/event (\d+)/)[1];
  focused = null;
  citation.click();
  assert(focused && focused.tagName === "LI");
  assert.equal(focused.attributes["data-row-index"], "1");
  assert.equal(focused.attributes["data-event-index"], selectedEvent);
  assert.equal(focused.closest("details").open, true);
  assert.equal(JSON.stringify(report), original);
});

test("native V1 case label and context retain their original output", () => {
  const report = JSON.parse(readFileSync(resolve(__dirname, "../fixtures/report_contracts/native-repository.json"), "utf8"));
  const original = JSON.stringify(report), row = report.rows[0];
  const root = renderCases(report);
  const label = nodes(root).find(node => node.className === "row-name");
  assert.equal(label.textContent, row.case_id[0].toUpperCase() + row.case_id.slice(1).replaceAll("_", " "));
  assert.equal(label.attributes.title, undefined);
  assert.equal(label.parentNode.children[1].textContent, `${row.variant} · ${row.case_id}`);
  label.click();
  const detail = nodes(root).find(node => node.className === "panel native-detail");
  assert.equal(nodes(detail).find(node => node.tagName === "H2").textContent, row.case_id);
  assert.equal(detail.textContent.includes("Full case identifier"), false);
  assert.equal(JSON.stringify(report), original);
});

test("visible payload labels and carrier context are searchable without changing identifiers", () => {
  const report = payloadReport("clean");
  report.rows = ["suppress_findings_note", "claim_owner_approval"].flatMap(entry => ["clean", "attack", "benign_quote"].map(condition => {
    const row = payloadReport(condition).rows[0];
    row.payload_ref.entry_id = entry;
    row.surface = row.payload_ref.carrier = "tool_output";
    row.case_id = `rp2:${"a".repeat(64)}:${"b".repeat(64)}:v1:${entry}:tool_output:${condition}`;
    return row;
  }));
  report.rows.forEach((row, index) => { row.case_sha256 = String(index + 1).repeat(64); });
  Object.assign(report.metadata, {
    case_count: 6, expected_count: 6,
    expected_slots: report.rows.map(row => ({ case_sha256: row.case_sha256, reviewer: row.reviewer, epoch: row.epoch })),
  });
  const original = JSON.stringify(report), ids = report.rows.map(row => row.case_id), view = {};
  assert.equal(new Set(ids.map(id => id.slice(0, 120))).size, 1);
  const root = renderCases(report, view);
  const search = nodes(root).find(node => node.tagName === "INPUT" && node.attributes["aria-label"] === "Search cases");
  const visibleIds = () => nodes(root).filter(node => node.className === "row-name").map(node => node.attributes.title);
  for (const [phrase, expected] of [
    ["suppress findings note", ids.slice(0, 3)],
    ["benign quote", [ids[2], ids[5]]],
    ["tool response", ids],
    ["suppress_findings_note", ids.slice(0, 3)],
    [ids[1], [ids[1]]],
  ]) {
    search.value = phrase;
    search.dispatch("input");
    assert.deepEqual(visibleIds(), expected, phrase);
    assert.equal(JSON.stringify(report), original);
  }
  search.value = "no such case";
  search.dispatch("input");
  assert.deepEqual(visibleIds(), []);
  const reset = nodes(root).find(node => node.tagName === "BUTTON" && node.textContent === "Reset filters");
  reset.click();
  assert.deepEqual(visibleIds(), ids);
  assert.equal(view.search, "");
  assert.equal(JSON.stringify(report), original);
});
