"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const dashboard = require("../../src/review_boundary/web/dashboard.js");
const load = name => JSON.parse(readFileSync(resolve(__dirname, "../fixtures/report_contracts", name), "utf8"));

// This DOM contract rejects HTML sinks so candidate strings must remain text.
class TextNode {
  constructor(text) { this.textContent = String(text); }
}
let focused = null;
class Element {
  constructor(tag) {
    this.tagName = tag.toUpperCase(); this.childNodes = []; this.attributes = {}; this.listeners = {};
    this.open = false; this.tabIndex = null; this.scrolled = null;
    const classes = new Set();
    this.classList = { add: name => classes.add(name), contains: name => classes.has(name) };
  }
  append(...items) {
    for (const item of items) {
      const child = item instanceof Element || item instanceof TextNode ? item : new TextNode(item);
      child.parentNode = this;
      this.childNodes.push(child);
    }
  }
  replaceChildren(...items) { this.childNodes = []; this.append(...items); }
  get children() { return this.childNodes.filter(item => item instanceof Element); }
  get textContent() { return this.childNodes.map(item => item.textContent).join(""); }
  set textContent(text) { this.replaceChildren(new TextNode(text)); }
  set innerHTML(_) { throw new Error("Native candidate text must never enter an HTML sink"); }
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
function render(report, options = {}) {
  const root = new Element("main");
  dashboard.renderNativeView(report, { document: dom, root, ...options });
  return root;
}
function nodes(root) { return [root, ...root.children.flatMap(nodes)]; }
function field(root, name) {
  const label = nodes(root).find(node => node.tagName === "DT" && node.textContent === name);
  assert(label, name);
  return label.parentNode.children[label.parentNode.children.indexOf(label) + 1].textContent;
}

test("native fixture views identify scripted provenance and retain unknown usage", () => {
  for (const name of ["native-repository.json", "native-boundary.json"]) {
    const root = render(load(name));
    assert(root.textContent.includes("Calibration run"));
    assert(root.textContent.includes("Scripted reviewers"));
    assert.equal(field(root, "Recorded call cost"), "Unknown");
    assert.equal(field(root, "Recorded latency (ms)"), "Unknown");
    assert.equal(field(root, "Recorded provider"), "Unknown");
    assert(root.textContent.includes("no row can be shown as matching"));
  }
});

test("adapter and absent run kinds are not mislabeled as native model performance", () => {
  const report = load("native-repository.json");
  report.metadata.run_kind = "adapter";
  assert(render(report).textContent.includes("External reviewer run"));
  delete report.metadata.run_kind;
  assert(render(report).textContent.includes("Run kind not recorded"));
});

test("recorded costs retain partial coverage and do not infer latency from dates", () => {
  const report = load("native-repository.json");
  report.generated_at = "2026-11-06T12:00:00Z";
  report.metadata.usage = { provider_reported_cost_usd: 0.01, api_calls_with_reported_cost: 2, api_calls_without_reported_cost: 1 };
  const root = render(report);
  assert.equal(field(root, "Recorded call cost"), "0.01 USD (partial known cost)");
  assert.equal(field(root, "Calls without reported cost"), "1");
  assert.equal(field(root, "Recorded latency (ms)"), "Unknown");
});

test("native findings, paths and excerpts stay inert and complete", () => {
  const report = load("native-repository.json");
  const hostile = '</script><img src=x onerror="globalThis.pwned=true">';
  report.rows[0].case_id = hostile;
  const finding = report.rows[0].findings[0];
  assert(finding);
  finding.finding.summary = hostile;
  finding.finding.evidence[0].excerpt = hostile + "x".repeat(5000);
  report.rows[0].review.findings[0] = structuredClone(finding.finding);
  const root = render(report, { page: "cases", view: { selected: 0 } });
  assert(root.textContent.includes(hostile + "x".repeat(5000)));
  assert.equal(nodes(root).some(node => ["SCRIPT", "IMG", "IFRAME"].includes(node.tagName)), false);
  assert.equal(nodes(root).some(node => Object.keys(node.attributes).some(key => /^on/i.test(key))), false);
  assert.equal(globalThis.pwned, undefined);
});

test("raw imports reject duplicate or inexact integer tokens and clear verification", () => {
  for (const text of [
    '{"schema_version":2.0,"metadata":{},"rows":[]}',
    '{"schema_version":2,"schema_version":2,"metadata":{},"rows":[]}',
  ]) assert.throws(() => dashboard.makeImportedEntry("report.json", Buffer.from(text)));
  assert.throws(() => dashboard.makeImportedEntry("report.json", Uint8Array.from([0xff])));
  const report = load("envelope-repository.json");
  report.report.metadata.evidence_verification = { status: "matching_supplied_artifact" };
  const entry = dashboard.makeImportedEntry("report.json", Buffer.from(JSON.stringify(report)));
  assert.equal(entry.evidence_verification, null);
  assert.deepEqual(entry.document, report);
});

test("native case search operates on document-scoped positions without mutation", () => {
  const report = load("native-repository.json"), original = JSON.stringify(report);
  const root = render(report, { page: "cases", view: {} });
  const search = nodes(root).find(node => node.tagName === "INPUT");
  search.value = "no such case anywhere";
  search.dispatch("input");
  assert(root.textContent.includes("No matching cases"));
  assert.equal(JSON.stringify(report), original);
});

test("native run records never dump unknown provider transcript fields", () => {
  const report = load("native-repository.json");
  report.metadata.provider_transcript = "should-stay-out-of-view";
  report.metadata.api_key = "should-stay-out-of-view";
  assert.equal(render(report).textContent.includes("should-stay-out-of-view"), false);
});

function citedReport() {
  const report = load("native-repository.json");
  report.rows[0].events[5] = { tool: "search_files", status: "ok", response_bytes: 413, matches: [{ path: "src/service.py", line: 4 }, { path: "src/service.py", line: 6 }] };
  return report;
}
const citationButtons = root => nodes(root).filter(node => node.tagName === "BUTTON" && node.textContent.startsWith("Recorded "));
const highlighted = root => nodes(root).filter(node => node.classList.contains("evidence-target"));

test("citation buttons show recorded events and omit links when none exist", () => {
  const report = citedReport();
  report.rows[0].events[4] = { tool: "list_files", status: "ok", response_bytes: 360 };
  const root = render(report, { page: "cases", view: { selected: 0 } });
  const buttons = citationButtons(root);
  assert.equal(buttons.length, 1);
  assert(buttons[0].textContent.startsWith("Recorded search event [5]"));
  assert(buttons[0].textContent.includes("lines 4, 6"));
  assert(buttons[0].textContent.includes("(partial)"));
  assert(root.textContent.includes("No recorded read or search event returned these lines."));
});

test("clicking a citation focuses the exact recorded event without navigation", () => {
  const report = citedReport(), original = JSON.stringify(report);
  const calls = [];
  const route = { hash: "#/cases" };
  const view = { selected: 0 };
  const root = render(report, { page: "cases", view, navigate: target => { calls.push(target); route.hash = target; } });
  const buttons = citationButtons(root);
  assert.equal(buttons.length, 2);
  assert(buttons[0].textContent.startsWith("Recorded read event [4]"));
  assert(buttons[0].textContent.includes("lines 4, 5"));
  assert.equal(nodes(root).some(node => node.tagName === "DETAILS" && node.open), false);
  focused = null;
  buttons[1].click();
  assert(focused);
  assert.equal(focused.tagName, "LI");
  assert.equal(focused.attributes["data-row-index"], "0");
  assert.equal(focused.attributes["data-event-index"], "5");
  assert.equal(focused.closest("details").open, true);
  assert.equal(focused.tabIndex, -1);
  assert(focused.scrolled);
  assert.deepEqual(highlighted(root), [focused]);
  assert.equal(view.pendingEvidence, null);
  assert.equal(view.selected, 0);
  assert.deepEqual(calls, []);
  assert.equal(route.hash, "#/cases");
  assert.equal(JSON.stringify(report), original);
  focused = null;
  citationButtons(root)[0].click();
  assert.equal(focused.attributes["data-event-index"], "4");
  assert.deepEqual(highlighted(root), [focused]);
  assert.deepEqual(calls, []);
  assert.equal(route.hash, "#/cases");
});

test("repository findings page reveals event detail inline without a route change", () => {
  const report = citedReport();
  const calls = [];
  const route = { hash: "#/pairs" };
  const view = {};
  const root = render(report, { page: "pairs", view, navigate: target => { calls.push(target); route.hash = target; } });
  assert.equal(root.textContent.includes("Tool trace"), false);
  focused = null;
  citationButtons(root)[0].click();
  assert(root.textContent.includes("Tool trace"));
  assert.equal(nodes(root).filter(node => node.className === "panel native-detail").length, 1);
  assert(focused);
  assert.equal(focused.attributes["data-event-index"], "4");
  assert.equal(focused.closest("details").open, true);
  assert.deepEqual(highlighted(root), [focused]);
  assert.deepEqual(calls, []);
  assert.equal(route.hash, "#/pairs");
  nodes(root).find(node => node.tagName === "BUTTON" && node.textContent === "Close details").click();
  assert.equal(root.textContent.includes("Tool trace"), false);
  assert.equal(view.inlineRow, null);
  assert.deepEqual(calls, []);
});

const snapshotSection = root => nodes(root).find(node => node.className === "native-section" && node.textContent.startsWith("EVIDENCE SNAPSHOT"));

test("primary snapshot text is human readable and machine codes stay in details", () => {
  const root = render(load("native-repository.json"), { page: "cases", view: { selected: 0 } });
  const section = snapshotSection(root);
  assert(section);
  const primary = section.children.filter(node => node.tagName !== "DETAILS").map(node => node.textContent).join(" ");
  assert(primary.includes("No snapshot reference is recorded for this row."));
  assert(primary.includes("Authenticity: not established"));
  assert.equal(/[a-z]+_[a-z_]+/.test(primary), false);
  const details = section.children.find(node => node.tagName === "DETAILS");
  assert(details);
  assert(details.textContent.startsWith("Snapshot details"));
  assert(details.textContent.includes("no_snapshot_reference"));
  assert(details.textContent.includes("unchecked_in_js"));
});

test("unknown snapshot reasons use a generic status sentence", () => {
  const verification = { source_report_sha256: "e".repeat(64), rows: [{
    row_index: 0, status: "mismatch", reason: "weird_code", snapshot_kind: "repository", snapshot_version: 1,
    snapshot_sha256: "b".repeat(64), authenticity: "not_established",
  }] };
  const root = render(load("native-repository.json"), { page: "cases", view: { selected: 0 }, verification });
  const section = snapshotSection(root);
  const primary = section.children.filter(node => node.tagName !== "DETAILS").map(node => node.textContent).join(" ");
  assert(primary.includes("Mismatch"));
  assert(primary.includes("The recorded snapshot reference disagrees with the report."));
  assert.equal(primary.includes("weird_code"), false);
  assert(section.children.find(node => node.tagName === "DETAILS").textContent.includes("weird_code"));
});

test("optional extension containers are ignored across native overview, cases and findings", () => {
  for (const extension of [null, ["display-extension-note"], { toString: { note: "display-extension-note" }, valueOf: null }]) {
    const report = load("native-repository.json"), row = report.rows[0];
    row.family = extension;
    row.guard = extension;
    row.condition = extension;
    Object.assign(report.metadata, { provider: extension, latency_ms: extension, observation_scope: extension, fixture_note: extension });
    delete report.metadata.reviewers;
    const before = JSON.stringify(report);
    for (const page of ["overview", "cases", "pairs"]) {
      const root = render(report, { page, view: { selected: 0 }, runs: [extension] });
      assert.equal(root.textContent.includes("display-extension-note"), false);
      assert.equal(root.textContent.includes("[object Object]"), false);
      assert.equal(root.textContent.includes("function Object"), false);
      assert.equal(nodes(root).some(node => ["SCRIPT", "IMG", "IFRAME"].includes(node.tagName)), false);
      if (page === "overview") {
        assert.equal(field(root, "Recorded provider"), "Unknown");
        assert.equal(field(root, "Recorded reviewers"), "Unknown");
        assert.equal(field(root, "Recorded latency (ms)"), "Unknown");
      } else if (page === "cases") {
        assert.equal(nodes(root).find(node => node.className === "row-name").textContent, row.case_id[0].toUpperCase() + row.case_id.slice(1).replaceAll("_", " "));
        const search = nodes(root).find(node => node.tagName === "INPUT");
        for (const query of ["display-extension-note", "[object Object]"]) {
          search.value = query; search.dispatch("input");
          assert(root.textContent.includes("No matching cases"));
        }
        search.value = row.case_id; search.dispatch("input");
        assert(root.textContent.includes("1 recorded samples"));
        const reviewers = nodes(root).find(node => node.tagName === "SELECT" && node.attributes["aria-label"] === "Filter by reviewer");
        reviewers.value = row.reviewer; reviewers.dispatch("change");
        assert(root.textContent.includes("1 recorded samples"));
      } else assert(root.textContent.includes("Recorded findings"));
    }
    assert.equal(JSON.stringify(report), before);
  }
});

test("prototype-shaped labels remain recorded text in every native view and run title", () => {
  for (const value of ["constructor", "toString", "__proto__"]) {
    for (const name of ["native-repository.json", "native-boundary.json"]) {
      const report = load(name);
      report.metadata.reviewers = [value];
      for (const slot of report.metadata.expected_slots) slot.reviewer = value;
      for (const row of report.rows) Object.assign(row, { reviewer: value, family: value, surface: value });
      const before = JSON.stringify(report);
      for (const page of ["overview", "cases", "pairs"]) {
        const root = render(report, { page, view: { selected: 0 } });
        assert.equal(root.textContent.includes("[object Object]"), false);
        assert.equal(root.textContent.includes("function "), false);
        if (page === "overview") assert.equal(field(root, "Recorded reviewers"), value);
        if (page === "cases") {
          const search = nodes(root).find(node => node.tagName === "INPUT");
          search.value = value; search.dispatch("input");
          assert(root.textContent.includes("recorded samples"));
          const reviewers = nodes(root).find(node => node.tagName === "SELECT" && node.attributes["aria-label"] === "Filter by reviewer");
          assert(reviewers.children.some(choice => choice.textContent === value));
          reviewers.value = value; reviewers.dispatch("change");
          assert(root.textContent.includes("recorded samples"));
        }
      }
      assert.equal(JSON.stringify(report), before);
    }
    assert.equal(typeof dashboard.runName({ name: value }), "string");
    assert.equal(dashboard.runName({ name: value }).includes("function "), false);
  }
  for (const value of [null, ["extension"], { toString: "extension" }]) {
    const entry = dashboard.makeEntry(value, load("native-repository.json"));
    assert.equal(entry.name, "Saved evaluation");
    assert.equal(dashboard.runName(entry), "Saved evaluation");
    assert.equal(dashboard.runName({ name: value }), "Imported evaluation");
    assert.equal(dashboard.formatDate({ generated_at: value }), "Date not recorded");
  }
});

test("case paging and finding navigation reuse one owned validation view", () => {
  const report = citedReport();
  const first = report.rows[0];
  report.metadata.epochs = 22;
  for (let epoch = 2; epoch <= 22; epoch++) {
    report.rows.push({ ...structuredClone(first), epoch });
    report.metadata.expected_slots.push({ case_sha256: first.case_sha256, reviewer: first.reviewer, epoch });
  }
  report.metadata.expected_count = 22;
  let visits = 0;
  Object.defineProperty(report.metadata, "display_visit", { enumerable: true, get() { visits++; return "recorded"; } });
  for (const page of ["cases", "pairs"]) {
    visits = 0;
    const root = render(report, { page, view: { selected: page === "cases" ? 0 : null } });
    assert.equal(visits, 1);
    const next = nodes(root).find(node => node.tagName === "BUTTON" && node.textContent === "Next");
    assert(next && !next.disabled);
    next.click();
    assert.equal(visits, 1);
    const previous = nodes(root).find(node => node.tagName === "BUTTON" && node.textContent === "Previous");
    previous.click();
    assert.equal(visits, 1);
    citationButtons(root)[0].click();
    assert.equal(visits, 1);
    assert.equal(highlighted(root).length, 1);
    dashboard.renderNativeView(report, { document: dom, root, page, view: {} });
    assert.equal(visits, 2);
  }
});

test("an existing render stays on its owned report while a new public render checks mutations", () => {
  const report = citedReport();
  const originalCase = report.rows[0].case_id;
  const root = render(report, { page: "pairs", view: {} });
  report.rows[0].case_id = "changed case";
  report.rows[0].events[4].path = "src/other.py";
  citationButtons(root)[0].click();
  assert(root.textContent.includes(originalCase));
  assert.equal(root.textContent.includes("changed case"), false);
  assert.equal(highlighted(root)[0].attributes["data-event-index"], "4");
  const current = render(report, { page: "pairs" });
  assert(current.textContent.includes("changed case"));
  assert.equal(citationButtons(current).some(button => button.textContent.startsWith("Recorded read event [4]")), false);
  report.rows[0].completed = "yes";
  assert.throws(() => render(report));
});
