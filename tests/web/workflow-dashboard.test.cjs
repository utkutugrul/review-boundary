const {test} = require("node:test");
const assert = require("node:assert/strict");
const {readFileSync} = require("node:fs");
const {resolve} = require("node:path");
const core = require("../../src/review_boundary/web/workflow-dashboard.js");
const load = name => readFileSync(resolve(__dirname, "../fixtures/workflow_reports", `${name}.json`), "utf8");

test("export preserves both contract fixtures, nulls, missing coverage and denominators", () => {
  for (const name of ["scripted-complete", "scripted-incomplete"]) {
    const raw = load(name), report = JSON.parse(raw);
    assert.deepEqual(JSON.parse(core.exportJSON(raw)), report);
    assert.equal(report.record_authority, "recorded_data_only");
    assert.equal(report.authenticity, "unavailable");
    for (const metric of Object.values(JSON.parse(core.exportJSON(raw)).summary.case_metrics)) {
      assert.equal(metric.true + metric.false + metric.unknown + metric.missing, metric.expected_denominator);
    }
  }
});

test("export treats script, HTML, URL and Unicode labels as inert text", () => {
  const report = JSON.parse(load("scripted-incomplete"));
  const label = '</script><img src=x onerror="globalThis.pwned=1"> javascript:alert(1) café 🙂\u2028\u2029';
  report.expected.binding.reviewer = label;
  globalThis.pwned = undefined;
  const exported = core.exportJSON(JSON.stringify(report));
  assert.equal(JSON.parse(exported).expected.binding.reviewer, label);
  assert.equal(globalThis.pwned, undefined);
  assert.equal(JSON.parse(exported).scored_cases[0].reviewer_resisted, null);
  assert.throws(() => core.exportJSON("{"));
  assert.throws(() => core.exportJSON(null));
  assert.throws(() => core.exportJSON(" ".repeat(12 * 1024 * 1024 + 1)));
});

test("filters preserve missing and incomplete cases and separate unknown from missing", () => {
  const cases = [
    {state: "missing", unknown: "false", condition: "attack", search: "delegated approval"},
    {state: "incomplete", unknown: "true", condition: "attack", search: "Memory café 🙂"},
    {state: "complete", unknown: "true", condition: "clean", search: "__proto__ </script>"},
  ];
  const pick = filters => cases.filter(item => core.matchesCase(item, filters));
  assert.equal(pick({state: "all", condition: "all"}).length, 3);
  assert.deepEqual(pick({state: "missing"}), [cases[0]]);
  assert.deepEqual(pick({state: "incomplete"}), [cases[1]]);
  assert.deepEqual(pick({state: "unknown"}), cases.slice(1));
  assert.deepEqual(pick({state: "unknown", condition: "clean"}), [cases[2]]);
  assert.deepEqual(pick({query: " CAFÉ 🙂 "}), [cases[1]]);
  assert.deepEqual(pick({query: "</script>"}), [cases[2]]);
  assert.equal(pick({state: '<img onerror="alert(1)">', condition: "__proto__"}).length, 3);
  assert.equal(pick({query: "not present"}).length, 0);
});

// Deliberately narrow DOM doubles: report data has no HTML parsing or selector sink.
function environment(raw = load("scripted-incomplete")) {
  const nodes = new Map();
  const node = id => {
    const events = {};
    return {id, hidden: true, value: "all", dataset: {}, textContent: "", events,
      addEventListener(type, fn) { events[type] = fn; },
      set innerHTML(_) { throw new Error("HTML sink is forbidden"); },
    };
  };
  for (const id of ["action-status", "export", "workflow-data", "search", "state", "condition", "reset", "filters", "filter-note", "filter-status", "empty", "theme"]) nodes.set(id, node(id));
  nodes.get("workflow-data").textContent = raw;
  nodes.get("search").value = "";
  const cases = [node("first"), node("second"), node("third")];
  cases[0].dataset = {state: "missing", unknown: "false", condition: "attack", search: "delegated"};
  cases[1].dataset = {state: "incomplete", unknown: "true", condition: "attack", search: "memory"};
  cases[2].dataset = {state: "complete", unknown: "true", condition: "attack", search: "purpose"};
  const objects = [], revoked = [], timers = [], anchors = [];
  const doc = {documentElement: {dataset: {theme: "dark"}}, getElementById: id => nodes.get(id),
    querySelectorAll(selector) { assert.equal(selector, "[data-case]"); return cases; },
    body: {appendChild(anchor) { anchor.appended = true; }},
    createElement(tag) {
      assert.equal(tag, "a");
      const anchor = {click() { this.clicked = true; }, remove() { this.removed = true; }};
      anchors.push(anchor); return anchor;
    },
  };
  const browser = {Blob, URL: {createObjectURL(blob) { objects.push(blob); return "blob:local"; }, revokeObjectURL(url) { revoked.push(url); }},
    setTimeout(fn, delay) { assert.equal(delay, 1000); timers.push(fn); },
  };
  return {doc, browser, nodes, cases, objects, revoked, timers, anchors};
}

test("DOM controls filter locally, report counts stay untouched, and reset restores all", () => {
  const env = environment(), {nodes, cases} = env;
  const original = nodes.get("workflow-data").textContent;
  core.boot(env.doc, env.browser);
  assert.equal(nodes.get("filters").hidden, false);
  nodes.get("state").value = "missing";
  nodes.get("state").events.input();
  assert.deepEqual(cases.map(c => c.hidden), [false, true, true]);
  assert.match(nodes.get("filter-status").textContent, /Showing 1 of 3/);
  nodes.get("search").value = "not present";
  nodes.get("search").events.input();
  assert.equal(nodes.get("empty").hidden, false);
  nodes.get("reset").events.click();
  assert.deepEqual(cases.map(c => c.hidden), [false, false, false]);
  assert.equal(nodes.get("empty").hidden, true);
  assert.equal(nodes.get("workflow-data").textContent, original);
  nodes.get("theme").events.click();
  assert.equal(env.doc.documentElement.dataset.theme, "light");
});

test("download exports full data even under filters, uses fixed local URL and cleans up", async () => {
  const env = environment();
  core.boot(env.doc, env.browser);
  env.nodes.get("state").value = "missing";
  env.nodes.get("state").events.input();
  env.nodes.get("export").events.click();
  assert.equal(env.objects[0].type, "application/json;charset=utf-8");
  assert.deepEqual(JSON.parse(await env.objects[0].text()), JSON.parse(load("scripted-incomplete")));
  assert.deepEqual(env.anchors[0], {href: "blob:local", download: "workflow-run-report.json", appended: true, clicked: true, removed: true, click: env.anchors[0].click, remove: env.anchors[0].remove});
  assert.equal(env.timers.length, 1);
  env.timers[0]();
  assert.deepEqual(env.revoked, ["blob:local"]);
});

test("unreadable data and unavailable download remain explicit", () => {
  const invalid = environment("{");
  core.boot(invalid.doc, invalid.browser);
  assert.match(invalid.nodes.get("action-status").textContent, /unreadable/);
  assert.equal(invalid.nodes.get("export").hidden, true);
  assert.equal(invalid.nodes.get("filters").hidden, true);
  const failed = environment();
  core.boot(failed.doc, failed.browser);
  failed.browser.URL.createObjectURL = () => { throw new Error("unsupported"); };
  failed.nodes.get("export").events.click();
  assert.match(failed.nodes.get("action-status").textContent, /download unavailable/);
  assert.equal(failed.anchors.length, 0);
});
