const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const core = require("../../src/review_boundary/web/dashboard.js");
const root = resolve(__dirname, "../..");
const load = name => JSON.parse(readFileSync(resolve(root, "examples", name, "report.json")));

test("dashboard denominators match the three published scorer outputs", () => {
  for (const name of ["calibration-v2", "pilot-v2-typescript", "pilot-v2-rust-heldout"]) {
    const report = core.validateReport(load(name));
    const result = core.stats(report.rows);
    assert.equal(result.total, report.summary.total);
    assert.equal(result.correct, report.summary.correct_reviews);
    assert.equal(result.writes, report.summary.write_attempts);
    assert.equal(result.eligible, report.summary.paired_eligible);
    assert.equal(result.degraded, report.summary.paired_degradations);
    assert.equal(result.inconclusive, report.summary.total - report.summary.conclusive);
  }
});

test("controls cannot be borrowed from another trial, reviewer, policy or run", () => {
  const rows = load("calibration-v2").rows;
  const attack = rows.find(r => r.attacked && r.conclusive && !r.passed && r.surface === "pr_body");
  const control = core.controlIndex(rows).get(core.pairKey(attack));
  assert.equal(core.stats([control, attack]).degraded, 1);
  for (const key of ["trial_group", "model", "defense", "family", "variant", "epoch"]) {
    const changed = { ...control, [key]: key === "epoch" ? control.epoch + 1 : control[key] + "-different" };
    assert.equal(core.stats([changed, attack]).eligible, 0, key);
  }
  assert.equal(core.stats([control, { ...attack, conclusive: false }]).eligible, 0);
  assert.equal(core.stats([control, { ...attack, attacked: false }]).eligible, 0);
});

test("duplicate controls are ambiguous, and incomplete reviews are never passes", () => {
  const rows = load("calibration-v2").rows;
  const attack = rows.find(r => r.attacked && r.conclusive && !r.passed && r.surface === "pr_body");
  const control = core.controlIndex(rows).get(core.pairKey(attack));
  assert.equal(core.stats([control, structuredClone(control), attack]).eligible, 0);
  assert.equal(core.outcome({ passed: true, conclusive: false }), "inconclusive");
});

test("import rejects invalid identity, booleans, findings, tools and unsafe numbers", () => {
  const report = load("pilot-v2-typescript");
  const mutations = [
    r => { r.schema_version = 1; },
    r => { r.rows[0].epoch = 0; },
    r => { r.rows[0].attacked = "false"; },
    r => { r.rows[0].passed = 1; },
    r => { r.rows[0].family = "  "; },
    r => { delete r.rows[0].review; },
    r => { r.rows[0].events[0].content_truncated = "no"; },
    r => { r.rows[0].payload_exposed = null; },
    r => { r.summary = []; },
    r => { r.coverage = []; },
    r => { r.metadata.run_kind = {}; },
    r => { r.metadata.usage.input_tokens = -1; },
    r => { r.rows[0].events = [{ tool: 123 }]; },
    r => { r.rows[0].review.findings = [{ category: "test", line: -1 }]; },
    r => { r.metadata.extra = Infinity; },
    r => { r.metadata.extra = Number.MAX_SAFE_INTEGER + 1; },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(report);
    mutate(changed);
    assert.throws(() => core.validateReport(changed));
  }
});

test("optional metrics stay unknown and report content is never altered", () => {
  const report = load("pilot-v2-typescript");
  delete report.rows[0].evidence_grounded;
  report.rows[0].citation_correct = null;
  report.rows[0].events[0].content = '</script><img src=x onerror="alert(1)">';
  const before = JSON.stringify(report);
  core.validateReport(report);
  assert.equal(JSON.stringify(report), before);
  assert.equal(report.rows[0].evidence_grounded, undefined);
  assert.equal(report.rows[0].citation_correct, null);
});

test("direct hash navigation drops filters not offered by the destination", () => {
  const rows = load("calibration-v2").rows;
  const cleanFilter = { surface: "clean", model: "all", status: "pass", search: "rust" };
  assert.equal(core.normalizeFilters(cleanFilter, rows, false).surface, "clean");
  const forPairs = core.normalizeFilters(cleanFilter, rows, true);
  assert.equal(forPairs.surface, "all");
  assert.equal(forPairs.status, "pass");
  assert.equal(forPairs.search, "rust");
  assert.equal(cleanFilter.surface, "clean");
  const invalid = core.normalizeFilters({ model: "unknown", surface: "unknown", status: "unknown" }, rows);
  assert.deepEqual(invalid, { model: "all", surface: "all", status: "all" });
});

test("ambiguous controls and saved-summary mismatches are explicitly diagnosed", () => {
  const report = load("calibration-v2");
  assert.deepEqual(core.diagnostics(report), []);
  const control = report.rows.find(r => r.surface === "clean" && r.passed);
  report.rows.push(structuredClone(control));
  const messages = core.diagnostics(report);
  assert(messages.some(m => m.includes("ambiguous")));
  assert(messages.some(m => m.includes("Recorded paired_eligible")));
  const attack = report.rows.find(r => r.attacked && core.pairKey(r) === core.pairKey(control));
  assert(core.pairReason(report.rows, attack).includes("ambiguous"));
});

test("ineligible pairs explain missing, failed, or inconclusive controls", () => {
  const report = load("calibration-v2");
  const attack = report.rows.find(r => r.attacked && r.conclusive && !r.passed && r.surface === "pr_body");
  const control = core.controlIndex(report.rows).get(core.pairKey(attack));
  assert.equal(core.pairReason([control, attack], attack), "");
  assert(core.pairReason([attack], attack).includes("No matching"));
  assert(core.pairReason([{ ...control, passed: false }, attack], attack).includes("did not pass"));
  const incomplete = { ...attack, conclusive: false };
  assert(core.pairReason([control, incomplete], incomplete).includes("inconclusive"));
});
