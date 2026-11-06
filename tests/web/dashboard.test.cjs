const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const core = require("../../src/review_boundary/web/dashboard.js");
const root = resolve(__dirname, "../..");
const load = name => JSON.parse(readFileSync(resolve(root, "examples", name, "report.json")));

test("experiment records preserve missing fingerprints as unknown", () => {
  const fields = Object.fromEntries(core.experimentFields({}));
  assert.equal(fields["Harness source"], "Not recorded");
  assert.equal(fields["Declared reviewer source"], "Not recorded");
  assert.equal(fields["Recorded score consistency"], "unknown");
  const malformed = Object.fromEntries(core.experimentFields({provenance: "invalid", score_verification: {status: "trusted"}}));
  assert.equal(malformed["Instructions"], "Not recorded");
  assert.equal(malformed["Recorded score consistency"], "unknown");
});

test("experiment display selects bounded hashes and recorded check statuses", () => {
  const hash = "a".repeat(64);
  const fields = Object.fromEntries(core.experimentFields({provenance: {
    schema_version: 1, hash_algorithm: "sha256", prompts: {baseline: hash},
    tools: {protocol: "inspect", sha256: hash}, harness: {sha256: hash},
    reviewer_source: {sha256: null},
  }, score_verification: {status: "partial"}}));
  assert.equal(fields["Instructions / baseline"], hash);
  assert.equal(fields["Tool protocol"], "inspect");
  assert.equal(fields["Declared reviewer source"], "Not recorded or invalid");
  assert.equal(fields["Recorded score consistency"], "partial");
});

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

function failingPair() {
  const rows = load("calibration-v2").rows;
  const attack = rows.find(r => r.attacked && r.conclusive && !r.passed && r.surface === "pr_body");
  return [core.controlIndex(rows).get(core.pairKey(attack)), attack];
}

test("duplicate attacked identities are excluded without losing raw rows or independent pairs", () => {
  const [control, attack] = failingPair();
  for (const results of [[false, false], [false, true], [true, false, true]]) {
    const independent = [control, attack].map(row => ({ ...row, trial_group: "independent" }));
    const rows = [control, ...results.map(passed => ({ ...attack, passed })), ...independent];
    const result = core.stats(rows);
    assert.equal(result.total, rows.length);
    assert.equal(result.eligible, 1);
    assert.equal(result.degraded, 1);
    assert(core.pairReason(rows, attack).includes("ambiguous"));
    assert.equal(core.pairEligible(attack, core.pairContext(rows)), false);
    const report = { rows, metadata: {} };
    assert(core.diagnostics(report).some(message => message.includes("sample identities") && message.includes("ambiguous")));
  }
});

test("changing descriptive fields cannot turn a duplicate identity into a unique attack", () => {
  const [control, attack] = failingPair();
  for (const field of ["family", "variant", "surface", "attacked"]) {
    const duplicate = { ...attack, [field]: field === "attacked" ? false : "different" };
    const rows = [control, attack, duplicate];
    assert.equal(core.stats(rows).eligible, 0, field);
    assert(core.pairReason(rows, attack).includes("ambiguous"), field);
  }
  const conflict = { ...control, surface: "readme", attacked: true };
  assert.equal(core.stats([control, conflict, attack]).eligible, 0);
});

test("same cases in different trial groups, reviewers, policies and epochs remain separate", () => {
  const first = failingPair();
  for (const field of ["trial_group", "model", "defense", "epoch"]) {
    const second = first.map(row => ({ ...row, [field]: field === "epoch" ? row.epoch + 1 : row[field] + "-other" }));
    assert.equal(core.stats([...first, ...second]).eligible, 2, field);
    assert.equal(core.stats([...first, ...second]).degraded, 2, field);
  }
});

test("coverage is derived from expected slots, including wholly missing groups", () => {
  const row = failingPair()[0];
  const metadata = {
    expected_samples: [{ case_id: row.case_id, epoch: row.epoch }, { case_id: "missing-case", epoch: row.epoch }],
    expected_groups: [{ model: row.model, defense: row.defense }, { model: "missing-model", defense: row.defense }],
  };
  const result = core.coverage([row, structuredClone(row)], metadata);
  assert.equal(result.expected, 4);
  assert.equal(result.recorded, 2);
  assert.equal(result.missing, 3);
  assert.equal(result.duplicates, 1);
  assert.equal(result.scope, "declared");
  assert.equal(result.expected_samples_known, true);
  assert.equal(result.expected_groups_known, true);
  const report = { rows: [row, structuredClone(row)], metadata, coverage: { missing: 0, duplicates: 0 } };
  const messages = core.diagnostics(report);
  assert(messages.some(message => message.includes("3 expected samples are missing")));
  assert(messages.some(message => message.includes("1 repeated sample slots")));
  assert(messages.some(message => message.includes("Recorded coverage.missing: 0")));
  assert.equal(report.coverage.missing, 0);
});

test("missing expected groups leave whole-run coverage unknown even when visible slots match", () => {
  const row = failingPair()[0];
  const metadata = { expected_samples: [{ case_id: row.case_id, epoch: row.epoch }] };
  const result = core.coverage([row], metadata);
  assert.equal(result.expected, null);
  assert.equal(result.missing, 0);
  assert.equal(result.scope, "observed");
  assert.equal(result.expected_groups_known, false);
  assert.equal(result.unexpected_groups, null);
  assert(core.diagnostics({ rows: [row], metadata }).some(message => message.includes("Whole-run coverage is unknown")));
});

test("missing or invalid expected samples leave missing coverage unknown but retain duplicates", () => {
  const row = failingPair()[0];
  for (const expected_samples of [undefined, null, "invalid", [{ case_id: row.case_id, epoch: true }], [{ case_id: "", epoch: 1 }], [{ case_id: row.case_id, epoch: 1 }, { case_id: row.case_id, epoch: 1 }]]) {
    const result = core.coverage([row, structuredClone(row)], { expected_samples });
    assert.equal(result.expected, null);
    assert.equal(result.missing, null);
    assert.equal(result.duplicates, 1);
    assert.equal(result.scope, "unknown");
    assert.equal(result.expected_samples_known, false);
  }
});

test("invalid expected group declarations cannot establish complete coverage", () => {
  const row = failingPair()[0];
  const expected_samples = [{ case_id: row.case_id, epoch: row.epoch }];
  for (const expected_groups of [undefined, null, "invalid", [{ model: row.model }], [{ model: row.model, defense: row.defense }, { model: row.model, defense: row.defense }]]) {
    const result = core.coverage([row], { expected_samples, expected_groups });
    assert.equal(result.expected, null);
    assert.equal(result.expected_groups_known, false);
    assert.equal(result.scope, "observed");
  }
});

test("undeclared observed groups remain visible without enlarging the expected denominator", () => {
  const row = { ...failingPair()[0], model: "extra" };
  const metadata = { expected_samples: [{ case_id: row.case_id, epoch: row.epoch }], expected_groups: [{ model: "declared", defense: row.defense }] };
  const result = core.coverage([row], metadata);
  assert.equal(result.expected, 1);
  assert.equal(result.missing, 1);
  assert.equal(result.unexpected, 1);
  assert.equal(result.unexpected_groups, 1);
  const extra = result.groups.find(group => group.model === "extra");
  assert.equal(extra.declared, false);
  assert.equal(extra.expected, 0);
  assert.equal(extra.present, 1);
  assert(core.diagnostics({ rows: [row], metadata }).some(message => message.includes("undeclared reviewer/policy groups")));
});

test("declared empty coverage and repeated manifest slots retain their precise meaning", () => {
  assert.equal(core.coverage([], { expected_samples: [], expected_groups: [] }).expected, 0);
  assert.equal(core.coverage([], {}).missing, null);
  const row = failingPair()[0];
  const second = { ...row, trial_group: "other" };
  const metadata = { expected_samples: [{ case_id: row.case_id, epoch: row.epoch }], expected_groups: [{ model: row.model, defense: row.defense }] };
  const result = core.coverage([row, second], metadata);
  assert.equal(result.recorded, 2);
  assert.equal(result.duplicates, 1);
  assert.equal(result.missing, 0);
  assert.equal(core.sampleCounts([row, second]).size, 2);
});

test("published coverage counts match freshly derived values without mutating saved reports", () => {
  for (const name of ["calibration-v2", "pilot-v2-typescript", "pilot-v2-rust-heldout"]) {
    const report = load(name), before = JSON.stringify(report);
    const result = core.coverage(report.rows, report.metadata);
    for (const field of ["expected", "recorded", "missing", "duplicates"]) assert.equal(result[field], report.coverage[field], field);
    assert.equal(result.unexpected, 0);
    assert.equal(result.unexpected_groups, 0);
    assert.equal(JSON.stringify(report), before);
  }
});
