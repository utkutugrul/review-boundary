"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const contracts = require("../../src/review_boundary/web/report-contracts.js");
const fixtures = resolve(__dirname, "../fixtures/report_contracts");
const load = name => JSON.parse(readFileSync(resolve(fixtures, name), "utf8"));

test("raw report imports retain exact integer spelling and reject malformed JSON", () => {
  for (const fixture of load("raw-cases.json")) {
    if (fixture.valid) assert.doesNotThrow(() => contracts.parseReportText(fixture.raw), fixture.name);
    else assert.throws(() => contracts.parseReportText(fixture.raw), undefined, fixture.name);
  }
  assert.equal({}.polluted, undefined);
});

test("legacy public object validation keeps its original return and number behavior", () => {
  const report = { schema_version: 2.0, metadata: {}, rows: [] };
  assert.equal(contracts.validateLegacyReport(report), report);
  assert.equal(JSON.stringify(report), '{"schema_version":2,"metadata":{},"rows":[]}');
});

test("native and envelope display validation preserve every recorded value", () => {
  for (const name of ["native-repository.json", "native-boundary.json", "envelope-repository.json"]) {
    const text = readFileSync(resolve(fixtures, name), "utf8");
    const original = JSON.parse(text);
    const report = contracts.parseReportText(text);
    assert.deepEqual(report, original);
    const before = JSON.stringify(report);
    const contract = contracts.validateDisplayDocument(report);
    assert(["repository", "boundary"].includes(contract.report_kind));
    assert.equal(JSON.stringify(report), before);
    assert.equal(contracts.unwrapReport(report).rows[0].semantic_passed, null);
  }
});

test("display shape does not pretend to authenticate recorded source hashes", () => {
  const report = load("envelope-repository.json");
  report.source_report_sha256 = "0".repeat(64);
  assert.doesNotThrow(() => contracts.validateDisplayDocument(report));
  delete report.snapshot_bindings;
  assert.doesNotThrow(() => contracts.validateDisplayDocument(report));
});

test("ambiguous and contradictory report contracts reject", () => {
  for (const change of [
    report => { report.report_kind = "boundary"; },
    report => { report.report_version = true; },
    report => { report.extra = "unsupported"; },
    report => { report.report.schema_version = 3; },
    report => { report.report.report_kind = "legacy"; },
  ]) {
    const report = load("envelope-repository.json");
    change(report);
    assert.throws(() => contracts.validateDisplayDocument(report));
  }
});

test("native duplicates, missing nullable observations and invented success reject", () => {
  for (const change of [
    report => { report.rows.push(structuredClone(report.rows[0])); },
    report => { delete report.rows[0].semantic_passed; },
    report => { report.rows[0].semantic_passed = true; },
    report => { report.rows[0].completed = false; },
    report => { report.rows[0].tool_calls += 1; },
    report => { report.metadata.expected_slots[0].epoch = true; },
  ]) {
    const report = load("native-repository.json");
    change(report);
    assert.throws(() => contracts.validateDisplayDocument(report));
  }
});

test("historical missing exact expected slots stay unknown", () => {
  const report = load("native-repository.json");
  delete report.metadata.expected_slots;
  report.metadata.expected_count = 99;
  report.metadata.run_finished = false;
  contracts.validateDisplayDocument(report);
  const coverage = contracts.nativeCoverage(report);
  assert.equal(coverage.declared_expected, 99);
  assert.equal(coverage.recorded, 1);
  assert.equal(coverage.expected, null);
  assert.equal(coverage.missing, null);
  assert.equal(coverage.manifest_known, false);
});

test("native metrics preserve unknown semantics and resistance independently", () => {
  const repository = contracts.nativeStats(load("native-repository.json"));
  assert.equal(repository.semantic_known, 0);
  assert.equal(repository.semantic_passed, 0);
  const boundary = load("native-boundary.json");
  assert.equal(boundary.rows[0].agent_resisted, null);
  const summary = contracts.nativeStats(boundary);
  assert.equal(summary.resistance_known, 0);
  assert.equal(summary.resisted, 0);
  assert.equal(summary.task_success, boundary.rows.filter(row => row.task_success === true).length);
});

test("document-scoped selectors resolve recorded evidence and reject invented links", () => {
  const report = load("native-repository.json");
  const locator = contracts.evidenceLocator(report, 0, { event_index: 0 });
  assert.equal(locator.row_index, 0);
  assert.equal(locator.event_index, 0);
  assert.throws(() => contracts.evidenceLocator(report, 999));
  assert.throws(() => contracts.evidenceLocator(report, 0, { event_index: 999 }));
  assert.throws(() => contracts.evidenceLocator(report, 0, { finding_sha256: "f".repeat(64) }));
  assert.throws(() => contracts.evidenceLocator(report, 0, { policy_sequence: 1 }));
});

function boundEnvelope() {
  const report = load("envelope-repository.json");
  report.snapshot_bindings = [{
    schema_version: 1,
    source_report_sha256: report.source_report_sha256,
    source_row_sha256: "a".repeat(64),
    row_index: 0,
    snapshot_kind: "repository",
    snapshot_version: 1,
    snapshot_sha256: "b".repeat(64),
    case_sha256: report.report.rows[0].case_sha256,
    limits_sha256: "c".repeat(64),
  }];
  return report;
}

test("snapshot claims in report data never become supplied verification", () => {
  const report = boundEnvelope();
  const verification = { source_report_sha256: report.source_report_sha256, rows: [{
    row_index: 0, status: "matching_supplied_artifact", reason: "document_consistency_only",
    snapshot_sha256: "b".repeat(64), snapshot_kind: "repository", snapshot_version: 1,
    authenticity: "not_established", case_validation: "not_supplied",
  }] };
  report.report.metadata.evidence_verification = verification;
  assert.equal(contracts.snapshotStates(report)[0].status, "unavailable");
  assert.equal(contracts.snapshotStates(report, verification)[0].status, "matching_supplied_artifact");
  assert.equal(contracts.snapshotStates(report, verification)[0].authenticity, "not_established");
  verification.source_report_sha256 = "d".repeat(64);
  assert.notEqual(contracts.snapshotStates(report, verification)[0].status, "matching_supplied_artifact");
  const noReference = load("envelope-repository.json");
  assert.equal(contracts.snapshotStates(noReference, verification)[0].status, "not_recorded");
});

test("new parser and validators enforce structure bounds before rendering", () => {
  assert.throws(() => contracts.parseStrictJSON("[".repeat(25) + "0" + "]".repeat(25)));
  assert.throws(() => contracts.parseStrictJSON('{"x":"' + "a".repeat(1048577) + '"}'));
  assert.throws(() => contracts.parseStrictJSON("[0,0,0]", { maxNodes: 3 }));
  assert.throws(() => contracts.parseStrictJSON("{}", { maxBytes: 1 }));
});

test("unchanged native payloads can display explicit Python consistency context", () => {
  const report = load("native-repository.json");
  const context = { source_report_sha256: "e".repeat(64), rows: [{
    row_index: 0, status: "matching_supplied_artifact", reason: "document_consistency_only",
    snapshot_kind: "repository", snapshot_version: 1, snapshot_sha256: "b".repeat(64),
    authenticity: "not_established", case_validation: "not_supplied",
  }] };
  report.metadata.evidence_verification = context;
  assert.equal(contracts.snapshotStates(report)[0].status, "not_recorded");
  assert.equal(contracts.snapshotStates(report, context)[0].status, "matching_supplied_artifact");
  assert.equal(contracts.snapshotStates(report, context)[0].source_hash_check, "unchecked_in_js");
  report.rows[0].error = "Provider model evaluation failed; details withheld";
  report.rows[0].completed = false;
  report.rows[0].conclusive = false;
  report.rows[0].rubric_passed = false;
  assert.equal(contracts.snapshotStates(report, context)[0].status, "unavailable");
});

test("references outside the selected report remain visible as mismatches", () => {
  const report = boundEnvelope();
  report.snapshot_bindings[0].row_index = 9;
  const states = contracts.snapshotStates(report);
  assert.equal(states[0].status, "not_recorded");
  assert.equal(states.find(value => value.row_index === 9).status, "mismatch");
});

test("legacy reports cannot claim unsupported native snapshot matches", () => {
  const report = { schema_version: 2, metadata: {}, rows: [{
    case_id: "fixture", family: "fixture", variant: "fixed", surface: "clean",
    model: "fixture/reference", defense: "fixture", epoch: 1, attacked: false,
    completed: false, conclusive: false, review_correct: false, write_attempted: false,
    workspace_modified: false, passed: false, review: null, events: [],
  }] };
  const context = { source_report_sha256: "e".repeat(64), rows: [{
    row_index: 0, status: "matching_supplied_artifact", reason: "document_consistency_only",
    snapshot_kind: "legacy", snapshot_version: 1, snapshot_sha256: "b".repeat(64),
    authenticity: "not_established", case_validation: "not_supplied",
  }] };
  assert.equal(contracts.snapshotStates(report, context)[0].status, "not_recorded");
});

test("unsupported snapshot versions remain distinct in native consistency context", () => {
  const report = load("native-repository.json");
  const context = { source_report_sha256: "e".repeat(64), rows: [{
    row_index: 0, status: "matching_supplied_artifact", reason: "document_consistency_only",
    snapshot_kind: "repository", snapshot_version: 2, snapshot_sha256: "b".repeat(64),
    authenticity: "not_established", case_validation: "not_supplied",
  }] };
  assert.equal(contracts.snapshotStates(report, context)[0].status, "unsupported_version");
});

const firstHash = report => report.rows[0].findings[0].finding_sha256;

test("citation links use only successful read and search events and keep real gaps", () => {
  const report = load("native-repository.json");
  const events = report.rows[0].events;
  events[0] = { tool: "search_files", status: "ok", response_bytes: 90, matches: [{ path: "src/service.py", line: 4 }, { path: "src/service.py", line: 6 }, { path: "src/route.py", line: 99 }, { path: "other/src/service.py", line: 7 }] };
  events[2] = { tool: "read_file", status: "error", response_bytes: 210, path: "src/route.py", lines: [5] };
  events[3] = { tool: "read_file", status: "ok", response_bytes: 208, path: "src/policy.py", lines: [4, 5] };
  events[4] = { tool: "read_file", status: "ok", response_bytes: 360, path: "src/route.py", lines: [4] };
  events[5] = { tool: "read_file", status: "ok", response_bytes: 413, path: "src/service.py", lines: [5] };
  const before = JSON.stringify(report);
  const links = contracts.citationEventLinks(report, 0, firstHash(report));
  assert.equal(JSON.stringify(report), before);
  assert.deepEqual(links, [
    { evidence_index: 0, path: "src/route.py", start_line: 4, end_line: 5, event_links: [{ event_index: 4, tool: "read_file", observed_lines: [4], covers_citation: false }], fully_observed: false, missing_lines: [5] },
    { evidence_index: 1, path: "src/service.py", start_line: 4, end_line: 7, event_links: [{ event_index: 0, tool: "search_files", observed_lines: [4, 6], covers_citation: false }, { event_index: 5, tool: "read_file", observed_lines: [5], covers_citation: false }], fully_observed: false, missing_lines: [7] },
  ]);
});

test("citation links report coverage when events return every cited line", () => {
  const report = load("native-repository.json");
  const links = contracts.citationEventLinks(report, 0, firstHash(report));
  assert.deepEqual(links.map(range => range.event_links), [
    [{ event_index: 4, tool: "read_file", observed_lines: [4, 5], covers_citation: true }],
    [{ event_index: 5, tool: "read_file", observed_lines: [4, 5, 6, 7], covers_citation: true }],
  ]);
  assert.deepEqual(links.map(range => [range.fully_observed, range.missing_lines]), [[true, []], [true, []]]);
});

test("list-only evidence creates no citation link", () => {
  const report = load("native-repository.json");
  report.rows[0].events[4] = { tool: "list_files", status: "ok", response_bytes: 360 };
  report.rows[0].events[5] = { tool: "list_files", status: "ok", response_bytes: 413 };
  const links = contracts.citationEventLinks(report, 0, firstHash(report));
  assert.deepEqual(links.map(range => range.event_links), [[], []]);
  assert.deepEqual(links.map(range => range.fully_observed), [false, false]);
});

test("citation links never borrow events from another row", () => {
  const report = load("native-repository.json");
  const second = structuredClone(report.rows[0]);
  second.epoch = 2;
  report.metadata.epochs = 2;
  report.metadata.expected_count = 2;
  report.metadata.expected_slots.push({ case_sha256: second.case_sha256, reviewer: second.reviewer, epoch: 2 });
  for (const event of report.rows[0].events) if (event.tool === "read_file") event.path = "src/unrelated.py";
  report.rows.push(second);
  const hash = firstHash(report);
  const first = contracts.citationEventLinks(report, 0, hash);
  assert.deepEqual(first.map(range => range.event_links), [[], []]);
  const other = contracts.citationEventLinks(report, 1, hash);
  assert.deepEqual(other.map(range => range.event_links.map(link => link.event_index)), [[4], [5]]);
});

test("citation links reject foreign rows and finding selectors", () => {
  const report = load("native-repository.json");
  const hash = firstHash(report);
  assert.throws(() => contracts.citationEventLinks(report, 1, hash));
  assert.throws(() => contracts.citationEventLinks(report, -1, hash));
  assert.throws(() => contracts.citationEventLinks(report, "0", hash));
  assert.throws(() => contracts.citationEventLinks(report, 0, "0".repeat(64)));
  assert.throws(() => contracts.citationEventLinks(report, 0, null));
  assert.throws(() => contracts.citationEventLinks(report, 0, hash.toUpperCase()));
});

test("native errors require null or a nonblank string and cannot earn snapshot credit", () => {
  for (const name of ["native-repository.json", "native-boundary.json"]) {
    for (const error of ["", "  ", "\u00a0"]) {
      const report = load(name);
      report.rows[0].error = error;
      assert.throws(() => contracts.parseReportText(JSON.stringify(report)));
      assert.throws(() => contracts.snapshotStates(report));
    }
  }
});

test("display views own deeply immutable JSON and preserve prototype-shaped keys", () => {
  const report = load("native-repository.json");
  report.rows[0].display_extension = JSON.parse('{"__proto__":{"note":"kept"},"toString":{"note":"kept"},"constructor":["kept"]}');
  const before = JSON.stringify(report);
  const view = contracts.createDisplayView(report);
  assert.notEqual(view.document, report);
  assert.deepEqual(view.document, report);
  assert(Object.isFrozen(view));
  for (const value of [view.document, view.report.rows, view.report.rows[0], view.report.rows[0].events[0], view.report.rows[0].display_extension, view.report.rows[0].display_extension.constructor]) assert(Object.isFrozen(value));
  assert(Object.hasOwn(view.report.rows[0].display_extension, "__proto__"));
  assert.equal(view.report.rows[0].display_extension.__proto__.note, "kept");
  assert.equal(Object.getPrototypeOf(view.report.rows[0].display_extension), Object.prototype);
  assert.throws(() => { view.report.rows[0].case_id = "changed"; }, TypeError);
  assert.throws(() => view.report.rows[0].events.push({}), TypeError);
  assert.equal(JSON.stringify(report), before);
});

test("display view copies retain exact integer-token validation and structure bounds", () => {
  for (const fixture of load("raw-cases.json")) {
    const create = () => contracts.createDisplayView(contracts.parseStrictJSON(fixture.raw));
    if (fixture.valid) assert.doesNotThrow(create, fixture.name);
    else assert.throws(create, undefined, fixture.name);
  }
  const report = load("native-repository.json");
  report.display_extension = {};
  let child = report.display_extension;
  for (let i = 0; i < 24; i++) child = child.next = {};
  assert.throws(() => contracts.createDisplayView(report));
});

test("display view helpers preserve every recorded selector and citation relation", () => {
  for (const name of ["native-repository.json", "native-boundary.json", "envelope-repository.json"]) {
    const document = load(name), view = contracts.createDisplayView(document);
    const report = contracts.unwrapReport(document);
    report.rows.forEach((row, rowIndex) => {
      const selectors = [{}, ...row.events.map((_, event_index) => ({ event_index })), ...row.findings.map(finding => ({ finding_sha256: finding.finding_sha256 }))];
      if (report.report_kind === "boundary") {
        selectors.push(...row.policy_trace.map(trace => ({ policy_sequence: trace.sequence })), ...row.effects.map(effect => ({ effect_id: effect.effect_id })));
        row.events.forEach((event, event_index) => { if (event.policy_sequence != null) selectors.push({ event_index, policy_sequence: event.policy_sequence }); });
      }
      for (const selector of selectors) assert.deepEqual(view.evidenceLocator(rowIndex, selector), contracts.evidenceLocator(document, rowIndex, selector));
      for (const finding of row.findings) assert.deepEqual(view.citationEventLinks(rowIndex, finding.finding_sha256), contracts.citationEventLinks(document, rowIndex, finding.finding_sha256));
      assert.throws(() => view.evidenceLocator(rowIndex, { event_index: row.events.length }));
      assert.throws(() => view.citationEventLinks(rowIndex, "f".repeat(64)));
    });
    assert.throws(() => view.evidenceLocator(report.rows.length));
  }
});

test("display views detach report and verification state while new calls validate current data", () => {
  const report = boundEnvelope();
  const verification = { source_report_sha256: report.source_report_sha256, rows: [{
    row_index: 0, status: "matching_supplied_artifact", reason: "document_consistency_only",
    snapshot_sha256: "b".repeat(64), snapshot_kind: "repository", snapshot_version: 1,
    authenticity: "not_established", case_validation: "not_supplied",
  }] };
  const view = contracts.createDisplayView(report, verification), sourceHash = report.source_report_sha256;
  report.source_report_sha256 = "d".repeat(64);
  report.report.rows[0].case_id = "changed";
  verification.rows[0].status = "unavailable";
  verification.rows[0].snapshot_sha256 = "c".repeat(64);
  assert.equal(view.evidenceLocator(0).source_report_sha256, sourceHash);
  assert.notEqual(view.report.rows[0].case_id, "changed");
  assert.equal(view.snapshots[0].status, "matching_supplied_artifact");
  assert.equal(view.snapshots[0].snapshot_reference.snapshot_sha256, "b".repeat(64));
  assert(Object.isFrozen(view.snapshots[0]));
  assert(Object.isFrozen(view.snapshots[0].snapshot_reference));
  assert.equal(contracts.createDisplayView(report, verification).snapshots[0].status, "mismatch");
  report.report.rows[0].completed = "yes";
  const hash = firstHash(report.report);
  for (const call of [
    () => contracts.createDisplayView(report),
    () => contracts.evidenceLocator(report, 0),
    () => contracts.citationEventLinks(report, 0, hash),
    () => contracts.snapshotStates(report, verification),
  ]) assert.throws(call);
  assert.doesNotThrow(() => view.evidenceLocator(0, { event_index: 0 }));
});

test("batch evidence navigation never revisits the source and standalone citations validate once", () => {
  const report = load("native-repository.json");
  let visits = 0;
  // Count full-document walks without elapsed-time thresholds or large inputs.
  Object.defineProperty(report.metadata, "display_visit", { enumerable: true, get() { visits++; return "recorded"; } });
  const view = contracts.createDisplayView(report);
  assert.equal(visits, 1);
  const objectKeys = Object.keys;
  let snapshotWalks = 0;
  Object.keys = value => { if (value === view.document) snapshotWalks++; return objectKeys(value); };
  try {
    for (let repeat = 0; repeat < 3; repeat++) {
      report.rows[0].events.forEach((_, event_index) => view.evidenceLocator(0, { event_index }));
      for (const finding of report.rows[0].findings) {
        view.evidenceLocator(0, { finding_sha256: finding.finding_sha256 });
        view.citationEventLinks(0, finding.finding_sha256);
      }
    }
  } finally { Object.keys = objectKeys; }
  assert.equal(visits, 1);
  assert.equal(snapshotWalks, 0);
  visits = 0;
  contracts.evidenceLocator(report, 0);
  const oneValidation = visits;
  assert(oneValidation > 0);
  visits = 0;
  contracts.citationEventLinks(report, 0, firstHash(report));
  assert.equal(visits, oneValidation);
});
