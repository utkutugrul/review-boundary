const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const core = require("../../src/review_boundary/web/adjudication.js");

const h = c => c.repeat(64);
const context = {
  schema_version: 1,
  source_report_sha256: h("a"),
  template_reason: "Awaiting evaluator adjudication.",
  run: { rows: 2, reviewers: ["m"], epochs: 1 },
  cases: {
    [h("b")]: { case_id: "case:one", issues: [
      { issue_id: "present-issue", category: "authorization", expectation: "present", ranges: ["a.py:1-2"] },
      { issue_id: "absent-issue", category: "authorization", expectation: "absent", ranges: ["a.py:1-2"] },
    ] },
  },
  findings: [{ case_sha256: h("b"), finding_sha256: h("c"), category: "authorization", summary: "s", evidence: [], slots: [] }],
  reviews: [{ case_sha256: h("b"), review_sha256: h("d"), verdict: "request_changes", finding_sha256s: [h("c")], slots: [] }],
};
const finding = (extra = {}) => ({ case_sha256: h("b"), finding_sha256: h("c"), decision: "unknown", issue_id: null, reason: "r", ...extra });
const review = (extra = {}) => ({ case_sha256: h("b"), review_sha256: h("d"), decision: "unknown", reason: "r", ...extra });
const artifact = (extra = {}) => ({ schema_version: 1, adjudication_kind: "repository", source_report_sha256: h("a"), finding_decisions: [finding()], review_decisions: [review()], ...extra });
const rejects = (value, pattern) => assert.throws(() => core.validateArtifact(value, context), pattern);

test("starting state is all unknown and exports the exact strict template", () => {
  const state = core.startState(context);
  assert.deepEqual([...state.findings, ...state.reviews].map(item => item.decision), ["unknown", "unknown"]);
  const exported = core.artifactFromState(context, state);
  assert.deepEqual(Object.keys(exported), ["schema_version", "adjudication_kind", "source_report_sha256", "finding_decisions", "review_decisions"]);
  assert.deepEqual(Object.keys(exported.finding_decisions[0]), ["case_sha256", "finding_sha256", "decision", "issue_id", "reason"]);
  assert.deepEqual(Object.keys(exported.review_decisions[0]), ["case_sha256", "review_sha256", "decision", "reason"]);
  assert.deepEqual(core.validateArtifact(exported, context), exported);
  assert.ok(core.serializeArtifact(exported).endsWith("}\n"));
});

test("changing a decision never writes a judgment or keeps a placeholder reason", () => {
  let label = core.startState(context).findings[0];
  label = core.setDecision(context, label, "supported");
  assert.deepEqual(label, { decision: "supported", issue_id: null, reason: "" });
  assert.throws(() => core.validateArtifact(core.artifactFromState(context, { findings: [label], reviews: core.startState(context).reviews }), context), /reason/);
  label = { decision: "supported", issue_id: "present-issue", reason: "Checked line 2." };
  assert.deepEqual(core.setDecision(context, label, "unknown"), { decision: "unknown", issue_id: null, reason: "Checked line 2." });
  assert.equal(core.setDecision(context, { decision: "rejected", issue_id: null, reason: "" }, "unknown").reason, context.template_reason);
  assert.equal(core.setDecision(context, label, "bogus"), label);
});

test("import fails closed on stale, foreign, duplicate and inconsistent decisions", () => {
  assert.doesNotThrow(() => core.validateArtifact(artifact(), context));
  assert.doesNotThrow(() => core.validateArtifact({ ...artifact(), finding_decisions: [], review_decisions: [] }, context));
  rejects(artifact({ source_report_sha256: h("e") }), /different or modified/);
  rejects(artifact({ finding_decisions: [finding({ finding_sha256: h("e") })] }), /absent from the report/);
  rejects(artifact({ finding_decisions: [finding({ case_sha256: h("e") })] }), /unknown case/);
  rejects(artifact({ review_decisions: [review({ review_sha256: h("e") })] }), /absent from the report/);
  rejects(artifact({ finding_decisions: [finding(), finding()] }), /Duplicate/);
  rejects(artifact({ finding_decisions: [finding(), finding({ decision: "rejected" })] }), /Duplicate/);
  rejects(artifact({ finding_decisions: [finding({ issue_id: "present-issue" })] }), /Unknown finding decisions/);
  rejects(artifact({ finding_decisions: [finding({ decision: "rejected", issue_id: "missing" })] }), /unknown issue/);
  rejects(artifact({ finding_decisions: [finding({ decision: "supported", issue_id: "absent-issue" })] }), /absent issue/);
  assert.doesNotThrow(() => core.validateArtifact(artifact({ finding_decisions: [finding({ decision: "rejected", issue_id: "absent-issue" })] }), context));
  rejects(artifact({ review_decisions: [{ ...review(), issue_id: null }] }), /unexpected field/);
  rejects({ ...artifact(), extra: 1 }, /unexpected field/);
  rejects(artifact({ schema_version: 2 }), /schema_version/);
  rejects(artifact({ schema_version: true }), /schema_version/);
  rejects(artifact({ schema_version: null }), /schema_version/);
  rejects(artifact({ schema_version: "1" }), /schema_version/);
  rejects(artifact({ adjudication_kind: "boundary" }), /adjudication_kind/);
  rejects(artifact({ adjudication_kind: true }), /adjudication_kind/);
  rejects(artifact({ adjudication_kind: null }), /adjudication_kind/);
  rejects(artifact({ adjudication_kind: 1.0 }), /adjudication_kind/);
  const missingSchema = artifact(); delete missingSchema.schema_version;
  const missingKind = artifact(); delete missingKind.adjudication_kind;
  rejects(missingSchema, /schema_version.*required/);
  rejects(missingKind, /adjudication_kind.*required/);
  rejects(artifact({ finding_decisions: [finding({ decision: "Supported" })] }), /decision/);
  rejects(artifact({ finding_decisions: [finding({ reason: "" })] }), /reason/);
  rejects(artifact({ finding_decisions: [finding({ reason: "x".repeat(2001) })] }), /reason/);
  assert.doesNotThrow(() => core.validateArtifact(artifact({ finding_decisions: [finding({ reason: "😀".repeat(2000) })] }), context));
  rejects(artifact({ finding_decisions: [finding({ reason: "\ud800" })] }), /Unicode/);
  rejects(artifact({ finding_decisions: [finding({ case_sha256: h("B") })] }), /SHA-256/);
  rejects(artifact({ finding_decisions: {} }), /list/);
});

test("the strict parser rejects what JSON.parse silently normalizes", () => {
  assert.deepEqual({ ...core.parseStrictJson('{"a": [1, true, null, "x\\u00e9"]}') }, { a: [1, true, null, "xé"] });
  for (const text of ['{"a":1,"a":2}', '{"a":1.0}', '{"a":1e0}', '{"a":01}', '{"a":NaN}', '{"a":1,}', '{"a":1} x', '[1]', '{"a":"\\ud800"}', '{"a":"\u0001"}', '{"a":"\\x"}', '{"a":', '', '{"__proto__":1,"__proto__":2}']) {
    assert.throws(() => core.parseStrictJson(text), text === "[1]" ? /object/ : /Invalid JSON/, text);
  }
  const deep = n => "[".repeat(n) + "]".repeat(n);
  assert.throws(() => core.parseStrictJson(`{"a":${deep(70)}}`), /nesting/);
  assert.equal(Object.keys(core.parseStrictJson('{"__proto__":1}'))[0], "__proto__");
});

test("a partially labeled import leaves every unlisted item unknown", () => {
  const imported = core.validateArtifact({ ...artifact(), finding_decisions: [finding({ decision: "supported", issue_id: "present-issue", reason: "Verified." })], review_decisions: [] }, context);
  const state = core.stateFromArtifact(context, imported);
  assert.equal(state.findings[0].decision, "supported");
  assert.deepEqual(state.reviews[0], { decision: "unknown", issue_id: null, reason: context.template_reason });
});

test("the page script is offline, never auto-judges and never builds HTML from data", () => {
  const source = readFileSync(resolve(__dirname, "../../src/review_boundary/web/adjudication.js"), "utf8");
  for (const forbidden of [/innerHTML/, /outerHTML/, /insertAdjacentHTML/, /document\.write/, /\beval\(/, /new Function/, /fetch\(/, /XMLHttpRequest/, /WebSocket/, /sendBeacon/, /https?:\/\//, /localStorage/, /import\(/]) {
    assert.doesNotMatch(source, forbidden);
  }
});
