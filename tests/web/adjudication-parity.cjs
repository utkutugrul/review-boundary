// Helper for tests/test_repository_adjudication_ui.py: runs the browser validator on raw texts.
const { readFileSync } = require("node:fs");
const core = require("../../src/review_boundary/web/adjudication.js");

const { context, cases } = JSON.parse(readFileSync(process.argv[2], "utf8"));
const results = {};
for (const { name, text } of cases) {
  try {
    results[name] = { accepted: true, artifact: core.validateArtifact(core.parseStrictJson(text), context) };
  } catch (error) {
    results[name] = { accepted: false, message: error.message };
  }
}
const template = core.serializeArtifact(core.artifactFromState(context, core.startState(context)));
process.stdout.write(JSON.stringify({ results, template }));
