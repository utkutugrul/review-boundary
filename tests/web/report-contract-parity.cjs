"use strict";

const { readFileSync } = require("node:fs");
const contracts = require("../../src/review_boundary/web/report-contracts.js");

try {
  const document = contracts.parseReportText(readFileSync(0, "utf8"));
  process.stdout.write(JSON.stringify({ valid: true, contract: contracts.detectContract(document) }));
} catch {
  process.stdout.write(JSON.stringify({ valid: false }));
}
