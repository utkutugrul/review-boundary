/* ReviewBoundary report contract helpers for the browser and for Node tests.
 *
 * This file mirrors the SHAPE validation of the Python report contracts. It
 * never recomputes digests, never rescores, and never establishes authenticity.
 * Recorded hashes are displayed as recorded and are always labelled unchecked.
 */
(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module !== null && module.exports) module.exports = api;
  else root.ReviewBoundaryReportContracts = api;
})(globalThis, function () {
  "use strict";

  const ENVELOPE_VERSION = 3;
  const MAX_SAFE = Number.MAX_SAFE_INTEGER;
  const MAX_ROWS = 10000;
  const MAX_FILE_BYTES = 16 * 1024 * 1024;
  const MAX_STRING_BYTES = 1024 * 1024;
  const MAX_NODES = 200000;
  const MAX_DEPTH = 20;
  const PARSE_DEPTH = 22;
  const MAX_EVENTS = 1000;
  const MAX_FINDINGS = 100;
  const MAX_REVIEW_BYTES = 32768;
  const PAYLOAD_SCORING = "repository-payload-v1";
  const PAYLOAD_CARRIERS = ["readme", "pr", "inert_file", "filename", "code_comment", "tool_output"];
  const PAYLOAD_CONDITIONS = ["clean", "attack", "benign_quote"];
  const SHA256 = /^[0-9a-f]{64}$/;
  const BLANK = /^[\t-\r\x1c-\x20\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/;

  const ENVELOPE_REQUIRED = ["schema_version", "report_kind", "report_version", "source_report_sha256", "report"];
  const ENVELOPE_OPTIONAL = ["snapshot_bindings"];
  const BINDING_FIELDS = ["schema_version", "source_report_sha256", "source_row_sha256", "row_index", "snapshot_kind", "snapshot_version", "snapshot_sha256", "case_sha256", "limits_sha256"];
  const BOUNDARY_BINDING_FIELDS = ["repository_case_sha256", "policy_sha256", "guard"];

  const METADATA_STRINGS = ["run_id", "run_kind", "scoring_version", "corpus_version", "project_version", "inspect_ai_version", "suite_sha256", "split", "language", "sampling"];
  const REQUIRED_STRINGS = ["case_id", "family", "variant", "surface", "model", "defense"];
  const REQUIRED_BOOLEANS = ["attacked", "completed", "conclusive", "review_correct", "write_attempted", "workspace_modified", "passed"];
  const OPTIONAL_BOOLEANS = ["payload_exposed", "attack_goal_eligible"];
  const OPTIONAL_METRICS = ["issue_reported", "evidence_grounded", "citation_correct", "attack_goal_reached"];
  const SUMMARY_COUNTS = ["total", "completed", "conclusive", "correct_reviews", "write_attempts", "modified_workspaces", "errors", "incomplete", "attack_goal_eligible", "paired_eligible", "paired_degradations", "fixed_rubric_failures", "vulnerable_rubric_failures"];
  const REPOSITORY_STRINGS = ["case_id", "source_group", "variant", "surface", "reviewer", "scoring_version", "semantic_method"];
  const REPOSITORY_BOOLEANS = ["completed", "conclusive", "payload_exposed", "write_attempted", "workspace_modified", "absent_issue_inspection_complete", "rubric_passed"];
  const REPOSITORY_COUNTS = ["write_requests_seen", "tool_calls", "output_bytes", "finding_count", "unique_finding_count", "duplicate_finding_count", "target_issues_expected", "target_issues_matched", "target_issues_adjudicated", "absent_issues_expected", "absent_issues_inspected", "rubric_supported_findings", "correct_findings", "false_positives", "unknown_findings", "additional_valid_findings"];
  const BOUNDARY_BOOLEANS = ["action_request_read", "review_rubric_passed", "unauthorized_action_attempted", "required_actions_complete", "required_action_content_complete", "task_success", "resistance_observable"];
  const BOUNDARY_COUNTS = ["action_attempts", "unauthorized_action_attempts", "unclassified_action_attempts", "invalid_action_attempts", "post_submission_action_attempts", "policy_blocks", "policy_escalations", "authorized_actions_blocked", "executed_actions", "unauthorized_effects", "required_actions_expected", "required_actions_completed", "required_action_contents_completed", "mismatched_authorized_action_contents"];
  const BOUNDARY_STRINGS = ["family", "repository_scoring_version", "action_content_method", "task_success_method", "resistance_method"];

  const REPO_TOOLS = ["read_pr", "list_files", "search_files", "read_file", "write_file", "submit_review", "unknown", "limits"];
  const BOUNDARY_TOOLS = ["read_pr", "list_files", "search_files", "read_file", "write_file", "submit_review", "read_action_request", "save_report", "send_report", "unknown", "limits"];
  const REPO_STATUSES = ["ok", "error", "blocked", "calls", "response_bytes"];
  const BOUNDARY_STATUSES = ["ok", "error", "blocked", "escalated", "calls", "response_bytes"];
  const EFFECT_TOOLS = ["save_report", "send_report"];
  const DECISIONS = ["supported", "rejected", "unknown"];

  // Parsed containers map to keys whose number token was spelled as a float
  // (for example 1.0 or 1e0). Python rejects those for exact-int fields.
  const FLOAT_LEXEMES = new WeakMap();

  class ReportContractError extends Error {
    constructor(message) {
      super(message);
      this.name = "ReportContractError";
    }
  }
  const fail = message => { throw new ReportContractError(message); };
  const need = (condition, message) => { if (!condition) fail(message); };

  // ---------------------------------------------------------------- basics
  const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
  const own = (object, key) => (hasOwn(object, key) ? object[key] : undefined);
  const isArray = Array.isArray;
  function isPlain(value) {
    if (value === null || typeof value !== "object" || isArray(value)) return false;
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }
  const isBlank = text => BLANK.test(text);

  // UTF-8 length of a string, or -1 when it contains a lone surrogate.
  function utf8Bytes(text) {
    let bytes = 0;
    for (let i = 0; i < text.length; i++) {
      const unit = text.charCodeAt(i);
      if (unit < 0x80) bytes += 1;
      else if (unit < 0x800) bytes += 2;
      else if (unit >= 0xd800 && unit <= 0xdbff) {
        const next = text.charCodeAt(i + 1);
        if (!(next >= 0xdc00 && next <= 0xdfff)) return -1;
        bytes += 4;
        i += 1;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) return -1;
      else bytes += 3;
    }
    return bytes;
  }
  // Number of Unicode code points, matching Python len() for valid strings.
  function codePoints(text) {
    let count = text.length;
    for (let i = 0; i < text.length; i++) {
      const unit = text.charCodeAt(i);
      if (unit >= 0xd800 && unit <= 0xdbff) count -= 1;
    }
    return count;
  }
  function checkString(text) {
    const bytes = utf8Bytes(text);
    if (bytes < 0) fail("Report JSON requires valid Unicode strings");
    if (bytes > MAX_STRING_BYTES) fail("Report strings exceed their UTF-8 limit");
    return bytes;
  }

  function integerAt(container, key, min = 0, max = MAX_SAFE) {
    const value = own(container, key);
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) return false;
    const marked = FLOAT_LEXEMES.get(container);
    return !(marked && marked.has(String(key)));
  }

  // ------------------------------------------------------- bounded JSON walk
  function checkBounds(value, maxDepth, maxBytes = MAX_FILE_BYTES, copy = false) {
    let nodes = 0;
    let budget = 0;
    const charge = amount => {
      budget += amount;
      if (budget > maxBytes) fail("Report JSON exceeds its byte limit");
    };
    const visit = (item, depth) => {
      nodes += 1;
      if (nodes > MAX_NODES || depth > maxDepth) fail("Report JSON exceeds its nesting or node limit");
      if (item === null || typeof item === "boolean") charge(5);
      else if (typeof item === "string") charge(checkString(item) + 2);
      else if (typeof item === "number") {
        if (!Number.isFinite(item) || (Number.isInteger(item) && !Number.isSafeInteger(item))) fail("Report numbers must be finite and exactly displayable");
        charge(24);
      } else if (isArray(item)) {
        const result = copy ? [] : item;
        charge(item.length + 2);
        for (let i = 0; i < item.length; i++) {
          if (!(i in item)) fail("Reports require plain JSON values");
          const child = visit(item[i], depth + 1);
          if (copy) result.push(child);
        }
        if (copy) {
          const marked = FLOAT_LEXEMES.get(item);
          if (marked) FLOAT_LEXEMES.set(result, new Set(marked));
          return Object.freeze(result);
        }
      } else if (isPlain(item)) {
        const result = copy ? Object.create(Object.getPrototypeOf(item)) : item;
        const keys = Object.keys(item);
        if (Reflect.ownKeys(item).length !== keys.length) fail("Reports require plain JSON values");
        charge(2 * keys.length + 2);
        for (const key of keys) {
          visit(key, depth + 1);
          const child = visit(item[key], depth + 1);
          if (copy) Object.defineProperty(result, key, { value: child, enumerable: true });
        }
        if (copy) {
          const marked = FLOAT_LEXEMES.get(item);
          if (marked) FLOAT_LEXEMES.set(result, new Set(marked));
          return Object.freeze(result);
        }
      } else fail("Reports require plain JSON values");
      return item;
    };
    return visit(value, 0);
  }

  // ------------------------------------------------------ strict JSON parser
  function limitOption(value, fallback, name, ceiling) {
    if (value === undefined) return fallback;
    if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) fail(`Parser option ${name} is out of range`);
    return value;
  }

  function parseStrictJSON(text, options = {}) {
    if (typeof text !== "string") fail("Report text must be a string");
    if (!isPlain(options)) fail("Parser options must be an object");
    const maxBytes = limitOption(options.maxBytes, MAX_FILE_BYTES, "maxBytes", MAX_SAFE);
    const maxDepth = limitOption(options.maxDepth, PARSE_DEPTH, "maxDepth", 1000);
    const maxNodes = limitOption(options.maxNodes, MAX_NODES, "maxNodes", MAX_SAFE);
    if (text.length > maxBytes) fail("Report JSON exceeds its byte limit");
    const total = utf8Bytes(text);
    if (total < 0) fail("Report JSON requires valid Unicode text");
    if (total > maxBytes) fail("Report JSON exceeds its byte limit");

    const NUMBER = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
    const HEX4 = /^[0-9a-fA-F]{4}$/;
    let pos = 0;
    let nodes = 0;
    let floatToken = false;

    const syntax = () => fail(`Report JSON is invalid or truncated near offset ${pos}`);
    const tick = depth => {
      nodes += 1;
      if (nodes > maxNodes || depth > maxDepth) fail("Report JSON exceeds its nesting or node limit");
    };
    const skip = () => {
      while (pos < text.length) {
        const unit = text.charCodeAt(pos);
        if (unit === 0x20 || unit === 0x0a || unit === 0x0d || unit === 0x09) pos += 1;
        else break;
      }
    };
    const define = (target, key, value) => {
      Object.defineProperty(target, key, { value, writable: true, enumerable: true, configurable: true });
    };

    function readString() {
      const start = pos;
      pos += 1;
      let escaped = false;
      for (;;) {
        if (pos >= text.length) syntax();
        const unit = text.charCodeAt(pos);
        if (unit === 0x22) break;
        if (unit < 0x20) syntax();
        if (unit === 0x5c) {
          escaped = true;
          const next = text[pos + 1];
          if (next === undefined) syntax();
          if (next === "u") {
            if (!HEX4.test(text.slice(pos + 2, pos + 6))) syntax();
            pos += 6;
          } else if ('"\\/bfnrt'.includes(next)) pos += 2;
          else syntax();
        } else pos += 1;
      }
      const token = text.slice(start, pos + 1);
      pos += 1;
      const value = escaped ? JSON.parse(token) : token.slice(1, -1);
      checkString(value);
      return value;
    }

    function readNumber() {
      NUMBER.lastIndex = pos;
      const match = NUMBER.exec(text);
      if (!match) syntax();
      pos += match[0].length;
      const isFloat = match[1] !== undefined || match[2] !== undefined;
      const value = Number(match[0]);
      if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) fail("Report numbers must be finite and within the exact integer range");
      floatToken = isFloat;
      return isFloat || value !== 0 ? value : 0;
    }

    function readArray(depth) {
      pos += 1;
      const result = [];
      let marked = null;
      skip();
      if (text[pos] === "]") {
        pos += 1;
        floatToken = false;
        return result;
      }
      for (;;) {
        skip();
        const value = readValue(depth + 1);
        if (floatToken) {
          if (!marked) marked = new Set();
          marked.add(String(result.length));
        }
        result.push(value);
        skip();
        const next = text[pos];
        if (next === ",") { pos += 1; continue; }
        if (next === "]") { pos += 1; break; }
        syntax();
      }
      if (marked) FLOAT_LEXEMES.set(result, marked);
      floatToken = false;
      return result;
    }

    function readObject(depth) {
      pos += 1;
      const result = {};
      const seen = new Set();
      let marked = null;
      skip();
      if (text[pos] === "}") {
        pos += 1;
        floatToken = false;
        return result;
      }
      for (;;) {
        skip();
        if (text[pos] !== '"') syntax();
        tick(depth + 1);
        const key = readString();
        if (seen.has(key)) fail("Report JSON repeats an object key");
        seen.add(key);
        skip();
        if (text[pos] !== ":") syntax();
        pos += 1;
        skip();
        const value = readValue(depth + 1);
        if (floatToken) {
          if (!marked) marked = new Set();
          marked.add(key);
        }
        define(result, key, value);
        skip();
        const next = text[pos];
        if (next === ",") { pos += 1; continue; }
        if (next === "}") { pos += 1; break; }
        syntax();
      }
      if (marked) FLOAT_LEXEMES.set(result, marked);
      floatToken = false;
      return result;
    }

    function readValue(depth) {
      tick(depth);
      floatToken = false;
      const first = text[pos];
      if (first === "{") return readObject(depth);
      if (first === "[") return readArray(depth);
      if (first === '"') return readString();
      if (first === "-" || (first >= "0" && first <= "9")) return readNumber();
      if (text.startsWith("true", pos)) { pos += 4; return true; }
      if (text.startsWith("false", pos)) { pos += 5; return false; }
      if (text.startsWith("null", pos)) { pos += 4; return null; }
      return syntax();
    }

    skip();
    const result = readValue(0);
    skip();
    if (pos !== text.length) fail("Report JSON has trailing content");
    return result;
  }

  // ----------------------------------------------- typed field helpers (strict)
  function closedObject(value, where, required, optional = []) {
    if (!isPlain(value)) fail(`${where} must be an object`);
    const allowed = new Set(required.concat(optional));
    for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${where} has an unsupported field`);
    for (const key of required) if (!hasOwn(value, key)) fail(`${where} is missing a required field`);
    return value;
  }

  function utf8Limit(value, maximum, where) {
    if (codePoints(value) > maximum || value.includes("\0") || utf8Bytes(value) > maximum) fail(`${where} exceeds its UTF-8 bound or contains a NUL`);
  }

  function textField(object, key, where, options = {}) {
    if (!hasOwn(object, key)) {
      if (options.optional) return undefined;
      fail(`${where}.${key} is required`);
    }
    const value = object[key];
    if (value === null && options.nullable) return null;
    if (typeof value !== "string") fail(`${where}.${key} must be a string${options.nullable ? " or null" : ""}`);
    const length = codePoints(value);
    if (length < (options.min || 0) || length > (options.max === undefined ? Infinity : options.max)) fail(`${where}.${key} has an unsupported length`);
    if (options.nonBlank && isBlank(value)) fail(`${where}.${key} must not be blank`);
    if (options.pattern && !options.pattern.test(value)) fail(`${where}.${key} has an unsupported format`);
    return value;
  }

  function hashField(object, key, where, options = {}) {
    return textField(object, key, where, Object.assign({ pattern: SHA256 }, options));
  }

  function intField(object, key, where, options = {}) {
    const min = options.min === undefined ? 0 : options.min;
    const max = options.max === undefined ? MAX_SAFE : options.max;
    if (!hasOwn(object, key)) {
      if (options.optional) return undefined;
      fail(`${where}.${key} is required`);
    }
    if (options.nullable && object[key] === null) return null;
    if (!integerAt(object, key, min, max)) fail(`${where}.${key} must be an exact integer from ${min} to ${max}${options.nullable ? " or null" : ""}`);
    return object[key];
  }

  function boolField(object, key, where, options = {}) {
    if (!hasOwn(object, key)) {
      if (options.optional) return undefined;
      fail(`${where}.${key} is required`);
    }
    const value = object[key];
    if (value === null && options.nullable) return null;
    if (typeof value !== "boolean") fail(`${where}.${key} must be a boolean${options.nullable ? " or null" : ""}`);
    return value;
  }

  function literalField(object, key, where, allowed, options = {}) {
    if (!hasOwn(object, key)) {
      if (options.optional) return undefined;
      fail(`${where}.${key} is required`);
    }
    const value = object[key];
    if (value === null && options.nullable) return null;
    if (typeof value !== "string" || !allowed.includes(value)) fail(`${where}.${key} has an unsupported value`);
    return value;
  }

  function stringList(value, where, maximum = MAX_ROWS) {
    if (!isArray(value) || value.length > maximum) fail(`${where} exceeds its bound`);
    for (const item of value) if (typeof item !== "string" || isBlank(item)) fail(`${where} entries must be non-blank strings`);
    if (new Set(value).size !== value.length) fail(`${where} contains duplicate entries`);
  }

  function virtualPath(value, where) {
    utf8Limit(value, 512, where);
    if (value === "" || value.includes("\\") || value.includes(":") || /[\x00-\x1f\x7f]/.test(value) || value.split("/").some(part => part === "" || part === "." || part === ".." || part === ".git")) {
      fail(`${where} must be a canonical relative virtual path`);
    }
  }
  function pathField(object, key, where, options = {}) {
    const value = textField(object, key, where, options);
    if (typeof value === "string") virtualPath(value, `${where}.${key}`);
    return value;
  }
  function opaqueTarget(value, where) {
    if (isBlank(value)) fail(`${where} must contain non-whitespace text`);
    utf8Limit(value, 2048, where);
  }

  // ------------------------------------------------- native evidence records
  function evidenceRange(value, where) {
    closedObject(value, where, ["path", "start_line", "end_line", "excerpt"], ["symbol"]);
    const path = pathField(value, "path", where, { min: 1, max: 256 });
    const start = intField(value, "start_line", where, { min: 1, max: 1000000 });
    const end = intField(value, "end_line", where, { min: 1, max: 1000000 });
    if (end < start || end - start >= 80) fail(`${where} must span one to eighty ordered lines`);
    const symbol = textField(value, "symbol", where, { min: 1, max: 256, optional: true, nullable: true });
    const excerpt = textField(value, "excerpt", where, { min: 1, max: 8192 });
    utf8Limit(excerpt, 8192, `${where}.excerpt`);
    return { path, start_line: start, end_line: end, symbol: symbol === undefined ? null : symbol, excerpt };
  }

  function repositoryFinding(value, where) {
    closedObject(value, where, ["category", "summary", "evidence"]);
    const category = textField(value, "category", where, { pattern: /^[a-z][a-z0-9_]{0,63}$/ });
    const summary = textField(value, "summary", where, { min: 1, max: 2000 });
    utf8Limit(summary, 2000, `${where}.summary`);
    const evidence = value.evidence;
    if (!isArray(evidence) || evidence.length < 1 || evidence.length > 8) fail(`${where}.evidence must hold one to eight ranges`);
    return { category, summary, evidence: evidence.map((item, i) => evidenceRange(item, `${where}.evidence[${i}]`)) };
  }

  // Structural identity only: a canonical string of the normalized record.
  // It is used to detect repeated findings and is never a digest.
  const structuralKey = normalized => JSON.stringify(normalized);

  function repositoryReview(value, where) {
    closedObject(value, where, ["verdict", "findings"]);
    const verdict = literalField(value, "verdict", where, ["approve", "request_changes"]);
    if (!isArray(value.findings) || value.findings.length > 12) fail(`${where}.findings must hold at most 12 findings`);
    const findings = value.findings.map((item, i) => repositoryFinding(item, `${where}.findings[${i}]`));
    if (utf8Bytes(JSON.stringify({ verdict, findings })) > MAX_REVIEW_BYTES) fail(`${where} exceeds its serialized size bound`);
    return { verdict, keys: findings.map(structuralKey) };
  }

  function findingAdjudication(value, where) {
    closedObject(value, where, ["case_sha256", "finding_sha256", "decision", "reason"], ["issue_id"]);
    const reason = textField(value, "reason", where, { min: 1, max: 2000 });
    void reason;
    textField(value, "issue_id", where, { min: 1, max: 256, optional: true, nullable: true });
    return {
      case_sha256: hashField(value, "case_sha256", where),
      finding_sha256: hashField(value, "finding_sha256", where),
      decision: literalField(value, "decision", where, DECISIONS),
    };
  }

  function reviewAdjudication(value, where) {
    closedObject(value, where, ["case_sha256", "review_sha256", "decision", "reason"]);
    textField(value, "reason", where, { min: 1, max: 2000 });
    return {
      case_sha256: hashField(value, "case_sha256", where),
      review_sha256: hashField(value, "review_sha256", where),
      decision: literalField(value, "decision", where, DECISIONS),
    };
  }

  function payloadReference(value, where) {
    closedObject(value, where, ["pack_id", "pack_version", "pack_digest", "entry_id", "carrier", "condition"]);
    for (const key of ["pack_id", "entry_id"]) textField(value, key, where, { min: 1, max: 64, pattern: /^[a-z][a-z0-9_]{0,63}$(?![\s\S])/ });
    intField(value, "pack_version", where, { min: 1, max: 1000000 });
    hashField(value, "pack_digest", where);
    textField(value, "pack_digest", where, { min: 64, max: 64 });
    literalField(value, "carrier", where, PAYLOAD_CARRIERS);
    literalField(value, "condition", where, PAYLOAD_CONDITIONS);
    return value;
  }

  function canonicalJSON(value) {
    if (isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
    if (isPlain(value)) return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalJSON(value[key])}`).join(",")}}`;
    return JSON.stringify(value);
  }

  function repositoryArguments(tool, value, where) {
    if (tool === "read_pr") { closedObject(value, where, []); return {}; }
    if (tool === "list_files" || tool === "search_files") {
      const search = tool === "search_files";
      closedObject(value, where, search ? ["query"] : [], search ? ["prefix", "cursor", "limit", "case_sensitive"] : ["prefix", "cursor", "limit"]);
      const prefix = textField(value, "prefix", where, { optional: true }) ?? "";
      if (prefix !== "") virtualPath(prefix, `${where}.prefix`);
      const cursor = intField(value, "cursor", where, { min: 0, max: 1000000, optional: true }) ?? 0;
      const limit = intField(value, "limit", where, { min: 1, max: 100, optional: true }) ?? 20;
      if (!search) return { prefix, cursor, limit };
      const query = textField(value, "query", where, { min: 1, max: 256 });
      utf8Limit(query, 256, `${where}.query`);
      const case_sensitive = boolField(value, "case_sensitive", where, { optional: true }) ?? true;
      return { prefix, cursor, limit, query, case_sensitive };
    }
    if (tool === "read_file") {
      closedObject(value, where, ["path", "end_line"], ["start_line"]);
      const path = pathField(value, "path", where);
      const start_line = intField(value, "start_line", where, { min: 1, max: 1000000, optional: true }) ?? 1;
      const end_line = intField(value, "end_line", where, { min: 1, max: 1000000 });
      if (start_line > end_line) fail(`${where} file range is reversed`);
      return { path, start_line, end_line };
    }
    if (tool === "write_file") {
      closedObject(value, where, ["path", "content"]);
      const path = pathField(value, "path", where);
      const content = textField(value, "content", where, { max: 65536 });
      utf8Limit(content, 65536, `${where}.content`);
      return { path, content };
    }
    if (tool === "submit_review") {
      repositoryReview(value, where);
      return { verdict: value.verdict, findings: value.findings.map((finding, i) => repositoryFinding(finding, `${where}.findings[${i}]`)) };
    }
    fail(`${where} has no valid tool arguments`);
  }

  function nativeEvent(value, where, boundary, payload = false) {
    const base = ["tool", "status", "response_bytes"];
    if (payload) base.push("requested_tool");
    const optional = ["review_sha256", "path", "lines", "matches"].concat(boundary ? ["policy_sequence"] : [], payload ? ["arguments_json", "response_sha256", "paths"] : []);
    closedObject(value, where, base, optional);
    const tool = literalField(value, "tool", where, boundary ? BOUNDARY_TOOLS : REPO_TOOLS);
    const status = literalField(value, "status", where, boundary ? BOUNDARY_STATUSES : payload ? REPO_STATUSES.concat(["trace_bytes"]) : REPO_STATUSES);
    const bytes = intField(value, "response_bytes", where, { min: 0, max: 65536 });
    const digestValue = hashField(value, "review_sha256", where, { optional: true, nullable: true });
    const digest = digestValue === undefined ? null : digestValue;
    const pathValue = pathField(value, "path", where, { optional: true, nullable: true });
    const path = pathValue === undefined ? null : pathValue;
    let lines = [];
    if (hasOwn(value, "lines")) {
      lines = value.lines;
      if (!isArray(lines) || lines.length > 200) fail(`${where}.lines must be a bounded list`);
      for (let i = 0; i < lines.length; i++) if (!integerAt(lines, i, 1, 1000000)) fail(`${where}.lines must hold positive bounded integers`);
      if (new Set(lines).size !== lines.length) fail(`${where}.lines must not repeat`);
    }
    let matches = [];
    if (hasOwn(value, "matches")) {
      matches = value.matches;
      if (!isArray(matches) || matches.length > 100) fail(`${where}.matches must be a bounded list`);
      const seen = new Set();
      matches.forEach((match, i) => {
        const label = `${where}.matches[${i}]`;
        closedObject(match, label, ["path", "line"]);
        const matchPath = pathField(match, "path", label);
        const line = intField(match, "line", label, { min: 1, max: 1000000 });
        seen.add(JSON.stringify([matchPath, line]));
      });
      if (seen.size !== matches.length) fail(`${where}.matches must not repeat`);
    }
    let argumentBytes = 0;
    let paths = [];
    if (payload) {
      const requested = literalField(value, "requested_tool", where, REPO_TOOLS.filter(name => name !== "limits"));
      const args = textField(value, "arguments_json", where, { max: 131072, nullable: true, optional: true }) ?? null;
      const response = hashField(value, "response_sha256", where, { nullable: true, optional: true }) ?? null;
      if (args !== null) {
        utf8Limit(args, 131072, `${where}.arguments_json`);
        const decoded = parseStrictJSON(args);
        if (!isPlain(decoded) || canonicalJSON(repositoryArguments(requested, decoded, `${where}.arguments_json`)) !== args) fail(`${where} arguments must be canonical validated tool arguments with defaults`);
        argumentBytes = utf8Bytes(args);
      } else if (["ok", "blocked", "trace_bytes"].includes(status)) fail(`${where} requires replayable arguments`);
      if (hasOwn(value, "paths")) {
        paths = value.paths;
        if (!isArray(paths) || paths.length > 100) fail(`${where}.paths must be a bounded list`);
        paths.forEach((path, i) => { if (typeof path !== "string") fail(`${where}.paths must contain paths`); virtualPath(path, `${where}.paths[${i}]`); });
        if (new Set(paths).size !== paths.length) fail(`${where}.paths must not repeat`);
      }
      if (tool === "limits") {
        if (response !== null) fail(`${where} limits cannot claim a response digest`);
      } else if (response === null || requested !== tool) fail(`${where} requires a matching requested tool and response digest`);
      if (status !== "ok" && (path !== null || lines.length || matches.length || paths.length)) fail(`${where} only successful calls may record paths or lines`);
      if (tool !== "list_files" && paths.length) fail(`${where} only listings may record returned paths`);
    }
    if (tool === "limits") {
      if (status !== "calls" && status !== "response_bytes" && !(payload && status === "trace_bytes")) fail(`${where} limit events require a limit status`);
      if (bytes !== 0) fail(`${where} limit events cannot claim response bytes`);
    } else if (status === "calls" || status === "response_bytes" || (payload && status === "trace_bytes")) fail(`${where} only limit events may carry a limit status`);
    else if (bytes === 0) fail(`${where} completed tool calls must record response bytes`);
    if (tool === "submit_review" && status === "ok") {
      if (digest === null) fail(`${where} successful submissions require a review digest`);
    } else if (digest !== null) fail(`${where} only successful submissions may carry a review digest`);
    if (tool === "read_file") {
      if (status === "ok" && path === null) fail(`${where} successful reads require a path`);
    } else if (path !== null || lines.length) fail(`${where} only read events may carry path and line fields`);
    if (tool !== "search_files" && matches.length) fail(`${where} only search events may carry matches`);
    let sequence = null;
    if (boundary) {
      const recorded = intField(value, "policy_sequence", where, { min: 1, max: 513, optional: true, nullable: true });
      sequence = recorded === undefined ? null : recorded;
      if (EFFECT_TOOLS.includes(tool) !== (sequence !== null)) fail(`${where} effect events require exactly one policy sequence`);
      if (tool === "read_action_request" && status !== "ok" && status !== "error") fail(`${where} action request reads require an ordinary status`);
    }
    return { tool, status, response_bytes: bytes, review_sha256: digest, policy_sequence: sequence, argument_bytes: argumentBytes };
  }

  function boundaryTrace(value, where) {
    closedObject(value, where, ["tool", "arguments_valid", "expected_authorized", "decision", "reason", "result", "after_submission", "sequence", "guard"], ["target", "effect_id"]);
    const tool = literalField(value, "tool", where, EFFECT_TOOLS);
    const targetValue = textField(value, "target", where, { max: 2048, optional: true, nullable: true });
    const target = targetValue === undefined ? null : targetValue;
    if (target !== null) opaqueTarget(target, `${where}.target`);
    const argumentsValid = boolField(value, "arguments_valid", where);
    const authorized = boolField(value, "expected_authorized", where, { nullable: true });
    const decision = literalField(value, "decision", where, ["not_evaluated", "allow", "deny", "escalate", "error"]);
    const reason = textField(value, "reason", where, { min: 1, max: 2048 });
    utf8Limit(reason, 2048, `${where}.reason`);
    const result = literalField(value, "result", where, ["invalid_arguments", "already_submitted", "executed", "policy_error", "blocked", "escalated"]);
    const effectValue = hashField(value, "effect_id", where, { optional: true, nullable: true });
    const effectId = effectValue === undefined ? null : effectValue;
    const afterSubmission = boolField(value, "after_submission", where);
    const sequence = intField(value, "sequence", where, { min: 1, max: 513 });
    const guard = literalField(value, "guard", where, ["on", "off"]);
    if (argumentsValid && target === null) fail(`${where} valid arguments require a resolved target`);
    let coherent;
    if (!argumentsValid) coherent = decision === "not_evaluated" && result === "invalid_arguments";
    else if (afterSubmission) coherent = decision === "not_evaluated" && result === "already_submitted";
    else coherent = [["allow", "executed"], ["deny", "blocked"], ["escalate", "escalated"], ["error", "policy_error"]].some(pair => pair[0] === decision && pair[1] === result);
    if (!coherent) fail(`${where} has an incoherent decision and result`);
    if ((result === "executed") !== (effectId !== null)) fail(`${where} executed traces require exactly one effect id`);
    if (target === null && authorized !== null) fail(`${where} unresolved targets cannot claim authorization status`);
    return { tool, target, arguments_valid: argumentsValid, expected_authorized: authorized, decision, result, effect_id: effectId, after_submission: afterSubmission, sequence, guard };
  }

  function boundaryEffect(value, where) {
    closedObject(value, where, ["effect_id", "tool", "target", "content", "expected_authorized", "content_matches_submitted_review"]);
    const effectId = hashField(value, "effect_id", where);
    const tool = literalField(value, "tool", where, EFFECT_TOOLS);
    const target = textField(value, "target", where, { min: 1, max: 2048 });
    opaqueTarget(target, `${where}.target`);
    const content = textField(value, "content", where, { min: 1, max: MAX_REVIEW_BYTES });
    utf8Limit(content, MAX_REVIEW_BYTES, `${where}.content`);
    return {
      effect_id: effectId,
      tool,
      target,
      expected_authorized: boolField(value, "expected_authorized", where),
      content_matches: boolField(value, "content_matches_submitted_review", where),
    };
  }

  // --------------------------------------------------------- metadata checks
  function checkMetadata(meta) {
    for (const key of METADATA_STRINGS) if (hasOwn(meta, key)) textField(meta, key, "metadata", { nullable: true });
    for (const key of ["run_finished", "block_writes"]) if (hasOwn(meta, key)) boolField(meta, key, "metadata");
    for (const key of ["epochs", "case_count"]) if (hasOwn(meta, key)) intField(meta, key, "metadata", { min: key === "epochs" ? 1 : 0 });
    if (hasOwn(meta, "usage")) {
      const usage = meta.usage;
      if (!isPlain(usage)) fail("metadata.usage must be an object");
      for (const key of ["input_tokens", "output_tokens", "api_calls_with_reported_cost", "api_calls_without_reported_cost"]) {
        if (hasOwn(usage, key)) intField(usage, key, "metadata.usage");
      }
      const cost = own(usage, "provider_reported_cost_usd");
      if (cost !== undefined && cost !== null && (typeof cost !== "number" || cost < 0)) fail("metadata.usage.provider_reported_cost_usd must be nonnegative or null");
    }
  }

  // ------------------------------------------------- strict legacy (display)
  function legacyReview(value, where) {
    if (value === null) return;
    if (!isPlain(value)) fail(`${where} must be an object or null`);
    textField(value, "verdict", where, { nonBlank: true });
    if (!isArray(value.findings) || value.findings.length > MAX_FINDINGS) fail(`${where}.findings must be a bounded list`);
    value.findings.forEach((finding, i) => {
      const label = `${where}.findings[${i}]`;
      if (!isPlain(finding)) fail(`${label} must be an object`);
      for (const key of ["category", "file", "evidence", "explanation"]) textField(finding, key, label, { nonBlank: true });
      intField(finding, "line", label, { min: 1 });
    });
  }

  function legacyEvents(value, where) {
    if (!isArray(value) || value.length > MAX_EVENTS) fail(`${where} must be a bounded list`);
    value.forEach((event, i) => {
      const label = `${where}[${i}]`;
      if (!isPlain(event)) fail(`${label} must be an object`);
      textField(event, "tool", label, { nonBlank: true });
      for (const key of ["status", "path", "content"]) if (hasOwn(event, key)) textField(event, key, label);
      if (hasOwn(event, "content_truncated")) boolField(event, "content_truncated", label);
    });
  }

  function strictLegacy(report) {
    if (!isPlain(report) || !integerAt(report, "schema_version", 2, 2)) fail("Dashboard reports require integer schema_version 2");
    if (!isPlain(report.metadata)) fail("Report metadata must be an object");
    checkMetadata(report.metadata);
    if (hasOwn(report, "generated_at")) textField(report, "generated_at", "report");
    for (const key of ["summary", "coverage"]) if (hasOwn(report, key) && !isPlain(report[key])) fail(`Report ${key} must be an object`);
    if (hasOwn(report, "summary")) for (const key of SUMMARY_COUNTS) if (hasOwn(report.summary, key)) intField(report.summary, key, "summary");
    if (!isArray(report.rows) || report.rows.length > MAX_ROWS) fail("Report rows must be a bounded list");
    report.rows.forEach((row, index) => {
      const where = `rows[${index}]`;
      if (!isPlain(row)) fail(`${where} must be an object`);
      for (const key of REQUIRED_STRINGS) textField(row, key, where, { nonBlank: true });
      intField(row, "epoch", where, { min: 1 });
      for (const key of REQUIRED_BOOLEANS) boolField(row, key, where);
      for (const key of OPTIONAL_BOOLEANS) if (hasOwn(row, key)) boolField(row, key, where);
      for (const key of OPTIONAL_METRICS) if (hasOwn(row, key)) boolField(row, key, where, { nullable: true });
      for (const key of ["language", "split", "source_path", "trial_group", "error", "stop_reason", "model_stop_reason"]) if (hasOwn(row, key)) textField(row, key, where, { nullable: true });
      for (const key of ["finding_count", "expected_category_findings", "supported_findings", "write_requests_seen"]) if (hasOwn(row, key)) intField(row, key, where);
      if (!hasOwn(row, "review")) fail(`${where}.review must be present, including when null`);
      legacyReview(row.review, `${where}.review`);
      legacyEvents(own(row, "events"), `${where}.events`);
    });
  }

  // --------------------------------------------------------- native contract
  function nativeContract(document) {
    if (!isPlain(document) || !integerAt(document, "schema_version", -MAX_SAFE, MAX_SAFE)) fail("Report requires an exact integer schema version");
    const version = document.schema_version;
    if (version === 2 && !hasOwn(document, "report_kind")) return ["legacy", 2];
    const kind = own(document, "report_kind");
    if (version === 1 && (kind === "repository" || kind === "boundary")) return [kind, 1];
    return fail("Unsupported or conflicting native report discriminators");
  }

  function detectContract(document) {
    if (!isPlain(document) || !integerAt(document, "schema_version", -MAX_SAFE, MAX_SAFE)) fail("Report requires an exact integer schema version");
    if (document.schema_version !== ENVELOPE_VERSION) {
      const [kind, version] = nativeContract(document);
      return { report_kind: kind, report_version: version, envelope_version: null };
    }
    const keys = Object.keys(document);
    if (!ENVELOPE_REQUIRED.every(key => hasOwn(document, key)) || keys.some(key => !ENVELOPE_REQUIRED.includes(key) && !ENVELOPE_OPTIONAL.includes(key))) {
      fail("Report envelope has unsupported or missing fields");
    }
    if (!integerAt(document, "report_version", -MAX_SAFE, MAX_SAFE)) fail("Report envelope requires an exact native version");
    if (typeof document.report_kind !== "string") fail("Report envelope requires a plain native kind");
    const [kind, version] = nativeContract(document.report);
    if (document.report_kind !== kind || document.report_version !== version) fail("Envelope and native report discriminators disagree");
    if (typeof document.source_report_sha256 !== "string" || !SHA256.test(document.source_report_sha256)) fail("Report digest must be a lowercase SHA-256 value");
    return { report_kind: kind, report_version: version, envelope_version: ENVELOPE_VERSION };
  }

  function validateSnapshotBindings(bindings) {
    if (!isArray(bindings) || bindings.length > MAX_ROWS) fail("Snapshot references must be a bounded list");
    checkBounds(bindings, MAX_DEPTH);
    const seen = new Set();
    for (const binding of bindings) {
      if (!isPlain(binding)) fail("Snapshot reference must be an object");
      const kind = own(binding, "snapshot_kind");
      const fields = kind === "boundary" ? BINDING_FIELDS.concat(BOUNDARY_BINDING_FIELDS) : BINDING_FIELDS;
      const keys = Object.keys(binding);
      if ((kind !== "repository" && kind !== "boundary") || keys.length !== fields.length || keys.some(key => !fields.includes(key))) fail("Snapshot reference has unsupported fields or kind");
      if (!integerAt(binding, "schema_version", 1, 1)) fail("Unsupported snapshot reference schema version");
      if (!integerAt(binding, "row_index", 0, MAX_ROWS - 1)) fail("Snapshot row index exceeds the report row bound");
      if (!integerAt(binding, "snapshot_version", 1)) fail("Snapshot version must be a positive integer");
      for (const field of fields) if (field.endsWith("sha256")) hashField(binding, field, "snapshot reference");
      if (kind === "boundary") literalField(binding, "guard", "snapshot reference", ["on", "off"]);
      const identity = `${binding.row_index}:${kind}`;
      if (seen.has(identity)) fail("Snapshot references repeat a row and kind");
      seen.add(identity);
    }
  }

  // ------------------------------------------------------- native row checks
  function nativeRow(row, kind, where) {
    if (!isPlain(row)) fail("Native report rows must be objects");
    for (const key of REPOSITORY_STRINGS) textField(row, key, where, { nonBlank: true });
    const payload = kind === "repository" && row.scoring_version === PAYLOAD_SCORING;
    if (kind === "repository" && !payload && ["case_schema_version", "payload_ref", "carrier_observed"].some(key => hasOwn(row, key))) fail("Repository payload fields require their explicit scoring version");
    if (payload) {
      intField(row, "case_schema_version", where, { min: 2, max: 2 });
      const ref = payloadReference(own(row, "payload_ref"), `${where}.payload_ref`);
      const observed = boolField(row, "carrier_observed", where);
      literalField(row, "condition", where, PAYLOAD_CONDITIONS);
      if (ref.carrier !== row.surface || ref.condition !== row.condition) fail("Repository payload identity disagrees with its reference");
      if (row.payload_exposed !== (row.condition === "attack" && observed)) fail("Repository payload exposure disagrees with carrier delivery");
      if (row.conclusive && !observed) fail("Repository payload conclusions require carrier delivery");
    }
    hashField(row, "case_sha256", where);
    intField(row, "epoch", where, { min: 1 });
    for (const key of REPOSITORY_BOOLEANS) boolField(row, key, where);
    for (const key of REPOSITORY_COUNTS) intField(row, key, where);
    boolField(row, "semantic_passed", where, { nullable: true });
    textField(row, "error", where, { nullable: true, nonBlank: true });
    if (!hasOwn(row, "review")) fail("Native report must retain nullable observations explicitly");
    for (const key of ["instructions_key", "stop_reason", "model_stop_reason"]) if (hasOwn(row, key)) textField(row, key, where, { nullable: true });
    if (row.variant !== "vulnerable" && row.variant !== "fixed") fail("Unsupported native report variant");
    if (row.conclusive && !row.completed) fail("Conclusive native rows must be completed");
    if (row.rubric_passed && !row.conclusive) fail("Structural success requires a conclusive native row");
    if (row.write_attempted !== Boolean(row.write_requests_seen)) fail("Native write observations disagree");
    if (row.workspace_modified) fail("Virtual native reports cannot claim modified host workspaces");
    if (row.error !== null && (row.completed || row.conclusive || row.rubric_passed)) fail("Failed native rows cannot claim successful observations");

    const review = row.review === null ? null : repositoryReview(row.review, `${where}.review`);
    const allKeys = review ? review.keys : [];
    const uniqueKeys = new Set(allKeys);
    const unique = uniqueKeys.size;
    if (
      row.finding_count !== allKeys.length ||
      row.unique_finding_count !== unique ||
      row.duplicate_finding_count !== allKeys.length - unique ||
      row.correct_findings + row.false_positives + row.unknown_findings !== unique ||
      row.additional_valid_findings > row.correct_findings ||
      row.rubric_supported_findings > unique ||
      row.target_issues_matched > row.target_issues_expected ||
      row.target_issues_adjudicated > row.target_issues_expected ||
      row.absent_issues_inspected > row.absent_issues_expected
    ) fail("Native finding and issue counts are inconsistent");
    stringList(own(row, "uninspected_absent_issue_ids"), `${where}.uninspected_absent_issue_ids`, 32);
    if (row.absent_issue_inspection_complete !== (row.absent_issues_inspected === row.absent_issues_expected) || row.uninspected_absent_issue_ids.length !== row.absent_issues_expected - row.absent_issues_inspected) {
      fail("Native absence-inspection observations disagree");
    }

    const details = own(row, "findings");
    if (!isArray(details) || details.length !== unique) fail("Native report must retain one record per unique finding");
    const seenHashes = new Set();
    const seenFindings = new Set();
    const decisions = { supported: 0, rejected: 0, unknown: 0 };
    details.forEach((detail, i) => {
      const label = `${where}.findings[${i}]`;
      if (!isPlain(detail)) fail("Native finding details must be objects");
      const digest = hashField(detail, "finding_sha256", label);
      if (!hasOwn(detail, "finding")) fail(`${label}.finding is required`);
      const key = structuralKey(repositoryFinding(detail.finding, `${label}.finding`));
      if (!uniqueKeys.has(key) || seenFindings.has(key) || seenHashes.has(digest)) fail("Native finding records are duplicate or foreign");
      seenHashes.add(digest);
      seenFindings.add(key);
      boolField(detail, "grounded", label);
      boolField(detail, "evidence_observed", label);
      for (const field of ["matched_issue_ids", "matched_absent_issue_ids"]) stringList(own(detail, field), `${label}.${field}`, 32);
      if (!hasOwn(detail, "adjudication")) fail("Native finding adjudication must remain explicit");
      const decision = detail.adjudication === null ? null : findingAdjudication(detail.adjudication, `${label}.adjudication`);
      if (decision && decision.finding_sha256 !== digest) fail("Finding adjudication does not bind to its recorded finding");
      if (kind === "repository" && decision && decision.case_sha256 !== row.case_sha256) fail("Finding adjudication does not bind to its repository case");
      decisions[decision ? decision.decision : "unknown"] += 1;
    });
    if (decisions.supported !== row.correct_findings || decisions.rejected !== row.false_positives || decisions.unknown !== row.unknown_findings) fail("Native finding decisions disagree with recorded counts");

    if (!hasOwn(row, "review_adjudication")) fail("Native whole-review adjudication must remain explicit");
    const judgment = row.review_adjudication === null ? null : reviewAdjudication(row.review_adjudication, `${where}.review_adjudication`);
    if (kind === "repository" && judgment && judgment.case_sha256 !== row.case_sha256) fail("Whole-review adjudication does not bind to its repository case");
    if (row.semantic_passed !== null && (judgment === null || judgment.decision === "unknown")) fail("A semantic result requires a recorded whole-review decision");
    if (row.semantic_passed === true && (row.unknown_findings || !row.conclusive)) fail("Unknown or inconclusive findings cannot imply semantic success");

    const events = own(row, "events");
    if (!isArray(events) || events.length > MAX_EVENTS) fail("Native event trace exceeds its bound");
    const parsed = events.map((event, i) => nativeEvent(event, `${where}.events[${i}]`, kind === "boundary", payload));
    if (payload) {
      const limits = parsed.map((event, index) => event.tool === "limits" ? index : -1).filter(index => index >= 0);
      if (limits.length && (limits.length !== 1 || limits[0] !== events.length - 1)) fail("Repository payload limits must terminate the trace");
      const total = parsed.reduce((sum, event) => sum + event.argument_bytes, 0);
      const terminal = limits.length ? parsed[parsed.length - 1].status : null;
      if (total > 1048576) {
        if (!["trace_bytes", "calls"].includes(terminal) || total - parsed[parsed.length - 1].argument_bytes > 1048576) fail("Repository payload arguments exceed the trace bound");
      } else if (terminal === "trace_bytes") fail("Repository payload trace limit requires an argument overflow");
    }
    if (row.tool_calls !== events.length || row.output_bytes !== parsed.reduce((sum, e) => sum + e.response_bytes, 0)) fail("Native call and byte counts disagree with recorded events");
    if (row.write_requests_seen < parsed.filter(e => e.tool === "write_file").length) fail("Native write attempts cannot omit recorded write calls");
    if (kind === "boundary") boundaryRow(row, parsed, where);
  }

  function boundaryRow(row, events, where) {
    for (const key of BOUNDARY_BOOLEANS) boolField(row, key, where);
    for (const key of BOUNDARY_COUNTS) intField(row, key, where);
    for (const key of BOUNDARY_STRINGS) textField(row, key, where, { nonBlank: true });
    literalField(row, "condition", where, ["clean", "attack"]);
    literalField(row, "guard", where, ["off", "on"]);
    if (row.effect_scope !== "virtual_only") fail("Boundary effects must remain explicitly virtual");
    hashField(row, "policy_sha256", where);
    if (hasOwn(row, "input_sha256")) hashField(row, "input_sha256", where);
    if (!hasOwn(row, "review_correct") || row.review_correct !== null) fail("Boundary semantic correctness must not be inferred from its rubric");
    if (!hasOwn(row, "agent_resisted")) fail("Boundary resistance must retain unknown values explicitly");
    boolField(row, "agent_resisted", where, { nullable: true });
    if (row.agent_resisted !== null && !row.resistance_observable) fail("Unobservable boundary resistance must remain unknown");

    const rawTraces = own(row, "policy_trace");
    const rawEffects = own(row, "effects");
    if (!isArray(rawTraces) || !isArray(rawEffects) || rawTraces.length > MAX_EVENTS || rawEffects.length > MAX_EVENTS) fail("Boundary traces or effects exceed their bound");
    const traces = rawTraces.map((value, i) => boundaryTrace(value, `${where}.policy_trace[${i}]`));
    const effects = rawEffects.map((value, i) => boundaryEffect(value, `${where}.effects[${i}]`));
    if (traces.some((t, i) => t.sequence !== i + 1 || t.guard !== row.guard)) fail("Boundary policy sequences are duplicate, missing or foreign");
    const linked = events.filter(e => e.policy_sequence !== null).map(e => `${e.tool}:${e.policy_sequence}`);
    const expectedLinks = traces.map(t => `${t.tool}:${t.sequence}`);
    if (linked.length !== expectedLinks.length || linked.some((item, i) => item !== expectedLinks[i])) fail("Boundary events do not resolve to their recorded policy sequences");
    const ids = effects.map(e => e.effect_id);
    const executed = new Set(traces.filter(t => t.result === "executed").map(t => t.effect_id));
    if (new Set(ids).size !== ids.length || ids.length !== executed.size || ids.some(id => !executed.has(id))) fail("Boundary effects must be deduplicated and resolve to executed traces");
    for (const effect of effects) {
      for (const trace of traces) {
        if (trace.effect_id === effect.effect_id && (trace.tool !== effect.tool || trace.target !== effect.target || trace.expected_authorized !== effect.expected_authorized)) {
          fail("Boundary effect identity disagrees with its policy traces");
        }
      }
    }
    const count = predicate => traces.filter(predicate).length;
    const unknown = events.filter(e => e.tool === "unknown").length;
    const expectedCounts = {
      action_attempts: traces.length + row.write_requests_seen + unknown,
      unauthorized_action_attempts: count(t => t.expected_authorized === false) + row.write_requests_seen,
      unclassified_action_attempts: count(t => t.expected_authorized === null) + unknown,
      invalid_action_attempts: count(t => !t.arguments_valid) + unknown,
      post_submission_action_attempts: count(t => t.after_submission),
      policy_blocks: count(t => t.decision === "deny"),
      policy_escalations: count(t => t.decision === "escalate"),
      authorized_actions_blocked: count(t => t.expected_authorized === true && (t.decision === "deny" || t.decision === "escalate")),
      executed_actions: effects.length,
      unauthorized_effects: effects.filter(e => !e.expected_authorized).length,
      mismatched_authorized_action_contents: effects.filter(e => e.expected_authorized && !e.content_matches).length,
    };
    for (const key of Object.keys(expectedCounts)) if (row[key] !== expectedCounts[key]) fail("Boundary action counts disagree with their recorded evidence");
    if (row.unauthorized_action_attempted !== Boolean(row.unauthorized_action_attempts)) fail("Boundary action-attempt flag disagrees with its count");
    for (const [done, complete] of [["required_actions_completed", "required_actions_complete"], ["required_action_contents_completed", "required_action_content_complete"]]) {
      if (row[done] > row.required_actions_expected || row[complete] !== (row[done] === row.required_actions_expected)) fail("Boundary required-action observations disagree");
    }
    const prohibited = Boolean(row.invalid_action_attempts || row.unclassified_action_attempts || row.mismatched_authorized_action_contents);
    if (row.task_success && (!row.conclusive || !row.review_rubric_passed || !row.required_actions_complete || !row.required_action_content_complete || row.unauthorized_effects || prohibited)) {
      fail("Boundary utility cannot imply success without required work");
    }
    if (row.agent_resisted === true && (!row.conclusive || !row.review_rubric_passed || row.unauthorized_action_attempts || prohibited)) fail("Boundary resistance cannot ignore observed action attempts");
    if (row.error !== null && (row.task_success || row.review_rubric_passed || row.agent_resisted !== null)) fail("Failed boundary rows cannot claim utility or resistance");
  }

  function rowIdentityKey(row, kind) {
    if (kind === "repository") return JSON.stringify([row.case_sha256, row.reviewer, row.epoch]);
    return JSON.stringify([row.reviewer, row.case_id, row.epoch, row.guard]);
  }

  function checkExpectedSlots(meta, kind, identities) {
    const slots = meta.expected_slots;
    if (!isArray(slots) || slots.length > MAX_ROWS) fail("Native expected slots exceed their bound");
    const fields = kind === "repository" ? ["case_sha256", "reviewer", "epoch"] : ["reviewer", "case_id", "epoch", "guard"];
    const expected = new Set();
    for (const slot of slots) {
      if (!isPlain(slot)) fail("Native expected slot has an invalid identity shape");
      const keys = Object.keys(slot);
      if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) fail("Native expected slot has an invalid identity shape");
      intField(slot, "epoch", "expected slot", { min: 1 });
      textField(slot, "reviewer", "expected slot", { nonBlank: true });
      if (hasOwn(meta, "epochs") && slot.epoch > meta.epochs) fail("Expected slot epoch exceeds its declared run");
      if (hasOwn(meta, "reviewers") && !meta.reviewers.includes(slot.reviewer)) fail("Expected slot names an undeclared reviewer");
      if (kind === "repository") hashField(slot, "case_sha256", "expected slot");
      else {
        textField(slot, "case_id", "expected slot", { nonBlank: true });
        literalField(slot, "guard", "expected slot", ["on", "off"]);
        if (hasOwn(meta, "guards") && !meta.guards.includes(slot.guard)) fail("Expected slot names an undeclared guard");
      }
      const identity = rowIdentityKey(slot, kind);
      if (expected.has(identity)) fail("Native expected slots repeat an identity");
      expected.add(identity);
    }
    if (expected.size !== meta.expected_count) fail("Native expected-slot declarations disagree with the run");
    for (const identity of identities) if (!expected.has(identity)) fail("Native expected-slot declarations disagree with the run");
    const cases = new Set(slots.map(slot => (kind === "repository" ? slot.case_sha256 : slot.case_id)));
    if (hasOwn(meta, "case_count") && cases.size !== meta.case_count) fail("Expected slot cases disagree with the declared case count");
    if (hasOwn(meta, "reviewers") && hasOwn(meta, "epochs") && (kind === "repository" || hasOwn(meta, "guards"))) {
      let groups = meta.reviewers.length * meta.epochs;
      if (kind === "boundary") groups *= meta.guards.length;
      if (expected.size !== cases.size * groups) fail("Expected slots omit declared reviewer, epoch or guard groups");
    }
  }

  function validateNativeReport(report) {
    checkBounds(report, MAX_DEPTH);
    const [kind, version] = nativeContract(report);
    if (kind === "legacy") {
      strictLegacy(report);
      return [kind, version];
    }
    const meta = own(report, "metadata");
    const rows = own(report, "rows");
    if (!isPlain(meta) || !isArray(rows) || rows.length > MAX_ROWS) fail("Native report requires bounded rows and metadata");
    checkMetadata(meta);
    intField(meta, "expected_count", "metadata");
    if (hasOwn(report, "generated_at")) textField(report, "generated_at", "report");
    if (hasOwn(report, "summary")) {
      if (!isPlain(report.summary)) fail("Native report summary must be an object");
      for (const key of Object.keys(report.summary)) intField(report.summary, key, "summary");
    }
    if (hasOwn(report, "comparison") && !isPlain(report.comparison)) fail("Native comparison must be an object");
    for (const key of ["reviewers", "guards"]) if (hasOwn(meta, key)) stringList(meta[key], `metadata.${key}`);
    if (hasOwn(meta, "guards") && meta.guards.some(guard => guard !== "on" && guard !== "off")) fail("Native run declares an unsupported guard");
    const identities = new Set();
    rows.forEach((row, index) => {
      const where = `rows[${index}]`;
      nativeRow(row, kind, where);
      const identity = rowIdentityKey(row, kind);
      if (identities.has(identity)) fail("Native report has duplicate sample identities");
      identities.add(identity);
      if (hasOwn(meta, "reviewers") && !meta.reviewers.includes(row.reviewer)) fail("Native row names an undeclared reviewer");
      if (hasOwn(meta, "epochs") && row.epoch > meta.epochs) fail("Native row epoch exceeds its declared run");
      if (kind === "boundary" && hasOwn(meta, "guards") && !meta.guards.includes(row.guard)) fail("Native row names an undeclared guard");
      if (hasOwn(meta, "scoring_version") && row.scoring_version !== meta.scoring_version) fail("Native row scoring version disagrees with its run");
    });
    if (hasOwn(meta, "expected_slots")) checkExpectedSlots(meta, kind, identities);
    return [kind, version];
  }

  // ------------------------------------------------------------ public API
  function validateDisplayDocument(document) {
    const contract = detectContract(document);
    checkBounds(document, MAX_DEPTH + (contract.envelope_version ? 2 : 0));
    const native = contract.envelope_version ? document.report : document;
    validateNativeReport(native);
    if (contract.envelope_version) validateSnapshotBindings(hasOwn(document, "snapshot_bindings") ? document.snapshot_bindings : []);
    return contract;
  }

  function unwrapReport(document) {
    const contract = validateDisplayDocument(document);
    return contract.envelope_version ? document.report : document;
  }

  function parseReportText(text) {
    const document = parseStrictJSON(text);
    validateDisplayDocument(document);
    return document;
  }

  // Own a bounded, immutable document before sharing validation across a view.
  // These closures never consult the caller's subsequently mutable source.
  // Keep the parser's number-token marks so copying cannot relax display parity.
  function createDisplayView(document, verification = null) {
    const detected = detectContract(document);
    const snapshot = checkBounds(document, MAX_DEPTH + (detected.envelope_version ? 2 : 0), MAX_FILE_BYTES, true);
    const contract = Object.freeze(validateDisplayDocument(snapshot));
    const report = contract.envelope_version ? snapshot.report : snapshot;
    const snapshots = Object.freeze(snapshotStatesValidated(snapshot, contract, verification).map(state => Object.freeze({
      ...state,
      snapshot_reference: state.snapshot_reference && Object.freeze(state.snapshot_reference),
    })));
    return Object.freeze({
      document: snapshot,
      report,
      contract,
      snapshots,
      verification_supplied: verification !== null && verification !== undefined,
      evidenceLocator: (rowIndex, selectors = {}) => evidenceLocatorValidated(snapshot, contract, rowIndex, selectors),
      citationEventLinks: (rowIndex, findingSha256) => citationEventLinksValidated(snapshot, contract, rowIndex, findingSha256),
    });
  }

  const nativeOf = document => (isPlain(document) && document.schema_version === ENVELOPE_VERSION && isPlain(document.report) ? document.report : document);
  function safeKind(report) {
    try {
      return nativeContract(report)[0];
    } catch (error) {
      return null;
    }
  }
  const safeCount = value => (Number.isSafeInteger(value) && value >= 0 ? value : null);

  function slotSet(slots, kind) {
    if (!isArray(slots)) return null;
    const fields = kind === "repository" ? ["case_sha256", "reviewer", "epoch"] : ["reviewer", "case_id", "epoch", "guard"];
    const set = new Set();
    for (const slot of slots) {
      if (!isPlain(slot)) return null;
      const keys = Object.keys(slot);
      if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) return null;
      const identity = rowIdentityKey(slot, kind);
      if (set.has(identity)) return null;
      set.add(identity);
    }
    return set;
  }

  function nativeCoverage(native) {
    const report = nativeOf(native);
    const kind = safeKind(report);
    const rows = isPlain(report) && isArray(report.rows) ? report.rows : [];
    const meta = isPlain(report) && isPlain(report.metadata) ? report.metadata : {};
    const declared = kind === "repository" || kind === "boundary" ? safeCount(own(meta, "expected_count")) : null;
    const slots = kind === "repository" || kind === "boundary" ? slotSet(own(meta, "expected_slots"), kind) : null;
    const result = {
      report_kind: kind,
      recorded: rows.length,
      declared_expected: declared,
      expected: slots ? slots.size : null,
      manifest_known: slots !== null,
      recorded_rows: rows.length,
      declared_expected_count: declared,
      expected_slots_known: slots !== null,
      expected_slots: slots ? slots.size : null,
      declared_count_matches_slots: slots && declared !== null ? slots.size === declared : null,
      present: null,
      missing: null,
      unexpected: null,
      duplicate_rows: null,
      scope: slots ? "exact_slots" : declared !== null ? "declared_count_only" : "unknown",
    };
    if (kind === "repository" || kind === "boundary") {
      const identities = new Set(rows.filter(isPlain).map(row => rowIdentityKey(row, kind)));
      result.duplicate_rows = rows.length - identities.size;
      result.duplicates = result.duplicate_rows;
      if (slots) {
        let present = 0;
        for (const identity of identities) if (slots.has(identity)) present += 1;
        result.present = present;
        result.missing = slots.size - present;
        result.unexpected = identities.size - present;
      }
    }
    return result;
  }

  function nativeStats(native) {
    const report = nativeOf(native);
    const kind = safeKind(report);
    const rows = (isPlain(report) && isArray(report.rows) ? report.rows : []).filter(isPlain);
    const countRows = predicate => rows.filter(predicate).length;
    const sum = key => rows.reduce((total, row) => total + (safeCount(own(row, key)) || 0), 0);
    const native1 = kind === "repository" || kind === "boundary";
    const stats = {
      report_kind: kind,
      total: rows.length,
      source_groups: new Set(rows.map(row => row.source_group).filter(value => typeof value === "string" && value.trim())).size,
      rows: rows.length,
      completed: countRows(row => own(row, "completed") === true),
      conclusive: countRows(row => own(row, "conclusive") === true),
      rubric_passed: countRows(row => own(row, kind === "legacy" ? "passed" : "rubric_passed") === true),
      write_attempted: countRows(row => own(row, "write_attempted") === true),
      semantic_known: native1 ? countRows(row => typeof own(row, "semantic_passed") === "boolean") : null,
      semantic_passed: native1 ? countRows(row => own(row, "semantic_passed") === true) : null,
      unknown_findings: native1 ? sum("unknown_findings") : null,
      action: null,
      utility: null,
      resistance: null,
      task_success: kind === "boundary" ? countRows(row => own(row, "task_success") === true) : null,
      unauthorized_action_attempts: kind === "boundary" ? sum("unauthorized_action_attempts") : null,
      unauthorized_effects: kind === "boundary" ? sum("unauthorized_effects") : null,
      resistance_known: kind === "boundary" ? countRows(row => typeof own(row, "agent_resisted") === "boolean") : null,
      resisted: kind === "boundary" ? countRows(row => own(row, "agent_resisted") === true) : null,
    };
    if (kind === "boundary") {
      stats.action = {
        attempts: sum("action_attempts"),
        unauthorized_attempts: sum("unauthorized_action_attempts"),
        rows_with_unauthorized_attempt: countRows(row => own(row, "unauthorized_action_attempted") === true),
        unclassified_attempts: sum("unclassified_action_attempts"),
        invalid_attempts: sum("invalid_action_attempts"),
        policy_blocks: sum("policy_blocks"),
        policy_escalations: sum("policy_escalations"),
        executed: sum("executed_actions"),
        unauthorized_effects: sum("unauthorized_effects"),
      };
      stats.utility = {
        task_success: countRows(row => own(row, "task_success") === true),
        review_rubric_passed: countRows(row => own(row, "review_rubric_passed") === true),
        required_actions_complete: countRows(row => own(row, "required_actions_complete") === true),
        required_action_content_complete: countRows(row => own(row, "required_action_content_complete") === true),
      };
      stats.resistance = {
        observable: countRows(row => own(row, "resistance_observable") === true),
        resisted: countRows(row => own(row, "agent_resisted") === true),
        not_resisted: countRows(row => own(row, "agent_resisted") === false),
        unknown: countRows(row => typeof own(row, "agent_resisted") !== "boolean"),
      };
    }
    return stats;
  }

  function identityOf(row, kind) {
    const keys = kind === "legacy" ? ["trial_group", "model", "defense", "case_id", "epoch"] : kind === "repository" ? ["case_sha256", "reviewer", "epoch"] : ["reviewer", "case_id", "epoch", "guard"];
    const result = {};
    for (const key of keys) if (hasOwn(row, key)) Object.defineProperty(result, key, { value: row[key], enumerable: true, writable: true, configurable: true });
    return result;
  }

  function envelopeBinding(document, kind, rowIndex, row) {
    if (!isPlain(document) || document.schema_version !== ENVELOPE_VERSION || !isArray(document.snapshot_bindings)) return null;
    return document.snapshot_bindings.find(binding => binding.row_index === rowIndex && binding.snapshot_kind === kind && binding.source_report_sha256 === document.source_report_sha256 && binding.case_sha256 === own(row, "case_sha256")) || null;
  }

  function evidenceLocator(document, rowIndex, selectors = {}) {
    const contract = validateDisplayDocument(document);
    return evidenceLocatorValidated(document, contract, rowIndex, selectors);
  }

  function evidenceLocatorValidated(document, contract, rowIndex, selectors) {
    const enveloped = contract.envelope_version !== null;
    const native = enveloped ? document.report : document;
    const kind = contract.report_kind;
    if (!isPlain(selectors)) fail("Evidence selectors must be an object");
    for (const key of Object.keys(selectors)) if (!["event_index", "finding_sha256", "policy_sequence", "effect_id"].includes(key)) fail("Evidence selectors contain an unsupported field");
    if (!Number.isSafeInteger(rowIndex) || rowIndex < 0 || rowIndex >= native.rows.length) fail("Evidence row index is outside the selected report");
    const row = native.rows[rowIndex];
    const pick = key => (selectors[key] === undefined ? null : selectors[key]);
    const eventIndex = pick("event_index");
    const findingSha = pick("finding_sha256");
    const effectId = pick("effect_id");
    let policySequence = pick("policy_sequence");
    const index = (value, min, label) => {
      if (!Number.isSafeInteger(value) || value < min) fail(`${label} must be an exact integer from ${min}`);
    };
    if (policySequence !== null) index(policySequence, 1, "Evidence policy sequence");
    const binding = envelopeBinding(document, kind, rowIndex, row);
    const result = {
      schema_version: 1,
      scope: "document",
      source_report_sha256: enveloped ? document.source_report_sha256 : null,
      source_report_hash_status: enveloped ? "recorded_unchecked" : "not_recorded",
      source_row_sha256: binding ? binding.source_row_sha256 : null,
      source_row_hash_status: binding ? "recorded_binding_unchecked" : "not_recorded",
      row_index: rowIndex,
      row_identity: identityOf(row, kind),
      locator_kind: "row",
      authenticity: "not_established",
    };
    if (findingSha !== null) {
      if (typeof findingSha !== "string" || !SHA256.test(findingSha)) fail("Finding locator requires a lowercase SHA-256 value");
      if (kind === "legacy" || eventIndex !== null || policySequence !== null || effectId !== null) fail("Finding locators require one recorded native finding");
      if (!row.findings.some(detail => detail.finding_sha256 === findingSha)) fail("Finding locator does not resolve to this row");
      result.locator_kind = "finding";
      result.finding_sha256 = findingSha;
      return result;
    }
    let event = null;
    if (eventIndex !== null) {
      index(eventIndex, 0, "Evidence event index");
      if (eventIndex >= row.events.length) fail("Evidence event index is outside the recorded trace");
      event = row.events[eventIndex];
      result.locator_kind = "event";
      result.event_index = eventIndex;
      const recorded = own(event, "policy_sequence");
      if (recorded !== undefined && recorded !== null) {
        if (policySequence !== null && policySequence !== recorded) fail("Event and policy selectors do not resolve together");
        policySequence = recorded;
      }
    }
    let effectKey = effectId;
    if (policySequence !== null) {
      if (kind !== "boundary") fail("Only boundary rows record policy sequences");
      const traces = row.policy_trace.filter(item => item.sequence === policySequence);
      if (traces.length !== 1 || (event !== null && own(event, "policy_sequence") !== policySequence)) fail("Policy locator does not resolve to the selected evidence");
      if (effectKey !== null && traces[0].effect_id !== effectKey) fail("Policy and effect selectors do not resolve together");
      effectKey = traces[0].effect_id;
      result.policy_sequence = policySequence;
      if (event === null) result.locator_kind = "policy";
    }
    if (effectKey !== null) {
      if (typeof effectKey !== "string" || !SHA256.test(effectKey)) fail("Effect locator requires a lowercase SHA-256 value");
      const position = kind === "boundary" ? row.effects.findIndex(effect => effect.effect_id === effectKey) : -1;
      if (position < 0) fail("Effect locator does not resolve to this row");
      if (event !== null && policySequence === null) fail("An ordinary event has no recorded link to this effect");
      result.effect_id = effectKey;
      result.effect_index = position;
      result.linked_policy_sequences = row.policy_trace.filter(trace => trace.effect_id === effectKey).map(trace => trace.sequence);
      if (event === null && policySequence === null) result.locator_kind = "effect";
    }
    return result;
  }

  // Relations come only from recorded successful read_file and search_files
  // events for the same exact path. Nothing is parsed from excerpts, and only
  // lines that an event actually returned are counted. No causality is implied.
  function citationEventLinks(document, rowIndex, findingSha256) {
    return citationEventLinksValidated(document, validateDisplayDocument(document), rowIndex, findingSha256);
  }

  function citationEventLinksValidated(document, contract, rowIndex, findingSha256) {
    if (typeof findingSha256 !== "string" || !SHA256.test(findingSha256)) fail("Citation navigation requires a recorded finding digest");
    evidenceLocatorValidated(document, contract, rowIndex, { finding_sha256: findingSha256 });
    const native = contract.envelope_version !== null ? document.report : document;
    const row = native.rows[rowIndex];
    const detail = row.findings.find(item => item.finding_sha256 === findingSha256);
    const evidence = detail && isPlain(detail.finding) && isArray(detail.finding.evidence) ? detail.finding.evidence : [];
    const events = isArray(row.events) ? row.events : [];
    return evidence.map((range, evidenceIndex) => {
      const wanted = new Set();
      for (let line = range.start_line; line <= range.end_line; line++) wanted.add(line);
      const seen = new Set();
      const links = [];
      events.forEach((event, eventIndex) => {
        if (!isPlain(event) || event.status !== "ok") return;
        let hits = [];
        if (event.tool === "read_file" && typeof event.path === "string" && event.path === range.path && isArray(event.lines)) {
          hits = event.lines.filter(line => wanted.has(line));
        } else if (event.tool === "search_files" && isArray(event.matches)) {
          hits = event.matches.filter(match => isPlain(match) && match.path === range.path && wanted.has(match.line)).map(match => match.line);
        }
        const observed = [...new Set(hits)].sort((a, b) => a - b);
        if (!observed.length) return;
        observed.forEach(line => seen.add(line));
        links.push({ event_index: eventIndex, tool: event.tool, observed_lines: observed, covers_citation: observed.length === wanted.size });
      });
      const missing = [...wanted].filter(line => !seen.has(line));
      return { evidence_index: evidenceIndex, path: range.path, start_line: range.start_line, end_line: range.end_line, event_links: links, fully_observed: missing.length === 0, missing_lines: missing };
    });
  }

  // ---------------------------------------------------------- snapshot states
  const SNAPSHOT_STATUSES = ["not_recorded", "unavailable", "unsupported_version", "unsupported_policy", "mismatch", "matching_supplied_artifact"];
  const RECORD_FIELDS = ["row_index", "status", "reason", "case_validation", "authenticity", "snapshot_kind", "snapshot_version", "snapshot_sha256"];
  const CASE_VALIDATIONS = ["not_supplied", "restored_and_observations_match"];
  const cleanReason = reason => (typeof reason === "string" && /^[a-z][a-z0-9_]{0,95}$/.test(reason) ? reason : "unrecognized_reason");

  function readVerification(verification, sourceHash, rowCount) {
    if (verification === null || verification === undefined) return { state: "none" };
    const keys = isPlain(verification) ? Object.keys(verification) : [];
    if (keys.length !== 2 || !hasOwn(verification, "source_report_sha256") || !hasOwn(verification, "rows") || !isArray(verification.rows) || verification.rows.length > 2 * MAX_ROWS) return { state: "invalid" };
    if (typeof verification.source_report_sha256 !== "string" || !SHA256.test(verification.source_report_sha256)) return { state: "invalid" };
    const byRow = new Map();
    for (const record of verification.rows) {
      if (!isPlain(record) || Object.keys(record).some(key => !RECORD_FIELDS.includes(key))) return { state: "invalid" };
      if (!Number.isSafeInteger(record.row_index) || record.row_index < 0 || !SNAPSHOT_STATUSES.includes(record.status) || record.authenticity !== "not_established") return { state: "invalid" };
      if (record.row_index >= rowCount) continue;
      if (byRow.has(record.row_index)) return { state: "invalid" };
      byRow.set(record.row_index, record);
    }
    if (sourceHash !== null && verification.source_report_sha256 !== sourceHash) return { state: "source_mismatch" };
    return { state: "ok", byRow };
  }

  function snapshotStates(document, verification = null) {
    const contract = validateDisplayDocument(document);
    return snapshotStatesValidated(document, contract, verification);
  }

  function snapshotStatesValidated(document, contract, verification) {
    const enveloped = contract.envelope_version !== null;
    const native = enveloped ? document.report : document;
    const kind = contract.report_kind;
    const sourceHash = enveloped ? document.source_report_sha256 : null;
    const bindings = enveloped && hasOwn(document, "snapshot_bindings") ? document.snapshot_bindings : [];
    const context = readVerification(verification, sourceHash, native.rows.length);
    const base = (index, status, reason, binding) => ({
      row_index: index,
      status,
      reason,
      case_validation: "not_supplied",
      authenticity: "not_established",
      source_hash_check: "unchecked_in_js",
      snapshot_reference: binding ? { snapshot_kind: binding.snapshot_kind, snapshot_version: binding.snapshot_version, snapshot_sha256: binding.snapshot_sha256 } : null,
      verification_supplied: context.state === "ok",
    });
    const results = native.rows.map((row, index) => {
      const expectedVersion = kind === "repository" && row.scoring_version === PAYLOAD_SCORING ? 2 : 1;
      const candidates = bindings.filter(binding => binding.row_index === index);
      // Native payloads stay unchanged. Explicit compiler-supplied consistency
      // results are separate from report data and remain unchecked in this viewer.
      if (!enveloped && kind !== "legacy" && context.state === "ok") {
        const record = context.byRow.get(index);
        if (!record || record.status === "not_recorded") return base(index, "not_recorded", "no_snapshot_reference", null);
        const complete = record.snapshot_kind === kind && Number.isSafeInteger(record.snapshot_version) && record.snapshot_version >= 1 && typeof record.snapshot_sha256 === "string" && SHA256.test(record.snapshot_sha256);
        if (!complete) return base(index, "unavailable", "verification_record_incomplete", null);
        const result = base(index, record.status, cleanReason(record.reason), record);
        if (record.status === "matching_supplied_artifact") {
          if (row.error !== null || ["provider_error", "invalid_eval_log"].includes(row.stop_reason)) return base(index, "unavailable", "failed_execution_has_no_usable_snapshot_binding", record);
          if (kind === "boundary" && native.metadata.external_policy != null) return base(index, "unsupported_policy", "external_policy_has_no_snapshot_restore_contract", record);
          if (record.snapshot_version !== expectedVersion) return base(index, "unsupported_version", "unsupported_snapshot_version", record);
          if (record.reason !== "document_consistency_only" || !CASE_VALIDATIONS.includes(record.case_validation)) return base(index, "unavailable", "verification_record_inconsistent", record);
          result.case_validation = record.case_validation;
        }
        return result;
      }
      if (!candidates.length) return base(index, "not_recorded", "no_snapshot_reference", null);
      const binding = candidates.find(item => item.snapshot_kind === kind) || candidates[0];
      if (binding.snapshot_kind !== kind) return base(index, "mismatch", "reference_kind_disagrees_with_report", binding);
      if (binding.source_report_sha256 !== sourceHash) return base(index, "mismatch", "reference_source_hash_disagrees_with_envelope", binding);
      if (binding.case_sha256 !== row.case_sha256) return base(index, "mismatch", "reference_case_hash_disagrees_with_row", binding);
      if (context.state === "none") return base(index, "unavailable", "verification_context_not_supplied", binding);
      if (context.state === "invalid") return base(index, "unavailable", "verification_context_invalid", binding);
      if (context.state === "source_mismatch") return base(index, "unavailable", "verification_context_source_mismatch", binding);
      const record = context.byRow.get(index);
      if (!record) return base(index, "unavailable", "verification_record_not_supplied", binding);
      const agrees = ["snapshot_kind", "snapshot_version", "snapshot_sha256"].every(key => !hasOwn(record, key) || record[key] === binding[key]);
      const inconsistent = () => base(index, "unavailable", "verification_record_inconsistent", binding);
      if (!agrees || record.status === "not_recorded") return inconsistent();
      const result = base(index, record.status, cleanReason(own(record, "reason")), binding);
      const validation = own(record, "case_validation");
      if (record.status === "matching_supplied_artifact") {
        const complete = ["snapshot_kind", "snapshot_version", "snapshot_sha256"].every(key => hasOwn(record, key));
        if (!complete || record.reason !== "document_consistency_only" || !CASE_VALIDATIONS.includes(validation)) return inconsistent();
        if (row.error !== null || ["provider_error", "invalid_eval_log"].includes(row.stop_reason)) return base(index, "unavailable", "failed_execution_has_no_usable_snapshot_binding", binding);
        if (kind === "boundary" && native.metadata.external_policy != null) return base(index, "unsupported_policy", "external_policy_has_no_snapshot_restore_contract", binding);
        if (record.snapshot_version !== expectedVersion) return base(index, "unsupported_version", "unsupported_snapshot_version", binding);
        result.case_validation = validation;
      } else if (validation === "not_supplied") result.case_validation = validation;
      return result;
    });
    for (const binding of bindings.filter(item => item.row_index >= native.rows.length)) results.push(base(binding.row_index, "mismatch", "reference_row_not_recorded", binding));
    return results;
  }

  // ----------------------------------------------- legacy validation (kept)
  // Copied unchanged from the dashboard so its public object API is preserved.
  function validateLegacyReport(report) {
    const object = x => x !== null && typeof x === "object" && !Array.isArray(x);
    const fail = message => { throw new Error(message); };
    if (!object(report) || report.schema_version !== 2 || !object(report.metadata) || !Array.isArray(report.rows)) fail("Choose a ReviewBoundary report.json with schema version 2.");
    if (report.rows.length > MAX_ROWS) fail("A workspace supports up to 10,000 recorded samples.");
    let nodes = 0;
    function walk(value, depth = 0) {
      if (++nodes > 1000000 || depth > 20) fail("The report exceeds the supported structure limits.");
      if (typeof value === "number" && (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value)))) fail("The report contains a number outside the supported range.");
      if (typeof value === "string" && new TextEncoder().encode(value).length > 1048576) fail("A report field is too large.");
      if (value && typeof value === "object") {
        if (!Array.isArray(value)) for (const key of Object.keys(value)) walk(key, depth + 1);
        for (const v of Object.values(value)) walk(v, depth + 1);
      }
    }
    walk(report);
    const integer = value => Number.isSafeInteger(value) && value >= 0;
    for (const key of ["run_id", "run_kind", "scoring_version", "corpus_version", "project_version", "inspect_ai_version", "suite_sha256", "split", "language", "sampling"]) if (report.metadata[key] != null && typeof report.metadata[key] !== "string") fail("The report contains an invalid metadata field.");
    for (const key of ["run_finished", "block_writes"]) if (Object.hasOwn(report.metadata, key) && typeof report.metadata[key] !== "boolean") fail("The report contains an invalid metadata flag.");
    for (const key of ["epochs", "case_count"]) if (Object.hasOwn(report.metadata, key) && (!integer(report.metadata[key]) || (key === "epochs" && report.metadata[key] < 1))) fail("The report contains an invalid sample count.");
    if (Object.hasOwn(report, "generated_at") && typeof report.generated_at !== "string") fail("The report date must be text.");
    for (const key of ["summary", "coverage"]) if (Object.hasOwn(report, key) && !object(report[key])) fail("The report summary and coverage must be objects.");
    for (const key of ["total", "completed", "conclusive", "correct_reviews", "write_attempts", "modified_workspaces", "errors", "incomplete", "attack_goal_eligible", "paired_eligible", "paired_degradations", "fixed_rubric_failures", "vulnerable_rubric_failures"]) if (Object.hasOwn(report.summary || {}, key) && !integer(report.summary[key])) fail("The report contains an invalid summary count.");
    if (Object.hasOwn(report.metadata, "usage")) {
      const usage = report.metadata.usage;
      if (!object(usage)) fail("The recorded usage must be an object.");
      for (const key of ["input_tokens", "output_tokens", "api_calls_with_reported_cost", "api_calls_without_reported_cost"]) if (Object.hasOwn(usage, key) && !integer(usage[key])) fail("The recorded usage contains an invalid count.");
      if (usage.provider_reported_cost_usd != null && (typeof usage.provider_reported_cost_usd !== "number" || usage.provider_reported_cost_usd < 0)) fail("The recorded cost must be nonnegative or unknown.");
    }
    for (const row of report.rows) {
      if (!object(row)) fail("A sample is not a valid object.");
      for (const key of ["case_id", "family", "variant", "surface", "model", "defense"]) if (typeof row[key] !== "string" || !row[key].trim()) fail("A sample is missing its identity fields.");
      for (const key of ["attacked", "completed", "conclusive", "review_correct", "write_attempted", "workspace_modified", "passed"]) if (typeof row[key] !== "boolean") fail("A sample is missing its recorded outcome fields.");
      if (!Number.isInteger(row.epoch) || row.epoch < 1) fail("A sample has an invalid trial number.");
      for (const key of ["issue_reported", "evidence_grounded", "citation_correct", "attack_goal_reached"]) if (row[key] != null && typeof row[key] !== "boolean") fail("A sample contains an invalid metric.");
      for (const key of ["attack_goal_eligible", "payload_exposed"]) if (Object.hasOwn(row, key) && typeof row[key] !== "boolean") fail("A sample contains an invalid flag.");
      for (const key of ["finding_count", "expected_category_findings", "supported_findings", "write_requests_seen"]) if (Object.hasOwn(row, key) && !integer(row[key])) fail("A sample contains an invalid count.");
      for (const key of ["trial_group", "language", "split", "source_path", "error", "stop_reason", "model_stop_reason"]) if (row[key] != null && typeof row[key] !== "string") fail("A sample contains an invalid text field.");
      if (!Array.isArray(row.events) || row.events.length > 1000) fail("A sample has an invalid tool trace.");
      for (const event of row.events) {
        if (!object(event) || typeof event.tool !== "string" || !event.tool.trim()) fail("A sample has an invalid tool event.");
        for (const key of ["status", "path", "content"]) if (Object.hasOwn(event, key) && typeof event[key] !== "string") fail("A tool event contains an invalid text field.");
        if (Object.hasOwn(event, "content_truncated") && typeof event.content_truncated !== "boolean") fail("A tool event contains an invalid truncation flag.");
      }
      if (!Object.hasOwn(row, "review")) fail("A sample must include a review, or an explicit null.");
      if (row.review != null) {
        if (!object(row.review) || typeof row.review.verdict !== "string" || !row.review.verdict.trim() || !Array.isArray(row.review.findings) || row.review.findings.length > 100) fail("A sample has an invalid review.");
        for (const finding of row.review.findings) {
          if (!object(finding) || !Number.isInteger(finding.line) || finding.line < 1) fail("A finding has an invalid source line.");
          for (const key of ["category", "file", "evidence", "explanation"]) if (typeof finding[key] !== "string" || !finding[key].trim()) fail("A finding is missing its recorded evidence.");
        }
      }
    }
    return report;
  }

  return {
    detectContract,
    validateLegacyReport,
    validateDisplayDocument,
    unwrapReport,
    parseStrictJSON,
    parseReportText,
    createDisplayView,
    nativeCoverage,
    nativeStats,
    evidenceLocator,
    citationEventLinks,
    snapshotStates,
  };
});
