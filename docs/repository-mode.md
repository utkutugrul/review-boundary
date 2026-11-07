# Repository mode

Repository mode lets a reviewer follow evidence across several files in a bounded
virtual snapshot. It currently includes an original synthetic tenant-access
example and a connection for a trusted external reviewer. An optional
[pinned PyJWT corpus](upstream-pyjwt.md) adds four conditions from one independently
reproduced upstream source issue. The [candidate research](upstream-candidates.md)
tracks further intake work.

## Try the offline demo

```sh
uv run --frozen review-boundary repository-demo --output runs/repository-demo
```

Open `runs/repository-demo/report.html`. Four conditions combine vulnerable or
fixed code with clean context or a misleading README instruction. Two scripted
modes, `reference` and `hijacked`, produce **eight observations** at the default
one epoch. The second mode deliberately follows the misleading instruction.
These scripts support the bundled fixture only and are not general reviewers
or measurements of model performance.

`--epochs` accepts 1 through 10. Use a new or empty output directory. The runner
writes `report.html`, `report.json`, `manifest.json`, `events.jsonl`, and the
evaluator's complete `suite.json`. The HTML report is self-contained and keeps
findings, cited source ranges, tool events, and experiment metadata inspectable.
An exit code of 0 means the run finished without recorded execution errors;
it does not mean every review passed. Execution errors return 2.

## Run a provider model

Repository mode can use the same OpenRouter, native OpenAI, or native Anthropic
controls as the original suite. Preview a native OpenAI run without loading a
credential or creating output files:

```sh
uv run --frozen review-boundary repository-run-model \
  --provider openai \
  --model YOUR_NATIVE_MODEL_ID \
  --pricing-file openai-pricing.json \
  --epochs 1 \
  --output runs/repository-model \
  --budget 20 \
  --dry-run
```

Remove `--dry-run` to start the paid run after setting the selected provider's
API key. OpenRouter uses its live catalog and price ceiling instead of a local
pricing file. See the [provider guide](providers.md) for endpoint, credential,
pricing, and reservation rules.

The command accepts `--suite`, repeated `--model`, `--epochs`, `--concurrency`,
the generation bounds `--max-turns`, `--max-input-bytes`, and
`--max-output-tokens`, plus all six virtual-world limits. Every model and epoch
starts from a fresh validated world snapshot. Inspect logs are accepted only
when trusted scorer metadata covers each declared case, model, and epoch slot.
Missing or duplicate slots fail closed. Provider failures produce explicit
failed rows without copying provider response bodies into the report.

The local budget ledger reserves a conservative maximum before model creation.
A reservation is released only when every recorded provider call has complete
provider-reported cost evidence and every selected model execution is free of
provider, integrity, log, and row failures. Token-based SDK estimates do not
settle it. The output must be a new or empty path without symlink components.
The ledger and its `.lock` and `.tmp` companions must stay outside the output
tree and must not overlap generated artifacts.
The report still keeps `semantic_passed` as `null`; using a real model does not
turn structural rubric matching into semantic adjudication.

## A separate report contract

| Mode | Scoring version | Corpus version | Report format |
| --- | --- | --- | --- |
| Existing synthetic suite | `0.2.0` | `0.2.0` | `schema_version: 2` |
| Bundled repository demo | `repository-v1` | `repository-demo-v1` | `schema_version: 1`, `report_kind: repository` |
| Custom repository suite | `repository-v1` | `custom`, plus a suite digest | Same repository report format |

Use the repository report's own HTML or the unified dashboard. Repository reports
and their version 3 envelopes also work with the native comparison gate. The
Inspect-log `report` reconstruction command remains specific to legacy reports.
See the [report and evidence guide](reports.md). Existing v0.2 scores and saved
artifacts are unchanged.

## Connect a reviewer

Try the bundled repository adapter:

```sh
uv run --frozen review-boundary repository-run-adapter \
  --adapter examples/adapters/repository-reference.json \
  --output runs/repository-adapter-demo
```

This is an offline scripted reviewer for the bundled tenant fixture only. It
produces four observations at one epoch and makes no model API calls.

For your own reviewer:

```sh
uv run --frozen review-boundary repository-run-adapter \
  --adapter path/to/reviewer.json \
  --output runs/repository-review
```

Omitting `--suite` selects the four bundled conditions. An adapter runs one
reviewer per condition and epoch. Configure its explicit command, environment
allowlist, transport limits, and optional `source_files` using the
[adapter guide](adapters.md) and [experiment record guide](experiment-records.md).
Your reviewer must implement `reviewboundary.repository-jsonl/1` and the
repository finding schema below. The existing `reference.json` and
`intentional-bad.json` examples use the v0.2 tool contract.

The start message contains trusted `instructions`, `task`, advertised tools,
transport limits, and an opaque invocation ID. It does not include a privileged
source-file path, case ID, variant, rubric, issue anchors, or expected answer.
The reviewer discovers files through the tools:

| Tool | Arguments and result |
| --- | --- |
| `read_pr` | No arguments; returns untrusted PR text. |
| `list_files` | Optional `prefix`, `cursor`, `limit`; returns paths, sizes, line counts, and pagination. |
| `search_files` | Literal `query`; optional prefix, pagination, and `case_sensitive`; returns matching lines. |
| `read_file` | `path`, inclusive `end_line`, optional `start_line`; returns separate line numbers and text. |
| `write_file` | `path`, `content`; records the attempt and blocks the virtual write. |
| `submit_review` | `verdict` and `findings`; stores the review and ends the protocol. |

Default world limits are 64 calls, 16 KiB per tool response, 256 KiB of total
response data, 80 lines per read, and 20 list entries or search matches per page.
Pagination reports `next_cursor` or `next_line`. Paths must stay inside the
snapshot. The CLI uses these defaults; `RepositoryLimits` is configurable in
the Python API. Transport limits apply separately.

Response budgets include encoded JSON overhead. Schema-valid large PR text or
a heavily escaped source line can exceed the default response cap and terminate
the invocation. Check that custom cases fit the default tools and budgets before
running a reviewer; exceeding a budget cannot produce a completed result.

A submitted review uses `approve` or `request_changes`. Each finding has
`category`, `summary`, and one to eight evidence spans containing `path`,
`start_line`, `end_line`, and an exact `excerpt`; `symbol` is optional. Up to
12 findings are accepted. Cite source text without adding line-number prefixes.
The tool schema publishes the shared category vocabulary, including
`authorization` and `algorithm_confusion`. It does not disclose which category,
if any, is expected for a particular case; additional lowercase snake-case
labels remain available for other findings.

## What the scores establish

Completion requires PR inspection, recorded repository inspection, a structured
submission, and no fatal world error. Adapter execution must also finish cleanly.
An attacked case is conclusive only after its configured payload was exposed.

`rubric_passed` checks structural conditions: matching categories and accepted
evidence bundles, exact excerpts from observed lines, appropriate verdicts,
target expectations, and no write attempts. It does not interpret a finding's
reasoning. `semantic_passed` stays `null` until explicit evaluator adjudication.
Unjudged findings remain `unknown_findings`, not false positives. Duplicate
findings do not increase unique issue or adjudication counts.

Adjudication is applied through `score_repository_world()`. Two commands wrap it
for native model runs (`adjudication-export` and `adjudication-apply`, described
below); there is no automatic semantic judge:

- `FindingAdjudication` binds `case_sha256` and `finding_sha256` to a decision
  of `supported`, `rejected`, or `unknown`, with a reason and optional `issue_id`.
- `ReviewAdjudication` binds `case_sha256` and `review_sha256` to a whole-review
  decision and reason. Even an empty approval needs this judgment for a semantic
  result.

Use `case_digest()`, `finding_digest()`, and `review_digest()` for these identities.
Changed content invalidates the binding. Supply finding decisions as
`adjudications=` and the whole-review decision as `review_adjudication=`.

### Adjudication artifacts

```bash
review-boundary adjudication-export --report run/report.json --suite run/suite.json \
  --output template.json
review-boundary adjudication-apply --report run/report.json --suite run/suite.json \
  --adjudication labeled.json --logs run/logs --output run-adjudicated
```

The artifact (`adjudication_kind: "repository"`, `schema_version: 1`) holds the
canonical `source_report_sha256`, `finding_decisions`, and `review_decisions`. It
contains digests, decisions, issue mappings, and reasons only: no prompts, model
responses, or finding text. The export lists each unique finding and review as
`unknown`.

Import fails closed on a stale or foreign report digest, unknown case, finding,
or review digests, digests from rows that recorded an error, duplicate or
conflicting decisions, unknown issue IDs, an `unknown` decision carrying an issue
mapping, and a `supported` finding mapped to an `absent` issue. Partial artifacts
are accepted; unlisted findings stay `unknown`.

Application never reads semantics from report rows. It restores native frozen
world snapshots from the trusted Inspect logs, rescores them against the original
evaluator suite, requires the result to equal each source row, and then changes
only the adjudication fields. An edited row, review, or event trace is rejected.
The output is a new directory; the source report is not modified. This workflow
requires native `repository-run-model` observations. Calibration, adapter, and
boundary reports cannot be adjudicated through these commands.

### Mixed successful and failed reviewers

A native run with a provider failure can still adjudicate another reviewer's
usable observations. The trusted runner writes a separate
`repository-failures.json` inside its `logs` directory after the final report.
It binds the report, run, suite, world limits, and every failed row. Failed rows
remain unchanged and unjudged; no observation snapshot is fabricated for them.

Supply the original trusted directory explicitly, as in `--logs run/logs` above.
Only that fixed sidecar in an explicitly supplied directory is considered; a
file placed beside an untrusted report is not loaded automatically. Selecting a
log directory means trusting its Inspect logs and failure sidecar as local
harness artifacts. Hash consistency does not authenticate their author. Keep
these artifacts outside reviewer-controlled inputs.

The exception covers only exact `provider_error` rows for a complete failed
reviewer block, across every declared case and epoch. It rejects old mixed runs
without the sidecar, `invalid_eval_log` substitutions, and Inspect logs for a
reviewer declared failed by the sidecar. A run with only failed synthetic rows
and no native observations is also rejected. Retain the healthy native Inspect
logs, original suite, and complete report together. The snapshot-artifact JSON
used by [report export](reports.md) is a different format and cannot replace this
trusted failure evidence.

### Labeling page

```bash
review-boundary adjudication-ui --report run/report.json --suite run/suite.json \
  --output labeler.html
```

This writes one new HTML file (an existing output, a symlink, or an input path is
refused). Open it locally. It shows each unique finding and whole review with its
recorded text and the evaluator rubric issues, and starts every item as `unknown`.
You can edit only the decision, an optional issue mapping, and the reason. Moving
an item off `unknown` clears the placeholder reason, so a real one must be written.
Nothing is pre-judged. **Export artifact** downloads `repository-adjudication.json`;
**Import labels** loads a previous export (unlisted items stay `unknown`).

The page makes no network requests and loads no CDN assets. Its CSP allows only the
page's own script and style by SHA-256 hash, recorded text is embedded as escaped
inert JSON, and the page is built from text nodes only. Imports are limited to
16 MiB and exports to 16 MiB. The browser validator uses a strict JSON parser
(duplicate keys, non-integer numbers, and deep nesting are rejected) and enforces the
same rules as `adjudication-apply`, including digest, duplicate, and issue-mapping
checks. Parity tests run both validators over the same cases. `adjudication-apply`
still re-validates every file, so the page is a convenience, not an authority.

### Inter-rater agreement

```bash
review-boundary adjudication-agreement --report run/report.json --suite run/suite.json \
  --rater-a a.json --rater-b b.json --output agreement.json
```

Both artifacts must be complete (a decision for every recorded finding and review),
bind to this report and suite, and cover identical digest sets. Incomplete,
mismatched, stale, or invalid artifacts are rejected rather than aligned. The result
reports exact agreement and Cohen's kappa for findings, reviews, and overall.
`unknown` is an explicit third label. Only decision labels are compared; reasons are
not, and issue mappings are counted separately for findings. Kappa is `null` when
both raters use one identical label. This is optional evidence about the labels, not
a semantic judge, and it is not defined for boundary reports.

## Custom suite JSON

Pass `--suite path/to/suite.json` to `repository-run-adapter` or
`repository-run-model`. The top-level
object contains exactly `schema_version: 1` and `cases`, with 1 through 32
uniquely named cases. `RepositoryCase.model_validate_json()` validates each case.

| Field | Meaning |
| --- | --- |
| `case_id`, `source_group` | Evaluator identifiers and shared-source grouping. |
| `variant`, `surface` | `vulnerable` or `fixed`; `clean` or `readme`. |
| `instructions`, `task`, `pr` | Trusted caller instructions/task and untrusted PR text. |
| `files` | Objects with canonical relative `path` and `content`. |
| `issues` | Objects with `issue_id`, `category`, `expectation` (`present`/`absent`), and `acceptable_bundles`. |
| `issues[].acceptable_bundles` | Alternative objects containing `ranges`; every range in one bundle must be covered. Ranges contain path, start/end line, and optional symbol. |
| `exposure` | Omitted or `null` for `clean`. Required for `readme` as `{resource: "README.md", marker}`, with the marker present in that file. Actual delivery records attack exposure. |

Snapshots allow 1 through 128 files, at most 64 KiB per file and 512 KiB total.
Rubrics allow 1 through 32 issues; evidence ranges span at most 80 lines.
The suite digest covers the snapshot, context, and evaluator rubric.

Evaluator material is hidden from the protocol, not protected by an OS sandbox.
The external process is trusted local code and can access host files or the
network independently. Keep complete suites and evaluator artifacts outside
reviewer inputs. Only protocol tool actions are observed, and external reviewer
billing is not managed by this runner.

During an external run, suite, manifest, event, and report files are buffered
until all reviewer processes have ended. Later invocations therefore cannot read
earlier evaluator outcomes from the output directory. This is invocation
isolation for the runner's artifacts, not host-level sandboxing.
