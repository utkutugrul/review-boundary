# Reports, exports, and evidence

One local dashboard accepts the existing synthetic reports and the native
repository and action-boundary reports. Their measurements stay separate:

| Native report | Discriminators | What remains visible |
| --- | --- | --- |
| Synthetic suite | `schema_version: 2`, no `report_kind` | Review outcomes, clean controls, write attempts |
| Repository | `schema_version: 1`, `report_kind: "repository"` | Structural rubric, citations, findings, explicit adjudication |
| Action boundary | `schema_version: 1`, `report_kind: "boundary"` | Review quality, task utility, policy decisions, virtual effects |

A version 3 envelope wraps one of these documents unchanged. It records the
native kind and version, its canonical `source_report_sha256`, and optional
snapshot references. Wrapping does not add judgments, infer missing coverage,
or turn a virtual effect into a real action.

## Open recorded runs

These commands make two offline scripted examples and combine them with a
recorded legacy example. Use new or empty demo output directories.

```sh
uv run --frozen review-boundary repository-demo --output runs/repository-demo
uv run --frozen review-boundary boundary-demo --output runs/boundary-demo
uv run --frozen review-boundary dashboard \
  examples/calibration-v2/report.json \
  runs/repository-demo/report.json runs/boundary-demo/report.json \
  --output reports/combined.html
```

Open `reports/combined.html`. You can also import native or version 3 JSON in the
browser. The dashboard runs locally and starts no model evaluations. Exporting
a selected report retains its original document, including its envelope when
present. See the [dashboard guide](dashboard.md) for navigation and legacy pairs.

## Export a version 3 envelope

```sh
uv run --frozen review-boundary report-export runs/repository-demo/report.json \
  --output reports/repository.v3.json
```

The output must be a new file. Its creation is private and exclusive; an existing
file or output symlink is refused. Export is deterministic for identical inputs
and adds no current timestamp. It accepts a native document or a valid existing
envelope and preserves recorded fields and nulls. Canonical JSON hashes identify
the parsed data, not the source file's whitespace or key order.

## Supply local snapshots

Snapshot references are optional. Keep full snapshots locally, separate from the
public envelope. They may contain source text and other evaluator material.

The snapshot-artifact JSON has exactly three fields: `schema_version: 1`,
`source_report_sha256`, and `snapshots`. Each list item has exactly `row_index`,
`source_row_sha256`, and `snapshot`. Indices are zero-based and unique. Hashes
refer to the native report and its original row, even when the input is an
envelope. Extra fields, including paths or claimed verification results, are
rejected.

A Python integration can produce this file while it retains the original world
that produced a row. This helper uses the actual world snapshot and checks its
binding before writing a new private file:

```python
import json
from pathlib import Path

from review_boundary.provenance import json_digest
from review_boundary.report_contract import unwrap_report
from review_boundary.report_export import prepare_report_export
from review_boundary.repository_adjudication import write_new_text


def save_snapshot_artifact(document, row_index, world, output: Path):
    native = unwrap_report(document)
    artifacts = {
        "schema_version": 1,
        "source_report_sha256": json_digest(native),
        "snapshots": [
            {
                "row_index": row_index,
                "source_row_sha256": json_digest(native["rows"][row_index]),
                "snapshot": world.snapshot(),
            }
        ],
    }
    prepare_report_export(native, snapshot_artifacts=artifacts)
    return write_new_text(output, json.dumps(artifacts) + "\n", "snapshot artifacts")
```

Use that integration's report, artifact, and original suite together:

```sh
uv run --frozen review-boundary report-export run/report.json \
  --snapshot-artifacts local-snapshots.json --suite run/suite.json \
  --output reports/with-references.v3.json
uv run --frozen review-boundary dashboard reports/with-references.v3.json \
  --snapshot-artifacts local-snapshots.json --suite run/suite.json \
  --output reports/with-evidence.html
```

`--suite` is optional JSON data with exactly `schema_version: 1` and `cases`,
containing one to 32 original cases. With it, Python restores supplied snapshots
and checks observations against those cases. Without it, `case_validation` stays
`not_supplied`; matching checks only the supplied artifact and recorded data.
Snapshot evidence options require exactly one dashboard report.

When artifacts are supplied, source-report, row, case, limits, policy, or snapshot
mismatches fail before output is written. Missing references stay `not_recorded`;
references without supplied artifacts stay `unavailable`. Legacy reports have no
native world snapshot contract. Failed execution rows have no usable binding, and
boundary snapshots with external policy callbacks cannot be restored. Unsupported
snapshot versions cannot establish a matching binding.

`matching_supplied_artifact` means consistency with explicitly supplied data.
It does not establish who produced the artifacts, whether they came from a real
run, or whether evaluator judgments are correct. Python checks canonical hashes;
the browser labels hashes as unchecked and displays supplied Python results
separately. Importing raw JSON clears those external results. A report cannot
grant itself a matching status through its metadata.

## Compare compatible reports

`compare` accepts native reports and their envelopes, dispatching by exact kind.
It compares one selected group on each side:

| Report kind | Selectors |
| --- | --- |
| Synthetic | `--baseline-model`, `--baseline-defense`, `--candidate-model`, `--candidate-defense` |
| Repository | `--baseline-reviewer`, `--candidate-reviewer` |
| Boundary | Reviewer selectors plus `--baseline-guard`, `--candidate-guard` (`on` or `off`) |

Use the exact labels recorded in each report. Multiple groups are not pooled;
changing a reviewer, model, defense, or guard requires both corresponding
selectors. A single identical group needs no selector.

For example, select the two guard arms in the scripted boundary report:

```sh
uv run --frozen review-boundary compare \
  runs/boundary-demo/report.json runs/boundary-demo/report.json \
  --baseline-reviewer reference --candidate-reviewer reference \
  --baseline-guard off --candidate-guard on \
  --expected-suite runs/boundary-demo/suite.json \
  --output reports/guard-comparison.json
```

`--expected-suite` supplies bounded case data, in the same format as `--suite`.
It can establish expected slots for older native reports that lack them, only
when it binds to each report's suite, input, and policy identities. Scoring,
case identity, epochs, execution bounds, and other required experiment settings
must remain compatible. A partial report can be displayed without establishing
a comparison baseline.

Exit `0` means no new regressions; `1` means a regression, including a missing
candidate sample; `2` means invalid or incompatible inputs. Missing baseline
coverage, ambiguous groups, or an explicitly unfinished native run are invalid.
Known observations becoming unknown are losses. Newly available adjudication is
reported as evidence availability, not a model improvement. The
[legacy comparison guide](comparison.md) retains its original metric policy.

## Read unknowns honestly

Unjudged semantic results stay `null`. Missing coverage declarations cannot prove
a complete run. Provider errors remain visible and unjudged. Missing or partial
cost and timing evidence stays unknown; observed subtotals are not complete run
totals or invoices. Scripted calibration is not a model measurement.

Evidence links locate content inside one report using its digest, row index,
event index, finding digest, or recorded policy/effect link. Ordinary events do
not acquire invented causal identifiers. Boundary effects remain virtual. A
passing comparison can retain existing baseline failures and does not establish
production safety or a ranking across unrelated suites.
