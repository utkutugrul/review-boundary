# Workflow run report contract v1

`review_boundary.workflow_report` is a standalone library contract over delivered
CORE11 scored rows. A CORE11 row has `report_kind: workflow` and describes one
scored case. The new envelope has `report_kind: workflow_run`, integer
`schema_version: 1`, `contract_version: workflow-run-report-v1` and the unchanged
`scoring_version: workflow-scoring-v1`. No existing source or metric is replaced.

## Declare, assemble, validate

```python
from review_boundary.workflow_report import (
    assemble_workflow_run,
    declare_workflow_run,
    serialize_workflow_run,
    validate_workflow_run,
)

expected = declare_workflow_run(
    selected_core11_cases,
    binding={"run_id": "b" * 32, "reviewer": "scripted_calibration", "epoch": 1},
    guard="on",
    evidence_kind="scripted",
)
report = assemble_workflow_run(expected, unchanged_core11_scored_rows)
raw = serialize_workflow_run(report, expected=expected)
checked_report = validate_workflow_run(raw, expected=expected)
```

Declare the selected coverage before collecting rows. A report binds exactly one
run ID, reviewer label, epoch and guard. Repeated epochs or different guards need
separate reports. `expected.cases` contains each case ID, workflow case digest,
Source group, family, condition, variant and ordered session index/actor roster.
The factory derives these declarations from validated CORE11 case definitions.
The expected roster cannot be empty. Missing scored rows never shrink it.

`assemble_workflow_run` accepts a plain declaration object (or JSON object bytes)
and a bounded list/tuple of scored row objects or JSON object bytes. It returns a
detached plain JSON object. Rows retain every original CORE11 key and value,
including `report_kind`, nulls and refusal-verification labels. No row is rescored
or replayed. Lists of expected cases and scored cases sort by case ID; session
order stays fixed. Duplicate expected IDs/digests, duplicate rows, unexpected
cases, mismatched identities/bindings and inconsistent session coverage fail.

`validate_workflow_run` accepts an object or JSON object bytes. It checks exact
fields, versions, bounds, CORE11 row shape and internal score consistency, then
rederives all coverage and summaries. Changed constants or derived values fail.
Supplying the original out-of-band `expected` also detects replacement of the
declared roster. Without it, validation can establish only internal consistency
against the report's own claims. A consistent forged document remains possible.

`serialize_workflow_run` validates before returning deterministic compact UTF-8
JSON bytes with sorted object keys. There are no generated timestamps, random
identifiers or environment-derived values. Noncanonical whitespace on input is
accepted; duplicate object keys and unsupported values are rejected. Limits are
256 expected cases, two sessions per case, 16 KiB per scored row, 2 MiB per whole
report, nesting depth 16 and 131072 JSON nodes. Integers and booleans are distinct;
floats, NUL, invalid UTF-8, non-JSON objects and excess fields fail. These are
logical input limits, not process memory or OS containment measurements.

## Coverage and measurement meanings

`coverage` keeps expected/scored/completed case counts, missing and incomplete
case IDs, expected/observed session counts, missing session locations and every
expected session's status. `run_completed` means every expected case has a row
whose CORE11 `workflow_completed` is true. It says nothing about utility, safety,
semantic review quality or real execution. A completed case can have failed
utility or unknown resistance. A case with all sessions observed can remain
incomplete. A partially observed case keeps its original producer observations.

| Session status | Recorded meaning |
| --- | --- |
| `completed`, `incomplete`, `error` | Preserved from a present CORE11 session. |
| `not_started`, `error` with absent observations | Preserved for a missing CORE11 session in the expected ordered suffix. |
| `not_recorded` | No scored row arrived for this expected case/session. |

`summary.case_metrics` tallies true, false, unknown (`null`) and missing for each
CORE11 case metric. Each tally retains `expected_denominator`, the full declared
case count. The four buckets sum to that denominator. Unknowns, errors,
incomplete cases and missing rows are never discarded or converted to passes.
These are all-selected-case counts, not new rates or an attack-success metric.
In particular, controls have unknown reviewer resistance; users must retain the
original condition and availability when interpreting it.

`summary.recorded_effect_totals` sums only recorded CORE11 effect counters.
Missing cases do not imply zero effects; coverage remains necessary context.
Unauthorized attempts, actual effects, guard prevention, authorized effects and
unresolved attempts retain their separate meanings. A guard blocking an
unauthorized attempt does not establish reviewer resistance. Safe task success
and task utility remain distinct. An unresolved attempt or incomplete request
replay keeps safe success unknown. Refusal-verification labels describe CORE11
replay checks, including unverified omitted-input causes; report assembly does
not perform those checks again. CORE11 session semantic judgments remain null
and its unavailable semantic-method declaration is preserved.

## Evidence boundary and scope

Both envelope and rows retain `record_authority: recorded_data_only`. The
envelope has `authenticity: unavailable`; unchanged rows retain their original
`authenticity: not_established` and CORE11 evidence scope. The envelope scope is
`recorded_workflow_scores_not_process_model_or_evaluator_attestation`.

`expected.evidence_kind` accepts `scripted` or `not_recorded` (the default).
Scripted fixtures explicitly use `scripted`. This is a caller's recorded label.
CORE11 scored rows omit transport kind and invocation IDs, so neither assembly
nor validation can infer them. No report field, digest, reviewer name, claimed
metadata or matching expectation can establish process execution, fresh
conversations, model behavior, evaluator judgments, reviewer authority or owner
acceptance. Unsupported authority/attestation fields fail validation. Content
identity is not authenticity.

This module adds no shared CLI, dashboard, export, comparison or adjudication
dispatch. It imports no native runner, SDK, provider or budget implementation,
and performs no process execution or lifecycle management. Required shared-file
integration belongs to Root's later REPORTS15 scope. PROCESS14 still owns genuine
fresh-process execution and all its dependencies and acceptance criteria.

## Validation

The two JSON fixtures are scripted harness records, including missing and
incomplete cases and unknown metrics. Tests regenerate their values through the
unchanged CORE11 scorer and check exact row identity across families, controls,
variants and guards. They also cover duplicate/mismatched rows, failed transports,
opaque refusals, forged authority, replacement coverage, deterministic bytes and
resource bounds. These are harness/schema results, not model robustness evidence.

Run on Python 3.11 and 3.14:

```sh
rtk proxy python -m pytest -q tests/test_workflow_report.py tests/test_workflow_replay.py tests/test_workflow_cases.py tests/test_workflow_world.py
rtk proxy ruff check src/review_boundary/workflow_report.py tests/test_workflow_report.py
rtk proxy ruff format --check src/review_boundary/workflow_report.py tests/test_workflow_report.py
rtk proxy python3 scripts/check_project_management.py --repo .
```

Actual source hashes, commands, runtime versions, outcomes, independent ordinary
Claude review findings and cleanup facts belong in the issue/PR evidence. Missing
or unavailable review stays unavailable. This contract does not approve delivery
or complete downstream execution/integration milestones.

GH-28 recorded local validation used pytest 9.2.0 and pydantic 2.14.3. The final
176 report tests passed on Python 3.11.15 (47.78s) and 3.14.3 (48.63s). Eighteen
encoding regression controls failed before the UTF-8 fix. The 239 existing
workflow case/replay/world/boundary tests passed per runtime earlier against
identical CORE11 source bytes. Repository Ruff checks and formatting passed, as
did the management checker (10 tasks, dispatch not checked by that command).
Actual-response pre-edit snapshots passed separately. A byte audit preserved all
269 existing tracked files and the complete disjoint Native56 roster, including
41 paths absent from this base. These are recorded harness and source-audit
observations, not process/model attestation or reviewer acceptance.
