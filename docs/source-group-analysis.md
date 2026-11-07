# Analyze repeated runs by source group

Use saved repository or action-boundary reports to see how results vary across
sources and repeated runs. The command writes a separate JSON analysis with exact
counts, missing observations and descriptive uncertainty.

## Start with explicit files

Save this as `analysis-plan.json` beside your report and evaluator suite. Replace
`reviewer-from-report` with the exact reviewer name recorded in the report.

```json
{
  "schema_version": 1,
  "artifacts": [
    {
      "artifact_id": "run_1",
      "report": "report.json",
      "suite": "suite.json"
    }
  ],
  "selections": [
    {
      "selection_id": "reviewer_run_1",
      "artifact_id": "run_1",
      "reviewer": "reviewer-from-report",
      "repetition_id": "repeat_1"
    }
  ],
  "seed": 0,
  "resamples": 2000
}
```

```sh
uv run --frozen review-boundary analyze-groups \
  --plan analysis-plan.json --output analysis.json
```

All evidence paths are literal paths relative to the plan directory. Every input
must be a regular UTF-8 JSON file, with no symlink components. The command reads
only declared files. It makes no model requests and runs no reviewer, test command
or behavior oracle. The output must be new; existing files and links are preserved.
`--plan` and `--output` paths cannot contain `..` components or symlinked ancestor
directories. Missing output parent directories are created after the analysis
passes validation.
A filesystem failure can leave a partial output for inspection.

For another recorded run, add an artifact and selection with a new
`repetition_id`. Several reviewer or guard selections may refer to one artifact;
its report-level cost is counted once. For boundary selections, specify
`"guard": "on"` or `"guard": "off"`.

## Read the result

- Each metric shows expected, present and included slots, its numerator and
  denominator, and separate exclusions for missing, failed, incomplete, unexposed
  or unknown observations. A zero denominator gives a null estimate.
- Epochs are pooled within each case and recorded run. Runs are averaged equally
  within a case, cases within a source, and sources across the selected stratum.
  Raw pooled totals remain available alongside these equal-weight results.
- Structural findings, explicit semantic judgments, citations, legitimate utility,
  attempts, effects and guard intervention keep their individual meanings.
  Unjudged semantics remain unknown. Repository resistance is not measured by the
  current native report format.
- Cost stays at its recorded report scope. Missing costs remain unknown; the
  analysis does not allocate totals to models or source groups. Native latency
  cannot be derived from a report timestamp.

The analysis retains valid unfinished and partially observed runs. Existing
`compare` and CI gates keep their stricter baseline requirements. Coverage that
cannot be established from the declared slots or a bound suite stays unknown;
historical reports never receive an invented complete denominator.

## Comparisons, shards and agreement

An optional `pairs` entry names `baseline` and `candidate` selection ID arrays.
Each arm must select one recorded campaign and reviewer. Pairing requires matching
immutable cases, inputs, controls and epochs; differing epoch counts are not
silently truncated. Guard comparisons remain conditional on eligible matched
observations, with per-arm utility and exclusions retained.

For a [sharded export](corpus-tooling.md), declare an `exports` entry with
`export_id`, `index`, `provenance`, `source_manifest`, `evaluator_manifest` and the
complete ordinal-ordered `suites` path array. Bind each report artifact with
`export_id` and `shard_ordinal`. This preserves the full case roster when report
shards are missing. Export suite digests and native report suite digests use their
own conventions and are checked independently.

An optional `agreements` entry supplies `agreement_id`, the raw report's
`artifact_id`, and two complete `rater_a`/`rater_b` adjudication paths. Agreement is
recomputed from the exact bound report and suite. Repository findings and reviews
are shown separately; boundary semantic agreement remains unsupported. Raw context
may use artifact `role: "agreement_context"` without becoming another repetition.

## Limits and claims

Each physical file is limited to 32 MiB. The plan and all unique evidence files
together are also limited to 32 MiB, so a larger valid corpus export may not fit.
Existing native limits of 16 MiB canonical report JSON, 10,000 rows and 32 cases per
suite remain in effect. The analysis output is limited to 64 MiB. Resampling work
is checked for the entire request before any result is written.

Intervals resample whole source blocks. Fewer than six contributing sources have
no default interval. Larger sets receive a descriptive sensitivity interval with
the recorded seed and draw digests. Recorded cluster labels do not establish
independent real issues or population-wide confidence.

Saved-file analysis always reports `publication.status: "not_established"` and
`ranking_eligible: false`. Its unmet gates remain explicit. Only PyJWT is currently
admitted; its conditions are one source. The original carrier and worker scenarios
also share one synthetic lineage. More labels, variants or repetitions do not
establish additional independent sources or authorize a public ranking.
