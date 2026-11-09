# Saved workflow dashboard CLI

The shared installed entry renders one saved `workflow_run` JSON report:

```sh
review-boundary workflow-dashboard REPORT --output NEW_HTML [--expected ROSTER]
```

For example, from a source checkout with the project installed:

```sh
review-boundary workflow-dashboard tests/fixtures/workflow_reports/scripted-incomplete.json \
  --output runs/workflow-incomplete.html
```

`--expected` accepts the original expected-roster JSON when available. A supplied
roster must match the saved report. Without it, validation establishes internal
consistency against the report's declared roster only. See the
[report contract](workflow-report-contract.md) and [dashboard](workflow-dashboard.md).

The command reads each input as a regular JSON file of at most 2,097,152 bytes.
It delegates to the existing workflow validator, renderer and atomic writer.
The new self-contained HTML file is at most 16,777,216 bytes and retains the
renderer escaping, embedded assets and restrictive content security policy.
The command prints the resolved output path after successful publication and
cleanup. It does not start a service or open a browser.

Exit `0` means the valid saved report was rendered. Incomplete reports also exit
`0`; their `run_completed` remains false. Every expected case/session, missing
observation, unknown metric, false value and denominator remains in the embedded
validated document. Guard prevention and reviewer resistance stay separate.
Scripted evidence stays labeled scripted, with `recorded_data_only` authority
and authenticity `unavailable`. Rendering supplies no evaluator or model result.

Argument, validation and I/O failures exit `2` without printing an output path.
Malformed JSON, duplicate keys, unsupported versions, tampered derived summaries,
roster mismatches and oversized inputs refuse before publication. Existing
destinations, including symlinks, hardlinks and input paths, are never overwritten.
Ordinary write/publication failures attempt staging cleanup. If publication
succeeds but staging cleanup fails, the command still exits `2` and reports that
the dashboard was published; a nonzero exit does not establish output absence.
Keep that diagnostic and inspect the selected path before choosing another one.

This route returns before credential/environment loading, evaluation,
provider/model preparation, budget accounting or isolated execution dispatch.
The shared CLI retains its existing eager Inspect and dotenv imports. This is
not an SDK-free cold import guarantee or an audit of third-party initialization.
The installed entry remains `review-boundary = review_boundary.cli:main`.

Focused keyless route checks live in
[test_cli_workflow_dashboard.py](../tests/test_cli_workflow_dashboard.py), alongside
the existing renderer/report and shared parser compatibility checks. Source tests
cover both unchanged scripted fixtures, optional rosters, refusal controls,
protected destinations, effect-path traps and cleanup diagnostics. Installed
console/package verification is separate delivery evidence.

This saved-data route is a bounded part of REPORTS15. Shared comparison, export,
adjudication and evidence integration, actual fresh conversations, full
fresh-process14/REPORTS15, Native/VM runtime and model/accounting acceptance remain
open under their existing ownership and dependencies.
