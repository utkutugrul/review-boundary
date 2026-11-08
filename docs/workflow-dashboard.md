# Standalone workflow run dashboard

Open one validated `workflow_run` report as a portable HTML file. The renderer
uses the unchanged [workflow report contract](workflow-report-contract.md).
It embeds its packaged CSS, JavaScript and report data, with no server, account,
API key, network request or added dependency.

With the package installed, run from the checkout using the two existing scripted
fixtures. Choose new output paths each time:

```sh
python -m review_boundary.workflow_dashboard \
  tests/fixtures/workflow_reports/scripted-complete.json \
  --output reports/workflow-complete.html
python -m review_boundary.workflow_dashboard \
  tests/fixtures/workflow_reports/scripted-incomplete.json \
  --output reports/workflow-incomplete.html
```

Open either HTML file directly in a browser. The fixture files belong to the
repository; an installed wheel supplies the renderer and web assets. Outside the
checkout, supply your own saved report path. The same entry works without shared
`review-boundary` CLI routing. There is no evaluation or process execution step.

The overview shows run, reviewer label, guard, epoch, coverage, case metrics and
recorded effect counters. Every declared case and session remains visible,
including absent rows and unstarted sessions. Expand **Result details** for case
metrics, session observations, hashes and original refusal verifications. Hashes
identify content; they do not authenticate its origin.

Search and filters affect only the case timeline. Summary denominators always
cover the full declared roster. **With unknown metrics** selects recorded cases
with a null case metric; missing rows remain a separate state. **Export recorded
JSON** downloads the full report, preserving values and unknowns while formatting
may differ. Details also work with JavaScript disabled. All controls stay local.

`True`, `False`, `Unknown (null)`, `Missing` and `Not recorded` have separate
meanings. Missing rows never imply zero effects. Guard prevention does not imply
reviewer resistance. Completion, task utility and safe task success stay distinct.
The report supplies no timing, cost, citation judgment, comparison or ranking.

The page prominently retains `recorded_data_only`, unavailable authenticity and
the caller's scripted/not-recorded label. These fixtures are scripted harness
data. Reports and screenshots do not prove execution, fresh conversations, model
robustness, source authenticity, evaluator judgments or runtime authority.

For library use:

```python
from pathlib import Path
from review_boundary.workflow_dashboard import render_workflow_dashboard, write_workflow_dashboard

html = render_workflow_dashboard(report_bytes, expected=original_expected_roster)
write_workflow_dashboard(Path("run.json"), Path("new-dashboard.html"), expected=original_expected_roster)
```

`expected` is optional. Supplying the original declaration detects roster
replacement. Without it, validation checks internal consistency against the
report's own declared roster. The module entry accepts the declaration as
`--expected original-expected.json`. Neither mode establishes authenticity.

Validation occurs before rendering or creating output. Invalid JSON, duplicate
keys, unsupported versions, inconsistent summaries and mismatched bindings fail.
Input files must be regular UTF-8 JSON files of at most 2 MiB, with the unchanged
contract's case, node, depth and label limits. Output is bounded to 16 MiB and
existing paths are never overwritten. These are logical bounds, not OS isolation
guarantees. CLI errors exit with status 2. Keep generated HTML private when its
embedded report contains information you do not intend to share.

The visual direction follows the existing dashboard's restrained green palette,
serif headings and panel structure. An actual screenshot, when captured, belongs
at `assets/workflow-dashboard.png`; a missing screenshot is unavailable evidence.
This standalone view does not complete Native12, PROCESS14, REPORTS15 shared
CLI/export/comparison/adjudication integration or benchmark18.

Focused checks (Python 3.11+ and Node 22):

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_workflow_dashboard.py
node --test tests/web/workflow-dashboard.test.cjs
ruff check src/review_boundary/workflow_dashboard.py tests/test_workflow_dashboard.py
ruff format --check src/review_boundary/workflow_dashboard.py tests/test_workflow_dashboard.py
python3 scripts/check_project_management.py --repo .
```

Python checks validate rendering and escaping; Node checks exercise data handling
and controls with DOM doubles. They are separate from actual browser observations,
package verification, genuine ordinary Claude Source review and exact-head CI.
