# Evaluation dashboard

ReviewBoundary's dashboard puts recorded outcomes, findings, and tool actions in
one workspace. It works locally, without an account, API key, or build step.

From the repository, run:

```sh
uv run --frozen review-boundary dashboard
```

Open `reports/dashboard.html` in your browser. The file includes the existing
full-suite calibration and the TypeScript and Rust model pilots. Calibration
uses scripted reviewers and is labeled separately from model results.

![Dark-theme overview with recorded outcomes and matched controls.](../assets/dashboard-overview.png)

![Light-theme paired review showing the finding and tool trace beside the attacked result.](../assets/dashboard-paired-review.png)

Both screenshots are captured from the working dashboard with the saved
scripted calibration report. They are interface examples, not real-model scores.

To select your own saved runs:

```sh
uv run --frozen review-boundary dashboard \
  runs/first/report.json runs/second/report.json \
  --output reports/my-dashboard.html
```

The output is one portable HTML file with its styles, scripts, and selected
reports embedded. An installation without the repository's example files
starts with an empty workspace. Import a schema version 2 `report.json` using
**Import report**, or drag it into the page. Imported reports last for the
current page session; refreshing restores the reports embedded in the file.
The color theme is the only preference stored between visits.

## What you can explore

- **Overview:** recorded samples, correct reviews, paired degradations, write
  attempts, and outcomes by context. Counts and denominators remain visible.
- **Evaluation runs:** switch between saved evaluations. Each run keeps its own
  samples, metadata, and controls.
- **Case explorer:** search and filter by reviewer, context, and outcome. Open a
  sample to read the submitted findings, source evidence, and tool trace.
- **Paired reviews:** inspect an attacked review beside its matching clean
  control. Degradations appear first. Matching includes the trial group,
  reviewer, policy, family, code variant, and trial number.
- **Export:** download the selected report's recorded fields from the sample
  details dialog. JSON formatting and number notation may differ from the source.

The interface supports light and dark themes, keyboard navigation, and mobile
layouts. Files are parsed in the browser; the dashboard makes no API requests
and does not start model evaluations. **Create an evaluation** shows the local
CLI command and links to provider and adapter setup.

## Reading the results

A paired degradation requires a passing clean control and a conclusive attacked
review that fails. Missing or duplicate clean controls cannot establish a
degradation. The dashboard aggregates the recorded rows and flags disagreements
with saved summary counts. Ambiguous controls are excluded and explicitly labeled.
Correct-review totals use all recorded samples as the denominator,
including incomplete samples. A displayed N/A means the metric was not recorded
or was not applicable, rather than a pass.

An imported report is a record supplied by its author. The dashboard checks its
structure; it does not authenticate the run, rescore the agent, or replace the
strict [CLI regression gate](comparison.md). It does not compare independent
suites as a model leaderboard. See the [methodology](methodology.md) for the
scope and limitations of the evaluation itself.

Coverage warnings display the report author's recorded coverage. An absent
warning is not proof that an imported run contains every expected sample.

A workspace accepts up to eight reports, 16 MiB per input file, 32 MiB of input
data in total, and 10,000 recorded samples. Keep exported HTML files private if
their embedded reports contain material you do not want to share.

## Development

The source is in `src/review_boundary/web/`. The Python exporter embeds those
assets into each output. Re-run the dashboard command and reload the page after
changing them. No JavaScript package installation is required.

```sh
uv run --frozen pytest tests/test_dashboard.py
node --test tests/web/dashboard.test.cjs
```

The visual direction references [EVMbench](https://github.com/paradigmxyz/evmbench):
restrained colors, serif display typography, and a clear panel structure.
ReviewBoundary's layout, implementation, and evaluation content are its own.
