# Evaluate a reviewer in GitHub Actions

The reusable workflow runs ReviewBoundary's controlled review tasks and compares the results with an approved baseline. It evaluates the reviewer. It does not scan the caller repository or execute its application code.

The default job is a free scripted calibration across all 144 conditions. Model mode evaluates exactly the cases and trial count recorded in the selected baseline, with the same execution bounds. Both modes upload a browser report, machine-readable results, and a short summary.

## Start with free calibration

Add this workflow to your repository:

```yaml
name: ReviewBoundary
on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  evaluate:
    uses: utkutugrul/review-boundary/.github/workflows/evaluate.yml@main
```

This uses `examples/baselines/reference-v02.json` from the harness checkout and the fixed reference reviewer. It requires no model API key and makes no model API calls. Scripted calibration checks the test machinery; its passing score is not evidence of AI model safety.

The `main` reference follows updates. For a stable deployment, replace it with a reviewed full commit SHA, especially before adding paid provider credentials. The reusable workflow checks out its own source at the exact commit that defines the job. It uses GitHub's `job.workflow_repository` and `job.workflow_sha`, which are available on GitHub.com but not GitHub Enterprise Server. See the [official workflow identity documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#example-usage-of-job-context-workflow-identity).

## Evaluate a real model

First create and inspect a baseline for a small selection of cases, using the [provider guide](providers.md). Commit that report and your dated pricing configuration to the caller repository. Use an approved baseline from the same corpus and scoring version as the chosen workflow commit.

This example requires replacing the model placeholders and pinning `uses` to a reviewed commit:

```yaml
name: ReviewBoundary model evaluation
on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  evaluate:
    uses: utkutugrul/review-boundary/.github/workflows/evaluate.yml@main
    with:
      mode: model
      provider: openai
      model: YOUR_CANDIDATE_MODEL_ID
      defense: explicit
      baseline_source: caller
      baseline: security/reviewer-baseline.json
      baseline_model: openai/YOUR_BASELINE_MODEL_ID
      baseline_defense: baseline
      pricing_file: security/openai-pricing.json
      budget: 20
    secrets:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

The model input is the provider's model ID. The baseline selector is the complete model label stored in the report, including its provider prefix. Selecting both sides explicitly allows an intentional model or prompt change. A baseline containing several groups requires an unambiguous `baseline_model` and `baseline_defense` selection.

Direct OpenAI and Anthropic runs require `pricing_file` and the corresponding `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`. OpenRouter uses `OPENROUTER_API_KEY` and its provider price controls. Pass only the secret needed for the selected provider. Native pricing is a recorded cost assumption, not an account-wide spending cap. Each CI execution uses its own conservative budget ledger; the budget does not accumulate across separate workflow runs.

The baseline determines the exact case IDs, split, epochs, maximum turns, input and output limits, retry policy, and virtual write policy. A changed or unsupported corpus fingerprint, missing cases, invalid bounds, or malformed baseline stops the job before model evaluation. A reservation that exceeds the configured budget also prevents the paid run. Reduce the selected baseline suite when a run is too large.

## Inputs

| Input | Default | Purpose |
| --- | --- | --- |
| `mode` | `calibration` | Fixed scripted reference or `model` evaluation |
| `provider` | `openrouter` | `openrouter`, `openai`, or `anthropic` in model mode |
| `model` | Empty | Required candidate model ID for model mode |
| `defense` | `baseline` | Candidate prompt: `baseline` or `explicit` |
| `baseline` | `examples/baselines/reference-v02.json` | Report path relative to the selected data checkout |
| `baseline_source` | `harness` | Read baseline and pricing data from `harness` or `caller` |
| `baseline_model`, `baseline_defense` | Empty | Select one existing baseline group |
| `pricing_file` | Empty | Dated native-provider pricing JSON, relative to the same data checkout |
| `budget` | `20` | Maximum USD reservation for this CI execution |
| `artifact_name` | `reviewboundary-results` | Artifact base name; use a unique value for each call in one workflow |
| `publish_comment` | `false` | Opt into a GitHub App result comment |
| `app_id`, `installation_id` | Empty | Identifiers required when enabling App publication |

Named secrets are `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and `GITHUB_APP_PRIVATE_KEY`. None are needed for default calibration.

The uploaded artifact name appends `-<run_id>-<run_attempt>` to `artifact_name`. Multiple calls within the same workflow run must use different base names.

## Data and execution boundaries

Only the trusted harness checkout supplies executable code. Caller baseline and pricing files are data. Paths must be relative, remain inside the selected checkout, identify regular files, contain no symlink components, and stay within the 32 MiB limit. Absolute paths and `..` traversal are rejected. Workflow inputs are passed through environment variables and structured Python arguments, not interpolated into shell commands.

For a pull request, `baseline_source: caller` reads the caller's base commit. Proposed changes to the baseline or pricing file therefore do not take effect until accepted into that base. Push and manual runs use the event commit. The workflow does not run a caller-supplied adapter, shell command, or reviewer executable in the job holding model credentials.

Supported triggering events are `push`, `pull_request`, and `workflow_dispatch`. Fork pull requests can run calibration. Model jobs reject fork pull requests. Keep changes to paid workflow inputs and accepted baselines under review.

## Results and failure handling

| Exit code | Meaning |
| --- | --- |
| `0` | Completed, compatible comparison with no new regressions |
| `1` | Completed comparison found a new behavioral regression |
| `2` | Invalid configuration, incompatible data, or execution/API failure |

The uploaded output contains:

- `candidate/report.html`, `candidate/report.json`, and the run manifest, when produced.
- The budget ledger and settlement record, when produced.
- `summary.md`, a bounded summary containing counts and fixed labels without raw model text or mentions.
- `ci-result.json`, the CI status, exit code, error category, and comparison counts when available.
- `comparison.json`, only after a completed evaluation and valid comparison.

Handled failures preserve recorded candidate evidence and produce error summaries when a safe output directory is available. API or outer execution errors remain failures even if already-recorded rows happen to match the baseline. They do not create a publishable comparison. Existing output directories are refused, so prior results are not overwritten.

Raw provider execution logs remain in `candidate/logs` on the evaluation runner. The workflow deliberately excludes them from the uploaded artifact. A local CI run retains that directory for inspection.

The gate flags individual losses; an improvement elsewhere does not cancel a regression. Citation-only changes are informational. Existing baseline failures remain visible. Read the [comparison policy](comparison.md) before treating a passing gate as an acceptance criterion.

## Optional GitHub App comments

Set `publish_comment: true`, supply `app_id` and `installation_id`, and pass `GITHUB_APP_PRIVATE_KEY` after completing the [App setup guide](github-app.md). This requires an App installed and authorized by the repository owner; adding the workflow does not install an App.

A separate reporting job receives the App key, downloads the exact artifact ID returned by the evaluation job's successful upload, and checks the current pull-request head before publishing. Publication requires a valid comparison and a same-repository pull request. A failed upload cannot fall back to a different artifact with the same name. The evaluation job does not receive the App private key. App setup and provider credentials are owner-managed integrations, not an automatically activated hosted service.

## Run the same gate locally

From the ReviewBoundary checkout:

```sh
uv run review-boundary ci examples/baselines/reference-v02.json \
  --output runs/ci-reference
```

Use a new output directory for each run. A native-provider example is:

```sh
uv run review-boundary ci /path/to/reviewer-baseline.json \
  --output runs/ci-model --mode model --provider openai --model YOUR_CANDIDATE_MODEL_ID \
  --baseline-model openai/YOUR_BASELINE_MODEL_ID --baseline-defense baseline \
  --defense explicit --pricing-file /path/to/openai-pricing.json --budget 20
```

The local command uses your own environment credentials. It returns the same gate codes and writes the same artifact layout as the reusable workflow.
