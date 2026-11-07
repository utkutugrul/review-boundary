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

## Native repository and boundary adapters

Use `.github/workflows/evaluate-adapter.yml` for trusted caller-owned adapter programs. It is a separate reusable workflow with no provider or App secrets. Do not pass secrets, use `secrets: inherit`, attach an environment with secrets, or move adapter execution into `evaluate.yml`. GitHub permits inherited secrets even when the callee does not declare them, so keeping the caller secretless is part of this boundary. See [GitHub's reusable workflow secret rules](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows#passing-secrets-to-nested-workflows).

The adapter job uses a fresh GitHub-hosted runner with read-only repository permission. Every checkout sets `persist-credentials: false`, and dependency caching is disabled. It checks out the pinned harness, reads baseline and suite data from the caller's trusted PR base, and selects adapter code at the exact PR head. Provider and App credentials must never have been supplied to this runner. [Checkout documents how credential persistence works](https://github.com/actions/checkout#usage).

A second fresh runner downloads the candidate report by immutable artifact ID and reloads approved baseline and suite data. It consumes bounded JSON only. It never checks out adapter code, reads adapter configuration, executes adapter commands, or receives an App key. Failed execution, missing or invalid output, and unfinished native runs exit `2` and produce no publishable comparison. A finished candidate missing expected slots exits `1`.

Both profiles require a suite file, explicit baseline and candidate reviewers, and a compatible complete baseline. `boundary-adapter` also requires explicit `on` or `off` guard selectors. Custom boundary suites use the existing bounded native suite loader and retain the adapter report's full-case-list digest convention. Historical native reports without `expected_slots` need a suite that proves their exact declared case, reviewer, epoch and guard coverage. Unknown coverage never passes.

Pin this example to a reviewed full commit SHA after preparing and reviewing the baseline and suite:

```yaml
name: Native reviewer adapter
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  adapter:
    uses: utkutugrul/review-boundary/.github/workflows/evaluate-adapter.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      profile: repository-adapter
      baseline_source: caller
      baseline: security/repository-baseline.json
      suite: security/repository-suite.json
      adapter: security/reviewer.json
      baseline_reviewer: adapter/approved-reviewer
      candidate_reviewer: adapter/candidate-reviewer
```

The adapter file is the existing bounded JSON configuration with a `command` array of literal argv strings. CI refuses nonempty `env_allowlist` values, shell command strings, oversized files, duplicate keys, traversal and symlink data paths. The harness performs no shell evaluation or workflow-input interpolation. It also rejects known provider, App and explicitly exported GitHub credential variables before launching an adapter. These checks are defense in depth, not a substitute for a separate runner.

Two adapter reports must record matching transport and world limits. A scripted `reference` calibration baseline can test adapter contract regressions when the supplied suite proves the same inputs and limits. Its absent adapter transport is explicitly inapplicable; this comparison does not establish model improvement. Model baselines with model-specific bounds and external policy callbacks are not supported by adapter CI.

To use the same profile locally on a host without provider/App credentials or credential files:

```sh
uv run review-boundary ci security/repository-baseline.json \
  --output runs/repository-ci --profile repository-adapter \
  --suite security/repository-suite.json --adapter security/reviewer.json \
  --baseline-reviewer adapter/approved-reviewer --candidate-reviewer adapter/candidate-reviewer
```

For boundary CI, select `--profile boundary-adapter` and add `--baseline-guard off --candidate-guard on` for an intentional guard comparison. Baseline and candidate retain their recorded corpus identity; a custom-suite baseline runs with that explicit suite even when its cases equal bundled fixtures.

Adapter programs remain trusted caller-owned code. The ephemeral job and minimal environment are not an operating-system sandbox, and protocol evidence cannot attest external side effects. Local use assumes the host filesystem has no reachable credentials. GitHub still provides ordinary workflow runtime services and tokens; the boundary here excludes provider/App credentials and a retained checkout token. A full OS-isolated runner is separate work.

Native GitHub App publication remains unsupported. The existing legacy calibration, model CI and optional App publishing workflow retain their behavior.

## Native repository and boundary provider models

Use `.github/workflows/evaluate-native-model.yml` for the fixed trusted provider runners. The `repository-model` and `boundary-model` profiles accept one provider and model. They do not accept caller adapters, commands, setup scripts, credential files, external policy processes, or GitHub App publishing. The provider workflow and the secretless adapter workflow must stay separate.

Live execution requires `allow_live: true`; the default skips execution and comparison. Pass only the selected provider secret explicitly. Do not use `secrets: inherit`. OpenRouter uses its existing catalog admission and remote price ceilings. Direct OpenAI and Anthropic runs require an approved dated pricing file and use native endpoints; quoted prices are recorded assumptions rather than remote price ceilings.

The baseline must be a complete native model report with an explicit suite, exact execution bounds, matching world limits, provider markers and a conclusive selected reviewer group. Calibration and adapter baselines cannot establish this model gate. Baseline and suite validation finishes before the runner reads credentials or starts provider work. The candidate reproduces the baseline's epochs and execution limits, runs at concurrency one, and must reserve no more than the supplied positive finite budget. CI limits that budget to USD 20 per run. This ceiling does not track an account-wide or session-wide spending allowance; operators must manage that allowance separately.

Both workflow jobs check out the harness at the callee's immutable SHA. Caller baseline, suite and pricing files come from the trusted PR base revision, or from the explicitly selected harness checkout. The provider step runs inside the harness directory and uses only bounded virtual suite data. It never checks out the caller head, installs the caller project, imports caller code, or executes caller setup scripts. Paid fork pull requests are rejected before secrets are loaded. These boundaries follow [GitHub's callee source context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context), [explicit reusable workflow secrets](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows), and [untrusted checkout guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

The provider job transfers only `candidate/report.json`. A fresh job without provider or App secrets downloads that report by immutable artifact ID, reloads approved baseline and suite data, and compares bounded JSON with the pinned harness. The final artifact allows only the candidate report, `summary.md`, `ci-result.json` and `comparison.json`. Raw Inspect `.eval` files, API transcripts, event logs, credential files and arbitrary directory contents are excluded. Budget ledgers and settlement records stay in the provider runner's local output; the report preserves recorded usage and unknown billed costs. No cache is saved by these jobs.

Pin the reusable workflow to a reviewed full commit SHA. This example requires a manual opt-in and an approved model baseline and virtual suite:

```yaml
name: Native model regression
on:
  workflow_dispatch:
    inputs:
      allow_live:
        type: boolean
        default: false

permissions:
  contents: read

jobs:
  model:
    uses: OWNER/REPOSITORY/.github/workflows/evaluate-native-model.yml@REVIEWED_FULL_COMMIT_SHA
    with:
      allow_live: ${{ inputs.allow_live }}
      profile: repository-model
      provider: openrouter
      model: YOUR_PROVIDER_NATIVE_MODEL_ID
      baseline_source: caller
      baseline: security/repository-model-baseline.json
      suite: security/repository-suite.json
      baseline_reviewer: openrouter/YOUR_APPROVED_MODEL_ID
      candidate_reviewer: openrouter/YOUR_PROVIDER_NATIVE_MODEL_ID
      budget: 20
    secrets:
      OPENROUTER_API_KEY: ${{ secrets.OPENROUTER_API_KEY }}
```

For boundary models use `profile: boundary-model` and explicit `baseline_guard` and `candidate_guard` values of `on` or `off`. The same reviewer and guard selection rules apply to local CI:

```sh
uv run review-boundary ci security/repository-model-baseline.json \
  --output runs/repository-model-ci --profile repository-model --mode model \
  --suite security/repository-suite.json \
  --baseline-reviewer openrouter/YOUR_APPROVED_MODEL_ID \
  --candidate-reviewer openrouter/YOUR_PROVIDER_NATIVE_MODEL_ID \
  --provider openrouter --model YOUR_PROVIDER_NATIVE_MODEL_ID --budget 20
```

Native model profiles deliberately require `--mode model`. Optional `--prompt-price-cap` and `--completion-price-cap` use the existing provider admission checks. Local runs retain their normal evidence and ledger files, including raw logs. The workflow upload allowlist does not change local runner output. A passing gate exits `0`, an observed regression or finished candidate missing selected slots exits `1`, and invalid inputs, unfinished runs or provider failures exit `2`. Provider failure bodies and credential values do not become CI summaries. Unknown semantic judgments and partial costs retain their native meanings.
