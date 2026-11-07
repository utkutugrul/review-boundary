# Contributing

ReviewBoundary welcomes reproducible cases, scorer improvements, and reviewer adapters.

## Development

Use Python 3.11+, Node 22.18+, and Rust. CI pins Node 22.23.1 and Rust 1.93.1 and tests Python 3.11 and 3.14. Missing fixture runtimes fail the full test suite rather than silently skipping ground truth.

```sh
uv sync --frozen --all-extras --group dev
uv run ruff check .
uv run ruff format --check .
uv run --frozen --all-extras pytest -q
uv run review-boundary demo --output runs/my-calibration
```

Tests and calibration do not require a model API key. Paid model runs are optional and use the contributor's own account.

## Adding a case

Add an original vulnerable/fixed pair through `src/review_boundary/cases.py` and the appropriate corpus module. State caller assumptions, source path, language, split, primary evidence anchors, and relevant alternative source anchors. Add an executable ground-truth test in `tests/test_fixtures.py`. Verify legitimate behavior, the actual vulnerable outcome, and rejection after the fix. Keep model tool operations inside the finite virtual environment.

The v0.2 heldout-family digest is frozen by `tests/test_corpus.py`. Changes to those fixtures require a new corpus version and new baselines. Do not tune reviewer prompts on heldout outcomes and continue calling them heldout. The shared public payload styles are not a heldout attack distribution.

Use synthetic data and code you have permission to contribute. Describe what a payload attempts to change and preserve the clean control. A keyword appearing in output is not sufficient evidence of a successful attack.

## Contributing a repository suite

Run `review-boundary case-template --output PATH --name NAME` for a complete original example, edit it, and check it with `review-boundary validate-suite`. Validation is structural and never runs your code or tests, and it does not admit a corpus. See [suite contributions](docs/suite-contributions.md).

## Reporting results

Include the model ID, prompt condition, suite digest, generation bounds, number of trials, completion count, eligible paired count, and errors. Attach the report or relevant trace. Keep calibration separate from real-model results, and describe rubric disagreements as such.

Run `review-boundary compare` against a saved compatible baseline when changing a reviewer. The default CI compares an offline reference calibration, which tests harness behavior only. It also tests the reusable workflow's artifact transfer and credential-free PR comment preview. The optional manually triggered model workflow supports OpenRouter, OpenAI, and Anthropic with explicitly configured provider credentials and pricing. Each CI job has a fresh local ledger; the job budget is not a cumulative account-wide cap. See the [Actions guide](docs/github-actions.md).

## Pull requests

Explain the problem, the resulting behavior, and how you verified it. If a change affects the corpus or scoring, identify the old and new behavior and whether previous results remain comparable. Include a minimal reproduction for bugs.
