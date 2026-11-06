# Contributing

ReviewBoundary welcomes reproducible cases, scorer improvements, and reviewer adapters.

## Development

Use Python 3.11+, Node 22.18+, and Rust. CI pins Node 22.23.1 and Rust 1.93.1 and tests Python 3.11 and 3.14. Missing fixture runtimes fail the full test suite rather than silently skipping ground truth.

```sh
uv sync --frozen --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run review-boundary demo --output runs/my-calibration
```

Tests and calibration do not require a model API key. Paid model runs are optional and use the contributor's own account.

## Adding a case

Add an original vulnerable/fixed pair through `src/review_boundary/cases.py` and the appropriate corpus module. State caller assumptions, source path, language, split, primary evidence anchors, and relevant alternative source anchors. Add an executable ground-truth test in `tests/test_fixtures.py`. Verify legitimate behavior, the actual vulnerable outcome, and rejection after the fix. Keep model tool operations inside the finite virtual environment.

The v0.2 heldout-family digest is frozen by `tests/test_corpus.py`. Changes to those fixtures require a new corpus version and new baselines. Do not tune reviewer prompts on heldout outcomes and continue calling them heldout. The shared public payload styles are not a heldout attack distribution.

Use synthetic data and code you have permission to contribute. Describe what a payload attempts to change and preserve the clean control. A keyword appearing in output is not sufficient evidence of a successful attack.

## Reporting results

Include the model ID, prompt condition, suite digest, generation bounds, number of trials, completion count, eligible paired count, and errors. Attach the report or relevant trace. Keep calibration separate from real-model results, and describe rubric disagreements as such.

Run `review-boundary compare` against a saved compatible baseline when changing a reviewer. The default CI compares an offline reference calibration, which tests harness behavior only. The optional manually triggered model workflow uses a separately configured OpenRouter secret and paid trials. Each CI job has a fresh local ledger; the job budget is not a cumulative account-wide cap.

## Pull requests

Explain the problem, the resulting behavior, and how you verified it. If a change affects the corpus or scoring, identify the old and new behavior and whether previous results remain comparable. Include a minimal reproduction for bugs.
