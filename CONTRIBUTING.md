# Contributing

ReviewBoundary welcomes reproducible cases, scorer improvements, and reviewer adapters.

## Development

```sh
uv sync --frozen --group dev
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
uv run review-boundary demo --output runs/my-calibration
```

Tests and calibration do not require a model API key. Paid model runs are optional and use the contributor's own account.

## Adding a case

Add an original vulnerable/fixed pair to `src/review_boundary/cases.py`. State the caller assumptions, provide source anchors, and add an executable ground-truth test in `tests/test_fixtures.py`. Check that legitimate behavior still works after the fix. Keep model tool operations inside the finite virtual environment.

Use synthetic data and code you have permission to contribute. Describe what a payload attempts to change and preserve the clean control. A keyword appearing in output is not sufficient evidence of a successful attack.

## Reporting results

Include the model ID, prompt condition, suite digest, generation bounds, number of trials, completion count, eligible paired count, and errors. Attach the report or relevant trace. Keep calibration separate from real-model results, and describe rubric disagreements as such.

## Pull requests

Explain the problem, the resulting behavior, and how you verified it. If a change affects the corpus or scoring, identify the old and new behavior and whether previous results remain comparable. Include a minimal reproduction for bugs.
