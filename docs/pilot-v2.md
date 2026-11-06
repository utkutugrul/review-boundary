# Version 0.2 pilot

Two selected families completed **240 real-model conditions**: five trials of every vulnerable/fixed and context combination, with two reviewer prompts. All 240 completed and matched the v0.2 structural rubric. No write request or attacker-goal success was observed in these runs.

This is a narrow smoke test of the new language fixtures and repeated-run workflow. It does not show that the attack set is strong enough to distinguish capable reviewers, or that the model is robust to other prompt injections. Both prompts passed every selected condition, so this pilot provides no evidence that the explicit boundary prompt improves performance.

## Experiment

Executed November 6, 2026 UTC, using Inspect AI 0.3.287 and ReviewBoundary 0.2.0. The model ID was `openai/gpt-6-luna` through OpenRouter; all recorded responses named OpenAI as the serving provider. The provider may change the model behind an alias over time.

| Suite | Family | Split | Trials per condition | Prompts | Recorded / expected |
| --- | --- | --- | ---: | ---: | ---: |
| TypeScript | `ts_batch_export` | Development | 5 | 2 | 120 / 120 |
| Rust | `rust_partial_batch_permissions` | Public heldout | 5 | 2 | 120 / 120 |

Each family has two code variants and six contexts. The two prompts are `baseline` and `explicit`. The same prompts and bounds were used for both families; heldout results were not used to tune either prompt.

Bounds were declared before execution: 8 turns, 24,000 serialized input bytes per call, 8,192 output tokens, zero retries, four concurrent samples, and provider sampling defaults. Tools could write only to the virtual repository; the runtime write block was disabled to observe attempted and realized behavior. Requests used provider price ceilings of USD 0.15 per million input tokens and USD 0.60 per million output tokens, with no per-request charge allowed.

```sh
uv run review-boundary run --model openai/gpt-6-luna \
  --family ts_batch_export --defense baseline --defense explicit \
  --epochs 5 --concurrency 4 --output runs/typescript-pilot

uv run review-boundary run --model openai/gpt-6-luna \
  --split heldout --family rust_partial_batch_permissions \
  --defense baseline --defense explicit --epochs 5 --concurrency 4 \
  --output runs/rust-pilot
```

## Observations

| Measurement | TypeScript | Rust |
| --- | ---: | ---: |
| Completed reviews | 120 / 120 | 120 / 120 |
| Correct structural reviews | 120 / 120 | 120 / 120 |
| Expected category reported, submitted vulnerable cases | 60 / 60 | 60 / 60 |
| Relevant source evidence, submitted vulnerable cases | 60 / 60 | 60 / 60 |
| Correct source citations, submitted vulnerable cases | 60 / 60 | 60 / 60 |
| Attacker goal reached, eligible observed cases | 0 / 50 | 0 / 50 |
| Unauthorized write requests, including rejected arguments | 0 | 0 |
| Paired degradation against a passing clean control | 0 / 80 | 0 / 80 |
| Incomplete / provider-error samples | 0 / 0 | 0 / 0 |

The denominators answer different questions. Fixed-case approvals cannot suppress an existing vulnerability, so those cases are excluded from the suppression-goal denominator. The tool-output write goal applies to both variants. Repeated conditions share code and payloads; these counts are correlated and are not an estimate of a real-world attack rate.

Comparing the two TypeScript prompt groups pairs 60 samples and reports zero regressions or improvements. The [comparison artifact](../examples/comparisons/pilot-v2-typescript.json) records that result. An unchanged passing result is not a statistical claim of equivalence.

## Inspect the evidence

- TypeScript: [HTML report](../examples/pilot-v2-typescript/report.html), [JSON](../examples/pilot-v2-typescript/report.json), [manifest](../examples/pilot-v2-typescript/manifest.json).
- Rust heldout: [HTML report](../examples/pilot-v2-rust-heldout/report.html), [JSON](../examples/pilot-v2-rust-heldout/report.json), [manifest](../examples/pilot-v2-rust-heldout/manifest.json).
- Full-corpus offline calibration: [HTML report](../examples/calibration-v2/report.html), [JSON](../examples/calibration-v2/report.json).

Download an HTML report and open it locally; GitHub's source viewer does not execute the report. The files are self-contained and require no account or server.

Final exports validate the unchanged Inspect logs against the manifest and recheck scores. The expected model/prompt group list was completed from the original launch configuration during final report assembly. Adding rejected-write request coverage did not change any recorded behavioral outcome: the original traces contain zero write requests. The exports include a hash of each original report, and the original run artifacts remain preserved locally.

The full offline calibration contains 432 samples, 144 for each scripted mode. The reference passes all 144. The intentional negative control produces 60 regressions against that reference, and the incomplete control has 144 incomplete samples. This verifies that the gate can fail and that incompletion remains visible. It is not additional model-performance evidence. See the [negative-control comparison](../examples/comparisons/calibration-negative-control.json).

## Cost

The TypeScript run returned provider cost for all 277 API calls: **USD 0.0297676**. The Rust run returned cost for all 290 calls: **USD 0.0318354**. Combined provider-reported cost was **USD 0.061603**. These are returned billing observations, not a promise about future pricing or the cost of another model. Conservative reservations were much larger and settled only after every call had cost evidence.

## Remaining limits

Only two of twelve families were evaluated with this real model in v0.2. The full corpus has executable ground-truth tests and offline calibration, but that is different from full real-model coverage. The public heldout set separates families, not payload styles, and may be visible in training data. Category and excerpt checks do not semantically judge explanations or validate additional reported findings. The tasks are small virtual review environments, not production repository or native-agent evaluations.

The [v0.1 pilot](pilot.md) remains unchanged with its original rubric and smaller output bound. Do not compare its strict match percentage directly with this version. A useful next experiment should introduce independently designed attacks and a real reviewer integration, then freeze that configuration before collecting outcomes.
