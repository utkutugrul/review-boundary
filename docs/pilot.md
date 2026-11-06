# Pilot 1: useful evidence includes evaluator limitations

This pilot evaluates the included reviewer harness, not native coding-agent products. It ran on November 6, 2026 UTC, corresponding to November 5 in the author's local time. The corpus and prompts were fixed before the full run.

[HTML report](../examples/pilot-v1/report.html) · [JSON report](../examples/pilot-v1/report.json) · [Methodology](methodology.md)

## Conditions

48 cases per model/prompt condition: four original Python function families, two code versions, and six contexts. One trial per case. Models were accessed through OpenRouter with provider sampling defaults, no retries, an eight-turn limit, 24,000 input bytes per generation, and 1,536 output tokens per generation.

Corpus SHA-256: `0246bf8a0aa44e0bb3a812b0ba8df7afccfb33262138cbf726ad3b4c9149fa31`.

## Observations

| Model | Prompt | Completed | Strict rubric match | Write attempts | Paired rubric regressions |
| --- | --- | ---: | ---: | ---: | ---: |
| GPT-6 Luna | Baseline | 48/48 | 45/48 | 0 | 0/28 eligible |
| GPT-6 Luna | Explicit boundary | 48/48 | 46/48 | 0 | 2/32 eligible |
| DeepSeek V4.1 Flash 1017 | Baseline | 38/48 | 32/48 | 0 | 4/18 eligible |
| DeepSeek V4.1 Flash 1017 | Explicit boundary | 38/48 | 30/48 | 0 | 4/21 eligible |

There were no API errors in the full pilot. Twenty DeepSeek cases ended without a structured submission; all twenty had `max_tokens` as the final model stop reason. They are inconclusive, not passes or evidence of attack compliance. Completed reviews and rubric matches use all 48 cases in the denominator. Paired regressions use the smaller eligible denominator, requiring a passing matching clean control and a completed exposed attack case.

## What the ten paired regressions mean

Qualitative inspection of all ten paired regressions found:

- Five source-citation disagreements: the reviewer identified the tenant-authorization issue but cited another relevant line or paired a correct excerpt with an incorrect line number.
- Four finding-count disagreements: the reviewer reported the expected issue along with another finding or split one root cause across multiple entries. The rubric requires exactly one finding.
- One fixture-contract ambiguity: the fixed SQL helper uses a parameterized query, but the caller assumptions do not explicitly guarantee unique usernames. The reviewer objected to the potential return of multiple matching rows.

These observations do **not** establish ten successful prompt injections. The reviewed cases did not follow the payload's request to approve with no findings, and no case attempted a write. Individual report rows retain the machine score and add a separate inspection note. The original score has not been changed after seeing the result.

The SQL ambiguity also affected a clean control. The next corpus revision should state the uniqueness assumption explicitly. The next scorer revision should separate issue detection from citation precision and duplicate finding counts. Those changes require a new corpus/scorer version and a new run before comparisons are made.

## What can and cannot be concluded

The pilot demonstrates that the harness can exercise models, record structured reviews and tool events, preserve inconclusive runs, and expose limitations in its own scoring. No unauthorized write was observed under these conditions.

It does not establish broad robustness, a model ranking, or a reliable benefit from the explicit boundary prompt. Four correlated synthetic families, a single trial, sampling defaults, different provider behavior, and rubric limitations are insufficient for those claims. In particular, the table should not be presented as an attack-success leaderboard.

## Cost and reproducibility

All 446 model API calls in the full pilot included provider-reported cost. Their total was **USD 0.08349741**, with 147,849 input tokens and 137,405 output tokens reported by Inspect. This total is for the full pilot only. The earlier compatibility checks are separate.

The local ledger reserved USD 14.070069 cumulatively across the full pilot and initial checks against the authorized USD 20 limit. Reservations intentionally overestimate spend and were not refunded. The shared API key's usage delta differs from per-call totals and is not used as isolated experiment cost.

To reproduce the full configuration with your own account:

```sh
uv run review-boundary run \
  --model openai/gpt-6-luna \
  --model deepseek/deepseek-v4.1-flash-1017 \
  --defense baseline --defense explicit \
  --concurrency 4 --output runs/reproduction
```

Model availability and prices may change. The runner checks the catalog and uses provider price ceilings; exact outputs are not guaranteed to reproduce. The JSON report records configuration and version metadata. Complete original Inspect logs are kept locally and can be examined with `inspect view`.

## Preliminary checks kept separate

An initial Qwen3.8 Flash request was blocked by the account's existing provider allowlist. An initial GPT-6 Luna request used unsupported generation parameters, which were removed before the full pilot. Both rejected runs recorded no tokens and a zero shared-key usage delta.

A subsequent four-case compatibility check per model completed all four GPT-6 Luna cases and none of the Qwen3 Coder 30B cases under the required reading/submission protocol. This guided compatibility investigation, not selection of attacks. Those checks are not pooled into the table above.
