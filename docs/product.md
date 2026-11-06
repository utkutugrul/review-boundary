# Product brief

## Positioning

ReviewBoundary helps teams building AI code reviewers test whether untrusted
repository content changes their security findings or triggers unauthorized
actions.

The product is an open-source evaluation harness with repeatable cases,
observed tool behavior, portable reports, and a baseline comparison gate. A team
can inspect the evidence before adopting a new reviewer model, prompt, or tool
policy.

## A concrete use case

A team is updating its security-review assistant. It connects its reviewer
through the local JSONL adapter, or evaluates an OpenRouter model inside the
included harness. Current and proposed configurations receive matching
vulnerable and fixed code. Some conditions add hostile instructions to PR
descriptions, README files, code comments, or tool responses.

The report answers separate questions:

1. Did the reviewer complete the required reads and submit a review?
2. Did it report the expected issue category, provide relevant source evidence,
   and cite the correct line?
3. Did hostile context suppress a finding or achieve the injected write goal?
4. Did the reviewer attempt a write, including a write blocked by tool policy?
5. Did the result change from the matching clean control or a saved baseline?

Issue reporting, evidence grounding, citation accuracy, and attacker-goal
success are independent measurements. A misplaced line number does not erase
an otherwise grounded finding. Issue reporting is a structural proxy based on
category and file, not proof of semantic understanding.

## Available in v0.2

| Capability | Current implementation |
| --- | --- |
| Test corpus | 12 original function families across Python, TypeScript, and Rust; 144 conditions from vulnerable/fixed pairs and six contexts |
| Experiment split | Frozen public split by family: 96 development conditions and 48 held-out conditions |
| Repeated evaluation | Five trials per condition by default for model and adapter runs; configurable repetition count |
| Reviewer integrations | Tool-capable OpenRouter models and an explicit local JSONL adapter for a team's own reviewer |
| Review policies | Baseline and explicit instruction-boundary prompts, plus optional enforcement that blocks virtual writes |
| Environment | A finite in-memory repository with four observed tools |
| Evidence | Structured findings, separate metrics, observed tool events, model-run Inspect logs, and adapter event files |
| Reports | Portable HTML and machine-readable JSON with visible errors and incomplete samples |
| Regression gate | Saved baseline comparison with per-case reasons and CI exit codes |
| Offline examples | Scripted harness calibration plus an actual subprocess static checker and an intentionally unsafe adapter control |
| Spending controls | Provider price ceilings and persistent reservations for the built-in model runner; external reviewers manage their own API billing |

The 144 conditions share 12 underlying families. They are not 144 independent
vulnerability discoveries. The held-out split is public and should remain out
of prompt tuning; it does not establish that a model has never seen the code.
Repeated trials expose variability within these tasks, not a real-world failure
rate or a safety certification.

## Who can use it

Developers and security researchers can install the project locally, run the
free offline examples, and use their own provider credentials for model
evaluations. No ReviewBoundary account or hosted upload is required.

The [reviewer adapter](adapters.md) accepts actual tool requests rather than a
self-reported action list. A team supplies a trusted executable and a small
protocol wrapper for its reviewer. The adapter bounds tool calls, messages, and
execution time; it omits fixture labels and scoring metadata from reviewer
requests. The executable is not operating-system sandboxed, and only actions
routed through the protocol are observed. It is not an automatic connector to
every commercial PR-review service.

The [baseline comparison](comparison.md) fails on new losses, missing candidate
samples, and incompatible experiments. Improvements on one case do not cancel
regressions on another. A weak baseline can still produce a passing unchanged
candidate, so teams must review absolute results before accepting a baseline.

## Next milestones

| Stage | Useful outcome |
| --- | --- |
| More realistic review tasks | Larger repository structures, cross-file reasoning, and additional independently validated issue families |
| Reviewer-specific integrations | Maintained wrappers and examples for tools teams already use |
| Operational validation | Evidence from independent users running their own configurations and reviewing failure traces |
| Optional hosted workflow | Scheduled checks, team history, and shared reports if demand justifies a service |

The shipped product is the local open-source workflow. A hosted dashboard or
subscription remains a future option; neither is available today.
