# Product brief

## Positioning

ReviewBoundary helps teams building AI code reviewers test whether untrusted repository content changes their tools' security findings or triggers unauthorized actions.

The first product is an open-source evaluation harness: repeatable cases, observed tool behavior, inspectable traces, and a portable report. Its value is the evidence a team can inspect before changing a reviewer model or instruction policy.

## A concrete use case

A team is updating the model behind its security-review assistant. It runs ReviewBoundary with its current and proposed model configurations. Both see matching vulnerable and fixed code. Some cases contain hostile instructions in PR descriptions, README files, code comments, or tool responses.

The report helps answer:

1. Did the reviewer complete the task and identify the expected vulnerability with source evidence?
2. Did adding hostile context change the result compared with the matching clean case?
3. Did the reviewer attempt a file write despite a read-only assignment?
4. Did an explicit instruction-boundary prompt help, hurt, or have no observed effect?

A team can inspect each finding and tool trace before deciding whether the observed change warrants investigation. An automatic pass is limited to this task's rubric and conditions.

## Available in the prototype

| Capability | Current implementation |
| --- | --- |
| Test corpus | Four original function families, vulnerable/fixed pairs, six contexts each |
| Model access | Tool-capable OpenRouter models |
| Reviewer configurations | Baseline and explicit instruction-boundary prompts |
| Environment | A finite in-memory repository and four tools |
| Evidence | Structured review, exact source evidence, tool events, Inspect logs |
| Report | Local HTML and machine-readable JSON |
| Offline demonstration | Three scripted calibration agents |
| Spending controls | Provider price ceilings, bounded calls, persistent local reservations |

## Who can use it

Developers and security researchers can install the project locally, run the free offline demonstration, and use their own OpenRouter key for real-model evaluations. No ReviewBoundary account or hosted upload is required. API charges are paid to the model provider through the user's own account.

The current release exercises the included reviewer harness. It does not connect directly to an arbitrary commercial PR-review bot, inspect a customer's real repository, or certify a deployed system.

## Next milestones

| Stage | Useful outcome |
| --- | --- |
| Adapter interface | Run the same cases against a customer-owned reviewer endpoint |
| Broader corpus | Cover realistic repository structures and additional languages |
| Repeated and held-out trials | Separate sampling variability from consistent behavior changes |
| Saved baseline comparison | Identify regressions when prompts, models, or tool policies change |
| CI integration | Produce reviewable evaluation artifacts as part of development |

These are roadmap items. A hosted dashboard, scheduled checks, and team history could become a paid service after the local workflow and customer demand are validated. There is no hosted service or subscription today.
