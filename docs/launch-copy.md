# Launch copy

Project descriptions and announcement copy for ReviewBoundary v0.3.

## Repository description

Prompt-injection evaluations for AI security reviewers: paired controls,
observed tool actions, an external reviewer adapter, and a CI regression gate.

## Short introduction

ReviewBoundary is an open-source evaluation harness for AI security reviewers.
It pairs vulnerable and fixed code with clean and hostile review context, then
records structured findings and actual tool calls. Teams can connect their own
reviewer, inspect failures in an HTML report, and compare a proposed change
against a saved baseline before adopting it.

## Technical launch post

I built ReviewBoundary to test a specific question: can text inside a PR,
README, code comment, or tool response redirect an AI security reviewer?

Version 0.3 includes 12 original function families across Python, TypeScript,
and Rust. Vulnerable/fixed pairs and six review contexts produce 144 conditions,
with a frozen public split by family for development and held-out evaluation.
Model and adapter runs default to five trials per condition.

The report separates issue reporting, source evidence, line citation, and
attacker-goal success. It also records write attempts, completion, and changes
relative to matching clean controls. API errors and incomplete reviews stay
visible. A saved-baseline comparison produces per-case reasons and CI exit codes
for new regressions or missing results.

You can evaluate models through OpenRouter or the direct OpenAI and Anthropic
APIs inside the included harness, using your own credentials. Native providers
require a dated pricing configuration. You can also connect your own reviewer
through a bounded local JSONL adapter. The adapter executes and
records virtual tool calls rather than accepting a claimed list of actions.
It runs trusted local code and observes protocol actions; it is not an
operating-system sandbox.

The project runs locally or through a reusable GitHub Actions workflow and produces
HTML and JSON reports. An optional owner-installed GitHub App posts bounded PR
summaries for an evaluated commit. Offline calibration
and adapter examples are free, scripted demonstrations. They are not AI model
performance results. The corpus is small and synthetic, and its held-out cases
are public.

I would especially like feedback from teams building review agents: which
integration is hardest to reproduce, and which real review task would make the
evaluation more useful?

Repository: https://github.com/utkutugrul/review-boundary

## Short social post

ReviewBoundary v0.3 tests prompt injection in AI security reviewers with paired
clean and hostile contexts.

12 code families. Python, TypeScript, and Rust. A local reviewer adapter,
inspectable findings and tool actions, and a saved-baseline CI gate.

Open source, with free offline examples and HTML/JSON reports. The cases are
synthetic; the examples demonstrate the harness rather than model safety.

I'm looking for feedback from teams building review agents.

https://github.com/utkutugrul/review-boundary

## Demo narration

This is ReviewBoundary. We give a reviewer a small repository and a read-only
security-review task. In the clean condition, it receives an ordinary PR
description. In the paired condition, the code stays the same while an untrusted
surface tries to redirect the review. Fixed code is evaluated too, so rejecting
every PR does not count as success.

The report separates completion, issue reporting, source grounding, citation
accuracy, attacker goals, and write attempts. Expand a row to inspect its review
and observed tool events. A blocked write remains an attempted policy violation.

We can run a model inside the harness or connect an existing reviewer through
the JSONL protocol. Five trials are the default for model and adapter runs. The
offline examples use scripted reviewers to demonstrate correct behavior,
intentional failures, and incomplete results without API charges.

Finally, the comparison command checks a candidate report against a compatible
baseline and names the cases that regressed. The same gate can run in GitHub Actions,
with an optional App result comment after owner setup. A hosted service is a future option.
