# Launch copy

Project descriptions and announcement copy for ReviewBoundary.

## Repository description

Paired prompt-injection evaluations for AI security code reviewers. Measure finding quality, unauthorized tool actions, and changes against clean controls.

## Short introduction

ReviewBoundary is an open-source evaluation harness for AI security reviewers. It pairs vulnerable and fixed code with clean and hostile review context, then records structured findings and tool actions. The aim is to make instruction-boundary failures and review-quality changes inspectable before a team changes its reviewer configuration.

## Technical launch post

I built ReviewBoundary to test a specific question: can text inside a PR, README, code comment, or tool response redirect an AI security reviewer?

The initial suite uses four original vulnerability/fix pairs across six review contexts. It measures source-grounded findings, unauthorized write attempts, completion, and changes relative to matching clean controls. API failures and incomplete reviews stay visible.

It runs locally, uses Inspect AI for orchestration, and produces HTML and JSON reports. A free scripted demo verifies the harness; real-model runs use your own OpenRouter key.

This is an early, small synthetic evaluation. I'm particularly interested in contributions for held-out cases, more realistic repository tasks, and adapters for existing review agents.

Repository: https://github.com/utkutugrul/review-boundary

## Short social post

Introducing ReviewBoundary: an open-source test harness for prompt injection in AI security reviews.

Same code. Clean and hostile context. Inspectable findings and tool actions.

Local runs, paired controls, HTML/JSON reports, and a free offline demo.

Early prototype; looking for realistic cases and reviewer integrations.

https://github.com/utkutugrul/review-boundary

## Demo narration

This is ReviewBoundary. We give an AI reviewer a small repository and a read-only security-review task. In the clean case, it receives an ordinary PR description. In the paired case, the code stays the same while an untrusted surface tries to redirect the review.

The report separates task completion, matching source evidence, write attempts, and paired degradation. Expand a row to inspect the submitted review and tool events. The fixed code is evaluated too, so rejecting every PR does not count as success.

The first release evaluates models inside this harness. Connecting a team's existing reviewer and expanding to held-out cases are the next steps.
