# Harness engineering: design review

Source: Graham Helton and Ryan Basden, *Harness Engineering for Vulnerability Research*, [un]prompted II, San Francisco, October 2026. Reviewed from the supplied 56-page PDF `2026-unprompted-harness-engineering.pdf`. The authors publish a companion [workshop book](https://github.com/grahamhelton/harness-engineering-workshop-book). The PDF is not redistributed here.

The workshop's central distinction is useful for ReviewBoundary: model capability alone does not establish reliable research. The surrounding environment must provide bounded tools, relevant context, durable observations, and a way to validate the claim. This is design guidance, not independent validation of ReviewBoundary.

## Changes informed by the workshop

| Workshop topic | Pages | Application in ReviewBoundary v0.2 |
| --- | --- | --- |
| Local validation and readiness | 9-13 | Every fixture executes a legitimate operation, demonstrates the vulnerable behavior, and verifies the fix. Finding a runtime binary alone is insufficient. |
| Bounded integrations | 14-18 | External reviewers use explicit commands with bounded calls, messages, and time. Credentials are not inherited by default. |
| Operational interfaces | 19-25 | Named CLI commands produce the same JSON evidence used by the HTML report and baseline comparison. |
| Durable memory | 26-31 | Run manifests, per-sample tool events, report versions, and source hashes preserve what was tested. Earlier pilot artifacts remain unchanged. |
| Context selection | 32-36 | A reviewer receives task assumptions and tool results. Scoring labels, case IDs, split labels, and ground-truth anchors are withheld from the external protocol. |
| Telemetry outside the model | 37-40 | The harness records executed tool requests. A model's claim that it read, wrote, or completed something is not accepted as execution evidence. |
| Reusable procedures | 41-44 | Repeatable CLI entry points and documented adapter contracts reduce setup ambiguity. They do not make model output deterministic. |
| Deterministic tools and coverage | 45-49 | Ground-truth tests and a frozen suite digest define coverage. Source evidence is matched independently of cited line numbers; line movement alone does not imply a security regression. |
| Hooks and enforcement | 50-53 | `--block-writes` rejects writes in the tool implementation while recording the attempt. An instruction to remain read-only is measured separately. |
| Queryable oracles | 54-56 | Fixture ground truth remains a test oracle. Scripted oracle agents validate the harness and are explicitly separated from real reviewer performance. |

## Limits the workshop helps clarify

A category match is not proof that an explanation demonstrates attacker control or impact. ReviewBoundary retains explanations for inspection and calls its automatic scoring a structural rubric. Similarly, a read event proves that a result was supplied, not that a model understood it.

An attack goal, an attempted unauthorized action, and a task-quality regression are different observations. The report distinguishes them. A blocked configuration write is an attempt, not a successful configuration change. Approving a correctly fixed function is not finding suppression.

The in-memory world enforces the built-in reviewer's action boundary. The external adapter launches trusted host code and does not provide OS containment or visibility into actions outside its protocol. Testing native agents with arbitrary shell access would require an additional container or VM boundary and separate runtime telemetry.

The next useful extension is a small repository task with reproducible runtime validation and a real reviewer integration. More payload text alone would not solve the remaining gap between a controlled function-level test and a deployed review service.
