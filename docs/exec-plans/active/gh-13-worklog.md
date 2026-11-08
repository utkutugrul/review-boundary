# GH-13 worklog

Scope: ordinary Claude CLI review helper, focused contract tests, English
procedure, GH-13 plan evidence, and the existing management-test fixture fix.
Codex implements; real Claude independently reviews. Human owner: utkutugrul.
Production dispatch checks and #10/#11/#12 remain unchanged.

## Claim and continuation

- Actual host github_api observation at 2026-11-08T04:46:14Z: GH-13 open,
  assigned to utkutugrul, with symphony, owner:codex, review:claude,
  status:ready and dispatch:enabled. All six task headings and distinct roles
  match the plan; both records have no dependencies. The bounded actual-response
  snapshot passed the checker before source edits.
- Continue standard PR #20 and codex/gh-13-independent-claude-review from
  e3f52d044afb0cfe75eaa9d31c9a56373c6b0e8f. All seven initial scoped files
  matched that candidate. Comparison base: 6b7efd375e2c77380dc513e2f4304aa154ec1827.
- Operator comment 6717378408 authorizes the two concrete corrections and
  confirms existing ordinary coding-review authorization. This continuation
  hands the frozen result to the operator for that authorized real CLI review.
- Local Git metadata is read-only. Publication uses repository-scoped native
  GitHub APIs on the existing branch/PR. No new delivery branch or PR.
- The operator maintains canonical work_state outside this child. Maintain this
  one bounded worklog and the issue; no external state update is claimed.

## Preserved failure history

- The previous candidate's 24 fake-executable helper tests and 47 management
  tests passed locally on Python 3.11 and 3.14. These were helper contracts,
  not model evidence. Installed Claude Code 2.1.319 help/version verified the
  requested flags including public --model sonnet, with cleanup and no model call.
- Linux full-suite jobs in CI runs 42446553803 and 42446550479 failed only
  test_blocked_stdin_does_not_escape_the_deadline, with 3839 other tests and
  51 subtests passed per operator verification. A 60,000-byte request can fit
  in a Linux pipe without a reader. This invalidated the test's capacity
  assumption, not the production deadline. Other matrix jobs were cancelled.
- The operator attempted the real normal-Claude review of the previous frozen
  source. It returned unavailable/process_exit before review, with safe fixed
  category missing_login. Cleanup was confirmed for all six supervised groups
  and source stayed unchanged. This is failure history, never a review pass.
  No raw provider error text is retained.
- Operator auth-status checks reported loggedIn=false with HOME/PATH/LANG,
  and loggedIn=true, authMethod=claude.ai when only existing USER was added.
  LOGNAME alone did not fix it. No account/config/authentication mutation occurred.
- A previous local full-suite attempt stopped during collection with 48 missing
  application-dependency errors, including inspect_ai and jsonschema. It was
  not a full-suite pass. An earlier waitid approach was also unavailable on
  Python 3.11 and was replaced by the existing supervised-group implementation.

## Corrections and actual validation

- Retain existing non-secret USER when present, alongside HOME/PATH/LANG/TMPDIR.
  No identity is invented and no credential/config files are read. The fake CLI
  checks identity presence and absence during version, help and review, while
  rejecting synthetic API/auth secrets, endpoint/config overrides, alternate
  provider switches, Node options and GitHub tokens. Identity and fixture secret
  values never appear in the structured artifact.
- The stdin control fills the actual review pipe with nonblocking writes until
  the OS reports EAGAIN. The trusted child never reads, and its stdout readiness
  marker proves the review stage was reached. No source-size/pipe-capacity
  assumption, fake successful I/O, skip or production-limit change remains.
  Assertions require incomplete input, timeout within three seconds for a
  one-second deadline, actual TERM/KILL, retained group ownership, leader reaping,
  absent group and removed scratch directory.
- Python 3.11.15 and 3.14.10: all 25 helper tests and all 47 management tests
  pass in the actual GH-13 workspace, 72 per version. The helper uses unittest;
  management uses an existing pytest installation with plugin autoload disabled.
  The bare interpreters lack pytest, so their initial direct invocations were
  unavailable. Reusing installed pytest passes with one asyncio_mode warning
  per version; these suites do not require that plugin. No installation occurred.
- Ruff 0.17.4 repository lint and format checks pass. Repository management
  contracts pass. Existing source binding, flag verification, refusal behavior,
  supervisor ownership and all production bounds remain unchanged.
- This continuation runs focused checks only. New Linux CI and real Claude
  outcomes must be observed separately; neither is inferred from local passes.

## Frozen handoff and outstanding gates

- GH-13 and PR #20 record the exact published revision/tree, review key, full
  seven-file review scope, actual validation evidence and operator command.
  Run the helper from that revision. Describe-only launches no Claude process.
- Handoff state: open, status:review, dispatch disabled. The final independent
  normal-Claude review is outstanding under the existing authorization.
  Require a structured source-bound result, full coverage, zero permission
  denials and confirmed cleanup. Review subprocess lifetime, source binding and
  refusal behavior independently. Fake executables never satisfy this gate.
- Material-risk delivery remains WAIT for explicit human owner acceptance.
  No merge, gated approval/HOLD, other-task promotion or dispatch enablement.
- Ordinary coding-account usage remains separate from the USD20 application
  benchmark cap. No application benchmarks, credential access, provider/config
  changes, daemon start, install or authentication change in this continuation.
