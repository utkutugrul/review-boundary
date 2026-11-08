# GH-13 worklog

Scope: ordinary Claude CLI helper, contract tests, English procedure and GH-13
plan evidence. The current continuation corrects only the management CLI's mixed
live/offline flags and deadline diagnostic, their tests and operations guidance.
Codex implements; real Claude reviews. Human owner: utkutugrul.
No other task ownership, workflow configuration or authentication changes.

## Claim and continuation

- Actual host github_api observation at 2026-11-08T04:58:03Z: GH-13 open,
  assigned to utkutugrul, with symphony, owner:codex, review:claude, status:ready
  and dispatch:enabled. All six headings and distinct roles match the plan;
  both records have no dependencies. The bounded actual-response snapshot
  passed the live-claim checker before source edits. Its observation is not
  a fixture or evidence of model behavior.
- Continue standard PR #20 and codex/gh-13-independent-claude-review from
  2623cc3e43c696cefa12cfe5b646d5c2efd66540. All eight scoped files initially
  matched that committed candidate byte for byte.
  Comparison base: 6b7efd375e2c77380dc513e2f4304aa154ec1827.
- The actual issue follow-up authorizes these corrections and preserves existing
  normal coding-review authorization. Freeze for the operator's final-source
  real normal-Claude review; no native operator execution in this child.
- Git metadata in the issue workspace is read-only. Use an isolated local
  validation checkout and repository-scoped native GitHub APIs on the existing
  branch/PR. No new delivery branch or PR.
- The operator maintains canonical work_state outside this child. This one
  worklog and the issue record evidence; no external state update is claimed.

## Previous real review and complete disposition

The operator reports a completed independent real normal-Claude review of
2623cc3e43c696cefa12cfe5b646d5c2efd66540: eleven selected paths reviewed,
zero permission denials, confirmed cleanup and unchanged source. The operator
independently passed 72 tests plus 53 subtests on Python 3.11.15 and 3.14.3 and
Ruff checks. Completion is not approval, final-source coverage or model robustness.

1. CLAUDE.md/user-memory exposure: unconfirmed. Actual installed safe-mode help
   explicitly disables CLAUDE.md and customizations; the reviewer acknowledged
   relying on unverified general knowledge. Preserve safe/restricted modes,
   empty tools/MCP and the workspace-confined scratch. No filesystem widening.
2. Executing-helper provenance: helper_sha256 and review_key already bind the
   executed helper bytes. The operator independently compared committed bytes
   and executed a byte-identical frozen copy. The procedure now requires this
   operator-side comparison when reviewing the helper itself and checking the
   reported helper hash afterward. Matching hashes establish content identity,
   not authenticity or correctness. No same-named-path repository restriction.
3. Citation bounds: confirmed and corrected. splitlines() counted non-LF Unicode
   separators. Count literal LF bytes, including an unterminated final line
   and excluding a phantom line after final LF. Empty files have zero lines.
   The trusted prompt, schema descriptions and procedure state the 1-based LF
   convention. Byte/hash and aggregate source bounds stay unchanged.
4. Dependency references: confirmed and corrected in the explicitly extended
   production scope. Reject unsupported numeric references left after consuming
   bare #N, including foreign/qualified short forms, GH-N and invalid #0/#05.
   Refusal applies alone, beside valid references and beside None. Canonical
   same-repository URLs, bare #N, the real None explanatory sentence, exact
   registry/dependency matching and existing gates remain covered.

## Actual correction checks

- Before production edits, the new Python 3.11 regression selection exposed
  both defects: 25 failures, three supported-reference passes, 72 deselected.
  The Unicode fake CLI accepted an impossible second-line citation; mixed
  unsupported dependencies were silently dropped. These were intentional
  negative controls, not a successful validation run.
- Final Python 3.11.15 and 3.14.10 focused runs each pass 106 tests:
  27 trusted-fake helper tests plus 79 management cases. Both ran pytest.main
  with the existing pytest installation on sys.path, plugin autoload disabled,
  no cache provider and temporary paths inside the workspace. Each reported
  one unknown asyncio_mode warning; these suites do not need that plugin.
  No installation occurred.
- Location controls cover empty, unterminated, trailing-LF, blank, CRLF and
  non-LF Unicode source in both current/base snapshots, checking original
  bytes/hashes and accepted/rejected actual citation bounds. A real trusted-fake
  CLI positive/negative pair checks Unicode citation refusal end to end.
- Parser controls preserve all other task headings, prove canonical URL/bare
  reference plan binding and None support, and reject mixed unsupported forms.
  The fake-HTTP boundary refuses them after only the current issue request,
  before any dependency request. All original functional controls remain.
- Repository Ruff lint/format, management contracts and scoped whitespace checks
  pass. Only the two production corrections above and their prompt/schema
  context changed. Source limits, CLI flags/environment, subprocess supervision,
  cleanup evidence, refusal behavior and the remaining dispatch gates are intact.
- The previous candidate's actual Linux CI test jobs passed in PR run
  42448514386 and branch run 42448508285 on both Python matrix versions.
  This is previous-source evidence. Fresh CI for the new revision must be
  observed separately; local counts do not establish a full-suite or model pass.

## URL refusal follow-up

- Actual host github_api observation at 2026-11-08T05:15:28Z: GH-13 open,
  assigned to utkutugrul, with symphony, status:ready and dispatch:enabled;
  distinct Codex/Claude roles and no dependencies match the plan. The bounded
  actual-response snapshot passed the checker before source changes.
- Continue the same branch and standard PR #20 from
  43bbb0486d0a3763a6f15ec4136830a8f04c29b4. All eight delivery files
  initially matched its Git blobs. Only the parser, existing management tests,
  this worklog and GH-13 plan evidence change in this continuation.
- The operator reports that revision's seven-file current/base real review
  completed in 65.894 seconds with full selected coverage, zero denials,
  all nine supervised groups retired, scratch removed and unchanged source.
  Its PR CI 42449462722 and branch CI 42449459502 now report success.
  These remain evidence for that original revision, not the new parser.
- The remaining P3 URL finding is corrected: consume whole canonical
  same-repository HTTPS issue URL tokens and bare ASCII #N references, then
  refuse residual reference/URL-like text. Foreign, HTTP, schemeless, uppercase,
  pull, prefixed and malformed-suffix URLs fail with a fixed non-secret message.
  No host/protocol, authentication, network or ownership expansion occurs.
- Paired controls cover 19 unsupported URLs alone, beside supported references
  and beside None. Both the supplied-snapshot and fake-HTTP paths refuse;
  the latter makes only the current-issue request. Positive controls preserve
  genuine explanatory None, Markdown/bare canonical URLs, exact roles and
  registered dependencies. All original short-reference and gate controls stay.
- Before production edits, the regression selection reported 54 failures,
  10 passes and 76 deselected. Some malformed forms already refused, while
  others were dropped or consumed by prefix; all must use the bounded refusal.
- Final focused runs each pass 140 management tests on Python 3.11.15 and
  3.14.10. Existing pytest was reused via sys.path with plugin autoload and
  cache disabled; each run has one unknown asyncio_mode warning. No install.
  Repository-wide Ruff lint/format, management contracts and whitespace pass.
- scripts/claude_review.py, tests/test_claude_review.py and the procedure remain
  byte-identical to 43bbb0486d0a3763a6f15ec4136830a8f04c29b4. The helper
  SHA-256 remains f64a4e4aaa7884728ab0901b7856589f4cc89636e08fc70766e65bbed843b1b2.
  No unchanged helper test/model scope was rerun. Reuse retains the operator's
  original reviewed revision and exact content identity, not a rewritten review.

## Preserved failure history

- The operator's separate twelve-file current-only review of 43bbb0486d0a3763a6f15ec4136830a8f04c29b4
  returned incomplete_review. It remains unavailable, not a pass or a substitute
  for the completed seven-file current/base review.

- Older e3f52d044afb0cfe75eaa9d31c9a56373c6b0e8f Linux jobs failed the stdin
  test's pipe-capacity assumption, with 3839 other tests and 51 subtests passed
  per operator verification. The existing corrected control fills the real
  review pipe to EAGAIN, checks child readiness, incomplete input, deadline and
  actual cleanup. No capacity guess, fake successful I/O, skip or limit change.
- That older source's real normal-Claude attempt was unavailable/process_exit,
  safe category missing_login, before review. The operator confirmed cleanup
  of all six supervised groups and unchanged source. It was not a review pass;
  no raw provider error is retained. Existing non-secret USER propagation fixes
  OS-login selection while keeping secrets and configuration overrides excluded.
- A previous local full-suite attempt stopped on 48 missing application
  dependency collection errors. It was not a full-suite pass. Initial bare
  interpreter pytest invocations were unavailable; installed pytest reuse
  subsequently passed. No installation or account/config mutation occurred.
- Installed Claude Code 2.1.319 help/version previously verified the requested
  flags and public model alias sonnet. Static flags and fake executables do
  not replace the independently reported real review.

## Historical URL-refusal handoff

At that handoff, the issue and PR recorded the revision/tree, four changed paths,
source hashes, validation and operator command. That immutable source's
independent follow-up review used
43bbb0486d0a3763a6f15ec4136830a8f04c29b4 as its comparison base and includes
the parser/tests and changed plan/worklog evidence. Keep current/base payload
within 192 KiB; describe-only launches no Claude. Existing completed helper
evidence is reused only by exact identity and retains its reviewed revision.

Keep GH-13 open in status:review with dispatch disabled for independent delta review.
Require structured source/key binding, full selected coverage, zero permission
denials, confirmed cleanup and unchanged source. Independently assess lifetime,
source binding and refusal. Existing authorization remains valid within scope.
Material-risk delivery stays WAIT for explicit human owner acceptance.
No merge, gated approval/HOLD, other-task promotion, application provider run,
credential-file access, install, daemon start, native operator execution,
authentication or permission change. Ordinary coding-account usage remains
separate from the USD20 application benchmark cap.

## Management CLI correction

- Actual host github_api observation at 2026-11-08T06:17:37Z: GH-13 open,
  assigned to utkutugrul, with symphony, status:active and dispatch:enabled.
  All six headings, distinct Codex/Claude roles and no dependencies matched the
  plan. The bounded actual-response snapshot passed before source changes.
- PR #20 remained open at e3a1f6e4955a5925bc8ba4c62c26f6585de38e9b on
  codex/gh-13-independent-claude-review. All eight existing delivery files matched
  that remote revision byte for byte. The original dirty/untracked workspace
  was preserved; an isolated validation clone continues the same issue branch.
  Only the checker, its tests, operations guide and these two evidence files
  change. Manual claims 10/11/12 and all other task records remain unchanged.
- Mixed --issue-snapshot/--require-live-claim now fails in argument parsing,
  before source/snapshot reads, authentication or transport. Separate successful
  outputs identify offline snapshot validation or a live GitHub fetch. Both
  retain explicit operator promotion; plan status remains coordination metadata.
- A specific ManagementError subtype preserves the fixed absolute deadline
  refusal through JSON decoding. Other ValueError/UnicodeError cases still
  suppress response details, duplicate keys and exception context.
- Before production edits, the 12 new regression cases against e3a1f6e produced
  eight failures and four passes, with 140 deselected. Both flag orders and
  existing/missing snapshot files failed; injected expiry during the current
  issue and both dependency decodes lost its diagnostic. Four malformed JSON,
  duplicate-key, nonfinite and invalid-encoding controls already kept redaction.
  No real signals, transport, credential or model calls were used in these tests.
- All 152 management tests pass on actual Python 3.11.15 and 3.14.10. Installed
  pytest 8.4.2 was reused without installation, with plugin autoload and cache
  disabled; each run reported one unknown asyncio_mode configuration warning.
  Ruff lint passed; its initial format check requested three wrapped print
  calls, which were corrected. Final lint/format, management contracts and
  whitespace are checked before the correction is committed.
- The helper, helper tests and procedure are unchanged. Executed helper bytes
  must match the committed helper, whose SHA-256 remains
  f64a4e4aaa7884728ab0901b7856589f4cc89636e08fc70766e65bbed843b1b2.
  Prior completed helper reviews retain their original revisions. The earlier
  e3a1f6e CI (3936 tests plus 63 subtests per Python version and 78 browser tests)
  and the operator's private integration rehearsal are historical evidence,
  not review or CI of this correction. The e3a1f6e owner question is superseded.
- Actual ordinary Claude Code 2.1.319 reviewed all five changed paths at
  2804a9d7b531305bf0b2a80a6ceb9c1f6c2e7ac7 against e3a1f6e, with key
  30fa5e8e4f9b3498af90850974a271a9172d31c5715ccb99a985dd422f6cd451.
  The model command completed in 19.899929 seconds with zero permission denials;
  all nine supervised groups were absent after retirement and scratch was
  removed. One P3 identified stale prior-handoff wording, now explicitly marked
  historical. No code finding was reported. The reviewer ran no tests and did
  not inspect the unchanged helper. This is that revision's evidence; the final
  worklog correction requires its own committed-source review.
- Freeze these five changed files with e3a1f6e as the comparison base for the
  installed ordinary Claude helper. This commit precedes its real final review
  and exact-head CI; actual availability, findings/triage, source/key bindings,
  process/scratch cleanup and CI outcomes will be recorded in GH-13 and PR #20
  against that immutable revision. A missing account or uncertain cleanup is
  unavailable, never a pass. No unchanged helper model scope is repeated.
- After successful correction checks, independent review and push, hand off
  with status:review and dispatch removed. Root must verify the exact new head
  before a new owner decision. Material-risk acceptance remains WAIT; no merge,
  approval/HOLD, auth change, provider-budget use or native operator execution.
  The operator maintains canonical work_state outside this child.
