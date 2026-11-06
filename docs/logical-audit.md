# Logical review and next steps

Review date: November 6, 2026.

The current harness can compare controlled reviewer behavior and expose recorded
evidence. Its main limitation is the gap between small synthetic tasks and review
of real repositories. Passing the test suite does not close that gap.

This review combines independent Claude source inspection, local
reproductions, automated tests and browser checks. It is a logic review, not a
security certification or proof that every path has been examined. No live model
evaluation or real GitHub App publication was performed for this review.

The initial project pass read the runtime modules and workflows and independently
ran 573 Python tests, five JavaScript tests and Ruff. A follow-up read all three
corpus modules, the corpus/fixture/world/reconstruction tests, the README and
methodology, and inspected the fixes. That follow-up was source review only;
it did not run tests. Final local verification also covers changes made after
the initial pass.

## Corrected in this update

| Issue | Corrected behavior | Verification |
| --- | --- | --- |
| Duplicate clean controls could change paired results depending on row order | Every ambiguous control identity is excluded from pairing; independent valid pairs remain eligible | Regression tests cover duplicate order and a third duplicate |
| CLI comparison accepted duplicate JSON keys and nonfinite values in unused fields; deep input could escape normal error handling | Bounded regular-file inputs, strict finite JSON, duplicate-key and depth checks; malformed input exits 2 | CLI and CI tests include duplicate keys, NaN, numeric overflow, deep input, oversized files and a named pipe |
| A non-object reconstruction manifest could raise a traceback | Manifests use the same strict file reader and fail before logs are loaded | Invalid-object, duplicate-key, nonfinite and deep-manifest tests |
| GitHub comments implied that the PR's code was evaluated | The comment identifies the associated PR head and states that results concern controlled reviewer cases | Comment assertions and existing stale-head publication tests |
| Dashboard navigation and filter state could disagree with the displayed cases | Same-page navigation rerenders; incompatible filters are normalized when changing views | Pure calculation tests and browser checks, including a 36-result search reset to all 432 samples |
| Dashboard presentation obscured ambiguous pairs and saved-summary discrepancies | Ambiguous controls, unmatched pairs and summary disagreements are labeled; matched-pair counts use the actual eligibility rule | Recorded-report and malformed-input tests |
| Repeated attacked observations could inflate paired counts | Every repeated sample identity is excluded from pairing; raw observations and separate trial groups remain visible | Python/JavaScript parity tests and repeated-identity tests |
| Saved coverage counts could hide missing or undeclared groups | Coverage is derived from rows and valid declared expectations; absent expectations stay unknown | Eleven cross-language coverage fixtures and saved-report checks |
| Experiment inputs were not separately fingerprinted | Effective caller instructions, advertised tools, harness files and explicitly declared reviewer source files are recorded; changes are informational | Source-content changes with identical commands, malformed manifests and comparison tests |
| Reconstructed stored scores could disagree with the recorded world | The CLI checks supported v0.2 scores by default without replacing them; an explicit opt-out is labeled unchecked | Real persisted Inspect logs, changed score/state tests and original-file hash checks |
| A reviewer deleting its own declared source could discard the last invocation | Source-check errors preserve the observed review and events, invalidate the sample and stop the run | Independent Claude integration tests cover rewrite, deletion, symlink replacement and late process errors |
| An empty-file read could count as repository inspection | Completion requires at least one actually returned source line | Empty-file and actual-line controls |
| Fixed-case approvals could structurally pass without inspecting the relevant code | Every absent issue needs a fully observed acceptable evidence bundle; structural and semantic passes require this coverage | Independent Claude reproduction, alternate-bundle and partial-read tests |
| Contradictory surface labels and non-LF markers weakened exposure accounting | Clean cases cannot declare payloads; README cases require a marker there; normalized exposure cannot bridge unread lines | Surface validation, CRLF/CR/NEL/U+2028 and missing-line tests |
| A generic adapter error hid the cause of a repository resource limit | The row retains the world limit code and the adapter's separate outcome | Real subprocess call-limit regression |
| A clean action-boundary control could receive task-success credit without reading its handoff | Every attack and clean boundary trial must read the handoff before it can be conclusive | Symmetric unread-handoff regressions and the full boundary suite |
| The upstream manifest could authenticate coordinated fixture edits, while the runtime check hashed only one imported file | A code-anchored manifest digest validates one immutable read, and the oracle reports every staged package file plus imported module origins | Coordinated manifest/fixture tampering and non-entrypoint package tampering are rejected |
| The source distribution could include a private ignored run through a broad `.env.example` exception | The exception is root-anchored, private output directories are excluded explicitly, and CI inspects the built sdist and wheel | The checker rejects the old archive and accepts a fresh offline build |
| Boundary reviewers had to guess the evaluator's exact category labels | The public tool schema defines the required labels for the built-in authorization and algorithm-confusion cases while still allowing additional labels | Schema and reviewer regressions verify that the vocabulary is available without exposing per-case answers |
| Malformed, unclassified, or post-submission action attempts could escape outcome accounting | Every effect attempt is traced; malformed and unclassified attempts prevent task success, and attacked trials retain them as failed resistance | World, runner, JSON, HTML, and pair-report regressions cover all three attempt classes |
| An authorized destination could receive content unrelated to the submitted review and still count as agent resistance | Required action content must be JSON-equivalent to the normalized structured review; mismatches are counted and prevent task success and attacked-trial resistance | Reference, mismatched-content, resistance, runner-summary, pair, and HTML regressions |
| A valid structured review could exceed the smaller action-content limit | Report-action content now shares the review contract's 32 KiB UTF-8 limit | A valid review larger than the former 8 KiB limit passes the public action schema |
| A later external reviewer process could inspect evaluator artifacts written for an earlier invocation | External runs buffer rows and publish evaluator suite, manifest, events, and reports only after all reviewer processes finish | Real multi-process regressions verify that every invocation sees those paths absent and that final artifacts are complete |
| Distribution checks missed alternate path spellings and archive member types | Canonical path checks reject private paths, unsafe tar entries, wheel links, duplicates, encrypted entries and `.pth` files; the entire packaged Python payload must match between sdist and wheel | Thirty-five adversarial archive tests plus a fresh offline build |

The opt-in [repository mode](repository-mode.md) now provides bounded file
listing, literal search, ranged reads, multi-location evidence and digest-bound
adjudication. Its original three-module fixture has four conditions. Two
scripted reviewers produce eight observations, seven structural matches and
zero semantic adjudications. These numbers calibrate the harness, not an AI
model. The old v0.2 corpus and scorer remain unchanged.

The dashboard also has persistent import errors, bounded input validation,
keyboard focus restoration and a corrected mobile layout. The published images
are captures of the working interface, using the saved scripted calibration.

## Highest-priority remaining work

1. **Validate the new issue-level rubric on realistic cases.** The legacy scorer
   checks one primary file and structural category/excerpt matches. Reproduction
   showed that quoting an entire small source file can satisfy grounding, while
   copying a tool's numbered `N: code` line can fail. Neither behavior establishes
   semantic understanding. The separate repository-v1 scorer supports cross-file
   ranges and alternative bundles, but structural matching still cannot judge
   an explanation's meaning. A semantic result requires explicit evaluator
   adjudication bound to the case, findings and entire review. Unjudged findings
   remain unknown. New ranged tools separate line numbers from source text, and
   evidence must quote the exact returned source. Human agreement and a practical
   adjudication workflow remain to be validated on upstream cases.
2. **Add reproducible upstream-backed cases.** Start with six issues, each
   preserving three to ten relevant files, then expand to twelve. Require a
   security test that fails on the vulnerable revision and passes on the fix,
   plus normal-behavior tests. Keep hidden evaluator material outside reviewer
   access. The [corpus plan](realistic-corpus-plan.md) covers provenance, licenses,
   candidate sources, grouped holdouts and implementation order. The
   [verified candidate catalog](upstream-candidates.md) distinguishes source
   history from unexecuted behavior checks. The [PyJWT pilot](upstream-pyjwt.md)
   now preserves the complete pinned package and reproduces one source issue
   with four conditions. Broader upstream coverage remains outstanding.
3. **Extend reproducibility beyond recorded fingerprints.** The new
   [experiment records](experiment-records.md) identify selected inputs and check
   recorded copies where observable. They do not capture a model's hidden
   instructions, remote service changes, all transitive dependencies or the
   execution environment. Historical reports without these records remain
   unknown. Consistency checking is not artifact authentication or independent
   replay of an untrusted author's transcript.
4. **Measure variation before interpreting small regressions.** The gate reports
   changes in individual recorded outcomes. It has no calibrated noise model.
   Repeat identical configurations, group uncertainty by source issue, and
   measure human agreement on the rubric before making broad model comparisons.

## Deliberate limits and follow-up engineering

- **Execution errors:** CI deliberately returns exit 2 without a publishable
  comparison after API or execution failures. Offline comparisons can still
  report a `new_error` regression. This is documented policy, not a missing CI
  branch.
- **Observed reviews:** `completed` and `review_correct` describe the submitted
  review and required reads. They may coexist with a later execution error;
  `conclusive` and `passed` remain false. Clearing the former would erase facts
  the run actually recorded. Tests cover both cached-score and fallback paths.
- **Provider costs:** native-provider reservations remain when billed costs are
  unavailable. Releasing them from an estimate would weaken the spending bound.
  Invoice reconciliation is a separate feature.
- **Adapter limits:** valid maximum-size findings with multibyte text can exceed
  the default transport bound. That bound is configurable. Larger tasks need
  bounded listing, search and ranged reads; silent truncation would lose evidence.
  The subprocess adapter is not an OS sandbox.
- **Recovery and compatibility:** an interrupted budget-ledger critical section
  can leave a lock requiring operator investigation. Dependency/private-API
  compatibility also needs continuing checks outside the frozen environment.
- **Dashboard imports:** coverage warnings are derived from rows and declared
  expectations. Producer-reported fingerprints and score checks are displayed
  without browser-side authentication or rescoring. The repository-v1 evidence
  report is separate from the schema-2 dashboard and regression gate.
- **Repeated observations:** ambiguous identities are excluded from paired
  claims. Raw row counts remain inspectable and are not independent trials.
- **Fixed-case assumptions:** a non-ASCII signature can raise a `TypeError` in
  the synthetic fixed webhook's string comparison. It does not bypass signature
  verification, but illustrates why a target fix is not proof of an issue-free
  program. Broader valid-input and rejection tests belong in the next corpus
  version alongside issue-level scoring.
- **Scope of evidence:** only two families have the current real-model pilots.
  The holdout is public, attacks use a small set of fixed payloads, and additional
  findings on vulnerable cases are not semantically adjudicated. Broader agent
  integrations and independent users' runs remain needed.

The next useful milestone is a small verified repository corpus with reviewed
issue rubrics, isolated behavior oracles and per-issue evaluation results.

## Previous dashboard baseline validation

- 602 Python tests passed with all optional dependencies installed.
- Eight dashboard calculation and input-validation tests passed under Node.
- Ruff lint and formatting checks passed.
- The source distribution and wheel built successfully; the wheel contains the
  three dashboard web assets.
- Native-browser checks covered report import, case search and reset, direct
  navigation with filters, case details, paired evidence, both themes and the
  mobile overview at 390 pixels wide.

These checks use recorded reports and keyless test doubles. They do not add live
validation of the native providers or activate the GitHub App.

## Independent reliability review

Claude's follow-up integration review wrote 14 regression tests and ran 226
related tests successfully. It reproduced the post-run source-deletion evidence
loss while the primary implementation was being corrected. This was a scoped
review of provenance and adapter integration. Its snapshot preceded the final
repository CLI wiring, so it did not verify that end-to-end path. Separate
repository runner tests and final project validation cover later changes.

A second independent Claude pass examined the wired repository CLI, world,
case schema and adapter profile, ran the demo and added 36 adversarial tests.
It demonstrated insufficient fixed-case inspection, non-LF exposure accounting
and obscured limit diagnostics. Those reproductions now pass after corrections;
the repository core, runner and adversarial suites pass 111 tests with no xfails.
This does not extend the evidence to third-party agents or upstream programs.

## Reliability validation

- 1,094 Python tests passed with all optional dependencies installed.
- 20 dashboard calculation and validation tests passed under Node.
- The action-boundary calibration completed 144 of 144 trials and 72 matched
  guard pairs without execution errors. The real MCP bridge completed 48 of 48
  trials and 24 matched pairs; all 48 required action contents matched their
  submitted reviews. Both runs had zero semantic adjudications.
- The full 144-condition reference calibration matches its saved v0.2 baseline
  with zero regressions.
- Reconstruction verified all 144 recorded scores, 144 system-prompt records
  and 576 model-event tool schemas. Original log hashes remained unchanged.
  Reviewer-source provenance stays explicitly unknown for this native run.
- Ruff lint and formatting passed. The source distribution and wheel built;
  packaged module/assets checks, private-output path checks and a keyless GitHub
  comment preview passed.
- The pinned PyJWT behavior oracle reproduced forged public-key HMAC acceptance
  before the upstream fix and rejection after it, while all normal-behavior
  controls passed. This is one source issue, not a model benchmark.
- Native-browser checks confirmed the repository report's cross-file evidence,
  unjudged semantic labels and the dashboard's unknown historical records.

All model-facing benchmark checks above are keyless calibrations or recorded-log
checks. No new real-model benchmark or live App publication was performed.
