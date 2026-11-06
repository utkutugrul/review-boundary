# Logical review and next steps

Review date: November 6, 2026.

The current harness can compare controlled reviewer behavior and expose recorded
evidence. Its main limitation is the gap between small synthetic tasks and review
of real repositories. Passing the test suite does not close that gap.

This review combines independent Claude Sonnet 5.5 source inspection, local
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

The dashboard also has persistent import errors, bounded input validation,
keyboard focus restoration and a corrected mobile layout. The published images
are captures of the working interface, using the saved scripted calibration.

## Highest-priority remaining work

1. **Version the scorer for realistic multi-file issues.** The current scorer
   checks one primary file and structural category/excerpt matches. Reproduction
   showed that quoting an entire small source file can satisfy grounding, while
   copying a tool's numbered `N: code` line can fail. Neither behavior establishes
   semantic understanding. New issue-level evidence rules should accept relevant
   cross-file spans and equivalent valid findings, judge false positives, and
   handle numbered excerpts deliberately. Retain historical v0.2 scores under
   their original contract.
2. **Add reproducible upstream-backed cases.** Start with six issues, each
   preserving three to ten relevant files, then expand to twelve. Require a
   security test that fails on the vulnerable revision and passes on the fix,
   plus normal-behavior tests. Keep hidden evaluator material outside reviewer
   access. The [corpus plan](realistic-corpus-plan.md) covers provenance, licenses,
   candidate sources, grouped holdouts and implementation order. No new cases
   are included in this update.
3. **Make experiment provenance more explicit.** Record the effective prompt,
   tool-schema and reviewer-source fingerprints. Display intentional changes
   rather than requiring equality, because testing a changed prompt or reviewer
   is a core use case. The existing suite digest and adapter configuration hash
   do not capture all of this information.
4. **Check reconstructed-score consistency without rewriting history.** Current
   log validation can accept stored score flags that disagree with the stored
   world, and reporting preserves the original scores. Add an explicit check
   against the matching versioned scorer, report discrepancies, and distinguish
   original scores from any requested rescoring. Neither check authenticates a
   log supplied by an untrusted author.
5. **Measure variation before interpreting small regressions.** The gate reports
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
- **Dashboard imports:** coverage warnings use recorded coverage metadata. The
  dashboard is a viewer, not a substitute for the strict comparison gate, a
  provenance verifier or a rescorer.
- **Duplicate attacked observations:** arbitrary rows passed to the summary can
  still repeat an attacked sample and inflate paired counts. Strict comparison
  and reconstruction reject duplicate samples. Summary-level deduplication is
  remaining work; raw imported row counts should not be treated as independent
  trials.
- **Fixed-case assumptions:** a non-ASCII signature can raise a `TypeError` in
  the synthetic fixed webhook's string comparison. It does not bypass signature
  verification, but illustrates why a target fix is not proof of an issue-free
  program. Broader valid-input and rejection tests belong in the next corpus
  version alongside issue-level scoring.
- **Scope of evidence:** only two families have the current real-model pilots.
  The holdout is public, attacks use a small set of fixed payloads, and additional
  findings on vulnerable cases are not semantically adjudicated. Broader agent
  integrations and independent users' runs remain needed.

The source-inspection passes and test results should be read with these limits.
The next useful milestone is a small verified repository corpus with a versioned
multi-file rubric, not a larger count of loosely labeled examples.

## Final local validation

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
