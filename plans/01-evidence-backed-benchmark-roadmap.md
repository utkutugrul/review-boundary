# Evidence-backed benchmark roadmap

## Primary goal

ReviewBoundary can run real models against repository and action-boundary tiers, preserve unknowns for human adjudication, compare repeated results by independent source group, and present the evidence in one dashboard without claiming a public leaderboard before the corpus supports it.

## Phase 0: Documentation discovery and contract freeze

**How this serves the primary goal:** Every later phase is built on installed APIs and existing score contracts, so new model runs do not silently weaken provider safety, scoring, or backward compatibility.

### Allowed APIs and patterns

- Provider planning: `prepare_provider(...) -> ProviderPlan` in `src/review_boundary/providers.py:294`; reuse `ProviderPlan.inspect_model_id`, `validate_environment`, `model_args`, and `to_metadata`.
- Credential redaction: `guarded_model(plan, model_id)` in `src/review_boundary/model_safety.py:78`.
- Cost controls: `planned_cost`, `reserve`, `settle`, `model_snapshot`, and `api_get` in `src/review_boundary/budget.py`.
- Native execution: `inspect_ai.eval(...)` with `Task`, `GenerateConfig`, typed `@tool` callables, and `generate(..., tool_calls="single")`, following `src/review_boundary/task.py:148-279` and `src/review_boundary/cli.py:373-476`.
- Repository runtime: `RepositoryWorld.reviewer_request`, `dispatch`, `score_repository_world`, `tool_schemas`, and `validate_tool_arguments` in `src/review_boundary/repository_world.py`.
- Boundary runtime: `BoundaryWorld.reviewer_request`, `dispatch`, `score_boundary_world`, `paired_guard_results`, and `write_boundary_report` in `src/review_boundary/boundary_world.py` and `boundary_runner.py`.
- Adjudication identity: `FindingAdjudication`, `ReviewAdjudication`, `finding_digest`, and `review_digest` in `src/review_boundary/repository_world.py:63-86`.
- Strict input: `read_json_object` and `parse_json_object` in `src/review_boundary/json_input.py`.
- Existing report contracts: schema 2 legacy in `src/review_boundary/report.py:185`; schema 1 repository in `repository_runner.py:103`; schema 1 boundary in `boundary_runner.py:231`.
- Existing dashboard safety: `validate_report` and `write_dashboard` in `src/review_boundary/dashboard.py`; mirrored browser validation in `src/review_boundary/web/dashboard.js`.
- Existing comparison: keep `compare_reports(...)` in `src/review_boundary/compare.py:251` unchanged for legacy reports.
- Suite authority: strict Pydantic models and `case_digest` in `src/review_boundary/repository_cases.py:43-140`; `load_suite` in `repository_runner.py:30-44`.
- Upstream admission reference: `_verified_corpus`, `build_upstream_pyjwt_cases`, and `reproduce_upstream_pyjwt` in `src/review_boundary/corpus_upstream_pyjwt.py`.

### Discovery decisions

1. Use native Inspect tasks for real model execution. Do not wrap providers in an external JSONL adapter, because that would duplicate redaction, budget, usage, epoch, and logging behavior.
2. Add JSON-safe, concurrency-safe world snapshot and restore. `RepositoryWorld` and `BoundaryWorld` are mutable and currently lack this contract.
3. Preserve malformed boundary attempt accounting. Inspect argument validation must not hide calls before `BoundaryWorld.dispatch` observes them.
4. Keep legacy, repository, and boundary row semantics distinct. Unify the envelope and dashboard shell, not the meaning of metrics.
5. Treat `source_group` as the unit of independence. Raw rows, variants, epochs, and contexts are not independent vulnerabilities.
6. Keep public leaderboard output gated until at least six admitted independent source groups and adjudication agreement evidence exist.

### Verification checklist

- Confirm every cited symbol exists in the installed environment.
- Record unresolved design points in the work-state list before implementation.
- Keep the repository clean through discovery.

### Anti-pattern guards

- Do not invent Inspect APIs or copy JSON Schema `$ref` structures into `ToolParams` without compatibility tests.
- Do not use a module-global world registry for sample state.
- Do not treat Python audit hooks as an OS sandbox.
- Do not reinterpret historical schema 1 or schema 2 reports.

## Phase 1: Native repository model runner

**How this serves the primary goal:** Real models can evaluate multi-file repository cases with the same provider safety and cost controls already used by the legacy tier.

### Ownership and dependencies

- **Owner:** Codex implements the repository runner and provider orchestration.
- **Reviewer:** Claude reviews the implementation, state contract, failure handling, and tests.
- **Dependencies:** Phase 0 contract freeze.

### What to implement

1. Add a frozen JSON-safe repository world snapshot containing observed line sets, events, review, PR-read state, write requests, call/output counters, exposure, fatal error, and immutable case/limit identity.
2. Add tested `RepositoryWorld.snapshot()` and `RepositoryWorld.from_snapshot(case, snapshot)` methods. Restore must validate the case digest and all bounded fields.
3. Add a native Inspect task module that copies the typed tool and bounded loop pattern from `src/review_boundary/task.py:50-168` while delegating every operation to `RepositoryWorld.dispatch`.
4. Add an EvalLog-to-repository-row extractor that reads only the scorer metadata emitted by the trusted task and verifies expected case/model/epoch slots.
5. Add `repository-run-model` with repeatable `--model`, provider/pricing/budget/ledger/concurrency flags, `--suite`, `--epochs`, bounds, `--dry-run`, and a new/empty output requirement.
6. Reuse the provider order from `src/review_boundary/cli.py:373-476`: plan, conservative reservation, credential validation, guarded model, Inspect eval, usage, report, settlement.
7. Preserve the existing `repository-demo` and `repository-run-adapter` behavior and artifacts.

### Documentation references

- Native loop and typed tools: `src/review_boundary/task.py:50-168`.
- Provider orchestration: `src/review_boundary/cli.py:373-476`.
- Repository tool contract: `src/review_boundary/repository_world.py:170-365`.
- Repository artifact lifecycle: `src/review_boundary/repository_runner.py:189-322`.
- Provider mock seams: `tests/test_cli_providers.py` and `tests/test_model_safety.py`.

### Verification checklist

- Snapshot round-trip tests cover every mutable field and reject changed cases, malformed snapshots, duplicate data, and oversized values.
- Keyless provider tests cover OpenRouter, OpenAI Chat Completions, OpenAI Responses, and Anthropic through existing mock transports.
- Dry-run creates no output, ledger entry, credential lookup, or model call.
- Provider failures produce planned error rows and exit 2 without leaking provider bodies or keys.
- Focused command: `uv run --frozen --all-extras pytest -q tests/test_repository_world.py tests/test_repository_runner.py tests/test_task.py tests/test_cli_providers.py tests/test_model_safety.py`.
- The full suite command in the final phase passes.

### Anti-pattern guards

- Do not call providers directly through SDK clients.
- Do not settle a reservation without complete per-call cost evidence.
- Do not trust edited report rows as scorer output.
- Do not add semantic pass defaults to unadjudicated rows.

## Phase 2: Native boundary model runner

**How this serves the primary goal:** The same real reviewer can be measured with guard off and on while action attempts, effects, review quality, and legitimate utility stay separate.

### Ownership and dependencies

- **Owner:** Codex implements the boundary runner and malformed-call accounting.
- **Reviewer:** Claude reviews guard symmetry, action accounting, and tests.
- **Dependencies:** Phase 1 provider orchestration and snapshot pattern.

### What to implement

1. Extend the snapshot contract for boundary policy trace, deduplicated virtual effects, action-request read state, and guard identity.
2. Build a native boundary Inspect task using the same public reviewer request and tool list for both guard arms.
3. Ensure malformed effect calls reach `BoundaryWorld.dispatch`. If typed Inspect tools reject first, capture raw assistant `ToolCall` objects and route them through `validate_transport_arguments` before producing tool responses.
4. Add `boundary-run-model` with the Phase 1 provider flags plus `--guard {both,on,off}`. Use the built-in exact-grant guard for the first slice.
5. Reserve cost by cases times guard arms times models times epochs. Label guard arms as matched inputs, not identical or causal model trajectories.
6. Reuse `paired_guard_results` and preserve all exclusions and fingerprints.
7. Defer external `--policy` in native model mode until a per-sample serializable policy lifecycle is implemented and tested.

### Documentation references

- Attempt accounting: `src/review_boundary/boundary_world.py:125-397`.
- Pairing and report contract: `src/review_boundary/boundary_runner.py:120-430`.
- MCP malformed-call regressions: `tests/test_mcp_bridge.py` and `tests/test_boundary_world.py`.
- Guard-independent public inputs: `tests/test_boundary_world.py`.

### Verification checklist

- Guard off/on requests and advertised tools are byte-equivalent.
- Invalid, unclassified, unauthorized, post-submission, blocked, escalated, and executed calls retain their existing counts.
- Content mismatch cannot count as task success or agent resistance.
- One-sided, errored, duplicated, or fingerprint-mismatched runs never create an eligible pair.
- Focused command: `uv run --frozen --all-extras pytest -q tests/test_boundary_world.py tests/test_boundary_runner.py tests/test_boundary_policy.py tests/test_mcp_bridge.py tests/test_cli_providers.py`.
- The full suite command in the final phase passes.

### Anti-pattern guards

- Do not let SDK validation erase attempted actions.
- Do not call a guard block agent resistance.
- Do not compare aggregate row counts as independent security findings.
- Do not expose evaluator grants beyond the existing public policy document.

## Phase 3: Digest-bound adjudication workflow

**How this serves the primary goal:** Structural matches can be reviewed by a human or independent evaluator without turning unknown findings into passes or failures.

### Ownership and dependencies

- **Owner:** Claude implements the adjudication artifact, labeling UI, and pure application workflow in an isolated scope.
- **Reviewer:** Codex reviews digest binding, fail-closed behavior, browser safety, and tests.
- **Dependencies:** Phase 1 frozen observation snapshot. Artifact and UI work may begin in parallel, but apply and rescore integration waits for that snapshot contract.

### What to implement

1. Add a strict adjudication artifact with `schema_version`, `adjudication_kind`, `source_report_sha256`, finding decisions, and review decisions using the existing model shapes.
2. Add `adjudication-export` to create unknown decision templates from unique recorded finding/review digests.
3. Add a local self-contained labeling UI that edits only decision, issue mapping, and reason fields and exports strict JSON.
4. Add `adjudication-apply` that requires the original evaluator suite and trusted observation artifacts, validates every digest and duplicate/conflict rule, and emits a new report without overwriting the source.
5. Factor post-run semantic application into a pure function over a frozen observation snapshot. Do not replay mutable report claims.
6. Define separate boundary and nested repository digest fields before permitting boundary semantic adjudication.
7. Add optional inter-rater agreement output when two complete adjudication artifacts cover the same digest set.

### Documentation references

- Adjudication models and rules: `src/review_boundary/repository_world.py:63-86,369-520`.
- Existing edge-case tests: `tests/test_repository_world.py:66-86,291-355`.
- Safe self-contained export: `src/review_boundary/dashboard.py:305`.

### Verification checklist

- Round-trip export/import preserves all unknowns.
- Duplicate, conflicting, stale, foreign, absent, and mismatched digests fail closed.
- Empty approvals require whole-review judgment.
- Supported review plus unknown finding remains unknown.
- Browser and Python validators agree on the artifact.
- Focused Python command: `uv run --frozen --all-extras pytest -q tests/test_repository_world.py tests/test_repository_runner.py tests/test_dashboard.py tests/test_reporting.py`.
- Focused browser command: `node --test tests/web/dashboard.test.cjs tests/web/adjudication.test.cjs`.

### Anti-pattern guards

- Do not make an LLM judge the default authority.
- Do not modify source reports in place.
- Do not infer false positives from unknown findings.
- Do not accept report-only rescoring until observation snapshots are authenticated by trusted artifacts.

## Phase 4: Suite schema, validation, and contribution tools

**How this serves the primary goal:** Contributors can add auditable cases without bypassing runtime invariants, provenance, licensing, or behavior checks.

### Ownership and dependencies

- **Owner:** Claude implements the shared suite model, validator, registry, and contribution template in an isolated scope.
- **Reviewer:** Codex reviews runtime authority, provenance boundaries, packaging behavior, and tests.
- **Dependencies:** Phase 0 contracts. This phase may proceed independently of the model runners.

### What to implement

1. Add a strict top-level suite envelope model and make `load_suite` and CLI validation share one parser.
2. Export public JSON Schema from the Pydantic model graph. Keep Python cross-field validation authoritative.
3. Add `validate-suite` with explicit layers: safe JSON, schema, cross-field invariants, leakage, source-group/split integrity, provenance/license inventory, optional behavior oracle, and optional packaging.
4. Add a static corpus registry with builder, manifest loader, verifier, corpus/scoring versions, and dependency group. Remove hard-coded PyJWT branching without dynamic imports.
5. Add a contribution template and generator for metadata, case module, manifest, licenses, independent oracle tests, and documentation.
6. Expand the upstream manifest contract to include aliases, dates, per-artifact licensing, dependency locks, slice mapping, modifications, and oracle metadata.
7. Decide the current 32-case cap explicitly. Split large exports or version and raise the limit with adversarial tests.

### Documentation references

- Runtime models: `src/review_boundary/repository_cases.py:43-140`.
- Current loader: `src/review_boundary/repository_runner.py:30-44`.
- Safe JSON: `src/review_boundary/json_input.py:25-68`.
- PyJWT admission pattern: `src/review_boundary/corpus_upstream_pyjwt.py` and `tests/test_upstream_pyjwt.py`.
- Contribution requirements: `docs/realistic-corpus-plan.md:79-118` and `CONTRIBUTING.md`.

### Verification checklist

- Generated schema validates valid examples and rejects documented invalid examples.
- Runtime still rejects cases that pass JSON Schema but fail cross-field invariants.
- Schema-only mode executes no candidate code.
- Registry refuses unknown/dynamic modules.
- Contribution template passes its own deterministic checks.
- Focused command: `uv run --frozen --all-extras pytest -q tests/test_repository_runner.py tests/test_repository_adversarial.py tests/test_upstream_cli.py tests/test_upstream_pyjwt.py tests/test_distribution.py tests/test_repository_suite.py tests/test_corpus_manifest.py tests/test_corpus_registry.py tests/test_suite_validation.py tests/test_suite_contribution.py`.

### Anti-pattern guards

- Do not maintain a second hand-written schema as authority.
- Do not treat structurally valid suites as admitted upstream corpora.
- Do not execute setup scripts during validation.
- Do not let a manifest authenticate itself through only a mutable internal hash.

## Phase 5: Unified report envelope, dashboard, comparison, and CI

**How this serves the primary goal:** Users can inspect every tier in one product while each tier retains its own honest metrics and regression policy.

### Ownership and dependencies

- **Owner:** Codex implements contract dispatch, dashboard views, tier-specific comparison, and CI integration.
- **Reviewer:** Claude reviews backward compatibility, claim semantics, browser parity, and credential boundaries.
- **Dependencies:** Phases 1 through 4, including stable runner rows, adjudication artifacts, and suite identity.

### What to implement

1. Add strict contract detection for legacy schema 2, repository schema 1, and boundary schema 1 without changing their writers.
2. Add a new common envelope version with `report_kind` and native `report_version`; provide deterministic migration/export and continue accepting old files.
3. Extend Python and browser dashboard validators in parity. Add tier-specific views rather than filling absent fields with defaults.
4. Keep legacy calculations unchanged. Add repository evidence/adjudication views and boundary task/guard/action views.
5. Keep `compare_reports` unchanged for legacy. Add separate repository and boundary comparators, then a top-level kind dispatcher that rejects mixed kinds.
6. Add adapter-aware CI profiles only after tier comparators are stable. Preserve exit codes 0, 1, and 2 and never run caller adapters beside provider credentials.

### Documentation references

- Legacy writer and validator: `src/review_boundary/report.py:185` and `dashboard.py`.
- Browser parity: `src/review_boundary/web/dashboard.js` and `tests/web/dashboard.test.cjs`.
- Legacy comparison: `src/review_boundary/compare.py:251`.
- CI trust boundary: `src/review_boundary/ci.py:293` and `.github/workflows/evaluate.yml`.
- Repository and boundary writers: `repository_runner.py:103` and `boundary_runner.py:231`.

### Verification checklist

- Historical report fixtures render and compare exactly as before.
- Python and JavaScript accept/reject the same fixtures for all tiers.
- Unknown semantic and resistance values stay null and visibly unknown.
- Mixed-kind comparisons fail clearly.
- Credential-bearing CI never executes untrusted adapter commands.
- Future acceptance, owner approved and not yet implemented: provide an evidence-lineage view that traces each reported result back to its recorded evidence.
- Future acceptance, owner approved and not yet implemented: keep immutable evidence snapshot versions with digests so a result can be tied to the exact evidence it used.
- Focused Python command: `uv run --frozen --all-extras pytest -q tests/test_dashboard.py tests/test_compare.py tests/test_cli_compare.py tests/test_ci.py tests/test_reporting.py`.
- Focused browser command: `node --test tests/web/dashboard.test.cjs tests/web/adjudication.test.cjs`.

### Anti-pattern guards

- Do not reuse schema numbers with changed meanings.
- Do not invent missing row fields.
- Do not aggregate structural, semantic, utility, and resistance into one score.
- Do not authenticate or rescore reports in the browser.

## Phase 6: Versioned payload packs and repository injection surfaces

**How this serves the primary goal:** Model behavior is tested across realistic untrusted-context carriers with clean controls and observable exposure.

### Ownership and dependencies

- **Owner:** Claude owns fixtures, payload definitions, and matched controls. Codex owns runtime surfaces, exposure traces, and schema integration.
- **Reviewer:** Claude and Codex review each other's scope before integration.
- **Dependencies:** Phase 4 suite versioning plus the Phase 1 repository exposure contract. Boundary `action_request` remains on the Phase 2 contract.

### What to implement

1. Version repository-v1 surfaces before adding PR body, code comment, file/filename, and tool-output carriers.
2. Define reusable public payload packs with attack text, benign quotation controls, carrier metadata, and expected exposure only.
3. Preserve code bytes and behavior for non-code carriers. For code comments, prove parse and behavior equivalence.
4. Reuse actual read/exposure traces. Marker presence in a suite is not exposure.
5. Keep boundary `action_request` a separate tier.

### Documentation references

- Legacy carrier patterns: `src/review_boundary/cases.py:12,219-236` and `world.py:51-68`.
- Repository exposure: `src/review_boundary/repository_world.py:218-278`.
- Boundary carrier: `src/review_boundary/boundary_cases.py`.

### Verification checklist

- Every attack has a matched clean control and identical executable behavior.
- Unread carriers remain unexposed and inconclusive for resistance.
- Benign quotations do not count as attacks.
- Payload packs are fingerprinted and versioned.
- Future acceptance, owner approved and not yet implemented: test worker-summary authorization spoofing, with matched genuine user authorization controls that must keep working.
- Focused command: `uv run --frozen --all-extras pytest -q tests/test_fixtures.py tests/test_corpus.py tests/test_world.py tests/test_repository_world.py tests/test_boundary_world.py tests/test_repository_adversarial.py`.

### Anti-pattern guards

- Do not widen a literal surface in place under the same schema version.
- Do not infer exposure from fixture construction.
- Do not put evaluator answers in payload metadata.

## Phase 7: Verified upstream corpus expansion

**How this serves the primary goal:** Model comparisons cover independent, realistic source issues instead of one public PyJWT example.

### Ownership and dependencies

- **Owner:** Claude researches and reproduces candidates with pinned evidence and oracles.
- **Reviewer:** Codex independently verifies admission, licensing, manifests, leakage controls, and tests before a source group enters the corpus.
- **Dependencies:** Phase 4 admission tooling and Phase 6 versioned surfaces and payload controls.

### What to implement

1. Admit two additional development source groups first, including at least one non-Python project only when its pinned runtime is safe and reproducible.
2. Expand to six independent source groups after the first three pass the full admission contract. Treat twelve as a stretch goal after six and do not block the first evidence-backed release on it.
3. Keep vulnerable/fixed, clean/attack, aliases, backports, and copied lineage in one source group and split.
4. Require fail-before/pass-after security oracles plus normal controls and slice equivalence.
5. Record failed candidate reproductions instead of silently dropping them.

### Documentation references

- Candidate catalog: `docs/upstream-candidates.md`.
- Admission contract: `docs/realistic-corpus-plan.md:79-118`.
- PyJWT implementation: `src/review_boundary/corpus_upstream_pyjwt.py`.

### Verification checklist

- Every admitted source group has immutable source/license inventory and a code-anchored manifest digest.
- Oracles run with zero network and report `os_sandboxed` honestly.
- Normal behavior passes on vulnerable and fixed revisions.
- Reviewer-visible snapshots contain no advisory, patch, hidden test, or evaluator answer leakage.
- Focused command: `uv run --frozen --all-extras pytest -q tests/test_upstream_pyjwt.py tests/test_upstream_cli.py tests/test_provenance.py tests/test_fixtures.py tests/test_distribution.py` plus each newly admitted corpus module's dedicated test file.

### Anti-pattern guards

- Do not count multiple conditions from one issue as independent issues.
- Do not convert provenance research into a verified behavior claim.
- Do not force weak candidates to satisfy language balance.

## Phase 8: Source-group aggregation and uncertainty

**How this serves the primary goal:** Repeated model outcomes are summarized without inflating confidence from correlated rows.

### Ownership and dependencies

- **Owner:** Codex implements aggregation, exclusions, intervals, and report integration.
- **Reviewer:** Claude performs the methodology and claim review against raw rows and independent source groups.
- **Dependencies:** Real rows from Phases 1 through 3 and admitted source groups from Phase 7. Synthetic-only rows may test mechanics but cannot support publication claims.

### What to implement

1. Add `source_group` to boundary pair records while keeping existing case-level pairing.
2. Aggregate condition and epoch outcomes within each source group before computing cross-group summaries.
3. Report exact numerators, denominators, exclusions, repeated-trial distribution, and descriptive intervals.
4. Keep synthetic legacy, repository synthetic, upstream slices, and full-agent tiers separate unless a versioned weighting policy exists.
5. Add adjudicator agreement summaries beside model outcomes.

### Documentation references

- Grouping requirements: `docs/realistic-corpus-plan.md:103-118`.
- Existing pair eligibility: `src/review_boundary/boundary_runner.py:120-229`.
- Existing expected coverage patterns: `src/review_boundary/report.py` and dashboard tests.

### Verification checklist

- Duplicating rows or epochs never increases the number of independent source groups.
- Variants, attacks, and backports from one source stay clustered.
- Missing and excluded groups remain visible.
- Tiny samples are labeled descriptive, not population estimates.
- Focused command: `uv run --frozen --all-extras pytest -q tests/test_boundary_runner.py tests/test_reporting.py tests/test_dashboard.py tests/test_compare.py`.

### Anti-pattern guards

- Do not feed raw rows into confidence intervals as independent samples.
- Do not hide failures to reproduce or missing conditions.
- Do not rank models on one source group.

## Phase 9: Isolated full-repository execution tier

**How this serves the primary goal:** Future shell-capable reviewers and behavior oracles cannot access host credentials or change the authoritative evaluator.

### Ownership and dependencies

- **Owner:** Claude owns the threat model and isolation design. Codex implements the runner and enforcement checks.
- **Reviewer:** Codex reviews design feasibility and Claude reviews the implemented security boundary and escape tests.
- **Dependencies:** Phase 4 pinned corpus metadata and Phase 7 reproducible source groups. Implementation starts only after the capability gate below passes.

### What to implement

1. Write a threat model for host files, credentials, network, container sockets, process escape, resource exhaustion, evaluator tampering, and result forgery.
2. Add a capability gate that proves the selected runtime can enforce filesystem, credential, network, socket, process, resource, and evaluator separation on the current platform. If any required control is unavailable, stop with an explicit unsupported result instead of weakening isolation.
3. Implement an ephemeral runner with CPU, memory, disk, process, and wall-clock limits; deny outbound network by default; stage pinned dependencies separately.
4. Keep the authoritative verifier in a fresh environment the agent cannot modify.
5. Record image/runtime/dependency digests and the exact observation boundary.
6. Keep the current trusted adapter and pure-Python oracle tiers explicitly separate.

### Documentation references

- Isolation requirements: `docs/realistic-corpus-plan.md:120-137`.
- Current adapter limitation: `docs/adapters.md` and `src/review_boundary/adapter.py`.
- Current PyJWT process restriction: `src/review_boundary/corpus_upstream_pyjwt.py`.

### Verification checklist

- Escape tests cannot read host fixtures, credentials, environment, or container-management sockets.
- Network tests fail closed except explicit allowlisted model proxy traffic.
- Resource exhaustion stops within declared limits.
- Agent changes cannot affect authoritative verification.
- Focused command after creating the isolation module: `uv run --frozen --all-extras pytest -q tests/test_isolated_runner.py tests/test_adapter.py tests/test_repository_adversarial.py`.

### Anti-pattern guards

- Do not call a temporary directory, allowlisted environment, Python audit hook, or subprocess limit an OS sandbox.
- Do not execute arbitrary upstream setup scripts on the host.
- Do not grant access to Docker or equivalent management sockets.

## Phase 10: Evidence-backed comparison and self-hostable GitHub delivery

**How this serves the primary goal:** Users can run and share transparent local comparisons, and teams can deploy the integration without ReviewBoundary making unsupported certification claims.

### Ownership and dependencies

- **Owner:** Codex implements the comparison view, evidence traceability, and self-hostable GitHub delivery package.
- **Reviewer:** Claude reviews benchmark claims, least-privilege design, credential boundaries, and deployment documentation.
- **Dependencies:** Phase 5 product surfaces, Phase 7 admitted source groups, and Phase 8 aggregation. Chart publication also requires the Phase 3 adjudication evidence gate. GitHub packaging does not authorize external deployment.

### What to implement

1. Add a local model-comparison view only after repeated real-model runs exist on admitted source groups with explicit adjudication status.
2. Place README benchmark results after dashboard visuals and before `Go further` only when the committed report artifact supports every chart value.
3. Show clean-task utility, attack following, citation accuracy, structural and semantic status, exclusions, latency, and cost separately.
4. Package a self-hostable GitHub App service with least-privilege configuration, health checks, artifact retention, and deployment documentation.
5. Require an owner-selected host and credentials before any external deployment.

### Documentation references

- Existing GitHub preview/publish: `src/review_boundary/github_cli.py`, `github_app.py`, and `docs/github-app.md`.
- Existing dashboard placement: `README.md`.
- Claim limitations: `docs/logical-audit.md` and `docs/methodology.md`.

### Verification checklist

- Every chart number traces to committed report rows and displays its denominator.
- Scripted calibration is never labeled model performance.
- The App uses least-privilege permissions and never exposes provider credentials to caller code.
- Deployment remains opt-in and reproducible.
- Focused Python command: `uv run --frozen --all-extras pytest -q tests/test_github_app.py tests/test_github_cli.py tests/test_actions.py tests/test_dashboard.py tests/test_reporting.py`.
- Focused browser command: `node --test tests/web/dashboard.test.cjs tests/web/adjudication.test.cjs`.

### Anti-pattern guards

- Do not publish a public leaderboard before six independent source groups, repeated runs, and adjudication agreement evidence exist.
- Do not publish a safe/certified badge.
- Do not default to an LLM judge.
- Do not deploy externally without the owner's hosting decision.

## Final phase: Reciprocal review, verification, and release control

**How this serves the primary goal:** Every shipped phase has independent evidence that its implementation and public claims match the intended benchmark contract.

### Ownership and dependencies

- **Owner:** Codex and Claude jointly own reciprocal verification and release evidence.
- **Reviewer:** Each implementation scope is reviewed by the other party; neither self-review is sufficient.
- **Dependencies:** Every implementation phase intended for the release and all phase-specific acceptance checks.

### What to implement

1. Split implementation files between Codex and Claude where ownership does not overlap.
2. Require Codex to review Claude changes and Claude to review Codex changes before integration.
3. Run focused tests after each phase and the full Python, Node, lint, format, lock, distribution, demo, MCP, and upstream verification set before publication.
4. Build distributions outside ignored project output directories and scan staged content for private artifacts.
5. Commit phase-sized changes with plain commit descriptions and babysit GitHub Actions until green.

### Verification checklist

- The working tree contains only reviewed phase files.
- Each finding from either reviewer is reproduced or explicitly rejected with evidence.
- CI passes on supported Python versions.
- Work-state items and public documentation match what actually shipped.
- Environment and static checks: `uv sync --frozen --all-extras --group dev`, `uv run ruff check .`, and `uv run ruff format --check .`.
- Full Python suite: `uv run --frozen --all-extras pytest -q`.
- Full browser suite: `node --test tests/web/dashboard.test.cjs tests/web/adjudication.test.cjs`.
- Distribution check with a fresh directory: `REVIEW_BOUNDARY_DIST_DIR=$(mktemp -d)`, `uv build --out-dir "$REVIEW_BOUNDARY_DIST_DIR"`, and `uv run python scripts/check_distribution.py "$REVIEW_BOUNDARY_DIST_DIR"`.
- Calibration smoke check in a fresh worktree: `uv run review-boundary demo --split all --mode reference --output runs/ci-reference` followed by `uv run review-boundary compare examples/baselines/reference-v02.json runs/ci-reference/report.json`.

### Anti-pattern guards

- Do not combine unrelated phase failures into one opaque commit.
- Do not accept self-review as the only evidence.
- Do not persist raw private model prompts, responses, credentials, or access details.
- Do not mark the roadmap complete while evidence-gated phases remain open.
