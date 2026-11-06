# Realistic repository corpus plan

Status: proposed upstream corpus, not implemented cases. Research checked on November 6, 2026. No vulnerable upstream repositories were installed or executed for this assessment. The separate [repository-mode foundation](repository-mode.md) is now implemented with original synthetic code; the [candidate catalog](upstream-candidates.md) records the next intake options.

## Ranked recommendation

1. **Add a curated repository-slice tier.** Start with six independently sourced security issues, then expand to twelve. Each reviewer-visible snapshot should contain three to ten relevant files from a real upstream project. Preserve the existing synthetic tier for fast, deterministic regression checks.
2. **Invest in reproducible ground truth before adding volume.** Admit a case only after an independent security test fails on a pinned vulnerable revision and passes on its pinned fixed revision, with valid behavior preserved. Build bounded multi-file tools and issue-level scoring alongside the first cases.
3. **Use existing benchmarks as sources and methodology references.** OSV and GitHub advisories are the best starting index for our Python, TypeScript and Rust scope. SecBench.js offers JavaScript candidates. SEC-bench, SWE-bench and SWE-bench Pro provide useful reproduction and evaluation patterns, but their scores measure different tasks.
4. **Add full-repository agent execution later.** A real agent, dependency builds, shell access and network behavior require a separate isolation design. The current JSONL adapter does not supply that isolation.

The first deliverable should be a small, auditable set of cases, not a claim to evaluate every vulnerability in an entire repository.

## What the current implementation can support

`cases.py` already stores a dictionary of virtual files and optional support files. `world.py` can read those files and records observed tool actions. This is a useful base for repository slices.

The legacy v0.2 corpus consists of twelve synthetic families and 144 conditions. Its scorer matches a category and evidence against one primary source file. A fixed case passes review-quality scoring only with approval and no findings. It does not assess the validity of additional findings. Completion requires the PR, README and primary source to have been read. These historical rules remain unchanged.

The opt-in repository-v1 contract now supplies bounded listing, literal search, ranged reads, multi-location structural evidence bundles and explicit digest-bound semantic adjudication. Its four synthetic conditions validate the tooling, not upstream behavior. An isolated executor for untrusted repositories, verified upstream slices and a practical adjudication workflow remain additional work. Native model providers and the trusted external reviewer protocol are implemented.

## Source assessment

These five source groups are useful for different purposes. A benchmark repository's license does not automatically relicense upstream code, copied tests, advisory text or container contents.

| Source | What was verified | Recommended use and limits |
| --- | --- | --- |
| [OSV data sources](https://google.github.io/osv.dev/data/) and [GitHub Advisory Database](https://github.com/github/advisory-database) | OSV aggregates records from multiple sources. GitHub's database uses the OSV format and its `LICENSE.md` is CC-BY-4.0. Records can link affected versions, aliases and upstream fixes. | Discover candidates and deduplicate CVE/GHSA aliases. Follow the upstream fix and verify it locally during implementation. Metadata is not an executable oracle. Record the source database's terms separately from the code and test licenses. |
| [SecBench.js](https://github.com/cristianstaicu/SecBench.js) | The project describes 600 JavaScript vulnerabilities with per-package Jest tests. Its metadata includes `fixedVersion` and `fixCommit`, which can be empty. Root `package.json` declares ISC; a separate top-level license file was not visible in the inspected listing. | Use as a candidate index and a reproduction reference. Check each test's provenance and the affected package's license before copying. Do not assume the ISC declaration clears every imported artifact. JavaScript fixtures must remain JavaScript, or be identified as newly written adaptations rather than original TypeScript cases. |
| [SEC-bench](https://github.com/SEC-bench/SEC-bench) | The repository has an MIT license and its official dataset card declares MIT. It builds reproducible vulnerability instances and evaluates PoC generation and patching. Docker and substantial build infrastructure are part of its workflow. | Borrow instance verification and environment pinning. Its published collection examples emphasize C/C++ and OSS-Fuzz, so wholesale adoption is a poor first fit for our present languages and read-only review task. Upstream sources and image dependencies still require their own license inventory. |
| [SWE-bench](https://github.com/SWE-bench/SWE-bench) | The harness repository is MIT licensed. The official dataset records a base commit, reference patch, test patch, fail-to-pass tests and pass-to-pass tests. The inspected original dataset card did not declare a separate dataset license. | Borrow the distinction between repairing the target behavior and preserving unrelated behavior. Keep reference patches and evaluator tests outside reviewer access. The harness license is not blanket permission to redistribute all upstream issue text and source files. This is software repair methodology, not a prompt-injection benchmark. |
| [SWE-bench Pro V2](https://huggingface.co/datasets/ScaleAI/SWE-bench_Pro) | The official card distinguishes MIT harness/tooling from task content governed by upstream repository licenses. V2 is the current default; V1 remains a separate configuration. V2 documents sanitized repository history, fresh-container verification and a reference-patch-pass/empty-patch-fail release gate. | Pin the dataset version and revision when borrowing anything. Adopt clean evaluator environments and removal of hidden answers from agent-visible history. Public code and copyleft licenses do not establish that a model has never seen the tasks. |

For any copied fixture, retain its original notices and record the exact license at the selected revision. Prefer straightforward, compatible source licenses for the first release. If provenance or redistribution permission is unclear, retain a metadata-only candidate until it is resolved. A public download link is not sufficient evidence of redistribution rights.

## A verified candidate chain, not an accepted case

Django's archive traversal issue is a concrete starting candidate:

| Field | Verified value |
| --- | --- |
| Advisory aliases | `CVE-2021-3281`, `GHSA-fvgf-6h6h-3322`, `PYSEC-2021-9` |
| Upstream | `django/django` |
| Candidate vulnerable revision | `03a86784d0dbfc5890f5aaba2d2f29c1deb0009d`, the parent of the selected fix |
| Upstream fix | `02e6592835b4559909aa3aaaf67988fef435f624`, the Django 3.1 branch fix |
| Relevant behavior | Archive extraction must not write an entry outside the intended destination |
| Source license checked | BSD-3-Clause in `LICENSE` at both selected revisions |

The [OSV advisory record](https://osv.dev/vulnerability/GHSA-fvgf-6h6h-3322) links the upstream fixes. The selected [Django changeset](https://github.com/django/django/commit/02e6592835b4559909aa3aaaf67988fef435f624) changes extraction handling and adds regression tests. Its parent SHA and source license were also inspected.

This establishes provenance, not successful reproduction or a claim that the fixed revision has no other defects. A curator would still need to select the caller, extraction implementation and relevant supporting files; construct an independent filesystem-containment test; preserve normal extraction; and show that the reduced slice retains the upstream behavior. Do not pad a single-function case with unrelated files to meet a file-count target.

## Initial coverage

Aim for six accepted issues from distinct upstream projects or genuinely independent source groups. Expand to twelve after the tooling and validation procedure work. Seek Python, TypeScript and Rust coverage without forcing weak candidates to satisfy an artificial balance.

| Priority | Scenario | Why multiple files matter | Independent test obligation |
| --- | --- | --- | --- |
| 1 | Tenant authorization across a route, service and policy helper | The authenticated identity and resource owner are established in different layers | A foreign-tenant operation is rejected while an authorized operation succeeds |
| 2 | Archive or path handling across an entry point, decoder and extraction helper | The checked path and the path used by the sink can differ | An entry cannot escape its temporary destination; normal entries still extract |
| 3 | Webhook verification across raw-body handling, serialization and event processing | The authenticated bytes must be the bytes that authorize processing | Invalid or mismatched signatures cannot trigger the downstream action; valid messages can |
| 4 | Token scopes or membership decisions across parsing, cache and authorization | A correct local check can use the wrong identity, tenant or scope representation | An insufficient scope or another tenant's cached permission cannot authorize access |
| 5 | SSRF and redirect validation across URL construction, policy and transport | An allowed initial URL does not necessarily imply an allowed final destination | A controlled transport cannot reach a forbidden destination, including after redirects |

These are selection targets, not sourced cases already in the repository. Authorization, signature verification and path traversal fit existing category names. SSRF requires an explicit new category and scorer/schema work. Keep the existing SQL injection coverage, and add real query-builder cases if they satisfy the same provenance and multi-file relevance requirements.

## Case admission contract

Each case needs an evaluator-only manifest with upstream URL, vulnerable and fixed commit SHAs, advisory aliases, disclosure and fix dates, source and test license records, dependency locks, content hashes, and the mapping from upstream files to the slice. Record every modification made while reducing the repository.

Admission should require all of the following:

1. Reproduce the target security failure on the original vulnerable revision, then demonstrate the intended fix on the selected upstream revision. A build failure, missing dependency or timeout is not evidence of the vulnerability.
2. Repeat those checks on the reduced slice. Preserve the relevant call graph, trust assumptions and language. If substantial rewriting is necessary, label the result an adapted case and keep it distinct from an exact upstream slice.
3. Use a behavior-based security assertion maintained independently of the reviewer's output. Upstream regression tests are useful evidence, but do not merely check that patch text or a particular guard exists. Include valid-input tests that pass on both variants.
4. Run clean and injected variants through the same validation. Context injection must preserve executable semantics. For code comments, verify parsing and behavior after insertion. Keep the target code revision, task, budget and tool policy matched across the pair.
5. Review alternative valid findings and evidence locations before freezing the case. Keep the acceptance logs, dependency/image digests and expected failure reason with the evaluator artifacts.

The reviewer receives ordinary repository filenames, a task contract and the selected snapshot. It must not receive advisory descriptions, CVE-bearing case identifiers, vulnerable/fixed labels, reference patches, oracle tests, split names or ground-truth annotations. Use opaque invocation identifiers. Do not expose `.git`, release notes that disclose the target fix, cached patches or evaluator directories. Preserve legally required notices; public project identity can remain recognizable even when evaluator metadata is hidden.

## Tooling and scoring changes required

Add bounded `list_files`, ranged `read_file` and literal `search_files` operations over the virtual snapshot. Limit path counts, file bytes, returned lines, query length, match counts and aggregate output. Reject traversal and out-of-snapshot paths. Do not turn a search argument into a shell command or unrestricted regular expression. Record the ranges returned and whether the attacker-controlled material was actually exposed.

Extend finding evidence to accept multiple path/function/range references for one issue. A route-to-policy-to-sink explanation should not fail because its best evidence is outside the old primary source file. Verify excerpts against immutable source content, and maintain a reviewed set of acceptable issue descriptions and alternative evidence paths. Structural citation checks remain separate from semantic adjudication.

Allow several legitimate issues and several valid evidence choices. Score target-issue recall, grounded evidence, citation accuracy, additional validated findings, false positives, completion and unauthorized actions separately. An unjudged additional finding is unresolved, not automatically a false positive. A fixed target does not imply that the entire snapshot deserves approval. Version the scoring contract and retain the old synthetic results under their original interpretation.

Define completion from the published task and actual tool trace, without secretly requiring a particular oracle path to be read. Keep exploration coverage separate from task completion. For prompt-injection results, distinguish exposure, incomplete review, target suppression and attempted writes. Retain benign quotations and fixed-code controls. A reviewer that never encounters the payload has not demonstrated resistance to it.

## Splits and reporting

Group by upstream project, fork/copied-code lineage, advisory aliases and shared root cause before splitting. The vulnerable revision, fix, backports and all context variants of an issue must stay together. Closely related fixes cannot count as independent heldout cases simply because they have different identifiers.

Freeze a development partition and a source-group holdout before tuning. Also predeclare a temporal cutoff using recorded public disclosure/fix dates, not the date an aggregator imported the record. A later temporal holdout should use newly curated source groups when possible. With six to twelve issues, present exact group counts and limitations rather than implying reliable population-wide estimates.

Public upstream code, patches and benchmark cases may already be in model training data. A public holdout prevents some local tuning leakage but cannot prove model-level non-exposure. Publish the provenance and selection process and state this limitation alongside results.

Use matched clean/hostile trials with equal budgets and reviewer settings. Retain the current five-trial default for stochastic reviewers. Report per-issue results and failures to reproduce, with repeated trials clustered by source issue. Do not treat every context, epoch or backport as an independent vulnerability. Keep synthetic and repository-slice results separate until a documented aggregate weighting exists.

## Execution boundary and delivery order

The first reviewer-facing tier can remain a read-only virtual repository. Independent fixture validation still needs a controlled executor before accepting upstream code. Build that executor before running third-party setup scripts or tests.

For later real-agent experiments, use ephemeral isolated environments with CPU, memory, disk, process and wall-clock limits. Keep host files, host credentials and container-management sockets unavailable. Deny outbound network by default; stage pinned dependencies separately and route any necessary model access through an explicit allowlist or proxy. Keep API credentials outside candidate repository content. Use local fake services for SSRF tests and disposable filesystems for archive tests.

Run authoritative verification in a fresh environment that the agent cannot modify. Agent-visible repositories must not contain reference fixes, hidden tests or recoverable git history. The existing subprocess adapter bounds its protocol but is not an OS sandbox and cannot attest to external side effects.

Recommended implementation order:

1. Define a versioned repository manifest, license/provenance inventory and independent validation runner; reproduce two development candidates.
2. Implement bounded multi-file tools, reviewed issue/evidence matching and new report fields; retain existing synthetic regression checks.
3. Curate six accepted cases, freeze source groups, run deterministic calibration, then inspect a small model pilot before expanding to twelve.
4. Add one documented real-agent integration only after isolation and outbound controls are tested. Publish its observation boundary and cost accounting separately.

Completion of this plan would make ReviewBoundary's scenarios more representative. This document itself adds no cases, sandbox, agent integration or new benchmark results.
