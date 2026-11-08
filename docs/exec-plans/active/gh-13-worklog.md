# GH-13 worklog

Scope: repository-owned ordinary Claude CLI review helper, focused contract tests,
and English operating documentation. Codex implements; real Claude independently
reviews. Human owner: utkutugrul. No changes to #10/#11/#12 or dispatch gates.

## Claim and ownership

- Actual host github_api observation at 2026-11-08T03:48:21Z: GH-13 open, assigned
  to utkutugrul, with
  symphony, owner:codex, review:claude, status:ready and dispatch:enabled.
- No dependencies in the actual issue or versioned plan. Manual claims exclude
  #10/#11/#12. Supplied live snapshot passed the repository checker before code.
- Base: 6b7efd375e2c77380dc513e2f4304aa154ec1827. Fresh GH-13 workspace was clean.
- Local Git ref creation failed because metadata is read-only. Approved native
  github_api created codex/gh-13-independent-claude-review at that base instead.
- The operator maintains canonical work_state outside this child; no external
  state update is claimed here. Handoff requires status:blocked and no dispatch.

## Implementation and evidence

- Installed ordinary Claude CLI reports 2.1.319. Local --help and official CLI
  documentation were inspected; these probes are not a live model review.
- Implemented a stdlib-only helper reading explicitly selected immutable Git
  blobs, with base context, content/mode hashes, coverage and finding bounds.
- CLI subprocesses use nonblocking bounded pipes, a shared deadline, fresh POSIX
  groups, TERM/KILL and actual cleanup observations. Missing/partial/refused
  reviews stay unavailable; raw CLI errors and account metadata are discarded.
- Source inspection found cancellation must defer through child acquisition;
  standalone SIGINT/SIGTERM now request cancellation without interrupting cleanup.
- Runtime helper contract tests use trusted fake executables only. Nineteen tests
  cover positive findings and negative scope, flag, refusal, denial, malformed
  output, output bounds, timeout, blocked stdin, descendants and cleanup cases.
- Focused helper plus existing management suite: 66 passed on Python 3.11.15
  and Python 3.14.10 in an isolated neutral-name clone with identical scoped
  source. Pytest warned that asyncio_mode was unknown because plugin autoload
  was disabled; neither focused suite needs that plugin. No package installed.
- Initial run in GH-13: 65 passed, one existing management test failed because
  it assumes the checkout basename is not GH-N. The gate correctly refused a
  missing explicit host credential. The checker/test was not modified.
- Repository project-management checker passed. Frozen-source describe-only
  invocation passed without launching Claude. AST parsing and diff whitespace
  checks passed. These do not establish model behavior.
- Ruff is unavailable on PATH; the offline tool runner could not initialize its
  cache under sandbox permissions. Lint/format and the full application suite
  are unverified here. No install or broader sandbox was requested.

## Outstanding gates

- Separately authorized frozen-source normal-CLI smoke and independent final
  Claude review, including subprocess lifetime, binding and refusal handling.
- No live model request or independent Claude pass is claimed. The exact source
  revision, PR and operator review request belong in the linked GH-13 handoff.
- Reviewable draft PR and exact source revision via the native GitHub API.
- Material-risk delivery remains WAIT for explicit human owner acceptance.
- No application benchmarks, provider keys, daemon, install or auth changes.
