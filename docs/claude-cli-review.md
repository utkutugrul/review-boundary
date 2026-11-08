# Independent ordinary Claude CLI review

[scripts/claude_review.py](../scripts/claude_review.py) is a standalone Python
3.11+ helper for Symphony tasks. It invokes the installed normal Claude Code CLI,
independently of Codex App Server. It needs no private helper, SDK, added tool,
application provider key, or Symphony configuration change. A role label, mock,
or Codex agent never substitutes for a real independent Claude review.

## Authorize and freeze

Obtain separate owner authorization for the concrete live review and its ordinary
coding-account usage. Existing application-benchmark authorization does not cover
this usage. The USD20 application benchmark cap neither funds nor caps a coding
account; normal CLI usage is not promised free. Do not export credentials, change
login, install a CLI, or route through private endpoints to make a pass.
An unavailable CLI/account remains unavailable.

Use trusted installed `claude` on PATH, or supply its executable with `--claude`.
The helper checks bounded `--version` and `--help` output before a model request
and refuses missing flags, including `--model`. The fixed public alias is
`sonnet`; account or user configuration does not select the review model.
Initial compatibility evidence: installed Claude Code
2.1.319 help and the official [CLI reference](https://code.claude.com/docs/en/cli-reference)
and [structured-output procedure](https://code.claude.com/docs/en/headless).
That verifies declarations, not live model behavior.

Commit the source first. Supply full immutable commit IDs, an optional immutable
comparison base, and every exact current file needed to assess the change:

```sh
rtk proxy python3 scripts/claude_review.py \
  --repo . --revision "$REVIEW_SHA" --base "$BASE_SHA" \
  --path scripts/claude_review.py --path tests/test_claude_review.py \
  --path docs/claude-cli-review.md --timeout 180
```

Capture stdout to an operator-chosen private artifact outside the source tree.
Run the helper from the reviewed revision. Inspect findings before publishing;
they are untrusted model text. Review does not authorize publication of gated
approval/HOLD, merge, or material-risk acceptance.

The helper reads Git objects, never worktree source or ignored/untracked context.
It does not inspect user documents, conversation history, credentials or account
settings. The real CLI owns its existing normal account authentication. API
credentials, custom endpoint variables, GitHub tokens and CLI configuration
environment overrides are not forwarded. HOME/PATH/LANG/TMPDIR are retained for
the normal installed CLI; the helper does not inspect their contents.

Select at most 32 regular UTF-8 files, each at most 64 KiB. Current plus base
contents total at most 192 KiB. Paths use letters, numbers, `_`, `.`, `/`, `-`,
with no traversal, `.git`, symlinks, directories or submodules. Deleted-only paths
are unsupported; select surviving context or request a procedure covering the
deletion. Missing context must not become full coverage.

## Process and result contract

Frozen source goes through stdin with hashes, paths and original line counts.
Optional base contents accompany current contents. Claude starts in an empty
temporary directory inside the writable repository, removed afterward. The
helper does not write source files. Its fixed invocation requests:

- Print mode with explicit `--model sonnet`, JSON schema and a separate trusted
  system prompt.
- `--tools ""`, empty strict MCP configuration, disabled slash commands and Chrome.
- Safe/restricted modes, empty setting sources, disabled hooks, `dontAsk`
  permissions, and no saved conversation or session continuation.

No tool grants or permission bypass flags are used. Approved host policy remains
a prerequisite: managed Claude policy can override CLI settings. Do not run on a
host whose mandatory policy introduces hooks or tools. These are CLI capability
restrictions, not an OS sandbox or guarantees about the CLI's account files. The
report separates requested isolation declarations from observed process facts
and the CLI's permission-denial result.

The shared deadline defaults to 180 seconds, configurable from 0.1 to 600. Source
collection additionally has a ten-second deadline. Nonblocking stdin/stdout/stderr
keep pipe backpressure within that deadline. Each CLI invocation admits at most
128 KiB of combined output (help: 64 KiB; version: 4 KiB); overflow aborts. Stderr
is counted and discarded. Raw stdout, provider errors, account/session identifiers
and billing metadata are not copied into reports.

Each invocation has a small stdlib Python supervisor owning its POSIX session/group.
It launches the actual command in that group, reaps the command, sends its exit
code through a separate bounded pipe, and stays alive. The command cannot inherit
the status pipe. The parent never polls or waits for the supervisor before cleanup.
Cleanup attempts group TERM, gives an unfinished command at most 0.2 seconds,
and attempts group KILL before the final supervisor wait of at most 0.5 seconds.
An already finished command needs no grace period. No retiring signal is
sent after reaping. The final signal-zero probe delivers no signal; only an absent
group confirms cleanup. A remaining or possibly reused group stays unavailable.
Lost ownership prevents further group signals and leaves cleanup unconfirmed.
Hosts without the default SIGCHLD disposition are unavailable before launch.
Reports distinguish the command return code from the supervisor's final return
code and preserve ownership, signal outcomes, leader reaping,
pipe EOF, input completion and the final group probe. Denied signals, remaining
groups (including zombies), and unknown retirement never become cleanup success.
SIGINT/SIGTERM request cancellation without interrupting child-handle acquisition
or cleanup. These are bounded userspace waits, not hard OS process-creation or
filesystem guarantees. Detached descendants and forced termination of the helper
are not contained. Windows is explicitly unavailable.

Exit 0 means `completed` or offline `described`; inspect `status`. Completion
requires successful exit/cleanup, a successful CLI envelope, explicitly empty
`permission_denials`, a valid structured result, exact revision/key binding, one
reviewed coverage entry per path, and findings within current-source line bounds.
Findings contain priority, path, line range, title and body. Refusal, partial
coverage, malformed JSON, missing permission evidence, denial, timeout, overflow,
or cleanup uncertainty produce exit 1 and `unavailable` with a fixed reason code.
They never mean no findings. No-findings output is a model assessment, not proof
of robustness or owner acceptance.

## Reuse and final evidence

Before another live review, run the same scope with `--describe`. It launches no
Claude process and returns the manifest and `review_key`. Compare with a trusted
previous completed result. The key binds helper bytes, prompt, CLI policy,
selected paths and current/base blob identities. Unrelated commits preserve it;
changed source, base context, scope or helper changes it. Do not rerun unchanged
completed scope. Keep the original reviewed revision and the new manifest as an
applicability record; never rewrite a prior review as if Claude reviewed a newer
commit. Changed context or an unavailable review needs a newly authorized review.
Matching hashes prove content identity, not report authenticity or correctness.
Recheck CLI/host-policy compatibility when changing hosts.

For GH-13, retain the exact reviewed revision, full scope, structured report with
zero permission denials, cleanup facts, contract checks, and independent Claude
findings about lifetime, source binding and refusal. Include final source/diff
and validation evidence in that review scope. Separate source inspection, static
flag declarations, runtime helper tests and real model review. If the sandbox
cannot run the normal CLI, preserve the frozen revision, request the operator's
real CLI review, remove dispatch and mark the issue blocked. Fake tests do not
satisfy that gate. Material-risk delivery stays WAIT for owner acceptance.

Focused checks use Python, Git and trusted fake reviewer executables:

```sh
rtk proxy python3.11 -m unittest discover -s tests -p test_claude_review.py -v
rtk proxy python3.14 -m unittest discover -s tests -p test_claude_review.py -v
rtk proxy python3 scripts/check_project_management.py --repo .
```
