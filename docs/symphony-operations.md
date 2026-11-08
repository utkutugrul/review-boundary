# Symphony operations

Configuration, claim checks and the independent Claude CLI bridge are shipped.
The maintainer's owner-approved local coordinator has delivered tasks13 and11.
Other installations must complete the launch checks below.
[WORKFLOW.md](../WORKFLOW.md) uses the
[pinned native GitHub adapter](https://github.com/openai/symphony/blob/be10a1b79df723d6d7612b5651c8522704dafb2e/elixir/README.md#github-issues-adapter).
The [pinned loader](https://github.com/openai/symphony/blob/be10a1b79df723d6d7612b5651c8522704dafb2e/elixir/lib/symphony_elixir/workflow.ex)
loads YAML as a map. Pretty JSON is valid YAML, allowing a stdlib checker.
These links define the reference contract. Actual local activation and delivery
evidence are recorded in the [execution plan](exec-plans/active/symphony-management.md);
static compatibility checks alone do not establish another installation's state.

The [GitHub client](https://github.com/openai/symphony/blob/be10a1b79df723d6d7612b5651c8522704dafb2e/elixir/lib/symphony_elixir/github/client.ex)
sets blocked_by to an empty list, so dependency gating is our explicit contract.
The short map/versioned plan follows
[harness engineering](https://openai.com/index/harness-engineering/).
The existing workshop document is unrelated and untouched.

## Before launch

1. Land/check this scaffold first: after_create clones public main, so an unmerged
   local setup cannot bootstrap itself.
2. Operator chooses a fresh dedicated SYMPHONY_WORKSPACE_ROOT, separate from
   existing checkouts/dirty worktrees. Concurrency stays two.
3. Existing host-side SYMPHONY_GITHUB_TOKEN must have approved repository permissions.
   Never print/copy the token or change account permissions as a task. Verify
   the approved Git/PR delivery route separately. provider.repo scopes polling;
   raw github_api access follows the host token permissions, not a new sandbox.
4. Review pinned upstream prerequisites and actual [Codex app-server](https://developers.openai.com/codex/app-server/) compatibility.
   This document does not authorize installation, daemon start or auth changes.
5. Ship/check the portable real Claude CLI bridge before its research/review tasks.
   No private helper path is published. Ordinary account usage is not promised free.
   For bootstrap, Codex may implement #13 as the first explicitly promoted pilot
   after launch acceptance. Its real independent Claude review must complete
   before delivery; missing review blocks delivery, not bridge implementation.
6. Obtain owner acceptance for launch. Keep workspace-write sandbox defaults.
   Dependency network/setup needs an explicit reviewed operating decision.

## Promotion and worker checks

A fresh installation starts without enabled issues. The operator fetches actual current dependency
issues, requires closed state, then explicitly adds symphony, status:ready and
dispatch:enabled. Keep one status label; only ready/active may retain dispatch.
Workers recheck before code. required_labels only filters labels.
The gate requires issue roles and dependency references to match the versioned
plan. Update and review both records when changing scope; editing the issue body
alone cannot remove a dependency or switch its delivery roles.
Open-task plan statuses are coordination metadata. A terminal `done` record
requires an explicit versioned plan reopening before it can dispatch again,
even if its GitHub issue is reopened and labeled ready. Registered
roles/dependencies, manual claims and fresh GitHub state/labels form the gate;
explicit operator promotion remains required.

Use host github_api GET /repos/utkutugrul/review-boundary/issues/N and every dependency.
Build a private snapshot from actual responses using only:
- repository: utkutugrul/review-boundary
- observed_at: actual timezone-aware UTC observation time
- issue: number, html_url, state, title, body, labels and assignee
- dependencies: number, html_url and state for every referenced dependency

Do not retain unrelated fields/tokens. Maximum256KiB, age at most five minutes,
clock skew at most five seconds. Run:
rtk proxy python3 scripts/check_project_management.py --repo . --issue-snapshot /path/to/private-snapshot.json

A pass prints `offline snapshot GH-N` and validates supplied data only, not API
authenticity or observation time. A fabricated/offline fixture is never live
dependency evidence. `--require-live-claim` instead fetches actual issue data and
prints `live GitHub fetch GH-N` only after the fetched claim passes validation.
The two flags are mutually exclusive; combining them fails during argument
parsing before file reads, credential access or network requests. Both modes
still require explicit operator promotion. Live mode adds only bounded GETs,
never labels, promotion or scheduling.

Blocked/review removes dispatch:enabled after saving evidence. No automatic
promotion/resumption. Removing a required label may stop the current session.
Upstream in-memory blocked state clears on restart; labels/rechecks remain needed.

## Failed turns and repeated dispatch

The coordinator can report normal turn completion even when the actual task
turn records a service failure. Inspect the current thread's terminal status
and error category when repeated runs produce no new work. An activity label,
session file or aggregate token counter cannot establish successful execution.

For an automatic safety-review refusal, retain a sanitized reason, set the
affected issue to status:blocked and remove dispatch:enabled. Verify that the
same coordinator retires the worker and its retry queue. Preserve the original
task and acceptance criteria. Resume only after an actual relevant external
change; do not reroute or disguise the denied request or alter access settings
to get around it. Keep unrelated eligible work separate.

An observation timeout alone does not establish failure or retirement. Recheck
the same live handle rather than starting another coordinator or writer.
Missing cleanup evidence stays unknown. Keep raw service errors and private
account/access details out of issues and repository artifacts.

## Review and delivery

Codex app-server coordinates. Claude review/research uses the
[ordinary CLI review procedure](claude-cli-review.md), independently of App Server.
Record final source/diff identity, independent
findings, actual checks and unknowns. Never relabel a Codex subagent as Claude.
Workers leave a PR and issue in status:review for the operator. The operator
uses recorded owner authorization and merges only the verified exact head.
The current owner has authorized project PR delivery without repeated permission
questions. Keep Source review, runtime execution and external activation
decisions distinct; a source review cannot authorize itself. The application-test USD20 cap
stays unchanged and does not cap ordinary coding-account usage.

## Controlled migration

Respect the actual manual_claims list in the versioned plan. PR21 released
claims11 and12; claim10 remains with the operator. Active manual owners are
exclusive until an explicit accepted handoff.
Finish existing verification/handoff first; new work then goes only through
Symphony/GitHub tasks, with no parallel manual cascade.

before_run requires --require-live-claim. Pinned workspace.ex preserves GH-N as
workspace basename and invokes the hook there. The gate checks the registered
issue/manual claims before token access. It then uses only explicit
SYMPHONY_GITHUB_TOKEN, fixed api.github.com/utkutugrul/review-boundary, GET and exact
current/dependency issue IDs. Proxy discovery and redirects are disabled. Limits:
five-second socket timeout/64KiB per response, an owned standalone POSIX
ten-second timer/256KiB aggregate, at most33requests.
It has no gh/global-auth lookup, label mutation, scheduling or daemon. Missing
credential/data fails closed. The host hook inherits configured environment;
the tracker declares its token variable for removal from the later Codex child.
Verify actual host/config compatibility before activation. No auth was read here.
Expiry during JSON decoding retains the fixed absolute-deadline diagnostic.
Malformed JSON, duplicate keys and invalid encoding retain the fixed invalid-JSON
refusal without response contents or key names.
The timer/socket bounds are implemented, not runtime evidence of DNS interruption
or process retirement on every platform. Keep dispatch off until supported host
behavior is reviewed and verified; do not claim a hard DNS/cleanup guarantee.

Offline --issue-snapshot remains usable in a matching GH-N workspace; supplied
data does not establish API authenticity. The live CLI writes no snapshot/token. This local-only profile does not configure SSH.
Closed issues and completed plan records remain ineligible until an explicit
versioned reopening; released claims still require fresh live dispatch checks.

Activation is owner-controlled. Pinned CLI requires the explicit acknowledgement
--i-understand-that-this-will-be-running-without-the-usual-guardrails.
An operator must accept it for the concrete launch; never add it automatically
or start a daemon from a task. A release version alone does not establish pinned
source compatibility. Verify the installed revision/config first and record
actual activation separately from repository configuration.

Local check: rtk proxy python3 scripts/check_project_management.py --repo .
The current local deployment has actual dispatch and delivery evidence. New
profiles or installations need their own relevant verification; prior passing
evidence applies only to its recorded Source and environment.
