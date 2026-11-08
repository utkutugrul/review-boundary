# Plans and task contracts

[AGENTS.md](../AGENTS.md) is the map. The
[active execution plan](exec-plans/active/symphony-management.md) is a versioned
contract, GitHub issues are external dispatch records, and canonical work_state
tracks durable work. Keep all three aligned without invented successful updates.

Tasks have id, title, issue, owner, reviewer, status, dependencies, acceptance,
validation and evidence. Owner/Reviewer are distinct Codex/Claude roles. Human
GitHub assignee: utkutugrul. issue:null means pending bootstrap, not a fake URL
or a dispatchable task.

GitHub bodies use six nonempty headings: Goal, Ownership, Dependencies,
Acceptance criteria, Validation and Delivery. Ownership uses Implementation lead: Codex and
Independent reviewer: Claude, or the opposite for Claude-led analysis. Acceptance criteria
include a checklist. Dependencies are None or same-repository issue references.

Use one status label: status:backlog, status:ready, status:active, status:review
or status:blocked. Only ready/active may carry dispatch:enabled. An operator
promotes explicitly after actual dependency issues are closed; workers recheck.
Open/closed issue state is separate from these labels.

Versioned plan records may also use `done` to retain delivered tasks and their
dependency links. This does not add a GitHub `status:done` label. A completed plan
record cannot dispatch again until it is explicitly reopened in the versioned
plan, even when its actual GitHub issue has been reopened and labeled ready.

Local check: rtk proxy python3 scripts/check_project_management.py --repo .
Offline dispatch checking validates a supplied fresh issue snapshot. Live mode
fetches the issue and its dependencies using explicit read-only GitHub requests.
Both modes bind roles and dependencies to this versioned plan. The checker
cannot change labels or schedule work; offline data is not authenticated.
See [operations](symphony-operations.md).

The plan-level manual_claims list protects current issue owners; it is separate
from a Codex/Claude delivery role. Remove a claim only after explicit owner
handoff. After current owners finish, new work enters through Symphony/GitHub,
not another manual task cascade. Never assign two writers to one scope.
