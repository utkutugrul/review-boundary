# Agent map

ReviewBoundary tests whether untrusted content can redirect AI code reviewers.
Start with [architecture](ARCHITECTURE.md), then the relevant code and tests.

## Work and ownership

- [Plans](docs/PLANS.md) define scope, roles and acceptance.
- [WORKFLOW.md](WORKFLOW.md) defines GitHub dispatch.
- [Operations](docs/symphony-operations.md) explains setup and status changes.
- GitHub is the external dispatch record. Keep the versioned plan and canonical
  work_state aligned; neither replaces the other.
- Work only in the assigned issue workspace and file scope. Current manually
  owned dirty branches/worktrees are excluded from automation.
- Codex implements/verifies. Claude review/research uses a real independent CLI
  through a separately shipped bridge, never a substitute app-server.
- After current owners finish, new work goes only through Symphony/GitHub tasks.
  No manual task cascade or takeover of active #10/#11/#12.
- Recheck actual dependency issues before code. Missing/stale data blocks work.

## Evidence and validation

- Follow [contribution checks](CONTRIBUTING.md) and run relevant checks.
- Run: rtk proxy python3 scripts/check_project_management.py --repo .
- Separate Source review, static declarations, runtime passes and model results.
  Test counts do not prove model robustness. Preserve unknown/failure outcomes.
- Keep README short; use linked focused docs.
- Never store credentials, personal data, private access details or provider errors.
- Paid application tests require existing authorization and the USD20 total cap.
  Ordinary coding-account usage is not promised free or covered by that cap.

## Delivery

- Never merge automatically. Leave a reviewable PR and actual validation evidence.
- Material trust-boundary, infrastructure, deployment or irreversible changes
  stay WAIT for explicit human owner acceptance.
- Never publish a gated GitHub approval/HOLD without owner approval.
- Do not install/start Symphony or change authentication as a routine task.
- Never add Co-Authored-By or AI attribution to commit messages.
- Never use em dashes in prose, comments, reviews or external messages.
