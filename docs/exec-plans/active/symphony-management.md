# Symphony management and remaining milestones

Status: proposed core and native custody handoff after delivered reviewer task13.
These are the actual [repository issues](https://github.com/utkutugrul/review-boundary/issues).
The previous manual writers have stopped. Claim10 remains held by the operator;
claims11 and12 are released only on accepted landing of this custody proposal.
Dispatch stays explicit and operator-controlled. Native Source review and runtime
acceptance are separate and remain incomplete. Earlier scaffold/source-freeze
statements below are historical, not authority for another launch or execution.
Null links are permitted only for future pending tasks.

```json task-contract
{
  "manual_claims": [
    10
  ],
  "tasks": [
    {
      "id": "ops-10",
      "title": "Manage agent delivery with Symphony and repository execution plans",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/10",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "active",
      "dependencies": [],
      "acceptance": [
        "Eight scoped management files pass meaningful checks and independent review.",
        "Owner accepts setup before any daemon or dispatch.",
        "Before-run rejects missing/stale/mismatched live claims and active manual ownership."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR.",
        "Validate the bounded fixed-GitHub live gate with fake HTTP controls before launch."
      ],
      "evidence": [
        "Root reviewed the management source and bound live roles/dependencies to the versioned plan.",
        "All 47 offline management cases passed on Python 3.11 and 3.14; local contracts and Ruff checks passed.",
        "No live API, installed Symphony loader, daemon or dispatch was exercised."
      ]
    },
    {
      "id": "core-11",
      "title": "Ship paired agent workflow evaluation core",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/11",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "blocked",
      "dependencies": [
        "claude-13"
      ],
      "acceptance": [
        "Final core APIs, docs and tests pass supported-version, package and independent review checks."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": [
        "All previous manual agents completed and stopped. The operator reverified the preserved 256-file core snapshot and 296-file native snapshot without differences.",
        "Exactly ten frozen core candidate files and the documentation proposal have the expected byte counts and hashes in the intake table below. They are staged read-only in GH-11; the original dirty worktree remains preserved and inactive.",
        "Historical frozen-core evidence includes 4003 passing tests per supported Python version, 78 browser tests, package and installed-wheel checks, and independent Claude review. New integration checks are still required.",
        "Actual historical core verification report SHA256 51d77424fe71ec634d15df73c9640cf8e5340d911ac56cdbcc02d238bd53331d. This identifies prior evidence, not new integration or model results."
      ]
    },
    {
      "id": "native-12",
      "title": "Complete isolated reviewer native execution and runtime validation",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/12",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "blocked",
      "dependencies": [
        "claude-13"
      ],
      "acceptance": [
        "Native lifecycle, privacy and ownership evidence closes actual supported tests without invented guarantees.",
        "Adopt only the 56 verified native inputs under the accepted custody contract, preserving CORE11 ownership and current main.",
        "Keep the old hard-bound private operator unadopted; new or corrected runtime profiles require complete Source review and a concrete bounded operator execution decision."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": [
        "All original 63 changed native paths match the preserved snapshot. Six workflow modules/tests belong to CORE11; the README description is already delivered in main. Exactly 56 native candidates remain.",
        "The dedicated GH-12 workspace contains those 56 read-only inputs only as ignored data. No product adoption, import, collection, runtime grant or native dispatch occurred.",
        "The separately frozen native operator remains NOT_READY_FOR_RUNTIME after partial independent review. Known Source corrections and all 50 selected runtime controls remain open.",
        "The child-program context can reproduce all original 790743 JSON bytes from bounded quoted Source without omitting any of the 38 programs. This is reconstruction, not semantic review or execution."
      ]
    },
    {
      "id": "claude-13",
      "title": "Add a portable independent Claude CLI review capability",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/13",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "done",
      "dependencies": [],
      "acceptance": [
        "Uses the installed ordinary Claude CLI with explicit frozen source scope and structured findings.",
        "Verifies supported flags, disables tools and avoids source writes.",
        "Bounds process lifetime/output and preserves unavailable outcomes and actual cleanup facts.",
        "Binds coverage/findings to revision and scoped content identity for relevant-change reuse.",
        "Separates coding-account usage from application budgets and excludes credentials from artifacts.",
        "Refuses mixed live/offline claim modes before access and preserves deadline diagnostics while redacting invalid JSON details."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": [
        "Delivered through owner-authorized PR20 squash merge 4bc0110146c84467b870d5efaba5bc828a2989fb. Exact reviewed head ec5a306 passed final independent Claude delta review, Root checks and complete CI; issue13 is actually closed. Earlier Source-freeze and pending statements below remain historical.",
        "Current CLI correction: 152 management tests pass on Python 3.11.15 and 3.14.10. New regression controls produced eight failures and four redaction passes against e3a1f6e before production edits. Final independent changed-source review and exact-head CI are recorded on GH-13 and PR20 after this source freeze; prior review/CI remains historical and owner acceptance WAIT.",
        "GH-13 URL refusal follow-up: 140 management tests pass on Python 3.11.15 and 3.14.10; repository Ruff and management checks pass. Whole canonical URL tokens and bare references are consumed before refusing residual reference/URL-like text, including beside None. All original controls remain.",
        "The operator reports completed independent normal-Claude current/base review of 43bbb0486d0a3763a6f15ec4136830a8f04c29b4: seven selected paths, zero denials, nine groups retired, scratch removed and unchanged source. Both CI runs passed for that revision. The helper, its tests and procedure remain byte-identical to that reviewed source and were not rerun. The new parser/test delta still needs independent review and fresh CI; the separate incomplete twelve-file review and earlier unavailable/failure outcomes remain explicit.",
        "See gh-13-worklog.md for scope, observed failures, checks and delivery unknowns; material-risk acceptance remains WAIT."
      ]
    },
    {
      "id": "process-14",
      "title": "Run workflow sessions in fresh processes with durable untrusted bridges",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/14",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "blocked",
      "dependencies": [
        "core-11",
        "native-12"
      ],
      "acceptance": [
        "Uses two actual fresh conversations and private durable reopened bridge bytes; failed producer blocks consumer.",
        "Whole selected run accounting preserves unresolved usage and the application-test cap."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
    },
    {
      "id": "reports-15",
      "title": "Integrate workflow results with CLI, reports, comparison, and dashboard",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/15",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "blocked",
      "dependencies": [
        "process-14"
      ],
      "acceptance": [
        "Versioned workflow reports/CLI/dashboard preserve unknowns, evidence bindings and paired controls."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
    },
    {
      "id": "corpus-16",
      "title": "Expand the admitted corpus with independent reproducible upstream cases",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/16",
      "owner": "Claude",
      "reviewer": "Codex",
      "status": "backlog",
      "dependencies": [],
      "acceptance": [
        "Independent real cases have verified provenance, meaningful ground truth and honest source-group counts."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
    },
    {
      "id": "service-17",
      "title": "Deliver opt-in self-hosted GitHub report service",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/17",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "blocked",
      "dependencies": [
        "native-12",
        "reports-15"
      ],
      "acceptance": [
        "Service isolation, installation and delivery are reviewed and actually verified before launch."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
    },
    {
      "id": "benchmark-18",
      "title": "Publish evidence-backed repeated cross-model comparisons",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/18",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "blocked",
      "dependencies": [
        "corpus-16",
        "native-12",
        "reports-15"
      ],
      "acceptance": [
        "Actual repeated paired model results have source diversity, adjudication and uncertainty; no synthetic ranking."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
    }
  ]
}
```

The graph covers the remaining goal, not just this scaffold: core publication,
fresh-process execution, shared CLI/report/dashboard integration, native
ownership, realistic corpus/adjudication/repeats and service readiness. A status
or task label is not runtime or model evidence.

The native GitHub adapter has no dependency inference. Operator promotion and
worker rechecks remain required. Claude-led work needs the real CLI bridge;
a role label alone cannot supply it. Current dirty worktrees stay excluded until
explicit ownership handoff.

Next: land this reviewed custody proposal against actual main after reviewer
issue13 delivery. The operator then checks each task's actual dependency/role
record and accepted intake pins before explicit promotion. CORE11 and NATIVE12
have distinct file scopes and can advance independently; neither may overwrite
the other's accepted work. No old native private operator is automatically
adopted or executed. See [plan rules](../../PLANS.md) and
[operations](../../symphony-operations.md).

Migration: new implementation/research goes through Symphony/GitHub, with one
writer per issue/scope. Accepted landing releases only completed manual claims11
and12. Claim10 remains held while the operator finishes management work. A plan
status coordinates open work; a terminal done record must be explicitly reopened
in the versioned plan. Neither status grants a runtime claim or dispatch authority.
Actual operating/review evidence is recorded in issues10/13; offline checks do
not establish a live claim, model result or native execution authority.

## Controlled core handoff

Landing this registry change requires explicit owner acceptance of this custody
handoff. Before landing, main still protects #11. Accepted landing releases this
completed manual claim and the separate native claim described below; it does not
promote or dispatch either task. Hold10 remains. Both11 and12 require the actual
closed13 dependency and their own matching live claim.

The old owner stays stopped and its dirty worktree is preserved. Verified input
is staged read-only at `.runtime-cache/core-handoff/` in the dedicated GH-11
workspace. Before adoption, compare every file's actual length and SHA-256 with
this committed table, not merely a manifest supplied beside the input. Reject
missing, extra, mismatched or unknown input. Apply only the listed ten files and
the separately listed documentation proposal after a genuine live claim passes.
The managed task then performs integration checks against current main.

| Input | Bytes | Expected SHA-256 |
| --- | ---: | --- |
| `README.md` | 5094 | `5147d736bdd5f65fa4465272f74764fa4e11a0bb75e6ea1f6a259e2ce0151cc7` |
| `docs/agent-workflows.md` | 5387 | `f3541b5d10d6abc695ad998039421f8a37f97675a5a6379c5874ddc207e0ca30` |
| `src/review_boundary/provenance.py` | 10163 | `991e9aa5eb2845d48fe39c3847df8c85df394be9f0094a31e8fb075ef79411b5` |
| `src/review_boundary/workflow_cases.py` | 22226 | `b553efab000c8d9d035c94852cab62c99ce95e833406b29cec5e4c3ae8063362` |
| `src/review_boundary/workflow_replay.py` | 17645 | `428673f29845743fc31483db0a68704e198d2b1b4d4c0fd07319f5424e05db0e` |
| `src/review_boundary/workflow_world.py` | 29740 | `55b62ddeb99ac505504a2221ccc07ab3bba9261efeeb0ffd10270e197c50e96c` |
| `tests/test_provenance.py` | 8677 | `7f40a974f6f67d65336aeb19006e15786bd0e51cfcebc79b67de40c048aee2c1` |
| `tests/test_workflow_cases.py` | 14479 | `e6fd7fa120e3cf0b31010f49511bdaf5af9454735afc2188dbbf37a65f3b4e3b` |
| `tests/test_workflow_replay.py` | 34476 | `80d0e1b5cb8db5927588f779c6a6c3dea6b5b4c41106b3ef5f2fb809b017fa50` |
| `tests/test_workflow_world.py` | 28188 | `7cb8f8c812d5e9402885ea7f92c834246f92cf56263c04e23c14b28981df6e38` |
| `docs-only-proposal.patch` | 3319 | `148f5291333e771d030f090c0a9b4ff31c92a79ee76ed370c323d9a5826a2f88` |

The table binds source identity, not historical execution authenticity. The
operator's preserved receipts remain the evidence for earlier checks. No native
execution, dependency closure, reviewer approval or automatic promotion follows
from these hashes. The operator requires #13 closed, the accepted registry and
matching actual #11 roles/dependencies before adding dispatch:enabled.

## Controlled native handoff

The native file contract is [native-custody-inputs.json](native-custody-inputs.json),
SHA-256 `c1d325b2836bd611719dff4adb50b1e51400d3ef146d6b729805441e683c8d00`. The operator must verify that committed identity, then
compare every staged input's path, byte length and hash against its `files` list.
Reject missing, extra, mismatched, symlinked or unknown inputs. The staged receipt
belongs outside `.runtime-cache/native-handoff/`; it is not its own authority.

Exactly 56 native files are eligible for managed adoption. The six excluded
workflow modules/tests remain CORE11-owned, including any newer accepted version.
The excluded README description is already delivered; preserve current main and
core documentation. Excluded files stay preserved in the old worktree and must
never be overlaid from this native intake. This prevents ownership collisions;
it does not drop core features from the full project goal.

Before accepted landing, main still holds manual12. After landing and an actual
closed13 dependency, only explicit operator promotion plus a matching fresh
GH-12 live claim may start the managed source integration/correction task. Its
first phase may adopt the verified product sources and author corrected Source.
The old hard-bound private operator remains separate, unretargeted and UNRUN.
No old receipt, source hash, task label or custody release grants execution.

Complete independent review must cover the corrected profiles and their actual
workspace/interpreter/dependency inputs before the operator issues a concrete
bounded runtime decision. Preserve partial/unavailable outcomes and actual
ownership on uncertainty. Existing ordinary coding-account Source review remains
authorized. No application-provider benchmark request, paid reservation, broad
collection, host/VM activation or other lane's file edit follows from this handoff.
The remaining native/SDK/host/VM acceptance and downstream issues remain open.
