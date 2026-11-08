# Symphony management and remaining milestones

Status: proposed CORE #11 custody handoff, blocked on the reviewer task #13.
These are the actual [repository issues](https://github.com/utkutugrul/review-boundary/issues).
Dispatch remains operator-controlled. Completed manual owners have stopped;
#10 and #12 retain their holds. Only #11 receives the verified continuation
handoff described below, with no automatic dispatch or native runtime grant.
Initial scaffold evidence below is historical; current runtime and delivery
facts are recorded in the linked issues. Null links are for pending tasks only.

```json task-contract
{
  "manual_claims": [
    10,
    12
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
      "status": "active",
      "dependencies": [],
      "acceptance": [
        "Native lifecycle, privacy and ownership evidence closes actual supported tests without invented guarantees."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
    },
    {
      "id": "claude-13",
      "title": "Add a portable independent Claude CLI review capability",
      "issue": "https://github.com/utkutugrul/review-boundary/issues/13",
      "owner": "Codex",
      "reviewer": "Claude",
      "status": "backlog",
      "dependencies": [],
      "acceptance": [
        "Invokes the real ordinary Claude CLI independently with bounded ownership and sanitized structured evidence."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
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

Next: complete the owner-gated #13 delivery and close that actual dependency.
Accept this custody handoff before landing its claim release. The operator then
checks the actual #11 issue and intake hashes and explicitly promotes it. Native
#12 stays held; no private native operator is adopted. The earlier #13 pilot and
initial launch statements are historical, not authority for another startup.
See [plan rules](../../PLANS.md) and [operations](../../symphony-operations.md).

Migration: finish only currently owned work and its verification/handoff. All new
implementation/research tasks then go through Symphony/GitHub, with one writer
per issue/scope. manual_claims is the sole small plan-level extension needed to
protect #10 and #12. The completed #11 owner has handed custody to the operator;
this proposed release becomes active only on owner-accepted landing. A delivery
role or plan status is not a runtime claim or dispatch authorization.
The host gate has offline fake-HTTP coverage for fixed GitHub HTTPS, registered
GH-N identity/dependencies and explicit host token. Actual operating evidence is
recorded in #10/#13; offline checks do not establish a live claim or model result.


## Controlled core handoff

Landing this registry change requires explicit owner acceptance of this custody
handoff. Before landing, main still protects #11. Accepted landing releases only
that completed manual claim; it does not promote or dispatch a task. Holds #10
and #12 remain, and #11 is blocked on the actual closed #13 dependency.

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
