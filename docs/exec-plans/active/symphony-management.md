# Symphony management and remaining milestones

Status: Management scaffold validated offline; launch and first dispatch pending.
These are the actual [repository issues](https://github.com/utkutugrul/review-boundary/issues).
All lack dispatch:enabled. The previous agents have stopped, but #10/#11/#12 retain
manual handoff holds until their uncommitted sources are explicitly migrated.
Null links are permitted only for future pending tasks.

```json task-contract
{
  "manual_claims": [
    10,
    11,
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
      "status": "active",
      "dependencies": [],
      "acceptance": [
        "Final core APIs, docs and tests pass supported-version, package and independent review checks."
      ],
      "validation": [
        "Record scoped actual checks and independent final-source review in the issue/PR."
      ],
      "evidence": []
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

Next: review/land #10, preserve the completed owners' handoffs, ship #13, obtain
launch acceptance, then explicitly promote one eligible task.
See [plan rules](../../PLANS.md) and [operations](../../symphony-operations.md).

Migration: finish only currently owned work and its verification/handoff. All new
implementation/research tasks then go through Symphony/GitHub, with one writer
per issue/scope. manual_claims is the sole small plan-level extension needed to
protect #10/#11/#12 until explicit owner handoff; role owner is not a runtime claim.
The one-shot host gate has offline fake-HTTP coverage: fixed GitHub HTTPS, registered GH-N
identity/dependencies and explicit host token. Fake-HTTP checks and actual
upstream host/config compatibility are distinct; only the former has run.
