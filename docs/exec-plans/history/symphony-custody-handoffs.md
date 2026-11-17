# Historical managed custody handoffs

Archived from the active plan at fb1b65c0d131d71f783edd4c9d005f1ea4cccd4b.
The custody terms below remain historical evidence. This move grants no dispatch
or runtime authority. The native manifest link is adjusted for this directory.

## Controlled core handoff

The proposal below is historical accepted custody evidence. PR21 landed it;
PR22 subsequently delivered the core. Its old pre-landing descriptions do not
reopen completed work or grant another dispatch.

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

This section preserves the historical proposal accepted by PR21. Manual12 was
released and the initial GH12 worker entered a Source-only phase at that time.
That worker has retired; the current registry and actual GitHub state govern any
future promotion. The pre-landing descriptions below grant no new dispatch or
runtime authority.

The native file contract is [native-custody-inputs.json](../active/native-custody-inputs.json),
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
