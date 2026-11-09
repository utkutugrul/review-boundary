# Durable data-only workflow bundles

CORE11 data seal/replay/restore only, without process/SDK/provider/transport/
ownership/accounting authority. PROCESS14/Native12 remain separate.

`write_workflow_bridge` and `reopen_workflow_bridge` require `directory: Path`;
keyword-only `case: WorkflowCase`, `producer_snapshot: WorkflowSnapshot`,
`binding: WorkflowRunBinding`, `guard: Literal["on","off"]`,
`limits: WorkflowLimits`. No defaults. Immutable `ReopenedWorkflowBridge`
contains `raw_bridge: bytes` and reopened `producer_snapshot: WorkflowSnapshot`.

Independent expected inputs, including unchecked copies/constructs, undergo
Python-mode and core checked validation. Before effects require two-session
memory/handoff, matching case/session0/binding/guard/limits, complete replay,
completed nonfatal producer, notes and terminal successful submit_review, then
exact seal. Notes stay untrusted_data_only, never evaluated/imported.
Completion establishes data consistency only.

## Filesystem contract

Supply an absolute new leaf under an existing trusted operator-owned parent with
physical ancestors (canonical on Darwin). Refuse dotdot, symlinks and existing
leaves, including dangling/partial/unknown ones, before payload reads. Require
POSIX UID, nofollow/nonblocking, directory-relative operations, metadata and
directory fsync. No normalization, parent creation, chmod, overwrite, deletion,
reuse, rotation or retry.

Verify UID, exact leaf0700, regular nonsymlink files0600/link-count1;
restrictive modes fail. Exclusively create producer.json and bridge.json,
each with one bounded exact-count write, flush/fsync/single close. Fsync directory,
exclusively write/flush/fsync/close complete.json, fsync directory again, close
directories, then use the public reopener on distinct actual readers.

Strict canonical UTF-8 JSON, sorted/compact, no LF, duplicate/unknown keys,
boolean counts/versions, nonfinite or unsupported values.

| Data | Bound |
| --- | --- |
| Case | 131072B/65536nodes/depth24 |
| producer.json, full checked snapshot | explicit max_trace_bytes <=2097152B/262144nodes/depth24 |
| bridge.json, exact whole seal | 16384B |
| complete.json | 4096B/512nodes/depth8 |

Exact sidecar: bundle_version integer1; state="data_files_closed";
workflow_case_sha256; binding; guard; limits; producer_session integer0;
consumer_session integer1; producer_snapshot_bytes; producer_snapshot_sha256;
bridge_bytes; bridge_sha256. Byte counts: positive bounded exact integers.
Digests: lowercase64hex. State grants no authenticity/consumer authority.

Reopen checks private directory identity, exact roster and all file metadata
before payload opens/reads. Check fstat/path identities before/after bounded reads
plus EOF; close independently. Read sidecar first; match trusted arguments/counts/
hashes, exact canonical expected snapshot and seal, then restore consumer1 with
reopened snapshot and recheck roster/identities.
## Ownership correction

_Resources.open_file registers the actual unopened FileIO before _open_file
initializes it; _open_directory registers its wrapper before opening. Unbuffered FileIO avoids buffered retry after failed
flush. _Owned separates attempted from closed: _Resources.close marks before
calling and observes closed after return. _Resources.__exit__ makes one independent
cleanup pass, retaining all originals lacking that observation.

Before-attempt interruption permits cleanup. After-attempt interruption, even
before the call or after return, retains without retry. Interrupted cleanup can
retain an unattempted original. Any cleanup exception prevents success. Strong
originals stay in WorkflowBridgeIOError._unclosed or
interruption._workflow_bridge_unclosed; retain the exception. No saved-FD adoption
or second attempt. Real controls separate product calls/order from caller cleanup.
Python line/return injection proves no OS-signal/universal interruption safety,
hard syscall deadline or forced cleanup.

## Fixed diagnostics

Public str/repr: fixed code/phase, no exception prose or matching.
Precedence: schema, expected identity, replay, completion, seal.

At validate: missing capability=unsupported, schema/resource/replay/seal=invalid,
identity=binding, incomplete producer=incomplete, forbidden path/parent=path.
Existing leaf/mkdir collision=exists:create. Bad UID/type/mode/links=path at
create/reopen/read. Missing leaf/roster=incomplete:reopen; extra/oversize=invalid:reopen.
Short read=incomplete:read; excess/EOF=invalid:read. Malformed/noncanonical=invalid:verify;
trusted-data difference=binding:verify. Identity changes/operation exceptions/
short write=io_unknown at create/write/sync/reopen/read/verify. Close/cleanup
uncertainty=io_unknown:close.

Interruption takes precedence; retain partial files/namespaces. Reopen establishes
current consistency, never prior writer success, unknown reconciliation, consumer
authority or retry. Writer refuses reuse. The operator retains crash ambiguity.
No journal/lease/recovery. Hostile parent replacement, concurrent writers/storage
and hardware durability are outside the trusted-local assumption; fsync proves
no race/power-loss guarantee.

## Exact reachable envelope

Core dispatch bounds encoded notes at14336B (16384-2048). Maximum binding838B
uses run_id32hex, reviewer128 characters at most6 JSON bytes each, epoch10.
NUL/surrogates refuse; other Unicode uses at most4 UTF-8 bytes. Fixed remaining
envelope adds495B with handoff, guard off, versions/sessions/digests and five
payload-count digits. Exact reachable maximum:14336+838+495=15669B; memory15668B.
Thus an over16384B replay-consistent seal is impossible under unchanged limits.

Real-core tests reach both maxima: six2048B notes, one2026B note, reviewer
U+0001 repeated128, epoch10, guard off. A2027B last note makes14337B:
dispatch refuses note_limit with leaf absent. Accepted data replays/seals/
writes/reopens. The retained oversized model-copy negative fails replay, without
isolating the envelope cap. Replay and seal precede creation; core keeps16384B.
