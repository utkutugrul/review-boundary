# Durable data-only workflow bundles

`review_boundary.workflow_bridge_io` writes one private local bundle and inspects
its current bytes. It wraps the unchanged CORE11 seal, replay and restore APIs.
It creates no reviewer process, conversation, SDK task, provider request,
transport result, process ownership decision or accounting record. Completing
this child does not complete PROCESS14 or Native12. Their transport, retirement,
fresh conversation/workspace, SDK, provenance, accounting and acceptance gates
remain independent.

## Caller contract

The two public functions have the same explicit arguments:

```python
write_workflow_bridge(
    directory: Path, *, case: WorkflowCase,
    producer_snapshot: WorkflowSnapshot, binding: WorkflowRunBinding,
    guard: Literal["on", "off"], limits: WorkflowLimits,
) -> ReopenedWorkflowBridge

reopen_workflow_bridge(
    directory: Path, *, case: WorkflowCase,
    producer_snapshot: WorkflowSnapshot, binding: WorkflowRunBinding,
    guard: Literal["on", "off"], limits: WorkflowLimits,
) -> ReopenedWorkflowBridge
```

Supply the independently expected producer snapshot, binding, case, guard and
limits from the controller. Files cannot supply their own expected values.
Both functions revalidate model instances through core checked APIs, including
instances made with unchecked model copy/construct. They require the exact
two-session memory or handoff case, replay session zero, and require its terminal
successful `submit_review`, completed/nonfatal state and observed notes. They
obtain the exact seal before filesystem mutation. Replay inconsistency, forged
completion or an oversized full envelope cannot create a leaf. Completed data
does not prove a producer process succeeded, retired or was billed.

The immutable result contains only `raw_bridge: bytes` and the newly checked
`producer_snapshot: WorkflowSnapshot` read from disk. Notes remain
`untrusted_data_only`. They are never evaluated, imported or executed.

## Trusted filesystem and publication order

Supply one explicit absolute leaf under an existing operator-owned local parent.
The parent and every supplied ancestor must already be physical directories.
On Darwin, a caller creating a temporary parent through `/var` must first select
its canonical physical path and pass that path. The library refuses symlink
aliases and `..`; it never resolves forbidden input or creates parents. Ancestor
directories need not share the operator UID; the immediate parent must. No new
parent-mode requirement is imposed. The host must support POSIX effective UID,
nofollow/nonblocking/directory opens, descriptor metadata, directory-relative
operations and directory fsync. A missing required capability refuses before
effects; an unsuccessful directory fsync is an unknown I/O outcome.

The writer refuses an existing leaf of every kind, including dangling symlinks,
valid bundles, partial bundles and unknown prior attempts, before payload reads.
It uses exclusive mkdir/open, verifies the leaf's actual current-UID ownership
and exact `0700`, and verifies regular/nonsymlink files with actual `0600`, current
UID and link count one. It never chmods an existing path. A restrictive umask
that prevents the exact modes fails explicitly, retaining created paths.

1. Write `producer.json` and `bridge.json` separately. For each original
   unbuffered writer, make one bounded write, require its full byte count, flush,
   fsync and attempt close once. A short write is unknown and is never retried.
2. Fsync the leaf directory after both data writers have closed successfully.
3. Exclusively create, write, flush, fsync and close `complete.json`.
4. Fsync the directory again, then close the owned directory handles.
5. Call the same public reopener on new actual read handles. No writer handle or
   in-memory seal substitutes for the reopened result.

Every acquired resource remains independently owned until its close attempt.
Unbuffered FileIO prevents cleanup close from retrying buffered payload after a
failed flush. It does not itself prove resource custody. Close exceptions keep
strong references to the original resources in `WorkflowBridgeIOError._unclosed`.
The module makes no second close attempt, saved-descriptor adoption or unknown
write retry. The caller must retain the exception and reconcile that custody.
No public success is returned if an owned close fails.

Cancellation/interruption propagates after best-effort independent single-close
cleanup. Original unresolved resources are retained on that interruption as
`_workflow_bridge_unclosed`. Cleanup continues for other owners even when one
close fails or is interrupted. These calls are bounded in number and bytes;
there is no hard OS syscall deadline or forced-termination cleanup guarantee.

## Fixed private format

There are exactly three entries, with no subdirectories or extra entries.
There is no trailing LF. Digests are lowercase SHA-256 hex over exact file bytes.
JSON is strict canonical UTF-8 with sorted keys and compact separators. Duplicate
or unknown keys, nonfinite numbers and unsupported JSON values are refused.

| File | Exact bound and content |
| --- | --- |
| `producer.json` | Full canonical checked WorkflowSnapshot; at most explicit `limits.max_trace_bytes`, never above 2097152 bytes, 262144 logical nodes, depth 24. |
| `bridge.json` | Exact core seal bytes, at most 16384 bytes for the whole envelope. No reconstruction or appended LF. Core bridge schema/node/depth limits remain unchanged. |
| `complete.json` | At most 4096 bytes, 512 logical nodes, depth 8. Exact fields below. |

The case keeps its existing 131072-byte, 65536-node, depth-24 cap. The sidecar has
exactly `bundle_version` (exact integer 1), `state` (`data_files_closed`),
`workflow_case_sha256`, `binding`, `guard`, `limits`, `producer_session` (exact
integer 0), `consumer_session` (exact integer 1), `producer_snapshot_bytes`,
`producer_snapshot_sha256`, `bridge_bytes`, and `bridge_sha256`. Binding and limits
contain the full checked core model fields. All counts are exact integers, so
booleans are rejected. Both byte counts are positive and bounded by their file
caps. This sidecar is a private file format, without authenticity or consumer
readiness authority; its state records data files written and closed.

The reopener checks private directory identity, the exact roster, and metadata
for all files before payload opens/reads. It uses nofollow/nonblocking opens,
checks every fstat against its path before reading, reads within its declared
cap plus an EOF witness, and compares descriptor/path identities afterward.
Each actual reader is kept and closed independently. The small sidecar is read
first. Its exact identity, counts and digests must match the caller's trusted
expected data before the other payloads are read. The producer must also be
canonical, checked, and byte-for-byte equal to the independently expected full
snapshot; matching attacker-supplied hashes are insufficient. The reopened bridge
must equal the exact seal and pass `restore_workflow_bridge(case, 1, ...)` with
the reopened snapshot. Final roster and identity checks precede return.

## Fixed error classification

`WorkflowBridgeIOError.code` and `.phase` use only these fixed values. Public
str/repr omit file contents, OSError text and arbitrary exception prose. Core
exceptions are never classified by searching their messages.

| Predicate | Code | Phase |
| --- | --- | --- |
| Required POSIX/private-identity capability missing | `unsupported` | `validate` |
| Explicit model/type/schema/resource/guard failure, unsupported case, or replay/seal validation failure | `invalid` | `validate` |
| Checked snapshot case/session/binding/guard/limits differs from explicit expected identity | `binding` | `validate` |
| Replayed snapshot lacks successful terminal submit, completion, nonfatal state, notes or complete request replay | `incomplete` | `validate` |
| Relative/dotdot/NUL path, absent or symlinked ancestor, unowned parent | `path` | `validate` |
| Existing writer leaf, including an exclusive-mkdir collision | `exists` | `create` |
| Bad actual directory/file UID/type/mode/link count | `path` | `create`, `reopen` or `read`, at the actual check |
| Missing inspection leaf or roster entries | `incomplete` | `reopen` |
| Extra roster entry, or file metadata above its byte cap | `invalid` | `reopen` |
| Short payload against prechecked size | `incomplete` | `read` |
| Excess bytes/nonempty EOF | `invalid` | `read` |
| Malformed/noncanonical checked payload or sidecar fields/bounds | `invalid` | `verify` |
| Well-formed sidecar differs from trusted expected identity/counts/hashes, or reopened bytes differ from expected snapshot/seal | `binding` | `verify` |
| Observed descriptor/path identity changes | `io_unknown` | `create`, `sync`, `reopen`, `read` or `verify`, at the actual check |
| Open/mkdir/write/flush/fsync/read/metadata exception or short write | `io_unknown` | `create`, `write`, `sync`, `reopen`, `read` or `verify`, at the operation |
| Any owned close exception, including cleanup after another failure | `io_unknown` | `close` |

Explicit validation/identity predicates take precedence in that order: checked
input schema, expected identity, core replay, replayed completion, core seal.
Core replay/seal/restore errors map to `invalid` at their validation phase.
Unexpected exceptions within owned filesystem operations map to `io_unknown` at
the current phase. A close failure overrides an ordinary prior refusal because
custody is uncertain; an interruption takes precedence and remains interruption.
Fixed refusal codes after creation do not imply rollback. Every post-creation
failure retains the entire namespace and every partial file. No deletion,
replacement, rotation, overwrite or automatic retry is implemented.

## Irreducible uncertainty

A successful reopen establishes current data consistency. It does not prove a
previous writer returned success and cannot reconcile an earlier unknown. A
read-only inspection can succeed after a writer's final-sync error, while the
original error remains unknown and a second write is still refused. Inspection
cannot authorize a consumer or retry work. Across crashes the caller/operator
must retain and reconcile ambiguity. This module adds no journal, lease, process
authority or automatic recovery framework.

The contract assumes a trusted local parent. Parent-directory replacement,
concurrent hostile writers, hostile storage and hardware durability are outside
that assumption. Successful fsync/identity checks imply no filesystem race or
power-loss guarantee. Source review, local file tests, installed-module checks
and model robustness are separate evidence categories.

## Focused validation

Run `tests/test_workflow_bridge_io.py` directly with each selected interpreter and
`-B`. It uses stdlib unittest, a bounded Source import path and physical temporary
parents; it needs no plugin discovery or caches. The controls use real core
dispatch/replay for memory/handoff clean, attack and authorized data, and real
FileIO resources for publication order, EOF, corruption, failures and custody.
Both literal supported runtimes and fresh wheel-installed smoke checks remain
required delivery evidence. Tests do not establish model or process acceptance.

Implementation validation on Darwin used the selected Python 3.11.15 and 3.14.3
launchers with `-B`: all 30 methods passed on each. The named controls include
`test_real_close_sync_then_distinct_reopen_and_eof_order`,
`test_real_write_flush_fsync_close_and_publication_failures`,
`test_truncated_and_nonempty_eof_refuse_after_real_reads`,
`test_directory_close_failures_retain_each_original_owner_once`, and
`test_self_consistent_forgery_and_different_expected_snapshot`. Their operation
witnesses wrap real acquired FileIO objects and real fsync calls. Truncation and
EOF growth physically mutate temporary files between checks and reads.

The normal wheel and sdist built without packaging changes. Fresh task-owned
environments for each runtime installed the wheel without resolving new
dependencies, sharing the existing pinned dependency directories read-only.
Both verified the installed module path and exact Source/wheel/installed byte
identity, then passed real memory and handoff write/reopen, mode, existing-leaf
refusal and changed-expected-binding refusal controls. Ten selected unchanged
core bridge controls passed on each runtime; disabling pytest plugins retained
the expected unused `asyncio_mode` configuration warning. An initial test run
caught unchecked integer booleans being normalized by JSON serialization and an
incorrect assumption about unbuffered close calling flush. The implementation
now validates Python-mode fields first, and tests prove no payload write retry.
