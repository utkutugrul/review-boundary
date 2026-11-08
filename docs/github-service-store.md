# Standalone service job store

[github_service_store.py](../src/review_boundary/github_service_store.py) provides
local bookkeeping only. It uses Python's standard-library SQLite module, without
HTTP/CLI wiring, authentication, evaluation, shell dispatch or worker activation.
Full SERVICE17 still requires its Native/report dependencies and actual running
receiver/store/worker/CLI integration. This module does not publish anything.

## Version 1 contract

Pass an explicit absolute `pathlib.Path` in an existing trusted operator-owned
local directory. The target must be a regular file or a new file, never a symlink.
The operator controls directory permissions, backups, filesystem choice and all
callers. Parent-directory symlinks, concurrent filesystem replacement, hostile
SQLite files and remote filesystems are outside this trust assumption. No path
discovery, directory creation or credential loading occurs. One connection belongs
to one caller/thread; use separate `JobStore` objects for concurrent connections.

The database uses SQLite 3.37+ STRICT tables, `application_id = 0x52424A31`,
`user_version = 1`, one clock row and one jobs table. Only an empty unversioned
database is initialized. Other
versions/applications or unrelated tables are refused; there is no migration.
SQLite transactions use `BEGIN IMMEDIATE`, FULL synchronous mode and a busy
timeout from 0 through 1000 ms (default 1000). There is no event-history table.
Busy timeout bounds SQLite's lock wait, not total filesystem/OS operation time.

Identity consists of all these immutable caller-supplied fields:

| Field | Exact accepted value |
| --- | --- |
| `repository` | Lowercase ASCII owner/repository; owner 1..39 alphanumeric/hyphen characters starting alphanumeric; repository 1..100 alphanumeric/`_.-` characters, excluding `.` and `..`. No normalization. |
| `pull_number` | Integer 1..2^63-1. |
| `head_sha` | Exactly 40 lowercase hexadecimal characters. |
| `request_digest` | Exactly 64 lowercase hexadecimal characters, a caller-claimed SHA-256 reference. |
| `idempotency_key` | 1..128 ASCII alphanumeric/`._:-` characters, starting alphanumeric; globally unique within this database. |
| `run_id`, `attempt_id`, `artifact_id` | Optional integers 1..2^63-1. |
| `artifact_digest` | Optional 64 lowercase hexadecimal characters. |

Booleans, floats, coercions and string subclasses are refused for typed identity
fields. The full identity is checked on every lookup and lease write. Repeating
the same key and identity returns its original record, including any tombstone;
changing any other identity field under that key raises `identity_conflict`.
A different key is a different request. Keys must therefore be assigned by a
trusted integration with a stable namespace, never blindly from unauthenticated
input. The store cannot determine whether a caller's key/digest is correct.

Persist only these bounded references and local state, timestamps, lease
owner/generation/deadline, one fixed error category and a tombstone flag. Never
put secrets, personal data, private source, request/report bodies, provider errors
or encoded versions of those contents in identity/owner fields. Run, attempt and
artifact IDs are unverified references. Neither stored hashes nor `complete`
authenticate GitHub data, validate a report or establish evaluator/model success.

## State and time

All operations take trusted integer Unix `now_ms` in 0..253402300799999. A
database-wide persisted high-water mark refuses earlier times across connections
and reopen; equal times are allowed. The caller supplies a correct wall clock.
Clock skew/rollback needs operator resolution, never backdating or resetting the
clock row. The store does not independently measure elapsed time or worker life.
Every accepted time observation, even a refused state/identity write, persists
the clock and expires all due leases before selecting results.

| Operation | Required state/fence | Result |
| --- | --- | --- |
| `enqueue(identity)` | Absent key and free capacity | `pending`, generation 0. Exact replay returns the retained record in any state. |
| `claim(identity, owner, lease_ms)` | `pending` | `leased`, generation 1, exclusive owner and deadline. Competing claims are refused. |
| `renew(lease, lease_ms)` | Current full identity, owner, generation, exact deadline; `now_ms < deadline` | A strictly later deadline and generation + 1. The old lease is stale immediately. |
| `finish(lease, outcome)` | Same current fence and unexpired lease | Exactly `JobState.COMPLETE`, `FAILED` or `UNKNOWN`. Strings are refused. |
| Any time observation | `leased` and `now_ms >= deadline` | `unknown` with `lease_expired`, persisted even when the requested write is refused. |
| `prune(before_ms, limit)` | Known `complete`/`failed`, finish time strictly before cutoff | Tombstone retaining identity, outcome, error category, creation/finish times; clears execution owner/generation/deadline. |

Owners are 1..64 ASCII alphanumeric/`._-` characters starting alphanumeric.
Lease durations are integers 1..300000 ms and must fit the timestamp range.
Generations are bounded by 2^63-1; exhaustion refuses renewal. A lease is a local
concurrency fence, not an authentication token. Knowledge of its fields grants no
external authority. Public writes run after checking the fence in the same
exclusive transaction, so stale connections cannot overwrite a newer generation.

`failed` means a caller explicitly reported local failure (`worker_failed`).
Explicit `unknown` records `worker_unknown`; expiry records `lease_expired`.
`unknown` has no finish time and is never compacted. There is no reset, release,
reclaim, retry or unknown-to-success transition. A finished lease cannot finish
again, even identically; read the retained record to reconcile the result.
Expiry never proves worker retirement or authorizes repetition of a possibly
completed external action. The integration must enforce this outside the store.

## Ambiguity and bounds

A SQLite lock refusal before transaction acquisition is `busy`, with no intake.
SQLite/I/O failure after acquisition returns `outcome_unknown` and quarantines
that connection. Recovery attempts a separate transaction: mark outstanding
leases and the affected pending record `unknown`/`storage_unknown`, since expiry
bookkeeping may also have been rolled back. Only intake may reserve a missing
identity; a savepoint isolates reservation/capacity refusal from lease downgrades
and the clock update. Reads, replays and refused writes preserve already-known
terminal outcomes and tombstones. An ambiguous actual finish instead downgrades
its newly written terminal state to unknown. Errors before and after commit take
the same recovery path. Interruption attempts recovery, then propagates.

If storage also refuses recovery, the unknown marker may not persist. The prior
row could still be pending, leased or complete. Close the quarantined connection
and quarantine the database path at the operator/integration boundary until
reconciled. Automatic reopen/retry is not reconciliation. The API cannot promise
an atomic database commit plus delivery of its return value: process death after
commit but before return is intrinsically ambiguous. Reopened local state is
evidence for reconciliation, never proof of an external action or safe repetition.
Public errors contain only fixed codes, with SQLite/provider text excluded.

`StoreError.code` is one of `invalid`, `path`, `schema`, `storage`, `closed`,
`busy`, `capacity`, `identity_conflict`, `not_found`, `state_conflict`,
`stale_lease`, `time` or `outcome_unknown`.

At most **10000 total records including tombstones** are admitted, enforced by
the transaction and an insert trigger. Capacity exhaustion returns `capacity`;
exact replay still works. Retention never deletes identities or frees capacity.
Pending, leased and unknown records are retained. There is no public deletion.
Any archive/rotation policy must preserve the original idempotency namespace and
requires a later operator/integration design.

`list_jobs` and `prune` take integer limits 1..100, default 100. Lists sort by
ASCII idempotency key with an optional exclusive `after_key` cursor and typed
state filter. Each page is a separate observation, not a multi-page snapshot.
Retention requires `0 <= before_ms <= now_ms` and compacts at most the limit.
Global expiry updates can touch all 10000 rows; result/prune batches stay bounded.
Unknown outcomes remain visible and cannot disappear through retention.

```python
from pathlib import Path
from review_boundary.github_service_store import JobIdentity, JobStore

request = JobIdentity("example/repository", 42, "a" * 40, "b" * 64, "request-1")
with JobStore(Path("/operator-owned/state/jobs.sqlite")) as store:
    record = store.enqueue(request, now_ms=1_800_000_000_000)
```

The example values are synthetic caller claims, with no GitHub authenticity.
Only a trusted future integration should claim or finish actual work.

## Local validation

Run the focused tests with Python 3.11.15 and 3.14.3, bytecode disabled, plugin
autoload disabled and test caches disabled. For example:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=src \
  python3.11 -m unittest discover -s tests -p test_github_service_store.py -v
```

The tests use actual temporary SQLite files, close/reopen, separate connections,
competing claims, independent identity/fence/type/size/time/state changes,
retained unknowns, tombstone replay, capacity and injected ambiguous commits.
These are local database observations, not power-loss durability, worker
retirement, process-cleanup proof, model robustness or full service readiness.
Independent Source review and exact-head CI remain separate delivery evidence.

Pre-review local observations: 37 store methods and 165 existing management
cases passed on each Python 3.11.15/3.14.3 (202 each). Disabled plugin autoload
leaves the existing `asyncio_mode` configuration warning. Scoped Ruff lint,
formatting, whitespace and management contracts passed. A local Hatchling wheel
contains byte-identical module source; wheel-imported SQLite close/reopen and
the unchanged distribution-parity checker passed. No dependency was installed.

An initial genuine Claude Source review found recovery reservation and retained
outcome defects. Three new regression methods failed on that Source and passed
after operation-specific recovery and savepoint isolation. Earlier evidence is
retained separately; the corrected Source requires its own final review.
