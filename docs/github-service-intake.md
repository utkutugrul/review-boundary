# Authenticated local GitHub intake

The stdlib-only [module](../src/review_boundary/github_service_intake.py) retains
authenticated local intents in a dedicated intake namespace. A `202 retained`
response means local retention only. It grants no execution, lease, evaluation,
publication, artifact provenance or budget authority. Full SERVICE17 still needs
its worker, staged provenance/reconciliation and full integration after12/15/36.
The unchanged [store contract](github-service-store.md) remains separate.

Default invocation and `--help` only show help. `validate` checks explicit argument
syntax without reading a secret, opening a database, binding or using credentials.
Serving requires an explicit command, an absolute trusted secret-file path, a
dedicated absolute intake-directory path, repository name:ID pairs and sender IDs:

```sh
python -m review_boundary.github_service_intake validate \
  --secret-file /operator/secret --intake-directory /operator/intake \
  --repository example/repo:101 --sender-id 201 --port 0

python -m review_boundary.github_service_intake serve \
  --secret-file /operator/secret --intake-directory /operator/intake \
  --repository example/repo:101 --sender-id 201 --port 8765
```

These synthetic paths and IDs are examples, not deployment authorization. This
child does not activate a service or GitHub App. The secret must be an explicit
regular nonsymlink file containing32..128 raw bytes. Newlines remain significant.
There is no default secret or ambient credential lookup. Repeat `--repository`
and `--sender-id` for additional trusted claims, at most64 pairs and256 senders.
Repository names must already be canonical lowercase ASCII; IDs are integers
1..2^63-1. Names and repository IDs must each be unique. Allowlists are trusted
configuration, not payload claims. No shared console command is added.

## Frozen protocol

Only IPv4 `127.0.0.1` is bound. Port0 selects an OS-assigned proof port; explicit
configured ports are1..65535. The Python API exposes the actual bound port for
owned loopback controls. This implementation requires POSIX file descriptors,
`flock`, `O_NOFOLLOW` and directory `fsync` on a trusted local filesystem.

| Limit | Contract |
| --- | --- |
| Request | One `POST /github/intake HTTP/1.0` or `HTTP/1.1` per connection, CRLF only |
| Request line |4096 bytes including CRLF |
| Headers |16384 bytes after the request line, including final empty CRLF;64 fields |
| Body |262144 exact raw bytes |
| Concurrency |8 admitted connections; excess connections receive `busy` and close |
| Read deadline |3.0 seconds of total loop monotonic time from connection handling, across headers and body |
| Response | At most1024 application bytes including HTTP framing, then connection close |

One decimal Content-Length is required. Leading zeroes are permitted. Content-Type
must be `application/json`, optionally `charset=utf-8`, with ASCII case-insensitive
media type/charset matching. Duplicate names are refused case-insensitively,
including signature and Content-Length. Folded headers, Transfer-Encoding,
Content-Encoding, Expect, query strings, alternate routes and unsupported versions
are refused before enqueue. Extra bytes already delivered with the framed request
are refused as pipelining. After a complete request the connection closes and no
later request is processed. There is no keep-alive or pipelined-request execution.

The absolute deadline is checked on received data and before enqueue, alongside
one absolute timer. A slow drip cannot refresh it. SQLite can synchronously delay
the event loop; expired reads still refuse before enqueue when handling resumes.
These are application bounds, not hard kernel scheduling, memory, filesystem or
process-retirement guarantees. A peer continuing an oversized upload may observe
a connection reset instead of a readable rejection response.

`X-Hub-Signature-256` must be exactly `sha256=` plus64 lowercase hexadecimal digits.
Constant-time comparison authenticates the exact body before any JSON parser is
called. Only `X-GitHub-Event: pull_request` is accepted. Delivery IDs are ignored
transport metadata and cannot authorize identity or deduplication.

The unchanged bounded JSON parser rejects duplicate keys, nonfinite numbers and
depth above64. Explicit UTF-8 decoding also refuses UTF-16/32 and malformed UTF-8.
Only actions opened/reopened/synchronize for an open PR are admitted. Exact typed
repository, sender, PR number, head SHA and base-repository claims must match the
trusted policy. Booleans never serve as integers. Other bounded fields, including
Unicode and execution-shaped fields, are ignored and never become references.
No raw headers, body, delivery ID, secret, private key or error content is retained.

## Identity and durable lifecycle

The identity contains validated repository/PR/head and SHA256(raw_body). Its key is
`intake-v1:` plus SHA256 of ASCII `intake-v1`, one NUL byte, the32 digest bytes and32 canonical
policy-digest bytes. The policy digest hashes sorted repository pairs and sender
IDs in compact, sorted-key ASCII JSON with version `intake-v1`. Changing delivery
metadata preserves identity. Changing authenticated content or policy changes the
key. All four run/attempt/artifact reference fields remain permanently `None`.

Only unchanged `JobStore.enqueue` is called for retention and replay, with the
current Unix milliseconds and busy timeout1000ms. Capacity remains10000 lifetime
rows including tombstones. No SQL, claim, renew, finish, pruning, eviction, repair,
rotation, subprocess, GitHub API, provider, publisher or budget path is added.
Known pre-acquisition busy and committed capacity/identity refusals stay distinct
from `outcome_unknown`. A lost response after a known commit may be reconciled by
the identical authenticated request on another connection without adding a row.

The intake directory must be new on first use, owned by the operator and mode0700.
An existing directory needs its exact private intake-purpose marker and regular
database; an unmarked directory or execution database is never adopted. Ancestors
must be directories without symlinks. Checks inspect only named ancestors and
fixed filenames, never scan directories. The operator must preserve exclusive
trusted path custody; this does not contain a hostile same-user filesystem owner.

Fixed names are `intents.sqlite3`, `intake-v1.json`, `intake-v1.lock`,
`intake-v1.active` and the exclusive update staging path `intake-v1.next`.
Private regular marker/lock/session files are mode0600. A nonblocking exclusive
lock keeps one cooperative session. The durable active session fence and active
purpose marker precede SQLite initialization and every retained intent.

Any ambiguous database/marker/ownership failure poisons the session and stops
intake. A best-effort unknown marker can fail; the previously durable active
session fence still refuses restart. No automatic reopen or retry follows.
Unexpected leased, unknown, terminal or tombstone replay requires reconciliation,
preserving its retained identity and granting no fresh execution authority.
The unchanged store can observe lease expiry while enqueue checks an existing
record; expiry remains unknown and never establishes worker retirement.

Clean shutdown first closes sockets/protocols and SQLite, then durably writes a
clean marker and finally removes the session fence. Fence deletion deliberately
has no subsequent directory fsync: crash recovery can conservatively retain the
old fence and require reconciliation. Failed clean-marker publication keeps the
fence even if a clean marker became visible and a later unknown update failed.
Unclean sessions or staging files require explicit operator reconciliation. There
is no reconcile, reset or override switch in this module. Do not delete markers
or edit SQL to manufacture admission. Clean close never certifies an unresolved
write, and socket/expiry observations never prove external worker retirement.

Responses contain only a fixed `status` category: retained, malformed,
unauthenticated, forbidden, deadline, identity_conflict, too_large, invalid_payload,
busy, capacity, reconciliation_required, outcome_unknown, configuration_refused
or closed. Internal storage uncertainty remains explicit and stops the listener.

## Validation and delivery boundaries

[Focused controls](../tests/test_github_service_intake.py) use synthetic secrets,
owned temporary SQLite/marker files and actual bounded loopback requests. They
exercise authentication before parsing/enqueue, ignored Unicode, digest/policy
identity separation, close/reopen replay, lost response after commit, malformed
framing, absolute slow drips, lifetime capacity including tombstones, real lock
contention, marker failure, unclean restart and physical socket/protocol closure.
Execution transitions and SQL population in tests are synthetic owned fixtures,
never receiver call paths. Static callable-path checks supplement actual runtime
observations; test counts are not evidence of model robustness or power-loss tests.

```sh
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  python3.11 -B -m unittest discover -s tests -p test_github_service_intake.py -v
```

Run the same controls on Python3.14.3, the unchanged store/parser compatibility
checks, scoped Ruff lint/format and repository management checks. Installed module
checks need fresh task-owned build/install environments and byte identity with
Source. They establish bounded keyless behavior, not shared-console, external
deployment, model results or full SERVICE17 readiness. Final immutable Source,
actual evidence, genuine independent Claude review and exact-head CI remain
separate requirements. Material-risk acceptance belongs to the human owner.

Pre-review observations: Python3.11.15 and3.14.3 each passed36 intake controls,
39 unchanged store controls and7 direct unchanged-parser compatibility checks.
All75 unittest methods passed again from each fresh wheel-installed environment;
no tests were skipped. Installed intake/store/parser bytes matched Source.
Installed `python -m` default/help/validation passed on both runtimes without
creating their nonexistent configured secret or intake paths. The real-loopback
controls observed EOF or explicit peer reset, closed socket file descriptors,
completed protocol futures, cancelled timers, an absent listener and no extra
asyncio tasks after shutdown. These observations do not establish external worker
retirement.

An initial build with an empty offline cache could not resolve Hatchling. The
successful build used task-owned copies of already cached Hatchling1.33.0 and its
public dependencies, with no download and fresh task-owned build/install
environments. The unchanged wheel/sdist parity checker passed. Earlier protocol
test failures and the corrected close/category defects are preserved in the task
worklog; independent review and exact-head CI are reported with the PR.
