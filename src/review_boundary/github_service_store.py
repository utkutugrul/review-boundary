"""Bounded local SQLite state, without intake, execution or publication authority."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Self, TypeVar

CONTRACT_VERSION = 1
MAX_RECORDS = 10_000
MAX_BATCH = 100
MAX_BUSY_MS = 1_000
MAX_LEASE_MS = 300_000
MAX_TIME_MS = 253_402_300_799_999
MAX_ID = 2**63 - 1
_APPLICATION_ID = 0x52424A31
_T = TypeVar("_T")
_IDENTITY_COLUMNS = (
    "repository",
    "pull_number",
    "head_sha",
    "request_digest",
    "idempotency_key",
    "run_id",
    "attempt_id",
    "artifact_id",
    "artifact_digest",
)
_KEY_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"
_OWNER_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
_ERROR_CODES = frozenset(
    {
        "invalid",
        "path",
        "schema",
        "storage",
        "closed",
        "busy",
        "capacity",
        "identity_conflict",
        "not_found",
        "state_conflict",
        "stale_lease",
        "time",
        "outcome_unknown",
    }
)


class StoreError(ValueError):
    """Fixed public category only; never include database or caller contents."""

    def __init__(self, code: str):
        if code not in _ERROR_CODES:
            code = "invalid"
        self.code = code
        super().__init__(code)


class JobState(str, Enum):
    PENDING = "pending"
    LEASED = "leased"
    COMPLETE = "complete"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ErrorCategory(str, Enum):
    WORKER_FAILED = "worker_failed"
    WORKER_UNKNOWN = "worker_unknown"
    LEASE_EXPIRED = "lease_expired"
    STORAGE_UNKNOWN = "storage_unknown"


def _integer(value: object, low: int, high: int, code: str = "invalid") -> None:
    if type(value) is not int or not low <= value <= high:
        raise StoreError(code)


def _text(value: object, pattern: str) -> None:
    if type(value) is not str or re.fullmatch(pattern, value, re.ASCII) is None:
        raise StoreError("invalid")


@dataclass(frozen=True)
class JobIdentity:
    """Exact, immutable caller claims. Digests and IDs are unverified references."""

    repository: str
    pull_number: int
    head_sha: str
    request_digest: str
    idempotency_key: str
    run_id: int | None = None
    attempt_id: int | None = None
    artifact_id: int | None = None
    artifact_digest: str | None = None

    def __post_init__(self) -> None:
        _text(self.repository, r"[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_.-]{1,100}")
        if self.repository.rsplit("/", 1)[-1] in {".", ".."}:
            raise StoreError("invalid")
        _integer(self.pull_number, 1, MAX_ID)
        _text(self.head_sha, r"[0-9a-f]{40}")
        _text(self.request_digest, r"[0-9a-f]{64}")
        _text(self.idempotency_key, _KEY_PATTERN)
        for value in (self.run_id, self.attempt_id, self.artifact_id):
            if value is not None:
                _integer(value, 1, MAX_ID)
        if self.artifact_digest is not None:
            _text(self.artifact_digest, r"[0-9a-f]{64}")


def _identity(value: object) -> None:
    if type(value) is not JobIdentity:
        raise StoreError("invalid")
    value.__post_init__()


@dataclass(frozen=True)
class Lease:
    """Local concurrency fence, not a credential or proof of worker retirement."""

    identity: JobIdentity
    owner: str
    generation: int
    expires_at_ms: int

    def __post_init__(self) -> None:
        _identity(self.identity)
        _text(self.owner, _OWNER_PATTERN)
        _integer(self.generation, 1, MAX_ID)
        _integer(self.expires_at_ms, 1, MAX_TIME_MS)


@dataclass(frozen=True)
class JobRecord:
    identity: JobIdentity
    state: JobState
    created_at_ms: int
    updated_at_ms: int
    finished_at_ms: int | None
    lease_owner: str | None
    generation: int
    lease_until_ms: int | None
    error: ErrorCategory | None
    tombstone: bool


_SCHEMA = (
    """CREATE TABLE store_meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        last_now_ms INTEGER NOT NULL CHECK(last_now_ms BETWEEN 0 AND 253402300799999)
    ) STRICT""",
    """CREATE TABLE jobs (
        repository TEXT NOT NULL CHECK(length(repository) BETWEEN 3 AND 140),
        pull_number INTEGER NOT NULL CHECK(pull_number > 0),
        head_sha TEXT NOT NULL CHECK(length(head_sha) = 40),
        request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
        idempotency_key TEXT PRIMARY KEY NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),
        run_id INTEGER CHECK(run_id > 0),
        attempt_id INTEGER CHECK(attempt_id > 0),
        artifact_id INTEGER CHECK(artifact_id > 0),
        artifact_digest TEXT CHECK(length(artifact_digest) = 64),
        state TEXT NOT NULL CHECK(state IN ('pending','leased','complete','failed','unknown')),
        created_at_ms INTEGER NOT NULL CHECK(created_at_ms BETWEEN 0 AND 253402300799999),
        updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms BETWEEN created_at_ms AND 253402300799999),
        finished_at_ms INTEGER CHECK(finished_at_ms BETWEEN created_at_ms AND updated_at_ms),
        lease_owner TEXT CHECK(length(lease_owner) BETWEEN 1 AND 64),
        generation INTEGER NOT NULL CHECK(generation >= 0),
        lease_until_ms INTEGER CHECK(lease_until_ms BETWEEN 1 AND 253402300799999),
        error TEXT CHECK(error IN ('worker_failed','worker_unknown','lease_expired','storage_unknown')),
        tombstone INTEGER NOT NULL DEFAULT 0 CHECK(tombstone IN (0,1)),
        CHECK(tombstone = 0 OR (state IN ('complete','failed') AND generation = 0
            AND lease_owner IS NULL AND lease_until_ms IS NULL)),
        CHECK((state = 'pending' AND generation = 0 AND lease_owner IS NULL
            AND lease_until_ms IS NULL AND error IS NULL AND finished_at_ms IS NULL)
          OR (state = 'leased' AND generation > 0 AND lease_owner IS NOT NULL
            AND lease_until_ms > updated_at_ms AND error IS NULL AND finished_at_ms IS NULL)
          OR (state = 'complete' AND finished_at_ms IS NOT NULL AND error IS NULL)
          OR (state = 'failed' AND finished_at_ms IS NOT NULL AND error = 'worker_failed')
          OR (state = 'unknown' AND finished_at_ms IS NULL AND error IS NOT NULL))
    ) STRICT""",
    """CREATE TRIGGER jobs_capacity BEFORE INSERT ON jobs
        WHEN (SELECT count(*) FROM jobs) >= 10000
        BEGIN SELECT RAISE(ABORT, 'capacity'); END""",
    "CREATE INDEX jobs_expiry ON jobs(state, lease_until_ms)",
    "CREATE INDEX jobs_retention ON jobs(state, tombstone, finished_at_ms)",
)


class JobStore:
    """One connection per caller/thread at an explicit trusted absolute path.

    Every operation observes caller-supplied Unix milliseconds under a persisted
    nondecreasing clock. No method starts, retries, retires or authenticates work.
    """

    def __init__(self, path: Path, *, busy_timeout_ms: int = MAX_BUSY_MS):
        _integer(busy_timeout_ms, 0, MAX_BUSY_MS)
        if not isinstance(path, Path) or not path.is_absolute():
            raise StoreError("path")
        try:
            if (
                not path.parent.is_dir()
                or path.is_symlink()
                or (path.exists() and not path.is_file())
            ):
                raise StoreError("path")
        except OSError:
            raise StoreError("path") from None
        self._closed = False
        self._quarantined = False
        try:
            self._db = sqlite3.connect(
                str(path),
                timeout=busy_timeout_ms / 1000,
                isolation_level=None,
            )
            self._db.row_factory = sqlite3.Row
            self._db.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
            self._db.execute("PRAGMA trusted_schema = OFF")
            self._db.execute("PRAGMA synchronous = FULL")
            self._db.execute("BEGIN IMMEDIATE")
            version = self._db.execute("PRAGMA user_version").fetchone()[0]
            app_id = self._db.execute("PRAGMA application_id").fetchone()[0]
            if version == 0 and app_id == 0:
                if self._db.execute(
                    "SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' LIMIT 1"
                ).fetchone():
                    raise StoreError("schema")
                for statement in _SCHEMA:
                    self._db.execute(statement)
                self._db.execute("INSERT INTO store_meta VALUES (1, 0)")
                self._db.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
                self._db.execute(f"PRAGMA user_version = {CONTRACT_VERSION}")
            elif version != CONTRACT_VERSION or app_id != _APPLICATION_ID:
                raise StoreError("schema")
            meta = self._db.execute("SELECT singleton, last_now_ms FROM store_meta").fetchall()
            if len(meta) != 1 or meta[0][0] != 1:
                raise StoreError("schema")
            _integer(meta[0][1], 0, MAX_TIME_MS, "schema")
            if self._db.execute("SELECT count(*) FROM jobs").fetchone()[0] > MAX_RECORDS:
                raise StoreError("schema")
            self._db.commit()
        except BaseException as error:
            if hasattr(self, "_db"):
                self._db.close()
            self._closed = True
            if isinstance(error, sqlite3.Error):
                raise StoreError(self._sqlite_code(error)) from None
            raise

    @staticmethod
    def _sqlite_code(error: sqlite3.Error) -> str:
        code = getattr(error, "sqlite_errorcode", 0) or 0
        return "busy" if code & 0xFF in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} else "storage"

    def close(self) -> None:
        if not self._closed:
            self._db.close()
            self._closed = True

    def __enter__(self) -> Self:
        self._available()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _available(self) -> None:
        if self._closed:
            raise StoreError("closed")
        if self._quarantined:
            raise StoreError("outcome_unknown")

    def _commit(self) -> None:
        self._db.commit()

    def _recover_unknown(
        self,
        identity: JobIdentity | None,
        now_ms: int,
        *,
        reserve_identity: bool,
        terminal_write: bool,
    ) -> None:
        # Best effort only. An unavailable disk cannot promise a durable marker.
        # Keep this connection quarantined even if the recovery transaction succeeds.
        self._quarantined = True
        try:
            self._db.rollback()
            self._db.execute("BEGIN IMMEDIATE")
            last = self._db.execute("SELECT last_now_ms FROM store_meta").fetchone()[0]
            now_ms = max(last, now_ms)
            # Preserve global fencing even if an intake reservation cannot fit.
            self._db.execute(
                """UPDATE jobs SET state = 'unknown', error = 'storage_unknown',
                updated_at_ms = ?, finished_at_ms = NULL WHERE state = 'leased'""",
                (now_ms,),
            )
            self._db.execute("UPDATE store_meta SET last_now_ms = ?", (now_ms,))
            if identity is not None:
                row = self._db.execute(
                    "SELECT * FROM jobs WHERE idempotency_key = ?",
                    (identity.idempotency_key,),
                ).fetchone()
                record = self._record(row) if row is not None else None
                if record is None and reserve_identity:
                    self._db.execute("SAVEPOINT intake_reservation")
                    try:
                        self._insert(
                            identity, now_ms, JobState.UNKNOWN, ErrorCategory.STORAGE_UNKNOWN
                        )
                    except sqlite3.IntegrityError:
                        self._db.execute("ROLLBACK TO intake_reservation")
                    self._db.execute("RELEASE intake_reservation")
                elif (
                    record is not None
                    and record.identity == identity
                    and (record.state is JobState.PENDING or terminal_write)
                ):
                    self._db.execute(
                        """UPDATE jobs SET state = 'unknown', error = 'storage_unknown',
                        updated_at_ms = ?, finished_at_ms = NULL, tombstone = 0
                        WHERE idempotency_key = ?""",
                        (now_ms, identity.idempotency_key),
                    )
            self._db.commit()
        except (sqlite3.Error, StoreError):
            try:
                self._db.rollback()
            except sqlite3.Error:
                pass

    def _transaction(
        self,
        now_ms: int,
        action: Callable[[], _T],
        identity: JobIdentity | None = None,
        *,
        reserve_identity: bool = False,
        finishing: bool = False,
    ) -> _T:
        self._available()
        _integer(now_ms, 0, MAX_TIME_MS, "time")
        try:
            self._db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            raise StoreError(self._sqlite_code(error)) from None
        terminal_write = False
        try:
            last = self._db.execute("SELECT last_now_ms FROM store_meta").fetchone()[0]
            if now_ms < last:
                self._db.rollback()
                raise StoreError("time")
            self._db.execute(
                """UPDATE jobs SET state = 'unknown', error = 'lease_expired',
                updated_at_ms = ?, finished_at_ms = NULL
                WHERE state = 'leased' AND lease_until_ms <= ?""",
                (now_ms, now_ms),
            )
            self._db.execute("UPDATE store_meta SET last_now_ms = ?", (now_ms,))
            refusal = None
            try:
                result = action()
                terminal_write = finishing
            except StoreError as error:
                # Persist expiry/time observation even when the requested write is refused.
                refusal = error
            self._commit()
        except StoreError:
            raise
        except (sqlite3.Error, OSError):
            self._recover_unknown(
                identity, now_ms, reserve_identity=reserve_identity, terminal_write=terminal_write
            )
            raise StoreError("outcome_unknown") from None
        except BaseException:
            self._recover_unknown(
                identity, now_ms, reserve_identity=reserve_identity, terminal_write=terminal_write
            )
            raise
        if refusal is not None:
            raise refusal
        return result

    @staticmethod
    def _record(row: sqlite3.Row) -> JobRecord:
        try:
            return JobRecord(
                JobIdentity(*(row[name] for name in _IDENTITY_COLUMNS)),
                JobState(row["state"]),
                row["created_at_ms"],
                row["updated_at_ms"],
                row["finished_at_ms"],
                row["lease_owner"],
                row["generation"],
                row["lease_until_ms"],
                ErrorCategory(row["error"]) if row["error"] is not None else None,
                bool(row["tombstone"]),
            )
        except (ValueError, KeyError, IndexError):
            raise StoreError("storage") from None

    def _find(self, identity: JobIdentity) -> JobRecord:
        row = self._db.execute(
            "SELECT * FROM jobs WHERE idempotency_key = ?",
            (identity.idempotency_key,),
        ).fetchone()
        if row is None:
            raise StoreError("not_found")
        record = self._record(row)
        if record.identity != identity:
            raise StoreError("identity_conflict")
        return record

    def _insert(
        self,
        identity: JobIdentity,
        now_ms: int,
        state: JobState = JobState.PENDING,
        error: ErrorCategory | None = None,
    ) -> None:
        values = tuple(getattr(identity, name) for name in _IDENTITY_COLUMNS)
        self._db.execute(
            """INSERT INTO jobs (repository, pull_number, head_sha, request_digest,
            idempotency_key, run_id, attempt_id, artifact_id, artifact_digest,
            state, created_at_ms, updated_at_ms, generation, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)""",
            (*values, state.value, now_ms, now_ms, error.value if error is not None else None),
        )

    def enqueue(self, identity: JobIdentity, *, now_ms: int) -> JobRecord:
        _identity(identity)

        def action() -> JobRecord:
            try:
                return self._find(identity)
            except StoreError as error:
                if error.code != "not_found":
                    raise
            if self._db.execute("SELECT count(*) FROM jobs").fetchone()[0] >= MAX_RECORDS:
                raise StoreError("capacity")
            self._insert(identity, now_ms)
            return self._find(identity)

        return self._transaction(now_ms, action, identity, reserve_identity=True)

    def get(self, identity: JobIdentity, *, now_ms: int) -> JobRecord:
        _identity(identity)
        return self._transaction(now_ms, lambda: self._find(identity), identity)

    @staticmethod
    def _deadline(now_ms: int, lease_ms: int) -> int:
        _integer(now_ms, 0, MAX_TIME_MS, "time")
        _integer(lease_ms, 1, MAX_LEASE_MS, "time")
        _integer(now_ms + lease_ms, 1, MAX_TIME_MS, "time")
        return now_ms + lease_ms

    def claim(
        self,
        identity: JobIdentity,
        owner: str,
        *,
        now_ms: int,
        lease_ms: int,
    ) -> Lease:
        _identity(identity)
        _text(owner, _OWNER_PATTERN)
        deadline = self._deadline(now_ms, lease_ms)

        def action() -> Lease:
            record = self._find(identity)
            if record.state is not JobState.PENDING:
                raise StoreError("state_conflict")
            self._db.execute(
                """UPDATE jobs SET state = 'leased', lease_owner = ?, generation = 1,
                lease_until_ms = ?, updated_at_ms = ? WHERE idempotency_key = ?""",
                (owner, deadline, now_ms, identity.idempotency_key),
            )
            return Lease(identity, owner, 1, deadline)

        return self._transaction(now_ms, action, identity)

    def _fenced(self, lease: Lease) -> JobRecord:
        record = self._find(lease.identity)
        if (
            record.state is not JobState.LEASED
            or record.lease_owner != lease.owner
            or record.generation != lease.generation
            or record.lease_until_ms != lease.expires_at_ms
        ):
            raise StoreError("stale_lease")
        return record

    @staticmethod
    def _lease(lease: Lease) -> None:
        if type(lease) is not Lease:
            raise StoreError("invalid")
        lease.__post_init__()

    def renew(self, lease: Lease, *, now_ms: int, lease_ms: int) -> Lease:
        self._lease(lease)
        deadline = self._deadline(now_ms, lease_ms)

        def action() -> Lease:
            self._fenced(lease)
            if deadline <= lease.expires_at_ms or lease.generation == MAX_ID:
                raise StoreError("time" if deadline <= lease.expires_at_ms else "state_conflict")
            generation = lease.generation + 1
            self._db.execute(
                """UPDATE jobs SET generation = ?, lease_until_ms = ?, updated_at_ms = ?
                WHERE idempotency_key = ?""",
                (generation, deadline, now_ms, lease.identity.idempotency_key),
            )
            return Lease(lease.identity, lease.owner, generation, deadline)

        return self._transaction(now_ms, action, lease.identity)

    def finish(self, lease: Lease, outcome: JobState, *, now_ms: int) -> JobRecord:
        self._lease(lease)
        if type(outcome) is not JobState or outcome not in {
            JobState.COMPLETE,
            JobState.FAILED,
            JobState.UNKNOWN,
        }:
            raise StoreError("invalid")

        def action() -> JobRecord:
            self._fenced(lease)
            error = {
                JobState.COMPLETE: None,
                JobState.FAILED: ErrorCategory.WORKER_FAILED.value,
                JobState.UNKNOWN: ErrorCategory.WORKER_UNKNOWN.value,
            }[outcome]
            self._db.execute(
                """UPDATE jobs SET state = ?, updated_at_ms = ?, finished_at_ms = ?, error = ?
                WHERE idempotency_key = ?""",
                (
                    outcome.value,
                    now_ms,
                    None if outcome is JobState.UNKNOWN else now_ms,
                    error,
                    lease.identity.idempotency_key,
                ),
            )
            return self._find(lease.identity)

        return self._transaction(now_ms, action, lease.identity, finishing=True)

    def list_jobs(
        self,
        *,
        now_ms: int,
        state: JobState | None = None,
        after_key: str | None = None,
        limit: int = MAX_BATCH,
    ) -> tuple[JobRecord, ...]:
        _integer(limit, 1, MAX_BATCH)
        if state is not None and type(state) is not JobState:
            raise StoreError("invalid")
        if after_key is not None:
            _text(after_key, _KEY_PATTERN)

        def action() -> tuple[JobRecord, ...]:
            rows = self._db.execute(
                """SELECT * FROM jobs WHERE (? IS NULL OR state = ?)
                AND (? IS NULL OR idempotency_key > ?) ORDER BY idempotency_key LIMIT ?""",
                (
                    state.value if state is not None else None,
                    state.value if state is not None else None,
                    after_key,
                    after_key,
                    limit,
                ),
            ).fetchall()
            return tuple(self._record(row) for row in rows)

        return self._transaction(now_ms, action)

    def prune(self, *, now_ms: int, before_ms: int, limit: int = MAX_BATCH) -> int:
        _integer(limit, 1, MAX_BATCH)
        _integer(now_ms, 0, MAX_TIME_MS, "time")
        _integer(before_ms, 0, now_ms, "time")

        def action() -> int:
            cursor = self._db.execute(
                """UPDATE jobs SET tombstone = 1, generation = 0, lease_owner = NULL,
                lease_until_ms = NULL, updated_at_ms = ? WHERE idempotency_key IN (
                    SELECT idempotency_key FROM jobs WHERE state IN ('complete','failed')
                    AND tombstone = 0 AND finished_at_ms < ?
                    ORDER BY finished_at_ms, idempotency_key LIMIT ?
                )""",
                (now_ms, before_ms, limit),
            )
            return cursor.rowcount

        return self._transaction(now_ms, action)
