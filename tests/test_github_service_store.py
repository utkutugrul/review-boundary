"""Real temporary SQLite observations, not process cleanup or model evidence."""

import sqlite3
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from review_boundary.github_service_store import (
    MAX_BATCH,
    MAX_BUSY_MS,
    MAX_ID,
    MAX_LEASE_MS,
    MAX_RECORDS,
    MAX_TIME_MS,
    ErrorCategory,
    JobIdentity,
    JobState,
    JobStore,
    Lease,
    StoreError,
)


def identity(key="request-1", **changes):
    return replace(
        JobIdentity("example/repository", 42, "a" * 40, "b" * 64, key, 101, 2, 303, "c" * 64),
        **changes,
    )


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.scratch = TemporaryDirectory(prefix="job-store-")
        self.addCleanup(self.scratch.cleanup)
        self.path = Path(self.scratch.name) / "jobs.sqlite"
        self.store = JobStore(self.path)
        self.addCleanup(self.store.close)
        self.request = identity()

    def error(self, code, operation, *args, **kwargs):
        with self.assertRaises(StoreError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)
        return caught.exception

    def leased(self, *, key="request-1", now=100, duration=100):
        request = identity(key)
        self.store.enqueue(request, now_ms=now)
        return self.store.claim(request, "worker-a", now_ms=now, lease_ms=duration)

    def test_persistence_replay_and_exact_references_across_reopen(self):
        original = self.store.enqueue(self.request, now_ms=100)
        self.assertEqual(original.identity, self.request)
        self.assertEqual(original.state, JobState.PENDING)
        self.assertIsNone(original.error)
        self.assertEqual(original.generation, 0)
        self.store.close()
        with JobStore(self.path) as reopened:
            self.assertEqual(reopened.enqueue(self.request, now_ms=101), original)
            self.assertEqual(reopened.get(self.request, now_ms=102), original)
            self.assertEqual(len(reopened.list_jobs(now_ms=102)), 1)
        with sqlite3.connect(self.path) as raw:
            row = raw.execute(
                "SELECT repository, pull_number, head_sha, request_digest, idempotency_key, "
                "run_id, attempt_id, artifact_id, artifact_digest, state FROM jobs"
            ).fetchone()
            self.assertEqual(
                row,
                (
                    "example/repository",
                    42,
                    "a" * 40,
                    "b" * 64,
                    "request-1",
                    101,
                    2,
                    303,
                    "c" * 64,
                    "pending",
                ),
            )

    def test_each_changed_identity_field_conflicts_before_and_after_tombstone(self):
        changes = {
            "repository": "different/repository",
            "pull_number": 43,
            "head_sha": "d" * 40,
            "request_digest": "e" * 64,
            "run_id": 102,
            "attempt_id": 3,
            "artifact_id": 304,
            "artifact_digest": "f" * 64,
        }
        lease = self.leased()
        for compact in (False, True):
            if compact:
                self.store.finish(lease, JobState.COMPLETE, now_ms=102)
                self.assertEqual(self.store.prune(now_ms=102, before_ms=102), 0)
                self.assertEqual(self.store.prune(now_ms=103, before_ms=103), 1)
            now = 103 if compact else 102
            for field, value in changes.items():
                with self.subTest(tombstone=compact, field=field):
                    changed = replace(self.request, **{field: value})
                    self.error("identity_conflict", self.store.enqueue, changed, now_ms=now)
                    self.error("identity_conflict", self.store.get, changed, now_ms=now)
        self.assertTrue(self.store.enqueue(self.request, now_ms=103).tombstone)

    def test_new_key_is_a_distinct_request_and_namespace_is_database_wide(self):
        first = self.store.enqueue(self.request, now_ms=100)
        second = self.store.enqueue(identity("another-key"), now_ms=100)
        self.assertNotEqual(first.identity, second.identity)
        self.assertEqual(len(self.store.list_jobs(now_ms=100)), 2)
        self.error(
            "identity_conflict",
            self.store.enqueue,
            replace(self.request, repository="another/repo"),
            now_ms=100,
        )

    def test_identity_types_formats_and_sizes_are_strict_without_coercion(self):
        invalid = {
            "repository": [
                None,
                1,
                "EXAMPLE/repo",
                "a/..",
                "a/.",
                "a/",
                "a/b/c",
                "a/" + "r" * 101,
                "a" * 40 + "/r",
                "a/r\n",
                "a/ré",
            ],
            "pull_number": [True, False, "42", 42.0, None, 0, -1, MAX_ID + 1],
            "head_sha": [None, 1, "A" * 40, "a" * 39, "a" * 41, "g" * 40, "a" * 40 + "\n"],
            "request_digest": [False, 1, "b" * 63, "b" * 65, "B" * 64, "z" * 64],
            "idempotency_key": [None, 1, "", "k" * 129, "with space", "key\n", "κ", "'"],
            "run_id": [True, "101", 101.0, 0, -1, MAX_ID + 1],
            "attempt_id": [True, "2", 2.0, 0, -1, MAX_ID + 1],
            "artifact_id": [True, "303", 303.0, 0, -1, MAX_ID + 1],
            "artifact_digest": [False, "c" * 63, "c" * 65, "C" * 64, "z" * 64],
        }
        for field, values in invalid.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.error("invalid", identity, **{field: value})
        largest = JobIdentity(
            "a" * 39 + "/" + "r" * 100,
            MAX_ID,
            "a" * 40,
            "b" * 64,
            "K" * 128,
            MAX_ID,
            MAX_ID,
            MAX_ID,
            "c" * 64,
        )
        self.assertEqual(self.store.enqueue(largest, now_ms=100).identity, largest)
        optional = replace(
            self.request, run_id=None, attempt_id=None, artifact_id=None, artifact_digest=None
        )
        self.assertEqual(self.store.enqueue(optional, now_ms=100).identity, optional)

    def test_public_methods_revalidate_objects_and_do_not_accept_dicts(self):
        for value in (None, {}, self.request.__dict__, "request-1", 42):
            with self.subTest(value=value):
                self.error("invalid", self.store.enqueue, value, now_ms=100)
                self.error("invalid", self.store.get, value, now_ms=100)
        altered = identity()
        object.__setattr__(altered, "pull_number", True)
        self.error("invalid", self.store.enqueue, altered, now_ms=100)
        self.assertEqual(self.store.list_jobs(now_ms=100), ())

    def test_success_failure_and_unknown_are_distinct_local_outcomes(self):
        for outcome, error in (
            (JobState.COMPLETE, None),
            (JobState.FAILED, ErrorCategory.WORKER_FAILED),
            (JobState.UNKNOWN, ErrorCategory.WORKER_UNKNOWN),
        ):
            with self.subTest(outcome=outcome):
                lease = self.leased(key=outcome.value, now=101)
                result = self.store.finish(lease, outcome, now_ms=101)
                self.assertEqual(result.state, outcome)
                self.assertEqual(result.error, error)
                self.assertEqual(
                    result.finished_at_ms, None if outcome is JobState.UNKNOWN else 101
                )
                self.assertEqual(self.store.enqueue(lease.identity, now_ms=101), result)
                self.error("stale_lease", self.store.finish, lease, JobState.COMPLETE, now_ms=101)
                self.error(
                    "state_conflict",
                    self.store.claim,
                    lease.identity,
                    "worker-b",
                    now_ms=101,
                    lease_ms=100,
                )
        self.store.close()
        with JobStore(self.path) as reopened:
            self.assertEqual(
                {r.state for r in reopened.list_jobs(now_ms=102)},
                {JobState.COMPLETE, JobState.FAILED, JobState.UNKNOWN},
            )

    def test_finish_requires_real_lease_and_terminal_enum(self):
        lease = self.leased()
        for bad in (None, {}, "lease", self.store.get(self.request, now_ms=100)):
            self.error("invalid", self.store.finish, bad, JobState.COMPLETE, now_ms=100)
        for bad in (
            "complete",
            "failed",
            "unknown",
            "passed",
            None,
            True,
            JobState.PENDING,
            JobState.LEASED,
        ):
            with self.subTest(outcome=bad):
                self.error("invalid", self.store.finish, lease, bad, now_ms=100)
        self.assertEqual(self.store.get(self.request, now_ms=100).state, JobState.LEASED)
        self.assertEqual(
            self.store.finish(lease, JobState.COMPLETE, now_ms=100).state, JobState.COMPLETE
        )

    def test_independent_connections_see_claim_renew_and_final_fence(self):
        self.store.enqueue(self.request, now_ms=100)
        with JobStore(self.path) as other:
            first = self.store.claim(self.request, "worker-a", now_ms=101, lease_ms=100)
            self.assertEqual(other.get(self.request, now_ms=101).lease_owner, "worker-a")
            self.error(
                "state_conflict", other.claim, self.request, "worker-b", now_ms=101, lease_ms=100
            )
            current = other.renew(first, now_ms=102, lease_ms=100)
            self.assertEqual(current.generation, 2)
            self.error("stale_lease", self.store.finish, first, JobState.COMPLETE, now_ms=102)
            result = self.store.finish(current, JobState.COMPLETE, now_ms=103)
            self.assertEqual(other.get(self.request, now_ms=103), result)

    def test_simultaneous_claims_have_one_winner_with_two_connections(self):
        self.store.enqueue(self.request, now_ms=100)
        barrier = threading.Barrier(2, timeout=5)

        def compete(owner):
            with JobStore(self.path) as connection:
                barrier.wait()
                try:
                    return connection.claim(self.request, owner, now_ms=101, lease_ms=100)
                except StoreError as error:
                    return error.code

        with ThreadPoolExecutor(max_workers=2) as threads:
            futures = [threads.submit(compete, owner) for owner in ("worker-a", "worker-b")]
            results = [future.result(timeout=10) for future in futures]
        winners = [result for result in results if isinstance(result, Lease)]
        self.assertEqual(len(winners), 1)
        self.assertEqual([r for r in results if isinstance(r, str)], ["state_conflict"])
        self.assertEqual(self.store.get(self.request, now_ms=101).lease_owner, winners[0].owner)

    def test_each_fence_component_changes_independently(self):
        lease = self.leased()
        lease = self.store.renew(lease, now_ms=101, lease_ms=100)
        changed = (
            replace(lease, owner="worker-b"),
            replace(lease, generation=1),
            replace(lease, generation=3),
            replace(lease, expires_at_ms=202),
        )
        for forged in changed:
            with self.subTest(fence=forged):
                self.error("stale_lease", self.store.finish, forged, JobState.COMPLETE, now_ms=101)
                self.error("stale_lease", self.store.renew, forged, now_ms=101, lease_ms=200)
        for field, value in {
            "repository": "other/repo",
            "pull_number": 43,
            "head_sha": "d" * 40,
            "request_digest": "e" * 64,
            "run_id": 102,
            "attempt_id": 3,
            "artifact_id": 304,
            "artifact_digest": "f" * 64,
        }.items():
            with self.subTest(binding=field):
                forged = replace(lease, identity=replace(self.request, **{field: value}))
                self.error(
                    "identity_conflict", self.store.finish, forged, JobState.COMPLETE, now_ms=101
                )
        missing = replace(lease, identity=identity("missing"))
        self.error("not_found", self.store.finish, missing, JobState.COMPLETE, now_ms=101)
        self.assertEqual(
            self.store.finish(lease, JobState.COMPLETE, now_ms=101).state, JobState.COMPLETE
        )

    def test_lease_owner_generation_and_deadline_types_and_sizes(self):
        lease = self.leased()
        for field, values in {
            "owner": [None, True, "", "w" * 65, "worker with spaces", "worker\n", "é"],
            "generation": [None, True, "1", 1.0, 0, -1, MAX_ID + 1],
            "expires_at_ms": [None, True, "200", 200.0, 0, -1, MAX_TIME_MS + 1],
            "identity": [None, {}, "key"],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    self.error("invalid", replace, lease, **{field: value})
        mutated = replace(lease)
        object.__setattr__(mutated, "generation", True)
        self.error("invalid", self.store.finish, mutated, JobState.COMPLETE, now_ms=100)
        self.error("invalid", self.store.claim, self.request, "w" * 65, now_ms=100, lease_ms=100)

    def test_expiry_is_inclusive_persisted_unknown_and_never_reclaimed(self):
        lease = self.leased()
        self.assertEqual(self.store.get(self.request, now_ms=199).state, JobState.LEASED)
        self.error("stale_lease", self.store.finish, lease, JobState.COMPLETE, now_ms=200)
        record = self.store.get(self.request, now_ms=200)
        self.assertEqual(record.state, JobState.UNKNOWN)
        self.assertEqual(record.error, ErrorCategory.LEASE_EXPIRED)
        self.assertIsNone(record.finished_at_ms)
        self.store.close()
        with JobStore(self.path) as reopened:
            self.assertEqual(reopened.enqueue(self.request, now_ms=201), record)
            self.error(
                "state_conflict", reopened.claim, self.request, "worker-b", now_ms=201, lease_ms=100
            )
            self.assertEqual(reopened.prune(now_ms=202, before_ms=202), 0)

    def test_renew_at_expiry_and_competing_claim_record_unknown_before_refusal(self):
        lease = self.leased()
        self.error("stale_lease", self.store.renew, lease, now_ms=200, lease_ms=100)
        self.assertEqual(self.store.get(self.request, now_ms=200).state, JobState.UNKNOWN)
        second = self.leased(key="second", now=200)
        self.error(
            "state_conflict",
            self.store.claim,
            second.identity,
            "worker-b",
            now_ms=300,
            lease_ms=100,
        )
        self.assertEqual(self.store.get(second.identity, now_ms=300).state, JobState.UNKNOWN)

    def test_completion_one_millisecond_before_expiry_is_known(self):
        lease = self.leased()
        completed = self.store.finish(lease, JobState.COMPLETE, now_ms=199)
        self.assertEqual(self.store.get(self.request, now_ms=200), completed)

    def test_list_observes_expiry_before_filter_and_pagination(self):
        self.leased(key="a")
        self.store.enqueue(identity("b"), now_ms=100)
        self.assertEqual(self.store.list_jobs(now_ms=200, state=JobState.LEASED), ())
        rows = self.store.list_jobs(now_ms=200, state=JobState.UNKNOWN)
        self.assertEqual([r.identity.idempotency_key for r in rows], ["a"])
        self.assertEqual(rows[0].error, ErrorCategory.LEASE_EXPIRED)

    def test_persisted_global_clock_refuses_backdating_on_other_connection_and_reopen(self):
        lease = self.leased()
        with JobStore(self.path) as other:
            other.get(self.request, now_ms=150)
            self.error("time", self.store.finish, lease, JobState.COMPLETE, now_ms=149)
            self.assertEqual(other.get(self.request, now_ms=150).state, JobState.LEASED)
        self.store.close()
        with JobStore(self.path) as reopened:
            self.error("time", reopened.get, self.request, now_ms=149)
            self.assertEqual(
                reopened.finish(lease, JobState.COMPLETE, now_ms=150).state, JobState.COMPLETE
            )

    def test_invalid_times_and_durations_never_write_and_upper_boundary_is_valid(self):
        self.store.enqueue(self.request, now_ms=0)
        for bad in (None, True, "100", 100.0, float("nan"), float("inf"), -1, MAX_TIME_MS + 1):
            with self.subTest(time=bad):
                self.error("time", self.store.get, self.request, now_ms=bad)
                self.error("time", self.store.claim, self.request, "worker", now_ms=bad, lease_ms=1)
        for bad in (None, True, "1", 1.0, 0, -1, MAX_LEASE_MS + 1):
            with self.subTest(duration=bad):
                self.error("time", self.store.claim, self.request, "worker", now_ms=0, lease_ms=bad)
        self.error("time", self.store.claim, self.request, "worker", now_ms=MAX_TIME_MS, lease_ms=1)
        lease = self.store.claim(self.request, "w" * 64, now_ms=MAX_TIME_MS - 1, lease_ms=1)
        self.assertEqual(lease.expires_at_ms, MAX_TIME_MS)
        self.assertEqual(
            self.store.finish(lease, JobState.COMPLETE, now_ms=MAX_TIME_MS - 1).state,
            JobState.COMPLETE,
        )

    def test_renew_must_extend_deadline_and_generation_exhaustion_refuses(self):
        lease = self.leased(duration=MAX_LEASE_MS)
        self.error("time", self.store.renew, lease, now_ms=100, lease_ms=MAX_LEASE_MS)
        self.error("time", self.store.renew, lease, now_ms=101, lease_ms=1)
        current = self.store.renew(lease, now_ms=101, lease_ms=MAX_LEASE_MS)
        self.assertEqual(current.generation, 2)
        # Boundary setup via SQL avoids billions of artificial renewal calls.
        with sqlite3.connect(self.path) as raw:
            raw.execute("UPDATE jobs SET generation = ?", (MAX_ID,))
        exhausted = replace(current, generation=MAX_ID)
        self.error("state_conflict", self.store.renew, exhausted, now_ms=102, lease_ms=MAX_LEASE_MS)
        self.assertEqual(
            self.store.finish(exhausted, JobState.FAILED, now_ms=102).state, JobState.FAILED
        )

    def test_retention_boundary_tombstone_replay_and_original_outcome(self):
        lease = self.leased()
        result = self.store.finish(lease, JobState.FAILED, now_ms=101)
        self.assertEqual(self.store.prune(now_ms=102, before_ms=101), 0)
        self.assertEqual(self.store.prune(now_ms=102, before_ms=102), 1)
        tombstone = self.store.enqueue(self.request, now_ms=103)
        self.assertTrue(tombstone.tombstone)
        self.assertEqual(tombstone.identity, result.identity)
        self.assertEqual(tombstone.state, result.state)
        self.assertEqual(tombstone.error, ErrorCategory.WORKER_FAILED)
        self.assertEqual(tombstone.created_at_ms, result.created_at_ms)
        self.assertEqual(tombstone.finished_at_ms, result.finished_at_ms)
        self.assertEqual(tombstone.generation, 0)
        self.assertIsNone(tombstone.lease_owner)
        self.assertIsNone(tombstone.lease_until_ms)
        self.assertEqual(self.store.prune(now_ms=103, before_ms=103), 0)
        self.store.close()
        with JobStore(self.path) as reopened:
            self.assertEqual(reopened.enqueue(self.request, now_ms=104), tombstone)

    def test_pending_leased_and_unknown_are_retained_by_prune(self):
        self.store.enqueue(identity("pending"), now_ms=100)
        self.leased(key="leased", duration=1000)
        expired = self.leased(key="expired", duration=1)
        unknown = self.leased(key="unknown")
        self.store.finish(unknown, JobState.UNKNOWN, now_ms=100)
        complete = self.leased(key="complete")
        failed = self.leased(key="failed")
        self.store.finish(complete, JobState.COMPLETE, now_ms=100)
        self.store.finish(failed, JobState.FAILED, now_ms=100)
        self.assertEqual(self.store.prune(now_ms=200, before_ms=200), 2)
        rows = {r.identity.idempotency_key: r for r in self.store.list_jobs(now_ms=200)}
        self.assertEqual(len(rows), 6)
        self.assertEqual(rows["pending"].state, JobState.PENDING)
        self.assertEqual(rows["leased"].state, JobState.LEASED)
        self.assertEqual(rows[expired.identity.idempotency_key].state, JobState.UNKNOWN)
        self.assertEqual(rows["unknown"].state, JobState.UNKNOWN)
        self.assertEqual({k for k, r in rows.items() if r.tombstone}, {"complete", "failed"})

    def test_list_and_prune_batches_are_bounded_and_paginate_deterministically(self):
        for index in range(MAX_BATCH + 1):
            lease = self.leased(key=f"key-{index:03d}")
            self.store.finish(lease, JobState.COMPLETE, now_ms=100)
        rows = self.store.list_jobs(now_ms=100)
        self.assertEqual(len(rows), MAX_BATCH)
        tail = self.store.list_jobs(now_ms=100, after_key=rows[-1].identity.idempotency_key)
        self.assertEqual([r.identity.idempotency_key for r in tail], ["key-100"])
        self.assertEqual(self.store.prune(now_ms=101, before_ms=101), MAX_BATCH)
        self.assertEqual(self.store.prune(now_ms=101, before_ms=101), 1)
        for bad in (True, None, "1", 1.0, 0, -1, MAX_BATCH + 1):
            with self.subTest(limit=bad):
                self.error("invalid", self.store.list_jobs, now_ms=101, limit=bad)
                self.error("invalid", self.store.prune, now_ms=101, before_ms=101, limit=bad)
        for bad in (True, "complete", "passed", {}):
            self.error("invalid", self.store.list_jobs, now_ms=101, state=bad)
        for bad in ("", "k" * 129, "bad key", True):
            self.error("invalid", self.store.list_jobs, now_ms=101, after_key=bad)
        for bad in (True, "101", 101.0, -1, 102):
            self.error("time", self.store.prune, now_ms=101, before_ms=bad)

    def test_total_capacity_includes_tombstones_and_unknowns_after_reopen(self):
        self.assertEqual(MAX_RECORDS, 10_000)
        complete = self.leased(key="complete")
        self.store.finish(complete, JobState.COMPLETE, now_ms=100)
        self.store.prune(now_ms=101, before_ms=101)
        unknown = self.leased(key="unknown", now=101)
        self.store.finish(unknown, JobState.UNKNOWN, now_ms=101)
        # Fill real disk rows in one transaction, retaining actual API boundary controls.
        with sqlite3.connect(self.path) as raw:
            raw.executemany(
                "INSERT INTO jobs (repository, pull_number, head_sha, request_digest, "
                "idempotency_key, state, created_at_ms, updated_at_ms, generation) "
                "VALUES ('example/repository', 42, ?, ?, ?, 'pending', 101, 101, 0)",
                (("a" * 40, "b" * 64, f"fill-{n:05d}") for n in range(MAX_RECORDS - 3)),
            )
        self.store.enqueue(identity("last-slot"), now_ms=101)
        self.error("capacity", self.store.enqueue, identity("overflow"), now_ms=101)
        self.assertTrue(self.store.enqueue(complete.identity, now_ms=101).tombstone)
        self.assertEqual(self.store.enqueue(unknown.identity, now_ms=101).state, JobState.UNKNOWN)
        with sqlite3.connect(self.path) as raw:
            self.assertEqual(raw.execute("SELECT count(*) FROM jobs").fetchone()[0], 10_000)
            with self.assertRaises(sqlite3.IntegrityError):
                raw.execute(
                    "INSERT INTO jobs SELECT repository, pull_number, head_sha, "
                    "request_digest, 'direct-overflow', run_id, attempt_id, artifact_id, "
                    "artifact_digest, state, created_at_ms, updated_at_ms, finished_at_ms, "
                    "lease_owner, generation, lease_until_ms, error, tombstone "
                    "FROM jobs LIMIT 1"
                )
        self.store.close()
        with JobStore(self.path) as reopened:
            self.error("capacity", reopened.enqueue, identity("overflow"), now_ms=102)
            self.assertEqual(reopened.prune(now_ms=102, before_ms=102), 0)
            self.assertEqual(reopened.get(unknown.identity, now_ms=102).state, JobState.UNKNOWN)

    def test_busy_before_transaction_is_a_refusal_and_does_not_intake(self):
        with JobStore(self.path, busy_timeout_ms=0) as other, sqlite3.connect(self.path) as lock:
            lock.execute("BEGIN IMMEDIATE")
            self.error("busy", other.enqueue, self.request, now_ms=100)
            lock.rollback()
            self.assertEqual(other.list_jobs(now_ms=100), ())
            self.assertEqual(other.enqueue(self.request, now_ms=100).state, JobState.PENDING)

    def test_busy_timeout_is_bounded_and_applied_to_real_connections(self):
        self.assertEqual(MAX_BUSY_MS, 1000)
        for bad in (True, None, "1", 1.0, -1, 1001):
            self.error("invalid", JobStore, self.path, busy_timeout_ms=bad)
        for good in (0, 1, 1000):
            with JobStore(self.path, busy_timeout_ms=good) as store:
                self.assertEqual(store._db.execute("PRAGMA busy_timeout").fetchone()[0], good)
                self.assertEqual(store._db.execute("PRAGMA synchronous").fetchone()[0], 2)

    def test_path_must_be_explicit_absolute_local_file_in_existing_directory(self):
        for bad in (
            None,
            str(self.path),
            Path(":memory:"),
            Path("relative.sqlite"),
            self.path.parent,
            self.path.parent / "missing" / "jobs.sqlite",
        ):
            with self.subTest(path=bad):
                self.error("path", JobStore, bad)
        link = self.path.parent / "link.sqlite"
        link.symlink_to(self.path)
        self.error("path", JobStore, link)

    def test_unknown_schema_and_unrelated_database_are_not_adopted(self):
        self.store.close()
        with sqlite3.connect(self.path) as raw:
            raw.execute("PRAGMA user_version = 2")
        self.error("schema", JobStore, self.path)
        with sqlite3.connect(self.path) as raw:
            self.assertEqual(raw.execute("PRAGMA user_version").fetchone()[0], 2)
        unrelated = self.path.parent / "unrelated.sqlite"
        with sqlite3.connect(unrelated) as raw:
            raw.execute("CREATE TABLE unrelated (value TEXT)")
            raw.execute("INSERT INTO unrelated VALUES ('preserved')")
        self.error("schema", JobStore, unrelated)
        with sqlite3.connect(unrelated) as raw:
            self.assertEqual(raw.execute("SELECT * FROM unrelated").fetchall(), [("preserved",)])

    def test_schema_version_application_binding_and_finite_column_roster(self):
        with sqlite3.connect(self.path) as raw:
            self.assertEqual(raw.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(raw.execute("PRAGMA application_id").fetchone()[0], 0x52424A31)
            tables = {
                r[0] for r in raw.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            }
            self.assertEqual(tables, {"store_meta", "jobs"})
            columns = {r[1] for r in raw.execute("PRAGMA table_info(jobs)")}
            self.assertEqual(
                columns,
                {
                    "repository",
                    "pull_number",
                    "head_sha",
                    "request_digest",
                    "idempotency_key",
                    "run_id",
                    "attempt_id",
                    "artifact_id",
                    "artifact_digest",
                    "state",
                    "created_at_ms",
                    "updated_at_ms",
                    "finished_at_ms",
                    "lease_owner",
                    "generation",
                    "lease_until_ms",
                    "error",
                    "tombstone",
                },
            )
            raw.execute("PRAGMA application_id = 1")
        self.store.close()
        self.error("schema", JobStore, self.path)

    def test_ambiguous_enqueue_before_and_after_commit_reserves_unknown_identity(self):
        for committed in (False, True):
            with self.subTest(committed=committed):
                path = self.path.parent / f"enqueue-{committed}.sqlite"
                with JobStore(path) as store:

                    def fail(committed=committed):
                        if committed:
                            store._db.commit()
                        raise sqlite3.OperationalError("sensitive simulated database detail")

                    with patch.object(store, "_commit", side_effect=fail):
                        self.error("outcome_unknown", store.enqueue, self.request, now_ms=100)
                    self.error(
                        "outcome_unknown",
                        store.claim,
                        self.request,
                        "worker",
                        now_ms=100,
                        lease_ms=100,
                    )
                with JobStore(path) as reopened:
                    record = reopened.enqueue(self.request, now_ms=101)
                    self.assertEqual(record.state, JobState.UNKNOWN)
                    self.assertEqual(record.error, ErrorCategory.STORAGE_UNKNOWN)
                    self.assertEqual(len(reopened.list_jobs(now_ms=101)), 1)
                    self.error(
                        "state_conflict",
                        reopened.claim,
                        self.request,
                        "worker",
                        now_ms=101,
                        lease_ms=100,
                    )

    def test_ambiguous_claim_renew_and_finish_never_leave_a_retryable_job(self):
        for operation in ("claim", "renew", "finish"):
            for committed in (False, True):
                with self.subTest(operation=operation, committed=committed):
                    path = self.path.parent / f"{operation}-{committed}.sqlite"
                    with JobStore(path) as store:
                        store.enqueue(self.request, now_ms=100)
                        lease = None
                        if operation != "claim":
                            lease = store.claim(self.request, "worker", now_ms=100, lease_ms=100)

                        def fail(committed=committed):
                            if committed:
                                store._db.commit()
                            raise sqlite3.OperationalError("private failure")

                        with patch.object(store, "_commit", side_effect=fail):
                            if operation == "claim":
                                self.error(
                                    "outcome_unknown",
                                    store.claim,
                                    self.request,
                                    "worker",
                                    now_ms=101,
                                    lease_ms=100,
                                )
                            elif operation == "renew":
                                self.error(
                                    "outcome_unknown", store.renew, lease, now_ms=101, lease_ms=100
                                )
                            else:
                                self.error(
                                    "outcome_unknown",
                                    store.finish,
                                    lease,
                                    JobState.COMPLETE,
                                    now_ms=101,
                                )
                    with JobStore(path) as reopened:
                        result = reopened.get(self.request, now_ms=102)
                        self.assertEqual(result.state, JobState.UNKNOWN)
                        self.assertEqual(result.error, ErrorCategory.STORAGE_UNKNOWN)
                        self.assertEqual(reopened.prune(now_ms=103, before_ms=103), 0)
                        self.error(
                            "state_conflict",
                            reopened.claim,
                            self.request,
                            "worker",
                            now_ms=103,
                            lease_ms=100,
                        )

    def test_ambiguous_global_observation_marks_outstanding_leases_unknown(self):
        self.leased()
        with patch.object(self.store, "_commit", side_effect=sqlite3.OperationalError("private")):
            self.error("outcome_unknown", self.store.list_jobs, now_ms=200)
        self.store.close()
        with JobStore(self.path) as reopened:
            result = reopened.get(self.request, now_ms=201)
            self.assertEqual(result.state, JobState.UNKNOWN)
            self.assertEqual(result.error, ErrorCategory.STORAGE_UNKNOWN)

    def test_recovery_write_failure_remains_unknown_and_connection_quarantined(self):
        lease = self.leased()

        def fail():
            self.store._db.commit()
            # Refuse recovery after a real committed write whose result was lost.
            self.store._db.execute("PRAGMA query_only = ON")
            raise sqlite3.OperationalError("simulated lost commit response")

        with patch.object(self.store, "_commit", side_effect=fail):
            self.error("outcome_unknown", self.store.finish, lease, JobState.COMPLETE, now_ms=101)
        self.error("outcome_unknown", self.store.get, self.request, now_ms=101)
        with sqlite3.connect(self.path) as raw:
            self.assertEqual(raw.execute("SELECT state FROM jobs").fetchone()[0], "complete")
        # A trusted operator must quarantine the path; automatic reopen is not reconciliation.

    def test_storage_refusal_before_transaction_does_not_claim_an_ambiguous_write(self):
        self.store._db.execute("PRAGMA query_only = ON")
        self.error("storage", self.store.enqueue, self.request, now_ms=100)
        self.store._db.execute("PRAGMA query_only = OFF")
        self.assertEqual(self.store.list_jobs(now_ms=100), ())

    def test_interrupted_commit_attempts_unknown_marker_then_reraises(self):
        lease = self.leased()
        with (
            patch.object(self.store, "_commit", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            self.store.finish(lease, JobState.COMPLETE, now_ms=101)
        self.store.close()
        with JobStore(self.path) as reopened:
            self.assertEqual(reopened.get(self.request, now_ms=102).state, JobState.UNKNOWN)

    def test_store_close_is_idempotent_and_public_errors_exclude_input(self):
        self.store.close()
        self.store.close()
        self.error("closed", self.store.enqueue, self.request, now_ms=100)
        self.assertEqual(str(StoreError("private text")), "invalid")


if __name__ == "__main__":
    unittest.main()
