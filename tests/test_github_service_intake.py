"""Keyless real loopback/SQLite controls. No application or external-network calls."""

import ast
import asyncio
import contextlib
import hashlib
import hmac
import io
import json
import os
import sqlite3
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from review_boundary import github_service_intake as intake
from review_boundary.github_service_store import JobState, StoreError

SECRET = b"generated-test-secret-" + bytes(range(32)) + b"\n"
POLICY = intake.IntakePolicy((("example/repo", 101), ("other/repo", 102)), (201, 202))


def payload():
    return {
        "action": "opened",
        "number": 7,
        "repository": {"full_name": "example/repo", "id": 101},
        "sender": {"id": 201},
        "pull_request": {
            "number": 7,
            "state": "open",
            "head": {"sha": "a" * 40},
            "base": {"repo": {"full_name": "example/repo", "id": 101}},
        },
    }


def encoded(value=None):
    return json.dumps(payload() if value is None else value, ensure_ascii=False).encode("utf-8")


def signature(raw):
    return "sha256=" + hmac.digest(SECRET, raw, "sha256").hex()


def identity(raw=None, policy=POLICY):
    raw = encoded() if raw is None else raw
    return intake.authenticated_identity(
        raw,
        {"x-hub-signature-256": signature(raw), "x-github-event": "pull_request"},
        SECRET,
        policy,
    )


def request(raw=None, *, headers=(), omitted=(), line=b"POST /github/intake HTTP/1.1"):
    raw = encoded() if raw is None else raw
    defaults = [
        ("Host", "127.0.0.1"),
        ("Content-Type", "application/json; charset=utf-8"),
        ("Content-Length", str(len(raw))),
        ("X-Hub-Signature-256", signature(raw)),
        ("X-GitHub-Event", "pull_request"),
        ("X-GitHub-Delivery", "ignored-transport-value"),
    ]
    lines = [line] + [f"{k}: {v}".encode("ascii") for k, v in defaults if k.lower() not in omitted]
    lines.extend(f"{k}: {v}".encode("ascii") for k, v in headers)
    return b"\r\n".join(lines) + b"\r\n\r\n" + raw


def category(response):
    if len(response) > 1024:
        raise AssertionError("unbounded response")
    head, body = response.split(b"\r\n\r\n", 1)
    if b"Connection: close" not in head:
        raise AssertionError("connection not closed")
    return json.loads(body)["status"]


def rows(directory):
    with contextlib.closing(sqlite3.connect(directory / intake.DATABASE)) as db:
        return db.execute("SELECT * FROM jobs ORDER BY idempotency_key").fetchall()


class Scratch(unittest.TestCase):
    def setUp(self):
        # A task can choose TMPDIR; resolve the test root to avoid OS /var aliases.
        self.temp = tempfile.TemporaryDirectory(prefix="intake-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "intake"
        self.secret_file = self.root / "secret"
        self.secret_file.write_bytes(SECRET)

    def error(self, code, function, *args, **kwargs):
        with self.assertRaises(intake.IntakeError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertEqual(str(caught.exception), code)


class AuthenticationTests(Scratch):
    def test_raw_secret_bounded_regular_nonsymlink_and_untrimmed(self):
        self.assertEqual(intake.read_secret(self.secret_file), SECRET)
        for length in (0, 31, 129, 4096):
            self.secret_file.write_bytes(b"s" * length)
            self.error("configuration_refused", intake.read_secret, self.secret_file)
        for length in (32, 128):
            raw = b"s" * (length - 1) + b"\n"
            self.secret_file.write_bytes(raw)
            self.assertEqual(intake.read_secret(self.secret_file), raw)
        link = self.root / "link"
        link.symlink_to(self.secret_file)
        self.error("configuration_refused", intake.read_secret, link)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        self.error("configuration_refused", intake.read_secret, fifo)
        self.error("configuration_refused", intake.read_secret, self.root)
        self.error("configuration_refused", intake.read_secret, Path("relative"))

    def test_policy_canonicalization_and_strict_allowlists(self):
        reordered = intake.IntakePolicy(tuple(reversed(POLICY.repositories)), (202, 201))
        self.assertEqual(POLICY.digest, reordered.digest)
        for repos, senders in (
            ((), (201,)),
            ((("EXAMPLE/repo", 101),), (201,)),
            ((("example/repo", True),), (201,)),
            ((("example/repo", 101),), (True,)),
            ((("a/..", 101),), (201,)),
            ((("a/ré", 101),), (201,)),
            ((("a/r", 101), ("a/r", 102)), (201,)),
            ((("a/r", 101), ("b/r", 101)), (201,)),
            (POLICY.repositories, (201, 201)),
            (POLICY.repositories, ()),
            (list(POLICY.repositories), (201,)),
        ):
            with self.subTest(repos=repos, senders=senders):
                self.error("configuration_refused", intake.IntakePolicy, repos, senders)

    def test_authentication_precedes_json_and_uses_constant_time_comparison(self):
        raw = b"not json"
        for sig in (
            "",
            "sha1=" + "a" * 40,
            "sha256=" + "A" * 64,
            "sha256=" + "0" * 64,
            signature(raw) + "\n",
        ):
            with patch.object(intake, "parse_json_object", side_effect=AssertionError):
                self.error(
                    "unauthenticated",
                    intake.authenticated_identity,
                    raw,
                    {"x-hub-signature-256": sig},
                    SECRET,
                    POLICY,
                )
        with patch.object(intake.hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
            identity()
            compare.assert_called_once()
        self.error(
            "unauthenticated",
            intake.authenticated_identity,
            encoded() + b" ",
            {"x-hub-signature-256": signature(encoded())},
            SECRET,
            POLICY,
        )

    def test_exact_identity_policy_digest_and_permanently_absent_execution_references(self):
        raw = encoded()
        original = identity(raw)
        self.assertEqual(original.request_digest, hashlib.sha256(raw).hexdigest())
        self.assertTrue(original.idempotency_key.startswith("intake-v1:"))
        self.assertEqual(original, identity(raw))
        for field in intake._REFERENCES:
            self.assertIsNone(getattr(original, field))
        modified = payload()
        modified.update(
            run_id=123,
            attempt_id=2,
            artifact_id=99,
            artifact_digest="f" * 64,
            workflow={"id": 77},
            ignored="valid Unicode: 水 café ☃",
        )
        ignored = identity(encoded(modified))
        for field in intake._REFERENCES:
            self.assertIsNone(getattr(ignored, field))
        self.assertNotEqual(original.idempotency_key, ignored.idempotency_key)
        changed_policy = intake.IntakePolicy(POLICY.repositories, (201,))
        self.assertNotEqual(original.idempotency_key, identity(raw, changed_policy).idempotency_key)
        self.assertNotEqual(original.idempotency_key, identity(raw + b" ").idempotency_key)
        for field in ("repo", "pr", "head"):
            value = payload()
            if field == "repo":
                value["repository"] = {"full_name": "other/repo", "id": 102}
                value["pull_request"]["base"]["repo"] = value["repository"].copy()
            elif field == "pr":
                value["number"] = value["pull_request"]["number"] = 8
            else:
                value["pull_request"]["head"]["sha"] = "b" * 40
            self.assertNotEqual(original.idempotency_key, identity(encoded(value)).idempotency_key)

    def test_duplicate_nonfinite_deep_invalid_utf8_and_nonobject_json(self):
        samples = [
            b"{",
            b"[]",
            b'{"x":1,"x":2}',
            b'{"x":NaN}',
            b'{"x":Infinity}',
            b'{"x":1e999}',
            b'{"x":"\xff"}',
            encoded().decode().encode("utf-16"),
            b'{"x":' + b"[" * 66 + b"0" + b"]" * 66 + b"}",
        ]
        for raw in samples:
            with self.subTest(raw_length=len(raw)):
                self.error("invalid_payload", identity, raw)

    def test_required_claims_have_exact_types_and_shapes(self):
        cases = [
            (("repository",), []),
            (("sender",), []),
            (("pull_request",), []),
            (("repository", "id"), True),
            (("repository", "id"), "101"),
            (("repository", "full_name"), "EXAMPLE/repo"),
            (("sender", "id"), True),
            (("sender", "id"), 201.0),
            (("number",), True),
            (("number",), 0),
            (("number",), 2**63),
            (("pull_request", "number"), "7"),
            (("pull_request", "number"), 8),
            (("pull_request", "head"), []),
            (("pull_request", "head", "sha"), "A" * 40),
            (("pull_request", "head", "sha"), "a" * 39),
            (("pull_request", "base"), []),
            (("pull_request", "base", "repo"), []),
            (("pull_request", "base", "repo", "id"), True),
            (("action",), []),
        ]
        for path, replacement in cases:
            value = payload()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            with self.subTest(path=path, replacement=replacement):
                self.error("invalid_payload", identity, encoded(value))
        for field in payload():
            value = payload()
            del value[field]
            self.error("invalid_payload", identity, encoded(value))

    def test_disallowed_claims_and_event(self):
        changes = [
            (("repository", "id"), 999),
            (("sender", "id"), 999),
            (("action",), "closed"),
            (("pull_request", "state"), "closed"),
            (("pull_request", "base", "repo", "id"), 102),
        ]
        for path, replacement in changes:
            value = payload()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = replacement
            self.error("forbidden", identity, encoded(value))
        raw = encoded()
        self.error(
            "forbidden",
            intake.authenticated_identity,
            raw,
            {"x-hub-signature-256": signature(raw), "x-github-event": "push"},
            SECRET,
            POLICY,
        )
        for action in ("opened", "reopened", "synchronize"):
            value = payload()
            value["action"] = action
            self.assertEqual(identity(encoded(value)).pull_number, 7)


class StorageTests(Scratch):
    def store(self):
        value = intake.IntakeStore(self.directory)
        self.addCleanup(value.close)
        return value

    def test_durable_active_before_sqlite_and_clean_reopen_preserves_intent(self):
        real_store = intake.JobStore

        def open_store(*args, **kwargs):
            marker = json.loads((self.directory / intake.MARKER).read_bytes())
            self.assertEqual(marker["state"], "active")
            self.assertEqual(kwargs["busy_timeout_ms"], 1000)
            return real_store(*args, **kwargs)

        with patch.object(intake, "JobStore", side_effect=open_store):
            store = self.store()
        original = store.retain(identity())
        self.assertEqual(original.state, JobState.PENDING)
        store.close()
        self.assertEqual(
            json.loads((self.directory / intake.MARKER).read_bytes())["state"], "clean"
        )
        reopened = self.store()
        self.assertEqual(reopened.retain(identity()), original)
        self.assertEqual(len(rows(self.directory)), 1)

    def test_existing_unmarked_empty_or_execution_store_is_not_adopted(self):
        self.directory.mkdir(mode=0o700)
        self.error("configuration_refused", intake.IntakeStore, self.directory)
        dbpath = self.directory / intake.DATABASE
        with intake.JobStore(dbpath) as execution:
            execution.enqueue(replace(identity(), run_id=8), now_ms=100)
        before = dbpath.read_bytes()
        self.error("configuration_refused", intake.IntakeStore, self.directory)
        self.assertEqual(dbpath.read_bytes(), before)

    def test_unclean_session_and_unknown_marker_write_failure_refuse_restart(self):
        store = self.store()
        store.retain(identity())
        with (
            patch.object(store, "_write_marker", side_effect=OSError("synthetic private detail")),
            patch.object(store._db, "enqueue", side_effect=StoreError("outcome_unknown")),
        ):
            self.error("outcome_unknown", store.retain, identity(encoded() + b" "))
        self.assertTrue(store.poisoned)
        store.close()
        self.assertEqual(
            json.loads((self.directory / intake.MARKER).read_bytes())["state"], "active"
        )
        self.error("reconciliation_required", intake.IntakeStore, self.directory)

    def test_real_commit_uncertainty_quarantines_and_never_auto_reopens(self):
        store = self.store()

        def fail():
            store._db._db.commit()
            store._db._db.execute("PRAGMA query_only = ON")
            raise sqlite3.OperationalError("private storage error")

        with patch.object(store._db, "_commit", side_effect=fail):
            self.error("outcome_unknown", store.retain, identity())
        self.assertTrue(store.poisoned)
        with patch.object(intake, "JobStore", side_effect=AssertionError("automatic reopen")):
            self.error("outcome_unknown", store.retain, identity())
        store.close()
        self.error("reconciliation_required", intake.IntakeStore, self.directory)
        self.assertEqual(len(rows(self.directory)), 1)

    def test_process_like_unclean_release_does_not_resume(self):
        store = self.store()
        store.retain(identity())
        store._release()
        store._closed = True
        self.error("reconciliation_required", intake.IntakeStore, self.directory)

    def test_busy_is_known_pre_acquisition_and_does_not_poison(self):
        store = self.store()
        with contextlib.closing(sqlite3.connect(self.directory / intake.DATABASE, timeout=0)) as db:
            db.execute("BEGIN IMMEDIATE")
            before = time.monotonic()
            self.error("busy", store.retain, identity())
            self.assertLess(time.monotonic() - before, 1.5)
            self.assertFalse(store.poisoned)
            db.rollback()
        self.assertEqual(len(rows(self.directory)), 0)
        store.retain(identity())

    def test_lifetime_capacity_includes_tombstones_and_exact_replay_survives(self):
        store = self.store()
        original = store.retain(identity())
        now = original.created_at_ms
        # Owned synthetic fixtures populate the unchanged actual 10000-row bound.
        with contextlib.closing(sqlite3.connect(self.directory / intake.DATABASE)) as db:
            db.executemany(
                "INSERT INTO jobs (repository,pull_number,head_sha,request_digest,idempotency_key,"
                "state,created_at_ms,updated_at_ms,finished_at_ms,generation,tombstone) "
                "VALUES ('example/repo',7,?,?,?,'complete',?,?,?,0,1)",
                (("a" * 40, "b" * 64, f"synthetic-{n}", now, now, now) for n in range(9999)),
            )
            db.commit()
        self.error("capacity", store.retain, identity(encoded() + b" "))
        self.assertFalse(store.poisoned)
        self.assertEqual(store.retain(identity()), original)
        self.assertEqual(len(rows(self.directory)), 10000)

    def test_identity_conflict_refuses_without_replacing_a_row(self):
        store = self.store()
        original = store.retain(identity())
        changed = replace(original.identity, head_sha="b" * 40)
        self.error("identity_conflict", store.retain, changed)
        self.assertFalse(store.poisoned)
        self.assertEqual(store.retain(identity()), original)
        self.assertEqual(len(rows(self.directory)), 1)

    def test_nonintake_unknown_leased_terminal_and_tombstone_replay_needs_reconciliation(self):
        for state, tombstone in (
            ("unknown", False),
            ("leased", False),
            ("complete", False),
            ("failed", False),
            ("complete", True),
        ):
            with self.subTest(state=state, tombstone=tombstone):
                directory = self.root / f"{state}-{tombstone}"
                store = intake.IntakeStore(directory)
                original = store.retain(identity())
                # These execution transitions are fixtures, never receiver call paths.
                db = store._db
                now = original.updated_at_ms
                lease = db.claim(
                    original.identity, "synthetic-fixture", now_ms=now, lease_ms=300000
                )
                if state != "leased":
                    db.finish(lease, JobState(state), now_ms=now + 1)
                    if tombstone:
                        db.prune(now_ms=now + 2, before_ms=now + 2)
                with patch.object(intake.time, "time_ns", return_value=(now + 3) * 1_000_000):
                    self.error("reconciliation_required", store.retain, identity())
                self.assertEqual(rows(directory)[0][9], state)
                self.assertEqual(bool(rows(directory)[0][-1]), tombstone)
                store.close()
                self.error("reconciliation_required", intake.IntakeStore, directory)

    def test_reference_bearing_identity_is_never_stored(self):
        store = self.store()
        for field, value in (
            ("run_id", 9),
            ("attempt_id", 2),
            ("artifact_id", 5),
            ("artifact_digest", "b" * 64),
        ):
            self.error("invalid_payload", store.retain, replace(identity(), **{field: value}))
        self.assertEqual(rows(self.directory), [])

    def test_unexpected_storage_diagnostics_are_fixed_and_nonresumable(self):
        store = self.store()
        with patch.object(store._db, "enqueue", side_effect=RuntimeError("synthetic private text")):
            self.error("outcome_unknown", store.retain, identity())
        self.assertTrue(store.poisoned)
        store.close()
        self.error("reconciliation_required", intake.IntakeStore, self.directory)

    def test_marker_path_bounds_duplicate_schema_permissions_and_cooperative_ownership(self):
        store = self.store()
        self.error("busy", intake.IntakeStore, self.directory)
        store.close()
        marker = self.directory / intake.MARKER
        original = marker.read_bytes()
        for raw in (
            b"{}",
            original.replace(b'"version":1', b'"version":true'),
            b"x" * 1025,
            b'{"version":1,"version":1}',
        ):
            marker.write_bytes(raw)
            self.error("configuration_refused", intake.IntakeStore, self.directory)
        marker.write_bytes(original)
        marker.chmod(0o644)
        self.error("configuration_refused", intake.IntakeStore, self.directory)
        marker.chmod(0o600)
        link = self.root / "linked-dir"
        link.symlink_to(self.directory, target_is_directory=True)
        self.error("configuration_refused", intake.IntakeStore, link)
        self.error("configuration_refused", intake.IntakeStore, Path("relative"))

    def test_failed_activation_never_opens_database_and_staging_blocks_resume(self):
        with (
            patch.object(intake.IntakeStore, "_write_marker", side_effect=OSError),
            patch.object(intake, "JobStore", side_effect=AssertionError),
        ):
            self.error("configuration_refused", intake.IntakeStore, self.directory)
        self.assertFalse((self.directory / intake.DATABASE).exists())
        (self.directory / intake.STAGING).write_bytes(b"interrupted staging fixture")
        self.error("reconciliation_required", intake.IntakeStore, self.directory)

    def test_clean_close_failure_does_not_certify_unresolved_write(self):
        store = self.store()
        store.retain(identity())
        with patch.object(store._db, "close", side_effect=OSError):
            self.error("outcome_unknown", store.close)
        # The fixture's intentionally failed close is still ours to release.
        store._db.close()
        self.assertTrue(store.poisoned)
        self.assertNotEqual(
            json.loads((self.directory / intake.MARKER).read_bytes())["state"], "clean"
        )
        self.error("reconciliation_required", intake.IntakeStore, self.directory)

    def test_failed_clean_publication_and_failed_unknown_update_keep_session_fence(self):
        store = self.store()
        store.retain(identity())
        real_write = store._write_marker

        def uncertain(state):
            if state == "clean":
                real_write(state)
            raise OSError("synthetic marker outcome loss")

        with patch.object(store, "_write_marker", side_effect=uncertain):
            self.error("outcome_unknown", store.close)
        self.assertEqual(
            json.loads((self.directory / intake.MARKER).read_bytes())["state"], "clean"
        )
        self.assertTrue((self.directory / intake.SESSION).is_file())
        self.error("reconciliation_required", intake.IntakeStore, self.directory)


class LoopbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="intake-loopback-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "intake"
        self.secret_file = self.root / "secret"
        self.secret_file.write_bytes(SECRET)
        self.server = await intake.start_server(
            policy=POLICY, secret_file=self.secret_file, intake_directory=self.directory
        )
        self.addAsyncCleanup(self.server.close)

    async def exchange(self, raw, *, eof=False, server=None):
        server = self.server if server is None else server
        reader, writer = await asyncio.open_connection("127.0.0.1", server.port)
        response = bytearray()
        try:
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                writer.write(raw)
                await writer.drain()
                if eof:
                    writer.write_eof()
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(1025), 5)
                except ConnectionResetError:
                    # An actual reset is distinct from EOF; keep any delivered reply.
                    self.assertTrue(response)
                    break
                if not chunk:
                    self.assertTrue(reader.at_eof())
                    break
                response.extend(chunk)
                self.assertLessEqual(len(response), 1024)
            return bytes(response)
        finally:
            sock = writer.get_extra_info("socket")
            writer.close()
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                await writer.wait_closed()
            self.assertEqual(sock.fileno(), -1)

    async def test_intent_replay_new_connection_and_close_reopen_with_absent_references(self):
        self.assertEqual(category(await self.exchange(request())), "retained")
        first = rows(self.directory)
        self.assertEqual(
            category(
                await self.exchange(
                    request(headers=[("X-GitHub-Delivery", "new")], omitted={"x-github-delivery"})
                )
            ),
            "retained",
        )
        self.assertEqual(rows(self.directory), first)
        self.assertEqual(first[0][5:9], (None, None, None, None))
        await self.server.close()
        self.server = await intake.start_server(
            policy=POLICY, secret_file=self.secret_file, intake_directory=self.directory
        )
        self.addAsyncCleanup(self.server.close)
        self.assertEqual(category(await self.exchange(request())), "retained")
        self.assertEqual(rows(self.directory), first)

    async def test_raw_tampering_disallowed_claims_and_ignored_unicode_before_enqueue(self):
        with patch.object(
            self.server.store, "retain", side_effect=AssertionError("enqueue reached")
        ):
            self.assertEqual(
                category(await self.exchange(request().replace(b'"opened"', b'"closed"'))),
                "unauthenticated",
            )
            for path, replacement in (
                (("sender", "id"), 999),
                (("repository", "id"), 999),
                (("action",), "closed"),
                (("number",), True),
            ):
                value = payload()
                target = value
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = replacement
                self.assertIn(
                    category(await self.exchange(request(encoded(value)))),
                    {"forbidden", "invalid_payload"},
                )
            self.assertEqual(
                category(
                    await self.exchange(
                        request(headers=[("X-GitHub-Event", "push")], omitted={"x-github-event"})
                    )
                ),
                "forbidden",
            )
        value = payload()
        value["ignored"] = "水 café ☃"
        self.assertEqual(category(await self.exchange(request(encoded(value)))), "retained")
        content = (self.directory / intake.DATABASE).read_bytes()
        self.assertNotIn("水 café ☃".encode(), content)
        self.assertNotIn(SECRET, content)

    async def test_duplicate_folded_and_oversized_headers_refuse_before_enqueue(self):
        cases = [
            request(headers=[("Content-Length", "1")]),
            request(headers=[("x-HUB-signature-256", signature(encoded()))]),
            request(headers=[("X-GitHub-Event", "pull_request")]),
            request(headers=[("Host", "other")]),
            request().replace(b"Host:", b" Host:"),
            request().replace(b"Host:", b"\tHost:"),
            request(headers=[("X-Pad", "p" * intake.MAX_HEADERS)]),
            request(headers=[(f"X-{n}", "v") for n in range(65)]),
            b"P" * (intake.MAX_REQUEST_LINE + 1),
            request(line=b"POST /github/intake?x=1 HTTP/1.1"),
            request(line=b"GET /github/intake HTTP/1.1"),
            request(line=b"POST /alternate HTTP/1.1"),
            request(line=b"POST /github/intake HTTP/2.0"),
            request().replace(b"Host: ", b"Host : "),
            request().replace(b"Host: ", b"Host: \x00"),
            request().replace(b"\r\n", b"\n"),
            request() + request(),
        ]
        with patch.object(self.server.store, "retain", side_effect=AssertionError):
            for raw in cases:
                self.assertIn(
                    category(await self.exchange(raw, eof=True)), {"malformed", "too_large"}
                )
        self.assertEqual(rows(self.directory), [])

    async def test_length_framing_compression_expect_and_signature_refusals(self):
        cases = [
            request(omitted={"content-length"}),
            request(omitted={"x-hub-signature-256"}),
            request(headers=[("Transfer-Encoding", "chunked")]),
            request(headers=[("Transfer-Encoding", "")]),
            request(headers=[("Content-Encoding", "identity")]),
            request(headers=[("Expect", "100-continue")]),
        ]
        for length in ("-1", "+1", "1,1", "1.0", "", "262145", "9" * 5000):
            cases.append(request(headers=[("Content-Length", length)], omitted={"content-length"}))
        for mime in ("text/json", "application/json; charset=utf-16", "application/json; x=y"):
            cases.append(request(headers=[("Content-Type", mime)], omitted={"content-type"}))
        for sig in ("sha256=" + "A" * 64, "sha256=" + "0" * 64):
            cases.append(
                request(headers=[("X-Hub-Signature-256", sig)], omitted={"x-hub-signature-256"})
            )
        cases.extend((request()[:-1], request(b"x" * (intake.MAX_BODY + 1))))
        with patch.object(self.server.store, "retain", side_effect=AssertionError):
            for raw in cases:
                self.assertIn(
                    category(await self.exchange(raw, eof=True)),
                    {"malformed", "too_large", "unauthenticated"},
                )
        self.assertEqual(rows(self.directory), [])

    async def test_http10_optional_charset_decimal_leading_zero_and_valid_boundaries(self):
        raw = encoded()
        good = request(
            raw,
            line=b"POST /github/intake HTTP/1.0",
            omitted={"content-length", "content-type"},
            headers=[
                ("Content-Length", "00" + str(len(raw))),
                ("Content-Type", "application/json"),
            ],
        )
        self.assertEqual(category(await self.exchange(good)), "retained")
        value = payload()
        value["ignored"] = ""
        base = encoded(value)
        value["ignored"] = "x" * (intake.MAX_BODY - len(base))
        raw = encoded(value)
        self.assertEqual(len(raw), intake.MAX_BODY)
        self.assertEqual(category(await self.exchange(request(raw))), "retained")
        self.assertEqual(len(rows(self.directory)), 2)

    async def test_signed_malformed_duplicate_nonfinite_deep_and_utf8_json_refuse(self):
        cases = [
            b"{",
            b'{"number":7,"number":7}',
            b'{"ignored":NaN}',
            b'{"ignored":1e999}',
            b'{"ignored":"\xff"}',
            b'{"ignored":' + b"[" * 66 + b"0" + b"]" * 66 + b"}",
        ]
        with patch.object(self.server.store, "retain", side_effect=AssertionError):
            for raw in cases:
                self.assertEqual(category(await self.exchange(request(raw))), "invalid_payload")

    async def test_absolute_real_slow_drip_header_and_body_deadline(self):
        for prefix, drip in ((b"P", b"O"), (request()[:-30], b" ")):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.server.port)
            start = time.monotonic()
            try:
                writer.write(prefix)
                await writer.drain()
                for _ in range(5):
                    await asyncio.sleep(0.5)
                    writer.write(drip)
                    await writer.drain()
                result = await asyncio.wait_for(reader.read(), 1.5)
                elapsed = time.monotonic() - start
                self.assertEqual(category(result), "deadline")
                self.assertGreaterEqual(elapsed, 2.9)
                self.assertLess(elapsed, 4.0)
            finally:
                writer.close()
                await writer.wait_closed()
        self.assertEqual(rows(self.directory), [])

    async def test_short_body_without_eof_hits_total_deadline(self):
        self.assertEqual(category(await self.exchange(request()[:-5])), "deadline")
        self.assertEqual(rows(self.directory), [])

    async def test_eight_inflight_and_actual_socket_protocol_timer_closure(self):
        clients = [await asyncio.open_connection("127.0.0.1", self.server.port) for _ in range(8)]
        await asyncio.sleep(0)
        protocols = tuple(self.server.connections)
        self.assertEqual(len(self.server.active), 8)
        self.assertEqual(category(await self.exchange(request())), "busy")
        port = self.server.port
        sockets = tuple(self.server.server.sockets)
        tasks_before = asyncio.all_tasks()
        await self.server.close()
        for reader, writer in clients:
            await asyncio.wait_for(reader.read(), 1)
            self.assertTrue(reader.at_eof())
            writer.close()
            await writer.wait_closed()
        self.assertEqual(self.server.connections, set())
        self.assertEqual(self.server.active, set())
        self.assertTrue(all(p.closed.done() and p.timer.cancelled() for p in protocols))
        self.assertTrue(all(s.fileno() == -1 for s in sockets))
        self.assertFalse(self.server.server.is_serving())
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", port)
        self.assertFalse(asyncio.all_tasks() - tasks_before)

    async def test_lost_response_after_actual_commit_reconciles_without_second_row(self):
        real_response = intake._Connection.respond

        def lose(connection, code):
            if code == "retained":
                connection.done = True
                connection.timer.cancel()
                connection.transport.abort()
            else:
                real_response(connection, code)

        with patch.object(intake._Connection, "respond", lose):
            self.assertEqual(await self.exchange(request()), b"")
        before = rows(self.directory)
        self.assertEqual(len(before), 1)
        self.assertEqual(category(await self.exchange(request())), "retained")
        self.assertEqual(rows(self.directory), before)

    async def test_poisoned_storage_stops_listener_and_preserves_unknown(self):
        port = self.server.port
        with patch.object(
            self.server.store._db, "enqueue", side_effect=StoreError("outcome_unknown")
        ):
            self.assertEqual(category(await self.exchange(request())), "outcome_unknown")
        await asyncio.wait_for(self.server.stopped, 1)
        await self.server.close()
        self.assertTrue(self.server.store.poisoned)
        with self.assertRaises(OSError):
            await asyncio.open_connection("127.0.0.1", port)
        self.assertEqual(
            json.loads((self.directory / intake.MARKER).read_bytes())["state"], "unknown"
        )


class InertCliTests(unittest.TestCase):
    def test_default_help_validation_never_open_bind_or_load_credentials(self):
        with (
            patch.object(intake, "read_secret", side_effect=AssertionError),
            patch.object(intake, "IntakeStore", side_effect=AssertionError),
            patch.object(asyncio, "run", side_effect=AssertionError),
            patch.dict(os.environ, {"GITHUB_TOKEN": "synthetic-never-read"}),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            self.assertEqual(intake.main([]), 0)
            with self.assertRaises(SystemExit) as caught:
                intake.main(["--help"])
            self.assertEqual(caught.exception.code, 0)
            self.assertEqual(
                intake.main(
                    [
                        "validate",
                        "--secret-file",
                        "/absent/secret",
                        "--intake-directory",
                        "/absent/intake",
                        "--repository",
                        "example/repo:101",
                        "--sender-id",
                        "201",
                    ]
                ),
                0,
            )
            self.assertEqual(
                intake.main(
                    [
                        "validate",
                        "--secret-file",
                        "/absent/secret",
                        "--intake-directory",
                        "/absent/intake",
                        "--repository",
                        "EXAMPLE/repo:101",
                        "--sender-id",
                        "201",
                    ]
                ),
                1,
            )

    def test_stdlib_imports_and_finite_store_method_call_roster(self):
        tree = ast.parse(Path(intake.__file__).read_text())
        imported = [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
        self.assertEqual(
            {m for m in imported if m and m.startswith("github")}, {"github_service_store"}
        )
        names = {
            a.name.split(".")[0]
            for n in ast.walk(tree)
            if isinstance(n, ast.Import)
            for a in n.names
        }
        self.assertFalse(
            names
            & {"subprocess", "urllib", "requests", "http", "inspect_ai", "openai", "anthropic"}
        )
        calls = {
            n.func.attr
            for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        }
        self.assertFalse(
            calls
            & {
                "claim",
                "renew",
                "finish",
                "prune",
                "list_jobs",
                "dispatch",
                "publish",
                "evaluate",
                "reserve",
                "settle",
                "getenv",
            }
        )
        self.assertIn("enqueue", calls)

    def test_invalid_port_is_inert(self):
        for port in (-1, 65536, True, "0"):
            with (
                patch.object(intake, "read_secret", side_effect=AssertionError),
                self.assertRaises(intake.IntakeError),
            ):
                asyncio.run(
                    intake.start_server(
                        policy=POLICY,
                        secret_file=Path("/missing"),
                        intake_directory=Path("/missing"),
                        port=port,
                    )
                )


if __name__ == "__main__":
    unittest.main()
