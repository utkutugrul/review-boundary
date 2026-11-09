"""Authenticated local GitHub intents. No worker or execution authority."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import re
import signal
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from .github_service_store import MAX_ID, JobIdentity, JobRecord, JobState, JobStore, StoreError
from .json_input import parse_json_object

MAX_REQUEST_LINE = 4096
MAX_HEADERS = 16384
MAX_HEADER_COUNT = 64
MAX_BODY = 262144
MAX_CONNECTIONS = 8
READ_SECONDS = 3.0
DATABASE = "intents.sqlite3"
MARKER = "intake-v1.json"
LOCK = "intake-v1.lock"
STAGING = "intake-v1.next"
SESSION = "intake-v1.active"
_REPOSITORY = r"[a-z0-9][a-z0-9-]{0,38}/[a-z0-9_.-]{1,100}"
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_REFERENCES = ("run_id", "attempt_id", "artifact_id", "artifact_digest")
_CATEGORIES = {
    "retained": (202, "Accepted"),
    "malformed": (400, "Bad Request"),
    "unauthenticated": (401, "Unauthorized"),
    "forbidden": (403, "Forbidden"),
    "deadline": (408, "Request Timeout"),
    "identity_conflict": (409, "Conflict"),
    "too_large": (413, "Content Too Large"),
    "invalid_payload": (422, "Unprocessable Content"),
    "busy": (503, "Service Unavailable"),
    "capacity": (503, "Service Unavailable"),
    "reconciliation_required": (503, "Service Unavailable"),
    "outcome_unknown": (503, "Service Unavailable"),
    "configuration_refused": (503, "Service Unavailable"),
    "closed": (503, "Service Unavailable"),
}


class IntakeError(ValueError):
    """Only fixed categories may cross the receiver boundary."""

    def __init__(self, code: str):
        self.code = code if code in _CATEGORIES else "configuration_refused"
        super().__init__(self.code)


def _need(condition: bool, code: str = "configuration_refused") -> None:
    if not condition:
        raise IntakeError(code)


def _positive(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_ID


def _repository(value: object) -> bool:
    return (
        type(value) is str
        and re.fullmatch(_REPOSITORY, value, re.ASCII) is not None
        and value.split("/")[1] not in {".", ".."}
    )


@dataclass(frozen=True)
class IntakePolicy:
    repositories: tuple[tuple[str, int], ...]
    sender_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        _need(type(self.repositories) is tuple and 1 <= len(self.repositories) <= 64)
        _need(type(self.sender_ids) is tuple and 1 <= len(self.sender_ids) <= 256)
        _need(all(type(p) is tuple and len(p) == 2 for p in self.repositories))
        _need(all(_repository(n) and _positive(i) for n, i in self.repositories))
        _need(all(_positive(i) for i in self.sender_ids))
        _need(len({p[0] for p in self.repositories}) == len(self.repositories))
        _need(len({p[1] for p in self.repositories}) == len(self.repositories))
        _need(len(set(self.sender_ids)) == len(self.sender_ids))

    @property
    def digest(self) -> str:
        canonical = json.dumps(
            {
                "version": "intake-v1",
                "repositories": sorted(self.repositories),
                "sender_ids": sorted(self.sender_ids),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(canonical).hexdigest()


def _bounded_file(
    path: Path, limit: int, *, private: bool = False, modes: tuple[int, ...] = (0o600,)
) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_size <= limit)
        if private:
            _need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) in modes)
        value = os.read(fd, limit + 1)
        _need(len(value) <= limit)
        return value
    finally:
        os.close(fd)


def read_secret(path: Path) -> bytes:
    """Read exactly the trusted raw bytes, without trimming or discovery."""
    try:
        _need(isinstance(path, Path) and path.is_absolute() and len(os.fsencode(path)) <= 4096)
        for parent in path.parents:
            _need(stat.S_ISDIR(parent.lstat().st_mode))
        value = _bounded_file(path, 128, private=True, modes=(0o400, 0o600))
        _need(32 <= len(value) <= 128)
        return value
    except (OSError, ValueError):
        raise IntakeError("configuration_refused") from None


def authenticated_identity(
    raw: bytes, headers: dict[str, str], secret: bytes, policy: IntakePolicy
) -> JobIdentity:
    """Only a verified body and trusted canonical policy can name an intent."""
    _need(type(raw) is bytes and len(raw) <= MAX_BODY, "too_large")
    signature = headers.get("x-hub-signature-256", "")
    _need(re.fullmatch(r"sha256=[0-9a-f]{64}", signature, re.ASCII) is not None, "unauthenticated")
    expected = "sha256=" + hmac.digest(secret, raw, "sha256").hex()
    _need(hmac.compare_digest(signature, expected), "unauthenticated")
    _need(headers.get("x-github-event") == "pull_request", "forbidden")
    try:
        # Decode explicitly: json.loads(bytes) otherwise also accepts UTF-16/32.
        payload = parse_json_object(raw.decode("utf-8"))
        repo = payload["repository"]
        sender = payload["sender"]
        pr = payload["pull_request"]
        _need(type(repo) is dict and type(sender) is dict and type(pr) is dict, "invalid_payload")
        _need(type(payload["action"]) is str, "invalid_payload")
        _need(payload["action"] in {"opened", "reopened", "synchronize"}, "forbidden")
        _need(_repository(repo["full_name"]) and _positive(repo["id"]), "invalid_payload")
        _need((repo["full_name"], repo["id"]) in policy.repositories, "forbidden")
        _need(_positive(sender["id"]), "invalid_payload")
        _need(sender["id"] in policy.sender_ids, "forbidden")
        _need(_positive(payload["number"]) and _positive(pr["number"]), "invalid_payload")
        _need(payload["number"] == pr["number"], "invalid_payload")
        _need(type(pr["state"]) is str and pr["state"] == "open", "forbidden")
        _need(type(pr["head"]) is dict and type(pr["head"]["sha"]) is str, "invalid_payload")
        _need(
            re.fullmatch(r"[0-9a-f]{40}", pr["head"]["sha"], re.ASCII) is not None,
            "invalid_payload",
        )
        _need(type(pr["base"]) is dict and type(pr["base"]["repo"]) is dict, "invalid_payload")
        base = pr["base"]["repo"]
        _need(_positive(base["id"]) and _repository(base["full_name"]), "invalid_payload")
        _need((base["full_name"], base["id"]) == (repo["full_name"], repo["id"]), "forbidden")
    except IntakeError:
        raise
    except (ValueError, KeyError, TypeError, RecursionError):
        raise IntakeError("invalid_payload") from None
    digest = hashlib.sha256(raw).hexdigest()
    key = hashlib.sha256(
        b"intake-v1\0" + bytes.fromhex(digest) + bytes.fromhex(policy.digest)
    ).hexdigest()
    return JobIdentity(
        repo["full_name"], payload["number"], pr["head"]["sha"], digest, "intake-v1:" + key
    )


class IntakeStore:
    """Dedicated private namespace and durable session fence around unchanged enqueue.

    The explicit local path and its ancestors must stay under trusted operator
    custody. This is cooperative ownership, not containment of a hostile owner.
    """

    def __init__(self, directory: Path):
        self.directory = directory
        self._db = None
        self._lock_fd = None
        self._dir_fd = None
        self._marker_raw = None
        self._marker_identity = None
        self._closed = False
        self.poisoned = False
        self.refusal = "outcome_unknown"
        self._session = os.urandom(16).hex()
        try:
            self._prepare()
            self._activate()
            self._write_marker("active")
            # An active marker is durable before SQLite initialization or writes.
            self._db = JobStore(directory / DATABASE, busy_timeout_ms=1000)
            info = (directory / DATABASE).lstat()
            self._database_identity = (info.st_dev, info.st_ino)
        except BaseException as error:
            self.poisoned = True
            self._release()
            self._closed = True
            if isinstance(error, StoreError) and error.code == "busy":
                raise IntakeError("busy") from None
            if isinstance(error, Exception):
                code = error.code if isinstance(error, IntakeError) else "configuration_refused"
                raise IntakeError(code) from None
            raise

    def _prepare(self) -> None:
        import fcntl

        path = self.directory
        _need(isinstance(path, Path) and path.is_absolute() and len(os.fsencode(path)) <= 4096)
        # Check only named ancestors and fixed owned filenames, never list a directory.
        for parent in path.parents:
            _need(stat.S_ISDIR(parent.lstat().st_mode))
        created = False
        try:
            path.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
        info = path.lstat()
        _need(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700
        )
        self._directory_identity = (info.st_dev, info.st_ino)
        self._dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        if created:
            parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        self._lock_fd = os.open(path / LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        lock_info = os.fstat(self._lock_fd)
        _need(
            stat.S_ISREG(lock_info.st_mode)
            and lock_info.st_size == 0
            and lock_info.st_uid == os.geteuid()
            and stat.S_IMODE(lock_info.st_mode) == 0o600
        )
        self._lock_identity = (lock_info.st_dev, lock_info.st_ino)
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise IntakeError("busy") from None
        _need(not os.path.lexists(path / STAGING), "reconciliation_required")
        _need(not os.path.lexists(path / SESSION), "reconciliation_required")
        if created:
            _need(
                not any(
                    os.path.lexists(path / p)
                    for p in (
                        MARKER,
                        DATABASE,
                        DATABASE + "-journal",
                        DATABASE + "-wal",
                        DATABASE + "-shm",
                    )
                )
            )
            os.fsync(self._lock_fd)
            os.fsync(self._dir_fd)
        else:
            try:
                self._marker_raw = _bounded_file(path / MARKER, 1024, private=True)
                marker_info = (path / MARKER).lstat()
                self._marker_identity = (marker_info.st_dev, marker_info.st_ino)
                marker = parse_json_object(self._marker_raw)
                _need(set(marker) == {"version", "purpose", "database", "state", "session"})
                _need(type(marker["version"]) is int and marker["version"] == 1)
                _need(marker["purpose"] == "github-intake-only" and marker["database"] == DATABASE)
                _need(marker["state"] == "clean", "reconciliation_required")
                _need(
                    type(marker["session"]) is str
                    and re.fullmatch(r"[0-9a-f]{32}", marker["session"]) is not None
                )
                db_info = (path / DATABASE).lstat()
                _need(stat.S_ISREG(db_info.st_mode) and db_info.st_uid == os.geteuid())
                for suffix in ("-journal", "-wal", "-shm"):
                    p = path / (DATABASE + suffix)
                    if os.path.lexists(p):
                        _need(stat.S_ISREG(p.lstat().st_mode))
            except FileNotFoundError:
                raise IntakeError("configuration_refused") from None

    def _activate(self) -> None:
        fd = os.open(
            self.directory / SESSION, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            _need(os.write(fd, self._session.encode("ascii")) == 32, "outcome_unknown")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._dir_fd)

    def _ownership(self) -> None:
        info = self.directory.lstat()
        _need((info.st_dev, info.st_ino) == self._directory_identity)
        info = (self.directory / LOCK).lstat()
        _need((info.st_dev, info.st_ino) == self._lock_identity and stat.S_ISREG(info.st_mode))
        if self._marker_raw is None:
            _need(not os.path.lexists(self.directory / MARKER))
        else:
            info = (self.directory / MARKER).lstat()
            _need((info.st_dev, info.st_ino) == self._marker_identity)
            _need(_bounded_file(self.directory / MARKER, 1024, private=True) == self._marker_raw)
        if hasattr(self, "_database_identity"):
            info = (self.directory / DATABASE).lstat()
            _need((info.st_dev, info.st_ino) == self._database_identity)
        _need(
            _bounded_file(self.directory / SESSION, 32, private=True)
            == self._session.encode("ascii")
        )

    def _write_marker(self, state: str) -> None:
        self._ownership()
        raw = json.dumps(
            {
                "version": 1,
                "purpose": "github-intake-only",
                "database": DATABASE,
                "state": state,
                "session": self._session,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        fd = os.open(
            self.directory / STAGING, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            _need(os.write(fd, raw) == len(raw), "outcome_unknown")
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(self.directory / STAGING, self.directory / MARKER)
        self._marker_raw = raw
        info = (self.directory / MARKER).lstat()
        self._marker_identity = (info.st_dev, info.st_ino)
        os.fsync(self._dir_fd)

    def _poison(self, code: str = "outcome_unknown") -> None:
        self.poisoned = True
        self.refusal = code
        try:
            self._write_marker(
                "unknown" if code == "outcome_unknown" else "reconciliation_required"
            )
        except (OSError, ValueError):
            # The earlier durable active marker still prevents automatic resume.
            pass

    def retain(self, identity: JobIdentity) -> JobRecord:
        _need(not self._closed, "closed")
        _need(not self.poisoned, self.refusal)
        _need(
            type(identity) is JobIdentity
            and all(getattr(identity, p) is None for p in _REFERENCES),
            "invalid_payload",
        )
        try:
            self._ownership()
            record = self._db.enqueue(identity, now_ms=time.time_ns() // 1_000_000)
            if not (
                record.identity == identity
                and record.state is JobState.PENDING
                and record.generation == 0
                and record.lease_owner is None
                and record.lease_until_ms is None
                and record.error is None
                and record.finished_at_ms is None
                and record.tombstone is False
            ):
                self._poison("reconciliation_required")
                raise IntakeError("reconciliation_required")
            return record
        except IntakeError as error:
            if error.code == "reconciliation_required":
                raise
            self._poison()
            raise IntakeError("outcome_unknown") from None
        except StoreError as error:
            if error.code in {"busy", "capacity", "identity_conflict"}:
                raise IntakeError(error.code) from None
            if error.code == "time":
                self._poison("reconciliation_required")
                raise IntakeError("reconciliation_required") from None
            self._poison()
            raise IntakeError("outcome_unknown") from None
        # Unexpected storage diagnostics must not escape into protocol logging.
        except Exception:  # noqa: BLE001
            self._poison()
            raise IntakeError("outcome_unknown") from None
        except BaseException:
            self._poison()
            raise

    def _release(self, *, database: bool = True) -> None:
        try:
            if database and self._db is not None:
                self._db.close()
        finally:
            try:
                if self._lock_fd is not None:
                    os.close(self._lock_fd)
                    self._lock_fd = None
            finally:
                if self._dir_fd is not None:
                    os.close(self._dir_fd)
                    self._dir_fd = None

    def close(self) -> None:
        if self._closed:
            return
        database_closed = False
        try:
            if self._db is not None:
                self._db.close()
            database_closed = True
            if not self.poisoned:
                self._write_marker("clean")
                self._ownership()
                # Last namespace mutation, only after known DB close and durable clean.
                # No fsync after unlink: loss of this deletion only refuses restart.
                os.unlink(self.directory / SESSION)
        except Exception:  # noqa: BLE001
            self._poison()
            raise IntakeError("outcome_unknown") from None
        except BaseException:
            self._poison()
            raise
        finally:
            if database_closed:
                self._closed = True
                self._release(database=False)
            # Failed close retains the SQLite handle and cooperative lock. An
            # explicit later close may release custody, never retry an intake.


def _response(code: str) -> bytes:
    status, reason = _CATEGORIES[code]
    body = ('{"status":"' + code + '"}\n').encode("ascii")
    value = (
        f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + body
    _need(len(value) <= 1024)
    return value


def _headers(block: bytes) -> tuple[dict[str, str], int]:
    lines = block.split(b"\r\n")
    _need(
        lines[0] in (b"POST /github/intake HTTP/1.0", b"POST /github/intake HTTP/1.1"), "malformed"
    )
    _need(len(lines[0]) + 2 <= MAX_REQUEST_LINE, "too_large")
    _need(len(lines) - 1 <= MAX_HEADER_COUNT, "too_large")
    headers = {}
    for line in lines[1:]:
        _need(line and not line.startswith((b" ", b"\t")) and b":" in line, "malformed")
        name, value = line.split(b":", 1)
        _need(
            re.fullmatch(_TOKEN, name) is not None and all(c == 9 or 32 <= c <= 126 for c in value),
            "malformed",
        )
        name = name.decode("ascii").lower()
        _need(name not in headers, "malformed")
        headers[name] = value.strip(b" \t").decode("ascii")
    _need(
        not any(k in headers for k in ("transfer-encoding", "content-encoding", "expect")),
        "malformed",
    )
    length = headers.get("content-length", "")
    _need(re.fullmatch(r"[0-9]+", length, re.ASCII) is not None, "malformed")
    digits = length.lstrip("0") or "0"
    _need(len(digits) <= 6 and int(digits) <= MAX_BODY, "too_large")
    _need(
        re.fullmatch(
            r"application/json(?:[ \t]*;[ \t]*charset=utf-8)?",
            headers.get("content-type", ""),
            re.IGNORECASE | re.ASCII,
        )
        is not None,
        "malformed",
    )
    return headers, int(digits)


class _Connection(asyncio.Protocol):
    def __init__(self, owner: IntakeServer):
        self.owner = owner
        self.transport = None
        self.buffer = bytearray()
        self.headers = None
        self.body_start = None
        self.body_length = None
        self.done = False
        self.timer = None
        self.closed = owner.loop.create_future()

    def connection_made(self, transport: asyncio.Transport) -> None:
        self.transport = transport
        self.deadline = self.owner.loop.time() + READ_SECONDS
        self.owner.connections.add(self)
        if self.owner.closing or len(self.owner.active) >= MAX_CONNECTIONS:
            self.respond("busy")
            return
        self.owner.active.add(self)
        self.timer = self.owner.loop.call_at(self.deadline, self.respond, "deadline")

    def respond(self, code: str) -> None:
        if self.done:
            return
        self.done = True
        if self.timer is not None:
            self.timer.cancel()
        self.buffer.clear()
        try:
            self.transport.write(_response(code))
        except (ConnectionError, OSError):
            pass
        finally:
            self.transport.close()

    def data_received(self, data: bytes) -> None:
        if self.done:
            return
        try:
            _need(not self.owner.closing, "closed")
            _need(self.owner.loop.time() < self.deadline, "deadline")
            _need(
                len(self.buffer) + len(data) <= MAX_REQUEST_LINE + MAX_HEADERS + MAX_BODY,
                "too_large",
            )
            self.buffer.extend(data)
            if self.headers is None:
                first = self.buffer.find(b"\r\n")
                _need(
                    first < MAX_REQUEST_LINE
                    if first >= 0
                    else len(self.buffer) <= MAX_REQUEST_LINE,
                    "too_large",
                )
                end = self.buffer.find(b"\r\n\r\n")
                if end < 0:
                    if first >= 0:
                        _need(len(self.buffer) - first - 2 <= MAX_HEADERS, "too_large")
                    return
                self.body_start = end + 4
                _need(self.body_start - first - 2 <= MAX_HEADERS, "too_large")
                self.headers, self.body_length = _headers(bytes(self.buffer[:end]))
            total = self.body_start + self.body_length
            _need(len(self.buffer) <= total, "malformed")
            if len(self.buffer) < total:
                return
            _need(self.owner.loop.time() < self.deadline, "deadline")
            identity = authenticated_identity(
                bytes(self.buffer[self.body_start :]),
                self.headers,
                self.owner.secret,
                self.owner.policy,
            )
            self.owner.store.retain(identity)
            self.respond("retained")
        except IntakeError as error:
            self.respond(error.code)
        finally:
            if self.owner.store.poisoned:
                self.owner.stop()

    def eof_received(self) -> bool:
        if not self.done:
            self.respond("malformed")
        return False

    def connection_lost(self, _error: Exception | None) -> None:
        self.done = True
        self.buffer.clear()
        if self.timer is not None:
            self.timer.cancel()
        self.owner.active.discard(self)
        self.owner.connections.discard(self)
        if not self.closed.done():
            self.closed.set_result(None)


class IntakeServer:
    """One loop owns every socket, protocol, timer and the dedicated store."""

    def __init__(self, policy: IntakePolicy, secret: bytes, store: IntakeStore):
        self.loop = asyncio.get_running_loop()
        self.policy = policy
        self.secret = secret
        self.store = store
        self.connections = set()
        self.active = set()
        self.closing = False
        self.server = None
        self.stopped = self.loop.create_future()

    @property
    def port(self) -> int:
        return self.server.sockets[0].getsockname()[1]

    def stop(self) -> None:
        self.closing = True
        if self.server is not None:
            self.server.close()
        for connection in tuple(self.connections):
            connection.respond(self.store.refusal if self.store.poisoned else "closed")
        if not self.stopped.done():
            self.stopped.set_result(None)

    async def close(self) -> None:
        self.stop()
        connections = tuple(self.connections)
        for connection in connections:
            connection.transport.abort()
        try:
            if self.server is not None:
                await self.server.wait_closed()
            if connections:
                await asyncio.gather(*(c.closed for c in connections))
        finally:
            self.secret = b""
            self.store.close()


async def start_server(
    *, policy: IntakePolicy, secret_file: Path, intake_directory: Path, port: int = 0
) -> IntakeServer:
    _need(type(port) is int and 0 <= port <= 65535 and type(policy) is IntakePolicy)
    policy.__post_init__()
    secret = read_secret(secret_file)
    store = IntakeStore(intake_directory)
    owner = IntakeServer(policy, secret, store)
    try:
        owner.server = await owner.loop.create_server(
            lambda: _Connection(owner),
            host="127.0.0.1",
            port=port,
            family=2,
            backlog=MAX_CONNECTIONS,
        )
        return owner
    except OSError:
        await owner.close()
        raise IntakeError("configuration_refused") from None
    except BaseException:
        await owner.close()
        raise


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.exit(2, "configuration_refused\n")


def _configuration(args: argparse.Namespace) -> IntakePolicy:
    try:
        _need(0 <= args.port <= 65535)
        _need(Path(args.secret_file).is_absolute() and Path(args.intake_directory).is_absolute())
        _need(1 <= len(args.repository) <= 64 and 1 <= len(args.sender_id) <= 256)
        pairs = []
        for value in args.repository:
            name, number = value.split(":")
            _need(re.fullmatch(r"[0-9]{1,19}", number) is not None)
            pairs.append((name, int(number)))
        _need(all(re.fullmatch(r"[0-9]{1,19}", i) is not None for i in args.sender_id))
        return IntakePolicy(tuple(pairs), tuple(int(i) for i in args.sender_id))
    except (ValueError, TypeError):
        raise IntakeError("configuration_refused") from None


async def _serve(args: argparse.Namespace, policy: IntakePolicy) -> int:
    owner = await start_server(
        policy=policy,
        secret_file=Path(args.secret_file),
        intake_directory=Path(args.intake_directory),
        port=args.port,
    )
    previous = {}
    try:
        for signum in (signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            owner.loop.add_signal_handler(signum, owner.stop)
        await owner.stopped
    finally:
        try:
            await owner.close()
        finally:
            for signum, handler in previous.items():
                owner.loop.remove_signal_handler(signum)
                signal.signal(signum, handler)
    return int(owner.store.poisoned)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    for command in ("validate", "serve"):
        child = commands.add_parser(command)
        child.add_argument("--secret-file", required=True)
        child.add_argument("--intake-directory", required=True)
        child.add_argument("--repository", action="append", required=True, metavar="NAME:ID")
        child.add_argument("--sender-id", action="append", required=True)
        child.add_argument("--port", type=int, default=0)
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    try:
        policy = _configuration(args)
        if args.command == "validate":
            print("configuration_valid")
            return 0
        return asyncio.run(_serve(args, policy))
    except IntakeError as error:
        print(error.code)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
