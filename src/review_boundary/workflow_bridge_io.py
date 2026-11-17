"""Fixed, private, data-only workflow bundles under a trusted local parent.

Successful inspection establishes present consistency only. It cannot reconcile
an earlier unknown writer outcome or authorize a consumer. See the companion
workflow-bridge-io document for the trust assumptions and error mapping.
"""

import os
import stat
from dataclasses import dataclass
from io import FileIO
from pathlib import Path
from typing import Literal

from .json_input import parse_json_object
from .workflow_cases import (
    MAX_BRIDGE_BYTES,
    WorkflowCase,
    WorkflowLimits,
    WorkflowRunBinding,
    bounded_json,
    byte_digest,
    canonical_bytes,
    checked,
    validate_workflow_case,
    workflow_case_digest,
)
from .workflow_replay import replay_workflow
from .workflow_world import WorkflowSnapshot, restore_workflow_bridge, seal_workflow_bridge

__all__ = [
    "ReopenedWorkflowBridge",
    "WorkflowBridgeIOError",
    "reopen_workflow_bridge",
    "write_workflow_bridge",
]

Code = Literal["unsupported", "invalid", "path", "exists", "incomplete", "binding", "io_unknown"]
Phase = Literal["validate", "create", "write", "sync", "close", "reopen", "read", "verify"]
_CODES = {"unsupported", "invalid", "path", "exists", "incomplete", "binding", "io_unknown"}
_PHASES = {"validate", "create", "write", "sync", "close", "reopen", "read", "verify"}
_NAMES = ("producer.json", "bridge.json", "complete.json")
_DATA_ERRORS = (ValueError, TypeError, AttributeError, UnicodeError, RecursionError, OverflowError)


class WorkflowBridgeIOError(Exception):
    """Fixed diagnostics; _unclosed retains original resources for caller custody.

    A resource in _unclosed lacks an observed successful close. An interruption
    may precede its close call. This module never retries an attempted close,
    adopts a descriptor, or treats uncertain custody as resolved.
    """

    def __init__(self, code: Code, phase: Phase):
        if type(code) is not str or code not in _CODES:
            code = "invalid"
        if type(phase) is not str or phase not in _PHASES:
            phase = "validate"
        self.code, self.phase = code, phase
        self._unclosed = ()
        super().__init__(code, phase)

    def __str__(self):
        return f"workflow_bridge_io:{self.code}:{self.phase}"

    def __repr__(self):
        return f"WorkflowBridgeIOError({self.code!r}, {self.phase!r})"


@dataclass(frozen=True, slots=True)
class ReopenedWorkflowBridge:
    raw_bridge: bytes
    producer_snapshot: WorkflowSnapshot


@dataclass(frozen=True, slots=True)
class _Expected:
    case: WorkflowCase
    snapshot: WorkflowSnapshot
    binding: WorkflowRunBinding
    guard: Literal["on", "off"]
    limits: WorkflowLimits
    producer: bytes
    bridge: bytes
    complete: bytes


def _data(phase, function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except _DATA_ERRORS:
        raise WorkflowBridgeIOError("invalid", phase) from None


def _revalidate(model, value):
    # JSON serialization of an unchecked strict-int field can coerce True to 1.
    # Validate the Python representation first, including nested model fields.
    return model.model_validate(value.model_dump(mode="python", warnings=False))


def _expected(case, producer_snapshot, binding, guard, limits):
    if (
        not isinstance(case, WorkflowCase)
        or not isinstance(producer_snapshot, WorkflowSnapshot)
        or not isinstance(binding, WorkflowRunBinding)
        or not isinstance(limits, WorkflowLimits)
        or type(guard) is not str
        or guard not in ("on", "off")
    ):
        raise WorkflowBridgeIOError("invalid", "validate")
    case = _data(
        "validate", validate_workflow_case, _data("validate", _revalidate, WorkflowCase, case)
    )
    binding = _data(
        "validate",
        checked,
        WorkflowRunBinding,
        _data("validate", _revalidate, WorkflowRunBinding, binding),
    )
    limits = _data(
        "validate", checked, WorkflowLimits, _data("validate", _revalidate, WorkflowLimits, limits)
    )
    source = _data(
        "validate",
        checked,
        WorkflowSnapshot,
        _data("validate", _revalidate, WorkflowSnapshot, producer_snapshot),
        maximum=limits.max_trace_bytes,
    )
    if len(case.sessions) != 2 or case.bridge_kind not in ("memory", "handoff"):
        raise WorkflowBridgeIOError("invalid", "validate")
    if (
        source.workflow_case_sha256 != workflow_case_digest(case)
        or source.session_index != 0
        or source.binding != binding
        or source.guard != guard
        or source.limits != limits
    ):
        raise WorkflowBridgeIOError("binding", "validate")
    replay = _data(
        "validate",
        replay_workflow,
        case,
        (source,),
        expected_guard=guard,
        expected_binding=binding,
        expected_limits=limits,
    )
    source = replay.snapshots[0]
    if (
        not replay.request_replay_complete
        or not source.completed
        or source.fatal_error is not None
        or not source.notes
        or not source.events
        or source.events[-1].tool != "submit_review"
        or source.events[-1].status != "ok"
    ):
        raise WorkflowBridgeIOError("incomplete", "validate")
    raw = _data(
        "validate", seal_workflow_bridge, case, source, binding=binding, guard=guard, limits=limits
    )
    producer = _data("validate", canonical_bytes, source, maximum=limits.max_trace_bytes)
    complete = _data(
        "validate",
        bounded_json,
        {
            "bundle_version": 1,
            "state": "data_files_closed",
            "workflow_case_sha256": workflow_case_digest(case),
            "binding": binding.model_dump(mode="json"),
            "guard": guard,
            "limits": limits.model_dump(mode="json"),
            "producer_session": 0,
            "consumer_session": 1,
            "producer_snapshot_bytes": len(producer),
            "producer_snapshot_sha256": byte_digest(producer),
            "bridge_bytes": len(raw),
            "bridge_sha256": byte_digest(raw),
        },
        maximum=4096,
        nodes=512,
        depth=8,
    )
    return _Expected(case, source, binding, guard, limits, producer, raw, complete)


class _Directory:
    def __init__(self, fd):
        self.fd = fd

    def close(self):
        if self.fd is not None:
            os.close(self.fd)


class _Owned:
    def __init__(self, resource):
        self.resource = resource
        self.attempted = False
        self.closed = False


class _Resources:
    """Keep each acquired original, including failed closers, independently."""

    def __init__(self, phase):
        self.phase = phase
        self.owned = []

    @property
    def unclosed(self):
        # Attempt bookkeeping is not an observation of successful closure.
        return [
            owner.resource
            for owner in reversed(self.owned)
            if owner.resource is not None and not owner.closed
        ]

    def __enter__(self):
        return self

    def keep(self, resource):
        owner = _Owned(resource)
        self.owned.append(owner)
        return owner

    def open_file(self, directory, name, mode):
        # Retain the actual original before it can acquire a descriptor. A
        # helper-return interruption must not lose an already opened FileIO.
        owner = self.keep(FileIO.__new__(FileIO))
        _open_file(directory, name, mode, owner=owner)
        return owner

    def close(self, owner):
        if owner.attempted:
            raise AssertionError("owned close already attempted")
        self.phase = "close"
        owner.attempted = True
        if owner.resource is not None:
            owner.resource.close()
        owner.closed = True

    def __exit__(self, _kind, error, _traceback):
        interruption = error if error is not None and not isinstance(error, Exception) else None
        close_failed = False
        phase = self.phase
        for owner in reversed(self.owned):
            if not owner.attempted:
                try:
                    self.close(owner)
                except BaseException as cleanup_error:  # noqa: BLE001
                    # Finish independent owned cleanup, then propagate interruption.
                    close_failed = True
                    if not isinstance(cleanup_error, Exception) and interruption is None:
                        interruption = cleanup_error
        close_failed = close_failed or bool(self.unclosed)
        if interruption is not None:
            interruption._workflow_bridge_unclosed = tuple(self.unclosed)
            raise interruption from None
        if close_failed:
            failure = WorkflowBridgeIOError("io_unknown", "close")
        elif error is None:
            return False
        elif isinstance(error, WorkflowBridgeIOError):
            failure = error
        else:
            failure = WorkflowBridgeIOError("io_unknown", phase)
        failure._unclosed = tuple(self.unclosed)
        raise failure from None


def _supported():
    if (
        os.name != "posix"
        or not callable(getattr(os, "geteuid", None))
        or any(not getattr(os, flag, 0) for flag in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK"))
        or any(fn not in os.supports_dir_fd for fn in (os.open, os.stat, os.mkdir))
        or os.stat not in os.supports_follow_symlinks
        or os.listdir not in os.supports_fd
    ):
        raise WorkflowBridgeIOError("unsupported", "validate")


def _identity(info):
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink


def _file_identity(info):
    return _identity(info), info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _directory(info, phase, *, private):
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or private
        and stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise WorkflowBridgeIOError("path", phase)


def _parent_path(directory):
    _supported()
    if (
        not isinstance(directory, Path)
        or not directory.is_absolute()
        or ".." in directory.parts
        or not directory.name
        or "\0" in str(directory)
    ):
        raise WorkflowBridgeIOError("path", "validate")
    # Do not resolve aliases: every supplied ancestor must already be physical.
    for ancestor in reversed(directory.parents):
        try:
            info = ancestor.lstat()
        except OSError:
            raise WorkflowBridgeIOError("path", "validate") from None
        if not stat.S_ISDIR(info.st_mode):
            raise WorkflowBridgeIOError("path", "validate")
    _directory(info, "validate", private=False)


def _open_directory(resources, path, *, dir_fd=None):
    # The descriptor's original wrapper is owned before it acquires anything.
    owner = resources.keep(_Directory(None))
    owner.resource.fd = os.open(
        path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd
    )
    return owner


def _stat(directory, name):
    return os.stat(name, dir_fd=directory.resource.fd, follow_symlinks=False)


def _file(info, maximum, phase):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o600
        or info.st_nlink != 1
    ):
        raise WorkflowBridgeIOError("path", phase)
    if not 0 <= info.st_size <= maximum:
        raise WorkflowBridgeIOError("invalid", phase)


def _open_file(directory, name, mode, *, owner):
    def opener(path, flags):
        return os.open(
            path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory.resource.fd
        )

    # Initialize the already retained original, without a buffered payload.
    file = owner.resource
    file.__init__(name, mode, opener=opener)
    return file


def _match_file(directory, name, owner, initial, maximum, phase):
    descriptor = os.fstat(owner.resource.fileno())
    path = _stat(directory, name)
    _file(descriptor, maximum, phase)
    _file(path, maximum, phase)
    if _file_identity(initial) != _file_identity(descriptor) or descriptor != path:
        raise WorkflowBridgeIOError("io_unknown", phase)


def _write_file(resources, directory, name, raw):
    resources.phase = "create"
    owner = resources.open_file(directory, name, "xb")
    info = _stat(directory, name)
    _match_file(directory, name, owner, info, len(raw), "create")
    if info.st_size != 0:
        raise WorkflowBridgeIOError("io_unknown", "create")
    resources.phase = "write"
    count = owner.resource.write(raw)
    if type(count) is not int or count != len(raw):
        raise WorkflowBridgeIOError("io_unknown", "write")
    owner.resource.flush()
    resources.phase = "sync"
    os.fsync(owner.resource.fileno())
    info = _stat(directory, name)
    _match_file(directory, name, owner, info, len(raw), "sync")
    if info.st_size != len(raw):
        raise WorkflowBridgeIOError("io_unknown", "sync")
    resources.close(owner)


def _sync_directory(resources, directory):
    resources.phase = "sync"
    os.fsync(directory.resource.fd)


def write_workflow_bridge(
    directory: Path,
    *,
    case: WorkflowCase,
    producer_snapshot: WorkflowSnapshot,
    binding: WorkflowRunBinding,
    guard: Literal["on", "off"],
    limits: WorkflowLimits,
) -> ReopenedWorkflowBridge:
    """Create once, close/sync, then validate new independent read handles."""
    expected = _expected(case, producer_snapshot, binding, guard, limits)
    _parent_path(directory)
    with _Resources("create") as resources:
        parent = _open_directory(resources, directory.parent)
        parent_info = directory.parent.lstat()
        _directory(parent_info, "create", private=False)
        if _identity(os.fstat(parent.resource.fd)) != _identity(parent_info):
            raise WorkflowBridgeIOError("path", "create")
        try:
            _stat(parent, directory.name)
        except FileNotFoundError:
            pass
        else:
            raise WorkflowBridgeIOError("exists", "create")
        try:
            os.mkdir(directory.name, 0o700, dir_fd=parent.resource.fd)
        except FileExistsError:
            raise WorkflowBridgeIOError("exists", "create") from None
        info = _stat(parent, directory.name)
        _directory(info, "create", private=True)
        leaf = _open_directory(resources, directory.name, dir_fd=parent.resource.fd)
        if _identity(os.fstat(leaf.resource.fd)) != _identity(info):
            raise WorkflowBridgeIOError("io_unknown", "create")
        _write_file(resources, leaf, _NAMES[0], expected.producer)
        _write_file(resources, leaf, _NAMES[1], expected.bridge)
        _sync_directory(resources, leaf)
        _write_file(resources, leaf, _NAMES[2], expected.complete)
        _sync_directory(resources, leaf)
    return reopen_workflow_bridge(
        directory,
        case=expected.case,
        producer_snapshot=expected.snapshot,
        binding=expected.binding,
        guard=expected.guard,
        limits=expected.limits,
    )


def _roster(directory):
    names = set(os.listdir(directory.resource.fd))
    if names - set(_NAMES):
        raise WorkflowBridgeIOError("invalid", "reopen")
    if names != set(_NAMES):
        raise WorkflowBridgeIOError("incomplete", "reopen")


def _read_file(resources, directory, name, owner, info, maximum):
    resources.phase = "read"
    _match_file(directory, name, owner, info, maximum, "read")
    raw = owner.resource.read(info.st_size + 1)
    eof = owner.resource.read(1)
    if type(raw) is not bytes or type(eof) is not bytes:
        raise WorkflowBridgeIOError("io_unknown", "read")
    if len(raw) < info.st_size:
        raise WorkflowBridgeIOError("incomplete", "read")
    if len(raw) != info.st_size or eof != b"":
        raise WorkflowBridgeIOError("invalid", "read")
    _match_file(directory, name, owner, info, maximum, "read")
    resources.close(owner)
    return raw


def _complete(raw, expected):
    value = _data("verify", parse_json_object, _data("verify", bytes.decode, raw, "utf-8"))
    canonical = _data("verify", bounded_json, value, maximum=4096, nodes=512, depth=8)
    reference = parse_json_object(expected.complete)
    if raw != canonical or set(value) != set(reference):
        raise WorkflowBridgeIOError("invalid", "verify")
    for name in ("bundle_version", "producer_session", "consumer_session"):
        if type(value[name]) is not int or value[name] != reference[name]:
            raise WorkflowBridgeIOError("invalid", "verify")
    for name, maximum in (
        ("producer_snapshot_bytes", expected.limits.max_trace_bytes),
        ("bridge_bytes", MAX_BRIDGE_BYTES),
    ):
        if type(value[name]) is not int or not 1 <= value[name] <= maximum:
            raise WorkflowBridgeIOError("invalid", "verify")
    for name in ("workflow_case_sha256", "producer_snapshot_sha256", "bridge_sha256"):
        digest = value[name]
        if (
            type(digest) is not str
            or len(digest) != 64
            or any(c not in "0123456789abcdef" for c in digest)
        ):
            raise WorkflowBridgeIOError("invalid", "verify")
    if value["state"] != "data_files_closed" or value["guard"] not in ("on", "off"):
        raise WorkflowBridgeIOError("invalid", "verify")
    for name, model in (("binding", WorkflowRunBinding), ("limits", WorkflowLimits)):
        normalized = _data("verify", checked, model, value[name]).model_dump(mode="json")
        if normalized != value[name]:
            raise WorkflowBridgeIOError("invalid", "verify")
    if value != reference:
        raise WorkflowBridgeIOError("binding", "verify")


def reopen_workflow_bridge(
    directory: Path,
    *,
    case: WorkflowCase,
    producer_snapshot: WorkflowSnapshot,
    binding: WorkflowRunBinding,
    guard: Literal["on", "off"],
    limits: WorkflowLimits,
) -> ReopenedWorkflowBridge:
    """Inspect present data without resolving writer history or authorizing work."""
    expected = _expected(case, producer_snapshot, binding, guard, limits)
    _parent_path(directory)
    with _Resources("reopen") as resources:
        try:
            initial = directory.lstat()
        except FileNotFoundError:
            raise WorkflowBridgeIOError("incomplete", "reopen") from None
        _directory(initial, "reopen", private=True)
        leaf = _open_directory(resources, directory)
        if _identity(initial) != _identity(os.fstat(leaf.resource.fd)):
            raise WorkflowBridgeIOError("io_unknown", "reopen")
        _roster(leaf)
        caps = (expected.limits.max_trace_bytes, MAX_BRIDGE_BYTES, 4096)
        infos = {name: _stat(leaf, name) for name in _NAMES}
        # All metadata is checked before opening or reading any payload.
        for name, cap in zip(_NAMES, caps):
            _file(infos[name], cap, "reopen")
        readers = {}
        for name, cap in zip(_NAMES, caps):
            owner = resources.open_file(leaf, name, "rb")
            readers[name] = owner
            _match_file(leaf, name, owner, infos[name], cap, "reopen")
        complete = _read_file(
            resources, leaf, _NAMES[2], readers[_NAMES[2]], infos[_NAMES[2]], 4096
        )
        resources.phase = "verify"
        _complete(complete, expected)
        producer = _read_file(
            resources, leaf, _NAMES[0], readers[_NAMES[0]], infos[_NAMES[0]], caps[0]
        )
        snapshot = _data("verify", checked, WorkflowSnapshot, producer, maximum=caps[0], wire=True)
        if producer != expected.producer or byte_digest(producer) != byte_digest(expected.producer):
            raise WorkflowBridgeIOError("binding", "verify")
        raw = _read_file(
            resources, leaf, _NAMES[1], readers[_NAMES[1]], infos[_NAMES[1]], MAX_BRIDGE_BYTES
        )
        resources.phase = "verify"
        if raw != expected.bridge or byte_digest(raw) != byte_digest(expected.bridge):
            raise WorkflowBridgeIOError("binding", "verify")
        _data(
            "verify",
            restore_workflow_bridge,
            expected.case,
            1,
            raw,
            binding=expected.binding,
            guard=expected.guard,
            producer_snapshot=snapshot,
            limits=expected.limits,
        )
        _roster(leaf)
        for name, cap in zip(_NAMES, caps):
            if _file_identity(_stat(leaf, name)) != _file_identity(infos[name]):
                raise WorkflowBridgeIOError("io_unknown", "verify")
        final = directory.lstat()
        if _identity(final) != _identity(initial) or _identity(
            os.fstat(leaf.resource.fd)
        ) != _identity(initial):
            raise WorkflowBridgeIOError("io_unknown", "verify")
        return ReopenedWorkflowBridge(raw, snapshot)
