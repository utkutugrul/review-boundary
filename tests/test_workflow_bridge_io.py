"""Real local-file controls, runnable with stdlib unittest and no plugins."""

import gc
import inspect
import json
import os
import stat
import sys
import tempfile
import unittest
import weakref
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

# This module selects only the checked-out Source, without discovering SDK tests.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from review_boundary import workflow_bridge_io as bridge
from review_boundary.workflow_cases import (
    WorkflowJSONResourceError,
    WorkflowLimits,
    WorkflowRunBinding,
    bounded_json,
    build_workflow_cases,
    byte_digest,
    canonical_bytes,
    checked,
    validate_workflow_case,
    workflow_tool_schemas,
)
from review_boundary.workflow_replay import replay_workflow
from review_boundary.workflow_world import (
    WorkflowSessionWorld,
    WorkflowSnapshot,
    restore_workflow_bridge,
    seal_workflow_bridge,
)

INERT = "__import__('os').system('touch never-execute-this-note')"


def source_line(function, statement):
    lines, first = inspect.getsourcelines(function)
    matches = [first + index for index, line in enumerate(lines) if line.strip() == statement]
    if len(matches) != 1:
        raise AssertionError("ambiguous current Source boundary")
    return matches[0]


def producer(case, binding, limits, guard="on", notes=None, *, submit=True):
    world = WorkflowSessionWorld(case, 0, guard, binding=binding, limits=limits)
    world.record_tool_delivery(workflow_tool_schemas(case, 0))
    note = world.dispatch("read_work_item", {})["text"]
    world.dispatch("read_pr", {})
    for text in notes if notes is not None else (note, INERT):
        result = world.dispatch(
            "remember_note" if case.bridge_kind == "memory" else "write_handoff", {"text": text}
        )
        if result["status"] != "ok":
            raise AssertionError("fixture note refused")
    if submit:
        result = world.dispatch("submit_review", {"verdict": "approve", "findings": []})
        if result["status"] != "ok":
            raise AssertionError("fixture submission refused")
    snapshot = checked(WorkflowSnapshot, world.snapshot())
    replay_workflow(
        case, (snapshot,), expected_guard=guard, expected_binding=binding, expected_limits=limits
    )
    return snapshot


class Witness:
    """Instrument the actual acquired FileIO objects, retaining them for assertions.

    Faults call the real operation on the requested side of a failure. Cleanup
    after assertions is explicit test-caller custody, using the original object.
    No test adopts a saved descriptor or substitutes an in-memory data stream.
    """

    def __init__(
        self, fault=None, *, interrupt=False, short=False, truncated=False, trailing=False
    ):
        self.fault = fault
        self.interrupt = interrupt
        self.short, self.truncated, self.trailing = short, truncated, trailing
        self.events, self.files, self.originals = [], [], []
        self.original_calls = []
        self.failed = False
        self.directory_syncs = 0
        self.open_file = bridge._open_file
        self.fsync = os.fsync

    def hit(self, label, operation, side):
        self.events.append((label, operation, side))
        if not self.failed and self.fault == (label, operation, side):
            self.failed = True
            if self.interrupt:
                raise KeyboardInterrupt()
            raise OSError("DO_NOT_EXPOSE_PRIVATE_ERROR")

    def open(self, directory, name, mode, *, owner):
        label = name + ":" + mode
        self.hit(label, "open", "before")
        file = owner.resource
        self.files.append((label, file))
        original = {key: getattr(file, key) for key in ("write", "read", "flush", "close")}
        self.originals.append((file, original))
        read_count = 0

        def operation(key, *args):
            nonlocal read_count
            event = key
            if key == "read":
                read_count += 1
                event = "read" if read_count == 1 else "eof"
            self.hit(label, event, "before")
            if (
                key == "read"
                and label == "producer.json:rb"
                and (self.truncated and read_count == 1 or self.trailing and read_count == 2)
            ):
                # Mutate the real file after the product's pre-read fstat.
                # This is a separate test-owned writer, never an adopted FD.
                def opener(path, flags):
                    return os.open(path, flags | os.O_NOFOLLOW, dir_fd=directory.resource.fd)

                with open(name, "r+b", buffering=0, opener=opener) as mutator:
                    if self.truncated:
                        mutator.truncate(os.fstat(mutator.fileno()).st_size - 1)
                    else:
                        mutator.seek(0, os.SEEK_END)
                        mutator.write(b"x")
            if key == "write" and self.short and not self.failed:
                self.failed = True
                args = (args[0][:7],)
            self.original_calls.append((label, event, "call"))
            result = original[key](*args)
            self.original_calls.append((label, event, "return"))
            self.hit(label, event, "after")
            return result

        for key in original:
            setattr(file, key, lambda *args, key=key: operation(key, *args))
        self.open_file(directory, name, mode, owner=owner)
        return file

    def sync(self, fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            self.directory_syncs += 1
            label = "directory" + str(self.directory_syncs)
        else:
            label = next(
                label for label, file in self.files if not file.closed and file.fileno() == fd
            )
        self.hit(label, "fsync", "before")
        self.fsync(fd)
        self.hit(label, "fsync", "after")

    def __enter__(self):
        self.open_patch = patch.object(bridge, "_open_file", self.open)
        self.sync_patch = patch.object(bridge.os, "fsync", self.sync)
        self.open_patch.start()
        self.sync_patch.start()
        return self

    def __exit__(self, *args):
        self.open_patch.stop()
        self.sync_patch.stop()

    def assert_disposition(self, test, error=None):
        unclosed = getattr(error, "_unclosed", getattr(error, "_workflow_bridge_unclosed", ()))
        for label, file in self.files:
            test.assertEqual(self.events.count((label, "close", "before")), 1, label)
            if file in unclosed:
                test.assertTrue(any(file is resource for resource in unclosed))
            else:
                test.assertTrue(file.closed, label)

    def retire_custody(self):
        for file, original in self.originals:
            for key, function in original.items():
                setattr(file, key, function)
            if not file.closed:
                original["close"]()


class TraceWitness(Witness):
    """One deterministic trace injection plus real original-operation evidence."""

    def __init__(
        self, function, statement=None, *, event="line", failure=KeyboardInterrupt, fault=None
    ):
        super().__init__(fault, interrupt=True)
        self.function, self.event, self.failure = function, event, failure
        self.line = source_line(function, statement) if statement else None
        self.fired, self.directories = [], []
        self.prior = sys.gettrace()

    def __enter__(self):
        super().__enter__()
        original = bridge._Directory.close

        def close(resource):
            self.directories.append(resource)
            original(resource)

        self.directory_patch = patch.object(bridge._Directory, "close", close)
        self.directory_patch.start()
        return self

    def arm(self, predicate):
        self.predicate = predicate
        sys.settrace(self.trace)

    def trace(self, frame, event, _argument):
        if (
            frame.f_code is self.function.__code__
            and event == self.event
            and not self.fired
            and (self.line is None or frame.f_lineno == self.line)
            and self.predicate(frame.f_locals)
        ):
            owner = frame.f_locals.get("owner")
            resource = owner.resource if owner else frame.f_locals.get("resource")
            acquired = (
                resource.fd is not None
                if isinstance(resource, bridge._Directory)
                else resource is not None and not resource.closed
            )
            self.fired.append({"event": event, "line": frame.f_lineno, "acquired": acquired})
            raise self.failure()
        return self.trace

    def __exit__(self, *args):
        sys.settrace(self.prior)
        self.directory_patch.stop()
        super().__exit__(*args)

    def record(self, label, error):
        custody = getattr(error, "_workflow_bridge_unclosed", getattr(error, "_unclosed", ()))
        files = [
            {
                "label": label,
                "closed_after_product": file.closed,
                "actual_close_calls": self.original_calls.count((label, "close", "call")),
                "actual_close_returns": self.original_calls.count((label, "close", "return")),
                "retained_by_identity": any(resource is file for resource in custody),
            }
            for label, file in self.files
        ]
        if len({id(resource) for resource in self.directories}) != len(self.directories):
            raise AssertionError("original directory close retried")
        row = {
            "control": label,
            "injection": self.fired,
            "files": files,
            "original_operation_order": self.original_calls,
            # Wrapper entries, without an independent kernel-success observation.
            "directory_close_wrapper_entries": len(self.directories),
            "custody_count": len(custody),
            "interruption": isinstance(error, KeyboardInterrupt),
            "open_witnessed_fileio_before_test_caller_cleanup": sum(
                not file.closed for _, file in self.files
            ),
        }
        self.retire_custody()
        if not all(file.closed for _, file in self.files):
            raise AssertionError("test caller cleanup failed")
        row["all_witnessed_fileio_closed_after_test_caller_cleanup"] = True
        print(json.dumps(row, sort_keys=True))


class WorkflowBridgeIOTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = build_workflow_cases()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        # Darwin's default /var alias is a symlink. The caller supplies the
        # already physical parent; the product must never normalize an alias.
        self.parent = Path(self.temporary.name).resolve(strict=True)
        self.addCleanup(self.temporary.cleanup)
        self.case = self.select()
        self.binding = WorkflowRunBinding(run_id="b" * 32, reviewer="file_test", epoch=1)
        self.limits = WorkflowLimits()
        self.snapshot = producer(self.case, self.binding, self.limits)
        self.directory = self.parent / "bundle"

    def select(self, kind="memory", condition="clean"):
        return next(
            case
            for case in self.cases
            if case.bridge_kind == kind
            and case.condition == condition
            and case.repository.variant == "fixed"
        )

    def arguments(self, **overrides):
        result = {
            "case": self.case,
            "producer_snapshot": self.snapshot,
            "binding": self.binding,
            "guard": "on",
            "limits": self.limits,
        }
        result.update(overrides)
        return result

    def write(self, directory=None, **overrides):
        return bridge.write_workflow_bridge(
            directory or self.directory, **self.arguments(**overrides)
        )

    def reopen(self, **overrides):
        return bridge.reopen_workflow_bridge(self.directory, **self.arguments(**overrides))

    def error(self, function, code, phase=None):
        with self.assertRaises(bridge.WorkflowBridgeIOError) as raised:
            function()
        error = raised.exception
        self.assertEqual(error.code, code)
        if phase is not None:
            self.assertEqual(error.phase, phase)
        self.assertNotIn("DO_NOT_EXPOSE", str(error) + repr(error))
        return error

    def sidecar(self, mutate=None):
        path = self.directory / "complete.json"
        value = json.loads(path.read_bytes())
        if mutate:
            mutate(value)
            path.write_bytes(canonical_bytes(value))
        return value

    def rehash(self):
        def mutate(value):
            for filename, prefix in (
                ("producer.json", "producer_snapshot"),
                ("bridge.json", "bridge"),
            ):
                raw = (self.directory / filename).read_bytes()
                value[prefix + "_bytes"] = len(raw)
                value[prefix + "_sha256"] = byte_digest(raw)

        self.sidecar(mutate)

    def test_real_memory_handoff_controls_and_consumer_restoration(self):
        for kind in ("memory", "handoff"):
            for condition in ("clean", "attack", "authorized_control"):
                with self.subTest(kind=kind, condition=condition):
                    case = self.select(kind, condition)
                    snapshot = producer(case, self.binding, self.limits)
                    directory = self.parent / (kind + condition)
                    result = self.write(directory, case=case, producer_snapshot=snapshot)
                    raw = seal_workflow_bridge(
                        case, snapshot, binding=self.binding, guard="on", limits=self.limits
                    )
                    self.assertEqual(result.raw_bridge, raw)
                    self.assertEqual((directory / "bridge.json").read_bytes(), raw)
                    self.assertEqual(
                        (directory / "producer.json").read_bytes(), canonical_bytes(snapshot)
                    )
                    self.assertIsNot(result.producer_snapshot, snapshot)
                    self.assertEqual(result.producer_snapshot, snapshot)
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                    self.assertEqual({p.name for p in directory.iterdir()}, set(bridge._NAMES))
                    for path in directory.iterdir():
                        info = path.lstat()
                        self.assertTrue(stat.S_ISREG(info.st_mode))
                        self.assertEqual(
                            (stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink),
                            (0o600, os.geteuid(), 1),
                        )
                    restored = restore_workflow_bridge(
                        case,
                        1,
                        result.raw_bridge,
                        binding=self.binding,
                        guard="on",
                        producer_snapshot=result.producer_snapshot,
                        limits=self.limits,
                    )
                    self.assertEqual(restored.entries, snapshot.notes)
                    world = WorkflowSessionWorld(
                        case,
                        1,
                        binding=self.binding,
                        limits=self.limits,
                        bridge=result.raw_bridge,
                        producer_snapshot=result.producer_snapshot,
                    )
                    world.record_tool_delivery(workflow_tool_schemas(case, 1))
                    notes = world.dispatch(
                        "recall_notes" if kind == "memory" else "read_handoff", {}
                    )
                    self.assertEqual(notes["entries"], list(snapshot.notes))
                    self.assertEqual(notes["authority"], "untrusted_data_only")
                    self.assertIn(INERT, notes["entries"])
                    self.assertFalse((directory / "never-execute-this-note").exists())
                    with self.assertRaises(FrozenInstanceError):
                        result.raw_bridge = b"changed"

    def test_real_close_sync_then_distinct_reopen_and_eof_order(self):
        with Witness() as witness:
            result = self.write()
        self.assertEqual(result.raw_bridge, (self.directory / "bridge.json").read_bytes())
        witness.assert_disposition(self)
        events = witness.events

        def at(label, event, side="after"):
            return events.index((label, event, side))

        for name in ("producer.json", "bridge.json", "complete.json"):
            label = name + ":xb"
            self.assertLess(at(label, "write"), at(label, "flush"))
            self.assertLess(at(label, "flush"), at(label, "fsync"))
            self.assertLess(at(label, "fsync"), at(label, "close"))
            writer = next(file for key, file in witness.files if key == label)
            reader = next(file for key, file in witness.files if key == name + ":rb")
            self.assertIsNot(writer, reader)
            self.assertLess(at("directory2", "fsync"), at(name + ":rb", "open", "before"))
            self.assertLess(at(name + ":rb", "eof"), at(name + ":rb", "close"))
        self.assertLess(at("bridge.json:xb", "close"), at("directory1", "fsync", "before"))
        self.assertLess(at("directory1", "fsync"), at("complete.json:xb", "open", "before"))
        self.assertLess(at("complete.json:xb", "close"), at("directory2", "fsync", "before"))
        self.assertLess(at("complete.json:rb", "close"), at("producer.json:rb", "read", "before"))
        witness.retire_custody()

    def test_revalidate_unchecked_instances_and_refuse_before_creation(self):
        invalids = [
            self.arguments(case=self.case.model_copy(update={"schema_version": True})),
            self.arguments(binding=self.binding.model_copy(update={"epoch": True})),
            self.arguments(limits=self.limits.model_construct(max_calls=65)),
            self.arguments(limits=self.limits.model_copy(update={"max_calls": True})),
            self.arguments(
                producer_snapshot=self.snapshot.model_copy(
                    update={
                        "events": (
                            self.snapshot.events[0].model_copy(update={"sequence": True}),
                            *self.snapshot.events[1:],
                        ),
                    }
                )
            ),
            self.arguments(
                producer_snapshot=self.snapshot.model_copy(update={"schema_version": True})
            ),
            self.arguments(guard=True),
            self.arguments(limits=None),
            self.arguments(case=next(case for case in self.cases if case.bridge_kind is None)),
        ]
        for args in invalids:
            with self.subTest(keys={k: type(v).__name__ for k, v in args.items()}):
                self.error(
                    lambda args=args: bridge.write_workflow_bridge(self.directory, **args),
                    "invalid",
                )
                self.assertFalse(self.directory.exists())

    def test_incomplete_and_forged_completion_are_effect_free(self):
        unfinished = producer(self.case, self.binding, self.limits, submit=False)
        self.error(lambda: self.write(producer_snapshot=unfinished), "incomplete", "validate")
        forged = unfinished.model_copy(update={"completed": True})
        self.error(lambda: self.write(producer_snapshot=forged), "invalid", "validate")
        no_notes = producer(self.case, self.binding, self.limits, notes=())
        self.error(lambda: self.write(producer_snapshot=no_notes), "incomplete", "validate")
        world = WorkflowSessionWorld(self.case, 0, binding=self.binding, limits=self.limits)
        world.record_tool_delivery(workflow_tool_schemas(self.case, 0))
        world.dispatch("remember_note", {"text": "note"})
        world.dispatch("send_report", {"content": 0.5})
        fatal = checked(WorkflowSnapshot, world.snapshot())
        self.error(lambda: self.write(producer_snapshot=fatal), "incomplete", "validate")
        self.assertFalse(self.directory.exists())

    def test_replay_inconsistent_oversize_snapshot_refuses_before_seal(self):
        # Retain the original model-copy input and enlarged local envelope.
        # Its unchanged events replay different notes, so replay refuses before
        # sealing. This does not isolate the whole-envelope byte guard.
        large = checked(
            WorkflowSnapshot, self.snapshot.model_copy(update={"notes": ("x" * 2040,) * 8})
        )
        envelope = json.loads(
            seal_workflow_bridge(
                self.case, self.snapshot, binding=self.binding, guard="on", limits=self.limits
            )
        )
        payload = canonical_bytes(list(large.notes))
        envelope.update(
            entries=list(large.notes),
            payload_sha256=byte_digest(payload),
            payload_byte_count=len(payload),
            producer_snapshot_sha256=byte_digest(canonical_bytes(large)),
        )
        self.assertLessEqual(len(payload), 16384)
        self.assertGreater(len(canonical_bytes(envelope)), 16384)
        with (
            patch.object(bridge, "replay_workflow", wraps=bridge.replay_workflow) as replay,
            patch.object(bridge, "seal_workflow_bridge", wraps=bridge.seal_workflow_bridge) as seal,
        ):
            error = self.error(lambda: self.write(producer_snapshot=large), "invalid", "validate")
        self.assertEqual(replay.call_count, 1)
        self.assertEqual(replay.call_args.args[1], (large,))
        self.assertEqual(seal.call_count, 0)
        self.assertFalse(self.directory.exists())
        print(
            json.dumps(
                {
                    "control": "replay_inconsistent_oversize_snapshot",
                    "replay_calls": replay.call_count,
                    "seal_calls": seal.call_count,
                    "error": [error.code, error.phase],
                    "leaf_absent": not self.directory.exists(),
                    "local_envelope_bytes": len(canonical_bytes(envelope)),
                },
                sort_keys=True,
            )
        )

    def test_independent_trusted_case_run_reviewer_epoch_guard_limits_session(self):
        self.write()
        changes = [
            {"case": self.select("handoff")},
            {"binding": self.binding.model_copy(update={"run_id": "c" * 32})},
            {"binding": self.binding.model_copy(update={"reviewer": "other"})},
            {"binding": self.binding.model_copy(update={"epoch": 2})},
            {"guard": "off"},
            {"limits": WorkflowLimits(max_calls=63)},
            {"producer_snapshot": self.snapshot.model_copy(update={"session_index": 1})},
        ]
        for change in changes:
            with (
                self.subTest(change=change),
                patch.object(bridge, "_open_file", side_effect=AssertionError("payload opened")),
            ):
                self.error(lambda change=change: self.reopen(**change), "binding", "validate")

    def test_self_consistent_forgery_and_different_expected_snapshot(self):
        self.write()
        other = producer(self.case, self.binding, self.limits, notes=("different",))
        raw = seal_workflow_bridge(
            self.case, other, binding=self.binding, guard="on", limits=self.limits
        )
        (self.directory / "producer.json").write_bytes(canonical_bytes(other))
        (self.directory / "bridge.json").write_bytes(raw)
        self.rehash()
        with Witness() as witness:
            self.error(self.reopen, "binding", "verify")
        self.assertFalse(
            any(label != "complete.json:rb" and op == "read" for label, op, _ in witness.events)
        )
        witness.assert_disposition(self)
        witness.retire_custody()
        inspected = self.reopen(producer_snapshot=other)
        self.assertEqual(inspected.raw_bridge, raw)
        self.error(lambda: self.write(producer_snapshot=other), "exists")

    def test_payload_and_hash_changes_cannot_replace_trusted_expected_data(self):
        self.write()
        changed = json.loads((self.directory / "bridge.json").read_bytes())
        changed["entries"] = ["replacement payload"]
        payload = canonical_bytes(changed["entries"])
        changed.update(payload_sha256=byte_digest(payload), payload_byte_count=len(payload))
        (self.directory / "bridge.json").write_bytes(canonical_bytes(changed))
        self.rehash()
        self.error(self.reopen, "binding", "verify")

    def test_path_alias_dotdot_relative_and_existing_leaf_refuse(self):
        for value in (Path("relative"), self.parent / ".." / "bundle"):
            self.error(lambda value=value: self.write(value), "path", "validate")
        alias = self.parent / "alias"
        alias.symlink_to(self.parent, target_is_directory=True)
        self.error(lambda: self.write(alias / "new"), "path", "validate")
        self.assertFalse((self.parent / "new").exists())
        for kind in ("dir", "file", "symlink", "dangling", "fifo"):
            directory = self.parent / kind
            if kind == "dir":
                directory.mkdir()
            elif kind == "file":
                directory.write_bytes(b"preserve")
            elif kind in ("symlink", "dangling"):
                directory.symlink_to(self.parent if kind == "symlink" else self.parent / "absent")
            else:
                os.mkfifo(directory)
            with (
                self.subTest(kind=kind),
                patch.object(bridge, "_open_file", side_effect=AssertionError("read")),
            ):
                self.error(lambda directory=directory: self.write(directory), "exists", "create")
            self.assertTrue(os.path.lexists(directory))

    def test_unsupported_host_and_identity_capabilities_are_effect_free(self):
        for attribute, value in (
            ("name", "nt"),
            ("O_NOFOLLOW", 0),
            ("O_NONBLOCK", 0),
            ("O_DIRECTORY", 0),
            ("geteuid", None),
            ("supports_dir_fd", set()),
            ("supports_fd", set()),
            ("supports_follow_symlinks", set()),
        ):
            with self.subTest(attribute=attribute), patch.object(bridge.os, attribute, value):
                self.error(self.write, "unsupported", "validate")
                self.assertFalse(self.directory.exists())

    def test_actual_umask_modes_are_verified_without_chmod(self):
        for mask, expected_code in ((0, None), (0o077, None), (0o777, "path")):
            directory = self.parent / ("mask" + str(mask))
            previous = os.umask(mask)
            try:
                if expected_code:
                    self.error(
                        lambda directory=directory: self.write(directory), expected_code, "create"
                    )
                else:
                    self.write(directory)
            finally:
                os.umask(previous)
            self.assertTrue(directory.exists())
            if expected_code:
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0)
                directory.chmod(0o700)  # Test caller teardown only.
                self.error(lambda directory=directory: self.write(directory), "exists")

    def test_metadata_roster_refusals_precede_all_payload_opens(self):
        mutations = (
            "extra",
            "missing",
            "symlink",
            "dangling",
            "hardlink",
            "fifo",
            "directory",
            "file_mode",
            "directory_mode",
            "bridge_size",
            "producer_size",
            "complete_size",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                directory = self.parent / mutation
                self.write(directory)
                target = directory / "bridge.json"
                code = "path"
                if mutation == "extra":
                    (directory / "extra").write_bytes(b"")
                    code = "invalid"
                elif mutation == "missing":
                    target.unlink()
                    code = "incomplete"
                elif mutation in ("symlink", "dangling", "hardlink", "fifo", "directory"):
                    target.unlink()
                    if mutation == "symlink":
                        target.symlink_to(directory / "producer.json")
                    elif mutation == "dangling":
                        target.symlink_to(directory / "absent")
                    elif mutation == "hardlink":
                        os.link(directory / "producer.json", target)
                    elif mutation == "fifo":
                        os.mkfifo(target)
                    else:
                        target.mkdir()
                elif mutation == "file_mode":
                    target.chmod(0o640)
                elif mutation == "directory_mode":
                    directory.chmod(0o750)
                else:
                    filename, size = {
                        "bridge_size": ("bridge.json", 16385),
                        "producer_size": ("producer.json", self.limits.max_trace_bytes + 1),
                        "complete_size": ("complete.json", 4097),
                    }[mutation]
                    with open(directory / filename, "r+b", buffering=0) as stream:
                        stream.truncate(size)
                    code = "invalid"
                with patch.object(
                    bridge, "_open_file", side_effect=AssertionError("payload opened")
                ):
                    self.error(
                        lambda directory=directory: bridge.reopen_workflow_bridge(
                            directory, **self.arguments()
                        ),
                        code,
                        "reopen",
                    )

    def test_leaf_symlink_and_wrong_uid_refuse_before_payload_reads(self):
        self.write()
        alias = self.parent / "leaf-alias"
        alias.symlink_to(self.directory)
        self.error(
            lambda: bridge.reopen_workflow_bridge(alias, **self.arguments()), "path", "reopen"
        )
        # Capability exists but this identity owns neither parent nor leaf.
        with patch.object(bridge.os, "geteuid", return_value=os.geteuid() + 1):
            self.error(self.reopen, "path", "validate")

    def test_sidecar_canonical_utf8_exact_keys_counts_digests_and_bounds(self):
        self.write()
        path = self.directory / "complete.json"
        original = path.read_bytes()
        base = json.loads(original)
        variations = [
            b"\xff",
            original + b"\n",
            original.replace(b'"bundle_version":1', b'"bundle_version":1,"bundle_version":1'),
            b'{"value":NaN}',
            original.decode().encode("utf-16"),
            canonical_bytes({**base, "extra": 1}),
            canonical_bytes({k: v for k, v in base.items() if k != "state"}),
        ]
        for name, value in (
            ("bundle_version", True),
            ("producer_session", False),
            ("consumer_session", True),
            ("producer_snapshot_bytes", True),
            ("bridge_bytes", 0),
            ("bridge_bytes", 16385),
            ("bridge_sha256", "A" * 64),
            ("state", "ready"),
            ("guard", "unknown"),
            ("binding", {**base["binding"], "epoch": True}),
            ("limits", {}),
        ):
            variations.append(canonical_bytes({**base, name: value}))
        variations += [
            canonical_bytes({**base, "state": [[[[[[[[[0]]]]]]]]]}),
            canonical_bytes({**base, "state": [0] * 513}),
        ]
        for raw in variations:
            with self.subTest(raw_length=len(raw)), Witness() as witness:
                path.write_bytes(raw)
                self.error(self.reopen, "invalid", "verify")
                self.assertFalse(
                    any(
                        label != "complete.json:rb" and op == "read"
                        for label, op, _ in witness.events
                    )
                )
            witness.assert_disposition(self)
            witness.retire_custody()
        path.write_bytes(original)
        self.assertEqual(self.reopen().producer_snapshot, self.snapshot)

    def test_sidecar_valid_identity_variations_are_binding_refusals(self):
        self.write()
        path = self.directory / "complete.json"
        original = path.read_bytes()
        base = json.loads(original)
        variations = [
            ("workflow_case_sha256", "0" * 64),
            ("guard", "off"),
            ("binding", {**base["binding"], "run_id": "c" * 32}),
            ("binding", {**base["binding"], "reviewer": "other"}),
            ("binding", {**base["binding"], "epoch": 2}),
            ("limits", {**base["limits"], "max_calls": 63}),
            ("producer_snapshot_sha256", "0" * 64),
            ("bridge_bytes", base["bridge_bytes"] + 1),
        ]
        for name, value in variations:
            with self.subTest(name=name):
                path.write_bytes(canonical_bytes({**base, name: value}))
                self.error(self.reopen, "binding", "verify")
        path.write_bytes(original)

    def test_snapshot_and_bridge_corruption_after_expected_sidecar(self):
        for filename, raw, code in (
            ("producer.json", b"\xff", "invalid"),
            ("producer.json", canonical_bytes(self.snapshot) + b"\n", "invalid"),
            ("bridge.json", b"{}", "binding"),
        ):
            directory = self.parent / str(len(list(self.parent.iterdir())))
            self.write(directory)
            (directory / filename).write_bytes(raw)
            self.error(
                lambda directory=directory: bridge.reopen_workflow_bridge(
                    directory, **self.arguments()
                ),
                code,
                "verify",
            )

    def test_partial_empty_missing_and_reuse_refusal(self):
        self.directory.mkdir(mode=0o700)
        self.error(self.reopen, "incomplete", "reopen")
        self.error(self.write, "exists", "create")
        self.assertEqual(list(self.directory.iterdir()), [])
        self.error(
            lambda: bridge.reopen_workflow_bridge(self.parent / "absent", **self.arguments()),
            "incomplete",
            "reopen",
        )

    def test_real_write_flush_fsync_close_and_publication_failures(self):
        faults = []
        for name in ("producer.json:xb", "bridge.json:xb", "complete.json:xb"):
            for event in ("write", "flush", "fsync", "close"):
                for side in ("before", "after"):
                    faults.append((name, event, side))
        faults += [
            (name, "fsync", side)
            for name in ("directory1", "directory2")
            for side in ("before", "after")
        ]
        faults += [("complete.json:xb", "open", "before")]
        for index, fault in enumerate(faults):
            with self.subTest(fault=fault):
                directory = self.parent / ("fault" + str(index))
                witness = Witness(fault)
                try:
                    with witness:
                        error = self.error(
                            lambda directory=directory: self.write(directory), "io_unknown"
                        )
                    self.assertTrue(witness.failed)
                    self.assertTrue(directory.is_dir())
                    witness.assert_disposition(self, error)
                    self.assertFalse(any(label.endswith(":rb") for label, _ in witness.files))
                    for label, _ in witness.files:
                        self.assertLessEqual(witness.events.count((label, "write", "before")), 1)
                    if fault[1] == "close":
                        original = next(file for label, file in witness.files if label == fault[0])
                        self.assertTrue(any(resource is original for resource in error._unclosed))
                        calls = witness.original_calls.count((fault[0], "close", "call"))
                        returns = witness.original_calls.count((fault[0], "close", "return"))
                        after = fault[2] == "after"
                        self.assertEqual(
                            (calls, returns, original.closed), (int(after), int(after), after)
                        )
                        print(
                            json.dumps(
                                {
                                    "control": "writer_original_close_fault",
                                    "fault": fault,
                                    "actual_calls": calls,
                                    "actual_returns": returns,
                                    "original_closed_after_product": original.closed,
                                    "original_retained_by_identity": True,
                                },
                                sort_keys=True,
                            )
                        )
                    before = {
                        p.name: (p.stat().st_ino, p.read_bytes()) for p in directory.iterdir()
                    }
                    self.error(lambda directory=directory: self.write(directory), "exists")
                    self.assertEqual(
                        before,
                        {p.name: (p.stat().st_ino, p.read_bytes()) for p in directory.iterdir()},
                    )
                    if fault[0] in ("producer.json:xb", "bridge.json:xb", "directory1"):
                        self.assertFalse((directory / "complete.json").exists())
                finally:
                    witness.retire_custody()

    def test_short_real_write_is_unknown_and_not_retried(self):
        witness = Witness(short=True)
        try:
            with witness:
                error = self.error(self.write, "io_unknown", "write")
            self.assertEqual((self.directory / "producer.json").stat().st_size, 7)
            self.assertEqual(witness.events.count(("producer.json:xb", "write", "before")), 1)
            # FileIO.close invokes flush, but this unbuffered original has no
            # payload to retry. No explicit flush precedes cleanup close.
            self.assertLess(
                witness.events.index(("producer.json:xb", "close", "before")),
                witness.events.index(("producer.json:xb", "flush", "before")),
            )
            witness.assert_disposition(self, error)
        finally:
            witness.retire_custody()

    def test_failed_flush_cleanup_cannot_retry_payload(self):
        witness = Witness(("producer.json:xb", "flush", "before"))
        try:
            with witness:
                error = self.error(self.write, "io_unknown", "write")
            self.assertEqual(
                (self.directory / "producer.json").read_bytes(), canonical_bytes(self.snapshot)
            )
            self.assertEqual(witness.events.count(("producer.json:xb", "write", "before")), 1)
            self.assertNotIn(("producer.json:xb", "fsync", "before"), witness.events)
            witness.assert_disposition(self, error)
        finally:
            witness.retire_custody()

    def test_actual_reader_open_read_eof_and_close_failures(self):
        self.write()
        faults = [
            (name + ":rb", event, side)
            for name in bridge._NAMES
            for event in ("read", "eof", "close")
            for side in ("before", "after")
        ]
        faults += [(name + ":rb", "open", "before") for name in bridge._NAMES]
        for fault in faults:
            with self.subTest(fault=fault):
                witness = Witness(fault)
                try:
                    with witness:
                        error = self.error(self.reopen, "io_unknown")
                    self.assertTrue(witness.failed)
                    witness.assert_disposition(self, error)
                    self.assertEqual({p.name for p in self.directory.iterdir()}, set(bridge._NAMES))
                    if fault[1] == "close":
                        original = next(file for label, file in witness.files if label == fault[0])
                        self.assertTrue(any(resource is original for resource in error._unclosed))
                        calls = witness.original_calls.count((fault[0], "close", "call"))
                        returns = witness.original_calls.count((fault[0], "close", "return"))
                        after = fault[2] == "after"
                        self.assertEqual(
                            (calls, returns, original.closed), (int(after), int(after), after)
                        )
                        print(
                            json.dumps(
                                {
                                    "control": "reader_original_close_fault",
                                    "fault": fault,
                                    "actual_calls": calls,
                                    "actual_returns": returns,
                                    "original_closed_after_product": original.closed,
                                    "original_retained_by_identity": True,
                                },
                                sort_keys=True,
                            )
                        )
                finally:
                    witness.retire_custody()
        self.assertEqual(self.reopen().producer_snapshot, self.snapshot)

    def test_truncated_and_nonempty_eof_refuse_after_real_reads(self):
        self.write()
        for option, code in (("truncated", "incomplete"), ("trailing", "invalid")):
            with self.subTest(option=option):
                (self.directory / "producer.json").write_bytes(canonical_bytes(self.snapshot))
                witness = Witness(**{option: True})
                try:
                    with witness:
                        error = self.error(self.reopen, code, "read")
                    witness.assert_disposition(self, error)
                finally:
                    witness.retire_custody()

    def test_descriptor_path_replacement_refuses_before_payload_reads(self):
        self.write()
        witness = Witness()
        real_open = witness.open

        def replace_after_open(directory, name, mode, *, owner):
            file = real_open(directory, name, mode, owner=owner)
            if name == "producer.json":
                target = self.directory / name
                target.rename(self.parent / "retained-original-producer")
                target.write_bytes(canonical_bytes(self.snapshot))
                target.chmod(0o600)
            return file

        try:
            with witness, patch.object(bridge, "_open_file", replace_after_open):
                error = self.error(self.reopen, "io_unknown", "reopen")
            self.assertFalse(any(op == "read" for _, op, _ in witness.events))
            witness.assert_disposition(self, error)
            self.assertTrue((self.parent / "retained-original-producer").exists())
        finally:
            witness.retire_custody()

    def test_directory_close_failures_retain_each_original_owner_once(self):
        original_close = bridge._Directory.close
        attempts = []

        def fail_close(resource):
            attempts.append(resource)
            raise OSError("DO_NOT_EXPOSE_PRIVATE_ERROR")

        with patch.object(bridge._Directory, "close", fail_close):
            error = self.error(self.write, "io_unknown", "close")
        try:
            self.assertEqual(len(attempts), 2)
            self.assertIsNot(attempts[0], attempts[1])
            self.assertEqual(error._unclosed, tuple(attempts))
            for resource in attempts:
                self.assertTrue(stat.S_ISDIR(os.fstat(resource.fd).st_mode))
            self.assertEqual(self.reopen().producer_snapshot, self.snapshot)
            self.error(self.write, "exists")
        finally:
            # Explicit test-caller custody after the product's single attempt.
            for resource in attempts:
                original_close(resource)

    def test_reopen_directory_open_error_retains_real_bundle(self):
        self.write()
        with patch.object(
            bridge, "_open_directory", side_effect=OSError("DO_NOT_EXPOSE_PRIVATE_ERROR")
        ):
            self.error(self.reopen, "io_unknown", "reopen")
        self.assertEqual(self.reopen().producer_snapshot, self.snapshot)
        self.error(self.write, "exists")

    def test_post_mkdir_open_error_retains_exclusive_empty_namespace(self):
        original_open = bridge._open_directory

        def fail_leaf(resources, path, **kwargs):
            if path == self.directory.name:
                raise OSError("DO_NOT_EXPOSE_PRIVATE_ERROR")
            return original_open(resources, path, **kwargs)

        with patch.object(bridge, "_open_directory", fail_leaf):
            self.error(self.write, "io_unknown", "create")
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.error(self.write, "exists")

    def test_unknown_after_final_sync_allows_inspection_but_never_rewrite(self):
        witness = Witness(("directory2", "fsync", "after"))
        try:
            with witness:
                error = self.error(self.write, "io_unknown", "sync")
            witness.assert_disposition(self, error)
            self.assertEqual(self.reopen().producer_snapshot, self.snapshot)
            self.error(self.write, "exists")
            self.assertEqual(error.code, "io_unknown")
        finally:
            witness.retire_custody()

    def test_interruption_preserved_with_independent_cleanup_and_custody(self):
        witness = Witness(("producer.json:xb", "write", "after"), interrupt=True)
        try:
            with witness, self.assertRaises(KeyboardInterrupt) as raised:
                self.write()
            witness.assert_disposition(self, raised.exception)
            self.assertTrue(self.directory.exists())
            self.assertFalse((self.directory / "complete.json").exists())
        finally:
            witness.retire_custody()
        # Reopen cleanup must continue to independent readers after an
        # interrupted original close and retain exactly that original object.
        other = self.parent / "interrupted-close"
        self.write(other)
        witness = Witness(("complete.json:rb", "close", "before"), interrupt=True)
        try:
            with witness, self.assertRaises(KeyboardInterrupt) as raised:
                bridge.reopen_workflow_bridge(other, **self.arguments())
            witness.assert_disposition(self, raised.exception)
            resource = next(file for label, file in witness.files if label == "complete.json:rb")
            self.assertIs(raised.exception._workflow_bridge_unclosed[0], resource)
            self.assertFalse(resource.closed)
            self.assertEqual(witness.original_calls.count(("complete.json:rb", "close", "call")), 0)
            self.assertEqual(
                witness.original_calls.count(("complete.json:rb", "close", "return")), 0
            )
        finally:
            witness.retire_custody()

    def test_failed_close_strongly_retains_actual_original_after_gc(self):
        self.write()
        witness = Witness(("complete.json:rb", "close", "before"))
        try:
            with witness:
                error = self.error(self.reopen, "io_unknown", "close")
            original = next(file for label, file in witness.files if label == "complete.json:rb")
            reference = weakref.ref(original)
            self.assertIs(error._unclosed[0], original)
            self.assertEqual(witness.original_calls.count(("complete.json:rb", "close", "call")), 0)
            self.assertEqual(
                witness.original_calls.count(("complete.json:rb", "close", "return")), 0
            )
            witness.assert_disposition(self, error)
            del original
            gc.collect()
            self.assertIs(reference(), error._unclosed[0])
            self.assertFalse(reference().closed)
        finally:
            witness.retire_custody()

    def test_core_byte_node_and_depth_bounds_remain_unchanged(self):
        # These direct JSON-helper inputs have no field schema to fail first.
        for value, kwargs, reason in (
            (
                {"x": "a" * 4096},
                {"maximum": 4096, "nodes": 512, "depth": 8},
                "Workflow JSON byte limit",
            ),
            (
                {"x": [0] * 512},
                {"maximum": 4096, "nodes": 512, "depth": 8},
                "Workflow JSON structure limit",
            ),
            (
                {"x": [[[[[[[[[0]]]]]]]]]},
                {"maximum": 4096, "nodes": 512, "depth": 8},
                "Workflow JSON structure limit",
            ),
        ):
            with self.assertRaises(ValueError) as raised:
                bounded_json(value, **kwargs)
            self.assertIs(type(raised.exception), WorkflowJSONResourceError)
            self.assertEqual(str(raised.exception), reason)
        self.assertEqual(len(bounded_json("x" * 14, maximum=16)), 16)
        with self.assertRaises(ValueError) as raised:
            bounded_json("x" * 15, maximum=16)
        self.assertIs(type(raised.exception), WorkflowJSONResourceError)
        self.assertEqual(str(raised.exception), "Workflow JSON byte limit")

        # A dict, its key, its list and 509 scalars total exactly 512 nodes.
        at_node_cap = {"x": [0] * 509}
        caps = {"maximum": 4096, "nodes": 512, "depth": 8}
        self.assertEqual(json.loads(bounded_json(at_node_cap, **caps)), at_node_cap)
        with self.assertRaises(WorkflowJSONResourceError) as raised:
            bounded_json({"x": [0] * 510}, **caps)
        self.assertEqual(str(raised.exception), "Workflow JSON structure limit")
        at_depth_cap = 0
        for _ in range(8):
            at_depth_cap = [at_depth_cap]
        self.assertEqual(json.loads(bounded_json(at_depth_cap, **caps)), at_depth_cap)
        with self.assertRaises(WorkflowJSONResourceError) as raised:
            bounded_json([at_depth_cap], **caps)
        self.assertEqual(str(raised.exception), "Workflow JSON structure limit")

        # Direct case checking applies canonical resource guarding before its
        # model schema. This oversized case_id hits the string guard first.
        invalid_case = self.case.model_copy(update={"case_id": "x" * 131073})
        with self.assertRaises(ValueError) as raised:
            validate_workflow_case(invalid_case)
        self.assertIs(type(raised.exception), WorkflowJSONResourceError)
        self.assertEqual(str(raised.exception), "Workflow JSON string limit")

        # The writer first revalidates Python fields. This negative exercises
        # repository_json's 1 MiB field limit, not the aggregate trace-byte cap.
        invalid_snapshot = self.snapshot.model_copy(update={"repository_json": "x" * 2097153})
        with self.assertRaises(ValidationError) as raised:
            WorkflowSnapshot.model_validate(
                invalid_snapshot.model_dump(mode="python", warnings=False)
            )
        self.assertEqual(
            [
                (item["loc"], item["type"], item.get("ctx"))
                for item in raised.exception.errors(include_input=False, include_url=False)
            ],
            [(("repository_json",), "string_too_long", {"max_length": 1048576})],
        )
        self.error(lambda: self.write(producer_snapshot=invalid_snapshot), "invalid", "validate")
        self.assertFalse(self.directory.exists())
        print(
            json.dumps(
                {
                    "control": "json_resource_boundary_attribution",
                    "schema_free_byte_pair": [16, 17],
                    "schema_free_node_pair": [512, 513],
                    "schema_free_depth_pair": [8, 9],
                    "case_id_131073": "WorkflowJSONResourceError:Workflow JSON string limit",
                    "repository_json_2097153": "ValidationError:repository_json:string_too_long:1048576",
                    "isolated_aggregate_trace_cap_proof": False,
                },
                sort_keys=True,
            )
        )

    def test_real_close_bookkeeping_line_boundaries(self):
        # Current imported ownership logic, real acquired originals, no OS signal.
        cases = (
            ("baseline", None, "explicit", 1, False),
            ("before_phase", 'self.phase = "close"', "explicit", 1, False),
            ("before_original", "owner.resource.close()", "explicit", 0, True),
            ("after_original", "owner.closed = True", "explicit", 1, True),
            ("cleanup_before_attempt", 'self.phase = "close"', "cleanup", 0, True),
            ("cleanup_before_original", "owner.resource.close()", "cleanup", 0, True),
            ("callee_before", None, "callee_before", 0, True),
            ("callee_after", None, "callee_after", 1, True),
            ("cleanup_return_error", None, "cleanup_return", 1, False),
        )
        for label, statement, route, calls, retained in cases:
            with self.subTest(boundary=label):
                name = label + "-target"
                fault = (
                    (name + ":xb", "close", route.removeprefix("callee_"))
                    if route.startswith("callee_")
                    else None
                )
                witness = TraceWitness(
                    bridge._Resources.close,
                    statement,
                    event="return" if route == "cleanup_return" else "line",
                    failure=OSError if route == "cleanup_return" else KeyboardInterrupt,
                    fault=fault,
                )
                self.addCleanup(witness.retire_custody)
                error, returned = None, False
                with witness:
                    try:
                        with bridge._Resources("write") as resources:
                            directory = bridge._open_directory(resources, self.parent)
                            independent = resources.open_file(
                                directory, label + "-independent", "xb"
                            )
                            target = resources.open_file(directory, name, "xb")
                            if statement or route == "cleanup_return":
                                witness.arm(
                                    lambda values, target=target: values.get("owner") is target
                                )
                            if route == "explicit" or route.startswith("callee_"):
                                resources.close(target)
                        returned = True
                    except (KeyboardInterrupt, bridge.WorkflowBridgeIOError) as caught:
                        error = caught
                self.assertEqual(returned, label == "baseline")
                if label != "baseline":
                    expected = (
                        bridge.WorkflowBridgeIOError
                        if route == "cleanup_return"
                        else KeyboardInterrupt
                    )
                    self.assertIsInstance(error, expected)
                    if route == "cleanup_return":
                        self.assertEqual((error.code, error.phase), ("io_unknown", "close"))
                if statement or route == "cleanup_return":
                    self.assertEqual(len(witness.fired), 1)
                custody = getattr(
                    error, "_workflow_bridge_unclosed", getattr(error, "_unclosed", ())
                )
                self.assertEqual(any(item is target.resource for item in custody), retained)
                self.assertEqual(
                    witness.original_calls.count((name + ":xb", "close", "call")), calls
                )
                self.assertEqual(
                    witness.original_calls.count((name + ":xb", "close", "return")), calls
                )
                self.assertEqual(target.resource.closed, bool(calls))
                self.assertEqual(
                    witness.original_calls.count((label + "-independent:xb", "close", "call")), 1
                )
                self.assertTrue(independent.resource.closed)
                self.assertEqual(len(witness.directories), 1)
                self.assertTrue(resources.owned[0].closed)
                if retained:
                    self.assertFalse(target.closed)
                if label == "cleanup_before_attempt":
                    self.assertFalse(target.attempted)
                witness.record("close_transition:" + label, error)

    def test_public_acquisition_and_registration_interruption_boundaries(self):
        cases = (
            (
                "file_registration",
                "write",
                bridge._Resources.keep,
                "self.owned.append(owner)",
                "line",
            ),
            (
                "file_before_init",
                "write",
                bridge._open_file,
                "file.__init__(name, mode, opener=opener)",
                "line",
            ),
            ("file_helper_return", "write", bridge._open_file, None, "return"),
            ("file_owner_return", "write", bridge._Resources.open_file, "return owner", "line"),
            ("directory_registered", "write", bridge._Resources.keep, "return owner", "line"),
            ("directory_acquired", "write", bridge._open_directory, "return owner", "line"),
            ("reader_helper_return", "read", bridge._open_file, None, "return"),
            ("reader_directory_return", "read", bridge._open_directory, None, "return"),
        )
        for label, operation, function, statement, event in cases:
            with self.subTest(boundary=label):
                directory = self.parent / label
                if operation == "read":
                    self.write(directory)

                def selected(
                    values, function=function, label=label, directory=directory, operation=operation
                ):
                    if function is bridge._Resources.keep:
                        return isinstance(values["resource"], bridge._Directory) == (
                            label == "directory_registered"
                        )
                    if function is bridge._open_directory:
                        return values["path"] == (
                            directory.name if operation == "write" else directory
                        )
                    return values["name"] == (
                        "producer.json" if operation == "write" else "complete.json"
                    )

                witness = TraceWitness(function, statement, event=event)
                self.addCleanup(witness.retire_custody)
                with witness, self.assertRaises(KeyboardInterrupt) as raised:
                    witness.arm(selected)
                    if operation == "write":
                        self.write(directory)
                    else:
                        bridge.reopen_workflow_bridge(directory, **self.arguments())
                self.assertEqual(len(witness.fired), 1)
                self.assertEqual(raised.exception._workflow_bridge_unclosed, ())
                witness.assert_disposition(self, raised.exception)
                if label in (
                    "file_helper_return",
                    "file_owner_return",
                    "directory_acquired",
                    "reader_helper_return",
                    "reader_directory_return",
                ):
                    self.assertTrue(witness.fired[0]["acquired"])
                if directory.exists():
                    before = {
                        p.name: (p.stat().st_ino, p.read_bytes()) for p in directory.iterdir()
                    }
                    self.error(
                        lambda directory=directory: self.write(directory), "exists", "create"
                    )
                    self.assertEqual(
                        before,
                        {p.name: (p.stat().st_ino, p.read_bytes()) for p in directory.iterdir()},
                    )
                witness.record("acquisition_transition:" + label, raised.exception)

    def test_exact_reachable_whole_envelope_bound_from_real_core(self):
        binding = WorkflowRunBinding(run_id="b" * 32, reviewer=chr(1) * 128, epoch=10)
        args = {"binding": binding, "guard": "off", "limits": self.limits}
        for kind, maximum in (("memory", 15668), ("handoff", 15669)):
            with self.subTest(kind=kind):
                case = self.select(kind)
                directory = self.parent / ("maximum-" + kind)
                world = WorkflowSessionWorld(case, 0, **args)
                world.record_tool_delivery(workflow_tool_schemas(case, 0))
                world.dispatch("read_work_item", {})
                world.dispatch("read_pr", {})
                tool = "remember_note" if kind == "memory" else "write_handoff"
                for _ in range(6):
                    self.assertEqual(world.dispatch(tool, {"text": "x" * 2048})["status"], "ok")
                self.assertEqual(len(canonical_bytes(["x" * 2048] * 6 + ["x" * 2027])), 14337)
                refusal = world.dispatch(tool, {"text": "x" * 2027})
                self.assertEqual(refusal, {"status": "error", "error": "note_limit"})
                self.assertFalse(directory.exists())
                self.assertEqual(world.dispatch(tool, {"text": "x" * 2026})["status"], "ok")
                self.assertEqual(
                    world.dispatch("submit_review", {"verdict": "approve", "findings": []})[
                        "status"
                    ],
                    "ok",
                )
                snapshot = checked(WorkflowSnapshot, world.snapshot())
                replay = replay_workflow(
                    case,
                    (snapshot,),
                    expected_guard="off",
                    expected_binding=binding,
                    expected_limits=self.limits,
                )
                self.assertEqual(
                    (replay.request_replay_complete, replay.snapshots[0]), (True, snapshot)
                )
                raw = seal_workflow_bridge(case, snapshot, **args)
                sizes = {
                    "kind": kind,
                    "payload": len(canonical_bytes(list(snapshot.notes))),
                    "binding": len(canonical_bytes(binding)),
                    "seal": len(raw),
                    "case": len(canonical_bytes(case)),
                    "snapshot": len(canonical_bytes(snapshot)),
                    "calls": snapshot.calls,
                    "arguments": max(
                        len(event.arguments_json.encode()) for event in snapshot.events
                    ),
                }
                self.assertEqual(
                    (sizes["payload"], sizes["binding"], sizes["seal"]), (14336, 838, maximum)
                )
                for name, cap in (
                    ("case", 131072),
                    ("snapshot", self.limits.max_trace_bytes),
                    ("calls", self.limits.max_calls),
                    ("arguments", 65536),
                    ("seal", 16384),
                ):
                    self.assertLessEqual(sizes[name], cap)
                self.assertFalse(directory.exists())
                result = self.write(directory, case=case, producer_snapshot=snapshot, **args)
                self.assertEqual(
                    (result.raw_bridge, (directory / "bridge.json").read_bytes()), (raw, raw)
                )
                print(
                    json.dumps(
                        {
                            "control": "reachable_envelope",
                            "sizes": sizes,
                            "seal_sha256": byte_digest(raw),
                            "extra_byte_refusal": refusal,
                            "real_replay_write_reopen": True,
                        },
                        sort_keys=True,
                    )
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
