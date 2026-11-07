"""Explicit bounded files for the separate saved-report analysis contract."""

from __future__ import annotations

import json
import os
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from .json_input import MAX_REPORT_BYTES, parse_json_object
from .report_validation import MAX_EXPORT_BYTES
from .repository_cases import virtual_path
from .source_group_analysis import AnalysisEvidence, AnalysisPlan, analyze_source_groups

MAX_ANALYSIS_INPUT_BYTES = MAX_REPORT_BYTES
MAX_ANALYSIS_OUTPUT_BYTES = MAX_EXPORT_BYTES


def _parts(value: str) -> tuple[str, ...]:
    """Evidence paths are literal, canonical paths below the plan directory."""
    virtual_path(value)
    parts = tuple(value.split("/"))
    if any(len(part.encode("utf-8")) > 128 for part in parts):
        raise ValueError("Analysis path component exceeds its byte bound")
    return parts


def _flags(*, directory: bool = False) -> int:
    # Refuse platforms without the required no-follow primitives.
    if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")):
        raise NotImplementedError("Analysis requires no-follow file descriptors")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    return flags | os.O_DIRECTORY if directory else flags


@contextmanager
def _directory(path: Path, *, create: bool = False):
    absolute = path.absolute()
    parts = absolute.parts
    if not parts or any(part in (".", "..") for part in parts):
        raise ValueError("Analysis directory must be canonical")
    descriptor = os.open(absolute.anchor, _flags(directory=True))
    try:
        for name in parts[1:]:
            # System ancestors are explicit user paths, not evidence references.
            if any(ord(char) < 32 or ord(char) == 127 for char in name):
                raise ValueError("Analysis directory must be printable")
            name.encode("utf-8")
            if create:
                try:
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            following = os.open(name, _flags(directory=True), dir_fd=descriptor)
            previous, descriptor = descriptor, following
            os.close(previous)
        yield descriptor
    finally:
        os.close(descriptor)


class _Reader:
    def __init__(self):
        self.total = 0
        self.files: dict[tuple[int, int], tuple[int, int, dict]] = {}

    def read(self, root: int, parts: tuple[str, ...]) -> dict:
        parent = os.dup(root)
        try:
            for name in parts[:-1]:
                following = os.open(name, _flags(directory=True), dir_fd=parent)
                previous, parent = parent, following
                os.close(previous)
            descriptor = os.open(parts[-1], _flags(), dir_fd=parent)
            try:
                with os.fdopen(descriptor, "rb", closefd=False) as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
                        raise ValueError("Analysis input requires a bounded regular file")
                    identity = (info.st_dev, info.st_ino)
                    cached = self.files.get(identity)
                    if cached is not None:
                        if cached[:2] != (info.st_size, info.st_mtime_ns):
                            raise ValueError("Analysis input changed during loading")
                        return cached[2]
                    remaining = MAX_ANALYSIS_INPUT_BYTES - self.total
                    if info.st_size > remaining:
                        raise ValueError("Analysis aggregate input byte bound exceeded")
                    raw = stream.read(min(MAX_REPORT_BYTES, remaining) + 1)
                    after = os.fstat(stream.fileno())
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
        if (
            len(raw) != info.st_size
            or len(raw) > remaining
            or (after.st_size, after.st_mtime_ns) != (info.st_size, info.st_mtime_ns)
        ):
            raise ValueError("Analysis input changed or exceeded its byte bound")
        raw.decode("utf-8")
        document = parse_json_object(raw)
        self.total += len(raw)
        self.files[identity] = (info.st_size, info.st_mtime_ns, document)
        return document


def load_analysis_inputs(plan_path: Path) -> tuple[AnalysisPlan, AnalysisEvidence]:
    """Load only declared local evidence, counting each physical file once."""
    path = Path(plan_path)
    _parts(path.name)
    reader = _Reader()
    with _directory(path.parent) as root:
        document = reader.read(root, (path.name,))
        plan = AnalysisPlan.model_validate_json(json.dumps(document, allow_nan=False))
        names = [item.report for item in plan.artifacts]
        names.extend(item.suite for item in plan.artifacts if item.suite is not None)
        for export in plan.exports:
            names.extend(
                (export.index, export.provenance, export.source_manifest, export.evaluator_manifest)
            )
            names.extend(export.suites)
        for agreement in plan.agreements:
            names.extend((agreement.rater_a, agreement.rater_b))
        paths = {name: _parts(name) for name in names}
        documents = {name: reader.read(root, parts) for name, parts in paths.items()}
    reports = {item.artifact_id: documents[item.report] for item in plan.artifacts}
    suites = {
        item.artifact_id: documents[item.suite] for item in plan.artifacts if item.suite is not None
    }
    exports = {
        item.export_id: {
            "index": documents[item.index],
            "provenance": documents[item.provenance],
            "source_manifest": documents[item.source_manifest],
            "evaluator_manifest": documents[item.evaluator_manifest],
            "suites": tuple(documents[name] for name in item.suites),
        }
        for item in plan.exports
    }
    adjudications = {
        name: documents[name] for item in plan.agreements for name in (item.rater_a, item.rater_b)
    }
    return plan, AnalysisEvidence(reports, suites, exports, adjudications)


def _identity(info) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _write_output(path: Path, raw: bytes) -> Path:
    output = Path(path)
    _parts(output.name)
    with _directory(output.parent, create=True) as parent:
        identity = _identity(os.fstat(parent))
        with _directory(output.parent) as current:
            if _identity(os.fstat(current)) != identity:
                raise ValueError("Analysis output parent changed")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        descriptor = os.open(output.name, flags, 0o600, dir_fd=parent)
        try:
            created = os.fstat(descriptor)
            if not stat.S_ISREG(created.st_mode):
                raise ValueError("Analysis output requires a regular file")
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                if stream.write(raw) != len(raw):
                    raise OSError("Incomplete analysis output")
        finally:
            os.close(descriptor)
        if _identity(os.stat(output.name, dir_fd=parent, follow_symlinks=False)) != _identity(
            created
        ):
            raise ValueError("Analysis output changed")
        with _directory(output.parent) as current:
            if _identity(os.fstat(current)) != identity:
                raise ValueError("Analysis output parent changed")
    # Never unlink a pathname after a write failure: preserve partial or replaced files.
    return output


def write_source_group_analysis(plan_path: Path, output_path: Path) -> Path:
    plan, evidence = load_analysis_inputs(plan_path)
    result = analyze_source_groups(evidence, plan=plan)
    raw = (
        json.dumps(result.model_dump(mode="json"), indent=2, ensure_ascii=False, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if len(raw) > MAX_ANALYSIS_OUTPUT_BYTES:
        raise ValueError("Analysis output byte bound exceeded")
    return _write_output(output_path, raw)


def analyze_groups_command(args) -> int:
    try:
        write_source_group_analysis(args.plan, args.output)
    except (OSError, ValueError, TypeError, RecursionError, NotImplementedError):
        print(
            "Source-group analysis refused: expected bounded local inputs and a new JSON output.",
            file=sys.stderr,
        )
        return 2
    print("Source-group analysis written.")
    return 0
