"""Bounded JSON objects for file-based evaluation inputs."""

import json
import math
import os
import stat
from pathlib import Path

MAX_REPORT_BYTES = 32 * 1024 * 1024


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON objects must not contain duplicate keys")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ValueError("JSON inputs must contain only finite numbers")


def parse_json_object(raw: bytes) -> dict:
    """Reject ambiguous keys, nonfinite numbers and excessive nesting."""
    try:
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    except RecursionError as exc:
        raise ValueError("JSON input exceeds the nesting limit") from exc
    if not isinstance(result, dict):
        raise ValueError("JSON input must be an object")  # noqa: TRY004

    def check(value, depth=0):
        if depth > 64:
            raise ValueError("JSON input exceeds the nesting limit")
        if isinstance(value, float) and not math.isfinite(value):
            _nonfinite(value)
        if isinstance(value, dict):
            for item in value.values():
                check(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                check(item, depth + 1)

    check(result)
    return result


def read_json_object(path: Path) -> dict:
    """Read a regular file with a size limit, without blocking on a FIFO."""
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
        raise ValueError("JSON input must be a regular file no larger than 32 MiB")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError("JSON input changed or exceeded the file size limit")
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("JSON input exceeds the file size limit")
    return parse_json_object(raw)
