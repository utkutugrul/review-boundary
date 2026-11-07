"""Strict, inert metadata for candidate corpora that are still under research.

A ``CandidateCatalog`` is a list of unverified research notes. Nothing here fetches a URL,
imports or evaluates candidate text, registers a corpus, or runs an oracle. Parsing checks
structure only: it never establishes admission, authenticity, runtime behavior or source
independence. Revision fields describe comparisons and selected changes. They do not assert
that vulnerable or fixed behavior was reproduced, and a proposed source group or an advisory
alias proves no independence.

Public entry points raise a bounded static ``ValueError`` and never echo input text.
"""

import json
import math
import os
import re
import stat
import unicodedata
from pathlib import Path
from typing import Annotated, Any, Literal, get_args

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)

from .corpus_manifest import Alias, HttpsUrl, Revision, Text
from .json_input import parse_json_object

CANDIDATE_CATALOG_SCHEMA_VERSION = 1
MAX_CANDIDATE_CATALOG_BYTES = 256 * 1024
MAX_CANDIDATE_RECORDS = 64

_MAX_DEPTH = 64
_MAX_NODES = 16384
_MAX_STRING_CHARS = 512
_MAX_KEY_CHARS = 64
_MAX_INTEGER = 2**63
_INVALID = "Invalid candidate catalog input."
_SLUG = re.compile(r"[a-z][a-z0-9_-]{0,63}")

MetadataStatus = Literal["unknown", "researched"]
RuntimeStatus = Literal["unknown", "requirements_recorded", "unavailable"]
LicenseStatus = Literal["unknown", "notices_pending", "inventory_recorded"]
Disposition = Literal["research", "held", "deferred", "rejected"]


def _safe_text(value: str, cap: int) -> str:
    """Bound characters and UTF-8 bytes, and reject surrogates and Unicode Cc/Cs controls."""
    if len(value) > cap:
        raise ValueError("Text exceeds its character bound.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("Text contains an unpaired surrogate.") from None
    if len(encoded) > cap:
        raise ValueError("Text exceeds its UTF-8 byte bound.")
    if any(unicodedata.category(char) in ("Cc", "Cs") for char in value):
        raise ValueError("Text contains a control character or surrogate.")
    return value


def _checker(cap: int):
    def check(value: str) -> str:
        return _safe_text(value, cap)

    return check


def _slug(value: str) -> str:
    if not _SLUG.fullmatch(value):
        raise ValueError("Expected a lowercase candidate slug of 1 to 64 characters.")
    return value


def _unique(values, message: str) -> None:
    values = list(values)
    if len(set(values)) != len(values):
        raise ValueError(message)


# The shared manifest types stay in force. These only add the candidate-local checks.
SafeText = Annotated[Text, AfterValidator(_checker(256))]
SafeUrl = Annotated[HttpsUrl, AfterValidator(_checker(512))]
CandidateId = Annotated[StrictStr, AfterValidator(_slug)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)


class CandidateRecord(_Model):
    """One unverified research note. Every field is required, nullable ones take null."""

    candidate_id: CandidateId
    upstream_url: SafeUrl
    advisory_url: SafeUrl | None
    aliases: Annotated[tuple[Alias, ...], Field(max_length=16)]
    language: SafeText
    proposed_source_group: SafeText | None
    comparison_revision: Revision | None
    selected_change_revision: Revision | None
    metadata_status: MetadataStatus
    runtime_status: RuntimeStatus
    license_status: LicenseStatus
    disposition: Disposition
    evidence_urls: Annotated[tuple[SafeUrl, ...], Field(max_length=8)]
    note: SafeText

    @model_validator(mode="after")
    def distinct_values(self):
        _unique(self.aliases, "Advisory aliases must be unique.")
        _unique(self.evidence_urls, "Evidence URLs must be unique.")
        return self


class CandidateCatalog(_Model):
    schema_version: Literal[1]
    records: Annotated[tuple[CandidateRecord, ...], Field(max_length=MAX_CANDIDATE_RECORDS)]

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_integer_version(cls, value: Any) -> Any:
        if type(value) is not int or value != CANDIDATE_CATALOG_SCHEMA_VERSION:
            raise ValueError("schema_version must be the exact integer 1.")
        return value

    @model_validator(mode="after")
    def unique_ids(self):
        _unique((record.candidate_id for record in self.records), "Candidate IDs must be unique.")
        return self


def _walk(value: Any) -> None:
    """Accept only a bounded tree of exact dict, list and builtin JSON scalar types."""
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > _MAX_NODES or depth > _MAX_DEPTH:
            raise ValueError(_INVALID)
        kind = type(item)
        if kind is dict:
            if nodes + len(pending) + len(item) > _MAX_NODES:
                raise ValueError(_INVALID)
            for key, child in item.items():
                if type(key) is not str:
                    raise ValueError(_INVALID)
                _safe_text(key, _MAX_KEY_CHARS)
                pending.append((child, depth + 1))
        elif kind is list:
            if nodes + len(pending) + len(item) > _MAX_NODES:
                raise ValueError(_INVALID)
            pending.extend((child, depth + 1) for child in item)
        elif kind is str:
            _safe_text(item, _MAX_STRING_CHARS)
        elif kind is int:
            if abs(item) >= _MAX_INTEGER:
                raise ValueError(_INVALID)
        elif kind is float:
            if not math.isfinite(item):
                raise ValueError(_INVALID)
        elif kind is not bool and item is not None:
            raise ValueError(_INVALID)


def _catalog_from_tree(value: Any) -> CandidateCatalog:
    if type(value) is not dict:
        raise ValueError(_INVALID)
    records = value.get("records")
    if type(records) is list and len(records) > MAX_CANDIDATE_RECORDS:
        raise ValueError(_INVALID)
    _walk(value)
    encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > MAX_CANDIDATE_CATALOG_BYTES:
        raise ValueError(_INVALID)
    # Reuses the shared duplicate key, nonfinite and nesting checks.
    parse_json_object(encoded)
    # JSON text keeps bool, float and null distinct from integers and strings.
    return CandidateCatalog.model_validate_json(encoded)


def _guarded(operation, *args):
    """Run an operation and replace any failure with a static error that chains nothing."""
    try:
        return operation(*args)
    except (ValueError, TypeError, OverflowError, RecursionError, OSError):
        error = ValueError(_INVALID)
    raise error


def parse_candidate_catalog(value: dict) -> CandidateCatalog:
    """Validate an already-decoded JSON object. This is metadata structure only."""
    return _guarded(_catalog_from_tree, value)


def _read_bounded(path: Path) -> bytes:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CANDIDATE_CATALOG_BYTES:
        raise ValueError(_INVALID)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CANDIDATE_CATALOG_BYTES:
            raise ValueError(_INVALID)
        raw = stream.read(MAX_CANDIDATE_CATALOG_BYTES + 1)
    if len(raw) > MAX_CANDIDATE_CATALOG_BYTES:
        raise ValueError(_INVALID)
    return raw


def _load(path: Path) -> CandidateCatalog:
    if not isinstance(path, Path):
        raise ValueError(_INVALID)  # noqa: TRY004
    raw = _read_bounded(path)
    # Strict UTF-8 only. NUL bytes and a BOM would let the JSON reader guess another encoding.
    if b"\x00" in raw or raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError(_INVALID)
    raw.decode("utf-8")
    return _catalog_from_tree(parse_json_object(raw))


def load_candidate_catalog(path: Path) -> CandidateCatalog:
    """Read a bounded regular UTF-8 file without blocking on a FIFO, then validate it."""
    return _guarded(_load, path)


def _counts(records, field: str, allowed: tuple[str, ...]) -> dict[str, int]:
    counts = dict.fromkeys(sorted(allowed), 0)
    for record in records:
        counts[getattr(record, field)] += 1
    return counts


def _summary(catalog: CandidateCatalog) -> dict:
    if type(catalog) is not CandidateCatalog:
        raise ValueError(_INVALID)
    # Revalidate so an unchecked model_copy cannot turn invalid metadata into a summary.
    checked = _catalog_from_tree(catalog.model_dump(mode="json"))
    records = checked.records
    return {
        "schema_version": CANDIDATE_CATALOG_SCHEMA_VERSION,
        "candidate_count": len(records),
        "metadata_status_counts": _counts(records, "metadata_status", get_args(MetadataStatus)),
        "runtime_status_counts": _counts(records, "runtime_status", get_args(RuntimeStatus)),
        "license_status_counts": _counts(records, "license_status", get_args(LicenseStatus)),
        "disposition_counts": _counts(records, "disposition", get_args(Disposition)),
        "admission": "not_established",
        "authenticity": "unverified_metadata",
        "independence": "not_inferred",
    }


def candidate_catalog_summary(catalog: CandidateCatalog) -> dict:
    """Count recorded statuses. Every allowed category is listed, in sorted key order.

    The result establishes no admission, authenticity or independence.
    """
    return _guarded(_summary, catalog)
