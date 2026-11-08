"""Inspectable experiment fingerprints, not an authenticity or reproducibility guarantee."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


class ProvenanceError(ValueError):
    """Invalid or unavailable experiment fingerprint inputs."""


SCHEMA_VERSION = 1
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 16 * 1024 * 1024
MAX_HARNESS_FILES = 128
_HASH = re.compile(r"[0-9a-f]{64}")
HARNESS_FILES = (
    "cli.py",
    "report.py",
    "reconstruct.py",
    "compare.py",
    "native_compare.py",
    "source_group_analysis.py",
    "source_group_analysis_io.py",
    "report_validation.py",
    "report_contract.py",
    "evidence_refs.py",
    "report_export.py",
    "dashboard.py",
    "ci.py",
    "budget.py",
    "json_input.py",
    "task.py",
    "world.py",
    "cases.py",
    "corpus_typescript.py",
    "corpus_rust.py",
    "corpus_manifest.py",
    "corpus_registry.py",
    "corpus_candidates.py",
    "corpus_sharding.py",
    "suite_contribution.py",
    "adapter.py",
    "isolation_payload.py",
    "isolated_runner.py",
    "isolated_verifier.py",
    "model_safety.py",
    "providers.py",
    "provenance.py",
    "repository_cases.py",
    "repository_cases_v2.py",
    "repository_runtime.py",
    "payload_packs.py",
    "payload_fixtures.py",
    "repository_suite.py",
    "suite_validation.py",
    "repository_world.py",
    "repository_world_v2.py",
    "repository_runner.py",
    "repository_task.py",
    "repository_adjudication.py",
    "repository_adjudication_agreement.py",
    "repository_adjudication_ui.py",
    "boundary_cases.py",
    "boundary_world.py",
    "boundary_policy.py",
    "boundary_runner.py",
    "boundary_task.py",
    "mcp_adapter.py",
    "mcp_bridge.py",
    "corpus_upstream_pyjwt.py",
    "upstream_runner.py",
    "workflow_cases.py",
    "workflow_world.py",
    "workflow_replay.py",
)


def json_digest(value: Any) -> str:
    data = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def source_path(value: str) -> str:
    """Validate an explicitly declared relative source path without resolving it."""
    if not isinstance(value, str):
        raise ProvenanceError("Reviewer source paths must be strings")
    path = PurePosixPath(value)
    if (
        not value
        or not path.parts
        or len(value) > 512
        or path.is_absolute()
        or str(path) != value
        or any(part in (".", "..") for part in path.parts)
        or "\\" in value
        or ":" in value
        or any(ord(char) < 32 for char in value)
    ):
        raise ProvenanceError("Reviewer source paths must be bounded, normalized relative paths")
    return value


def source_fingerprint(base_dir: Path, paths: list[str] | tuple[str, ...]) -> dict:
    """Hash only explicit regular source files, without storing contents or host paths."""
    return _source_fingerprint(base_dir, paths, maximum_files=32)


def _source_fingerprint(
    base_dir: Path, paths: list[str] | tuple[str, ...], *, maximum_files: int
) -> dict:
    if not paths:
        return {"status": "not_recorded", "sha256": None, "files": {}}
    if len(paths) > maximum_files or len(set(paths)) != len(paths):
        raise ProvenanceError(f"Declare at most {maximum_files} distinct source files")
    base = base_dir.resolve(strict=True)
    files = {}
    total = 0
    for value in sorted(paths):
        source_path(value)
        path = base / value
        # Refuse source aliases rather than accidentally hashing a file outside the declaration.
        for component in path.relative_to(base).parents:
            if (base / component).is_symlink():
                raise ProvenanceError("Declared source paths must not contain symlinks")
        if path.is_symlink():
            raise ProvenanceError("Declared source files must not be symlinks")
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
            raise ProvenanceError("Declared source files must be regular files up to 4 MiB")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
                raise ProvenanceError("Declared source file changed or exceeded the size limit")
            data = stream.read(MAX_SOURCE_BYTES + 1)
        total += len(data)
        if len(data) > MAX_SOURCE_BYTES or total > MAX_TOTAL_SOURCE_BYTES:
            raise ProvenanceError("Declared source files exceed the 16 MiB aggregate limit")
        files[value] = hashlib.sha256(data).hexdigest()
    return {"status": "recorded", "sha256": json_digest(files), "files": files}


def experiment_provenance(
    prompts: dict[str, str],
    tools: list[dict],
    *,
    protocol: str,
    reviewer_source: dict | None = None,
    harness_files: tuple[str, ...] = HARNESS_FILES,
) -> dict:
    """Fingerprint actual caller instructions, advertised schemas and declared source files."""
    return {
        "schema_version": SCHEMA_VERSION,
        "hash_algorithm": "sha256",
        "prompts": {name: text_digest(text) for name, text in prompts.items()},
        "tools": {"protocol": protocol, "sha256": json_digest(tools)},
        "harness": _source_fingerprint(
            Path(__file__).parent, harness_files, maximum_files=MAX_HARNESS_FILES
        ),
        "reviewer_source": reviewer_source or source_fingerprint(Path.cwd(), ()),
        "scope": "Caller instructions, advertised tool schemas and declared local source files only",
    }


def validate_provenance(value: Any) -> None:
    """Validate recorded fingerprints without claiming that their contents are authentic."""
    if (
        not isinstance(value, dict)
        or type(value.get("schema_version")) is not int
        or value["schema_version"] != SCHEMA_VERSION
    ):
        raise ProvenanceError("Unsupported experiment provenance")
    if value.get("hash_algorithm") != "sha256":
        raise ProvenanceError("Unsupported experiment fingerprint algorithm")
    prompts = value.get("prompts")
    if not isinstance(prompts, dict) or not prompts or len(prompts) > 32:
        raise ProvenanceError("Provenance requires a bounded prompt fingerprint map")
    for name, fingerprint in prompts.items():
        if not isinstance(name, str) or not name or len(name) > 128:
            raise ProvenanceError("Invalid provenance prompt label")
        _validate_hash(fingerprint)
    tools = value.get("tools")
    if not isinstance(tools, dict) or not isinstance(tools.get("protocol"), str):
        raise ProvenanceError("Invalid provenance tool schema")
    if not tools["protocol"] or len(tools["protocol"]) > 128:
        raise ProvenanceError("Invalid provenance tool protocol")
    _validate_hash(tools.get("sha256"))
    for name in ("harness", "reviewer_source"):
        source = value.get(name)
        if not isinstance(source, dict) or not isinstance(source.get("files"), dict):
            raise ProvenanceError("Invalid provenance source manifest")
        if source.get("status") == "not_recorded":
            if source.get("sha256") is not None or source["files"]:
                raise ProvenanceError("Unknown source provenance must not claim a fingerprint")
            continue
        maximum_files = MAX_HARNESS_FILES if name == "harness" else 32
        if source.get("status") != "recorded" or not 1 <= len(source["files"]) <= maximum_files:
            raise ProvenanceError("Invalid provenance source status")
        for path, digest in source["files"].items():
            source_path(path)
            _validate_hash(digest)
        _validate_hash(source.get("sha256"))
        if source["sha256"] != json_digest(source["files"]):
            raise ProvenanceError("Provenance source manifest does not match its aggregate hash")


def _validate_hash(value: Any) -> None:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ProvenanceError("Invalid SHA-256 provenance fingerprint")


def compare_provenance(before: dict, after: dict, before_defense: str, after_defense: str) -> dict:
    """Describe intentional differences; missing fingerprints never count as equality."""
    for metadata in (before, after):
        if metadata.get("provenance") is not None:
            validate_provenance(metadata["provenance"])
    old, new = before.get("provenance"), after.get("provenance")

    def fields(provenance, defense):
        if provenance is None:
            return {}
        return {
            "instructions": provenance["prompts"].get(defense),
            "tool_schema": provenance["tools"]["sha256"],
            "tool_protocol": provenance["tools"]["protocol"],
            "harness_source": provenance["harness"]["sha256"],
            "reviewer_source": provenance["reviewer_source"]["sha256"],
        }

    left, right = fields(old, before_defense), fields(new, after_defense)
    changes, unknown, unchanged = [], [], []
    for name in (
        "instructions",
        "tool_schema",
        "tool_protocol",
        "harness_source",
        "reviewer_source",
    ):
        a, b = left.get(name), right.get(name)
        if a is None or b is None:
            unknown.append(name)
        elif a != b:
            changes.append({"field": name, "baseline": a, "candidate": b})
        else:
            unchanged.append(name)
    return {
        "status": "changed" if changes else "unknown" if unknown else "unchanged",
        "changes": changes,
        "unknown_fields": unknown,
        "unchanged_fields": unchanged,
        "gating": False,
        "note": "Fingerprints describe experiment inputs; they do not authenticate artifacts or prove reviewer equivalence.",
    }
