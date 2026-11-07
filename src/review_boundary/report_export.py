"""Deterministic report envelopes from explicitly supplied, bounded JSON evidence."""

import json
from copy import deepcopy
from pathlib import Path

from .evidence_refs import create_snapshot_binding, verify_snapshot_bindings
from .json_input import read_json_object
from .provenance import json_digest
from .report_contract import (
    detect_contract,
    export_report_envelope,
    unwrap_report,
    validate_report_document,
)
from .report_validation import (
    MAX_DEPTH,
    MAX_EXPORT_BYTES,
    MAX_ROWS,
    MAX_TOTAL_BYTES,
    DashboardError,
    bounded_json,
)

SNAPSHOT_ARTIFACT_VERSION = 1
SNAPSHOT_ARTIFACT_FIELDS = frozenset({"schema_version", "source_report_sha256", "snapshots"})
SNAPSHOT_ITEM_FIELDS = frozenset({"row_index", "source_row_sha256", "snapshot"})


def _snapshot_items(artifacts, native):
    if artifacts is None:
        return []
    bounded_json(artifacts, max_depth=MAX_DEPTH + 3)
    if (
        type(artifacts) is not dict
        or set(artifacts) != SNAPSHOT_ARTIFACT_FIELDS
        or type(artifacts["schema_version"]) is not int
        or artifacts["schema_version"] != SNAPSHOT_ARTIFACT_VERSION
    ):
        raise DashboardError("Snapshot artifacts require the supported closed schema version 1")
    if artifacts["source_report_sha256"] != json_digest(native):
        raise DashboardError("Snapshot artifacts do not match the selected source report")
    items = artifacts["snapshots"]
    if type(items) is not list or len(items) > MAX_ROWS:
        raise DashboardError("Snapshot artifacts require a bounded list of rows")
    seen = set()
    for item in items:
        if type(item) is not dict or set(item) != SNAPSHOT_ITEM_FIELDS:
            raise DashboardError("Snapshot artifact rows have unsupported or missing fields")
        index = item["row_index"]
        if type(index) is not int or not 0 <= index < len(native["rows"]):
            raise DashboardError("Snapshot artifact row index is outside the selected report")
        if index in seen:
            raise DashboardError("Snapshot artifacts repeat a source row")
        seen.add(index)
        if item["source_row_sha256"] != json_digest(native["rows"][index]):
            raise DashboardError(f"Snapshot artifact does not match source row {index}")
        if type(item["snapshot"]) is not dict:
            raise DashboardError(f"Snapshot artifact for row {index} must be an object")
        bounded_json(item["snapshot"])
    return items


def compile_snapshot_evidence(document, *, snapshot_artifacts=None, suite=None):
    """Return references and separate consistency results, without trusting claimed checks.

    Artifacts contain only schema_version, source_report_sha256 and snapshots.
    Each snapshot item contains row_index, source_row_sha256 and snapshot. All
    digests identify the unchanged native document or its recorded row. A suite
    is optional bounded case data, never a module or a path inside JSON.
    """
    native = unwrap_report(document)
    contract = detect_contract(document)
    bindings = deepcopy(document.get("snapshot_bindings", [])) if contract.envelope_version else []
    by_row = {binding["row_index"]: binding for binding in bindings}
    snapshots = {}
    supplied_rows = set()
    for item in _snapshot_items(snapshot_artifacts, native):
        index = item["row_index"]
        try:
            binding = create_snapshot_binding(native, index, item["snapshot"])
        except ValueError:
            raise DashboardError(
                f"Supplied snapshot does not consistently bind to source row {index}"
            ) from None
        if index in by_row and binding != by_row[index]:
            raise DashboardError(f"Supplied snapshot conflicts with the reference for row {index}")
        if index not in by_row:
            bindings.append(binding)
            by_row[index] = binding
        snapshots[binding["snapshot_sha256"]] = item["snapshot"]
        supplied_rows.add(index)
    results = verify_snapshot_bindings(native, bindings, snapshots=snapshots, suite=suite)
    for result in results:
        if (
            result["row_index"] in supplied_rows
            and result["status"] != "matching_supplied_artifact"
        ):
            raise DashboardError(
                f"Supplied snapshot verification failed for row {result['row_index']}: "
                + result["reason"]
            )
    return bindings, {"source_report_sha256": json_digest(native), "rows": results}


def prepare_report_export(document, *, snapshot_artifacts=None, suite=None) -> dict:
    """Wrap native or already wrapped data deterministically, preserving recorded fields."""
    bindings, _ = compile_snapshot_evidence(
        document, snapshot_artifacts=snapshot_artifacts, suite=suite
    )
    return export_report_envelope(unwrap_report(document), snapshot_bindings=bindings)


def write_report_export(
    source: Path,
    output: Path,
    *,
    snapshot_artifacts: Path | None = None,
    suite: Path | None = None,
) -> Path:
    """Create a private new JSON envelope; supplied snapshots stay outside the output."""
    from .repository_adjudication import write_new_text

    inputs = [
        Path(path).expanduser() for path in (source, snapshot_artifacts, suite) if path is not None
    ]
    if sum(path.stat().st_size for path in inputs) > MAX_TOTAL_BYTES:
        raise DashboardError("Report export inputs must total at most 32 MiB")
    document = read_json_object(Path(source).expanduser())
    validate_report_document(document)
    artifacts = (
        read_json_object(Path(snapshot_artifacts).expanduser()) if snapshot_artifacts else None
    )
    supplied_suite = read_json_object(Path(suite).expanduser()) if suite else None
    envelope = prepare_report_export(document, snapshot_artifacts=artifacts, suite=supplied_suite)
    text = json.dumps(
        envelope, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    if len(text.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise DashboardError("The escaped report exceeds the 64 MiB export limit")
    return write_new_text(Path(output).expanduser(), text + "\n", "report export")
