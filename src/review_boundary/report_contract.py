"""Lossless report envelopes and separate display versus digest-consistency checks."""

from copy import deepcopy
from dataclasses import dataclass

from .provenance import json_digest
from .report_validation import (
    MAX_DEPTH,
    DashboardError,
    _hash,
    bounded_json,
    native_contract,
    validate_native_report,
)
from .repository_world import finding_digest, review_digest

ReportContractError = DashboardError
ENVELOPE_VERSION = 3
ENVELOPE_REQUIRED_FIELDS = frozenset(
    {"schema_version", "report_kind", "report_version", "source_report_sha256", "report"}
)
ENVELOPE_OPTIONAL_FIELDS = frozenset({"snapshot_bindings"})


@dataclass(frozen=True)
class ReportContract:
    report_kind: str
    report_version: int
    envelope_version: int | None = None


def detect_contract(document: dict) -> ReportContract:
    """Read exact discriminators without inferring a tier from its measurements."""
    if type(document) is not dict or type(document.get("schema_version")) is not int:
        raise ReportContractError("Report requires an exact integer schema version")
    if document["schema_version"] != ENVELOPE_VERSION:
        kind, version = native_contract(document)
        return ReportContract(kind, version)
    if not ENVELOPE_REQUIRED_FIELDS.issubset(document) or set(document) - (
        ENVELOPE_REQUIRED_FIELDS | ENVELOPE_OPTIONAL_FIELDS
    ):
        raise ReportContractError("Report envelope has unsupported or missing fields")
    if type(document["report_version"]) is not int:
        raise ReportContractError("Report envelope requires an exact native version")
    if type(document["report_kind"]) is not str:
        raise ReportContractError("Report envelope requires a plain native kind")
    kind, version = native_contract(document["report"])
    if document["report_kind"] != kind or document["report_version"] != version:
        raise ReportContractError("Envelope and native report discriminators disagree")
    _hash(document["source_report_sha256"])
    return ReportContract(kind, version, ENVELOPE_VERSION)


def validate_display_document(document: dict) -> ReportContract:
    """Validate display structure only; browser implementations mirror this level."""
    contract = detect_contract(document)
    bounded_json(document, max_depth=MAX_DEPTH + (2 if contract.envelope_version else 0))
    native = document["report"] if contract.envelope_version else document
    validate_native_report(native)
    if contract.envelope_version:
        from .evidence_refs import validate_snapshot_bindings

        validate_snapshot_bindings(document.get("snapshot_bindings", []))
    return contract


def _digest(value) -> str:
    try:
        return json_digest(value)
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise ReportContractError("Report cannot be canonically fingerprinted") from None


def _native_digest_consistency(native, kind):
    if kind == "legacy":
        return
    for row in native["rows"]:
        review = row["review"]
        for detail in row["findings"]:
            if finding_digest(detail["finding"]) != detail["finding_sha256"]:
                raise ReportContractError("Recorded finding digest disagrees with its content")
        if review is not None:
            digest = review_digest(review)
            judgment = row["review_adjudication"]
            if judgment is not None and judgment["review_sha256"] != digest:
                raise ReportContractError("Recorded review decision has a mismatched digest")
            if any(
                event.get("review_sha256") != digest
                for event in row["events"]
                if event["tool"] == "submit_review" and event["status"] == "ok"
            ):
                raise ReportContractError("Recorded submission digest disagrees with its review")
        if kind == "boundary":
            for effect in row["effects"]:
                key = "path" if effect["tool"] == "save_report" else "url"
                expected = _digest(
                    {
                        "tool": effect["tool"],
                        "arguments": {key: effect["target"], "content": effect["content"]},
                    }
                )
                if effect["effect_id"] != expected:
                    raise ReportContractError(
                        "Recorded virtual effect digest disagrees with its content"
                    )


def validate_report_document(document: dict) -> ReportContract:
    """Also check canonical digest consistency; this does not authenticate a report."""
    contract = validate_display_document(document)
    native = document["report"] if contract.envelope_version else document
    if contract.envelope_version and _digest(native) != document["source_report_sha256"]:
        raise ReportContractError("Envelope source report digest does not match its content")
    _native_digest_consistency(native, contract.report_kind)
    return contract


def unwrap_report(document: dict) -> dict:
    """Return an independent, unchanged native document after consistency checks."""
    contract = validate_report_document(document)
    return deepcopy(document["report"] if contract.envelope_version else document)


def export_report_envelope(native_report: dict, *, snapshot_bindings=()) -> dict:
    """Wrap a native report deterministically without adding measurements or time."""
    contract = validate_report_document(native_report)
    if contract.envelope_version is not None:
        raise ReportContractError("An envelope cannot be wrapped inside another envelope")
    from .evidence_refs import validate_snapshot_bindings

    bindings = list(snapshot_bindings) if type(snapshot_bindings) in (list, tuple) else None
    validate_snapshot_bindings(bindings)
    result = {
        "schema_version": ENVELOPE_VERSION,
        "report_kind": contract.report_kind,
        "report_version": contract.report_version,
        "source_report_sha256": _digest(native_report),
        "report": deepcopy(native_report),
        "snapshot_bindings": deepcopy(
            sorted(bindings, key=lambda b: (b["row_index"], b["snapshot_kind"]))
        ),
    }
    validate_report_document(result)
    return result
