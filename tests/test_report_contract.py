"""Native report compatibility, strict envelope dispatch and honest unknowns."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from report_contract_support import legacy_fixture, native_fixture

from review_boundary.boundary_cases import build_boundary_cases
from review_boundary.boundary_runner import boundary_error_rows
from review_boundary.provenance import json_digest
from review_boundary.report_contract import (
    ReportContract,
    detect_contract,
    export_report_envelope,
    unwrap_report,
    validate_display_document,
    validate_report_document,
)
from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import repository_error_rows


@pytest.mark.parametrize("kind", ["legacy", "repository", "boundary"])
def test_native_envelope_roundtrip_is_lossless_deterministic_and_independent(kind):
    native = legacy_fixture() if kind == "legacy" else native_fixture(kind)[0]
    original = deepcopy(native)
    envelope = export_report_envelope(native)
    assert envelope == export_report_envelope(native)
    assert envelope["report"] == original
    assert envelope["snapshot_bindings"] == []
    assert envelope["source_report_sha256"] == json_digest(original)
    assert detect_contract(envelope) == ReportContract(kind, 2 if kind == "legacy" else 1, 3)
    restored = unwrap_report(envelope)
    assert restored == original
    restored["metadata"]["edited"] = True
    assert native == original and "edited" not in envelope["report"]["metadata"]
    native["metadata"]["later"] = True
    assert "later" not in envelope["report"]["metadata"]


@pytest.mark.parametrize("version", [True, False, 1.0, 2.0, 3.0, "3", None])
def test_versions_are_exact_integer_discriminators(version):
    report = legacy_fixture()
    report["schema_version"] = version
    with pytest.raises(ValueError):
        detect_contract(report)


@pytest.mark.parametrize(
    "change",
    [
        lambda e: e.update(report_kind="boundary"),
        lambda e: e.update(report_version=True),
        lambda e: e.update(report_version=1.0),
        lambda e: e.update(report_version=2),
        lambda e: e.update(extra="unrecognized"),
        lambda e: e["report"].update(report_kind="legacy"),
        lambda e: e["report"].update(schema_version=3),
    ],
)
def test_conflicting_ambiguous_or_nested_envelopes_fail(change):
    envelope = export_report_envelope(native_fixture()[0])
    change(envelope)
    with pytest.raises(ValueError):
        validate_report_document(envelope)


def test_display_validation_does_not_pretend_to_verify_canonical_hashes():
    envelope = export_report_envelope(native_fixture()[0])
    envelope["source_report_sha256"] = "0" * 64
    validate_display_document(envelope)
    with pytest.raises(ValueError, match="digest"):
        validate_report_document(envelope)
    envelope = export_report_envelope(native_fixture()[0])
    del envelope["snapshot_bindings"]
    assert unwrap_report(envelope) == envelope["report"]


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_provider_error_rows_display_without_fabricating_trusted_evidence(kind):
    report, _, _ = native_fixture(kind)
    if kind == "repository":
        case = build_repository_demo_cases()[0]
        row = repository_error_rows((case,), "fixture/reference", 1, "provider_error")[0]
    else:
        case = build_boundary_cases()[0]
        row = boundary_error_rows((case,), "fixture/reference", 1, ["off"], "provider_error")[0]
    report["rows"] = [row]
    validate_report_document(report)
    assert row["semantic_passed"] is None
    assert export_report_envelope(report)["snapshot_bindings"] == []


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("error", ["", " ", "\t\n", "\u0085", "\x1c", False, 0])
def test_native_error_requires_null_or_nonblank_bounded_string(kind, error):
    report, _, _ = native_fixture(kind)
    report["rows"][0]["error"] = error
    with pytest.raises(ValueError, match="Native report error"):
        validate_report_document(report)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_every_nonnull_native_error_denotes_failed_execution(kind):
    report, _, _ = native_fixture(kind)
    row = report["rows"][0]
    row["error"] = "\ufeff"
    with pytest.raises(ValueError, match="Failed native rows"):
        validate_report_document(report)
    row.update(completed=False, conclusive=False, rubric_passed=False)
    if kind == "boundary":
        row.update(task_success=False, review_rubric_passed=False, agent_resisted=None)
    validate_report_document(report)


@pytest.mark.parametrize("error", ["", " ", "\u0085", "\x1c"])
def test_legacy_error_strings_keep_historical_validation(error):
    report = json.loads(Path("examples/calibration-v2/report.json").read_text())
    report["rows"][0]["error"] = error
    validate_report_document(report)


def test_historical_repository_coverage_and_partial_run_remain_unknown():
    report, _, _ = native_fixture(slots=False)
    report["metadata"].update(run_finished=False, expected_count=4)
    original = deepcopy(report)
    assert unwrap_report(export_report_envelope(report)) == original
    assert "expected_slots" not in report["metadata"]


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r["rows"].append(deepcopy(r["rows"][0])),
        lambda r: r["metadata"]["expected_slots"].append(
            deepcopy(r["metadata"]["expected_slots"][0])
        ),
        lambda r: r["metadata"]["expected_slots"][0].update(epoch=1.0),
        lambda r: r["metadata"].update(expected_count=2),
        lambda r: r["rows"][0].update(unique_finding_count=99),
        lambda r: r["rows"][0].update(semantic_passed=True),
        lambda r: r["rows"][0].update(tool_calls=999),
    ],
)
def test_invalid_native_counts_slots_or_semantics_fail(change):
    report, _, _ = native_fixture()
    change(report)
    with pytest.raises(ValueError):
        validate_report_document(report)


@pytest.mark.parametrize(
    "field", ["unauthorized_action_attempts", "invalid_action_attempts", "executed_actions"]
)
def test_impossible_boundary_counts_fail(field):
    report, _, _ = native_fixture("boundary")
    report["rows"][0][field] += 1
    with pytest.raises(ValueError):
        validate_report_document(report)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), 2**53, "\ud800", b"not-json"])
def test_invalid_json_values_are_bounded_and_never_echoed(value):
    report = legacy_fixture()
    report["metadata"]["marker-secret-not-for-diagnostics"] = value
    with pytest.raises(ValueError) as error:
        validate_report_document(report)
    assert "marker-secret-not-for-diagnostics" not in str(error.value)


def test_excessive_depth_nodes_and_size_reject_before_copy_or_hash():
    report = legacy_fixture()
    nested = {}
    for _ in range(24):
        nested = {"nested": nested}
    report["metadata"]["nested"] = nested
    with pytest.raises(ValueError):
        export_report_envelope(report)
    report = legacy_fixture()
    report["metadata"]["too_many"] = [None] * 200_001
    with pytest.raises(ValueError):
        validate_report_document(report)
    report = legacy_fixture()
    report["metadata"]["oversized"] = "x" * (1024 * 1024 + 1)
    with pytest.raises(ValueError):
        validate_report_document(report)


@pytest.mark.parametrize("case_index", range(len(build_repository_demo_cases())))
@pytest.mark.parametrize("mode", ["reference", "hijacked"])
def test_all_bundled_repository_rows_keep_unknown_semantics(case_index, mode):
    report, _, _ = native_fixture(case_index=case_index, mode=mode)
    validate_report_document(report)
    assert unwrap_report(export_report_envelope(report))["rows"][0]["semantic_passed"] is None


@pytest.mark.parametrize("case_index", range(len(build_boundary_cases())))
@pytest.mark.parametrize("guard", ["off", "on"])
@pytest.mark.parametrize("mode", ["reference", "gullible", "overblocking"])
def test_all_bundled_boundary_rows_keep_guard_and_utility_meanings(case_index, guard, mode):
    report, _, _ = native_fixture("boundary", case_index=case_index, guard=guard, mode=mode)
    validate_report_document(report)


def test_existing_legacy_example_still_roundtrips_without_rescoring():
    path = Path("examples/calibration-v2/report.json")
    report = json.loads(path.read_text())
    assert unwrap_report(export_report_envelope(report)) == report


@pytest.mark.parametrize(
    "change",
    [
        lambda report: report["metadata"]["expected_slots"][0].update(reviewer="undeclared"),
        lambda report: report["metadata"]["expected_slots"][0].update(epoch=2),
        lambda report: report["metadata"].update(case_count=2),
        lambda report: report["metadata"]["reviewers"].append("missing-group"),
    ],
)
def test_expected_slots_cannot_claim_incomplete_or_foreign_declared_groups(change):
    report, _, _ = native_fixture()
    report["rows"] = []
    change(report)
    with pytest.raises(ValueError):
        validate_report_document(report)


def test_discriminator_detection_never_invokes_non_json_object_methods():
    class NotJson:
        def __eq__(self, other):
            raise AssertionError("Object methods must not run during JSON dispatch")

    for report in (
        {"schema_version": 1, "report_kind": NotJson()},
        {
            "schema_version": 3,
            "report_kind": NotJson(),
            "report_version": 1,
            "source_report_sha256": "0" * 64,
            "report": native_fixture()[0],
        },
    ):
        with pytest.raises(ValueError):
            detect_contract(report)
