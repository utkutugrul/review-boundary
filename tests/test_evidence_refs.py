"""Bound references to supplied immutable artifacts without inventing their origin."""

from copy import deepcopy

import pytest
from report_contract_support import legacy_fixture, native_fixture

from review_boundary.evidence_refs import (
    create_snapshot_binding,
    evidence_locator,
    validate_snapshot_bindings,
    verify_snapshot_bindings,
)
from review_boundary.provenance import json_digest
from review_boundary.report_contract import export_report_envelope


def supplied(kind="repository", **kwargs):
    report, case, world = native_fixture(kind, **kwargs)
    snapshot = world.snapshot()
    binding = create_snapshot_binding(report, 0, snapshot)
    return report, case, snapshot, binding


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_snapshot_reference_roundtrip_binds_actual_supplied_artifact(kind):
    report, case, snapshot, binding = supplied(kind)
    original = deepcopy((report, snapshot, binding))
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[0]
    assert result["status"] == "matching_supplied_artifact"
    assert result["case_validation"] == "not_supplied"
    assert result["authenticity"] == "not_established"
    with_case = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}, suite=(case,)
    )[0]
    assert with_case["status"] == "matching_supplied_artifact"
    assert with_case["case_validation"] == "restored_and_observations_match"
    assert (report, snapshot, binding) == original
    envelope = export_report_envelope(report, snapshot_bindings=[binding])
    assert envelope["snapshot_bindings"] == [binding]
    assert "snapshot" not in envelope and "events" not in binding


def test_missing_references_and_missing_artifacts_have_separate_states():
    report, _, _, binding = supplied()
    missing_ref = verify_snapshot_bindings(report, [], snapshots={})[0]
    missing_artifact = verify_snapshot_bindings(report, [binding], snapshots={})[0]
    assert missing_ref["status"] == "not_recorded"
    assert missing_artifact["status"] == "unavailable"


@pytest.mark.parametrize(
    "field", ["source_report_sha256", "source_row_sha256", "case_sha256", "limits_sha256"]
)
def test_changed_report_row_case_or_limits_cannot_reuse_snapshot(field):
    report, _, snapshot, binding = supplied()
    binding[field] = "0" * 64
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[0]
    assert result["status"] == "mismatch"


def test_changed_snapshot_bytes_do_not_match_original_digest():
    report, _, snapshot, binding = supplied()
    snapshot["read_pr"] = False
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[0]
    assert result["status"] == "mismatch"
    assert result["reason"] == "snapshot_digest_mismatch"


def test_future_snapshot_versions_remain_explicitly_unsupported():
    report, _, snapshot, binding = supplied()
    binding["snapshot_version"] = 2
    assert (
        verify_snapshot_bindings(report, [binding], snapshots={})[0]["status"]
        == "unsupported_version"
    )
    binding["snapshot_version"] = 1
    snapshot["schema_version"] = 2
    binding["snapshot_sha256"] = json_digest(snapshot)
    assert (
        verify_snapshot_bindings(
            report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
        )[0]["status"]
        == "unsupported_version"
    )


@pytest.mark.parametrize("field", ["repository_case_sha256", "policy_sha256", "guard"])
def test_boundary_nested_case_guard_and_policy_bindings_cannot_be_substituted(field):
    report, _, snapshot, binding = supplied("boundary")
    binding[field] = "on" if field == "guard" else "0" * 64
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[0]
    assert result["status"] == "mismatch"
    assert binding["case_sha256"] != snapshot["repository_case_sha256"]


def test_external_policy_snapshot_is_explicitly_unsupported():
    report, _, snapshot, binding = supplied("boundary")
    report["metadata"]["external_policy"] = {"declared": "external-process"}
    binding["source_report_sha256"] = json_digest(report)
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[0]
    assert result["status"] == "unsupported_policy"


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("error", ["Provider model evaluation failed; details withheld", "\ufeff"])
def test_failed_execution_cannot_be_rescored_into_verified_evidence(kind, error):
    report, _, snapshot, binding = supplied(kind)
    row = report["rows"][0]
    row.update(
        error=error,
        completed=False,
        conclusive=False,
        rubric_passed=False,
    )
    if kind == "boundary":
        row.update(task_success=False, review_rubric_passed=False, agent_resisted=None)
    binding.update(source_report_sha256=json_digest(report), source_row_sha256=json_digest(row))
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
    )[0]
    assert result["status"] == "unavailable"
    assert result["case_validation"] == "not_supplied"
    with pytest.raises(ValueError):
        create_snapshot_binding(report, 0, snapshot)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("error", ["", " \t", "\u0085", "\x1c"])
def test_blank_native_error_never_earns_snapshot_credit(kind, error):
    report, _, snapshot, binding = supplied(kind)
    row = report["rows"][0]
    row["error"] = error
    binding.update(source_report_sha256=json_digest(report), source_row_sha256=json_digest(row))
    with pytest.raises(ValueError, match="Native report error"):
        verify_snapshot_bindings(
            report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}
        )
    with pytest.raises(ValueError, match="Native report error"):
        create_snapshot_binding(report, 0, snapshot)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_valid_snapshot_for_other_case_is_not_an_authoritative_case_restore(kind):
    report, _, snapshot, binding = supplied(kind)
    _, other, _ = native_fixture(kind, case_index=1)
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}, suite=(other,)
    )[0]
    assert result["status"] == "mismatch"


@pytest.mark.parametrize("run_kind", ["model", "calibration", "adapter"])
def test_historical_boundary_suite_digest_conventions_are_preserved(run_kind):
    report, case, snapshot, binding = supplied("boundary")
    report["metadata"]["run_kind"] = run_kind
    payload = [binding["case_sha256"]] if run_kind == "model" else [case.model_dump(mode="json")]
    report["metadata"]["suite_sha256"] = json_digest(payload)
    binding["source_report_sha256"] = json_digest(report)
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}, suite=(case,)
    )[0]
    assert result["status"] == "matching_supplied_artifact"
    wrong = [case.model_dump(mode="json")] if run_kind == "model" else [binding["case_sha256"]]
    report["metadata"]["suite_sha256"] = json_digest(wrong)
    binding["source_report_sha256"] = json_digest(report)
    assert (
        verify_snapshot_bindings(
            report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}, suite=(case,)
        )[0]["status"]
        == "mismatch"
    )


def test_snapshot_row_observations_cannot_be_substituted_even_with_rebound_hashes():
    report, case, snapshot, binding = supplied()
    row = report["rows"][0]
    row["payload_exposed"] = not row["payload_exposed"]
    binding.update(source_report_sha256=json_digest(report), source_row_sha256=json_digest(row))
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}, suite=(case,)
    )[0]
    assert result["status"] == "mismatch"


def test_ordinary_events_have_document_scoped_indexes_only():
    report, _, _ = native_fixture()
    locator = evidence_locator(report, 0, event_index=0)
    assert locator["scope"] == "document"
    assert locator["locator_kind"] == "event"
    assert locator["event_index"] == 0
    assert locator["source_row_sha256"] == json_digest(report["rows"][0])
    assert not {"event_id", "parent", "timestamp", "causal"}.intersection(locator)
    changed = deepcopy(report)
    changed["metadata"]["note"] = "Another immutable document"
    assert (
        evidence_locator(changed, 0, event_index=0)["source_report_sha256"]
        != locator["source_report_sha256"]
    )


def test_finding_locator_resolves_only_recorded_finding_digest():
    report, _, _ = native_fixture()
    digest = report["rows"][0]["findings"][0]["finding_sha256"]
    assert evidence_locator(report, 0, finding_sha256=digest)["locator_kind"] == "finding"
    with pytest.raises(ValueError):
        evidence_locator(report, 0, finding_sha256="0" * 64)


def test_boundary_event_policy_effect_links_resolve_and_deduplicate():
    report, _, _ = native_fixture("boundary")
    row = report["rows"][0]
    event_index = next(
        i for i, event in enumerate(row["events"]) if event.get("policy_sequence") is not None
    )
    locator = evidence_locator(report, 0, event_index=event_index)
    trace = next(
        item for item in row["policy_trace"] if item["sequence"] == locator["policy_sequence"]
    )
    assert locator["effect_id"] == trace["effect_id"]
    assert sum(effect["effect_id"] == locator["effect_id"] for effect in row["effects"]) == 1
    assert evidence_locator(report, 0, effect_id=locator["effect_id"])["locator_kind"] == "effect"
    with pytest.raises(ValueError):
        evidence_locator(report, 0, event_index=0, effect_id=locator["effect_id"])
    with pytest.raises(ValueError):
        evidence_locator(report, 0, event_index=event_index, policy_sequence=99)
    with pytest.raises(ValueError):
        evidence_locator(report, 0, event_index=event_index, policy_sequence=True)


@pytest.mark.parametrize(
    "selector",
    [
        {"row_index": True},
        {"row_index": 99},
        {"row_index": 0, "event_index": -1},
        {"row_index": 0, "event_index": True},
    ],
)
def test_locator_indexes_are_exact_bounded_integers(selector):
    report, _, _ = native_fixture()
    with pytest.raises(ValueError):
        evidence_locator(report, **selector)


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.update(schema_version=True),
        lambda b: b.update(snapshot_version=1.0),
        lambda b: b.update(row_index=True),
        lambda b: b.update(snapshot_sha256="https://example.invalid/untrusted"),
        lambda b: b.update(snapshot_path="/never-open-this"),
    ],
)
def test_malformed_references_are_rejected_without_reading_paths_or_urls(change):
    _, _, _, binding = supplied()
    change(binding)
    with pytest.raises(ValueError):
        validate_snapshot_bindings([binding])


def test_legacy_events_can_have_locators_but_not_native_snapshot_claims():
    report = legacy_fixture()
    assert verify_snapshot_bindings(report, [], snapshots={}) == []
    with pytest.raises(ValueError):
        create_snapshot_binding(report, 0, {})


def test_artifact_only_consistency_does_not_imply_supplied_case_restoration():
    report, case, snapshot, binding = supplied()
    path = snapshot["observed"][0]["path"]
    event = next(e for e in snapshot["events"] if e["tool"] == "read_file" and e["path"] == path)
    row_event = next(
        e for e in report["rows"][0]["events"] if e["tool"] == "read_file" and e["path"] == path
    )
    event["lines"].append(100_000)
    row_event["lines"].append(100_000)
    snapshot["observed"][0]["lines"].append(100_000)
    binding.update(
        source_report_sha256=json_digest(report),
        source_row_sha256=json_digest(report["rows"][0]),
        snapshot_sha256=json_digest(snapshot),
    )
    snapshots = {binding["snapshot_sha256"]: snapshot}
    unbound = verify_snapshot_bindings(report, [binding], snapshots=snapshots)[0]
    assert unbound["status"] == "matching_supplied_artifact"
    assert unbound["case_validation"] == "not_supplied"
    bound = verify_snapshot_bindings(report, [binding], snapshots=snapshots, suite=(case,))[0]
    assert bound["status"] == "mismatch"
    assert bound["case_validation"] == "not_supplied"


def test_case_restore_checks_structural_results_without_inventing_semantic_labels():
    report, case, snapshot, binding = supplied()
    report["rows"][0]["rubric_passed"] = False
    binding.update(
        source_report_sha256=json_digest(report), source_row_sha256=json_digest(report["rows"][0])
    )
    result = verify_snapshot_bindings(
        report, [binding], snapshots={binding["snapshot_sha256"]: snapshot}, suite=(case,)
    )[0]
    assert result["status"] == "mismatch"
    assert report["rows"][0]["semantic_passed"] is None


def test_duplicate_and_out_of_report_references_stay_invalid_or_visible():
    report, _, snapshot, binding = supplied()
    with pytest.raises(ValueError):
        validate_snapshot_bindings([binding, deepcopy(binding)])
    binding["row_index"] = 50
    second = {**binding, "row_index": 1}
    results = verify_snapshot_bindings(
        report, [binding, second], snapshots={binding["snapshot_sha256"]: snapshot}
    )
    assert results[0]["status"] == "not_recorded"
    assert [r["row_index"] for r in results[1:]] == [50, 1]
    assert all(r["status"] == "mismatch" for r in results[1:])
