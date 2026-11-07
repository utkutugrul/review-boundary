"""Lossless versioned exports and explicitly supplied snapshot consistency."""

import json
import os
import stat
from copy import deepcopy

import pytest
from report_contract_support import legacy_fixture, native_fixture

from review_boundary import report_export
from review_boundary.cli import main
from review_boundary.provenance import json_digest
from review_boundary.report_contract import export_report_envelope
from review_boundary.report_export import (
    compile_snapshot_evidence,
    prepare_report_export,
    write_report_export,
)
from review_boundary.repository_world import (
    ReviewAdjudication,
    review_digest,
    score_repository_world,
)


def artifact_for(report, snapshot):
    return {
        "schema_version": 1,
        "source_report_sha256": json_digest(report),
        "snapshots": [
            {
                "row_index": 0,
                "source_row_sha256": json_digest(report["rows"][0]),
                "snapshot": snapshot,
            }
        ],
    }


def save(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(json.dumps(value))
    return path


@pytest.mark.parametrize("kind", ["legacy", "repository", "boundary"])
def test_export_is_deterministic_lossless_and_idempotent(tmp_path, kind):
    report = legacy_fixture() if kind == "legacy" else native_fixture(kind)[0]
    original = deepcopy(report)
    source = save(tmp_path, "source.json", report)
    first = write_report_export(source, tmp_path / "first.json")
    second = write_report_export(source, tmp_path / "second.json")
    envelope = json.loads(first.read_text())
    assert first.read_bytes() == second.read_bytes()
    assert envelope == export_report_envelope(original)
    assert envelope["source_report_sha256"] == json_digest(original)
    assert prepare_report_export(envelope) == envelope
    assert envelope["report"] == original == json.loads(source.read_text())
    if os.name == "posix":
        assert stat.S_IMODE(first.stat().st_mode) == 0o600


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_explicit_snapshot_and_optional_suite_have_distinct_consistency_levels(kind):
    report, case, world = native_fixture(kind)
    artifacts = artifact_for(report, world.snapshot())
    original = deepcopy((report, artifacts))
    bindings, context = compile_snapshot_evidence(report, snapshot_artifacts=artifacts)
    assert len(bindings) == 1
    assert context["source_report_sha256"] == json_digest(report)
    result = context["rows"][0]
    assert result["status"] == "matching_supplied_artifact"
    assert result["case_validation"] == "not_supplied"
    assert result["authenticity"] == "not_established"
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json")]}
    _, restored = compile_snapshot_evidence(report, snapshot_artifacts=artifacts, suite=suite)
    assert restored["rows"][0]["case_validation"] == "restored_and_observations_match"
    envelope = prepare_report_export(report, snapshot_artifacts=artifacts, suite=suite)
    assert envelope["snapshot_bindings"] == bindings
    assert "snapshot" not in envelope and "snapshots" not in envelope
    assert "evidence_verification" not in envelope
    assert (report, artifacts) == original


def test_missing_artifacts_remain_unavailable_when_reexported():
    report, _, world = native_fixture()
    envelope = prepare_report_export(
        report, snapshot_artifacts=artifact_for(report, world.snapshot())
    )
    bindings, context = compile_snapshot_evidence(envelope)
    assert context["rows"][0]["status"] == "unavailable"
    assert context["rows"][0]["case_validation"] == "not_supplied"
    assert prepare_report_export(envelope)["snapshot_bindings"] == bindings


@pytest.mark.parametrize(
    "mutation,pattern",
    [
        (lambda a: a.update(schema_version=True), "schema"),
        (lambda a: a.update(status="matching_supplied_artifact"), "schema"),
        (lambda a: a.update(source_report_sha256="0" * 64), "source report"),
        (lambda a: a["snapshots"][0].update(source_row_sha256="0" * 64), "source row"),
        (lambda a: a["snapshots"][0].update(snapshot_path="/never/open"), "fields"),
        (lambda a: a["snapshots"][0].update(row_index=True), "row index"),
        (lambda a: a["snapshots"][0].update(row_index=1), "row index"),
        (lambda a: a["snapshots"].append(deepcopy(a["snapshots"][0])), "repeat"),
        (lambda a: a["snapshots"][0]["snapshot"].update(calls=999), "source row 0"),
        (lambda a: a["snapshots"][0]["snapshot"].update(schema_version=2), "source row 0"),
    ],
)
def test_ambiguous_unbound_or_claimed_artifacts_fail_without_output(tmp_path, mutation, pattern):
    report, _, world = native_fixture()
    artifacts = artifact_for(report, world.snapshot())
    mutation(artifacts)
    source = save(tmp_path, "report.json", report)
    supplied = save(tmp_path, "snapshots.json", artifacts)
    output = tmp_path / "output.json"
    with pytest.raises(ValueError, match=pattern):
        write_report_export(source, output, snapshot_artifacts=supplied)
    assert not output.exists()


def test_suite_case_mismatch_does_not_claim_restoration(tmp_path):
    report, _, world = native_fixture()
    _, wrong_case, _ = native_fixture(case_index=1)
    source = save(tmp_path, "report.json", report)
    supplied = save(tmp_path, "snapshots.json", artifact_for(report, world.snapshot()))
    suite = save(
        tmp_path, "suite.json", {"schema_version": 1, "cases": [wrong_case.model_dump(mode="json")]}
    )
    with pytest.raises(ValueError, match="row 0: supplied_case_not_bound"):
        write_report_export(
            source, tmp_path / "output.json", snapshot_artifacts=supplied, suite=suite
        )
    assert not (tmp_path / "output.json").exists()


def test_aggregate_export_input_limit_is_enforced_before_writing(tmp_path, monkeypatch):
    report, _, world = native_fixture()
    source = save(tmp_path, "source.json", report)
    artifacts = save(tmp_path, "snapshots.json", artifact_for(report, world.snapshot()))
    monkeypatch.setattr(
        report_export, "MAX_TOTAL_BYTES", source.stat().st_size + artifacts.stat().st_size - 1
    )
    with pytest.raises(ValueError, match="total at most"):
        write_report_export(source, tmp_path / "output.json", snapshot_artifacts=artifacts)
    assert not (tmp_path / "output.json").exists()


def test_adjudicated_report_keeps_recorded_judgment_separate_from_snapshot_consistency():
    report, case, world = native_fixture()
    row = report["rows"][0]
    judgment = ReviewAdjudication(
        case_sha256=row["case_sha256"],
        review_sha256=review_digest(row["review"]),
        decision="rejected",
        reason="Explicit evaluator judgment retained as recorded data.",
    )
    derived = score_repository_world(case, world, review_adjudication=judgment)
    derived.update(reviewer=row["reviewer"], epoch=row["epoch"])
    report["rows"] = [derived]
    report["metadata"]["adjudication"] = {"source_report_sha256": "a" * 64}
    artifacts = artifact_for(report, world.snapshot())
    envelope = prepare_report_export(
        report,
        snapshot_artifacts=artifacts,
        suite={"schema_version": 1, "cases": [case.model_dump(mode="json")]},
    )
    assert envelope["report"] == report
    assert envelope["report"]["rows"][0]["review_adjudication"]["decision"] == "rejected"
    _, context = compile_snapshot_evidence(envelope, snapshot_artifacts=artifacts, suite=(case,))
    assert context["rows"][0]["status"] == "matching_supplied_artifact"
    assert context["rows"][0]["authenticity"] == "not_established"


@pytest.mark.parametrize("kind", ["existing", "source", "symlink", "hardlink", "parent_symlink"])
def test_export_never_replaces_an_existing_output_or_follows_output_aliases(tmp_path, kind):
    source = save(tmp_path, "source.json", legacy_fixture())
    before = source.read_bytes()
    output = tmp_path / "output.json"
    if kind == "existing":
        output.write_text("keep")
    elif kind == "source":
        output = source
    elif kind == "symlink":
        output.symlink_to(source)
    elif kind == "hardlink":
        os.link(source, output)
    else:
        target = tmp_path / "target"
        target.mkdir()
        alias = tmp_path / "alias"
        alias.symlink_to(target)
        output = alias / "output.json"
    with pytest.raises((ValueError, OSError)):
        write_report_export(source, output)
    assert source.read_bytes() == before
    if kind == "existing":
        assert output.read_text() == "keep"
    if kind == "parent_symlink":
        assert not (tmp_path / "target/output.json").exists()


def test_cli_exports_only_recorded_report_data(tmp_path, capsys):
    report, case, world = native_fixture()
    source = save(tmp_path, "source.json", report)
    artifacts = save(tmp_path, "snapshots.json", artifact_for(report, world.snapshot()))
    suite = save(
        tmp_path, "suite.json", {"schema_version": 1, "cases": [case.model_dump(mode="json")]}
    )
    output = tmp_path / "new/report.json"
    assert (
        main(
            [
                "report-export",
                str(source),
                "--output",
                str(output),
                "--snapshot-artifacts",
                str(artifacts),
                "--suite",
                str(suite),
            ]
        )
        == 0
    )
    captured = capsys.readouterr()
    assert captured.out.strip() == str(output)
    assert captured.err == ""
    assert json.loads(output.read_text())["report"] == report
    assert main(["report-export", str(source), "--output", str(output)]) == 2
    assert "ReviewBoundary:" in capsys.readouterr().err


@pytest.mark.parametrize(
    "raw", ['{"schema_version":2,"rows":[],"rows":[],"metadata":{}}', '{"unused":NaN}', "[[]]", "{"]
)
def test_invalid_export_json_returns_two_without_success_or_output(tmp_path, capsys, raw):
    source = tmp_path / "source.json"
    source.write_text(raw)
    output = tmp_path / "output.json"
    assert main(["report-export", str(source), "--output", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ReviewBoundary:" in captured.err and "Traceback" not in captured.err
    assert not output.exists()
