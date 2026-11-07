"""Payload suites retain their identity through actual execution and saved evidence."""

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest
from inspect_ai import eval
from test_repository_task import repository_calibration_model

from review_boundary.cli import main
from review_boundary.evidence_refs import create_snapshot_binding, verify_snapshot_bindings
from review_boundary.json_input import parse_json_object
from review_boundary.native_compare import compare_repository_reports
from review_boundary.payload_fixtures import build_repository_payload_cases
from review_boundary.payload_packs import CARRIERS, build_original_payload_pack
from review_boundary.provenance import json_digest
from review_boundary.report_contract import export_report_envelope, validate_report_document
from review_boundary.report_validation import validate_native_report
from review_boundary.repository_adjudication import (
    apply_repository_adjudication,
    export_adjudication_template,
    observations_from_logs,
    repository_failure_evidence,
)
from review_boundary.repository_cases import build_repository_demo_cases, case_digest
from review_boundary.repository_cases_v2 import REPOSITORY_PAYLOAD_SCORING_VERSION
from review_boundary.repository_runner import (
    PAYLOAD_PROTOCOL,
    PROTOCOL,
    calibrate,
    repository_error_rows,
    repository_profile,
    repository_rows_from_logs,
    repository_scoring_version,
    write_repository_report,
)
from review_boundary.repository_runtime import (
    repository_world_for_case,
    restore_repository_world,
    score_repository_case,
)
from review_boundary.repository_suite import parse_repository_suite, repository_suite_schema
from review_boundary.repository_task import repository_review_task
from review_boundary.repository_world import RepositoryLimitError, RepositoryLimits
from review_boundary.suite_validation import validate_suite


def cases_for(carrier):
    pack = build_original_payload_pack()
    return tuple(
        case
        for base in build_repository_demo_cases()
        if base.surface == "clean"
        for case in build_repository_payload_cases(base, pack, carrier=carrier)
    )


def suite_for(cases):
    return {"schema_version": 2, "cases": [case.model_dump(mode="json") for case in cases]}


def report_for(tmp_path, cases, rows, *, reviewers=None, provenance=None):
    reviewers = reviewers or list(dict.fromkeys(row["reviewer"] for row in rows))
    metadata = {
        "run_id": "payload-fixture",
        "run_kind": "model",
        "run_finished": True,
        "scoring_version": REPOSITORY_PAYLOAD_SCORING_VERSION,
        "corpus_version": "custom",
        "suite_sha256": json_digest([case_digest(case) for case in cases]),
        "expected_count": len(rows),
        "case_count": len(cases),
        "epochs": 1,
        "reviewers": reviewers,
        "expected_slots": [
            {"case_sha256": case_digest(case), "reviewer": reviewer, "epoch": 1}
            for reviewer in reviewers
            for case in cases
        ],
        "world_limits": RepositoryLimits().model_dump(mode="json"),
        "bounds": {
            "max_turns": 8,
            "max_input_bytes": 24000,
            "max_output_tokens": 8192,
            "retries": 0,
        },
    }
    if provenance is not None:
        metadata["provenance"] = provenance
    tmp_path.mkdir(parents=True, exist_ok=True)
    write_repository_report(rows, tmp_path, metadata)
    return json.loads((tmp_path / "report.json").read_text())


@pytest.mark.parametrize("carrier", CARRIERS)
def test_all_carrier_suites_validate_execute_restore_and_keep_unknowns(tmp_path, carrier):
    cases = cases_for(carrier)
    suite = suite_for(cases)
    assert len(cases) == 12 and len({case.source_group for case in cases}) == 1
    assert parse_repository_suite(suite).model_dump(mode="json") == suite
    jsonschema.Draft202012Validator(repository_suite_schema(schema_version=2)).validate(suite)
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(suite))
    assert validate_suite(path)["valid"]
    for case in cases:
        world = repository_world_for_case(case)
        calibrate(world, "reference")
        row = score_repository_case(case, world)
        assert row["carrier_observed"] and row["conclusive"] and row["rubric_passed"]
        assert row["payload_exposed"] == (case.condition == "attack")
        assert row["semantic_passed"] is None
        restored = restore_repository_world(case, world.snapshot(), expected_limits=world.limits)
        assert score_repository_case(case, restored) == row


@pytest.mark.parametrize("version", [True, 2.0, "2", 3, None])
def test_suite_version_dispatch_rejects_coercions(version):
    suite = suite_for(cases_for("pr")[:1])
    suite["schema_version"] = version
    with pytest.raises(ValueError):
        parse_repository_suite(suite)


def test_suite_dispatch_rejects_mixed_case_versions_and_keeps_default_schema():
    v1 = build_repository_demo_cases()[0].model_dump(mode="json")
    v2 = cases_for("pr")[0].model_dump(mode="json")
    for version in (1, 2):
        with pytest.raises(ValueError):
            parse_repository_suite({"schema_version": version, "cases": [v1, v2]})
    assert repository_suite_schema()["properties"]["schema_version"]["const"] == 1
    assert repository_profile().protocol == PROTOCOL
    assert repository_profile(schema_version=2).protocol == PAYLOAD_PROTOCOL


def test_native_v2_logs_mixed_failure_adjudication_and_snapshot_envelope(tmp_path):
    cases = cases_for("tool_output")[:2]
    task = repository_review_task(cases=cases)
    logs = eval(
        [task],
        model=repository_calibration_model(),
        log_dir=str(tmp_path / "logs"),
        display="none",
        log_model_api=False,
    )
    assert all(log.status == "success" for log in logs)
    reviewer = logs[0].eval.model
    rows = repository_rows_from_logs(logs, cases, [reviewer], 1)
    assert all(row["carrier_observed"] and row["rubric_passed"] for row in rows)
    failures = repository_error_rows(cases, "mockllm/provider-failed", 1, "provider_error")
    assert all(row["case_schema_version"] == 2 and not row["carrier_observed"] for row in failures)
    report = report_for(tmp_path / "report", cases, rows + failures)
    artifact = export_adjudication_template(report, cases)
    observations, limits = observations_from_logs(logs, cases)
    failure = repository_failure_evidence(report, cases, ["mockllm/provider-failed"])
    applied, metadata = apply_repository_adjudication(
        report,
        cases,
        artifact,
        observations,
        limits,
        failure_evidence=failure,
    )
    assert applied[len(cases) :] == report["rows"][len(cases) :]
    assert all(row["semantic_passed"] is None for row in applied)
    assert [row["rubric_passed"] for row in applied] == [
        row["rubric_passed"] for row in report["rows"]
    ]
    assert metadata["adjudication"]["rows_adjudicated"] == len(cases)
    supported = artifact.model_dump(mode="json")
    for decision in supported["finding_decisions"]:
        decision.update(decision="supported", issue_id=cases[0].issues[0].issue_id)
    for decision in supported["review_decisions"]:
        decision.update(decision="supported")
    judged, _ = apply_repository_adjudication(
        report,
        cases,
        supported,
        observations,
        limits,
        failure_evidence=failure,
    )
    assert all(row["semantic_passed"] is True for row in judged[: len(cases)])
    assert judged[len(cases) :] == failures
    snapshot = logs[0].samples[0].store["repository_world"]
    assert snapshot["schema_version"] == 2
    binding = create_snapshot_binding(report, 0, snapshot)
    results = verify_snapshot_bindings(
        report,
        [binding],
        snapshots={binding["snapshot_sha256"]: snapshot},
        suite=suite_for(cases),
    )
    assert results[0]["case_validation"] == "restored_and_observations_match"
    validate_report_document(export_report_envelope(report, snapshot_bindings=[binding]))
    changed = deepcopy(snapshot)
    changed["carrier_observed"] = not changed["carrier_observed"]
    assert (
        verify_snapshot_bindings(
            report,
            [binding],
            snapshots={binding["snapshot_sha256"]: changed},
            suite=cases,
        )[0]["status"]
        == "mismatch"
    )


def test_cli_v2_demo_adapter_and_compare_bind_expected_suite(tmp_path):
    cases = cases_for("filename")[:1]
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps(suite_for(cases)))
    demo = tmp_path / "demo"
    assert main(["repository-demo", "--suite", str(suite), "--output", str(demo)]) == 0
    baseline = json.loads((demo / "report.json").read_text())
    assert all(row["carrier_observed"] for row in baseline["rows"])
    adapter = tmp_path / "adapter.json"
    script = Path(__file__).resolve().parents[1] / "examples/adapters/repository_reference.py"
    adapter.write_text(
        json.dumps({"name": "payload-reference", "command": ["{python}", str(script)]})
    )
    output = tmp_path / "adapter-output"
    assert (
        main(
            [
                "repository-run-adapter",
                "--suite",
                str(suite),
                "--adapter",
                str(adapter),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    candidate = json.loads((output / "report.json").read_text())
    assert candidate["metadata"]["adapter"]["protocol"] == PAYLOAD_PROTOCOL
    result = compare_repository_reports(
        baseline,
        candidate,
        expected_suite=suite_for(cases),
        baseline_reviewer="reference",
        candidate_reviewer="adapter/payload-reference",
    )
    assert result["status"] == "pass"
    changed = deepcopy(candidate)
    changed["rows"][0]["condition"] = "attack"
    with pytest.raises(ValueError):
        compare_repository_reports(
            baseline,
            changed,
            expected_suite=cases,
            baseline_reviewer="reference",
            candidate_reviewer="adapter/payload-reference",
        )


def test_raw_python_browser_payload_validation_parity(tmp_path):
    case = cases_for("pr")[0]
    world = repository_world_for_case(case)
    calibrate(world, "reference")
    row = score_repository_case(case, world)
    row.update(reviewer="fixture/reference", epoch=1)
    report = report_for(tmp_path / "report", (case,), [row])
    texts = [json.dumps(report)]
    for key, value in (("case_schema_version", 2), ("pack_version", 1)):
        for spelling in (f"{value}.0", f"{value}e0", "true"):
            texts.append(texts[0].replace(f'"{key}": {value}', f'"{key}": {spelling}', 1))
    for mutate in (
        lambda row: row.update(carrier_observed=False),
        lambda row: row["events"][0].update(arguments_json="{ }"),
        lambda row: row["events"][0].update(arguments_json=None),
        lambda row: row["events"][1].update(arguments_json="{}"),
        lambda row: row["events"][1].update(paths=["README.md", "README.md"]),
        lambda row: row["events"][0].update(paths=["README.md"]),
        lambda row: row["events"][0].update(response_sha256=None),
    ):
        changed = deepcopy(report)
        mutate(changed["rows"][0])
        texts.append(json.dumps(changed))
    overflowing = repository_world_for_case(case)
    with pytest.raises(RepositoryLimitError):
        for _ in range(17):
            overflowing.dispatch("write_file", {"path": "notes/draft.txt", "content": "x" * 65536})
    trace_row = score_repository_case(case, overflowing)
    trace_row.update(reviewer="fixture/reference", epoch=1)
    trace_report = report_for(tmp_path / "trace", (case,), [trace_row])
    texts.append(json.dumps(trace_report))
    results = []
    for text in texts:
        try:
            validate_native_report(parse_json_object(text))
        except ValueError:
            results.append(False)
        else:
            results.append(True)
    assert results == [True] + [False] * (len(texts) - 2) + [True]
    script = """
const fs = require('node:fs');
const contracts = require('./src/review_boundary/web/report-contracts.js');
const texts = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(texts.map(text => {
  try { contracts.validateDisplayDocument(contracts.parseReportText(text)); return true; }
  catch { return false; }
})));
"""
    checked = subprocess.run(
        ["node", "-e", script],
        input=json.dumps(texts),
        text=True,
        capture_output=True,
        cwd=Path(__file__).resolve().parents[1],
        check=True,
    )
    assert json.loads(checked.stdout) == results


def test_repository_version_bindings_reject_crossed_cases_scores_and_snapshots(tmp_path):
    case = cases_for("pr")[0]
    v1 = build_repository_demo_cases()[0]
    with pytest.raises(ValueError, match="homogeneous"):
        repository_scoring_version((v1, case))
    with pytest.raises(ValueError, match="homogeneous"):
        repository_review_task(cases=(v1, case))
    world = repository_world_for_case(case)
    calibrate(world, "reference")
    row = score_repository_case(case, world)
    row.update(reviewer="fixture/reference", epoch=1)
    report = report_for(tmp_path / "report", (case,), [row])
    changed = deepcopy(report)
    changed["rows"][0]["scoring_version"] = changed["metadata"]["scoring_version"] = "repository-v1"
    with pytest.raises(ValueError):
        validate_report_document(changed)
    snapshot = world.snapshot()
    snapshot["schema_version"] = 1
    with pytest.raises(ValueError, match="version"):
        restore_repository_world(case, snapshot, expected_limits=world.limits)
    with pytest.raises(ValueError, match="version"):
        restore_repository_world(v1, world.snapshot(), expected_limits=world.limits)
    with pytest.raises(ValueError, match="versions disagree"):
        verify_snapshot_bindings(report, [], snapshots={}, suite=(v1,))
    assert repository_review_task(cases=(case,)).metadata["case_schema_version"] == 2


def test_tool_output_leakage_checks_actual_reviewer_visible_text(tmp_path):
    case = cases_for("tool_output")[0]
    document = suite_for((case,))
    document["cases"][0]["exposure"]["untrusted_text"] += "\n" + case.case_id
    suite = tmp_path / "leaking.json"
    suite.write_text(json.dumps(document))
    result = validate_suite(suite)
    assert not result["valid"]
    assert result["layers"]["leakage"]["status"] == "failed"
    request = repository_world_for_case(case).reviewer_request()
    assert set(request) == {"instructions", "task"}
    assert case.case_id not in json.dumps(request)
