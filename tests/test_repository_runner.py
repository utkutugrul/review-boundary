import html
import json
import os
from pathlib import Path

import pytest

from review_boundary.adapter import AdapterConfig, RepositoryAdapterRequest, run_adapter
from review_boundary.cli import main
from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import (
    PROTOCOL,
    calibrate,
    load_suite,
    repository_profile,
    write_repository_report,
)
from review_boundary.repository_world import (
    RepositoryLimits,
    RepositoryWorld,
    score_repository_world,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "adapters"
REFERENCE = EXAMPLES / "repository_reference.py"
CONFIG = EXAMPLES / "repository-reference.json"
POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="Adapter process groups require POSIX")


def child_program(tmp_path, program):
    script = tmp_path / "adapter.py"
    script.write_text(program, encoding="utf-8")
    path = tmp_path / "adapter.json"
    path.write_text(
        json.dumps(
            {
                "name": "repository-test",
                "command": ["{python}", "{config_dir}/adapter.py"],
                "source_files": ["adapter.py"],
                "limits": {"idle_timeout": 5.0, "total_timeout": 15.0, "shutdown_timeout": 2.0},
            }
        )
    )
    return path


def run_cli(tmp_path, config=CONFIG, suite=None):
    output = tmp_path / "result"
    argv = ["repository-run-adapter", "--adapter", str(config), "--output", str(output)]
    if suite is not None:
        argv += ["--suite", str(suite)]
    status = main(argv)
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["run_finished"]
    assert [
        json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()
    ] == report["rows"]
    assert report["schema_version"] == 1 and report["report_kind"] == "repository"
    assert manifest["adapter"]["protocol"] == PROTOCOL
    assert manifest["os_sandboxed"] is False
    return status, report


@POSIX_ONLY
async def test_repository_start_envelope_omits_all_evaluator_identifiers(tmp_path):
    capture = tmp_path / "start.json"
    config = child_program(
        tmp_path,
        f"""
import json
from pathlib import Path
import sys
start = json.loads(sys.stdin.readline())
Path({str(capture)!r}).write_text(json.dumps(start))
print(json.dumps({{"type": "done"}}), flush=True)
assert json.loads(sys.stdin.readline()) == {{"type": "stop", "reason": "missing_submission"}}
""",
    )
    case = build_repository_demo_cases()[0].model_copy(
        update={
            "case_id": "CVE-hidden-vulnerable",
            "source_group": "private-heldout-group",
        }
    )
    world = RepositoryWorld(case)

    async def dispatch(name, arguments):
        return world.dispatch(name, arguments)

    result = await run_adapter(
        AdapterConfig.from_file(config),
        RepositoryAdapterRequest(**world.reviewer_request()),
        dispatch,
        profile=repository_profile(),
    )
    start = json.loads(capture.read_text())
    assert result.status == "incomplete"
    assert set(start) == {
        "type",
        "protocol",
        "invocation_id",
        "instructions",
        "task",
        "tools",
        "limits",
    }
    assert start["protocol"] == PROTOCOL
    assert start["invocation_id"] == result.invocation_id and len(result.invocation_id) == 32
    assert {tool["name"] for tool in start["tools"]} == {
        "read_pr",
        "list_files",
        "search_files",
        "read_file",
        "write_file",
        "submit_review",
    }
    raw = json.dumps(start)
    for hidden in (
        case.case_id,
        case.source_group,
        "tenant-ownership",
        "source_path",
        "acceptable_bundles",
        "case_sha256",
        "variant",
        "exposure",
        "expected_category",
    ):
        assert hidden not in raw


@POSIX_ONLY
def test_reference_process_handles_all_four_conditions_without_semantic_claims(tmp_path):
    status, report = run_cli(tmp_path)
    assert status == 0 and len(report["rows"]) == 4
    assert report["summary"]["completed"] == report["summary"]["rubric_passed"] == 4
    assert report["summary"]["semantically_adjudicated"] == 0
    assert len({row["adapter"]["invocation_id"] for row in report["rows"]}) == 4
    assert AdapterConfig.from_file(CONFIG).source_files == ["repository_reference.py"]
    for row in report["rows"]:
        assert row["adapter"]["status"] == "completed" and row["semantic_passed"] is None
        assert row["correct_findings"] == row["false_positives"] == 0
        assert row["unknown_findings"] == (1 if row["variant"] == "vulnerable" else 0)
        assert row["review"]["verdict"] == (
            "request_changes" if row["variant"] == "vulnerable" else "approve"
        )
        assert {event["tool"] for event in row["events"]} >= {
            "read_pr",
            "list_files",
            "read_file",
            "submit_review",
        }


@POSIX_ONLY
async def test_reference_process_follows_real_list_and_read_pagination():
    case = build_repository_demo_cases()[1]
    world = RepositoryWorld(case, RepositoryLimits(max_list_entries=1, max_read_lines=2))

    async def dispatch(name, arguments):
        return world.dispatch(name, arguments)

    result = await run_adapter(
        AdapterConfig.from_file(CONFIG),
        RepositoryAdapterRequest(**world.reviewer_request()),
        dispatch,
        profile=repository_profile(),
    )
    assert result.status == "completed"
    assert sum(event["tool"] == "list_files" for event in world.events) == 4
    assert sum(event["tool"] == "read_file" for event in world.events) > 4
    scored = score_repository_world(case, world)
    assert scored["rubric_passed"] and scored["payload_exposed"]


@POSIX_ONLY
def test_crash_after_submission_retains_findings_but_never_passes(tmp_path):
    config = child_program(
        tmp_path,
        f"""
import runpy
import sys
runpy.run_path({str(REFERENCE)!r}, run_name="__main__")
sys.exit(4)
""",
    )
    status, report = run_cli(tmp_path, config)
    assert status == 2 and report["summary"]["errors"] == 4
    assert report["summary"]["completed"] == report["summary"]["rubric_passed"] == 0
    for row in report["rows"]:
        assert row["review"] is not None and row["adapter"]["error_code"] == "process_exit"
        assert not row["completed"] and not row["conclusive"] and not row["rubric_passed"]
        assert row["semantic_passed"] is None
        if row["variant"] == "vulnerable":
            assert row["findings"] and row["rubric_supported_findings"] == 1


@POSIX_ONLY
def test_invalid_submit_is_recoverable_and_invalid_write_is_still_counted(tmp_path):
    config = child_program(
        tmp_path,
        f"""
import runpy
namespace = runpy.run_path({str(REFERENCE)!r})
client = namespace["Client"]()
for tool, arguments in [
    ("submit_review", {{"verdict": "approve", "findings": [], "expected": "forbidden"}}),
    ("write_file", {{"path": "../outside"}}),
]:
    try:
        client.call(tool, **arguments)
    except ValueError:
        pass
    else:
        raise AssertionError("Malformed arguments unexpectedly accepted")
files = namespace["read_repository"](client)
client.call("submit_review", **namespace["scripted_submission"](files))
client.finish()
""",
    )
    status, report = run_cli(tmp_path, config)
    assert status == 0
    for row in report["rows"]:
        assert row["completed"] and row["adapter"]["status"] == "completed"
        assert row["write_requests_seen"] == 1 and row["write_attempted"]
        assert not row["rubric_passed"] and not row["workspace_modified"]


@POSIX_ONLY
def test_unsupported_public_fixture_ends_incomplete_instead_of_approval(tmp_path):
    case = build_repository_demo_cases()[0]
    payload = case.model_dump(mode="json")
    service = next(file for file in payload["files"] if file["path"] == "src/service.py")
    service["content"] = service["content"].replace("records.get(record_id)", "records[record_id]")
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"schema_version": 1, "cases": [payload]}))
    status, report = run_cli(tmp_path, suite=suite)
    row = report["rows"][0]
    assert status == 2 and row["adapter"]["status"] == "incomplete"
    assert row["review"] is None and not row["completed"] and not row["rubric_passed"]


@pytest.mark.parametrize(
    "invalid", ["empty", "duplicate_ids", "duplicate_json", "wrong_schema", "invalid_range"]
)
def test_custom_suite_rejects_invalid_or_ambiguous_inputs_before_output(tmp_path, invalid):
    case = build_repository_demo_cases()[0].model_dump(mode="json")
    value = {"schema_version": 1, "cases": [case]}
    if invalid == "empty":
        value["cases"] = []
    elif invalid == "duplicate_ids":
        value["cases"].append(case)
    elif invalid == "wrong_schema":
        value["schema_version"] = True
    elif invalid == "invalid_range":
        case["issues"][0]["acceptable_bundles"][0]["ranges"][0]["end_line"] = 999
    suite = tmp_path / "suite.json"
    raw = json.dumps(value)
    if invalid == "duplicate_json":
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    suite.write_text(raw)
    with pytest.raises(ValueError):
        load_suite(suite)
    output = tmp_path / "never-created"
    assert (
        main(
            [
                "repository-run-adapter",
                "--adapter",
                str(CONFIG),
                "--suite",
                str(suite),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_runner_preserves_existing_outputs(tmp_path, kind):
    output = tmp_path / "existing"
    if kind == "directory":
        output.mkdir()
        preserved = output / "report.json"
    else:
        preserved = output
    preserved.write_text("Do not overwrite this artifact.")
    assert main(["repository-demo", "--output", str(output)]) == 2
    assert preserved.read_text() == "Do not overwrite this artifact."
    if kind == "directory":
        assert list(output.iterdir()) == [preserved]


def test_demo_reports_calibration_and_unjudged_semantics(tmp_path):
    output = tmp_path / "calibration"
    assert main(["repository-demo", "--output", str(output)]) == 0
    report = json.loads((output / "report.json").read_text())
    assert report["metadata"]["run_kind"] == "calibration"
    assert report["summary"]["recorded"] == report["summary"]["expected"] == 8
    assert report["summary"]["rubric_passed"] == 7
    assert report["summary"]["semantically_adjudicated"] == 0
    assert all(row["semantic_passed"] is None for row in report["rows"])


def test_html_report_escapes_model_evidence_and_evaluator_metadata(tmp_path):
    case = build_repository_demo_cases()[0]
    world = RepositoryWorld(case)
    calibrate(world, "reference")
    row = score_repository_world(case, world)
    payload = '<script>alert("unsafe")</script><img src=x onerror=alert(1)>'
    row.update(case_id=payload, reviewer=payload, epoch=1, error=payload)
    row["findings"][0]["finding"]["summary"] = payload
    row["findings"][0]["finding"]["evidence"][0].update(path=payload, excerpt=payload)
    path = write_repository_report(
        [row],
        tmp_path,
        {
            "expected_count": 1,
            "run_kind": "calibration",
            "note": payload,
        },
    )
    document = path.read_text()
    assert payload not in document and html.escape(payload) in document
    assert "<script>" not in document and "<img " not in document
    assert "default-src 'none'" in document
    assert json.loads((tmp_path / "report.json").read_text())["rows"][0]["case_id"] == payload
