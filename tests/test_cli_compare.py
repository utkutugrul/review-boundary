"""Exercise real scored reports through the CLI comparison boundary."""

import json
from copy import deepcopy

import pytest

from review_boundary.cases import build_cases, suite_digest
from review_boundary.cli import main
from review_boundary.compare import compare_reports
from review_boundary.report import write_report
from review_boundary.world import World, score_world


def scored_report(cases):
    rows = []
    for case in cases:
        world = World.for_case(case)
        world.read_pr(case)
        world.read_file(case, "README.md")
        world.read_file(case, case.source_path)
        findings = []
        if case.variant == "vulnerable":
            line = case.evidence_lines[0]
            findings.append(
                {
                    "category": case.category,
                    "file": case.source_path,
                    "line": line,
                    "evidence": case.files[case.source_path].splitlines()[line - 1].strip(),
                    "explanation": "The fixture contains the expected security issue.",
                }
            )
        world.submit("request_changes" if findings else "approve", findings)
        rows.append(
            score_world(case, world)
            | {
                "model": "test-reviewer",
                "defense": "baseline",
                "epoch": 1,
                "error": None,
            }
        )
    return {
        "schema_version": 2,
        "metadata": {
            "scoring_version": "0.2.0",
            "corpus_version": "0.2.0",
            "suite_sha256": suite_digest(cases),
            "split": "all",
            "epochs": 1,
            "bounds": {
                "max_turns": 12,
                "max_input_bytes": 65536,
                "max_output_tokens": 2048,
                "retries": 0,
                "block_writes": False,
            },
            "expected_samples": [{"case_id": case.id, "epoch": 1} for case in cases],
        },
        "rows": rows,
    }


@pytest.fixture
def report_files(tmp_path):
    cases = [case for case in build_cases() if case.family == "tenant_lookup"]
    payload = scored_report(cases)
    baseline_dir = tmp_path / "baseline"
    candidate_dir = tmp_path / "candidate"
    write_report(payload["rows"], baseline_dir, payload["metadata"])
    write_report(deepcopy(payload["rows"]), candidate_dir, deepcopy(payload["metadata"]))
    return baseline_dir / "report.json", candidate_dir / "report.json"


def test_all_real_case_variants_produce_comparison_compatible_metrics():
    payload = scored_report(build_cases())
    result = compare_reports(payload, deepcopy(payload))
    assert result["exit_code"] == 0
    assert result["summary"]["unchanged_passing_samples"] == len(payload["rows"])


@pytest.mark.parametrize("state,expected_exit", [("pass", 0), ("regression", 1)])
def test_cli_writes_json_and_returns_gate_exit_code(
    report_files, tmp_path, capsys, state, expected_exit
):
    baseline, candidate = report_files
    if state == "regression":
        payload = json.loads(candidate.read_text())
        payload["rows"][0].update(conclusive=False, passed=False, error="provider failed")
        candidate.write_text(json.dumps(payload))
    output = tmp_path / "artifacts" / "comparison.json"
    status = main(["compare", str(baseline), str(candidate), "--output", str(output)])
    captured = capsys.readouterr()
    assert status == expected_exit
    result = json.loads(output.read_text())
    assert result["exit_code"] == expected_exit
    assert result["status"] == state
    assert f"comparison: {state.upper()}" in captured.out
    assert captured.err == ""
    if state == "regression":
        assert "new_error" in {reason["code"] for reason in result["regressions"][0]["reasons"]}


@pytest.mark.parametrize(
    "invalid", ["malformed_json", "old_schema", "missing_metric", "missing_file"]
)
def test_cli_invalid_input_exits_two_without_green_output(report_files, tmp_path, capsys, invalid):
    baseline, candidate = report_files
    if invalid == "malformed_json":
        candidate.write_text("{ invalid JSON")
    elif invalid == "missing_file":
        candidate.unlink()
    else:
        payload = json.loads(candidate.read_text())
        if invalid == "old_schema":
            payload["schema_version"] = 1
        else:
            del payload["rows"][0]["completed"]
        candidate.write_text(json.dumps(payload))
    output = tmp_path / "comparison.json"
    assert main(["compare", str(baseline), str(candidate), "--output", str(output)]) == 2
    captured = capsys.readouterr()
    assert "ReviewBoundary:" in captured.err
    assert "PASS" not in captured.out
    assert "Traceback" not in captured.err
    assert not output.exists()


def test_cli_output_write_failure_is_not_masked_as_success(report_files, tmp_path, capsys):
    baseline, candidate = report_files
    output = tmp_path / "output-is-a-directory"
    output.mkdir()
    assert main(["compare", str(baseline), str(candidate), "--output", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("ReviewBoundary:")
    assert "PASS" not in captured.out


def test_cli_group_selectors_are_forwarded(report_files, tmp_path):
    baseline, candidate = report_files
    payload = json.loads(candidate.read_text())
    for row in payload["rows"]:
        row.update(model="changed-reviewer", defense="hardened")
    candidate.write_text(json.dumps(payload))
    output = tmp_path / "comparison.json"
    assert (
        main(
            [
                "compare",
                str(baseline),
                str(candidate),
                "--baseline-model",
                "test-reviewer",
                "--baseline-defense",
                "baseline",
                "--candidate-model",
                "changed-reviewer",
                "--candidate-defense",
                "hardened",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    result = json.loads(output.read_text())
    assert result["baseline_group"] == {"model": "test-reviewer", "defense": "baseline"}
    assert result["candidate_group"] == {"model": "changed-reviewer", "defense": "hardened"}


@pytest.mark.parametrize(
    "extra",
    [
        '"schema_version": 1,',
        '"unused": NaN,',
        '"unused": Infinity,',
        '"unused": 1e999,',
        '"unused": ' + "[" * 1500 + "0" + "]" * 1500 + ",",
    ],
)
def test_ambiguous_nonfinite_or_deep_json_is_invalid_input(report_files, tmp_path, capsys, extra):
    baseline, candidate = report_files
    candidate.write_text("{" + extra + candidate.read_text()[1:])
    output = tmp_path / "comparison.json"
    assert main(["compare", str(baseline), str(candidate), "--output", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ReviewBoundary:" in captured.err
    assert "Traceback" not in captured.err
    assert not output.exists()


def test_oversized_comparison_input_is_rejected_before_parsing(report_files, capsys):
    from review_boundary.json_input import MAX_REPORT_BYTES

    baseline, candidate = report_files
    with candidate.open("r+b") as stream:
        stream.truncate(MAX_REPORT_BYTES + 1)
    assert main(["compare", str(baseline), str(candidate)]) == 2
    assert "32 MiB" in capsys.readouterr().err


def test_fifo_comparison_input_is_rejected_without_waiting(report_files, tmp_path, capsys):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("Named pipes are unavailable")
    baseline, _candidate = report_files
    pipe = tmp_path / "report-pipe"
    os.mkfifo(pipe)
    assert main(["compare", str(baseline), str(pipe)]) == 2
    assert "regular file" in capsys.readouterr().err
