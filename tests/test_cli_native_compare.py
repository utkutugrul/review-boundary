"""Native CLI gates dispatch on exact report kinds and explicit reviewer groups."""

import json
from copy import deepcopy

import pytest
from report_contract_support import native_fixture

from review_boundary.cli import main
from review_boundary.provenance import json_digest
from review_boundary.report_contract import export_report_envelope


def comparable(kind):
    report, case, _ = native_fixture(kind)
    report["metadata"].update(
        corpus_version="fixture-v1",
        suite_sha256=json_digest([report["rows"][0]["case_sha256"]]),
        bounds={"max_turns": 8, "max_input_bytes": 24000, "max_output_tokens": 8192, "retries": 0},
    )
    if kind == "boundary":
        report["metadata"]["guards"] = [report["rows"][0]["guard"]]
    return report, case


def write_pair(tmp_path, baseline, candidate):
    paths = tmp_path / "baseline.json", tmp_path / "candidate.json"
    for path, document in zip(paths, (baseline, candidate), strict=True):
        path.write_text(json.dumps(document))
    return paths


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("missing_candidate,expected_exit", [(False, 0), (True, 1)])
def test_native_cli_supports_native_and_enveloped_gate_outputs(
    tmp_path, capsys, kind, wrapped, missing_candidate, expected_exit
):
    baseline, _ = comparable(kind)
    candidate = deepcopy(baseline)
    if missing_candidate:
        candidate["rows"] = []
    if wrapped:
        baseline, candidate = export_report_envelope(baseline), export_report_envelope(candidate)
    paths = write_pair(tmp_path, baseline, candidate)
    output = tmp_path / "comparison.json"
    assert main(["compare", *map(str, paths), "--output", str(output)]) == expected_exit
    result = json.loads(output.read_text())
    assert result["comparison_schema_version"] == 1
    assert result["report_kind"] == kind
    assert result["exit_code"] == expected_exit
    assert result["summary"]["expected_samples"] == 1
    assert result["summary"]["candidate"]["missing"] == int(missing_candidate)
    captured = capsys.readouterr()
    assert f"{kind} comparison: {result['status'].upper()}" in captured.out
    assert captured.err == ""
    if missing_candidate:
        assert "missing_candidate" in captured.out


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_native_reviewer_and_guard_selectors_are_forwarded(tmp_path, kind):
    baseline, _ = comparable(kind)
    candidate = deepcopy(baseline)
    candidate["metadata"]["reviewers"] = ["changed/reviewer"]
    candidate["metadata"]["expected_slots"][0]["reviewer"] = "changed/reviewer"
    candidate["rows"][0]["reviewer"] = "changed/reviewer"
    paths = write_pair(tmp_path, baseline, candidate)
    output = tmp_path / "comparison.json"
    args = [
        "compare",
        *map(str, paths),
        "--baseline-reviewer",
        "fixture/reference",
        "--candidate-reviewer",
        "changed/reviewer",
        "--output",
        str(output),
    ]
    if kind == "boundary":
        args.extend(["--baseline-guard", "off", "--candidate-guard", "off"])
    assert main(args) == 0
    result = json.loads(output.read_text())
    assert result["baseline_group"]["reviewer"] == "fixture/reference"
    assert result["candidate_group"]["reviewer"] == "changed/reviewer"
    if kind == "boundary":
        assert result["baseline_group"]["guard"] == result["candidate_group"]["guard"] == "off"


def test_cli_expected_suite_is_data_only_and_binds_undeclared_slots(tmp_path, capsys):
    baseline, case = comparable("repository")
    del baseline["metadata"]["expected_slots"]
    paths = write_pair(tmp_path, baseline, deepcopy(baseline))
    assert main(["compare", *map(str, paths)]) == 2
    assert "coverage is unknown" in capsys.readouterr().err
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"schema_version": 1, "cases": [case.model_dump(mode="json")]}))
    output = tmp_path / "comparison.json"
    assert (
        main(["compare", *map(str, paths), "--expected-suite", str(suite), "--output", str(output)])
        == 0
    )
    assert json.loads(output.read_text())["experiment"]["supplied_suite_bound"] is True


@pytest.mark.parametrize(
    "extra", [["--baseline-model", "legacy-model"], ["--baseline-guard", "off"]]
)
def test_native_cli_rejects_inapplicable_selectors_without_green_output(tmp_path, capsys, extra):
    report, _ = comparable("repository")
    paths = write_pair(tmp_path, report, deepcopy(report))
    output = tmp_path / "comparison.json"
    assert main(["compare", *map(str, paths), "--output", str(output), *extra]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "ReviewBoundary:" in captured.err
    assert not output.exists()


def test_mixed_native_kinds_are_invalid(tmp_path, capsys):
    paths = write_pair(tmp_path, comparable("repository")[0], comparable("boundary")[0])
    assert main(["compare", *map(str, paths)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "Mixed report kinds" in captured.err


@pytest.mark.parametrize("side", ["baseline", "candidate"])
def test_explicit_unfinished_native_run_is_invalid(tmp_path, capsys, side):
    baseline, _ = comparable("repository")
    candidate = deepcopy(baseline)
    selected = baseline if side == "baseline" else candidate
    selected["metadata"]["run_finished"] = False
    paths = write_pair(tmp_path, baseline, candidate)
    assert main(["compare", *map(str, paths)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and "ReviewBoundary:" in captured.err
