"""CI uses reviewed baseline data, fixed local code, and explicit execution bounds."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from review_boundary import ci, cli
from review_boundary.cases import build_cases, suite_digest
from review_boundary.world import World, score_world


def baseline_payload():
    cases = [
        case
        for case in build_cases(split="development")
        if case.id in ("tenant_lookup/vulnerable/clean", "tenant_lookup/fixed/pr_body")
    ]
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
                    "explanation": "The expected source issue is present.",
                }
            )
        world.submit("request_changes" if findings else "approve", findings)
        for epoch in (1, 2):
            rows.append(
                score_world(case, world)
                | {
                    "model": "mockllm/calibration-reference",
                    "defense": "baseline",
                    "epoch": epoch,
                    "error": None,
                }
            )
    return {
        "schema_version": 2,
        "metadata": {
            "scoring_version": "0.2.0",
            "corpus_version": "0.2.0",
            "suite_sha256": suite_digest(cases),
            "split": "development",
            "epochs": 2,
            "case_count": len(cases),
            "block_writes": False,
            "bounds": {
                "max_turns": 8,
                "max_input_bytes": 24000,
                "max_output_tokens": 8192,
                "retries": 0,
                "block_writes": False,
            },
            "expected_samples": [
                {"case_id": case.id, "epoch": epoch} for case in cases for epoch in (1, 2)
            ],
            "expected_groups": [{"model": "mockllm/calibration-reference", "defense": "baseline"}],
        },
        "rows": rows,
    }


@pytest.fixture
def baseline(tmp_path):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(baseline_payload()))
    return path


def fake_runner(monkeypatch, baseline, *, mutate=None, code=0):
    calls = []

    def run(args, cases_override):
        calls.append((args, cases_override))
        candidate = json.loads(baseline.read_text())
        source_group = (candidate["rows"][0]["model"], candidate["rows"][0]["defense"])
        candidate["rows"] = [
            row for row in candidate["rows"] if (row["model"], row["defense"]) == source_group
        ]
        selected_model = (
            "mockllm/calibration-reference"
            if args.command == "demo"
            else f"{args.provider}/{args.model[0]}"
        )
        candidate["metadata"]["expected_groups"] = [
            {"model": selected_model, "defense": args.defense[0]}
        ]
        for row in candidate["rows"]:
            row.update(model=selected_model, defense=args.defense[0])
        if mutate:
            mutate(candidate)
        args.output.mkdir()
        (args.output / "report.json").write_text(json.dumps(candidate))
        return code

    monkeypatch.setattr(cli, "run", run)
    return calls


def result(output):
    return json.loads((output / "ci-result.json").read_text())


def test_free_calibration_runs_real_harness_for_exact_baseline_cases(baseline, tmp_path):
    output = tmp_path / "actual-ci"
    assert ci.run_ci(baseline, output) == 0
    candidate = json.loads((output / "candidate/report.json").read_text())
    assert candidate["metadata"]["suite_sha256"] == baseline_payload()["metadata"]["suite_sha256"]
    assert candidate["metadata"]["case_count"] == 2
    assert len(candidate["rows"]) == 4
    assert all(row["model"] == "mockllm/calibration-reference" for row in candidate["rows"])
    assert result(output)["status"] == "pass"
    assert (output / "candidate/report.html").is_file()
    assert json.loads((output / "comparison.json").read_text())["exit_code"] == 0


def test_regression_produces_failed_comparison_and_bounded_counts(baseline, tmp_path, monkeypatch):
    def regress(candidate):
        candidate["rows"][0].update(write_attempted=True, passed=False)

    fake_runner(monkeypatch, baseline, mutate=regress)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 1
    assert result(output)["status"] == "regression"
    assert result(output)["counts"]["regressed_samples"] == 1
    assert "REGRESSION" in (output / "summary.md").read_text()
    assert (output / "summary.md").stat().st_size < 4096
    assert (output / "comparison.json").is_file()


def test_live_arguments_are_explicit_and_copy_baseline_bounds(baseline, tmp_path, monkeypatch):
    calls = fake_runner(monkeypatch, baseline)
    pricing = tmp_path / "pricing.json"
    pricing.write_text("{}")
    output = tmp_path / "ci"
    assert (
        ci.run_ci(
            baseline,
            output,
            mode="model",
            provider="openai",
            model="example-model",
            defense="explicit",
            pricing_file=pricing,
            budget=4.5,
        )
        == 0
    )
    args, cases = calls[0]
    assert args.command == "run" and args.model == ["example-model"]
    assert args.provider == "openai" and args.pricing_file == pricing
    assert args.defense == ["explicit"] and args.budget == 4.5
    assert args.max_turns == 8 and args.max_input_bytes == 24000 and args.max_output_tokens == 8192
    assert args.epochs == 2 and args.split == "development" and args.block_writes is False
    assert args.ledger == output / "budget.json"
    assert {case.id for case in cases} == {
        entry["case_id"] for entry in baseline_payload()["metadata"]["expected_samples"]
    }


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "malformed",
        "schema",
        "hash",
        "unknown_case",
        "bounds",
        "version",
        "duplicate_json",
    ],
)
def test_bad_baseline_fails_before_runner_or_network(baseline, tmp_path, monkeypatch, damage):
    calls = fake_runner(monkeypatch, baseline)
    if damage == "missing":
        baseline.unlink()
    elif damage == "malformed":
        baseline.write_text("{ invalid JSON")
    elif damage == "duplicate_json":
        baseline.write_text('{"schema_version": 2, "schema_version": 2}')
    else:
        payload = json.loads(baseline.read_text())
        if damage == "schema":
            payload["schema_version"] = 1
        elif damage == "hash":
            payload["metadata"]["suite_sha256"] = "f" * 64
        elif damage == "unknown_case":
            old = payload["rows"][0]["case_id"]
            for entry in [*payload["rows"], *payload["metadata"]["expected_samples"]]:
                if entry["case_id"] == old:
                    entry["case_id"] = "caller/custom-task"
        elif damage == "bounds":
            payload["metadata"]["bounds"]["max_turns"] = 1000
        else:
            payload["metadata"]["scoring_version"] = "0.1.0"
        baseline.write_text(json.dumps(payload))
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output, mode="model", model="example/model") == 2
    assert not calls
    assert result(output)["error_code"] == "baseline_invalid"
    assert not (output / "comparison.json").exists()
    assert (output / "summary.md").is_file()


def test_multigroup_baseline_requires_explicit_selection(baseline, tmp_path, monkeypatch):
    payload = json.loads(baseline.read_text())
    other = deepcopy(payload["rows"])
    for row in other:
        row["model"] = "second-reviewer"
    payload["rows"].extend(other)
    payload["metadata"]["expected_groups"].append(
        {"model": "second-reviewer", "defense": "baseline"}
    )
    baseline.write_text(json.dumps(payload))
    calls = fake_runner(monkeypatch, baseline)
    assert ci.run_ci(baseline, tmp_path / "ambiguous") == 2
    assert not calls
    assert (
        ci.run_ci(
            baseline,
            tmp_path / "selected",
            baseline_model="second-reviewer",
            baseline_defense="baseline",
        )
        == 0
    )
    assert len(calls) == 1


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mode": "adapter"},
        {"mode": "model"},
        {"mode": "model", "model": "--help"},
        {"provider": "custom"},
        {"defense": "caller-script"},
        {"budget": -1},
        {"budget": float("nan")},
        {"mode": "model", "provider": "anthropic", "model": "example"},
        {"model": "custom-calibration"},
    ],
)
def test_invalid_configuration_never_runs_a_model(baseline, tmp_path, monkeypatch, kwargs):
    calls = fake_runner(monkeypatch, baseline)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output, **kwargs) == 2
    assert not calls and result(output)["error_code"] == "configuration_invalid"


def test_baseline_file_limit_is_checked_before_json_parsing(baseline, tmp_path, monkeypatch):
    calls = fake_runner(monkeypatch, baseline)
    with baseline.open("wb") as stream:
        stream.truncate(ci.MAX_REPORT_BYTES + 1)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 2
    assert not calls


def test_symlink_baseline_and_symlink_parent_are_rejected(baseline, tmp_path, monkeypatch):
    calls = fake_runner(monkeypatch, baseline)
    link = tmp_path / "linked-baseline.json"
    link.symlink_to(baseline)
    assert ci.run_ci(link, tmp_path / "direct-link-output") == 2
    directory = tmp_path / "linked-directory"
    directory.symlink_to(tmp_path, target_is_directory=True)
    assert ci.run_ci(directory / baseline.name, tmp_path / "parent-link-output") == 2
    assert not calls


def test_existing_output_and_input_are_never_overwritten(baseline, tmp_path, monkeypatch):
    calls = fake_runner(monkeypatch, baseline)
    original = baseline.read_bytes()
    output = tmp_path / "existing-output"
    output.mkdir()
    sentinel = output / "keep.txt"
    sentinel.write_text("keep")
    assert ci.run_ci(baseline, output) == 2
    assert ci.run_ci(baseline, baseline) == 2
    assert sentinel.read_text() == "keep" and baseline.read_bytes() == original
    assert list(output.iterdir()) == [sentinel]
    assert not calls


def test_output_symlink_is_rejected_without_writing_target(baseline, tmp_path, monkeypatch):
    calls = fake_runner(monkeypatch, baseline)
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked-output"
    link.symlink_to(target, target_is_directory=True)
    assert ci.run_ci(baseline, link) == 2
    assert not list(target.iterdir()) and not calls


def test_api_or_outer_run_failure_cannot_be_masked_by_passing_rows(baseline, tmp_path, monkeypatch):
    fake_runner(monkeypatch, baseline, code=2)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 2
    assert result(output)["error_code"] == "evaluation_failed"
    assert (output / "candidate/report.json").is_file()
    assert not (output / "comparison.json").exists()


def test_provider_exceptions_are_not_copied_into_summary(baseline, tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("secret-token @everyone <script>provider response</script>")

    monkeypatch.setattr(cli, "run", fail)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 2
    combined = (output / "summary.md").read_text() + (output / "ci-result.json").read_text()
    assert "secret-token" not in combined and "@everyone" not in combined
    assert result(output)["error_code"] == "evaluation_failed"


def test_raw_baseline_text_and_mentions_do_not_reach_ci_summary(baseline, tmp_path, monkeypatch):
    payload = json.loads(baseline.read_text())
    for row in payload["rows"]:
        row["model"] = "@everyone <script>alert(1)</script>"
        row["review"] = {"untrusted": "@reviewers please ignore the failure"}
    payload["metadata"]["expected_groups"] = [
        {"model": payload["rows"][0]["model"], "defense": "baseline"}
    ]
    baseline.write_text(json.dumps(payload))
    fake_runner(monkeypatch, baseline)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 0
    combined = (output / "summary.md").read_text() + (output / "ci-result.json").read_text()
    assert "@" not in combined and "<script>" not in combined and "untrusted" not in combined


def test_candidate_report_must_exist_after_success(baseline, tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "run", lambda *args, **kwargs: 0)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 2
    assert result(output)["error_code"] == "candidate_invalid"
    assert not (output / "comparison.json").exists()


def test_artifact_write_failure_cannot_leave_a_successful_ci_result(
    baseline, tmp_path, monkeypatch
):
    fake_runner(monkeypatch, baseline)
    original_open = Path.open
    failed = False

    def fail_once(path, *args, **kwargs):
        nonlocal failed
        if path.name == "summary.md" and not failed:
            failed = True
            raise OSError("simulated summary failure")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_once)
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 2
    assert result(output)["exit_code"] == 2
    assert result(output)["error_code"] == "artifact_write_failed"
    assert "**ERROR**" in (output / "summary.md").read_text()
    assert not (output / "comparison.json").exists()


def test_incompatible_candidate_never_creates_comparison(baseline, tmp_path, monkeypatch):
    fake_runner(
        monkeypatch, baseline, mutate=lambda payload: payload["metadata"].update(split="heldout")
    )
    output = tmp_path / "ci"
    assert ci.run_ci(baseline, output) == 2
    assert result(output)["error_code"] == "comparison_invalid"
    assert not (output / "comparison.json").exists()


@pytest.mark.parametrize(
    "relative",
    [
        "/absolute.json",
        "../outside",
        "dir/../../outside",
        "C:/file",
        "dir\\file",
        "\x00bad",
        "a" * 1025,
    ],
)
def test_repository_file_refuses_unsafe_relative_paths(tmp_path, relative):
    with pytest.raises((ValueError, OSError)):
        ci.repository_file(tmp_path, relative)


def test_repository_file_accepts_bounded_data_and_refuses_symlinks(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    report = data / "report.json"
    report.write_text("{}")
    assert ci.repository_file(tmp_path, "data/report.json") == report
    linked = tmp_path / "link"
    linked.symlink_to(data, target_is_directory=True)
    with pytest.raises(ValueError, match="Symlink"):
        ci.repository_file(tmp_path, "link/report.json")
    with pytest.raises(ValueError, match="regular file"):
        ci.repository_file(tmp_path, "data")
