"""Native gates exercise keyless transports and keep provider code unreachable."""

import json
from argparse import Namespace
from pathlib import Path

import pytest

from review_boundary import boundary_runner, ci, cli, repository_runner
from review_boundary.boundary_cases import build_boundary_cases
from review_boundary.report_contract import export_report_envelope, validate_report_document
from review_boundary.repository_cases import build_repository_demo_cases

EXAMPLES = Path(__file__).resolve().parents[1] / "examples/adapters"


@pytest.fixture(autouse=True)
def no_host_credentials(monkeypatch):
    for name in ci.ADAPTER_FORBIDDEN_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(params=("repository", "boundary"))
def native_ci(request, tmp_path, monkeypatch):
    kind = request.param

    def forbidden(*args, **kwargs):
        pytest.fail("Adapter CI reached a credential or provider entry point")

    monkeypatch.setattr(cli, "credential", forbidden)
    monkeypatch.setattr(cli, "prepare_provider", forbidden)
    monkeypatch.setattr(repository_runner, "prepare_provider", forbidden)
    monkeypatch.setattr(repository_runner, "run_repository_model", forbidden)
    monkeypatch.setattr(boundary_runner, "prepare_provider", forbidden)
    monkeypatch.setattr(boundary_runner, "run_boundary_model", forbidden)
    cases = (build_repository_demo_cases() if kind == "repository" else build_boundary_cases())[:2]
    suite = tmp_path / "suite.json"
    suite.write_text(
        json.dumps({"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]})
    )
    baseline_output = tmp_path / "baseline-run"
    runner = (
        repository_runner.run_repository_command
        if kind == "repository"
        else boundary_runner.run_boundary_command
    )
    assert (
        runner(
            Namespace(
                command=f"{kind}-demo",
                output=baseline_output,
                suite=suite,
                epochs=1,
                guard="both",
                policy=None,
            )
        )
        == 0
    )
    config = EXAMPLES / f"{kind}-reference.json"
    name = json.loads(config.read_text())["name"]
    return (
        kind,
        baseline_output / "report.json",
        {
            "profile": f"{kind}-adapter",
            "suite_path": suite,
            "adapter_path": config,
            "baseline_reviewer": "reference",
            "candidate_reviewer": "adapter/" + name,
            "baseline_guard": "off" if kind == "boundary" else None,
            "candidate_guard": "on" if kind == "boundary" else None,
        },
    )


def read_result(output):
    return json.loads((output / "ci-result.json").read_text())


def test_native_profiles_run_keyless_jsonl_transport_and_derive_historical_coverage(
    native_ci, tmp_path
):
    kind, baseline, options = native_ci
    original = baseline.read_bytes()
    output = tmp_path / "native-ci"
    assert ci.run_ci(baseline, output, **options) == 0
    candidate = json.loads((output / "candidate/report.json").read_text())
    assert candidate["report_kind"] == kind and candidate["metadata"]["run_finished"] is True
    assert candidate["metadata"]["run_kind"] == "adapter"
    assert candidate["metadata"]["case_count"] == 2
    assert all(row["reviewer"] == options["candidate_reviewer"] for row in candidate["rows"])
    result = read_result(output)
    assert result["status"] == "pass" and result["report_kind"] == kind
    assert result["counts"]["expected_samples"] == result["counts"]["paired_samples"] == 2
    assert baseline.read_bytes() == original
    assert (output / "summary.md").stat().st_size < 4096
    assert json.loads((output / "comparison.json").read_text())["exit_code"] == 0


def test_native_v3_baselines_keep_the_native_dispatch(native_ci, tmp_path):
    _, baseline, options = native_ci
    baseline.write_text(json.dumps(export_report_envelope(json.loads(baseline.read_text()))))
    assert ci.run_ci(baseline, tmp_path / "v3-ci", **options) == 0


@pytest.mark.parametrize("name", sorted(ci.ADAPTER_FORBIDDEN_ENV))
def test_known_provider_and_app_credentials_prevent_any_adapter_launch(
    native_ci, tmp_path, monkeypatch, name
):
    _, baseline, options = native_ci
    monkeypatch.setenv(name, "synthetic-private-value")
    monkeypatch.setattr(ci, "_execute_adapter", lambda **kwargs: pytest.fail("adapter launched"))
    output = tmp_path / "credential-rejected"
    assert ci.run_ci(baseline, output, **options) == 2
    assert read_result(output)["error_code"] == "configuration_invalid"
    assert "synthetic-private-value" not in (output / "summary.md").read_text()
    assert not (output / "comparison.json").exists()


@pytest.mark.parametrize(
    "damage",
    (
        "no_suite",
        "no_reviewer",
        "wrong_kind",
        "wrong_suite",
        "unfinished",
        "model_bounds",
        "model_run",
    ),
)
def test_invalid_native_baseline_or_selection_fails_before_transport(
    native_ci, tmp_path, monkeypatch, damage
):
    _, baseline, options = native_ci
    payload = json.loads(baseline.read_text())
    if damage == "no_suite":
        options["suite_path"] = None
    elif damage == "no_reviewer":
        options["baseline_reviewer"] = None
    elif damage == "wrong_kind":
        payload["report_kind"] = (
            "boundary" if payload["report_kind"] == "repository" else "repository"
        )
    elif damage == "wrong_suite":
        payload["metadata"]["suite_sha256"] = "f" * 64
    elif damage == "unfinished":
        payload["metadata"]["run_finished"] = False
    elif damage == "model_bounds":
        payload["metadata"]["bounds"] = {"max_turns": 8}
    else:
        payload["metadata"]["run_kind"] = "model"
    baseline.write_text(json.dumps(payload))
    monkeypatch.setattr(ci, "_execute_adapter", lambda **kwargs: pytest.fail("adapter launched"))
    output = tmp_path / "invalid-native"
    assert ci.run_ci(baseline, output, **options) == 2
    assert not (output / "comparison.json").exists()


@pytest.mark.parametrize("damage", ("allowlist", "name", "shell_string", "duplicate", "oversized"))
def test_native_config_is_bounded_explicit_argv_without_environment_forwarding(
    native_ci, tmp_path, monkeypatch, damage
):
    _, baseline, options = native_ci
    value = {"name": "test", "command": ["{python}", "program.py"]}
    config = tmp_path / "config.json"
    options.update(adapter_path=config, candidate_reviewer="adapter/test")
    if damage == "allowlist":
        value["env_allowlist"] = ["HOME"]
    elif damage == "name":
        options["candidate_reviewer"] = "adapter/another-name"
    elif damage == "shell_string":
        value["command"] = "python program.py; echo injected"
    config.write_text(json.dumps(value))
    if damage == "duplicate":
        config.write_text('{"name":"test","name":"test","command":["python"]}')
    elif damage == "oversized":
        config.write_bytes(b" " * 65537)
    monkeypatch.setattr(ci, "_execute_adapter", lambda **kwargs: pytest.fail("adapter launched"))
    output = tmp_path / "invalid-config"
    assert ci.run_ci(baseline, output, **options) == 2
    assert read_result(output)["error_code"] == "configuration_invalid"


def test_failed_adapter_process_keeps_evidence_and_cannot_create_passing_comparison(
    native_ci, tmp_path
):
    _, baseline, options = native_ci
    config = tmp_path / "failed-adapter.json"
    config.write_text(
        json.dumps(
            {
                "name": "failed-process",
                "command": [
                    "{python}",
                    "-c",
                    "import sys; print('private-stderr-payload', file=sys.stderr); sys.exit(7)",
                ],
            }
        )
    )
    options.update(adapter_path=config, candidate_reviewer="adapter/failed-process")
    output = tmp_path / "failed-process-output"
    assert ci.run_ci(baseline, output, **options) == 2
    assert read_result(output)["error_code"] == "evaluation_failed"
    assert (output / "candidate/report.json").is_file()
    assert "private-stderr-payload" not in (output / "summary.md").read_text()
    assert not (output / "comparison.json").exists()


def test_changed_adapter_transport_bounds_stop_before_next_adapter_launch(
    native_ci, tmp_path, monkeypatch
):
    _, baseline, options = native_ci
    approved = tmp_path / "approved-adapter"
    assert ci.run_ci(baseline, approved, **options) == 0
    config = json.loads(options["adapter_path"].read_text())
    config["limits"]["total_timeout"] += 1.0
    changed = tmp_path / "changed-config.json"
    changed.write_text(json.dumps(config))
    options.update(
        adapter_path=changed,
        baseline_reviewer=options["candidate_reviewer"],
        baseline_guard=options["candidate_guard"],
    )
    monkeypatch.setattr(ci, "_execute_adapter", lambda **kwargs: pytest.fail("adapter launched"))
    output = tmp_path / "changed-transport-output"
    assert ci.run_ci(approved / "candidate/report.json", output, **options) == 2
    assert read_result(output)["error_code"] == "configuration_invalid"
    assert not (output / "comparison.json").exists()


@pytest.mark.parametrize("mode", ("model", "adapter"))
def test_native_adapter_profile_cannot_dispatch_a_paid_mode(native_ci, tmp_path, monkeypatch, mode):
    _, baseline, options = native_ci
    monkeypatch.setattr(ci, "_execute_adapter", lambda **kwargs: pytest.fail("adapter launched"))
    output = tmp_path / "wrong-mode"
    assert ci.run_ci(baseline, output, mode=mode, model="test-model", **options) == 2
    assert read_result(output)["error_code"] == (
        "native_model_unsupported" if mode == "model" else "configuration_invalid"
    )


@pytest.mark.parametrize("damage", ("outer_failure", "missing", "malformed", "unfinished", "empty"))
def test_failed_or_unfinished_native_output_never_passes_but_missing_finished_slots_regress(
    native_ci, tmp_path, monkeypatch, damage
):
    _, baseline, options = native_ci
    original = ci._execute_adapter

    def execute(**kwargs):
        original(**kwargs)
        report = kwargs["output"] / "candidate/report.json"
        candidate = json.loads(report.read_text())
        if damage == "outer_failure":
            raise RuntimeError("private-adapter-payload @everyone")
        if damage == "missing":
            report.rename(report.with_suffix(".saved"))
        elif damage == "malformed":
            report.write_text("{malformed private-adapter-payload")
        else:
            if damage == "unfinished":
                candidate["metadata"]["run_finished"] = False
                validate_report_document(candidate)
            else:
                candidate["rows"] = []
            report.write_text(json.dumps(candidate))

    monkeypatch.setattr(ci, "_execute_adapter", execute)
    output = tmp_path / "damaged-output"
    expected = 1 if damage == "empty" else 2
    assert ci.run_ci(baseline, output, **options) == expected
    assert (output / "comparison.json").exists() is (expected == 1)
    assert "private-adapter-payload" not in (output / "summary.md").read_text()
    if damage == "empty":
        assert read_result(output)["counts"]["regressed_samples"] == 2


def test_separate_comparison_reads_data_only_and_outer_failure_overrides_valid_rows(
    native_ci, tmp_path, monkeypatch
):
    _, baseline, options = native_ci
    config = options.pop("adapter_path")
    execution = tmp_path / "execution"
    assert ci.execute_adapter_ci(baseline, execution, adapter_path=config, **options) == 0

    def forbidden(*args, **kwargs):
        pytest.fail("Data-only comparison attempted to load or execute an adapter")

    monkeypatch.setattr(ci, "_adapter_configuration", forbidden)
    monkeypatch.setattr(ci, "_execute_adapter", forbidden)
    monkeypatch.setattr(repository_runner, "run_repository_command", forbidden)
    monkeypatch.setattr(boundary_runner, "run_boundary_command", forbidden)
    candidate = execution / "candidate/report.json"
    assert (
        ci.compare_native_ci(
            baseline, candidate, tmp_path / "comparison", evaluation_code=0, **options
        )
        == 0
    )
    failed = tmp_path / "failed-comparison"
    assert ci.compare_native_ci(baseline, candidate, failed, evaluation_code=2, **options) == 2
    assert read_result(failed)["error_code"] == "evaluation_failed"
    assert not (failed / "comparison.json").exists()


def test_native_cli_exposes_explicit_profile_suite_and_group_options(native_ci, tmp_path):
    kind, baseline, options = native_ci
    arguments = [
        "ci",
        str(baseline),
        "--output",
        str(tmp_path / "cli-ci"),
        "--profile",
        options["profile"],
        "--suite",
        str(options["suite_path"]),
        "--adapter",
        str(options["adapter_path"]),
        "--baseline-reviewer",
        options["baseline_reviewer"],
        "--candidate-reviewer",
        options["candidate_reviewer"],
    ]
    if kind == "boundary":
        arguments.extend(["--baseline-guard", "off", "--candidate-guard", "on"])
    assert cli.main(arguments) == 0
