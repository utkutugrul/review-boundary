"""Payload CI uses corpus metadata produced by the version-aware repository runner."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from review_boundary import ci, cli, providers, repository_runner
from review_boundary.report_contract import export_report_envelope
from review_boundary.repository_runtime import repository_world_for_case, score_repository_case

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "examples/adapters/repository-reference.json"
ADAPTER_NAME = json.loads(ADAPTER.read_text())["name"]


@pytest.fixture(autouse=True)
def synthetic_environment_and_no_live_calls(monkeypatch):
    # Supply an empty mapping without reading the host's environment values.
    monkeypatch.setattr(ci.os, "environ", {})

    def forbidden(*args, **kwargs):
        pytest.fail("Payload CI reached a credential, provider, pricing network or model call")

    monkeypatch.setattr(cli, "credential", forbidden)
    for name in ("api_get", "model_snapshot", "guarded_model", "eval"):
        monkeypatch.setattr(repository_runner, name, forbidden)


def payload_suite(tmp_path, carrier="pr"):
    suite = tmp_path / "suite.json"
    assert cli.main(["payload-suite", "--carrier", carrier, "--output", str(suite)]) == 0
    return suite


def adapter_baseline(tmp_path, suite):
    output = tmp_path / "baseline"
    assert cli.main(["repository-demo", "--suite", str(suite), "--output", str(output)]) == 0
    report = json.loads((output / "report.json").read_text())
    assert report["metadata"]["corpus_version"] == "repository-payload-suite-v1"
    assert report["metadata"]["scoring_version"] == "repository-payload-v1"
    assert (
        report["metadata"]["provenance"]["tools"]["protocol"] == repository_runner.PAYLOAD_PROTOCOL
    )
    return output / "report.json", report


def adapter_options(suite):
    return {
        "profile": "repository-adapter",
        "suite_path": suite,
        "baseline_reviewer": "reference",
        "candidate_reviewer": "adapter/" + ADAPTER_NAME,
        "baseline_guard": None,
        "candidate_guard": None,
    }


def model_baseline_from_runner_dry_run(tmp_path, suite, capsys):
    pricing = tmp_path / "pricing.json"
    pricing.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": "openai",
                "source": "https://openai.com/api/pricing/",
                "as_of": "2026-01-01",
                "models": {
                    model: {"input_usd_per_million": 0.1, "output_usd_per_million": 0.2}
                    for model in ("approved-model", "candidate-model")
                },
            }
        )
    )
    output = tmp_path / "dry-run-output"
    ledger = tmp_path / "dry-run-ledger.json"
    capsys.readouterr()
    assert (
        cli.main(
            [
                "repository-run-model",
                "--provider",
                "openai",
                "--model",
                "approved-model",
                "--pricing-file",
                str(pricing),
                "--suite",
                str(suite),
                "--output",
                str(output),
                "--ledger",
                str(ledger),
                "--dry-run",
            ]
        )
        == 0
    )
    metadata = json.loads(capsys.readouterr().out)
    assert metadata["corpus_version"] == "repository-payload-suite-v1"
    assert metadata["scoring_version"] == "repository-payload-v1"
    assert not output.exists() and not ledger.exists()
    # Build a synthetic completed baseline from scripted scorer observations and
    # the actual dry-run metadata. No provider execution is represented by this test.
    rows = []
    for index, case in enumerate(repository_runner.load_suite(suite)):
        world = repository_world_for_case(case)
        repository_runner.calibrate(world, "reference")
        row = score_repository_case(case, world)
        row.update(reviewer=metadata["reviewers"][0], epoch=1, instructions_key=f"input-{index}")
        rows.append(row)
    metadata["run_finished"] = True
    baseline = tmp_path / "model-baseline"
    baseline.mkdir()
    repository_runner.write_repository_report(rows, baseline, metadata)
    report = json.loads((baseline / "report.json").read_text())
    return baseline / "report.json", report, pricing


def model_options(suite):
    return {
        "profile": "repository-model",
        "suite_path": suite,
        "baseline_reviewer": "openai/approved-model",
        "candidate_reviewer": "openai/candidate-model",
        "baseline_guard": None,
        "candidate_guard": None,
    }


@pytest.mark.parametrize("carrier", ("pr", "tool_output"))
def test_payload_adapter_ci_accepts_actual_runner_corpus_and_keeps_v2_transport(tmp_path, carrier):
    suite = payload_suite(tmp_path, carrier)
    baseline, report = adapter_baseline(tmp_path, suite)
    original = baseline.read_bytes()
    options = adapter_options(suite)
    _, _, selected_suite, epochs, checked = ci._native_plan(baseline, **options)
    assert selected_suite == suite and epochs == 1 and checked["exit_code"] == 0
    output = tmp_path / "ci-output"
    assert ci.run_ci(baseline, output, adapter_path=ADAPTER, **options) == 0
    candidate = json.loads((output / "candidate/report.json").read_text())
    assert candidate["metadata"]["corpus_version"] == report["metadata"]["corpus_version"]
    assert candidate["metadata"]["adapter"]["protocol"] == repository_runner.PAYLOAD_PROTOCOL
    assert all(
        row["carrier_observed"] and row["semantic_passed"] is None for row in candidate["rows"]
    )
    result = json.loads((output / "ci-result.json").read_text())
    assert result["status"] == "pass" and result["counts"]["paired_samples"] == 12
    assert baseline.read_bytes() == original


def test_payload_model_plan_uses_actual_dry_run_metadata_without_key_or_network(tmp_path, capsys):
    suite = payload_suite(tmp_path)
    baseline, report, pricing = model_baseline_from_runner_dry_run(tmp_path, suite, capsys)
    options = model_options(suite)
    _, _, selected_suite, metadata, checked = ci._native_model_plan(baseline, **options)
    assert selected_suite == suite and metadata == report["metadata"] and checked["exit_code"] == 0
    _, _, args = ci._prepare_native_model_ci(
        baseline,
        tmp_path / "ci-plan",
        mode="model",
        provider="openai",
        model="candidate-model",
        pricing_file=pricing,
        budget=20,
        **options,
    )
    assert args.command == "repository-run-model" and args.suite == suite
    assert args.model == ["candidate-model"] and args.provider == "openai"
    assert args.concurrency == 1 and args.opencode_auth is None
    for name, value in report["metadata"]["world_limits"].items():
        assert getattr(args, name) == value
    for name, value in report["metadata"]["bounds"].items():
        if name != "retries":
            assert getattr(args, name) == value
    assert not (tmp_path / "ci-plan").exists()


def test_payload_model_ci_delegates_to_fixed_runner_and_data_only_compare(
    tmp_path, capsys, monkeypatch
):
    suite = payload_suite(tmp_path)
    baseline, report, pricing = model_baseline_from_runner_dry_run(tmp_path, suite, capsys)
    calls = []

    def fake_runner(args):
        calls.append(args)
        candidate = deepcopy(report)
        reviewer = "openai/candidate-model"
        candidate["metadata"].update(
            reviewers=[reviewer],
            provider=providers.prepare_provider(
                "openai", ["candidate-model"], pricing_file=pricing
            ).to_metadata(),
        )
        for row in candidate["rows"]:
            row["reviewer"] = reviewer
        for slot in candidate["metadata"]["expected_slots"]:
            slot["reviewer"] = reviewer
        args.output.mkdir()
        (args.output / "report.json").write_text(json.dumps(candidate))
        return 0

    monkeypatch.setattr(repository_runner, "run_repository_model", fake_runner)
    output = tmp_path / "model-ci"
    assert (
        ci.run_ci(
            baseline,
            output,
            mode="model",
            provider="openai",
            model="candidate-model",
            pricing_file=pricing,
            budget=20,
            **model_options(suite),
        )
        == 0
    )
    assert len(calls) == 1 and calls[0].suite == suite
    assert json.loads((output / "ci-result.json").read_text())["status"] == "pass"


@pytest.mark.parametrize("profile", ("adapter", "model"))
@pytest.mark.parametrize("corpus", ("custom", "repository-synthetic-v1", "unrecognized-payload"))
def test_payload_planners_reject_incorrect_corpus_before_execution(
    tmp_path, capsys, profile, corpus
):
    suite = payload_suite(tmp_path)
    if profile == "adapter":
        baseline, report = adapter_baseline(tmp_path, suite)
        planner, options = ci._native_plan, adapter_options(suite)
    else:
        baseline, report, _ = model_baseline_from_runner_dry_run(tmp_path, suite, capsys)
        planner, options = ci._native_model_plan, model_options(suite)
    report["metadata"]["corpus_version"] = corpus
    baseline.write_text(json.dumps(report))
    with pytest.raises(ci.CIError):
        planner(baseline, **options)


def test_payload_v3_baseline_uses_same_bounded_suite_and_adapter_gates(tmp_path, monkeypatch):
    suite = payload_suite(tmp_path)
    baseline, report = adapter_baseline(tmp_path, suite)
    baseline.write_text(json.dumps(export_report_envelope(report)))
    options = adapter_options(suite)
    assert ci._native_plan(baseline, **options)[2] == suite
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-test-key")
    monkeypatch.setattr(
        ci, "_execute_adapter", lambda **kwargs: pytest.fail("Credential gate bypassed")
    )
    output = tmp_path / "denied"
    assert ci.run_ci(baseline, output, adapter_path=ADAPTER, **options) == 2
    assert (
        json.loads((output / "ci-result.json").read_text())["error_code"] == "configuration_invalid"
    )
