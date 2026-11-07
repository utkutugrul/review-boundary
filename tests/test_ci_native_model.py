"""Native provider CI delegates only to trusted runners with offline fake providers."""

import json
from copy import deepcopy

import pytest
from report_contract_support import native_fixture

from review_boundary import boundary_runner, ci, cli, providers, repository_runner
from review_boundary.provenance import json_digest, text_digest
from review_boundary.report_contract import export_report_envelope


@pytest.fixture(autouse=True)
def no_live_provider_or_adapter(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Native CI reached a live provider, credential or caller adapter")

    for name in ci.ADAPTER_FORBIDDEN_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cli, "credential", forbidden)
    for module in (repository_runner, boundary_runner):
        monkeypatch.setattr(module, "api_get", forbidden)
        monkeypatch.setattr(module, "guarded_model", forbidden)
        monkeypatch.setattr(module, "eval", forbidden)
    monkeypatch.setattr(repository_runner, "run_repository_model", forbidden)
    monkeypatch.setattr(boundary_runner, "run_boundary_model", forbidden)
    monkeypatch.setattr(repository_runner, "run_repository_command", forbidden)
    monkeypatch.setattr(boundary_runner, "run_boundary_command", forbidden)


@pytest.fixture(params=("repository", "boundary"))
def native_model_ci(request, tmp_path):
    kind = request.param
    report, case, world = native_fixture(kind, guard="off")
    row = report["rows"][0]
    row.update(reviewer="openrouter/approved-model", instructions_key="input-0")
    report["metadata"].update(
        run_id="offline-baseline-fixture",
        corpus_version="custom",
        suite_sha256=json_digest([row["case_sha256"]]),
        reviewers=[row["reviewer"]],
        provider=providers.prepare_provider("openrouter", ["approved-model"]).to_metadata(),
        bounds={"max_turns": 8, "max_input_bytes": 24000, "max_output_tokens": 8192, "retries": 0},
        provenance={
            "schema_version": 1,
            "hash_algorithm": "sha256",
            "prompts": {
                "input-0": text_digest(
                    json.dumps(world.reviewer_request(), ensure_ascii=False, sort_keys=True)
                )
            },
            "tools": {"protocol": "offline-fixture", "sha256": json_digest([])},
            "harness": {
                "status": "recorded",
                "files": {"fixture.py": "a" * 64},
                "sha256": json_digest({"fixture.py": "a" * 64}),
            },
            "reviewer_source": {"status": "not_recorded", "files": {}, "sha256": None},
        },
    )
    fields = (
        ("reviewer", "case_sha256", "epoch")
        if kind == "repository"
        else ("reviewer", "case_id", "epoch", "guard")
    )
    report["metadata"]["expected_slots"] = [{key: row[key] for key in fields}]
    if kind == "boundary":
        report["metadata"].update(
            guards=["off"],
            external_policy=None,
            policy_sha256={row["case_id"]: row["policy_sha256"]},
        )
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps(report))
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"schema_version": 1, "cases": [case.model_dump(mode="json")]}))
    options = {
        "profile": kind + "-model",
        "mode": "model",
        "suite_path": suite,
        "provider": "openrouter",
        "model": "candidate-model",
        "budget": 20,
        "baseline_reviewer": row["reviewer"],
        "candidate_reviewer": "openrouter/candidate-model",
        "baseline_guard": "off" if kind == "boundary" else None,
        "candidate_guard": "off" if kind == "boundary" else None,
    }
    return kind, baseline, report, options


def quote(tmp_path, provider):
    path = tmp_path / "pricing.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": provider,
                "source": "https://openai.com/api/pricing/"
                if provider == "openai"
                else "https://platform.claude.com/docs/en/about-claude/pricing",
                "as_of": "2026-01-01",
                "models": {
                    "candidate-model": {"input_usd_per_million": 0.1, "output_usd_per_million": 0.2}
                },
            }
        )
    )
    return path


def fake_model(monkeypatch, kind, report, *, damage=None, code=0):
    calls = []

    def run(args):
        calls.append(args)
        candidate = deepcopy(report)
        reviewer = args.provider + "/" + args.model[0]
        candidate["metadata"].update(
            reviewers=[reviewer],
            provider=providers.prepare_provider(
                args.provider, args.model, pricing_file=args.pricing_file
            ).to_metadata(),
        )
        for row in candidate["rows"]:
            row["reviewer"] = reviewer
        for slot in candidate["metadata"]["expected_slots"]:
            slot["reviewer"] = reviewer
        if damage == "missing":
            candidate["rows"] = []
        elif damage == "unfinished":
            candidate["metadata"]["run_finished"] = False
        elif damage == "bounds":
            candidate["metadata"].pop("bounds")
        elif damage == "exception":
            args.output.mkdir()
            (args.output / "partial-evidence.json").write_text("{}")
            raise RuntimeError("synthetic-private-provider-response-and-key")
        args.output.mkdir()
        (args.output / "report.json").write_text(json.dumps(candidate))
        return code

    monkeypatch.setattr(
        repository_runner if kind == "repository" else boundary_runner,
        "run_" + kind + "_model",
        run,
    )
    return calls


def result(output):
    return json.loads((output / "ci-result.json").read_text())


@pytest.mark.parametrize("provider", providers.PROVIDERS)
def test_exact_trusted_native_runner_delegation_for_each_provider(
    native_model_ci, tmp_path, monkeypatch, provider
):
    kind, baseline, report, options = native_model_ci
    options.update(provider=provider, candidate_reviewer=provider + "/candidate-model")
    if provider != "openrouter":
        options["pricing_file"] = quote(tmp_path, provider)
    calls = fake_model(monkeypatch, kind, report)
    output = tmp_path / "provider-ci"
    assert ci.run_ci(baseline, output, **options) == 0
    (args,) = calls
    assert args.command == kind + "-run-model"
    assert args.model == ["candidate-model"] and args.provider == provider
    assert args.suite == options["suite_path"]
    assert args.epochs == report["metadata"]["epochs"] and args.concurrency == 1
    assert args.output == output / "candidate" and args.ledger == output / "budget.json"
    assert args.opencode_auth is None and args.dry_run is False
    assert not hasattr(args, "adapter") and not hasattr(args, "policy")
    for name, value in report["metadata"]["world_limits"].items():
        assert getattr(args, name) == value
    for name, value in report["metadata"]["bounds"].items():
        if name != "retries":
            assert getattr(args, name) == value
    assert result(output)["status"] == "pass"
    assert result(output)["report_kind"] == kind
    comparison = json.loads((output / "comparison.json").read_text())
    assert comparison["summary"]["expected_samples"] == 1


@pytest.mark.parametrize(
    "damage,expected", ((None, 0), ("missing", 1), ("unfinished", 2), ("bounds", 2))
)
def test_native_model_comparison_exit_contract(
    native_model_ci, tmp_path, monkeypatch, damage, expected
):
    kind, baseline, report, options = native_model_ci
    fake_model(monkeypatch, kind, report, damage=damage)
    output = tmp_path / "gate"
    assert ci.run_ci(baseline, output, **options) == expected
    assert result(output)["exit_code"] == expected
    assert (output / "comparison.json").exists() is (expected in (0, 1))


@pytest.mark.parametrize(
    "damage",
    (
        "no_suite",
        "wrong_suite",
        "unfinished",
        "missing_bounds",
        "bounds",
        "retry",
        "calibration",
        "no_provider",
        "provider_marker",
        "wrong_kind",
        "no_reviewer",
        "missing_slot",
    ),
)
def test_baseline_suite_and_coverage_fail_before_provider_preparation(
    native_model_ci, tmp_path, monkeypatch, damage
):
    _, baseline, report, options = native_model_ci
    if damage == "no_suite":
        options["suite_path"] = None
    elif damage == "wrong_suite":
        report["metadata"]["suite_sha256"] = "f" * 64
    elif damage == "unfinished":
        report["metadata"]["run_finished"] = False
    elif damage == "missing_bounds":
        report["metadata"].pop("bounds")
    elif damage == "bounds":
        report["metadata"]["bounds"]["max_output_tokens"] = 9000
    elif damage == "retry":
        report["metadata"]["bounds"]["retries"] = 1
    elif damage == "calibration":
        report["metadata"]["run_kind"] = "calibration"
    elif damage == "no_provider":
        report["metadata"].pop("provider")
    elif damage == "provider_marker":
        report["metadata"]["provider"]["name"] = "openai"
    elif damage == "wrong_kind":
        report["report_kind"] = (
            "boundary" if report["report_kind"] == "repository" else "repository"
        )
    elif damage == "no_reviewer":
        options["baseline_reviewer"] = None
    else:
        report["rows"] = []
    baseline.write_text(json.dumps(report))
    monkeypatch.setattr(
        providers,
        "prepare_provider",
        lambda *a, **k: pytest.fail("provider preparation before valid baseline"),
    )
    output = tmp_path / "invalid-baseline"
    assert ci.run_ci(baseline, output, **options) == 2
    assert not (output / "comparison.json").exists()


@pytest.mark.parametrize(
    "option,value",
    (
        ("mode", "calibration"),
        ("adapter_path", "unread-adapter.json"),
        ("defense", "explicit"),
        ("baseline_model", "other"),
        ("baseline_defense", "baseline"),
    ),
)
def test_native_provider_rejects_adapter_and_legacy_options_before_any_input_or_key_access(
    native_model_ci, tmp_path, monkeypatch, option, value
):
    _, baseline, _, options = native_model_ci
    options[option] = value
    monkeypatch.setattr(
        ci,
        "_native_model_plan",
        lambda *a, **k: pytest.fail("native baseline loaded before fixed options checked"),
    )
    assert ci.run_ci(baseline, tmp_path / "invalid-options", **options) == 2


@pytest.mark.parametrize("option", ("policy", "policy_path", "command", "source", "opencode_auth"))
def test_provider_execution_api_rejects_any_callback_or_credential_file_options(
    native_model_ci, tmp_path, monkeypatch, option
):
    _, baseline, _, options = native_model_ci
    options[option] = "never-read-or-executed"
    monkeypatch.setattr(
        ci, "_native_model_plan", lambda *a, **k: pytest.fail("callback option reached preflight")
    )
    assert ci.execute_native_model_ci(baseline, tmp_path / "no-callbacks", **options) == 2


@pytest.mark.parametrize("budget", (0, -1, 20.01, float("inf"), float("nan"), True))
def test_native_budget_ceiling_precedes_provider_preparation(
    native_model_ci, tmp_path, monkeypatch, budget
):
    _, baseline, _, options = native_model_ci
    options["budget"] = budget
    monkeypatch.setattr(
        providers,
        "prepare_provider",
        lambda *a, **k: pytest.fail("invalid budget reached provider preparation"),
    )
    assert ci.run_ci(baseline, tmp_path / "invalid-budget", **options) == 2


def test_reservation_rejects_insufficient_budget_before_model_runner(native_model_ci, tmp_path):
    _, baseline, _, options = native_model_ci
    options["budget"] = 0.000001
    assert ci.run_ci(baseline, tmp_path / "insufficient", **options) == 2


@pytest.mark.parametrize("code", (1, 2, True, None))
def test_provider_failure_keeps_candidate_and_never_compares(
    native_model_ci, tmp_path, monkeypatch, code
):
    kind, baseline, report, options = native_model_ci
    fake_model(monkeypatch, kind, report, code=code)
    output = tmp_path / "failed-provider"
    assert ci.run_ci(baseline, output, **options) == 2
    assert result(output)["error_code"] == "evaluation_failed"
    assert (output / "candidate/report.json").exists()
    assert not (output / "comparison.json").exists()


def test_provider_exception_is_redacted_and_partial_evidence_survives(
    native_model_ci, tmp_path, monkeypatch, capsys
):
    kind, baseline, report, options = native_model_ci
    fake_model(monkeypatch, kind, report, damage="exception")
    output = tmp_path / "exception"
    assert ci.run_ci(baseline, output, **options) == 2
    assert result(output)["error_code"] == "evaluation_failed"
    assert (output / "candidate/partial-evidence.json").exists()
    assert (
        "synthetic-private"
        not in str(result(output)) + (output / "summary.md").read_text() + capsys.readouterr().err
    )


def test_model_v3_baseline_and_fresh_data_only_comparison(native_model_ci, tmp_path, monkeypatch):
    kind, baseline, report, options = native_model_ci
    baseline.write_text(json.dumps(export_report_envelope(report)))
    fake_model(monkeypatch, kind, report)
    execution = tmp_path / "execution"
    assert ci.execute_native_model_ci(baseline, execution, **options) == 0
    monkeypatch.setattr(
        providers,
        "prepare_provider",
        lambda *a, **k: pytest.fail("data comparison prepared provider"),
    )
    selected = {
        name: options[name]
        for name in (
            "profile",
            "suite_path",
            "baseline_reviewer",
            "candidate_reviewer",
            "baseline_guard",
            "candidate_guard",
        )
    }
    assert (
        ci.compare_native_ci(
            baseline,
            execution / "candidate/report.json",
            tmp_path / "comparison",
            evaluation_code=0,
            **selected,
        )
        == 0
    )


def test_native_model_cli_requires_explicit_model_mode_and_rejects_policy(
    native_model_ci, tmp_path
):
    _, baseline, _, options = native_model_ci
    args = [
        "ci",
        str(baseline),
        "--output",
        str(tmp_path / "cli"),
        "--profile",
        options["profile"],
        "--suite",
        str(options["suite_path"]),
        "--baseline-reviewer",
        options["baseline_reviewer"],
        "--candidate-reviewer",
        options["candidate_reviewer"],
        "--model",
        "candidate-model",
    ]
    assert cli.main(args) == 2
    with pytest.raises(SystemExit) as caught:
        cli.parser().parse_args(args + ["--policy", "never-read.json"])
    assert caught.value.code == 2


def test_nondefault_approved_limits_epochs_and_cost_unknowns_are_preserved(
    native_model_ci, tmp_path, monkeypatch
):
    kind, baseline, report, options = native_model_ci
    metadata = report["metadata"]
    metadata["bounds"].update(max_turns=3, max_input_bytes=8192, max_output_tokens=512)
    metadata["world_limits"].update(max_calls=32, max_response_bytes=8192, max_read_lines=40)
    metadata.update(
        epochs=2,
        expected_count=2,
        usage={"provider_reported_cost_usd": None, "api_calls_without_reported_cost": 2},
    )
    report["rows"].append({**deepcopy(report["rows"][0]), "epoch": 2})
    metadata["expected_slots"].append({**metadata["expected_slots"][0], "epoch": 2})
    baseline.write_text(json.dumps(report))
    calls = fake_model(monkeypatch, kind, report)
    output = tmp_path / "nondefault-bounds"
    assert ci.run_ci(baseline, output, **options) == 0
    (args,) = calls
    assert (args.max_turns, args.max_input_bytes, args.max_output_tokens, args.epochs) == (
        3,
        8192,
        512,
        2,
    )
    assert (args.max_calls, args.max_response_bytes, args.max_read_lines) == (32, 8192, 40)
    candidate = json.loads((output / "candidate/report.json").read_text())
    assert candidate["metadata"]["usage"] == metadata["usage"]
    assert candidate["metadata"]["usage"]["provider_reported_cost_usd"] is None


@pytest.mark.parametrize(
    "field,value",
    (
        ("provider", "other"),
        ("model", "bad model"),
        ("model", ""),
        ("candidate_reviewer", "adapter/wrong"),
        ("prompt_price_cap", float("inf")),
        ("completion_price_cap", 0),
    ),
)
def test_invalid_provider_selection_or_rates_never_reach_model_execution(
    native_model_ci, tmp_path, field, value
):
    _, baseline, _, options = native_model_ci
    options[field] = value
    assert ci.run_ci(baseline, tmp_path / "invalid-provider", **options) == 2


def test_native_cli_model_mode_runs_the_fixed_profile_with_caps(
    native_model_ci, tmp_path, monkeypatch
):
    kind, baseline, report, options = native_model_ci
    fake_model(monkeypatch, kind, report)
    args = [
        "ci",
        str(baseline),
        "--output",
        str(tmp_path / "cli-model"),
        "--profile",
        options["profile"],
        "--mode",
        "model",
        "--suite",
        str(options["suite_path"]),
        "--baseline-reviewer",
        options["baseline_reviewer"],
        "--candidate-reviewer",
        options["candidate_reviewer"],
        "--provider",
        "openrouter",
        "--model",
        "candidate-model",
        "--prompt-price-cap",
        "0.5",
        "--completion-price-cap",
        "1",
    ]
    if kind == "boundary":
        args += ["--baseline-guard", "off", "--candidate-guard", "off"]
    assert cli.main(args) == 0


@pytest.mark.parametrize("field", ("baseline", "suite_path"))
def test_model_json_inputs_reject_symlinks_and_duplicates_before_preparation(
    native_model_ci, tmp_path, monkeypatch, field
):
    _, baseline, _, options = native_model_ci
    selected = baseline if field == "baseline" else options["suite_path"]
    link = tmp_path / "linked.json"
    link.symlink_to(selected)
    if field == "baseline":
        baseline = link
    else:
        options["suite_path"] = link
    monkeypatch.setattr(
        providers,
        "prepare_provider",
        lambda *a, **k: pytest.fail("unsafe JSON reached provider preparation"),
    )
    assert ci.run_ci(baseline, tmp_path / "symlink", **options) == 2
    if field == "baseline":
        baseline = selected
    else:
        options["suite_path"] = selected
    selected.write_text('{"schema_version":1,"schema_version":1}')
    assert ci.run_ci(baseline, tmp_path / "duplicate", **options) == 2


def test_existing_native_output_directory_is_never_reused(native_model_ci, tmp_path):
    _, baseline, _, options = native_model_ci
    output = tmp_path / "existing"
    output.mkdir()
    marker = output / "marker.txt"
    marker.write_text("keep")
    assert ci.run_ci(baseline, output, **options) == 2
    assert marker.read_text() == "keep"
    assert not (output / "ci-result.json").exists()
