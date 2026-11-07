"""Trusted native provider workflow routes never receive caller commands or App keys."""

import json
import re
from pathlib import Path

import pytest
import yaml

from review_boundary import actions, ci, cli

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def model_environment(tmp_path, monkeypatch):
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "number": 5,
                "pull_request": {
                    "base": {"repo": {"full_name": "owner/repo"}, "sha": "b" * 40},
                    "head": {"repo": {"full_name": "owner/repo"}, "sha": "a" * 40},
                },
            }
        )
    )
    for name in ("harness", "baseline-source"):
        root = tmp_path / name
        root.mkdir()
        for filename in ("baseline.json", "suite.json", "pricing.json"):
            (root / filename).write_text("{}")
    monkeypatch.chdir(tmp_path / "harness")
    return {
        "RB_SERVER_URL": "https://github.com",
        "RB_EVENT": "pull_request",
        "RB_REPOSITORY": "owner/repo",
        "RB_MODE": "model",
        "RB_ALLOW_LIVE": "true",
        "RB_PROFILE": "repository-model",
        "RB_PROVIDER": "openai",
        "RB_MODEL": "candidate-model",
        "RB_BUDGET": "3",
        "RB_BASELINE_SOURCE": "caller",
        "RB_BASELINE": "baseline.json",
        "RB_SUITE": "suite.json",
        "RB_PRICING_FILE": "pricing.json",
        "RB_BASELINE_REVIEWER": "openai/approved-model",
        "RB_CANDIDATE_REVIEWER": "openai/candidate-model",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "step-output"),
    }


class NoSecretReads(dict):
    def get(self, name, *args):
        if name in ci.ADAPTER_FORBIDDEN_ENV:
            pytest.fail("A rejected native provider workflow inspected a key")
        return super().get(name, *args)


@pytest.mark.parametrize("allow_live", (None, "false", "False", "", "1"))
def test_native_live_opt_in_required_before_paths_runner_or_keys(
    model_environment, monkeypatch, allow_live
):
    environ = NoSecretReads(model_environment)
    if allow_live is None:
        environ.pop("RB_ALLOW_LIVE")
    else:
        environ["RB_ALLOW_LIVE"] = allow_live
    monkeypatch.setattr(
        ci,
        "execute_native_model_ci",
        lambda *a, **k: pytest.fail("provider execution without opt-in"),
    )
    with pytest.raises(actions.WorkflowError, match="explicit allow_live"):
        actions.native_model_run(environ)
    with pytest.raises(actions.WorkflowError, match="explicit allow_live"):
        actions.native_model_compare(environ)


def test_paid_fork_rejected_before_provider_inputs_and_keys(model_environment, monkeypatch):
    event_path = Path(model_environment["GITHUB_EVENT_PATH"])
    event = json.loads(event_path.read_text())
    event["pull_request"]["head"]["repo"]["full_name"] = "fork/repo"
    event_path.write_text(json.dumps(event))
    monkeypatch.setattr(actions, "_native_model_inputs", lambda *a: pytest.fail("fork inputs read"))
    for operation in (actions.native_model_run, actions.native_model_compare):
        with pytest.raises(actions.WorkflowError, match="disabled for fork"):
            operation(NoSecretReads(model_environment))


@pytest.mark.parametrize(
    "field,value",
    (
        ("RB_PROFILE", "repository-adapter"),
        ("RB_PROFILE", "legacy"),
        ("RB_MODE", "calibration"),
        ("RB_ADAPTER", "adapter.json"),
        ("RB_ADAPTER_PATH", "adapter.json"),
        ("RB_POLICY", "policy.json"),
        ("RB_POLICY_PATH", "policy.json"),
        ("RB_COMMAND", "caller-program"),
        ("RB_OPENCODE_AUTH", "credential.json"),
        ("RB_APP_ID", "123"),
        ("RB_INSTALLATION_ID", "456"),
        ("RB_PUBLISH_COMMENT", "true"),
    ),
)
def test_native_model_options_reject_callbacks_or_app_paths_before_keys(
    model_environment, monkeypatch, field, value
):
    model_environment[field] = value
    monkeypatch.setattr(
        actions,
        "_native_model_inputs",
        lambda *a: pytest.fail("native data selected for incompatible options"),
    )
    with pytest.raises(actions.WorkflowError):
        actions.native_model_run(NoSecretReads(model_environment))


@pytest.mark.parametrize("profile", ("repository-model", "boundary-model"))
def test_native_execution_uses_approved_data_and_never_general_or_adapter_dispatch(
    model_environment, tmp_path, monkeypatch, profile
):
    model_environment.update(
        RB_PROFILE=profile, RB_PROMPT_PRICE_CAP="1.5", RB_COMPLETION_PRICE_CAP="2.5"
    )
    calls = []

    def execute(baseline, output, **options):
        calls.append((baseline, output, options))
        return 0

    monkeypatch.setattr(ci, "execute_native_model_ci", execute)
    monkeypatch.setattr(ci, "execute_adapter_ci", lambda *a, **k: pytest.fail("adapter dispatched"))
    monkeypatch.setattr(ci, "run_ci", lambda *a, **k: pytest.fail("general CI dispatched"))
    assert actions.native_model_run(NoSecretReads(model_environment)) == 0
    baseline, output, options = calls.pop()
    assert baseline == tmp_path / "baseline-source/baseline.json"
    assert options["suite_path"] == tmp_path / "baseline-source/suite.json"
    assert options["pricing_file"] == tmp_path / "baseline-source/pricing.json"
    assert output == tmp_path / "native-model-results"
    assert options["mode"] == "model" and options["provider"] == "openai"
    assert options["model"] == "candidate-model" and options["budget"] == 3
    assert options["prompt_price_cap"] == 1.5 and options["completion_price_cap"] == 2.5
    assert options["profile"] == profile
    assert not {"adapter_path", "policy", "command", "opencode_auth"} & options.keys()


def test_native_operations_require_the_trusted_harness_cwd(
    model_environment, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path / "baseline-source")
    monkeypatch.setattr(
        ci, "execute_native_model_ci", lambda *a, **k: pytest.fail("caller project selected")
    )
    with pytest.raises(actions.WorkflowError, match="trusted harness directory"):
        actions.native_model_run(model_environment)


@pytest.mark.parametrize("field", ("RB_BASELINE", "RB_SUITE", "RB_PRICING_FILE"))
@pytest.mark.parametrize("path", ("../outside.json", "/tmp/outside.json", "link.json"))
def test_native_data_paths_cannot_escape_the_trusted_base_checkout(
    model_environment, tmp_path, monkeypatch, field, path
):
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (tmp_path / "baseline-source/link.json").symlink_to(outside)
    model_environment[field] = path
    monkeypatch.setattr(
        ci, "execute_native_model_ci", lambda *a, **k: pytest.fail("unsafe data selected")
    )
    with pytest.raises((ValueError, OSError)):
        actions.native_model_run(model_environment)


@pytest.mark.parametrize("code,expected", (("0", 0), ("1", 2), ("2", 2), ("", 2), ("bogus", 2)))
def test_native_fresh_comparison_is_data_only_and_preserves_outer_failure(
    model_environment, tmp_path, monkeypatch, code, expected
):
    model_environment.update(
        RB_EVALUATION_EXIT=code, RB_PRICING_FILE="../not-read-by-comparison.json"
    )
    calls = []

    def compare(baseline, candidate, output, **options):
        calls.append((baseline, candidate, output, options))
        return options["evaluation_code"]

    monkeypatch.setattr(ci, "compare_native_ci", compare)
    monkeypatch.setattr(
        ci,
        "execute_native_model_ci",
        lambda *a, **k: pytest.fail("provider dispatched from comparison"),
    )
    assert actions.native_model_compare(NoSecretReads(model_environment)) == expected
    baseline, candidate, output, options = calls.pop()
    assert baseline == tmp_path / "baseline-source/baseline.json"
    assert candidate == tmp_path / "native-model-artifact/report.json"
    assert output == tmp_path / "reviewboundary-results"
    assert not {"model", "provider", "pricing_file", "adapter_path"} & options.keys()


@pytest.mark.parametrize("code", (0, 1, 2))
def test_native_model_comparison_entrypoint_preserves_gate_outputs(
    model_environment, tmp_path, monkeypatch, code
):
    for key, value in model_environment.items():
        monkeypatch.setenv(key, value)

    def compare(_):
        output = tmp_path / "reviewboundary-results"
        output.mkdir()
        if code != 2:
            (output / "comparison.json").write_text("{}")
        return code

    monkeypatch.setattr(actions, "native_model_compare", compare)
    assert actions.main(["native-model-compare"]) == code
    outputs = (tmp_path / "step-output").read_text()
    assert f"exit_code={code}\n" in outputs
    assert f"comparison_ready={str(code != 2).lower()}\n" in outputs


@pytest.mark.parametrize("operation", ("native-model-run", "native-model-compare"))
def test_native_entrypoint_failure_redacts_payloads_and_never_publishes(
    model_environment, tmp_path, monkeypatch, capsys, operation
):
    for key, value in model_environment.items():
        monkeypatch.setenv(key, value)

    def fail(_):
        raise RuntimeError("synthetic-secret-private-provider-response")

    monkeypatch.setattr(actions, operation.replace("-", "_"), fail)
    monkeypatch.setattr(actions, "publish", lambda *a: pytest.fail("App publication"))
    assert actions.main([operation]) == 2
    assert "synthetic-secret" not in capsys.readouterr().err
    outputs = (tmp_path / "step-output").read_text()
    assert (
        "evaluation_exit=2" if operation.endswith("run") else "comparison_ready=false"
    ) in outputs


def test_native_app_publication_stays_unsupported_before_key_access(model_environment, monkeypatch):
    monkeypatch.setattr(cli, "main", lambda *a: pytest.fail("App publication"))
    with pytest.raises(actions.WorkflowError, match="publication is not supported"):
        actions.publish(NoSecretReads(model_environment))


def workflow():
    return yaml.load(
        (ROOT / ".github/workflows/evaluate-native-model.yml").read_text(), Loader=yaml.BaseLoader
    )


def using(job, action):
    return [step for step in job["steps"] if step.get("uses", "").startswith(action + "@")]


def test_native_workflow_defaults_to_no_live_calls_and_has_no_adapter_or_app_inputs():
    value = workflow()
    call = value["on"]["workflow_call"]
    assert call["inputs"]["allow_live"]["default"] == "false"
    assert call["inputs"]["budget"]["default"] == "20"
    assert set(call["secrets"]) == {"OPENROUTER_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}
    assert all(secret["required"] == "false" for secret in call["secrets"].values())
    assert (
        not {"adapter", "policy", "command", "source", "app_id", "publish_comment"}
        & call["inputs"].keys()
    )
    assert set(value["jobs"]) == {"evaluate", "compare"}
    assert value["jobs"]["evaluate"]["if"] == "inputs.allow_live"
    assert "inputs.allow_live" in value["jobs"]["compare"]["if"]
    assert "secrets." not in str(value.get("env", {}))


def test_native_provider_secrets_exist_only_on_selected_provider_execution_step():
    jobs = workflow()["jobs"]
    evaluate = jobs["evaluate"]
    secret_steps = [step for step in evaluate["steps"] if "secrets." in str(step)]
    assert len(secret_steps) == 1
    (execute,) = secret_steps
    assert execute["run"].endswith("actions native-model-run")
    assert execute["working-directory"] == "harness"
    for provider, name in (
        ("openrouter", "OPENROUTER_API_KEY"),
        ("openai", "OPENAI_API_KEY"),
        ("anthropic", "ANTHROPIC_API_KEY"),
    ):
        assert (
            execute["env"][name]
            == "${{ inputs.allow_live && inputs.provider == '"
            + provider
            + "' && secrets."
            + name
            + " || '' }}"
        )
    for operation in ("actions.py check", "actions native-model-check"):
        check = next(step for step in evaluate["steps"] if step.get("run", "").endswith(operation))
        assert evaluate["steps"].index(check) < evaluate["steps"].index(execute)
    assert "secrets." not in str(jobs["compare"])
    assert "APP_PRIVATE_KEY" not in str(jobs)
    assert "adapter-source" not in str(jobs)


def test_native_workflow_pins_trusted_code_base_data_and_all_action_revisions():
    for job in workflow()["jobs"].values():
        assert job["runs-on"] == "ubuntu-latest"
        assert job["permissions"] == {"contents": "read"}
        assert "environment" not in job and "secrets" not in job
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", step["uses"])
            assert "${{ inputs." not in step.get("run", "")
            if step.get("run", "").startswith("uv "):
                assert step["working-directory"] == "harness"
            assert "--project" not in step.get("run", "")
        checkouts = using(job, "actions/checkout")
        assert len(checkouts) == 2
        for checkout in checkouts:
            assert checkout["with"]["persist-credentials"] == "false"
            if checkout["with"]["path"] == "harness":
                assert checkout["with"]["repository"] == "${{ job.workflow_repository }}"
                assert checkout["with"]["ref"] == "${{ job.workflow_sha }}"
            else:
                assert checkout["with"]["path"] == "baseline-source"
                assert (
                    checkout["with"]["ref"]
                    == "${{ github.event.pull_request.base.sha || github.sha }}"
                )
                assert checkout["if"] == "inputs.baseline_source == 'caller'"
        assert all(
            step["with"]["enable-cache"] == "false" for step in using(job, "astral-sh/setup-uv")
        )
        assert not using(job, "actions/cache")


def test_native_report_artifacts_are_allowlisted_and_fresh_compare_uses_exact_id():
    jobs = workflow()["jobs"]
    evaluate, compare = jobs["evaluate"], jobs["compare"]
    assert (
        using(evaluate, "actions/upload-artifact")[0]["with"]["path"]
        == "native-model-results/candidate/report.json"
    )
    (download,) = using(compare, "actions/download-artifact")
    assert download["with"]["artifact-ids"] == "${{ needs.evaluate.outputs.artifact_id }}"
    assert "name" not in download["with"]
    assert download["with"]["path"] == "native-model-artifact"
    (upload,) = using(compare, "actions/upload-artifact")
    assert set(upload["with"]["path"].split()) == {
        "native-model-artifact/report.json",
        "reviewboundary-results/summary.md",
        "reviewboundary-results/ci-result.json",
        "reviewboundary-results/comparison.json",
    }
    assert all(
        "*" not in step["with"]["path"]
        for job in jobs.values()
        for step in using(job, "actions/upload-artifact")
    )
    run = next(step for step in compare["steps"] if step.get("id") == "run")
    assert run["run"].endswith("actions native-model-compare")
    assert run["env"]["RB_EVALUATION_EXIT"] == "${{ needs.evaluate.outputs.evaluation_exit }}"
    assert "steps.artifacts.outcome == 'success'" in compare["outputs"]["comparison_ready"]
    for job in jobs.values():
        assert job["steps"][-1]["if"] == "always()"
        assert "else 2" in job["steps"][-1]["run"]


def test_existing_test_workflow_runs_every_browser_suite_without_live_providers():
    value = yaml.load((ROOT / ".github/workflows/test.yml").read_text(), Loader=yaml.BaseLoader)
    browser = next(
        step
        for step in value["jobs"]["test"]["steps"]
        if step.get("name") == "Check browser data handling"
    )
    assert browser["run"] == "node --test tests/web/*.test.cjs"
    assert {path.name for path in (ROOT / "tests/web").glob("*.test.cjs")} == {
        "adjudication.test.cjs",
        "dashboard.test.cjs",
        "native-dashboard.test.cjs",
        "payload-report.test.cjs",
        "report-contracts.test.cjs",
    }
    assert "evaluate-native-model.yml" not in str(value)
