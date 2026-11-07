"""Workflow dispatch keeps caller adapters outside trusted provider and App paths."""

import json
from pathlib import Path

import pytest

from review_boundary import actions, ci, cli


@pytest.fixture
def native_environment(tmp_path, monkeypatch):
    for name in ci.ADAPTER_FORBIDDEN_ENV:
        monkeypatch.delenv(name, raising=False)
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "number": 3,
                "pull_request": {
                    "base": {"repo": {"full_name": "owner/repo"}, "sha": "b" * 40},
                    "head": {"repo": {"full_name": "owner/repo"}, "sha": "a" * 40},
                },
            }
        )
    )
    for name in ("harness", "baseline-source", "adapter-source"):
        root = tmp_path / name
        root.mkdir()
        for filename in ("baseline.json", "suite.json", "adapter.json"):
            (root / filename).write_text("{}")
    return {
        "RB_SERVER_URL": "https://github.com",
        "RB_EVENT": "pull_request",
        "RB_REPOSITORY": "owner/repo",
        "RB_PROFILE": "repository-adapter",
        "RB_BASELINE_SOURCE": "caller",
        "RB_BASELINE": "baseline.json",
        "RB_SUITE": "suite.json",
        "RB_ADAPTER": "adapter.json",
        "RB_BASELINE_REVIEWER": "reference",
        "RB_CANDIDATE_REVIEWER": "adapter/test",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "step-output"),
    }


def test_adapter_workflow_paths_separate_head_code_from_trusted_base_data(
    native_environment, tmp_path, monkeypatch
):
    calls = []

    def execute(baseline, output, **kwargs):
        calls.append((baseline, output, kwargs))
        return 0

    monkeypatch.setattr(ci, "execute_adapter_ci", execute)
    monkeypatch.setattr(ci, "run_ci", lambda *args, **kwargs: pytest.fail("provider dispatch"))
    assert actions.adapter_run(native_environment) == 0
    baseline, output, options = calls.pop()
    assert baseline == tmp_path / "baseline-source/baseline.json"
    assert options["suite_path"] == tmp_path / "baseline-source/suite.json"
    assert options["adapter_path"] == tmp_path / "adapter-source/adapter.json"
    assert output == tmp_path / "adapter-results"
    assert options["candidate_reviewer"] == "adapter/test"


@pytest.mark.parametrize("field", ("RB_BASELINE", "RB_SUITE", "RB_ADAPTER"))
@pytest.mark.parametrize("path", ("../outside.json", "/tmp/outside.json", "link.json"))
def test_adapter_data_and_configuration_paths_cannot_escape_their_selected_checkout(
    native_environment, tmp_path, monkeypatch, field, path
):
    target = tmp_path / "outside.json"
    target.write_text("{}")
    for root in ("baseline-source", "adapter-source"):
        (tmp_path / root / "link.json").symlink_to(target)
    native_environment[field] = path
    monkeypatch.setattr(ci, "execute_adapter_ci", lambda *a, **k: pytest.fail("adapter dispatched"))
    with pytest.raises((ValueError, OSError)):
        actions.adapter_run(native_environment)


@pytest.mark.parametrize("code,expected", (("0", 0), ("1", 2), ("2", 2), ("", 2), ("bogus", 2)))
def test_adapter_comparison_cannot_mask_outer_execution_failure_or_load_config(
    native_environment, tmp_path, monkeypatch, code, expected
):
    native_environment["RB_EVALUATION_EXIT"] = code
    native_environment["RB_ADAPTER"] = "../not-loaded-by-comparison.json"
    calls = []

    def compare(baseline, candidate, output, **kwargs):
        calls.append((baseline, candidate, output, kwargs))
        return kwargs["evaluation_code"]

    monkeypatch.setattr(ci, "compare_native_ci", compare)
    monkeypatch.setattr(ci, "execute_adapter_ci", lambda *a, **k: pytest.fail("adapter dispatch"))
    assert actions.adapter_compare(native_environment) == expected
    baseline, candidate, output, options = calls.pop()
    assert baseline == tmp_path / "baseline-source/baseline.json"
    assert candidate == tmp_path / "adapter-artifact/report.json"
    assert output == tmp_path / "reviewboundary-results"
    assert "adapter_path" not in options


def test_provider_evaluate_and_app_publisher_refuse_adapter_profiles_before_key_access(
    native_environment, monkeypatch
):
    class Guarded(dict):
        def get(self, name, *args):
            if name in ci.ADAPTER_FORBIDDEN_ENV:
                pytest.fail("A trusted path read a key for an adapter profile")
            return super().get(name, *args)

    environ = Guarded(native_environment)
    monkeypatch.setattr(ci, "run_ci", lambda *args, **kwargs: pytest.fail("provider dispatch"))
    monkeypatch.setattr(cli, "main", lambda *args, **kwargs: pytest.fail("App publication"))
    with pytest.raises(actions.WorkflowError, match="separate secretless"):
        actions.evaluate(environ)
    with pytest.raises(actions.WorkflowError, match="publication is not supported"):
        actions.publish(environ)


def test_paid_fork_rejection_precedes_any_key_or_adapter_access(native_environment, monkeypatch):
    event_path = Path(native_environment["GITHUB_EVENT_PATH"])
    event = json.loads(event_path.read_text())
    event["pull_request"]["head"]["repo"]["full_name"] = "fork/repo"
    event_path.write_text(json.dumps(event))
    native_environment.update(RB_MODE="model", RB_MODEL="paid-model")
    monkeypatch.setattr(ci, "adapter_environment", lambda *a: pytest.fail("keys inspected"))
    monkeypatch.setattr(ci, "run_ci", lambda *a, **k: pytest.fail("provider invoked"))
    monkeypatch.setattr(ci, "execute_adapter_ci", lambda *a, **k: pytest.fail("adapter invoked"))
    with pytest.raises(actions.WorkflowError, match="disabled for fork"):
        actions.evaluate(native_environment)
    with pytest.raises(actions.WorkflowError, match="disabled for fork"):
        actions.adapter_run(native_environment)


@pytest.mark.parametrize("name", sorted(ci.ADAPTER_FORBIDDEN_ENV))
def test_adapter_context_rejects_known_provider_and_app_credentials(native_environment, name):
    native_environment[name] = "synthetic-secret"
    with pytest.raises(ci.CIError, match="without provider or App credentials"):
        actions.adapter_context(native_environment)


@pytest.mark.parametrize(
    "field,value",
    (
        ("RB_MODE", "model"),
        ("RB_MODE", "adapter"),
        ("RB_PROFILE", "repository-model"),
        ("RB_PROFILE", "legacy"),
        ("RB_MODEL", "test-model"),
        ("RB_PRICING_FILE", "quote.json"),
        ("RB_PUBLISH_COMMENT", "true"),
    ),
)
def test_adapter_context_rejects_provider_and_publication_options(native_environment, field, value):
    native_environment[field] = value
    with pytest.raises(actions.WorkflowError):
        actions.adapter_context(native_environment)


@pytest.mark.parametrize("operation", ("adapter-run", "adapter-compare"))
def test_adapter_entrypoint_errors_are_redacted_and_never_publish(
    native_environment, tmp_path, monkeypatch, capsys, operation
):
    for key, value in native_environment.items():
        monkeypatch.setenv(key, value)

    def fail(_):
        raise ValueError("synthetic-secret @everyone private adapter payload")

    monkeypatch.setattr(actions, operation.replace("-", "_"), fail)
    monkeypatch.setattr(actions, "publish", lambda *a: pytest.fail("App publisher"))
    assert actions.main([operation]) == 2
    assert "synthetic-secret" not in capsys.readouterr().err
    outputs = (tmp_path / "step-output").read_text()
    if operation == "adapter-run":
        assert outputs == "evaluation_exit=2\n"
    else:
        assert "comparison_ready=false" in outputs and "exit_code=2" in outputs
        assert not (tmp_path / "reviewboundary-results/comparison.json").exists()
