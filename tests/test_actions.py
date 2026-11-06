"""Exercise workflow context, data-only input, and credential separation boundaries."""

import json
from pathlib import Path

import pytest

from review_boundary import actions, ci, cli


@pytest.fixture
def environ(tmp_path):
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "number": 7,
                "pull_request": {
                    "base": {"repo": {"full_name": "owner/repo"}},
                    "head": {"repo": {"full_name": "owner/repo"}, "sha": "a" * 40},
                },
            }
        )
    )
    return {
        "RB_SERVER_URL": "https://github.com",
        "RB_EVENT": "pull_request",
        "RB_REPOSITORY": "owner/repo",
        "RB_MODE": "calibration",
        "RB_PROVIDER": "openrouter",
        "RB_BASELINE_SOURCE": "harness",
        "RB_BASELINE": "baseline.json",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_WORKSPACE": str(tmp_path),
        "GITHUB_OUTPUT": str(tmp_path / "step-output"),
    }


def make_fork(environ):
    event_path = Path(environ["GITHUB_EVENT_PATH"])
    event = json.loads(event_path.read_text())
    event["pull_request"]["head"]["repo"]["full_name"] = "contributor/repo"
    event_path.write_text(json.dumps(event))


def test_fork_can_run_free_calibration_but_cannot_use_paid_provider(environ):
    make_fork(environ)
    assert actions.context(environ)["fork"] is True
    environ["RB_MODE"] = "model"
    with pytest.raises(actions.WorkflowError, match="disabled for fork"):
        actions.context(environ)


@pytest.mark.parametrize(
    "field,value",
    [
        ("RB_SERVER_URL", "https://other.example"),
        ("RB_EVENT", "pull_request_target"),
        ("RB_EVENT", "workflow_run"),
        ("RB_EVENT", "issue_comment"),
        ("RB_MODE", "adapter"),
        ("RB_PROVIDER", "unknown"),
        ("RB_REPOSITORY", "../../etc/passwd"),
        ("RB_BASELINE_SOURCE", "pr-head"),
    ],
)
def test_unsupported_context_is_rejected(environ, field, value):
    environ[field] = value
    with pytest.raises(actions.WorkflowError):
        actions.context(environ)


def test_invalid_event_fails_without_echoing_payload(environ):
    Path(environ["GITHUB_EVENT_PATH"]).write_text("private-payload")
    with pytest.raises(actions.WorkflowError, match="context is invalid") as caught:
        actions.context(environ)
    assert "private-payload" not in str(caught.value)


def test_evaluation_reads_only_selected_repository_data(environ, monkeypatch, tmp_path):
    root = tmp_path / "baseline-source"
    root.mkdir()
    (root / "baseline.json").write_text("{}")
    (root / "pricing.json").write_text("{}")
    environ.update(
        RB_BASELINE_SOURCE="caller",
        RB_PRICING_FILE="pricing.json",
        RB_BUDGET="3",
        RB_MODE="model",
        RB_MODEL="test-model",
        RB_PROVIDER="openai",
    )
    calls = []

    def run(baseline, output, **kwargs):
        calls.append((baseline, output, kwargs))
        return 1

    monkeypatch.setattr(ci, "run_ci", run)
    assert actions.evaluate(environ) == 1
    baseline, output, options = calls.pop()
    assert baseline == root / "baseline.json"
    assert output == tmp_path / "reviewboundary-results"
    assert options["pricing_file"] == root / "pricing.json"
    assert options["model"] == "test-model"
    assert options["budget"] == 3


@pytest.mark.parametrize("path", ["../outside.json", "/tmp/outside.json", "link.json"])
def test_data_escape_is_rejected_before_evaluation(environ, monkeypatch, tmp_path, path):
    root = tmp_path / "harness"
    root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    (root / "link.json").symlink_to(outside)
    environ["RB_BASELINE"] = path
    monkeypatch.setattr(ci, "run_ci", lambda *args, **kwargs: pytest.fail("evaluation started"))
    with pytest.raises((ValueError, OSError)):
        actions.evaluate(environ)


def test_publisher_uses_event_head_and_removes_private_key(environ, monkeypatch):
    environ.update(RB_APP_ID="123", RB_INSTALLATION_ID="456", RB_APP_PRIVATE_KEY="test-pem")
    temporary_paths = []

    def publish(argv):
        assert argv[0] == "github-publish"
        options = dict(zip(argv[1::2], argv[2::2], strict=True))
        assert options["--repository"] == "owner/repo"
        assert options["--pull-number"] == "7"
        assert options["--expected-head"] == "a" * 40
        config_file = Path(options["--config"])
        config = json.loads(config_file.read_text())
        assert config["allowed_repositories"] == ["owner/repo"]
        assert config["app_id"] == 123
        private_key = Path(config["private_key_path"])
        assert private_key.stat().st_mode & 0o777 == 0o600
        assert private_key.read_text() == "test-pem"
        temporary_paths.extend([config_file, private_key])
        return 0

    monkeypatch.setattr(cli, "main", publish)
    assert actions.publish(environ) == 0
    assert temporary_paths and all(not path.exists() for path in temporary_paths)


def test_fork_publisher_never_reads_app_key_or_calls_github(environ, monkeypatch):
    make_fork(environ)
    monkeypatch.setattr(cli, "main", lambda *args: pytest.fail("publisher was invoked"))
    with pytest.raises(actions.WorkflowError, match="same repository"):
        actions.publish(environ)


@pytest.mark.parametrize("result", [0, 1, 2])
def test_workflow_preserves_gate_status(environ, monkeypatch, tmp_path, result):
    for key, value in environ.items():
        monkeypatch.setenv(key, value)

    def evaluate(_):
        output = tmp_path / "reviewboundary-results"
        output.mkdir()
        if result != 2:
            (output / "comparison.json").write_text("{}")
        return result

    monkeypatch.setattr(actions, "evaluate", evaluate)
    assert actions.main(["evaluate"]) == result
    outputs = Path(environ["GITHUB_OUTPUT"]).read_text()
    assert f"exit_code={result}\n" in outputs
    assert f"comparison_ready={str(result != 2).lower()}\n" in outputs


def test_failed_workflow_does_not_publish_or_echo_exception(environ, monkeypatch, capsys):
    for key, value in environ.items():
        monkeypatch.setenv(key, value)

    def fail(_):
        raise RuntimeError("synthetic-secret-in-provider-response")

    monkeypatch.setattr(actions, "evaluate", fail)
    assert actions.main(["evaluate"]) == 2
    assert "synthetic-secret" not in capsys.readouterr().err
    assert "comparison_ready=false" in Path(environ["GITHUB_OUTPUT"]).read_text()
    result = Path(environ["GITHUB_WORKSPACE"]) / "reviewboundary-results/ci-result.json"
    assert json.loads(result.read_text())["exit_code"] == 2
