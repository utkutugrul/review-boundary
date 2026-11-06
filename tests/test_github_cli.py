import argparse
import json
from pathlib import Path

import pytest

from review_boundary.github_app import GitHubPublishError, PublishResult
from review_boundary.github_cli import MAX_CONFIG_BYTES, add_commands, handle_command

SHA = "a" * 40
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_real_publication(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Tests must not call the real GitHub publisher")

    monkeypatch.setattr("review_boundary.github_cli.publish_pr_result", forbidden)


@pytest.fixture
def paths(tmp_path):
    comparison = tmp_path / "comparison.json"
    comparison.write_bytes(
        (ROOT / "examples/comparisons/calibration-negative-control.json").read_bytes()
    )
    config = tmp_path / "app.json"
    config.write_text(
        json.dumps(
            {
                "app_id": 123,
                "installation_id": 456,
                "private_key_path": str(tmp_path / "not-read-by-preview.pem"),
                "allowed_repositories": ["owner/repo"],
            }
        )
    )
    return comparison, config


def run(command, comparison, *extra):
    parser = argparse.ArgumentParser()
    add_commands(parser.add_subparsers(dest="command", required=True))
    arguments = [
        command,
        "--repository",
        "owner/repo",
        "--pull-number",
        "12",
        "--expected-head",
        SHA,
        "--comparison",
        str(comparison),
        *map(str, extra),
    ]
    return handle_command(parser.parse_args(arguments))


def test_preview_prints_exact_commit_summary_without_credentials(paths, capsys):
    comparison, _ = paths
    assert run("github-preview", comparison, "--app-id", 123) == 0
    output = capsys.readouterr()
    assert f"PR head associated with this result: `{SHA}`" in output.out
    assert "It does not evaluate the pull request's code." in output.out
    assert "reviewboundary:app:123:pr:12:v1" in output.out
    assert "REGRESSIONS FOUND" in output.out and output.err == ""


def test_preview_writes_new_output_and_preserves_existing_file(paths, tmp_path, capsys):
    comparison, _ = paths
    output = tmp_path / "nested/preview.md"
    assert run("github-preview", comparison, "--app-id", 123, "--output", output) == 0
    original = output.read_text()
    assert SHA in original and "ReviewBoundary" in original
    assert run("github-preview", comparison, "--app-id", 123, "--output", output) == 2
    assert output.read_text() == original
    assert "existing files are preserved" in capsys.readouterr().err


def test_publish_requires_explicit_config_and_passes_only_validated_inputs(
    paths, monkeypatch, capsys
):
    comparison, config = paths
    seen = []

    def fake_publish(config, request):
        seen.append((config, request))
        return PublishResult(
            "created", 88, SHA, "https://github.com/owner/repo/pull/12#issuecomment-88", True
        )

    monkeypatch.setattr("review_boundary.github_cli.publish_pr_result", fake_publish)
    assert run("github-publish", comparison, "--config", config) == 0
    config_object, request = seen[0]
    assert config_object.app_id == 123 and config_object.installation_id == 456
    assert config_object.allowed_repositories == ("owner/repo",)
    assert (
        request.repository == "owner/repo"
        and request.pull_number == 12
        and request.expected_head_sha == SHA
    )
    output = json.loads(capsys.readouterr().out)
    assert output["action"] == "created" and output["token_revoked"] is True


@pytest.mark.parametrize("code", ["stale_head", "head_changed_after_publish", "github_http_403"])
def test_publisher_failures_return_two_and_preserve_safe_error_distinction(
    paths, monkeypatch, capsys, code
):
    comparison, config = paths

    def fake_publish(*args):
        raise GitHubPublishError(
            code, "A commit-specific comment may already exist; inspect the PR."
        )

    monkeypatch.setattr("review_boundary.github_cli.publish_pr_result", fake_publish)
    assert run("github-publish", comparison, "--config", config) == 2
    output = capsys.readouterr()
    assert output.out == "" and code in output.err and "may already exist" in output.err


def test_wrong_repository_is_rejected_before_publication(paths, capsys):
    comparison, config = paths
    data = json.loads(config.read_text())
    data["allowed_repositories"] = ["other/repo"]
    config.write_text(json.dumps(data))
    assert run("github-publish", comparison, "--config", config) == 2
    assert "repository_not_allowed" in capsys.readouterr().err


@pytest.mark.parametrize(
    "text",
    [
        '{"app_id":123,"app_id":456}',
        '{"app_id":NaN}',
        "[]",
        '{"raw_secret":"synthetic-inline-secret"}',
        "invalid synthetic-inline-secret",
    ],
)
def test_invalid_config_contents_are_never_printed(paths, text, capsys):
    comparison, config = paths
    config.write_text(text)
    assert run("github-publish", comparison, "--config", config) == 2
    output = capsys.readouterr()
    assert "synthetic-inline-secret" not in output.err + output.out
    assert "invalid_input" in output.err


@pytest.mark.parametrize(
    "update",
    [
        {"private_key_path": "relative.pem"},
        {"allowed_repositories": "owner/repo"},
        {"allowed_repositories": ["*"]},
        {"app_id": True},
        {"installation_id": -1},
    ],
)
def test_invalid_configuration_shapes_and_scopes_do_not_reach_publisher(paths, update):
    comparison, config = paths
    data = json.loads(config.read_text())
    data.update(update)
    config.write_text(json.dumps(data))
    assert run("github-publish", comparison, "--config", config) == 2


def test_config_size_is_bounded_before_parsing(paths):
    comparison, config = paths
    config.write_bytes(b"x" * (MAX_CONFIG_BYTES + 1))
    assert run("github-publish", comparison, "--config", config) == 2


@pytest.mark.parametrize(
    "text", ['{"x":1,"x":2}', '{"x":Infinity}', "[]", "private malformed data"]
)
def test_comparison_json_rejects_duplicates_nonfinite_and_malformed_content(paths, text, capsys):
    comparison, _ = paths
    comparison.write_text(text)
    assert run("github-preview", comparison, "--app-id", 123) == 2
    output = capsys.readouterr()
    assert "private malformed data" not in output.err + output.out


def test_comparison_size_missing_and_directory_inputs_are_rejected(paths, tmp_path):
    comparison, _ = paths
    comparison.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    assert run("github-preview", comparison, "--app-id", 123) == 2
    assert run("github-preview", tmp_path / "missing", "--app-id", 123) == 2
    assert run("github-preview", tmp_path, "--app-id", 123) == 2


def test_comparison_schema_validation_cannot_be_bypassed_by_preview(paths):
    comparison, _ = paths
    comparison.write_text('{"status":"pass"}')
    assert run("github-preview", comparison, "--app-id", 123) == 2


def test_input_and_output_symlinks_are_rejected(paths, tmp_path):
    comparison, config = paths
    link = tmp_path / "linked.json"
    link.symlink_to(comparison)
    assert run("github-preview", link, "--app-id", 123) == 2
    app_link = tmp_path / "app-link.json"
    app_link.symlink_to(config)
    assert run("github-publish", comparison, "--config", app_link) == 2
    output = tmp_path / "linked-output.md"
    output.symlink_to(comparison)
    original = comparison.read_bytes()
    assert run("github-preview", comparison, "--app-id", 123, "--output", output) == 2
    assert comparison.read_bytes() == original


def test_cli_parser_requires_every_publication_target_binding(paths):
    comparison, config = paths
    parser = argparse.ArgumentParser()
    add_commands(parser.add_subparsers(dest="command", required=True))
    base = [
        "github-publish",
        "--repository",
        "owner/repo",
        "--pull-number",
        "12",
        "--expected-head",
        SHA,
        "--comparison",
        str(comparison),
        "--config",
        str(config),
    ]
    for flag in ("--repository", "--pull-number", "--expected-head", "--comparison", "--config"):
        missing = list(base)
        position = missing.index(flag)
        del missing[position : position + 2]
        with pytest.raises(SystemExit) as caught:
            parser.parse_args(missing)
        assert caught.value.code == 2
