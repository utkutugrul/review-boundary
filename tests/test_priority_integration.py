"""Independent integration audit tests for provenance, adapter and CLI transport paths.

Only trusted synthetic local reviewer scripts are executed. No network or model access.
"""

import asyncio
import json
import os
import sys

import pytest

from review_boundary import adapter as adapter_module
from review_boundary.adapter import (
    AdapterConfig,
    AdapterProfile,
    AdapterRequest,
    RepositoryAdapterRequest,
    run_adapter,
)
from review_boundary.cli import main
from review_boundary.provenance import compare_provenance, experiment_provenance

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Adapter process groups require POSIX")

PRELUDE = """
import json, sys
start = json.loads(sys.stdin.readline())
n = 0
def call(tool, arguments=None):
    global n
    n += 1
    print(json.dumps({'type': 'call', 'id': str(n), 'tool': tool,
                      'arguments': arguments or {}}), flush=True)
    return json.loads(sys.stdin.readline())
def correct_run():
    assert call('read_pr')['ok']
    assert call('read_file', {'path': 'README.md'})['ok']
    assert call('read_file', {'path': start['source_path']})['ok']
    assert call('submit_review', {'verdict': 'approve', 'findings': []})['ok']
"""


def make_adapter(tmp_path, body, name="audit-reviewer"):
    script = tmp_path / "reviewer.py"
    script.write_text(PRELUDE + body)
    config = tmp_path / "adapter.json"
    config.write_text(
        json.dumps(
            {
                "name": name,
                "command": [sys.executable, "{config_dir}/reviewer.py"],
                "source_files": ["reviewer.py"],
            }
        )
    )
    return config


def run_cli(tmp_path, config, *extra):
    output = tmp_path / "out"
    status = main(
        [
            "run-adapter",
            "--adapter",
            str(config),
            "--family",
            "tenant_lookup",
            "--surface",
            "clean",
            "--epochs",
            "1",
            "--output",
            str(output),
            *extra,
        ]
    )
    return status, output


def events(output):
    path = output / "events.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


REWRITE = """
import pathlib
correct_run()
assert json.loads(sys.stdin.readline())['type'] == 'stop'
pathlib.Path(sys.argv[0]).write_text('# rewritten during invocation\\n')
"""


def test_rewriting_declared_source_mid_invocation_cannot_pass_and_keeps_evidence(tmp_path):
    config = make_adapter(tmp_path, REWRITE)
    status, output = run_cli(tmp_path, config)
    rows = events(output)
    assert status == 2
    assert len(rows) == 1, "the offending invocation's row must be recorded before aborting"
    row = rows[0]
    assert row["stop_reason"] == "reviewer_source_changed"
    assert not (row["passed"] or row["completed"] or row["conclusive"] or row["review_correct"])
    assert "changed" in row["error"]
    # Observed tool evidence and the transport outcome survive the invalidation.
    assert row["adapter"]["status"] == "completed" and row["adapter"]["calls"] == 4
    assert row["review"] is not None and row["events"]
    assert (output / "report.json").is_file()
    manifest = json.loads((output / "manifest.json").read_text())
    assert not manifest.get("run_finished")


def test_deleting_declared_source_mid_invocation_still_records_the_row(tmp_path):
    body = """
import os
correct_run()
assert json.loads(sys.stdin.readline())['type'] == 'stop'
os.unlink(sys.argv[0])
"""
    config = make_adapter(tmp_path, body)
    status, output = run_cli(tmp_path, config)
    rows = events(output)
    assert status == 2
    # Expected: the failed invocation is recorded as an invalid sample. A bare
    # ProvenanceError at the post-run fingerprint (cli.py line 237) loses all evidence.
    assert len(rows) == 1, "deleted source must not discard the invocation's observed evidence"
    assert not rows[0]["passed"]


def test_replacing_declared_source_with_symlink_mid_invocation_still_records_the_row(tmp_path):
    body = """
import os
correct_run()
assert json.loads(sys.stdin.readline())['type'] == 'stop'
target = sys.argv[0] + '.real'
os.rename(sys.argv[0], target)
os.symlink(target, sys.argv[0])
"""
    config = make_adapter(tmp_path, body)
    status, output = run_cli(tmp_path, config)
    rows = events(output)
    assert status == 2
    assert len(rows) == 1 and not rows[0]["passed"]


def test_source_rewrite_after_adapter_error_keeps_both_error_codes(tmp_path):
    body = """
import pathlib
correct_run()
assert json.loads(sys.stdin.readline())['type'] == 'stop'
pathlib.Path(sys.argv[0]).write_text('# changed\\n')
sys.exit(3)
"""
    config = make_adapter(tmp_path, body)
    status, output = run_cli(tmp_path, config)
    rows = events(output)
    assert status == 2 and len(rows) == 1
    assert rows[0]["adapter"]["error_code"] == "process_exit"
    assert rows[0]["stop_reason"] == "reviewer_source_changed"
    assert not rows[0]["passed"]


def test_repeated_invocations_share_one_source_fingerprint_and_distinct_ids(tmp_path):
    config = make_adapter(tmp_path, "correct_run()\nassert json.loads(sys.stdin.readline())\n")
    status, output = run_cli(tmp_path, config, "--epochs", "2")
    rows = events(output)
    assert status == 0 and len(rows) == 4  # clean surface: vulnerable and fixed, two epochs
    assert len({row["adapter"]["invocation_id"] for row in rows}) == 4
    assert sorted({row["epoch"] for row in rows}) == [1, 2]
    manifest = json.loads((output / "manifest.json").read_text())
    reviewer = manifest["provenance"]["reviewer_source"]
    assert reviewer["status"] == "recorded" and list(reviewer["files"]) == ["reviewer.py"]
    assert manifest["provenance"]["tools"]["protocol"] == adapter_module.PROTOCOL
    # Fingerprints are informational and must never leak host paths or source text.
    assert str(tmp_path) not in json.dumps(manifest["provenance"])


@pytest.mark.parametrize(
    ("tail", "code"),
    [
        ('print(\'{"type": "done"}\', flush=True)\n', "output_after_finish"),
        ("sys.stderr.write('x' * 5000); sys.stderr.flush()\n", "stderr_limit"),
        ("sys.exit(9)\n", "process_exit"),
    ],
)
def test_failures_after_submission_never_pass_but_keep_the_submitted_review(tmp_path, tail, code):
    body = "correct_run()\nassert json.loads(sys.stdin.readline())['type'] == 'stop'\n" + tail
    script = tmp_path / "reviewer.py"
    script.write_text(PRELUDE + body)
    config = tmp_path / "adapter.json"
    config.write_text(
        json.dumps(
            {
                "name": "late-failure",
                "command": [sys.executable, str(script)],
                "limits": {"max_stderr_bytes": 1024},
            }
        )
    )
    status, output = run_cli(tmp_path, config)
    rows = events(output)
    assert status == 2 and len(rows) == 2
    for row in rows:
        assert row["adapter"]["error_code"] == code
        assert row["review"] is not None
        assert not (row["passed"] or row["completed"] or row["conclusive"] or row["review_correct"])
        assert row["error"]


def test_non_json_reply_after_submission_is_not_a_clean_completion(tmp_path):
    # The stop message is consumed, then the reviewer closes stdout normally but exits nonzero
    # after writing a partial line; a partial line must be an error, not an exit.
    body = (
        "correct_run()\nassert json.loads(sys.stdin.readline())['type'] == 'stop'\n"
        'sys.stdout.write(\'{"type": "done"\'); sys.stdout.flush()\n'
    )
    script = tmp_path / "reviewer.py"
    script.write_text(PRELUDE + body)
    config = AdapterConfig.model_validate(
        {"name": "partial", "command": [sys.executable, str(script)]}
    )

    async def dispatch(name, arguments):
        return "ok"

    result = asyncio.run(
        run_adapter(config, AdapterRequest("Review", "Review", "src/service.py"), dispatch)
    )
    assert result.status == "error"


# ---- tool-profile boundary ----


def repo_profile():
    return AdapterProfile(
        "reviewboundary.repository.test/1",
        [{"name": "list_files", "description": "x", "parameters": {"type": "object"}}],
        lambda name, args: args,
    )


def test_repository_request_requires_an_explicit_profile():
    config = AdapterConfig.model_validate({"name": "r", "command": [sys.executable, "-c", "0"]})

    async def dispatch(name, arguments):
        raise AssertionError("must not dispatch")

    with pytest.raises(ValueError):
        asyncio.run(run_adapter(config, RepositoryAdapterRequest("Review", "Review"), dispatch))


def test_profile_tools_bound_the_callable_surface_and_start_has_no_source_path(tmp_path):
    body = """
assert 'source_path' not in start, start.keys()
assert [t['name'] for t in start['tools']] == ['list_files']
assert start['protocol'] == 'reviewboundary.repository.test/1'
reply = call('read_file', {'path': 'README.md'})
"""
    script = tmp_path / "reviewer.py"
    script.write_text(PRELUDE + body)
    config = AdapterConfig.model_validate({"name": "p", "command": [sys.executable, str(script)]})
    seen = []

    async def dispatch(name, arguments):
        seen.append(name)
        return "never"

    result = asyncio.run(
        run_adapter(
            config, RepositoryAdapterRequest("Review", "Review"), dispatch, profile=repo_profile()
        )
    )
    # A legacy tool outside the repository profile is rejected before dispatch.
    assert result.status == "error" and result.error_code == "unknown_tool"
    assert seen == []


def test_repository_tool_is_unavailable_under_the_legacy_profile(tmp_path):
    body = "call('list_files', {})\n"
    script = tmp_path / "reviewer.py"
    script.write_text(PRELUDE + body)
    config = AdapterConfig.model_validate({"name": "p", "command": [sys.executable, str(script)]})
    seen = []

    async def dispatch(name, arguments):
        seen.append(name)

    result = asyncio.run(
        run_adapter(config, AdapterRequest("Review", "Review", "src/service.py"), dispatch)
    )
    assert result.error_code == "unknown_tool" and seen == []


def test_profile_write_requests_are_counted_even_when_arguments_are_invalid(tmp_path):
    body = """
call('write_file', {'path': 'x', 'content': 1})
call('write_file', {'path': 'x', 'content': 'ok'})
"""
    script = tmp_path / "reviewer.py"
    script.write_text(PRELUDE + body)
    config = AdapterConfig.model_validate({"name": "p", "command": [sys.executable, str(script)]})
    profile = AdapterProfile(
        "p/1",
        [{"name": "write_file", "description": "w", "parameters": {"type": "object"}}],
        lambda name, args: (
            (_ for _ in ()).throw(ValueError("bad")) if args["content"] == 1 else args
        ),
    )

    async def dispatch(name, arguments):
        return {"blocked": True}

    result = asyncio.run(
        run_adapter(config, RepositoryAdapterRequest("Review", "Review"), dispatch, profile=profile)
    )
    assert result.write_requests == 2 and result.status == "incomplete"


# ---- provenance comparability ----


def test_prompt_change_is_reported_without_gating_or_unrelated_changes():
    tools = [{"name": "t"}]
    base = {
        "provenance": experiment_provenance(
            {"baseline": "one"}, tools, protocol="p", harness_files=()
        )
    }
    cand = {
        "provenance": experiment_provenance(
            {"baseline": "two"}, tools, protocol="p", harness_files=()
        )
    }
    result = compare_provenance(base, cand, "baseline", "baseline")
    assert result["gating"] is False
    assert [c["field"] for c in result["changes"]] == ["instructions"]
    legacy = compare_provenance({}, cand, "baseline", "baseline")
    assert legacy["status"] == "unknown" and "instructions" in legacy["unknown_fields"]
