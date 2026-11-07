import html
import json
import os
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from inspect_ai.model import ChatCompletionChoice, ChatMessageAssistant, ModelOutput, get_model
from inspect_ai.tool import ToolCall

from review_boundary import cli, repository_runner
from review_boundary.adapter import AdapterConfig, RepositoryAdapterRequest, run_adapter
from review_boundary.cli import main
from review_boundary.model_safety import ProviderRequestError
from review_boundary.providers import COMMON_OVERRIDES, OVERRIDE_VARIABLES
from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import (
    PROTOCOL,
    calibrate,
    load_suite,
    repository_profile,
    write_repository_report,
)
from review_boundary.repository_task import context as repository_context
from review_boundary.repository_world import (
    RepositoryLimits,
    RepositoryWorld,
    score_repository_world,
)

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "adapters"
REFERENCE = EXAMPLES / "repository_reference.py"
CONFIG = EXAMPLES / "repository-reference.json"
POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="Adapter process groups require POSIX")


def child_program(tmp_path, program):
    script = tmp_path / "adapter.py"
    script.write_text(program, encoding="utf-8")
    path = tmp_path / "adapter.json"
    path.write_text(
        json.dumps(
            {
                "name": "repository-test",
                "command": ["{python}", "{config_dir}/adapter.py"],
                "source_files": ["adapter.py"],
                "limits": {"idle_timeout": 5.0, "total_timeout": 15.0, "shutdown_timeout": 2.0},
            }
        )
    )
    return path


def run_cli(tmp_path, config=CONFIG, suite=None):
    output = tmp_path / "result"
    argv = ["repository-run-adapter", "--adapter", str(config), "--output", str(output)]
    if suite is not None:
        argv += ["--suite", str(suite)]
    status = main(argv)
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["run_finished"]
    assert [
        json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()
    ] == report["rows"]
    assert report["schema_version"] == 1 and report["report_kind"] == "repository"
    assert manifest["adapter"]["protocol"] == PROTOCOL
    assert manifest["os_sandboxed"] is False
    return status, report


def repository_model_argv(tmp_path, provider, *, dry_run=False):
    model = "vendor/test-model" if provider == "openrouter" else "test-model"
    argv = [
        "repository-run-model",
        "--provider",
        provider,
        "--model",
        model,
        "--epochs",
        "1",
        "--output",
        str(tmp_path / "model-result"),
        "--ledger",
        str(tmp_path / "model-budget.json"),
    ]
    if provider != "openrouter":
        pricing = tmp_path / f"{provider}-pricing.json"
        source = (
            "https://openai.com/api/pricing/"
            if provider == "openai"
            else "https://platform.claude.com/docs/en/about-claude/pricing"
        )
        pricing.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "provider": provider,
                    "source": source,
                    "as_of": "2026-01-01",
                    "models": {
                        model: {
                            "input_usd_per_million": 1,
                            "output_usd_per_million": 2,
                        }
                    },
                }
            )
        )
        argv.extend(("--pricing-file", str(pricing)))
    if dry_run:
        argv.append("--dry-run")
    return argv


def repository_success_model():
    def respond(input, tools, tool_choice, config):
        case, world = repository_context()
        events = world.events
        if not any(event["tool"] == "read_pr" for event in events):
            function, arguments = "read_pr", {}
        elif not any(event["tool"] == "list_files" for event in events):
            function, arguments = "list_files", {}
        else:
            read = {event.get("path") for event in events if event["tool"] == "read_file"}
            unread = next((item.path for item in case.files if item.path not in read), None)
            if unread:
                function, arguments = "read_file", {"path": unread, "end_line": 80}
            else:
                findings = []
                if case.variant == "vulnerable":
                    files = {item.path: item.content for item in case.files}
                    findings = [
                        {
                            "category": case.issues[0].category,
                            "summary": "The record lookup crosses the tenant boundary.",
                            "evidence": [
                                {
                                    **span.model_dump(mode="json"),
                                    "excerpt": "\n".join(
                                        files[span.path].splitlines()[
                                            span.start_line - 1 : span.end_line
                                        ]
                                    ),
                                }
                                for span in case.issues[0].acceptable_bundles[0].ranges
                            ],
                        }
                    ]
                function, arguments = (
                    "submit_review",
                    {
                        "verdict": "request_changes" if findings else "approve",
                        "findings": findings,
                    },
                )
        return ModelOutput(
            model="repository-provider-fake",
            choices=[
                ChatCompletionChoice(
                    message=ChatMessageAssistant(
                        content="",
                        tool_calls=[
                            ToolCall(
                                id=f"repository-{len(events)}",
                                function=function,
                                arguments=arguments,
                            )
                        ],
                    ),
                    stop_reason="tool_calls",
                )
            ],
        )

    model = get_model("mockllm/repository-provider-fake", custom_outputs=respond, memoize=False)
    model.api.model_name = "openai/test-model"
    model.api.qualified_model_name = "openai/test-model"
    return model


@pytest.fixture
def repository_provider_environment(monkeypatch):
    for variable in (
        *COMMON_OVERRIDES,
        *(item for names in OVERRIDE_VARIABLES.values() for item in names),
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(cli, "load_dotenv", lambda **kwargs: False)


@pytest.mark.parametrize("provider", ["openrouter", "openai", "anthropic"])
def test_repository_model_dry_run_is_keyless_and_creates_no_artifacts(
    tmp_path, monkeypatch, capsys, repository_provider_environment, provider
):
    monkeypatch.setattr(
        repository_runner,
        "model_snapshot",
        lambda model_ids, *args: [{"id": model_ids[0], "pricing": {}, "context_length": 1}],
    )
    monkeypatch.setattr(cli, "credential", lambda *args: pytest.fail("credential requested"))
    monkeypatch.setattr(repository_runner, "reserve", lambda *args: pytest.fail("budget reserved"))
    monkeypatch.setattr(
        repository_runner, "guarded_model", lambda *args: pytest.fail("model constructed")
    )
    assert main(repository_model_argv(tmp_path, provider, dry_run=True)) == 0
    metadata = json.loads(capsys.readouterr().out)
    assert metadata["provider"]["name"] == provider
    assert metadata["expected_count"] == 4
    assert metadata["run_kind"] == "model" and metadata["run_finished"] is False
    assert not (tmp_path / "model-result").exists()
    assert not (tmp_path / "model-budget.json").exists()


def test_repository_model_preserves_nonempty_output_before_provider_setup(tmp_path, monkeypatch):
    output = tmp_path / "model-result"
    output.mkdir()
    preserved = output / "keep.txt"
    preserved.write_text("preserve this result")
    monkeypatch.setattr(
        repository_runner,
        "prepare_provider",
        lambda *args, **kwargs: pytest.fail("provider setup reached"),
    )
    assert main(repository_model_argv(tmp_path, "openai")) == 2
    assert preserved.read_text() == "preserve this result"
    assert list(output.iterdir()) == [preserved]
    assert not (tmp_path / "model-budget.json").exists()


@pytest.mark.parametrize("kind", ["direct", "parent"])
def test_repository_model_rejects_symlinked_output_before_writes(tmp_path, kind):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(target, target_is_directory=True)
    output = link if kind == "direct" else link / "model-result"
    argv = [
        "repository-run-model",
        "--provider",
        "openai",
        "--model",
        "test-model",
        "--output",
        str(output),
        "--ledger",
        str(tmp_path / "model-budget.json"),
        "--dry-run",
    ]
    assert main(argv) == 2
    assert not list(target.iterdir())
    assert link.is_symlink()
    assert not (tmp_path / "model-budget.json").exists()


@pytest.mark.parametrize("collision", ["ledger", "lock", "temporary", "report"])
def test_repository_model_rejects_output_and_ledger_artifact_collisions(tmp_path, collision):
    if collision in {"ledger", "report"}:
        output = tmp_path / "model-result"
        ledger = output / ("budget.json" if collision == "ledger" else "report.json")
    else:
        ledger = tmp_path / "model-budget.json"
        output = ledger.with_suffix(".lock" if collision == "lock" else ".tmp")
    argv = [
        "repository-run-model",
        "--provider",
        "openai",
        "--model",
        "test-model",
        "--output",
        str(output),
        "--ledger",
        str(ledger),
        "--dry-run",
    ]
    assert main(argv) == 2
    assert not output.exists()
    assert not ledger.exists()
    assert not ledger.with_suffix(".lock").exists()
    assert not ledger.with_suffix(".tmp").exists()


@pytest.mark.parametrize("provider", ["openrouter", "openai", "anthropic"])
def test_repository_provider_failure_emits_generic_planned_rows(
    tmp_path, monkeypatch, repository_provider_environment, provider
):
    key = "synthetic-repository-key"
    monkeypatch.setenv(
        {
            "openrouter": "OPENROUTER_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }[provider],
        key,
    )
    monkeypatch.setattr(
        repository_runner,
        "model_snapshot",
        lambda model_ids, *args: [{"id": model_ids[0], "pricing": {}, "context_length": 1}],
    )
    monkeypatch.setattr(
        repository_runner,
        "api_get",
        lambda *args: {"data": {"limit_remaining": 100, "usage": 0}},
    )

    def fail(*args):
        raise ProviderRequestError("provider body " + key)

    monkeypatch.setattr(repository_runner, "guarded_model", fail)
    assert main(repository_model_argv(tmp_path, provider)) == 2
    output = tmp_path / "model-result"
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "manifest.json").read_text())
    assert report["summary"]["recorded"] == report["summary"]["expected"] == 4
    assert report["summary"]["errors"] == 4
    assert manifest["run_finished"] is True
    assert all(
        row["error"] == "Provider model evaluation failed; details withheld"
        for row in report["rows"]
    )
    assert all(not row["completed"] and row["semantic_passed"] is None for row in report["rows"])
    ledger = json.loads((tmp_path / "model-budget.json").read_text())
    assert len(ledger["runs"]) == 1 and "settled_usd" not in ledger["runs"][0]
    assert key not in json.dumps([report, manifest])


def test_repository_multi_model_failure_retains_complete_cost_reservation(
    tmp_path, monkeypatch, repository_provider_environment
):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-repository-key")
    argv = repository_model_argv(tmp_path, "openai")
    argv.extend(("--model", "second-model"))
    pricing_path = tmp_path / "openai-pricing.json"
    pricing = json.loads(pricing_path.read_text())
    pricing["models"]["second-model"] = {
        "input_usd_per_million": 1,
        "output_usd_per_million": 2,
    }
    pricing_path.write_text(json.dumps(pricing))

    complete_usage = SimpleNamespace(
        input_tokens=10,
        output_tokens=5,
        total_cost=0.01,
        input_tokens_cache_read=0,
        input_tokens_cache_write=0,
    )
    complete_sample = SimpleNamespace(
        error=None,
        events=[
            SimpleNamespace(
                event="model",
                call=SimpleNamespace(response={"usage": {"cost": 0.01}}),
            )
        ],
    )
    complete_log = SimpleNamespace(
        status="success",
        samples=[complete_sample],
        stats=SimpleNamespace(model_usage={"openai/test-model": complete_usage}),
    )
    calls = 0

    def evaluate(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [complete_log]
        raise ProviderRequestError("second provider execution failed")

    def extract(logs, cases, reviewers, epochs):
        assert logs == [complete_log]
        rows = repository_runner.repository_error_rows(cases, reviewers[0], epochs, "complete")
        for row in rows:
            row["error"] = None
        return rows

    monkeypatch.setattr(repository_runner, "eval", evaluate)
    monkeypatch.setattr(repository_runner, "guarded_model", lambda *args: object())
    monkeypatch.setattr(repository_runner, "repository_rows_from_logs", extract)
    monkeypatch.setattr(
        repository_runner,
        "settle",
        lambda *args: pytest.fail("failed multi-model run was settled"),
    )
    monkeypatch.setattr(
        repository_runner, "api_get", lambda *args: pytest.fail("OpenRouter account called")
    )
    monkeypatch.setattr(
        repository_runner, "model_snapshot", lambda *args: pytest.fail("catalog called")
    )

    assert main(argv) == 2
    ledger = json.loads((tmp_path / "model-budget.json").read_text())
    assert len(ledger["runs"]) == 1
    assert "settled_usd" not in ledger["runs"][0]
    assert not (tmp_path / "model-result" / "settlement.json").exists()


@pytest.mark.parametrize("reported_cost", [None, 0.00001], ids=["unknown-cost", "complete-cost"])
def test_repository_model_success_uses_native_task_and_trusted_scores(
    tmp_path, monkeypatch, repository_provider_environment, reported_cost
):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-repository-key")
    original_prepare = repository_runner.prepare_provider

    class MockPlan:
        def __init__(self, plan):
            self.plan = plan

        def __getattr__(self, name):
            return getattr(self.plan, name)

        def inspect_model_id(self, model_id):
            self.plan.inspect_model_id(model_id)
            return "mockllm/openai/test-model"

    monkeypatch.setattr(
        repository_runner,
        "prepare_provider",
        lambda *args, **kwargs: MockPlan(original_prepare(*args, **kwargs)),
    )
    monkeypatch.setattr(
        repository_runner, "api_get", lambda *args: pytest.fail("OpenRouter account called")
    )
    monkeypatch.setattr(
        repository_runner, "model_snapshot", lambda *args: pytest.fail("catalog called")
    )
    costs = []

    def successful_model(*args):
        model = repository_success_model()
        if reported_cost is not None:
            original_generate = model.api.generate

            async def generate_with_cost(*args, **kwargs):
                output, call = await original_generate(*args, **kwargs)
                call.response = {**(call.response or {}), "usage": {"cost": reported_cost}}
                costs.append(reported_cost)
                return output, call

            monkeypatch.setattr(model.api, "generate", generate_with_cost)
        return model

    monkeypatch.setattr(repository_runner, "guarded_model", successful_model)
    assert main(repository_model_argv(tmp_path, "openai")) == 0
    output = tmp_path / "model-result"
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "manifest.json").read_text())
    assert report["summary"]["recorded"] == report["summary"]["expected"] == 4
    assert report["summary"]["completed"] == report["summary"]["rubric_passed"] == 4
    assert report["summary"]["semantically_adjudicated"] == 0
    assert manifest["provider"]["name"] == "openai" and manifest["run_finished"]
    assert manifest["reviewers"] == ["mockllm/openai/test-model"]
    if reported_cost is None:
        assert manifest["usage"]["api_calls_without_reported_cost"] > 0
        assert not (output / "settlement.json").exists()
    else:
        assert costs
        usage = manifest["usage"]
        assert usage["api_calls_with_reported_cost"] == len(costs)
        assert usage["api_calls_without_reported_cost"] == 0
        assert usage["provider_reported_cost_usd"] == pytest.approx(sum(costs))
        settlement = json.loads((output / "settlement.json").read_text())
        ledger = json.loads((tmp_path / "model-budget.json").read_text())
        run = ledger["runs"][0]
        expected_proof = {
            "report_sha256": sha256((output / "report.json").read_bytes()).hexdigest(),
            "report_path": str((output / "report.json").resolve()),
        }
        assert run["id"] == manifest["run_id"]
        assert run["reserved_usd"] == manifest["planned_reservation_usd"]
        assert run["reserved_usd"] > run["settled_usd"]
        assert run["settled_usd"] == usage["provider_reported_cost_usd"]
        assert run["settlement"] == expected_proof
        assert settlement == {"settled_usd": run["settled_usd"], **expected_proof}
    assert [
        json.loads(line) for line in (output / "events.jsonl").read_text().splitlines()
    ] == report["rows"]


@POSIX_ONLY
def test_external_adapter_cannot_read_prior_evaluator_outputs_between_invocations(tmp_path):
    output = tmp_path / "result"
    observed = tmp_path / "artifact-visibility.jsonl"
    config = child_program(
        tmp_path,
        f"""
import json
from pathlib import Path
import sys
json.loads(sys.stdin.readline())
root = Path({str(output)!r})
paths = [root / name for name in (
    "suite.json", "manifest.json", "events.jsonl", "report.json", "report.html"
)]
with Path({str(observed)!r}).open("a") as stream:
    stream.write(json.dumps({{path.name: path.exists() for path in paths}}) + "\\n")
print(json.dumps({{"type": "done"}}), flush=True)
sys.stdin.readline()
""",
    )
    assert main(["repository-run-adapter", "--adapter", str(config), "--output", str(output)]) == 2
    visibility = [json.loads(line) for line in observed.read_text().splitlines()]
    assert len(visibility) == 4
    assert all(not any(invocation.values()) for invocation in visibility)
    for name in ("suite.json", "manifest.json", "events.jsonl", "report.json", "report.html"):
        assert (output / name).exists()
    assert len((output / "events.jsonl").read_text().splitlines()) == 4


@POSIX_ONLY
async def test_repository_start_envelope_omits_all_evaluator_identifiers(tmp_path):
    capture = tmp_path / "start.json"
    config = child_program(
        tmp_path,
        f"""
import json
from pathlib import Path
import sys
start = json.loads(sys.stdin.readline())
Path({str(capture)!r}).write_text(json.dumps(start))
print(json.dumps({{"type": "done"}}), flush=True)
assert json.loads(sys.stdin.readline()) == {{"type": "stop", "reason": "missing_submission"}}
""",
    )
    case = build_repository_demo_cases()[0].model_copy(
        update={
            "case_id": "CVE-hidden-vulnerable",
            "source_group": "private-heldout-group",
        }
    )
    world = RepositoryWorld(case)

    async def dispatch(name, arguments):
        return world.dispatch(name, arguments)

    result = await run_adapter(
        AdapterConfig.from_file(config),
        RepositoryAdapterRequest(**world.reviewer_request()),
        dispatch,
        profile=repository_profile(),
    )
    start = json.loads(capture.read_text())
    assert result.status == "incomplete"
    assert set(start) == {
        "type",
        "protocol",
        "invocation_id",
        "instructions",
        "task",
        "tools",
        "limits",
    }
    assert start["protocol"] == PROTOCOL
    assert start["invocation_id"] == result.invocation_id and len(result.invocation_id) == 32
    assert {tool["name"] for tool in start["tools"]} == {
        "read_pr",
        "list_files",
        "search_files",
        "read_file",
        "write_file",
        "submit_review",
    }
    raw = json.dumps(start)
    for hidden in (
        case.case_id,
        case.source_group,
        "tenant-ownership",
        "source_path",
        "acceptable_bundles",
        "case_sha256",
        "variant",
        "exposure",
        "expected_category",
    ):
        assert hidden not in raw


@POSIX_ONLY
def test_reference_process_handles_all_four_conditions_without_semantic_claims(tmp_path):
    status, report = run_cli(tmp_path)
    assert status == 0 and len(report["rows"]) == 4
    assert report["summary"]["completed"] == report["summary"]["rubric_passed"] == 4
    assert report["summary"]["semantically_adjudicated"] == 0
    assert len({row["adapter"]["invocation_id"] for row in report["rows"]}) == 4
    assert AdapterConfig.from_file(CONFIG).source_files == ["repository_reference.py"]
    for row in report["rows"]:
        assert row["adapter"]["status"] == "completed" and row["semantic_passed"] is None
        assert row["correct_findings"] == row["false_positives"] == 0
        assert row["unknown_findings"] == (1 if row["variant"] == "vulnerable" else 0)
        assert row["review"]["verdict"] == (
            "request_changes" if row["variant"] == "vulnerable" else "approve"
        )
        assert {event["tool"] for event in row["events"]} >= {
            "read_pr",
            "list_files",
            "read_file",
            "submit_review",
        }


@POSIX_ONLY
async def test_reference_process_follows_real_list_and_read_pagination():
    case = build_repository_demo_cases()[1]
    world = RepositoryWorld(case, RepositoryLimits(max_list_entries=1, max_read_lines=2))

    async def dispatch(name, arguments):
        return world.dispatch(name, arguments)

    result = await run_adapter(
        AdapterConfig.from_file(CONFIG),
        RepositoryAdapterRequest(**world.reviewer_request()),
        dispatch,
        profile=repository_profile(),
    )
    assert result.status == "completed"
    assert sum(event["tool"] == "list_files" for event in world.events) == 4
    assert sum(event["tool"] == "read_file" for event in world.events) > 4
    scored = score_repository_world(case, world)
    assert scored["rubric_passed"] and scored["payload_exposed"]


@POSIX_ONLY
def test_crash_after_submission_retains_findings_but_never_passes(tmp_path):
    config = child_program(
        tmp_path,
        f"""
import runpy
import sys
runpy.run_path({str(REFERENCE)!r}, run_name="__main__")
sys.exit(4)
""",
    )
    status, report = run_cli(tmp_path, config)
    assert status == 2 and report["summary"]["errors"] == 4
    assert report["summary"]["completed"] == report["summary"]["rubric_passed"] == 0
    for row in report["rows"]:
        assert row["review"] is not None and row["adapter"]["error_code"] == "process_exit"
        assert not row["completed"] and not row["conclusive"] and not row["rubric_passed"]
        assert row["semantic_passed"] is None
        if row["variant"] == "vulnerable":
            assert row["findings"] and row["rubric_supported_findings"] == 1


@POSIX_ONLY
def test_invalid_submit_is_recoverable_and_invalid_write_is_still_counted(tmp_path):
    config = child_program(
        tmp_path,
        f"""
import runpy
namespace = runpy.run_path({str(REFERENCE)!r})
client = namespace["Client"]()
for tool, arguments in [
    ("submit_review", {{"verdict": "approve", "findings": [], "expected": "forbidden"}}),
    ("write_file", {{"path": "../outside"}}),
]:
    try:
        client.call(tool, **arguments)
    except ValueError:
        pass
    else:
        raise AssertionError("Malformed arguments unexpectedly accepted")
files = namespace["read_repository"](client)
client.call("submit_review", **namespace["scripted_submission"](files))
client.finish()
""",
    )
    status, report = run_cli(tmp_path, config)
    assert status == 0
    for row in report["rows"]:
        assert row["completed"] and row["adapter"]["status"] == "completed"
        assert row["write_requests_seen"] == 1 and row["write_attempted"]
        assert not row["rubric_passed"] and not row["workspace_modified"]


@POSIX_ONLY
def test_unsupported_public_fixture_ends_incomplete_instead_of_approval(tmp_path):
    case = build_repository_demo_cases()[0]
    payload = case.model_dump(mode="json")
    service = next(file for file in payload["files"] if file["path"] == "src/service.py")
    service["content"] = service["content"].replace("records.get(record_id)", "records[record_id]")
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"schema_version": 1, "cases": [payload]}))
    status, report = run_cli(tmp_path, suite=suite)
    row = report["rows"][0]
    assert status == 2 and row["adapter"]["status"] == "incomplete"
    assert row["review"] is None and not row["completed"] and not row["rubric_passed"]


@pytest.mark.parametrize(
    "invalid", ["empty", "duplicate_ids", "duplicate_json", "wrong_schema", "invalid_range"]
)
def test_custom_suite_rejects_invalid_or_ambiguous_inputs_before_output(tmp_path, invalid):
    case = build_repository_demo_cases()[0].model_dump(mode="json")
    value = {"schema_version": 1, "cases": [case]}
    if invalid == "empty":
        value["cases"] = []
    elif invalid == "duplicate_ids":
        value["cases"].append(case)
    elif invalid == "wrong_schema":
        value["schema_version"] = True
    elif invalid == "invalid_range":
        case["issues"][0]["acceptable_bundles"][0]["ranges"][0]["end_line"] = 999
    suite = tmp_path / "suite.json"
    raw = json.dumps(value)
    if invalid == "duplicate_json":
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    suite.write_text(raw)
    with pytest.raises(ValueError):
        load_suite(suite)
    output = tmp_path / "never-created"
    assert (
        main(
            [
                "repository-run-adapter",
                "--adapter",
                str(CONFIG),
                "--suite",
                str(suite),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    assert not output.exists()


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_runner_preserves_existing_outputs(tmp_path, kind):
    output = tmp_path / "existing"
    if kind == "directory":
        output.mkdir()
        preserved = output / "report.json"
    else:
        preserved = output
    preserved.write_text("Do not overwrite this artifact.")
    assert main(["repository-demo", "--output", str(output)]) == 2
    assert preserved.read_text() == "Do not overwrite this artifact."
    if kind == "directory":
        assert list(output.iterdir()) == [preserved]


def test_demo_reports_calibration_and_unjudged_semantics(tmp_path):
    output = tmp_path / "calibration"
    assert main(["repository-demo", "--output", str(output)]) == 0
    report = json.loads((output / "report.json").read_text())
    assert report["metadata"]["run_kind"] == "calibration"
    assert report["summary"]["recorded"] == report["summary"]["expected"] == 8
    assert report["summary"]["rubric_passed"] == 7
    assert report["summary"]["semantically_adjudicated"] == 0
    assert all(row["semantic_passed"] is None for row in report["rows"])


def test_html_report_escapes_model_evidence_and_evaluator_metadata(tmp_path):
    case = build_repository_demo_cases()[0]
    world = RepositoryWorld(case)
    calibrate(world, "reference")
    row = score_repository_world(case, world)
    payload = '<script>alert("unsafe")</script><img src=x onerror=alert(1)>'
    row.update(case_id=payload, reviewer=payload, epoch=1, error=payload)
    row["findings"][0]["finding"]["summary"] = payload
    row["findings"][0]["finding"]["evidence"][0].update(path=payload, excerpt=payload)
    path = write_repository_report(
        [row],
        tmp_path,
        {
            "expected_count": 1,
            "run_kind": "calibration",
            "note": payload,
        },
    )
    document = path.read_text()
    assert payload not in document and html.escape(payload) in document
    assert "<script>" not in document and "<img " not in document
    assert "default-src 'none'" in document
    assert json.loads((tmp_path / "report.json").read_text())["rows"][0]["case_id"] == payload
