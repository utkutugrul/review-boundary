import json
import os
from types import SimpleNamespace

import pytest
from inspect_ai.model import ChatCompletionChoice, ChatMessageAssistant, ModelOutput, get_model
from inspect_ai.tool import ToolCall

from review_boundary import boundary_runner, cli
from review_boundary.boundary_cases import build_boundary_cases
from review_boundary.boundary_task import context
from review_boundary.cli import main
from review_boundary.model_safety import ProviderRequestError
from review_boundary.providers import COMMON_OVERRIDES, OVERRIDE_VARIABLES


def review_for(case):
    repository = case.repository
    if repository.variant == "fixed":
        return {"verdict": "approve", "findings": []}
    files = {item.path: item.content for item in repository.files}
    issue = repository.issues[0]
    return {
        "verdict": "request_changes",
        "findings": [
            {
                "category": issue.category,
                "summary": "The record lookup crosses the tenant boundary.",
                "evidence": [
                    {
                        **span.model_dump(mode="json"),
                        "excerpt": "\n".join(
                            files[span.path].splitlines()[span.start_line - 1 : span.end_line]
                        ),
                    }
                    for span in issue.acceptable_bundles[0].ranges
                ],
            }
        ],
    }


def boundary_success_model():
    def respond(input, tools, tool_choice, config):
        case, world = context()
        events = world.events
        if not any(event["tool"] == "read_pr" for event in events):
            function, arguments = "read_pr", {}
        elif not any(event["tool"] == "list_files" for event in events):
            function, arguments = "list_files", {}
        else:
            read = {event.get("path") for event in events if event["tool"] == "read_file"}
            unread = next(
                (item.path for item in case.repository.files if item.path not in read), None
            )
            if unread:
                function, arguments = "read_file", {"path": unread, "end_line": 80}
            elif not world.action_request_read:
                function, arguments = "read_action_request", {}
            elif not world.policy_trace and case.grants:
                grant = case.grants[0]
                function = grant.tool
                arguments = {
                    "path" if grant.tool == "save_report" else "url": grant.target,
                    "content": json.dumps(review_for(case)),
                }
            else:
                function, arguments = "submit_review", review_for(case)
        return ModelOutput(
            model="boundary-provider-fake",
            choices=[
                ChatCompletionChoice(
                    message=ChatMessageAssistant(
                        content="",
                        tool_calls=[
                            ToolCall(
                                id=f"boundary-{len(events)}",
                                function=function,
                                arguments=arguments,
                            )
                        ],
                    ),
                    stop_reason="tool_calls",
                )
            ],
        )

    model = get_model("mockllm/boundary-provider-fake", custom_outputs=respond, memoize=False)
    model.api.model_name = "openai/test-model"
    model.api.qualified_model_name = "openai/test-model"
    return model


def write_pricing(tmp_path, provider):
    path = tmp_path / f"{provider}-pricing.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": provider,
                "source": f"https://{provider}.com/pricing/",
                "as_of": "2026-01-01",
                "models": {
                    "test-model": {
                        "input_usd_per_million": 0.01,
                        "output_usd_per_million": 0.02,
                    }
                },
            }
        )
    )
    return path


def write_suite(tmp_path):
    case = next(
        case
        for case in build_boundary_cases()
        if case.family == "path_target_mismatch"
        and case.condition == "attack"
        and case.repository.variant == "vulnerable"
    )
    path = tmp_path / "boundary-suite.json"
    path.write_text(json.dumps({"schema_version": 1, "cases": [case.model_dump(mode="json")]}))
    return path, case


def boundary_model_argv(tmp_path, provider, *, dry_run=False, guard="both"):
    suite, _ = write_suite(tmp_path)
    argv = [
        "boundary-run-model",
        "--provider",
        provider,
        "--model",
        "test-model",
        "--suite",
        str(suite),
        "--guard",
        guard,
        "--epochs",
        "1",
        "--output",
        str(tmp_path / "boundary-result"),
        "--ledger",
        str(tmp_path / "boundary-budget.json"),
        "--budget",
        "1",
    ]
    if provider in ("openai", "anthropic"):
        argv.extend(("--pricing-file", str(write_pricing(tmp_path, provider))))
    if dry_run:
        argv.append("--dry-run")
    return argv


@pytest.fixture
def provider_environment(monkeypatch):
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
@pytest.mark.parametrize("guard,expected", [("both", 2), ("on", 1), ("off", 1)])
def test_boundary_model_dry_run_is_keyless_and_counts_guard_arms(
    tmp_path, monkeypatch, capsys, provider_environment, provider, guard, expected
):
    monkeypatch.setattr(
        boundary_runner,
        "model_snapshot",
        lambda model_ids, *args: [{"id": model_ids[0], "pricing": {}, "context_length": 1}],
    )
    monkeypatch.setattr(cli, "credential", lambda *args: pytest.fail("credential requested"))
    monkeypatch.setattr(boundary_runner, "reserve", lambda *args: pytest.fail("budget reserved"))
    monkeypatch.setattr(
        boundary_runner, "guarded_model", lambda *args: pytest.fail("model constructed")
    )
    assert main(boundary_model_argv(tmp_path, provider, dry_run=True, guard=guard)) == 0
    metadata = json.loads(capsys.readouterr().out)
    assert metadata["provider"]["name"] == provider
    assert metadata["expected_count"] == expected
    assert metadata["guards"] == (["off", "on"] if guard == "both" else [guard])
    assert "independent stochastic runs" in metadata["sampling"]
    assert not (tmp_path / "boundary-result").exists()
    assert not (tmp_path / "boundary-budget.json").exists()


def test_boundary_model_reservation_multiplies_cases_guards_models_and_epochs(
    tmp_path, monkeypatch, capsys, provider_environment
):
    argv = boundary_model_argv(tmp_path, "openai", dry_run=True)
    argv.extend(("--model", "test-model", "--epochs", "3"))
    captured = []

    def planned(samples, *args):
        captured.append(samples)
        return 0.01

    monkeypatch.setattr(boundary_runner, "planned_cost", planned)
    assert main(argv) == 0
    assert captured == [1 * 2 * 1 * 3]
    assert json.loads(capsys.readouterr().out)["expected_count"] == 6


def test_boundary_model_success_uses_native_task_and_trusted_scores(
    tmp_path, monkeypatch, provider_environment
):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-boundary-key")
    original_prepare = boundary_runner.prepare_provider

    class MockPlan:
        def __init__(self, plan):
            self.plan = plan

        def __getattr__(self, name):
            return getattr(self.plan, name)

        def inspect_model_id(self, model_id):
            self.plan.inspect_model_id(model_id)
            return "mockllm/openai/test-model"

    monkeypatch.setattr(
        boundary_runner,
        "prepare_provider",
        lambda *args, **kwargs: MockPlan(original_prepare(*args, **kwargs)),
    )
    monkeypatch.setattr(
        boundary_runner, "api_get", lambda *args: pytest.fail("OpenRouter account called")
    )
    monkeypatch.setattr(
        boundary_runner, "model_snapshot", lambda *args: pytest.fail("catalog called")
    )
    monkeypatch.setattr(boundary_runner, "guarded_model", lambda *args: boundary_success_model())
    assert main(boundary_model_argv(tmp_path, "openai")) == 0
    output = tmp_path / "boundary-result"
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "manifest.json").read_text())
    assert report["summary"]["recorded"] == report["summary"]["expected"] == 2
    assert report["summary"]["completed"] == report["summary"]["task_success"] == 2
    assert report["comparison"]["eligible_pairs"] == 1
    assert report["comparison"]["missing_samples"] == 0
    assert manifest["reviewers"] == ["mockllm/openai/test-model"]
    assert manifest["run_finished"] is True
    assert manifest["usage"]["api_calls_without_reported_cost"] > 0
    assert all(row["semantic_passed"] is None for row in report["rows"])
    assert len({row["input_sha256"] for row in report["rows"]}) == 1
    assert not (output / "settlement.json").exists()


@pytest.mark.parametrize("provider", ["openrouter", "openai", "anthropic"])
def test_boundary_provider_failure_emits_generic_planned_rows(
    tmp_path, monkeypatch, provider_environment, provider
):
    key = "synthetic-boundary-key"
    monkeypatch.setenv(
        {
            "openrouter": "OPENROUTER_API_KEY",
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
        }[provider],
        key,
    )
    monkeypatch.setattr(
        boundary_runner,
        "model_snapshot",
        lambda model_ids, *args: [{"id": model_ids[0], "pricing": {}, "context_length": 1}],
    )
    monkeypatch.setattr(
        boundary_runner,
        "api_get",
        lambda *args: {"data": {"limit_remaining": 100, "usage": 0}},
    )

    def fail(*args):
        raise ProviderRequestError("provider body " + key)

    monkeypatch.setattr(boundary_runner, "guarded_model", fail)
    assert main(boundary_model_argv(tmp_path, provider)) == 2
    report = json.loads((tmp_path / "boundary-result" / "report.json").read_text())
    manifest = json.loads((tmp_path / "boundary-result" / "manifest.json").read_text())
    assert report["summary"]["recorded"] == report["summary"]["expected"] == 2
    assert report["summary"]["errors"] == 2
    assert report["comparison"]["eligible_pairs"] == 0
    assert all(not row["completed"] and row["semantic_passed"] is None for row in report["rows"])
    assert key not in json.dumps([report, manifest])
    ledger = json.loads((tmp_path / "boundary-budget.json").read_text())
    assert len(ledger["runs"]) == 1 and "settled_usd" not in ledger["runs"][0]


def test_boundary_model_preserves_nonempty_output_before_provider_setup(tmp_path, monkeypatch):
    output = tmp_path / "boundary-result"
    output.mkdir()
    preserved = output / "keep.txt"
    preserved.write_text("preserve this result")
    monkeypatch.setattr(
        boundary_runner,
        "prepare_provider",
        lambda *args, **kwargs: pytest.fail("provider setup reached"),
    )
    assert main(boundary_model_argv(tmp_path, "openai")) == 2
    assert preserved.read_text() == "preserve this result"
    assert list(output.iterdir()) == [preserved]


@pytest.mark.parametrize(
    "invalid", ["empty", "duplicate_ids", "duplicate_json", "wrong_schema", "invalid_case"]
)
def test_boundary_model_rejects_invalid_custom_suites_before_output(tmp_path, invalid):
    case = build_boundary_cases()[0].model_dump(mode="json")
    value = {"schema_version": 1, "cases": [case]}
    if invalid == "empty":
        value["cases"] = []
    elif invalid == "duplicate_ids":
        value["cases"].append(case)
    elif invalid == "wrong_schema":
        value["schema_version"] = True
    elif invalid == "invalid_case":
        case["condition"] = "unknown"
    raw = json.dumps(value)
    if invalid == "duplicate_json":
        raw = raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    suite = tmp_path / "invalid-suite.json"
    suite.write_text(raw)
    argv = boundary_model_argv(tmp_path, "openai", dry_run=True)
    argv[argv.index("--suite") + 1] = str(suite)
    assert main(argv) == 2
    assert not (tmp_path / "boundary-result").exists()
    assert not (tmp_path / "boundary-budget.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="Symlink behavior requires POSIX")
@pytest.mark.parametrize("kind", ["direct", "parent"])
def test_boundary_model_rejects_symlinked_output_before_writes(tmp_path, kind):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(target, target_is_directory=True)
    output = link if kind == "direct" else link / "boundary-result"
    argv = boundary_model_argv(tmp_path, "openai", dry_run=True)
    argv[argv.index("--output") + 1] = str(output)
    assert main(argv) == 2
    assert not list(target.iterdir())
    assert link.is_symlink()


@pytest.mark.parametrize("collision", ["ledger", "lock", "temporary", "report"])
def test_boundary_model_rejects_output_and_ledger_collisions(tmp_path, collision):
    argv = boundary_model_argv(tmp_path, "openai", dry_run=True)
    if collision in {"ledger", "report"}:
        output = tmp_path / "boundary-result"
        ledger = output / ("budget.json" if collision == "ledger" else "report.json")
    else:
        ledger = tmp_path / "boundary-budget.json"
        output = ledger.with_suffix(".lock" if collision == "lock" else ".tmp")
    argv[argv.index("--output") + 1] = str(output)
    argv[argv.index("--ledger") + 1] = str(ledger)
    assert main(argv) == 2
    assert not output.exists() and not ledger.exists()


def test_boundary_multi_model_failure_retains_complete_cost_reservation(
    tmp_path, monkeypatch, provider_environment
):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-boundary-key")
    argv = boundary_model_argv(tmp_path, "openai", guard="on")
    argv[argv.index("--budget") + 1] = "20"
    argv.extend(("--model", "second-model"))
    pricing_path = tmp_path / "openai-pricing.json"
    pricing = json.loads(pricing_path.read_text())
    pricing["models"]["second-model"] = {
        "input_usd_per_million": 1,
        "output_usd_per_million": 2,
    }
    pricing_path.write_text(json.dumps(pricing))
    usage = SimpleNamespace(
        input_tokens=10,
        output_tokens=5,
        total_cost=0.01,
        input_tokens_cache_read=0,
        input_tokens_cache_write=0,
    )
    sample = SimpleNamespace(
        error=None,
        events=[
            SimpleNamespace(event="model", call=SimpleNamespace(response={"usage": {"cost": 0.01}}))
        ],
    )
    complete_log = SimpleNamespace(
        status="success",
        samples=[sample],
        stats=SimpleNamespace(model_usage={"openai/test-model": usage}),
    )
    calls = 0

    def evaluate(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return [complete_log]
        raise ProviderRequestError("second provider execution failed")

    def extract(logs, cases, reviewers, epochs, guards):
        assert logs == [complete_log]
        rows = boundary_runner.boundary_error_rows(cases, reviewers[0], epochs, guards, "ok")
        for row in rows:
            row["error"] = None
        return rows

    monkeypatch.setattr(boundary_runner, "eval", evaluate)
    monkeypatch.setattr(boundary_runner, "guarded_model", lambda *args: object())
    monkeypatch.setattr(boundary_runner, "boundary_rows_from_logs", extract)
    monkeypatch.setattr(
        boundary_runner,
        "settle",
        lambda *args: pytest.fail("failed multi-model run was settled"),
    )
    monkeypatch.setattr(
        boundary_runner, "api_get", lambda *args: pytest.fail("OpenRouter account called")
    )
    assert main(argv) == 2
    ledger = json.loads((tmp_path / "boundary-budget.json").read_text())
    assert len(ledger["runs"]) == 1 and "settled_usd" not in ledger["runs"][0]
    assert not (tmp_path / "boundary-result" / "settlement.json").exists()
