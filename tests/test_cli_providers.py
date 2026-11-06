"""Verify direct-provider CLI wiring without network access or real credentials."""

import json
from types import SimpleNamespace as NS

import pytest

from review_boundary import cli
from review_boundary.providers import COMMON_OVERRIDES, OVERRIDE_VARIABLES


@pytest.fixture
def quoted_run(tmp_path, monkeypatch):
    for variable in (
        *COMMON_OVERRIDES,
        *OVERRIDE_VARIABLES["openai"],
        *OVERRIDE_VARIABLES["anthropic"],
    ):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(cli, "load_dotenv", lambda **kwargs: False)

    def prepare(provider):
        quote = tmp_path / f"{provider}.json"
        quote.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "provider": provider,
                    "source": f"https://{provider}.com/pricing/",
                    "as_of": "2026-01-01",
                    "models": {
                        "test-model": {"input_usd_per_million": 1, "output_usd_per_million": 2}
                    },
                }
            )
        )
        return [
            "run",
            "--provider",
            provider,
            "--model",
            "test-model",
            "--pricing-file",
            str(quote),
            "--family",
            "tenant_lookup",
            "--surface",
            "clean",
            "--epochs",
            "1",
            "--output",
            str(tmp_path / "candidate"),
            "--ledger",
            str(tmp_path / "budget.json"),
        ]

    return prepare


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_native_dry_run_requires_no_key_and_no_openrouter_call(
    quoted_run, monkeypatch, capsys, provider
):
    monkeypatch.delenv(provider.upper() + "_API_KEY", raising=False)
    monkeypatch.setattr(
        cli, "model_snapshot", lambda *args: pytest.fail("OpenRouter catalog called")
    )
    monkeypatch.setattr(cli, "api_get", lambda *args: pytest.fail("OpenRouter account called"))
    assert cli.main([*quoted_run(provider), "--dry-run"]) == 0
    metadata = json.loads(capsys.readouterr().out)
    assert metadata["provider"]["name"] == provider
    assert metadata["provider"]["remote_price_ceiling_enforced"] is False
    assert metadata["expected_groups"] == [
        {"model": f"{provider}/test-model", "defense": "baseline"}
    ]
    assert metadata["scoring_version"] == metadata["corpus_version"] == "0.2.0"


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_native_run_keeps_reservation_when_sdk_only_reports_estimated_cost(
    quoted_run, tmp_path, monkeypatch, provider
):
    monkeypatch.setenv(provider.upper() + "_API_KEY", "synthetic-native-key")
    monkeypatch.setattr(
        cli, "model_snapshot", lambda *args: pytest.fail("OpenRouter catalog called")
    )
    monkeypatch.setattr(cli, "api_get", lambda *args: pytest.fail("OpenRouter account called"))
    monkeypatch.setattr(cli, "settle", lambda *args: pytest.fail("Estimate settled as billed cost"))
    monkeypatch.setattr(cli, "rows_from_logs", lambda *args: [])
    models, tasks_seen = [], []

    def guard(plan, model_id):
        models.append((plan.name, model_id))
        return "guarded-native-model"

    def evaluate(tasks, **kwargs):
        tasks_seen.extend(tasks)
        assert kwargs["model"] == "guarded-native-model"
        event = NS(event="model", call=NS(response={"usage": {"input_tokens": 100}}))
        usage = NS(input_tokens=100, output_tokens=20, total_cost=0.00014)
        return [
            NS(
                status="success",
                samples=[NS(events=[event], error=None)],
                stats=NS(model_usage={"test-model": usage}),
            )
        ]

    monkeypatch.setattr(cli, "guarded_model", guard)
    monkeypatch.setattr(cli, "eval", evaluate)
    assert cli.main(quoted_run(provider)) == 0
    assert models == [(provider, "test-model")]
    assert tasks_seen[0].config.reasoning_summary == ("none" if provider == "openai" else None)
    metadata = json.loads((tmp_path / "candidate" / "manifest.json").read_text())
    assert metadata["usage"]["provider_reported_cost_usd"] is None
    assert metadata["usage"]["inspect_cost_estimate_usd"] == 0.00014
    ledger = json.loads((tmp_path / "budget.json").read_text())
    assert len(ledger["runs"]) == 1
    assert "settled_usd" not in ledger["runs"][0]
    assert "synthetic-native-key" not in json.dumps(metadata)


@pytest.mark.parametrize("cost", [True, float("nan"), float("inf"), -0.01, "0.01"])
def test_untrusted_cost_values_do_not_release_reservations(cost):
    event = NS(event="model", call=NS(response={"usage": {"cost": cost}}))
    log = NS(samples=[NS(events=[event])], stats=NS(model_usage={}))
    result = cli.usage_from_logs([log])
    assert result["provider_reported_cost_usd"] is None
    assert result["api_calls_without_reported_cost"] == 1


def test_redacted_native_initialization_failure_is_a_cli_error(quoted_run, monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-native-key")

    def fail(*args):
        raise cli.ProviderRequestError("Provider initialization failed; details withheld")

    monkeypatch.setattr(cli, "guarded_model", fail)
    monkeypatch.setattr(cli, "eval", lambda *args, **kwargs: pytest.fail("evaluation started"))
    assert cli.main(quoted_run("openai")) == 2
    output = capsys.readouterr()
    assert "initialization failed" in output.err
    assert "Traceback" not in output.err
    assert "synthetic-native-key" not in output.err + output.out
