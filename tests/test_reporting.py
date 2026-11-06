from types import SimpleNamespace as NS

from review_boundary.cli import usage_from_logs
from review_boundary.report import coverage, summarize


def row(surface, group, passed):
    return {
        "model": "model",
        "defense": "baseline",
        "family": "tenant_lookup",
        "variant": "vulnerable",
        "epoch": 1,
        "trial_group": group,
        "surface": surface,
        "attacked": surface != "clean",
        "conclusive": True,
        "completed": True,
        "passed": passed,
        "review_correct": passed,
        "write_attempted": False,
        "workspace_modified": False,
        "error": None,
    }


def test_controls_are_not_borrowed_from_other_runs():
    rows = [row("clean", "first", True), row("readme", "second", False)]
    assert summarize(rows)["paired_eligible"] == 0
    rows.append(row("clean", "second", True))
    assert summarize(rows)["paired_eligible"] == 1
    assert summarize(rows)["paired_degradations"] == 1


def test_manifest_coverage_preserves_missing_groups_and_samples():
    rows = [row("clean", "first", True) | {"case_id": "one"}]
    metadata = {
        "expected_samples": [{"case_id": "one", "epoch": 1}, {"case_id": "two", "epoch": 1}],
        "expected_groups": [
            {"model": "model", "defense": "baseline"},
            {"model": "other", "defense": "baseline"},
        ],
    }
    result = coverage(rows, metadata)
    assert result["recorded"] == 1 and result["expected"] == 4 and result["missing"] == 3
    assert coverage(rows * 2, metadata)["duplicates"] == 1


def test_raw_provider_cost_and_missing_cost_are_distinguished():
    event = NS(event="model", call=NS(response={"usage": {"cost": 0.0123}}))
    usage = NS(input_tokens=100, output_tokens=20, total_cost=None)
    log = NS(stats=NS(model_usage={"model": usage}), samples=[NS(events=[event])])
    assert usage_from_logs([log])["provider_reported_cost_usd"] == 0.0123
    log.samples[0].events.append(NS(event="model", call=None))
    result = usage_from_logs([log])
    assert result["provider_reported_cost_usd"] is None
    assert result["api_calls_without_reported_cost"] == 1
