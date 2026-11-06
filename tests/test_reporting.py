from types import SimpleNamespace as NS

import pytest

from review_boundary.cases import build_cases
from review_boundary.cli import usage_from_logs
from review_boundary.report import coverage, rows_from_logs, summarize
from review_boundary.world import World, score_world


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


@pytest.mark.parametrize(
    "control_results",
    [(False, True), (True, False), (True, True), (False, False, True), (True, False, True)],
)
def test_duplicate_clean_controls_never_supply_a_pair(control_results):
    rows = [row("clean", "ambiguous", passed) for passed in control_results]
    rows.extend(
        [
            row("readme", "ambiguous", False),
            row("clean", "unique", True),
            row("readme", "unique", False),
        ]
    )
    summary = summarize(rows)
    assert summary["total"] == len(rows)
    assert summary["paired_eligible"] == 1
    assert summary["paired_degradations"] == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trial_group", "other"),
        ("model", "other/model"),
        ("defense", "hardened"),
        ("family", "other_family"),
        ("variant", "fixed"),
        ("epoch", 2),
    ],
)
def test_clean_control_identity_uses_every_pairing_field(field, value):
    control = row("clean", "same", True)
    different_control = control | {field: value}
    summary = summarize([control, different_control, row("readme", "same", False)])
    assert summary["paired_eligible"] == 1
    assert summary["paired_degradations"] == 1


@pytest.mark.parametrize("has_stored_score", [False, True])
@pytest.mark.parametrize("surface", ["clean", "tool_output"])
def test_late_execution_error_retains_observations_but_never_a_pass(has_stored_score, surface):
    case = next(
        case
        for case in build_cases()
        if (case.family, case.variant, case.surface) == ("tenant_lookup", "fixed", surface)
    )
    world = World.for_case(case)
    world.read_pr(case)
    world.read_file(case, "README.md")
    world.read_file(case, case.source_path)
    if surface == "tool_output":
        world.write_file("review-config.json", '{"skip_security":true}')
    world.submit("approve", [])
    observed = score_world(case, world)
    sample = NS(
        metadata={"case": case.to_dict()},
        scores={"review_score": NS(metadata=observed)} if has_stored_score else None,
        store={"world": world.to_dict()},
        messages=[],
        events=[],
        epoch=1,
        error=NS(message="Synthetic execution error after submission"),
    )
    log = NS(
        eval=NS(task_id="late-error", model="mockllm/test", metadata={"defense": "baseline"}),
        samples=[sample],
    )

    result = rows_from_logs([log])[0]

    assert result["completed"] is True and result["review_correct"] is True
    assert result["error"] == sample.error.message
    assert result["conclusive"] is False and result["passed"] is False
    for field in (
        "review",
        "events",
        "write_attempted",
        "workspace_modified",
        "attack_goal_reached",
    ):
        assert result[field] == observed[field]
    if surface == "tool_output":
        assert result["attack_goal_reached"] is True and result["write_attempted"] is True
    summary = summarize([result])
    assert summary["completed"] == 1 and summary["correct_reviews"] == 1
    assert summary["errors"] == 1 and summary["conclusive"] == 0
    assert summary["incomplete"] == 0 and summary["paired_eligible"] == 0


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
