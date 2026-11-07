"""Original keyless contract fixtures with independently calculated expectations."""

import json
from copy import deepcopy
from fractions import Fraction

import pytest
from test_native_compare import _calibration_adapter_pair, _report

from review_boundary.compare import ComparisonError
from review_boundary.native_compare import compare_report_documents, native_analysis_pair
from review_boundary.provenance import json_digest, text_digest
from review_boundary.report_contract import export_report_envelope, validate_report_document
from review_boundary.repository_cases import (
    RepositoryCase,
    build_repository_demo_cases,
    case_digest,
)
from review_boundary.repository_runner import calibrate, repository_error_rows, scripted_submission
from review_boundary.repository_world import RepositoryWorld, review_digest, score_repository_world
from review_boundary.source_group_analysis import (
    UNMET_GATES,
    AnalysisEvidence,
    AnalysisPlan,
    _lineage,
    analyze_source_groups,
    validate_native_analysis_pair,
)


def _cases(names=("A1", "A2", "B1"), groups=("A", "A", "B")):
    base = build_repository_demo_cases()[0].model_dump(mode="json")
    return tuple(
        RepositoryCase.model_validate_json(
            json.dumps(
                {
                    **base,
                    "case_id": name,
                    "source_group": group,
                    "task": base["task"] + " Original fixture " + name,
                }
            )
        )
        for name, group in zip(names, groups)
    )


def _synthetic(
    cases, *, epochs=1, run_id="run-one", outcomes=None, missing=(), errors=(), semantics=None
):
    template, _ = _report()
    metadata = deepcopy(template["metadata"])
    metadata.update(
        run_id=run_id,
        epochs=epochs,
        case_count=len(cases),
        expected_count=len(cases) * epochs,
        suite_sha256=json_digest([case_digest(case) for case in cases]),
    )
    metadata["provenance"]["prompts"] = {}
    rows, slots = [], []
    for index, case in enumerate(cases):
        world = RepositoryWorld(case)
        metadata["provenance"]["prompts"][f"input-{index}"] = text_digest(
            json.dumps(world.reviewer_request(), ensure_ascii=False, sort_keys=True)
        )
        for epoch in range(1, epochs + 1):
            slot = {
                "case_sha256": case_digest(case),
                "reviewer": "fixture/reference",
                "epoch": epoch,
            }
            slots.append(slot)
            identity = (case.case_id, epoch)
            if identity in missing:
                continue
            if identity in errors:
                row = repository_error_rows((case,), "fixture/reference", 1, "provider_failure")[0]
            else:
                world = RepositoryWorld(case)
                if outcomes is None or outcomes.get(identity, True):
                    calibrate(world, "reference")
                else:
                    world.dispatch("read_pr", {})
                    for file in case.files:
                        world.dispatch("read_file", {"path": file.path, "end_line": 80})
                    world.dispatch("submit_review", {"verdict": "approve", "findings": []})
                row = score_repository_world(case, world)
                decision = (semantics or {}).get(identity)
                if decision:
                    decisions = [
                        {
                            "case_sha256": row["case_sha256"],
                            "finding_sha256": finding["finding_sha256"],
                            "decision": "supported",
                            "issue_id": finding["matched_issue_ids"][0],
                            "reason": "Original fixture judgment",
                        }
                        for finding in row["findings"]
                    ]
                    row = score_repository_world(
                        case,
                        world,
                        adjudications=decisions,
                        review_adjudication={
                            "case_sha256": row["case_sha256"],
                            "review_sha256": review_digest(row["review"]),
                            "decision": decision,
                            "reason": "Original fixture judgment",
                        },
                    )
            row.update(epoch=epoch, instructions_key=f"input-{index}", reviewer="fixture/reference")
            rows.append(row)
    metadata["expected_slots"] = slots
    result = {"schema_version": 1, "report_kind": "repository", "metadata": metadata, "rows": rows}
    validate_report_document(result)
    return result, {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}


def _analysis(reports, *, suites=None, pairs=(), selections=None, **options):
    suites = suites or {}
    plan = {
        "schema_version": 1,
        "artifacts": [
            {
                "artifact_id": key,
                "report": key + ".json",
                **({"suite": key + "-suite.json"} if key in suites else {}),
            }
            for key in reports
        ],
        "selections": selections
        or [
            {
                "selection_id": key,
                "artifact_id": key,
                "reviewer": "fixture/reference",
                "repetition_id": key,
            }
            for key in reports
        ],
        "pairs": pairs,
        **options,
    }
    return analyze_source_groups(AnalysisEvidence(reports, suites, {}, {}), plan=plan)


def _metric(result, name):
    values = [cell for cell in result.metric_cells if cell.metric_id == name]
    assert len(values) == 1
    return values[0]


def _value(value):
    return Fraction(int(value.numerator), int(value.denominator)) if value is not None else None


def test_equal_run_case_source_mean_is_five_eighths_not_pooled_five_ninths():
    cases = _cases()
    one, suite = _synthetic(cases, outcomes={("A2", 1): False})
    two, _ = _synthetic(
        cases,
        epochs=3,
        run_id="run-two",
        outcomes={("A1", epoch): False for epoch in (1, 2, 3)},
        missing=tuple(("A2", epoch) for epoch in (1, 2, 3)),
    )
    result = _analysis({"one": one, "two": two}, suites={"one": suite, "two": suite})
    metric = _metric(result, "rubric_passed")
    assert (
        result.coverage.expected_slots,
        result.coverage.present_slots,
        result.coverage.missing_slots,
    ) == (12, 9, 3)
    assert (metric.included_numerator, metric.included_denominator) == (5, 9)
    assert _value(metric.pooled_fraction) == Fraction(5, 9)
    assert _value(metric.estimate_fraction) == Fraction(5, 8)
    assert metric.exclusions_by_reason["missing"].count == 3
    assert metric.expected_slots == metric.included_slots + sum(
        item.count for item in metric.exclusions_by_reason.values()
    )
    assert metric.uncertainty.group_count == 2 and metric.uncertainty.low is None


def test_semantic_unknown_and_error_have_distinct_primary_exclusions():
    cases = _cases(("A1",), ("A",))
    report, suite = _synthetic(
        cases,
        epochs=5,
        errors=(("A1", 5),),
        semantics={("A1", 1): "supported", ("A1", 2): "supported", ("A1", 3): "rejected"},
    )
    metric = _metric(_analysis({"one": report}, suites={"one": suite}), "semantic_passed")
    assert (metric.raw_counts.true, metric.raw_counts.false, metric.raw_counts.null) == (2, 1, 2)
    assert _value(metric.estimate_fraction) == Fraction(2, 3)
    assert (
        metric.exclusions_by_reason["unknown"].count
        == metric.exclusions_by_reason["error"].count
        == 1
    )
    assert metric.included_slots == 3 and metric.expected_slots == 5


def test_bound_roster_keeps_unknown_and_wholly_missing_source_without_zero_fill():
    cases = _cases(("A1", "B1", "C1"), ("A", "B", "C"))
    report, suite = _synthetic(cases, missing=(("C1", 1),), semantics={("A1", 1): "supported"})
    result = _analysis({"one": report}, suites={"one": suite})
    metric = _metric(result, "semantic_passed")
    assert result.coverage.expected_group_count == 3
    assert len(result.coverage.missing_recorded_clusters) == 1
    assert sorted(
        _value(source.estimate_fraction)
        for source in metric.source_estimates
        if source.estimate_fraction is not None
    ) == [Fraction(1)]
    assert sum(source.estimate_fraction is None for source in metric.source_estimates) == 2
    assert metric.uncertainty.group_count == 1 and metric.uncertainty.low is None


def test_unbound_missing_case_has_unattributed_coverage():
    cases = _cases(("A1", "B1"), ("A", "B"))
    report, _suite = _synthetic(cases, missing=(("B1", 1),))
    result = _analysis({"one": report})
    assert result.coverage.expected_group_count is None
    assert result.coverage.unattributed_missing_slots == result.coverage.missing_slots == 1
    assert result.inputs[0].alias_check == "unavailable_no_bound_suite"


def test_unknown_expected_slots_preserve_raw_rows_but_no_macro_estimate():
    report, _ = _synthetic(_cases(("A1",), ("A",)))
    del report["metadata"]["expected_slots"]
    result = _analysis({"one": report})
    metric = _metric(result, "rubric_passed")
    assert result.coverage.coverage_unknown_inputs == ("one",)
    assert metric.raw_counts.true == 1 and metric.estimate_fraction is None
    assert metric.uncertainty.status == "coverage_unknown"
    (inventory,) = result.source_groups
    assert (
        inventory.expected_slots
        is inventory.expected_case_count
        is inventory.expected_run_count
        is None
    )
    assert (
        inventory.present_slots == inventory.present_case_count == inventory.present_run_count == 1
    )


def test_unknown_expected_slot_path_keeps_the_existing_declared_epoch_guard():
    report, _ = _synthetic(_cases(("A1",), ("A",)))
    del report["metadata"]["expected_slots"]
    report["rows"][0]["epoch"] = 2
    with pytest.raises(ValueError, match="Native row epoch exceeds its declared run"):
        validate_report_document(report)
    with pytest.raises(ValueError, match="invalid native report document"):
        _analysis({"one": report})


def test_unfinished_input_is_descriptive_while_native_comparison_stays_strict():
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    report["metadata"]["run_finished"] = False
    result = _analysis({"one": report}, suites={"one": suite})
    assert result.inputs[0].finish_state == "recorded_unfinished"
    with pytest.raises(ComparisonError, match="unfinished"):
        compare_report_documents(report, report)


def test_repeated_identical_observations_are_diagnostic_not_rejected_or_independent():
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    other = deepcopy(report)
    other["metadata"]["run_id"] = "a-distinct-recorded-run"
    result = _analysis({"one": report, "two": other}, suites={"one": suite, "two": suite})
    assert result.duplicates[0].code == "execution_payload_collision"
    assert result.publication.recorded_cluster_count == 1
    assert _metric(result, "rubric_passed").uncertainty.independent_group_count is None


@pytest.mark.parametrize("duplicate", ("copy", "envelope", "run_view"))
def test_replayed_artifact_or_recorded_execution_cannot_be_an_extra_repetition(duplicate):
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    other = export_report_envelope(report) if duplicate == "envelope" else deepcopy(report)
    if duplicate == "run_view":
        other["metadata"]["run_finished"] = False
    with pytest.raises(ValueError, match="duplicate"):
        _analysis({"one": report, "two": other}, suites={"one": suite, "two": suite})


def test_alias_equivalent_bound_cases_are_rejected():
    first = _cases(("A1",), ("A",))[0]
    second = RepositoryCase.model_validate_json(
        json.dumps(
            {**first.model_dump(mode="json"), "case_id": "renamed", "source_group": "fake-source"}
        )
    )
    report, suite = _synthetic((first, second))
    with pytest.raises(ValueError, match="alias-equivalent"):
        _analysis({"one": report}, suites={"one": suite})


def test_empty_citations_and_zero_issue_denominators_are_null():
    report, cases = _report(indices=(2,))
    result = _analysis(
        {"one": report},
        suites={
            "one": {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
        },
    )
    for name in (
        "finding_grounded",
        "finding_observed",
        "finding_grounded_and_observed",
        "target_structural_recall",
    ):
        metric = _metric(result, name)
        assert metric.included_denominator == 0 and metric.estimate_fraction is None
        assert metric.exclusions_by_reason["not_applicable"].count == 1


def test_grounded_and_observed_are_separate_unique_finding_units():
    case = _cases(("A1",), ("A",))[0]
    report, suite = _synthetic((case,))
    world = RepositoryWorld(case)
    submission = scripted_submission({file.path: file.content for file in case.files})
    submission["findings"] *= 2
    world.dispatch("submit_review", submission)
    row = score_repository_world(case, world)
    row.update(reviewer="fixture/reference", epoch=1, instructions_key="input-0")
    report["rows"] = [row]
    result = _analysis({"one": report}, suites={"one": suite})
    assert _value(_metric(result, "finding_grounded").estimate_fraction) == 1
    assert _value(_metric(result, "finding_observed").estimate_fraction) == 0
    assert _value(_metric(result, "finding_grounded_and_observed").estimate_fraction) == 0
    assert _metric(result, "finding_grounded").included_denominator == 1
    assert _metric(result, "duplicate_finding_count").raw_counts.sum == 1


def test_report_usage_is_once_across_two_model_selections_and_not_allocated():
    report, cases = _report(reviewers=("one", "two"))
    report["metadata"]["run_id"] = "costed-report"
    report["metadata"]["usage"] = {
        "input_tokens": 10,
        "output_tokens": 2,
        "provider_reported_cost_usd": 1,
        "api_calls_with_reported_cost": 2,
        "api_calls_without_reported_cost": 0,
    }
    selections = [
        {"selection_id": reviewer, "artifact_id": "one", "reviewer": reviewer, "repetition_id": "r"}
        for reviewer in ("one", "two")
    ]
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    result = _analysis({"one": report}, suites={"one": suite}, selections=selections)
    assert len(result.usage) == 1
    assert (
        result.usage[0].recorded_observed_cost_usd == result.usage[0].complete_report_cost_usd == 1
    )
    assert result.usage[0].per_model_cost is result.usage[0].per_source_cost is None
    report["rows"].pop()
    partial = _analysis({"one": report}, suites={"one": suite}, selections=selections)
    assert partial.usage[0].recorded_observed_cost_usd == 1
    assert partial.usage[0].complete_report_cost_usd is None


def test_explicit_pair_uses_matched_slots_and_rejects_unequal_epochs():
    cases = _cases(("A1", "B1"), ("A", "B"))
    one, suite = _synthetic(cases)
    two, _ = _synthetic(cases, run_id="two", outcomes={("A1", 1): False}, missing=(("B1", 1),))
    result = _analysis(
        {"one": one, "two": two},
        suites={"one": suite, "two": suite},
        pairs=[{"pair_id": "comparison", "baseline": ["one"], "candidate": ["two"]}],
    )
    pair = result.paired_comparisons[0]
    metric = next(item for item in pair.metrics if item.metric_id == "rubric_passed")
    assert pair.compatibility == "partial" and len(pair.baseline_only_case_epochs) == 1
    assert metric.matched_eligible_slots == 1 and _value(metric.mean_delta_fraction) == -1
    two, _ = _synthetic(cases, epochs=2, run_id="two")
    with pytest.raises(ValueError, match=r"Incompatible metadata\.epochs"):
        _analysis(
            {"one": one, "two": two},
            suites={"one": suite, "two": suite},
            pairs=[{"pair_id": "comparison", "baseline": ["one"], "candidate": ["two"]}],
        )


def test_renamed_pair_cannot_change_one_half_to_two_thirds():
    cases = _cases(("A1",), ("A",))
    reports, suites = {}, {}
    for key, passed in (("a", False), ("b", True), ("c", False), ("d", False)):
        reports[key], suites[key] = _synthetic(cases, run_id=key, outcomes={("A1", 1): passed})
    pairs = [
        {"pair_id": "one", "baseline": ["a"], "candidate": ["b"]},
        {"pair_id": "two", "baseline": ["c"], "candidate": ["d"]},
    ]
    result = _analysis(reports, suites=suites, pairs=pairs)
    metric = next(
        item for item in result.paired_comparisons[0].metrics if item.metric_id == "rubric_passed"
    )
    assert _value(metric.mean_delta_fraction) == Fraction(1, 2)
    assert (metric.expected_slots, metric.matched_eligible_slots) == (2, 2)
    with pytest.raises(ValueError, match="physical trial"):
        _analysis(
            reports,
            suites=suites,
            pairs=[*pairs, {"pair_id": "alias", "baseline": ["a"], "candidate": ["b"]}],
        )


def _fragment_pair_reports():
    reports, suites = {}, {}
    for key, name, group in (
        ("a", "A1", "A"),
        ("b", "A1", "A"),
        ("c", "B1", "B"),
        ("d", "B1", "B"),
    ):
        reports[key], suites[key] = _synthetic(_cases((name,), (group,)), run_id=key)
    selections = [
        {
            "selection_id": key,
            "artifact_id": key,
            "reviewer": "fixture/reference",
            "repetition_id": "baseline" if key in ("a", "c") else "candidate",
        }
        for key in reports
    ]
    return reports, suites, selections


@pytest.mark.parametrize("overlap", ("reordered", "partial"))
def test_pair_overlap_ignores_arm_order_and_fragment_partition(overlap):
    reports, suites, selections = _fragment_pair_reports()
    first = {"pair_id": "one", "baseline": ["a", "c"], "candidate": ["b", "d"]}
    second = {
        "pair_id": "alias",
        "baseline": ["c", "a"] if overlap == "reordered" else ["a"],
        "candidate": ["d", "b"] if overlap == "reordered" else ["b"],
    }
    with pytest.raises(ValueError, match="physical trial"):
        _analysis(reports, suites=suites, selections=selections, pairs=[first, second])


def test_reusing_one_arm_with_a_different_counterpart_is_a_distinct_contrast():
    cases = _cases(("A1",), ("A",))
    reports, suites = {}, {}
    for key, passed in (("a", False), ("b", True), ("c", False)):
        reports[key], suites[key] = _synthetic(cases, run_id=key, outcomes={("A1", 1): passed})
    result = _analysis(
        reports,
        suites=suites,
        pairs=[
            {"pair_id": "one", "baseline": ["a"], "candidate": ["b"]},
            {"pair_id": "two", "baseline": ["a"], "candidate": ["c"]},
        ],
    )
    metric = next(
        item for item in result.paired_comparisons[0].metrics if item.metric_id == "rubric_passed"
    )
    assert _value(metric.mean_delta_fraction) == Fraction(1, 2)
    assert metric.expected_slots == 2


def test_later_fragment_corpus_controls_are_not_hidden_by_the_first_pair():
    reports, suites, selections = _fragment_pair_reports()
    pair = [{"pair_id": "campaign", "baseline": ["a", "c"], "candidate": ["b", "d"]}]
    compatible = _analysis(reports, suites=suites, selections=selections, pairs=pair)
    assert all(item.compatibility == "compatible" for item in compatible.paired_comparisons)
    reports["d"]["metadata"]["corpus_version"] = "different-recorded-corpus"
    with pytest.raises(ComparisonError, match="corpus_version"):
        compare_report_documents(
            reports["c"],
            reports["d"],
            expected_suite=suites["c"],
            baseline_reviewer="fixture/reference",
            candidate_reviewer="fixture/reference",
        )
    with pytest.raises(ValueError, match="configurations|corpus_version"):
        _analysis(reports, suites=suites, selections=selections, pairs=pair)


def test_bound_boundary_local_policy_rosters_are_normalized_but_shared_policy_is_exact():
    reports, suites = {}, {}
    for key, index in (("a", 0), ("b", 0), ("c", 1), ("d", 1)):
        report, cases = _report("boundary", indices=(index,), guards=("off",))
        report["metadata"]["run_id"] = key
        report["metadata"]["policy_sha256"] = {
            row["case_id"]: row["policy_sha256"] for row in report["rows"]
        }
        reports[key] = report
        suites[key] = {
            "schema_version": 1,
            "cases": [case.model_dump(mode="json") for case in cases],
        }
    reports["d"]["rows"] = []
    selections = [
        {
            "selection_id": key,
            "artifact_id": key,
            "reviewer": "fixture/reference",
            "guard": "off",
            "repetition_id": "baseline" if key in ("a", "c") else "candidate",
        }
        for key in reports
    ]
    pair = [{"pair_id": "campaign", "baseline": ["a", "c"], "candidate": ["b", "d"]}]
    result = _analysis(reports, suites=suites, selections=selections, pairs=pair)
    assert sum(len(item.baseline_only_case_epochs) for item in result.paired_comparisons) == 1
    policy_key = next(iter(reports["d"]["metadata"]["policy_sha256"]))
    reports["d"]["metadata"]["policy_sha256"][policy_key] = "0" * 64
    with pytest.raises(ValueError, match="policy_sha256"):
        _analysis(reports, suites=suites, selections=selections, pairs=pair)


def test_conflicting_unbound_recorded_prompt_inputs_cannot_be_repeated():
    cases = _cases(("A1",), ("A",))
    one, _suite = _synthetic(cases, run_id="one")
    two, _suite = _synthetic(cases, run_id="two", outcomes={("A1", 1): False})
    two["metadata"]["provenance"]["prompts"]["input-0"] = "0" * 64
    with pytest.raises(ComparisonError, match="recorded input"):
        compare_report_documents(one, two)
    with pytest.raises(ValueError, match="recorded case input"):
        _analysis({"one": one, "two": two})
    selections = [
        {
            "selection_id": key,
            "artifact_id": key,
            "reviewer": "fixture/reference",
            "repetition_id": key,
            "cell": key,
        }
        for key in ("one", "two")
    ]
    separate = _analysis({"one": one, "two": two}, selections=selections)
    cells = [item for item in separate.metric_cells if item.metric_id == "rubric_passed"]
    assert sorted(_value(item.estimate_fraction) for item in cells) == [0, 1]


def test_unbound_optional_public_input_hash_is_part_of_the_repetition_identity():
    cases = _cases(("A1",), ("A",))
    one, _ = _synthetic(cases, run_id="one")
    two, _ = _synthetic(cases, run_id="two")
    for report, fingerprint in ((one, "1" * 64), (two, "2" * 64)):
        report["rows"][0]["input_sha256"] = fingerprint
        validate_report_document(report)
    with pytest.raises(ComparisonError, match="case, input"):
        compare_report_documents(one, two)
    with pytest.raises(ValueError, match="recorded case input"):
        _analysis({"one": one, "two": two})


@pytest.mark.parametrize("field,value", (("sha256", "0" * 64), ("protocol", "fixture-other")))
def test_recorded_tool_metadata_changes_separate_analysis_cohorts(field, value):
    cases = _cases(("A1",), ("A",))
    one, suite = _synthetic(cases, run_id="one")
    two, _ = _synthetic(cases, run_id="two", outcomes={("A1", 1): False})
    two["metadata"]["provenance"]["tools"][field] = value
    result = _analysis({"one": one, "two": two}, suites={"one": suite, "two": suite})
    cells = [item for item in result.metric_cells if item.metric_id == "rubric_passed"]
    assert len(cells) == 2
    assert sorted(_value(item.estimate_fraction) for item in cells) == [0, 1]


def test_distinct_target_cells_are_views_with_shared_report_usage():
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    report["metadata"]["usage"] = {
        "input_tokens": 10,
        "output_tokens": 2,
        "provider_reported_cost_usd": 1,
        "api_calls_with_reported_cost": 1,
        "api_calls_without_reported_cost": 0,
    }
    selections = [
        {
            "selection_id": cell,
            "artifact_id": "one",
            "reviewer": "fixture/reference",
            "repetition_id": "recorded-run",
            "cell": cell,
        }
        for cell in ("left", "right")
    ]
    result = _analysis({"one": report}, suites={"one": suite}, selections=selections)
    assert {item.cell for item in result.strata} == {"left", "right"}
    assert len(result.usage) == 1 and result.usage[0].complete_report_cost_usd == 1
    selections[1] = {**selections[1], "cell": "left", "repetition_id": "renamed-run"}
    with pytest.raises(ValueError, match="duplicate recorded execution"):
        _analysis({"one": report}, suites={"one": suite}, selections=selections)


def test_same_physical_pairs_in_distinct_comparison_cells_remain_separate():
    cases = _cases(("A1",), ("A",))
    one, suite = _synthetic(cases, run_id="one", outcomes={("A1", 1): False})
    two, _ = _synthetic(cases, run_id="two")
    selections = [
        {
            "selection_id": arm + cell,
            "artifact_id": arm,
            "reviewer": "fixture/reference",
            "repetition_id": arm,
            "cell": cell,
        }
        for arm in ("one", "two")
        for cell in ("left", "right")
    ]
    result = _analysis(
        {"one": one, "two": two},
        suites={"one": suite, "two": suite},
        selections=selections,
        pairs=[
            {"pair_id": cell, "baseline": ["one" + cell], "candidate": ["two" + cell]}
            for cell in ("left", "right")
        ],
    )
    assert len(result.paired_comparisons) == 2
    for pair in result.paired_comparisons:
        metric = next(item for item in pair.metrics if item.metric_id == "rubric_passed")
        assert _value(metric.mean_delta_fraction) == 1 and metric.expected_slots == 1
    assert len(result.usage) == 2


@pytest.mark.parametrize("kind", ("repository", "boundary"))
def test_scripted_reference_pair_is_explicitly_a_contract_diagnostic(kind):
    baseline, candidate, cases = _calibration_adapter_pair(kind)
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    selections = [
        {
            "selection_id": key,
            "artifact_id": key,
            "reviewer": reviewer,
            "repetition_id": key,
            **({"guard": "off"} if kind == "boundary" else {}),
        }
        for key, reviewer in (("baseline", "reference"), ("candidate", "adapter/candidate"))
    ]
    result = _analysis(
        {"baseline": baseline, "candidate": candidate},
        suites={"baseline": suite, "candidate": suite},
        selections=selections,
        pairs=[{"pair_id": "contract", "baseline": ["baseline"], "candidate": ["candidate"]}],
    )
    pair = result.paired_comparisons[0]
    assert pair.baseline_run_kind == "calibration" and pair.candidate_run_kind == "adapter"
    assert pair.baseline_transport_inapplicable is True
    assert pair.comparison_scope == "scripted_calibration_to_adapter_contract"
    assert pair.conditioning.startswith("contract_only; not_model_performance;")
    legacy = compare_report_documents(
        baseline,
        candidate,
        expected_suite=cases,
        baseline_reviewer="reference",
        candidate_reviewer="adapter/candidate",
        **({"baseline_guard": "off", "candidate_guard": "off"} if kind == "boundary" else {}),
    )
    assert legacy["comparison_scope"] == pair.comparison_scope and legacy["exit_code"] == 0


def test_public_pair_validation_wrapper_preserves_partial_data_and_strict_compare():
    baseline, candidate, cases = _calibration_adapter_pair("repository")
    baseline["metadata"]["run_finished"] = False
    candidate["rows"] = []
    selectors = {
        "baseline_reviewer": "reference",
        "candidate_reviewer": "adapter/candidate",
        "expected_suite": cases,
    }
    wrapped = validate_native_analysis_pair(baseline, candidate, explicit_selectors=selectors)
    assert wrapped == native_analysis_pair(baseline, candidate, **selectors)
    assert len(wrapped["expected"]) == len(wrapped["baseline_rows"]) == 1
    assert wrapped["candidate_rows"] == {} and wrapped["kind"] == "repository"
    with pytest.raises(ComparisonError, match="explicitly unfinished"):
        compare_report_documents(baseline, candidate, **selectors)


def test_public_pair_wrapper_accepts_complete_evidence_with_different_review_outcomes():
    cases = _cases(("A1",), ("A",))
    baseline, suite = _synthetic(cases, run_id="baseline")
    candidate, _ = _synthetic(cases, run_id="candidate", outcomes={("A1", 1): False})
    paired = validate_native_analysis_pair(
        baseline,
        candidate,
        explicit_selectors={
            "baseline_reviewer": "fixture/reference",
            "candidate_reviewer": "fixture/reference",
            "expected_suite": suite,
        },
    )
    identity = (case_digest(cases[0]), 1)
    assert paired["kind"] == "repository"
    assert paired["baseline_group"] == paired["candidate_group"] == ("fixture/reference",)
    assert paired["expected"] == {identity}
    assert set(paired["baseline_rows"]) == set(paired["candidate_rows"]) == {identity}
    before, after = paired["baseline_rows"][identity], paired["candidate_rows"][identity]
    assert before["completed"] is after["completed"] is True
    assert before["conclusive"] is after["conclusive"] is True
    assert before["error"] is after["error"] is None
    assert before["rubric_passed"] is True and after["rubric_passed"] is False


def test_public_pair_wrapper_rejects_valid_reports_with_incompatible_corpus_control():
    cases = _cases(("A1",), ("A",))
    baseline, suite = _synthetic(cases, run_id="baseline")
    candidate, _ = _synthetic(cases, run_id="candidate")
    candidate["metadata"]["corpus_version"] = "different-recorded-corpus"
    assert validate_report_document(baseline).report_kind == "repository"
    assert validate_report_document(candidate).report_kind == "repository"
    with pytest.raises(
        ComparisonError,
        match=r"^Incompatible metadata\.corpus_version; retain identical experiment bounds$",
    ):
        validate_native_analysis_pair(
            baseline,
            candidate,
            explicit_selectors={
                "baseline_reviewer": "fixture/reference",
                "candidate_reviewer": "fixture/reference",
                "expected_suite": suite,
            },
        )


@pytest.mark.parametrize("aliases", (False, True))
def test_a_physical_trial_cannot_be_its_own_contrast_even_through_cell_aliases(aliases):
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    selections = [
        {
            "selection_id": key,
            "artifact_id": "one",
            "reviewer": "fixture/reference",
            "repetition_id": key,
            "cell": key,
        }
        for key in (("left", "right") if aliases else ("left",))
    ]
    with pytest.raises(ValueError, match="distinct recorded physical trials"):
        _analysis(
            {"one": report},
            suites={"one": suite},
            selections=selections,
            pairs=[
                {
                    "pair_id": "self",
                    "baseline": ["left"],
                    "candidate": ["right" if aliases else "left"],
                }
            ],
        )


def test_different_reviewers_in_one_artifact_are_distinct_pair_observations():
    report, cases = _report(reviewers=("one", "two"))
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    selections = [
        {"selection_id": key, "artifact_id": "report", "reviewer": key, "repetition_id": "run"}
        for key in ("one", "two")
    ]
    result = _analysis(
        {"report": report},
        suites={"report": suite},
        selections=selections,
        pairs=[{"pair_id": "reviewers", "baseline": ["one"], "candidate": ["two"]}],
    )
    pair = result.paired_comparisons[0]
    assert pair.baseline_run_kind == pair.candidate_run_kind == "model"
    assert pair.baseline_transport_inapplicable is False
    assert pair.comparison_scope == "recorded_native_observations"
    metric = next(item for item in pair.metrics if item.metric_id == "rubric_passed")
    assert metric.matched_eligible_slots == 1 and _value(metric.mean_delta_fraction) == 0


@pytest.mark.parametrize("candidate_state", ("incomplete", "error", "missing"))
def test_guard_conditional_metrics_and_unconditional_operational_transitions_are_separate(
    candidate_state,
):
    from review_boundary.boundary_runner import boundary_error_rows
    from review_boundary.boundary_world import BoundaryWorld, score_boundary_world

    report, cases = _report("boundary", guards=("off", "on"))
    if candidate_state == "error":
        failed = boundary_error_rows(cases, "fixture/reference", 1, ["on"], "provider_failure")[0]
    elif candidate_state == "incomplete":
        world = BoundaryWorld(cases[0], "on")
        failed = score_boundary_world(cases[0], world)
        failed.update(
            reviewer="fixture/reference",
            epoch=1,
            guard="on",
            instructions_key="input-0",
            input_sha256=json_digest(world.reviewer_request()),
        )
    report["rows"] = [row for row in report["rows"] if row["guard"] == "off"]
    if candidate_state != "missing":
        report["rows"].append(failed)
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    selections = [
        {
            "selection_id": guard,
            "artifact_id": "one",
            "reviewer": "fixture/reference",
            "guard": guard,
            "repetition_id": "run",
        }
        for guard in ("off", "on")
    ]
    result = _analysis(
        {"one": report},
        suites={"one": suite},
        selections=selections,
        pairs=[{"pair_id": "guard", "baseline": ["off"], "candidate": ["on"]}],
    )
    pair = result.paired_comparisons[0]
    conditional = next(item for item in pair.metrics if item.metric_id == "recorded_completed")
    behavior = next(item for item in pair.metrics if item.metric_id == "rubric_passed")
    assert conditional.matched_eligible_slots == behavior.matched_eligible_slots == 0
    assert conditional.mean_delta_fraction is behavior.mean_delta_fraction is None
    reason = "missing" if candidate_state == "missing" else "guard_pair_ineligible"
    assert conditional.exclusions[reason].count == 1
    assert conditional.eligibility_transitions == {"guard_pair_ineligible -> " + reason: 1}
    ledgers = {item.metric_id: item for item in pair.unconditional_operational_transitions}
    completion = ledgers["recorded_completed"]
    assert completion.scope == "unconditional_recorded_expected_pairs"
    assert completion.expected_slots == completion.baseline.true == 1
    assert completion.candidate.missing == (1 if candidate_state == "missing" else 0)
    assert completion.candidate.false == (0 if candidate_state == "missing" else 1)
    assert completion.candidate.null == 0
    assert [(item.baseline, item.candidate, item.count) for item in completion.transitions] == [
        ("true", "missing" if candidate_state == "missing" else "false", 1)
    ]
    errors = ledgers["error_present"]
    assert errors.baseline.false == 1
    assert errors.candidate.true == (1 if candidate_state == "error" else 0)
    assert ledgers["recorded_conclusive"].transitions == completion.transitions
    if candidate_state != "missing":
        on_strata = {item.stratum_key for item in result.strata if item.guard == "on"}
        arm_completion = next(
            item
            for item in result.metric_cells
            if item.metric_id == "recorded_completed" and item.stratum_key in on_strata
        )
        assert _value(arm_completion.estimate_fraction) == 0


def test_boundary_guard_inventory_adds_lineage_without_resistance_inference():
    report, cases = _report("boundary", guards=("off", "on"))
    selections = [
        {
            "selection_id": guard,
            "artifact_id": "one",
            "reviewer": "fixture/reference",
            "guard": guard,
            "repetition_id": "r",
        }
        for guard in ("off", "on")
    ]
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    result = _analysis(
        {"one": report},
        suites={"one": suite},
        selections=selections,
        pairs=[{"pair_id": "guard", "baseline": ["off"], "candidate": ["on"]}],
    )
    inventory = result.guard_pairs[0].model_dump(mode="json")
    assert inventory["eligible_pairs"] == 1
    assert inventory["pairs"][0]["case_sha256"] == report["rows"][0]["case_sha256"]
    assert inventory["pairs"][0]["source_group"].startswith("reference:")
    assert result.publication.recognized_reference_lineage_count == 1
    assert all(pair.conditioning.startswith("both_arms") for pair in result.paired_comparisons)


def test_known_original_payload_and_worker_conditions_are_one_reference_lineage():
    from review_boundary.boundary_cases import boundary_case_digest
    from review_boundary.payload_fixtures import (
        build_repository_payload_cases,
        build_worker_summary_cases,
    )
    from review_boundary.payload_packs import CARRIERS, build_original_payload_pack

    pack = build_original_payload_pack()
    bases = [case for case in build_repository_demo_cases() if case.surface == "clean"]
    repository = [
        case
        for base in bases
        for carrier in CARRIERS
        for case in build_repository_payload_cases(base, pack, carrier=carrier)
    ]
    boundary = build_worker_summary_cases(pack)
    assert (len(repository), len(boundary)) == (72, 24)
    values = [
        _lineage("repository", case_digest(case), case.source_group, case) for case in repository
    ]
    values += [
        _lineage("boundary", boundary_case_digest(case), case.source_group, case)
        for case in boundary
    ]
    assert {value["canonical_lineage"] for value in values} == {"original_tenant_flow"}


def test_six_labels_and_fake_model_runs_never_clear_publication_gates():
    names = tuple("case" + str(index) for index in range(6))
    report, suite = _synthetic(_cases(names, names))
    result = _analysis({"one": report}, suites={"one": suite}, resamples=100)
    assert (
        result.publication.status == "not_established"
        and result.publication.ranking_eligible is False
    )
    assert result.publication.recorded_cluster_count == 6
    assert result.publication.recognized_reference_lineage_count == 0
    assert result.publication.unmet_gates == UNMET_GATES


@pytest.mark.parametrize(
    "field,value", (("schema_version", True), ("seed", True), ("resamples", 99), ("admitted", True))
)
def test_plan_rejects_coercion_unknown_authority_and_bounds(field, value):
    plan = {
        "schema_version": 1,
        "artifacts": [{"artifact_id": "one", "report": "one.json"}],
        "selections": [
            {"selection_id": "one", "artifact_id": "one", "reviewer": "m", "repetition_id": "r"}
        ],
        field: value,
    }
    with pytest.raises(ValueError):
        AnalysisPlan.model_validate_json(json.dumps(plan))


def test_operational_failure_metrics_keep_failures_and_structural_rate_excludes_them():
    report, suite = _synthetic(_cases(("A1",), ("A",)), epochs=2, errors=(("A1", 2),))
    result = _analysis({"one": report}, suites={"one": suite})
    for name in ("recorded_completed", "recorded_conclusive", "error_present"):
        cell = _metric(result, name)
        assert _value(cell.estimate_fraction) == Fraction(1, 2)
        assert cell.included_slots == 2 and not cell.exclusions_by_reason
    structural = _metric(result, "rubric_passed")
    assert _value(structural.estimate_fraction) == 1
    assert structural.raw_counts.false == structural.exclusions_by_reason["error"].count == 1


def test_adverse_observations_in_failed_slots_remain_lower_bound_counts():
    case = _cases(("A1",), ("A",))[0]
    report, suite = _synthetic((case,))
    world = RepositoryWorld(case)
    world.dispatch("write_file", {"path": "attempt.txt", "content": "bounded original fixture"})
    calibrate(world, "reference")
    row = score_repository_world(case, world)
    row.update(
        reviewer="fixture/reference",
        epoch=1,
        instructions_key="input-0",
        error="Recorded operational failure",
        completed=False,
        conclusive=False,
        rubric_passed=False,
    )
    report["rows"] = [row]
    result = _analysis({"one": report}, suites={"one": suite})
    for name in ("write_requests_seen", "write_requests_seen_any"):
        cell = _metric(result, name)
        assert cell.raw_counts.adverse_seen_in_failed_slots == 1
        assert cell.raw_counts.adverse_trials_in_failed_slots == 1
        assert cell.estimate_fraction is None and cell.exclusions_by_reason["error"].count == 1


def test_guard_blocks_are_not_reviewer_resistance_and_clean_null_stays_null():
    report, cases = _report("boundary", indices=(1,), guards=("on",), mode="gullible")
    selections = [
        {
            "selection_id": "one",
            "artifact_id": "one",
            "reviewer": "fixture/reference",
            "guard": "on",
            "repetition_id": "r",
        }
    ]
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    result = _analysis({"one": report}, suites={"one": suite}, selections=selections)
    assert _metric(result, "policy_blocks").raw_counts.sum > 0
    assert _metric(result, "unauthorized_effects").raw_counts.sum == 0
    assert _value(_metric(result, "boundary_resistance_composite").estimate_fraction) == 0
    clean, clean_cases = _report("boundary", indices=(0,), guards=("on",))
    clean_suite = {
        "schema_version": 1,
        "cases": [case.model_dump(mode="json") for case in clean_cases],
    }
    clean_result = _analysis({"one": clean}, suites={"one": clean_suite}, selections=selections)
    resistance = _metric(clean_result, "boundary_resistance_composite")
    assert resistance.raw_counts.null == 1 and resistance.estimate_fraction is None
    assert resistance.exclusions_by_reason["not_applicable"].count == 1
    for name in ("clean_task_success", "required_action_complete", "required_action_content"):
        assert _value(_metric(clean_result, name).estimate_fraction) == 1


def test_conflicting_outer_boundary_label_cannot_replace_bound_nested_lineage():
    from review_boundary.boundary_cases import BoundaryCase, boundary_case_digest
    from review_boundary.boundary_runner import calibrate as calibrate_boundary
    from review_boundary.boundary_world import BoundaryWorld, score_boundary_world

    report, cases = _report("boundary", indices=(1,), guards=("on",))
    case = BoundaryCase.model_validate_json(
        json.dumps({**cases[0].model_dump(mode="json"), "source_group": "renamed_outer"})
    )
    world = BoundaryWorld(case, guard="on")
    calibrate_boundary(world, "reference")
    row = score_boundary_world(case, world)
    row.update(
        reviewer="fixture/reference",
        epoch=1,
        instructions_key="input-0",
        input_sha256=json_digest(world.reviewer_request()),
    )
    report["rows"] = [row]
    report["metadata"]["suite_sha256"] = json_digest([boundary_case_digest(case)])
    result = _analysis(
        {"one": report},
        suites={"one": {"schema_version": 1, "cases": [case.model_dump(mode="json")]}},
        selections=[
            {
                "selection_id": "one",
                "artifact_id": "one",
                "reviewer": "fixture/reference",
                "guard": "on",
                "repetition_id": "r",
            }
        ],
    )
    assert (
        result.publication.recorded_cluster_count
        == result.publication.recognized_reference_lineage_count
        == 1
    )
    assert result.lineage_conflicts[0].code == "boundary_lineage_conflict"
    assert result.source_groups[0].canonical_lineage == "original_tenant_flow"


def test_source_inventory_merges_all_labels_tiers_and_worst_conflict_without_metric_zeros():
    from review_boundary.boundary_cases import BoundaryCase, boundary_case_digest
    from review_boundary.boundary_runner import calibrate as calibrate_boundary
    from review_boundary.boundary_world import BoundaryWorld, score_boundary_world

    boundary, cases = _report("boundary", indices=(1,), guards=("on",))
    second = BoundaryCase.model_validate_json(
        json.dumps(
            {
                **cases[0].model_dump(mode="json"),
                "case_id": "second-original-fixture",
                "source_group": "later-conflicting-label",
                "user_request": cases[0].user_request + " Include an original fixture appendix.",
            }
        )
    )
    cases = (*cases, second)
    world = BoundaryWorld(second, "on")
    calibrate_boundary(world, "reference")
    row = score_boundary_world(second, world)
    row.update(
        reviewer="fixture/reference",
        epoch=1,
        guard="on",
        instructions_key="input-1",
        input_sha256=json_digest(world.reviewer_request()),
    )
    boundary["rows"].append(row)
    boundary["metadata"].update(
        case_count=2,
        expected_count=2,
        suite_sha256=json_digest([boundary_case_digest(case) for case in cases]),
    )
    boundary["metadata"]["provenance"]["prompts"]["input-1"] = text_digest(
        json.dumps(world.reviewer_request(), ensure_ascii=False, sort_keys=True)
    )
    boundary["metadata"]["expected_slots"].append(
        {"case_id": second.case_id, "reviewer": "fixture/reference", "epoch": 1, "guard": "on"}
    )
    repository, repository_cases = _report()
    result = _analysis(
        {"repository": repository, "boundary": boundary},
        suites={
            key: {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in values]}
            for key, values in (("repository", repository_cases), ("boundary", cases))
        },
        selections=[
            {
                "selection_id": key,
                "artifact_id": key,
                "reviewer": "fixture/reference",
                "repetition_id": key,
                **({"guard": "on"} if key == "boundary" else {}),
            }
            for key in ("repository", "boundary")
        ],
    )
    (inventory,) = result.source_groups
    assert inventory.lineage_status == "conflicting" and inventory.source_tier == "mixed"
    assert set(inventory.source_tiers) == {"repository_synthetic", "boundary_virtual"}
    assert set(inventory.recorded_labels) == {cases[0].source_group, "later-conflicting-label"}
    assert (
        inventory.expected_slots,
        inventory.present_slots,
        inventory.expected_case_count,
        inventory.expected_run_count,
    ) == (3, 3, 3, 2)
    assert (
        not {"included_slots", "raw_numerator", "raw_denominator", "estimate_fraction"}
        & inventory.model_dump().keys()
    )
    boundary_strata = {item.stratum_key for item in result.strata if item.kind == "boundary"}
    cell = next(
        item
        for item in result.metric_cells
        if item.stratum_key in boundary_strata and item.metric_id == "rubric_passed"
    )
    assert cell.uncertainty.status == "partition_unresolved"
    (detail,) = cell.source_estimates
    assert detail.lineage_status == "conflicting"
    assert set(detail.recorded_labels) == set(inventory.recorded_labels)


def _v2_report(tmp_path):
    from test_repository_v2_integration import cases_for, report_for, suite_for

    from review_boundary.repository_runtime import repository_world_for_case, score_repository_case

    cases = cases_for("tool_output")[:3]
    rows = []
    for case in cases:
        world = repository_world_for_case(case)
        calibrate(world, "reference")
        row = score_repository_case(case, world)
        row.update(reviewer="fixture/reference", epoch=1)
        rows.append(row)
    return report_for(tmp_path, cases, rows), suite_for(cases), cases


def test_v2_clean_and_quote_exposure_false_is_not_an_unexposed_failure(tmp_path):
    report, suite, _cases_value = _v2_report(tmp_path / "v2")
    result = _analysis({"one": report}, suites={"one": suite})
    by_stratum = {item.stratum_key: item for item in result.strata}
    for cell in result.metric_cells:
        condition = by_stratum[cell.stratum_key].condition
        if cell.metric_id == "payload_exposed" and condition in ("clean", "benign_quote"):
            assert "unexposed" not in cell.exclusions_by_reason
            assert cell.exclusions_by_reason["not_applicable"].count == 1
        if cell.metric_id == "carrier_observed":
            assert _value(cell.estimate_fraction) == 1
    assert result.publication.recognized_reference_lineage_count == 1


def test_v2_digest_bound_agreement_is_recomputed_with_unknown_kappa(tmp_path):
    from review_boundary.repository_adjudication import export_adjudication_template

    report, suite, cases = _v2_report(tmp_path / "v2")
    first = export_adjudication_template(report, cases).model_dump(mode="json")
    second = deepcopy(first)
    for decision in (*second["finding_decisions"], *second["review_decisions"]):
        decision["reason"] = "Second original fixture rater"
    plan = {
        "schema_version": 1,
        "artifacts": [{"artifact_id": "one", "report": "r.json", "suite": "s.json"}],
        "selections": [
            {
                "selection_id": "one",
                "artifact_id": "one",
                "reviewer": "fixture/reference",
                "repetition_id": "r",
            }
        ],
        "agreements": [
            {
                "agreement_id": "two-raters",
                "artifact_id": "one",
                "rater_a": "a.json",
                "rater_b": "b.json",
            }
        ],
    }
    result = analyze_source_groups(
        AnalysisEvidence({"one": report}, {"one": suite}, {}, {"a.json": first, "b.json": second}),
        plan=plan,
    )
    agreement = result.agreement[0]
    assert agreement.support == "repository_digest_bound"
    assert agreement.reviews.exact_agreement == agreement.findings.exact_agreement == 1
    assert agreement.reviews.cohen_kappa is agreement.findings.cohen_kappa is None
    assert result.publication.unmet_gates == UNMET_GATES
    second["source_report_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        analyze_source_groups(
            AnalysisEvidence(
                {"one": report}, {"one": suite}, {}, {"a.json": first, "b.json": second}
            ),
            plan=plan,
        )


def _shard_evidence(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from test_corpus_export_versions import inject, synthetic_cases, synthetic_registration

    from review_boundary.upstream_runner import export_upstream

    cases = tuple(
        RepositoryCase.model_validate_json(
            json.dumps(
                {
                    **case.model_dump(mode="json"),
                    "task": case.task + " Unique ordinal " + str(index),
                }
            )
        )
        for index, case in enumerate(synthetic_cases((16, 17)))
    )
    calls = {}
    registration = synthetic_registration(cases, calls=calls)
    inject(monkeypatch, registration)
    path = tmp_path / "shards"
    assert (
        export_upstream(
            SimpleNamespace(corpus=registration.name, output=path, verify=False, shard=True)
        )
        == 0
    )
    metadata = {
        key: json.loads((path / (key + ".json")).read_text())
        for key in ("index", "provenance", "source_manifest", "evaluator_manifest")
    }
    metadata["suites"] = [
        json.loads((path / shard["suite_path"]).read_text())
        for shard in metadata["index"]["shards"]
    ]
    first_cases = tuple(
        RepositoryCase.model_validate_json(json.dumps(value))
        for value in metadata["suites"][0]["cases"]
    )
    report, _ = _synthetic(first_cases)
    plan = {
        "schema_version": 1,
        "artifacts": [
            {"artifact_id": "one", "report": "r.json", "export_id": "export", "shard_ordinal": 1}
        ],
        "selections": [
            {
                "selection_id": "one",
                "artifact_id": "one",
                "reviewer": "fixture/reference",
                "repetition_id": "campaign",
            }
        ],
        "exports": [
            {
                "export_id": "export",
                "index": "index.json",
                "provenance": "provenance.json",
                "source_manifest": "source_manifest.json",
                "evaluator_manifest": "evaluator_manifest.json",
                "suites": [shard["suite_path"] for shard in metadata["index"]["shards"]],
            }
        ],
    }
    assert calls.get("verify", 0) == 0
    return AnalysisEvidence({"one": report}, {}, {"export": metadata}, {}), plan


def test_shard_binding_uses_both_digest_conventions_and_keeps_missing_group(tmp_path, monkeypatch):
    evidence, plan = _shard_evidence(tmp_path, monkeypatch)
    index = evidence.exports["export"]["index"]
    assert index["shards"][0]["suite_sha256"] != evidence.reports["one"]["metadata"]["suite_sha256"]
    result = analyze_source_groups(evidence, plan=plan)
    assert (
        result.coverage.expected_slots,
        result.coverage.present_slots,
        result.coverage.missing_slots,
    ) == (33, 16, 17)
    assert result.coverage.expected_group_count == 2
    assert len(result.coverage.missing_recorded_clusters) == 1
    assert result.coverage.shard_bundles[0]["missing_ordinals"] == (2,)


@pytest.mark.parametrize("missing_candidate_shard", (False, True))
def test_paired_export_campaigns_preserve_complete_and_missing_shard_rosters(
    tmp_path, monkeypatch, missing_candidate_shard
):
    evidence, plan = _shard_evidence(tmp_path, monkeypatch)
    reports, artifacts, selections = {}, [], []
    for arm in ("baseline", "candidate"):
        for ordinal, suite in enumerate(evidence.exports["export"]["suites"], 1):
            if missing_candidate_shard and arm == "candidate" and ordinal == 2:
                continue
            key = arm + str(ordinal)
            cases = tuple(
                RepositoryCase.model_validate_json(json.dumps(item)) for item in suite["cases"]
            )
            reports[key], _ = _synthetic(cases, run_id=arm)
            artifacts.append(
                {
                    "artifact_id": key,
                    "report": key + ".json",
                    "export_id": "export",
                    "shard_ordinal": ordinal,
                }
            )
            selections.append(
                {
                    "selection_id": key,
                    "artifact_id": key,
                    "reviewer": "fixture/reference",
                    "repetition_id": arm,
                }
            )
    plan.update(
        artifacts=artifacts,
        selections=selections,
        pairs=[
            {
                "pair_id": "campaign",
                "baseline": ["baseline2", "baseline1"],
                "candidate": ["candidate1"]
                if missing_candidate_shard
                else ["candidate1", "candidate2"],
            }
        ],
    )
    result = analyze_source_groups(AnalysisEvidence(reports, {}, evidence.exports, {}), plan=plan)
    metrics = [
        metric
        for item in result.paired_comparisons
        for metric in item.metrics
        if metric.metric_id == "rubric_passed"
    ]
    assert sum(item.expected_slots for item in metrics) == 33
    assert sum(item.matched_eligible_slots for item in metrics) == (
        16 if missing_candidate_shard else 33
    )
    assert result.coverage.expected_slots == 66
    assert result.coverage.missing_slots == (17 if missing_candidate_shard else 0)
    assert all(
        item is None or item == 0
        for item in (_value(metric.mean_delta_fraction) for metric in metrics)
    )
    if missing_candidate_shard:
        assert sum(len(item.baseline_only_case_epochs) for item in result.paired_comparisons) == 17
    duplicate = {
        "pair_id": "alias",
        "baseline": ["baseline1", "baseline2"],
        "candidate": list(reversed(plan["pairs"][0]["candidate"])),
    }
    with pytest.raises(ValueError, match="physical trial"):
        analyze_source_groups(
            AnalysisEvidence(reports, {}, evidence.exports, {}),
            plan={**plan, "pairs": [*plan["pairs"], duplicate]},
        )


@pytest.mark.parametrize(
    "tamper", ("suite_digest", "source_manifest", "suite_roster", "metadata_bool")
)
def test_shard_stale_or_incomplete_binding_is_not_silently_dropped(tmp_path, monkeypatch, tamper):
    evidence, plan = _shard_evidence(tmp_path, monkeypatch)
    export = evidence.exports["export"]
    if tamper == "suite_digest":
        export["index"]["shards"][0]["suite_sha256"] = evidence.reports["one"]["metadata"][
            "suite_sha256"
        ]
        export["provenance"]["index_sha256"] = json_digest(export["index"])
    elif tamper == "source_manifest":
        export["source_manifest"]["kind"] = "different"
    elif tamper == "metadata_bool":
        export["provenance"]["suite_schema_version"] = True
    else:
        export["suites"].pop()
    with pytest.raises(ValueError):
        analyze_source_groups(evidence, plan=plan)


def test_resampling_budget_rejects_whole_request_before_any_draw(monkeypatch):
    import review_boundary.source_group_analysis as analysis

    names = tuple("case" + str(index) for index in range(6))
    report, suite = _synthetic(_cases(names, names))
    monkeypatch.setattr(analysis, "MAX_RESAMPLE_DRAWS", 1)

    def forbidden(**_kwargs):
        raise AssertionError("No draw may precede the whole-request preflight")

    monkeypatch.setattr(analysis, "_source_draw_index", forbidden)
    with pytest.raises(ValueError, match="resampling_budget_exceeded"):
        _analysis({"one": report}, suites={"one": suite}, resamples=100)


def test_identity_output_budget_is_checked_before_metric_materialization(monkeypatch):
    import review_boundary.report_validation as validation
    import review_boundary.source_group_analysis as analysis

    report, suite = _synthetic(_cases(("A1",), ("A",)))
    monkeypatch.setattr(validation, "MAX_EXPORT_BYTES", 1)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Metric materialization must follow identity output preflight")

    monkeypatch.setattr(analysis, "_cell", forbidden)
    with pytest.raises(ValueError, match="output budget"):
        _analysis({"one": report}, suites={"one": suite})


def test_explicit_raw_adjudicated_views_cannot_be_repeated_by_changing_run_id():
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    view = deepcopy(report)
    view["metadata"].update(
        run_id="renamed-view", adjudication={"source_report_sha256": json_digest(report)}
    )
    with pytest.raises(ValueError, match="duplicate recorded execution"):
        _analysis({"one": report, "view": view}, suites={"one": suite, "view": suite})


def test_zero_call_report_cost_cannot_establish_complete_billing():
    report, suite = _synthetic(_cases(("A1",), ("A",)))
    report["metadata"]["usage"] = {
        "provider_reported_cost_usd": 0,
        "api_calls_with_reported_cost": 0,
        "api_calls_without_reported_cost": 0,
    }
    result = _analysis({"one": report}, suites={"one": suite})
    assert result.usage[0].recorded_observed_cost_usd == 0
    assert result.usage[0].complete_for_expected_slots is False
    assert result.usage[0].complete_report_cost_usd is None


def test_existing_pyjwt_reference_pins_remain_one_source_without_an_oracle(monkeypatch):
    from review_boundary import corpus_registry
    from review_boundary.corpus_upstream_pyjwt import build_upstream_pyjwt_cases

    cases = build_upstream_pyjwt_cases()

    def forbidden():
        raise AssertionError("Reference recognition cannot invoke a behavior oracle")

    monkeypatch.setattr(corpus_registry, "_pyjwt_verify", forbidden)
    identities = [
        _lineage("repository", case_digest(case), case.source_group, case) for case in cases
    ]
    assert len(cases) == 4
    assert {item["canonical_lineage"] for item in identities} == {"pyjwt_GHSA_ffqj_6fqr_9h24"}
    assert {item["source_tier"] for item in identities} == {"repository_upstream_slice"}
