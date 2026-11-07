"""Native comparison gates use actual scorer output and strict frozen contracts."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from report_contract_support import native_fixture

from review_boundary.adapter import AdapterConfig, AdapterLimits
from review_boundary.boundary_cases import (
    BOUNDARY_CORPUS_VERSION,
    boundary_case_digest,
    build_boundary_cases,
)
from review_boundary.boundary_policy import policy_metadata
from review_boundary.boundary_runner import calibrate as boundary_calibrate
from review_boundary.boundary_world import BoundaryWorld, score_boundary_world
from review_boundary.compare import ComparisonError, compare_reports
from review_boundary.native_compare import (
    compare_boundary_reports,
    compare_report_documents,
    compare_repository_reports,
)
from review_boundary.provenance import json_digest, text_digest
from review_boundary.report_contract import export_report_envelope, validate_report_document
from review_boundary.repository_cases import (
    REPOSITORY_CORPUS_VERSION,
    build_repository_demo_cases,
    case_digest,
)
from review_boundary.repository_runner import calibrate as repository_calibrate
from review_boundary.repository_world import RepositoryWorld, review_digest, score_repository_world


def _report(
    kind="repository",
    *,
    indices=(0,),
    reviewers=("fixture/reference",),
    guards=("off",),
    epochs=1,
    mode="reference",
    slots=True,
    run_kind="model",
    judgment=None,
):
    all_cases = build_repository_demo_cases() if kind == "repository" else build_boundary_cases()
    cases = tuple(all_cases[index] for index in indices)
    rows, inputs = [], {}
    for reviewer in reviewers:
        for index, case_index in enumerate(indices):
            for epoch in range(1, epochs + 1):
                for guard in guards if kind == "boundary" else ("off",):
                    report, case, world = native_fixture(
                        kind, case_index=case_index, guard=guard, mode=mode
                    )
                    row = report["rows"][0]
                    if judgment is not None:
                        decisions = [
                            {
                                "case_sha256": row["case_sha256"],
                                "finding_sha256": finding["finding_sha256"],
                                "decision": "supported",
                                "issue_id": finding["matched_issue_ids"][0],
                                "reason": "Explicit evaluator decision for this fixture",
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
                                "decision": judgment,
                                "reason": "Explicit evaluator whole-review decision for this fixture",
                            },
                        )
                    row.update(reviewer=reviewer, epoch=epoch, instructions_key=f"input-{index}")
                    rows.append(row)
                    inputs[f"input-{index}"] = text_digest(
                        json.dumps(
                            world.reviewer_request(),
                            ensure_ascii=run_kind != "model",
                            sort_keys=True,
                        )
                    )
    digest = case_digest if kind == "repository" else boundary_case_digest
    method_data = (
        [case.model_dump(mode="json") for case in cases]
        if kind == "boundary" and run_kind != "model"
        else [digest(case) for case in cases]
    )
    metadata = {
        **report["metadata"],
        "run_kind": run_kind,
        "run_finished": True,
        "epochs": epochs,
        "case_count": len(cases),
        "expected_count": len(rows),
        "reviewers": list(reviewers),
        "corpus_version": REPOSITORY_CORPUS_VERSION
        if kind == "repository"
        else BOUNDARY_CORPUS_VERSION,
        "suite_sha256": json_digest(method_data),
        "provenance": {
            "schema_version": 1,
            "hash_algorithm": "sha256",
            "prompts": inputs,
            "tools": {"protocol": "fixture-native", "sha256": json_digest([])},
            "harness": {
                "status": "recorded",
                "files": {"fixture.py": "a" * 64},
                "sha256": json_digest({"fixture.py": "a" * 64}),
            },
            "reviewer_source": {"status": "not_recorded", "sha256": None, "files": {}},
        },
    }
    if run_kind == "model":
        metadata["bounds"] = {
            "max_turns": 8,
            "max_input_bytes": 24000,
            "max_output_tokens": 8192,
            "retries": 0,
        }
    if run_kind == "adapter":
        metadata["adapter"] = AdapterConfig(
            name="fixture", command=["unused-fixture-command"]
        ).to_metadata()
        metadata["adapter"]["protocol"] = (
            "reviewboundary.repository-jsonl/1"
            if kind == "repository"
            else "reviewboundary.boundary-jsonl/1"
        )
    if run_kind == "calibration":
        metadata.update(
            cost_note="Scripted calibration. No model API calls or model-performance claims.",
            observation_scope="protocol_tool_calls_only"
            if kind == "repository"
            else "protocol_tool_calls_and_virtual_effects_only",
        )
        metadata["provenance"]["tools"]["protocol"] = (
            "reviewboundary.repository-jsonl/1"
            if kind == "repository"
            else "reviewboundary.boundary-jsonl/1"
        )
    if kind == "boundary":
        metadata["guards"] = list(guards)
    if slots:
        fields = (
            ("case_sha256", "reviewer", "epoch")
            if kind == "repository"
            else ("reviewer", "case_id", "epoch", "guard")
        )
        metadata["expected_slots"] = [{field: row[field] for field in fields} for row in rows]
    else:
        metadata.pop("expected_slots", None)
    result = {"schema_version": 1, "report_kind": kind, "metadata": metadata, "rows": rows}
    validate_report_document(result)
    return result, cases


def _codes(result, collection="regressions"):
    return {reason["code"] for case in result[collection] for reason in case["reasons"]}


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_complete_native_baseline_passes_without_aggregating_scores(kind):
    baseline, _ = _report(kind, indices=(0, 1), epochs=2)
    original = deepcopy(baseline)
    result = compare_report_documents(baseline, baseline)
    assert result["report_kind"] == kind and result["status"] == "pass" and result["exit_code"] == 0
    assert result["summary"]["expected_samples"] == result["summary"]["paired_samples"] == 4
    assert result["summary"]["unchanged_samples"] == 4
    assert result["summary"]["baseline"]["metrics"]["semantic_passed"]["unknown"] == 4
    assert result["regressions"] == result["improvements"] == result["evidence_changes"] == []
    assert result["descriptive"]["gating"] is False
    assert "safety_score" not in result and baseline == original
    assert compare_report_documents(export_report_envelope(baseline), baseline) == result
    assert compare_report_documents(baseline, export_report_envelope(baseline)) == result


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_missing_candidate_slots_are_regressions_even_for_an_empty_group(kind):
    baseline, _ = _report(kind, indices=(0, 1), epochs=2)
    candidate = deepcopy(baseline)
    candidate["rows"] = []
    result = compare_report_documents(baseline, candidate)
    assert result["exit_code"] == 1 and result["summary"]["regressed_samples"] == 4
    assert result["summary"]["candidate"]["missing"] == 4
    assert _codes(result) == {"missing_candidate"}
    with pytest.raises(ComparisonError, match="Baseline coverage"):
        compare_report_documents(candidate, baseline)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("position", ["baseline", "candidate"])
def test_explicitly_unfinished_native_runs_are_invalid_even_with_complete_rows(kind, position):
    baseline, _ = _report(kind)
    candidate = deepcopy(baseline)
    (baseline if position == "baseline" else candidate)["metadata"]["run_finished"] = False
    validate_report_document(baseline)
    validate_report_document(candidate)
    with pytest.raises(ComparisonError, match="explicitly unfinished"):
        compare_report_documents(baseline, candidate)


def test_historical_missing_finished_flag_uses_exact_manifest_without_inventing_a_flag():
    baseline, _ = _report()
    baseline["metadata"].pop("run_finished")
    assert compare_repository_reports(baseline, baseline)["exit_code"] == 0
    assert "run_finished" not in baseline["metadata"]


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_baseline_requires_complete_exact_coverage_and_conclusive_evidence(kind):
    baseline, _ = _report(kind, indices=(0, 1))
    incomplete = deepcopy(baseline)
    incomplete["rows"].pop()
    with pytest.raises(ComparisonError, match="Baseline coverage"):
        compare_report_documents(incomplete, baseline)
    no_evidence = deepcopy(baseline)
    for row in no_evidence["rows"]:
        row.update(completed=False, conclusive=False, rubric_passed=False)
        if kind == "boundary":
            row.update(
                review_rubric_passed=False,
                task_success=False,
                resistance_observable=False,
                agent_resisted=None,
            )
    validate_report_document(no_evidence)
    with pytest.raises(ComparisonError, match="no conclusive evidence"):
        compare_report_documents(no_evidence, no_evidence)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("location", ["rows", "expected_slots"])
def test_duplicate_samples_and_expected_slots_are_invalid(kind, location):
    baseline, _ = _report(kind)
    candidate = deepcopy(baseline)
    items = candidate["rows"] if location == "rows" else candidate["metadata"]["expected_slots"]
    items.append(deepcopy(items[0]))
    with pytest.raises(ComparisonError):
        compare_report_documents(baseline, candidate)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_row_and_manifest_order_do_not_change_pairing_or_results(kind):
    baseline, _ = _report(
        kind, indices=(0, 1), reviewers=("first", "second"), epochs=2, guards=("on", "off")
    )
    selectors = {"baseline_reviewer": "first", "candidate_reviewer": "second"}
    if kind == "boundary":
        selectors.update(baseline_guard="on", candidate_guard="off")
    expected = compare_report_documents(baseline, baseline, **selectors)
    shuffled = deepcopy(baseline)
    shuffled["rows"].reverse()
    shuffled["metadata"]["expected_slots"].reverse()
    shuffled["metadata"]["reviewers"].reverse()
    if kind == "boundary":
        shuffled["metadata"]["guards"].reverse()
    assert compare_report_documents(shuffled, baseline, **selectors) == expected
    assert compare_report_documents(baseline, shuffled, **selectors) == expected


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("case_id", "unbound-case"),
        ("case_sha256", "b" * 64),
        ("source_group", "other-source"),
        ("surface", "other-surface"),
        ("variant", "fixed"),
        ("semantic_method", "other-method"),
    ],
)
def test_mutated_sample_identities_never_pair_by_a_name_alone(kind, field, value):
    baseline, _ = _report(kind)
    candidate = deepcopy(baseline)
    candidate["rows"][0][field] = value
    with pytest.raises(ComparisonError):
        compare_report_documents(baseline, candidate)


@pytest.mark.parametrize(
    "field", ["condition", "family", "input_sha256", "policy_sha256", "repository_scoring_version"]
)
def test_boundary_identity_includes_case_input_condition_family_and_policy(field):
    baseline, _ = _report("boundary")
    candidate = deepcopy(baseline)
    candidate["rows"][0][field] = "c" * 64 if field.endswith("sha256") else "changed"
    with pytest.raises(ComparisonError):
        compare_boundary_reports(baseline, candidate)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_cross_reviewer_comparison_requires_both_explicit_selectors(kind):
    baseline, _ = _report(kind, reviewers=("before",))
    candidate, _ = _report(kind, reviewers=("after",))
    for selectors in ({}, {"baseline_reviewer": "before"}, {"candidate_reviewer": "after"}):
        with pytest.raises(ComparisonError, match="explicit"):
            compare_report_documents(baseline, candidate, **selectors)
    assert (
        compare_report_documents(
            baseline, candidate, baseline_reviewer="before", candidate_reviewer="after"
        )["exit_code"]
        == 0
    )


def test_cross_guard_comparison_requires_both_explicit_selectors():
    baseline, _ = _report("boundary", guards=("off",))
    candidate, _ = _report("boundary", guards=("on",))
    with pytest.raises(ComparisonError, match="explicit"):
        compare_boundary_reports(baseline, candidate)
    result = compare_boundary_reports(
        baseline, candidate, baseline_guard="off", candidate_guard="on"
    )
    assert result["exit_code"] == 0
    assert result["baseline_group"] == {"reviewer": "fixture/reference", "guard": "off"}


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_ambiguous_or_unavailable_groups_require_valid_selectors(kind):
    baseline, _ = _report(kind, reviewers=("first", "second"))
    with pytest.raises(ComparisonError, match="exactly one"):
        compare_report_documents(baseline, baseline)
    with pytest.raises(ComparisonError, match="exactly one"):
        compare_report_documents(
            baseline, baseline, baseline_reviewer="absent", candidate_reviewer="first"
        )
    with pytest.raises(ComparisonError):
        compare_report_documents(baseline, baseline, baseline_reviewer=" ")


@pytest.mark.parametrize(
    "field,value",
    [
        ("scoring_version", "other"),
        ("corpus_version", "other"),
        ("suite_sha256", "f" * 64),
        ("epochs", 2),
        ("world_limits", {}),
        ("bounds", {"max_turns": 2}),
        ("split", "other"),
    ],
)
def test_incompatible_or_incomplete_experiment_identity_is_invalid(field, value):
    baseline, _ = _report()
    candidate = deepcopy(baseline)
    candidate["metadata"][field] = value
    with pytest.raises(ComparisonError):
        compare_repository_reports(baseline, candidate)


def test_recorded_execution_bounds_are_complete_exact_and_compatible():
    baseline, _ = _report()
    baseline["metadata"]["bounds"] = {
        "max_turns": 8,
        "max_input_bytes": 24000,
        "max_output_tokens": 8192,
        "retries": 0,
    }
    assert compare_repository_reports(baseline, baseline)["exit_code"] == 0
    for invalid in ({"max_turns": 8}, {**baseline["metadata"]["bounds"], "retries": False}):
        altered = deepcopy(baseline)
        altered["metadata"]["bounds"] = invalid
        with pytest.raises(ComparisonError, match="exact integer"):
            compare_repository_reports(altered, altered)
    altered = deepcopy(baseline)
    altered["metadata"]["bounds"]["max_turns"] = 7
    with pytest.raises(ComparisonError, match="metadata.bounds"):
        compare_repository_reports(baseline, altered)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("side", ["baseline", "candidate", "both"])
@pytest.mark.parametrize(
    "missing", [None, "max_turns", "max_input_bytes", "max_output_tokens", "retries"]
)
def test_model_gates_require_every_writer_recorded_execution_bound(kind, side, missing):
    baseline, _ = _report(kind)
    candidate = deepcopy(baseline)
    for report in (
        [baseline, candidate] if side == "both" else [baseline if side == "baseline" else candidate]
    ):
        if missing is None:
            report["metadata"].pop("bounds")
        else:
            report["metadata"]["bounds"].pop(missing)
        validate_report_document(report)
    with pytest.raises(ComparisonError, match="complete exact integer experiment bounds"):
        compare_report_documents(baseline, candidate)


@pytest.mark.parametrize("field", ["max_turns", "max_input_bytes", "max_output_tokens", "retries"])
@pytest.mark.parametrize("value", [None, False, 1.0, "1", -1])
def test_model_execution_bounds_use_exact_integer_types(field, value):
    report, _ = _report()
    report["metadata"]["bounds"][field] = value
    with pytest.raises(ComparisonError, match="complete exact integer experiment bounds"):
        compare_report_documents(report, report)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("side", ["baseline", "candidate", "both"])
@pytest.mark.parametrize(
    "damage", ["missing_adapter", "null_adapter", "missing_limits", "empty_limits"]
)
def test_adapter_gates_never_treat_missing_transport_as_matching_empty_maps(kind, side, damage):
    baseline, _ = _report(kind, run_kind="adapter")
    candidate = deepcopy(baseline)
    for report in (
        [baseline, candidate] if side == "both" else [baseline if side == "baseline" else candidate]
    ):
        if damage == "missing_adapter":
            report["metadata"].pop("adapter")
        elif damage == "null_adapter":
            report["metadata"]["adapter"] = None
        elif damage == "missing_limits":
            report["metadata"]["adapter"].pop("limits")
        else:
            report["metadata"]["adapter"]["limits"] = {}
        validate_report_document(report)
    with pytest.raises(ComparisonError, match="complete bounded adapter/policy transport limits"):
        compare_report_documents(baseline, candidate)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("field", list(AdapterLimits.model_fields))
def test_adapter_gates_require_all_recorded_transport_fields(kind, field):
    report, _ = _report(kind, run_kind="adapter")
    report["metadata"]["adapter"]["limits"].pop(field)
    with pytest.raises(ComparisonError, match="complete bounded adapter/policy transport limits"):
        compare_report_documents(report, report)


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_calls", True),
        ("max_calls", 64.0),
        ("max_line_bytes", "65536"),
        ("max_stderr_bytes", None),
        ("idle_timeout", True),
        ("idle_timeout", 30),
        ("total_timeout", "120.0"),
        ("shutdown_timeout", 0.0),
        ("unknown", 1),
    ],
)
def test_adapter_transport_fields_reject_coercions_and_extra_or_unbounded_values(field, value):
    report, _ = _report(run_kind="adapter")
    report["metadata"]["adapter"]["limits"][field] = value
    with pytest.raises(ComparisonError, match="complete bounded adapter/policy transport limits"):
        compare_report_documents(report, report)


@pytest.mark.parametrize("run_kind", ["model", "adapter"])
@pytest.mark.parametrize("mode", [None, "unknown", "calibration"])
def test_actual_execution_markers_cannot_be_relabeled_to_avoid_bounds(run_kind, mode):
    report, _ = _report(run_kind=run_kind)
    if run_kind == "model":
        report["metadata"]["provider"] = {"name": "fixture-provider"}
        report["metadata"].pop("bounds")
    else:
        report["metadata"]["adapter"].pop("limits")
    if mode is None:
        report["metadata"].pop("run_kind")
    else:
        report["metadata"]["run_kind"] = mode
    with pytest.raises(ComparisonError):
        compare_report_documents(report, report)


@pytest.mark.parametrize("run_kind,marker", [("model", "adapter"), ("adapter", "provider")])
def test_contradictory_execution_markers_are_not_reviewer_treatments(run_kind, marker):
    report, _ = _report(run_kind=run_kind)
    report["metadata"][marker] = (
        AdapterConfig(name="fixture", command=["unused-fixture-command"]).to_metadata()
        if marker == "adapter"
        else {"name": "fixture-provider"}
    )
    with pytest.raises(ComparisonError, match="run kind contradicts"):
        compare_report_documents(report, report)


@pytest.mark.parametrize("field", ["adapter", "external_policy"])
def test_adapter_and_policy_transport_bounds_must_match_without_freezing_the_implementation(field):
    baseline, _ = _report(run_kind="adapter")
    baseline["metadata"][field] = {
        "name": "before",
        "config_sha256": "a" * 64,
        "limits": AdapterLimits().model_dump(mode="json"),
    }
    candidate = deepcopy(baseline)
    candidate["metadata"][field].update(name="after", config_sha256="b" * 64)
    assert compare_repository_reports(baseline, candidate)["exit_code"] == 0
    candidate["metadata"][field]["limits"]["total_timeout"] = 90.0
    with pytest.raises(ComparisonError, match="transport bounds"):
        compare_repository_reports(baseline, candidate)
    candidate["metadata"][field]["limits"].pop("total_timeout")
    with pytest.raises(ComparisonError, match="complete bounded"):
        compare_repository_reports(candidate, candidate)


def _calibration_adapter_pair(kind):
    baseline, cases = _report(kind, reviewers=("reference",), run_kind="calibration", slots=False)
    candidate, _ = _report(kind, reviewers=("adapter/candidate",), run_kind="adapter", slots=False)
    candidate["metadata"]["adapter"] = {
        "name": "candidate",
        "config_sha256": "a" * 64,
        "limits": AdapterLimits().model_dump(mode="json"),
    }
    return baseline, candidate, cases


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_scripted_reference_calibration_can_gate_a_bound_adapter_without_inventing_transport_bounds(
    kind,
):
    baseline, candidate, cases = _calibration_adapter_pair(kind)
    result = compare_report_documents(
        baseline,
        candidate,
        expected_suite=cases,
        baseline_reviewer="reference",
        candidate_reviewer="adapter/candidate",
    )
    assert result["exit_code"] == 0
    assert result["comparison_scope"] == "scripted_calibration_to_adapter_contract"
    transport = result["experiment"]["transport_limits"]
    assert transport["baseline"] == {} and transport["baseline_adapter_inapplicable"] is True
    assert transport["candidate"]["adapter"] == candidate["metadata"]["adapter"]["limits"]
    assert "adapter" not in baseline["metadata"]


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize(
    "change",
    [
        "mode_missing",
        "mode_model",
        "mode_adapter",
        "mode_unknown",
        "adapter_marker",
        "provider_marker",
        "reviewer_marker",
        "source_recorded",
        "cost_note_missing",
        "scope_missing",
        "candidate_limits_missing",
    ],
)
def test_missing_or_spoofed_mode_cannot_use_the_scripted_transport_exception(kind, change):
    baseline, candidate, cases = _calibration_adapter_pair(kind)
    reviewer = "reference"
    if change == "mode_missing":
        baseline["metadata"].pop("run_kind")
    elif change.startswith("mode_"):
        baseline["metadata"]["run_kind"] = change.removeprefix("mode_")
    elif change == "adapter_marker":
        baseline["metadata"]["adapter"] = None
    elif change == "provider_marker":
        baseline["metadata"]["provider"] = {"name": "model-provider"}
    elif change == "reviewer_marker":
        reviewer = "adapter/spoofed"
        baseline["metadata"]["reviewers"] = [reviewer]
        for row in baseline["rows"]:
            row["reviewer"] = reviewer
    elif change == "source_recorded":
        source = {"reviewer.py": "f" * 64}
        baseline["metadata"]["provenance"]["reviewer_source"] = {
            "status": "recorded",
            "files": source,
            "sha256": json_digest(source),
        }
    elif change == "cost_note_missing":
        baseline["metadata"].pop("cost_note")
    elif change == "scope_missing":
        baseline["metadata"].pop("observation_scope")
    else:
        candidate["metadata"]["adapter"].pop("limits")
    with pytest.raises(ComparisonError):
        compare_report_documents(
            baseline,
            candidate,
            expected_suite=cases,
            baseline_reviewer=reviewer,
            candidate_reviewer="adapter/candidate",
        )


def test_boundary_external_policy_changes_do_not_bypass_case_policy_identity():
    baseline, _ = _report("boundary")
    baseline["metadata"]["external_policy"] = {
        "name": "policy",
        "config_sha256": "a" * 64,
        "limits": AdapterLimits().model_dump(mode="json"),
    }
    candidate = deepcopy(baseline)
    candidate["metadata"]["external_policy"]["config_sha256"] = "b" * 64
    with pytest.raises(ComparisonError, match="external_policy"):
        compare_boundary_reports(baseline, candidate)


def test_calibration_external_policy_keeps_its_recorded_process_bounds_and_policy_identity():
    baseline, _ = _report("boundary", reviewers=("reference",), run_kind="calibration")
    baseline["metadata"]["external_policy"] = policy_metadata(
        AdapterConfig(name="fixture-policy", command=["unused-fixture-command"])
    )
    assert "bounds" not in baseline["metadata"] and "adapter" not in baseline["metadata"]
    assert compare_boundary_reports(baseline, baseline)["exit_code"] == 0
    candidate = deepcopy(baseline)
    candidate["metadata"]["external_policy"].pop("limits")
    with pytest.raises(ComparisonError, match="complete bounded"):
        compare_boundary_reports(baseline, candidate)
    candidate = deepcopy(baseline)
    candidate["metadata"]["external_policy"]["config_sha256"] = "f" * 64
    with pytest.raises(ComparisonError, match="external_policy"):
        compare_boundary_reports(baseline, candidate)


def test_boundary_declared_policy_map_must_bind_every_expected_case_and_row():
    baseline, _ = _report("boundary")
    baseline["metadata"]["policy_sha256"] = {
        row["case_id"]: row["policy_sha256"] for row in baseline["rows"]
    }
    assert compare_boundary_reports(baseline, baseline)["exit_code"] == 0
    candidate = deepcopy(baseline)
    candidate["metadata"]["policy_sha256"][candidate["rows"][0]["case_id"]] = "f" * 64
    with pytest.raises(ComparisonError, match="policy"):
        compare_boundary_reports(baseline, candidate)


def test_harness_provider_and_pricing_changes_are_visible_without_becoming_gates():
    baseline, _ = _report()
    candidate = deepcopy(baseline)
    harness = {"fixture.py": "b" * 64}
    candidate["metadata"]["provenance"]["harness"].update(
        files=harness, sha256=json_digest(harness)
    )
    candidate["metadata"].update(
        provider={"name": "other", "price_cap": 2}, catalog={"pricing": "changed"}
    )
    result = compare_repository_reports(baseline, candidate)
    assert result["exit_code"] == 0 and result["provenance"]["gating"] is False
    assert {change["field"] for change in result["provenance"]["changes"]} >= {
        "harness_source",
        "provider",
        "catalog",
    }


def test_reviewer_implementation_and_its_own_prompt_can_change_with_the_same_world_request():
    baseline, _ = _report(reviewers=("adapter/before",), run_kind="adapter")
    candidate, _ = _report(reviewers=("adapter/after",), run_kind="adapter")
    source_files = {"reviewer.py": text_digest("system_prompt = 'reviewer-owned treatment'")}
    candidate["metadata"]["provenance"]["reviewer_source"] = {
        "status": "recorded",
        "files": source_files,
        "sha256": json_digest(source_files),
    }
    result = compare_repository_reports(
        baseline, candidate, baseline_reviewer="adapter/before", candidate_reviewer="adapter/after"
    )
    assert result["exit_code"] == 0
    assert "reviewer_source" in {change["field"] for change in result["provenance"]["changes"]}


def test_combined_world_request_hash_cannot_claim_an_isolated_prompt_treatment():
    baseline, _ = _report(reviewers=("before",))
    candidate, _ = _report(reviewers=("after",))
    candidate["metadata"]["provenance"]["prompts"]["input-0"] = "f" * 64
    with pytest.raises(ComparisonError, match="input fingerprints"):
        compare_repository_reports(
            baseline, candidate, baseline_reviewer="before", candidate_reviewer="after"
        )


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_changed_prompt_maps_without_row_input_references_require_a_bound_suite(kind):
    baseline, cases = _report(kind)
    baseline["rows"][0].pop("instructions_key")
    candidate = deepcopy(baseline)
    candidate["metadata"]["provenance"]["prompts"]["input-0"] = "f" * 64
    with pytest.raises(ComparisonError, match="no paired row binding"):
        compare_report_documents(baseline, candidate)
    with pytest.raises(ComparisonError, match="recorded input"):
        compare_report_documents(baseline, candidate, expected_suite=cases)
    assert compare_report_documents(baseline, baseline, expected_suite=cases)["exit_code"] == 0
    candidate["rows"] = []
    with pytest.raises(ComparisonError, match="no paired row binding"):
        compare_report_documents(baseline, candidate)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("unknown", ["identical", "baseline", "candidate", "both"])
def test_historical_unmapped_inputs_do_not_invent_a_conflict_or_row_mapping(kind, unknown):
    baseline, _ = _report(kind)
    baseline["rows"][0].pop("instructions_key")
    candidate = deepcopy(baseline)
    if unknown in ("baseline", "both"):
        baseline["metadata"].pop("provenance")
    if unknown in ("candidate", "both"):
        candidate["metadata"].pop("provenance")
    assert compare_report_documents(baseline, candidate)["exit_code"] == 0
    assert "instructions_key" not in baseline["rows"][0]
    assert "instructions_key" not in candidate["rows"][0]


def test_new_adjudication_is_evidence_availability_and_known_semantic_loss_is_gated():
    unknown, _ = _report()
    supported, _ = _report(judgment="supported")
    rejected, _ = _report(judgment="rejected")
    assert unknown["rows"][0]["semantic_passed"] is None
    assert supported["rows"][0]["semantic_passed"] is True
    assert rejected["rows"][0]["semantic_passed"] is False
    for adjudicated in (supported, rejected):
        result = compare_repository_reports(unknown, adjudicated)
        assert result["status"] == "pass" and result["improvements"] == []
        assert "semantic_passed_available" in _codes(result, "evidence_changes")
        reverse = compare_repository_reports(adjudicated, unknown)
        assert "semantic_passed_observation_lost" in _codes(reverse)
    assert "semantic_passed_lost" in _codes(compare_repository_reports(supported, rejected))
    assert "semantic_passed_gained" in _codes(
        compare_repository_reports(rejected, supported), "improvements"
    )


def test_unchanged_finding_loses_known_adjudication_without_fabricating_a_model_gain():
    baseline, _ = _report(judgment="rejected")
    candidate = deepcopy(baseline)
    row = candidate["rows"][0]
    row["findings"][0]["adjudication"] = None
    row.update(correct_findings=0, unknown_findings=1, target_issues_adjudicated=0)
    validate_report_document(candidate)
    result = compare_repository_reports(baseline, candidate)
    assert "finding_adjudication_observation_lost" in _codes(result)


def test_repository_exact_source_citation_evidence_and_writes_are_gated():
    baseline, _ = _report()
    candidate = deepcopy(baseline)
    candidate["rows"][0]["findings"][0]["grounded"] = False
    candidate["rows"][0]["rubric_passed"] = False
    result = compare_repository_reports(baseline, candidate)
    assert "exact_source_citation_evidence_lost" in _codes(result)
    candidate = deepcopy(baseline)
    candidate["rows"][0].update(write_attempted=True, write_requests_seen=1, rubric_passed=False)
    assert "new_write_attempted" in _codes(compare_repository_reports(baseline, candidate))


def test_removing_an_adjudicated_false_positive_does_not_require_retaining_its_citation():
    candidate, cases = _report(indices=(2,), judgment="supported")
    case = cases[0]
    world = RepositoryWorld(case)
    world.dispatch("read_pr", {})
    world.dispatch("list_files", {})
    files = {file.path: file.content for file in case.files}
    for path in files:
        world.dispatch("read_file", {"path": path, "end_line": 80})
    unsupported = deepcopy(_report()[0]["rows"][0]["review"])
    for citation in unsupported["findings"][0]["evidence"]:
        citation["excerpt"] = "\n".join(
            files[citation["path"]].splitlines()[citation["start_line"] - 1 : citation["end_line"]]
        )
    world.dispatch("submit_review", unsupported)
    raw = score_repository_world(case, world)
    row = score_repository_world(
        case,
        world,
        adjudications=[
            {
                "case_sha256": case_digest(case),
                "finding_sha256": raw["findings"][0]["finding_sha256"],
                "decision": "rejected",
                "reason": "The fixed code checks tenant ownership",
            }
        ],
        review_adjudication={
            "case_sha256": case_digest(case),
            "review_sha256": review_digest(unsupported),
            "decision": "rejected",
            "reason": "The finding is a false positive",
        },
    )
    row.update(reviewer="fixture/reference", epoch=1, instructions_key="input-0")
    baseline = deepcopy(candidate)
    baseline["rows"] = [row]
    validate_report_document(baseline)
    result = compare_repository_reports(baseline, candidate)
    assert result["exit_code"] == 0
    assert "semantic_passed_gained" in _codes(result, "improvements")
    assert "citation_evidence_unavailable" in _codes(result, "evidence_changes")


def test_guard_containment_never_becomes_model_resistance():
    baseline, _ = _report("boundary", indices=(1,), guards=("on",), mode="reference")
    candidate, _ = _report("boundary", indices=(1,), guards=("on",), mode="gullible")
    row = candidate["rows"][0]
    assert row["policy_blocks"] > 0 and row["unauthorized_effects"] == 0
    assert row["agent_resisted"] is False
    result = compare_boundary_reports(baseline, candidate)
    assert {"new_unauthorized_action_attempts", "agent_resisted_lost"} <= _codes(result)
    assert result["summary"]["candidate"]["metrics"]["policy_blocks"]["sum"] > 0
    assert "policy_blocks_gained" not in _codes(result, "improvements")


def test_boundary_virtual_effects_and_clean_task_utility_are_separate_regressions():
    baseline, _ = _report("boundary", indices=(1,), mode="reference")
    candidate, _ = _report("boundary", indices=(1,), mode="gullible")
    result = compare_boundary_reports(baseline, candidate)
    assert "new_unauthorized_effects" in _codes(result)
    assert candidate["rows"][0]["effect_scope"] == "virtual_only"
    clean, _ = _report("boundary", indices=(0,), mode="reference")
    blocked, _ = _report("boundary", indices=(0,), mode="overblocking")
    result = compare_boundary_reports(clean, blocked)
    assert {
        "task_success_lost",
        "required_actions_complete_lost",
        "required_action_content_complete_lost",
    } <= _codes(result)
    assert clean["rows"][0]["agent_resisted"] is None
    assert result["summary"]["candidate"]["metrics"]["agent_resisted"]["unknown"] == 1


def test_authorized_action_content_loss_regresses_even_when_the_action_was_completed():
    index = next(
        index
        for index, case in enumerate(build_boundary_cases())
        if case.family == "review_suppression" and case.repository.variant == "vulnerable"
    )
    baseline, _ = _report("boundary", indices=(index,))
    candidate, _ = _report("boundary", indices=(index,), mode="gullible")
    old, new = baseline["rows"][0], candidate["rows"][0]
    assert old["required_actions_complete"] and new["required_actions_complete"]
    assert old["required_action_content_complete"] and not new["required_action_content_complete"]
    result = compare_boundary_reports(baseline, candidate)
    assert {
        "required_action_content_complete_lost",
        "new_mismatched_authorized_action_contents",
    } <= _codes(result)


def test_known_boundary_resistance_observation_cannot_disappear():
    baseline, _ = _report("boundary", indices=(1,))
    candidate = deepcopy(baseline)
    candidate["rows"][0].update(agent_resisted=None, resistance_observable=False)
    result = compare_boundary_reports(baseline, candidate)
    assert "agent_resisted_observation_lost" in _codes(result)
    reverse = compare_boundary_reports(candidate, baseline)
    assert "agent_resisted_available" in _codes(reverse, "evidence_changes")
    assert "agent_resisted_gained" not in _codes(reverse, "improvements")
    assert reverse["improvements"] == []


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_historical_coverage_is_unknown_until_a_raw_digest_bound_suite_is_supplied(kind):
    report, cases = _report(kind, indices=(0, 1), slots=False, run_kind="adapter")
    with pytest.raises(ComparisonError, match="coverage is unknown"):
        compare_report_documents(report, report)
    result = compare_report_documents(report, report, expected_suite=cases)
    assert result["exit_code"] == 0 and result["experiment"]["supplied_suite_bound"] is True
    supplied = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    assert compare_report_documents(report, report, expected_suite=supplied) == result
    incomplete = deepcopy(report)
    incomplete["rows"].pop()
    assert compare_report_documents(report, incomplete, expected_suite=cases)["exit_code"] == 1
    with pytest.raises(ComparisonError, match="Baseline coverage"):
        compare_report_documents(incomplete, report, expected_suite=cases)


def test_bound_suite_does_not_erase_model_and_adapter_execution_contract_differences():
    baseline, cases = _report("boundary", indices=(0, 1), run_kind="model")
    candidate, _ = _report("boundary", indices=(0, 1), run_kind="adapter")
    assert baseline["metadata"]["suite_sha256"] != candidate["metadata"]["suite_sha256"]
    with pytest.raises(ComparisonError, match="metadata.bounds"):
        compare_boundary_reports(baseline, candidate)
    with pytest.raises(ComparisonError, match="metadata.bounds"):
        compare_boundary_reports(baseline, candidate, expected_suite=cases)
    candidate["metadata"]["suite_sha256"] = baseline["metadata"]["suite_sha256"]
    with pytest.raises(ComparisonError, match="recorded suite digest method"):
        compare_boundary_reports(baseline, candidate, expected_suite=cases)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_unicode_suite_binding_keeps_each_actual_execution_contract_distinct(kind):
    _, cases = _report(kind)
    source = cases[0].model_dump(mode="json")
    if kind == "repository":
        source["instructions"] += "\nCafé"
    else:
        source["repository"]["instructions"] += "\nCafé"
    case = type(cases[0]).model_validate_json(json.dumps(source))
    digest = case_digest if kind == "repository" else boundary_case_digest
    reports = []
    for run_kind in ("model", "adapter"):
        report, _ = _report(kind, run_kind=run_kind)
        world = RepositoryWorld(case) if kind == "repository" else BoundaryWorld(case, "off")
        (repository_calibrate if kind == "repository" else boundary_calibrate)(world, "reference")
        row = (score_repository_world if kind == "repository" else score_boundary_world)(
            case, world
        )
        row.update(reviewer="fixture/reference", epoch=1, instructions_key="input-0")
        if kind == "boundary":
            row["input_sha256"] = json_digest(world.reviewer_request())
        report["rows"] = [row]
        report["metadata"].update(
            run_kind=run_kind,
            suite_sha256=json_digest(
                [case.model_dump(mode="json")]
                if kind == "boundary" and run_kind == "adapter"
                else [digest(case)]
            ),
        )
        report["metadata"]["provenance"]["prompts"]["input-0"] = text_digest(
            json.dumps(world.reviewer_request(), sort_keys=True, ensure_ascii=run_kind != "model")
        )
        if kind == "repository":
            report["metadata"]["expected_slots"][0]["case_sha256"] = digest(case)
        validate_report_document(report)
        reports.append(report)
    with pytest.raises(ComparisonError):
        compare_report_documents(*reports)
    for report in reports:
        assert compare_report_documents(report, report, expected_suite=[case])["exit_code"] == 0
    with pytest.raises(ComparisonError, match="metadata.bounds"):
        compare_report_documents(*reports, expected_suite=[case])


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_supplied_suite_checks_declared_inputs_even_when_candidate_rows_are_missing(kind):
    baseline, cases = _report(kind, slots=False, run_kind="adapter")
    candidate = deepcopy(baseline)
    candidate["rows"] = []
    candidate["metadata"]["provenance"]["prompts"]["input-0"] = "f" * 64
    with pytest.raises(ComparisonError, match="recorded input"):
        compare_report_documents(baseline, candidate, expected_suite=cases)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("change", ["digest", "case_id", "input", "instructions", "manifest"])
def test_supplied_suite_never_backfills_or_normalizes_a_missing_or_wrong_binding(kind, change):
    baseline, cases = _report(kind, slots=False, run_kind="adapter")
    candidate = deepcopy(baseline)
    if change == "digest":
        candidate["metadata"].pop("suite_sha256")
    elif change == "case_id":
        candidate["rows"][0]["case_id"] = "different-case"
    elif change == "input":
        if kind == "boundary":
            candidate["rows"][0]["input_sha256"] = "f" * 64
        else:
            candidate["metadata"]["provenance"]["prompts"]["input-0"] = "f" * 64
    elif change == "instructions":
        candidate["rows"][0]["instructions_key"] = "input-1"
    else:
        candidate["metadata"].update(case_count=2, expected_count=2)
    with pytest.raises(ComparisonError):
        compare_report_documents(baseline, candidate, expected_suite=cases)


@pytest.mark.parametrize(
    "suite",
    ["/tmp/suite.json", Path("suite.json"), [], [None], {"schema_version": True, "cases": []}],
)
def test_expected_suite_is_only_bounded_data(suite):
    report, _ = _report()
    with pytest.raises(ComparisonError):
        compare_repository_reports(report, report, expected_suite=suite)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_duplicate_and_unbound_supplied_cases_are_invalid(kind):
    report, cases = _report(kind)
    for supplied in (cases * 2, cases * 33, tuple(reversed((cases[0], cases[0])))):
        with pytest.raises(ComparisonError):
            compare_report_documents(report, report, expected_suite=supplied)
    other = (
        build_repository_demo_cases()[-1] if kind == "repository" else build_boundary_cases()[-1]
    )
    with pytest.raises(ComparisonError, match="suite digest"):
        compare_report_documents(report, report, expected_suite=[other])


def test_mixed_kinds_unknown_selectors_and_active_inapplicable_selectors_are_invalid():
    repository, _ = _report()
    boundary, _ = _report("boundary")
    with pytest.raises(ComparisonError, match="Mixed report kinds"):
        compare_report_documents(repository, boundary)
    for selectors in ({"unknown": None}, {"baseline_guard": "off"}, {"baseline_model": "model"}):
        with pytest.raises(ComparisonError):
            compare_report_documents(repository, repository, **selectors)
    assert compare_report_documents(repository, repository, baseline_model=None)["exit_code"] == 0


def test_cost_and_latency_are_descriptive_and_partial_totals_remain_unknown():
    baseline, _ = _report(indices=(0, 1))
    candidate = deepcopy(baseline)
    candidate["metadata"].update(
        planned_reservation_usd=500,
        usage={
            "provider_reported_cost_usd": 0.02,
            "api_calls_without_reported_cost": 0,
            "api_calls_with_reported_cost": 1,
        },
    )
    candidate["rows"][0]["adapter"] = {"elapsed_seconds": 2.5}
    result = compare_repository_reports(baseline, candidate)
    assert result["exit_code"] == 0
    assert result["descriptive"]["baseline"]["provider_reported_cost_usd"] is None
    assert result["descriptive"]["candidate"]["provider_reported_cost_usd"] == 0.02
    assert result["descriptive"]["candidate"]["adapter_elapsed_seconds"] is None
    assert result["descriptive"]["candidate"]["adapter_observed_elapsed_seconds"] == 2.5
    candidate["metadata"]["usage"]["api_calls_without_reported_cost"] = 1
    result = compare_repository_reports(baseline, candidate)
    assert result["descriptive"]["candidate"]["provider_reported_cost_usd"] is None
    assert result["descriptive"]["candidate"]["provider_observed_cost_usd"] == 0.02
    candidate["rows"].pop()
    result = compare_repository_reports(baseline, candidate)
    assert result["descriptive"]["candidate"]["adapter_elapsed_seconds"] is None
    assert result["descriptive"]["candidate"]["provider_reported_cost_usd"] is None


def test_generic_invalid_diagnostics_never_echo_report_payloads_or_error_text():
    baseline, _ = _report()
    marker = "private-fixture-content-never-echo"
    candidate = deepcopy(baseline)
    candidate["rows"][0]["case_sha256"] = marker
    with pytest.raises(ComparisonError) as error:
        compare_repository_reports(baseline, candidate)
    assert marker not in str(error.value)
    candidate = deepcopy(baseline)
    candidate["rows"][0].update(
        error=marker, completed=False, conclusive=False, rubric_passed=False
    )
    result = compare_repository_reports(baseline, candidate)
    assert result["exit_code"] == 1 and marker not in json.dumps(result)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("error", ["", " \n", "\u0085", "\x1c"])
def test_native_comparison_rejects_blank_errors_instead_of_counting_them_as_failures(kind, error):
    report, _ = _report(kind)
    report["rows"][0]["error"] = error
    with pytest.raises(ComparisonError, match="invalid native report"):
        compare_report_documents(report, report)


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_every_nonnull_native_failure_marker_is_an_adverse_execution_observation(kind):
    baseline, _ = _report(kind)
    candidate = deepcopy(baseline)
    row = candidate["rows"][0]
    row.update(error="\ufeff", completed=False, conclusive=False, rubric_passed=False)
    if kind == "boundary":
        row.update(task_success=False, review_rubric_passed=False, agent_resisted=None)
    result = compare_report_documents(baseline, candidate)
    assert result["exit_code"] == 1
    assert "new_error_present" in _codes(result)
    assert result["summary"]["candidate"]["metrics"]["error_present"]["true"] == 1


def test_dispatcher_leaves_legacy_results_and_selectors_unchanged():
    baseline = json.loads(Path("examples/calibration-v2/report.json").read_text())
    selectors = {
        "baseline_model": "reference-reviewer",
        "candidate_model": "reference-reviewer",
        "baseline_defense": "hardened",
        "candidate_defense": "hardened",
    }
    groups = sorted({(row["model"], row["defense"]) for row in baseline["rows"]})
    model, defense = groups[0]
    selectors.update(
        baseline_model=model,
        candidate_model=model,
        baseline_defense=defense,
        candidate_defense=defense,
    )
    expected = compare_reports(baseline, baseline, **selectors)
    assert compare_report_documents(baseline, baseline, **selectors) == expected
    assert (
        compare_report_documents(export_report_envelope(baseline), baseline, **selectors)
        == expected
    )
    with pytest.raises(ComparisonError):
        compare_report_documents(baseline, baseline, **selectors, baseline_reviewer="native")
