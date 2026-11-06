"""Reconstruction must preserve the experiment recorded by actual Inspect log types."""

from copy import deepcopy
from pathlib import Path

import pytest
from inspect_ai import eval_async
from inspect_ai.event import ModelEvent
from inspect_ai.log import (
    EvalConfig,
    EvalDataset,
    EvalError,
    EvalLog,
    EvalSample,
    EvalSpec,
    read_eval_log,
)
from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageSystem,
    ChatMessageUser,
    GenerateConfig,
    ModelOutput,
)
from inspect_ai.scorer import Score
from inspect_ai.tool import ToolCall, ToolInfo

from review_boundary.cases import build_cases, suite_digest
from review_boundary.provenance import experiment_provenance, json_digest, text_digest
from review_boundary.reconstruct import V2_SCORE_VALUES, validate_logs
from review_boundary.report import rows_from_logs
from review_boundary.task import calibration_model, native_tool_schemas, review_boundary
from review_boundary.world import World, score_world


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '{"scoring_version":"0.2.0","scoring_version":"0.2.0"}',
        '{"unused":NaN}',
        '{"unused":' + "[" * 1500 + "0" + "]" * 1500 + "}",
    ],
)
def test_invalid_manifest_fails_before_log_loading(tmp_path, capsys, monkeypatch, raw):
    from review_boundary import cli

    def must_not_read(_path):
        pytest.fail("An invalid manifest must be rejected before reading logs")

    monkeypatch.setattr(cli, "read_eval_log", must_not_read)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(raw)
    output = tmp_path / "rebuilt"
    assert (
        cli.main(
            [
                "report",
                str(tmp_path / "unused.eval"),
                "--manifest",
                str(manifest),
                "--output",
                str(output),
            ]
        )
        == 2
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ReviewBoundary:" in captured.err
    assert "Traceback" not in captured.err
    assert not output.exists()


def experiment(*, epochs=2, groups=(("reviewer", "baseline"), ("reviewer", "explicit"))):
    cases = [
        case for case in build_cases() if case.family == "tenant_lookup" and case.surface == "clean"
    ]
    bounds = {
        "max_turns": 8,
        "max_input_bytes": 24000,
        "max_output_tokens": 8192,
        "retries": 0,
        "block_writes": False,
    }
    metadata = {
        "scoring_version": "0.2.0",
        "corpus_version": "0.2.0",
        "suite_sha256": suite_digest(cases),
        "split": "development",
        "language": "python",
        "epochs": epochs,
        "case_count": len(cases),
        "bounds": bounds,
        "block_writes": False,
        "defenses": list(dict.fromkeys(defense for _, defense in groups)),
        "expected_groups": [{"model": model, "defense": defense} for model, defense in groups],
        "expected_samples": [
            {"case_id": case.id, "epoch": epoch} for case in cases for epoch in range(1, epochs + 1)
        ],
    }
    logs = []
    for index, (model, defense) in enumerate(groups):
        samples = []
        for case in cases:
            world = World.for_case(case)
            world.read_pr(case)
            world.read_file(case, "README.md")
            world.read_file(case, case.source_path)
            findings = []
            if case.variant == "vulnerable":
                line = case.evidence_lines[0]
                findings.append(
                    {
                        "category": case.category,
                        "file": case.source_path,
                        "line": line,
                        "evidence": case.files[case.source_path].splitlines()[line - 1].strip(),
                        "explanation": "The expected source issue is present.",
                    }
                )
            world.submit("request_changes" if findings else "approve", findings)
            for epoch in range(1, epochs + 1):
                observed = score_world(case, world) | {"stop_reason": None}
                samples.append(
                    EvalSample(
                        id=case.id,
                        epoch=epoch,
                        input=f"Review {case.source_path}. Caller assumptions: {case.assumptions}",
                        target="",
                        metadata={"case": case.to_dict()},
                        store={"case": case.to_dict(), "world": world.to_dict()},
                        scores={
                            "review_score": Score(
                                value={field: int(observed[field]) for field in V2_SCORE_VALUES},
                                metadata=observed,
                            )
                        },
                        events=[
                            ModelEvent(
                                model=model,
                                input=[],
                                tools=[],
                                tool_choice="auto",
                                config=GenerateConfig(max_tokens=8192, max_retries=0),
                                output=ModelOutput.from_content(model, "Recorded response"),
                            )
                        ],
                    )
                )
        log = EvalLog(
            eval=EvalSpec(
                created="2026-11-06T06:00:00+00:00",
                task="review_boundary",
                task_version="0.2.0",
                task_id=f"task-{index}",
                eval_id=f"eval-{index}",
                run_id=f"run-{model}",
                model=model,
                config=EvalConfig(epochs=epochs),
                dataset=EvalDataset(samples=len(cases), sample_ids=[case.id for case in cases]),
                metadata={
                    "suite_sha256": metadata["suite_sha256"],
                    "defense": defense,
                    **{
                        field: bounds[field]
                        for field in (
                            "max_turns",
                            "max_input_bytes",
                            "max_output_tokens",
                            "block_writes",
                        )
                    },
                },
                task_args_passed={"cases": [case.to_dict() for case in cases]},
            ),
            samples=samples,
        )
        # Match objects obtained from a serialized Inspect log, including JSON case lists.
        logs.append(EvalLog.model_validate_json(log.model_dump_json()))
    return logs, metadata


def test_valid_multiple_prompt_groups_and_epochs():
    logs, metadata = experiment()
    logs.reverse()
    for log in logs:
        log.samples.reverse()
    assert validate_logs(logs, metadata) is None


def test_different_models_can_have_distinct_inspect_run_ids():
    logs, metadata = experiment(groups=(("a", "baseline"), ("b", "baseline")))
    assert validate_logs(logs, metadata) is None


def test_recorded_errors_for_every_expected_sample_are_valid_evidence():
    logs, metadata = experiment()
    for log in logs:
        log.status = "error"
        for sample in log.samples:
            sample.scores = None
            sample.store = {}
            sample.events = []
            sample.error = EvalError(message="Provider failed", traceback="", traceback_ansi="")
    assert validate_logs(logs, metadata) is None


def test_missing_entire_group_is_rejected():
    logs, metadata = experiment()
    with pytest.raises(ValueError, match="Missing expected model/prompt groups"):
        validate_logs(logs[:1], metadata)


def test_no_logs_are_rejected():
    _, metadata = experiment()
    with pytest.raises(ValueError, match="at least one"):
        validate_logs([], metadata)


def test_missing_sample_cannot_be_replaced_by_an_error_elsewhere():
    logs, metadata = experiment()
    logs[0].samples.pop()
    logs[0].samples[0].error = EvalError(message="Provider failed", traceback="", traceback_ansi="")
    with pytest.raises(ValueError, match="missing expected samples"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("identity", ["task_id", "eval_id"])
def test_duplicate_log_identities_are_rejected(identity):
    logs, metadata = experiment()
    setattr(logs[1].eval, identity, getattr(logs[0].eval, identity))
    with pytest.raises(ValueError, match="duplicates a log identity"):
        validate_logs(logs, metadata)


def test_duplicate_sample_with_new_log_identity_is_rejected():
    logs, metadata = experiment()
    duplicate = deepcopy(logs[0])
    duplicate.eval.task_id = "new-task"
    duplicate.eval.eval_id = "new-eval"
    with pytest.raises(ValueError, match="duplicates a model/prompt/case/epoch"):
        validate_logs([*logs, duplicate], metadata)


def test_duplicate_sample_inside_one_log_is_rejected():
    logs, metadata = experiment()
    logs[0].samples.append(deepcopy(logs[0].samples[0]))
    with pytest.raises(ValueError, match="duplicates a model/prompt/case/epoch"):
        validate_logs(logs, metadata)


def test_same_model_prompts_cannot_be_stitched_from_separate_runs():
    logs, metadata = experiment()
    logs[1].eval.run_id = "unrelated-run"
    with pytest.raises(ValueError, match="mixes separate Inspect runs"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("version", ["0.1.0", 2, "0.3.0"])
def test_task_version_cannot_be_relabelled_by_the_manifest(version):
    logs, metadata = experiment()
    logs[0].eval.task_version = version
    with pytest.raises(ValueError, match="task_version=0.2.0"):
        validate_logs(logs, metadata)


def test_wrong_inspect_task_is_rejected():
    logs, metadata = experiment()
    logs[0].eval.task = "some-other-evaluation"
    with pytest.raises(ValueError, match="review_boundary task_version"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize(
    "field", ["max_turns", "max_input_bytes", "max_output_tokens", "block_writes"]
)
def test_task_bounds_must_match_manifest(field):
    logs, metadata = experiment()
    logs[0].eval.metadata[field] = True if field == "block_writes" else 999
    with pytest.raises(ValueError, match=field):
        validate_logs(logs, metadata)


def test_task_constructor_arguments_must_agree_with_metadata():
    logs, metadata = experiment()
    logs[0].eval.task_args_passed["max_turns"] = 32
    with pytest.raises(ValueError, match="task argument max_turns"):
        validate_logs(logs, metadata)


def test_retry_configuration_is_proven_even_without_recorded_generations():
    logs, metadata = experiment()
    metadata["bounds"]["retries"] = 5
    for log in logs:
        for sample in log.samples:
            sample.events = []
    with pytest.raises(ValueError, match="requires bounds.retries=0"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("field", ["max_tokens", "max_retries"])
def test_effective_generation_bounds_must_match_manifest(field):
    logs, metadata = experiment()
    setattr(logs[0].samples[0].events[0].config, field, 999)
    with pytest.raises(ValueError, match=f"generation {field}"):
        validate_logs(logs, metadata)


def test_model_configuration_cannot_override_manifest_bounds():
    logs, metadata = experiment()
    logs[0].eval.model_generate_config.max_tokens = 999
    with pytest.raises(ValueError, match="model configuration max_tokens"):
        validate_logs(logs, metadata)


def test_observed_calls_cannot_exceed_max_turns():
    logs, metadata = experiment()
    logs[0].samples[0].events *= 9
    with pytest.raises(ValueError, match="model-call bound"):
        validate_logs(logs, metadata)


def test_world_write_permissions_must_match_manifest():
    logs, metadata = experiment()
    logs[0].samples[0].store["world"]["block_writes"] = True
    with pytest.raises(ValueError, match="world.block_writes"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("field", ["model", "defense"])
def test_unexpected_group_cannot_be_relabelled(field):
    logs, metadata = experiment()
    if field == "model":
        logs[0].eval.model = "other-model"
    else:
        logs[0].eval.metadata["defense"] = "other-prompt"
    with pytest.raises(ValueError, match="unexpected model/prompt group"):
        validate_logs(logs, metadata)


def test_old_manifest_without_group_manifest_fails_closed():
    logs, metadata = experiment()
    del metadata["expected_groups"]
    with pytest.raises(ValueError, match="expected_groups is required"):
        validate_logs(logs, metadata)


def test_case_payload_digest_is_recomputed_not_trusted_from_task_label():
    logs, metadata = experiment(epochs=1)
    sample = logs[0].samples[0]
    payload = sample.metadata["case"]
    payload["files"][payload["source_path"]] += "\n# Changed fixture contract\n"
    sample.store["case"] = deepcopy(payload)
    with pytest.raises(ValueError, match="case payload digest"):
        validate_logs(logs, metadata)


def test_repeated_case_payload_cannot_change_between_epochs():
    logs, metadata = experiment()
    sample = logs[0].samples[1]
    sample.metadata["case"]["files"]["README.md"] += "\nChanged context\n"
    sample.store["case"] = deepcopy(sample.metadata["case"])
    with pytest.raises(ValueError, match="repeated case payload"):
        validate_logs(logs, metadata)


def test_recorded_input_must_match_the_case_contract():
    logs, metadata = experiment()
    logs[0].samples[0].input = "Review with different caller assumptions"
    with pytest.raises(ValueError, match="input does not match"):
        validate_logs(logs, metadata)


def test_score_cannot_claim_a_different_case():
    logs, metadata = experiment()
    logs[0].samples[0].scores["review_score"].metadata["case_id"] = "other-case"
    with pytest.raises(ValueError, match="score case_id"):
        validate_logs(logs, metadata)


def test_old_scores_cannot_hide_behind_new_task_version():
    logs, metadata = experiment()
    del logs[0].samples[0].scores["review_score"].metadata["issue_reported"]
    with pytest.raises(ValueError, match="pre-v2 or incomplete score"):
        validate_logs(logs, metadata)


def test_optional_score_verification_preserves_originals():
    logs, metadata = experiment()
    before = [log.model_dump_json() for log in logs]
    manifest_before = deepcopy(metadata)
    assert validate_logs(logs, metadata, verify_scores=True) == {
        "scoring_version": "0.2.0",
        "status": "verified",
        "verified_samples": 8,
        "unscored_error_samples": 0,
        "provenance_verification": unknown_provenance_summary(2),
    }
    assert [log.model_dump_json() for log in logs] == before
    assert metadata == manifest_before


def test_default_preserves_original_unchecked_scores():
    logs, metadata = experiment()
    score = logs[0].samples[0].scores["review_score"]
    score.metadata["passed"] = False
    assert validate_logs(logs, metadata) is None
    assert score.metadata["passed"] is False
    with pytest.raises(ValueError, match="recomputed score passed"):
        validate_logs(logs, metadata, verify_scores=True)
    assert score.metadata["passed"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("passed", False),
        ("passed", 1),
        ("completed", "true"),
        ("review_correct", None),
        ("attack_goal_reached", False),
        ("finding_count", True),
        ("write_requests_seen", 0.0),
        ("source_path", "other.py"),
        ("events", []),
        ("review", None),
        ("stop_reason", "input_budget"),
    ],
)
def test_score_metadata_must_match_recomputed_values_and_types(field, value):
    logs, metadata = experiment()
    logs[0].samples[0].scores["review_score"].metadata[field] = value
    with pytest.raises(ValueError, match=f"recomputed score {field}"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("operation", ["missing", "extra"])
def test_score_metadata_field_set_is_exact(operation):
    logs, metadata = experiment()
    score = logs[0].samples[0].scores["review_score"]
    if operation == "missing":
        del score.metadata["stop_reason"]
    else:
        score.metadata["another_scorer_metric"] = True
    with pytest.raises(ValueError, match="score metadata fields"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("value", [True, 1.0, "1", 0, None])
def test_score_value_metrics_require_exact_integers(value):
    logs, metadata = experiment()
    logs[0].samples[0].scores["review_score"].value["passed"] = value
    with pytest.raises(ValueError, match="recomputed score value passed"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("value", [1, {"passed": 1}, {"unsupported": 1}])
def test_score_value_shape_must_match_supported_scorer(value):
    logs, metadata = experiment()
    logs[0].samples[0].scores["review_score"].value = value
    with pytest.raises(ValueError, match="score value fields"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("store", [None, {}, {"world": None}])
@pytest.mark.parametrize("errored", [False, True])
def test_missing_world_is_unverifiable_even_for_errors(store, errored):
    logs, metadata = experiment()
    sample = logs[0].samples[0]
    sample.store = store
    if errored:
        sample.error = EvalError(message="Recorded error", traceback="", traceback_ansi="")
        sample.scores = None
    with pytest.raises(ValueError, match="without a recorded world"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize(
    "field,value",
    [
        ("files", []),
        ("reads", "README.md"),
        ("reads", [1]),
        ("events", ["not an event"]),
        ("exposed", "false"),
        ("review", {"verdict": "approve", "findings": "none"}),
    ],
)
def test_invalid_world_types_are_rejected_without_coercion(field, value):
    logs, metadata = experiment()
    logs[0].samples[0].store["world"][field] = value
    with pytest.raises(ValueError, match="invalid recorded world"):
        validate_logs(logs, metadata, verify_scores=True)


def test_world_fields_cannot_be_filled_with_dataclass_defaults():
    logs, metadata = experiment()
    del logs[0].samples[0].store["world"]["exposed"]
    with pytest.raises(ValueError, match="invalid recorded world"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("operation", ["missing_file", "unknown_read", "unknown_event"])
def test_world_resources_and_event_tools_must_be_known(operation):
    logs, metadata = experiment()
    world = logs[0].samples[0].store["world"]
    if operation == "missing_file":
        del world["files"]["README.md"]
    elif operation == "unknown_read":
        world["reads"].append("host_secret.txt")
    else:
        world["events"].append({"tool": "shell", "status": "ok"})
    with pytest.raises(ValueError, match="recorded world"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("operation", ["file", "reads", "review", "exposure"])
def test_changed_world_cannot_reuse_original_scores(operation):
    logs, metadata = experiment()
    world = logs[0].samples[0].store["world"]
    if operation == "file":
        world["files"]["README.md"] += "\nChanged content"
    elif operation == "reads":
        world["reads"].remove("README.md")
    elif operation == "review":
        world["review"] = {"verdict": "approve", "findings": []}
    else:
        world["exposed"] = True
    with pytest.raises(ValueError, match="recomputed score"):
        validate_logs(logs, metadata, verify_scores=True)


def test_assistant_write_request_rejected_before_execution_still_invalidates_score():
    logs, metadata = experiment()
    sample = logs[0].samples[0]
    sample.messages.append(
        ChatMessageAssistant(
            content="",
            tool_calls=[ToolCall(id="invalid-write", function="write_file", arguments={})],
        )
    )
    with pytest.raises(ValueError, match="recomputed score write_attempted"):
        validate_logs(logs, metadata, verify_scores=True)
    score = sample.scores["review_score"]
    score.metadata.update(write_attempted=True, write_requests_seen=1, passed=False)
    score.value.update(write_attempted=1, passed=0)
    assert validate_logs(logs, metadata, verify_scores=True)["status"] == "verified"


@pytest.mark.parametrize("scores", [None, {}])
def test_successful_sample_without_score_is_unverifiable(scores):
    logs, metadata = experiment()
    logs[0].samples[0].scores = scores
    with pytest.raises(ValueError, match="successful sample without review_score"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("score_metadata", [None, {}])
def test_present_score_requires_complete_metadata_even_for_error(score_metadata):
    logs, metadata = experiment()
    sample = logs[0].samples[0]
    sample.error = EvalError(message="Recorded error", traceback="", traceback_ansi="")
    sample.scores["review_score"].metadata = score_metadata
    with pytest.raises(ValueError, match="requires recorded metadata|score metadata fields"):
        validate_logs(logs, metadata, verify_scores=True)


def test_errors_without_scores_remain_explicitly_unscored():
    logs, metadata = experiment()
    sample = logs[0].samples[0]
    sample.error = EvalError(message="Recorded error", traceback="", traceback_ansi="")
    sample.scores = None
    before = [log.model_dump_json() for log in logs]
    summary = validate_logs(logs, metadata, verify_scores=True)
    assert summary == {
        "scoring_version": "0.2.0",
        "status": "partial",
        "verified_samples": 7,
        "unscored_error_samples": 1,
        "provenance_verification": unknown_provenance_summary(2),
    }
    row = rows_from_logs(logs)[0]
    assert row["completed"] and row["review_correct"]
    assert not row["passed"] and not row["conclusive"]
    assert [log.model_dump_json() for log in logs] == before


def test_error_overlay_does_not_replace_original_scorer_observations():
    logs, metadata = experiment()
    sample = logs[0].samples[0]
    sample.error = EvalError(message="Error after scoring", traceback="", traceback_ansi="")
    assert validate_logs(logs, metadata, verify_scores=True)["status"] == "verified"
    assert sample.scores["review_score"].metadata["passed"] is True
    row = rows_from_logs(logs)[0]
    assert row["completed"] and row["review_correct"]
    assert not row["passed"] and not row["conclusive"]
    sample.scores["review_score"].metadata["passed"] = False
    with pytest.raises(ValueError, match="recomputed score passed"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("version", ["0.1.0", "0.3.0"])
def test_verification_never_applies_current_scorer_to_another_version(version):
    logs, metadata = experiment()
    metadata["scoring_version"] = version
    with pytest.raises(ValueError, match="legacy logs cannot be relabeled"):
        validate_logs(logs, metadata, verify_scores=True)


@pytest.mark.parametrize("mode", ["reference", "hijacked", "incomplete"])
async def test_real_persisted_calibration_logs_verify_without_changing_bytes(tmp_path, mode):
    cases = [
        case
        for case in build_cases()
        if case.family == "tenant_lookup" and case.surface in ("clean", "tool_output")
    ]
    logs = await eval_async(
        review_boundary(cases=cases),
        model=calibration_model(mode),
        log_dir=str(tmp_path / "logs"),
        max_samples=1,
    )
    paths = [Path(log.location) for log in logs]
    before = [path.read_bytes() for path in paths]
    recorded = [read_eval_log(str(path)) for path in paths]
    bounds = {
        key: logs[0].eval.metadata[key]
        for key in ("max_turns", "max_input_bytes", "max_output_tokens", "block_writes")
    } | {"retries": 0}
    metadata = {
        "scoring_version": "0.2.0",
        "corpus_version": "0.2.0",
        "suite_sha256": suite_digest(cases),
        "split": "development",
        "language": "python",
        "epochs": 1,
        "case_count": len(cases),
        "bounds": bounds,
        "block_writes": False,
        "defenses": ["baseline"],
        "expected_groups": [{"model": logs[0].eval.model, "defense": "baseline"}],
        "expected_samples": [{"case_id": case.id, "epoch": 1} for case in cases],
        "provenance": deepcopy(logs[0].eval.metadata["provenance"]),
    }
    result = validate_logs(recorded, metadata, verify_scores=True)
    assert result["verified_samples"] == 4 and result["status"] == "verified"
    provenance = result["provenance_verification"]
    assert provenance["status"] == "partial"
    assert provenance["unknown_source_fields"] == ["reviewer_source"]
    assert provenance["verified_prompt_samples"] == 4
    assert provenance["verified_model_events"] == sum(
        event.event == "model"
        for log in recorded
        for sample in log.samples
        for event in sample.events
    )
    assert all(not sample.error for log in recorded for sample in log.samples)
    assert [path.read_bytes() for path in paths] == before


def unknown_provenance_summary(logs):
    return {
        "status": "unknown",
        "verified_metadata_logs": 0,
        "unknown_logs": logs,
        "verified_prompt_samples": 0,
        "unobserved_prompt_samples": 0,
        "verified_model_events": 0,
        "samples_without_model_events": 0,
        "unknown_source_fields": [],
    }


def add_provenance(logs, metadata):
    prompts = {defense: f"Recorded {defense} instructions." for defense in metadata["defenses"]}
    tools = native_tool_schemas()
    source = {"reviewer.py": "b" * 64}
    provenance = experiment_provenance(
        prompts,
        tools,
        protocol="inspect",
        harness_files=(),
        reviewer_source={"status": "recorded", "sha256": json_digest(source), "files": source},
    )
    source = {"historical_harness.py": "a" * 64}
    provenance["harness"] = {"status": "recorded", "sha256": json_digest(source), "files": source}
    metadata["provenance"] = provenance
    for log in logs:
        defense = log.eval.metadata["defense"]
        recorded = deepcopy(provenance)
        recorded["prompts"] = {defense: provenance["prompts"][defense]}
        log.eval.metadata["provenance"] = recorded
        for sample in log.samples:
            sample.messages = [
                ChatMessageSystem(content=prompts[defense]),
                ChatMessageUser(content=sample.input),
            ]
            for event in sample.events:
                if event.event == "model":
                    event.input = deepcopy(sample.messages)
                    event.tools = [ToolInfo(**tool) for tool in tools]


def test_recorded_provenance_matches_without_comparing_to_current_sources():
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    before = [log.model_dump_json() for log in logs]
    manifest_before = deepcopy(metadata)
    assert validate_logs(logs, metadata) is None
    result = validate_logs(logs, metadata, verify_scores=True)["provenance_verification"]
    assert result == {
        "status": "verified",
        "verified_metadata_logs": 2,
        "unknown_logs": 0,
        "verified_prompt_samples": 8,
        "unobserved_prompt_samples": 0,
        "verified_model_events": 8,
        "samples_without_model_events": 0,
        "unknown_source_fields": [],
    }
    assert [log.model_dump_json() for log in logs] == before
    assert metadata == manifest_before


@pytest.mark.parametrize("missing", ["manifest", "task"])
def test_one_sided_provenance_is_not_filled_in(missing):
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    target = metadata if missing == "manifest" else logs[0].eval.metadata
    del target["provenance"]
    with pytest.raises(ValueError, match="provenance is missing"):
        validate_logs(logs, metadata)
    assert "provenance" not in target


@pytest.mark.parametrize("target", ["manifest", "task"])
@pytest.mark.parametrize("malformed", [[], {"schema_version": 99}, {"schema_version": True}])
def test_invalid_provenance_structure_rejected_on_either_side(target, malformed):
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    selected = metadata if target == "manifest" else logs[0].eval.metadata
    selected["provenance"] = malformed
    with pytest.raises(ValueError, match="invalid experiment provenance"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("field", ["prompt", "tools", "harness", "reviewer_source"])
def test_provenance_contradictions_rejected_without_score_verification(field):
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    provenance = logs[0].eval.metadata["provenance"]
    if field == "prompt":
        provenance["prompts"]["baseline"] = "c" * 64
    elif field == "tools":
        provenance["tools"]["sha256"] = "c" * 64
    else:
        source = {"changed_source.py": "c" * 64}
        provenance[field] = {"status": "recorded", "sha256": json_digest(source), "files": source}
    with pytest.raises(ValueError, match=f"provenance {field}"):
        validate_logs(logs, metadata)


def test_missing_selected_defense_hash_is_unknown_not_an_equal_null():
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    for provenance in (metadata["provenance"], logs[0].eval.metadata["provenance"]):
        provenance["prompts"] = {"another-defense": "a" * 64}
    with pytest.raises(ValueError, match="selected-defense prompt hash"):
        validate_logs(logs, metadata)


def test_native_log_cannot_claim_a_different_protocol_even_if_both_copies_agree():
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    metadata["provenance"]["tools"]["protocol"] = "reviewboundary.jsonl/1"
    for log in logs:
        log.eval.metadata["provenance"]["tools"]["protocol"] = "reviewboundary.jsonl/1"
    with pytest.raises(ValueError, match="inspect tool protocol"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("location", ["sample", "event"])
def test_recorded_system_text_must_match_claimed_hash(location):
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    sample = logs[0].samples[0]
    messages = sample.messages if location == "sample" else sample.events[0].input
    messages[0].content += " Changed instruction."
    with pytest.raises(ValueError, match="recorded system prompt hash"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("location", ["sample", "event"])
@pytest.mark.parametrize("operation", ["missing", "duplicate"])
def test_missing_or_additional_system_messages_cannot_hide_changed_instructions(
    location, operation
):
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    sample = logs[0].samples[0]
    messages = sample.messages if location == "sample" else sample.events[0].input
    if operation == "missing":
        del messages[0]
    else:
        messages.append(ChatMessageSystem(content="Additional policy"))
    with pytest.raises(ValueError, match="exactly one task system message"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("missing", [False, True])
def test_system_prompt_attachment_references_are_checked_without_log_mutation(missing):
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    sample = logs[0].samples[0]
    text = sample.events[0].input[0].content
    sample.events[0].input[0].content = "attachment://recorded-prompt"
    if not missing:
        sample.attachments["recorded-prompt"] = text
    before = sample.model_dump_json()
    if missing:
        with pytest.raises(ValueError, match="prompt attachment is missing"):
            validate_logs(logs, metadata)
    else:
        assert validate_logs(logs, metadata) is None
    assert sample.model_dump_json() == before


def test_each_generation_tool_schema_is_checked():
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    sample = logs[0].samples[0]
    sample.events.append(deepcopy(sample.events[0]))
    sample.events[1].tools[0].description += " Changed tool."
    with pytest.raises(ValueError, match="generation 2 tool schema hash"):
        validate_logs(logs, metadata)


def test_undeclared_reviewer_source_remains_unknown():
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    unknown = {"status": "not_recorded", "sha256": None, "files": {}}
    metadata["provenance"]["reviewer_source"] = unknown
    for log in logs:
        log.eval.metadata["provenance"]["reviewer_source"] = deepcopy(unknown)
    result = validate_logs(logs, metadata, verify_scores=True)["provenance_verification"]
    assert result["status"] == "partial"
    assert result["unknown_source_fields"] == ["reviewer_source"]
    assert metadata["provenance"]["reviewer_source"] == unknown


def test_pre_prompt_error_is_unobserved_not_falsely_verified():
    logs, metadata = experiment()
    add_provenance(logs, metadata)
    sample = logs[0].samples[0]
    sample.messages = []
    sample.events = []
    sample.scores = None
    sample.error = EvalError(message="Setup error", traceback="", traceback_ansi="")
    result = validate_logs(logs, metadata, verify_scores=True)
    assert result["status"] == "partial"
    provenance = result["provenance_verification"]
    assert provenance["status"] == "partial"
    assert provenance["unobserved_prompt_samples"] == 1
    assert provenance["samples_without_model_events"] == 1
    assert provenance["verified_prompt_samples"] == 7


def test_new_prompt_text_with_matching_fingerprints_is_valid_historical_evidence():
    logs, metadata = experiment(groups=(("reviewer", "baseline"),))
    add_provenance(logs, metadata)
    text = "A historical prompt different from the installed runner."
    metadata["provenance"]["prompts"]["baseline"] = text_digest(text)
    logs[0].eval.metadata["provenance"]["prompts"]["baseline"] = text_digest(text)
    for sample in logs[0].samples:
        sample.messages[0].content = text
        sample.events[0].input[0].content = text
    assert (
        validate_logs(logs, metadata, verify_scores=True)["provenance_verification"]["status"]
        == "verified"
    )


def test_missing_case_schema_fields_are_not_backfilled_as_v2():
    logs, metadata = experiment()
    del logs[0].samples[0].metadata["case"]["source_path"]
    with pytest.raises(ValueError, match="complete case schema"):
        validate_logs(logs, metadata)


def test_different_task_case_arguments_are_rejected():
    logs, metadata = experiment()
    logs[0].eval.task_args_passed["cases"][0]["assumptions"] = "Different task arguments"
    with pytest.raises(ValueError, match="task case arguments"):
        validate_logs(logs, metadata)


@pytest.mark.parametrize("field,value", [("split", "heldout"), ("language", "rust")])
def test_case_partition_must_match_manifest(field, value):
    logs, metadata = experiment()
    metadata[field] = value
    with pytest.raises(ValueError, match=field):
        validate_logs(logs, metadata)


def test_changed_manifest_suite_digest_does_not_relabel_logs():
    logs, metadata = experiment()
    metadata["suite_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="suite_sha256"):
        validate_logs(logs, metadata)


def test_out_of_range_epoch_is_rejected():
    logs, metadata = experiment()
    logs[0].samples[0].epoch = 99
    with pytest.raises(ValueError, match="absent from expected_samples"):
        validate_logs(logs, metadata)


def test_task_epoch_configuration_must_match_manifest():
    logs, metadata = experiment()
    logs[0].eval.config.epochs = 1
    with pytest.raises(ValueError, match="epochs does not match"):
        validate_logs(logs, metadata)


def test_dataset_ids_must_match_manifest():
    logs, metadata = experiment()
    logs[0].eval.dataset.sample_ids.pop()
    with pytest.raises(ValueError, match="dataset sample_ids"):
        validate_logs(logs, metadata)
