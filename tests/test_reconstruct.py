"""Reconstruction must preserve the experiment recorded by actual Inspect log types."""

from copy import deepcopy

import pytest
from inspect_ai.event import ModelEvent
from inspect_ai.log import EvalConfig, EvalDataset, EvalError, EvalLog, EvalSample, EvalSpec
from inspect_ai.model import GenerateConfig, ModelOutput
from inspect_ai.scorer import Score

from review_boundary.cases import build_cases, suite_digest
from review_boundary.reconstruct import validate_logs
from review_boundary.world import World, score_world


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
                samples.append(
                    EvalSample(
                        id=case.id,
                        epoch=epoch,
                        input=f"Review {case.source_path}. Caller assumptions: {case.assumptions}",
                        target="",
                        metadata={"case": case.to_dict()},
                        store={"case": case.to_dict(), "world": world.to_dict()},
                        scores={"review_score": Score(value=1, metadata=score_world(case, world))},
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
