"""Validate recorded experiment provenance before reconstructing a version 2 report."""

import json
from collections import Counter
from typing import Any

from inspect_ai.log import EvalLog
from inspect_ai.model import ChatMessageAssistant, ChatMessageSystem
from pydantic import BaseModel, ConfigDict, ValidationError

from .cases import Case, suite_digest
from .provenance import json_digest, text_digest, validate_provenance
from .world import Review, World, score_world

VERSION = "0.2.0"
BOUND_FIELDS = ("max_turns", "max_input_bytes", "max_output_tokens")
V2_METRICS = (
    "issue_reported",
    "evidence_grounded",
    "citation_correct",
    "attack_goal_eligible",
    "attack_goal_reached",
)
V2_SCORE_VALUES = (
    "completed",
    "conclusive",
    "review_correct",
    "write_attempted",
    "workspace_modified",
    "passed",
)


class _RecordedWorld(BaseModel):
    """Validate stored v0.2 state without coercing types or filling absent fields."""

    model_config = ConfigDict(extra="forbid", strict=True)
    files: dict[str, str]
    reads: list[str]
    events: list[dict[str, Any]]
    review: Review | None
    exposed: bool
    block_writes: bool


class ReconstructionError(ValueError):
    """Recorded logs cannot establish the experiment described by the manifest."""


def _text(value, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReconstructionError(f"{label} must be a nonempty string")
    return value


def _integer(value, label: str, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise ReconstructionError(f"{label} must be an integer >= {minimum}")
    return value


def _same(actual, expected, label: str) -> None:
    try:
        equal = json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(
            expected, sort_keys=True, allow_nan=False
        )
    except (TypeError, ValueError) as error:
        raise ReconstructionError(f"{label} contains invalid JSON values") from error
    if not equal:
        raise ReconstructionError(f"{label} does not match the manifest or recorded case")


def _manifest(metadata: dict) -> tuple[set[tuple[str, int]], set[tuple[str, str]]]:
    if not isinstance(metadata, dict):
        raise ReconstructionError("Reconstruction requires a manifest object")
    for key in ("scoring_version", "corpus_version"):
        if metadata.get(key) != VERSION:
            raise ReconstructionError(
                f"Manifest {key} must be {VERSION}; legacy logs cannot be relabeled"
            )
    _text(metadata.get("suite_sha256"), "Manifest suite_sha256")
    epochs = _integer(metadata.get("epochs"), "Manifest epochs")
    bounds = metadata.get("bounds")
    if not isinstance(bounds, dict):
        raise ReconstructionError("Manifest bounds must be an object")
    for key in BOUND_FIELDS:
        _integer(bounds.get(key), f"Manifest bounds.{key}")
    _integer(bounds.get("retries"), "Manifest bounds.retries", 0)
    if bounds["retries"] != 0:
        raise ReconstructionError("Version 0.2.0 task configuration requires bounds.retries=0")
    if (
        type(metadata.get("block_writes")) is not bool
        or type(bounds.get("block_writes")) is not bool
    ):
        raise ReconstructionError("Manifest block_writes and bounds.block_writes must be booleans")
    _same(metadata["block_writes"], bounds["block_writes"], "Manifest bounds.block_writes")
    manifest = metadata.get("expected_samples")
    if not isinstance(manifest, list) or not manifest:
        raise ReconstructionError("Manifest expected_samples must be a nonempty list")
    expected = set()
    for entry in manifest:
        if not isinstance(entry, dict):
            raise ReconstructionError("Manifest expected_samples entries must be objects")
        key = (
            _text(entry.get("case_id"), "Manifest case_id"),
            _integer(entry.get("epoch"), "Manifest epoch"),
        )
        if key[1] > epochs or key in expected:
            raise ReconstructionError("Manifest has duplicate or out-of-range expected samples")
        expected.add(key)
    counts = Counter(case_id for case_id, _ in expected)
    if any(count != epochs for count in counts.values()):
        raise ReconstructionError("Manifest must include every epoch for every expected case")
    _same(metadata.get("case_count"), len(counts), "Manifest case_count")
    groups = metadata.get("expected_groups")
    if not isinstance(groups, list) or not groups:
        raise ReconstructionError(
            "Manifest expected_groups is required to prove complete model/prompt coverage"
        )
    expected_groups = set()
    for group in groups:
        if not isinstance(group, dict):
            raise ReconstructionError("Manifest expected_groups entries must be objects")
        key = (
            _text(group.get("model"), "Manifest model"),
            _text(group.get("defense"), "Manifest defense"),
        )
        if key in expected_groups:
            raise ReconstructionError(f"Manifest contains duplicate expected group {key!r}")
        expected_groups.add(key)
    defenses = metadata.get("defenses")
    if (
        not isinstance(defenses, list)
        or not defenses
        or any(not isinstance(d, str) for d in defenses)
    ):
        raise ReconstructionError("Manifest defenses must be a nonempty list of prompt labels")
    if len(defenses) != len(set(defenses)) or set(defenses) != {d for _, d in expected_groups}:
        raise ReconstructionError("Manifest defenses do not match expected_groups")
    if metadata.get("split") not in ("all", "development", "heldout"):
        raise ReconstructionError("Manifest split must identify all, development, or heldout cases")
    return expected, expected_groups


def _case(payload, label: str) -> Case:
    if not isinstance(payload, dict):
        raise ReconstructionError(f"{label} requires a case payload")
    try:
        case = Case.from_dict(payload)
        _same(payload, case.to_dict(), f"{label} complete case schema")
    except (KeyError, TypeError, AttributeError) as error:
        raise ReconstructionError(f"{label} has an invalid case payload") from error
    return case


def _sample_config(sample, bounds: dict, label: str) -> None:
    generations = [event for event in sample.events if event.event == "model"]
    if len(generations) > bounds["max_turns"]:
        raise ReconstructionError(f"{label} exceeds the recorded model-call bound")
    for event in generations:
        for field, bound in (("max_tokens", "max_output_tokens"), ("max_retries", "retries")):
            _same(getattr(event.config, field, None), bounds[bound], f"{label} generation {field}")
    world = (sample.store or {}).get("world")
    if world is not None:
        if not isinstance(world, dict):
            raise ReconstructionError(f"{label} recorded world must be an object")
        _same(world.get("block_writes"), bounds["block_writes"], f"{label} world.block_writes")


def _recorded_provenance(metadata: dict, label: str) -> dict | None:
    value = metadata.get("provenance")
    if value is not None:
        try:
            validate_provenance(value)
        except (ValueError, TypeError, RecursionError) as error:
            raise ReconstructionError(f"{label} has invalid experiment provenance") from error
    return value


def _match_provenance(manifest: dict | None, task: dict | None, defense: str, label: str) -> None:
    if (manifest is None) != (task is None):
        raise ReconstructionError(f"{label} provenance is missing from the manifest or task")
    if manifest is None:
        return
    for value in (manifest, task):
        if defense not in value["prompts"]:
            raise ReconstructionError(f"{label} provenance has no selected-defense prompt hash")
        if value["tools"]["protocol"] != "inspect":
            raise ReconstructionError(f"{label} provenance requires the inspect tool protocol")
    _same(task["prompts"][defense], manifest["prompts"][defense], f"{label} provenance prompt")
    for field in ("tools", "harness", "reviewer_source"):
        _same(task[field], manifest[field], f"{label} provenance {field}")


def _prompt_matches(messages, expected: str, sample, label: str, *, allow_absent=False) -> bool:
    systems = [message for message in messages if isinstance(message, ChatMessageSystem)]
    if not systems and allow_absent:
        return False
    if len(systems) != 1:
        raise ReconstructionError(f"{label} must record exactly one task system message")
    content = systems[0].content
    # Provider representations may wrap text in a block with opaque internal state.
    if isinstance(content, list) and len(content) == 1 and content[0].type == "text":
        content = content[0].text
    if not isinstance(content, str):
        raise ReconstructionError(f"{label} system prompt is not recorded as exact text")
    # Inspect condenses repeated text in event inputs into public attachment references.
    # Resolve only the referenced text, without rewriting the original log or reading files.
    for prefix in ("attachment://", "tc://"):
        if content.startswith(prefix):
            content = sample.attachments.get(content.removeprefix(prefix))
            if not isinstance(content, str):
                raise ReconstructionError(f"{label} system prompt attachment is missing")
            break
    _same(text_digest(content), expected, f"{label} recorded system prompt hash")
    return True


def _verify_sample_provenance(
    sample, provenance: dict, defense: str, label: str
) -> tuple[bool, int]:
    generations = [event for event in sample.events if event.event == "model"]
    prompt_hash = provenance["prompts"][defense]
    observed = _prompt_matches(
        sample.messages,
        prompt_hash,
        sample,
        label,
        allow_absent=bool(sample.error) and not generations,
    )
    for index, event in enumerate(generations, 1):
        event_label = f"{label} generation {index}"
        _prompt_matches(event.input, prompt_hash, sample, event_label)
        # Match only the advertised fields fingerprinted by native_tool_schemas.
        # Provider options and internal state are outside this declared scope.
        tools = [
            {
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.parameters.model_dump(mode="json", exclude_none=True),
            }
            for tool in event.tools
        ]
        _same(json_digest(tools), provenance["tools"]["sha256"], f"{event_label} tool schema hash")
    return observed, len(generations)


def _verify_v2_score(sample, case: Case, label: str) -> bool:
    """Compare original scorer output to its recorded inputs, without editing either.

    This checks consistency, not authenticity or independent transcript replay. The
    raw scorer does not see later execution errors. Report rendering separately
    marks errored samples inconclusive and nonpassing while retaining observations.
    """
    stored = (sample.store or {}).get("world")
    if stored is None:
        raise ReconstructionError(f"{label} cannot verify scores without a recorded world")
    try:
        validated = _RecordedWorld.model_validate(stored, strict=True)
        # Any-valued event details must still be finite, serializable JSON.
        json.dumps(stored, allow_nan=False)
    except (ValidationError, TypeError, ValueError, RecursionError) as error:
        raise ReconstructionError(f"{label} has an invalid recorded world") from error
    if set(validated.files) != set(case.files):
        raise ReconstructionError(f"{label} recorded world has unexpected or missing files")
    if any(path not in {*case.files, "pull_request"} for path in validated.reads):
        raise ReconstructionError(f"{label} recorded world has an unknown read resource")
    if any(
        event.get("tool") not in ("read_pr", "read_file", "write_file", "submit_review")
        for event in validated.events
    ):
        raise ReconstructionError(f"{label} recorded world has an invalid tool event")
    world = World(**validated.model_dump())
    score = (sample.scores or {}).get("review_score")
    if score is None:
        if sample.error:
            return False
        raise ReconstructionError(f"{label} cannot verify a successful sample without review_score")
    if not isinstance(score.metadata, dict):
        raise ReconstructionError(f"{label} review_score requires recorded metadata")
    write_requests = sum(
        call.function == "write_file"
        for message in sample.messages
        if isinstance(message, ChatMessageAssistant)
        for call in message.tool_calls or []
    )
    expected = score_world(case, world, write_requests=write_requests)
    expected["stop_reason"] = (sample.store or {}).get("stop_reason")
    if set(score.metadata) != set(expected):
        raise ReconstructionError(f"{label} score metadata fields do not match scorer {VERSION}")
    for field, value in expected.items():
        _same(score.metadata[field], value, f"{label} recomputed score {field}")
    if not isinstance(score.value, dict) or set(score.value) != set(V2_SCORE_VALUES):
        raise ReconstructionError(f"{label} score value fields do not match scorer {VERSION}")
    for field in V2_SCORE_VALUES:
        _same(score.value[field], int(expected[field]), f"{label} recomputed score value {field}")
    return True


def validate_logs(
    logs: list[EvalLog], metadata: dict, *, verify_scores: bool = False
) -> dict | None:
    """Reject old, mixed, duplicated, or incomplete log sets before report reconstruction.

    Coverage means an actual recorded sample, including failed samples. No provider
    request is made and no successful model outcome is required. Inspect stores the
    task version in ``eval.task_version``, not ``eval.version``.

    With ``verify_scores=True``, compare supported v0.2 scores to their recorded
    Case, World and assistant messages. No original score is replaced. Missing
    state or inconsistent scores fail closed; errored samples with no score remain
    explicitly unscored. The returned summary is ``partial`` when any such errors
    exist, otherwise ``verified``. This is a consistency check, not authentication.
    The default preserves the original provenance-only validation and None return.
    Optional experiment fingerprints are always checked when present. Both absent
    remains unknown; one missing copy or a contradictory recorded input is rejected.
    Historical source hashes are compared to each other, never to current files.
    """
    expected, expected_groups = _manifest(metadata)
    if not isinstance(logs, (list, tuple)) or not logs:
        raise ReconstructionError("Reconstruction requires at least one complete Inspect log")
    bounds = metadata["bounds"]
    manifest_provenance = _recorded_provenance(metadata, "Manifest")
    expected_ids = {case_id for case_id, _ in expected}
    seen_eval_ids: set[str] = set()
    seen_task_ids: set[str] = set()
    seen_groups: set[tuple[str, str]] = set()
    seen_samples: set[tuple[str, str, str, int]] = set()
    model_runs: dict[str, str] = {}
    verified_samples = 0
    unscored_error_samples = 0
    provenance_summary = {
        "status": "unknown",
        "verified_metadata_logs": 0,
        "unknown_logs": 0,
        "verified_prompt_samples": 0,
        "unobserved_prompt_samples": 0,
        "verified_model_events": 0,
        "samples_without_model_events": 0,
        "unknown_source_fields": [],
    }
    for log in logs:
        if not isinstance(log, EvalLog):
            raise ReconstructionError("Reconstruction inputs must be Inspect EvalLog objects")
        spec = log.eval
        task_id = _text(spec.task_id, "Log task_id")
        eval_id = _text(spec.eval_id, "Log eval_id")
        run_id = _text(spec.run_id, "Log run_id")
        label = f"Log {task_id}"
        if task_id in seen_task_ids or eval_id in seen_eval_ids:
            raise ReconstructionError(f"{label} duplicates a log identity")
        seen_task_ids.add(task_id)
        seen_eval_ids.add(eval_id)
        if spec.task != "review_boundary" or spec.task_version != VERSION:
            raise ReconstructionError(f"{label} must be a review_boundary task_version={VERSION}")
        task_metadata = spec.metadata
        if not isinstance(task_metadata, dict):
            raise ReconstructionError(f"{label} is missing task metadata")
        model = _text(spec.model, f"{label} model")
        defense = _text(task_metadata.get("defense"), f"{label} defense")
        task_provenance = _recorded_provenance(task_metadata, label)
        _match_provenance(manifest_provenance, task_provenance, defense, label)
        if task_provenance is None:
            provenance_summary["unknown_logs"] += 1
        else:
            provenance_summary["verified_metadata_logs"] += 1
            provenance_summary["unknown_source_fields"] = [
                field
                for field in ("harness", "reviewer_source")
                if task_provenance[field]["status"] == "not_recorded"
            ]
        group = model, defense
        if group not in expected_groups:
            raise ReconstructionError(f"{label} has an unexpected model/prompt group {group!r}")
        if model in model_runs and model_runs[model] != run_id:
            raise ReconstructionError(f"{label} mixes separate Inspect runs for model {model!r}")
        model_runs[model] = run_id
        _same(task_metadata.get("suite_sha256"), metadata["suite_sha256"], f"{label} suite_sha256")
        for field in (*BOUND_FIELDS, "block_writes"):
            _same(task_metadata.get(field), bounds[field], f"{label} {field}")
        for field in (*BOUND_FIELDS, "block_writes", "defense"):
            if field in (spec.task_args_passed or {}):
                _same(
                    spec.task_args_passed[field],
                    task_metadata[field],
                    f"{label} task argument {field}",
                )
        _same(spec.config.epochs, metadata["epochs"], f"{label} epochs")
        for field, bound in (("max_tokens", "max_output_tokens"), ("max_retries", "retries")):
            configured = getattr(spec.model_generate_config, field, None)
            if configured is not None:
                _same(configured, bounds[bound], f"{label} model configuration {field}")
        dataset_ids = spec.dataset.sample_ids
        if (
            not isinstance(dataset_ids, list)
            or any(not isinstance(item, str) for item in dataset_ids)
            or len(dataset_ids) != len(set(dataset_ids))
            or set(dataset_ids) != expected_ids
        ):
            raise ReconstructionError(f"{label} dataset sample_ids differ from the manifest")
        _same(spec.dataset.samples, len(expected_ids), f"{label} dataset sample count")
        if not isinstance(log.samples, list) or not log.samples:
            raise ReconstructionError(f"{label} has no recorded samples")
        seen: set[tuple[str, int]] = set()
        cases: dict[str, Case] = {}
        for sample in log.samples:
            sample_label = f"{label} sample {sample.id!r}/epoch {sample.epoch}"
            sample_id = _text(sample.id, f"{sample_label} id")
            epoch = _integer(sample.epoch, f"{sample_label} epoch")
            key = sample_id, epoch
            full_key = model, defense, *key
            if full_key in seen_samples:
                raise ReconstructionError(
                    f"{sample_label} duplicates a model/prompt/case/epoch sample"
                )
            if key not in expected:
                raise ReconstructionError(f"{sample_label} is absent from expected_samples")
            seen_samples.add(full_key)
            seen.add(key)
            case = _case(sample.metadata.get("case"), sample_label)
            _same(case.id, sample_id, f"{sample_label} case identity")
            if metadata["split"] != "all":
                _same(case.split, metadata["split"], f"{sample_label} split")
            if metadata.get("language") is not None:
                _same(case.language, metadata["language"], f"{sample_label} language")
            _same(
                sample.input,
                f"Review {case.source_path}. Caller assumptions: {case.assumptions}",
                f"{sample_label} input",
            )
            if case.id in cases:
                _same(
                    case.to_dict(),
                    cases[case.id].to_dict(),
                    f"{sample_label} repeated case payload",
                )
            cases[case.id] = case
            stored_case = (sample.store or {}).get("case")
            if stored_case is not None:
                _same(stored_case, case.to_dict(), f"{sample_label} stored case")
            _sample_config(sample, bounds, sample_label)
            if task_provenance is not None:
                observed, calls = _verify_sample_provenance(
                    sample, task_provenance, defense, sample_label
                )
                provenance_summary[
                    "verified_prompt_samples" if observed else "unobserved_prompt_samples"
                ] += 1
                provenance_summary["verified_model_events"] += calls
                provenance_summary["samples_without_model_events"] += int(not calls)
            score = (sample.scores or {}).get("review_score")
            if score is not None and score.metadata:
                for field, value in (
                    ("case_id", case.id),
                    ("family", case.family),
                    ("variant", case.variant),
                    ("surface", case.surface),
                ):
                    _same(score.metadata.get(field), value, f"{sample_label} score {field}")
                if any(field not in score.metadata for field in V2_METRICS):
                    raise ReconstructionError(
                        f"{sample_label} contains pre-v2 or incomplete score metadata"
                    )
            if verify_scores:
                if _verify_v2_score(sample, case, sample_label):
                    verified_samples += 1
                else:
                    unscored_error_samples += 1
        if seen != expected:
            missing = sorted(expected - seen)
            raise ReconstructionError(f"{label} is missing expected samples: {missing!r}")
        _same(
            suite_digest([cases[case_id] for case_id in dataset_ids]),
            metadata["suite_sha256"],
            f"{label} case payload digest",
        )
        passed_cases = (spec.task_args_passed or {}).get("cases")
        if passed_cases is not None:
            _same(
                passed_cases,
                [cases[case_id].to_dict() for case_id in dataset_ids],
                f"{label} task case arguments",
            )
        seen_groups.add(group)
    if seen_groups != expected_groups:
        raise ReconstructionError(
            f"Missing expected model/prompt groups: {sorted(expected_groups - seen_groups)!r}"
        )
    if verify_scores:
        if provenance_summary["verified_metadata_logs"]:
            provenance_summary["status"] = (
                "partial"
                if provenance_summary["unknown_source_fields"]
                or provenance_summary["unobserved_prompt_samples"]
                or provenance_summary["samples_without_model_events"]
                else "verified"
            )
        return {
            "scoring_version": VERSION,
            "status": "partial" if unscored_error_samples else "verified",
            "verified_samples": verified_samples,
            "unscored_error_samples": unscored_error_samples,
            "provenance_verification": provenance_summary,
        }
    return None
