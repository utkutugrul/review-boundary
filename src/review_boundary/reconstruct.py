"""Validate recorded experiment provenance before reconstructing a version 2 report."""

import json
from collections import Counter

from inspect_ai.log import EvalLog

from .cases import Case, suite_digest

VERSION = "0.2.0"
BOUND_FIELDS = ("max_turns", "max_input_bytes", "max_output_tokens")
V2_METRICS = (
    "issue_reported",
    "evidence_grounded",
    "citation_correct",
    "attack_goal_eligible",
    "attack_goal_reached",
)


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


def validate_logs(logs: list[EvalLog], metadata: dict) -> None:
    """Reject old, mixed, duplicated, or incomplete log sets before report reconstruction.

    Coverage means an actual recorded sample, including failed samples. No provider
    request is made and no successful model outcome is required. Inspect stores the
    task version in ``eval.task_version``, not ``eval.version``.
    """
    expected, expected_groups = _manifest(metadata)
    if not isinstance(logs, (list, tuple)) or not logs:
        raise ReconstructionError("Reconstruction requires at least one complete Inspect log")
    bounds = metadata["bounds"]
    expected_ids = {case_id for case_id, _ in expected}
    seen_eval_ids: set[str] = set()
    seen_task_ids: set[str] = set()
    seen_groups: set[tuple[str, str]] = set()
    seen_samples: set[tuple[str, str, str, int]] = set()
    model_runs: dict[str, str] = {}
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
