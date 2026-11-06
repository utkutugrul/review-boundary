"""Run fixed reviewer evaluations against a validated, data-only CI baseline."""

import json
import math
import os
import re
import stat
import sys
from pathlib import Path

from .cases import build_cases, suite_digest
from .compare import compare_reports
from .json_input import MAX_REPORT_BYTES, parse_json_object

VERSION = "0.2.0"
BOUND_FIELDS = {"max_turns", "max_input_bytes", "max_output_tokens", "block_writes", "retries"}
MESSAGES = {
    "baseline_invalid": "The baseline is missing, invalid, or incompatible with this test suite.",
    "configuration_invalid": "The CI reviewer configuration is invalid.",
    "evaluation_failed": "The evaluation failed. Any recorded candidate evidence is retained.",
    "candidate_invalid": "The candidate report is missing or invalid.",
    "comparison_invalid": "The candidate and baseline could not be compared safely.",
    "artifact_write_failed": "The CI result artifacts could not be written completely.",
}


class CIError(ValueError):
    """CI input cannot be used for the fixed evaluation workflow."""


def _safe_path(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    # Check every existing component before resolve can hide a symlink.
    for component in (*reversed(path.parents), path):
        try:
            if stat.S_ISLNK(component.lstat().st_mode):
                raise CIError("Symlink paths are not accepted for CI inputs or outputs")
        except FileNotFoundError:
            continue
    return path


def _read_json(value: str | Path) -> dict:
    path = _safe_path(value)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
        raise CIError("CI input must be a regular JSON file no larger than 32 MiB")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise CIError("CI input changed or exceeded the file size limit")
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise CIError("CI input exceeds the file size limit")
    return parse_json_object(raw)


def repository_file(root: Path, relative: str) -> Path:
    """Select a bounded regular data file inside a checked-out repository."""
    if (
        not isinstance(relative, str)
        or not relative
        or len(relative) > 1024
        or "\\" in relative
        or any(ord(char) < 32 for char in relative)
        or Path(relative).is_absolute()
        or ".." in Path(relative).parts
        or ":" in relative
    ):
        raise CIError("Repository data paths must be bounded relative paths without traversal")
    directory = _safe_path(root)
    if not directory.is_dir():
        raise CIError("The repository root must be an existing directory")
    selected = _safe_path(directory / relative)
    if not selected.resolve(strict=True).is_relative_to(directory.resolve(strict=True)):
        raise CIError("The selected data file is outside the repository")
    info = selected.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
        raise CIError("Repository data must be a regular file no larger than 32 MiB")
    return selected


def _baseline(path, model, defense):
    baseline = _read_json(path)
    checked = compare_reports(
        baseline,
        baseline,
        baseline_model=model,
        baseline_defense=defense,
        candidate_model=model,
        candidate_defense=defense,
    )
    metadata = baseline["metadata"]
    if metadata["scoring_version"] != VERSION or metadata["corpus_version"] != VERSION:
        raise CIError("The baseline uses an unsupported scoring or corpus version")
    if metadata["split"] not in ("all", "development", "heldout"):
        raise CIError("The baseline split is unsupported")
    bounds = metadata["bounds"]
    if set(bounds) != BOUND_FIELDS or type(bounds.get("block_writes")) is not bool:
        raise CIError("The baseline execution bounds cannot be reproduced")
    for field, low, high in (
        ("max_turns", 1, 32),
        ("max_input_bytes", 1024, 100000),
        ("max_output_tokens", 128, 8192),
        ("retries", 0, 0),
    ):
        if type(bounds[field]) is not int or not low <= bounds[field] <= high:
            raise CIError("The baseline execution bounds are unsupported")
    if not 1 <= metadata["epochs"] <= 20:
        raise CIError("The baseline trial count is unsupported")
    if "block_writes" in metadata and metadata["block_writes"] != bounds["block_writes"]:
        raise CIError("The baseline write policy is inconsistent")
    selected_ids = {entry["case_id"] for entry in metadata["expected_samples"]}
    cases = [case for case in build_cases(split=metadata["split"]) if case.id in selected_ids]
    if {case.id for case in cases} != selected_ids or suite_digest(cases) != metadata[
        "suite_sha256"
    ]:
        raise CIError("The baseline does not match the available original fixtures")
    case_by_id = {case.id: case for case in cases}
    group = checked["baseline_group"]
    for row in baseline["rows"]:
        if (row["model"], row["defense"]) != (group["model"], group["defense"]):
            continue
        case = case_by_id[row["case_id"]]
        if any(row[field] != getattr(case, field) for field in ("family", "variant", "surface")):
            raise CIError("The baseline case descriptors do not match the original fixtures")
        eligible = case.surface == "tool_output" or (
            case.surface in ("pr_body", "readme", "code_comment") and case.variant == "vulnerable"
        )
        if row["attack_goal_eligible"] != eligible:
            raise CIError("The baseline attack eligibility does not match the original fixtures")
    return baseline, cases, group


def _arguments(metadata, output, *, mode, provider, model, defense, pricing_file, budget):
    if mode not in ("calibration", "model") or provider not in (
        "openrouter",
        "openai",
        "anthropic",
    ):
        raise CIError("Unsupported CI mode or provider")
    if defense not in ("baseline", "explicit"):
        raise CIError("Unsupported candidate prompt")
    if type(budget) not in (float, int) or not math.isfinite(budget) or budget <= 0:
        raise CIError("The budget must be a positive finite number")
    if mode == "model" and (
        not isinstance(model, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,255}", model) is None
    ):
        raise CIError("Model mode requires an explicit model ID")
    if mode == "calibration" and (model is not None or pricing_file is not None):
        raise CIError("Calibration only runs the fixed reference reviewer")
    if mode == "model" and provider != "openrouter" and pricing_file is None:
        raise CIError("Direct providers require a dated pricing file")
    if pricing_file is not None:
        _read_json(pricing_file)
    bounds = metadata["bounds"]
    arguments = [
        "demo" if mode == "calibration" else "run",
        "--output",
        str(output / "candidate"),
        "--split",
        metadata["split"],
        "--epochs",
        str(metadata["epochs"]),
        "--defense",
        defense,
        "--max-turns",
        str(bounds["max_turns"]),
        "--max-input-bytes",
        str(bounds["max_input_bytes"]),
        "--max-output-tokens",
        str(bounds["max_output_tokens"]),
    ]
    if bounds["block_writes"]:
        arguments.append("--block-writes")
    if mode == "calibration":
        arguments.extend(["--mode", "reference"])
    else:
        arguments.extend(
            [
                "--provider",
                provider,
                "--model",
                model,
                "--budget",
                str(budget),
                "--ledger",
                str(output / "budget.json"),
            ]
        )
        if pricing_file is not None:
            arguments.extend(["--pricing-file", str(_safe_path(pricing_file))])
    return arguments


def _summary(result: dict) -> str:
    lines = ["# ReviewBoundary CI", "", f"**{result['status'].upper()}**", "", result["message"]]
    counts = result.get("counts")
    if counts:
        lines.extend(
            [
                "",
                f"Expected samples: {counts['expected_samples']}",
                f"Paired samples: {counts['paired_samples']}",
                f"Regressed samples: {counts['regressed_samples']}",
                f"Improved samples: {counts['improved_samples']}",
                f"Unchanged passing samples: {counts['unchanged_passing_samples']}",
                f"Unchanged nonpassing samples: {counts['unchanged_nonpassing_samples']}",
                f"Citation changes: {counts['citation_changes']} (informational)",
                "",
                "| Measurement | Baseline | Candidate |",
                "| --- | ---: | ---: |",
            ]
        )
        for key, label in (
            ("completed", "Completed reviews"),
            ("conclusive", "Conclusive samples"),
            ("review_correct", "Correct reviews"),
            ("write_attempted", "Write attempts"),
            ("workspace_modified", "Modified workspaces"),
            ("errors", "Execution errors"),
        ):
            lines.append(f"| {label} | {counts['baseline'][key]} | {counts['candidate'][key]} |")
    lines.extend(
        [
            "",
            "Download the run artifacts to inspect the candidate report and recorded evidence.",
            "A passing comparison does not certify safety or erase existing baseline failures.",
        ]
    )
    return "\n".join(lines) + "\n"


def _finish(output: Path, *, code: int, error_code=None, comparison=None) -> int:
    result = {
        "ci_schema_version": 1,
        "status": "error" if code == 2 else ("regression" if code else "pass"),
        "exit_code": code,
        "error_code": error_code,
        "message": MESSAGES[error_code]
        if error_code
        else (
            "New regressions were observed in the selected samples."
            if code
            else "No new regressions were observed in the selected samples."
        ),
        "counts": comparison["summary"] if comparison else None,
    }
    comparison_created = False
    created: set[str] = set()
    try:
        with (output / "ci-result.json").open("x") as stream:
            created.add("ci-result.json")
            stream.write(json.dumps(result, indent=2) + "\n")
        with (output / "summary.md").open("x") as stream:
            created.add("summary.md")
            stream.write(_summary(result))
        if comparison is not None:
            with (output / "comparison.json").open("x") as stream:
                comparison_created = True
                stream.write(json.dumps(comparison, indent=2) + "\n")
    except OSError:
        if comparison_created:
            try:
                (output / "comparison.json").unlink()
            except OSError:
                pass
        result.update(
            status="error",
            exit_code=2,
            error_code="artifact_write_failed",
            message=MESSAGES["artifact_write_failed"],
        )
        for name, content in (
            ("ci-result.json", json.dumps(result, indent=2) + "\n"),
            ("summary.md", _summary(result)),
        ):
            try:
                path = _safe_path(output / name)
                with path.open("w" if name in created else "x") as stream:
                    stream.write(content)
            except (OSError, ValueError):
                continue
        print("ReviewBoundary CI: result artifacts could not be written.", file=sys.stderr)
        return 2
    return code


def run_ci(
    baseline_path: str | Path,
    output: str | Path,
    *,
    mode: str = "calibration",
    provider: str = "openrouter",
    model: str | None = None,
    defense: str = "baseline",
    baseline_model: str | None = None,
    baseline_defense: str | None = None,
    pricing_file: str | Path | None = None,
    budget: float = 20.0,
) -> int:
    """Produce a candidate report and CI evidence without executing caller-supplied code.

    Return 0 for no regression, 1 for a behavioral regression, and 2 for invalid
    input or execution failure. A new safe output directory is required. Handled
    failures retain their evidence and never leave a successful comparison file.
    """
    try:
        directory = _safe_path(output)
        directory.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, TypeError):
        print(
            "ReviewBoundary CI: output must be a new directory without symlink components.",
            file=sys.stderr,
        )
        return 2
    stage = "baseline_invalid"
    try:
        baseline, cases, group = _baseline(baseline_path, baseline_model, baseline_defense)
        stage = "configuration_invalid"
        arguments = _arguments(
            baseline["metadata"],
            directory,
            mode=mode,
            provider=provider,
            model=model,
            defense=defense,
            pricing_file=pricing_file,
            budget=budget,
        )
        # The parser only receives arguments for fixed built-in paths, never adapter commands.
        from .cli import parser, run

        args = parser().parse_args(arguments)
        stage = "evaluation_failed"
        evaluation_code = run(args, cases_override=cases)
        if type(evaluation_code) is not int or evaluation_code != 0:
            return _finish(directory, code=2, error_code=stage)
        stage = "candidate_invalid"
        candidate = _read_json(directory / "candidate" / "report.json")
        stage = "comparison_invalid"
        comparison = compare_reports(
            baseline,
            candidate,
            baseline_model=group["model"],
            baseline_defense=group["defense"],
            candidate_model="mockllm/calibration-reference"
            if mode == "calibration"
            else f"{provider}/{model}",
            candidate_defense=defense,
        )
        return _finish(directory, code=comparison["exit_code"], comparison=comparison)
    except (Exception, SystemExit):  # noqa: BLE001
        # This CI boundary deliberately omits provider exceptions and untrusted report text.
        return _finish(directory, code=2, error_code=stage)
