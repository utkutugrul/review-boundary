"""Run separately selected trusted model or caller-owned adapter CI profiles."""

import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

from .cases import build_cases, suite_digest
from .compare import compare_reports
from .json_input import MAX_REPORT_BYTES, parse_json_object

VERSION = "0.2.0"
BOUND_FIELDS = {"max_turns", "max_input_bytes", "max_output_tokens", "block_writes", "retries"}
ADAPTER_PROFILES = {"repository-adapter": "repository", "boundary-adapter": "boundary"}
MODEL_PROFILES = {"repository-model": "repository", "boundary-model": "boundary"}
MAX_NATIVE_MODEL_BUDGET_USD = 20.0
ADAPTER_FORBIDDEN_ENV = frozenset(
    {
        "OPENROUTER_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_ADMIN_KEY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "AZURE_OPENAI_API_KEY",
        "GITHUB_APP_PRIVATE_KEY",
        "RB_APP_PRIVATE_KEY",
        "GH_TOKEN",
        "GITHUB_TOKEN",
    }
)
MESSAGES = {
    "baseline_invalid": "The baseline is missing, invalid, or incompatible with this test suite.",
    "configuration_invalid": "The CI reviewer configuration is invalid.",
    "evaluation_failed": "The evaluation failed. Any recorded candidate evidence is retained.",
    "candidate_invalid": "The candidate report is missing or invalid.",
    "comparison_invalid": "The candidate and baseline could not be compared safely.",
    "artifact_write_failed": "The CI result artifacts could not be written completely.",
    "native_model_unsupported": (
        "Native repository/boundary model CI is not supported by adapter profiles. "
        "Use the separate native model runner and data-only comparison."
    ),
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


def _read_json(value: str | Path, *, max_bytes: int = MAX_REPORT_BYTES) -> dict:
    path = _safe_path(value)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
        raise CIError("CI input must be a regular JSON file no larger than 32 MiB")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_bytes:
            raise CIError("CI input changed or exceeded the file size limit")
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
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
    if result.get("report_kind") in ("repository", "boundary"):
        return _native_summary(result)
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
    if comparison and comparison.get("report_kind") in ("repository", "boundary"):
        result["report_kind"] = comparison["report_kind"]
        if "comparison_scope" in comparison:
            result["comparison_scope"] = comparison["comparison_scope"]
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
    profile: str = "legacy",
    suite_path: str | Path | None = None,
    adapter_path: str | Path | None = None,
    baseline_reviewer: str | None = None,
    candidate_reviewer: str | None = None,
    baseline_guard: str | None = None,
    candidate_guard: str | None = None,
    prompt_price_cap: float | None = None,
    completion_price_cap: float | None = None,
) -> int:
    """Produce a candidate report and CI evidence for one explicit profile.

    Return 0 for no regression, 1 for a behavioral regression, and 2 for invalid
    input or execution failure. A new safe output directory is required. Handled
    failures retain their evidence and never leave a successful comparison file.
    Adapter profiles execute trusted caller-owned programs on the current host.
    They require a separate host without provider/App credentials or credential files.
    """
    native_options = {
        "profile": profile,
        "suite_path": suite_path,
        "baseline_reviewer": baseline_reviewer,
        "candidate_reviewer": candidate_reviewer,
        "baseline_guard": baseline_guard,
        "candidate_guard": candidate_guard,
    }
    if profile in MODEL_PROFILES:
        return _run_native_model_ci(
            baseline_path,
            output,
            mode=mode,
            provider=provider,
            model=model,
            defense=defense,
            baseline_model=baseline_model,
            baseline_defense=baseline_defense,
            pricing_file=pricing_file,
            budget=budget,
            adapter_path=adapter_path,
            prompt_price_cap=prompt_price_cap,
            completion_price_cap=completion_price_cap,
            **native_options,
        )
    if profile != "legacy":
        return _run_adapter_ci(
            baseline_path,
            output,
            adapter_path=adapter_path,
            native_model_requested=mode == "model",
            provider_options=(
                mode == "calibration"
                and provider == "openrouter"
                and model is None
                and defense == "baseline"
                and baseline_model is None
                and baseline_defense is None
                and pricing_file is None
                and budget == 20.0
                and prompt_price_cap is None
                and completion_price_cap is None
            ),
            **native_options,
        )
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
        if (
            adapter_path is not None
            or any(value is not None for name, value in native_options.items() if name != "profile")
            or prompt_price_cap is not None
            or completion_price_cap is not None
        ):
            raise CIError("Native adapter options require an explicit adapter profile")
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


def _native_summary(result: dict) -> str:
    """Use fixed labels and computed counts only, never adapter strings or raw rows."""
    lines = ["# ReviewBoundary CI", "", f"**{result['status'].upper()}**", "", result["message"]]
    counts = result["counts"]
    for field, label in (
        ("expected_samples", "Expected samples"),
        ("paired_samples", "Paired samples"),
        ("regressed_samples", "Regressed samples"),
        ("improved_samples", "Improved samples"),
        ("unchanged_samples", "Unchanged samples"),
        ("evidence_availability_changes", "Evidence availability changes (informational)"),
    ):
        lines.append(f"{label}: {counts[field]}")
    lines.extend(
        [
            "",
            "Inspect the native comparison for separate structural, utility and evidence metrics.",
            "Recorded evidence covers the virtual evaluation world only.",
            "A passing gate does not certify safety or authenticate external actions.",
        ]
    )
    return "\n".join(lines) + "\n"


def adapter_environment(environ) -> None:
    """Defense in depth only; the workflow must also separate secret-bearing runners."""
    if any(environ.get(name) for name in ADAPTER_FORBIDDEN_ENV):
        raise CIError("Adapter CI requires a host without provider or App credentials")


def _native_plan(
    baseline_path,
    *,
    profile,
    suite_path,
    baseline_reviewer,
    candidate_reviewer,
    baseline_guard=None,
    candidate_guard=None,
):
    from .boundary_runner import load_boundary_suite
    from .native_compare import compare_report_documents
    from .report_contract import detect_contract, unwrap_report
    from .repository_runner import load_suite
    from .repository_world import RepositoryLimits

    if profile not in ADAPTER_PROFILES or suite_path is None:
        raise CIError("Select a native adapter profile and an explicit bounded suite")
    kind = ADAPTER_PROFILES[profile]
    if not baseline_reviewer or not candidate_reviewer:
        raise CIError("Native CI requires explicit baseline and candidate reviewer selectors")
    if kind == "boundary":
        if baseline_guard not in ("on", "off") or candidate_guard not in ("on", "off"):
            raise CIError("Boundary CI requires explicit baseline and candidate guard selectors")
    elif baseline_guard is not None or candidate_guard is not None:
        raise CIError("Repository CI does not accept guard selectors")
    suite = _safe_path(suite_path)
    suite_value = _read_json(suite, max_bytes=16 * 1024 * 1024)
    baseline = _read_json(baseline_path)
    if detect_contract(baseline).report_kind != kind:
        raise CIError("The baseline kind does not match the selected CI profile")
    metadata = unwrap_report(baseline)["metadata"]
    checked = compare_report_documents(
        baseline,
        baseline,
        baseline_reviewer=baseline_reviewer,
        candidate_reviewer=baseline_reviewer,
        baseline_guard=baseline_guard,
        candidate_guard=baseline_guard,
        expected_suite=suite_value,
    )
    loader = load_suite if kind == "repository" else load_boundary_suite
    cases = loader(suite)
    built_in = loader(None)
    from .boundary_runner import CORPUS_VERSION as boundary_corpus
    from .repository_cases import REPOSITORY_CORPUS_VERSION

    corpus = REPOSITORY_CORPUS_VERSION if kind == "repository" else boundary_corpus
    use_builtin = cases == built_in and metadata["corpus_version"] == corpus
    if (
        type(metadata.get("epochs")) is not int
        or not 1 <= metadata["epochs"] <= 10
        or metadata["world_limits"] != RepositoryLimits().model_dump(mode="json")
        or metadata["run_kind"] not in ("calibration", "adapter")
        or (metadata["run_kind"] == "calibration" and baseline_reviewer != "reference")
        or "bounds" in metadata
        or metadata.get("external_policy") is not None
        or metadata["corpus_version"] != (corpus if use_builtin else "custom")
    ):
        raise CIError("The native baseline cannot be reproduced by this adapter profile")
    return baseline, suite_value, None if use_builtin else suite, metadata["epochs"], checked


def _adapter_configuration(adapter_path, candidate_reviewer, *, baseline):
    from .adapter import AdapterConfig
    from .report_contract import unwrap_report

    path = _safe_path(adapter_path)
    value = _read_json(path, max_bytes=65536)
    config = AdapterConfig.model_validate(value)
    if config.env_allowlist:
        raise CIError("CI adapters cannot request host environment variables")
    if candidate_reviewer != "adapter/" + config.name:
        raise CIError("The candidate reviewer must match the configured adapter name")
    metadata = unwrap_report(baseline)["metadata"]
    if metadata["run_kind"] == "adapter" and metadata["adapter"][
        "limits"
    ] != config.limits.model_dump(mode="json"):
        raise CIError("Adapter transport bounds must match the approved adapter baseline")
    return path


def _native_model_plan(baseline_path, **options):
    """Validate a reproducible provider baseline using bounded data, before credentials."""
    from .boundary_runner import CORPUS_VERSION, load_boundary_suite
    from .native_compare import compare_report_documents
    from .providers import KEY_VARIABLES
    from .report_contract import detect_contract, unwrap_report
    from .repository_cases import REPOSITORY_CORPUS_VERSION
    from .repository_runner import load_suite

    profile, suite_path = options["profile"], options["suite_path"]
    if profile not in MODEL_PROFILES or suite_path is None:
        raise CIError("Select a native model profile and an explicit bounded suite")
    kind = MODEL_PROFILES[profile]
    if not options["baseline_reviewer"] or not options["candidate_reviewer"]:
        raise CIError("Native model CI requires explicit reviewer selectors")
    if kind == "boundary":
        if any(
            options[name] not in ("on", "off") for name in ("baseline_guard", "candidate_guard")
        ):
            raise CIError("Boundary model CI requires explicit guard selectors")
    elif options["baseline_guard"] is not None or options["candidate_guard"] is not None:
        raise CIError("Repository model CI does not accept guard selectors")
    suite_path = _safe_path(suite_path)
    suite = _read_json(suite_path, max_bytes=16 * 1024 * 1024)
    baseline = _read_json(baseline_path)
    if detect_contract(baseline).report_kind != kind:
        raise CIError("The baseline kind does not match the selected model profile")
    metadata = unwrap_report(baseline)["metadata"]
    checked = compare_report_documents(
        baseline,
        baseline,
        baseline_reviewer=options["baseline_reviewer"],
        candidate_reviewer=options["baseline_reviewer"],
        baseline_guard=options["baseline_guard"],
        candidate_guard=options["baseline_guard"],
        expected_suite=suite,
    )
    provider = metadata.get("provider")
    bounds = metadata.get("bounds", {})
    if (
        metadata["run_kind"] != "model"
        or type(provider) is not dict
        or provider.get("name") not in KEY_VARIABLES
        or provider.get("inspect_prefix") != provider["name"]
        or provider.get("api_key_env") != KEY_VARIABLES[provider["name"]]
        or not options["baseline_reviewer"].startswith(provider["name"] + "/")
        or metadata.get("adapter") is not None
        or any(row.get("adapter") is not None for row in unwrap_report(baseline)["rows"])
        or metadata.get("external_policy") is not None
        or type(metadata.get("epochs")) is not int
        or not 1 <= metadata["epochs"] <= 10
        or set(bounds) != {"max_turns", "max_input_bytes", "max_output_tokens", "retries"}
    ):
        raise CIError("The baseline must be a reproducible trusted native model run")
    for field, low, high in (
        ("max_turns", 1, 32),
        ("max_input_bytes", 1024, 100000),
        ("max_output_tokens", 128, 8192),
        ("retries", 0, 0),
    ):
        if type(bounds[field]) is not int or not low <= bounds[field] <= high:
            raise CIError("The native model execution bounds cannot be reproduced")
    loader = load_suite if kind == "repository" else load_boundary_suite
    cases = loader(suite_path)
    corpus = REPOSITORY_CORPUS_VERSION if kind == "repository" else CORPUS_VERSION
    use_builtin = cases == loader(None) and metadata["corpus_version"] == corpus
    if metadata["corpus_version"] != (corpus if use_builtin else "custom"):
        raise CIError("The native model corpus cannot be reproduced by this suite")
    return baseline, suite, None if use_builtin else suite_path, metadata, checked


def _native_model_arguments(
    metadata,
    output,
    *,
    provider,
    model,
    pricing_file,
    budget,
    prompt_price_cap,
    completion_price_cap,
):
    from .budget import planned_cost
    from .providers import prepare_provider

    if (
        type(budget) not in (int, float)
        or not math.isfinite(budget)
        or not 0 < budget <= MAX_NATIVE_MODEL_BUDGET_USD
    ):
        raise CIError("Native model CI requires a finite budget no larger than USD 20")
    pricing = None
    if pricing_file is not None:
        pricing = _safe_path(pricing_file)
        _read_json(pricing, max_bytes=65536)
    plan = prepare_provider(
        provider,
        [model],
        prompt_price_cap=prompt_price_cap,
        completion_price_cap=completion_price_cap,
        pricing_file=pricing,
    )
    bounds = metadata["bounds"]
    reservation = planned_cost(
        metadata["case_count"] * metadata["epochs"],
        bounds["max_turns"],
        bounds["max_input_bytes"],
        bounds["max_output_tokens"],
        plan.prompt_price_cap,
        plan.completion_price_cap,
    )
    if reservation > budget:
        raise CIError("The conservative native model reservation exceeds its budget")
    return plan, SimpleNamespace(
        output=output / "candidate",
        ledger=output / "budget.json",
        epochs=metadata["epochs"],
        provider=provider,
        model=[model],
        pricing_file=pricing,
        budget=budget,
        prompt_price_cap=prompt_price_cap,
        completion_price_cap=completion_price_cap,
        concurrency=1,
        opencode_auth=None,
        dry_run=False,
        **{name: value for name, value in bounds.items() if name != "retries"},
        **metadata["world_limits"],
    )


def _prepare_native_model_ci(
    baseline_path,
    output,
    *,
    mode="calibration",
    provider="openrouter",
    model=None,
    defense="baseline",
    baseline_model=None,
    baseline_defense=None,
    pricing_file=None,
    budget=20.0,
    adapter_path=None,
    prompt_price_cap=None,
    completion_price_cap=None,
    **options,
):
    """Resolve only bounded data and a fixed provider plan, before any key access."""
    if (
        mode != "model"
        or adapter_path is not None
        or defense != "baseline"
        or baseline_model is not None
        or baseline_defense is not None
        or set(options)
        != {
            "profile",
            "suite_path",
            "baseline_reviewer",
            "candidate_reviewer",
            "baseline_guard",
            "candidate_guard",
        }
    ):
        raise CIError("Native model profiles require explicit model mode without adapter options")
    baseline, suite, suite_path, metadata, _ = _native_model_plan(baseline_path, **options)
    plan, args = _native_model_arguments(
        metadata,
        output,
        provider=provider,
        model=model,
        pricing_file=pricing_file,
        budget=budget,
        prompt_price_cap=prompt_price_cap,
        completion_price_cap=completion_price_cap,
    )
    if options["candidate_reviewer"] != plan.inspect_model_id(model):
        raise CIError("The candidate reviewer must match the selected provider and model")
    args.suite = suite_path
    args.guard = options["candidate_guard"]
    args.command = MODEL_PROFILES[options["profile"]] + "-run-model"
    return baseline, suite, args


def _execute_native_model(args) -> int:
    from .boundary_runner import run_boundary_model
    from .repository_runner import run_repository_model

    runner = run_repository_model if args.command == "repository-run-model" else run_boundary_model
    code = runner(args)
    if type(code) is not int or code != 0:
        return 2
    return 0


def execute_native_model_ci(baseline_path, output, **options) -> int:
    """Provider workflow phase: run trusted code and leave raw logs on this runner."""
    try:
        directory = _safe_path(output)
        directory.mkdir(parents=True, exist_ok=False)
        _, _, args = _prepare_native_model_ci(baseline_path, directory, **options)
        if _execute_native_model(args) != 0:
            return 2
        _read_json(directory / "candidate/report.json")
        return 0
    except (Exception, SystemExit):  # noqa: BLE001
        print("ReviewBoundary: native model configuration or execution failed", file=sys.stderr)
        return 2


def _run_native_model_ci(baseline_path, output, **options) -> int:
    """Local orchestration retains the same native 0/1/2 comparison contract."""
    try:
        directory = _safe_path(output)
        directory.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, TypeError):
        print("ReviewBoundary CI: output must be a new safe directory.", file=sys.stderr)
        return 2
    stage = "configuration_invalid"
    try:
        from .native_compare import compare_report_documents

        baseline, suite, args = _prepare_native_model_ci(baseline_path, directory, **options)
        stage = "evaluation_failed"
        if _execute_native_model(args) != 0:
            return _finish(directory, code=2, error_code=stage)
        stage = "candidate_invalid"
        candidate = _read_json(directory / "candidate/report.json")
        selected = {
            name: options[name]
            for name in (
                "profile",
                "suite_path",
                "baseline_reviewer",
                "candidate_reviewer",
                "baseline_guard",
                "candidate_guard",
            )
        }
        stage = "comparison_invalid"
        comparison = compare_report_documents(
            baseline,
            candidate,
            expected_suite=suite,
            **{
                name: value
                for name, value in selected.items()
                if name not in ("profile", "suite_path")
            },
        )
        return _finish(directory, code=comparison["exit_code"], comparison=comparison)
    except (Exception, SystemExit):  # noqa: BLE001
        return _finish(directory, code=2, error_code=stage)


def _execute_adapter(*, profile, adapter_path, suite_path, epochs, candidate_guard, output):
    # Deliberately bypass provider preparation, dotenv loading and the general CLI dispatcher.
    from .boundary_runner import run_boundary_command
    from .repository_runner import run_repository_command

    adapter_environment(os.environ)
    args = SimpleNamespace(
        command=profile.replace("-adapter", "-run-adapter"),
        adapter=adapter_path,
        suite=suite_path,
        output=output / "candidate",
        epochs=epochs,
        guard=candidate_guard,
        policy=None,
    )
    runner = run_repository_command if profile == "repository-adapter" else run_boundary_command
    code = runner(args)
    if type(code) is not int or code != 0:
        raise CIError("Native adapter execution did not finish successfully")
    # Only bounded JSON is transferred to the fresh comparison runner.
    _read_json(output / "candidate/report.json")


def _run_adapter_ci(
    baseline_path,
    output,
    *,
    adapter_path,
    provider_options=True,
    native_model_requested=False,
    **options,
):
    try:
        directory = _safe_path(output)
        directory.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, TypeError):
        print("ReviewBoundary CI: output must be a new safe directory.", file=sys.stderr)
        return 2
    stage = "configuration_invalid"
    try:
        if native_model_requested:
            return _finish(directory, code=2, error_code="native_model_unsupported")
        if not provider_options:
            raise CIError("Native model CI is not supported by the adapter profile")
        adapter_environment(os.environ)
        stage = "baseline_invalid"
        baseline, suite, run_suite, epochs, _ = _native_plan(baseline_path, **options)
        stage = "configuration_invalid"
        config = _adapter_configuration(
            adapter_path, options["candidate_reviewer"], baseline=baseline
        )
        stage = "evaluation_failed"
        _execute_adapter(
            profile=options["profile"],
            adapter_path=config,
            suite_path=run_suite,
            epochs=epochs,
            candidate_guard=options["candidate_guard"],
            output=directory,
        )
        stage = "candidate_invalid"
        candidate = _read_json(directory / "candidate/report.json")
        stage = "comparison_invalid"
        from .native_compare import compare_report_documents

        comparison = compare_report_documents(
            baseline,
            candidate,
            **{
                name: value
                for name, value in options.items()
                if name not in ("profile", "suite_path")
            },
            expected_suite=suite,
        )
        return _finish(directory, code=comparison["exit_code"], comparison=comparison)
    except (Exception, SystemExit):  # noqa: BLE001
        return _finish(directory, code=2, error_code=stage)


def execute_adapter_ci(baseline_path, output, *, adapter_path, **options) -> int:
    """Secretless workflow phase: execute caller-owned code, produce only candidate data."""
    try:
        directory = _safe_path(output)
        directory.mkdir(parents=True, exist_ok=False)
        adapter_environment(os.environ)
        baseline, _, run_suite, epochs, _ = _native_plan(baseline_path, **options)
        config = _adapter_configuration(
            adapter_path, options["candidate_reviewer"], baseline=baseline
        )
        _execute_adapter(
            profile=options["profile"],
            adapter_path=config,
            suite_path=run_suite,
            epochs=epochs,
            candidate_guard=options.get("candidate_guard"),
            output=directory,
        )
    except (Exception, SystemExit):  # noqa: BLE001
        print("ReviewBoundary: adapter configuration or execution failed", file=sys.stderr)
        return 2
    return 0


def compare_native_ci(baseline_path, candidate_path, output, *, evaluation_code, **options) -> int:
    """Fresh trusted workflow phase: consume bounded data and never load adapter config/code."""
    try:
        directory = _safe_path(output)
        directory.mkdir(parents=True, exist_ok=False)
    except (OSError, ValueError, TypeError):
        print("ReviewBoundary CI: output must be a new safe directory.", file=sys.stderr)
        return 2
    stage = "evaluation_failed"
    try:
        if type(evaluation_code) is not int or evaluation_code != 0:
            raise CIError("The adapter evaluation failed")
        stage = "baseline_invalid"
        planner = _native_model_plan if options.get("profile") in MODEL_PROFILES else _native_plan
        baseline, suite, _, _, _ = planner(baseline_path, **options)
        stage = "candidate_invalid"
        candidate = _read_json(candidate_path)
        stage = "comparison_invalid"
        from .native_compare import compare_report_documents

        comparison = compare_report_documents(
            baseline,
            candidate,
            **{
                name: value
                for name, value in options.items()
                if name not in ("profile", "suite_path")
            },
            expected_suite=suite,
        )
        return _finish(directory, code=comparison["exit_code"], comparison=comparison)
    except (Exception, SystemExit):  # noqa: BLE001
        return _finish(directory, code=2, error_code=stage)
