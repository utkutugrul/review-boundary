"""Reusable-workflow entry points with separate provider and caller-adapter paths."""

import json
import os
import re
import sys
import tempfile
from pathlib import Path


class WorkflowError(ValueError):
    """A safe message explaining an unsupported workflow context."""


def context(environ):
    """Read only GitHub-provided context and fixed workflow inputs."""
    if environ.get("RB_SERVER_URL") != "https://github.com":
        raise WorkflowError("This reusable workflow supports GitHub.com only")
    event_name = environ.get("RB_EVENT")
    if event_name not in ("push", "pull_request", "workflow_dispatch"):
        raise WorkflowError("Use push, pull_request, or workflow_dispatch events")
    repository = environ.get("RB_REPOSITORY", "")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is None:
        raise WorkflowError("A valid caller repository is required")
    mode = environ.get("RB_MODE", "calibration")
    if mode not in ("calibration", "model"):
        raise WorkflowError("Unsupported evaluation mode")
    if environ.get("RB_PROVIDER", "openrouter") not in ("openrouter", "openai", "anthropic"):
        raise WorkflowError("Unsupported provider")
    if environ.get("RB_BASELINE_SOURCE", "harness") not in ("harness", "caller"):
        raise WorkflowError("Baseline source must be harness or caller")
    result = {"repository": repository, "mode": mode, "pull_number": None, "head": None}
    if event_name == "pull_request":
        try:
            with Path(environ["GITHUB_EVENT_PATH"]).open("rb") as stream:
                raw = stream.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError
            event = json.loads(raw)
            pr = event["pull_request"]
            base_repository = pr["base"]["repo"]["full_name"]
            head_repository = pr["head"]["repo"]["full_name"]
            number, head = event["number"], pr["head"]["sha"]
            if (
                base_repository != repository
                or not isinstance(head_repository, str)
                or type(number) is not int
                or number <= 0
                or not isinstance(head, str)
                or re.fullmatch(r"[0-9a-f]{40}", head) is None
            ):
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError):
            raise WorkflowError("Pull request context is invalid") from None
        fork = head_repository != repository
        if fork and mode == "model":
            raise WorkflowError("Paid model evaluations are disabled for fork pull requests")
        result.update(pull_number=number, head=head, fork=fork)
    return result


def evaluate(environ):
    from .ci import repository_file, run_ci

    context(environ)
    if environ.get("RB_PROFILE", "legacy") != "legacy":
        raise WorkflowError("Caller adapters require the separate secretless adapter workflow")
    workspace = Path(environ["GITHUB_WORKSPACE"])
    data_root = workspace / (
        "baseline-source" if environ.get("RB_BASELINE_SOURCE") == "caller" else "harness"
    )
    baseline = repository_file(data_root, environ["RB_BASELINE"])
    pricing = environ.get("RB_PRICING_FILE")
    return run_ci(
        baseline,
        workspace / "reviewboundary-results",
        mode=environ.get("RB_MODE", "calibration"),
        provider=environ.get("RB_PROVIDER", "openrouter"),
        model=environ.get("RB_MODEL") or None,
        defense=environ.get("RB_DEFENSE", "baseline"),
        baseline_model=environ.get("RB_BASELINE_MODEL") or None,
        baseline_defense=environ.get("RB_BASELINE_DEFENSE") or None,
        pricing_file=repository_file(data_root, pricing) if pricing else None,
        budget=float(environ.get("RB_BUDGET", "20")),
    )


def publish(environ):
    from .cli import main as cli_main

    selected = context(environ)
    if environ.get("RB_PROFILE", "legacy") != "legacy":
        raise WorkflowError("Native App publication is not supported")
    if not selected["pull_number"] or selected.get("fork"):
        raise WorkflowError("App reporting requires a pull request from the same repository")
    key = environ.get("RB_APP_PRIVATE_KEY", "")
    if not key:
        raise WorkflowError("Set GITHUB_APP_PRIVATE_KEY to enable App reporting")
    # The token-bearing process only receives trusted harness code and a data artifact.
    with tempfile.TemporaryDirectory(prefix="reviewboundary-app-") as directory:
        private_key = Path(directory) / "private-key.pem"
        descriptor = os.open(private_key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(key)
        config = Path(directory) / "config.json"
        config.write_text(
            json.dumps(
                {
                    "app_id": int(environ["RB_APP_ID"]),
                    "installation_id": int(environ["RB_INSTALLATION_ID"]),
                    "private_key_path": str(private_key),
                    "allowed_repositories": [selected["repository"]],
                }
            )
        )
        return cli_main(
            [
                "github-publish",
                "--config",
                str(config),
                "--repository",
                selected["repository"],
                "--pull-number",
                str(selected["pull_number"]),
                "--expected-head",
                selected["head"],
                "--comparison",
                str(Path(environ["GITHUB_WORKSPACE"]) / "reviewboundary-results/comparison.json"),
            ]
        )


def adapter_context(environ):
    from .ci import ADAPTER_PROFILES, adapter_environment

    selected = context(environ)
    if (
        environ.get("RB_PROFILE") not in ADAPTER_PROFILES
        or selected["mode"] != "calibration"
        or environ.get("RB_MODEL")
        or environ.get("RB_PRICING_FILE")
        or environ.get("RB_PUBLISH_COMMENT", "false") != "false"
    ):
        raise WorkflowError("Select a native adapter profile without model or publication options")
    adapter_environment(environ)
    return selected


def _adapter_inputs(environ):
    from .ci import repository_file

    workspace = Path(environ["GITHUB_WORKSPACE"])
    data_root = workspace / (
        "baseline-source" if environ.get("RB_BASELINE_SOURCE") == "caller" else "harness"
    )
    baseline = repository_file(data_root, environ["RB_BASELINE"])
    return baseline, {
        "profile": environ["RB_PROFILE"],
        "suite_path": repository_file(data_root, environ["RB_SUITE"]),
        "baseline_reviewer": environ.get("RB_BASELINE_REVIEWER") or None,
        "candidate_reviewer": environ.get("RB_CANDIDATE_REVIEWER") or None,
        "baseline_guard": environ.get("RB_BASELINE_GUARD") or None,
        "candidate_guard": environ.get("RB_CANDIDATE_GUARD") or None,
    }


def adapter_run(environ):
    from .ci import execute_adapter_ci, repository_file

    adapter_context(environ)
    baseline, options = _adapter_inputs(environ)
    workspace = Path(environ["GITHUB_WORKSPACE"])
    config = repository_file(workspace / "adapter-source", environ["RB_ADAPTER"])
    return execute_adapter_ci(
        baseline, workspace / "adapter-results", adapter_path=config, **options
    )


def adapter_compare(environ):
    from .ci import compare_native_ci

    adapter_context(environ)
    baseline, options = _adapter_inputs(environ)
    workspace = Path(environ["GITHUB_WORKSPACE"])
    return compare_native_ci(
        baseline,
        workspace / "adapter-artifact/report.json",
        workspace / "reviewboundary-results",
        evaluation_code=0 if environ.get("RB_EVALUATION_EXIT") == "0" else 2,
        **options,
    )


def native_model_context(environ):
    from .ci import MODEL_PROFILES

    selected = context(environ)
    if environ.get("RB_ALLOW_LIVE", "false") != "true":
        raise WorkflowError("Native provider execution requires explicit allow_live opt-in")
    if (
        environ.get("RB_PROFILE") not in MODEL_PROFILES
        or selected["mode"] != "model"
        or not environ.get("RB_MODEL")
        or any(
            environ.get(name)
            for name in (
                "RB_ADAPTER",
                "RB_ADAPTER_PATH",
                "RB_POLICY",
                "RB_POLICY_PATH",
                "RB_COMMAND",
                "RB_OPENCODE_AUTH",
                "RB_APP_ID",
                "RB_INSTALLATION_ID",
            )
        )
        or environ.get("RB_PUBLISH_COMMENT", "false") != "false"
    ):
        raise WorkflowError(
            "Native provider CI accepts fixed model profiles without adapter or App options"
        )
    return selected


def _native_model_inputs(environ):
    from .ci import _safe_path, repository_file

    workspace = _safe_path(environ["GITHUB_WORKSPACE"])
    harness = _safe_path(workspace / "harness")
    if Path.cwd() != harness.resolve(strict=True):
        raise WorkflowError(
            "Native provider operations must run from the trusted harness directory"
        )
    root = workspace / (
        "baseline-source" if environ.get("RB_BASELINE_SOURCE") == "caller" else "harness"
    )
    return (
        repository_file(root, environ["RB_BASELINE"]),
        {
            "profile": environ["RB_PROFILE"],
            "suite_path": repository_file(root, environ["RB_SUITE"]),
            "baseline_reviewer": environ.get("RB_BASELINE_REVIEWER") or None,
            "candidate_reviewer": environ.get("RB_CANDIDATE_REVIEWER") or None,
            "baseline_guard": environ.get("RB_BASELINE_GUARD") or None,
            "candidate_guard": environ.get("RB_CANDIDATE_GUARD") or None,
        },
        root,
    )


def native_model_run(environ):
    from .ci import execute_native_model_ci, repository_file

    native_model_context(environ)
    baseline, options, root = _native_model_inputs(environ)
    pricing = environ.get("RB_PRICING_FILE")
    return execute_native_model_ci(
        baseline,
        Path(environ["GITHUB_WORKSPACE"]) / "native-model-results",
        mode="model",
        provider=environ["RB_PROVIDER"],
        model=environ["RB_MODEL"],
        budget=float(environ["RB_BUDGET"]),
        pricing_file=repository_file(root, pricing) if pricing else None,
        prompt_price_cap=float(environ["RB_PROMPT_PRICE_CAP"])
        if environ.get("RB_PROMPT_PRICE_CAP")
        else None,
        completion_price_cap=float(environ["RB_COMPLETION_PRICE_CAP"])
        if environ.get("RB_COMPLETION_PRICE_CAP")
        else None,
        **options,
    )


def native_model_compare(environ):
    from .ci import compare_native_ci

    native_model_context(environ)
    baseline, options, _ = _native_model_inputs(environ)
    workspace = Path(environ["GITHUB_WORKSPACE"])
    return compare_native_ci(
        baseline,
        workspace / "native-model-artifact/report.json",
        workspace / "reviewboundary-results",
        evaluation_code=0 if environ.get("RB_EVALUATION_EXIT") == "0" else 2,
        **options,
    )


def main(argv=None):
    operation = (argv or sys.argv[1:] or [""])[0]
    code = 2
    try:
        if operation == "check":
            context(os.environ)
            return 0
        if operation == "adapter-check":
            adapter_context(os.environ)
            return 0
        if operation == "native-model-check":
            native_model_context(os.environ)
            return 0
        if operation == "evaluate":
            code = evaluate(os.environ)
        elif operation == "adapter-run":
            code = adapter_run(os.environ)
        elif operation == "adapter-compare":
            code = adapter_compare(os.environ)
        elif operation == "native-model-run":
            code = native_model_run(os.environ)
        elif operation == "native-model-compare":
            code = native_model_compare(os.environ)
        elif operation == "publish":
            return publish(os.environ)
        else:
            raise WorkflowError("Select a supported evaluation, adapter, or publication operation")
    except WorkflowError as error:
        print(f"ReviewBoundary: {error}", file=sys.stderr)
    except Exception:  # noqa: BLE001
        # Provider payloads, API keys, and malformed inputs must not become job output.
        print(
            "ReviewBoundary: workflow execution failed; check configuration and artifacts",
            file=sys.stderr,
        )
    if operation in ("adapter-run", "native-model-run"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write(f"evaluation_exit={code}\n")
    if operation in ("evaluate", "adapter-compare", "native-model-compare"):
        output = Path(os.environ["GITHUB_WORKSPACE"]) / "reviewboundary-results"
        output.mkdir(parents=True, exist_ok=True)
        if not (output / "summary.md").exists():
            (output / "summary.md").write_text(
                "# ReviewBoundary CI\n\n**ERROR**\n\nConfiguration or execution failed. "
                "No passing comparison was produced.\n"
            )
        if not (output / "ci-result.json").exists():
            (output / "ci-result.json").write_text(
                json.dumps(
                    {
                        "ci_schema_version": 1,
                        "status": "error",
                        "exit_code": 2,
                        "error_code": "workflow_configuration",
                        "message": "Configuration or execution failed before a result was written.",
                        "counts": None,
                    },
                    indent=2,
                )
                + "\n"
            )
        ready = code in (0, 1) and (output / "comparison.json").is_file()
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write(f"exit_code={code}\ncomparison_ready={str(ready).lower()}\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
