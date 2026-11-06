"""Trusted reusable-workflow entry points; never execute code from caller repositories."""

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


def main(argv=None):
    operation = (argv or sys.argv[1:] or [""])[0]
    code = 2
    try:
        if operation == "check":
            context(os.environ)
            return 0
        if operation == "evaluate":
            code = evaluate(os.environ)
        elif operation == "publish":
            return publish(os.environ)
        else:
            raise WorkflowError("Select check, evaluate, or publish")
    except WorkflowError as error:
        print(f"ReviewBoundary: {error}", file=sys.stderr)
    except Exception:  # noqa: BLE001
        # Provider payloads, API keys, and malformed inputs must not become job output.
        print(
            "ReviewBoundary: workflow execution failed; check configuration and artifacts",
            file=sys.stderr,
        )
    if operation == "evaluate":
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
