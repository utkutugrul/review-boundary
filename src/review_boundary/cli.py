"""Run offline calibration or a bounded OpenRouter pilot."""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from urllib.error import HTTPError, URLError
from uuid import uuid4

from dotenv import load_dotenv
from inspect_ai import eval
from inspect_ai.log import read_eval_log

from .budget import api_get, model_snapshot, planned_cost, reserve
from .cases import FAMILIES, SURFACES, build_cases, suite_digest
from .report import rows_from_logs, summarize, write_report
from .task import calibration_model, review_boundary


def parser():
    root = argparse.ArgumentParser(
        description="Paired security-review prompt injection evaluations"
    )
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List the synthetic case IDs")
    for name in ("demo", "run"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path)
        command.add_argument("--family", action="append", choices=[f.name for f in FAMILIES])
        command.add_argument("--surface", action="append", choices=SURFACES)
        command.add_argument("--defense", action="append", choices=("baseline", "explicit"))
        command.add_argument("--block-writes", action="store_true")
        command.add_argument("--epochs", type=int, default=1)
        command.add_argument("--max-turns", type=int, default=8)
        command.add_argument("--max-input-bytes", type=int, default=24000)
        command.add_argument("--max-output-tokens", type=int, default=1536)
        if name == "demo":
            command.add_argument(
                "--mode", action="append", choices=("reference", "hijacked", "incomplete")
            )
        else:
            command.add_argument(
                "--model",
                action="append",
                required=True,
                help="OpenRouter model ID, without an openrouter/ prefix",
            )
            command.add_argument(
                "--opencode-auth",
                type=Path,
                help="Explicitly load the OpenRouter key from this auth.json",
            )
            command.add_argument("--budget", type=float, default=20.0)
            command.add_argument("--ledger", type=Path, default=Path("runs/budget.json"))
            command.add_argument(
                "--prompt-price-cap",
                type=float,
                default=0.15,
                help="Maximum provider input price in USD per million tokens",
            )
            command.add_argument("--completion-price-cap", type=float, default=0.60)
            command.add_argument("--concurrency", type=int, default=2)
            command.add_argument("--dry-run", action="store_true")
    report = commands.add_parser("report", help="Rebuild an HTML report from Inspect logs")
    report.add_argument("logs", nargs="+", type=Path)
    report.add_argument("--output", type=Path, required=True)
    return root


def credential(args):
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
    if args.opencode_auth:
        entry = json.loads(args.opencode_auth.expanduser().read_text()).get("openrouter", {})
        if entry.get("type") != "api" or not entry.get("key"):
            raise ValueError("The selected OpenCode auth file has no OpenRouter API credential")
        os.environ["OPENROUTER_API_KEY"] = entry["key"]
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise ValueError("Set OPENROUTER_API_KEY or explicitly select --opencode-auth")
    if os.environ.get("OPENROUTER_BASE_URL"):
        raise ValueError("Custom OpenRouter base URLs are not supported by this bounded runner")
    return key


def usage_from_logs(logs):
    usages = [u for log in logs for u in log.stats.model_usage.values()]
    calls = [
        e
        for log in logs
        for sample in log.samples or []
        for e in sample.events
        if e.event == "model"
    ]
    costs = []
    for event in calls:
        response = event.call.response if event.call else None
        usage = response.get("usage") if response else None
        cost = usage.get("cost") if isinstance(usage, dict) else None
        if isinstance(cost, (float, int)) and cost >= 0:
            costs.append(cost)
    complete_cost = sum(costs) if calls and len(costs) == len(calls) else None
    return {
        "input_tokens": sum(u.input_tokens for u in usages),
        "output_tokens": sum(u.output_tokens for u in usages),
        "provider_reported_cost_usd": (
            sum(u.total_cost for u in usages)
            if usages and all(u.total_cost is not None for u in usages)
            else complete_cost
        ),
        "api_calls_with_reported_cost": len(costs),
        "api_calls_without_reported_cost": len(calls) - len(costs),
    }


def run(args):
    cases = [
        c
        for c in build_cases()
        if (not args.family or c.family in args.family)
        and (not args.surface or c.surface in args.surface)
    ]
    defenses = list(dict.fromkeys(args.defense or ["baseline"]))
    if not 1 <= args.epochs <= 20:
        raise ValueError("epochs must be between 1 and 20")
    tasks = [
        review_boundary(
            defense=d,
            block_writes=args.block_writes,
            max_turns=args.max_turns,
            max_input_bytes=args.max_input_bytes,
            max_output_tokens=args.max_output_tokens,
            cases=cases,
        )
        for d in defenses
    ]
    run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    output = args.output or Path("runs") / run_id
    if output.exists() and any(output.iterdir()):
        raise ValueError(
            "Output directory must be new or empty; earlier results are never overwritten"
        )
    metadata = {
        "run_id": run_id,
        "suite_sha256": suite_digest(cases),
        "inspect_ai_version": version("inspect-ai"),
        "project_version": version("review-boundary"),
        "run_kind": "calibration" if args.command == "demo" else "pilot",
        "case_count": len(cases),
        "epochs": args.epochs,
        "defenses": defenses,
        "block_writes": args.block_writes,
        "sampling": "Provider defaults; temperature and parallel_tool_calls are not forced.",
        "bounds": {
            "max_turns": args.max_turns,
            "max_input_bytes": args.max_input_bytes,
            "max_output_tokens": args.max_output_tokens,
            "retries": 0,
        },
    }
    logs = []
    if args.command == "run":
        if not 1 <= args.concurrency <= 8:
            raise ValueError("concurrency must be between 1 and 8")
        model_ids = list(dict.fromkeys(args.model))
        amount = planned_cost(
            len(cases) * len(defenses) * len(model_ids) * args.epochs,
            args.max_turns,
            args.max_input_bytes,
            args.max_output_tokens,
            args.prompt_price_cap,
            args.completion_price_cap,
        )
        if amount > args.budget:
            raise ValueError(f"Conservative reservation ${amount:.4f} exceeds this run's budget")
        metadata["catalog"] = model_snapshot(
            model_ids, args.prompt_price_cap, args.completion_price_cap
        )
        provider = {
            "require_parameters": True,
            "allow_fallbacks": False,
            "max_price": {
                "prompt": args.prompt_price_cap,
                "completion": args.completion_price_cap,
                "request": 0,
            },
        }
        metadata["provider_policy"] = provider
        metadata["planned_reservation_usd"] = amount
        if args.dry_run:
            print(json.dumps(metadata, indent=2))
            return 0
        key = credential(args)
        before = api_get("key", key)["data"]
        remaining = before.get("limit_remaining")
        if remaining is not None and remaining < amount:
            raise ValueError("OpenRouter key remaining credit cap is below the planned reservation")
        metadata["budget"] = reserve(args.ledger, amount, args.budget, run_id)
        output.mkdir(parents=True, exist_ok=True)
        (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
        for model_id in model_ids:
            print(f"Running {model_id}: {len(cases)} cases x {len(defenses)} prompts", flush=True)
            new = eval(
                tasks,
                model="openrouter/" + model_id,
                model_args={"provider": provider, "stream": False},
                epochs=args.epochs,
                max_samples=args.concurrency,
                log_dir=str(output / "logs"),
                display="none",
                log_model_api=True,
            )
            logs.extend(new)
            metadata["usage"] = usage_from_logs(logs)
            write_report(rows_from_logs(logs), output, metadata)
            print(json.dumps(summarize(rows_from_logs(new))), flush=True)
        try:
            after = api_get("key", key)["data"]
            metadata["shared_key_usage_delta_usd"] = after.get("usage", 0) - before.get("usage", 0)
            metadata["key_usage_note"] = (
                "May include concurrent use by other apps and delayed billing."
            )
        except (HTTPError, URLError, TimeoutError):
            metadata["key_usage_note"] = "Post-run key usage could not be fetched."
    else:
        for mode in list(dict.fromkeys(args.mode or ["reference", "hijacked", "incomplete"])):
            logs.extend(
                eval(
                    tasks,
                    model=calibration_model(mode),
                    epochs=args.epochs,
                    max_samples=4,
                    log_dir=str(output / "logs"),
                    display="none",
                    log_model_api=False,
                )
            )
    rows = rows_from_logs(logs)
    metadata["usage"] = usage_from_logs(logs)
    report = write_report(rows, output, metadata)
    print(json.dumps(summarize(rows), indent=2))
    print("Report: " + str(report.resolve()))
    return (
        2
        if any(log.status != "success" or any(s.error for s in log.samples or []) for log in logs)
        else 0
    )


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "list":
            print("\n".join(c.id for c in build_cases()))
            return 0
        if args.command == "report":
            logs = [read_eval_log(str(p)) for p in args.logs]
            calibration = all(log.eval.model.startswith("mockllm/") for log in logs)
            report = write_report(
                rows_from_logs(logs),
                args.output,
                {
                    "run_kind": "calibration" if calibration else "pilot",
                    "reconstructed": True,
                    "usage": usage_from_logs(logs),
                },
            )
            print(report.resolve())
            return 0
        return run(args)
    except (ValueError, OSError, HTTPError, URLError) as exc:
        # Do not dump SDK objects, request headers, auth files or full tracebacks here.
        print(f"ReviewBoundary: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
