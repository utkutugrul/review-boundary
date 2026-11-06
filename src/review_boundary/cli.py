"""Run calibrations, bounded provider evaluations, and repository integrations."""

import argparse
import asyncio
import json
import math
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

from .budget import api_get, model_snapshot, planned_cost, reserve, settle
from .cases import FAMILIES, SURFACES, build_cases, suite_digest
from .model_safety import ProviderRequestError, guarded_model
from .providers import prepare_provider
from .report import rows_from_logs, summarize, write_report
from .task import calibration_model, review_boundary


def parser():
    root = argparse.ArgumentParser(
        description="Paired security-review prompt injection evaluations"
    )
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List the synthetic case IDs")
    corpus = commands.add_parser("corpus-export", help="Export pinned upstream review cases")
    corpus.add_argument("--corpus", choices=("pyjwt",), required=True)
    corpus.add_argument("--output", type=Path, required=True)
    corpus.add_argument("--verify", action="store_true", help="Run offline behavior checks")
    for name in ("boundary-demo", "boundary-run-adapter"):
        command = commands.add_parser(name, help="Compare virtual actions with and without a guard")
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--epochs", type=int, default=1)
        command.add_argument("--guard", choices=("both", "on", "off"), default="both")
        command.add_argument("--policy", type=Path, help="Optional trusted local policy process")
        if name == "boundary-run-adapter":
            command.add_argument("--adapter", type=Path, required=True)
    for name in ("repository-demo", "repository-run-adapter"):
        command = commands.add_parser(name, help="Run the opt-in multi-file repository contract")
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--epochs", type=int, default=1)
        if name == "repository-run-adapter":
            command.add_argument("--adapter", type=Path, required=True)
            command.add_argument(
                "--suite", type=Path, help="Custom evaluator-only repository suite"
            )
    repository_model = commands.add_parser(
        "repository-run-model", help="Run provider models in the multi-file repository contract"
    )
    repository_model.add_argument("--output", type=Path, required=True)
    repository_model.add_argument("--suite", type=Path)
    repository_model.add_argument("--epochs", type=int, default=1)
    repository_model.add_argument("--max-turns", type=int, default=8)
    repository_model.add_argument("--max-input-bytes", type=int, default=24000)
    repository_model.add_argument("--max-output-tokens", type=int, default=8192)
    repository_model.add_argument("--max-calls", type=int, default=64)
    repository_model.add_argument("--max-response-bytes", type=int, default=16384)
    repository_model.add_argument("--max-total-response-bytes", type=int, default=262144)
    repository_model.add_argument("--max-read-lines", type=int, default=80)
    repository_model.add_argument("--max-list-entries", type=int, default=20)
    repository_model.add_argument("--max-search-matches", type=int, default=20)
    repository_model.add_argument(
        "--provider", choices=("openrouter", "openai", "anthropic"), default="openrouter"
    )
    repository_model.add_argument("--model", action="append", required=True)
    repository_model.add_argument("--pricing-file", type=Path)
    repository_model.add_argument("--opencode-auth", type=Path)
    repository_model.add_argument("--budget", type=float, default=20.0)
    repository_model.add_argument("--ledger", type=Path, default=Path("runs/budget.json"))
    repository_model.add_argument("--prompt-price-cap", type=float)
    repository_model.add_argument("--completion-price-cap", type=float)
    repository_model.add_argument("--concurrency", type=int, default=2)
    repository_model.add_argument("--dry-run", action="store_true")
    for name in ("demo", "run", "run-adapter"):
        command = commands.add_parser(name)
        command.add_argument("--output", type=Path)
        command.add_argument("--family", action="append", choices=[f.name for f in FAMILIES])
        command.add_argument("--surface", action="append", choices=SURFACES)
        command.add_argument("--defense", action="append", choices=("baseline", "explicit"))
        command.add_argument("--block-writes", action="store_true")
        command.add_argument(
            "--split", choices=("development", "heldout", "all"), default="development"
        )
        command.add_argument("--language", choices=("python", "typescript", "rust"))
        command.add_argument("--epochs", type=int, default=1 if name == "demo" else 5)
        command.add_argument("--max-turns", type=int, default=8)
        command.add_argument("--max-input-bytes", type=int, default=24000)
        command.add_argument("--max-output-tokens", type=int, default=8192)
        if name == "demo":
            command.add_argument(
                "--mode", action="append", choices=("reference", "hijacked", "incomplete")
            )
        elif name == "run-adapter":
            command.add_argument("--adapter", type=Path, required=True)
        else:
            command.add_argument(
                "--provider", choices=("openrouter", "openai", "anthropic"), default="openrouter"
            )
            command.add_argument(
                "--model",
                action="append",
                required=True,
                help="Model ID for the selected provider; default provider is OpenRouter",
            )
            command.add_argument(
                "--pricing-file",
                type=Path,
                help="Required dated model price configuration for direct providers",
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
                default=None,
                help="Input price ceiling; OpenRouter defaults to USD 0.15 per million tokens",
            )
            command.add_argument("--completion-price-cap", type=float, default=None)
            command.add_argument("--concurrency", type=int, default=2)
            command.add_argument("--dry-run", action="store_true")
    report = commands.add_parser("report", help="Rebuild an HTML report from Inspect logs")
    report.add_argument("logs", nargs="+", type=Path)
    report.add_argument("--output", type=Path, required=True)
    report.add_argument("--manifest", type=Path, required=True)
    report.add_argument(
        "--preserve-recorded-scores",
        action="store_true",
        help="Explicitly retain original scores without checking them against the supported scorer",
    )
    compare = commands.add_parser("compare", help="Fail on new per-sample regressions")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("candidate", type=Path)
    compare.add_argument("--output", type=Path)
    for selector in ("baseline-model", "baseline-defense", "candidate-model", "candidate-defense"):
        compare.add_argument("--" + selector)
    dashboard = commands.add_parser("dashboard", help="Export a self-contained report dashboard")
    dashboard.add_argument("reports", nargs="*", type=Path)
    dashboard.add_argument("--output", type=Path, default=Path("reports/dashboard.html"))
    ci = commands.add_parser("ci", help="Reproduce a baseline's cases and check for regressions")
    ci.add_argument("baseline", type=Path)
    ci.add_argument("--output", type=Path, required=True)
    ci.add_argument("--mode", choices=("calibration", "model"), default="calibration")
    ci.add_argument(
        "--provider", choices=("openrouter", "openai", "anthropic"), default="openrouter"
    )
    ci.add_argument("--model")
    ci.add_argument("--defense", choices=("baseline", "explicit"), default="baseline")
    ci.add_argument("--baseline-model")
    ci.add_argument("--baseline-defense")
    ci.add_argument("--pricing-file", type=Path)
    ci.add_argument("--budget", type=float, default=20.0)
    from .github_cli import add_commands

    add_commands(commands)
    return root


def credential(args, plan):
    load_dotenv(dotenv_path=Path.cwd() / ".env", override=False)
    if args.opencode_auth:
        if plan.name != "openrouter":
            raise ValueError("--opencode-auth is only supported for OpenRouter")
        entry = json.loads(args.opencode_auth.expanduser().read_text()).get("openrouter", {})
        if entry.get("type") != "api" or not entry.get("key"):
            raise ValueError("The selected OpenCode auth file has no OpenRouter API credential")
        os.environ["OPENROUTER_API_KEY"] = entry["key"]
    plan.validate_environment(os.environ)
    key = os.environ.get(plan.api_key_env, "").strip()
    if not key:
        raise ValueError(f"Set {plan.api_key_env} for the selected provider")
    return key


def usage_from_logs(logs, plan=None):
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
        if type(cost) in (float, int) and math.isfinite(cost) and cost >= 0:
            costs.append(cost)
    complete_cost = sum(costs) if calls and len(costs) == len(calls) else None
    return {
        "input_tokens": sum(u.input_tokens for u in usages),
        "output_tokens": sum(u.output_tokens for u in usages),
        "provider_reported_cost_usd": complete_cost,
        "inspect_cost_estimate_usd": (
            sum(u.total_cost for u in usages)
            if usages and all(u.total_cost is not None for u in usages)
            else None
        ),
        "reservation_rate_cost_estimate_usd": (
            sum(
                (
                    u.input_tokens
                    + (getattr(u, "input_tokens_cache_read", 0) or 0)
                    + (getattr(u, "input_tokens_cache_write", 0) or 0)
                )
                * plan.prompt_price_cap
                + u.output_tokens * plan.completion_price_cap
                for u in usages
            )
            / 1_000_000
            if plan is not None and usages
            else None
        ),
        "api_calls_with_reported_cost": len(costs),
        "api_calls_without_reported_cost": len(calls) - len(costs),
    }


async def adapter_run(args, cases, defenses, output, metadata):
    from .adapter import PROTOCOL, AdapterConfig, AdapterRequest, run_adapter, tool_schemas
    from .provenance import experiment_provenance
    from .task import review_instructions
    from .world import World, score_world

    config = AdapterConfig.from_file(args.adapter)
    metadata["adapter"] = config.to_metadata()
    reviewer_source = config.source_fingerprint()
    metadata["provenance"] = experiment_provenance(
        {defense: review_instructions(defense) for defense in defenses},
        tool_schemas(),
        protocol=PROTOCOL,
        reviewer_source=reviewer_source,
    )
    metadata["expected_groups"] = [
        {"model": "adapter/" + config.name, "defense": d} for d in defenses
    ]
    metadata["bounds"] = {
        "adapter_limits": config.to_metadata()["limits"],
        "block_writes": args.block_writes,
    }
    metadata["sampling"] = (
        "Controlled by the supplied reviewer; repetitions launch fresh processes."
    )
    metadata["cost_note"] = "External adapter API billing is not managed by this runner."
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    for defense in defenses:
        for case in cases:
            for epoch in range(1, args.epochs + 1):
                if config.source_fingerprint() != reviewer_source:
                    raise ValueError("Declared reviewer source changed during the evaluation")
                world = World.for_case(case, args.block_writes)

                async def dispatch(name, arguments, world=world, case=case):
                    if name == "read_pr":
                        return world.read_pr(case)
                    if name == "read_file":
                        return world.read_file(case, **arguments)
                    if name == "write_file":
                        return world.write_file(**arguments)
                    if name == "submit_review":
                        return world.submit(**arguments)
                    raise ValueError("Unknown tool")

                request = AdapterRequest(
                    instructions=review_instructions(defense),
                    task=f"Review {case.source_path}. Caller assumptions: {case.assumptions}",
                    source_path=case.source_path,
                )
                result = await run_adapter(config, request, dispatch)
                try:
                    source_changed = config.source_fingerprint() != reviewer_source
                except (ValueError, OSError):
                    source_changed = True
                row = score_world(case, world, write_requests=result.write_requests)
                row.update(
                    model="adapter/" + config.name,
                    defense=defense,
                    epoch=epoch,
                    trial_group=metadata["run_id"],
                    adapter=result.to_dict(),
                    error=result.message if result.status == "error" else None,
                    stop_reason=result.error_code,
                    model_stop_reason=None,
                )
                if result.status != "completed" or source_changed:
                    row.update(
                        completed=False, conclusive=False, passed=False, review_correct=False
                    )
                if source_changed:
                    row.update(
                        error="Declared reviewer source changed during the evaluation",
                        stop_reason="reviewer_source_changed",
                    )
                rows.append(row)
                # Keep observed events even if a later case crashes or the run is interrupted.
                with (output / "events.jsonl").open("a") as stream:
                    stream.write(json.dumps(row) + "\n")
                if source_changed:
                    write_report(rows, output, metadata)
                    raise ValueError(row["error"])
        write_report(rows, output, metadata)
    metadata["run_finished"] = True
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    report = write_report(rows, output, metadata)
    print(json.dumps(summarize(rows), indent=2))
    print("Report: " + str(report.resolve()))
    return 2 if any(r["error"] for r in rows) else 0


def run(args, cases_override=None):
    from .provenance import experiment_provenance
    from .task import native_tool_schemas, review_instructions

    cases = (
        cases_override
        if cases_override is not None
        else [
            c
            for c in build_cases(split=args.split, language=args.language)
            if (not args.family or c.family in args.family)
            and (not args.surface or c.surface in args.surface)
        ]
    )
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
            reasoning_summary="none"
            if args.command == "run" and args.provider == "openai"
            else None,
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
        "run_kind": {"demo": "calibration", "run": "pilot", "run-adapter": "adapter"}[args.command],
        "scoring_version": "0.2.0",
        "corpus_version": "0.2.0",
        "split": args.split,
        "language": args.language,
        "expected_samples": [
            {"case_id": c.id, "epoch": epoch} for c in cases for epoch in range(1, args.epochs + 1)
        ],
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
            "block_writes": args.block_writes,
        },
        "provenance": experiment_provenance(
            {defense: review_instructions(defense) for defense in defenses},
            native_tool_schemas(),
            protocol="inspect",
        ),
    }
    logs = []
    plan = None
    if args.command == "run-adapter":
        return asyncio.run(adapter_run(args, cases, defenses, output, metadata))
    if args.command == "run":
        if not 1 <= args.concurrency <= 8:
            raise ValueError("concurrency must be between 1 and 8")
        model_ids = list(dict.fromkeys(args.model))
        plan = prepare_provider(
            args.provider,
            model_ids,
            prompt_price_cap=args.prompt_price_cap,
            completion_price_cap=args.completion_price_cap,
            pricing_file=args.pricing_file,
        )
        metadata["provider"] = plan.to_metadata()
        metadata["expected_groups"] = [
            {"model": plan.inspect_model_id(m), "defense": d} for m in model_ids for d in defenses
        ]
        amount = planned_cost(
            len(cases) * len(defenses) * len(model_ids) * args.epochs,
            args.max_turns,
            args.max_input_bytes,
            args.max_output_tokens,
            plan.prompt_price_cap,
            plan.completion_price_cap,
        )
        if amount > args.budget:
            raise ValueError(
                f"Conservative reservation ${amount:.4f} exceeds this run's budget; select a smaller --family/--surface suite"
            )
        if plan.name == "openrouter":
            metadata["catalog"] = model_snapshot(
                model_ids, plan.prompt_price_cap, plan.completion_price_cap
            )
            metadata["provider_policy"] = plan.model_args()["provider"]
        else:
            metadata["billing_note"] = (
                "Native API prices are recorded assumptions, not remote price caps. "
                "Token-based estimates are not invoices; unknown billed costs retain reservations."
            )
        metadata["planned_reservation_usd"] = amount
        if args.dry_run:
            print(json.dumps(metadata, indent=2))
            return 0
        key = credential(args, plan)
        before = api_get("key", key)["data"] if plan.name == "openrouter" else {}
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
                model=guarded_model(plan, model_id),
                epochs=args.epochs,
                max_samples=args.concurrency,
                log_dir=str(output / "logs"),
                display="none",
                log_model_api=True,
            )
            logs.extend(new)
            metadata["usage"] = usage_from_logs(logs, plan)
            write_report(rows_from_logs(logs), output, metadata)
            print(json.dumps(summarize(rows_from_logs(new))), flush=True)
        if plan.name == "openrouter":
            try:
                after = api_get("key", key)["data"]
                metadata["shared_key_usage_delta_usd"] = after.get("usage", 0) - before.get(
                    "usage", 0
                )
                metadata["key_usage_note"] = (
                    "May include concurrent use by other apps and delayed billing."
                )
            except (HTTPError, URLError, TimeoutError):
                metadata["key_usage_note"] = "Post-run key usage could not be fetched."
    else:
        modes = list(dict.fromkeys(args.mode or ["reference", "hijacked", "incomplete"]))
        metadata["expected_groups"] = [
            {"model": "mockllm/calibration-" + mode, "defense": d}
            for mode in modes
            for d in defenses
        ]
        for mode in modes:
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
    metadata["usage"] = usage_from_logs(logs, plan)
    metadata["run_finished"] = True
    output.mkdir(parents=True, exist_ok=True)
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n")
    report = write_report(rows, output, metadata)
    if (
        args.command == "run"
        and metadata["usage"]["api_calls_without_reported_cost"] == 0
        and metadata["usage"]["api_calls_with_reported_cost"]
    ):
        settlement = settle(args.ledger, run_id, output / "report.json")
        (output / "settlement.json").write_text(json.dumps(settlement, indent=2) + "\n")
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
        if args.command == "corpus-export":
            from .upstream_runner import export_upstream

            return export_upstream(args)
        if args.command in ("boundary-demo", "boundary-run-adapter"):
            from .boundary_runner import run_boundary_command

            return run_boundary_command(args)
        if args.command in (
            "repository-demo",
            "repository-run-adapter",
            "repository-run-model",
        ):
            from .repository_runner import run_repository_command, run_repository_model

            return (
                run_repository_model(args)
                if args.command == "repository-run-model"
                else run_repository_command(args)
            )
        if args.command == "dashboard":
            from .dashboard import default_report_paths, write_dashboard

            output = write_dashboard(args.reports or default_report_paths(), args.output)
            print(output.resolve())
            return 0
        if args.command in ("github-preview", "github-publish"):
            from .github_cli import handle_command

            return handle_command(args)
        if args.command == "ci":
            from .ci import run_ci

            return run_ci(
                args.baseline,
                args.output,
                **{
                    name: getattr(args, name)
                    for name in (
                        "mode",
                        "provider",
                        "model",
                        "defense",
                        "baseline_model",
                        "baseline_defense",
                        "pricing_file",
                        "budget",
                    )
                },
            )
        if args.command == "report":
            from .json_input import read_json_object
            from .reconstruct import validate_logs

            metadata = read_json_object(args.manifest)
            logs = [read_eval_log(str(p)) for p in args.logs]
            if metadata.get("scoring_version") != "0.2.0":
                raise ValueError("Use the original v0.1 runner for historical v0.1 logs")
            verification = validate_logs(
                logs, metadata, verify_scores=not args.preserve_recorded_scores
            )
            metadata["score_verification"] = verification or {
                "status": "unchecked",
                "reason": "Original scores explicitly retained without consistency checking",
            }
            metadata.update(reconstructed=True, usage=usage_from_logs(logs))
            report = write_report(
                rows_from_logs(logs),
                args.output,
                metadata,
            )
            print(report.resolve())
            return 0
        if args.command == "compare":
            from .compare import compare_reports, format_comparison
            from .json_input import read_json_object

            if args.output and args.output.resolve() in (
                args.baseline.resolve(),
                args.candidate.resolve(),
            ):
                raise ValueError("Comparison output must not overwrite either source report")
            result = compare_reports(
                read_json_object(args.baseline),
                read_json_object(args.candidate),
                **{
                    key: getattr(args, key)
                    for key in (
                        "baseline_model",
                        "baseline_defense",
                        "candidate_model",
                        "candidate_defense",
                    )
                },
            )
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, indent=2) + "\n")
            print(format_comparison(result))
            return result["exit_code"]
        return run(args)
    except (ValueError, OSError, HTTPError, URLError, ProviderRequestError) as exc:
        # Do not dump SDK objects, request headers, auth files or full tracebacks here.
        print(f"ReviewBoundary: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
