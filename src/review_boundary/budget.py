"""Conservative local reservations plus OpenRouter provider price ceilings."""

import json
import math
import os
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from urllib.request import Request, urlopen

SCHEMA_TOKEN_ALLOWANCE = 16384
RESERVATION_MARGIN = 1.2


def planned_cost(samples, turns, input_bytes, output_tokens, prompt_price, completion_price):
    """Prices are dollars per million tokens. Input bytes overestimate text tokens."""
    values = (samples, turns, input_bytes, output_tokens, prompt_price, completion_price)
    if any(not math.isfinite(v) or v <= 0 for v in values):
        raise ValueError("Budget inputs must be positive finite numbers")
    calls = samples * turns
    cost = (
        calls
        * ((input_bytes + SCHEMA_TOKEN_ALLOWANCE) * prompt_price + output_tokens * completion_price)
        / 1_000_000
    )
    return math.ceil(cost * RESERVATION_MARGIN * 1_000_000) / 1_000_000


def ledger_artifact_paths(path: Path) -> tuple[Path, Path, Path]:
    """Return the ledger, exclusive lock, and atomic replacement paths."""
    path = Path(path)
    return path, path.with_suffix(".lock"), path.with_suffix(".tmp")


@contextmanager
def ledger_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    _, lock, _ = ledger_artifact_paths(path)
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise ValueError("Budget ledger is locked; inspect the active run before retrying") from exc
    try:
        os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def save_ledger(path: Path, data: dict) -> None:
    _, _, temporary = ledger_artifact_paths(path)
    temporary.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(temporary, path)


def reserve(path: Path, amount: float, limit: float, run_id: str) -> dict:
    """Reserve before requests. Unknown or incomplete billing retains the full reserve."""
    if not all(math.isfinite(v) and v > 0 for v in (amount, limit)):
        raise ValueError("Reservation and budget must be positive finite numbers")
    with ledger_lock(path):
        data = json.loads(path.read_text()) if path.exists() else {"limit_usd": limit, "runs": []}
        if data.get("billing_overrun"):
            raise ValueError("Budget ledger has an unresolved provider billing overrun")
        if limit > data["limit_usd"]:
            raise ValueError("This ledger's original limit cannot be raised by a run")
        total = sum(run.get("settled_usd", run["reserved_usd"]) for run in data["runs"])
        if total + amount > min(limit, data["limit_usd"]):
            raise ValueError(f"Budget exceeded: ${total:.4f} reserved + ${amount:.4f} requested")
        if any(run["id"] == run_id for run in data["runs"]):
            raise ValueError("Run ID already reserved")
        data["runs"].append(
            {"id": run_id, "reserved_usd": amount, "at": datetime.now(UTC).isoformat()}
        )
        save_ledger(path, data)
        return {
            "reserved_usd": amount,
            "total_accounted_usd": round(total + amount, 6),
            "limit_usd": min(limit, data["limit_usd"]),
        }


def settle(path: Path, run_id: str, report_path: Path) -> dict:
    """Settle a finished run only with complete per-call provider billing evidence."""
    raw = report_path.read_bytes()
    report = json.loads(raw)
    metadata = report["metadata"]
    usage = metadata.get("usage", {})
    cost = usage.get("provider_reported_cost_usd")
    if (
        metadata.get("run_id") != run_id
        or metadata.get("run_finished") is not True
        or usage.get("api_calls_without_reported_cost") != 0
        or usage.get("api_calls_with_reported_cost", 0) <= 0
        or isinstance(cost, bool)
        or not isinstance(cost, (int, float))
        or not math.isfinite(cost)
        or cost < 0
    ):
        raise ValueError("Settlement requires a finished run and complete provider cost evidence")
    with ledger_lock(path):
        data = json.loads(path.read_text())
        run = next((r for r in data["runs"] if r["id"] == run_id), None)
        if run is None:
            raise ValueError("No reservation for this run")
        proof = {
            "report_sha256": sha256(raw).hexdigest(),
            "report_path": str(report_path.resolve()),
        }
        if "settled_usd" in run:
            if (
                run["settled_usd"] != cost
                or run["settlement"]["report_sha256"] != proof["report_sha256"]
            ):
                raise ValueError("A settled run cannot be revised")
        else:
            run.update(settled_usd=cost, settlement=proof, settled_at=datetime.now(UTC).isoformat())
            if cost > run["reserved_usd"]:
                data["billing_overrun"] = True
            save_ledger(path, data)
        # Persist an unexpected overrun so subsequent requests cannot ignore it.
        if cost > run["reserved_usd"]:
            raise ValueError(
                "Provider cost exceeded the reservation; further runs need investigation"
            )
        return {"settled_usd": cost, **proof}


def api_get(endpoint: str, key: str | None = None) -> dict:
    if endpoint not in ("models", "key"):
        raise ValueError("Unsupported metadata endpoint")
    headers = {"Accept": "application/json"}
    if key:
        headers["Authorization"] = "Bearer " + key
    request = Request("https://openrouter.ai/api/v1/" + endpoint, headers=headers)
    with urlopen(request, timeout=30) as response:
        return json.load(response)


def model_snapshot(model_ids: list[str], prompt_cap: float, completion_cap: float) -> list[dict]:
    catalog = {m["id"]: m for m in api_get("models")["data"]}
    result = []
    for model_id in model_ids:
        if model_id not in catalog:
            raise ValueError(f"Model is not in the current OpenRouter catalog: {model_id}")
        model = catalog[model_id]
        if "tools" not in model.get("supported_parameters", []):
            raise ValueError(f"Model does not advertise tool support: {model_id}")
        pricing = model["pricing"]
        prices = [float(pricing.get(k, "nan")) for k in ("prompt", "completion")]
        if any(not math.isfinite(p) or p < 0 for p in prices):
            raise ValueError(f"Unsupported pricing for {model_id}")
        if prices[0] * 1_000_000 > prompt_cap or prices[1] * 1_000_000 > completion_cap:
            raise ValueError(f"Model advertised price exceeds configured cap: {model_id}")
        if float(pricing.get("request", 0)) != 0:
            raise ValueError(f"Per-request pricing is not supported: {model_id}")
        result.append(
            {"id": model_id, "pricing": pricing, "context_length": model.get("context_length")}
        )
    return result
