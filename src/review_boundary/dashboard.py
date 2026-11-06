"""Export recorded reports into a bounded, self-contained dashboard without rescoring."""

import json
import math
import os
import re
import stat
import tempfile
from importlib.resources import files
from pathlib import Path

MAX_REPORTS = 8
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_ROWS = 10_000
MAX_DEPTH = 20
MAX_STRING_BYTES = 1024 * 1024
MAX_EVENTS_PER_ROW = 1000
MAX_FINDINGS_PER_REVIEW = 100
MAX_EXPORT_BYTES = 64 * 1024 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
DEFAULT_REPORTS = (
    "examples/calibration-v2/report.json",
    "examples/pilot-v2-typescript/report.json",
    "examples/pilot-v2-rust-heldout/report.json",
)
REQUIRED_STRINGS = ("case_id", "family", "variant", "surface", "model", "defense")
REQUIRED_BOOLEANS = (
    "attacked",
    "completed",
    "conclusive",
    "review_correct",
    "write_attempted",
    "workspace_modified",
    "passed",
)
OPTIONAL_BOOLEANS = ("payload_exposed", "attack_goal_eligible")
OPTIONAL_METRICS = (
    "issue_reported",
    "evidence_grounded",
    "citation_correct",
    "attack_goal_reached",
)
SUMMARY_COUNTS = (
    "total",
    "completed",
    "conclusive",
    "correct_reviews",
    "write_attempts",
    "modified_workspaces",
    "errors",
    "incomplete",
    "attack_goal_eligible",
    "paired_eligible",
    "paired_degradations",
    "fixed_rubric_failures",
    "vulnerable_rubric_failures",
)


class DashboardError(ValueError):
    """A report or export cannot safely be displayed by the static dashboard."""


def default_report_paths(directory: Path | None = None) -> list[Path]:
    """Find the three example reports in the current checkout, when available."""
    root = Path.cwd() if directory is None else Path(directory)
    return [root / relative for relative in DEFAULT_REPORTS if (root / relative).is_file()]


def _json_values(value, depth=0) -> None:
    if depth > MAX_DEPTH:
        raise DashboardError(f"Report nesting must not exceed {MAX_DEPTH} levels")
    if value is None or type(value) is bool:
        return
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="surrogatepass")) > MAX_STRING_BYTES:
            raise DashboardError("Report strings must not exceed 1 MiB of UTF-8 data")
        return
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise DashboardError("Report integers must fit JavaScript's exact integer range")
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise DashboardError("Report numbers must be finite")
        if value.is_integer() and abs(value) > MAX_SAFE_INTEGER:
            raise DashboardError("Report integers must fit JavaScript's exact integer range")
        return
    if isinstance(value, list):
        for item in value:
            _json_values(item, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _json_values(key, depth + 1)
            _json_values(item, depth + 1)
        return
    raise DashboardError("Reports must contain only JSON-compatible values")


def _string(value, label: str, *, nullable=False, nonempty=False) -> None:
    if value is None and nullable:
        return
    if not isinstance(value, str) or (nonempty and not value.strip()):
        raise DashboardError(f"{label} must be a string" + (" or null" if nullable else ""))


def _integer(value, label: str, *, minimum=0) -> None:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise DashboardError(f"{label} must be an integer >= {minimum}")


def _review(value, label: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise DashboardError(f"{label} must be an object or null")
    _string(value.get("verdict"), f"{label}.verdict", nonempty=True)
    findings = value.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS_PER_REVIEW:
        raise DashboardError(
            f"{label}.findings must be a list with at most {MAX_FINDINGS_PER_REVIEW} entries"
        )
    for index, finding in enumerate(findings):
        name = f"{label}.findings[{index}]"
        if not isinstance(finding, dict):
            raise DashboardError(f"{name} must be an object")
        for field in ("category", "file", "evidence", "explanation"):
            _string(finding.get(field), f"{name}.{field}", nonempty=True)
        _integer(finding.get("line"), f"{name}.line", minimum=1)


def _events(value, label: str) -> None:
    if not isinstance(value, list) or len(value) > MAX_EVENTS_PER_ROW:
        raise DashboardError(f"{label} must be a list with at most {MAX_EVENTS_PER_ROW} entries")
    for index, event in enumerate(value):
        name = f"{label}[{index}]"
        if not isinstance(event, dict):
            raise DashboardError(f"{name} must be an object")
        _string(event.get("tool"), f"{name}.tool", nonempty=True)
        for field in ("status", "path", "content"):
            if field in event:
                _string(event[field], f"{name}.{field}")
        if "content_truncated" in event and type(event["content_truncated"]) is not bool:
            raise DashboardError(f"{name}.content_truncated must be a boolean")


def _metadata(value: dict) -> None:
    for field in (
        "run_id",
        "run_kind",
        "scoring_version",
        "corpus_version",
        "project_version",
        "inspect_ai_version",
        "suite_sha256",
        "split",
        "language",
        "sampling",
    ):
        if field in value:
            _string(value[field], f"metadata.{field}", nullable=True)
    for field in ("run_finished", "block_writes"):
        if field in value and type(value[field]) is not bool:
            raise DashboardError(f"metadata.{field} must be a boolean")
    for field in ("epochs", "case_count"):
        if field in value:
            _integer(value[field], f"metadata.{field}", minimum=1 if field == "epochs" else 0)
    if "usage" in value:
        usage = value["usage"]
        if not isinstance(usage, dict):
            raise DashboardError("metadata.usage must be an object")
        for field in (
            "input_tokens",
            "output_tokens",
            "api_calls_with_reported_cost",
            "api_calls_without_reported_cost",
        ):
            if field in usage:
                _integer(usage[field], f"metadata.usage.{field}")
        cost = usage.get("provider_reported_cost_usd")
        if cost is not None and (type(cost) not in (int, float) or cost < 0):
            raise DashboardError(
                "metadata.usage.provider_reported_cost_usd must be nonnegative or null"
            )


def validate_report(report: dict) -> None:
    """Validate display fields and limits, preserving every recorded measurement."""
    _json_values(report)
    if (
        not isinstance(report, dict)
        or type(report.get("schema_version")) is not int
        or report["schema_version"] != 2
    ):
        raise DashboardError("Dashboard reports require integer schema_version 2")
    if not isinstance(report.get("metadata"), dict):
        raise DashboardError("Report metadata must be an object")
    _metadata(report["metadata"])
    if "generated_at" in report:
        _string(report["generated_at"], "generated_at")
    for field in ("summary", "coverage"):
        if field in report and not isinstance(report[field], dict):
            raise DashboardError(f"Report {field} must be an object")
    for field in SUMMARY_COUNTS:
        if field in report.get("summary", {}):
            _integer(report["summary"][field], f"summary.{field}")
    rows = report.get("rows")
    if not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise DashboardError(f"Report rows must be a list with at most {MAX_ROWS} entries")
    for index, row in enumerate(rows):
        label = f"rows[{index}]"
        if not isinstance(row, dict):
            raise DashboardError(f"{label} must be an object")
        for field in REQUIRED_STRINGS:
            _string(row.get(field), f"{label}.{field}", nonempty=True)
        _integer(row.get("epoch"), f"{label}.epoch", minimum=1)
        for field in REQUIRED_BOOLEANS:
            if type(row.get(field)) is not bool:
                raise DashboardError(f"{label}.{field} must be a boolean")
        for field in OPTIONAL_BOOLEANS:
            if field in row and type(row[field]) is not bool:
                raise DashboardError(f"{label}.{field} must be a boolean")
        for field in OPTIONAL_METRICS:
            if field in row and row[field] is not None and type(row[field]) is not bool:
                raise DashboardError(f"{label}.{field} must be a boolean or null")
        for field in (
            "language",
            "split",
            "source_path",
            "trial_group",
            "error",
            "stop_reason",
            "model_stop_reason",
        ):
            if field in row:
                _string(row[field], f"{label}.{field}", nullable=True)
        for field in (
            "finding_count",
            "expected_category_findings",
            "supported_findings",
            "write_requests_seen",
        ):
            if field in row:
                _integer(row[field], f"{label}.{field}")
        if "review" not in row:
            raise DashboardError(f"{label}.review must be present, including when null")
        _review(row["review"], f"{label}.review")
        _events(row.get("events"), f"{label}.events")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DashboardError("Report JSON must not contain duplicate object keys")
        result[key] = value
    return result


def _read_report(path: Path) -> tuple[dict, int]:
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
        raise DashboardError("Each report must be a regular file no larger than 16 MiB")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise DashboardError("Each report must be a regular file no larger than 16 MiB")
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise DashboardError("Each report must be no larger than 16 MiB")
    try:
        report = json.loads(raw, object_pairs_hook=_unique_object)
    except (UnicodeError, RecursionError) as error:
        raise DashboardError(
            "Report JSON contains invalid encoding or excessive nesting"
        ) from error
    validate_report(report)
    return report, len(raw)


def _assets() -> dict[str, str]:
    resource = files("review_boundary").joinpath("web")
    return {
        name: resource.joinpath(name).read_text(encoding="utf-8")
        for name in ("index.html", "dashboard.css", "dashboard.js")
    }


def _script_json(value: dict) -> str:
    encoded = json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    for character, escaped in (
        ("<", "\\u003c"),
        (">", "\\u003e"),
        ("&", "\\u0026"),
        ("\u2028", "\\u2028"),
        ("\u2029", "\\u2029"),
    ):
        encoded = encoded.replace(character, escaped)
    return encoded


def write_dashboard(report_paths: list[Path], output: Path) -> Path:
    """Inline validated report data and local frontend assets into one HTML file."""
    if not isinstance(report_paths, (list, tuple)) or len(report_paths) > MAX_REPORTS:
        raise DashboardError(f"A dashboard accepts at most {MAX_REPORTS} report files")
    output = Path(output).expanduser()
    paths = [Path(path).expanduser() for path in report_paths]
    for path in paths:
        if output.resolve() == path.resolve() or (
            output.exists() and path.exists() and output.samefile(path)
        ):
            raise DashboardError("Dashboard output must not overwrite an input report")
    reports = []
    total_bytes = total_rows = 0
    for path in paths:
        report, byte_count = _read_report(path)
        total_bytes += byte_count
        total_rows += len(report["rows"])
        if total_bytes > MAX_TOTAL_BYTES or total_rows > MAX_ROWS:
            raise DashboardError("Dashboard inputs must total at most 32 MiB and 10,000 rows")
        parent = path.resolve().parent.name
        name = (parent or path.stem).replace("_", " ").replace("-", " ")
        reports.append({"name": name, "report": report})
    assets = _assets()
    replacements = {
        "/*__DASHBOARD_CSS__*/": assets["dashboard.css"],
        "/*__DASHBOARD_JS__*/": assets["dashboard.js"],
        "<!--__DASHBOARD_DATA__-->": (
            '<script id="dashboard-data" type="application/json">'
            + _script_json({"reports": reports})
            + "</script>"
        ),
    }
    template = assets["index.html"]
    if any(template.count(marker) != 1 for marker in replacements):
        raise DashboardError(
            "Dashboard template must contain each asset and data marker exactly once"
        )
    html = re.sub(
        "|".join(re.escape(marker) for marker in replacements),
        lambda match: replacements[match.group(0)],
        template,
    )
    if len(html.encode("utf-8")) > MAX_EXPORT_BYTES:
        raise DashboardError("The escaped dashboard exceeds the 64 MiB export limit")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            stream.write(html)
        temporary.replace(output)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return output
