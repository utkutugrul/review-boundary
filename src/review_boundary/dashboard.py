"""Export recorded reports into a bounded, self-contained dashboard without rescoring."""

import json
import os
import re
import stat
import tempfile
from collections import Counter
from importlib.resources import files
from pathlib import Path

from .report_contract import detect_contract, validate_report_document
from .report_validation import (
    DEFAULT_REPORTS,
    MAX_DEPTH,
    MAX_EVENTS_PER_ROW,
    MAX_EXPORT_BYTES,
    MAX_FILE_BYTES,
    MAX_FINDINGS_PER_REVIEW,
    MAX_REPORTS,
    MAX_ROWS,
    MAX_SAFE_INTEGER,
    MAX_STRING_BYTES,
    MAX_TOTAL_BYTES,
    OPTIONAL_BOOLEANS,
    OPTIONAL_METRICS,
    REQUIRED_BOOLEANS,
    REQUIRED_STRINGS,
    SUMMARY_COUNTS,
    DashboardError,
    _json_values,
    validate_legacy_report,
)

__all__ = [
    "DEFAULT_REPORTS",
    "MAX_DEPTH",
    "MAX_EVENTS_PER_ROW",
    "MAX_EXPORT_BYTES",
    "MAX_FILE_BYTES",
    "MAX_FINDINGS_PER_REVIEW",
    "MAX_REPORTS",
    "MAX_ROWS",
    "MAX_SAFE_INTEGER",
    "MAX_STRING_BYTES",
    "MAX_TOTAL_BYTES",
    "OPTIONAL_BOOLEANS",
    "OPTIONAL_METRICS",
    "REQUIRED_BOOLEANS",
    "REQUIRED_STRINGS",
    "SUMMARY_COUNTS",
    "DashboardError",
    "default_report_paths",
    "validate_report",
    "write_dashboard",
]


def default_report_paths(directory: Path | None = None) -> list[Path]:
    """Find the three example reports in the current checkout, when available."""
    root = Path.cwd() if directory is None else Path(directory)
    return [root / relative for relative in DEFAULT_REPORTS if (root / relative).is_file()]


def validate_report(report: dict) -> None:
    """Validate recorded documents while retaining the public dashboard limit overrides."""
    wrapped = (
        isinstance(report, dict)
        and type(report.get("schema_version")) is int
        and report["schema_version"] == 3
    )
    _json_values(
        report, max_depth=MAX_DEPTH + (2 if wrapped else 0), max_string_bytes=MAX_STRING_BYTES
    )
    contract = detect_contract(report)
    native = report["report"] if contract.envelope_version else report
    if contract.report_kind == "legacy":
        validate_legacy_report(
            native,
            max_rows=MAX_ROWS,
            max_depth=MAX_DEPTH,
            max_string_bytes=MAX_STRING_BYTES,
            max_events=MAX_EVENTS_PER_ROW,
            max_findings=MAX_FINDINGS_PER_REVIEW,
        )
        if contract.envelope_version is None:
            return
    validate_report_document(report)
    if len(native["rows"]) > MAX_ROWS:
        raise DashboardError(f"Report rows must be a list with at most {MAX_ROWS} entries")
    for row in native["rows"]:
        if len(row["events"]) > MAX_EVENTS_PER_ROW:
            raise DashboardError("Report row events exceed the dashboard limit")
        review = row["review"]
        if review is not None and len(review["findings"]) > MAX_FINDINGS_PER_REVIEW:
            raise DashboardError("Report review findings exceed the dashboard limit")


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
        for name in ("index.html", "dashboard.css", "report-contracts.js", "dashboard.js")
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


def _report_names(paths: list[Path]) -> list[str]:
    names = [
        (path.resolve().parent.name or path.stem).replace("_", " ").replace("-", " ")
        for path in paths
    ]
    counts = Counter(names)
    used = {name for name in names if counts[name] == 1}
    for index, (path, name) in enumerate(zip(paths, names, strict=True)):
        if counts[name] == 1:
            continue
        candidate = f"{name} / {path.name}"
        label, suffix = candidate, 2
        while label in used:
            label = f"{candidate} ({suffix})"
            suffix += 1
        names[index] = label
        used.add(label)
    return names


def write_dashboard(
    report_paths: list[Path], output: Path, *, snapshot_artifacts=None, suite=None
) -> Path:
    """Inline validated report data and local frontend assets into one HTML file."""
    if not isinstance(report_paths, (list, tuple)) or len(report_paths) > MAX_REPORTS:
        raise DashboardError(f"A dashboard accepts at most {MAX_REPORTS} report files")
    supplied_evidence = snapshot_artifacts is not None or suite is not None
    if supplied_evidence and len(report_paths) != 1:
        raise DashboardError("Supplied snapshot evidence requires exactly one dashboard report")
    output = Path(output).expanduser()
    paths = [Path(path).expanduser() for path in report_paths]
    for path in paths:
        if output.resolve() == path.resolve() or (
            output.exists() and path.exists() and output.samefile(path)
        ):
            raise DashboardError("Dashboard output must not overwrite an input report")
    reports = []
    total_bytes = total_rows = 0
    for path, name in zip(paths, _report_names(paths), strict=True):
        report, byte_count = _read_report(path)
        total_bytes += byte_count
        native = report["report"] if detect_contract(report).envelope_version else report
        total_rows += len(native["rows"])
        if total_bytes > MAX_TOTAL_BYTES or total_rows > MAX_ROWS:
            raise DashboardError("Dashboard inputs must total at most 32 MiB and 10,000 rows")
        entry = {"name": name, "report": report}
        if supplied_evidence:
            from .report_export import compile_snapshot_evidence

            _, entry["evidence_verification"] = compile_snapshot_evidence(
                report, snapshot_artifacts=snapshot_artifacts, suite=suite
            )
            evidence_bytes = sum(
                len(json.dumps(value, ensure_ascii=True, allow_nan=False).encode("utf-8"))
                for value in (snapshot_artifacts, suite)
                if value is not None
            )
            if total_bytes + evidence_bytes > MAX_TOTAL_BYTES:
                raise DashboardError("Dashboard inputs must total at most 32 MiB and 10,000 rows")
        reports.append(entry)
    assets = _assets()
    replacements = {
        "/*__DASHBOARD_CSS__*/": assets["dashboard.css"],
        "/*__REPORT_CONTRACT_JS__*/": assets["report-contracts.js"],
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
