"""Render one validated workflow run as a deterministic, self-contained HTML file."""

import argparse
import base64
import hashlib
import json
import os
import stat
import tempfile
from html import escape
from importlib.resources import files
from pathlib import Path

from .workflow_report import MAX_RUN_REPORT_BYTES, validate_workflow_run

MAX_DASHBOARD_BYTES = 16 * 1024 * 1024
_METRICS = {
    "workflow_completed": "Workflow completed",
    "carrier_exposed": "Carrier exposed",
    "request_replay_complete": "Request replay complete",
    "authorized_actions_completed": "Authorized actions completed",
    "task_utility": "Task utility",
    "safe_task_success": "Safe task success",
    "reviewer_resisted": "Reviewer resisted",
}
_EFFECTS = {
    "unauthorized_attempts": "Unauthorized attempts",
    "unauthorized_effects": "Unauthorized effects",
    "unauthorized_prevented": "Unauthorized prevented",
    "authorized_attempts": "Authorized attempts",
    "authorized_effects": "Authorized effects",
    "false_blocks": "False blocks",
    "unresolved_effect_attempts": "Unresolved effect attempts",
}
_SESSION_FIELDS = {
    "status": "Recorded status",
    "carrier_exposed": "Carrier exposed",
    "required_actions_completed": "Required actions completed",
    "review_completed": "Review completed",
    "review_structural_passed": "Structural review passed",
    "review_semantic_passed": "Semantic review passed",
    "finding_count": "Finding count",
    "write_attempted": "Write attempted",
    "write_requests_seen": "Write requests seen",
    "review_sha256": "Review SHA-256 (identity only)",
}


class WorkflowDashboardError(ValueError):
    """Invalid input or an output that cannot be safely produced."""


def _text(value):
    return escape(str(value), quote=True)


def _value(record, key):
    if record is None:
        return "Missing"
    if key not in record:
        return "Not recorded"
    value = record[key]
    if value is None:
        return "Unknown (null)"
    if type(value) is bool:
        return "True" if value else "False"
    return _text(value)


def _pairs(pairs):
    return "<dl>" + "".join(f"<dt>{_text(k)}</dt><dd>{_text(v)}</dd>" for k, v in pairs) + "</dl>"


def _table(headers, rows):
    head = "".join(f'<th scope="col">{_text(h)}</th>' for h in headers)
    body = "".join(
        "<tr>"
        + f'<th scope="row">{_text(row[0])}</th>'
        + "".join(f"<td>{cell}</td>" for cell in row[1:])
        + "</tr>"
        for row in rows
    )
    return f'<div class="table-scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _script_json(report):
    # ASCII also escapes Unicode line separators. No report text can close this script.
    return (
        json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _case_html(case, row, number):
    state = "missing" if row is None else "complete" if row["workflow_completed"] else "incomplete"
    unknown = row is not None and any(row[k] is None for k in _METRICS)
    search = " ".join(
        case[k] for k in ("case_id", "family", "source_group", "variant", "condition")
    )
    steps = []
    for session in case["sessions"]:
        index = session["session_index"]
        recorded = None if row is None else row["sessions"][index]
        status = "not_recorded" if recorded is None else recorded["status"]
        observed = row is not None and index < row["observed_sessions"]
        steps.append(
            f'<li><span class="step-index">{index + 1:02d}</span><div>'
            f'<strong>{_text(session["actor"])}</strong><span class="session-status">'
            f"{_text(status)} · {'Observed' if observed else 'Observation missing'}</span></div></li>"
        )
    metric_rows = [(label, _value(row, key)) for key, label in _METRICS.items()]
    effect_rows = [(label, _value(row, key)) for key, label in _EFFECTS.items()]
    sessions = []
    for session in case["sessions"]:
        index = session["session_index"]
        recorded = None if row is None else row["sessions"][index]
        # An absent row has no observations; an absent field is different from null.
        sessions.append(recorded if recorded is not None else {})
    session_rows = [
        (label, *(_value(session, key) for session in sessions))
        for key, label in _SESSION_FIELDS.items()
    ]
    session_table = _table(
        ["Session field", *(f"{s['session_index'] + 1}: {s['actor']}" for s in case["sessions"])],
        session_rows,
    )
    context = [
        ("Case ID", case["case_id"]),
        ("Source group", case["source_group"]),
        ("Case SHA-256 (identity only)", case["workflow_case_sha256"]),
        (
            "Resistance availability",
            "Unavailable: no scored row" if row is None else row["resistance_availability"],
        ),
        ("Row authenticity", "Unavailable: no scored row" if row is None else row["authenticity"]),
        (
            "Semantic method",
            "Unavailable: no scored row" if row is None else row["semantic_method"],
        ),
    ]
    raw = (
        "No scored row recorded."
        if row is None
        else json.dumps(row, ensure_ascii=False, indent=2, sort_keys=True)
    )
    missing_note = (
        '<p class="notice">No scored row recorded. Metrics and observations are missing.</p>'
        if row is None
        else ""
    )
    return (
        f'<article class="case" data-case data-state="{state}" data-unknown="{str(unknown).lower()}" '
        f'data-condition="{_text(case["condition"])}" data-search="{_text(search)}">'
        f'<header class="case-heading"><span class="case-number">{number:02d}</span><div>'
        f"<h3>{_text(case['family'].replace('_', ' '))}</h3>"
        f"<p>{_text(case['condition'])} · {_text(case['variant'])} · {_text(case['source_group'])}</p></div>"
        f'<span class="badge {state}">{state.capitalize()}</span></header>'
        f'<ol class="timeline">{"".join(steps)}</ol>'
        f'<details class="case-details"><summary>Result details</summary>{missing_note}{_pairs(context)}'
        f'<div class="detail-grid"><section><h4>Case metrics</h4>{_table(["Metric", "Recorded value"], metric_rows)}</section>'
        f"<section><h4>Recorded effects</h4>{_table(['Counter', 'Recorded value'], effect_rows)}</section></div>"
        f"<h4>Session observations</h4>{session_table}"
        '<p class="note">Unknown (null) is an explicit unknown. Not recorded means the field is absent. '
        "Semantic judgments are unavailable. Session order is declared order; no timing is recorded.</p>"
        f"<details><summary>Original scored row and refusal verifications</summary><pre>{_text(raw)}</pre></details>"
        "</details></article>"
    )


def render_workflow_dashboard(value, *, expected=None):
    """Validate through the unchanged report contract, then render without rescoring.

    Accept a plain report object or UTF-8 JSON bytes. An optional original expected
    roster adds binding validation. Neither validation mode authenticates data.
    """
    try:
        report = validate_workflow_run(value, expected=expected)
    except (ValueError, TypeError, UnicodeError, RecursionError) as error:
        raise WorkflowDashboardError(
            "Invalid or unsupported workflow run report: check schema, bounds, binding and totals"
        ) from error
    resource = files("review_boundary").joinpath("web")
    css = resource.joinpath("workflow-dashboard.css").read_text(encoding="utf-8")
    js = resource.joinpath("workflow-dashboard.js").read_text(encoding="utf-8")
    script_hash = base64.b64encode(hashlib.sha256(js.encode("utf-8")).digest()).decode("ascii")
    style_hash = base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    policy = (
        f"default-src 'none'; script-src 'sha256-{script_hash}'; style-src 'sha256-{style_hash}'; "
        "connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    )
    coverage, declared = report["coverage"], report["expected"]
    binding = declared["binding"]
    complete = coverage["run_completed"]
    scripted = declared["evidence_kind"] == "scripted"
    evidence_label = (
        "Scripted fixture · recorded label" if scripted else "Evidence kind: not_recorded"
    )
    cards = [
        (
            "Completed cases",
            coverage["completed_cases"],
            coverage["expected_cases"],
            "Completion is separate from utility and safety.",
        ),
        (
            "Observed sessions",
            coverage["observed_sessions"],
            coverage["expected_sessions"],
            "All declared sessions stay in the timeline.",
        ),
        (
            "Missing cases",
            len(coverage["missing_case_ids"]),
            coverage["expected_cases"],
            "No scored row received for these cases.",
        ),
        (
            "Incomplete cases",
            len(coverage["incomplete_case_ids"]),
            coverage["expected_cases"],
            "Recorded cases that did not complete.",
        ),
    ]
    card_html = "".join(
        f'<section class="metric-card"><h2>{label}</h2><p class="metric-value">{n}'
        f"<small>/ {d}</small></p><p>{note}</p></section>"
        for label, n, d, note in cards
    )
    metric_rows = [
        (
            label,
            *(
                str(report["summary"]["case_metrics"][key][bucket])
                for bucket in ("true", "false", "unknown", "missing", "expected_denominator")
            ),
        )
        for key, label in _METRICS.items()
    ]
    metrics = _table(
        ["Case metric", "True", "False", "Unknown", "Missing", "Expected"], metric_rows
    )
    effects = _pairs(
        (label, report["summary"]["recorded_effect_totals"][key]) for key, label in _EFFECTS.items()
    )
    rows = {row["case_id"]: row for row in report["scored_cases"]}
    cases = "".join(
        _case_html(case, rows.get(case["case_id"]), i + 1)
        for i, case in enumerate(declared["cases"])
    )
    context = _pairs(
        [
            ("Run ID", binding["run_id"]),
            ("Reviewer (recorded label)", binding["reviewer"]),
            ("Guard", declared["guard"]),
            ("Epoch", binding["epoch"]),
        ]
    )
    validation = _pairs(
        [
            ("Contract", report["contract_version"]),
            ("Scoring", report["scoring_version"]),
            ("Schema version", report["schema_version"]),
            (
                "Expectation check",
                "Matched supplied original roster"
                if expected is not None
                else "Internal consistency against declared roster only",
            ),
            ("Evidence scope", report["evidence_scope"]),
        ]
    )
    statuses = _pairs(coverage["session_status_counts"].items())
    raw = _text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    html = f'''<!doctype html>
<html lang="en" data-theme="dark"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{_text(policy)}">
<meta name="referrer" content="no-referrer"><title>Workflow run | ReviewBoundary</title>
<style>{css}</style></head><body>
<a class="skip-link" href="#main">Skip to run</a>
<div class="shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">[rb]</span>
<div>reviewboundary<small>WORKFLOW WORKSPACE</small></div></div>
<div class="workspace-label"><span class="dot"></span> Single recorded run <span>01</span></div>
<nav aria-label="Run sections"><a href="#overview">Overview <span>↗</span></a>
<a href="#cases">Cases &amp; sessions <span>↗</span></a><a href="#meaning">Measurement notes <span>↗</span></a>
<a href="#record">Recorded JSON <span>↗</span></a></nav>
<div class="sidebar-end"><p>Your report stays here.</p><p class="note">One local HTML file. No services.</p>
<button id="theme" type="button" hidden>Use light theme</button></div></aside>
<div class="workspace"><div class="topbar"><span>Workspace <span class="muted">/</span> Workflow run</span>
<span class="local"><span class="dot"></span> Local data</span></div>
<main id="main"><header class="page-heading" id="overview"><div><p class="eyebrow">RECORDED WORKFLOW / SINGLE RUN</p>
<h1>A run, in full view.</h1><p class="description">Follow declared cases, recorded sessions and the results that remain unknown.</p></div>
<div class="run-state"><span class="badge {"complete" if complete else "incomplete"}">Run {"complete" if complete else "incomplete"}</span>
<button id="export" type="button" hidden>Export recorded JSON ↓</button></div></header>
<section class="evidence-banner" aria-label="Evidence limits"><div class="evidence-tags"><strong>{evidence_label}</strong>
<code>recorded_data_only</code><span>Authenticity: <strong>unavailable</strong></span></div>
<p>A report or screenshot cannot establish execution, model robustness, source authenticity, evaluator judgments or runtime authority.</p></section>
<section class="context" aria-label="Run context">{context}</section>
<div class="metrics">{card_html}</div>
<div class="overview-grid"><section class="panel"><header><p class="eyebrow">ALL DECLARED CASES</p><h2>Recorded case metrics</h2>
<p class="note">Each row keeps the full expected denominator. Unknown and missing stay separate.</p></header>{metrics}
<p class="panel-foot">Counts of recorded booleans, with unknown and missing buckets. No rates or rankings.</p></section>
<section class="panel effects"><header><p class="eyebrow">RECORDED ROWS ONLY</p><h2>Effects &amp; boundaries</h2></header>{effects}
<p class="panel-foot">{coverage["scored_cases"]} / {coverage["expected_cases"]} cases have scored rows. Missing cases never imply zero effects.
Guard prevention is separate from reviewer resistance.</p></section></div>
<section id="cases"><div class="section-heading"><div><p class="eyebrow">DECLARED ORDER WITHIN EACH CASE</p>
<h2>Cases &amp; session timeline</h2><p class="note">Sessions show recorded status and observation coverage. No timestamps are supplied.</p></div>
<span class="badge">{coverage["expected_cases"]} expected cases</span></div>
<div class="toolbar" id="filters" hidden><label>Search cases<input id="search" type="search" maxlength="256" placeholder="Case, family or Source group"></label>
<label>Case state<select id="state"><option value="all">All states</option><option value="complete">Complete</option>
<option value="incomplete">Incomplete</option><option value="missing">Missing row</option><option value="unknown">With unknown metrics</option></select></label>
<label>Condition<select id="condition"><option value="all">All conditions</option><option value="attack">Attack</option>
<option value="clean">Clean</option><option value="authorized_control">Authorized control</option></select></label>
<button id="reset" type="button">Reset filters</button></div>
<p id="filter-status" class="note" role="status" aria-live="polite">Showing all {coverage["expected_cases"]} declared cases.</p>
<p class="note" id="filter-note" hidden>Filters affect this timeline only. Unknown means a recorded case has a null case metric. Summary counts always cover all declared cases.</p>
<div class="cases">{cases}</div><p id="empty" class="empty" hidden>No cases match these filters.</p></section>
<section class="panel meaning" id="meaning"><header><p class="eyebrow">READ THE RECORD WITH ITS LIMITS</p><h2>What these results mean</h2></header>
<div class="meaning-grid"><div><p>Run completion records whether every declared case completed. Task utility, safe task success and reviewer resistance are separate metrics.
Controls can have unknown resistance. Unresolved effects or incomplete request replay can leave safe task success unknown.</p>
<p>Semantic judgments are unavailable without session-bound evaluator judgments. Scored rows retain their CORE11 meanings and refusal-verification labels.
No latency, cost, citation quality, comparison or model ranking is supplied by this contract.</p>
<details><summary>Validation and declared evidence scope</summary>{validation}</details></div>
<div><h3>Recorded session statuses</h3>{statuses}<p class="note">Missing observations can carry error or not_started. No scored row yields not_recorded.</p></div></div></section>
<details class="panel raw-report" id="record"><summary>Full recorded report (JSON)</summary><pre>{raw}</pre></details>
<p id="action-status" class="note" role="status" aria-live="polite"></p>
<noscript><p class="notice">JavaScript is disabled. All cases and native details remain readable; filtering and JSON download require JavaScript.</p></noscript>
</main><footer><span>[ rb ]</span> Recorded data. Visible unknowns.<span>workflow-run-report-v1 / standalone view</span></footer></div></div>
<script type="application/json" id="workflow-data">{_script_json(report)}</script>
<script>{js}</script></body></html>
'''
    if len(html.encode("utf-8")) > MAX_DASHBOARD_BYTES:
        raise WorkflowDashboardError("Workflow dashboard exceeds the 16 MiB output limit")
    return html


def _read_input(path):
    try:
        # Check again after open so a replaced path cannot introduce a blocking FIFO.
        if not stat.S_ISREG(path.stat().st_mode):
            raise WorkflowDashboardError("Input must be a regular JSON file")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_RUN_REPORT_BYTES:
                    raise WorkflowDashboardError(
                        "Input must be a regular JSON file of at most 2 MiB"
                    )
                raw = stream.read(MAX_RUN_REPORT_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(raw) > MAX_RUN_REPORT_BYTES:
            raise WorkflowDashboardError("Input exceeds the 2 MiB report limit")
        return raw
    except OSError as error:
        raise WorkflowDashboardError("Cannot read input JSON file") from error


def write_workflow_dashboard(report_path, output, *, expected=None):
    """Write a new HTML file only after validation. Never overwrite an existing path."""
    html = render_workflow_dashboard(_read_input(Path(report_path)), expected=expected)
    output = Path(output)
    temporary = None
    failure = cause = None
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".workflow-dashboard-", dir=output.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(html.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)
        # Linking a complete same-directory file publishes atomically and fails
        # if any destination already exists, including a symlink or hardlink.
        os.link(temporary, output)
    except FileExistsError as error:
        failure, cause = "Output already exists; choose a new HTML path", error
    except OSError as error:
        failure, cause = "Cannot write dashboard HTML file", error
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError as error:
                if failure is not None:
                    failure += "; staging file cleanup also failed"
                else:
                    failure, cause = "Dashboard published, but staging file cleanup failed", error
    if failure is not None:
        raise WorkflowDashboardError(failure) from cause
    return output


def main(argv=None):
    """Installed-package entry, independent of shared CLI dispatch."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="One workflow_run report JSON file")
    parser.add_argument("--output", type=Path, required=True, help="New standalone HTML path")
    parser.add_argument("--expected", type=Path, help="Optional original expected roster JSON")
    args = parser.parse_args(argv)
    try:
        expected = None if args.expected is None else _read_input(args.expected)
        write_workflow_dashboard(args.report, args.output, expected=expected)
    except WorkflowDashboardError as error:
        parser.exit(2, f"workflow dashboard: {error}\n")
    print("Workflow dashboard written. Open the selected HTML file in a browser.")


if __name__ == "__main__":
    main()
