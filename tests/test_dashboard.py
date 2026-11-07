"""Dashboard export preserves evidence while keeping report text out of executable HTML."""

import json
import os
from copy import deepcopy
from html.parser import HTMLParser
from pathlib import Path

import pytest
from report_contract_support import native_fixture

from review_boundary import cli, dashboard
from review_boundary.boundary_runner import boundary_error_rows
from review_boundary.provenance import json_digest
from review_boundary.report_contract import export_report_envelope
from review_boundary.repository_runner import repository_error_rows


class EmbeddedData(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.scripts = []
        self.active = False
        self.text = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            attributes = dict(attrs)
            self.scripts.append(attributes)
            self.active = attributes.get("id") == "dashboard-data"

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.text.append(data)

    def parsed(self):
        return json.loads("".join(self.text))


def report():
    return {
        "schema_version": 2,
        "generated_at": "2026-11-06T10:00:00+00:00",
        "metadata": {"run_kind": "pilot", "scoring_version": "0.2.0", "epochs": 1},
        "summary": {"total": 1, "completed": 1},
        "rows": [
            {
                "case_id": "tenant/vulnerable/clean",
                "family": "tenant",
                "variant": "vulnerable",
                "surface": "clean",
                "model": "reviewer",
                "defense": "baseline",
                "epoch": 1,
                "attacked": False,
                "completed": True,
                "conclusive": True,
                "review_correct": True,
                "write_attempted": False,
                "workspace_modified": False,
                "passed": True,
                "review": {
                    "verdict": "request_changes",
                    "findings": [
                        {
                            "category": "authorization",
                            "file": "src/service.py",
                            "line": 5,
                            "evidence": "return record['value']",
                            "explanation": "Missing tenant check.",
                        }
                    ],
                },
                "events": [{"tool": "read_file", "path": "src/service.py", "status": "ok"}],
                "error": None,
            }
        ],
    }


@pytest.fixture
def assets(monkeypatch):
    content = {
        "index.html": (
            "<!doctype html><html><head><style>/*__DASHBOARD_CSS__*/</style></head><body>"
            "<!--__DASHBOARD_DATA__--><script>/*__REPORT_CONTRACT_JS__*/</script>"
            "<script>/*__DASHBOARD_JS__*/</script></body></html>"
        ),
        "dashboard.css": "body { color: white; background: black; }",
        "report-contracts.js": "globalThis.ReviewBoundaryReportContracts = {};",
        "dashboard.js": 'document.body.dataset.ready = "true";',
    }
    monkeypatch.setattr(dashboard, "_assets", lambda: content)
    return content


def save_report(tmp_path, payload=None, name="report.json"):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report() if payload is None else payload))
    return path


def test_script_breaking_text_is_escaped_and_original_data_round_trips(tmp_path, assets):
    payload = report()
    malicious = (
        "</script><script>globalThis.pwned=true</script><img src=x onerror=alert(1)>&\u2028\u2029"
    )
    payload["metadata"]["notes"] = malicious + " café 🙂"
    payload["rows"][0]["review"]["findings"][0]["explanation"] = malicious
    payload["rows"][0]["events"].append({"tool": "write_file", "content": malicious})
    source = save_report(tmp_path / "readable-report-name", payload)
    original = source.read_bytes()
    output = tmp_path / "dashboard.html"
    assert dashboard.write_dashboard([source], output) == output
    html = output.read_text()
    parsed = EmbeddedData(html)
    assert len(parsed.scripts) == 3
    assert parsed.parsed() == {"reports": [{"name": "readable report name", "report": payload}]}
    assert "<img src=x" not in html and "<script>globalThis.pwned" not in html
    assert "\\u003c/script\\u003e" in html and "\\u0026" in html
    assert "\\u2028" in html and "\\u2029" in html
    assert source.read_bytes() == original


def test_optional_metrics_and_original_labels_are_not_invented_or_rescored(tmp_path, assets):
    payload = report()
    payload["metadata"]["scoring_version"] = "recorded-custom-version"
    payload["rows"][0]["issue_reported"] = None
    payload["rows"][0]["custom_evidence"] = {"finding": ["original", 1.25, True]}
    original = deepcopy(payload)
    path = save_report(tmp_path, payload)
    output = dashboard.write_dashboard([path], tmp_path / "dashboard.html")
    embedded = EmbeddedData(output.read_text()).parsed()["reports"][0]["report"]
    assert embedded == original
    assert "evidence_grounded" not in embedded["rows"][0]
    assert embedded["rows"][0]["issue_reported"] is None


def test_replacement_markers_inside_report_text_are_preserved(tmp_path, assets):
    payload = report()
    payload["metadata"]["notes"] = (
        "/*__DASHBOARD_CSS__*/ /*__DASHBOARD_JS__*/ <!--__DASHBOARD_DATA__-->"
    )
    source = save_report(tmp_path, payload)
    output = dashboard.write_dashboard([source], tmp_path / "dashboard.html")
    assert EmbeddedData(output.read_text()).parsed()["reports"][0]["report"] == payload


def test_same_directory_names_are_distinct_stable_and_preserve_unique_names(tmp_path, assets):
    first_payload = report()
    second_payload = export_report_envelope(native_fixture()[0])
    first = save_report(tmp_path / "shared_reports", first_payload, "first.json")
    second = save_report(tmp_path / "shared_reports", second_payload, "second.json")
    unique = save_report(tmp_path / "unique_run", name="report.json")
    sources = [first, second, unique]
    original_bytes = [source.read_bytes() for source in sources]

    def entries(paths, name):
        output = dashboard.write_dashboard(paths, tmp_path / name)
        return EmbeddedData(output.read_text()).parsed()["reports"]

    forward = entries(sources, "forward.html")
    assert [entry["name"] for entry in forward] == [
        "shared reports / first.json",
        "shared reports / second.json",
        "unique run",
    ]
    assert forward == entries(sources, "repeat.html")
    assert entries(list(reversed(sources)), "reversed.html") == list(reversed(forward))
    assert [entry["report"] for entry in forward] == [first_payload, second_payload, report()]
    assert [source.read_bytes() for source in sources] == original_bytes
    repeated = entries([first, first], "duplicates.html")
    assert [entry["name"] for entry in repeated] == [
        "shared reports / first.json",
        "shared reports / first.json (2)",
    ]


@pytest.mark.parametrize("alias", ["same", "symlink", "hardlink"])
def test_output_cannot_overwrite_source_through_any_alias(tmp_path, assets, alias):
    source = save_report(tmp_path)
    before = source.read_bytes()
    output = source if alias == "same" else tmp_path / "alias.html"
    if alias == "symlink":
        output.symlink_to(source)
    elif alias == "hardlink":
        os.link(source, output)
    with pytest.raises(ValueError, match="must not overwrite"):
        dashboard.write_dashboard([source], output)
    assert source.read_bytes() == before


def test_malformed_second_report_does_not_destroy_existing_dashboard(tmp_path, assets):
    first = save_report(tmp_path, name="first.json")
    second = tmp_path / "second.json"
    second.write_text("{ broken JSON")
    output = tmp_path / "dashboard.html"
    output.write_text("previous dashboard")
    with pytest.raises(ValueError):
        dashboard.write_dashboard([first, second], output)
    assert output.read_text() == "previous dashboard"
    assert not list(tmp_path.glob(".dashboard.html.*.tmp"))


@pytest.mark.parametrize(
    "field,value",
    [
        ("attacked", "false"),
        ("completed", 1),
        ("conclusive", None),
        ("passed", "true"),
        ("model", []),
        ("case_id", ""),
        ("epoch", True),
        ("epoch", 0),
        ("issue_reported", "yes"),
        ("error", {}),
        ("write_requests_seen", -1),
        ("events", {}),
        ("events", [{"tool": 3}]),
        ("events", [{"tool": "read_file", "path": {}}]),
        ("events", [{"tool": "write_file", "content_truncated": "false"}]),
        ("review", []),
        ("review", {"verdict": "approve", "findings": {}}),
    ],
)
def test_malformed_display_fields_are_rejected(tmp_path, assets, field, value):
    payload = report()
    payload["rows"][0][field] = value
    source = save_report(tmp_path, payload)
    output = tmp_path / "dashboard.html"
    with pytest.raises(ValueError):
        dashboard.write_dashboard([source], output)
    assert not output.exists()


@pytest.mark.parametrize(
    "field,value", [("line", True), ("line", 0), ("file", []), ("evidence", {})]
)
def test_finding_fields_are_validated(tmp_path, assets, field, value):
    payload = report()
    payload["rows"][0]["review"]["findings"][0][field] = value
    with pytest.raises(ValueError, match=field):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "dashboard.html")


@pytest.mark.parametrize("field", ["attacked", "completed", "events", "review"])
def test_required_fields_cannot_be_omitted(tmp_path, assets, field):
    payload = report()
    del payload["rows"][0][field]
    with pytest.raises(ValueError, match=field):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "dashboard.html")


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {"schema_version": 1, "metadata": {}, "rows": []},
        {"schema_version": "2", "metadata": {}, "rows": []},
        {"schema_version": True, "metadata": {}, "rows": []},
        {"schema_version": 2, "metadata": [], "rows": []},
        {"schema_version": 2, "metadata": {}, "rows": {}},
    ],
)
def test_invalid_top_level_shapes_fail(tmp_path, assets, payload):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        dashboard.write_dashboard([path], tmp_path / "dashboard.html")


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf"), 2**53, 1e20, -1e20])
def test_nonfinite_or_inexact_numbers_are_rejected(tmp_path, assets, number):
    payload = report()
    payload["metadata"]["custom_number"] = number
    with pytest.raises(ValueError, match="finite|exact integer"):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "dashboard.html")


def test_duplicate_json_keys_are_not_silently_overwritten(tmp_path, assets):
    path = tmp_path / "report.json"
    path.write_text('{"schema_version":2,"metadata":{},"rows":[],"rows":[]}')
    with pytest.raises(ValueError, match="duplicate"):
        dashboard.write_dashboard([path], tmp_path / "dashboard.html")


def test_nesting_and_per_string_limits_are_enforced(tmp_path, assets, monkeypatch):
    payload = report()
    nested = {}
    for _ in range(dashboard.MAX_DEPTH + 1):
        nested = {"deeper": nested}
    payload["metadata"]["nested"] = nested
    with pytest.raises(ValueError, match="nesting"):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "nested.html")
    monkeypatch.setattr(dashboard, "MAX_STRING_BYTES", 20)
    with pytest.raises(ValueError, match="strings"):
        dashboard.write_dashboard([save_report(tmp_path)], tmp_path / "string.html")


def test_string_budget_counts_utf8_bytes_instead_of_codepoints(tmp_path, assets, monkeypatch):
    payload = report()
    payload["metadata"]["notes"] = "é" * 60
    monkeypatch.setattr(dashboard, "MAX_STRING_BYTES", 100)
    with pytest.raises(ValueError, match="UTF-8"):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "dashboard.html")


def test_excessive_json_parser_depth_becomes_value_error(tmp_path, assets):
    path = tmp_path / "report.json"
    path.write_text("[" * 2000 + "0" + "]" * 2000)
    with pytest.raises(ValueError, match="nesting"):
        dashboard.write_dashboard([path], tmp_path / "dashboard.html")


def test_file_count_and_size_limits_are_enforced_before_export(tmp_path, assets):
    source = save_report(tmp_path)
    with pytest.raises(ValueError, match="at most 8"):
        dashboard.write_dashboard([source] * 9, tmp_path / "many.html")
    with source.open("wb") as stream:
        stream.truncate(dashboard.MAX_FILE_BYTES + 1)
    with pytest.raises(ValueError, match="16 MiB"):
        dashboard.write_dashboard([source], tmp_path / "large.html")


def test_combined_row_and_file_size_limits_are_enforced(tmp_path, assets, monkeypatch):
    source = save_report(tmp_path)
    monkeypatch.setattr(dashboard, "MAX_TOTAL_BYTES", source.stat().st_size * 2 - 1)
    with pytest.raises(ValueError, match="total at most"):
        dashboard.write_dashboard([source, source], tmp_path / "bytes.html")
    monkeypatch.setattr(dashboard, "MAX_TOTAL_BYTES", 32 * 1024 * 1024)
    monkeypatch.setattr(dashboard, "MAX_ROWS", 1)
    with pytest.raises(ValueError, match="total at most"):
        dashboard.write_dashboard([source, source], tmp_path / "rows.html")


def test_excessive_events_and_findings_are_rejected(tmp_path, assets):
    payload = report()
    payload["rows"][0]["events"] *= dashboard.MAX_EVENTS_PER_ROW + 1
    with pytest.raises(ValueError, match="events"):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "events.html")
    payload = report()
    payload["rows"][0]["review"]["findings"] *= dashboard.MAX_FINDINGS_PER_REVIEW + 1
    with pytest.raises(ValueError, match="findings"):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "findings.html")


def test_special_files_are_refused_without_blocking(tmp_path, assets):
    fifo = tmp_path / "not-a-report"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="regular file"):
        dashboard.write_dashboard([fifo], tmp_path / "dashboard.html")


def test_empty_export_and_empty_report_are_valid(tmp_path, assets):
    output = dashboard.write_dashboard([], tmp_path / "empty.html")
    assert EmbeddedData(output.read_text()).parsed() == {"reports": []}
    empty = {"schema_version": 2, "metadata": {}, "rows": []}
    source = save_report(tmp_path, empty)
    output = dashboard.write_dashboard([source], tmp_path / "empty-report.html")
    assert EmbeddedData(output.read_text()).parsed()["reports"][0]["report"] == empty


def test_missing_template_markers_and_oversized_export_fail(tmp_path, assets, monkeypatch):
    assets["index.html"] = assets["index.html"].replace("<!--__DASHBOARD_DATA__-->", "")
    with pytest.raises(ValueError, match="template"):
        dashboard.write_dashboard([], tmp_path / "missing-marker.html")
    assets["index.html"] += "<!--__DASHBOARD_DATA__-->"
    monkeypatch.setattr(dashboard, "MAX_EXPORT_BYTES", 10)
    with pytest.raises(ValueError, match="export limit"):
        dashboard.write_dashboard([], tmp_path / "oversized.html")


def test_cli_without_examples_exports_empty_default_dashboard(
    tmp_path, assets, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "run", lambda *_: pytest.fail("evaluation must not run"))
    assert cli.main(["dashboard"]) == 0
    output = tmp_path / "reports/dashboard.html"
    assert EmbeddedData(output.read_text()).parsed() == {"reports": []}
    assert str(output) in capsys.readouterr().out


def test_cli_loads_only_existing_default_examples(tmp_path, assets, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for relative in dashboard.DEFAULT_REPORTS[:2]:
        save_report(tmp_path, name=relative)
    assert cli.main(["dashboard"]) == 0
    embedded = EmbeddedData((tmp_path / "reports/dashboard.html").read_text()).parsed()
    assert len(embedded["reports"]) == 2
    assert [entry["name"] for entry in embedded["reports"]] == [
        "calibration v2",
        "pilot v2 typescript",
    ]


def test_cli_explicit_input_and_malformed_input_exit_codes(tmp_path, assets, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = save_report(tmp_path)
    output = tmp_path / "selected/dashboard.html"
    assert cli.main(["dashboard", str(source), "--output", str(output)]) == 0
    previous = output.read_bytes()
    source.write_text("not JSON")
    assert cli.main(["dashboard", str(source), "--output", str(output)]) == 2
    assert output.read_bytes() == previous


def test_packaged_frontend_and_recorded_examples_export_together(tmp_path):
    root = Path(__file__).resolve().parents[1]
    reports = dashboard.default_report_paths(root)
    assert len(reports) == 3
    output = dashboard.write_dashboard(reports, tmp_path / "dashboard.html")
    html = output.read_text()
    parsed = EmbeddedData(html)
    assert len(parsed.scripts) == 2
    assert sum(len(entry["report"]["rows"]) for entry in parsed.parsed()["reports"]) == 672
    assert 'src="dashboard.js"' not in html
    assert 'href="dashboard.css"' not in html
    assert "/*__DASHBOARD_CSS__*/" not in html and "/*__DASHBOARD_JS__*/" not in html
    assert "/*__REPORT_CONTRACT_JS__*/" not in html
    assert 'src="report-contracts.js"' not in html
    assert html.index("root.ReviewBoundaryReportContracts = api") < html.index("const Contracts =")


@pytest.mark.parametrize("kind", ["repository", "boundary"])
@pytest.mark.parametrize("wrapped", [False, True])
def test_native_documents_round_trip_without_invented_measurements(tmp_path, assets, kind, wrapped):
    payload, _, _ = native_fixture(kind)
    payload["metadata"]["run_finished"] = False
    payload["metadata"]["evidence_verification"] = {"status": "matching_supplied_artifact"}
    payload["rows"][0]["semantic_passed"] = None
    if wrapped:
        payload = export_report_envelope(payload)
    before = deepcopy(payload)
    source = save_report(tmp_path, payload)
    output = dashboard.write_dashboard([source], tmp_path / "dashboard.html")
    entry = EmbeddedData(output.read_text()).parsed()["reports"][0]
    assert entry["report"] == before
    assert "evidence_verification" not in entry
    assert source.read_text() == json.dumps(before)


def test_wrapped_legacy_document_retains_optional_unknown_metrics(tmp_path, assets):
    payload = report()
    payload["rows"][0]["issue_reported"] = None
    wrapped = export_report_envelope(payload)
    source = save_report(tmp_path, wrapped)
    output = dashboard.write_dashboard([source], tmp_path / "dashboard.html")
    entry = EmbeddedData(output.read_text()).parsed()["reports"][0]
    assert entry["report"] == wrapped
    assert entry["report"]["report"]["rows"][0]["issue_reported"] is None


@pytest.mark.parametrize("kind", ["repository", "boundary"])
def test_native_provider_errors_remain_unjudged_display_data(tmp_path, assets, kind):
    payload, case, _ = native_fixture(kind)
    if kind == "repository":
        rows = repository_error_rows((case,), "fixture/reference", 1, "provider_error")
    else:
        rows = boundary_error_rows((case,), "fixture/reference", 1, ["off"], "provider_error")
    payload["rows"] = rows
    source = save_report(tmp_path, payload)
    output = dashboard.write_dashboard([source], tmp_path / "dashboard.html")
    embedded = EmbeddedData(output.read_text()).parsed()["reports"][0]["report"]
    assert embedded == payload
    assert embedded["rows"][0]["semantic_passed"] is None
    assert embedded["rows"][0]["error"]


def test_native_binding_consistency_context_is_separate_and_contains_no_snapshots(tmp_path, assets):
    payload, case, world = native_fixture()
    snapshot = world.snapshot()
    artifacts = {
        "schema_version": 1,
        "source_report_sha256": json_digest(payload),
        "snapshots": [
            {
                "row_index": 0,
                "source_row_sha256": json_digest(payload["rows"][0]),
                "snapshot": snapshot,
            }
        ],
    }
    source = save_report(tmp_path, payload)
    output = dashboard.write_dashboard(
        [source],
        tmp_path / "dashboard.html",
        snapshot_artifacts=artifacts,
        suite={"schema_version": 1, "cases": [case.model_dump(mode="json")]},
    )
    entry = EmbeddedData(output.read_text()).parsed()["reports"][0]
    assert entry["report"] == payload
    context = entry["evidence_verification"]
    assert context["source_report_sha256"] == json_digest(payload)
    assert context["rows"][0]["status"] == "matching_supplied_artifact"
    assert context["rows"][0]["case_validation"] == "restored_and_observations_match"
    assert context["rows"][0]["authenticity"] == "not_established"
    assert "snapshots" not in entry


def test_external_snapshot_context_requires_one_unambiguous_report(tmp_path, assets):
    payload, _, _ = native_fixture()
    source = save_report(tmp_path, payload)
    for sources in ([], [source, source]):
        with pytest.raises(ValueError, match="exactly one"):
            dashboard.write_dashboard(sources, tmp_path / "dashboard.html", snapshot_artifacts={})
    assert not (tmp_path / "dashboard.html").exists()


@pytest.mark.parametrize("limit", ["MAX_ROWS", "MAX_EVENTS_PER_ROW", "MAX_FINDINGS_PER_REVIEW"])
def test_native_public_dashboard_limits_remain_monkeypatchable(
    tmp_path, assets, monkeypatch, limit
):
    payload, _, _ = native_fixture()
    monkeypatch.setattr(dashboard, limit, 0)
    with pytest.raises(ValueError, match="rows|events|findings"):
        dashboard.write_dashboard([save_report(tmp_path, payload)], tmp_path / "dashboard.html")


def test_wrapped_report_rows_count_toward_aggregate_limit(tmp_path, assets, monkeypatch):
    payload, _, _ = native_fixture()
    source = save_report(tmp_path, export_report_envelope(payload))
    monkeypatch.setattr(dashboard, "MAX_ROWS", 1)
    with pytest.raises(ValueError, match="total at most"):
        dashboard.write_dashboard([source, source], tmp_path / "dashboard.html")


def test_contract_helper_is_inlined_before_dashboard_application(tmp_path, assets):
    output = dashboard.write_dashboard([], tmp_path / "dashboard.html")
    html = output.read_text()
    assert html.index(assets["report-contracts.js"]) < html.index(assets["dashboard.js"])
