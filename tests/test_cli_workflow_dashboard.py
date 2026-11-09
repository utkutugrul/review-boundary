"""Saved workflow data traverses the shared CLI without evaluation dispatch."""

import builtins
import hashlib
import json
import os
from html.parser import HTMLParser
from pathlib import Path

import pytest

from review_boundary import cli, github_cli
from review_boundary import workflow_dashboard as dashboard
from review_boundary.workflow_report import MAX_RUN_REPORT_BYTES, validate_workflow_run

FIXTURES = Path(__file__).parent / "fixtures" / "workflow_reports"


class EmbeddedReport(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.active = False
        self.data = ""
        self.policy = ""
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.active = tag == "script" and attrs.get("id") == "workflow-data"
        if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy":
            self.policy = attrs["content"]

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.data += data

    def report(self):
        return json.loads(self.data)


@pytest.fixture(autouse=True)
def keyless_route(monkeypatch):
    # These traps cover callable dispatch after the existing eager imports.
    # They do not promise an SDK-free import or audit third-party initialization.
    for name in tuple(os.environ):
        if name.endswith(("_API_KEY", "_AUTH_TOKEN")) or name in (
            "OPENROUTER_API_KEY",
            "INSPECT_EVAL_MODEL",
        ):
            monkeypatch.delenv(name)

    def forbidden(*args, **kwargs):
        raise AssertionError("saved dashboard entered an evaluation/effect path")

    for name in (
        "credential",
        "load_dotenv",
        "run",
        "eval",
        "adapter_run",
        "prepare_provider",
        "guarded_model",
        "calibration_model",
        "review_boundary",
        "api_get",
        "model_snapshot",
        "planned_cost",
        "reserve",
        "settle",
        "read_eval_log",
    ):
        monkeypatch.setattr(cli, name, forbidden)
    monkeypatch.setattr(cli.asyncio, "run", forbidden)
    monkeypatch.setattr(github_cli, "handle_command", forbidden)
    original_import = builtins.__import__
    denied = {
        "isolated_runner",
        "repository_runner",
        "boundary_runner",
        "ci",
        "reconstruct",
        "webbrowser",
        "subprocess",
    }

    def guarded_import(name, *args, **kwargs):
        if name.removeprefix("review_boundary.") in denied:
            forbidden()
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded_import)


def saved_report(tmp_path, name="scripted-incomplete"):
    original = (FIXTURES / f"{name}.json").read_bytes()
    source = tmp_path / "report.json"
    source.write_bytes(original)
    return source, original


def argv(source, output, expected=None):
    result = ["workflow-dashboard", str(source), "--output", str(output)]
    return result if expected is None else result + ["--expected", str(expected)]


@pytest.mark.parametrize("name", ["scripted-complete", "scripted-incomplete"])
@pytest.mark.parametrize("with_expected", [False, True], ids=["declared", "original-roster"])
def test_shared_main_preserves_validated_document_and_fixture_bytes(
    tmp_path, capsys, name, with_expected
):
    source, original = saved_report(tmp_path, name)
    report = json.loads(original)
    expected = tmp_path / "expected.json" if with_expected else None
    roster = json.dumps(report["expected"]).encode()
    if expected is not None:
        expected.write_bytes(roster)
    output = tmp_path / "new" / "dashboard.html"
    assert cli.main(argv(source, output, expected)) == 0
    captured = capsys.readouterr()
    assert captured.out == str(output.resolve()) + "\n"
    assert captured.err == ""
    html = output.read_text(encoding="utf-8")
    embedded = EmbeddedReport(html).report()
    assert embedded == validate_workflow_run(original, expected=roster if with_expected else None)
    assert embedded == report
    assert html == dashboard.render_workflow_dashboard(
        original, expected=roster if with_expected else None
    )
    assert source.read_bytes() == original
    assert (FIXTURES / f"{name}.json").read_bytes() == original
    assert (
        hashlib.sha256(original).hexdigest()
        == {
            "scripted-complete": "5b49d699af20d313939520e6944e5995035450bcd95cbed82cc7f2d08ebb01bf",
            "scripted-incomplete": "d711d123b9d918b224e9fb58a4636a8c85c5010df7c31b28be50a75a657ffc81",
        }[name]
    )
    if expected is not None:
        assert expected.read_bytes() == roster
        assert "Matched supplied original roster" in html
    assert len(output.read_bytes()) <= dashboard.MAX_DASHBOARD_BYTES == 16777216
    assert MAX_RUN_REPORT_BYTES == 2097152
    for label in (
        "Scripted fixture · recorded label",
        "recorded_data_only",
        "Authenticity:",
        "unavailable",
        "Guard prevention is separate from reviewer resistance",
    ):
        assert label in html
    assert "connect-src 'none'" in EmbeddedReport(html).policy
    assert embedded["record_authority"] == "recorded_data_only"
    assert embedded["authenticity"] == "unavailable"
    metrics = embedded["summary"]["case_metrics"]
    if name == "scripted-incomplete":
        coverage = embedded["coverage"]
        assert coverage["run_completed"] is False
        assert coverage["expected_cases"] == 3
        assert coverage["expected_sessions"] == 5
        assert coverage["observed_sessions"] == 2
        assert len(coverage["missing_sessions"]) == 3
        assert len(coverage["missing_case_ids"]) == 1
        assert metrics["reviewer_resisted"] == {
            "true": 0,
            "false": 0,
            "unknown": 2,
            "missing": 1,
            "expected_denominator": 3,
        }
        assert "Run incomplete" in html
    else:
        assert embedded["coverage"]["run_completed"] is True
        assert metrics["reviewer_resisted"]["true"] == 0
        assert metrics["reviewer_resisted"]["false"] == 1
        assert metrics["reviewer_resisted"]["unknown"] == 1
        assert embedded["summary"]["recorded_effect_totals"]["unauthorized_prevented"] == 1
    assert list(output.parent.glob(".workflow-dashboard-*")) == []


@pytest.mark.parametrize(
    "fault",
    [
        "malformed",
        "duplicate-key",
        "unsupported",
        "wrong-kind",
        "summary",
        "coverage",
        "encoding",
        "oversized",
        "non-object",
    ],
)
def test_invalid_saved_report_refuses_before_publication(tmp_path, capsys, fault):
    source, original = saved_report(tmp_path)
    report = json.loads(original)
    raw = {
        "malformed": b"{",
        "duplicate-key": b'{"schema_version":1,"schema_version":1}',
        "encoding": b"\xff",
        "oversized": b" " * (MAX_RUN_REPORT_BYTES + 1),
        "non-object": b"[]",
    }.get(fault)
    if raw is None:
        if fault == "unsupported":
            report["schema_version"] = 2
        elif fault == "wrong-kind":
            report["report_kind"] = "repository"
        elif fault == "summary":
            report["summary"]["case_metrics"]["reviewer_resisted"]["unknown"] = 0
        else:
            report["coverage"]["run_completed"] = True
        raw = json.dumps(report).encode()
    source.write_bytes(raw)
    output = tmp_path / "not-created" / "dashboard.html"
    assert cli.main(argv(source, output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ReviewBoundary:" in captured.err
    assert "Traceback" not in captured.err
    assert not output.parent.exists()
    assert source.read_bytes() == raw


@pytest.mark.parametrize(
    "fault", ["mismatch", "malformed", "duplicate-key", "unsupported", "oversized", "missing"]
)
def test_original_roster_refusal_uses_bounded_reader(tmp_path, capsys, fault):
    source, original = saved_report(tmp_path)
    roster = json.loads(original)["expected"]
    expected = tmp_path / "expected.json"
    raw = {
        "malformed": b"{",
        "duplicate-key": b'{"cases":[],"cases":[]}',
        "oversized": b" " * (MAX_RUN_REPORT_BYTES + 1),
    }.get(fault)
    if raw is None:
        if fault == "mismatch":
            roster["binding"]["epoch"] = 2
        elif fault == "unsupported":
            roster["schema_version"] = 999
        raw = json.dumps(roster).encode()
    if fault != "missing":
        expected.write_bytes(raw)
    output = tmp_path / "not-created" / "dashboard.html"
    assert cli.main(argv(source, output, expected)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ReviewBoundary:" in captured.err
    assert not output.parent.exists()
    assert source.read_bytes() == original
    if fault != "missing":
        assert expected.read_bytes() == raw


@pytest.mark.parametrize("fault", ["missing", "directory"])
def test_input_io_failure_exits_two_without_success(tmp_path, capsys, fault):
    source = tmp_path / "absent.json" if fault == "missing" else tmp_path
    output = tmp_path / "not-created" / "dashboard.html"
    assert cli.main(argv(source, output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "ReviewBoundary:" in captured.err
    assert not output.parent.exists()


@pytest.mark.parametrize(
    "kind", ["regular", "symlink", "dangling-symlink", "hardlink", "source", "expected"]
)
def test_existing_destinations_and_input_aliases_are_unchanged(tmp_path, capsys, kind):
    source, original = saved_report(tmp_path)
    expected = tmp_path / "expected.json"
    roster = json.dumps(json.loads(original)["expected"]).encode()
    expected.write_bytes(roster)
    output = tmp_path / "exists.html"
    if kind == "regular":
        output.write_bytes(b"existing HTML")
    elif kind == "symlink":
        output.symlink_to(source)
    elif kind == "dangling-symlink":
        output.symlink_to(tmp_path / "absent-target")
    elif kind == "hardlink":
        os.link(source, output)
    elif kind == "source":
        output = source
    else:
        output = expected
    before_stat = output.lstat()
    before = output.read_bytes() if output.exists() else None
    link = output.readlink() if output.is_symlink() else None
    assert cli.main(argv(source, output, expected)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Output already exists" in captured.err
    assert output.lstat().st_ino == before_stat.st_ino
    if before is not None:
        assert output.read_bytes() == before
    if link is not None:
        assert output.readlink() == link
    assert source.read_bytes() == original
    assert expected.read_bytes() == roster
    assert not (tmp_path / "absent-target").exists()
    assert list(tmp_path.glob(".workflow-dashboard-*")) == []


@pytest.mark.parametrize("operation", ["fsync", "link"])
def test_ordinary_write_failure_cleans_staging(tmp_path, capsys, monkeypatch, operation):
    source, original = saved_report(tmp_path)
    output = tmp_path / "dashboard.html"

    def fail(*args, **kwargs):
        raise OSError("simulated write failure")

    monkeypatch.setattr(dashboard.os, operation, fail)
    assert cli.main(argv(source, output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Cannot write dashboard HTML file" in captured.err
    assert not output.exists()
    assert source.read_bytes() == original
    assert list(tmp_path.glob(".workflow-dashboard-*")) == []


def test_post_publication_cleanup_failure_preserves_nonzero_and_publication_facts(
    tmp_path, capsys, monkeypatch
):
    source, original = saved_report(tmp_path)
    output = tmp_path / "dashboard.html"
    unlink = Path.unlink

    def fail_staging_unlink(path, *args, **kwargs):
        if path.name.startswith(".workflow-dashboard-"):
            raise OSError("simulated cleanup failure")
        return unlink(path, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(Path, "unlink", fail_staging_unlink)
        assert cli.main(argv(source, output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Dashboard published, but staging file cleanup failed" in captured.err
    assert EmbeddedReport(output.read_text()).report() == json.loads(original)
    assert source.read_bytes() == original
    staging = list(tmp_path.glob(".workflow-dashboard-*"))
    assert len(staging) == 1
    for path in staging:
        path.unlink()
    assert list(tmp_path.glob(".workflow-dashboard-*")) == []


def test_inherited_html_bound_refuses_without_publication(tmp_path, capsys, monkeypatch):
    source, original = saved_report(tmp_path)
    output = tmp_path / "not-created" / "dashboard.html"
    monkeypatch.setattr(dashboard, "MAX_DASHBOARD_BYTES", 100)
    assert cli.main(argv(source, output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "output limit" in captured.err
    assert not output.parent.exists()
    assert source.read_bytes() == original


def test_shared_parser_and_help_expose_exact_route(capsys):
    parsed = cli.parser().parse_args(
        argv(Path("report.json"), Path("new.html"), Path("roster.json"))
    )
    assert vars(parsed) == {
        "command": "workflow-dashboard",
        "report": Path("report.json"),
        "output": Path("new.html"),
        "expected": Path("roster.json"),
    }
    assert cli.parser().parse_args(argv(Path("report.json"), Path("new.html"))).expected is None
    assert "workflow-dashboard" in cli.parser().format_help()
    with pytest.raises(SystemExit) as caught:
        cli.main(["workflow-dashboard", "--help"])
    assert caught.value.code == 0
    help_text = capsys.readouterr().out
    assert "--output" in help_text
    assert "--expected" in help_text


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["report.json"],
        ["--output", "new.html"],
        ["report.json", "--output", "new.html", "extra.json"],
    ],
    ids=["no-arguments", "no-output", "no-report", "extra-report"],
)
def test_shared_parser_rejects_incomplete_or_extra_arguments(arguments, capsys):
    with pytest.raises(SystemExit) as caught:
        cli.main(["workflow-dashboard", *arguments])
    assert caught.value.code == 2
    assert capsys.readouterr().out == ""


def test_existing_shared_parser_and_list_route_remain_keyless(capsys):
    assert cli.parser().parse_args(["list"]).command == "list"
    args = cli.parser().parse_args(["dashboard", "one.json", "two.json"])
    assert args.reports == [Path("one.json"), Path("two.json")]
    assert args.output == Path("reports/dashboard.html")
    args = cli.parser().parse_args(["compare", "base.json", "candidate.json"])
    assert args.baseline == Path("base.json")
    assert args.candidate == Path("candidate.json")
    assert cli.main(["list"]) == 0
    captured = capsys.readouterr()
    assert "tenant_lookup" in captured.out
    assert captured.err == ""
