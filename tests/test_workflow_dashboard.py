"""Workflow presentation preserves the report contract and its evidence limits."""

import base64
import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from html.parser import HTMLParser
from importlib.resources import files
from pathlib import Path
from unittest.mock import patch

from review_boundary import workflow_dashboard as dashboard
from review_boundary.workflow_report import assemble_workflow_run, validate_workflow_run

FIXTURES = Path(__file__).parent / "fixtures" / "workflow_reports"


def fixture(name="scripted-incomplete"):
    return json.loads((FIXTURES / f"{name}.json").read_bytes())


class Document(HTMLParser):
    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.scripts = []
        self.style = []
        self.text = []
        self.active = None
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "script":
            self.scripts.append([attrs, ""])
            self.active = "script"
        elif tag == "style":
            self.active = "style"

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.active = None

    def handle_data(self, text):
        if self.active == "script":
            self.scripts[-1][1] += text
        elif self.active == "style":
            self.style.append(text)
        else:
            self.text.append(text)

    def report(self):
        return json.loads(self.scripts[0][1])


class WorkflowDashboardTests(unittest.TestCase):
    def test_both_scripted_fixtures_are_deterministic_detached_and_exact(self):
        for name in ("scripted-complete", "scripted-incomplete"):
            with self.subTest(name=name):
                report = fixture(name)
                before = deepcopy(report)
                html = dashboard.render_workflow_dashboard(report)
                doc = Document(html)
                self.assertEqual(doc.report(), validate_workflow_run(report))
                self.assertEqual(report, before)
                self.assertEqual(html, dashboard.render_workflow_dashboard(report))
                self.assertEqual(
                    html, dashboard.render_workflow_dashboard(json.dumps(report).encode())
                )
                self.assertLess(len(html.encode()), dashboard.MAX_DASHBOARD_BYTES)
                self.assertIn("Scripted fixture · recorded label", html)
                self.assertIn("recorded_data_only", html)
                self.assertIn("Authenticity:", html)
                self.assertIn("unavailable", html)
                self.assertIn(
                    "Run complete" if report["coverage"]["run_completed"] else "Run incomplete",
                    html,
                )
                self.assertEqual(
                    sum("data-case" in a for _, a in doc.tags), report["coverage"]["expected_cases"]
                )

    def test_unknown_missing_and_unstarted_sessions_remain_distinct(self):
        doc = Document(dashboard.render_workflow_dashboard(fixture()))
        text = " ".join(doc.text)
        self.assertIn("Unknown (null)", text)
        self.assertIn("Missing", text)
        self.assertIn("Not recorded", text)
        self.assertIn("not_recorded · Observation missing", text)
        self.assertIn("not_started · Observation missing", text)
        self.assertIn("completed · Observed", text)
        self.assertIn("Semantic review passed", text)
        self.assertIn("Missing cases never imply zero effects", text)
        self.assertEqual(doc.report()["summary"], fixture()["summary"])
        self.assertEqual(
            doc.report()["summary"]["case_metrics"]["reviewer_resisted"],
            {
                "true": 0,
                "false": 0,
                "unknown": 2,
                "missing": 1,
                "expected_denominator": 3,
            },
        )

    def test_no_rows_still_shows_every_case_and_session_without_inventing_zero(self):
        report = assemble_workflow_run(fixture()["expected"], [])
        doc = Document(dashboard.render_workflow_dashboard(report))
        cases = [a for _, a in doc.tags if "data-case" in a]
        self.assertEqual(len(cases), 3)
        self.assertTrue(all(a["data-state"] == "missing" for a in cases))
        self.assertEqual(" ".join(doc.text).count("not_recorded · Observation missing"), 5)
        self.assertIn(
            "No scored row recorded. Metrics and observations are missing.", " ".join(doc.text)
        )
        self.assertEqual(doc.report(), report)

    def test_missing_session_error_is_visible_without_claiming_observation(self):
        report = fixture()
        report["scored_cases"][0]["sessions"][1]["status"] = "error"
        report = assemble_workflow_run(report["expected"], report["scored_cases"])
        html = dashboard.render_workflow_dashboard(report)
        self.assertIn("error · Observation missing", html)
        self.assertEqual(Document(html).report()["coverage"]["observed_sessions"], 2)

    def test_reviewer_name_does_not_infer_scripted_evidence(self):
        report = fixture()
        report["expected"]["evidence_kind"] = "not_recorded"
        report = assemble_workflow_run(report["expected"], report["scored_cases"])
        html = dashboard.render_workflow_dashboard(report)
        self.assertIn("Evidence kind: not_recorded", html)
        self.assertNotIn("Scripted fixture · recorded label", html)
        self.assertIn("scripted_calibration", html)

    def test_supplied_roster_is_checked_and_validation_scope_is_visible(self):
        report = fixture()
        html = dashboard.render_workflow_dashboard(report, expected=report["expected"])
        self.assertIn("Matched supplied original roster", html)
        self.assertIn(
            "Internal consistency against declared roster only",
            dashboard.render_workflow_dashboard(report),
        )
        other = deepcopy(report["expected"])
        other["binding"]["epoch"] = 2
        with self.assertRaises(dashboard.WorkflowDashboardError):
            dashboard.render_workflow_dashboard(report, expected=other)

    def test_html_script_event_url_unicode_and_bounded_labels_are_inert(self):
        report = fixture("scripted-complete")
        attack = '</script><img src=x onerror="globalThis.pwned=1"> javascript:alert(1) & café 🙂\u2028\u2029'
        old = report["expected"]["cases"][0]["case_id"]
        report["expected"]["binding"]["reviewer"] = attack
        for case in report["expected"]["cases"]:
            if case["case_id"] == old:
                case["case_id"] = attack + "x" * (256 - len(attack))
                case["source_group"] = "界" * 256
        for row in report["scored_cases"]:
            row["binding"]["reviewer"] = attack
            if row["case_id"] == old:
                row["case_id"] = attack + "x" * (256 - len(attack))
                row["source_group"] = "界" * 256
        report = assemble_workflow_run(report["expected"], report["scored_cases"])
        html = dashboard.render_workflow_dashboard(report)
        doc = Document(html)
        self.assertEqual(doc.report(), report)
        self.assertEqual(len(doc.scripts), 2)
        self.assertNotIn("<img", html)
        self.assertIn("\\u003c/script\\u003e", doc.scripts[0][1])
        self.assertIn("\\u2028\\u2029", doc.scripts[0][1])
        self.assertIn("\\u0026", doc.scripts[0][1])
        self.assertIn(attack, " ".join(doc.text))
        for tag, attrs in doc.tags:
            self.assertFalse(any(key.lower().startswith("on") for key in attrs))
            self.assertNotIn(tag, ("img", "iframe", "object", "base", "link"))
            if "href" in attrs:
                self.assertTrue(attrs["href"].startswith("#"))
            self.assertNotIn("src", attrs)

    def test_invalid_malformed_mismatched_and_unsupported_inputs_fail_before_assets(self):
        mutations = []
        for key, value in (
            ("schema_version", 2),
            ("report_kind", "workflow"),
            ("authenticity", "verified"),
        ):
            report = fixture()
            report[key] = value
            mutations.append(report)
        report = fixture()
        report["scored_cases"][0]["binding"]["epoch"] = 2
        mutations.append(report)
        report = fixture()
        report["summary"]["case_metrics"]["reviewer_resisted"]["unknown"] = 0
        mutations.append(report)
        report = fixture()
        report["scored_cases"].append(deepcopy(report["scored_cases"][0]))
        mutations.append(report)
        mutations.extend(
            [
                None,
                [],
                {},
                "{}",
                b"[]",
                b'{"x":1,"x":2}',
                b"{",
                b"\xff",
                b" " * (2 * 1024 * 1024 + 1),
            ]
        )
        with patch.object(dashboard, "files", side_effect=AssertionError("must validate first")):
            for value in mutations:
                with (
                    self.subTest(value_type=type(value).__name__),
                    self.assertRaises(dashboard.WorkflowDashboardError),
                ):
                    dashboard.render_workflow_dashboard(value)

    def test_asset_bytes_are_embedded_and_exactly_bound_by_csp(self):
        doc = Document(dashboard.render_workflow_dashboard(fixture()))
        resource = files("review_boundary").joinpath("web")
        js = resource.joinpath("workflow-dashboard.js").read_text(encoding="utf-8")
        css = resource.joinpath("workflow-dashboard.css").read_text(encoding="utf-8")
        self.assertEqual(doc.scripts[1][1], js)
        self.assertEqual("".join(doc.style), css)
        policy = next(
            a["content"]
            for t, a in doc.tags
            if t == "meta" and a.get("http-equiv") == "Content-Security-Policy"
        )
        for asset in (js, css):
            digest = base64.b64encode(hashlib.sha256(asset.encode()).digest()).decode()
            self.assertIn(f"'sha256-{digest}'", policy)
        self.assertIn("connect-src 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)

    def test_io_is_bounded_nonclobbering_and_validates_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "report.json"
            original = (FIXTURES / "scripted-complete.json").read_bytes()
            source.write_bytes(original)
            output = root / "new" / "dashboard.html"
            self.assertEqual(dashboard.write_workflow_dashboard(source, output), output)
            self.assertEqual(Document(output.read_text()).report(), json.loads(original))
            for destination in (source, output):
                with self.assertRaisesRegex(dashboard.WorkflowDashboardError, "already exists"):
                    dashboard.write_workflow_dashboard(source, destination)
            hardlink = root / "hardlink.html"
            os.link(source, hardlink)
            with self.assertRaisesRegex(dashboard.WorkflowDashboardError, "already exists"):
                dashboard.write_workflow_dashboard(source, hardlink)
            self.assertEqual(source.read_bytes(), original)
            source.write_bytes(b"invalid")
            invalid_output = root / "not-created" / "view.html"
            with self.assertRaises(dashboard.WorkflowDashboardError):
                dashboard.write_workflow_dashboard(source, invalid_output)
            self.assertFalse(invalid_output.parent.exists())
            source.write_bytes(b"x" * (2 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(dashboard.WorkflowDashboardError, "2 MiB"):
                dashboard.write_workflow_dashboard(source, invalid_output)
            with self.assertRaisesRegex(dashboard.WorkflowDashboardError, "regular"):
                dashboard.write_workflow_dashboard(root, invalid_output)
            if hasattr(os, "mkfifo"):
                fifo = root / "pipe"
                os.mkfifo(fifo)
                with self.assertRaisesRegex(dashboard.WorkflowDashboardError, "regular"):
                    dashboard.write_workflow_dashboard(fifo, invalid_output)

    def test_output_bound_and_cli_failure_are_explicit(self):
        with (
            patch.object(dashboard, "MAX_DASHBOARD_BYTES", 100),
            self.assertRaisesRegex(dashboard.WorkflowDashboardError, "output limit"),
        ):
            dashboard.render_workflow_dashboard(fixture())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "invalid.json"
            source.write_bytes(b"{}")
            stderr, stdout = io.StringIO(), io.StringIO()
            with (
                redirect_stderr(stderr),
                redirect_stdout(stdout),
                self.assertRaises(SystemExit) as caught,
            ):
                dashboard.main([str(source), "--output", str(root / "out.html")])
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("Invalid or unsupported workflow run report", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertFalse(stdout.getvalue())
            self.assertFalse((root / "out.html").exists())

    def test_failed_write_or_publication_leaves_no_partial_output_or_staging_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "report.json", root / "dashboard.html"
            source.write_bytes((FIXTURES / "scripted-incomplete.json").read_bytes())
            original_open = io.open

            class PartialWriter:
                def __init__(self, stream):
                    self.stream = stream

                def __enter__(self):
                    return self

                def __exit__(self, *args):
                    return self.stream.__exit__(*args)

                def write(self, data):
                    self.stream.write(data[: len(data) // 2])
                    self.stream.flush()
                    raise OSError("simulated partial write")

            def failing_open(file, mode="r", *args, **kwargs):
                stream = original_open(file, mode, *args, **kwargs)
                return (
                    PartialWriter(stream)
                    if "b" in mode and ("w" in mode or "x" in mode)
                    else stream
                )

            with (
                patch.object(io, "open", side_effect=failing_open),
                self.assertRaisesRegex(dashboard.WorkflowDashboardError, "Cannot write"),
            ):
                dashboard.write_workflow_dashboard(source, output)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".workflow-dashboard-*")), [])
            for operation in ("fsync", "link"):
                with (
                    self.subTest(operation=operation),
                    patch.object(dashboard.os, operation, side_effect=OSError("simulated failure")),
                    self.assertRaisesRegex(dashboard.WorkflowDashboardError, "Cannot write"),
                ):
                    dashboard.write_workflow_dashboard(source, output)
                self.assertFalse(output.exists())
                self.assertEqual(list(root.glob(".workflow-dashboard-*")), [])
            dashboard.write_workflow_dashboard(source, output)
            self.assertEqual(Document(output.read_text()).report(), fixture())
            self.assertEqual(list(root.glob(".workflow-dashboard-*")), [])

    def test_descriptor_and_cleanup_failures_preserve_ownership_and_publication_facts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "report.json", root / "dashboard.html"
            source.write_bytes((FIXTURES / "scripted-incomplete.json").read_bytes())
            original_fdopen = os.fdopen
            descriptors = []

            def failing_fdopen(fd, mode, **kwargs):
                if mode == "wb":
                    descriptors.append(fd)
                    raise OSError("simulated stream failure")
                return original_fdopen(fd, mode, **kwargs)

            with (
                patch.object(dashboard.os, "fdopen", side_effect=failing_fdopen),
                self.assertRaisesRegex(dashboard.WorkflowDashboardError, "Cannot write"),
            ):
                dashboard.write_workflow_dashboard(source, output)
            with self.assertRaises(OSError):
                os.fstat(descriptors[0])
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".workflow-dashboard-*")), [])

            original_unlink = Path.unlink

            def failing_cleanup(path, *args, **kwargs):
                if path.name.startswith(".workflow-dashboard-"):
                    raise OSError("simulated cleanup failure")
                return original_unlink(path, *args, **kwargs)

            with (
                patch.object(Path, "unlink", failing_cleanup),
                patch.object(dashboard.os, "fsync", side_effect=OSError("primary failure")),
                self.assertRaisesRegex(
                    dashboard.WorkflowDashboardError, "Cannot write.*cleanup also failed"
                ) as caught,
            ):
                dashboard.write_workflow_dashboard(source, output)
            self.assertEqual(str(caught.exception.__cause__), "primary failure")
            self.assertFalse(output.exists())
            for path in root.glob(".workflow-dashboard-*"):
                path.unlink()

            with (
                patch.object(Path, "unlink", failing_cleanup),
                self.assertRaisesRegex(
                    dashboard.WorkflowDashboardError, "Dashboard published, but.*cleanup failed"
                ),
            ):
                dashboard.write_workflow_dashboard(source, output)
            self.assertEqual(Document(output.read_text()).report(), fixture())
            for path in root.glob(".workflow-dashboard-*"):
                path.unlink()


if __name__ == "__main__":
    unittest.main()
