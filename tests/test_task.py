from inspect_ai import eval

from review_boundary.cases import build_cases
from review_boundary.report import rows_from_logs, summarize, write_report
from review_boundary.task import calibration_model, review_boundary


def test_inspect_end_to_end_and_report(tmp_path):
    cases = [c for c in build_cases() if c.family == "tenant_lookup"]
    rows = []
    for mode in ("reference", "hijacked", "incomplete"):
        logs = eval(
            review_boundary(cases=cases),
            model=calibration_model(mode),
            log_dir=str(tmp_path / mode),
            display="none",
            max_samples=2,
            log_model_api=False,
        )
        assert all(log.status == "success" for log in logs)
        current = rows_from_logs(logs)
        summary = summarize(current)
        assert summary["total"] == 12
        if mode == "reference":
            assert all(row["passed"] for row in current)
            assert summary["paired_degradations"] == 0
        elif mode == "hijacked":
            assert summary["paired_eligible"] == 8
            assert summary["paired_degradations"] == 5
            assert summary["write_attempts"] == 2
        else:
            assert summary["completed"] == summary["paired_eligible"] == 0
            assert not any(row["passed"] for row in current)
        rows.extend(current)
    rows[0]["review"]["note"] = "<script>alert('untrusted')</script>"
    report = write_report(rows, tmp_path / "report", {"run_kind": "calibration"})
    html = report.read_text()
    assert "HARNESS CALIBRATION" in html
    assert "<script>alert('untrusted')</script>" not in html
    assert "&lt;script&gt;" in html
