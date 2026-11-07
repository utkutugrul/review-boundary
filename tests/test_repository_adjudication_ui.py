import base64
import copy
import hashlib
import json
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from test_repository_adjudication import CASES, native_run

from review_boundary.cli import main
from review_boundary.json_input import parse_json_object
from review_boundary.repository_adjudication import (
    TEMPLATE_REASON,
    export_adjudication_template,
    validate_adjudication,
)
from review_boundary.repository_adjudication_agreement import adjudication_agreement
from review_boundary.repository_adjudication_ui import (
    adjudication_ui_context,
    render_adjudication_ui,
)
from review_boundary.repository_cases import case_digest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "src" / "review_boundary" / "web"
NODE = shutil.which("node")


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    """Every case reports a finding, so fixed cases give absent-issue edge cases."""
    _, report, source = native_run(tmp_path_factory.mktemp("ui-run"), always_find=True)
    suite = source / "suite.json"
    suite.write_text(
        json.dumps({"schema_version": 1, "cases": [c.model_dump(mode="json") for c in CASES]})
    )
    return report, source / "report.json", suite


def template(report):
    return export_adjudication_template(report, CASES).model_dump(mode="json")


def test_context_matches_the_export_template_and_shows_recorded_text(run):
    report, *_ = run
    context = adjudication_ui_context(report, CASES)
    value = template(report)
    assert context["source_report_sha256"] == value["source_report_sha256"]
    assert context["template_reason"] == TEMPLATE_REASON
    assert [(f["case_sha256"], f["finding_sha256"]) for f in context["findings"]] == [
        (d["case_sha256"], d["finding_sha256"]) for d in value["finding_decisions"]
    ]
    assert [(r["case_sha256"], r["review_sha256"]) for r in context["reviews"]] == [
        (d["case_sha256"], d["review_sha256"]) for d in value["review_decisions"]
    ]
    assert len(context["findings"]) == 4 and len(context["reviews"]) == 4
    finding = context["findings"][0]
    assert finding["summary"] and finding["evidence"][0]["excerpt"]
    assert finding["slots"] and set(finding["slots"][0]) == {"reviewer", "epoch"}
    issues = context["cases"][finding["case_sha256"]]["issues"]
    assert issues[0]["issue_id"] == "tenant-ownership" and issues[0]["ranges"]


def test_context_refuses_already_adjudicated_reports(run):
    adjudicated = copy.deepcopy(run[0])
    adjudicated["metadata"]["adjudication"] = {}
    with pytest.raises(ValueError, match="already adjudicated"):
        adjudication_ui_context(adjudicated, CASES)


def hostile_context(run):
    report, *_ = run
    context = adjudication_ui_context(report, CASES)
    attack = '</script><img src=x onerror=alert(1)><!-- \u2028 & "quoted"'
    context["findings"][0]["summary"] = attack
    context["findings"][0]["evidence"][0]["excerpt"] = attack
    context["cases"][context["findings"][0]["case_sha256"]]["case_id"] = attack
    return context, attack


def test_page_embeds_hostile_text_as_inert_data_under_an_exact_hash_csp(run):
    context, attack = hostile_context(run)
    page = render_adjudication_ui(context)
    data = re.search(
        r'<script id="adjudication-data" type="application/json">(.*?)</script>', page, re.DOTALL
    )
    assert data and json.loads(data.group(1)) == context
    assert "</script><img" not in page and "\u2028" not in data.group(1)
    assert page.count("</script>") == 2 and page.count("<script") == 2
    csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page).group(1)
    script = re.search(r"<script>(.*?)</script>", page, re.DOTALL).group(1)
    style = re.search(r"<style>(.*?)</style>", page, re.DOTALL).group(1)
    for source, kind in ((script, "script"), (style, "style")):
        digest = base64.b64encode(hashlib.sha256(source.encode()).digest()).decode()
        assert f"{kind}-src 'sha256-{digest}'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    for directive in ("default-src 'none'", "connect-src 'none'", "form-action 'none'"):
        assert directive in csp
    assert "base-uri 'none'" in csp and "img-src 'none'" in csp
    assert attack not in page.replace(data.group(1), "")


def test_page_assets_are_offline_and_never_build_html_from_data():
    page = (WEB / "adjudication.html").read_text()
    script = (WEB / "adjudication.js").read_text()
    style = (WEB / "adjudication.css").read_text()
    for text in (page, script, style):
        assert not re.search(r"https?://|//cdn|@import|url\(", text)
    assert not re.search(r"\b(src|href|srcset|action)=", page.replace('type="file"', ""))
    assert "style=" not in page and not re.search(r"\son\w+=", page)
    for forbidden in ("innerHTML", "insertAdjacentHTML", "fetch(", "localStorage", "eval("):
        assert forbidden not in script


def test_ui_cli_writes_a_new_bounded_file_and_never_overwrites(run, tmp_path, capsys):
    _, report_path, suite = run
    output = tmp_path / "nested" / "labeler.html"
    argv = ["adjudication-ui", "--report", str(report_path), "--suite", str(suite)]
    original = (report_path.read_bytes(), suite.read_bytes())
    assert main([*argv, "--output", str(output)]) == 0
    assert "all unknown" in capsys.readouterr().out
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    page = output.read_text()
    assert 'id="adjudication-data"' in page and "<!--__" not in page and "/*__" not in page
    assert main([*argv, "--output", str(output)]) == 2  # never replaces an existing file
    assert main([*argv, "--output", str(report_path)]) == 2
    assert main([*argv, "--output", str(suite)]) == 2
    link = tmp_path / "link.html"
    link.symlink_to(tmp_path / "elsewhere.html")
    assert main([*argv, "--output", str(link)]) == 2
    assert not (tmp_path / "elsewhere.html").exists()
    assert (report_path.read_bytes(), suite.read_bytes()) == original


def parity_cases(run):
    report, *_ = run
    base = template(report)
    expectation = {case_digest(c): c.issues[0].expectation for c in CASES}
    present = next(
        i
        for i, d in enumerate(base["finding_decisions"])
        if expectation[d["case_sha256"]] == "present"
    )
    absent = next(
        i
        for i, d in enumerate(base["finding_decisions"])
        if expectation[d["case_sha256"]] == "absent"
    )
    first = base["finding_decisions"][0]
    cases = {}

    def add(name, value=None, *, raw=None):
        cases[name] = raw if raw is not None else json.dumps(value)

    def edit(change):
        value = copy.deepcopy(base)
        change(value)
        return value

    def finding(index=0, **fields):
        return edit(lambda v: v["finding_decisions"][index].update(fields))

    def review(**fields):
        return edit(lambda v: v["review_decisions"][0].update(fields))

    text = json.dumps(base)
    add("template", base)
    add("empty-partial", edit(lambda v: v.update(finding_decisions=[], review_decisions=[])))
    add("one-finding", edit(lambda v: v.update(finding_decisions=v["finding_decisions"][:1])))
    add("missing-schema", edit(lambda v: v.pop("schema_version")))
    add("missing-kind", edit(lambda v: v.pop("adjudication_kind")))
    add(
        "missing-discriminators",
        {k: v for k, v in base.items() if k not in ("schema_version", "adjudication_kind")},
    )
    add(
        "supported-present",
        finding(present, decision="supported", issue_id="tenant-ownership", reason="ok"),
    )
    add(
        "rejected-absent-mapping",
        finding(absent, decision="rejected", issue_id="tenant-ownership", reason="no"),
    )
    add(
        "supported-absent-mapping",
        finding(absent, decision="supported", issue_id="tenant-ownership", reason="yes"),
    )
    add("review-judged", review(decision="supported", reason="ok"))
    add("null-issue-explicit", finding(issue_id=None))
    add("whitespace-reason", finding(reason=" "))
    add("nul-reason", finding(reason="\u0000"))
    add("emoji-2000", finding(reason="\U0001f600" * 2000))
    add("emoji-2001", finding(reason="\U0001f600" * 2001))
    add("empty-reason", finding(reason=""))
    add("unknown-with-mapping", finding(issue_id="tenant-ownership"))
    add("unknown-issue", finding(decision="rejected", issue_id="missing"))
    add("empty-issue", finding(decision="rejected", issue_id=""))
    add("long-issue", finding(decision="rejected", issue_id="i" * 257))
    add("bad-decision", finding(decision="Supported"))
    add("null-decision", finding(decision=None))
    add("numeric-reason", finding(reason=7))
    add("stale-source", edit(lambda v: v.update(source_report_sha256="9" * 64)))
    add("uppercase-digest", finding(case_sha256=first["case_sha256"].upper()))
    add("short-digest", finding(finding_sha256=first["finding_sha256"][:63]))
    add("newline-digest", finding(finding_sha256=first["finding_sha256"] + "\n"))
    add("foreign-finding", finding(finding_sha256="9" * 64))
    add("foreign-case", finding(case_sha256="9" * 64))
    add("foreign-review", review(review_sha256="9" * 64))
    add(
        "duplicate-identical",
        edit(lambda v: v["finding_decisions"].append(copy.deepcopy(v["finding_decisions"][0]))),
    )
    add(
        "duplicate-conflict",
        edit(
            lambda v: v["finding_decisions"].append(
                {**v["finding_decisions"][0], "decision": "rejected"}
            )
        ),
    )
    add(
        "duplicate-review",
        edit(lambda v: v["review_decisions"].append(copy.deepcopy(v["review_decisions"][0]))),
    )
    add("extra-top", edit(lambda v: v.update(extra=1)))
    add("extra-finding", finding(extra=1))
    add("missing-finding-key", edit(lambda v: v["finding_decisions"][0].pop("reason")))
    add("missing-top-key", edit(lambda v: v.pop("review_decisions")))
    add("review-issue-key", review(issue_id=None))
    add("schema-2", edit(lambda v: v.update(schema_version=2)))
    add("schema-true", edit(lambda v: v.update(schema_version=True)))
    add("schema-null", edit(lambda v: v.update(schema_version=None)))
    add("schema-float", raw=text.replace('"schema_version": 1', '"schema_version": 1.0'))
    add("schema-exp", raw=text.replace('"schema_version": 1', '"schema_version": 1e0'))
    add("kind-boundary", edit(lambda v: v.update(adjudication_kind="boundary")))
    add("kind-null", edit(lambda v: v.update(adjudication_kind=None)))
    add("kind-true", edit(lambda v: v.update(adjudication_kind=True)))
    add("kind-float", edit(lambda v: v.update(adjudication_kind=1.0)))
    add("findings-object", edit(lambda v: v.update(finding_decisions={})))
    add("findings-null", edit(lambda v: v.update(finding_decisions=None)))
    add("entry-not-object", edit(lambda v: v["finding_decisions"].append("x")))
    add("lone-surrogate", raw=text.replace(TEMPLATE_REASON, "\\ud800", 1))
    add("surrogate-pair", raw=text.replace(TEMPLATE_REASON, "\\ud83d\\ude00", 1))
    add(
        "duplicate-json-key",
        raw=text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
    )
    add("nan", raw=text.replace('"schema_version": 1', '"schema_version": NaN'))
    add("trailing-comma", raw=text[:-1] + ",}")
    add("trailing-garbage", raw=text + " x")
    add("control-char", raw=text.replace(TEMPLATE_REASON, "a\tb", 1))
    add("top-array", raw="[]")
    add("empty-text", raw="")
    add("deep", raw='{"a":' + "[" * 70 + "]" * 70 + "}")
    add("padded", raw=" \n" + text + "\r\n\t")
    add("too-many", edit(lambda v: v.update(finding_decisions=[v["finding_decisions"][0]] * 32769)))
    return cases


def python_verdict(run, text):
    report, *_ = run
    try:
        artifact = validate_adjudication(parse_json_object(text.encode()), report, CASES)
    except ValueError:  # includes pydantic and JSON errors
        return None
    return artifact.model_dump(mode="json")


@pytest.mark.skipif(NODE is None, reason="Node.js is required for browser parity")
def test_browser_and_python_validators_agree_on_every_case(run, tmp_path):
    report, *_ = run
    cases = parity_cases(run)
    context = adjudication_ui_context(report, CASES)
    spec = tmp_path / "parity.json"
    spec.write_text(
        json.dumps(
            {"context": context, "cases": [{"name": n, "text": t} for n, t in cases.items()]}
        )
    )
    done = subprocess.run(
        [NODE, str(ROOT / "tests" / "web" / "adjudication-parity.cjs"), str(spec)],
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
    )
    browser = json.loads(done.stdout)
    accepted = rejected = 0
    for name, text in cases.items():
        expected = python_verdict(run, text)
        result = browser["results"][name]
        assert result["accepted"] == (expected is not None), (name, result.get("message"))
        if expected is None:
            rejected += 1
        else:
            accepted += 1
            assert result["artifact"] == expected, name
    assert accepted >= 10 and rejected >= 40
    # An untouched page exports exactly the all-unknown artifact the CLI template writes.
    assert browser["template"] == json.dumps(template(report), indent=2) + "\n"


def test_python_artifact_requires_exact_discriminators(run):
    value = template(run[0])
    assert validate_adjudication(value, run[0], CASES)
    for field, bad_values in (
        ("schema_version", (True, 1.0, "1", None, 2)),
        ("adjudication_kind", (True, 1.0, None, "boundary")),
    ):
        missing = copy.deepcopy(value)
        missing.pop(field)
        with pytest.raises(ValueError):
            validate_adjudication(missing, run[0], CASES)
        for bad in bad_values:
            with pytest.raises(ValueError):
                validate_adjudication({**value, field: bad}, run[0], CASES)


def test_python_artifact_never_synthesizes_missing_discriminators(run):
    value = template(run[0])
    for missing in ("schema_version", "adjudication_kind"):
        candidate = copy.deepcopy(value)
        candidate.pop(missing)
        with pytest.raises(ValueError):
            validate_adjudication(candidate, run[0], CASES)


def rate(report, a_findings, a_reviews, b_findings, b_reviews):
    """Complete artifacts whose i-th decisions come from the given label lists."""
    first, second = template(report), template(report)
    for artifact, findings, reviews in (
        (first, a_findings, a_reviews),
        (second, b_findings, b_reviews),
    ):
        for items, labels in (
            (artifact["finding_decisions"], findings),
            (artifact["review_decisions"], reviews),
        ):
            for item, label in zip(items, labels, strict=True):
                item.update(decision=label, reason=f"Reviewed as {label}.")
    return first, second


def test_agreement_reports_exact_agreement_and_cohen_kappa(run):
    report, *_ = run
    first, second = rate(
        report,
        ["supported"] * 4,
        ["supported", "supported", "rejected", "rejected"],
        ["supported", "supported", "supported", "rejected"],
        ["supported", "supported", "rejected", "unknown"],
    )
    result = adjudication_agreement(report, CASES, first, second)
    assert result["source_report_sha256"] == first["source_report_sha256"]
    overall = result["overall"]
    # Findings pair (S,S)x3 and (S,R); reviews pair (S,S)x2, (R,R) and (R,U).
    assert overall["items"] == 8
    assert overall["agreements"] == 6
    assert overall["exact_agreement"] == 0.75
    confusion = overall["confusion"]
    assert confusion["supported"]["supported"] == 5 and confusion["supported"]["rejected"] == 1
    assert confusion["rejected"]["rejected"] == 1 and confusion["rejected"]["unknown"] == 1
    # po = .75; A: S=.75 R=.25; B: S=.625 R=.25 U=.125; pe = .46875 + .0625.
    assert overall["cohen_kappa"] == round((0.75 - 0.53125) / (1 - 0.53125), 6)
    assert result["findings"]["items"] == 4 and result["reviews"]["items"] == 4
    assert result["findings"]["agreements"] == 3
    assert result["findings"]["agreements_with_issue_mapping"] == 3
    assert "reason" in result["compared"]
    assert result["rater_artifact_sha256"][0] != result["rater_artifact_sha256"][1]
    assert "tenant" not in json.dumps(result).casefold()


def test_agreement_kappa_edge_cases(run):
    report, *_ = run
    same, other = rate(
        report, ["supported"] * 4, ["supported"] * 4, ["supported"] * 4, ["supported"] * 4
    )
    constant = adjudication_agreement(report, CASES, same, other)["overall"]
    assert constant["exact_agreement"] == 1.0 and constant["cohen_kappa"] is None
    first, second = rate(
        report,
        ["supported", "rejected", "supported", "rejected"],
        ["supported", "rejected", "supported", "rejected"],
        ["rejected", "supported", "rejected", "supported"],
        ["rejected", "supported", "rejected", "supported"],
    )
    opposite = adjudication_agreement(report, CASES, first, second)["overall"]
    assert opposite["exact_agreement"] == 0.0 and opposite["cohen_kappa"] == -1.0
    unknowns = adjudication_agreement(report, CASES, template(report), template(report))["overall"]
    assert unknowns["exact_agreement"] == 1.0 and unknowns["confusion"]["unknown"]["unknown"] == 8


def test_agreement_rejects_incomplete_mismatched_and_invalid_sets(run, tmp_path):
    report, *_ = run
    full = template(report)
    other = copy.deepcopy(full)
    other["finding_decisions"].pop()
    for pair in ((full, other), (other, full)):
        with pytest.raises(ValueError, match="cover every"):
            adjudication_agreement(report, CASES, *pair)
    reviewless = copy.deepcopy(full)
    reviewless["review_decisions"] = []
    with pytest.raises(ValueError, match="cover every"):
        adjudication_agreement(report, CASES, full, reviewless)
    foreign = copy.deepcopy(full)
    foreign["finding_decisions"][0]["finding_sha256"] = "9" * 64
    with pytest.raises(ValueError, match="absent from the report"):
        adjudication_agreement(report, CASES, full, foreign)
    stale = {**full, "source_report_sha256": "9" * 64}
    with pytest.raises(ValueError, match="different or modified"):
        adjudication_agreement(report, CASES, full, stale)
    conflicting = copy.deepcopy(full)
    conflicting["finding_decisions"].append(
        {**conflicting["finding_decisions"][0], "decision": "rejected"}
    )
    with pytest.raises(ValueError, match="Conflicting"):
        adjudication_agreement(report, CASES, full, conflicting)
    with pytest.raises(ValueError):
        adjudication_agreement(report, CASES, full, {"nonsense": True})
    _, other_report, _ = native_run(tmp_path, always_find=False)
    with pytest.raises(ValueError, match="different or modified"):
        adjudication_agreement(report, CASES, full, template(other_report))


def test_agreement_cli_writes_a_new_file_and_rejects_bad_inputs(run, tmp_path, capsys):
    report, report_path, suite = run
    first, second = rate(
        report,
        ["supported"] * 4,
        ["supported"] * 4,
        ["supported", "supported", "supported", "rejected"],
        ["supported"] * 4,
    )
    a, b, c = (tmp_path / name for name in ("a.json", "b.json", "c.json"))
    a.write_text(json.dumps(first))
    b.write_text(json.dumps(second))
    partial = copy.deepcopy(first)
    partial["finding_decisions"].pop()
    c.write_text(json.dumps(partial))
    output = tmp_path / "agreement.json"

    def cli(one, two, *extra):
        argv = ["adjudication-agreement", "--report", str(report_path), "--suite", str(suite)]
        return main([*argv, "--rater-a", str(one), "--rater-b", str(two), *extra])

    assert cli(a, b, "--output", str(output)) == 0
    assert "Cohen kappa" in capsys.readouterr().out
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    result = json.loads(output.read_text())
    assert result["overall"]["items"] == 8 and result["overall"]["agreements"] == 7
    assert cli(a, b, "--output", str(output)) == 2  # never overwritten
    assert cli(a, a) == 2
    assert cli(a, c) == 2
    assert "cover every" in capsys.readouterr().err
