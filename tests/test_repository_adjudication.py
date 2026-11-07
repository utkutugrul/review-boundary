import copy
import json
import os
import stat

import pytest
from inspect_ai import eval
from inspect_ai.log import list_eval_logs, read_eval_log
from inspect_ai.model import ChatCompletionChoice, ChatMessageAssistant, ModelOutput, get_model
from inspect_ai.tool import ToolCall

from review_boundary.cli import main
from review_boundary.provenance import json_digest
from review_boundary.repository_adjudication import (
    FAILURE_EVIDENCE_FILENAME,
    TEMPLATE_REASON,
    RepositoryAdjudicationArtifact,
    adjudicate_observation,
    apply_repository_adjudication,
    canonical_report_digest,
    export_adjudication_template,
    observations_from_logs,
    repository_failure_evidence,
    validate_adjudication,
    write_new_text,
    write_repository_failure_evidence,
)
from review_boundary.repository_cases import (
    REPOSITORY_SCORING_VERSION,
    build_repository_demo_cases,
    case_digest,
)
from review_boundary.repository_runner import repository_rows_from_logs, write_repository_report
from review_boundary.repository_task import context, repository_review_task
from review_boundary.repository_world import RepositoryLimits, finding_digest

SUMMARY = "Distinctive tenant boundary summary 7f3a."
CASES = build_repository_demo_cases()


def reviewer_model(
    *, always_find=False, duplicate_findings=False, model_name="adjudication-fixture"
):
    def respond(input, tools, tool_choice, config):
        case, world = context()
        events = world.events
        if not any(e["tool"] == "read_pr" for e in events):
            function, arguments = "read_pr", {}
        elif not any(e["tool"] == "list_files" for e in events):
            function, arguments = "list_files", {}
        else:
            read = {e.get("path") for e in events if e["tool"] == "read_file"}
            unread = next((f.path for f in case.files if f.path not in read), None)
            if unread:
                function, arguments = "read_file", {"path": unread, "end_line": 80}
            else:
                files = {f.path: f.content for f in case.files}
                findings = []
                if always_find or case.variant == "vulnerable":
                    findings = [
                        {
                            "category": case.issues[0].category,
                            "summary": SUMMARY,
                            "evidence": [
                                {
                                    **r.model_dump(mode="json"),
                                    "excerpt": "\n".join(
                                        files[r.path].splitlines()[r.start_line - 1 : r.end_line]
                                    ),
                                }
                                for r in case.issues[0].acceptable_bundles[0].ranges
                            ],
                        }
                    ]
                    if duplicate_findings:
                        findings.append(copy.deepcopy(findings[0]))
                function, arguments = (
                    "submit_review",
                    {"verdict": "request_changes" if findings else "approve", "findings": findings},
                )
        call = ToolCall(id=f"call-{len(events)}", function=function, arguments=arguments)
        return ModelOutput(
            model="adjudication-fixture",
            choices=[
                ChatCompletionChoice(
                    message=ChatMessageAssistant(content="", tool_calls=[call]),
                    stop_reason="tool_calls",
                )
            ],
        )

    return get_model(f"mockllm/{model_name}", custom_outputs=respond, memoize=False)


def native_run(tmp_path, *, always_find=False, duplicate_findings=False, cases=CASES):
    logs = eval(
        [repository_review_task(cases=cases)],
        model=reviewer_model(
            always_find=always_find,
            duplicate_findings=duplicate_findings,
        ),
        log_dir=str(tmp_path / "logs"),
        display="none",
        log_model_api=False,
    )
    rows = repository_rows_from_logs(logs, cases, [logs[0].eval.model], 1)
    reviewer = logs[0].eval.model
    metadata = {
        "run_kind": "model",
        "scoring_version": REPOSITORY_SCORING_VERSION,
        "suite_sha256": json_digest([case_digest(c) for c in cases]),
        "expected_count": len(rows),
        "case_count": len(cases),
        "epochs": 1,
        "reviewers": [reviewer],
        "expected_slots": [
            {"case_sha256": case_digest(case), "reviewer": reviewer, "epoch": 1} for case in cases
        ],
        "world_limits": RepositoryLimits().model_dump(mode="json"),
    }
    output = tmp_path / "source"
    output.mkdir()
    write_repository_report(rows, output, metadata)
    report = json.loads((output / "report.json").read_text())
    return logs, report, output


@pytest.fixture
def run(tmp_path):
    logs, report, output = native_run(tmp_path)
    observations, limits = observations_from_logs(logs, CASES)
    return report, observations, limits, output


@pytest.fixture
def mixed_run(tmp_path, monkeypatch):
    """Use the real runner and Inspect for one healthy model plus pre-log failure."""
    from review_boundary import repository_runner
    from review_boundary.model_safety import ProviderRequestError

    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-adjudication-key")
    original_prepare = repository_runner.prepare_provider

    class MockPlan:
        def __init__(self, plan):
            self.plan = plan

        def __getattr__(self, name):
            return getattr(self.plan, name)

        def inspect_model_id(self, model_id):
            return f"mockllm/{model_id}"

    monkeypatch.setattr(
        repository_runner,
        "prepare_provider",
        lambda *args, **kwargs: MockPlan(original_prepare(*args, **kwargs)),
    )

    def model(plan, model_id):
        if model_id == "failed":
            raise ProviderRequestError("Synthetic provider initialization failure.")
        return reviewer_model(model_name=model_id)

    monkeypatch.setattr(repository_runner, "guarded_model", model)
    pricing = tmp_path / "pricing.json"
    pricing.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "provider": "openai",
                "source": "https://openai.com/api/pricing/",
                "as_of": "2026-01-01",
                "models": {
                    name: {"input_usd_per_million": 1, "output_usd_per_million": 2}
                    for name in ("healthy", "failed")
                },
            }
        )
    )
    output = tmp_path / "mixed"
    assert (
        main(
            [
                "repository-run-model",
                "--provider",
                "openai",
                "--model",
                "healthy",
                "--model",
                "failed",
                "--epochs",
                "1",
                "--pricing-file",
                str(pricing),
                "--output",
                str(output),
                "--ledger",
                str(tmp_path / "budget.json"),
            ]
        )
        == 2
    )
    report = json.loads((output / "report.json").read_text())
    logs = [read_eval_log(info.name) for info in list_eval_logs(str(output / "logs"))]
    observations, limits = observations_from_logs(logs, CASES)
    evidence = json.loads((output / "logs" / FAILURE_EVIDENCE_FILENAME).read_text())
    assert len(observations) == len(CASES)
    assert report["summary"]["errors"] == len(CASES)
    assert report["metadata"]["run_finished"] is True
    return report, observations, limits, output, evidence, logs


def decide(artifact, *, findings=None, reviews=None):
    """Replace decisions by matching all entries or the supplied predicate."""
    value = artifact.model_dump(mode="json")
    for key, change in (("finding_decisions", findings), ("review_decisions", reviews)):
        for item in value[key]:
            if change:
                item.update(change(item) or {})
    return value


def semantic(rows):
    return {row["case_id"]: row["semantic_passed"] for row in rows}


def refresh_summary(report):
    rows = report["rows"]
    report["summary"] = {
        "recorded": len(rows),
        "expected": report["metadata"]["expected_count"],
        "completed": sum(bool(row["completed"]) for row in rows),
        "rubric_passed": sum(bool(row["rubric_passed"]) for row in rows),
        "semantically_adjudicated": sum(row["semantic_passed"] is not None for row in rows),
        "unknown_findings": sum(row["unknown_findings"] for row in rows),
        "errors": sum(bool(row["error"]) for row in rows),
    }


def test_template_contains_unique_digests_and_no_model_text(run):
    report, *_ = run
    template = export_adjudication_template(report, CASES)
    assert template.source_report_sha256 == canonical_report_digest(report)
    assert template.adjudication_kind == "repository" and template.schema_version == 1
    # Two vulnerable cases submit the same finding text against different case digests.
    assert len(template.finding_decisions) == 2
    assert len(template.review_decisions) == 4
    assert {d.decision for d in (*template.finding_decisions, *template.review_decisions)} == {
        "unknown"
    }
    assert {d.reason for d in template.finding_decisions} == {TEMPLATE_REASON}
    text = json.dumps(template.model_dump(mode="json"))
    assert SUMMARY not in text and "tenant" not in text.casefold()
    assert (
        validate_adjudication(
            template.model_dump(mode="json"), report, CASES, require_complete=True
        )
        == template
    )


def test_unknown_round_trip_changes_no_semantics_and_leaves_source_untouched(run):
    report, observations, limits, _ = run
    before = copy.deepcopy(report)
    template = export_adjudication_template(report, CASES).model_dump(mode="json")
    rows, metadata = apply_repository_adjudication(report, CASES, template, observations, limits)
    assert report == before
    assert metadata["adjudication"]["rows_adjudicated"] == 4
    assert all(row["semantic_passed"] is None for row in rows)
    for new, old in zip(rows, report["rows"], strict=True):
        for key in old:
            if key not in ("findings", "review_adjudication"):
                assert new[key] == old[key]
        assert new["unknown_findings"] == old["unknown_findings"]
        assert new["review_adjudication"]["decision"] == "unknown"
    # A semantic claim must come from a stronger decision, not template application.
    assert metadata["adjudication"]["semantic_method"] == "explicit_evaluator_adjudication_only"


def test_supported_and_rejected_decisions_use_trusted_evidence(run):
    report, observations, limits, _ = run
    template = export_adjudication_template(report, CASES)
    supported = decide(
        template,
        findings=lambda d: {
            "decision": "supported",
            "issue_id": "tenant-ownership",
            "reason": "ok",
        },
        reviews=lambda d: {"decision": "supported", "reason": "ok"},
    )
    rows, _ = apply_repository_adjudication(report, CASES, supported, observations, limits)
    by_case = semantic(rows)
    assert by_case["tenant_flow:vulnerable:clean"] is True
    assert by_case["tenant_flow:fixed:clean"] is True
    vulnerable = next(r for r in rows if r["case_id"] == "tenant_flow:vulnerable:clean")
    assert vulnerable["correct_findings"] == 1 and vulnerable["unknown_findings"] == 0
    assert vulnerable["target_issues_adjudicated"] == 1

    rejected = decide(
        template,
        findings=lambda d: {"decision": "rejected", "reason": "no"},
        reviews=lambda d: {"decision": "rejected", "reason": "no"},
    )
    rows, _ = apply_repository_adjudication(report, CASES, rejected, observations, limits)
    assert set(semantic(rows).values()) == {False}
    assert (
        next(r for r in rows if r["surface"] == "clean" and r["variant"] == "vulnerable")[
            "false_positives"
        ]
        == 1
    )


def test_supported_review_with_unknown_finding_stays_unknown(run):
    report, observations, limits, _ = run
    template = export_adjudication_template(report, CASES)
    value = decide(template, reviews=lambda d: {"decision": "supported", "reason": "ok"})
    rows, _ = apply_repository_adjudication(report, CASES, value, observations, limits)
    by_case = semantic(rows)
    assert by_case["tenant_flow:vulnerable:clean"] is None
    assert by_case["tenant_flow:vulnerable:readme"] is None
    # Empty approvals have no findings, so whole-review judgment is the only authority.
    assert by_case["tenant_flow:fixed:clean"] is True


def test_empty_approval_without_review_judgment_is_unjudged(run):
    report, observations, limits, _ = run
    template = export_adjudication_template(report, CASES)
    value = template.model_dump(mode="json")
    value["review_decisions"] = []
    rows, _ = apply_repository_adjudication(report, CASES, value, observations, limits)
    assert set(semantic(rows).values()) == {None}
    assert all(row["review_adjudication"] is None for row in rows)


def test_partial_artifact_is_allowed_but_not_complete(run):
    report, *_ = run
    value = export_adjudication_template(report, CASES).model_dump(mode="json")
    value["finding_decisions"].pop()
    assert validate_adjudication(value, report, CASES)
    with pytest.raises(ValueError, match="cover every"):
        validate_adjudication(value, report, CASES, require_complete=True)


def mutate(value, change):
    value = copy.deepcopy(value)
    change(value)
    return value


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda v: v["finding_decisions"].append(v["finding_decisions"][0]), "Duplicate"),
        (
            lambda v: v["finding_decisions"].append(
                {**v["finding_decisions"][0], "decision": "rejected", "reason": "other"}
            ),
            "Conflicting",
        ),
        (lambda v: v["review_decisions"].append(v["review_decisions"][0]), "Duplicate"),
        (
            lambda v: v["review_decisions"].append(
                {**v["review_decisions"][0], "decision": "supported"}
            ),
            "Conflicting",
        ),
        (lambda v: v["finding_decisions"][0].update(case_sha256="0" * 64), "unknown case"),
        (lambda v: v["review_decisions"][0].update(case_sha256="1" * 64), "unknown case"),
        (lambda v: v["finding_decisions"][0].update(finding_sha256="2" * 64), "finding digest"),
        (lambda v: v["review_decisions"][0].update(review_sha256="3" * 64), "review digest"),
        (lambda v: v.update(source_report_sha256="4" * 64), "different or modified"),
        (lambda v: v.update(adjudication_kind="boundary"), None),
        (lambda v: v.update(schema_version=2), None),
        (lambda v: v.update(extra=True), None),
        (lambda v: v["finding_decisions"][0].update(decision="maybe"), None),
        (lambda v: v["finding_decisions"][0].update(issue_id="missing"), "Unknown finding"),
        (
            lambda v: v["finding_decisions"][0].update(
                decision="rejected", issue_id="missing", reason="r"
            ),
            "unknown issue",
        ),
    ],
)
def test_import_fails_closed(run, change, message):
    report, *_ = run
    template = export_adjudication_template(report, CASES).model_dump(mode="json")
    with pytest.raises(ValueError, match=message):
        validate_adjudication(mutate(template, change), report, CASES)


def test_cross_case_digest_pairing_is_rejected(run):
    report, *_ = run
    value = export_adjudication_template(report, CASES).model_dump(mode="json")
    first, second = value["finding_decisions"]
    first["case_sha256"] = second["case_sha256"]
    first["finding_sha256"] = "5" * 64
    with pytest.raises(ValueError, match="finding digest"):
        validate_adjudication(value, report, CASES)
    value = export_adjudication_template(report, CASES).model_dump(mode="json")
    value["review_decisions"][0]["case_sha256"] = value["review_decisions"][-1]["case_sha256"]
    value["review_decisions"][0]["review_sha256"] = "6" * 64
    with pytest.raises(ValueError, match="review digest"):
        validate_adjudication(value, report, CASES)


def test_stale_and_foreign_artifacts_are_rejected(run, tmp_path):
    report, *_ = run
    template = export_adjudication_template(report, CASES).model_dump(mode="json")
    stale = copy.deepcopy(report)
    stale["rows"][0]["tool_calls"] += 1
    with pytest.raises(ValueError, match="different or modified"):
        validate_adjudication(template, stale, CASES)
    foreign_logs, foreign, _ = native_run(tmp_path / "foreign", always_find=True)
    assert foreign_logs
    with pytest.raises(ValueError, match="different or modified"):
        validate_adjudication(template, foreign, CASES)


def test_absent_issue_mappings_and_foreign_suites_are_rejected(tmp_path):
    logs, report, _ = native_run(tmp_path, always_find=True)
    template = export_adjudication_template(report, CASES)
    # Every case, including the fixed ones, now has a finding; only absent-issue cases map badly.
    fixed = next(c for c in CASES if c.variant == "fixed" and c.surface == "clean")
    value = template.model_dump(mode="json")
    target = next(d for d in value["finding_decisions"] if d["case_sha256"] == case_digest(fixed))
    target.update(decision="supported", issue_id="tenant-ownership", reason="mapped")
    with pytest.raises(ValueError, match="absent issue"):
        validate_adjudication(value, report, CASES)
    target.update(decision="rejected")
    assert validate_adjudication(value, report, CASES)
    target.update(decision="supported", issue_id=None)
    assert validate_adjudication(value, report, CASES)
    with pytest.raises(ValueError, match="evaluator suite"):
        validate_adjudication(value, report, CASES[:2])
    assert logs


def test_unknown_decision_cannot_carry_an_issue_mapping(run):
    report, *_ = run
    value = export_adjudication_template(report, CASES).model_dump(mode="json")
    value["finding_decisions"][0]["issue_id"] = "tenant-ownership"
    with pytest.raises(ValueError, match="Unknown finding decisions"):
        validate_adjudication(value, report, CASES)


def forge_finding(row):
    """A self-consistent edit: new text with matching digests, but no matching observation."""
    row["review"]["findings"][0]["summary"] = "Edited after the run."
    recorded = row["findings"][0]
    recorded["finding"] = row["review"]["findings"][0]
    recorded["finding_sha256"] = finding_digest(recorded["finding"])


def test_edited_row_semantics_never_become_scorer_output(run):
    report, observations, limits, _ = run
    for change in (
        lambda r: r.update(rubric_passed=False),
        lambda r: r.update(semantic_passed=True),
        lambda r: r.update(unknown_findings=0),
        forge_finding,
        lambda r: r["events"].pop(),
        lambda r: r.update(write_attempted=True),
    ):
        edited = copy.deepcopy(report)
        row = next(r for r in edited["rows"] if r["variant"] == "vulnerable")
        change(row)
        refresh_summary(edited)
        template = export_adjudication_template(edited, CASES).model_dump(mode="json")
        with pytest.raises(ValueError):
            apply_repository_adjudication(edited, CASES, template, observations, limits)


def test_self_consistent_report_only_write_forgery_is_rejected(run):
    report, observations, limits, _ = run
    edited = copy.deepcopy(report)
    row = edited["rows"][0]
    row.update(write_requests_seen=1, write_attempted=True, rubric_passed=False)
    edited["summary"].update(rubric_passed=edited["summary"]["rubric_passed"] - 1)
    template = export_adjudication_template(edited, CASES).model_dump(mode="json")
    with pytest.raises(ValueError, match="trusted scorer observation"):
        apply_repository_adjudication(edited, CASES, template, observations, limits)


def test_inconsistent_report_rows_are_rejected_at_export(run):
    report, *_ = run
    edited = copy.deepcopy(report)
    next(r for r in edited["rows"] if r["findings"])["findings"][0]["finding_sha256"] = "7" * 64
    with pytest.raises(ValueError, match="do not match"):
        export_adjudication_template(edited, CASES)
    edited = copy.deepcopy(report)
    edited["rows"][0]["case_sha256"] = "8" * 64
    with pytest.raises(ValueError, match="evaluator suite"):
        export_adjudication_template(edited, CASES)
    edited = copy.deepcopy(report)
    edited["rows"].append(copy.deepcopy(edited["rows"][0]))
    edited["metadata"]["expected_count"] += 1
    refresh_summary(edited)
    with pytest.raises(ValueError, match="duplicate reviewer slot"):
        export_adjudication_template(edited, CASES)
    edited = copy.deepcopy(report)
    edited["report_kind"] = "legacy"
    with pytest.raises(ValueError, match="repository report"):
        export_adjudication_template(edited, CASES)


def test_recorded_finding_digests_must_be_unique_and_exact(run):
    report, *_ = run
    edited = copy.deepcopy(report)
    row = next(item for item in edited["rows"] if item["findings"])
    first = copy.deepcopy(row["review"]["findings"][0])
    second = copy.deepcopy(first)
    second["summary"] += " Distinct finding B."
    row["review"]["findings"] = [first, second]
    recorded = copy.deepcopy(row["findings"][0])
    row["findings"] = [recorded, copy.deepcopy(recorded)]
    with pytest.raises(ValueError, match="do not match"):
        export_adjudication_template(edited, CASES)


def test_native_duplicate_review_findings_use_one_recorded_digest(tmp_path):
    _, report, _ = native_run(tmp_path, duplicate_findings=True)
    duplicate = next(
        row for row in report["rows"] if row["review"] and len(row["review"]["findings"]) == 2
    )
    assert len(duplicate["findings"]) == 1
    artifact = export_adjudication_template(report, CASES)
    assert artifact.finding_decisions


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda report: report.update(schema_version=True), "schema 1"),
        (lambda report: report.update(schema_version=1.0), "schema 1"),
        (
            lambda report: report["metadata"].update(
                case_count=float(report["metadata"]["case_count"])
            ),
            "complete native model report contract",
        ),
        (
            lambda report: report["metadata"]["expected_slots"][0].update(epoch=1.0),
            "invalid declared sample slot",
        ),
        (
            lambda report: report["summary"].update(recorded=float(report["summary"]["recorded"])),
            "summary",
        ),
    ],
)
def test_report_contract_rejects_integer_coercions(run, change, message):
    report, *_ = run
    edited = copy.deepcopy(report)
    change(edited)
    with pytest.raises(ValueError, match=message):
        export_adjudication_template(edited, CASES)


def test_already_adjudicated_reports_are_not_stacked(run):
    report, observations, limits, _ = run
    template = export_adjudication_template(report, CASES).model_dump(mode="json")
    rows, metadata = apply_repository_adjudication(report, CASES, template, observations, limits)
    second = {**report, "rows": rows, "metadata": metadata}
    with pytest.raises(ValueError, match="already adjudicated"):
        export_adjudication_template(second, CASES)


def test_failed_rows_are_neither_exported_nor_adjudicable(run):
    report, observations, limits, _ = run
    failed = copy.deepcopy(report)
    victim = next(r for r in failed["rows"] if r["variant"] == "vulnerable")
    victim.update(error="Provider model evaluation failed; details withheld", completed=False)
    refresh_summary(failed)
    template = export_adjudication_template(failed, CASES)
    assert len(template.review_decisions) == 3
    full = export_adjudication_template(report, CASES).model_dump(mode="json")
    full["review_decisions"] = [
        d for d in full["review_decisions"] if d["case_sha256"] == victim["case_sha256"]
    ]
    with pytest.raises(ValueError, match="absent from the report"):
        validate_adjudication(
            {**full, "source_report_sha256": canonical_report_digest(failed)}, failed, CASES
        )
    with pytest.raises(ValueError, match="trusted scorer observation"):
        apply_repository_adjudication(
            failed, CASES, template.model_dump(mode="json"), observations, limits
        )


def test_mixed_provider_failure_requires_independent_evidence_and_preserves_failed_rows(mixed_run):
    report, observations, limits, output, evidence, _ = mixed_run
    before = copy.deepcopy(report)
    template = export_adjudication_template(report, CASES)
    assert len(template.review_decisions) == len(CASES)
    decisions = decide(
        template,
        findings=lambda _: {
            "decision": "supported",
            "issue_id": "tenant-ownership",
            "reason": "ok",
        },
        reviews=lambda _: {"decision": "supported", "reason": "ok"},
    )
    # Existing mixed reports without independent trusted run evidence stay closed.
    with pytest.raises(ValueError, match="observation is missing"):
        apply_repository_adjudication(report, CASES, decisions, observations, limits)
    rows, metadata = apply_repository_adjudication(
        report, CASES, decisions, observations, limits, failure_evidence=evidence
    )
    assert report == before
    assert metadata["adjudication"]["rows_adjudicated"] == len(CASES)
    assert metadata["adjudication"]["failure_evidence_sha256"] == json_digest(evidence)
    for row, original in zip(rows, report["rows"], strict=True):
        if row["reviewer"] == "mockllm/failed":
            assert json.dumps(row) == json.dumps(original)
            assert row["semantic_passed"] is None
            assert row["review_adjudication"] is None
            assert row["completed"] is False and row["conclusive"] is False
        else:
            assert row["semantic_passed"] is True
    if os.name == "posix":
        assert stat.S_IMODE((output / "logs" / FAILURE_EVIDENCE_FILENAME).stat().st_mode) == 0o600
    ledger = json.loads((output.parent / "budget.json").read_text())
    assert "settled_usd" not in ledger["runs"][0]
    assert not (output / "settlement.json").exists()


def test_mixed_provider_failure_cli_uses_only_explicit_trusted_log_directory(mixed_run, tmp_path):
    report, _, _, source, _, _ = mixed_run
    labels = tmp_path / "labels.json"
    labels.write_text(export_adjudication_template(report, CASES).model_dump_json())
    output = tmp_path / "adjudicated"
    argv = [
        "adjudication-apply",
        "--report",
        str(source / "report.json"),
        "--suite",
        str(source / "suite.json"),
        "--adjudication",
        str(labels),
        "--logs",
        str(source / "logs"),
        "--output",
        str(output),
    ]
    assert main(argv) == 0
    result = json.loads((output / "report.json").read_text())
    assert result["summary"]["semantically_adjudicated"] == 0
    assert result["summary"]["errors"] == len(CASES)
    assert result["metadata"]["adjudication"]["rows_adjudicated"] == len(CASES)
    assert json.loads((source / "report.json").read_text()) == report

    # An artifact beside the report is not authority for individually supplied logs.
    sidecar = source / "logs" / FAILURE_EVIDENCE_FILENAME
    (source / FAILURE_EVIDENCE_FILENAME).write_bytes(sidecar.read_bytes())
    log_file = next(iter(list_eval_logs(str(source / "logs")))).name
    argv[argv.index("--logs") + 1] = log_file
    argv[argv.index("--output") + 1] = str(tmp_path / "not-created")
    assert main(argv) == 2
    assert not (tmp_path / "not-created").exists()


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.update(schema_version=True),
        lambda value: value.update(schema_version=1.0),
        lambda value: value.update(evidence_kind="repository"),
        lambda value: value.update(run_id="different-run"),
        lambda value: value.update(source_report_sha256="0" * 64),
        lambda value: value.update(suite_sha256="0" * 64),
        lambda value: value.update(world_limits_sha256="0" * 64),
        lambda value: value["failures"].pop(),
        lambda value: value["failures"].append(copy.deepcopy(value["failures"][0])),
        lambda value: value["failures"][0].update(reviewer="undeclared"),
        lambda value: value["failures"][0].update(case_sha256="0" * 64),
        lambda value: value["failures"][0].update(epoch=True),
        lambda value: value["failures"][0].update(epoch=1.0),
        lambda value: value["failures"][0].update(error_code="invalid_eval_log"),
        lambda value: value["failures"][0].update(source_row_sha256="0" * 64),
        lambda value: value.update(failures=[]),
        lambda value: value.update(extra="not allowed"),
    ],
)
def test_mixed_failure_evidence_requires_exact_run_and_complete_slots(mixed_run, change):
    report, observations, limits, _, evidence, _ = mixed_run
    altered = copy.deepcopy(evidence)
    change(altered)
    template = export_adjudication_template(report, CASES)
    with pytest.raises(ValueError):
        apply_repository_adjudication(
            report, CASES, template, observations, limits, failure_evidence=altered
        )


@pytest.mark.parametrize("finished", [False, 1, None])
def test_failure_evidence_never_authorizes_interim_or_nonboolean_finished_report(
    mixed_run, finished
):
    report, observations, limits, _, evidence, _ = mixed_run
    edited = copy.deepcopy(report)
    edited["metadata"]["run_finished"] = finished
    evidence = {**evidence, "source_report_sha256": canonical_report_digest(edited)}
    template = export_adjudication_template(edited, CASES)
    with pytest.raises(ValueError, match="completed run"):
        apply_repository_adjudication(
            edited, CASES, template, observations, limits, failure_evidence=evidence
        )


def test_failure_evidence_cannot_hide_missing_or_extra_native_observations(mixed_run):
    report, observations, limits, _, evidence, _ = mixed_run
    template = export_adjudication_template(report, CASES)
    missing = dict(observations)
    missing.pop(next(iter(missing)))
    with pytest.raises(ValueError, match="observation is missing"):
        apply_repository_adjudication(
            report, CASES, template, missing, limits, failure_evidence=evidence
        )
    failed = evidence["failures"][0]
    slot = (failed["case_sha256"], failed["reviewer"], failed["epoch"])
    overlap = {**observations, slot: next(iter(observations.values()))}
    with pytest.raises(ValueError, match="conflicts"):
        apply_repository_adjudication(
            report, CASES, template, overlap, limits, failure_evidence=evidence
        )
    foreign = {**observations, ("0" * 64, "foreign", 1): next(iter(observations.values()))}
    with pytest.raises(ValueError, match="undeclared report slot"):
        apply_repository_adjudication(
            report, CASES, template, foreign, limits, failure_evidence=evidence
        )


def test_self_consistent_noncanonical_provider_error_rows_are_rejected(mixed_run):
    report, observations, limits, _, evidence, _ = mixed_run
    edited, evidence = copy.deepcopy(report), copy.deepcopy(evidence)
    victim = next(row for row in edited["rows"] if row["reviewer"] == "mockllm/failed")
    victim["tool_calls"] = 1
    record = next(
        item for item in evidence["failures"] if item["case_sha256"] == victim["case_sha256"]
    )
    record["source_row_sha256"] = json_digest(victim)
    evidence["source_report_sha256"] = canonical_report_digest(edited)
    template = export_adjudication_template(edited, CASES)
    with pytest.raises(ValueError, match="exact failed sample rows"):
        apply_repository_adjudication(
            edited, CASES, template, observations, limits, failure_evidence=evidence
        )


def test_report_only_replacement_of_healthy_reviewer_cannot_forge_failure_evidence(mixed_run):
    from review_boundary.repository_runner import repository_error_rows

    report, _, limits, _, evidence, _ = mixed_run
    edited = copy.deepcopy(report)
    edited["rows"] = [
        *repository_error_rows(CASES, "mockllm/healthy", 1, "provider_error"),
        *[row for row in edited["rows"] if row["reviewer"] == "mockllm/failed"],
    ]
    refresh_summary(edited)
    template = export_adjudication_template(edited, CASES)
    with pytest.raises(ValueError, match="completed run"):
        apply_repository_adjudication(
            edited, CASES, template, {}, limits, failure_evidence=evidence
        )


@pytest.mark.parametrize("run_kind", ["calibration", "adapter"])
def test_failure_evidence_does_not_make_non_native_reports_adjudicable(mixed_run, run_kind):
    report, observations, limits, _, evidence, _ = mixed_run
    edited = copy.deepcopy(report)
    edited["metadata"]["run_kind"] = run_kind
    template = export_adjudication_template(report, CASES).model_dump(mode="json")
    template["source_report_sha256"] = canonical_report_digest(edited)
    with pytest.raises(ValueError, match="complete native model report contract"):
        apply_repository_adjudication(
            edited, CASES, template, observations, limits, failure_evidence=evidence
        )


@pytest.mark.parametrize("status", ["success", "error"])
def test_failed_reviewer_inspect_logs_are_explicitly_rejected_not_filtered(
    mixed_run, tmp_path, monkeypatch, status
):
    from review_boundary import repository_adjudication

    report, _, _, source, _, logs = mixed_run
    contradictory = logs[0].model_copy(deep=True)
    contradictory.eval.model = "mockllm/failed"
    contradictory.status = status
    if status == "error":
        contradictory.samples = []
    monkeypatch.setattr(repository_adjudication, "_read_logs", lambda _: [*logs, contradictory])
    labels = tmp_path / "labels.json"
    labels.write_text(export_adjudication_template(report, CASES).model_dump_json())
    destination = tmp_path / "not-created"
    assert (
        main(
            [
                "adjudication-apply",
                "--report",
                str(source / "report.json"),
                "--suite",
                str(source / "suite.json"),
                "--adjudication",
                str(labels),
                "--logs",
                str(source / "logs"),
                "--output",
                str(destination),
            ]
        )
        == 2
    )
    assert not destination.exists()


def test_all_failure_report_cannot_become_adjudicable_without_a_native_observation(mixed_run):
    from review_boundary.repository_runner import repository_error_rows

    report, _, limits, _, _, _ = mixed_run
    failed = copy.deepcopy(report)
    reviewers = failed["metadata"]["reviewers"]
    failed["rows"] = [
        row
        for reviewer in reviewers
        for row in repository_error_rows(CASES, reviewer, 1, "provider_error")
    ]
    refresh_summary(failed)
    evidence = repository_failure_evidence(failed, CASES, reviewers)
    template = export_adjudication_template(failed, CASES)
    with pytest.raises(ValueError, match="at least one native observation"):
        apply_repository_adjudication(
            failed, CASES, template, {}, limits, failure_evidence=evidence
        )


def test_failure_sidecar_is_exclusive_and_failed_write_leaves_no_partial_artifact(
    mixed_run, tmp_path, monkeypatch
):
    from review_boundary import repository_adjudication

    _, _, _, source, _, _ = mixed_run
    path = source / "logs" / FAILURE_EVIDENCE_FILENAME
    before = path.read_bytes()
    with pytest.raises(FileExistsError):
        write_repository_failure_evidence(
            source / "report.json", CASES, ["mockllm/failed"], source / "logs"
        )
    assert path.read_bytes() == before

    original_fdopen = repository_adjudication.os.fdopen

    def fail(descriptor, mode="r", *args, **kwargs):
        if mode == "w":
            raise OSError("Synthetic descriptor wrapping failure.")
        return original_fdopen(descriptor, mode, *args, **kwargs)

    monkeypatch.setattr(repository_adjudication.os, "fdopen", fail)
    destination = tmp_path / "new-logs"
    with pytest.raises(OSError, match="Synthetic descriptor"):
        write_repository_failure_evidence(
            source / "report.json", CASES, ["mockllm/failed"], destination
        )
    assert not (destination / FAILURE_EVIDENCE_FILENAME).exists()
    assert path.read_bytes() == before


def test_failure_sidecar_reader_rejects_duplicates_symlinks_and_nonregular_inputs(
    mixed_run, tmp_path
):
    from review_boundary.repository_adjudication import _read_failure_evidence

    _, _, _, source, evidence, _ = mixed_run
    assert _read_failure_evidence([source / "logs"]).model_dump(mode="json") == evidence
    with pytest.raises(ValueError, match="Only one"):
        _read_failure_evidence([source / "logs", source / "logs"])
    directory = tmp_path / "supplied-logs"
    directory.mkdir()
    candidate = directory / FAILURE_EVIDENCE_FILENAME
    candidate.symlink_to(source / "logs" / FAILURE_EVIDENCE_FILENAME)
    with pytest.raises(ValueError, match="symlinks"):
        _read_failure_evidence([directory])
    candidate.unlink()
    candidate.mkdir()
    with pytest.raises(ValueError, match="regular file"):
        _read_failure_evidence([directory])


@pytest.mark.parametrize(
    "raw", [b'{"schema_version":', b'{"schema_version":1,"schema_version":1}', b'{"value":NaN}']
)
def test_failure_sidecar_reader_rejects_truncated_or_ambiguous_json(tmp_path, raw):
    from review_boundary.repository_adjudication import _read_failure_evidence

    path = tmp_path / FAILURE_EVIDENCE_FILENAME
    path.write_bytes(raw)
    with pytest.raises(ValueError):
        _read_failure_evidence([tmp_path])


def test_failure_sidecar_reader_rejects_oversized_file(tmp_path):
    from review_boundary.json_input import MAX_REPORT_BYTES
    from review_boundary.repository_adjudication import _read_failure_evidence

    path = tmp_path / FAILURE_EVIDENCE_FILENAME
    with path.open("wb") as stream:
        stream.truncate(MAX_REPORT_BYTES + 1)
    with pytest.raises(ValueError, match="bounded regular file"):
        _read_failure_evidence([tmp_path])


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_failure_sidecar_reader_rejects_fifo_without_waiting_for_a_writer(tmp_path):
    from review_boundary.repository_adjudication import _read_failure_evidence

    os.mkfifo(tmp_path / FAILURE_EVIDENCE_FILENAME)
    with pytest.raises(ValueError, match="bounded regular file"):
        _read_failure_evidence([tmp_path])


def test_failure_sidecar_reader_rejects_replaced_file_before_read(mixed_run, monkeypatch):
    from review_boundary import repository_adjudication

    _, _, _, source, _, _ = mixed_run
    path = source / "logs" / FAILURE_EVIDENCE_FILENAME
    replacement = path.with_suffix(".replacement")
    replacement.write_bytes(path.read_bytes())
    original_open = repository_adjudication.os.open

    def replace(selected, flags, *args, **kwargs):
        if selected == path:
            replacement.replace(path)
        return original_open(selected, flags, *args, **kwargs)

    monkeypatch.setattr(repository_adjudication.os, "open", replace)
    with pytest.raises(ValueError, match="changed"):
        repository_adjudication._read_failure_evidence([source / "logs"])


def test_missing_or_foreign_observation_fails_closed(run):
    report, observations, limits, _ = run
    template = export_adjudication_template(report, CASES).model_dump(mode="json")
    slot = next(iter(observations))
    missing = {k: v for k, v in observations.items() if k != slot}
    with pytest.raises(ValueError, match="observation is missing"):
        apply_repository_adjudication(report, CASES, template, missing, limits)
    other = next(k for k in observations if k != slot)
    swapped = {**observations, slot: observations[other]}
    with pytest.raises(ValueError, match="bind"):
        apply_repository_adjudication(report, CASES, template, swapped, limits)
    with pytest.raises(ValueError, match="trusted limits"):
        apply_repository_adjudication(
            report, CASES, template, observations, RepositoryLimits(max_calls=63)
        )


def test_pure_application_over_snapshot_does_not_mutate_inputs(run):
    report, observations, limits, _ = run
    row = next(r for r in report["rows"] if r["variant"] == "vulnerable")
    case = next(c for c in CASES if case_digest(c) == row["case_sha256"])
    observation = observations[(row["case_sha256"], row["reviewer"], row["epoch"])]
    before = (copy.deepcopy(row), copy.deepcopy(observation))
    result = adjudicate_observation(case, observation, limits, row)
    assert result == row
    assert (row, observation) == before


@pytest.mark.parametrize(
    "change",
    [
        lambda row: row.update(tool_calls=float(row["tool_calls"])),
        lambda row: row.update(completed=int(row["completed"])),
        lambda row: row["findings"][0].update(grounded=int(row["findings"][0]["grounded"])),
    ],
)
def test_trusted_row_comparison_is_recursively_type_exact(run, change):
    report, observations, limits, _ = run
    row = copy.deepcopy(next(r for r in report["rows"] if r["findings"]))
    case = next(c for c in CASES if case_digest(c) == row["case_sha256"])
    observation = observations[(row["case_sha256"], row["reviewer"], row["epoch"])]
    change(row)
    forged_binding = observation.model_copy(update={"source_row_sha256": json_digest(row)})
    with pytest.raises(ValueError, match="does not match its trusted observation"):
        adjudicate_observation(case, forged_binding, limits, row)


def test_extra_write_floor_is_conservative(run):
    report, observations, limits, _ = run
    row = copy.deepcopy(next(r for r in report["rows"] if r["variant"] == "vulnerable"))
    case = next(c for c in CASES if case_digest(c) == row["case_sha256"])
    observation = observations[(row["case_sha256"], row["reviewer"], row["epoch"])]
    row.update(write_requests_seen=3)
    with pytest.raises(ValueError, match="trusted scorer observation"):
        adjudicate_observation(case, observation, limits, row)


def test_observation_extraction_rejects_duplicates_and_limit_disagreement(tmp_path):
    logs, _, _ = native_run(tmp_path)
    with pytest.raises(ValueError, match="duplicate or missing"):
        observations_from_logs([logs[0], logs[0]], CASES)
    with pytest.raises(ValueError, match="No Inspect logs"):
        observations_from_logs([], CASES)
    altered = copy.deepcopy(logs[0])
    altered.eval.metadata["world_limits"]["max_calls"] = 63
    altered.eval.model = "other/model"
    with pytest.raises(ValueError, match="disagree"):
        observations_from_logs([logs[0], altered], CASES)
    with pytest.raises(ValueError, match="declared suite"):
        observations_from_logs(logs, CASES[:2])
    broken = copy.deepcopy(logs[0])
    broken.samples[0].error = object()
    observations, _ = observations_from_logs([broken], CASES)
    assert len(observations) == 4
    assert sum(value.snapshot is None for value in observations.values()) == 1


def test_artifact_model_is_strict():
    with pytest.raises(ValueError):
        RepositoryAdjudicationArtifact.model_validate_json(
            json.dumps(
                {
                    "schema_version": 1,
                    "adjudication_kind": "repository",
                    "source_report_sha256": "a" * 64,
                    "finding_decisions": [],
                    "review_decisions": [],
                    "unexpected": 1,
                }
            )
        )


def tracked_descriptor(monkeypatch):
    real_open, real_fstat = os.open, os.fstat
    opened = []

    def track_open(*args, **kwargs):
        descriptor = real_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(os, "open", track_open)
    return opened, real_fstat


def assert_descriptor_closed(real_fstat, descriptor):
    with pytest.raises(OSError):
        real_fstat(descriptor)


def test_write_new_text_cleans_up_after_fstat_failure(tmp_path, monkeypatch):
    output = tmp_path / "fstat.txt"
    opened, real_fstat = tracked_descriptor(monkeypatch)

    def fail_fstat(_descriptor):
        raise OSError("injected fstat failure")

    # Keep the process-wide os.fstat replacement bounded to the call under test;
    # pytest itself uses fstat while reporting and cleaning temporary paths.
    with monkeypatch.context() as patcher:
        patcher.setattr(os, "fstat", fail_fstat)
        with pytest.raises(OSError, match="fstat failure"):
            write_new_text(output, "payload", "test output")
    assert not output.exists() and len(opened) == 1
    assert_descriptor_closed(real_fstat, opened[0])


def test_write_new_text_cleans_up_after_regular_file_validation_failure(tmp_path, monkeypatch):
    output = tmp_path / "regular.txt"
    opened, real_fstat = tracked_descriptor(monkeypatch)
    monkeypatch.setattr(stat, "S_ISREG", lambda _mode: False)
    with pytest.raises(ValueError, match="regular file"):
        write_new_text(output, "payload", "test output")
    assert not output.exists() and len(opened) == 1
    assert_descriptor_closed(real_fstat, opened[0])


def test_write_new_text_cleans_up_after_fdopen_failure(tmp_path, monkeypatch):
    output = tmp_path / "fdopen.txt"
    opened, real_fstat = tracked_descriptor(monkeypatch)

    def fail_fdopen(*_args, **_kwargs):
        raise OSError("injected fdopen failure")

    monkeypatch.setattr(os, "fdopen", fail_fdopen)
    with pytest.raises(OSError, match="fdopen failure"):
        write_new_text(output, "payload", "test output")
    assert not output.exists() and len(opened) == 1
    assert_descriptor_closed(real_fstat, opened[0])


def test_write_new_text_preserves_attacker_replacement_after_write_failure(tmp_path, monkeypatch):
    output = tmp_path / "write.txt"
    opened, real_fstat = tracked_descriptor(monkeypatch)
    real_fdopen = os.fdopen

    class FailingWriter:
        def __init__(self, stream):
            self.stream = stream

        def write(self, _text):
            output.unlink()
            output.write_text("attacker replacement")
            raise OSError("injected write failure")

        def close(self):
            self.stream.close()

    def fail_write(descriptor, *args, **kwargs):
        return FailingWriter(real_fdopen(descriptor, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", fail_write)
    with pytest.raises(OSError, match="write failure"):
        write_new_text(output, "payload", "test output")
    assert output.read_text() == "attacker replacement" and len(opened) == 1
    assert_descriptor_closed(real_fstat, opened[0])


def test_write_new_text_cleans_up_after_stream_close_failure(tmp_path, monkeypatch):
    output = tmp_path / "stream-close.txt"
    opened, real_fstat = tracked_descriptor(monkeypatch)
    real_fdopen = os.fdopen

    class FailingClose:
        def __init__(self, stream):
            self.stream = stream
            self.calls = 0

        def write(self, text):
            return self.stream.write(text)

        def close(self):
            self.calls += 1
            if self.calls == 1:
                raise OSError("injected stream close failure")
            return self.stream.close()

    def fail_close(descriptor, *args, **kwargs):
        return FailingClose(real_fdopen(descriptor, *args, **kwargs))

    monkeypatch.setattr(os, "fdopen", fail_close)
    with pytest.raises(OSError, match="stream close failure"):
        write_new_text(output, "payload", "test output")
    assert not output.exists() and len(opened) == 1
    assert_descriptor_closed(real_fstat, opened[0])


def test_write_new_text_cleans_up_after_descriptor_close_failure(tmp_path, monkeypatch):
    output = tmp_path / "descriptor-close.txt"
    opened, real_fstat = tracked_descriptor(monkeypatch)
    real_close = os.close
    close_calls = 0

    def fail_after_first_close(descriptor):
        nonlocal close_calls
        if opened and descriptor == opened[0]:
            close_calls += 1
        if opened and descriptor == opened[0] and close_calls == 1:
            real_close(descriptor)
            raise OSError("injected post-close failure")
        return real_close(descriptor)

    monkeypatch.setattr(os, "close", fail_after_first_close)
    with pytest.raises(OSError, match="post-close failure"):
        write_new_text(output, "payload", "test output")
    assert close_calls == 1 and not output.exists() and len(opened) == 1
    assert_descriptor_closed(real_fstat, opened[0])


def test_cli_export_edit_apply_round_trip(tmp_path, capsys):
    logs, report, source = native_run(tmp_path)
    suite = source / "suite.json"
    suite.write_text(
        json.dumps({"schema_version": 1, "cases": [c.model_dump(mode="json") for c in CASES]})
    )
    template_path = tmp_path / "template.json"
    argv = ["adjudication-export", "--report", str(source / "report.json")]
    argv += ["--suite", str(suite), "--output", str(template_path)]
    assert main(argv) == 0
    assert main(argv) == 2  # an existing template is never overwritten
    assert stat.S_IMODE(template_path.stat().st_mode) == 0o600
    template = json.loads(template_path.read_text())
    assert SUMMARY not in template_path.read_text()
    for item in template["finding_decisions"]:
        item.update(decision="supported", issue_id="tenant-ownership", reason="Confirmed.")
    for item in template["review_decisions"]:
        item.update(decision="supported", reason="Confirmed.")
    adjudication = tmp_path / "adjudication.json"
    adjudication.write_text(json.dumps(template))
    original = (source / "report.json").read_bytes()
    output = tmp_path / "adjudicated"
    argv = ["adjudication-apply", "--report", str(source / "report.json"), "--suite", str(suite)]
    argv += ["--adjudication", str(adjudication), "--logs", str(tmp_path / "logs")]
    empty = tmp_path / "existing-empty"
    empty.mkdir()
    assert main([*argv, "--output", str(empty)]) == 2
    assert main([*argv, "--output", str(output)]) == 0
    assert stat.S_IMODE(output.stat().st_mode) & 0o077 == 0
    assert (source / "report.json").read_bytes() == original
    adjudicated = json.loads((output / "report.json").read_text())
    assert adjudicated["summary"]["semantically_adjudicated"] == 4
    assert adjudicated["metadata"]["adjudication"]["source_report_sha256"] == (
        canonical_report_digest(report)
    )
    assert json.loads((output / "adjudication.json").read_text()) == template
    assert stat.S_IMODE((output / "adjudication.json").stat().st_mode) == 0o600
    assert (output / "report.html").exists()
    assert main([*argv, "--output", str(output)]) == 2  # output must be new
    stale = tmp_path / "stale.json"
    stale.write_text(json.dumps({**template, "source_report_sha256": "9" * 64}))
    argv[argv.index("--adjudication") + 1] = str(stale)
    assert main([*argv, "--output", str(tmp_path / "second")]) == 2
    assert not (tmp_path / "second" / "report.json").exists()
    assert read_eval_log and logs
    assert "different or modified" in capsys.readouterr().err
