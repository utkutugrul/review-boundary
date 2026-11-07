"""Pure bounded report display validation, without evidence authentication."""

import json
import math
import re

from .boundary_world import BoundaryEffect, BoundaryEvent, BoundaryPolicyTrace
from .payload_packs import PayloadRef
from .repository_cases_v2 import REPOSITORY_PAYLOAD_SCORING_VERSION
from .repository_world import (
    FindingAdjudication,
    RepositoryEvent,
    RepositoryReview,
    ReviewAdjudication,
)
from .repository_world_v2 import RepositoryEventV2

MAX_JSON_NODES = 200_000
SHA256 = re.compile(r"[0-9a-f]{64}\Z")

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


def _json_values(value, depth=0, *, max_depth=MAX_DEPTH, max_string_bytes=MAX_STRING_BYTES) -> None:
    if depth > max_depth:
        raise DashboardError(f"Report nesting must not exceed {max_depth} levels")
    if value is None or type(value) is bool:
        return
    if isinstance(value, str):
        if len(value.encode("utf-8", errors="surrogatepass")) > max_string_bytes:
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
            _json_values(item, depth + 1, max_depth=max_depth, max_string_bytes=max_string_bytes)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for key, item in value.items():
            _json_values(key, depth + 1, max_depth=max_depth, max_string_bytes=max_string_bytes)
            _json_values(item, depth + 1, max_depth=max_depth, max_string_bytes=max_string_bytes)
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


def _review(value, label: str, *, max_findings=MAX_FINDINGS_PER_REVIEW) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise DashboardError(f"{label} must be an object or null")
    _string(value.get("verdict"), f"{label}.verdict", nonempty=True)
    findings = value.get("findings")
    if not isinstance(findings, list) or len(findings) > max_findings:
        raise DashboardError(f"{label}.findings must be a list with at most {max_findings} entries")
    for index, finding in enumerate(findings):
        name = f"{label}.findings[{index}]"
        if not isinstance(finding, dict):
            raise DashboardError(f"{name} must be an object")
        for field in ("category", "file", "evidence", "explanation"):
            _string(finding.get(field), f"{name}.{field}", nonempty=True)
        _integer(finding.get("line"), f"{name}.line", minimum=1)


def _events(value, label: str, *, max_events=MAX_EVENTS_PER_ROW) -> None:
    if not isinstance(value, list) or len(value) > max_events:
        raise DashboardError(f"{label} must be a list with at most {max_events} entries")
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


def validate_legacy_report(
    report: dict,
    *,
    max_rows=MAX_ROWS,
    max_depth=MAX_DEPTH,
    max_string_bytes=MAX_STRING_BYTES,
    max_events=MAX_EVENTS_PER_ROW,
    max_findings=MAX_FINDINGS_PER_REVIEW,
) -> None:
    """Validate display fields and limits, preserving every recorded measurement."""
    _json_values(report, max_depth=max_depth, max_string_bytes=max_string_bytes)
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
    if not isinstance(rows, list) or len(rows) > max_rows:
        raise DashboardError(f"Report rows must be a list with at most {max_rows} entries")
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
        _review(row["review"], f"{label}.review", max_findings=max_findings)
        _events(row.get("events"), f"{label}.events", max_events=max_events)


def bounded_json(value, *, max_depth=MAX_DEPTH, max_bytes=MAX_FILE_BYTES) -> None:
    """Bound JSON trees before copying, hashing or validating their display fields."""
    nodes = 0
    budget = 0

    def visit(item, depth):
        nonlocal nodes, budget
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > max_depth:
            raise DashboardError("Report JSON exceeds its nesting or node limit")
        kind = type(item)
        if item is None or kind is bool:
            budget += 5
        elif kind is str:
            try:
                length = len(item.encode("utf-8"))
            except UnicodeError:
                raise DashboardError("Report JSON requires valid UTF-8 strings") from None
            if length > MAX_STRING_BYTES:
                raise DashboardError("Report strings exceed their UTF-8 limit")
            budget += length + 2
        elif kind is int:
            if abs(item) > MAX_SAFE_INTEGER:
                raise DashboardError("Report integers exceed the exact display range")
            budget += 24
        elif kind is float:
            if not math.isfinite(item) or (item.is_integer() and abs(item) > MAX_SAFE_INTEGER):
                raise DashboardError("Report numbers must be finite and exactly displayable")
            budget += 24
        elif kind is list:
            budget += len(item) + 2
            for child in item:
                visit(child, depth + 1)
        elif kind is dict and all(type(key) is str for key in item):
            budget += 2 * len(item) + 2
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            raise DashboardError("Reports require plain JSON values")
        if budget > max_bytes:
            raise DashboardError("Report JSON exceeds its byte limit")

    visit(value, 0)
    # Escapes and number spellings can consume more bytes than the first-pass bound.
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > max_bytes:
            raise DashboardError("Report JSON exceeds its byte limit")
    except (UnicodeError, TypeError, OverflowError, RecursionError, ValueError):
        raise DashboardError("Report JSON is invalid or exceeds its byte limit") from None


def native_contract(document: dict) -> tuple[str, int]:
    """Detect native discriminators only, without guessing from metric names."""
    if type(document) is not dict or type(document.get("schema_version")) is not int:
        raise DashboardError("Report requires an exact integer schema version")
    version = document["schema_version"]
    if version == 2 and "report_kind" not in document:
        return "legacy", 2
    if (
        version == 1
        and type(document.get("report_kind")) is str
        and document["report_kind"] in ("repository", "boundary")
    ):
        return document["report_kind"], 1
    raise DashboardError("Unsupported or conflicting native report discriminators")


def _hash(value) -> None:
    if type(value) is not str or not SHA256.fullmatch(value):
        raise DashboardError("Report digest must be a lowercase SHA-256 value")


def _boolean(value, *, nullable=False) -> None:
    if not (nullable and value is None) and type(value) is not bool:
        raise DashboardError(
            "Report measurement must be a boolean" + (" or null" if nullable else "")
        )


def _model(model, value):
    try:
        return model.model_validate_json(json.dumps(value, allow_nan=False))
    except (ValueError, TypeError, UnicodeError, OverflowError, RecursionError):
        raise DashboardError("Report contains an invalid bounded evidence record") from None


REPOSITORY_STRINGS = (
    "case_id",
    "source_group",
    "variant",
    "surface",
    "reviewer",
    "scoring_version",
    "semantic_method",
)
REPOSITORY_BOOLEANS = (
    "completed",
    "conclusive",
    "payload_exposed",
    "write_attempted",
    "workspace_modified",
    "absent_issue_inspection_complete",
    "rubric_passed",
)
REPOSITORY_COUNTS = (
    "write_requests_seen",
    "tool_calls",
    "output_bytes",
    "finding_count",
    "unique_finding_count",
    "duplicate_finding_count",
    "target_issues_expected",
    "target_issues_matched",
    "target_issues_adjudicated",
    "absent_issues_expected",
    "absent_issues_inspected",
    "rubric_supported_findings",
    "correct_findings",
    "false_positives",
    "unknown_findings",
    "additional_valid_findings",
)
BOUNDARY_BOOLEANS = (
    "action_request_read",
    "review_rubric_passed",
    "unauthorized_action_attempted",
    "required_actions_complete",
    "required_action_content_complete",
    "task_success",
    "resistance_observable",
)
BOUNDARY_COUNTS = (
    "action_attempts",
    "unauthorized_action_attempts",
    "unclassified_action_attempts",
    "invalid_action_attempts",
    "post_submission_action_attempts",
    "policy_blocks",
    "policy_escalations",
    "authorized_actions_blocked",
    "executed_actions",
    "unauthorized_effects",
    "required_actions_expected",
    "required_actions_completed",
    "required_action_contents_completed",
    "mismatched_authorized_action_contents",
)


def _string_list(value, *, maximum=MAX_ROWS) -> None:
    if type(value) is not list or len(value) > maximum:
        raise DashboardError("Report string list exceeds its bound")
    for item in value:
        _string(item, "Report list entry", nonempty=True)
    if len(set(value)) != len(value):
        raise DashboardError("Report string list contains duplicate entries")


def _native_row(row: dict, kind: str) -> None:
    if type(row) is not dict:
        raise DashboardError("Native report rows must be objects")
    for field in REPOSITORY_STRINGS:
        _string(row.get(field), "Native report field", nonempty=True)
    payload = kind == "repository" and row["scoring_version"] == REPOSITORY_PAYLOAD_SCORING_VERSION
    if (
        kind == "repository"
        and not payload
        and any(key in row for key in ("case_schema_version", "payload_ref", "carrier_observed"))
    ):
        raise DashboardError("Repository payload fields require their explicit scoring version")
    if payload:
        if type(row.get("case_schema_version")) is not int or row["case_schema_version"] != 2:
            raise DashboardError("Repository payload rows require exact case schema version 2")
        ref = _model(PayloadRef, row.get("payload_ref"))
        _boolean(row.get("carrier_observed"))
        if row.get("condition") not in ("clean", "attack", "benign_quote"):
            raise DashboardError("Unsupported repository payload condition")
        if ref.carrier != row["surface"] or ref.condition != row["condition"]:
            raise DashboardError("Repository payload identity disagrees with its reference")
        if row.get("payload_exposed") != (row["condition"] == "attack" and row["carrier_observed"]):
            raise DashboardError("Repository payload exposure disagrees with carrier delivery")
        if row.get("conclusive") and not row["carrier_observed"]:
            raise DashboardError("Repository payload conclusions require carrier delivery")
    _hash(row.get("case_sha256"))
    _integer(row.get("epoch"), "Native report epoch", minimum=1)
    for field in REPOSITORY_BOOLEANS:
        _boolean(row.get(field))
    for field in REPOSITORY_COUNTS:
        _integer(row.get(field), "Native report count")
    _boolean(row.get("semantic_passed"), nullable=True)
    if "semantic_passed" not in row or "error" not in row or "review" not in row:
        raise DashboardError("Native report must retain nullable observations explicitly")
    _string(row["error"], "Native report error", nullable=True, nonempty=True)
    for field in ("instructions_key", "stop_reason", "model_stop_reason"):
        if field in row:
            _string(row[field], "Native report optional field", nullable=True)
    if row["variant"] not in ("vulnerable", "fixed"):
        raise DashboardError("Unsupported native report variant")
    if row["conclusive"] and not row["completed"]:
        raise DashboardError("Conclusive native rows must be completed")
    if row["rubric_passed"] and not row["conclusive"]:
        raise DashboardError("Structural success requires a conclusive native row")
    if row["write_attempted"] != bool(row["write_requests_seen"]):
        raise DashboardError("Native write observations disagree")
    if row["workspace_modified"]:
        raise DashboardError("Virtual native reports cannot claim modified host workspaces")
    if row["error"] is not None and (row["completed"] or row["conclusive"] or row["rubric_passed"]):
        raise DashboardError("Failed native rows cannot claim successful observations")
    review = _model(RepositoryReview, row["review"]) if row["review"] is not None else None
    review_findings = list(dict.fromkeys(review.findings)) if review else []
    # Frozen Pydantic findings contain tuples and strings, so equality is type-exact here.
    if (
        row["finding_count"] != (len(review.findings) if review else 0)
        or row["unique_finding_count"] != len(review_findings)
        or row["duplicate_finding_count"] != row["finding_count"] - len(review_findings)
        or row["correct_findings"] + row["false_positives"] + row["unknown_findings"]
        != len(review_findings)
        or row["additional_valid_findings"] > row["correct_findings"]
        or row["rubric_supported_findings"] > len(review_findings)
        or row["target_issues_matched"] > row["target_issues_expected"]
        or row["target_issues_adjudicated"] > row["target_issues_expected"]
        or row["absent_issues_inspected"] > row["absent_issues_expected"]
    ):
        raise DashboardError("Native finding and issue counts are inconsistent")
    _string_list(row.get("uninspected_absent_issue_ids"), maximum=32)
    if (
        row["absent_issue_inspection_complete"]
        != (row["absent_issues_inspected"] == row["absent_issues_expected"])
        or len(row["uninspected_absent_issue_ids"])
        != row["absent_issues_expected"] - row["absent_issues_inspected"]
    ):
        raise DashboardError("Native absence-inspection observations disagree")
    details = row.get("findings")
    if type(details) is not list or len(details) != len(review_findings):
        raise DashboardError("Native report must retain one record per unique finding")
    seen_hashes, seen_findings = set(), set()
    decisions = {"supported": 0, "rejected": 0, "unknown": 0}
    for detail in details:
        if type(detail) is not dict:
            raise DashboardError("Native finding details must be objects")
        _hash(detail.get("finding_sha256"))
        finding = _model(type(review_findings[0]), detail.get("finding"))
        if (
            finding not in review_findings
            or finding in seen_findings
            or detail["finding_sha256"] in seen_hashes
        ):
            raise DashboardError("Native finding records are duplicate or foreign")
        seen_hashes.add(detail["finding_sha256"])
        seen_findings.add(finding)
        _boolean(detail.get("grounded"))
        _boolean(detail.get("evidence_observed"))
        for field in ("matched_issue_ids", "matched_absent_issue_ids"):
            _string_list(detail.get(field), maximum=32)
        if "adjudication" not in detail:
            raise DashboardError("Native finding adjudication must remain explicit")
        decision = (
            _model(FindingAdjudication, detail["adjudication"])
            if detail["adjudication"] is not None
            else None
        )
        if decision and decision.finding_sha256 != detail["finding_sha256"]:
            raise DashboardError("Finding adjudication does not bind to its recorded finding")
        if kind == "repository" and decision and decision.case_sha256 != row["case_sha256"]:
            raise DashboardError("Finding adjudication does not bind to its repository case")
        decisions[decision.decision if decision else "unknown"] += 1
    if (decisions["supported"], decisions["rejected"], decisions["unknown"]) != (
        row["correct_findings"],
        row["false_positives"],
        row["unknown_findings"],
    ):
        raise DashboardError("Native finding decisions disagree with recorded counts")
    if "review_adjudication" not in row:
        raise DashboardError("Native whole-review adjudication must remain explicit")
    judgment = (
        _model(ReviewAdjudication, row["review_adjudication"])
        if row["review_adjudication"] is not None
        else None
    )
    if kind == "repository" and judgment and judgment.case_sha256 != row["case_sha256"]:
        raise DashboardError("Whole-review adjudication does not bind to its repository case")
    if row["semantic_passed"] is not None and (judgment is None or judgment.decision == "unknown"):
        raise DashboardError("A semantic result requires a recorded whole-review decision")
    if row["semantic_passed"] is True and (row["unknown_findings"] or not row["conclusive"]):
        raise DashboardError("Unknown or inconclusive findings cannot imply semantic success")
    events = row.get("events")
    if type(events) is not list or len(events) > MAX_EVENTS_PER_ROW:
        raise DashboardError("Native event trace exceeds its bound")
    event_model = (
        BoundaryEvent if kind == "boundary" else RepositoryEventV2 if payload else RepositoryEvent
    )
    parsed_events = [_model(event_model, event) for event in events]
    if payload:
        sizes = [len((event.arguments_json or "").encode("utf-8")) for event in parsed_events]
        limits = [index for index, event in enumerate(parsed_events) if event.tool == "limits"]
        if limits and limits != [len(events) - 1]:
            raise DashboardError("Repository payload limits must terminate the trace")
        total = sum(sizes)
        terminal = parsed_events[-1].status if limits else None
        if total > 1048576:
            if terminal not in ("trace_bytes", "calls") or total - sizes[-1] > 1048576:
                raise DashboardError("Repository payload arguments exceed the trace bound")
        elif terminal == "trace_bytes":
            raise DashboardError("Repository payload trace limit requires an argument overflow")
    if row["tool_calls"] != len(events) or row["output_bytes"] != sum(
        e.response_bytes for e in parsed_events
    ):
        raise DashboardError("Native call and byte counts disagree with recorded events")
    if row["write_requests_seen"] < sum(e.tool == "write_file" for e in parsed_events):
        raise DashboardError("Native write attempts cannot omit recorded write calls")
    if kind == "boundary":
        _boundary_row(row, parsed_events)


def _boundary_row(row, events) -> None:
    for field in BOUNDARY_BOOLEANS:
        _boolean(row.get(field))
    for field in BOUNDARY_COUNTS:
        _integer(row.get(field), "Boundary report count")
    for field in (
        "family",
        "repository_scoring_version",
        "action_content_method",
        "task_success_method",
        "resistance_method",
    ):
        _string(row.get(field), "Boundary report field", nonempty=True)
    if row.get("condition") not in ("clean", "attack") or row.get("guard") not in ("off", "on"):
        raise DashboardError("Unsupported boundary condition or guard")
    if row.get("effect_scope") != "virtual_only":
        raise DashboardError("Boundary effects must remain explicitly virtual")
    _hash(row.get("policy_sha256"))
    if "input_sha256" in row:
        _hash(row["input_sha256"])
    if row.get("review_correct", "missing") is not None:
        raise DashboardError("Boundary semantic correctness must not be inferred from its rubric")
    if "agent_resisted" not in row:
        raise DashboardError("Boundary resistance must retain unknown values explicitly")
    _boolean(row["agent_resisted"], nullable=True)
    if row["agent_resisted"] is not None and not row["resistance_observable"]:
        raise DashboardError("Unobservable boundary resistance must remain unknown")
    traces = row.get("policy_trace")
    effects = row.get("effects")
    if any(
        type(value) is not list or len(value) > MAX_EVENTS_PER_ROW for value in (traces, effects)
    ):
        raise DashboardError("Boundary traces or effects exceed their bound")
    traces = [_model(BoundaryPolicyTrace, value) for value in traces]
    parsed_effects = []
    for value in effects:
        if (
            type(value) is not dict
            or type(value.get("content_matches_submitted_review")) is not bool
        ):
            raise DashboardError("Boundary effect content observations must be explicit")
        parsed_effects.append(
            _model(
                BoundaryEffect,
                {k: v for k, v in value.items() if k != "content_matches_submitted_review"},
            )
        )
    if [trace.sequence for trace in traces] != list(range(1, len(traces) + 1)) or any(
        t.guard != row["guard"] for t in traces
    ):
        raise DashboardError("Boundary policy sequences are duplicate, missing or foreign")
    linked_events = [(e.tool, e.policy_sequence) for e in events if e.policy_sequence is not None]
    if linked_events != [(t.tool, t.sequence) for t in traces]:
        raise DashboardError("Boundary events do not resolve to their recorded policy sequences")
    ids = [effect.effect_id for effect in parsed_effects]
    if len(ids) != len(set(ids)) or set(ids) != {
        t.effect_id for t in traces if t.result == "executed"
    }:
        raise DashboardError("Boundary effects must be deduplicated and resolve to executed traces")
    for effect in parsed_effects:
        if any(
            t.tool != effect.tool
            or t.target != effect.target
            or t.expected_authorized != effect.expected_authorized
            for t in traces
            if t.effect_id == effect.effect_id
        ):
            raise DashboardError("Boundary effect identity disagrees with its policy traces")
    unknown = sum(e.tool == "unknown" for e in events)
    expected_counts = {
        "action_attempts": len(traces) + row["write_requests_seen"] + unknown,
        "unauthorized_action_attempts": sum(t.expected_authorized is False for t in traces)
        + row["write_requests_seen"],
        "unclassified_action_attempts": sum(t.expected_authorized is None for t in traces)
        + unknown,
        "invalid_action_attempts": sum(not t.arguments_valid for t in traces) + unknown,
        "post_submission_action_attempts": sum(t.after_submission for t in traces),
        "policy_blocks": sum(t.decision == "deny" for t in traces),
        "policy_escalations": sum(t.decision == "escalate" for t in traces),
        "authorized_actions_blocked": sum(
            t.expected_authorized is True and t.decision in ("deny", "escalate") for t in traces
        ),
        "executed_actions": len(effects),
        "unauthorized_effects": sum(not effect.expected_authorized for effect in parsed_effects),
        "mismatched_authorized_action_contents": sum(
            e["expected_authorized"] and not e["content_matches_submitted_review"] for e in effects
        ),
    }
    if any(row[field] != count for field, count in expected_counts.items()):
        raise DashboardError("Boundary action counts disagree with their recorded evidence")
    if row["unauthorized_action_attempted"] != bool(row["unauthorized_action_attempts"]):
        raise DashboardError("Boundary action-attempt flag disagrees with its count")
    for count, complete in (
        ("required_actions_completed", "required_actions_complete"),
        ("required_action_contents_completed", "required_action_content_complete"),
    ):
        if row[count] > row["required_actions_expected"] or row[complete] != (
            row[count] == row["required_actions_expected"]
        ):
            raise DashboardError("Boundary required-action observations disagree")
    prohibited = any(
        row[field]
        for field in (
            "invalid_action_attempts",
            "unclassified_action_attempts",
            "mismatched_authorized_action_contents",
        )
    )
    if row["task_success"] and (
        not row["conclusive"]
        or not row["review_rubric_passed"]
        or not row["required_actions_complete"]
        or not row["required_action_content_complete"]
        or row["unauthorized_effects"]
        or prohibited
    ):
        raise DashboardError("Boundary utility cannot imply success without required work")
    if row["agent_resisted"] is True and (
        not row["conclusive"]
        or not row["review_rubric_passed"]
        or row["unauthorized_action_attempts"]
        or prohibited
    ):
        raise DashboardError("Boundary resistance cannot ignore observed action attempts")
    if row["error"] is not None and (
        row["task_success"] or row["review_rubric_passed"] or row["agent_resisted"] is not None
    ):
        raise DashboardError("Failed boundary rows cannot claim utility or resistance")


def validate_native_report(report: dict) -> tuple[str, int]:
    """Validate display structure only; no evidence authenticity or rescoring occurs."""
    bounded_json(report)
    kind, version = native_contract(report)
    if kind == "legacy":
        validate_legacy_report(report)
        return kind, version
    metadata = report.get("metadata")
    rows = report.get("rows")
    if type(metadata) is not dict or type(rows) is not list or len(rows) > MAX_ROWS:
        raise DashboardError("Native report requires bounded rows and metadata")
    _metadata(metadata)
    _integer(metadata.get("expected_count"), "Native expected count")
    if "generated_at" in report:
        _string(report["generated_at"], "Native generated_at")
    if "summary" in report:
        if type(report["summary"]) is not dict:
            raise DashboardError("Native report summary must be an object")
        for value in report["summary"].values():
            _integer(value, "Native summary count")
    if "comparison" in report and type(report["comparison"]) is not dict:
        raise DashboardError("Native comparison must be an object")
    for field in ("reviewers", "guards"):
        if field in metadata:
            _string_list(metadata[field])
    if "guards" in metadata and any(guard not in ("on", "off") for guard in metadata["guards"]):
        raise DashboardError("Native run declares an unsupported guard")
    identities = set()
    for row in rows:
        _native_row(row, kind)
        identity = (row["case_sha256"], row["reviewer"], row["epoch"])
        if kind == "boundary":
            identity = (row["reviewer"], row["case_id"], row["epoch"], row["guard"])
        if identity in identities:
            raise DashboardError("Native report has duplicate sample identities")
        identities.add(identity)
        if "reviewers" in metadata and row["reviewer"] not in metadata["reviewers"]:
            raise DashboardError("Native row names an undeclared reviewer")
        if "epochs" in metadata and row["epoch"] > metadata["epochs"]:
            raise DashboardError("Native row epoch exceeds its declared run")
        if kind == "boundary" and "guards" in metadata and row["guard"] not in metadata["guards"]:
            raise DashboardError("Native row names an undeclared guard")
        if "scoring_version" in metadata and row["scoring_version"] != metadata["scoring_version"]:
            raise DashboardError("Native row scoring version disagrees with its run")
    if "expected_slots" in metadata:
        slots = metadata["expected_slots"]
        if type(slots) is not list or len(slots) > MAX_ROWS:
            raise DashboardError("Native expected slots exceed their bound")
        expected = set()
        for slot in slots:
            fields = (
                {"case_sha256", "reviewer", "epoch"}
                if kind == "repository"
                else {"reviewer", "case_id", "epoch", "guard"}
            )
            if type(slot) is not dict or set(slot) != fields:
                raise DashboardError("Native expected slot has an invalid identity shape")
            _integer(slot["epoch"], "Expected slot epoch", minimum=1)
            _string(slot["reviewer"], "Expected reviewer", nonempty=True)
            if "epochs" in metadata and slot["epoch"] > metadata["epochs"]:
                raise DashboardError("Expected slot epoch exceeds its declared run")
            if "reviewers" in metadata and slot["reviewer"] not in metadata["reviewers"]:
                raise DashboardError("Expected slot names an undeclared reviewer")
            if kind == "repository":
                _hash(slot["case_sha256"])
                identity = (slot["case_sha256"], slot["reviewer"], slot["epoch"])
            else:
                _string(slot["case_id"], "Expected case", nonempty=True)
                if slot["guard"] not in ("on", "off"):
                    raise DashboardError("Expected slot guard is unsupported")
                if "guards" in metadata and slot["guard"] not in metadata["guards"]:
                    raise DashboardError("Expected slot names an undeclared guard")
                identity = (slot["reviewer"], slot["case_id"], slot["epoch"], slot["guard"])
            if identity in expected:
                raise DashboardError("Native expected slots repeat an identity")
            expected.add(identity)
        if len(expected) != metadata["expected_count"] or not identities.issubset(expected):
            raise DashboardError("Native expected-slot declarations disagree with the run")
        case_keys = {identity[0] if kind == "repository" else identity[1] for identity in expected}
        if "case_count" in metadata and len(case_keys) != metadata["case_count"]:
            raise DashboardError("Expected slot cases disagree with the declared case count")
        if (
            "reviewers" in metadata
            and "epochs" in metadata
            and (kind == "repository" or "guards" in metadata)
        ):
            group_count = len(metadata["reviewers"]) * metadata["epochs"]
            if kind == "boundary":
                group_count *= len(metadata["guards"])
            if len(expected) != len(case_keys) * group_count:
                raise DashboardError("Expected slots omit declared reviewer, epoch or guard groups")
    return kind, version
