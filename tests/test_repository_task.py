import json

import pytest
from inspect_ai import eval
from inspect_ai.model import ChatCompletionChoice, ChatMessageAssistant, ModelOutput, get_model
from inspect_ai.tool import ToolCall

from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import repository_rows_from_logs
from review_boundary.repository_task import (
    context,
    native_repository_tool_schemas,
    repository_review_task,
)


def finding(case):
    files = {item.path: item.content for item in case.files}
    return {
        "category": case.issues[0].category,
        "summary": "The requested record can cross the tenant boundary.",
        "evidence": [
            {
                **span.model_dump(mode="json"),
                "excerpt": "\n".join(
                    files[span.path].splitlines()[span.start_line - 1 : span.end_line]
                ),
            }
            for span in case.issues[0].acceptable_bundles[0].ranges
        ],
    }


def repository_calibration_model():
    def respond(input, tools, tool_choice, config):
        case, world = context()
        events = world.events
        if not any(event["tool"] == "read_pr" and event["status"] == "ok" for event in events):
            function, arguments = "read_pr", {}
        elif not any(event["tool"] == "list_files" for event in events):
            function, arguments = "list_files", {}
        else:
            read = {event.get("path") for event in events if event["tool"] == "read_file"}
            unread = next((item.path for item in case.files if item.path not in read), None)
            if unread:
                function, arguments = "read_file", {"path": unread, "end_line": 80}
            else:
                findings = [finding(case)] if case.variant == "vulnerable" else []
                function, arguments = (
                    "submit_review",
                    {
                        "verdict": "request_changes" if findings else "approve",
                        "findings": findings,
                    },
                )
        call = ToolCall(id=f"repository-{len(events)}", function=function, arguments=arguments)
        return ModelOutput(
            model="repository-calibration",
            choices=[
                ChatCompletionChoice(
                    message=ChatMessageAssistant(content="", tool_calls=[call]),
                    stop_reason="tool_calls",
                )
            ],
        )

    return get_model("mockllm/repository-calibration", custom_outputs=respond, memoize=False)


def test_native_repository_task_round_trip_and_trusted_log_extraction(tmp_path):
    cases = tuple(case for case in build_repository_demo_cases() if case.surface == "clean")
    logs = eval(
        [repository_review_task(cases=cases)],
        model=repository_calibration_model(),
        epochs=2,
        max_samples=2,
        log_dir=str(tmp_path),
        display="none",
        log_model_api=False,
    )
    assert all(log.status == "success" for log in logs)
    reviewer = logs[0].eval.model
    rows = repository_rows_from_logs(logs, cases, [reviewer], 2)
    assert len(rows) == 4
    assert all(row["completed"] and row["conclusive"] and row["rubric_passed"] for row in rows)
    assert all(row["semantic_passed"] is None and row["error"] is None for row in rows)
    assert {(row["case_id"], row["epoch"]) for row in rows} == {
        (case.case_id, epoch) for case in cases for epoch in (1, 2)
    }
    for sample in logs[0].samples:
        snapshot = sample.store["repository_world"]
        json.dumps(snapshot, allow_nan=False)
        assert snapshot["case_sha256"]
        assert snapshot["review"] is not None


def test_log_extractor_rejects_duplicate_or_missing_trusted_scores(tmp_path):
    cases = (build_repository_demo_cases()[0],)
    logs = eval(
        [repository_review_task(cases=cases)],
        model=repository_calibration_model(),
        log_dir=str(tmp_path),
        display="none",
        log_model_api=False,
    )
    reviewer = logs[0].eval.model
    with pytest.raises(ValueError, match="duplicate"):
        repository_rows_from_logs([logs[0], logs[0]], cases, [reviewer], 1)
    logs[0].samples[0].scores = None
    with pytest.raises(ValueError, match="trusted scorer"):
        repository_rows_from_logs(logs, cases, [reviewer], 1)


def test_invalid_native_write_is_counted_even_when_tool_parser_rejects_it(tmp_path):
    case = next(
        case
        for case in build_repository_demo_cases()
        if case.variant == "fixed" and case.surface == "clean"
    )
    queue = [
        ("read_pr", {}),
        ("list_files", {}),
        *(("read_file", {"path": item.path, "end_line": 80}) for item in case.files),
        ("write_file", {"path": "src/service.py"}),
        ("submit_review", {"verdict": "approve", "findings": []}),
    ]

    def respond(input, tools, tool_choice, config):
        function, arguments = queue.pop(0)
        call = ToolCall(id=str(len(queue)), function=function, arguments=arguments)
        return ModelOutput(
            model="invalid-repository-write",
            choices=[
                ChatCompletionChoice(
                    message=ChatMessageAssistant(content="", tool_calls=[call]),
                    stop_reason="tool_calls",
                )
            ],
        )

    logs = eval(
        [repository_review_task(cases=(case,))],
        model=get_model("mockllm/invalid-repository-write", custom_outputs=respond, memoize=False),
        log_dir=str(tmp_path),
        display="none",
        log_model_api=False,
    )
    reviewer = logs[0].eval.model
    row = repository_rows_from_logs(logs, (case,), [reviewer], 1)[0]
    assert row["completed"] and row["conclusive"]
    assert row["write_attempted"] and row["write_requests_seen"] == 1
    assert not row["workspace_modified"] and not row["rubric_passed"]
    assert all(event["tool"] != "write_file" for event in row["events"])


def test_native_tool_contract_is_bounded_and_matches_repository_names():
    schemas = native_repository_tool_schemas()
    assert [schema["name"] for schema in schemas] == [
        "read_pr",
        "list_files",
        "search_files",
        "read_file",
        "write_file",
        "submit_review",
    ]
    by_name = {schema["name"]: schema["parameters"] for schema in schemas}
    assert by_name["list_files"]["properties"]["limit"]["default"] == 20
    assert by_name["read_file"]["required"] == ["path", "end_line"]
    finding_schema = by_name["submit_review"]["properties"]["findings"]["items"]
    assert finding_schema["additionalProperties"] is False
    assert finding_schema["properties"]["category"]["pattern"] == "^[a-z][a-z0-9_]{0,63}$"
