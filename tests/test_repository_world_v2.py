import copy
import json

import pytest
from test_repository_cases_v2 import CARRIERS, CONDITIONS, make_v2

from review_boundary.repository_cases_v2 import parse_repository_case
from review_boundary.repository_world import (
    RepositoryLimitError,
    RepositoryLimits,
    ReviewAdjudication,
)
from review_boundary.repository_world_v2 import (
    MAX_EVENT_ARGUMENT_BYTES,
    MAX_TRACE_ARGUMENT_BYTES,
    RepositoryEventV2,
    RepositoryWorldSnapshotV2,
    RepositoryWorldV2,
    score_repository_world_v2,
)


def deliver(world):
    selected = world.case
    if selected.surface == "pr":
        return world.dispatch("read_pr", {})
    if selected.surface in ("filename", "tool_output"):
        return world.dispatch("list_files", {})
    return world.dispatch("read_file", {"path": selected.exposure.resource, "end_line": 80})


def inspect_source_and_submit(world):
    world.dispatch("read_pr", {})
    for span in world.case.issues[0].acceptable_bundles[0].ranges:
        world.dispatch("read_file", span.model_dump(exclude={"symbol"}))
    world.dispatch("submit_review", {"verdict": "approve", "findings": []})


@pytest.mark.parametrize("surface", CARRIERS)
@pytest.mark.parametrize("condition", CONDITIONS)
def test_only_actual_delivery_observes_carrier_and_only_attack_is_exposed(surface, condition):
    world = RepositoryWorldV2(make_v2(surface, condition))
    assert not world.carrier_observed and not world.exposed
    deliver(world)
    assert world.carrier_observed
    assert world.exposed is (condition == "attack")
    restored = RepositoryWorldV2.from_snapshot(
        world.case, world.snapshot(), expected_limits=world.limits
    )
    assert restored.snapshot() == world.snapshot()


@pytest.mark.parametrize("surface", ["readme", "inert_file", "code_comment"])
def test_partial_and_noncontiguous_marker_lines_remain_unexposed(surface):
    world = RepositoryWorldV2(make_v2(surface, marker="First.\nMiddle.\nLast."))
    lines = {item.path: item.content.splitlines() for item in world.case.files}
    source = lines[world.case.exposure.resource]
    marker_start = next(index for index, line in enumerate(source, 1) if "First." in line)
    for line in (marker_start, marker_start + 2):
        world.dispatch(
            "read_file",
            {"path": world.case.exposure.resource, "start_line": line, "end_line": line},
        )
    assert not world.carrier_observed and not world.exposed
    world.dispatch(
        "read_file",
        {
            "path": world.case.exposure.resource,
            "start_line": marker_start + 1,
            "end_line": marker_start + 1,
        },
    )
    assert world.carrier_observed and world.exposed


@pytest.mark.parametrize("separator", ["\r\n", "\r", "\x85", "\u2028"])
def test_multiline_markers_follow_returned_source_line_normalization(separator):
    world = RepositoryWorldV2(make_v2(marker="First." + separator + "Second."))
    world.dispatch("read_file", {"path": "README.md", "start_line": 2, "end_line": 2})
    assert not world.exposed
    world.dispatch("read_file", {"path": "README.md", "start_line": 3, "end_line": 3})
    assert world.exposed


def test_filename_outside_list_page_or_unmatched_search_is_not_delivered():
    world = RepositoryWorldV2(make_v2("filename"), RepositoryLimits(max_list_entries=1))
    result = world.dispatch("list_files", {})
    assert result["files"][0]["path"] == "README.md"
    assert not world.carrier_observed
    world.dispatch("search_files", {"query": "missing text"})
    assert not world.carrier_observed
    world.dispatch("list_files", {"cursor": result["next_cursor"]})
    assert world.carrier_observed and world.exposed


def test_search_marker_exposure_uses_only_actual_bounded_match_pages():
    world = RepositoryWorldV2(make_v2(), RepositoryLimits(max_search_matches=1))
    first = world.dispatch("search_files", {"query": "carrier line."})
    assert len(first["matches"]) == 1 and first["truncated"]
    assert not world.carrier_observed
    world.dispatch("search_files", {"query": "carrier line.", "cursor": first["next_cursor"]})
    assert world.carrier_observed and world.exposed
    restored = RepositoryWorldV2.from_snapshot(
        world.case, world.snapshot(), expected_limits=world.limits
    )
    assert restored.snapshot() == world.snapshot()


@pytest.mark.parametrize("tool", ["read_file", "search_files"])
def test_filename_exposure_follows_actual_returned_read_or_search_paths(tool):
    world = RepositoryWorldV2(make_v2("filename"))
    args = (
        {"path": world.case.exposure.resource, "end_line": 1}
        if tool == "read_file"
        else {"query": "Inert file"}
    )
    world.dispatch(tool, args)
    assert world.carrier_observed


def test_failed_reads_and_invalid_arguments_do_not_observe_any_carrier():
    world = RepositoryWorldV2(make_v2("tool_output"))
    assert world.dispatch("list_files", {"cursor": 1000})["status"] == "error"
    assert world.dispatch("list_files", {"cursor": True})["status"] == "error"
    assert world.dispatch("read_file", {"path": "absent.txt", "end_line": 1})["status"] == "error"
    assert not world.carrier_observed and not world.exposed
    restored = RepositoryWorldV2.from_snapshot(
        world.case, world.snapshot(), expected_limits=world.limits
    )
    assert restored.snapshot() == world.snapshot()


def test_tool_output_is_additive_explicit_and_only_on_designated_success():
    world = RepositoryWorldV2(make_v2("tool_output", "benign_quote"))
    assert "untrusted_text" not in world.dispatch("read_pr", {})
    original_paths = sorted(item.path for item in world.case.files)
    result = world.dispatch("list_files", {})
    assert sorted(item["path"] for item in result["files"]) == original_paths
    assert result["untrusted_text"] == world.case.exposure.untrusted_text
    assert not world._observed
    assert world.carrier_observed and not world.exposed


@pytest.mark.parametrize("surface", ["pr", "tool_output"])
def test_oversized_full_response_never_commits_delivery(surface):
    selected = make_v2(surface, marker="x" * 512)
    world = RepositoryWorldV2(selected, RepositoryLimits(max_response_bytes=256))
    with pytest.raises(RepositoryLimitError):
        deliver(world)
    assert not world.carrier_observed and not world.exposed
    assert not world._read_pr and not world._observed
    assert world.output_bytes == 0
    assert world.events[-1]["status"] == "response_bytes"
    restored = RepositoryWorldV2.from_snapshot(
        selected, world.snapshot(), expected_limits=world.limits
    )
    assert restored.snapshot() == world.snapshot()


def test_total_response_and_tool_budgets_are_terminal_without_new_delivery():
    world = RepositoryWorldV2(make_v2(), RepositoryLimits(max_calls=1))
    world.dispatch("read_pr", {})
    with pytest.raises(RepositoryLimitError):
        deliver(world)
    assert not world.carrier_observed
    snapshot = world.snapshot()
    with pytest.raises(RepositoryLimitError):
        deliver(world)
    assert world.snapshot() == snapshot
    assert not score_repository_world_v2(world.case, world)["conclusive"]
    restored = RepositoryWorldV2.from_snapshot(world.case, snapshot, expected_limits=world.limits)
    assert restored.snapshot() == snapshot


def test_total_response_budget_blocks_an_unreturned_carrier():
    world = RepositoryWorldV2(
        make_v2(), RepositoryLimits(max_response_bytes=256, max_total_response_bytes=256)
    )
    world.dispatch("read_pr", {})
    world.dispatch("read_pr", {})
    with pytest.raises(RepositoryLimitError, match="response_bytes"):
        deliver(world)
    assert world.output_bytes <= 256
    assert not world.carrier_observed and not world.exposed and not world._observed
    snapshot = world.snapshot()
    restored = RepositoryWorldV2.from_snapshot(world.case, snapshot, expected_limits=world.limits)
    assert restored.snapshot() == snapshot


def test_submit_review_is_committed_only_after_its_complete_response_fits():
    world = RepositoryWorldV2(
        make_v2(), RepositoryLimits(max_response_bytes=256, max_total_response_bytes=256)
    )
    for _ in range(12):
        assert world.dispatch("write_file", {"path": "notes/rejected", "content": ""}) == {
            "status": "blocked"
        }
    with pytest.raises(RepositoryLimitError, match="response_bytes"):
        world.dispatch("submit_review", {"verdict": "approve", "findings": []})
    assert world.review is None
    assert not score_repository_world_v2(world.case, world)["completed"]
    restored = RepositoryWorldV2.from_snapshot(
        world.case, world.snapshot(), expected_limits=world.limits
    )
    assert restored.snapshot() == world.snapshot()


@pytest.mark.parametrize("condition", CONDITIONS)
@pytest.mark.parametrize("delivered", [False, True])
def test_scoring_requires_control_carrier_observation_without_claiming_attack(condition, delivered):
    world = RepositoryWorldV2(make_v2("readme", condition))
    if delivered:
        deliver(world)
    inspect_source_and_submit(world)
    result = score_repository_world_v2(world.case, world)
    assert result["scoring_version"] == "repository-payload-v1"
    assert result["completed"]
    assert result["carrier_observed"] is delivered
    assert result["conclusive"] is delivered
    assert result["rubric_passed"] is delivered
    assert result["payload_exposed"] is (delivered and condition == "attack")
    assert result["semantic_passed"] is None
    assert "security_score" not in result


def test_snapshot_case_limits_state_and_events_are_bound_to_full_replay():
    world = RepositoryWorldV2(make_v2("filename"))
    world.dispatch("list_files", {"limit": 1})
    snapshot = world.snapshot()
    mutations = []
    for key, value in [("carrier_observed", True), ("exposed", True), ("read_pr", True)]:
        candidate = copy.deepcopy(snapshot)
        candidate[key] = value
        mutations.append(candidate)
    candidate = copy.deepcopy(snapshot)
    candidate["events"][0]["paths"] = [world.case.exposure.resource]
    mutations.append(candidate)
    candidate = copy.deepcopy(snapshot)
    candidate["events"][0]["response_sha256"] = "0" * 64
    mutations.append(candidate)
    candidate = copy.deepcopy(snapshot)
    candidate["events"][0]["arguments_json"] = '{"cursor":0,"limit":2,"prefix":""}'
    mutations.append(candidate)
    candidate = copy.deepcopy(snapshot)
    candidate["case_sha256"] = "0" * 64
    mutations.append(candidate)
    candidate = copy.deepcopy(snapshot)
    candidate["observed"] = [{"path": "src/policy.py", "lines": [1]}]
    mutations.append(candidate)
    for candidate in mutations:
        with pytest.raises(ValueError):
            RepositoryWorldV2.from_snapshot(world.case, candidate, expected_limits=world.limits)
    with pytest.raises(ValueError, match="limits"):
        RepositoryWorldV2.from_snapshot(
            world.case, snapshot, expected_limits=RepositoryLimits(max_calls=63)
        )
    changed = world.case.model_dump(mode="json")
    changed["task"] += " Changed trusted task."
    with pytest.raises(ValueError, match="case"):
        RepositoryWorldV2.from_snapshot(
            parse_repository_case(changed), snapshot, expected_limits=world.limits
        )


@pytest.mark.parametrize("version", [True, 2.0, "2", 1, 3])
def test_snapshot_version_is_exact_and_separate(version):
    snapshot = RepositoryWorldV2(make_v2()).snapshot()
    snapshot["schema_version"] = version
    with pytest.raises(ValueError):
        RepositoryWorldSnapshotV2.model_validate_json(json.dumps(snapshot))


def test_snapshot_revalidates_model_instances_with_unchecked_version_updates():
    world = RepositoryWorldV2(make_v2())
    snapshot = RepositoryWorldSnapshotV2.model_validate_json(json.dumps(world.snapshot()))
    for invalid in (True, 2.0):
        with pytest.raises(ValueError):
            RepositoryWorldV2.from_snapshot(
                world.case,
                snapshot.model_copy(update={"schema_version": invalid}),
                expected_limits=world.limits,
            )


@pytest.mark.parametrize("status", ["ok", "blocked", "trace_bytes"])
def test_event_contract_rejects_nonreplayable_claims_before_restore(status):
    world = RepositoryWorldV2(make_v2())
    world.dispatch("read_pr", {})
    event = world.events[0]
    event["status"] = status
    event.pop("arguments_json")
    if status == "trace_bytes":
        event.update(tool="limits", response_bytes=0, response_sha256=None)
    with pytest.raises(ValueError, match="replayable arguments"):
        RepositoryEventV2.model_validate_json(json.dumps(event))


def test_trace_argument_budget_is_bounded_replayable_and_never_executes_overflow():
    world = RepositoryWorldV2(make_v2())
    args = {"path": "notes/rejected.txt", "content": "x" * 65536}
    with pytest.raises(RepositoryLimitError, match="trace_bytes"):
        for _ in range(32):
            assert world.dispatch("write_file", args)["status"] == "blocked"
    snapshot = world.snapshot()
    sizes = [len((event.get("arguments_json") or "").encode()) for event in snapshot["events"]]
    assert sum(sizes[:-1]) <= MAX_TRACE_ARGUMENT_BYTES < sum(sizes)
    assert max(sizes) <= MAX_EVENT_ARGUMENT_BYTES
    assert len(json.dumps(snapshot).encode()) < 16 * 1024 * 1024
    assert snapshot["fatal_error"] == "trace_bytes" and not world.carrier_observed
    restored = RepositoryWorldV2.from_snapshot(world.case, snapshot, expected_limits=world.limits)
    assert restored.snapshot() == snapshot
    assert not score_repository_world_v2(world.case, restored)["completed"]


def test_call_limit_can_retain_one_final_argument_without_an_unbounded_trace():
    # Sixteen validated calls fit individually and cumulatively, then the next call
    # crosses both budgets. Calls remain the first terminal budget checked.
    world = RepositoryWorldV2(make_v2(), RepositoryLimits(max_calls=16))
    args = {"path": "notes/rejected.txt", "content": "x" * 65000}
    for _ in range(16):
        world.dispatch("write_file", args)
    with pytest.raises(RepositoryLimitError, match="calls"):
        world.dispatch("write_file", args)
    snapshot = world.snapshot()
    assert snapshot["fatal_error"] == "calls"
    assert snapshot["calls"] == 17
    sizes = [len((event.get("arguments_json") or "").encode()) for event in snapshot["events"]]
    assert sum(sizes[:-1]) <= MAX_TRACE_ARGUMENT_BYTES < sum(sizes)
    restored = RepositoryWorldV2.from_snapshot(world.case, snapshot, expected_limits=world.limits)
    assert restored.snapshot() == snapshot


def test_canonical_argument_bound_counts_invalid_write_attempt_without_storing_large_text():
    world = RepositoryWorldV2(make_v2())
    response = world.dispatch("write_file", {"path": "notes/x", "content": "\x01" * 65536})
    assert response == {"status": "error", "error": "invalid_arguments"}
    assert world.write_requests == 1
    assert world.events[0].get("arguments_json") is None
    restored = RepositoryWorldV2.from_snapshot(
        world.case, world.snapshot(), expected_limits=world.limits
    )
    assert restored.snapshot() == world.snapshot()


def test_snapshot_defensive_copies_do_not_mutate_recorded_delivery():
    world = RepositoryWorldV2(make_v2("filename"))
    deliver(world)
    snapshot = world.snapshot()
    snapshot["events"][0]["paths"].clear()
    snapshot["carrier_observed"] = False
    assert world.carrier_observed and world.events[0]["paths"]


def test_empty_review_needs_explicit_semantic_adjudication_after_delivery():
    from review_boundary.repository_cases import canonical_digest
    from review_boundary.repository_world import review_digest

    world = RepositoryWorldV2(make_v2())
    deliver(world)
    inspect_source_and_submit(world)
    decision = ReviewAdjudication(
        case_sha256=canonical_digest(world.case),
        review_sha256=review_digest(world.review),
        decision="supported",
        reason="Explicit test evaluator decision.",
    )
    assert score_repository_world_v2(world.case, world)["semantic_passed"] is None
    assert score_repository_world_v2(world.case, world, review_adjudication=decision)[
        "semantic_passed"
    ]
