import json

import pytest

from review_boundary.repository_cases import RepositoryCase, build_repository_demo_cases
from review_boundary.repository_cases_v2 import RepositoryCaseV2, parse_repository_case

CARRIERS = ("readme", "pr", "inert_file", "filename", "code_comment", "tool_output")
CONDITIONS = ("clean", "attack", "benign_quote")


def make_v2(
    surface="readme", condition="attack", marker="First carrier line.\nSecond carrier line."
):
    original = next(
        case
        for case in build_repository_demo_cases()
        if case.variant == "fixed" and case.surface == "clean"
    )
    value = original.model_dump(mode="json")
    value.update(
        case_schema_version=2,
        case_id=f"runtime:{surface}:{condition}",
        surface=surface,
        condition=condition,
        payload_ref={
            "pack_id": "runtime",
            "pack_version": 1,
            "pack_digest": "a" * 64,
            "entry_id": "runtime",
            "carrier": surface,
            "condition": condition,
        },
    )
    if surface == "readme":
        path = "README.md"
        next(item for item in value["files"] if item["path"] == path)["content"] = (
            "# Context\n" + marker + "\nLast neutral line.\n"
        )
    elif surface == "pr":
        path = "pull_request"
        value["pr"] = "Change description.\n" + marker
    elif surface == "inert_file":
        path = "notes/context.txt"
        value["files"].append({"path": path, "content": marker + "\n"})
    elif surface == "filename":
        path = "notes/carrier-context.txt"
        marker = path
        value["files"].append({"path": path, "content": "Inert file content.\n"})
    elif surface == "code_comment":
        path = "src/policy.py"
        marker = "\n".join("# " + line for line in marker.splitlines())
        next(item for item in value["files"] if item["path"] == path)["content"] += marker + "\n"
    else:
        path = "tool_output"
    value["exposure"] = {"resource": path, "marker": marker}
    if surface == "tool_output":
        value["exposure"].update(tool="list_files", untrusted_text="Quoted context:\n" + marker)
    return RepositoryCaseV2.model_validate_json(json.dumps(value))


@pytest.mark.parametrize("surface", CARRIERS)
@pytest.mark.parametrize("condition", CONDITIONS)
def test_distinct_case_models_round_trip_every_carrier_and_condition(surface, condition):
    selected = make_v2(surface, condition)
    assert parse_repository_case(selected.model_dump(mode="json")) == selected
    assert selected.payload_ref.carrier == surface
    assert selected.payload_ref.condition == condition
    assert selected.case_schema_version == 2


@pytest.mark.parametrize("version", [None, True, False, 2.0, "2", 1, 3])
def test_case_parser_requires_exact_supported_version(version):
    value = make_v2().model_dump(mode="json")
    value["case_schema_version"] = version
    with pytest.raises(ValueError):
        parse_repository_case(value)
    with pytest.raises(ValueError):
        RepositoryCaseV2.model_validate_json(json.dumps(value))


def test_absent_v2_version_does_not_widen_the_v1_parser():
    value = make_v2().model_dump(mode="json")
    del value["case_schema_version"]
    with pytest.raises(ValueError):
        parse_repository_case(value)
    original = build_repository_demo_cases()[0]
    assert type(parse_repository_case(original.model_dump(mode="json"))) is RepositoryCase
    value = original.model_dump(mode="json")
    value["case_schema_version"] = 1
    with pytest.raises(ValueError):
        parse_repository_case(value)


@pytest.mark.parametrize("field,value", [("carrier", "pr"), ("condition", "clean")])
def test_payload_reference_must_match_case_identity(field, value):
    document = make_v2().model_dump(mode="json")
    document["payload_ref"][field] = value
    with pytest.raises(ValueError, match="reference"):
        parse_repository_case(document)


@pytest.mark.parametrize("surface", CARRIERS)
def test_exposure_rejects_absent_resource_or_marker(surface):
    value = make_v2(surface).model_dump(mode="json")
    value["exposure"]["marker"] = "Absent marker from all public data."
    with pytest.raises(ValueError):
        parse_repository_case(value)


@pytest.mark.parametrize("field,value", [("tool", "read_pr"), ("untrusted_text", "Extra text.")])
def test_tool_output_configuration_does_not_apply_to_other_carriers(field, value):
    document = make_v2().model_dump(mode="json")
    document["exposure"][field] = value
    with pytest.raises(ValueError):
        parse_repository_case(document)


@pytest.mark.parametrize("field", ["tool", "untrusted_text"])
def test_tool_output_requires_designated_tool_and_full_text(field):
    value = make_v2("tool_output").model_dump(mode="json")
    value["exposure"][field] = None
    with pytest.raises(ValueError):
        parse_repository_case(value)


@pytest.mark.parametrize("change", ["source", "task", "file", "rubric", "duplicate", "marker"])
def test_v2_source_rubric_and_text_bounds(change):
    value = make_v2().model_dump(mode="json")
    if change == "source":
        value["source_group"] = "😀" * 65
    elif change == "task":
        value["task"] = "x" * 16385
    elif change == "file":
        value["files"][0]["content"] = "x" * 4097
    elif change == "rubric":
        value["issues"][0]["acceptable_bundles"][0]["ranges"][0]["end_line"] = 1000
    elif change == "duplicate":
        value["files"].append(value["files"][0])
    else:
        value["exposure"]["marker"] = "\t\n"
    with pytest.raises(ValueError):
        parse_repository_case(value)


def test_parser_revalidates_unchecked_model_copies():
    selected = make_v2().model_copy(update={"case_schema_version": True})
    with pytest.raises(ValueError):
        parse_repository_case(selected)
