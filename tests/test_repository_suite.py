"""Shared repository suite parser and derived schema.

Suites are untrusted data. Candidate code strings below are only inspected as text.
"""

import json

import pytest
from pydantic import ValidationError

from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import load_suite
from review_boundary.repository_suite import (
    MAX_REPOSITORY_SUITE_CASES,
    RepositorySuite,
    load_repository_suite,
    parse_repository_suite,
    repository_suite_schema,
)


def suite_data(count=None):
    cases = [case.model_dump(mode="json") for case in build_repository_demo_cases()]
    if count is not None:
        cases = [dict(cases[0], case_id=f"case-{index}") for index in range(count)]
    return {"schema_version": 1, "cases": cases}


def one_case():
    return suite_data(1)


def first_range(data):
    return data["cases"][0]["issues"][0]["acceptable_bundles"][0]["ranges"][0]


@pytest.fixture
def schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = repository_suite_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


# Valid input


def test_demo_suite_round_trips_through_dict_and_file(tmp_path):
    demo = build_repository_demo_cases()
    data = suite_data()
    suite = parse_repository_suite(data)
    assert isinstance(suite.cases, tuple) and suite.cases == demo
    assert suite.model_dump(mode="json") == data
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(data))
    assert load_repository_suite(path) == suite
    loaded = load_suite(path)
    assert type(loaded) is tuple and loaded == demo
    with pytest.raises(ValidationError):
        suite.schema_version = 1


def test_runner_default_still_returns_the_bundled_demo_tuple():
    cases = load_suite(None)
    assert type(cases) is tuple and cases == build_repository_demo_cases()


def test_suite_size_bounds_are_inclusive_one_to_thirty_two():
    assert MAX_REPOSITORY_SUITE_CASES == 32
    assert len(parse_repository_suite(suite_data(1)).cases) == 1
    assert len(parse_repository_suite(suite_data(32)).cases) == 32
    for count in (0, 33):
        with pytest.raises(ValueError):
            parse_repository_suite(suite_data(count))


# Derived schema


def test_schema_is_derived_from_the_model_and_preserves_the_v1_shape():
    schema = repository_suite_schema()
    assert schema == RepositorySuite.model_json_schema()
    json.dumps(schema, allow_nan=False)
    assert set(schema["properties"]) == {"schema_version", "cases"}
    assert set(schema["required"]) == {"schema_version", "cases"}
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["const"] == 1
    cases = schema["properties"]["cases"]
    assert (cases["type"], cases["minItems"], cases["maxItems"]) == ("array", 1, 32)
    assert "RepositoryCase" in schema["$defs"]
    assert schema["$defs"]["RepositoryCase"]["additionalProperties"] is False


def test_schema_accepts_valid_and_rejects_structural_violations(schema_validator):
    assert schema_validator.is_valid(suite_data())
    assert schema_validator.is_valid(suite_data(32))
    assert not schema_validator.is_valid(suite_data(0))
    assert not schema_validator.is_valid(suite_data(33))
    missing = suite_data()
    del missing["schema_version"]
    assert not schema_validator.is_valid(missing)
    assert not schema_validator.is_valid({**suite_data(), "extra": 1})
    assert not schema_validator.is_valid({**suite_data(), "schema_version": 2})
    assert not schema_validator.is_valid({**suite_data(), "schema_version": "1"})


RUNTIME_ONLY = {
    "duplicate_ids": lambda s: s.update(cases=s["cases"] * 2),
    "evidence_beyond_file": lambda s: first_range(s).update(end_line=99),
    "dotdot_path": lambda s: s["cases"][0]["files"].append({"path": "src/../x.py", "content": "x"}),
    "backslash_path": lambda s: s["cases"][0]["files"].append({"path": "a\\b.py", "content": "x"}),
    "exposure_on_clean": lambda s: s["cases"][0].update(
        exposure={"resource": "missing.md", "marker": "m"}
    ),
    "marker_not_in_resource": lambda s: s["cases"][1]["exposure"].update(marker="absent text"),
}


@pytest.mark.parametrize("name", sorted(RUNTIME_ONLY))
def test_schema_valid_input_can_still_fail_runtime_cross_field_validation(name, schema_validator):
    data = suite_data()
    RUNTIME_ONLY[name](data)
    assert schema_validator.is_valid(data)
    with pytest.raises(ValueError):
        parse_repository_suite(data)


# Envelope and discriminator


def test_missing_or_extra_top_level_keys_are_rejected():
    for key in ("schema_version", "cases"):
        data = one_case()
        del data[key]
        with pytest.raises(ValueError):
            parse_repository_suite(data)
    with pytest.raises(ValueError):
        parse_repository_suite({**one_case(), "extra": 1})


@pytest.mark.parametrize("version", [True, False, 1.0, None, 0, 2, "1", [1]])
def test_schema_version_must_be_the_exact_integer_one(version, tmp_path):
    data = one_case()
    data["schema_version"] = version
    with pytest.raises(ValueError):
        parse_repository_suite(data)
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_repository_suite(path)
    with pytest.raises(ValueError):
        load_suite(path)


@pytest.mark.parametrize("version", [True, 1.0, None, "1", 2])
def test_model_rejects_coerced_versions_before_literal_matching(version):
    cases = build_repository_demo_cases()
    assert RepositorySuite(schema_version=1, cases=cases).cases == cases
    with pytest.raises(ValidationError):
        RepositorySuite(schema_version=version, cases=cases)


def test_nested_numbers_keep_strict_runtime_types():
    for bad in (True, 1.0):
        data = one_case()
        first_range(data).update(start_line=bad)
        with pytest.raises(ValueError):
            parse_repository_suite(data)


def test_cases_must_be_a_list_of_objects_and_input_a_dict():
    for cases in ({}, "case", [1], [None]):
        with pytest.raises(ValueError):
            parse_repository_suite({"schema_version": 1, "cases": cases})
    with pytest.raises(ValueError):
        parse_repository_suite([])
    with pytest.raises(ValueError):
        parse_repository_suite({"schema_version": 1, "cases": {1}})


def test_duplicate_case_ids_are_rejected():
    data = one_case()
    data["cases"].append(dict(data["cases"][0]))
    with pytest.raises(ValueError, match="unique"):
        parse_repository_suite(data)


@pytest.mark.parametrize("name", ["evidence", "path", "exposure"])
def test_invalid_case_content_is_rejected(name):
    data = one_case()
    if name == "evidence":
        first_range(data).update(end_line=99)
    elif name == "path":
        data["cases"][0]["files"][0]["path"] = "/absolute.py"
    else:
        data["cases"][0]["surface"] = "readme"
        data["cases"][0]["exposure"] = {"resource": "missing.md", "marker": "m"}
    with pytest.raises(ValueError):
        parse_repository_suite(data)


# Safe JSON source


def test_duplicate_keys_in_source_json_are_rejected(tmp_path):
    path = tmp_path / "suite.json"
    path.write_text(
        json.dumps(one_case()).replace(
            '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
        )
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_repository_suite(path)
    with pytest.raises(ValueError, match="duplicate"):
        load_suite(path)


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_nonfinite_numbers_in_source_json_are_rejected(literal, tmp_path):
    path = tmp_path / "suite.json"
    raw = json.dumps(one_case()).replace('"start_line": 4', f'"start_line": {literal}', 1)
    assert literal in raw
    path.write_text(raw)
    with pytest.raises(ValueError, match="finite"):
        load_repository_suite(path)


def test_nonfinite_numbers_in_decoded_dicts_are_rejected():
    for bad in (float("nan"), float("inf"), float("-inf")):
        data = one_case()
        first_range(data).update(start_line=bad)
        with pytest.raises(ValueError, match="finite"):
            parse_repository_suite(data)


def test_non_object_or_non_regular_sources_are_rejected(tmp_path):
    path = tmp_path / "suite.json"
    path.write_text("[]")
    with pytest.raises(ValueError, match="object"):
        load_repository_suite(path)
    with pytest.raises(ValueError):
        load_repository_suite(tmp_path)


# Candidate content is data


def test_candidate_code_in_suite_content_is_never_executed(tmp_path):
    marker = tmp_path / "executed.txt"
    code = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\nraise SystemExit(7)\n"
    data = one_case()
    data["cases"][0]["files"] += [
        {"path": "hook.py", "content": code},
        {"path": "conftest.py", "content": code},
        {"path": "setup.py", "content": code},
    ]
    data["cases"][0]["pr"] = code
    path = tmp_path / "suite.json"
    path.write_text(json.dumps(data))
    suite = load_repository_suite(path)
    assert load_suite(path) == suite.cases
    assert repository_suite_schema()
    contents = {item.path: item.content for item in suite.cases[0].files}
    assert contents["hook.py"] == code and suite.cases[0].pr == code
    assert not marker.exists()
