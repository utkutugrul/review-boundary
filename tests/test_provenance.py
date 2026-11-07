"""Fingerprint actual declared inputs without claiming reviewer equivalence."""

import json
import os
from copy import deepcopy

import pytest

from review_boundary import provenance
from review_boundary.adapter import AdapterConfig
from review_boundary.provenance import (
    compare_provenance,
    experiment_provenance,
    json_digest,
    source_fingerprint,
    source_path,
    text_digest,
    validate_provenance,
)
from review_boundary.task import native_tool_schemas, review_boundary, review_instructions


def recorded_inputs():
    value = experiment_provenance(
        {"baseline": "Original review instructions"},
        [{"name": "read_file", "parameters": {"type": "object"}}],
        protocol="inspect",
        harness_files=(),
    )
    for field, path in (("harness", "runner.py"), ("reviewer_source", "reviewer.py")):
        files = {path: text_digest(path)}
        value[field] = {"status": "recorded", "sha256": json_digest(files), "files": files}
    return value


def test_source_edit_changes_fingerprint_with_identical_adapter_command(tmp_path):
    reviewer = tmp_path / "reviewer.py"
    reviewer.write_text("print('first implementation')\n")
    config_file = tmp_path / "adapter.json"
    config_file.write_text(
        json.dumps(
            {
                "name": "reviewer",
                "command": ["{python}", "{config_dir}/reviewer.py"],
                "source_files": ["reviewer.py"],
            }
        )
    )
    config = AdapterConfig.from_file(config_file)
    before = config.source_fingerprint()
    command = config.argv()
    metadata = config.to_metadata()
    reviewer.write_text("print('second implementation')\n")
    after = config.source_fingerprint()
    assert config.argv() == command and config.to_metadata() == metadata
    assert before["sha256"] != after["sha256"]
    assert before["files"]["reviewer.py"] != after["files"]["reviewer.py"]
    serialized = json.dumps(after)
    assert str(tmp_path) not in serialized and "second implementation" not in serialized


def test_only_declared_sources_are_hashed_and_order_is_canonical(tmp_path):
    for name in ("a.py", "b.py", "unlisted.py"):
        (tmp_path / name).write_text(name)
    before = source_fingerprint(tmp_path, ["b.py", "a.py"])
    assert before == source_fingerprint(tmp_path, ["a.py", "b.py"])
    (tmp_path / "unlisted.py").write_text("outside declared scope")
    assert source_fingerprint(tmp_path, ["a.py", "b.py"]) == before
    assert source_fingerprint(tmp_path, []) == {
        "status": "not_recorded",
        "sha256": None,
        "files": {},
    }


@pytest.mark.parametrize(
    "path",
    [
        "",
        ".",
        "../a.py",
        "/a.py",
        "a/../b.py",
        "./a.py",
        "a//b.py",
        "a\\b.py",
        "a:b",
        "a\nb",
        "a" * 513,
        1,
    ],
)
def test_source_paths_must_name_normalized_relative_files(path):
    with pytest.raises(ValueError):
        source_path(path)


@pytest.mark.parametrize("kind", ["file", "directory"])
def test_source_aliases_cannot_escape_declaration(tmp_path, kind):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "reviewer.py").write_text("original")
    alias = tmp_path / "alias"
    alias.symlink_to(actual if kind == "directory" else actual / "reviewer.py")
    with pytest.raises(ValueError, match="symlink"):
        source_fingerprint(tmp_path, ["alias/reviewer.py" if kind == "directory" else "alias"])


def test_source_limits_reject_duplicates_count_size_and_aggregate(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_bytes(b"a" * 8)
    (tmp_path / "b.py").write_bytes(b"b" * 8)
    with pytest.raises(ValueError, match="distinct"):
        source_fingerprint(tmp_path, ["a.py", "a.py"])
    with pytest.raises(ValueError, match="32"):
        source_fingerprint(tmp_path, [f"{index}.py" for index in range(33)])
    monkeypatch.setattr(provenance, "MAX_SOURCE_BYTES", 7)
    with pytest.raises(ValueError, match="regular files"):
        source_fingerprint(tmp_path, ["a.py"])
    monkeypatch.setattr(provenance, "MAX_SOURCE_BYTES", 8)
    monkeypatch.setattr(provenance, "MAX_TOTAL_SOURCE_BYTES", 12)
    with pytest.raises(ValueError, match="aggregate"):
        source_fingerprint(tmp_path, ["a.py", "b.py"])


def test_nonregular_sources_are_refused_before_open(tmp_path):
    (tmp_path / "directory").mkdir()
    os.mkfifo(tmp_path / "pipe")
    for path in ("directory", "pipe"):
        with pytest.raises(ValueError, match="regular files"):
            source_fingerprint(tmp_path, [path])


@pytest.mark.parametrize("field", ["harness", "reviewer_source"])
@pytest.mark.parametrize(
    "problem",
    [
        "wrong_digest",
        "bad_path",
        "empty_recorded",
        "unknown_with_hash",
        "unknown_with_files",
        "bad_file_hash",
        "bad_path_type",
    ],
)
def test_malformed_source_manifests_are_rejected(field, problem):
    value = recorded_inputs()
    source = value[field]
    if problem == "wrong_digest":
        source["sha256"] = "0" * 64
    elif problem == "bad_path":
        source["files"] = {"../outside.py": "a" * 64}
        source["sha256"] = json_digest(source["files"])
    elif problem == "empty_recorded":
        source["files"] = {}
        source["sha256"] = json_digest({})
    elif problem == "unknown_with_hash":
        source.update(status="not_recorded", files={})
    elif problem == "unknown_with_files":
        source.update(status="not_recorded", sha256=None)
    elif problem == "bad_file_hash":
        source["files"] = {"a.py": "not a hash"}
    else:
        source["files"] = {1: "a" * 64}
    with pytest.raises(ValueError):
        validate_provenance(value)


@pytest.mark.parametrize("value", [True, "1", 0, 2])
def test_provenance_schema_version_requires_exact_supported_integer(value):
    recorded = recorded_inputs()
    recorded["schema_version"] = value
    with pytest.raises(ValueError, match="provenance"):
        validate_provenance(recorded)


def test_legacy_missing_fingerprints_are_unknown_not_unchanged():
    result = compare_provenance({}, {}, "baseline", "baseline")
    assert result["status"] == "unknown" and result["gating"] is False
    assert len(result["unknown_fields"]) == 5 and not result["unchanged_fields"]
    one_sided = compare_provenance({"provenance": recorded_inputs()}, {}, "baseline", "baseline")
    assert one_sided["unknown_fields"] == result["unknown_fields"]


def test_missing_selected_prompt_is_unknown_without_inventing_a_hash():
    value = recorded_inputs()
    before = deepcopy(value)
    result = compare_provenance({"provenance": value}, {"provenance": value}, "unknown", "baseline")
    assert result["unknown_fields"] == ["instructions"]
    assert result["status"] == "unknown" and value == before


def test_native_task_records_actual_selected_instructions_and_tool_schemas():
    task = review_boundary(defense="explicit")
    value = task.metadata["provenance"]
    validate_provenance(value)
    assert value["prompts"] == {"explicit": text_digest(review_instructions("explicit"))}
    assert value["tools"] == {"protocol": "inspect", "sha256": json_digest(native_tool_schemas())}
    assert value["harness"]["status"] == "recorded"
    assert value["reviewer_source"]["status"] == "not_recorded"
    assert {
        "native_compare.py",
        "report_validation.py",
        "report_contract.py",
        "evidence_refs.py",
        "report_export.py",
        "dashboard.py",
        "repository_adjudication.py",
        "repository_adjudication_agreement.py",
        "repository_adjudication_ui.py",
    }.issubset(value["harness"]["files"])
    assert len(value["harness"]["files"]) == len(set(provenance.HARNESS_FILES))
    assert len(value["harness"]["files"]) <= provenance.MAX_HARNESS_FILES == 128


def test_expanded_harness_inventory_does_not_expand_reviewer_source_limit():
    value = recorded_inputs()
    files = {f"module_{index}.py": text_digest(str(index)) for index in range(33)}
    record = {"status": "recorded", "sha256": json_digest(files), "files": files}
    value["harness"] = record
    validate_provenance(value)
    value["reviewer_source"] = record
    with pytest.raises(ValueError, match="source status"):
        validate_provenance(value)
    files = {f"module_{index}.py": text_digest(str(index)) for index in range(129)}
    value["harness"] = {"status": "recorded", "sha256": json_digest(files), "files": files}
    with pytest.raises(ValueError, match="source status"):
        validate_provenance(value)
