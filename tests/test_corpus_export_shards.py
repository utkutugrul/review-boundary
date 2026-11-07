"""Opt-in shard exports preserve original synthetic group and complete-set identity."""

import json
import os
from dataclasses import replace

import pytest
from test_corpus_export_versions import (
    frozen_export,  # noqa: F401
    inject,
    synthetic_cases,
    synthetic_registration,
)

from review_boundary import repository_adjudication, suite_validation, upstream_runner
from review_boundary.cli import main, parser
from review_boundary.provenance import json_digest, validate_provenance
from review_boundary.repository_cases import case_digest
from review_boundary.repository_runner import load_suite
from review_boundary.upstream_runner import CorpusExportIndex


def export_command(output):
    return ["corpus-export", "--corpus", "pyjwt", "--shard", "--output", str(output)]


@pytest.mark.parametrize("version", (1, 2))
@pytest.mark.parametrize(
    "sizes,counts", (((32,), [32]), ((16, 17), [16, 17]), ((12, 12, 12), [24, 12]))
)
def test_export_has_ordinary_bounded_suites_complete_identity_and_unchanged_root_manifests(
    tmp_path, monkeypatch, version, sizes, counts
):
    calls = {}
    cases = synthetic_cases(sizes, version=version)
    registration = synthetic_registration(cases, version=version, calls=calls)
    inject(monkeypatch, registration)
    output = tmp_path / "shards"
    assert main(export_command(output)) == 0
    index = json.loads((output / "index.json").read_text())
    assert CorpusExportIndex.model_validate_json(json.dumps(index)).model_dump(mode="json") == index
    flattened, groups_by_shard = [], []
    for ordinal, shard in enumerate(index["shards"], 1):
        assert shard["ordinal"] == ordinal
        assert shard["suite_path"] == f"shards/{ordinal:04d}/suite.json"
        path = output / shard["suite_path"]
        document = json.loads(path.read_text())
        loaded = load_suite(path)
        assert document["schema_version"] == version
        assert len(loaded) == shard["case_count"] <= 32
        assert shard["suite_sha256"] == json_digest(document)
        assert shard["source_groups"] == sorted({case.source_group for case in loaded})
        groups_by_shard.extend(shard["source_groups"])
        flattened.extend((case.case_id, case_digest(case)) for case in loaded)
    assert [shard["case_count"] for shard in index["shards"]] == counts
    expected = sorted((case.case_id, case_digest(case)) for case in cases)
    assert sorted(flattened) == expected
    assert index["case_set"] == [
        {"case_id": name, "case_sha256": digest} for name, digest in expected
    ]
    assert index["case_set_sha256"] == json_digest(expected)
    assert index["case_count"] == len(cases)
    assert index["source_groups"] == sorted(set(groups_by_shard))
    assert (
        len(groups_by_shard)
        == len(set(groups_by_shard))
        == index["source_issue_count"]
        == len(sizes)
    )
    assert index["shard_count"] == len(counts)
    assert index["corpus"] == registration.name
    assert index["corpus_version"] == registration.corpus_version
    assert index["suite_schema_version"] == version
    assert index["behavior_verification"] == "not_run"
    assert (
        json.loads((output / "source_manifest.json").read_text()) == registration.source_manifest()
    )
    assert (
        json.loads((output / "evaluator_manifest.json").read_text())
        == registration.evaluator_manifest()
    )
    metadata = json.loads((output / "provenance.json").read_text())
    validate_provenance(metadata["provenance"])
    assert metadata["schema_version"] == 2
    assert metadata["index_sha256"] == json_digest(index)
    assert metadata["case_count"] == len(cases)
    assert metadata["source_issue_count"] == len(sizes)
    assert metadata["suite_schema_version"] == version
    assert metadata["protocol"] == index["protocol"]
    assert metadata["behavior_verification"] == "not_run"
    assert calls.get("verify", 0) == 0
    assert not (output / "suite.json").exists()
    assert not (output / "verification.json").exists()


@pytest.mark.usefixtures("frozen_export")
def test_permuted_input_has_identical_files_with_frozen_run_fingerprints(tmp_path, monkeypatch):
    cases = synthetic_cases((12, 12, 12))
    paths = []
    for name, order in (("forward", cases), ("reversed", tuple(reversed(cases)))):
        inject(monkeypatch, synthetic_registration(order))
        path = tmp_path / name
        assert main(export_command(path)) == 0
        paths.append(path)
    documents = [
        {
            str(file.relative_to(path)): file.read_bytes()
            for file in path.rglob("*")
            if file.is_file()
        }
        for path in paths
    ]
    assert documents[0] == documents[1]


def test_a_shard_does_not_satisfy_the_validator_full_registered_set_binding(tmp_path, monkeypatch):
    registration = synthetic_registration(synthetic_cases((16, 17)))
    inject(monkeypatch, registration)
    monkeypatch.setattr(suite_validation, "get_corpus", lambda name: registration)
    output = tmp_path / "export"
    assert main(export_command(output)) == 0
    result = suite_validation.validate_suite(output / "shards/0001/suite.json", corpus_name="pyjwt")
    assert result["corpus"]["bound_to_registry"] is False
    assert result["layers"]["provenance_license"]["status"] == "failed"
    assert any("missing" in text for text in result["layers"]["provenance_license"]["messages"])


@pytest.mark.parametrize("version", (1, 2))
def test_shard_verify_rejects_before_any_builder_manifest_or_oracle(tmp_path, monkeypatch, version):
    calls = {}
    inject(monkeypatch, synthetic_registration(version=version, calls=calls))
    output = tmp_path / "rejected"
    assert main(export_command(output) + ["--verify"]) == 2
    assert calls == {}
    assert not output.exists()


def test_whole_33_case_source_group_is_refused_without_any_output(tmp_path, monkeypatch):
    inject(monkeypatch, synthetic_registration(synthetic_cases((33,))))
    output = tmp_path / "large_group"
    assert main(export_command(output)) == 2
    assert not output.exists()


@pytest.mark.usefixtures("frozen_export")
def test_aggregate_cap_includes_all_serialized_metadata_before_directory_creation(
    tmp_path, monkeypatch
):
    registration = synthetic_registration(synthetic_cases((16, 17)))
    registration = replace(
        registration,
        source_manifest=lambda: {"kind": "original_test", "synthetic_note": "x" * 32768},
    )
    inject(monkeypatch, registration)
    first = tmp_path / "measure"
    assert main(export_command(first)) == 0
    exact_size = sum(file.stat().st_size for file in first.rglob("*") if file.is_file())
    monkeypatch.setattr(upstream_runner, "MAX_EXPORT_BYTES", exact_size - 1)
    rejected = tmp_path / "rejected"
    assert main(export_command(rejected)) == 2
    assert not rejected.exists()
    monkeypatch.setattr(upstream_runner, "MAX_EXPORT_BYTES", exact_size)
    accepted = tmp_path / "exact"
    assert main(export_command(accepted)) == 0


@pytest.mark.parametrize("kind", ("file", "empty_directory", "nonempty_directory", "symlink"))
def test_shard_output_is_exclusive_and_preserves_collisions(tmp_path, monkeypatch, kind):
    inject(monkeypatch, synthetic_registration())
    output = tmp_path / "existing"
    target = tmp_path / "target"
    target.mkdir()
    (target / "user.txt").write_text("preserve")
    if kind == "file":
        output.write_text("preserve")
    elif kind in ("empty_directory", "nonempty_directory"):
        output.mkdir()
        if kind == "nonempty_directory":
            (output / "user.txt").write_text("preserve")
    else:
        output.symlink_to(target, target_is_directory=True)
    assert main(export_command(output)) == 2
    assert (target / "user.txt").read_text() == "preserve"
    if kind == "file":
        assert output.read_text() == "preserve"
    elif kind == "nonempty_directory":
        assert (output / "user.txt").read_text() == "preserve"
    elif kind == "empty_directory":
        assert list(output.iterdir()) == []
    else:
        assert output.is_symlink()


def test_partial_failure_removes_only_owned_created_paths(tmp_path, monkeypatch):
    inject(monkeypatch, synthetic_registration())
    original = repository_adjudication._write_new_text_owned
    calls = 0

    def fail_after_one(path, text, label):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("Synthetic write failure")
        return original(path, text, label)

    monkeypatch.setattr(repository_adjudication, "_write_new_text_owned", fail_after_one)
    output = tmp_path / "partial"
    assert main(export_command(output)) == 2
    assert calls == 2
    assert not output.exists()


@pytest.mark.parametrize("replacement_kind", ("regular_file", "symlink"))
def test_cleanup_preserves_a_replaced_file_inode(tmp_path, monkeypatch, replacement_kind):
    inject(monkeypatch, synthetic_registration())
    original = repository_adjudication._write_new_text_owned
    calls = 0

    def replace_then_fail(path, text, label):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("Synthetic write failure")
        owned = original(path, text, label)
        replacement = tmp_path / "user-replacement"
        target = tmp_path / "user-target"
        target.write_text("preserve replacement")
        if replacement_kind == "symlink":
            replacement.symlink_to(target)
        else:
            replacement.write_text("preserve replacement")
        os.replace(replacement, path)
        return owned

    monkeypatch.setattr(repository_adjudication, "_write_new_text_owned", replace_then_fail)
    output = tmp_path / "partial"
    assert main(export_command(output)) == 2
    assert (output / "index.json").read_text() == "preserve replacement"
    assert (output / "index.json").is_symlink() == (replacement_kind == "symlink")
    assert list(output.iterdir()) == [output / "index.json"]


def test_case_and_source_group_labels_are_never_used_as_host_paths(tmp_path, monkeypatch):
    case = synthetic_cases((1,))[0].model_copy(
        update={"case_id": "../../user-owned", "source_group": "../user-group"}
    )
    inject(monkeypatch, synthetic_registration((case,)))
    marker = tmp_path / "user-owned"
    marker.write_text("preserve")
    output = tmp_path / "shards"
    assert main(export_command(output)) == 0
    index = json.loads((output / "index.json").read_text())
    assert index["source_groups"] == ["../user-group"]
    assert index["shards"][0]["suite_path"] == "shards/0001/suite.json"
    assert load_suite(output / "shards/0001/suite.json")[0].case_id == "../../user-owned"
    assert marker.read_text() == "preserve"


@pytest.mark.parametrize(
    "mutation",
    (
        "boolean_version",
        "float_suite_version",
        "extra_authority",
        "missing_identity",
        "wrong_digest",
        "wrong_count",
        "inflated_groups",
        "nonordinal_path",
    ),
)
def test_export_index_is_strict_frozen_and_checks_full_identity(tmp_path, monkeypatch, mutation):
    inject(monkeypatch, synthetic_registration())
    output = tmp_path / "shards"
    assert main(export_command(output)) == 0
    document = json.loads((output / "index.json").read_text())
    index = CorpusExportIndex.model_validate_json(json.dumps(document))
    with pytest.raises(ValueError):
        index.case_count = 99
    if mutation == "boolean_version":
        document["schema_version"] = True
    elif mutation == "float_suite_version":
        document["suite_schema_version"] = 1.0
    elif mutation == "extra_authority":
        document["admitted"] = True
    elif mutation == "missing_identity":
        document["case_set"].pop()
    elif mutation == "wrong_digest":
        document["case_set_sha256"] = "f" * 64
    elif mutation == "wrong_count":
        document["case_count"] += 1
    elif mutation == "inflated_groups":
        document["source_issue_count"] += 1
    else:
        document["shards"][0]["suite_path"] = "../user-data/suite.json"
    with pytest.raises(ValueError):
        CorpusExportIndex.model_validate_json(json.dumps(document))
    # Existing suite-file consumers reject an index rather than silently selecting a shard.
    with pytest.raises(ValueError):
        load_suite(output / "index.json")


@pytest.mark.parametrize("replace_ancestor", (False, True))
def test_cleanup_preserves_replaced_or_symlinked_directories(
    tmp_path, monkeypatch, replace_ancestor
):
    inject(monkeypatch, synthetic_registration())
    original = repository_adjudication._write_new_text_owned
    parent = tmp_path / "parent"
    parent.mkdir()
    output = parent / "export"
    user = tmp_path / "user"
    user.mkdir()
    (user / "user.txt").write_text("preserve user directory")
    moved = tmp_path / "moved"

    def replace_directory(path, text, label):
        owned = original(path, text, label)
        selected = parent if replace_ancestor else output
        selected.rename(moved)
        selected.symlink_to(user, target_is_directory=True)
        return owned

    monkeypatch.setattr(repository_adjudication, "_write_new_text_owned", replace_directory)
    assert main(export_command(output)) == 2
    assert (user / "user.txt").read_text() == "preserve user directory"
    retained = moved / "export/index.json" if replace_ancestor else moved / "index.json"
    assert retained.is_file()
    assert (parent if replace_ancestor else output).is_symlink()


def test_shard_flag_is_opt_in_and_generic_transform_flags_remain_unavailable():
    args = parser().parse_args(["corpus-export", "--corpus", "pyjwt", "--output", "new"])
    assert args.shard is False
    for option, value in (("--pack", "metadata.json"), ("--carrier", "readme")):
        with pytest.raises(SystemExit):
            parser().parse_args(
                ["corpus-export", "--corpus", "pyjwt", "--output", "new", option, value]
            )
