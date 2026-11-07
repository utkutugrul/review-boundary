"""Saved-file analysis has bounded explicit IO and no execution authority."""

import json
import os
import subprocess
import urllib.request

import pytest
from report_contract_support import native_fixture

from review_boundary import cli, corpus_registry
from review_boundary import source_group_analysis_io as analysis_io
from review_boundary.cli import main
from review_boundary.provenance import HARNESS_FILES, json_digest, text_digest
from review_boundary.repository_cases import REPOSITORY_CORPUS_VERSION, case_digest

_PRIVATE = "private-input-must-not-appear-in-analysis-errors"


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
    return path


def _plan():
    return {
        "schema_version": 1,
        "artifacts": [{"artifact_id": "recorded", "report": "report.json", "suite": "suite.json"}],
        "selections": [
            {
                "selection_id": "reference",
                "artifact_id": "recorded",
                "reviewer": "fixture/reference",
                "repetition_id": "run-one",
            }
        ],
    }


def _inputs(tmp_path):
    report, case, world = native_fixture("repository")
    report["rows"][0]["instructions_key"] = "input-0"
    report["metadata"].update(
        run_id="original-analysis-cli-fixture",
        corpus_version=REPOSITORY_CORPUS_VERSION,
        suite_sha256=json_digest([case_digest(case)]),
        bounds={"max_turns": 8, "max_input_bytes": 24000, "max_output_tokens": 8192, "retries": 0},
        provenance={
            "schema_version": 1,
            "hash_algorithm": "sha256",
            "prompts": {
                "input-0": text_digest(
                    json.dumps(world.reviewer_request(), ensure_ascii=False, sort_keys=True)
                )
            },
            "tools": {"protocol": "fixture-native", "sha256": json_digest([])},
            "harness": {
                "status": "recorded",
                "files": {"fixture.py": "a" * 64},
                "sha256": json_digest({"fixture.py": "a" * 64}),
            },
            "reviewer_source": {"status": "not_recorded", "sha256": None, "files": {}},
        },
    )
    _write(tmp_path / "report.json", report)
    _write(tmp_path / "suite.json", {"schema_version": 1, "cases": [case.model_dump(mode="json")]})
    return _write(tmp_path / "plan.json", _plan())


def _run(plan, output):
    return main(["analyze-groups", "--plan", str(plan), "--output", str(output)])


def test_real_cli_derivative_is_separate_and_cannot_establish_publication(tmp_path, capsys):
    plan = _inputs(tmp_path)
    before = {path: path.read_bytes() for path in tmp_path.iterdir()}
    output = tmp_path / "new" / "analysis.json"
    assert _run(plan, output) == 0
    result = json.loads(output.read_bytes())
    assert result["analysis_schema_version"] == 1
    assert result["analysis_kind"] == "source_group_statistics"
    assert result["policy_version"] == "equal-source-case-run-v1"
    assert result["coverage"]["expected_slots"] == result["coverage"]["present_slots"] == 1
    assert result["coverage"]["missing_slots"] == 0
    assert result["publication"]["status"] == "not_established"
    assert result["publication"]["ranking_eligible"] is False
    assert len(result["publication"]["unmet_gates"]) == 5
    assert output.stat().st_mode & 0o777 == 0o600
    assert output.read_bytes().endswith(b"\n")
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert capsys.readouterr().out == "Source-group analysis written.\n"


def test_analysis_does_not_reach_provider_network_or_process_entries(tmp_path, monkeypatch):
    plan = _inputs(tmp_path)

    def refuse(*args, **kwargs):
        pytest.fail("Saved analysis attempted execution, credential or network access")

    for target, name in (
        (cli, "prepare_provider"),
        (cli, "load_dotenv"),
        (cli, "eval"),
        (subprocess, "run"),
        (urllib.request, "urlopen"),
        (corpus_registry, "get_corpus"),
    ):
        monkeypatch.setattr(target, name, refuse)
    assert _run(plan, tmp_path / "analysis.json") == 0
    assert corpus_registry.corpus_names() == ("pyjwt",)


def test_cli_requires_explicit_plan_and_new_output():
    with pytest.raises(SystemExit, match="2"):
        main(["analyze-groups", "--plan", "unused.json"])
    with pytest.raises(SystemExit, match="2"):
        main(["analyze-groups", "--output", "unused.json"])


@pytest.mark.parametrize(
    "field", ("module", "command", "provider", "environment", "admitted", "publication")
)
def test_plan_authority_fields_fail_without_echo_or_output(tmp_path, capsys, field):
    plan = _inputs(tmp_path)
    document = _plan()
    document[field] = _PRIVATE
    _write(plan, document)
    output = tmp_path / "not-created" / "analysis.json"
    assert _run(plan, output) == 2
    messages = capsys.readouterr()
    assert _PRIVATE not in messages.out + messages.err
    assert len(messages.err) < 256
    assert not output.parent.exists()


@pytest.mark.parametrize(
    "raw",
    (
        '{"schema_version":1,"schema_version":1}',
        '{"seed":NaN}',
        '{"seed":1e999}',
        "[1,2]",
        '{"' + _PRIVATE + '":',
        "[" * 100 + "0" + "]" * 100,
    ),
)
def test_ambiguous_or_invalid_json_is_refused_before_output(tmp_path, capsys, raw):
    plan = tmp_path / "plan.json"
    plan.write_text(raw, encoding="utf-8")
    output = tmp_path / "not-created" / "analysis.json"
    assert _run(plan, output) == 2
    messages = capsys.readouterr()
    assert messages.out == ""
    assert _PRIVATE not in messages.err
    assert not output.parent.exists()


@pytest.mark.parametrize(
    "reference",
    (
        "../report.json",
        "/report.json",
        "nested/../report.json",
        "./report.json",
        "nested//report.json",
        "https://example.org/report.json",
        "nested\\report.json",
        "bad\nreport.json",
        "x" * 129 + "/report.json",
        "é" * 65 + "/report.json",
    ),
)
def test_declared_paths_cannot_escape_or_select_remote_data(tmp_path, monkeypatch, reference):
    plan = _inputs(tmp_path)
    document = _plan()
    document["artifacts"][0]["report"] = reference
    _write(plan, document)

    def refuse(*args, **kwargs):
        pytest.fail("Invalid evidence path reached analysis")

    monkeypatch.setattr(analysis_io, "analyze_source_groups", refuse)
    assert _run(plan, tmp_path / "analysis.json") == 2
    assert not (tmp_path / "analysis.json").exists()


@pytest.mark.parametrize("target", ("plan", "file", "directory"))
def test_plan_and_evidence_symlinks_are_not_followed(tmp_path, target):
    plan = _inputs(tmp_path)
    original = (tmp_path / "report.json").read_bytes()
    if target == "plan":
        selected = tmp_path / "linked-plan.json"
        selected.symlink_to(plan)
        plan = selected
    elif target == "file":
        source = tmp_path / "report.json"
        source.rename(tmp_path / "original.json")
        source.symlink_to(tmp_path / "original.json")
    else:
        (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
        document = _plan()
        document["artifacts"][0]["report"] = "linked/report.json"
        _write(plan, document)
    assert _run(plan, tmp_path / "analysis.json") == 2
    assert not (tmp_path / "analysis.json").exists()
    assert (
        tmp_path / ("original.json" if target == "file" else "report.json")
    ).read_bytes() == original


@pytest.mark.parametrize("kind", ("directory", "fifo", "missing"))
def test_nonregular_or_missing_evidence_is_refused_without_blocking(tmp_path, kind):
    plan = _inputs(tmp_path)
    source = tmp_path / "report.json"
    source.unlink()
    if kind == "directory":
        source.mkdir()
    elif kind == "fifo":
        os.mkfifo(source)
    assert _run(plan, tmp_path / "analysis.json") == 2
    assert not (tmp_path / "analysis.json").exists()


def test_fixed_analysis_byte_policy_limits():
    assert analysis_io.MAX_REPORT_BYTES == 32 * 1024 * 1024
    assert analysis_io.MAX_ANALYSIS_INPUT_BYTES == 32 * 1024 * 1024
    assert analysis_io.MAX_ANALYSIS_OUTPUT_BYTES == 64 * 1024 * 1024


def test_aggregate_bound_counts_unique_files_including_plan(tmp_path, monkeypatch):
    plan = _inputs(tmp_path)
    total = sum(path.stat().st_size for path in tmp_path.iterdir())
    monkeypatch.setattr(analysis_io, "MAX_ANALYSIS_INPUT_BYTES", total)
    loaded, evidence = analysis_io.load_analysis_inputs(plan)
    assert loaded.artifacts[0].artifact_id == "recorded"
    assert set(evidence.reports) == set(evidence.suites) == {"recorded"}
    monkeypatch.setattr(analysis_io, "MAX_ANALYSIS_INPUT_BYTES", total - 1)
    output = tmp_path / "not-created" / "analysis.json"
    assert _run(plan, output) == 2
    assert not output.parent.exists()


def test_physical_file_bound_is_distinct_from_aggregate(tmp_path, monkeypatch):
    plan = _inputs(tmp_path)
    monkeypatch.setattr(
        analysis_io, "MAX_REPORT_BYTES", (tmp_path / "report.json").stat().st_size - 1
    )
    assert _run(plan, tmp_path / "analysis.json") == 2


def test_output_bound_fails_before_parent_creation(tmp_path, monkeypatch):
    plan = _inputs(tmp_path)
    monkeypatch.setattr(analysis_io, "MAX_ANALYSIS_OUTPUT_BYTES", 1)
    output = tmp_path / "not-created" / "analysis.json"
    assert _run(plan, output) == 2
    assert not output.parent.exists()


def test_existing_output_and_links_are_preserved(tmp_path, capsys):
    plan = _inputs(tmp_path)
    output = tmp_path / "analysis.json"
    assert _run(plan, output) == 0
    original = output.read_bytes()
    input_bytes = plan.read_bytes()
    assert _run(plan, output) == 2
    assert _run(plan, plan) == 2
    leaf = tmp_path / "linked.json"
    leaf.symlink_to(output)
    assert _run(plan, leaf) == 2
    directory = tmp_path / "linked-directory"
    directory.symlink_to(tmp_path, target_is_directory=True)
    assert _run(plan, directory / "other.json") == 2
    assert output.read_bytes() == original
    assert plan.read_bytes() == input_bytes
    assert leaf.is_symlink() and directory.is_symlink()
    assert not (tmp_path / "other.json").exists()
    capsys.readouterr()


def test_loader_builds_exact_inert_export_and_adjudication_maps(tmp_path, monkeypatch):
    document = _plan()
    document["artifacts"][0].update(export_id="registered", shard_ordinal=1)
    document["exports"] = [
        {
            "export_id": "registered",
            "index": "index.json",
            "provenance": "provenance.json",
            "source_manifest": "source.json",
            "evaluator_manifest": "evaluator.json",
            "suites": ["suite.json", "second.json"],
        }
    ]
    document["agreements"] = [
        {
            "agreement_id": "labels",
            "artifact_id": "recorded",
            "rater_a": "labels/a.json",
            "rater_b": "labels/b.json",
        }
    ]
    names = {
        "report.json": {"report": 1},
        "suite.json": {"ordinal": 1},
        "second.json": {"ordinal": 2},
        "index.json": {"index": 1},
        "provenance.json": {"provenance": 1},
        "source.json": {"source": 1},
        "evaluator.json": {"evaluator": 1},
        "labels/a.json": {"rater": "a"},
        "labels/b.json": {"rater": "b"},
    }
    for name, value in names.items():
        _write(tmp_path / name, value)
    plan = _write(tmp_path / "plan.json", document)
    total = sum(path.stat().st_size for path in tmp_path.rglob("*.json"))
    monkeypatch.setattr(analysis_io, "MAX_ANALYSIS_INPUT_BYTES", total)
    loaded, evidence = analysis_io.load_analysis_inputs(plan)
    assert loaded.exports[0].export_id == "registered"
    assert evidence.reports == {"recorded": {"report": 1}}
    assert evidence.suites == {"recorded": {"ordinal": 1}}
    assert evidence.exports == {
        "registered": {
            "index": {"index": 1},
            "provenance": {"provenance": 1},
            "source_manifest": {"source": 1},
            "evaluator_manifest": {"evaluator": 1},
            "suites": ({"ordinal": 1}, {"ordinal": 2}),
        }
    }
    assert evidence.adjudications == {
        "labels/a.json": {"rater": "a"},
        "labels/b.json": {"rater": "b"},
    }
    # Two explicit names for one file do not consume the aggregate budget twice.
    (tmp_path / "alias.json").hardlink_to(tmp_path / "suite.json")
    document["exports"][0]["suites"][0] = "alias.json"
    _write(plan, document)
    files = {
        (info.st_dev, info.st_ino): info.st_size
        for path in tmp_path.rglob("*.json")
        for info in (path.stat(),)
    }
    monkeypatch.setattr(analysis_io, "MAX_ANALYSIS_INPUT_BYTES", sum(files.values()))
    _, evidence = analysis_io.load_analysis_inputs(plan)
    assert evidence.exports["registered"]["suites"] == ({"ordinal": 1}, {"ordinal": 2})


def test_failed_write_preserves_replaced_file_and_created_inode(tmp_path, monkeypatch):
    output = tmp_path / "analysis.json"
    original_fdopen = analysis_io.os.fdopen

    class BrokenWrite:
        def __init__(self, descriptor):
            self.stream = original_fdopen(descriptor, "wb", closefd=False)

        def __enter__(self):
            return self

        def write(self, raw):
            output.rename(tmp_path / "partial.json")
            output.write_bytes(b"replacement")
            raise OSError("simulated write failure")

        def __exit__(self, *args):
            self.stream.close()

    monkeypatch.setattr(
        analysis_io.os, "fdopen", lambda descriptor, *args, **kwargs: BrokenWrite(descriptor)
    )
    with pytest.raises(OSError):
        analysis_io._write_output(output, b"complete output")
    assert output.read_bytes() == b"replacement"
    assert (tmp_path / "partial.json").exists()


def test_failed_write_preserves_replaced_parent(tmp_path, monkeypatch):
    parent = tmp_path / "output"
    output = parent / "analysis.json"
    original_fdopen = analysis_io.os.fdopen

    class BrokenWrite:
        def __init__(self, descriptor):
            self.stream = original_fdopen(descriptor, "wb", closefd=False)

        def __enter__(self):
            return self

        def write(self, raw):
            parent.rename(tmp_path / "moved")
            parent.mkdir()
            output.write_bytes(b"replacement")
            raise OSError("simulated write failure")

        def __exit__(self, *args):
            self.stream.close()

    monkeypatch.setattr(
        analysis_io.os, "fdopen", lambda descriptor, *args, **kwargs: BrokenWrite(descriptor)
    )
    with pytest.raises(OSError):
        analysis_io._write_output(output, b"complete output")
    assert output.read_bytes() == b"replacement"
    assert (tmp_path / "moved" / "analysis.json").exists()


def test_reader_closes_the_descriptor_when_stream_construction_fails(tmp_path, monkeypatch):
    _write(tmp_path / "report.json", {"recorded": True})
    descriptors = []

    def fail(descriptor, *args, **kwargs):
        descriptors.append(descriptor)
        raise OSError("simulated stream construction failure")

    monkeypatch.setattr(analysis_io.os, "fdopen", fail)
    with analysis_io._directory(tmp_path) as root:
        with pytest.raises(OSError):
            analysis_io._Reader().read(root, ("report.json",))
        assert len(descriptors) == 1
        with pytest.raises(OSError):
            os.fstat(descriptors[0])


def test_harness_inventory_includes_each_runtime_module_once():
    assert HARNESS_FILES.count("source_group_analysis.py") == 1
    assert HARNESS_FILES.count("source_group_analysis_io.py") == 1
