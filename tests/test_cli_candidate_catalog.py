"""Candidate CLI accepts bounded inert research metadata and emits no admission claim."""

import importlib
import json
import subprocess
import urllib.request

import pytest

from review_boundary import corpus_candidates, corpus_registry
from review_boundary.cli import main

_PRIVATE = "private-input-must-never-appear-in-errors"


def catalog_document():
    return {
        "schema_version": 1,
        "records": [
            {
                "candidate_id": "original-research",
                "upstream_url": "https://example.org/original-research",
                "advisory_url": None,
                "aliases": [],
                "language": "Python",
                "proposed_source_group": "proposed_original_group",
                "comparison_revision": None,
                "selected_change_revision": None,
                "metadata_status": "unknown",
                "runtime_status": "unknown",
                "license_status": "unknown",
                "disposition": "research",
                "evidence_urls": [],
                "note": "Original metadata example, no source or behavior claim.",
            }
        ],
    }


def write_catalog(tmp_path, document=None):
    path = tmp_path / "catalog.json"
    path.write_text(json.dumps(catalog_document() if document is None else document))
    return path


def test_catalog_stdout_summary_is_inert_and_does_not_change_registry(
    tmp_path, monkeypatch, capsys
):
    path = write_catalog(tmp_path)
    before = corpus_registry.corpus_names()

    def refuse(*args, **kwargs):
        pytest.fail("Candidate metadata reached a code, network, or registry selection entry point")

    monkeypatch.setattr(corpus_registry, "get_corpus", refuse)
    monkeypatch.setattr(importlib, "import_module", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    assert main(["candidate-catalog", "--input", str(path)]) == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary == corpus_candidates.candidate_catalog_summary(
        corpus_candidates.load_candidate_catalog(path)
    )
    assert summary["candidate_count"] == 1
    assert summary["admission"] == "not_established"
    assert summary["authenticity"] == "unverified_metadata"
    assert summary["independence"] == "not_inferred"
    assert corpus_registry.corpus_names() == before == ("pyjwt",)
    assert "records" not in summary


def test_catalog_output_is_exclusive_and_preserves_input_and_symlink_targets(tmp_path, capsys):
    source = write_catalog(tmp_path)
    original = source.read_bytes()
    output = tmp_path / "summary.json"
    assert main(["candidate-catalog", "--input", str(source), "--output", str(output)]) == 0
    summary = output.read_bytes()
    assert json.loads(summary)["admission"] == "not_established"
    for selected in (output, source):
        assert main(["candidate-catalog", "--input", str(source), "--output", str(selected)]) == 2
    link = tmp_path / "link.json"
    link.symlink_to(output)
    assert main(["candidate-catalog", "--input", str(source), "--output", str(link)]) == 2
    assert source.read_bytes() == original
    assert output.read_bytes() == summary
    assert link.is_symlink()
    capsys.readouterr()


@pytest.mark.parametrize(
    "field",
    (
        "module",
        "command",
        "oracle",
        "build_cases",
        "registered",
        "admitted",
        "verified",
        "source_path",
        "artifact_loader",
        "environment",
    ),
)
def test_candidate_execution_and_authority_fields_are_rejected_without_echo(
    tmp_path, capsys, field
):
    document = catalog_document()
    document["records"][0][field] = _PRIVATE
    source = write_catalog(tmp_path, document)
    output = tmp_path / "summary.json"
    assert main(["candidate-catalog", "--input", str(source), "--output", str(output)]) == 2
    result = capsys.readouterr()
    assert _PRIVATE not in result.err + result.out
    assert "Candidate catalog refused" in result.err
    assert not output.exists()


@pytest.mark.parametrize(
    "raw",
    (
        '{"schema_version":1,"records":[],"schema_version":1}',
        '{"schema_version":NaN,"records":[]}',
        '{"schema_version":1,"records":"' + _PRIVATE + '"}',
        '{"' + _PRIVATE + '":',
        "[" * 100 + '"' + _PRIVATE + '"' + "]" * 100,
    ),
)
def test_invalid_catalog_diagnostics_never_echo_input(tmp_path, capsys, raw):
    source = tmp_path / "catalog.json"
    source.write_text(raw)
    assert main(["candidate-catalog", "--input", str(source)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert _PRIVATE not in output.err
    assert len(output.err) < 256


def test_bounded_loader_errors_have_no_output_or_input_echo(tmp_path, capsys):
    source = tmp_path / "catalog.json"
    source.write_text(_PRIVATE * (256 * 1024 // len(_PRIVATE) + 1))
    assert main(["candidate-catalog", "--input", str(source)]) == 2
    source.unlink()
    source.symlink_to(tmp_path / _PRIVATE)
    assert main(["candidate-catalog", "--input", str(source)]) == 2
    result = capsys.readouterr()
    assert _PRIVATE not in result.err + result.out


@pytest.mark.parametrize(
    "field,value",
    (
        ("metadata_status", "verified"),
        ("runtime_status", "admitted"),
        ("license_status", "approved"),
        ("disposition", "registered"),
    ),
)
def test_catalog_statuses_cannot_grant_execution_or_admission(tmp_path, capsys, field, value):
    document = catalog_document()
    document["records"][0][field] = value
    source = write_catalog(tmp_path, document)
    assert main(["candidate-catalog", "--input", str(source)]) == 2
    assert capsys.readouterr().out == ""
