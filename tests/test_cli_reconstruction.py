"""Exercise checked and explicitly unchecked reconstruction through saved Inspect logs."""

import json
from hashlib import sha256

import pytest
from inspect_ai.log import EvalError, read_eval_log, write_eval_log

from review_boundary.cli import main


@pytest.fixture(scope="module")
def original_run(tmp_path_factory):
    directory = tmp_path_factory.mktemp("recorded-calibration") / "run"
    assert (
        main(
            [
                "demo",
                "--mode",
                "reference",
                "--family",
                "tenant_lookup",
                "--surface",
                "clean",
                "--output",
                str(directory),
            ]
        )
        == 0
    )
    return directory


@pytest.fixture
def recorded_files(original_run, tmp_path):
    original = next((original_run / "logs").glob("*.eval"))
    log_path = tmp_path / "input.eval"
    log_path.write_bytes(original.read_bytes())
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes((original_run / "manifest.json").read_bytes())
    return log_path, manifest


def reconstruct(log_path, manifest, output, *options):
    return main(
        ["report", str(log_path), "--manifest", str(manifest), "--output", str(output), *options]
    )


def fingerprint(paths):
    return [sha256(path.read_bytes()).hexdigest() for path in paths]


def change_score(path):
    log = read_eval_log(path)
    score = log.samples[0].scores["review_score"]
    score.metadata.update(passed=False, review_correct=False)
    score.value.update(passed=0, review_correct=0)
    write_eval_log(log, path)


def test_report_cli_checks_scores_by_default_and_preserves_original_files(
    recorded_files, original_run, tmp_path
):
    log, manifest = recorded_files
    before = fingerprint(recorded_files)
    output = tmp_path / "verified"
    assert reconstruct(log, manifest, output) == 0
    result = json.loads((output / "report.json").read_text())
    assert result["metadata"]["score_verification"]["status"] == "verified"
    assert result["metadata"]["score_verification"]["verified_samples"] == 2
    assert result["rows"] == json.loads((original_run / "report.json").read_text())["rows"]
    assert fingerprint(recorded_files) == before


def test_default_reconstruction_rejects_stale_scores_without_writing_report(
    recorded_files, tmp_path, capsys
):
    log, manifest = recorded_files
    change_score(log)
    before = fingerprint(recorded_files)
    output = tmp_path / "rejected"
    assert reconstruct(log, manifest, output) == 2
    assert not output.exists()
    error = capsys.readouterr().err
    assert "recomputed score" in error and "Traceback" not in error
    assert fingerprint(recorded_files) == before


def test_preserve_recorded_scores_is_explicitly_unchecked_and_does_not_rescore(
    recorded_files, tmp_path
):
    log, manifest = recorded_files
    change_score(log)
    before = fingerprint(recorded_files)
    output = tmp_path / "unchecked"
    assert reconstruct(log, manifest, output, "--preserve-recorded-scores") == 0
    result = json.loads((output / "report.json").read_text())
    assert result["metadata"]["score_verification"]["status"] == "unchecked"
    assert result["rows"][0]["passed"] is False
    assert result["rows"][0]["review_correct"] is False
    assert fingerprint(recorded_files) == before


def test_supported_legacy_logs_without_fingerprints_remain_unchanged(recorded_files, tmp_path):
    log_path, manifest_path = recorded_files
    log = read_eval_log(log_path)
    log.eval.metadata.pop("provenance")
    write_eval_log(log, log_path)
    manifest = json.loads(manifest_path.read_text())
    manifest.pop("provenance")
    manifest_path.write_text(json.dumps(manifest))
    before = fingerprint(recorded_files)
    output = tmp_path / "legacy"
    assert reconstruct(log_path, manifest_path, output) == 0
    result = json.loads((output / "report.json").read_text())
    verification = result["metadata"]["score_verification"]
    assert verification["status"] == "verified"
    assert verification["provenance_verification"]["status"] == "unknown"
    assert "provenance" not in result["metadata"]
    assert fingerprint(recorded_files) == before


def test_preserve_option_does_not_bypass_contradictory_provenance(recorded_files, tmp_path):
    log, manifest_path = recorded_files
    manifest = json.loads(manifest_path.read_text())
    manifest["provenance"]["prompts"]["baseline"] = "a" * 64
    manifest_path.write_text(json.dumps(manifest))
    output = tmp_path / "invalid-provenance"
    assert reconstruct(log, manifest_path, output, "--preserve-recorded-scores") == 2
    assert not output.exists()


@pytest.mark.parametrize("preserve", [False, True])
def test_unsupported_scoring_version_cannot_be_relabelled(recorded_files, tmp_path, preserve):
    log, manifest_path = recorded_files
    manifest = json.loads(manifest_path.read_text())
    manifest["scoring_version"] = "0.1.0"
    manifest_path.write_text(json.dumps(manifest))
    output = tmp_path / "unsupported"
    options = ("--preserve-recorded-scores",) if preserve else ()
    assert reconstruct(log, manifest_path, output, *options) == 2
    assert not output.exists()


def test_unscored_error_is_reported_as_partial_verification(recorded_files, tmp_path):
    log_path, manifest = recorded_files
    log = read_eval_log(log_path)
    log.samples[0].scores = None
    log.samples[0].error = EvalError(message="Recorded failure", traceback="", traceback_ansi="")
    write_eval_log(log, log_path)
    before = fingerprint(recorded_files)
    output = tmp_path / "partial"
    assert reconstruct(log_path, manifest, output) == 0
    result = json.loads((output / "report.json").read_text())
    verification = result["metadata"]["score_verification"]
    assert verification["status"] == "partial" and verification["unscored_error_samples"] == 1
    assert result["rows"][0]["passed"] is False
    assert result["rows"][0]["conclusive"] is False
    assert fingerprint(recorded_files) == before
