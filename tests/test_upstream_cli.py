import json
from dataclasses import replace

from review_boundary.cli import main


def test_exported_suite_and_provenance_match_existing_repository_contract(tmp_path):
    from review_boundary.provenance import json_digest, validate_provenance
    from review_boundary.repository_runner import load_suite

    output = tmp_path / "export"
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 0
    cases = load_suite(output / "suite.json")
    metadata = json.loads((output / "provenance.json").read_text())
    assert len(cases) == metadata["case_count"] == 4
    assert metadata["source_issue_count"] == 1
    assert metadata["suite_sha256"] == json_digest(json.loads((output / "suite.json").read_text()))
    validate_provenance(metadata["provenance"])
    assert metadata["provenance"]["harness"]["status"] == "recorded"
    assert metadata["provenance"]["harness"]["sha256"]
    assert metadata["provenance"]["reviewer_source"]["status"] == "not_recorded"
    assert metadata["behavior_verification"] == "not_run"
    assert not (output / "verification.json").exists()
    evaluator = json.loads((output / "evaluator_manifest.json").read_text())
    assert evaluator["scope"] == "evaluator_only"
    assert metadata["evaluator_manifest_sha256"] == json_digest(evaluator)
    assert evaluator["inventory"]["source_group"] == metadata["source"]["source_group"]
    suite_text = (output / "suite.json").read_text()
    assert evaluator["inventory"]["revisions"]["vulnerable"] not in suite_text
    assert "evaluator_manifest" not in suite_text
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 2


def test_failed_behavior_check_is_retained_and_exits_two(tmp_path, monkeypatch):
    from review_boundary import corpus_upstream_pyjwt

    monkeypatch.setattr(
        corpus_upstream_pyjwt, "reproduce_upstream_pyjwt", lambda: {"reproduced": False}
    )
    output = tmp_path / "failed"
    assert main(["corpus-export", "--corpus", "pyjwt", "--verify", "--output", str(output)]) == 2
    assert json.loads((output / "verification.json").read_text())["reproduced"] is False
    assert json.loads((output / "provenance.json").read_text())["behavior_verification"] == "failed"


def test_exporter_preserves_the_shared_v1_case_cap_before_writing(tmp_path, monkeypatch):
    from review_boundary import corpus_registry, upstream_runner

    registration = corpus_registry.get_corpus("pyjwt")
    case = registration.build_cases()[0]
    cases = tuple(case.model_copy(update={"case_id": f"opaque_{index}"}) for index in range(33))
    oversized = replace(registration, build_cases=lambda: cases)
    monkeypatch.setattr(upstream_runner, "get_corpus", lambda name: oversized)
    output = tmp_path / "too-large"
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 2
    assert not output.exists()


def test_oracle_timeout_is_a_clear_cli_failure(tmp_path, monkeypatch):
    import subprocess

    from review_boundary import corpus_upstream_pyjwt

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("private command text", 20)

    monkeypatch.setattr(corpus_upstream_pyjwt.subprocess, "run", timeout)
    assert (
        main(
            [
                "corpus-export",
                "--corpus",
                "pyjwt",
                "--verify",
                "--output",
                str(tmp_path / "timeout"),
            ]
        )
        == 2
    )
