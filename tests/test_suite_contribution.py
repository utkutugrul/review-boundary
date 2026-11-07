"""Contribution template generation, validation and refusal behavior."""

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tomllib
from argparse import Namespace
from pathlib import Path

import pytest

from review_boundary import suite_contribution
from review_boundary.cli import main
from review_boundary.corpus_manifest import parse_corpus_manifest
from review_boundary.json_input import read_json_object
from review_boundary.provenance import HARNESS_FILES, MAX_HARNESS_FILES
from review_boundary.repository_runner import load_suite
from review_boundary.repository_suite import MAX_REPOSITORY_SUITE_CASES, load_repository_suite
from review_boundary.suite_contribution import case_template_command, generate_case_template
from review_boundary.suite_validation import validate_suite

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_FILES = {
    "suite.json",
    "manifest.json",
    "splits.json",
    "case.py",
    "LICENSE",
    "README.md",
    "tests/test_behavior.py",
}
PASSED_LAYERS = (
    "safe_json",
    "json_schema",
    "runtime_parser",
    "leakage",
    "source_group_split",
    "provenance_license",
)


@pytest.fixture
def template(tmp_path):
    return generate_case_template(tmp_path / "example", "example")


def _mismatches(directory):
    manifest = parse_corpus_manifest(read_json_object(directory / "manifest.json"))
    suite = load_repository_suite(directory / "suite.json")
    bad = []
    for case in suite.cases:
        files = {item.path: item.content.encode("utf-8") for item in case.files}
        for record in manifest.artifacts:
            if record.variant != case.variant:
                continue
            raw = files[record.path]
            if len(raw) != record.size or hashlib.sha256(raw).hexdigest() != record.sha256:
                bad.append((case.case_id, record.path))
    oracle = (directory / "tests" / "test_behavior.py").read_bytes()
    if hashlib.sha256(oracle).hexdigest() != manifest.oracle.sha256:
        bad.append(("oracle", "tests/test_behavior.py"))
    return bad


def _run_oracle(directory):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(directory / "tests" / "test_behavior.py")],
        cwd=directory,
        env={"PATH": os.environ.get("PATH", "")},
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def test_generates_exact_files_with_private_modes(template):
    entries = list(template.rglob("*"))
    assert {p.relative_to(template).as_posix() for p in entries if p.is_file()} == EXPECTED_FILES
    assert not any(path.is_symlink() for path in entries)
    for path in [template, *entries]:
        assert stat.S_IMODE(path.lstat().st_mode) & 0o077 == 0
    for path in (template, template / "tests"):
        assert stat.S_IMODE(path.lstat().st_mode) & 0o700 == 0o700


@pytest.mark.parametrize("name", ["example", "alpha_2", "record"])
def test_template_validates_with_manifest_and_splits(tmp_path, name):
    template = generate_case_template(tmp_path / name, name)
    result = validate_suite(
        template / "suite.json",
        manifest_paths=(template / "manifest.json",),
        splits_path=template / "splits.json",
    )
    assert result["valid"] is True, result["layers"]
    assert result["admission"] == "not_established"
    for layer in PASSED_LAYERS:
        assert result["layers"][layer]["status"] == "passed", result["layers"][layer]
    assert result["layers"]["bundled_behavior"]["status"] == "not_requested"
    assert result["layers"]["installed_package"]["status"] == "not_requested"
    assert result["suite"]["case_count"] == 4
    assert result["suite"]["source_group_count"] == 1
    assert _mismatches(template) == []


def test_validate_command_accepts_template(template, tmp_path):
    report = tmp_path / "report.json"
    code = main(
        [
            "validate-suite",
            "--suite",
            str(template / "suite.json"),
            "--manifest",
            str(template / "manifest.json"),
            "--splits",
            str(template / "splits.json"),
            "--output",
            str(report),
        ]
    )
    assert code == 0
    assert read_json_object(report)["admission"] == "not_established"


def test_manifest_is_original_calibration_without_upstream_claims(template):
    raw = read_json_object(template / "manifest.json")
    for key in ("upstream_url", "advisory_url", "revisions", "disclosure_date", "fix_date"):
        assert key in raw
        assert raw[key] is None
    assert raw["aliases"] == []
    manifest = parse_corpus_manifest(raw)
    assert manifest.provenance_kind == "original_calibration"
    assert manifest.source_group == "original_example"
    assert manifest.corpus_name == "original_example"
    assert manifest.split == "development"
    assert manifest.validation_scope == "schema_and_inventory_only"
    assert manifest.dependencies.lock_status == "missing"
    assert manifest.dependencies.lock_paths == ()
    assert manifest.oracle.kind == "independent_python_test"
    assert manifest.synthetic_reviewer_paths == ("README.md",)
    assert all(item.source_url is None for item in manifest.artifacts)
    assert all(item.license == "MIT" for item in manifest.artifacts)
    assert {item.variant for item in manifest.artifacts} == {"vulnerable", "fixed"}
    assert len(manifest.artifacts) == 8
    assert all(item.transformation == "verbatim" for item in manifest.slice_mappings)


def test_splits_declare_development_only(template):
    splits = read_json_object(template / "splits.json")
    assert splits == {
        "schema_version": 1,
        "partitions": {"development": ["original_example"], "held_out": []},
    }


def test_code_bytes_match_across_context_and_license_is_project_license(template):
    cases = load_suite(template / "suite.json")
    assert len(cases) == 4
    by_key = {(c.variant, c.surface): {f.path: f.content for f in c.files} for c in cases}
    assert len(by_key) == 4
    assert {c.source_group for c in cases} == {"original_example"}
    for case in cases:
        assert "vulnerable" not in case.case_id
        assert "fixed" not in case.case_id
        assert "clean" not in case.case_id
        assert "readme" not in case.case_id
    for variant in ("vulnerable", "fixed"):
        clean, attacked = by_key[(variant, "clean")], by_key[(variant, "readme")]
        assert {path for path in clean if clean[path] != attacked[path]} == {"README.md"}
        assert attacked["README.md"].startswith(clean["README.md"])
    project_license = (ROOT / "LICENSE").read_text(encoding="utf-8")
    for files in by_key.values():
        assert files["LICENSE"] == project_license
    assert (template / "LICENSE").read_text(encoding="utf-8") == project_license
    vulnerable, fixed = by_key[("vulnerable", "clean")], by_key[("fixed", "clean")]
    assert vulnerable["src/service.py"] != fixed["src/service.py"]
    assert vulnerable["src/route.py"] == fixed["src/route.py"]
    assert vulnerable["src/policy.py"] == fixed["src/policy.py"]


def test_case_loader_matches_suite(template, monkeypatch):
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    spec = importlib.util.spec_from_file_location("_generated_case_loader", template / "case.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.SUITE_PATH == (template / "suite.json").resolve()
    assert module.load_cases() == load_repository_suite(template / "suite.json").cases


def test_behavior_oracle_passes_in_bounded_subprocess(template):
    before = sorted(p.relative_to(template).as_posix() for p in template.rglob("*"))
    result = _run_oracle(template)
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stderr
    assert sorted(p.relative_to(template).as_posix() for p in template.rglob("*")) == before


def test_behavior_oracle_detects_a_broken_fix(template):
    path = template / "suite.json"
    text = path.read_text(encoding="utf-8")
    guard = "record is None or not can_read(actor_tenant, record)"
    assert guard in text
    path.write_text(text.replace(guard, "record is None"), encoding="utf-8")
    result = _run_oracle(template)
    assert result.returncode != 0
    assert "FAILED" in result.stderr


def test_suite_tamper_is_detected_by_inventory_and_validator(template):
    path = template / "suite.json"
    text = path.read_text(encoding="utf-8")
    assert "record is None" in text
    path.write_text(text.replace("record is None", "record is not None"), encoding="utf-8")
    assert _mismatches(template)
    result = validate_suite(
        path,
        manifest_paths=(template / "manifest.json",),
        splits_path=template / "splits.json",
    )
    assert result["valid"] is False
    assert result["layers"]["provenance_license"]["status"] == "failed"
    assert result["admission"] == "not_established"


def test_oracle_tamper_is_detected_by_inventory(template):
    oracle = template / "tests" / "test_behavior.py"
    oracle.write_text(oracle.read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8")
    assert ("oracle", "tests/test_behavior.py") in _mismatches(template)


def test_generator_and_validator_never_run_candidate_code(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("no process may start")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    before = set(sys.modules)
    template = generate_case_template(tmp_path / "example", "example")
    oracle_marker = tmp_path / "oracle-ran"
    source_marker = tmp_path / "source-ran"
    (template / "tests" / "test_behavior.py").write_text(
        f"open({str(oracle_marker)!r}, 'w').close()\n", encoding="utf-8"
    )
    suite_path = template / "suite.json"
    data = json.loads(suite_path.read_text(encoding="utf-8"))
    for case in data["cases"]:
        for item in case["files"]:
            if item["path"] == "src/policy.py":
                item["content"] += f"open({str(source_marker)!r}, 'w').close()\n"
    suite_path.write_text(json.dumps(data), encoding="utf-8")
    validate_suite(
        suite_path,
        manifest_paths=(template / "manifest.json",),
        splits_path=template / "splits.json",
    )
    main(["validate-suite", "--suite", str(suite_path), "--schema-only"])
    assert not oracle_marker.exists()
    assert not source_marker.exists()
    assert [name for name in set(sys.modules) - before if name.startswith("_rb_")] == []


@pytest.mark.parametrize(
    "name", ["", "Example", "1case", "a-b", "a b", "a/b", "../x", "x" * 33, "café", "ok\n"]
)
def test_invalid_names_write_nothing(tmp_path, name):
    with pytest.raises(ValueError, match="lowercase slug"):
        generate_case_template(tmp_path / "out", name)
    assert list(tmp_path.iterdir()) == []


def test_non_string_name_writes_nothing(tmp_path):
    with pytest.raises(ValueError, match="lowercase slug"):
        generate_case_template(tmp_path / "out", None)
    assert list(tmp_path.iterdir()) == []


def test_existing_directory_and_file_are_refused(tmp_path):
    directory = tmp_path / "dir"
    directory.mkdir()
    (directory / "keep.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        generate_case_template(directory, "example")
    assert [p.name for p in directory.iterdir()] == ["keep.txt"]
    assert (directory / "keep.txt").read_text(encoding="utf-8") == "keep"
    file = tmp_path / "file"
    file.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError, match="already exists"):
        generate_case_template(file, "example")
    assert file.read_text(encoding="utf-8") == "x"


def test_symlink_components_are_refused(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    with pytest.raises(ValueError):
        generate_case_template(link, "example")
    with pytest.raises(ValueError, match="symlink"):
        generate_case_template(link / "child", "example")
    assert list(target.iterdir()) == []
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "nowhere")
    with pytest.raises(ValueError):
        generate_case_template(dangling, "example")
    assert not (tmp_path / "nowhere").exists()


def test_missing_parent_and_dotdot_are_refused(tmp_path):
    with pytest.raises(ValueError, match="parent"):
        generate_case_template(tmp_path / "missing" / "out", "example")
    assert not (tmp_path / "missing").exists()
    (tmp_path / "a").mkdir()
    with pytest.raises(ValueError, match="'..'"):
        generate_case_template(tmp_path / "a" / ".." / "out", "example")
    assert not (tmp_path / "out").exists()


def test_failed_write_removes_only_created_paths(tmp_path, monkeypatch):
    real = suite_contribution._write_new_text_owned
    calls = []

    def flaky(path, text, label):
        calls.append(path)
        if len(calls) == 3:
            raise OSError("injected")
        return real(path, text, label)

    monkeypatch.setattr(suite_contribution, "_write_new_text_owned", flaky)
    keep = tmp_path / "keep.txt"
    keep.write_text("keep", encoding="utf-8")
    with pytest.raises(OSError, match="injected"):
        generate_case_template(tmp_path / "out", "example")
    assert not (tmp_path / "out").exists()
    assert keep.read_text(encoding="utf-8") == "keep"


def test_partial_file_write_failure_cleans_created_template(tmp_path, monkeypatch):
    real_fdopen = os.fdopen
    calls = []

    class PartialWriteFailure:
        def __init__(self, stream):
            self.stream = stream

        def write(self, text):
            self.stream.write(text[:7])
            self.stream.flush()
            raise OSError("injected partial write")

        def close(self):
            self.stream.close()

    def fdopen(*args, **kwargs):
        stream = real_fdopen(*args, **kwargs)
        calls.append(stream)
        return PartialWriteFailure(stream) if len(calls) == 3 else stream

    keep = tmp_path / "keep.txt"
    keep.write_text("keep", encoding="utf-8")
    monkeypatch.setattr(os, "fdopen", fdopen)
    with pytest.raises(OSError, match="injected partial write"):
        generate_case_template(tmp_path / "out", "example")
    assert not (tmp_path / "out").exists()
    assert keep.read_text(encoding="utf-8") == "keep"


def test_cleanup_preserves_replacement_of_an_earlier_successful_file(tmp_path, monkeypatch):
    real = suite_contribution._write_new_text_owned
    output = tmp_path / "out"
    calls = []

    def flaky(path, text, label):
        calls.append(path)
        if len(calls) == 3:
            replacement = output / "replacement.tmp"
            replacement.write_text("unrelated replacement", encoding="utf-8")
            replacement.replace(output / "suite.json")
            raise OSError("injected after replacement")
        return real(path, text, label)

    monkeypatch.setattr(suite_contribution, "_write_new_text_owned", flaky)
    with pytest.raises(OSError, match="injected after replacement"):
        generate_case_template(output, "example")
    assert (output / "suite.json").read_text(encoding="utf-8") == "unrelated replacement"
    assert {path.name for path in output.iterdir()} == {"suite.json"}


def test_cleanup_preserves_replaced_directory_and_all_unknown_contents(tmp_path, monkeypatch):
    real = suite_contribution._write_new_text_owned
    output = tmp_path / "out"
    displaced = tmp_path / "displaced"
    calls = []

    def flaky(path, text, label):
        calls.append(path)
        if len(calls) == 3:
            output.rename(displaced)
            output.mkdir()
            (output / "tests").mkdir()
            (output / "suite.json").write_text("unrelated replacement", encoding="utf-8")
            (output / "tests" / "unknown.txt").write_text("keep", encoding="utf-8")
            raise OSError("injected after directory replacement")
        return real(path, text, label)

    monkeypatch.setattr(suite_contribution, "_write_new_text_owned", flaky)
    with pytest.raises(OSError, match="injected after directory replacement"):
        generate_case_template(output, "example")
    assert (output / "suite.json").read_text(encoding="utf-8") == "unrelated replacement"
    assert (output / "tests" / "unknown.txt").read_text(encoding="utf-8") == "keep"
    assert (displaced / "suite.json").is_file()
    assert (displaced / "manifest.json").is_file()


def test_cli_defaults_and_refusals(tmp_path, capsys):
    out = tmp_path / "new"
    assert main(["case-template", "--output", str(out)]) == 0
    assert read_json_object(out / "manifest.json")["corpus_name"] == "original_example"
    assert str(out) in capsys.readouterr().out
    assert main(["case-template", "--output", str(out)]) == 2
    assert main(["case-template", "--output", str(tmp_path / "x"), "--name", "Bad"]) == 2
    assert not (tmp_path / "x").exists()
    assert "refused" in capsys.readouterr().err


def test_command_function_returns_status(tmp_path):
    assert case_template_command(Namespace(output=tmp_path / "alpha", name="alpha")) == 0
    assert case_template_command(Namespace(output=tmp_path / "alpha", name="alpha")) == 2


def test_generated_text_has_no_em_dash(template):
    for path in template.rglob("*"):
        if path.is_file():
            assert "—" not in path.read_text(encoding="utf-8")


def test_runtime_module_is_packaged_and_cap_is_fixed():
    base = Path(suite_contribution.__file__).resolve().parent
    assert "suite_contribution.py" in HARNESS_FILES
    assert len(HARNESS_FILES) == len(set(HARNESS_FILES)) <= MAX_HARNESS_FILES == 128
    assert (base / "suite_contribution.py").is_file()
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    wheel = config["tool"]["hatch"]["build"]["targets"]["wheel"]
    assert "src/review_boundary" in wheel["packages"]
    assert MAX_REPOSITORY_SUITE_CASES == 32
