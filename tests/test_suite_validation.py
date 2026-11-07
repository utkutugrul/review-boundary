"""Validator layers, leakage rules and safe output. Suites, manifests and hooks are data only."""

import ast
import json
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from review_boundary import corpus_registry, suite_validation
from review_boundary import corpus_upstream_pyjwt as pyjwt
from review_boundary.cli import main, parser
from review_boundary.provenance import HARNESS_FILES, json_digest
from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_suite import repository_suite_schema
from review_boundary.suite_validation import validate_suite

GROUP = "original_tenant_flow"
SCHEMA_ONLY_STATUS = {
    "safe_json": "passed",
    "json_schema": "passed",
    "runtime_parser": "passed",
    "leakage": "not_requested",
    "source_group_split": "not_requested",
    "provenance_license": "not_requested",
    "bundled_behavior": "not_requested",
    "installed_package": "not_requested",
}


def demo_data():
    return {
        "schema_version": 1,
        "cases": [case.model_dump(mode="json") for case in build_repository_demo_cases()],
    }


def pyjwt_data():
    cases = corpus_registry.build_cases("pyjwt")
    return {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}


def write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value if isinstance(value, str) else json.dumps(value))
    return path


def statuses(result):
    return {name: layer["status"] for name, layer in result["layers"].items()}


def original_manifest(data):
    by_variant = {}
    for case in data["cases"]:
        by_variant.setdefault(case["variant"], {f["path"]: f["content"] for f in case["files"]})
    artifacts, mappings = [], []
    for variant, files in by_variant.items():
        artifacts.append(
            {
                "variant": variant,
                "path": "LICENSE",
                "role": "license",
                "source_url": None,
                "sha256": "c" * 64,
                "size": 1,
                "license": "CC0-1.0",
                "license_path": "LICENSE",
                "notice_paths": [],
            }
        )
        for path, content in files.items():
            if path == "README.md":
                continue
            raw = content.encode()
            artifacts.append(
                {
                    "variant": variant,
                    "path": path,
                    "role": "source",
                    "source_url": None,
                    "sha256": __import__("hashlib").sha256(raw).hexdigest(),
                    "size": len(raw),
                    "license": "CC0-1.0",
                    "license_path": "LICENSE",
                    "notice_paths": [],
                }
            )
            mappings.append(
                {
                    "variant": variant,
                    "artifact_path": path,
                    "reviewer_path": path,
                    "transformation": "verbatim",
                }
            )
    return {
        "schema_version": 1,
        "corpus_name": "tenant_flow",
        "corpus_version": "calibration-v1",
        "scoring_version": "repository-v1",
        "provenance_kind": "original_calibration",
        "upstream_url": None,
        "advisory_url": None,
        "aliases": [],
        "disclosure_date": None,
        "fix_date": None,
        "source_group": GROUP,
        "split": "development",
        "revisions": None,
        "artifacts": artifacts,
        "dependencies": {
            "lock_status": "missing",
            "lock_paths": [],
            "entries": [],
            "note": "No lock is inventoried.",
        },
        "slice_mappings": mappings,
        "synthetic_reviewer_paths": ["README.md"],
        "modifications": [
            {
                "kind": "synthetic_file",
                "description": "README.md is synthetic calibration text.",
                "reviewer_paths": ["README.md"],
            }
        ],
        "oracle": {
            "oracle_id": "calibration-oracle-9",
            "sha256": "b" * 64,
            "kind": "independent_python_test",
            "os_sandboxed": False,
            "controls": ["Baseline control."],
            "limitations": ["Synthetic calibration only."],
        },
        "validation_scope": "schema_and_inventory_only",
    }


def wrapped(inventory):
    return {
        "schema_version": 1,
        "scope": "evaluator_only",
        "inventory": inventory,
        "inventory_sha256": json_digest(inventory),
        "authority": {"note": "self declared"},
        "layers": {"admission": "not_decided_by_this_manifest"},
    }


def check(tmp_path, data, manifests=(), splits=None, **options):
    suite = write(tmp_path, "suite.json", data)
    paths = [write(tmp_path, f"manifest-{i}.json", m) for i, m in enumerate(manifests)]
    split_path = write(tmp_path, "splits.json", splits) if splits is not None else None
    return validate_suite(suite, manifest_paths=paths, splits_path=split_path, **options)


def split_document(development=(GROUP,), held_out=()):
    return {
        "schema_version": 1,
        "partitions": {"development": list(development), "held_out": list(held_out)},
    }


def artifact(inventory, variant, path):
    return next(a for a in inventory["artifacts"] if (a["variant"], a["path"]) == (variant, path))


@pytest.fixture
def oracle(monkeypatch):
    calls = []

    def fake():
        calls.append("run")
        return {"reproduced": True}

    monkeypatch.setattr(pyjwt, "reproduce_upstream_pyjwt", fake)
    return calls


@pytest.fixture
def exported(tmp_path):
    output = tmp_path / "export"
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 0
    return output


# Layers and schema-only


def test_schema_only_runs_three_layers_and_never_touches_hooks_or_oracles(tmp_path, monkeypatch):
    marker = tmp_path / "executed.txt"
    code = f"import pathlib\npathlib.Path({str(marker)!r}).write_text('ran')\n"
    data = demo_data()
    data["cases"][0]["files"] += [
        {"path": "hook.py", "content": code},
        {"path": "conftest.py", "content": code},
        {"path": "setup.py", "content": code},
    ]

    def refuse(*args, **kwargs):
        raise AssertionError("Nothing may run in schema-only mode.")

    monkeypatch.setattr(suite_validation, "get_corpus", refuse)
    monkeypatch.setattr(pyjwt, "reproduce_upstream_pyjwt", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    result = validate_suite(write(tmp_path, "suite.json", data), schema_only=True)
    assert result["valid"] is True and result["mode"] == "schema_only"
    assert statuses(result) == SCHEMA_ONLY_STATUS
    assert not marker.exists()
    json.dumps(result, allow_nan=False)


def test_default_run_has_no_fabricated_layers_and_states_no_admission(tmp_path, capsys):
    suite = write(tmp_path, "suite.json", demo_data())
    assert main(["validate-suite", "--suite", str(suite)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is True
    assert statuses(result) == {**SCHEMA_ONLY_STATUS, "leakage": "passed"}
    assert result["admission"] == "not_established"
    assert result["source_authenticity"] == "unverified_for_external_metadata"
    assert result["independence"] == "not_inferred"
    assert result["suite"]["case_count"] == 4 and result["suite"]["source_group_count"] == 1


def test_default_and_corpus_runs_never_invoke_the_oracle(tmp_path, oracle):
    suite = write(tmp_path, "suite.json", pyjwt_data())
    assert validate_suite(suite)["valid"] is True
    result = validate_suite(suite, corpus_name="pyjwt")
    assert result["layers"]["bundled_behavior"]["status"] == "not_requested"
    assert oracle == []


@pytest.mark.parametrize("failure", ["missing", "duplicate", "nan", "directory"])
def test_unreadable_suites_are_reported_not_raised(tmp_path, capsys, failure):
    path = tmp_path / "suite.json"
    if failure == "duplicate":
        path.write_text('{"schema_version": 1, "schema_version": 1, "cases": []}')
    elif failure == "nan":
        path.write_text('{"schema_version": NaN}')
    elif failure == "directory":
        path = tmp_path
    assert main(["validate-suite", "--suite", str(path)]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] is False
    assert statuses(result)["safe_json"] == "failed"
    assert statuses(result)["json_schema"] == statuses(result)["runtime_parser"] == "not_requested"
    assert all(
        len(message) <= 200 for layer in result["layers"].values() for message in layer["messages"]
    )


def test_invalid_suite_messages_never_echo_candidate_text(tmp_path):
    data = demo_data()
    data["cases"][0]["SECRET_INJECTED_NAME"] = "import os; os.system('x')"
    data["cases"][1]["surface"] = "import os; os.system('y')"
    out = tmp_path / "result.json"
    suite = write(tmp_path, "suite.json", data)
    assert main(["validate-suite", "--suite", str(suite), "--output", str(out)]) == 2
    text = out.read_text()
    result = json.loads(text)
    assert result["valid"] is False
    assert statuses(result)["json_schema"] == statuses(result)["runtime_parser"] == "failed"
    assert "SECRET_INJECTED_NAME" not in text and "os.system" not in text
    for layer in result["layers"].values():
        assert len(layer["messages"]) <= 20
    assert statuses(result)["leakage"] == "not_requested"


SCHEMA_VALID_RUNTIME_INVALID = {
    "duplicate_ids": lambda s: s.update(cases=s["cases"] * 2),
    "evidence_beyond_file": lambda s: s["cases"][0]["issues"][0]["acceptable_bundles"][0]["ranges"][
        0
    ].update(end_line=99),
    "dotdot_path": lambda s: s["cases"][0]["files"].append({"path": "src/../x.py", "content": "x"}),
    "marker_not_in_resource": lambda s: s["cases"][1]["exposure"].update(marker="absent text"),
}


@pytest.mark.parametrize("name", sorted(SCHEMA_VALID_RUNTIME_INVALID))
def test_schema_and_runtime_layers_disagree_where_only_runtime_knows(tmp_path, name):
    data = demo_data()
    SCHEMA_VALID_RUNTIME_INVALID[name](data)
    result = validate_suite(write(tmp_path, "suite.json", data))
    assert statuses(result)["json_schema"] == "passed"
    assert statuses(result)["runtime_parser"] == "failed"
    assert result["valid"] is False
    assert statuses(result)["leakage"] == "not_requested"


def test_integral_float_version_is_a_runtime_failure(tmp_path):
    raw = json.dumps(demo_data()).replace('"schema_version": 1', '"schema_version": 1.0', 1)
    result = validate_suite(write(tmp_path, "suite.json", raw))
    assert statuses(result)["runtime_parser"] == "failed" and result["valid"] is False


def test_unusable_or_external_schema_is_never_accepted(tmp_path, monkeypatch):
    monkeypatch.setattr(
        suite_validation,
        "repository_suite_schema",
        lambda: {"$ref": "https://example.test/schema.json"},
    )
    result = validate_suite(write(tmp_path, "suite.json", demo_data()))
    assert statuses(result)["json_schema"] == "failed"
    assert statuses(result)["runtime_parser"] == "passed"
    assert result["valid"] is False


def test_there_is_no_candidate_schema_option():
    with pytest.raises(SystemExit):
        parser().parse_args(["validate-suite", "--suite", "s", "--json-schema", "x.json"])
    with pytest.raises(SystemExit):
        parser().parse_args(["validate-suite", "--suite", "s", "--corpus", "other"])


# Leakage


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["cases"][0].update(pr=d["cases"][0]["pr"] + " " + d["cases"][1]["case_id"]),
        lambda d: d["cases"][0].update(task=d["cases"][0]["task"] + " original_tenant_flow"),
        lambda d: d["cases"][0].update(
            instructions=d["cases"][0]["instructions"] + " " + d["cases"][0]["case_id"]
        ),
        lambda d: d["cases"][0]["files"][0].update(
            content=d["cases"][0]["files"][0]["content"] + "\n# tenant-ownership\n"
        ),
        lambda d: d["cases"][0]["files"].append(
            {"path": "notes/original_tenant_flow.txt", "content": "x"}
        ),
    ],
)
def test_exact_suite_identifiers_in_reviewer_text_are_rejected(tmp_path, mutate):
    data = demo_data()
    mutate(data)
    result = validate_suite(write(tmp_path, "suite.json", data))
    assert statuses(result)["leakage"] == "failed" and result["valid"] is False
    text = json.dumps(result)
    assert "tenant-ownership" not in text and "original_tenant_flow" not in text


def test_generic_words_and_project_identity_are_not_leakage(tmp_path):
    data = demo_data()
    data["cases"][0]["pr"] += " vulnerable fixed authorization pyjwt tenant flow"
    data["cases"][0]["files"] += [
        {"path": "oracle/driver.py", "content": "# vulnerable fixed\n"},
        {"path": ".github/workflows/ci.yml", "content": "name: ci\n"},
        {"path": "docs/vulnerable-fixed-authorization.md", "content": "notes\n"},
        {"path": "patches/formatting.patch", "content": "x\n"},
    ]
    assert statuses(validate_suite(write(tmp_path, "suite.json", data)))["leakage"] == "passed"


def test_generic_identifier_labels_do_not_turn_ordinary_words_into_leakage(tmp_path):
    data = demo_data()
    data["cases"] = data["cases"][:1]
    data["cases"][0].update(case_id="fixed", source_group="authorization")
    data["cases"][0]["issues"][0]["issue_id"] = "vulnerable"
    data["cases"][0]["pr"] += " Discuss vulnerable and fixed authorization code."
    result = check(tmp_path, data)
    assert result["valid"] is True
    assert statuses(result)["leakage"] == "passed"


def test_plain_project_identity_and_repository_url_are_allowed(tmp_path):
    data = pyjwt_data()
    manifest = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    manifest["source_group"] = "pyjwt"
    for case in data["cases"]:
        case["source_group"] = "pyjwt"
        case["pr"] += " Project: " + manifest["upstream_url"]
    result = check(tmp_path, data, [manifest])
    assert result["valid"] is True
    assert statuses(result)["leakage"] == "passed"


@pytest.mark.parametrize(
    "path",
    [
        ".GIT/config",
        "docs/.Git/HEAD",
        "evaluator/rubric.txt",
        "reference-patch/change.txt",
        "fix.patch",
        "docs/reference-fix.diff",
        "docs/evaluator_manifest.json",
    ],
)
def test_evaluator_carrier_paths_are_rejected(tmp_path, path):
    data = demo_data()
    data["cases"][0]["files"].append({"path": path, "content": "x"})
    result = validate_suite(write(tmp_path, "suite.json", data))
    assert statuses(result)["leakage"] == "failed"
    assert any("carrier rule" in m for m in result["layers"]["leakage"]["messages"])


@pytest.mark.parametrize("field", ["alias", "advisory_url", "revision", "oracle_id", "oracle_sha"])
def test_manifest_reference_and_oracle_identifiers_are_rejected(tmp_path, field):
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    value = {
        "alias": inventory["aliases"][0],
        "advisory_url": inventory["advisory_url"],
        "revision": inventory["revisions"]["vulnerable"],
        "oracle_id": inventory["oracle"]["oracle_id"],
        "oracle_sha": inventory["oracle"]["sha256"],
    }[field]
    data = pyjwt_data()
    data["cases"][0]["pr"] += " " + value
    without = check(tmp_path, data)
    assert statuses(without)["leakage"] == "passed"
    result = check(tmp_path, data, [inventory])
    assert statuses(result)["leakage"] == "failed"
    assert value not in json.dumps(result)


# Splits


def test_valid_splits_pass_and_state_no_independence(tmp_path):
    result = check(tmp_path, demo_data(), splits=split_document())
    assert statuses(result)["source_group_split"] == "passed" and result["valid"] is True
    assert result["independence"] == "not_inferred"


@pytest.mark.parametrize(
    "document",
    [
        split_document(development=(GROUP, GROUP)),
        split_document(development=(GROUP,), held_out=(GROUP,)),
        split_document(development=(GROUP, "other_group")),
        split_document(development=()),
        {**split_document(), "schema_version": True},
        {**split_document(), "schema_version": 2},
        {**split_document(), "extra": 1},
        {"schema_version": 1, "partitions": {"development": [GROUP]}},
        {"schema_version": 1, "partitions": {"development": GROUP, "held_out": []}},
        {"schema_version": 1, "partitions": {"development": [1], "held_out": []}},
        {"schema_version": 1, "partitions": {"development": [GROUP], "held_out": [], "x": []}},
    ],
)
def test_split_files_must_be_strict_unique_and_complete(tmp_path, document):
    result = check(tmp_path, demo_data(), splits=document)
    assert statuses(result)["source_group_split"] == "failed" and result["valid"] is False


def test_manifest_split_must_match_the_splits_file(tmp_path):
    inventory = original_manifest(demo_data())
    ok = check(tmp_path, demo_data(), [inventory], splits=split_document())
    assert statuses(ok)["source_group_split"] == "passed"
    bad = check(tmp_path, demo_data(), [inventory], splits=split_document((), (GROUP,)))
    assert statuses(bad)["source_group_split"] == "failed"


def test_conflicting_manifest_splits_are_rejected(tmp_path):
    first = original_manifest(demo_data())
    second = dict(first, split="held_out")
    result = check(tmp_path, demo_data(), [first, second])
    assert statuses(result)["source_group_split"] == "failed"
    assert statuses(result)["provenance_license"] == "failed"


# Manifests


@pytest.mark.parametrize("wrap", [False, True])
def test_original_manifest_validates_bare_or_wrapped(tmp_path, wrap):
    data = demo_data()
    inventory = original_manifest(data)
    result = check(tmp_path, data, [wrapped(inventory) if wrap else inventory])
    assert result["valid"] is True
    assert statuses(result)["provenance_license"] == "inventory_only"
    assert statuses(result)["source_group_split"] == "passed"
    assert result["source_authenticity"] == "unverified_for_external_metadata"
    assert any("unverified" in m for m in result["layers"]["provenance_license"]["messages"])


def test_wrapper_digest_and_shape_must_match_exactly(tmp_path):
    inventory = original_manifest(demo_data())
    bad_digest = wrapped(inventory)
    bad_digest["inventory_sha256"] = "0" * 64
    extra = wrapped(inventory)
    extra["extra"] = 1
    wrong_scope = wrapped(inventory)
    wrong_scope["scope"] = "reviewer"
    for document in (bad_digest, extra, wrong_scope):
        result = check(tmp_path, demo_data(), [document])
        assert statuses(result)["provenance_license"] == "failed" and result["valid"] is False
    good = check(tmp_path, demo_data(), [wrapped(inventory)])
    assert good["source_authenticity"] == "unverified_for_external_metadata"


def test_invalid_manifest_is_bounded_and_never_echoes_input(tmp_path):
    inventory = original_manifest(demo_data())
    inventory["leaked_secret_key_name"] = "secret"
    result = check(tmp_path, demo_data(), [inventory])
    assert statuses(result)["provenance_license"] == "failed"
    assert statuses(result)["leakage"] == "failed"
    assert "leaked_secret_key_name" not in json.dumps(result)
    unreadable = check(tmp_path, demo_data(), ["{"])
    assert statuses(unreadable)["provenance_license"] == "failed"


def test_wrapper_surrogate_fails_without_raising_or_echoing_candidate_text(tmp_path):
    inventory = original_manifest(demo_data())
    document = wrapped(inventory)
    document["inventory"]["dependencies"]["note"] = "\ud800SECRET_WRAPPER_98765"
    result = check(tmp_path, demo_data(), [document])
    assert statuses(result)["provenance_license"] == "failed"
    assert result["valid"] is False
    assert "SECRET_WRAPPER_98765" not in json.dumps(result)
    assert "canonical UTF-8 JSON" in json.dumps(result)


def test_external_oracle_sandbox_claim_stays_explicitly_unverified(tmp_path):
    inventory = original_manifest(demo_data())
    inventory["oracle"]["os_sandboxed"] = True
    result = check(tmp_path, demo_data(), [inventory])
    assert result["valid"] is True
    assert result["admission"] == "not_established"
    assert result["layers"]["bundled_behavior"]["status"] == "not_requested"
    assert any(
        "sandbox claims are unverified declarations" in note and "neither read nor executed" in note
        for note in result["notes"]
    )


@pytest.mark.parametrize("field", ["upstream_url", "advisory_url", "artifact_url"])
@pytest.mark.parametrize("url", ["https://[SECRET_HOST_987654]/project", "https://[broken"])
def test_malformed_manifest_urls_never_echo_candidate_text(tmp_path, field, url):
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    if field == "artifact_url":
        inventory["artifacts"][0]["source_url"] = url
    else:
        inventory[field] = url
    result = check(tmp_path, pyjwt_data(), [inventory])
    assert statuses(result)["provenance_license"] == "failed"
    assert statuses(result)["leakage"] == "failed"
    serialized = json.dumps(result)
    assert "SECRET_HOST_987654" not in serialized
    assert "broken" not in serialized
    assert url not in serialized


def test_inventory_must_equal_case_files_and_verbatim_hashes(tmp_path):
    data = demo_data()
    tampered = original_manifest(data)
    artifact(tampered, "fixed", "src/service.py")["sha256"] = "d" * 64
    resized = original_manifest(data)
    artifact(resized, "fixed", "src/service.py")["size"] += 1
    unmapped = original_manifest(data)
    unmapped["slice_mappings"] = [
        m
        for m in unmapped["slice_mappings"]
        if not (m["variant"] == "fixed" and m["reviewer_path"] == "src/policy.py")
    ]
    regrouped = original_manifest(data)
    regrouped["source_group"] = "different_group"
    for manifest in (tampered, resized, unmapped, regrouped):
        result = check(tmp_path, data, [manifest])
        assert statuses(result)["provenance_license"] == "failed" and result["valid"] is False
    extra_file = demo_data()
    extra_file["cases"][0]["files"].append({"path": "NOTES.md", "content": "x"})
    result = check(tmp_path, extra_file, [original_manifest(data)])
    assert statuses(result)["provenance_license"] == "failed"


@pytest.mark.parametrize("missing_path", ["LICENSE", "THIRD_PARTY_LICENSES.txt"])
def test_evaluator_only_license_inventory_never_claims_unseen_byte_verification(
    tmp_path, missing_path
):
    data = pyjwt_data()
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    inventory["slice_mappings"] = [
        item for item in inventory["slice_mappings"] if item["reviewer_path"] != missing_path
    ]
    inventory["modifications"] = [
        item for item in inventory["modifications"] if missing_path not in item["reviewer_paths"]
    ]
    for case in data["cases"]:
        case["files"] = [item for item in case["files"] if item["path"] != missing_path]
    result = check(tmp_path, data, [inventory])
    assert result["valid"] is True
    assert statuses(result)["provenance_license"] == "inventory_only"
    assert result["admission"] == "not_established"
    assert result["source_authenticity"] == "unverified_for_external_metadata"
    assert any(
        "bytes and provenance" in message and "unverified" in message
        for message in result["layers"]["provenance_license"]["messages"]
    )


def test_each_source_group_needs_exactly_one_manifest(tmp_path):
    data = demo_data()
    inventory = original_manifest(data)
    result = check(tmp_path, data, [inventory, inventory])
    assert statuses(result)["provenance_license"] == "failed"


def test_adapted_content_is_declared_and_reported_unverified(tmp_path):
    data = demo_data()
    inventory = original_manifest(data)
    for mapping in inventory["slice_mappings"]:
        if mapping["reviewer_path"] == "src/service.py":
            mapping["transformation"] = "adapted"
    inventory["modifications"].append(
        {"kind": "content_edit", "description": "Edited.", "reviewer_paths": ["src/service.py"]}
    )
    for variant in ("vulnerable", "fixed"):
        artifact(inventory, variant, "src/service.py")["sha256"] = "e" * 64
    result = check(tmp_path, data, [inventory])
    assert result["valid"] is True
    messages = result["layers"]["provenance_license"]["messages"]
    assert any("adapted" in m and "declared and unverified" in m for m in messages)


# Registry binding


def test_exported_corpus_validates_against_its_registry_without_running_the_oracle(
    exported, tmp_path, oracle
):
    splits = write(tmp_path, "splits.json", split_document((pyjwt.SOURCE_GROUP,)))
    out = tmp_path / "result.json"
    argv = ["validate-suite", "--suite", str(exported / "suite.json")]
    argv += ["--manifest", str(exported / "evaluator_manifest.json"), "--splits", str(splits)]
    argv += ["--corpus", "pyjwt", "--check-package", "--output", str(out)]
    assert main(argv) == 0
    result = json.loads(out.read_text())
    assert result["valid"] is True
    assert statuses(result) == {
        **SCHEMA_ONLY_STATUS,
        "leakage": "passed",
        "source_group_split": "passed",
        "provenance_license": "passed",
        "installed_package": "passed",
    }
    assert result["corpus"] == {"name": "pyjwt", "bound_to_registry": True}
    assert result["bundled_bytes"] == "anchored_verified"
    assert result["admission"] == "not_established"
    assert oracle == []


@pytest.mark.parametrize("reproduced", [True, False])
def test_verify_runs_only_the_bound_registered_oracle(exported, monkeypatch, reproduced):
    calls = []
    monkeypatch.setattr(
        pyjwt, "reproduce_upstream_pyjwt", lambda: calls.append(1) or {"reproduced": reproduced}
    )
    result = validate_suite(exported / "suite.json", corpus_name="pyjwt", verify=True)
    assert calls == [1]
    assert statuses(result)["bundled_behavior"] == ("passed" if reproduced else "failed")
    assert result["valid"] is reproduced
    assert result["behavior"] == {"reproduced": reproduced}


def test_oracle_failures_are_reported_without_raw_text(exported, monkeypatch):
    def fail():
        raise ValueError("SECRET_ORACLE_TEXT")

    monkeypatch.setattr(pyjwt, "reproduce_upstream_pyjwt", fail)
    result = validate_suite(exported / "suite.json", corpus_name="pyjwt", verify=True)
    assert statuses(result)["bundled_behavior"] == "failed"
    assert "SECRET_ORACLE_TEXT" not in json.dumps(result)


def test_registry_mismatch_blocks_the_oracle_and_package_check(tmp_path, oracle):
    data = pyjwt_data()
    data["cases"][0]["pr"] += " Extra reviewer text."
    result = check(tmp_path, data, corpus_name="pyjwt", verify=True, check_package=True)
    assert statuses(result)["provenance_license"] == "failed"
    assert statuses(result)["bundled_behavior"] == "failed"
    assert statuses(result)["installed_package"] == "failed"
    assert any("Blocked" in m for m in result["layers"]["bundled_behavior"]["messages"])
    assert result["corpus"]["bound_to_registry"] is False and result["valid"] is False
    assert oracle == []


def test_invalid_split_prevents_even_a_bound_corpus_oracle(tmp_path, oracle):
    result = check(
        tmp_path,
        pyjwt_data(),
        splits=split_document((pyjwt.SOURCE_GROUP,), (pyjwt.SOURCE_GROUP,)),
        corpus_name="pyjwt",
        verify=True,
        check_package=True,
    )
    assert result["valid"] is False
    assert statuses(result)["source_group_split"] == "failed"
    assert statuses(result)["bundled_behavior"] == "failed"
    assert statuses(result)["installed_package"] == "failed"
    assert oracle == []


def test_supplied_metadata_must_equal_the_registered_manifest(tmp_path, oracle):
    document = corpus_registry.evaluator_manifest("pyjwt")
    document["inventory"]["aliases"].append("GHSA-xxxx-yyyy-zzzz")
    document["inventory_sha256"] = json_digest(document["inventory"])
    result = check(tmp_path, pyjwt_data(), [document], corpus_name="pyjwt", verify=True)
    assert statuses(result)["provenance_license"] == "failed"
    assert statuses(result)["bundled_behavior"] == "failed"
    assert oracle == []


def test_tampered_bundled_bytes_block_everything(tmp_path, monkeypatch, oracle):
    suite = write(tmp_path, "suite.json", pyjwt_data())
    destination = tmp_path / "pyjwt"
    shutil.copytree(pyjwt.FIXTURE_ROOT, destination)
    (destination / "vulnerable" / "jwt" / "algorithms.py.txt").write_text("print('changed')\n")
    monkeypatch.setattr(pyjwt, "FIXTURE_ROOT", destination)
    result = validate_suite(suite, corpus_name="pyjwt", verify=True, check_package=True)
    assert statuses(result)["provenance_license"] == "failed"
    assert statuses(result)["bundled_behavior"] == statuses(result)["installed_package"] == "failed"
    assert result["bundled_bytes"] == "not_checked"
    assert oracle == []


def test_package_check_reports_extra_installed_fixture_files(tmp_path, monkeypatch):
    suite = write(tmp_path, "suite.json", pyjwt_data())
    destination = tmp_path / "pyjwt"
    shutil.copytree(pyjwt.FIXTURE_ROOT, destination)
    (destination / "extra.txt").write_text("unexpected\n")
    monkeypatch.setattr(pyjwt, "FIXTURE_ROOT", destination)
    result = validate_suite(suite, corpus_name="pyjwt", check_package=True)
    assert statuses(result)["installed_package"] == "failed"


# Options


@pytest.mark.parametrize(
    "extra",
    [
        ["--manifest", "m.json"],
        ["--splits", "s.json"],
        ["--corpus", "pyjwt"],
        ["--verify"],
        ["--check-package"],
    ],
)
def test_schema_only_conflicts_with_every_other_layer_flag(tmp_path, capsys, extra):
    suite = write(tmp_path, "suite.json", demo_data())
    assert main(["validate-suite", "--suite", str(suite), "--schema-only", *extra]) == 2
    assert "--schema-only" in capsys.readouterr().err


@pytest.mark.parametrize("flag", ["--verify", "--check-package"])
def test_execution_flags_require_a_registered_corpus(tmp_path, capsys, flag):
    suite = write(tmp_path, "suite.json", demo_data())
    assert main(["validate-suite", "--suite", str(suite), flag]) == 2
    assert "require --corpus" in capsys.readouterr().err
    with pytest.raises(ValueError, match="require --corpus"):
        validate_suite(suite, verify=True)


def test_unknown_corpus_names_are_refused(tmp_path):
    suite = write(tmp_path, "suite.json", demo_data())
    with pytest.raises(ValueError, match="Unknown upstream corpus"):
        validate_suite(suite, corpus_name="../pyjwt")


# Output safety and schema command


def test_output_is_new_private_and_never_overwritten(tmp_path):
    suite = write(tmp_path, "suite.json", demo_data())
    out = tmp_path / "result.json"
    argv = ["validate-suite", "--suite", str(suite), "--output", str(out)]
    assert main(argv) == 0
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    before = out.read_text()
    assert main(argv) == 2
    assert out.read_text() == before


def test_output_refuses_input_aliases_and_hard_links(tmp_path):
    data = demo_data()
    suite = write(tmp_path, "suite.json", data)
    manifest = write(tmp_path, "manifest.json", original_manifest(data))
    for alias in (suite, manifest):
        before = alias.read_text()
        argv = ["validate-suite", "--suite", str(suite), "--output", str(alias)]
        assert main(argv) == 2
        assert alias.read_text() == before
    link = tmp_path / "hard.json"
    link.hardlink_to(suite)
    assert main(["validate-suite", "--suite", str(suite), "--output", str(link)]) == 2
    assert json.loads(suite.read_text()) == data


def test_output_refuses_symlinks_and_symlinked_directories(tmp_path):
    suite = write(tmp_path, "suite.json", demo_data())
    target = tmp_path / "target.txt"
    target.write_text("keep")
    link = tmp_path / "link.json"
    link.symlink_to(target)
    dangling = tmp_path / "dangling.json"
    dangling.symlink_to(tmp_path / "missing.txt")
    real = tmp_path / "real"
    real.mkdir()
    directory = tmp_path / "linked"
    directory.symlink_to(real)
    for out in (link, dangling, directory / "result.json"):
        assert main(["validate-suite", "--suite", str(suite), "--output", str(out)]) == 2
    assert target.read_text() == "keep"
    assert not (tmp_path / "missing.txt").exists()
    assert not (real / "result.json").exists()


def test_refused_output_runs_no_validation(tmp_path, monkeypatch):
    suite = write(tmp_path, "suite.json", demo_data())
    out = tmp_path / "result.json"
    out.write_text("keep")

    def refuse(*args, **kwargs):
        raise AssertionError("Validation must not start with a refused output.")

    monkeypatch.setattr(suite_validation, "validate_suite", refuse)
    assert main(["validate-suite", "--suite", str(suite), "--output", str(out)]) == 2
    assert out.read_text() == "keep"


def test_suite_schema_prints_or_writes_only_the_derived_schema(tmp_path, capsys):
    assert main(["suite-schema"]) == 0
    assert json.loads(capsys.readouterr().out) == repository_suite_schema()
    out = tmp_path / "schema.json"
    assert main(["suite-schema", "--output", str(out)]) == 0
    assert json.loads(out.read_text()) == repository_suite_schema()
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert main(["suite-schema", "--output", str(out)]) == 2


# Module properties


def test_module_is_fingerprinted_and_cannot_execute_candidate_code():
    path = Path(suite_validation.__file__)
    assert "suite_validation.py" in HARNESS_FILES
    tree = ast.parse(path.read_text())
    banned = {"subprocess", "importlib", "pickle", "runpy", "ctypes", "marshal"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert not {name.name.split(".")[0] for name in node.names} & banned
        if isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] not in banned
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"exec", "eval", "compile", "__import__"}


def test_pyproject_declares_jsonschema_as_a_direct_dependency():
    text = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    assert '"jsonschema>=4,<5"' in text
