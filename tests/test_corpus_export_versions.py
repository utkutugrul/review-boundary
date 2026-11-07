"""Registered export dispatch uses original synthetic cases and mocked callbacks only."""

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from review_boundary import corpus_registry, suite_validation, upstream_runner
from review_boundary.cli import main
from review_boundary.corpus_manifest import parse_corpus_manifest
from review_boundary.corpus_registry import (
    CorpusRegistration,
    checked_registered_cases,
    registration_suite_contract,
)
from review_boundary.provenance import json_digest
from review_boundary.repository_cases import (
    REPOSITORY_SCORING_VERSION,
    RepositoryCase,
    build_repository_demo_cases,
)
from review_boundary.repository_cases_v2 import (
    REPOSITORY_PAYLOAD_SCORING_VERSION,
    parse_repository_case,
)
from review_boundary.repository_runner import PAYLOAD_PROTOCOL, PROTOCOL, load_suite
from review_boundary.repository_suite import RepositorySuite
from review_boundary.repository_world import tool_schemas

_LICENSE = "Original synthetic export-test license inventory.\n"


def synthetic_cases(group_sizes=(4,), *, version=1):
    """Create original tenant cases without loading or executing upstream artifacts."""
    originals = build_repository_demo_cases()
    result = []
    for group, size in enumerate(group_sizes):
        for offset in range(size):
            data = originals[offset % len(originals)].model_dump(mode="json")
            data.update(
                case_id=f"opaque_{len(result):04d}", source_group=f"original_group_{group:03d}"
            )
            data["files"].append({"path": "LICENSE", "content": _LICENSE})
            if version == 2:
                marker = "Synthetic context marker."
                for file in data["files"]:
                    if file["path"] == "README.md":
                        file["content"] += "\n" + marker + "\n"
                data.update(
                    case_schema_version=2,
                    surface="readme",
                    condition="clean",
                    payload_ref={
                        "pack_id": "original_export_test",
                        "pack_version": 1,
                        "pack_digest": "0" * 64,
                        "entry_id": "synthetic_context",
                        "carrier": "readme",
                        "condition": "clean",
                    },
                    exposure={"resource": "README.md", "marker": marker},
                )
            result.append(parse_repository_case(data))
    return tuple(result)


def synthetic_inventory(*, version=1):
    artifacts, mappings = [], []
    for case in (build_repository_demo_cases()[0], build_repository_demo_cases()[2]):
        for file in (*case.files,):
            if file.path == "README.md":
                continue
            artifacts.append(
                {
                    "variant": case.variant,
                    "path": file.path,
                    "role": "source",
                    "source_url": None,
                    "sha256": hashlib.sha256(file.content.encode()).hexdigest(),
                    "size": len(file.content.encode()),
                    "license": "MIT",
                    "license_path": "LICENSE",
                    "notice_paths": [],
                }
            )
            mappings.append(
                {
                    "variant": case.variant,
                    "artifact_path": file.path,
                    "reviewer_path": file.path,
                    "transformation": "verbatim",
                }
            )
        artifacts.append(
            {
                "variant": case.variant,
                "path": "LICENSE",
                "role": "license",
                "source_url": None,
                "sha256": hashlib.sha256(_LICENSE.encode()).hexdigest(),
                "size": len(_LICENSE.encode()),
                "license": "MIT",
                "license_path": "LICENSE",
                "notice_paths": [],
            }
        )
        mappings.append(
            {
                "variant": case.variant,
                "artifact_path": "LICENSE",
                "reviewer_path": "LICENSE",
                "transformation": "verbatim",
            }
        )
    inventory = {
        "schema_version": 1,
        "corpus_name": "original_export_test",
        "corpus_version": "original-export-test-v1",
        "scoring_version": REPOSITORY_SCORING_VERSION
        if version == 1
        else REPOSITORY_PAYLOAD_SCORING_VERSION,
        "provenance_kind": "original_calibration",
        "upstream_url": None,
        "advisory_url": None,
        "aliases": [],
        "disclosure_date": None,
        "fix_date": None,
        "source_group": "original_group_000",
        "split": "development",
        "revisions": None,
        "artifacts": artifacts,
        "dependencies": {
            "lock_status": "missing",
            "lock_paths": [],
            "entries": [],
            "note": "Original synthetic inventory with no external dependencies.",
        },
        "slice_mappings": mappings,
        "synthetic_reviewer_paths": ["README.md"],
        "modifications": [
            {
                "kind": "synthetic_file",
                "description": "Original synthetic context.",
                "reviewer_paths": ["README.md"],
            }
        ],
        "oracle": {
            "oracle_id": "original-export-test-placeholder",
            "sha256": "0" * 64,
            "kind": "independent_python_test",
            "os_sandboxed": False,
            "controls": ["No behavior is executed by these export tests."],
            "limitations": ["Synthetic declared inventory only; no oracle implementation."],
        },
        "validation_scope": "schema_and_inventory_only",
    }
    return parse_corpus_manifest(inventory).model_dump(mode="json")


def synthetic_registration(cases=None, *, version=1, calls=None, verification=None):
    cases = synthetic_cases(version=version) if cases is None else cases
    calls = {} if calls is None else calls

    def record(name, result):
        calls[name] = calls.get(name, 0) + 1
        return result

    def verify():
        calls["verify"] = calls.get("verify", 0) + 1
        if isinstance(verification, Exception):
            raise verification
        return {"reproduced": True} if verification is None else verification

    return CorpusRegistration(
        name="original_export_test",
        corpus_version="original-export-test-v1",
        scoring_version=REPOSITORY_SCORING_VERSION
        if version == 1
        else REPOSITORY_PAYLOAD_SCORING_VERSION,
        dependency_group=None,
        scope="Original synthetic export tests only; no source admission.",
        build_cases=lambda: record("build", cases),
        source_manifest=lambda: record("source", {"schema_version": 1, "kind": "original_test"}),
        verify_behavior=verify,
        evaluator_manifest=lambda: record(
            "evaluator",
            {"scope": "evaluator_only", "inventory": synthetic_inventory(version=version)},
        ),
        package_inventory=lambda: (Path("unused"), ()),
        suite_schema_version=version,
    )


@pytest.fixture
def frozen_export(monkeypatch):
    class FrozenClock:
        @classmethod
        def now(cls, timezone):
            assert timezone is UTC
            return datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)

    def provenance(prompts, tools, *, protocol):
        return {"synthetic_fingerprint": {"prompts": prompts, "tools": tools, "protocol": protocol}}

    monkeypatch.setattr(upstream_runner, "datetime", FrozenClock)
    monkeypatch.setattr(upstream_runner, "experiment_provenance", provenance)
    return provenance


def inject(monkeypatch, registration):
    monkeypatch.setattr(upstream_runner, "get_corpus", lambda name: registration)


@pytest.mark.parametrize("version", (1, 2))
def test_checked_registration_derives_contract_from_exact_checked_cases(version):
    registration = synthetic_registration(version=version)
    cases = checked_registered_cases(registration)
    contract = registration_suite_contract(registration, cases)
    assert cases == registration.build_cases()
    assert contract.schema_version == version
    assert contract.scoring_version == (
        REPOSITORY_SCORING_VERSION if version == 1 else REPOSITORY_PAYLOAD_SCORING_VERSION
    )
    assert contract.protocol == (PROTOCOL if version == 1 else PAYLOAD_PROTOCOL)
    assert corpus_registry.corpus_names() == ("pyjwt",)


@pytest.mark.parametrize("value", (True, 1.0, "1", 0, 3, None))
def test_registration_schema_is_an_exact_supported_integer(value):
    with pytest.raises(ValueError):
        replace(synthetic_registration(), suite_schema_version=value)


def test_checked_registration_refuses_models_and_container_shortcuts():
    case = synthetic_cases((1,))[0]

    class UnsupportedCase(RepositoryCase):
        pass

    unsupported = UnsupportedCase.model_validate_json(case.model_dump_json())
    invalid = (
        [],
        (),
        (case for _ in range(1)),
        ({"case_id": "data_only"},),
        (unsupported,),
        (case.model_copy(update={"case_id": ""}),),
        (case, case),
        (case, synthetic_cases((1,), version=2)[0]),
        (case,) * 1025,
    )
    for cases in invalid:
        with pytest.raises(ValueError):
            checked_registered_cases(synthetic_registration(cases))


def test_tuple_bound_is_checked_before_serialization(monkeypatch):
    case = synthetic_cases((1,))[0]

    def refuse(*args, **kwargs):
        pytest.fail("An over-limit tuple was serialized")

    monkeypatch.setattr(RepositoryCase, "model_dump", refuse)
    with pytest.raises(ValueError, match="tuple of 1 to 1024"):
        checked_registered_cases(synthetic_registration((case,) * 1025))


@pytest.mark.parametrize("kind", ("mixed", "unchecked", "duplicate", "plain_data"))
def test_invalid_builder_models_fail_before_output_or_verification(tmp_path, monkeypatch, kind):
    case = synthetic_cases((1,))[0]
    cases = {
        "mixed": (case, synthetic_cases((1,), version=2)[0]),
        "unchecked": (case.model_copy(update={"case_id": ""}),),
        "duplicate": (case, case),
        "plain_data": (case.model_dump(mode="json"),),
    }[kind]
    calls = {}
    inject(monkeypatch, synthetic_registration(cases, calls=calls))
    output = tmp_path / "rejected"
    assert main(["corpus-export", "--corpus", "pyjwt", "--verify", "--output", str(output)]) == 2
    assert calls.get("verify", 0) == 0
    assert not output.exists()


@pytest.mark.parametrize("version", (1, 2))
@pytest.mark.parametrize("field", ("scoring_version", "suite_schema_version"))
def test_declared_case_contract_mismatch_has_no_output(tmp_path, monkeypatch, version, field):
    registration = synthetic_registration(version=version)
    registration = replace(
        registration, **{field: "incorrect" if field == "scoring_version" else 3 - version}
    )
    inject(monkeypatch, registration)
    output = tmp_path / "mismatch"
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 2
    assert not output.exists()


@pytest.mark.parametrize("field", ("corpus_name", "corpus_version", "scoring_version"))
def test_evaluator_identity_mismatch_refuses_before_verification_or_output(
    tmp_path, monkeypatch, field
):
    calls = {}
    registration = synthetic_registration(calls=calls)
    document = registration.evaluator_manifest()
    document["inventory"][field] = "other"
    registration = replace(registration, evaluator_manifest=lambda: document)
    inject(monkeypatch, registration)
    output = tmp_path / "mismatch"
    assert main(["corpus-export", "--corpus", "pyjwt", "--verify", "--output", str(output)]) == 2
    assert not output.exists()
    assert calls.get("verify", 0) == 0
    monkeypatch.setattr(suite_validation, "get_corpus", lambda name: registration)
    assert not suite_validation._bind_registry(
        "pyjwt", RepositorySuite(schema_version=1, cases=registration.build_cases())
    ).bound


def test_unsharded_v1_preserves_exact_legacy_text_order_metadata_and_default(
    tmp_path, monkeypatch, frozen_export
):
    calls = {}
    cases = tuple(reversed(synthetic_cases()))
    registration = synthetic_registration(cases, calls=calls)
    inject(monkeypatch, registration)
    output = tmp_path / "legacy"
    output.mkdir()  # The legacy path continues to accept an existing empty directory.
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 0
    suite = {"schema_version": 1, "cases": [case.model_dump(mode="json") for case in cases]}
    source = {"schema_version": 1, "kind": "original_test"}
    evaluator = {"scope": "evaluator_only", "inventory": synthetic_inventory()}
    expected = {
        "schema_version": 1,
        "corpus_version": registration.corpus_version,
        "generated_at": "2026-01-02T03:04:05+00:00",
        "suite_sha256": json_digest(suite),
        "evaluator_manifest_sha256": json_digest(evaluator),
        "case_count": len(cases),
        "source_issue_count": 1,
        "source": source,
        "provenance": frozen_export(
            {
                f"input-{index}": json.dumps(
                    {"instructions": case.instructions, "task": case.task}, sort_keys=True
                )
                for index, case in enumerate(cases)
            },
            tool_schemas(),
            protocol=PROTOCOL,
        ),
        "behavior_verification": "not_run",
        "scope": registration.scope,
    }
    for filename, document in (
        ("suite.json", suite),
        ("provenance.json", expected),
        ("evaluator_manifest.json", evaluator),
    ):
        assert (output / filename).read_text() == json.dumps(
            document, indent=2, ensure_ascii=False
        ) + "\n"
    assert {path.name for path in output.iterdir()} == {
        "suite.json",
        "provenance.json",
        "evaluator_manifest.json",
    }
    assert calls == {"source": 1, "build": 1, "evaluator": 1}


@pytest.mark.parametrize("reproduced,expected_exit", ((True, 0), (False, 2)))
def test_legacy_explicit_verification_preserves_callback_result_and_exit(
    tmp_path, monkeypatch, frozen_export, reproduced, expected_exit
):
    calls = {}
    result = {"reproduced": reproduced, "synthetic": "mocked callback only"}
    inject(monkeypatch, synthetic_registration(calls=calls, verification=result))
    output = tmp_path / "verified"
    assert (
        main(["corpus-export", "--corpus", "pyjwt", "--verify", "--output", str(output)])
        == expected_exit
    )
    assert calls["verify"] == 1
    assert (output / "verification.json").read_text() == json.dumps(result, indent=2) + "\n"
    metadata = json.loads((output / "provenance.json").read_text())
    assert metadata["behavior_verification"] == ("passed" if reproduced else "failed")
    assert metadata["schema_version"] == 1


def test_legacy_verifier_exception_keeps_no_output(tmp_path, monkeypatch):
    calls = {}
    inject(
        monkeypatch,
        synthetic_registration(calls=calls, verification=ValueError("Synthetic failure")),
    )
    output = tmp_path / "failed"
    assert main(["corpus-export", "--corpus", "pyjwt", "--verify", "--output", str(output)]) == 2
    assert calls["verify"] == 1
    assert not output.exists()


def test_unsharded_v2_selects_its_suite_scoring_protocol_and_metadata_schema(
    tmp_path, monkeypatch, frozen_export
):
    calls = {}
    registration = synthetic_registration(version=2, calls=calls)
    inject(monkeypatch, registration)
    output = tmp_path / "v2"
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 0
    assert load_suite(output / "suite.json") == registration.build_cases()
    suite = json.loads((output / "suite.json").read_text())
    metadata = json.loads((output / "provenance.json").read_text())
    assert suite["schema_version"] == metadata["suite_schema_version"] == 2
    assert metadata["schema_version"] == 2
    assert metadata["export_kind"] == "registered_corpus_suite"
    assert metadata["scoring_version"] == REPOSITORY_PAYLOAD_SCORING_VERSION
    assert (
        metadata["protocol"]
        == metadata["provenance"]["synthetic_fingerprint"]["protocol"]
        == PAYLOAD_PROTOCOL
    )
    assert metadata["suite_sha256"] == json_digest(suite)
    assert metadata["behavior_verification"] == "not_run"
    assert calls.get("verify", 0) == 0
    assert not (output / "verification.json").exists()


def test_v2_verify_rejects_before_any_builder_manifest_or_oracle(tmp_path, monkeypatch):
    calls = {}
    inject(monkeypatch, synthetic_registration(version=2, calls=calls))
    output = tmp_path / "rejected"
    assert main(["corpus-export", "--corpus", "pyjwt", "--verify", "--output", str(output)]) == 2
    assert calls == {}
    assert not output.exists()


def test_validator_v2_behavior_layer_rejects_without_invoking_a_verifier():
    calls = {}
    layer = suite_validation._Layer()
    result = suite_validation._run_behavior(layer, synthetic_registration(version=2, calls=calls))
    assert result == {"reproduced": False}
    assert layer.status == "failed"
    assert calls == {}


@pytest.mark.parametrize("version", (1, 2))
def test_default_unsharded_cap_remains_32(tmp_path, monkeypatch, version):
    inject(
        monkeypatch,
        synthetic_registration(synthetic_cases((16, 17), version=version), version=version),
    )
    output = tmp_path / "over_cap"
    assert main(["corpus-export", "--corpus", "pyjwt", "--output", str(output)]) == 2
    assert not output.exists()
