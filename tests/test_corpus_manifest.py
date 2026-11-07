"""Schema and inventory validation only. It never admits or authenticates a corpus."""

import functools
import json

import pytest
from pydantic import ValidationError

from review_boundary import corpus_registry
from review_boundary.corpus_manifest import (
    ArtifactRecord,
    CorpusManifest,
    OracleIdentity,
    parse_corpus_manifest,
)


@functools.cache
def _base() -> str:
    return json.dumps(corpus_registry.evaluator_manifest("pyjwt")["inventory"])


def inventory() -> dict:
    return json.loads(_base())


def artifact(data, variant, path):
    return next(
        item for item in data["artifacts"] if item["variant"] == variant and item["path"] == path
    )


def rejected(data, match=None):
    with pytest.raises(ValidationError, match=match):
        parse_corpus_manifest(data)


def lock_artifact(data):
    return {
        "variant": "fixed",
        "path": "poetry.lock",
        "role": "lock",
        "source_url": "https://example.test/" + data["revisions"]["fixed"] + "/poetry.lock",
        "sha256": "1" * 64,
        "size": 10,
        "license": "MIT",
        "license_path": "LICENSE",
        "notice_paths": [],
    }


def test_registered_inventory_round_trips_and_is_frozen():
    data = inventory()
    manifest = parse_corpus_manifest(data)
    assert manifest.model_dump(mode="json") == data
    assert isinstance(manifest.artifacts, tuple)
    with pytest.raises(ValidationError):
        manifest.split = "held_out"
    with pytest.raises(ValidationError):
        manifest.artifacts[0].sha256 = "0" * 64


def test_every_field_is_required_so_unknown_must_be_explicit():
    for model in (CorpusManifest, ArtifactRecord, OracleIdentity):
        assert all(field.is_required() for field in model.model_fields.values())


@pytest.mark.parametrize("key", list(CorpusManifest.model_fields))
def test_missing_top_level_field_is_rejected(key):
    data = inventory()
    del data[key]
    rejected(data)


@pytest.mark.parametrize("key", list(ArtifactRecord.model_fields))
def test_missing_artifact_field_is_rejected(key):
    data = inventory()
    del data["artifacts"][0][key]
    rejected(data)


def test_unknown_fields_are_rejected_at_every_level():
    data = inventory()
    data["unexpected"] = 1
    rejected(data)
    data = inventory()
    data["artifacts"][0]["unexpected"] = 1
    rejected(data)
    data = inventory()
    data["oracle"]["unexpected"] = 1
    rejected(data)
    with pytest.raises(ValueError, match="JSON object"):
        parse_corpus_manifest([])


def test_version_scope_and_split_are_closed_sets():
    for key, value in (
        ("schema_version", 2),
        ("schema_version", True),
        ("validation_scope", "admitted"),
        ("split", "test"),
    ):
        data = inventory()
        data[key] = value
        rejected(data)
    data = inventory()
    data["split"] = "held_out"
    assert parse_corpus_manifest(data).split == "held_out"


@pytest.mark.parametrize("field", ["disclosure_date", "fix_date"])
@pytest.mark.parametrize(
    "value",
    [
        "2022-13-01",
        "2022-02-30",
        "2022-1-1",
        "20220101",
        "",
        " 2022-01-01",
        "2022-01-01T00:00",
        7,
        True,
    ],
)
def test_invalid_dates_are_rejected(field, value):
    data = inventory()
    data[field] = value
    rejected(data)


@pytest.mark.parametrize("field", ["disclosure_date", "fix_date"])
def test_dates_accept_explicit_null_or_a_real_calendar_date(field):
    data = inventory()
    assert data[field] is None
    data[field] = "2024-02-29"
    assert getattr(parse_corpus_manifest(data), field) == "2024-02-29"


@pytest.mark.parametrize("which", ["vulnerable", "fixed"])
@pytest.mark.parametrize("value", ["", "abc123", "A" * 40, "g" * 40, "0" * 39, "0" * 41])
def test_revisions_must_be_full_lowercase_hex(which, value):
    data = inventory()
    data["revisions"][which] = value
    rejected(data)


def test_revisions_must_differ_and_urls_must_name_them():
    data = inventory()
    data["revisions"]["fixed"] = data["revisions"]["vulnerable"]
    rejected(data, "differ")
    data = inventory()
    artifact(data, "fixed", "jwt/utils.py")["source_url"] = (
        "https://raw.githubusercontent.com/jpadilla/pyjwt/main/jwt/utils.py"
    )
    rejected(data, "pinned revision")


@pytest.mark.parametrize(
    "url",
    ["http://example.test/x", "ftp://example.test/x", "https://u:p@example.test/x", "https:///x"]
    + [
        "https://example.test/x#frag",
        "https://example.test/a b",
        "https://example.test:99999/x",
        "https://example.test:abc/x",
    ],
)
def test_urls_must_be_plain_https(url):
    data = inventory()
    data["upstream_url"] = url
    rejected(data)


def test_duplicates_are_rejected():
    data = inventory()
    data["aliases"] = ["A-1", "A-1"]
    rejected(data, "aliases")
    data = inventory()
    data["artifacts"].append(dict(data["artifacts"][0]))
    rejected(data, "unique")
    data = inventory()
    data["slice_mappings"].append(dict(data["slice_mappings"][0]))
    rejected(data, "unique")
    data = inventory()
    data["oracle"]["controls"].append(data["oracle"]["controls"][0])
    rejected(data, "controls")
    data = inventory()
    data["synthetic_reviewer_paths"] = ["README.md", "README.md"]
    rejected(data, "unique")
    data = inventory()
    artifact(data, "fixed", "jwt/utils.py")["notice_paths"] = ["PEM-LICENSE.txt"] * 2
    rejected(data, "unique")


BAD_PATHS = ["", "../x", "/abs", "a//b", "a/./b", "a\\b", "C:x", ".git/config", "a\nb", "a/"]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_paths_must_be_canonical_relative_virtual_paths(path):
    data = inventory()
    artifact(data, "fixed", "LICENSE")["path"] = path
    rejected(data)
    data = inventory()
    data["slice_mappings"][0]["reviewer_path"] = path
    rejected(data)
    data = inventory()
    data["synthetic_reviewer_paths"] = [path]
    rejected(data)
    data = inventory()
    artifact(data, "fixed", "jwt/utils.py")["notice_paths"] = [path]
    rejected(data)


def test_hash_and_size_fields_are_strict():
    for key, value in (
        ("sha256", "A" * 64),
        ("sha256", "a" * 63),
        ("size", -1),
        ("size", True),
        ("size", "10"),
        ("size", 4 * 1024 * 1024 + 1),
        ("license", "MIT OR Apache-2.0"),
    ):
        data = inventory()
        artifact(data, "fixed", "jwt/utils.py")[key] = value
        rejected(data)
    data = inventory()
    data["oracle"]["sha256"] = "0" * 65
    rejected(data)


def test_license_and_notice_crossfields():
    data = inventory()
    artifact(data, "fixed", "jwt/utils.py")["license"] = "Apache-2.0"
    rejected(data, "match its license")
    for bad in ("NOPE", "jwt/utils.py", "PEM-LICENSE.txt"):
        data = inventory()
        artifact(data, "fixed", "jwt/utils.py")["license_path"] = bad
        rejected(data, "license artifact")
    for bad in ("NOPE", "LICENSE", "jwt/utils.py"):
        data = inventory()
        artifact(data, "fixed", "jwt/utils.py")["notice_paths"] = [bad]
        rejected(data, "notice artifact")
    data = inventory()
    artifact(data, "shared", "PEM-LICENSE.txt")["notice_paths"] = ["PEM-LICENSE.txt"]
    rejected(data, "license themselves")
    data = inventory()
    artifact(data, "fixed", "LICENSE")["license_path"] = "jwt/utils.py"
    rejected(data, "license themselves")


def test_each_variant_needs_source_and_license_artifacts():
    data = inventory()
    data["artifacts"] = [
        item
        for item in data["artifacts"]
        if not (item["variant"] == "fixed" and item["role"] == "license")
    ]
    rejected(data)


def test_mapping_and_modification_crossfields():
    data = inventory()
    data["slice_mappings"][0]["artifact_path"] = "missing.py"
    rejected(data, "existing artifact")
    data = inventory()
    data["slice_mappings"] = [m for m in data["slice_mappings"] if m["variant"] == "fixed"]
    rejected(data, "slice mappings")
    data = inventory()
    data["slice_mappings"][0]["transformation"] = "adapted"
    rejected(data, "agree")
    data = inventory()
    data["modifications"].append(
        {"kind": "content_edit", "description": "edit", "reviewer_paths": ["jwt/utils.py"]}
    )
    rejected(data, "agree")
    data = inventory()
    for mapping in data["slice_mappings"]:
        if mapping["reviewer_path"] == "jwt/utils.py":
            mapping["transformation"] = "adapted"
    data["modifications"].append(
        {"kind": "content_edit", "description": "edit", "reviewer_paths": ["jwt/utils.py"]}
    )
    rejected(data, "adapted content")
    data["provenance_kind"] = "adapted_upstream"
    assert parse_corpus_manifest(data).modifications[-1].kind == "content_edit"
    data = inventory()
    data["synthetic_reviewer_paths"].append("LICENSE")
    rejected(data, "collide")
    data = inventory()
    data["modifications"][0]["reviewer_paths"] = ["unmapped.txt"]
    rejected(data, "mapped or declared synthetic")
    data = inventory()
    data["synthetic_reviewer_paths"].append("NOTES.md")
    rejected(data, "synthetic file modification")
    data = inventory()
    data["modifications"][2]["reviewer_paths"] = ["LICENSE"]
    rejected(data)


def test_registered_pyjwt_reports_a_missing_lock_honestly():
    deps = inventory()["dependencies"]
    assert deps["lock_status"] == "missing"
    assert deps["lock_paths"] == []
    assert not any(entry["pinned_by"] == "upstream_lock" for entry in deps["entries"])


def test_dependency_lock_crossfields():
    data = inventory()
    data["dependencies"]["lock_status"] = "locked"
    rejected(data, "lock")
    data = inventory()
    data["dependencies"]["lock_paths"] = ["uv.lock"]
    rejected(data, "lock")
    data = inventory()
    data["dependencies"]["entries"][0]["pinned_by"] = "upstream_lock"
    rejected(data, "lock pins")
    data = inventory()
    data["dependencies"].update(lock_status="requirements_only", lock_paths=["LICENSE"])
    rejected(data, "lock artifacts")
    data = inventory()
    data["artifacts"].append(lock_artifact(data))
    rejected(data, "lock")
    data = inventory()
    data["artifacts"].append(lock_artifact(data))
    data["dependencies"].update(lock_status="locked", lock_paths=["poetry.lock"])
    data["dependencies"]["entries"][0]["pinned_by"] = "upstream_lock"
    assert parse_corpus_manifest(data).dependencies.lock_status == "locked"


def original_inventory():
    data = inventory()
    data.update(
        provenance_kind="original_calibration",
        upstream_url=None,
        advisory_url=None,
        revisions=None,
        aliases=[],
    )
    for item in data["artifacts"]:
        item["source_url"] = None
    return data


def test_registered_inventory_is_exact_upstream():
    assert inventory()["provenance_kind"] == "exact_upstream"


@pytest.mark.parametrize("value", ["upstream", "", None, True, "Exact_Upstream", 1])
def test_provenance_kind_is_a_closed_set(value):
    data = inventory()
    data["provenance_kind"] = value
    rejected(data)
    for kind in ("exact_upstream", "adapted_upstream"):
        data["provenance_kind"] = kind
        assert parse_corpus_manifest(data).provenance_kind == kind


def test_original_calibration_requires_explicit_null_pins():
    manifest = parse_corpus_manifest(original_inventory())
    assert manifest.upstream_url is None and manifest.revisions is None and manifest.aliases == ()
    claims = (
        ("upstream_url", "https://example.test/x"),
        ("advisory_url", "https://example.test/a"),
        ("revisions", {"vulnerable": "a" * 40, "fixed": "b" * 40}),
        ("aliases", ["A-1"]),
        ("disclosure_date", "2024-01-01"),
        ("fix_date", "2024-01-02"),
    )
    for key, value in claims:
        data = original_inventory()
        data[key] = value
        rejected(data)
    data = original_inventory()
    artifact(data, "fixed", "jwt/utils.py")["source_url"] = "https://example.test/x"
    rejected(data, "no upstream source URL")
    data = original_inventory()
    del data["upstream_url"]
    rejected(data)
    rejected(dict(inventory(), provenance_kind="original_calibration"))


@pytest.mark.parametrize("kind", ["exact_upstream", "adapted_upstream"])
def test_upstream_kinds_cannot_claim_missing_pins(kind):
    for key, value in (
        ("upstream_url", None),
        ("advisory_url", None),
        ("revisions", None),
        ("aliases", []),
    ):
        data = inventory()
        data["provenance_kind"] = kind
        data[key] = value
        rejected(data)
    for variant, path in (("fixed", "jwt/utils.py"), ("shared", "PEM-LICENSE.txt")):
        data = inventory()
        data["provenance_kind"] = kind
        artifact(data, variant, path)["source_url"] = None
        rejected(data)


@pytest.mark.parametrize("kind", ["exact_upstream", "adapted_upstream"])
def test_revision_must_be_a_url_path_segment(kind):
    revision = inventory()["revisions"]["fixed"]
    for url in (
        "https://example.test/x?ref=" + revision,
        "https://example.test/" + revision + "x/utils.py",
        "https://example.test/x" + revision + "/utils.py",
    ):
        data = inventory()
        data["provenance_kind"] = kind
        artifact(data, "fixed", "jwt/utils.py")["source_url"] = url
        rejected(data, "pinned revision")
    data = inventory()
    data["provenance_kind"] = kind
    artifact(data, "fixed", "jwt/utils.py")["source_url"] = (
        "https://example.test/" + revision + "/jwt/utils.py"
    )
    assert parse_corpus_manifest(data).provenance_kind == kind


def test_oracle_kind_allows_independent_python_test_without_execution():
    data = inventory()
    data["oracle"]["kind"] = "independent_python_test"
    assert parse_corpus_manifest(data).oracle.kind == "independent_python_test"
    data["oracle"]["kind"] = "shell"
    rejected(data)


@pytest.mark.parametrize("kind", ["independent_node_test", "independent_rust_test"])
def test_other_oracle_runtimes_are_metadata_with_explicit_limits(kind):
    data = inventory()
    data["oracle"]["kind"] = kind
    data["oracle"]["limitations"] = [
        "Unreproduced candidate; runtime compatibility and dependency resolution are unverified."
    ]
    manifest = parse_corpus_manifest(data)
    assert manifest.oracle.kind == kind
    assert manifest.oracle.os_sandboxed is False
    for bad in ([], [""], ["same", "same"]):
        data["oracle"]["limitations"] = bad
        rejected(data)


def test_artifacts_can_inventory_mixed_licenses_and_per_file_notices():
    data = inventory()
    for variant in ("vulnerable", "fixed"):
        archive_license = dict(artifact(data, variant, "LICENSE"))
        archive_license["path"] = archive_license["license_path"] = "licenses/python-archive.txt"
        archive_license["source_url"] = (
            f"https://example.test/{data['revisions'][variant]}/licenses/python-archive.txt"
        )
        data["artifacts"].append(archive_license)
        root_license = artifact(data, variant, "LICENSE")
        root_license["license"] = "BSD-3-Clause"
        for item in data["artifacts"]:
            if item["variant"] == variant and item["role"] == "source":
                if item["path"] == "jwt/utils.py":
                    item["license_path"] = "licenses/python-archive.txt"
                    item["notice_paths"] = ["PEM-LICENSE.txt"]
                else:
                    item["license"] = "BSD-3-Clause"
    manifest = parse_corpus_manifest(data)
    assert {item.license for item in manifest.artifacts} == {"MIT", "BSD-3-Clause"}
    assert manifest.validation_scope == "schema_and_inventory_only"


def test_large_rust_source_and_build_script_inventory_does_not_raise_runtime_cap():
    from review_boundary.repository_cases import RepositoryFile

    data = inventory()
    for variant in ("vulnerable", "fixed"):
        for path, size in (("src/read.rs", 71680), ("build.rs", 100)):
            source = dict(artifact(data, variant, "jwt/utils.py"))
            source.update(
                path=path,
                source_url=f"https://example.test/{data['revisions'][variant]}/{path}",
                size=size,
                notice_paths=[],
            )
            data["artifacts"].append(source)
    data["oracle"]["kind"] = "independent_rust_test"
    data["oracle"]["limitations"] = [
        "Cargo.lock is absent. build.rs is inventoried but has not been executed.",
        "The 71680-byte source exceeds suite v1's 65536-byte file cap; no suite is admitted.",
    ]
    manifest = parse_corpus_manifest(data)
    assert manifest.dependencies.lock_status == "missing"
    assert manifest.dependencies.lock_paths == ()
    assert any(item.path == "build.rs" for item in manifest.artifacts)
    assert any(item.size == 71680 for item in manifest.artifacts)
    with pytest.raises(ValidationError):
        RepositoryFile(path="src/read.rs", content="x\n" * 35840)
