"""The registry is static data plus bundled code. Manifests never select code to run."""

import ast
import dataclasses
import hashlib
import json
import shutil
import sys
import tomllib
from pathlib import Path

import pytest

from review_boundary import corpus_manifest, corpus_registry
from review_boundary import corpus_upstream_pyjwt as pyjwt
from review_boundary.cli import parser
from review_boundary.corpus_manifest import parse_corpus_manifest
from review_boundary.provenance import HARNESS_FILES, json_digest
from review_boundary.repository_cases import REPOSITORY_SCORING_VERSION, RepositoryCase


def test_registry_contains_only_pyjwt_with_preserved_versions():
    assert corpus_registry.corpus_names() == ("pyjwt",)
    registration = corpus_registry.get_corpus("pyjwt")
    assert registration.name == "pyjwt"
    assert registration.corpus_version == pyjwt.UPSTREAM_CORPUS_VERSION == "upstream-pyjwt-v1"
    assert registration.scoring_version == REPOSITORY_SCORING_VERSION
    assert registration.dependency_group == "upstream"


@pytest.mark.parametrize(
    "name",
    [
        "",
        "PyJWT",
        "pyjwt ",
        "../pyjwt",
        "os:system",
        "review_boundary.corpus_upstream_pyjwt",
        "pyjwt\0",
        None,
        3,
        ["pyjwt"],
    ],
)
def test_unknown_and_dynamic_names_are_refused(name):
    for function in (
        corpus_registry.get_corpus,
        corpus_registry.build_cases,
        corpus_registry.source_manifest,
        corpus_registry.verify_behavior,
        corpus_registry.evaluator_manifest,
    ):
        with pytest.raises(ValueError, match="Unknown upstream corpus"):
            function(name)


def test_registry_and_registrations_are_immutable():
    with pytest.raises(TypeError):
        corpus_registry._REGISTRY["extra"] = corpus_registry.get_corpus("pyjwt")
    with pytest.raises(TypeError):
        del corpus_registry._REGISTRY["pyjwt"]
    registration = corpus_registry.get_corpus("pyjwt")
    with pytest.raises(dataclasses.FrozenInstanceError):
        registration.name = "other"
    with pytest.raises(dataclasses.FrozenInstanceError):
        registration.build_cases = lambda: ()
    assert isinstance(corpus_registry.corpus_names(), tuple)


def test_original_source_manifest_is_unchanged_and_still_anchored():
    raw = (pyjwt.FIXTURE_ROOT / "manifest.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == pyjwt.MANIFEST_SHA256
    manifest = corpus_registry.source_manifest("pyjwt")
    assert manifest == pyjwt.source_manifest() == json.loads(raw)
    assert set(manifest) == {
        "additional_notices",
        "advisory",
        "license",
        "schema_version",
        "snapshots",
        "source_group",
        "upstream_repository",
    }


def test_registry_builds_the_existing_cases():
    assert corpus_registry.build_cases("pyjwt") == pyjwt.build_upstream_pyjwt_cases()


@pytest.mark.parametrize("function", ["source_manifest", "build_cases", "evaluator_manifest"])
def test_snapshot_tampering_is_rejected_by_every_registry_entry(tmp_path, monkeypatch, function):
    destination = tmp_path / "pyjwt"
    shutil.copytree(pyjwt.FIXTURE_ROOT, destination)
    monkeypatch.setattr(pyjwt, "FIXTURE_ROOT", destination)
    (destination / "vulnerable" / "jwt" / "algorithms.py.txt").write_text("print('changed')\n")
    with pytest.raises(ValueError, match="source content changed"):
        getattr(corpus_registry, function)("pyjwt")


@pytest.mark.parametrize("function", ["source_manifest", "build_cases", "evaluator_manifest"])
def test_coordinated_tampering_cannot_reanchor_the_enriched_manifest(
    tmp_path, monkeypatch, function
):
    destination = tmp_path / "pyjwt"
    shutil.copytree(pyjwt.FIXTURE_ROOT, destination)
    monkeypatch.setattr(pyjwt, "FIXTURE_ROOT", destination)
    changed = b"print('coordinated')\n"
    (destination / "vulnerable" / "jwt" / "algorithms.py.txt").write_bytes(changed)
    path = destination / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["snapshots"]["vulnerable"]["files"]["jwt/algorithms.py"].update(
        bytes=len(changed), sha256=hashlib.sha256(changed).hexdigest()
    )
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="source manifest changed"):
        getattr(corpus_registry, function)("pyjwt")


def test_evaluator_manifest_inventory_matches_anchored_source_and_code():
    source = pyjwt.source_manifest()
    document = corpus_registry.evaluator_manifest("pyjwt")
    inventory = document["inventory"]
    parsed = parse_corpus_manifest(inventory)
    assert parsed.model_dump(mode="json") == inventory
    assert document["scope"] == "evaluator_only"
    assert document["inventory_sha256"] == json_digest(inventory)
    assert document["authority"]["source_manifest_sha256"] == pyjwt.MANIFEST_SHA256
    assert document["layers"]["admission"] == "not_decided_by_this_manifest"
    assert document["layers"]["behavior_oracle"] == "not_run_by_this_manifest"
    assert inventory["validation_scope"] == "schema_and_inventory_only"
    assert inventory["revisions"] == pyjwt.REVISIONS
    assert inventory["source_group"] == pyjwt.SOURCE_GROUP
    assert inventory["upstream_url"] == source["upstream_repository"]
    assert inventory["advisory_url"] == source["advisory"]
    assert inventory["aliases"] == ["GHSA-ffqj-6fqr-9h24"]
    assert inventory["disclosure_date"] is None and inventory["fix_date"] is None
    assert inventory["split"] == "development"
    assert inventory["oracle"]["sha256"] == hashlib.sha256(pyjwt._ORACLE.encode()).hexdigest()
    assert inventory["oracle"]["os_sandboxed"] is False
    assert inventory["dependencies"]["lock_status"] == "missing"
    shared = [item for item in inventory["artifacts"] if item["variant"] == "shared"]
    assert len(inventory["artifacts"]) == 2 * len({*pyjwt.PACKAGE_PATHS, "LICENSE"}) + 1
    notice = source["additional_notices"][0]
    assert [(item["path"], item["sha256"], item["source_url"]) for item in shared] == [
        (notice["path"], notice["sha256"], notice["url"])
    ]
    for item in inventory["artifacts"]:
        if item["variant"] == "shared":
            continue
        expected = source["snapshots"][item["variant"]]["files"][item["path"]]
        assert (item["sha256"], item["size"], item["source_url"]) == (
            expected["sha256"],
            expected["bytes"],
            expected["url"],
        )
        assert item["license"] == source["license"]


def test_notice_is_attached_only_to_the_artifact_that_needs_it():
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    with_notices = {
        (item["variant"], item["path"]): item["notice_paths"]
        for item in inventory["artifacts"]
        if item["notice_paths"]
    }
    assert with_notices == {("fixed", "jwt/utils.py"): ["PEM-LICENSE.txt"]}


def test_oracle_dependency_pin_matches_the_packaged_project_requirement():
    with (Path(__file__).parents[1] / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    requirements = project["project"]["optional-dependencies"]["upstream"]
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    dependency = next(
        item for item in inventory["dependencies"]["entries"] if item["name"] == "cryptography"
    )
    assert dependency["name"] + dependency["specifier"] in requirements
    assert dependency["pinned_by"] == "harness_lock"


def test_public_suite_and_reviewer_fields_exclude_evaluator_metadata():
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    cases = corpus_registry.build_cases("pyjwt")
    suite = json.dumps({"schema_version": 1, "cases": [c.model_dump(mode="json") for c in cases]})
    private = [
        inventory["upstream_url"],
        inventory["advisory_url"],
        *inventory["revisions"].values(),
        inventory["oracle"]["sha256"],
        inventory["oracle"]["oracle_id"],
        *inventory["aliases"],
        *(item["source_url"] for item in inventory["artifacts"]),
        *(item["sha256"] for item in inventory["artifacts"] if item["role"] == "notice"),
    ]
    for value in private:
        assert value not in suite
    assert not set(RepositoryCase.model_fields) & {
        "aliases",
        "upstream_url",
        "advisory_url",
        "revisions",
        "artifacts",
        "oracle",
        "split",
        "license",
        "slice_mappings",
    }


def test_verbatim_mappings_match_reviewer_files_byte_for_byte():
    inventory = corpus_registry.evaluator_manifest("pyjwt")["inventory"]
    artifacts = {(item["variant"], item["path"]): item for item in inventory["artifacts"]}
    for case in corpus_registry.build_cases("pyjwt"):
        files = {file.path: file.content for file in case.files}
        mappings = [m for m in inventory["slice_mappings"] if m["variant"] == case.variant]
        for mapping in mappings:
            assert mapping["transformation"] == "verbatim"
            owner = (
                artifacts.get((case.variant, mapping["artifact_path"]))
                or artifacts[("shared", mapping["artifact_path"])]
            )
            content = files[mapping["reviewer_path"]].encode()
            assert hashlib.sha256(content).hexdigest() == owner["sha256"]
            assert len(content) == owner["size"]
        mapped = {m["reviewer_path"] for m in mappings}
        assert set(files) == mapped | set(inventory["synthetic_reviewer_paths"])


def test_registry_reads_data_and_imports_no_candidate_code(monkeypatch):
    def refuse():
        raise AssertionError("The behavior oracle must run only on explicit request.")

    monkeypatch.setattr(pyjwt, "reproduce_upstream_pyjwt", refuse)
    before = set(sys.modules)
    corpus_registry.source_manifest("pyjwt")
    corpus_registry.build_cases("pyjwt")
    corpus_registry.evaluator_manifest("pyjwt")
    added = set(sys.modules) - before
    assert not [name for name in added if name == "jwt" or name.startswith("jwt.")]
    root = str(pyjwt.FIXTURE_ROOT)
    for module in list(sys.modules.values()):
        assert not str(getattr(module, "__file__", None) or "").startswith(root)
    for module in (corpus_registry, corpus_manifest):
        tree = ast.parse(Path(module.__file__).read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not {name.name.split(".")[0] for name in node.names} & {
                    "importlib",
                    "subprocess",
                    "pickle",
                }
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in {
                    "importlib",
                    "subprocess",
                    "pickle",
                }
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"exec", "eval", "__import__"}


def test_verify_behavior_delegates_to_the_pyjwt_module_verifier(monkeypatch):
    monkeypatch.setattr(pyjwt, "reproduce_upstream_pyjwt", lambda: {"reproduced": True})
    assert corpus_registry.verify_behavior("pyjwt") == {"reproduced": True}


def test_cli_choices_come_from_the_registry():
    root = parser()
    assert root.parse_args(["corpus-export", "--corpus", "pyjwt", "--output", "x"]).corpus == (
        "pyjwt"
    )
    with pytest.raises(SystemExit):
        root.parse_args(["corpus-export", "--corpus", "other", "--output", "x"])


def test_new_runtime_modules_are_fingerprinted_and_within_the_source_limit():
    base = Path(corpus_registry.__file__).parent
    assert {"corpus_manifest.py", "corpus_registry.py"} <= set(HARNESS_FILES)
    from review_boundary.provenance import MAX_HARNESS_FILES

    assert len(HARNESS_FILES) == len(set(HARNESS_FILES)) <= MAX_HARNESS_FILES
    assert all((base / name).is_file() for name in HARNESS_FILES)
