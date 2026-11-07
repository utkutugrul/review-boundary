"""Static registry of bundled upstream corpora.

Names map to code that is imported at the top of this module. Manifests are data only: no
manifest field selects, loads or runs code. The original pinned source manifest and its
anchored hash remain the authority. The enriched evaluator manifest is regenerated from
those verified bytes and code constants on every call, and its own hashes prove nothing.
"""

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from . import corpus_upstream_pyjwt as pyjwt
from .corpus_manifest import (
    CORPUS_MANIFEST_SCHEMA_VERSION,
    ArtifactRecord,
    CorpusManifest,
    DependencyEntry,
    DependencyInventory,
    Modification,
    OracleIdentity,
    RevisionPair,
    SliceMapping,
)
from .provenance import json_digest
from .repository_cases import REPOSITORY_SCORING_VERSION, RepositoryCase
from .repository_cases_v2 import RepositoryCaseV2
from .repository_runner import (
    repository_profile,
    repository_scoring_version,
    repository_suite_version,
)
from .repository_runtime import parse_repository_case

RepositoryCaseLike = RepositoryCase | RepositoryCaseV2
MAX_REGISTERED_CASES = 1024

NOTICE_PATH = "PEM-LICENSE.txt"
NOTICE_REVIEWER_PATH = "THIRD_PARTY_LICENSES.txt"
_PYJWT_ALIASES = ("GHSA-ffqj-6fqr-9h24",)
_PYJWT_CONTROLS = (
    "Valid HS256 token accepted with its HMAC secret.",
    "HS256 token rejected under a wrong HMAC secret.",
    "Genuine EdDSA and ES256 tokens accepted for an asymmetric-only allowlist.",
    "Genuine EdDSA and ES256 tokens accepted when HS256 is also allowed.",
    "Forged HMAC tokens rejected when only the asymmetric algorithm is allowed.",
    "Network access, file writes and host file reads are denied by Python audit hooks.",
)


@dataclass(frozen=True, slots=True)
class CorpusRegistration:
    name: str
    corpus_version: str
    scoring_version: str
    dependency_group: str | None
    scope: str
    build_cases: Callable[[], tuple[RepositoryCaseLike, ...]]
    source_manifest: Callable[[], dict]
    verify_behavior: Callable[[], dict]
    evaluator_manifest: Callable[[], dict]
    package_inventory: Callable[[], tuple[Path, tuple[str, ...]]]
    suite_schema_version: int = 1

    def __post_init__(self):
        if type(self.suite_schema_version) is not int or self.suite_schema_version not in (1, 2):
            raise ValueError("Registered suite schema version must be the exact integer 1 or 2")


@dataclass(frozen=True, slots=True)
class RegisteredSuiteContract:
    schema_version: int
    scoring_version: str
    protocol: str


def registration_suite_contract(
    registration: CorpusRegistration, cases: tuple[RepositoryCaseLike, ...]
) -> RegisteredSuiteContract:
    """Derive a trusted registration's suite contract from its checked case versions."""
    if type(cases) is not tuple or not 1 <= len(cases) <= MAX_REGISTERED_CASES:
        raise ValueError("Registered cases must be a tuple of 1 to 1024 cases")
    if any(type(case) not in (RepositoryCase, RepositoryCaseV2) for case in cases):
        raise ValueError("Registered cases require exact supported case models")
    schema_version = repository_suite_version(cases)
    scoring_version = repository_scoring_version(cases)
    if (
        type(registration.suite_schema_version) is not int
        or registration.suite_schema_version != schema_version
        or registration.scoring_version != scoring_version
    ):
        raise ValueError("Registered suite schema or scoring version does not match its cases")
    return RegisteredSuiteContract(
        schema_version, scoring_version, repository_profile(schema_version=schema_version).protocol
    )


def checked_registered_cases(registration: CorpusRegistration) -> tuple[RepositoryCaseLike, ...]:
    """Check static builder results without accepting iterators or unchecked model updates."""
    cases = registration.build_cases()
    # Bound the tuple before inspecting or serializing any case.
    if type(cases) is not tuple or not 1 <= len(cases) <= MAX_REGISTERED_CASES:
        raise ValueError("Registered cases must be a tuple of 1 to 1024 cases")
    if any(type(case) not in (RepositoryCase, RepositoryCaseV2) for case in cases):
        raise ValueError("Registered cases require exact supported case models")
    checked = tuple(parse_repository_case(case) for case in cases)
    if len({case.case_id for case in checked}) != len(checked):
        raise ValueError("Registered case IDs must be unique")
    registration_suite_contract(registration, checked)
    return checked


def _pyjwt_cases() -> tuple[RepositoryCase, ...]:
    return pyjwt.build_upstream_pyjwt_cases()


def _pyjwt_source() -> dict:
    return pyjwt.source_manifest()


def _pyjwt_verify() -> dict:
    return pyjwt.reproduce_upstream_pyjwt()


def _pyjwt_package_inventory() -> tuple[Path, tuple[str, ...]]:
    source = pyjwt.source_manifest()
    expected = {
        "manifest.json",
        *(item["path"] for item in source["additional_notices"]),
        *(
            f"{variant}/{path}.txt"
            for variant, snapshot in source["snapshots"].items()
            for path in snapshot["files"]
        ),
    }
    return pyjwt.FIXTURE_ROOT, tuple(sorted(expected))


def _pyjwt_inventory() -> CorpusManifest:
    """Describe the anchored bytes. Verification happens first and any mismatch raises."""
    source, _, notice_bytes = pyjwt._verified_corpus()
    notice = source["additional_notices"][0]
    artifacts, mappings = [], []
    for variant in pyjwt.REVISIONS:
        files = source["snapshots"][variant]["files"]
        for path in (*pyjwt.PACKAGE_PATHS, "LICENSE"):
            record = files[path]
            artifacts.append(
                ArtifactRecord(
                    variant=variant,
                    path=path,
                    role="license" if path == "LICENSE" else "source",
                    source_url=record["url"],
                    sha256=record["sha256"],
                    size=record["bytes"],
                    license=source["license"],
                    license_path="LICENSE",
                    notice_paths=(NOTICE_PATH,)
                    if variant == "fixed" and path == "jwt/utils.py"
                    else (),
                )
            )
            mappings.append(
                SliceMapping(
                    variant=variant,
                    artifact_path=path,
                    reviewer_path=path,
                    transformation="verbatim",
                )
            )
        mappings.append(
            SliceMapping(
                variant=variant,
                artifact_path=NOTICE_PATH,
                reviewer_path=NOTICE_REVIEWER_PATH,
                transformation="verbatim",
            )
        )
    artifacts.append(
        ArtifactRecord(
            variant="shared",
            path=NOTICE_PATH,
            role="notice",
            source_url=notice["url"],
            sha256=notice["sha256"],
            size=len(notice_bytes),
            license=notice["license"],
            license_path=NOTICE_PATH,
            notice_paths=(),
        )
    )
    return CorpusManifest(
        schema_version=CORPUS_MANIFEST_SCHEMA_VERSION,
        corpus_name="pyjwt",
        corpus_version=pyjwt.UPSTREAM_CORPUS_VERSION,
        scoring_version=REPOSITORY_SCORING_VERSION,
        provenance_kind="exact_upstream",
        upstream_url=source["upstream_repository"],
        advisory_url=source["advisory"],
        aliases=_PYJWT_ALIASES,
        # Not recorded in the pinned source manifest. Unknown stays explicit null.
        disclosure_date=None,
        fix_date=None,
        source_group=pyjwt.SOURCE_GROUP,
        split="development",
        revisions=RevisionPair(**pyjwt.REVISIONS),
        artifacts=tuple(artifacts),
        dependencies=DependencyInventory(
            lock_status="missing",
            lock_paths=(),
            entries=(
                DependencyEntry(
                    name="cryptography",
                    scope="oracle_runtime",
                    specifier="==50.0.2",
                    pinned_by="harness_lock",
                ),
            ),
            note=(
                "No upstream lock or requirements file is inventoried for these snapshots and "
                "none is inferred. Upstream dependency resolution is not reproduced."
            ),
        ),
        slice_mappings=tuple(mappings),
        synthetic_reviewer_paths=("README.md",),
        modifications=(
            Modification(
                kind="storage_suffix",
                description="Fixtures are stored with an appended .txt suffix. Reviewer paths "
                "and contents are unchanged.",
                reviewer_paths=(),
            ),
            Modification(
                kind="relocation",
                description="The additional PEM notice is presented as THIRD_PARTY_LICENSES.txt "
                "in both conditions.",
                reviewer_paths=(NOTICE_REVIEWER_PATH,),
            ),
            Modification(
                kind="synthetic_file",
                description="README.md is synthetic benchmark text with an optional untrusted "
                "marker. It is not upstream content.",
                reviewer_paths=("README.md",),
            ),
        ),
        oracle=OracleIdentity(
            oracle_id=pyjwt.UPSTREAM_CORPUS_VERSION + "-key-confusion-oracle",
            sha256=hashlib.sha256(pyjwt._ORACLE.encode()).hexdigest(),
            kind="isolated_python_subprocess",
            os_sandboxed=False,
            controls=_PYJWT_CONTROLS,
            limitations=(
                "Audit hooks and resource limits are not an OS sandbox.",
                (
                    "The oracle covers this pinned package slice and uses the harness dependency "
                    "lock; it does not reproduce upstream dependency resolution or a full "
                    "repository build."
                ),
            ),
        ),
        validation_scope="schema_and_inventory_only",
    )


def _pyjwt_evaluator_manifest() -> dict:
    inventory = _pyjwt_inventory().model_dump(mode="json")
    return {
        "schema_version": CORPUS_MANIFEST_SCHEMA_VERSION,
        "scope": "evaluator_only",
        "inventory": inventory,
        "inventory_sha256": json_digest(inventory),
        "authority": {
            "source_manifest_sha256": pyjwt.MANIFEST_SHA256,
            "note": "The anchored hash in code and the original source manifest are the "
            "authority. inventory_sha256 only fingerprints this document.",
        },
        "layers": {
            "schema_and_inventory": "validated",
            "content_authentication": "anchored_source_manifest_and_fixture_bytes_verified",
            "behavior_oracle": "not_run_by_this_manifest",
            "admission": "not_decided_by_this_manifest",
        },
    }


_REGISTRY = MappingProxyType(
    {
        "pyjwt": CorpusRegistration(
            name="pyjwt",
            corpus_version=pyjwt.UPSTREAM_CORPUS_VERSION,
            scoring_version=REPOSITORY_SCORING_VERSION,
            dependency_group="upstream",
            scope="Complete pinned jwt package. Four conditions from one public source issue.",
            build_cases=_pyjwt_cases,
            source_manifest=_pyjwt_source,
            verify_behavior=_pyjwt_verify,
            evaluator_manifest=_pyjwt_evaluator_manifest,
            package_inventory=_pyjwt_package_inventory,
        )
    }
)


def corpus_names() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def get_corpus(name: str) -> CorpusRegistration:
    if not isinstance(name, str) or name not in _REGISTRY:
        raise ValueError("Unknown upstream corpus")
    return _REGISTRY[name]


def build_cases(name: str) -> tuple[RepositoryCaseLike, ...]:
    return get_corpus(name).build_cases()


def source_manifest(name: str) -> dict:
    return get_corpus(name).source_manifest()


def verify_behavior(name: str) -> dict:
    return get_corpus(name).verify_behavior()


def evaluator_manifest(name: str) -> dict:
    return get_corpus(name).evaluator_manifest()
