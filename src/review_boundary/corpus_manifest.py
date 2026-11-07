"""Strict evaluator-only provenance and license inventory for upstream corpora.

Parsing a ``CorpusManifest`` checks structure and cross-field consistency only. It does not
authenticate artifact bytes, decide corpus admission, or run a behavior oracle. Authenticity
comes from the pinned source manifest that each corpus module verifies against code anchors.
The hashes recorded here are descriptive inventory values, never an authority on their own.
Nothing in this module may be copied into reviewer-visible suites, tasks or files.
"""

import re
from datetime import date
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from .repository_cases import virtual_path

CORPUS_MANIFEST_SCHEMA_VERSION = 1
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024

_SHA256 = re.compile(r"[0-9a-f]{64}")
_REVISION = re.compile(r"[0-9a-f]{40}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_LICENSE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_GROUP = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _pattern(expression: re.Pattern, message: str):
    def check(value: str) -> str:
        if not expression.fullmatch(value):
            raise ValueError(message)
        return value

    return check


def _text(value: str) -> str:
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Text must not contain control characters.")
    return value


def _https_url(value: str) -> str:
    message = "Expected a bounded https URL without credentials or fragment."
    try:
        parts = urlsplit(value)
        hostname = parts.hostname
        # Accessing port validates its syntax and range; nothing is fetched.
        _ = parts.port
    except ValueError:
        # urllib may include a malformed host in its error. Never relay candidate text.
        raise ValueError(message) from None
    if (
        len(value) > 512
        or any(ord(char) <= 32 or ord(char) == 127 for char in value)
        or parts.scheme != "https"
        or not hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
    ):
        raise ValueError(message)
    return value


def _optional_https_url(value: str | None) -> str | None:
    return None if value is None else _https_url(value)


def _names_revision(url: str, revision: str) -> bool:
    """A pinned revision must be a whole URL path segment, never a query or substring."""
    return revision in urlsplit(url).path.split("/")


def _iso_date(value: str | None) -> str | None:
    if value is None:
        return None
    if not _DATE.fullmatch(value):
        raise ValueError("Expected YYYY-MM-DD or an explicit null.")
    try:
        date.fromisoformat(value)
    except ValueError:
        raise ValueError("Expected a real calendar date or an explicit null.") from None
    return value


def _unique(values, message: str) -> None:
    values = list(values)
    if len(set(values)) != len(values):
        raise ValueError(message)


Text = Annotated[StrictStr, Field(min_length=1, max_length=256), AfterValidator(_text)]
Sha256 = Annotated[
    StrictStr, AfterValidator(_pattern(_SHA256, "Expected a lowercase SHA-256 hex digest."))
]
Revision = Annotated[
    StrictStr,
    AfterValidator(_pattern(_REVISION, "Expected a full lowercase 40 character revision.")),
]
Alias = Annotated[
    StrictStr, AfterValidator(_pattern(_ALIAS, "Expected a bounded advisory identifier."))
]
LicenseId = Annotated[
    StrictStr, AfterValidator(_pattern(_LICENSE, "Expected one SPDX license identifier."))
]
HttpsUrl = Annotated[StrictStr, AfterValidator(_https_url)]
ArtifactPath = Annotated[
    StrictStr, Field(min_length=1, max_length=512), AfterValidator(virtual_path)
]
OptionalDate = Annotated[StrictStr | None, AfterValidator(_iso_date)]
OptionalHttpsUrl = Annotated[StrictStr | None, AfterValidator(_optional_https_url)]


class _Model(BaseModel):
    """Frozen and extra-forbidding. Scalars are strict. Containers accept JSON lists."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)


class RevisionPair(_Model):
    vulnerable: Revision
    fixed: Revision

    @model_validator(mode="after")
    def distinct(self):
        if self.vulnerable == self.fixed:
            raise ValueError("Vulnerable and fixed revisions must differ.")
        return self


class ArtifactRecord(_Model):
    variant: Literal["vulnerable", "fixed", "shared"]
    path: ArtifactPath
    role: Literal["source", "license", "notice", "lock"]
    source_url: OptionalHttpsUrl
    sha256: Sha256
    size: Annotated[StrictInt, Field(ge=0, le=MAX_ARTIFACT_BYTES)]
    license: LicenseId
    license_path: ArtifactPath
    notice_paths: Annotated[tuple[ArtifactPath, ...], Field(max_length=8)]

    @model_validator(mode="after")
    def shape(self):
        _unique(self.notice_paths, "Artifact notice paths must be unique.")
        if self.role in ("license", "notice") and (
            self.license_path != self.path or self.notice_paths
        ):
            raise ValueError(
                "License and notice artifacts license themselves and carry no notices."
            )
        return self


class DependencyEntry(_Model):
    name: Text
    scope: Literal["upstream_runtime", "oracle_runtime"]
    specifier: Text | None
    pinned_by: Literal["upstream_lock", "harness_lock", "unpinned"]


class DependencyInventory(_Model):
    lock_status: Literal["locked", "requirements_only", "missing"]
    lock_paths: Annotated[tuple[ArtifactPath, ...], Field(max_length=16)]
    entries: Annotated[tuple[DependencyEntry, ...], Field(max_length=64)]
    note: Text

    @model_validator(mode="after")
    def honest_status(self):
        _unique(self.lock_paths, "Lock paths must be unique.")
        _unique(((item.name, item.scope) for item in self.entries), "Dependencies must be unique.")
        if (self.lock_status == "missing") == bool(self.lock_paths):
            raise ValueError("A missing lock lists no lock paths, any other status lists some.")
        if self.lock_status != "locked" and any(
            item.pinned_by == "upstream_lock" for item in self.entries
        ):
            raise ValueError("Only a locked inventory may claim upstream lock pins.")
        return self


class SliceMapping(_Model):
    variant: Literal["vulnerable", "fixed"]
    artifact_path: ArtifactPath
    reviewer_path: ArtifactPath
    transformation: Literal["verbatim", "adapted"]


class Modification(_Model):
    kind: Literal["storage_suffix", "relocation", "synthetic_file", "content_edit"]
    description: Text
    reviewer_paths: Annotated[tuple[ArtifactPath, ...], Field(max_length=64)]


class OracleIdentity(_Model):
    oracle_id: Text
    sha256: Sha256
    kind: Literal[
        "isolated_python_subprocess",
        "independent_python_test",
        "independent_node_test",
        "independent_rust_test",
    ]
    os_sandboxed: StrictBool
    controls: Annotated[tuple[Text, ...], Field(min_length=1, max_length=32)]
    limitations: Annotated[tuple[Text, ...], Field(min_length=1, max_length=16)]

    @field_validator("controls", "limitations")
    @classmethod
    def distinct_controls(cls, value):
        _unique(value, "Oracle controls and limitations must each be unique.")
        return value


class CorpusManifest(_Model):
    schema_version: StrictInt
    corpus_name: Annotated[
        StrictStr, AfterValidator(_pattern(_NAME, "Expected a lowercase corpus name."))
    ]
    corpus_version: Text
    scoring_version: Text
    provenance_kind: Literal["exact_upstream", "adapted_upstream", "original_calibration"]
    upstream_url: OptionalHttpsUrl
    advisory_url: OptionalHttpsUrl
    aliases: Annotated[tuple[Alias, ...], Field(max_length=16)]
    disclosure_date: OptionalDate
    fix_date: OptionalDate
    source_group: Annotated[
        StrictStr, AfterValidator(_pattern(_GROUP, "Expected a bounded source group."))
    ]
    split: Literal["development", "held_out"]
    revisions: RevisionPair | None
    artifacts: Annotated[tuple[ArtifactRecord, ...], Field(min_length=1, max_length=256)]
    dependencies: DependencyInventory
    slice_mappings: Annotated[tuple[SliceMapping, ...], Field(min_length=1, max_length=512)]
    synthetic_reviewer_paths: Annotated[tuple[ArtifactPath, ...], Field(max_length=64)]
    modifications: Annotated[tuple[Modification, ...], Field(max_length=64)]
    oracle: OracleIdentity
    validation_scope: Literal["schema_and_inventory_only"]

    @field_validator("schema_version")
    @classmethod
    def known_version(cls, value):
        if value != CORPUS_MANIFEST_SCHEMA_VERSION:
            raise ValueError("Unsupported corpus manifest schema version.")
        return value

    @model_validator(mode="after")
    def cross_fields(self):
        _unique(self.aliases, "Advisory aliases must be unique.")
        original = self.provenance_kind == "original_calibration"
        if original:
            if (
                self.upstream_url is not None
                or self.advisory_url is not None
                or self.revisions is not None
            ):
                raise ValueError(
                    "Original calibration manifests declare null upstream URLs and revisions."
                )
            if self.aliases or self.disclosure_date is not None or self.fix_date is not None:
                raise ValueError("Original calibration manifests declare no aliases or dates.")
            if any(
                item.source_url is not None and item.variant != "shared" for item in self.artifacts
            ):
                raise ValueError("Original calibration artifacts name no upstream source URL.")
        else:
            if self.upstream_url is None or self.advisory_url is None or self.revisions is None:
                raise ValueError(
                    "Upstream manifests require upstream and advisory URLs and pinned revisions."
                )
            if not self.aliases:
                raise ValueError("Upstream manifests require at least one advisory alias.")
            if any(item.source_url is None for item in self.artifacts):
                raise ValueError("Upstream artifacts require a source URL.")
        keys = [(item.variant, item.path) for item in self.artifacts]
        _unique(keys, "Artifact variant and path pairs must be unique.")
        by_key = dict(zip(keys, self.artifacts, strict=True))

        def find(variant: str, path: str, *roles: str):
            found = by_key.get((variant, path)) or by_key.get(("shared", path))
            return found if found is not None and (not roles or found.role in roles) else None

        for item in self.artifacts:
            if (
                not original
                and item.variant != "shared"
                and not _names_revision(item.source_url, getattr(self.revisions, item.variant))
            ):
                raise ValueError("Artifact URL must name the pinned revision.")
            if item.role in ("source", "lock"):
                licence = find(item.variant, item.license_path, "license")
                if licence is None:
                    raise ValueError(
                        "Artifact license path must name a license artifact for its variant "
                        "or a shared one."
                    )
                if licence.license != item.license:
                    raise ValueError("Artifact license must match its license artifact.")
                for notice in item.notice_paths:
                    if find(item.variant, notice, "notice") is None:
                        raise ValueError(
                            "Artifact notice path must name a notice artifact for its variant "
                            "or a shared one."
                        )
        sourced = {item.variant for item in self.artifacts if item.role == "source"}
        licensed = {item.variant for item in self.artifacts if item.role == "license"}
        if not {"vulnerable", "fixed"} <= sourced or not {"vulnerable", "fixed"} <= licensed:
            raise ValueError("Both revision variants need source and license artifacts.")

        lock_paths = {item.path for item in self.artifacts if item.role == "lock"}
        if not set(self.dependencies.lock_paths) <= lock_paths or (
            lock_paths and self.dependencies.lock_status == "missing"
        ):
            raise ValueError("Dependency lock paths must name lock artifacts and agree on status.")
        if lock_paths and not set(self.dependencies.lock_paths) == lock_paths:
            raise ValueError("Every lock artifact must be listed in the dependency inventory.")

        mapped = [(item.variant, item.reviewer_path) for item in self.slice_mappings]
        _unique(mapped, "Reviewer paths must be unique per variant.")
        for item in self.slice_mappings:
            if find(item.variant, item.artifact_path, "source", "license", "notice") is None:
                raise ValueError("Slice mapping must name an existing artifact.")
        if {variant for variant, _ in mapped} != {"vulnerable", "fixed"}:
            raise ValueError("Both revision variants need slice mappings.")
        mapped_paths = {path for _, path in mapped}
        _unique(self.synthetic_reviewer_paths, "Synthetic reviewer paths must be unique.")
        synthetic = set(self.synthetic_reviewer_paths)
        if synthetic & mapped_paths:
            raise ValueError("Synthetic reviewer paths must not collide with mapped paths.")
        edited, declared = set(), set()
        for item in self.modifications:
            paths = set(item.reviewer_paths)
            if not paths <= mapped_paths | synthetic:
                raise ValueError("Modification paths must be mapped or declared synthetic.")
            if item.kind == "synthetic_file":
                if not paths or not paths <= synthetic:
                    raise ValueError("Synthetic file modifications must name synthetic paths.")
                declared |= paths
            elif paths & synthetic:
                raise ValueError("Only synthetic file modifications may name synthetic paths.")
            if item.kind == "content_edit":
                if not paths:
                    raise ValueError("Content edits must name reviewer paths.")
                edited |= paths
        if declared != synthetic:
            raise ValueError("Every synthetic reviewer path needs a synthetic file modification.")
        adapted = {
            item.reviewer_path for item in self.slice_mappings if item.transformation == "adapted"
        }
        if adapted != edited:
            raise ValueError("Adapted mappings and content edit modifications must agree.")
        if self.provenance_kind == "exact_upstream" and (adapted or edited):
            raise ValueError("Exact upstream manifests contain no adapted content.")
        return self


def parse_corpus_manifest(value: dict) -> CorpusManifest:
    """Validate an inventory document. This is not admission or content authentication."""
    if not isinstance(value, dict):
        raise ValueError("A corpus manifest must be a JSON object.")  # noqa: TRY004
    return CorpusManifest.model_validate(value)
