"""Separate versioned repository payload cases without changing the v1 contract."""

import json
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .payload_packs import PayloadRef
from .repository_cases import (
    FrozenModel,
    IssueRubric,
    RepositoryCase,
    RepositoryFile,
    ShortText,
    canonical_digest,
    utf8_size,
    virtual_path,
)

REPOSITORY_PAYLOAD_SCORING_VERSION = "repository-payload-v1"
RepositoryCarrier = Literal["readme", "pr", "inert_file", "filename", "code_comment", "tool_output"]
PayloadCondition = Literal["clean", "attack", "benign_quote"]
ExposureTool = Literal["read_pr", "list_files", "search_files", "read_file"]


class RepositoryExposureV2(FrozenModel):
    """Public carrier location and delivery marker, never an evaluator answer."""

    resource: ShortText
    marker: str = Field(min_length=1, max_length=4096)
    tool: ExposureTool | None = None
    untrusted_text: str | None = Field(default=None, min_length=1, max_length=4096)

    @field_validator("marker")
    @classmethod
    def meaningful_marker(cls, value: str) -> str:
        utf8_size(value, 4096)
        if not value.strip():
            raise ValueError("Exposure markers must contain non-whitespace text.")
        return value

    @field_validator("untrusted_text")
    @classmethod
    def bounded_untrusted_text(cls, value: str | None) -> str | None:
        return utf8_size(value, 4096) if value is not None else value


class RepositoryCaseV2(FrozenModel):
    """A bounded six-carrier case with explicit matched control identity."""

    case_schema_version: Literal[2]
    case_id: ShortText
    source_group: ShortText
    variant: Literal["vulnerable", "fixed"]
    surface: RepositoryCarrier
    condition: PayloadCondition
    instructions: str = Field(min_length=1, max_length=16384)
    task: str = Field(min_length=1, max_length=16384)
    pr: str = Field(min_length=1, max_length=16384)
    files: tuple[RepositoryFile, ...] = Field(min_length=1, max_length=128)
    issues: tuple[IssueRubric, ...] = Field(min_length=1, max_length=32)
    payload_ref: PayloadRef
    exposure: RepositoryExposureV2

    @field_validator("case_schema_version", mode="before")
    @classmethod
    def exact_integer_version(cls, value: Any) -> Any:
        if type(value) is not int or value != 2:
            raise ValueError("case_schema_version must be the exact integer 2.")
        return value

    @model_validator(mode="after")
    def coherent_snapshot(self):
        files = {item.path: item.content for item in self.files}
        if len(files) != len(self.files) or sum(len(v.encode()) for v in files.values()) > 524288:
            raise ValueError("Snapshot paths must be unique and content at most 524288 bytes.")
        if len({issue.issue_id for issue in self.issues}) != len(self.issues):
            raise ValueError("Issue identifiers must be unique.")
        for text in (self.case_id, self.source_group):
            utf8_size(text, 256)
        for text in (self.instructions, self.task, self.pr):
            utf8_size(text, 16384)
        for issue in self.issues:
            for bundle in issue.acceptable_bundles:
                for item in bundle.ranges:
                    if item.path not in files or item.end_line > len(files[item.path].splitlines()):
                        raise ValueError("Rubric evidence must refer to snapshot lines.")
        if self.payload_ref.carrier != self.surface or self.payload_ref.condition != self.condition:
            raise ValueError("Payload reference must match the case carrier and condition.")
        exposure = self.exposure
        if self.surface == "tool_output":
            if (
                exposure.resource != "tool_output"
                or exposure.tool is None
                or exposure.untrusted_text is None
                or exposure.marker not in exposure.untrusted_text
            ):
                raise ValueError(
                    "Tool output requires its designated tool and full untrusted text."
                )
            return self
        if exposure.tool is not None or exposure.untrusted_text is not None:
            raise ValueError("Only tool output may define a delivery tool or untrusted text.")
        if self.surface == "pr":
            if exposure.resource != "pull_request" or exposure.marker not in self.pr:
                raise ValueError("PR exposure must refer to a marker in the pull request.")
            return self
        virtual_path(exposure.resource)
        if exposure.resource not in files:
            raise ValueError("Exposure must refer to an existing snapshot path.")
        if self.surface == "readme" and exposure.resource != "README.md":
            raise ValueError("README exposure must refer to README.md.")
        if self.surface == "filename":
            if exposure.marker != exposure.resource:
                raise ValueError("Filename exposure requires the exact complete snapshot path.")
        elif exposure.marker not in files[exposure.resource]:
            raise ValueError("Exposure marker must exist in its public resource.")
        return self


def repository_case_v2_digest(case: RepositoryCaseV2) -> str:
    return canonical_digest(case)


def parse_repository_case(value: Any) -> RepositoryCase | RepositoryCaseV2:
    """Dispatch exact versions while retaining the original unversioned v1 format."""
    if isinstance(value, (RepositoryCase, RepositoryCaseV2)):
        # Revalidation also rejects instances made with unchecked model_copy updates.
        value = value.model_dump(mode="json")
    if not isinstance(value, dict):
        raise ValueError("Repository cases must be JSON objects.")  # noqa: TRY004
    if "case_schema_version" in value:
        if type(value["case_schema_version"]) is not int or value["case_schema_version"] != 2:
            raise ValueError("Unsupported repository case schema version.")
        model = RepositoryCaseV2
    else:
        model = RepositoryCase
    try:
        raw = json.dumps(value, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("Repository cases must contain finite JSON values.") from exc
    return model.model_validate_json(raw)
