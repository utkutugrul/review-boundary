"""Strict top-level repository suite envelope shared by every suite reader.

RepositoryCase stays the single runtime authority for case invariants. This module
only adds the exact schema v1 envelope, safe JSON loading and a derived JSON Schema.
Suite files are parsed as data and no candidate source is imported or executed.
"""

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .json_input import read_json_object
from .repository_cases import FrozenModel, RepositoryCase

MAX_REPOSITORY_SUITE_CASES = 32


class RepositorySuite(FrozenModel):
    schema_version: Literal[1]
    cases: tuple[RepositoryCase, ...] = Field(min_length=1, max_length=MAX_REPOSITORY_SUITE_CASES)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_integer_version(cls, value: Any) -> Any:
        # Literal matching alone can accept bool or integral float spellings of 1.
        if type(value) is not int:
            raise ValueError("schema_version must be the exact integer 1")
        return value

    @model_validator(mode="after")
    def unique_case_ids(self):
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Repository case IDs must be unique")
        return self


def parse_repository_suite(value: dict) -> RepositorySuite:
    """Validate an already-decoded JSON object, preserving strict runtime types.

    The value is re-encoded as JSON text so lists become tuples under strict validation
    while bool, float and null remain distinct from integers and strings.
    """
    if not isinstance(value, dict):
        raise ValueError("Repository suites must be JSON objects")  # noqa: TRY004
    try:
        raw = json.dumps(value, allow_nan=False)
    except (TypeError, RecursionError) as exc:
        raise ValueError("Repository suites must contain only JSON values") from exc
    except ValueError as exc:
        raise ValueError("Repository suites must contain only finite JSON values") from exc
    return RepositorySuite.model_validate_json(raw)


def load_repository_suite(path: Path) -> RepositorySuite:
    """Read a bounded suite file with the safe JSON parser, then validate it."""
    return parse_repository_suite(read_json_object(path))


def repository_suite_schema() -> dict:
    """Public JSON Schema derived from the model graph; cross-field checks stay in Python."""
    return RepositorySuite.model_json_schema()
