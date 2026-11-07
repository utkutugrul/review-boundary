"""Deterministic, pure sharding of repository cases into atomic source-group suites.

Cases are grouped solely by their unchanged ``source_group`` value. Groups are sorted
lexicographically, cases inside a group by ``case_id``, and whole groups are packed in that
order into suites of at most 32 cases. A group is never split, no group is ever merged
into a case, and nothing is inferred from case IDs, payload labels or variants. No case is
truncated, transformed or fetched, and no registry, runner, scorer or SDK is involved.

Byte accounting: every suite is measured exactly as it would be written (indent 2, no ASCII
escaping, one trailing newline, UTF-8). Each suite must fit MAX_REPORT_BYTES and the sum of
all suites must fit MAX_EXPORT_BYTES. This module sees only suites. The export integration
owns the root metadata and manifests, and it must count them against the same
MAX_EXPORT_BYTES bound together with these suite bytes before any directory is written.

Digests fingerprint an export. They are not authentication and not corpus admission.
"""

import json
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .corpus_manifest import Sha256
from .json_input import MAX_REPORT_BYTES
from .provenance import json_digest
from .repository_cases import FrozenModel, RepositoryCase, ShortText, case_digest
from .repository_cases_v2 import RepositoryCaseV2, parse_repository_case
from .repository_suite import MAX_REPOSITORY_SUITE_CASES, RepositorySuite, RepositorySuiteV2

__all__ = [
    "MAX_CORPUS_CASES",
    "MAX_CORPUS_SHARDS",
    "MAX_EXPORT_BYTES",
    "MAX_SOURCE_GROUPS",
    "CorpusShard",
    "CorpusShardPlan",
    "plan_corpus_shards",
]

CORPUS_SHARD_PLAN_SCHEMA_VERSION = 1
MAX_CORPUS_CASES = 1024
MAX_CORPUS_SHARDS = 32
MAX_SOURCE_GROUPS = 256
MAX_EXPORT_BYTES = 64 * 1024 * 1024


def _suite_size(suite: RepositorySuite | RepositorySuiteV2) -> int:
    try:
        text = json.dumps(suite.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
        return len(text.encode("utf-8"))
    except UnicodeEncodeError:
        raise ValueError("Suite text must be encodable as UTF-8.") from None


def _check_sizes(sizes: list[int]) -> None:
    if any(size > MAX_REPORT_BYTES for size in sizes):
        raise ValueError("A shard suite exceeds the per-file size limit.")
    if sum(sizes) > MAX_EXPORT_BYTES:
        raise ValueError("The shard suites exceed the total export size limit.")


def _case_set_digest(cases) -> str:
    return json_digest(sorted((case.case_id, case_digest(case)) for case in cases))


def _case_id(case) -> str:
    return case.case_id


class CorpusShard(FrozenModel):
    ordinal: int = Field(ge=1, le=MAX_CORPUS_SHARDS)
    suite: RepositorySuite | RepositorySuiteV2
    suite_sha256: Sha256
    source_groups: tuple[ShortText, ...] = Field(
        min_length=1, max_length=MAX_REPOSITORY_SUITE_CASES
    )

    @model_validator(mode="after")
    def coherent_shard(self):
        groups = list(self.source_groups)
        if groups != sorted(set(groups)):
            raise ValueError("Shard source groups must be unique and sorted.")
        cases = self.suite.cases
        if sorted({case.source_group for case in cases}) != groups:
            raise ValueError("Shard source groups must match the suite cases.")
        keys = [(case.source_group, case.case_id) for case in cases]
        if keys != sorted(keys):
            raise ValueError("Shard cases must be ordered by source group then case ID.")
        if self.suite_sha256 != json_digest(self.suite.model_dump(mode="json")):
            raise ValueError("Shard suite digest does not match the suite.")
        return self


class CorpusShardPlan(FrozenModel):
    schema_version: Literal[1]
    suite_schema_version: Literal[1, 2]
    case_count: int = Field(ge=1, le=MAX_CORPUS_CASES)
    case_set_sha256: Sha256
    source_groups: tuple[ShortText, ...] = Field(min_length=1, max_length=MAX_SOURCE_GROUPS)
    shards: tuple[CorpusShard, ...] = Field(min_length=1, max_length=MAX_CORPUS_SHARDS)

    @field_validator("schema_version", "suite_schema_version", mode="before")
    @classmethod
    def exact_integer_versions(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("Schema versions must be exact integers.")
        return value

    @model_validator(mode="after")
    def coherent_plan(self):
        shards = self.shards
        if [shard.ordinal for shard in shards] != list(range(1, len(shards) + 1)):
            raise ValueError("Shard ordinals must be consecutive from 1.")
        suites = [shard.suite for shard in shards]
        if any(suite.schema_version != self.suite_schema_version for suite in suites):
            raise ValueError("Every shard suite must use the plan suite schema version.")
        cases = [case for suite in suites for case in suite.cases]
        if len(cases) != self.case_count:
            raise ValueError("Case count does not match the shard suites.")
        if len({case.case_id for case in cases}) != len(cases):
            raise ValueError("Case IDs must be unique across shards.")
        flattened = [group for shard in shards for group in shard.source_groups]
        if flattened != list(self.source_groups) or flattened != sorted(set(flattened)):
            raise ValueError("Plan source groups must be unique, sorted and not split.")
        if self.case_set_sha256 != _case_set_digest(cases):
            raise ValueError("Case set digest does not match the shard suites.")
        _check_sizes([_suite_size(suite) for suite in suites])
        return self


def plan_corpus_shards(cases: tuple) -> CorpusShardPlan:
    """Plan atomic source-group shards. Pure: nothing is written or fetched."""
    if type(cases) is not tuple or not 1 <= len(cases) <= MAX_CORPUS_CASES:
        raise ValueError("Cases must be a tuple of 1 to 1024 repository cases.")
    kind = type(cases[0])
    if kind not in (RepositoryCase, RepositoryCaseV2) or any(
        type(case) is not kind for case in cases
    ):
        raise ValueError("Cases must be exact repository cases of one schema version.")

    checked = []
    for index, case in enumerate(cases):
        try:
            parsed = parse_repository_case(case)
        except ValueError:
            parsed = None
        if type(parsed) is not kind:
            raise ValueError(f"Repository case {index} failed revalidation.")
        checked.append(parsed)
    if len({case.case_id for case in checked}) != len(checked):
        raise ValueError("Repository case IDs must be unique.")

    by_group: dict[str, list] = {}
    for case in checked:
        by_group.setdefault(case.source_group, []).append(case)
    if len(by_group) > MAX_SOURCE_GROUPS:
        raise ValueError("Too many source groups.")

    packs: list[tuple[list, list[str]]] = []
    current: list = []
    current_groups: list[str] = []
    for group in sorted(by_group):
        members = sorted(by_group[group], key=_case_id)
        if len(members) > MAX_REPOSITORY_SUITE_CASES:
            raise ValueError("A source group exceeds the suite case limit and cannot be split.")
        if current and len(current) + len(members) > MAX_REPOSITORY_SUITE_CASES:
            packs.append((current, current_groups))
            current, current_groups = [], []
        current.extend(members)
        current_groups.append(group)
    packs.append((current, current_groups))
    if len(packs) > MAX_CORPUS_SHARDS:
        raise ValueError("Too many shards are needed to keep source groups whole.")

    version = 2 if kind is RepositoryCaseV2 else 1
    suite_model = RepositorySuiteV2 if version == 2 else RepositorySuite
    suites = [suite_model(schema_version=version, cases=tuple(members)) for members, _ in packs]
    _check_sizes([_suite_size(suite) for suite in suites])

    shards = tuple(
        CorpusShard(
            ordinal=ordinal,
            suite=suite,
            suite_sha256=json_digest(suite.model_dump(mode="json")),
            source_groups=tuple(groups),
        )
        for ordinal, (suite, (_, groups)) in enumerate(zip(suites, packs, strict=True), start=1)
    )
    return CorpusShardPlan(
        schema_version=CORPUS_SHARD_PLAN_SCHEMA_VERSION,
        suite_schema_version=version,
        case_count=len(checked),
        case_set_sha256=_case_set_digest(checked),
        source_groups=tuple(sorted(by_group)),
        shards=shards,
    )
