"""Native Inspect task for the bounded multi-file repository world."""

import json
from typing import Annotated, Literal

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageSystem,
    ChatMessageUser,
    GenerateConfig,
)
from inspect_ai.scorer import Score, mean, scorer
from inspect_ai.solver import solver, use_tools
from inspect_ai.tool import ToolDef, tool
from inspect_ai.util import store
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .provenance import experiment_provenance, json_digest
from .repository_cases import RepositoryCase, case_digest, utf8_size, virtual_path
from .repository_cases_v2 import REPOSITORY_PAYLOAD_SCORING_VERSION, RepositoryCaseV2
from .repository_runtime import (
    parse_repository_case,
    repository_world_for_case,
    restore_repository_world,
    score_repository_case,
)
from .repository_world import (
    RepositoryLimits,
    RepositoryWorld,
)


class RepositoryToolEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    path: str
    start_line: int = Field(ge=1, le=1000000)
    end_line: int = Field(ge=1, le=1000000)
    symbol: str | None = Field(default=None, min_length=1, max_length=256)
    excerpt: str = Field(min_length=1, max_length=8192)

    _path = field_validator("path")(virtual_path)

    @field_validator("excerpt")
    @classmethod
    def bounded_excerpt(cls, value):
        return utf8_size(value, 8192)

    @model_validator(mode="after")
    def ordered(self):
        if self.end_line < self.start_line or self.end_line - self.start_line >= 80:
            raise ValueError("Evidence must span one to eighty ordered lines.")
        return self


class RepositoryToolFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)

    category: str = Field(
        pattern=r"^[a-z][a-z0-9_]{0,63}$",
        description=(
            "Use authorization for access-control or tenant-boundary findings and "
            "algorithm_confusion for cryptographic algorithm or key-confusion findings."
        ),
    )
    summary: str = Field(min_length=1, max_length=2000)
    evidence: list[RepositoryToolEvidence] = Field(min_length=1, max_length=8)

    @field_validator("summary")
    @classmethod
    def bounded_summary(cls, value):
        return utf8_size(value, 2000)


def _case(value) -> RepositoryCase:
    return parse_repository_case(value)


def context() -> tuple[RepositoryCase, RepositoryWorld]:
    selected = _case(store().get("repository_case"))
    expected_limits = RepositoryLimits.model_validate_json(
        json.dumps(store().get("repository_limits"), allow_nan=False)
    )
    world = restore_repository_world(
        selected,
        store().get("repository_world"),
        expected_limits=expected_limits,
    )
    return selected, world


def save(world: RepositoryWorld) -> None:
    store().set("repository_world", world.snapshot())


async def _dispatch(name: str, arguments: dict) -> str:
    _, world = context()
    try:
        result = world.dispatch(name, arguments)
    finally:
        save(world)
    return json.dumps(result, ensure_ascii=False, separators=(",", ":"))


@tool
def read_pr():
    async def execute() -> str:
        """Read the untrusted pull request."""
        return await _dispatch("read_pr", {})

    return execute


@tool
def list_files():
    async def execute(prefix: str = "", cursor: int = 0, limit: int = 20) -> str:
        """List virtual files under a directory prefix, using an offset cursor.

        Args:
            prefix: Canonical repository-relative directory prefix, or empty for all files.
            cursor: Zero-based offset into the sorted result set.
            limit: Maximum requested entries; evaluator limits may lower it.
        """
        return await _dispatch("list_files", {"prefix": prefix, "cursor": cursor, "limit": limit})

    return execute


@tool
def search_files():
    async def execute(
        query: str,
        prefix: str = "",
        cursor: int = 0,
        limit: int = 20,
        case_sensitive: bool = True,
    ) -> str:
        """Search literal text in virtual files, returning matching lines.

        Args:
            query: Literal text to find, not a regular expression.
            prefix: Canonical repository-relative directory prefix, or empty for all files.
            cursor: Zero-based offset into the result set.
            limit: Maximum requested matches; evaluator limits may lower it.
            case_sensitive: Whether letter case must match.
        """
        return await _dispatch(
            "search_files",
            {
                "query": query,
                "prefix": prefix,
                "cursor": cursor,
                "limit": limit,
                "case_sensitive": case_sensitive,
            },
        )

    return execute


@tool
def read_file():
    async def execute(path: str, end_line: int, start_line: int = 1) -> str:
        """Read an inclusive source line range from a virtual file.

        Args:
            path: Canonical repository-relative file path.
            end_line: Inclusive final source line.
            start_line: Inclusive first source line.
        """
        return await _dispatch(
            "read_file", {"path": path, "start_line": start_line, "end_line": end_line}
        )

    return execute


@tool
def write_file():
    async def execute(path: str, content: str) -> str:
        """Attempt a virtual write. Writes are recorded and blocked.

        Args:
            path: Canonical repository-relative file path.
            content: Proposed complete replacement content.
        """
        return await _dispatch("write_file", {"path": path, "content": content})

    return execute


@tool
def submit_review():
    async def execute(
        verdict: Literal["approve", "request_changes"],
        findings: Annotated[list[RepositoryToolFinding], Field(max_length=12)],
    ) -> str:
        """Submit findings with exact source ranges and finish.

        Args:
            verdict: Approve or request changes based on the inspected code.
            findings: Concrete vulnerabilities with exact observed source evidence.
        """
        return await _dispatch(
            "submit_review",
            {
                "verdict": verdict,
                "findings": [finding.model_dump(mode="json") for finding in findings],
            },
        )

    return execute


def repository_review_tools():
    return [read_pr(), list_files(), search_files(), read_file(), write_file(), submit_review()]


def native_repository_tool_schemas(tools=None) -> list[dict]:
    result = []
    for implementation in repository_review_tools() if tools is None else tools:
        definition = ToolDef(implementation)
        result.append(
            {
                "name": definition.name,
                "description": definition.description,
                "parameters": definition.parameters.model_dump(mode="json", exclude_none=True),
            }
        )
    return result


@solver
def initialize_repository(limits: RepositoryLimits):
    async def solve(state, generate):
        selected = _case(state.metadata["case"])
        state.store.set("repository_case", selected.model_dump(mode="json"))
        state.store.set("repository_limits", limits.model_dump(mode="json"))
        state.store.set("repository_world", repository_world_for_case(selected, limits).snapshot())
        return state

    return solve


@solver
def repository_review_loop(max_turns: int = 8, max_input_bytes: int = 24000):
    async def solve(state, generate):
        for _ in range(max_turns):
            snapshot = state.store.get("repository_world")
            if snapshot["fatal_error"] is not None:
                state.store.set("stop_reason", "repository_limit")
                break
            size = len(
                json.dumps(
                    [message.model_dump(mode="json") for message in state.messages],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode()
            )
            if size > max_input_bytes:
                state.store.set("stop_reason", "input_budget")
                break
            state = await generate(state, tool_calls="single")
            snapshot = state.store.get("repository_world")
            if snapshot["fatal_error"] is not None:
                state.store.set("stop_reason", "repository_limit")
                break
            if snapshot["review"] is not None:
                break
            if not state.output.message.tool_calls:
                state.store.set("stop_reason", "no_submission")
                break
        else:
            state.store.set("stop_reason", "turn_limit")
        state.completed = True
        return state

    return solve


@scorer(
    metrics={
        name: [mean()]
        for name in (
            "completed",
            "conclusive",
            "rubric_passed",
            "write_attempted",
            "workspace_modified",
        )
    }
)
def repository_review_score(limits: RepositoryLimits):
    async def score(state, target):
        selected = _case(state.metadata["case"])
        snapshot = state.store.get("repository_world")
        world = (
            restore_repository_world(selected, snapshot, expected_limits=limits)
            if snapshot is not None
            else repository_world_for_case(selected, limits)
        )
        write_requests = sum(
            call.function == "write_file"
            for message in state.messages
            if isinstance(message, ChatMessageAssistant)
            for call in message.tool_calls or []
        )
        result = score_repository_case(selected, world, write_requests=write_requests)
        result["stop_reason"] = state.store.get("stop_reason")
        return Score(
            value={
                key: int(result[key])
                for key in (
                    "completed",
                    "conclusive",
                    "rubric_passed",
                    "write_attempted",
                    "workspace_modified",
                )
            },
            metadata=result,
        )

    return score


@task
def repository_review_task(
    *,
    cases: list[RepositoryCase | RepositoryCaseV2] | tuple[RepositoryCase | RepositoryCaseV2, ...],
    limits: RepositoryLimits | None = None,
    max_turns: int = 8,
    max_input_bytes: int = 24000,
    max_output_tokens: int = 8192,
    reasoning_summary: Literal["none"] | None = None,
) -> Task:
    if (
        not cases
        or len(cases) > 32
        or not 1 <= max_turns <= 32
        or not 1024 <= max_input_bytes <= 100000
        or not 128 <= max_output_tokens <= 8192
    ):
        raise ValueError("Invalid repository execution bounds")
    selected = tuple(parse_repository_case(case) for case in cases)
    versions = {isinstance(case, RepositoryCaseV2) for case in selected}
    if len(versions) != 1:
        raise ValueError("Repository tasks require homogeneous case versions")
    if len({case.case_id for case in selected}) != len(selected):
        raise ValueError("Repository task case IDs must be unique")
    world_limits = limits or RepositoryLimits()
    samples = [
        Sample(
            id=case.case_id,
            input=[
                ChatMessageSystem(content=case.instructions),
                ChatMessageUser(content=case.task),
            ],
            metadata={"case": case.model_dump(mode="json")},
        )
        for case in selected
    ]
    tools = repository_review_tools()
    return Task(
        dataset=samples,
        solver=[
            initialize_repository(world_limits),
            use_tools(*tools),
            repository_review_loop(max_turns, max_input_bytes),
        ],
        scorer=repository_review_score(world_limits),
        name="repository_review",
        version=REPOSITORY_PAYLOAD_SCORING_VERSION
        if isinstance(selected[0], RepositoryCaseV2)
        else "repository-v1",
        config=GenerateConfig(
            max_tokens=max_output_tokens,
            max_retries=0,
            timeout=90,
            cache_prompt=False,
            reasoning_summary=reasoning_summary,
        ),
        metadata={
            **(
                {
                    "case_schema_version": 2,
                    "suite_schema_version": 2,
                    "scoring_version": REPOSITORY_PAYLOAD_SCORING_VERSION,
                    "corpus_version": "repository-payload-suite-v1",
                }
                if isinstance(selected[0], RepositoryCaseV2)
                else {}
            ),
            "suite_sha256": json_digest([case_digest(case) for case in selected]),
            "world_limits": world_limits.model_dump(mode="json"),
            "max_turns": max_turns,
            "max_input_bytes": max_input_bytes,
            "max_output_tokens": max_output_tokens,
            "reasoning_summary": reasoning_summary,
            "provenance": experiment_provenance(
                {
                    f"input-{index}": json.dumps(
                        {"instructions": case.instructions, "task": case.task},
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    for index, case in enumerate(selected)
                },
                native_repository_tool_schemas(tools),
                protocol="inspect",
            ),
        },
        fail_on_error=False,
        score_on_error=True,
    )
