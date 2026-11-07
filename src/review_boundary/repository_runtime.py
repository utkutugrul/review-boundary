"""Explicit repository case dispatch preserving every original v1 implementation."""

from collections.abc import Sequence

from .repository_cases import RepositoryCase
from .repository_cases_v2 import RepositoryCaseV2, parse_repository_case
from .repository_world import (
    FindingAdjudication,
    RepositoryLimits,
    RepositoryWorld,
    ReviewAdjudication,
    score_repository_world,
)
from .repository_world_v2 import RepositoryWorldV2, score_repository_world_v2

RepositoryCaseLike = RepositoryCase | RepositoryCaseV2
RepositoryWorldLike = RepositoryWorld | RepositoryWorldV2


def repository_world_for_case(
    case: RepositoryCaseLike, limits: RepositoryLimits | None = None
) -> RepositoryWorldLike:
    selected = parse_repository_case(case)
    if isinstance(selected, RepositoryCaseV2):
        return RepositoryWorldV2(selected, limits)
    return RepositoryWorld(selected, limits)


def restore_repository_world(
    case: RepositoryCaseLike,
    snapshot,
    *,
    expected_limits: RepositoryLimits,
) -> RepositoryWorldLike:
    selected = parse_repository_case(case)
    value = snapshot.model_dump(mode="json") if hasattr(snapshot, "model_dump") else snapshot
    if not isinstance(value, dict):
        raise ValueError("Repository snapshots must be JSON objects.")  # noqa: TRY004
    expected_version = 2 if isinstance(selected, RepositoryCaseV2) else 1
    version = value.get("schema_version", 1)
    if type(version) is not int or version != expected_version:
        raise ValueError("Repository snapshot version does not match its case.")
    if isinstance(selected, RepositoryCaseV2):
        return RepositoryWorldV2.from_snapshot(selected, value, expected_limits=expected_limits)
    return RepositoryWorld.from_snapshot(selected, value, expected_limits=expected_limits)


def score_repository_case(
    case: RepositoryCaseLike,
    world: RepositoryWorldLike,
    adjudications: Sequence[FindingAdjudication] = (),
    review_adjudication: ReviewAdjudication | None = None,
    write_requests: int | None = None,
) -> dict:
    selected = parse_repository_case(case)
    if isinstance(selected, RepositoryCaseV2):
        if not isinstance(world, RepositoryWorldV2):
            raise ValueError("Repository case and runtime versions must match.")  # noqa: TRY004
        return score_repository_world_v2(
            selected, world, adjudications, review_adjudication, write_requests
        )
    if type(world) is not RepositoryWorld:
        raise ValueError("Repository case and runtime versions must match.")
    return score_repository_world(
        selected, world, adjudications, review_adjudication, write_requests
    )
