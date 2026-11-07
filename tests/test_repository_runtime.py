import pytest
from test_repository_cases_v2 import make_v2

from review_boundary.repository_cases import RepositoryCase, build_repository_demo_cases
from review_boundary.repository_cases_v2 import RepositoryCaseV2, parse_repository_case
from review_boundary.repository_runtime import (
    repository_world_for_case,
    restore_repository_world,
    score_repository_case,
)
from review_boundary.repository_world import (
    RepositoryLimits,
    RepositoryWorld,
    score_repository_world,
)
from review_boundary.repository_world_v2 import RepositoryWorldV2


@pytest.mark.parametrize("version", [1, 2])
def test_facade_dispatches_case_runtime_snapshot_and_scoring_together(version):
    selected = build_repository_demo_cases()[0] if version == 1 else make_v2()
    model, world_type = (
        (RepositoryCase, RepositoryWorld) if version == 1 else (RepositoryCaseV2, RepositoryWorldV2)
    )
    parsed = parse_repository_case(selected.model_dump(mode="json"))
    assert type(parsed) is model
    world = repository_world_for_case(parsed)
    assert type(world) is world_type
    world.dispatch("read_pr", {})
    restored = restore_repository_world(selected, world.snapshot(), expected_limits=world.limits)
    assert type(restored) is world_type
    assert restored.snapshot() == world.snapshot()
    result = score_repository_case(selected, restored)
    assert result["scoring_version"] == (
        "repository-v1" if version == 1 else "repository-payload-v1"
    )
    if version == 1:
        assert result == score_repository_world(selected, restored)


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("snapshot_version", [None, True, False, 1.0, 2.0, "1", "2", 3])
def test_facade_rejects_coerced_or_unsupported_snapshot_version(version, snapshot_version):
    selected = build_repository_demo_cases()[0] if version == 1 else make_v2()
    world = repository_world_for_case(selected)
    snapshot = world.snapshot()
    snapshot["schema_version"] = snapshot_version
    with pytest.raises(ValueError):
        restore_repository_world(selected, snapshot, expected_limits=world.limits)


def test_facade_rejects_cross_version_worlds_and_snapshots():
    v1, v2 = build_repository_demo_cases()[0], make_v2()
    world1, world2 = repository_world_for_case(v1), repository_world_for_case(v2)
    for selected, wrong_world in ((v1, world2), (v2, world1)):
        with pytest.raises(ValueError, match="versions"):
            score_repository_case(selected, wrong_world)
        with pytest.raises(ValueError, match="version"):
            restore_repository_world(
                selected, wrong_world.snapshot(), expected_limits=RepositoryLimits()
            )


def test_v2_facade_never_defaults_missing_snapshot_version_to_v2():
    selected = make_v2()
    snapshot = repository_world_for_case(selected).snapshot()
    del snapshot["schema_version"]
    with pytest.raises(ValueError, match="version"):
        restore_repository_world(selected, snapshot, expected_limits=RepositoryLimits())
