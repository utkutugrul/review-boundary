"""Actual scorer-shaped native reports used across contract and evidence tests."""

from review_boundary.boundary_cases import build_boundary_cases
from review_boundary.boundary_runner import calibrate as boundary_calibrate
from review_boundary.boundary_world import BoundaryWorld, score_boundary_world
from review_boundary.provenance import json_digest
from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import calibrate as repository_calibrate
from review_boundary.repository_world import RepositoryWorld, score_repository_world


def native_fixture(kind="repository", *, case_index=0, guard="off", mode="reference", slots=True):
    if kind == "repository":
        case = build_repository_demo_cases()[case_index]
        world = RepositoryWorld(case)
        repository_calibrate(world, mode)
        row = score_repository_world(case, world)
    else:
        case = build_boundary_cases()[case_index]
        world = BoundaryWorld(case, guard)
        boundary_calibrate(world, mode)
        row = score_boundary_world(case, world)
        row["input_sha256"] = json_digest(BoundaryWorld(case, "off").reviewer_request())
    row.update(reviewer="fixture/reference", epoch=1)
    metadata = {
        "run_kind": "model" if slots else "calibration",
        "run_finished": True,
        "expected_count": 1,
        "epochs": 1,
        "case_count": 1,
        "reviewers": [row["reviewer"]],
        "scoring_version": row["scoring_version"],
        "world_limits": world.limits.model_dump(mode="json"),
    }
    if slots:
        fields = (
            ("case_sha256", "reviewer", "epoch")
            if kind == "repository"
            else ("reviewer", "case_id", "epoch", "guard")
        )
        metadata["expected_slots"] = [{key: row[key] for key in fields}]
    report = {"schema_version": 1, "report_kind": kind, "metadata": metadata, "rows": [row]}
    return report, case, world


def legacy_fixture():
    return {"schema_version": 2, "metadata": {}, "rows": []}
