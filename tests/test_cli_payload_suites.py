"""Public payload exports are bounded data with explicit versioned execution paths."""

import json

import pytest

from review_boundary.boundary_runner import calibrate, load_boundary_suite
from review_boundary.boundary_world import BoundaryWorld, score_boundary_world
from review_boundary.cli import main
from review_boundary.payload_packs import (
    build_original_payload_pack,
    parse_payload_pack,
    payload_pack_digest,
)
from review_boundary.repository_runner import load_suite
from review_boundary.repository_suite import repository_suite_schema


def test_original_pack_stdout_round_trip_is_versioned_data(capsys):
    assert main(["payload-pack"]) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["schema_version"] == 1 and document["pack_version"] == 1
    assert parse_payload_pack(document) == build_original_payload_pack()


@pytest.mark.parametrize(
    "carrier", ["readme", "pr", "inert_file", "filename", "code_comment", "tool_output"]
)
def test_repository_suite_export_uses_two_variants_and_three_conditions(tmp_path, carrier):
    path = tmp_path / f"{carrier}.json"
    assert main(["payload-suite", "--carrier", carrier, "--output", str(path)]) == 0
    assert path.stat().st_size < 1048576
    cases = load_suite(path)
    assert len(cases) == 12
    assert {case.variant for case in cases} == {"vulnerable", "fixed"}
    assert {case.condition for case in cases} == {"clean", "attack", "benign_quote"}
    assert {case.surface for case in cases} == {carrier}
    assert len({case.source_group for case in cases}) == 1


def test_schema_export_selects_v2_and_keeps_v1_default(capsys):
    assert main(["suite-schema"]) == 0
    assert json.loads(capsys.readouterr().out) == repository_suite_schema()
    assert main(["suite-schema", "--schema-version", "2"]) == 0
    assert json.loads(capsys.readouterr().out) == repository_suite_schema(schema_version=2)


@pytest.mark.parametrize(
    "command", [["payload-pack"], ["payload-suite", "--carrier", "pr"], ["worker-summary-suite"]]
)
def test_payload_export_never_overwrites_or_follows_output_symlinks(tmp_path, command):
    existing = tmp_path / "existing.json"
    existing.write_text("preserve")
    assert main(command + ["--output", str(existing)]) == 2
    assert existing.read_text() == "preserve"
    link = tmp_path / "link.json"
    link.symlink_to(existing)
    assert main(command + ["--output", str(link)]) == 2
    assert existing.read_text() == "preserve"


def test_worker_export_preserves_real_authority_utility_without_summary_grants(tmp_path):
    path = tmp_path / "worker.json"
    assert main(["worker-summary-suite", "--output", str(path)]) == 0
    assert path.stat().st_size < 1048576
    cases = load_boundary_suite(path)
    assert len(cases) == 24 and len({case.source_group for case in cases}) == 1
    authorized, ungranted = 0, 0
    for case in cases:
        for guard in ("off", "on"):
            world = BoundaryWorld(case, guard=guard)
            calibrate(world, "reference")
            row = score_boundary_world(case, world)
            assert row["task_success"] and row["review_rubric_passed"]
            assert row["unauthorized_action_attempts"] == row["unauthorized_effects"] == 0
            assert row["semantic_passed"] is None
            if case.grants:
                authorized += 1
                assert row["executed_actions"] == len(case.required_actions)
            else:
                ungranted += 1
                assert row["executed_actions"] == 0
    assert authorized > 0 and ungranted > 0


def test_worker_export_is_usable_in_keyless_boundary_demo(tmp_path):
    path = tmp_path / "worker.json"
    assert main(["worker-summary-suite", "--output", str(path)]) == 0
    assert (
        main(
            [
                "boundary-demo",
                "--suite",
                str(path),
                "--guard",
                "both",
                "--output",
                str(tmp_path / "demo"),
            ]
        )
        == 0
    )


def test_explicit_pack_file_is_digest_bound_and_oversized_suite_fails_closed(tmp_path):
    document = build_original_payload_pack().model_dump(mode="json")
    document.update(pack_id="external_original", pack_version=2)
    pack = tmp_path / "pack.json"
    pack.write_text(json.dumps(document))
    suite = tmp_path / "suite.json"
    assert (
        main(["payload-suite", "--carrier", "pr", "--pack", str(pack), "--output", str(suite)]) == 0
    )
    expected = payload_pack_digest(parse_payload_pack(document))
    assert {case.payload_ref.pack_digest for case in load_suite(suite)} == {expected}
    entries = document["entries"]
    document["entries"] = [
        {**entries[index % 2], "entry_id": f"entry_{index}"} for index in range(8)
    ]
    pack.write_text(json.dumps(document))
    oversized = tmp_path / "too-many.json"
    assert (
        main(["payload-suite", "--carrier", "pr", "--pack", str(pack), "--output", str(oversized)])
        == 2
    )
    assert not oversized.exists()
