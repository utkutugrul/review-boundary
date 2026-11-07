import hashlib
import json

from review_boundary.repository_cases import (
    RepositoryCase,
    build_repository_demo_cases,
    canonical_digest,
)
from review_boundary.repository_suite import RepositorySuite, repository_suite_schema
from review_boundary.repository_world import RepositoryWorld, score_repository_world

CASE_DIGESTS = (
    "4facbef1955816a32d3c24f0c4a323716d54f8cbb3d71f7b2b61920aff0aaea2",
    "a3b68e2d06175b7c70483cbc72cfd36e20b5d14b8eb1331e0bbd863c418791db",
    "b8986f602baf747adf7ced4ccde147d0310fc2652c257f5a2f2dbbe2e2152659",
    "fa660c32069d3c7c3a5ba26e3bbea3108beddbc0c1240babc4dc6f274e4e5813",
)
SNAPSHOT_DIGESTS = (
    "9cbd31c7272fe13a6ef1eac9a491e80923ca2b0aed86ed784394499c5c49b51d",
    "396566b91664b910ba4e8a7df3f12c1ec71b82232003f8215f3f7bf0220565ac",
    "881140a1321483aee49e6ae20b7aa02b6bd3589d56899325dd08e69a8f3569ba",
    "29ea86a644700514a0e63eb1cd9ee1caa5ebb1aae2a65819946984dc7d63ae79",
)
SCORING_DIGESTS = (
    "787ecb6ebe3fbb03b87143aebffa0c8ab058239633466627d8707509d9b8b9e3",
    "365eb144eb195791300d6481c5a81d2fa852003e0355b415232746e1c4cb39d7",
    "22cac1651f0adebf0d0a654566bfe0974d4112391dc68e345b321fa0c56c91f3",
    "8d3ed4956c5aa03e5dd7b486c170b02d0f35ee08dc36c5a7c535839d1e6b6969",
)


def json_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def test_original_v1_case_model_dumps_and_default_builder_are_frozen():
    cases = build_repository_demo_cases()
    assert len(cases) == 4 and all(type(case) is RepositoryCase for case in cases)
    assert tuple(canonical_digest(case) for case in cases) == CASE_DIGESTS
    assert set(RepositoryCase.model_fields) == {
        "case_id",
        "source_group",
        "variant",
        "surface",
        "instructions",
        "task",
        "pr",
        "files",
        "issues",
        "exposure",
    }


def test_default_v1_schema_and_suite_digest_are_frozen():
    assert json_digest(repository_suite_schema()) == (
        "6e38829de358b6cb63b01bf3d8dfb00d48506b3254d2dd281238a6a912963d84"
    )
    suite = RepositorySuite(schema_version=1, cases=build_repository_demo_cases())
    assert (
        canonical_digest(suite)
        == "f83d7c7e5021fc9bb5f2422a97daf152a7d2ae1aa5eabc699eb3cf4513653ccb"
    )


def test_default_v1_snapshots_and_structural_scoring_are_frozen():
    cases = build_repository_demo_cases()
    assert (
        tuple(json_digest(RepositoryWorld(case).snapshot()) for case in cases) == SNAPSHOT_DIGESTS
    )
    assert (
        tuple(json_digest(score_repository_world(case, RepositoryWorld(case))) for case in cases)
        == SCORING_DIGESTS
    )
