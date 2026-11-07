"""Synthetic-only tests for pure atomic source-group corpus sharding."""

import ast
import json
import random
from pathlib import Path

import pytest
from pydantic import ValidationError

from review_boundary import corpus_sharding
from review_boundary.corpus_sharding import (
    MAX_CORPUS_CASES,
    MAX_CORPUS_SHARDS,
    MAX_EXPORT_BYTES,
    MAX_SOURCE_GROUPS,
    CorpusShard,
    CorpusShardPlan,
    plan_corpus_shards,
)
from review_boundary.json_input import MAX_REPORT_BYTES as JSON_MAX_REPORT_BYTES
from review_boundary.provenance import json_digest
from review_boundary.repository_cases import (
    RepositoryCase,
    build_repository_demo_cases,
    case_digest,
)
from review_boundary.repository_cases_v2 import RepositoryCaseV2
from review_boundary.repository_suite import (
    MAX_REPOSITORY_SUITE_CASES,
    RepositorySuite,
    RepositorySuiteV2,
)

BASE = build_repository_demo_cases()[0].model_dump(mode="json")
MARKER = "Synthetic inert marker line."


def make_case(group, name, **changes):
    data = dict(BASE, case_id=f"{group}:{name}", source_group=group)
    data.update(changes)
    return RepositoryCase.model_validate_json(json.dumps(data))


def make_v2(group, name, condition="attack"):
    files = [dict(item) for item in BASE["files"]]
    for item in files:
        if item["path"] == "README.md":
            item["content"] = "# Context\n" + MARKER + "\nLast neutral line.\n"
    data = dict(
        BASE,
        case_schema_version=2,
        case_id=f"{group}:{name}:{condition}",
        source_group=group,
        surface="readme",
        condition=condition,
        files=files,
        payload_ref={
            "pack_id": "synthetic",
            "pack_version": 1,
            "pack_digest": "a" * 64,
            "entry_id": "synthetic",
            "carrier": "readme",
            "condition": condition,
        },
        exposure={"resource": "README.md", "marker": MARKER},
    )
    return RepositoryCaseV2.model_validate_json(json.dumps(data))


def cases_for(sizes):
    return tuple(
        make_case(f"group-{index:03d}", f"c{number:03d}")
        for index, size in enumerate(sizes)
        for number in range(size)
    )


def serialized_size(suite):
    text = json.dumps(suite.model_dump(mode="json"), indent=2, ensure_ascii=False) + "\n"
    return len(text.encode("utf-8"))


def shard_sizes(plan):
    return [len(shard.suite.cases) for shard in plan.shards]


class Recorder:
    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise ValueError("unexpected call")


# Constants


def test_constants_match_the_agreed_bounds_without_copying_shared_limits():
    assert (MAX_CORPUS_CASES, MAX_CORPUS_SHARDS, MAX_SOURCE_GROUPS) == (1024, 32, 256)
    assert MAX_EXPORT_BYTES == 64 * 1024 * 1024
    assert corpus_sharding.MAX_REPORT_BYTES == JSON_MAX_REPORT_BYTES == 32 * 1024 * 1024
    assert MAX_REPOSITORY_SUITE_CASES == 32


# Valid plans


def test_demo_cases_form_one_atomic_v1_shard_with_exact_digests():
    demo = build_repository_demo_cases()
    plan = plan_corpus_shards(demo)
    assert type(plan) is CorpusShardPlan
    assert (plan.schema_version, plan.suite_schema_version, plan.case_count) == (1, 1, 4)
    assert plan.source_groups == ("original_tenant_flow",)
    (shard,) = plan.shards
    assert type(shard) is CorpusShard and shard.ordinal == 1
    assert type(shard.suite) is RepositorySuite and shard.suite.schema_version == 1
    assert shard.source_groups == plan.source_groups
    assert [case.case_id for case in shard.suite.cases] == sorted(case.case_id for case in demo)
    assert {(case.variant, case.surface) for case in shard.suite.cases} == {
        (variant, surface) for variant in ("vulnerable", "fixed") for surface in ("clean", "readme")
    }
    assert shard.suite_sha256 == json_digest(shard.suite.model_dump(mode="json"))
    expected = json_digest(sorted((case.case_id, case_digest(case)) for case in demo))
    assert plan.case_set_sha256 == expected
    by_id = {case.case_id: case for case in demo}
    for case in shard.suite.cases:
        assert case == by_id[case.case_id]
        assert case_digest(case) == case_digest(by_id[case.case_id])


def test_v2_conditions_stay_together_in_one_atomic_group():
    conditions = ("clean", "attack", "benign_quote")
    group_a = tuple(make_v2("v2-group-a", "x", condition) for condition in conditions)
    group_b = (make_v2("v2-group-b", "y"),)
    plan = plan_corpus_shards(group_a + group_b)
    assert plan.suite_schema_version == 2 and plan.case_count == 4
    (shard,) = plan.shards
    assert type(shard.suite) is RepositorySuiteV2
    assert [case.condition for case in shard.suite.cases[:3]] == sorted(conditions)
    assert shard.source_groups == ("v2-group-a", "v2-group-b")
    originals = {case.case_id: case_digest(case) for case in group_a + group_b}
    assert {case.case_id: case_digest(case) for case in shard.suite.cases} == originals
    assert plan.case_set_sha256 == json_digest(sorted(originals.items()))


def test_exactly_thirty_two_cases_fit_one_shard_and_thirty_three_need_two():
    one = plan_corpus_shards(cases_for([16, 16]))
    assert shard_sizes(one) == [32] and one.case_count == 32
    two = plan_corpus_shards(cases_for([16, 16, 1]))
    assert shard_sizes(two) == [32, 1]
    assert two.shards[0].source_groups == ("group-000", "group-001")
    assert two.shards[1].source_groups == ("group-002",)


def test_whole_group_boundary_is_thirty_two_and_a_group_is_never_split():
    assert shard_sizes(plan_corpus_shards(cases_for([32]))) == [32]
    with pytest.raises(ValueError):
        plan_corpus_shards(cases_for([33]))
    assert shard_sizes(plan_corpus_shards(cases_for([20, 20]))) == [20, 20]
    assert shard_sizes(plan_corpus_shards(cases_for([20, 12, 20]))) == [32, 20]
    assert shard_sizes(plan_corpus_shards(cases_for([30, 5, 2]))) == [30, 7]


def test_plan_is_independent_of_input_order():
    cases = cases_for([5, 7, 3, 9])
    reference = plan_corpus_shards(cases)
    orderings = [tuple(reversed(cases))]
    for seed in range(5):
        shuffled = list(cases)
        random.Random(seed).shuffle(shuffled)
        orderings.append(tuple(shuffled))
    for ordering in orderings:
        plan = plan_corpus_shards(ordering)
        assert plan == reference
        assert plan.model_dump(mode="json") == reference.model_dump(mode="json")


def test_flattened_shards_equal_the_whole_input_and_groups_stay_whole():
    cases = cases_for([10, 12, 15, 9, 20])
    plan = plan_corpus_shards(cases)
    flattened = [case for shard in plan.shards for case in shard.suite.cases]
    expected_order = sorted(cases, key=lambda case: (case.source_group, case.case_id))
    assert [case.case_id for case in flattened] == [case.case_id for case in expected_order]
    assert {case.case_id: case_digest(case) for case in flattened} == {
        case.case_id: case_digest(case) for case in cases
    }
    assert plan.case_count == len(cases) == len(flattened)
    assert plan.source_groups == tuple(sorted({case.source_group for case in cases}))
    assert len(plan.source_groups) == 5
    homes = {}
    for shard in plan.shards:
        assert len(shard.suite.cases) <= MAX_REPOSITORY_SUITE_CASES
        for case in shard.suite.cases:
            homes.setdefault(case.source_group, set()).add(shard.ordinal)
    assert all(len(ordinals) == 1 for ordinals in homes.values())
    assert [shard.ordinal for shard in plan.shards] == list(range(1, len(plan.shards) + 1))


def test_source_groups_are_not_rewritten_or_inferred():
    cases = (
        make_case("Group With Spaces/and:chars", "same-name"),
        make_case("other", "same-name"),
        make_case("other", "alpha"),
    )
    plan = plan_corpus_shards(cases)
    assert plan.source_groups == ("Group With Spaces/and:chars", "other")
    assert [case.source_group for case in plan.shards[0].suite.cases] == [
        "Group With Spaces/and:chars",
        "other",
        "other",
    ]


# Rejected inputs


class Sub(RepositoryCase):
    pass


class TupleSub(tuple):
    pass


def gen(cases):
    yield from cases


def test_foreign_containers_and_members_are_rejected():
    demo = build_repository_demo_cases()
    sub = Sub.model_validate_json(json.dumps(BASE))
    for bad in (
        list(demo),
        gen(demo),
        {case.case_id: case for case in demo},
        TupleSub(demo),
        None,
        "cases",
        (),
        (object(),),
        (demo[0], object()),
        (demo[0].model_dump(mode="json"),),
        (sub,),
        (demo[0], sub),
    ):
        with pytest.raises(ValueError):
            plan_corpus_shards(bad)


def test_mixed_versions_and_duplicates_are_rejected():
    demo = build_repository_demo_cases()
    with pytest.raises(ValueError):
        plan_corpus_shards((demo[0], make_v2("g", "x")))
    with pytest.raises(ValueError):
        plan_corpus_shards((make_v2("g", "x"), demo[0]))
    with pytest.raises(ValueError):
        plan_corpus_shards((demo[0], demo[0]))
    with pytest.raises(ValueError):
        plan_corpus_shards((make_case("a", "same"), make_case("b", "other", case_id="a:same")))
    v2 = make_v2("g", "x")
    with pytest.raises(ValueError):
        plan_corpus_shards((v2, v2))


def test_forged_unchecked_model_copies_are_rejected():
    demo = build_repository_demo_cases()
    v2 = make_v2("g", "x")
    for forged in (
        demo[0].model_copy(update={"surface": "readme"}),
        demo[0].model_copy(update={"case_id": ""}),
        demo[0].model_copy(update={"variant": "unknown"}),
        demo[0].model_copy(update={"files": ()}),
        v2.model_copy(update={"case_schema_version": True}),
        v2.model_copy(update={"condition": "clean"}),
    ):
        with pytest.raises(ValueError):
            plan_corpus_shards((forged,))
    with pytest.raises(ValueError):
        plan_corpus_shards((demo[1], demo[0].model_copy(update={"surface": "readme"})))


def test_size_and_type_bounds_reject_before_any_serialization(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(corpus_sharding, "parse_repository_case", recorder)
    monkeypatch.setattr(corpus_sharding, "json_digest", recorder)
    monkeypatch.setattr(corpus_sharding, "_suite_size", recorder)
    demo = build_repository_demo_cases()
    for bad in (
        (object(),) * (MAX_CORPUS_CASES + 1),
        (demo[0],) * (MAX_CORPUS_CASES + 1),
        (demo[0], object()),
        (demo[0], make_v2("g", "x")),
        list(demo),
        (),
    ):
        with pytest.raises(ValueError):
            plan_corpus_shards(bad)
    assert recorder.calls == []


def test_one_more_than_the_case_limit_is_rejected_even_when_valid():
    cases = cases_for([32] * 32) + (make_case("group-extra", "c000"),)
    assert len(cases) == MAX_CORPUS_CASES + 1
    with pytest.raises(ValueError):
        plan_corpus_shards(cases)


# Cap edges


def test_case_and_shard_cap_edge_at_1024_cases_and_32_shards():
    plan = plan_corpus_shards(cases_for([32] * 32))
    assert plan.case_count == MAX_CORPUS_CASES
    assert len(plan.shards) == MAX_CORPUS_SHARDS
    assert shard_sizes(plan) == [32] * 32
    assert len(plan.source_groups) == 32


def test_group_cap_edge_at_256_groups_and_257_rejected():
    plan = plan_corpus_shards(cases_for([4] * MAX_SOURCE_GROUPS))
    assert len(plan.source_groups) == MAX_SOURCE_GROUPS
    assert plan.case_count == 1024
    assert shard_sizes(plan) == [32] * 32
    with pytest.raises(ValueError):
        plan_corpus_shards(cases_for([1] * (MAX_SOURCE_GROUPS + 1)))


def test_thirty_three_shards_from_thirty_three_groups_of_seventeen_are_rejected():
    assert shard_sizes(plan_corpus_shards(cases_for([17] * 32))) == [17] * 32
    with pytest.raises(ValueError):
        plan_corpus_shards(cases_for([17] * 33))


def test_aggregate_export_cap_is_inclusive(monkeypatch):
    cases = cases_for([20, 20, 20])
    plan = plan_corpus_shards(cases)
    total = sum(serialized_size(shard.suite) for shard in plan.shards)
    monkeypatch.setattr(corpus_sharding, "MAX_EXPORT_BYTES", total)
    assert plan_corpus_shards(cases) == plan
    monkeypatch.setattr(corpus_sharding, "MAX_EXPORT_BYTES", total - 1)
    with pytest.raises(ValueError):
        plan_corpus_shards(cases)


def test_per_suite_report_cap_is_inclusive(monkeypatch):
    cases = cases_for([20, 20])
    plan = plan_corpus_shards(cases)
    largest = max(serialized_size(shard.suite) for shard in plan.shards)
    monkeypatch.setattr(corpus_sharding, "MAX_REPORT_BYTES", largest)
    assert plan_corpus_shards(cases) == plan
    monkeypatch.setattr(corpus_sharding, "MAX_REPORT_BYTES", largest - 1)
    with pytest.raises(ValueError):
        plan_corpus_shards(cases)


def test_suite_bytes_count_real_file_content_and_unicode_exactly(monkeypatch):
    line = "x = 1  # " + "y" * 60 + "\n"
    extra = [
        {"path": f"src/large_{index}.py", "content": line * 850 + "# é 日本語\n"}
        for index in range(5)
    ]
    big = make_case("big-group", "large", files=BASE["files"] + extra)
    plan = plan_corpus_shards((big, make_case("small-group", "small")))
    (shard,) = plan.shards
    size = serialized_size(shard.suite)
    assert size > 200_000
    monkeypatch.setattr(corpus_sharding, "MAX_EXPORT_BYTES", size)
    assert plan_corpus_shards((big, make_case("small-group", "small"))) == plan
    monkeypatch.setattr(corpus_sharding, "MAX_EXPORT_BYTES", size - 1)
    with pytest.raises(ValueError):
        plan_corpus_shards((big, make_case("small-group", "small")))


# Metadata models


def two_shard_plan():
    return plan_corpus_shards(cases_for([20, 20]))


def rebuild_plan(plan, **changes):
    fields = {
        "schema_version": plan.schema_version,
        "suite_schema_version": plan.suite_schema_version,
        "case_count": plan.case_count,
        "case_set_sha256": plan.case_set_sha256,
        "source_groups": plan.source_groups,
        "shards": plan.shards,
    }
    fields.update(changes)
    return CorpusShardPlan(**fields)


def rebuild_shard(shard, **changes):
    fields = {
        "ordinal": shard.ordinal,
        "suite": shard.suite,
        "suite_sha256": shard.suite_sha256,
        "source_groups": shard.source_groups,
    }
    fields.update(changes)
    return CorpusShard(**fields)


def plan_changes(plan):
    first, second = plan.shards
    return {
        "bool_schema_version": {"schema_version": True},
        "float_schema_version": {"schema_version": 1.0},
        "unsupported_schema_version": {"schema_version": 2},
        "bool_suite_version": {"suite_schema_version": True},
        "wrong_suite_version": {"suite_schema_version": 2},
        "unknown_suite_version": {"suite_schema_version": 3},
        "count_high": {"case_count": plan.case_count + 1},
        "count_low": {"case_count": plan.case_count - 1},
        "count_zero": {"case_count": 0},
        "count_bool": {"case_count": True},
        "count_over_cap": {"case_count": MAX_CORPUS_CASES + 1},
        "wrong_digest": {"case_set_sha256": "0" * 64},
        "malformed_digest": {"case_set_sha256": "XYZ"},
        "groups_reversed": {"source_groups": tuple(reversed(plan.source_groups))},
        "groups_duplicated": {"source_groups": (plan.source_groups[0],) * 2},
        "groups_missing": {"source_groups": plan.source_groups[:1]},
        "groups_extra": {"source_groups": (*plan.source_groups, "group-999")},
        "groups_empty": {"source_groups": ()},
        "shards_reversed": {"shards": (second, first)},
        "shards_missing": {"shards": (first,)},
        "shards_duplicated": {"shards": (first, first)},
        "shards_empty": {"shards": ()},
        "shards_list": {"shards": [first, second]},
        "ordinal_gap": {"shards": (first, rebuild_shard(second, ordinal=3))},
        "ordinal_repeat": {"shards": (first, rebuild_shard(second, ordinal=1))},
    }


def test_rebuilding_a_valid_plan_is_consistent_and_models_are_frozen():
    plan = two_shard_plan()
    assert rebuild_plan(plan) == plan
    assert rebuild_shard(plan.shards[0]) == plan.shards[0]
    with pytest.raises(ValidationError):
        plan.case_count = 3
    with pytest.raises(ValidationError):
        plan.shards[0].ordinal = 2


@pytest.mark.parametrize("name", sorted(plan_changes(two_shard_plan())))
def test_plan_model_rejects_inconsistent_metadata(name):
    plan = two_shard_plan()
    with pytest.raises(ValueError):
        rebuild_plan(plan, **plan_changes(plan)[name])


def test_plan_model_rejects_extra_fields():
    plan = two_shard_plan()
    with pytest.raises(ValueError):
        rebuild_plan(plan, unexpected=1)
    with pytest.raises(ValueError):
        CorpusShard(
            ordinal=1,
            suite=plan.shards[0].suite,
            suite_sha256=plan.shards[0].suite_sha256,
            source_groups=plan.shards[0].source_groups,
            unexpected=1,
        )
    assert set(plan.model_dump()) == {
        "schema_version",
        "suite_schema_version",
        "case_count",
        "case_set_sha256",
        "source_groups",
        "shards",
    }
    assert set(plan.shards[0].model_dump()) == {
        "ordinal",
        "suite",
        "suite_sha256",
        "source_groups",
    }


def test_plan_rejects_shards_with_mixed_suite_versions():
    v1 = plan_corpus_shards((make_case("group-a", "x"),))
    v2 = plan_corpus_shards((make_v2("group-b", "y"),))
    second = rebuild_shard(v2.shards[0], ordinal=2)
    with pytest.raises(ValueError):
        rebuild_plan(
            v1,
            case_count=2,
            source_groups=("group-a", "group-b"),
            shards=(
                v1.shards[0],
                second,
            ),
        )


@pytest.mark.parametrize("ordinal", [0, 33, -1, True, 1.0, "1", None])
def test_shard_ordinal_must_be_a_strict_integer_in_range(ordinal):
    shard = two_shard_plan().shards[0]
    with pytest.raises(ValueError):
        rebuild_shard(shard, ordinal=ordinal)


def test_shard_model_rejects_inconsistent_digest_groups_and_suite():
    plan = two_shard_plan()
    first, second = plan.shards
    for changes in (
        {"suite_sha256": "0" * 64},
        {"suite_sha256": second.suite_sha256},
        {"suite_sha256": "not-a-digest"},
        {"source_groups": second.source_groups},
        {"source_groups": ()},
        {"source_groups": (*first.source_groups, *second.source_groups)},
        {"source_groups": first.source_groups * 2},
        {"suite": second.suite},
        {"suite": first.suite.model_dump(mode="json")},
    ):
        with pytest.raises(ValueError):
            rebuild_shard(first, **changes)
    two_groups = plan_corpus_shards(cases_for([3, 3])).shards[0]
    with pytest.raises(ValueError):
        rebuild_shard(two_groups, source_groups=tuple(reversed(two_groups.source_groups)))


def test_shard_rejects_suites_whose_cases_are_not_ordered():
    plan = plan_corpus_shards(cases_for([3]))
    suite = plan.shards[0].suite
    reordered = RepositorySuite(schema_version=1, cases=tuple(reversed(suite.cases)))
    digest = json_digest(reordered.model_dump(mode="json"))
    with pytest.raises(ValueError):
        CorpusShard(
            ordinal=1, suite=reordered, suite_sha256=digest, source_groups=plan.source_groups
        )


# Purity


def test_source_imports_no_runner_registry_sdk_or_network_modules():
    tree = ast.parse(Path(corpus_sharding.__file__).read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add(("." * node.level) + (node.module or ""))
    forbidden = (
        "runner",
        "registry",
        "sdk",
        "anthropic",
        "openai",
        "inspect_ai",
        "subprocess",
        "socket",
        "urllib",
        "importlib",
        "scorer",
        "upstream",
        "payload_fixtures",
    )
    assert not [name for name in names if any(part in name for part in forbidden)]
    assert {".provenance", ".json_input", ".repository_suite"} <= names


def test_planning_does_not_mutate_inputs_or_write_files(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    demo = build_repository_demo_cases()
    before = [case.model_dump(mode="json") for case in demo]
    plan_corpus_shards(demo)
    assert [case.model_dump(mode="json") for case in demo] == before
    assert list(tmp_path.iterdir()) == []
