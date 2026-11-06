"""Validate corpus identity, family partitioning, source evidence, and compatibility."""

import ast
import json
from collections import Counter, defaultdict

import pytest

from review_boundary.cases import (
    CATEGORIES,
    FAMILIES,
    HOLDOUT_VERSION,
    LANGUAGES,
    SOURCE,
    SPLITS,
    SUPPRESSION,
    SURFACES,
    Case,
    build_cases,
    suite_digest,
)


def test_family_split_is_disjoint_and_covers_all_cases():
    development = build_cases(split="development")
    heldout = build_cases(split="heldout")
    assert len(development) == 96
    assert len(heldout) == 48
    assert {case.family for case in development}.isdisjoint(case.family for case in heldout)
    assert {case.id for case in build_cases()} == {case.id for case in development + heldout}
    assert {case.language for case in heldout} == {"typescript", "rust"}
    assert all(case.split == "development" for case in build_cases(language="python"))
    assert SPLITS == ("development", "heldout")


def test_language_counts_and_family_pairs():
    assert Counter(family.language for family in FAMILIES) == dict.fromkeys(LANGUAGES, 4)
    assert len({family.name for family in FAMILIES}) == len(FAMILIES) == 12
    groups = defaultdict(set)
    for case in build_cases():
        groups[case.family].add((case.variant, case.surface))
    pairs = {(variant, surface) for variant in ("vulnerable", "fixed") for surface in SURFACES}
    assert all(actual == pairs for actual in groups.values())
    assert {case.category for case in build_cases()} == set(CATEGORIES)


@pytest.mark.parametrize("language", LANGUAGES)
def test_language_filter(language):
    cases = build_cases(language=language)
    assert len(cases) == 48
    assert all(case.language == language for case in cases)
    assert {case.id for case in cases} == {
        case.id for case in build_cases() if case.language == language
    }


@pytest.mark.parametrize("split", SPLITS)
@pytest.mark.parametrize("language", LANGUAGES)
def test_combined_filters(split, language):
    assert build_cases(split=split, language=language) == [
        case for case in build_cases() if case.split == split and case.language == language
    ]


@pytest.mark.parametrize("filters", [{"split": "test"}, {"language": "go"}])
def test_unknown_filters_fail(filters):
    with pytest.raises(ValueError, match="Unknown"):
        build_cases(**filters)


def test_evidence_is_valid_source_not_attack_text():
    for case in build_cases():
        source = case.files[case.source_path].splitlines()
        assert bool(case.evidence_lines) == (case.variant == "vulnerable")
        assert case.relevant_lines
        assert set(case.evidence_lines) <= set(case.relevant_lines)
        assert tuple(sorted(set(case.relevant_lines))) == case.relevant_lines
        for number in (*case.evidence_lines, *case.relevant_lines):
            assert 1 <= number <= len(source)
            line = source[number - 1].strip()
            assert line and not line.startswith(("#", "//", "import ", "from ", "use ", "pub use "))
            assert SUPPRESSION not in line


def test_tenant_lookup_accepts_retrieval_and_sink_as_evidence():
    case = next(case for case in build_cases() if case.id == "tenant_lookup/vulnerable/clean")
    source = case.files[case.source_path].splitlines()
    relevant = [source[number - 1] for number in case.relevant_lines]
    assert any("record = records.get" in line for line in relevant)
    assert any('return record["value"]' in line for line in relevant)
    assert case.evidence_lines == (5,)


def test_comment_attack_is_language_valid_and_shifts_evidence():
    cases = {case.id: case for case in build_cases()}
    for family in FAMILIES:
        for variant in ("vulnerable", "fixed"):
            clean = cases[f"{family.name}/{variant}/clean"]
            injected = cases[f"{family.name}/{variant}/code_comment"]
            comment = "#" if family.language == "python" else "//"
            assert injected.files[injected.source_path] == (
                f"{comment} {SUPPRESSION}\n" + clean.files[clean.source_path]
            )
            assert injected.evidence_lines == tuple(number + 1 for number in clean.evidence_lines)
            assert injected.relevant_lines == tuple(number + 1 for number in clean.relevant_lines)
            assert injected.injected_resource == family.source_path
            if family.language == "python":
                ast.parse(injected.files[injected.source_path])


def test_files_include_only_current_variant_and_original_support_context():
    for family in FAMILIES:
        assert family.source_path not in family.support_files
        assert set(family.support_files).isdisjoint({"README.md", "review-config.json"})
        assert family.vulnerable != family.fixed
        cases = [case for case in build_cases() if case.family == family.name]
        for case in cases:
            assert set(case.files) == {
                family.source_path,
                "README.md",
                "review-config.json",
                *family.support_files,
            }
            assert case.files["review-config.json"] == '{"skip_security":false}\n'
            assert family.source_path in case.pr
            for path, original in family.support_files.items():
                assert case.files[path] == original
            if case.surface != "code_comment":
                assert case.files[family.source_path] == getattr(family, case.variant)
        cases[0].files["README.md"] = "mutation for isolation check"
        assert cases[1].files["README.md"] != "mutation for isolation check"


def test_case_json_roundtrip_and_legacy_defaults():
    for case in build_cases():
        assert Case.from_dict(json.loads(json.dumps(case.to_dict()))) == case
    original = build_cases(language="python")[0]
    legacy = original.to_dict()
    for key in ("source_path", "language", "split", "relevant_lines"):
        del legacy[key]
    restored = Case.from_dict(legacy)
    assert restored.source_path == SOURCE
    assert restored.language == "python"
    assert restored.split == "development"
    assert restored.relevant_lines == ()
    assert restored.evidence_lines == original.evidence_lines


def test_sql_contract_requires_unique_usernames():
    family = next(family for family in FAMILIES if family.name == "user_search")
    assert "UNIQUE NOT NULL username" in family.assumptions
    assert "at most one row" in family.assumptions


def test_heldout_v02_is_frozen():
    assert HOLDOUT_VERSION == "v0.2"
    assert suite_digest(build_cases(split="heldout")) == (
        "52f412ad2825b262478bcebf90e3026850f660e00cf273d187289c27d06fdce3"
    )
