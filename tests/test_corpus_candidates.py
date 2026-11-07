"""Synthetic-only tests for the inert candidate metadata catalog."""

import ast
import builtins
import json
import os
import socket
import subprocess
import sys
import urllib.request
import warnings
from collections import OrderedDict
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from review_boundary import corpus_candidates
from review_boundary.corpus_candidates import (
    MAX_CANDIDATE_CATALOG_BYTES,
    CandidateCatalog,
    candidate_catalog_summary,
    load_candidate_catalog,
    parse_candidate_catalog,
)

SENTINEL = "SENTINEL_DO_NOT_ECHO_7f3a"
RECORD_FIELDS = (
    "candidate_id",
    "upstream_url",
    "advisory_url",
    "aliases",
    "language",
    "proposed_source_group",
    "comparison_revision",
    "selected_change_revision",
    "metadata_status",
    "runtime_status",
    "license_status",
    "disposition",
    "evidence_urls",
    "note",
)


def record(**changes):
    value = {
        "candidate_id": "example-one",
        "upstream_url": "https://example.invalid/org/project",
        "advisory_url": "https://example.invalid/advisory/1",
        "aliases": ["EX-0001"],
        "language": "python",
        "proposed_source_group": "example_group",
        "comparison_revision": "a" * 40,
        "selected_change_revision": "b" * 40,
        "metadata_status": "researched",
        "runtime_status": "unknown",
        "license_status": "unknown",
        "disposition": "research",
        "evidence_urls": ["https://example.invalid/evidence/1"],
        "note": "Synthetic metadata only.",
    }
    value.update(changes)
    return value


def catalog(*records, **changes):
    value = {"schema_version": 1, "records": list(records)}
    value.update(changes)
    return value


def numbered(count):
    return [record(candidate_id=f"cand-{index}") for index in range(count)]


def write(tmp_path, raw, name="catalog.json"):
    path = tmp_path / name
    path.write_bytes(raw)
    return path


# Valid input


def test_valid_catalog_round_trips_with_tuples_and_explicit_nulls():
    sparse = record(
        candidate_id="second",
        advisory_url=None,
        aliases=[],
        proposed_source_group=None,
        comparison_revision=None,
        selected_change_revision=None,
        evidence_urls=[],
        metadata_status="unknown",
    )
    data = catalog(record(), sparse)
    parsed = parse_candidate_catalog(data)
    assert type(parsed) is CandidateCatalog
    assert isinstance(parsed.records, tuple)
    assert parsed.records[0].aliases == ("EX-0001",)
    assert parsed.records[1].advisory_url is None
    assert parsed.model_dump(mode="json") == data


def test_empty_catalog_is_allowed_and_models_are_frozen():
    parsed = parse_candidate_catalog(catalog())
    assert parsed.records == ()
    with pytest.raises(ValidationError):
        parsed.schema_version = 1
    one = parse_candidate_catalog(catalog(record()))
    with pytest.raises(ValidationError):
        one.records[0].note = "changed"


@pytest.mark.parametrize("field", RECORD_FIELDS)
def test_every_record_field_is_required(field):
    value = record()
    del value[field]
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(value))


@pytest.mark.parametrize("key", ["schema_version", "records"])
def test_top_level_fields_are_required(key):
    value = catalog()
    del value[key]
    with pytest.raises(ValueError):
        parse_candidate_catalog(value)


@pytest.mark.parametrize(
    "field",
    ["advisory_url", "proposed_source_group", "comparison_revision", "selected_change_revision"],
)
def test_nullable_fields_accept_explicit_null(field):
    parsed = parse_candidate_catalog(catalog(record(**{field: None})))
    assert getattr(parsed.records[0], field) is None


# Forbidden fields and statuses


FORBIDDEN_FIELDS = (
    "runtime",
    "admission",
    "admitted",
    "callable",
    "callback",
    "import",
    "module",
    "command",
    "env",
    "local_source",
    "oracle",
    "registration",
    "register",
    "path",
)


@pytest.mark.parametrize("name", FORBIDDEN_FIELDS)
def test_runtime_and_admission_fields_are_absent_from_the_schema(name):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(**{name: "value"})))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(), **{name: "value"}))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("metadata_status", "verified"),
        ("metadata_status", "admitted"),
        ("runtime_status", "admitted"),
        ("runtime_status", "runnable"),
        ("license_status", "approved"),
        ("disposition", "admitted"),
        ("disposition", "registered"),
        ("disposition", "Research"),
    ],
)
def test_statuses_outside_the_closed_sets_are_rejected(field, value):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(**{field: value})))


# Versions and identity


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 0, 2, None, [1]])
def test_schema_version_must_be_the_exact_integer_one(version):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(schema_version=version))


def test_extra_top_level_key_is_rejected():
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(extra=1))


@pytest.mark.parametrize("slug", ["", "A", "1a", "-a", "_a", "a b", "a.b", "a" * 65, "é"])
def test_candidate_id_must_be_a_lowercase_slug(slug):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(candidate_id=slug)))


@pytest.mark.parametrize("slug", ["a", "a" * 64, "a_b-c9"])
def test_candidate_id_slug_bounds_are_inclusive(slug):
    assert parse_candidate_catalog(catalog(record(candidate_id=slug))).records[0].candidate_id


def test_duplicate_ids_aliases_and_evidence_are_rejected():
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(), record()))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(aliases=["EX-1", "EX-1"])))
    url = "https://example.invalid/e"
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(evidence_urls=[url, url])))


# Bounds


def test_record_count_bound_is_inclusive_at_sixty_four():
    assert len(parse_candidate_catalog(catalog(*numbered(64))).records) == 64
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(*numbered(65)))


def test_alias_and_evidence_count_bounds():
    aliases = [f"EX-{index}" for index in range(17)]
    assert len(parse_candidate_catalog(catalog(record(aliases=aliases[:16]))).records) == 1
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(aliases=aliases)))
    urls = [f"https://example.invalid/e/{index}" for index in range(9)]
    assert len(parse_candidate_catalog(catalog(record(evidence_urls=urls[:8]))).records) == 1
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(evidence_urls=urls)))


@pytest.mark.parametrize("note", ["é" * 128, "x" * 256, "ascii and 日本語 text"])
def test_safe_text_accepts_values_within_character_and_byte_caps(note):
    assert parse_candidate_catalog(catalog(record(note=note))).records[0].note == note


@pytest.mark.parametrize(
    "note",
    [
        "",
        "x" * 257,
        "é" * 129,
        "a\x00b",
        "a\x1fb",
        "a\x7fb",
        "a\x80b",
        "a\x85b",
        "a\x9fb",
        "a\nb",
        "\ud800",
        "x\udc00y",
    ],
)
def test_unsafe_text_is_rejected(note):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(note=note)))


@pytest.mark.parametrize(
    "url",
    [
        "http://example.invalid/x",
        "ftp://example.invalid/x",
        "https://user:secret@example.invalid/x",
        "https://example.invalid/x#fragment",
        "https:///path",
        "https://example.invalid/a\x85b",
        "https://example.invalid/a\x7fb",
        "https://example.invalid/" + "é" * 250,
        "https://example.invalid/" + "x" * 500,
    ],
)
def test_unsafe_urls_are_rejected(url):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(upstream_url=url)))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(evidence_urls=[url])))


@pytest.mark.parametrize("revision", ["a" * 39, "a" * 41, "A" * 40, "g" * 40, "", 5])
def test_revisions_must_be_full_lowercase_hex(revision):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(comparison_revision=revision)))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(selected_change_revision=revision)))


# Python object shapes


class CustomObject:
    pass


class StrSubclass(str):
    pass


class DictSubclass(dict):
    pass


def generator():
    yield record()


@pytest.mark.parametrize(
    "value",
    [
        [],
        (),
        None,
        "{}",
        b"{}",
        DictSubclass(catalog()),
        OrderedDict(catalog()),
        {1: "x", "schema_version": 1, "records": []},
        {"schema_version": 1, "records": ()},
        {"schema_version": 1, "records": (record(),)},
        {"schema_version": 1, "records": {1}},
        {"schema_version": 1, "records": generator()},
        {"schema_version": 1, "records": [CustomObject()]},
        {"schema_version": 1, "records": [record(note=StrSubclass("x"))]},
        {"schema_version": 1, "records": [record(note=CustomObject())]},
        {"schema_version": 1, "records": [record(aliases=("EX-1",))]},
        {"schema_version": 1, "records": [record(note=Decimal(1))]},
        {"schema_version": 1, "records": [record(note=b"bytes")]},
        {"schema_version": True, "records": []},
        {StrSubclass("schema_version"): 1, "records": []},
    ],
)
def test_only_exact_json_trees_are_accepted(value):
    with pytest.raises(ValueError):
        parse_candidate_catalog(value)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf"), 2**70, -(2**70)])
def test_nonfinite_and_huge_scalars_are_rejected(bad):
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(), extra=bad))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(note=bad)))


def test_excessive_nesting_is_rejected_without_recursion_errors():
    deep = []
    for _ in range(5000):
        deep = [deep]
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(), extra=deep))
    nested = {}
    for _ in range(5000):
        nested = {"a": nested}
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(), extra=nested))


def test_cyclic_input_is_rejected():
    loop = []
    loop.append(loop)
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(), extra=loop))


def test_whole_input_byte_bound_is_checked_before_the_json_parser(monkeypatch):
    calls = []
    real = corpus_candidates.parse_json_object

    def spy(raw):
        calls.append(len(raw))
        return real(raw)

    monkeypatch.setattr(corpus_candidates, "parse_json_object", spy)
    oversized = catalog(record(), extra=["x" * 500] * 600)
    assert len(json.dumps(oversized)) > MAX_CANDIDATE_CATALOG_BYTES
    with pytest.raises(ValueError):
        parse_candidate_catalog(oversized)
    assert calls == []
    parse_candidate_catalog(catalog(record()))
    assert len(calls) == 1


def test_too_many_records_are_rejected_before_the_json_parser(monkeypatch):
    calls = []
    monkeypatch.setattr(corpus_candidates, "parse_json_object", lambda raw: calls.append(raw))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(*numbered(65)))
    assert calls == []


# Static, generic errors


def sentinel_inputs():
    slug = "sentinel-do-not-echo"
    return [
        catalog(record(), **{SENTINEL: 1}),
        catalog(record(), extra=SENTINEL),
        catalog(record(**{SENTINEL: 1})),
        catalog(record(note=SENTINEL + "\x00")),
        catalog(record(note=SENTINEL + "\ud800")),
        catalog(record(upstream_url="https://user:pw@example.invalid/" + SENTINEL)),
        catalog(record(candidate_id=slug), record(candidate_id=slug, note=SENTINEL)),
        catalog(record(aliases=[SENTINEL, SENTINEL])),
        catalog(record(runtime_status=SENTINEL)),
        catalog(record(), schema_version=SENTINEL),
        {SENTINEL + "\x85": 1},
        {1: SENTINEL},
        {"schema_version": 1, "records": [CustomObject(), SENTINEL]},
    ]


def test_parse_errors_are_static_and_never_echo_input():
    messages = set()
    for value in sentinel_inputs():
        with pytest.raises(ValueError) as caught:
            parse_candidate_catalog(value)
        error = caught.value
        assert type(error) is ValueError
        assert SENTINEL not in str(error)
        assert error.__cause__ is None
        assert error.__context__ is None
        messages.add(str(error))
    assert len(messages) == 1


def test_load_and_summary_errors_are_static_and_never_echo_input(tmp_path):
    with pytest.raises(ValueError) as parsed:
        parse_candidate_catalog({SENTINEL: 1})
    expected = str(parsed.value)
    secret_dir = tmp_path / SENTINEL
    secret_dir.mkdir()
    cases = [
        secret_dir / "missing.json",
        secret_dir,
        write(secret_dir, json.dumps(catalog(record(), **{SENTINEL: 1})).encode()),
        write(secret_dir, b'{"a": 1, "a": 2, "' + SENTINEL.encode() + b'": 3}', "dup.json"),
    ]
    for path in cases:
        with pytest.raises(ValueError) as caught:
            load_candidate_catalog(path)
        error = caught.value
        assert type(error) is ValueError
        assert SENTINEL not in str(error) and str(secret_dir) not in str(error)
        assert error.__cause__ is None and error.__context__ is None
        assert str(error) == expected
    with pytest.raises(ValueError) as summary:
        candidate_catalog_summary({SENTINEL: 1})
    assert SENTINEL not in str(summary.value)
    assert str(summary.value) == expected


# File loading


def test_load_matches_parse_for_a_regular_file(tmp_path):
    data = catalog(record(), record(candidate_id="other"))
    path = write(tmp_path, json.dumps(data).encode())
    assert load_candidate_catalog(path) == parse_candidate_catalog(data)


def test_load_size_bound_is_inclusive_and_rejects_one_more_byte(tmp_path):
    base = json.dumps(catalog(record())).encode()
    exact = base + b" " * (MAX_CANDIDATE_CATALOG_BYTES - len(base))
    assert len(exact) == MAX_CANDIDATE_CATALOG_BYTES
    assert len(load_candidate_catalog(write(tmp_path, exact)).records) == 1
    with pytest.raises(ValueError):
        load_candidate_catalog(write(tmp_path, exact + b" ", "over.json"))


def test_load_rejects_large_sparse_files_without_reading_them(tmp_path):
    path = tmp_path / "sparse.json"
    with path.open("wb") as stream:
        stream.truncate(MAX_CANDIDATE_CATALOG_BYTES + 10)
    with pytest.raises(ValueError):
        load_candidate_catalog(path)


def test_load_rejects_missing_directory_and_non_path_arguments(tmp_path):
    for bad in (tmp_path / "missing.json", tmp_path, str(tmp_path), None):
        with pytest.raises(ValueError):
            load_candidate_catalog(bad)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are unavailable")
def test_load_rejects_a_fifo_without_blocking(tmp_path):
    path = tmp_path / "pipe.json"
    os.mkfifo(path)
    with pytest.raises(ValueError):
        load_candidate_catalog(path)


def test_load_requires_strict_utf8_without_encoding_detection(tmp_path):
    text = json.dumps(catalog(record()))
    bad_inputs = {
        "invalid_utf8.json": text.replace("python", "py\\xff").encode().replace(b"\\xff", b"\xff"),
        "utf16.json": text.encode("utf-16"),
        "utf16le.json": text.encode("utf-16-le"),
        "utf32.json": text.encode("utf-32"),
        "bom.json": b"\xef\xbb\xbf" + text.encode(),
        "nul.json": text.encode() + b"\x00",
    }
    for name, raw in bad_inputs.items():
        with pytest.raises(ValueError):
            load_candidate_catalog(write(tmp_path, raw, name))


def test_load_keeps_duplicate_key_nonfinite_surrogate_and_depth_checks(tmp_path):
    text = json.dumps(catalog(record()))
    duplicate = text.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1')
    surrogate = text.replace("Synthetic metadata only.", "bad \\ud800 text")
    nonfinite = text[:-1] + ', "extra": NaN}'
    deep = text[:-1] + ', "extra": ' + "[" * 200 + "]" * 200 + "}"
    for name, raw in (
        ("dup.json", duplicate),
        ("surrogate.json", surrogate),
        ("nan.json", nonfinite),
        ("deep.json", deep),
        ("array.json", "[]"),
        ("scalar.json", "1"),
        ("empty.json", ""),
    ):
        with pytest.raises(ValueError):
            load_candidate_catalog(write(tmp_path, raw.encode(), name))


# Summary


def test_summary_has_exact_keys_and_every_allowed_category_in_sorted_order():
    second = record(
        candidate_id="second",
        metadata_status="unknown",
        runtime_status="unavailable",
        license_status="inventory_recorded",
        disposition="held",
    )
    summary = candidate_catalog_summary(parse_candidate_catalog(catalog(record(), second)))
    assert summary == {
        "schema_version": 1,
        "candidate_count": 2,
        "metadata_status_counts": {"researched": 1, "unknown": 1},
        "runtime_status_counts": {"requirements_recorded": 0, "unavailable": 1, "unknown": 1},
        "license_status_counts": {"inventory_recorded": 1, "notices_pending": 0, "unknown": 1},
        "disposition_counts": {"deferred": 0, "held": 1, "rejected": 0, "research": 1},
        "admission": "not_established",
        "authenticity": "unverified_metadata",
        "independence": "not_inferred",
    }
    for key in ("metadata_status_counts", "runtime_status_counts", "license_status_counts"):
        assert list(summary[key]) == sorted(summary[key])
    assert list(summary["disposition_counts"]) == sorted(summary["disposition_counts"])
    json.dumps(summary, allow_nan=False)


def test_empty_summary_lists_zero_counts_and_no_authority():
    summary = candidate_catalog_summary(parse_candidate_catalog(catalog()))
    assert summary["candidate_count"] == 0
    assert all(
        count == 0
        for key in ("metadata_status_counts", "runtime_status_counts", "disposition_counts")
        for count in summary[key].values()
    )
    assert summary["admission"] == "not_established"


def test_shared_group_or_alias_never_implies_independence_or_admission():
    shared = [
        record(candidate_id="one", proposed_source_group="same_group", aliases=["EX-1"]),
        record(candidate_id="two", proposed_source_group="same_group", aliases=["EX-1"]),
    ]
    distinct = [
        record(candidate_id="one", proposed_source_group="group_a", aliases=["EX-1"]),
        record(candidate_id="two", proposed_source_group="group_b", aliases=["EX-2"]),
    ]
    first = candidate_catalog_summary(parse_candidate_catalog(catalog(*shared)))
    second = candidate_catalog_summary(parse_candidate_catalog(catalog(*distinct)))
    assert first == second
    assert first["independence"] == "not_inferred"
    assert first["admission"] == "not_established"


def test_summary_revalidates_unchecked_model_copies():
    good = parse_candidate_catalog(catalog(record()))
    item = good.records[0]
    forged_status = item.model_copy(update={"disposition": "admitted"})
    forged_slug = item.model_copy(update={"candidate_id": "Not A Slug"})
    forged_extra_url = item.model_copy(update={"upstream_url": "http://example.invalid/"})
    forged = [
        good.model_copy(update={"records": (forged_status,)}),
        good.model_copy(update={"records": (forged_slug,)}),
        good.model_copy(update={"records": (forged_extra_url,)}),
        good.model_copy(update={"records": (item, item)}),
        good.model_copy(update={"records": ("junk",)}),
        good.model_copy(update={"schema_version": True}),
    ]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for catalog_value in forged:
            with pytest.raises(ValueError):
                candidate_catalog_summary(catalog_value)


@pytest.mark.parametrize("value", [None, {}, catalog(), [], "catalog"])
def test_summary_requires_a_catalog_model(value):
    with pytest.raises(ValueError):
        candidate_catalog_summary(value)


def test_summary_rejects_catalog_subclasses():
    class Sub(CandidateCatalog):
        pass

    with pytest.raises(ValueError):
        candidate_catalog_summary(Sub(schema_version=1, records=()))


# Inert data: nothing is fetched, imported, registered or invoked


def test_parse_load_and_summary_never_fetch_import_register_or_invoke(monkeypatch, tmp_path):
    evil = "evil_candidate_module"
    called = []

    def forbid(name):
        def inner(*_args, **_kwargs):
            called.append(name)
            raise AssertionError(name)

        return inner

    monkeypatch.setattr(socket, "socket", forbid("socket"))
    monkeypatch.setattr(socket, "create_connection", forbid("create_connection"))
    monkeypatch.setattr(urllib.request, "urlopen", forbid("urlopen"))
    monkeypatch.setattr(subprocess, "Popen", forbid("Popen"))
    monkeypatch.setattr(os, "system", forbid("system"))
    imported = []
    real_import = builtins.__import__

    def spy(name, *args, **kwargs):
        imported.append(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", spy)
    code = f"import {evil}; {evil}.run(); __import__('{evil}')"
    data = catalog(
        record(note=code, language="import-text", upstream_url="https://example.invalid/run?x=1")
    )
    path = write(tmp_path, json.dumps(data).encode())
    parsed = parse_candidate_catalog(data)
    assert load_candidate_catalog(path) == parsed
    candidate_catalog_summary(parsed)
    assert parsed.records[0].note == code
    assert called == []
    assert not [name for name in imported if evil in name]
    assert evil not in sys.modules


def test_callable_and_registration_values_are_rejected_and_never_invoked():
    invoked = []

    def callback():
        invoked.append(True)

    for key in ("callable", "callback", "registration", "oracle", "import", "module"):
        with pytest.raises(ValueError):
            parse_candidate_catalog(catalog(record(**{key: callback})))
        with pytest.raises(ValueError):
            parse_candidate_catalog(catalog(record(**{key: "evil_candidate_module:run"})))
    with pytest.raises(ValueError):
        parse_candidate_catalog(catalog(record(note=callback)))
    assert invoked == []


def test_source_imports_no_runner_registry_sdk_or_network_modules():
    tree = ast.parse(Path(corpus_candidates.__file__).read_text(encoding="utf-8"))
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
        "urllib.request",
        "importlib",
        "upstream",
    )
    assert not [name for name in names if any(part in name for part in forbidden)]
    assert {".corpus_manifest", ".json_input"} <= names
