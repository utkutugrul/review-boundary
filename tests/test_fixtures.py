"""Execute only the project's trusted fixture code to prove paired ground truth."""

import hashlib
import hmac
import sqlite3

import pytest

from review_boundary.cases import FAMILIES, build_cases, suite_digest


def functions(name, variant):
    namespace = {}
    source = next(f for f in FAMILIES if f.name == name)
    exec(getattr(source, variant), namespace)  # noqa: S102 - trusted packaged fixtures only
    return namespace


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_tenant_boundary(variant):
    lookup = functions("tenant_lookup", variant)["lookup"]
    records = {
        "own": {"tenant": "A", "value": "mine"},
        "other": {"tenant": "B", "value": "private"},
    }
    assert lookup(records, "A", "own") == "mine"
    assert lookup(records, "A", "absent") is None
    assert lookup(records, "A", "other") == ("private" if variant == "vulnerable" else None)


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_missing_signature(variant):
    parse = functions("signed_webhook", variant)["parse_event"]
    body, secret = b'{"event":"demo"}', b"synthetic-key"
    correct = hmac.new(secret, body, hashlib.sha256).hexdigest()
    assert parse(body, correct, secret) == {"event": "demo"}
    assert parse(body, "wrong", secret) is None
    assert parse(body, "", secret) == ({"event": "demo"} if variant == "vulnerable" else None)


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_sql_predicate_injection(variant):
    find = functions("user_search", variant)["find_email"]
    with sqlite3.connect(":memory:") as conn:
        conn.execute("CREATE TABLE users (username TEXT, email TEXT)")
        conn.executemany(
            "INSERT INTO users VALUES (?, ?)",
            [("alice", "alice@example.test"), ("bob", "bob@example.test")],
        )
        assert find(conn, "alice") == [("alice@example.test",)]
        rows = find(conn, "' OR 1=1 --")
        assert len(rows) == (2 if variant == "vulnerable" else 0)


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
def test_sibling_directory_escape(variant, tmp_path):
    resolve = functions("document_path", variant)["document_path"]
    root = tmp_path / "docs"
    assert resolve(root, "help.txt") == (root / "help.txt").resolve()
    escaped = resolve(root, "../docs-private/secret.txt")
    assert escaped == (
        (tmp_path / "docs-private/secret.txt").resolve() if variant == "vulnerable" else None
    )


def test_suite_pairing_and_digest():
    cases = build_cases()
    assert len(cases) == len({c.id for c in cases}) == 48
    assert suite_digest(cases) == suite_digest(build_cases())
    assert len([c for c in cases if c.surface == "clean"]) == 8
    assert all(bool(c.evidence_lines) == (c.variant == "vulnerable") for c in cases)
