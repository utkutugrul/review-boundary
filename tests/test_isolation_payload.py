# Pure parser, codec and data tests. Nothing here executes the bootstrap source or any
# candidate text: the bootstrap is only parsed into an AST and digest-checked.

import ast
import base64
import hashlib
import json

import pytest

from review_boundary import isolation_payload as payload
from review_boundary.isolation_payload import (
    BOOTSTRAP_SHA256,
    BOOTSTRAP_SOURCE,
    WIRE_PROTOCOL,
    ArtifactMetadata,
    IsolatedArtifact,
    IsolatedJob,
    IsolatedTextFile,
    ParsedContainerResult,
    artifact_digest,
    artifact_manifest,
    decode_result_wire,
    encode_command_input,
    encode_observer_input,
    job_digest,
    parse_isolated_job,
)

Q = chr(34)
BS = chr(92)
E_ACUTE = chr(0xE9)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def canon(tree):
    return json.dumps(tree, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def make_job(argv=("python", "a.py"), files=(), collect=()):
    return IsolatedJob(schema_version=1, argv=argv, files=files, collect_paths=collect)


def text_file(path="a.py", content="x"):
    return IsolatedTextFile(path=path, content=content)


def job_tree(content="SENTINEL", **over):
    tree = {
        "schema_version": 1,
        "argv": ["python", "a.py"],
        "files": [{"path": "a.py", "content": content}],
        "collect_paths": [],
    }
    tree.update(over)
    return tree


def job_json_with(literal):
    text = json.dumps(job_tree())
    return text.replace(Q + "SENTINEL" + Q, literal).encode()


# ---------------------------------------------------------------- schema and closed shape


def test_valid_job_parses_from_json_arrays_and_roundtrips_fields():
    raw = json.dumps(job_tree("print(1)" + chr(10) + chr(9))).encode()
    job = parse_isolated_job(raw)
    assert job.argv == ("python", "a.py")
    assert job.files[0].content == "print(1)" + chr(10) + chr(9)
    assert job.collect_paths == ()


@pytest.mark.parametrize("bad", [True, 1.0, "1", 2, 0, None])
def test_schema_version_must_be_exact_int_one(bad):
    with pytest.raises(ValueError):
        IsolatedJob(schema_version=bad, argv=("a",), files=(), collect_paths=())
    with pytest.raises(ValueError):
        parse_isolated_job(json.dumps(job_tree(schema_version=bad)).encode())


def test_closed_fields_and_model_field_sets():
    assert set(IsolatedJob.model_fields) == {"schema_version", "argv", "files", "collect_paths"}
    assert set(IsolatedTextFile.model_fields) == {"path", "content"}
    assert set(IsolatedArtifact.model_fields) == {"path", "data"}
    assert set(ArtifactMetadata.model_fields) == {"path", "byte_count", "sha256"}
    assert set(ParsedContainerResult.model_fields) == {
        "stdout",
        "stderr",
        "artifacts",
        "missing_paths",
        "claimed_child_return_code",
        "claimed_status",
        "error_code",
    }
    with pytest.raises(ValueError):
        parse_isolated_job(json.dumps(job_tree(stdin="x")).encode())
    missing = job_tree()
    del missing["collect_paths"]
    with pytest.raises(ValueError):
        parse_isolated_job(json.dumps(missing).encode())
    with pytest.raises(ValueError):
        IsolatedJob(schema_version=1, argv=("a",), files=(), collect_paths=(), env={})


def test_python_lists_rejected_for_tuple_fields():
    with pytest.raises(ValueError):
        IsolatedJob(schema_version=1, argv=["a"], files=(), collect_paths=())
    with pytest.raises(ValueError):
        IsolatedJob(schema_version=1, argv=("a",), files=[], collect_paths=())
    with pytest.raises(ValueError):
        IsolatedJob(schema_version=1, argv=("a",), files=(), collect_paths=[])


# ---------------------------------------------------------------- strict JSON text rules


def test_raw_text_hazards_are_rejected_with_fixed_errors():
    assert parse_isolated_job(job_json_with(Q + "ok" + Q)).files[0].content == "ok"
    bad_inputs = [
        b"\xef\xbb\xbf" + job_json_with(Q + "x" + Q),
        job_json_with(Q + "x" + Q).replace(b"x", b"\xff", 1),
        job_json_with("NaN"),
        job_json_with("Infinity"),
        job_json_with("-Infinity"),
        job_json_with("1.5"),
        job_json_with(Q + BS + "u0000" + Q),
        job_json_with(Q + BS + "ud800" + Q),
        job_json_with(Q + BS + "ufeffx" + Q),
        job_json_with(Q + chr(0xFEFF) + "x" + Q),
        job_json_with(Q + "x" + Q)[:-5],
    ]
    for raw in bad_inputs:
        with pytest.raises(ValueError) as info:
            parse_isolated_job(raw)
        assert str(info.value) == "Invalid isolated job."
        assert info.value.__context__ is None


def test_source_allows_newlines_tabs_and_surrogate_pairs():
    pair = Q + BS + "ud83d" + BS + "ude00" + BS + "n" + BS + "t" + Q
    job = parse_isolated_job(job_json_with(pair))
    assert job.files[0].content == chr(0x1F600) + chr(10) + chr(9)


def test_duplicate_keys_including_escaped_names_rejected():
    text = json.dumps(job_tree())
    parse_isolated_job(text.encode())
    dup = text[:-1] + "," + Q + "argv" + Q + ":[" + Q + "b" + Q + "]}"
    with pytest.raises(ValueError):
        parse_isolated_job(dup.encode())
    escaped = text[:-1] + "," + Q + "ar" + BS + "u0067v" + Q + ":[" + Q + "b" + Q + "]}"
    with pytest.raises(ValueError):
        parse_isolated_job(escaped.encode())


def test_depth_limit_is_sixteen_edges_from_root_and_ignores_string_brackets():
    ok = b"[" * 17 + b"]" * 17
    assert payload._strict_json(ok, 100) is not None
    with pytest.raises(ValueError):
        payload._strict_json(b"[" * 18 + b"]" * 18, 100)
    nested = ("{" + Q + "a" + Q + ":") * 18 + "1" + "}" * 18
    with pytest.raises(ValueError):
        payload._strict_json(nested.encode(), 1000)
    assert payload._strict_json((Q + "[" * 40 + Q).encode(), 100) == "[" * 40
    with pytest.raises(ValueError):
        payload._strict_json(b"[1]" + b" " * 100, 50)


# ---------------------------------------------------------------- paths

BAD_PATHS = [
    "",
    "/a",
    "a/",
    "a//b",
    ".",
    "..",
    "a/./b",
    "a/../b",
    "a" + BS + "b",
    "a:b",
    "a" + chr(0),
    "a" + chr(31),
    "a" + chr(127),
    "a" + chr(0x85),
    "a" + chr(0xD800),
    ".git/x",
    "x/.git",
    ".env",
    "x/.env.local",
    E_ACUTE * 65,
    "a" * 129,
    "/".join(["a" * 100] * 6),
]
GOOD_PATHS = [
    "a",
    "a.git",
    ".gitignore",
    ".environment",
    ".envrc",
    "x/.GIT/y",
    E_ACUTE * 64,
    "a" * 128,
    "dir/sub/file.py",
    "/".join(["a" * 127] * 4),
]


@pytest.mark.parametrize("path", BAD_PATHS)
def test_bad_paths_rejected_everywhere(path):
    with pytest.raises(ValueError):
        IsolatedTextFile(path=path, content="x")
    with pytest.raises(ValueError):
        IsolatedArtifact(path=path, data=b"")
    with pytest.raises(ValueError):
        make_job(collect=(path,))


@pytest.mark.parametrize("path", GOOD_PATHS)
def test_good_paths_accepted(path):
    assert IsolatedTextFile(path=path, content="x").path == path
    assert IsolatedArtifact(path=path, data=b"").path == path


def test_source_and_collect_sets_conflicts_are_independent():
    with pytest.raises(ValueError):
        make_job(files=(text_file("a"), text_file("a")))
    with pytest.raises(ValueError):
        make_job(files=(text_file("a"), text_file("a/b")))
    with pytest.raises(ValueError):
        make_job(files=(text_file("a/b/c"), text_file("a/b")))
    with pytest.raises(ValueError):
        make_job(collect=("a", "a"))
    with pytest.raises(ValueError):
        make_job(collect=("x/y", "x"))
    assert make_job(files=(text_file("a"), text_file("ab"))).files[1].path == "ab"
    assert make_job(files=(text_file("x.py"),), collect=("x.py",)).collect_paths == ("x.py",)
    assert make_job(files=(text_file("a"),), collect=("a/b",)).collect_paths == ("a/b",)


# ---------------------------------------------------------------- argv, content and count caps


def test_argv_caps_and_controls():
    assert len(make_job(argv=("a",) * 64).argv) == 64
    for bad in [(), ("a",) * 65, ("",), ("a", "")]:
        with pytest.raises(ValueError):
            make_job(argv=bad)
    assert make_job(argv=("a" * 4096,)).argv
    assert make_job(argv=(E_ACUTE * 2048,)).argv
    for bad in [("a" * 4097,), (E_ACUTE * 2049,)]:
        with pytest.raises(ValueError):
            make_job(argv=bad)
    assert make_job(argv=("a" * 4096,) * 8).argv
    with pytest.raises(ValueError):
        make_job(argv=("a" * 4096,) * 8 + ("a",))
    for control in [chr(0), chr(10), chr(9), chr(13), chr(127), chr(0x85), chr(0x9F), chr(0xD800)]:
        with pytest.raises(ValueError):
            make_job(argv=("a" + control + "b",))


def test_file_content_and_count_caps_with_multibyte_boundaries():
    assert text_file(content="a" * 65536).content
    assert text_file(content=E_ACUTE * 32768).content
    for bad in ["a" * 65537, E_ACUTE * 32769, "a" + chr(0), chr(0xFEFF) + "a", chr(0xD800)]:
        with pytest.raises(ValueError):
            text_file(content=bad)
    assert text_file(content="").content == ""
    assert text_file(content="a" + chr(10) + chr(9) + "b").content
    files = tuple(text_file(f"f{i}", "a" * 65536) for i in range(64))
    big = make_job(files=files)
    assert len(encode_command_input(big)) <= 8388608
    with pytest.raises(ValueError):
        make_job(files=files + (text_file("extra"),))
    assert len(make_job(collect=("a", "b", "c", "d")).collect_paths) == 4
    with pytest.raises(ValueError):
        make_job(collect=("a", "b", "c", "d", "e"))


def test_artifact_data_strictness_and_cap():
    assert IsolatedArtifact(path="a", data=b"x" * 65536).data
    assert IsolatedArtifact(path="a", data=b"").data == b""
    with pytest.raises(ValueError):
        IsolatedArtifact(path="a", data=b"x" * 65537)
    with pytest.raises(ValueError):
        IsolatedArtifact(path="a", data="text")


# ---------------------------------------------------------------- canonical input wire


def test_command_input_is_canonical_closed_and_has_null_stdin():
    job = make_job(
        files=(text_file("a.py", E_ACUTE + chr(10)),),
        collect=("out",),
    )
    raw = encode_command_input(job)
    expected = {
        "schema_version": 1,
        "protocol": WIRE_PROTOCOL,
        "job": {
            "argv": ["python", "a.py"],
            "files": [{"path": "a.py", "data_b64": b64((E_ACUTE + chr(10)).encode())}],
            "collect_paths": ["out"],
        },
        "observer_input_b64": None,
    }
    assert raw == canon(expected)
    assert not raw.endswith(chr(10).encode())
    assert WIRE_PROTOCOL == "reviewboundary.isolated/1"


def test_observer_input_is_bounded_bytes_only():
    job = make_job()
    wire = json.loads(encode_observer_input(job, b"{" + b"1" * 510 + b"}"))
    assert base64.b64decode(wire["observer_input_b64"]) == b"{" + b"1" * 510 + b"}"
    assert json.loads(encode_observer_input(job, b""))["observer_input_b64"] == ""
    with pytest.raises(ValueError):
        encode_observer_input(job, b"x" * 513)
    with pytest.raises(ValueError):
        encode_observer_input(job, "text")
    with pytest.raises(ValueError):
        encode_observer_input(job, None)
    for bad in (bytearray(b"x"), memoryview(b"x"), 1, [1]):
        with pytest.raises(ValueError):
            encode_observer_input(job, bad)
    assert json.loads(encode_command_input(job))["observer_input_b64"] is None


def test_encoders_and_digest_revalidate_unsafe_instances():
    bad_constructed = IsolatedJob.model_construct(
        schema_version=1, argv=("a",), files=(), collect_paths=("../x",)
    )
    bad_copy = make_job().model_copy(update={"argv": ()})
    bad_list = make_job().model_copy(update={"argv": ["a"]})
    bad_file = make_job(files=(text_file(),)).model_copy(
        update={"files": (IsolatedTextFile.model_construct(path="/abs", content="x"),)}
    )
    for bad in (bad_constructed, bad_copy, bad_list, bad_file):
        with pytest.raises(ValueError):
            encode_command_input(bad)
        with pytest.raises(ValueError):
            encode_observer_input(bad, b"")
        with pytest.raises(ValueError):
            job_digest(bad)
        with pytest.raises(ValueError):
            decode_result_wire(b"{}", bad)
    with pytest.raises(ValueError):
        artifact_digest(IsolatedArtifact.model_construct(path="/abs", data=b"x"))
    with pytest.raises(ValueError):
        encode_command_input("not a job")


# ---------------------------------------------------------------- result wire

REQUESTED = make_job(collect=("out.txt", "dir/b.bin"))
ALL_MISSING = ["out.txt", "dir/b.bin"]


def result_tree(**over):
    tree = {
        "schema_version": 1,
        "protocol": WIRE_PROTOCOL,
        "status": "completed",
        "error_code": None,
        "claimed_child_return_code": 0,
        "stdout_b64": "aGVsbG8=",
        "stderr_b64": "d29ybGQ=",
        "artifacts": [{"path": "out.txt", "data_b64": "AAE="}],
        "missing_artifacts": ["dir/b.bin"],
    }
    tree.update(over)
    return tree


def wire(**over):
    return json.dumps(result_tree(**over)).encode()


def test_fixed_result_fixture_decodes_with_untrusted_fields():
    parsed = decode_result_wire(wire(), REQUESTED)
    assert parsed.stdout == b"hello"
    assert parsed.stderr == b"world"
    assert parsed.artifacts[0].path == "out.txt"
    assert parsed.artifacts[0].data == bytes([0, 1])
    assert parsed.missing_paths == ("dir/b.bin",)
    assert parsed.claimed_child_return_code == 0
    assert parsed.claimed_status == "completed"
    assert parsed.error_code is None


def test_hash_independent_of_decoded_result_wire_order():
    swapped = wire(artifacts=[], missing_artifacts=["dir/b.bin", "out.txt"])
    assert decode_result_wire(swapped, REQUESTED).artifacts == ()


@pytest.mark.parametrize("rc", [0, 1, -9, -255, 255])
def test_return_code_range_accepted(rc):
    assert decode_result_wire(wire(claimed_child_return_code=rc), REQUESTED)


@pytest.mark.parametrize("rc", [256, -256, True, False, 1.0, "0", [0]])
def test_return_code_rejects_out_of_range_and_wrong_types(rc):
    with pytest.raises(ValueError):
        decode_result_wire(wire(claimed_child_return_code=rc), REQUESTED)


def test_status_and_error_code_exactness():
    codes = [
        "invalid_input",
        "child_start_failed",
        "child_output_overflow",
        "child_timeout",
        "artifact_collection_failed",
    ]
    for code in codes:
        parsed = decode_result_wire(
            wire(
                status="error",
                error_code=code,
                claimed_child_return_code=None,
                artifacts=[],
                missing_artifacts=ALL_MISSING,
            ),
            REQUESTED,
        )
        assert parsed.error_code == code
        assert parsed.claimed_status == "error"
    bad = [
        wire(error_code="child_timeout"),
        wire(claimed_child_return_code=None),
        wire(status="error", error_code=None, artifacts=[], missing_artifacts=ALL_MISSING),
        wire(status="error", error_code="boom", artifacts=[], missing_artifacts=ALL_MISSING),
        wire(status="ok"),
        wire(status=None),
        wire(status="error", error_code="child_timeout", missing_artifacts=["other"]),
        wire(status="error", error_code="child_timeout", artifacts=[], missing_artifacts=[]),
    ]
    for raw in bad:
        with pytest.raises(ValueError):
            decode_result_wire(raw, REQUESTED)


def test_error_envelope_requires_exact_partition_of_requested_paths():
    parsed = decode_result_wire(
        wire(
            status="error",
            error_code="artifact_collection_failed",
            claimed_child_return_code=3,
            artifacts=[],
            missing_artifacts=ALL_MISSING,
        ),
        REQUESTED,
    )
    assert parsed.missing_paths == ("out.txt", "dir/b.bin")
    mixed = decode_result_wire(
        wire(status="error", error_code="child_timeout", claimed_child_return_code=None),
        REQUESTED,
    )
    assert mixed.artifacts[0].path == "out.txt"
    assert mixed.missing_paths == ("dir/b.bin",)
    assert mixed.claimed_status == "error"
    one = {"path": "out.txt", "data_b64": ""}
    incomplete = [
        {"artifacts": [], "missing_artifacts": ["out.txt"]},
        {"artifacts": [], "missing_artifacts": []},
        {"artifacts": [one], "missing_artifacts": []},
        {"artifacts": [one], "missing_artifacts": ["out.txt", "dir/b.bin"]},
        {"artifacts": [], "missing_artifacts": ["out.txt", "dir/b.bin", "extra"]},
    ]
    for over in incomplete:
        raw = wire(
            status="error", error_code="child_timeout", claimed_child_return_code=None, **over
        )
        with pytest.raises(ValueError) as info:
            decode_result_wire(raw, REQUESTED)
        assert str(info.value) == "Invalid isolated result."
    with pytest.raises(ValueError):
        ParsedContainerResult(
            stdout=b"",
            stderr=b"",
            artifacts=(),
            missing_paths=("a", "b", "c", "d", "e"),
            claimed_child_return_code=None,
            claimed_status="error",
            error_code="child_timeout",
        )


def test_exact_partition_of_requested_paths():
    one = {"path": "out.txt", "data_b64": ""}
    bad = [
        wire(artifacts=[], missing_artifacts=["out.txt"]),
        wire(artifacts=[one], missing_artifacts=["out.txt", "dir/b.bin"]),
        wire(artifacts=[one, one], missing_artifacts=["dir/b.bin"]),
        wire(artifacts=[{"path": "other", "data_b64": ""}], missing_artifacts=["dir/b.bin"]),
        wire(artifacts=[one], missing_artifacts=["dir/b.bin", "extra"]),
        wire(artifacts=[one], missing_artifacts=["dir/b.bin", "dir/b.bin"]),
        wire(artifacts=[{"path": "dir", "data_b64": ""}], missing_artifacts=["out.txt"]),
    ]
    for raw in bad:
        with pytest.raises(ValueError):
            decode_result_wire(raw, REQUESTED)


def test_result_closed_shape_and_protocol():
    base = result_tree()
    extra_key = dict(base, digest="0" * 64)
    missing_key = {k: v for k, v in base.items() if k != "stderr_b64"}
    bad = [
        json.dumps(extra_key).encode(),
        json.dumps(missing_key).encode(),
        wire(artifacts=[{"path": "out.txt", "data_b64": "AAE=", "sha256": "0" * 64}]),
        wire(protocol="reviewboundary.isolated/2"),
        wire(schema_version=True),
        wire(schema_version=2),
        wire(artifacts={}),
        b"[]",
        b"",
        b"{",
        codecs_bom() + wire(),
        wire()[:-1],
    ]
    for raw in bad:
        with pytest.raises(ValueError) as info:
            decode_result_wire(raw, REQUESTED)
        assert str(info.value) == "Invalid isolated result."
    with pytest.raises(ValueError):
        decode_result_wire(
            wire().decode().replace("{", "{" + Q + "status" + Q + ":1,", 1).encode(), REQUESTED
        )
    for raw in ("text", bytearray(wire()), None, b"\xff\xfe{}"):
        with pytest.raises(ValueError):
            decode_result_wire(raw, REQUESTED)


def codecs_bom():
    import codecs

    return codecs.BOM_UTF8


def test_result_size_caps_for_streams_and_artifacts():
    full = b"a" * 65536
    assert decode_result_wire(wire(stdout_b64=b64(full), stderr_b64=b64(full)), REQUESTED)
    for key in ("stdout_b64", "stderr_b64"):
        with pytest.raises(ValueError):
            decode_result_wire(wire(**{key: b64(full + b"a")}), REQUESTED)
    job = make_job(collect=("a", "b", "c", "d"))
    four = [{"path": p, "data_b64": b64(full)} for p in "abcd"]
    parsed = decode_result_wire(wire(artifacts=four, missing_artifacts=[]), job)
    assert sum(len(a.data) for a in parsed.artifacts) == 262144
    over = [{"path": "a", "data_b64": b64(full + b"a")}]
    with pytest.raises(ValueError):
        decode_result_wire(wire(artifacts=over, missing_artifacts=["b", "c", "d"]), job)
    five = four + [{"path": "e", "data_b64": ""}]
    with pytest.raises(ValueError):
        decode_result_wire(wire(artifacts=five, missing_artifacts=[]), job)
    with pytest.raises(ValueError):
        decode_result_wire(b"{" + b" " * 2097153, REQUESTED)


@pytest.mark.parametrize(
    "value",
    [
        "AQ",
        "AAF=",
        "AA E=",
        "AAE=" + chr(10),
        "AA-_",
        "AAE",
        "AAE=AAE=",
        "====",
        "AAE=" + chr(0xE9),
        "A" * 87385,
    ],
)
def test_noncanonical_base64_rejected(value):
    with pytest.raises(ValueError):
        decode_result_wire(wire(stdout_b64=value), REQUESTED)
    with pytest.raises(ValueError):
        decode_result_wire(
            wire(artifacts=[{"path": "out.txt", "data_b64": value}]),
            REQUESTED,
        )


def test_result_duplicate_nonfinite_and_float_rejected():
    text = wire().decode()
    dup = text[:-1] + "," + Q + "status" + Q + ":" + Q + "error" + Q + "}"
    for raw in (dup, text.replace("0,", "NaN,", 1), text.replace(": 0,", ": 0.0,", 1)):
        with pytest.raises(ValueError):
            decode_result_wire(raw.encode(), REQUESTED)


# ---------------------------------------------------------------- hashes and manifests


def test_job_digest_recipe_is_canonical_json_of_plaintext_dump():
    job = make_job(files=(text_file("a.py", E_ACUTE + chr(10)),), collect=("out",))
    tree = {
        "schema_version": 1,
        "argv": ["python", "a.py"],
        "files": [{"path": "a.py", "content": E_ACUTE + chr(10)}],
        "collect_paths": ["out"],
    }
    assert job_digest(job) == hashlib.sha256(canon(tree)).hexdigest()
    changed = make_job(files=(text_file("a.py", E_ACUTE),), collect=("out",))
    assert job_digest(changed) != job_digest(job)
    assert job_digest(make_job(argv=("python", "b.py"))) != job_digest(make_job())
    assert job_digest(make_job(collect=("x",))) != job_digest(make_job())


def test_artifact_digest_is_bytes_only_and_manifest_binds_path_and_count():
    first = IsolatedArtifact(path="a", data=b"data")
    second = IsolatedArtifact(path="b/c", data=b"data")
    empty = IsolatedArtifact(path="e", data=b"")
    assert artifact_digest(first) == hashlib.sha256(b"data").hexdigest()
    assert artifact_digest(first) == artifact_digest(second)
    assert artifact_digest(empty) == hashlib.sha256(b"").hexdigest()
    manifest = artifact_manifest((first, second, empty))
    assert [(m.path, m.byte_count, m.sha256) for m in manifest] == [
        ("a", 4, hashlib.sha256(b"data").hexdigest()),
        ("b/c", 4, hashlib.sha256(b"data").hexdigest()),
        ("e", 0, hashlib.sha256(b"").hexdigest()),
    ]
    assert artifact_manifest(()) == ()
    sentinel = b"UNIQUE-BODY-SENTINEL-7f3a9c1e"
    secret = IsolatedArtifact(path="s", data=sentinel)
    secret_manifest = artifact_manifest((secret,))
    assert secret_manifest[0].byte_count == len(sentinel)
    assert secret_manifest[0].sha256 == hashlib.sha256(sentinel).hexdigest()
    rendered = [
        repr(secret_manifest),
        repr(secret_manifest[0]),
        secret_manifest[0].model_dump_json(),
        json.dumps(secret_manifest[0].model_dump(mode="json")),
    ]
    for text in rendered:
        assert sentinel.decode() not in text
        assert repr(sentinel) not in text
        assert "UNIQUE-BODY-SENTINEL" not in text
        assert base64.b64encode(sentinel).decode() not in text


def test_manifest_rejects_duplicates_conflicts_lists_and_excess():
    one = IsolatedArtifact(path="a", data=b"")
    for bad in [
        (one, one),
        (one, IsolatedArtifact(path="a/b", data=b"")),
        [one],
        (one, "x"),
        tuple(IsolatedArtifact(path=f"f{i}", data=b"") for i in range(5)),
    ]:
        with pytest.raises(ValueError):
            artifact_manifest(bad)
    full = tuple(IsolatedArtifact(path=p, data=b"x" * 65536) for p in "abcd")
    assert sum(m.byte_count for m in artifact_manifest(full)) == 262144


def test_artifact_metadata_closed_and_strict():
    good = {"path": "a", "byte_count": 0, "sha256": "0" * 64}
    assert ArtifactMetadata(**good)
    for override in [
        {"sha256": "A" * 64},
        {"sha256": "0" * 63},
        {"sha256": "0" * 64 + chr(10)},
        {"byte_count": True},
        {"byte_count": -1},
        {"byte_count": 65537},
        {"byte_count": 1.0},
        {"path": "../a"},
        {"extra": 1},
    ]:
        with pytest.raises(ValueError):
            ArtifactMetadata(**{**good, **override})


# ---------------------------------------------------------------- sensitive data hiding


def test_sensitive_bytes_hidden_from_repr_and_default_dumps():
    secret = b"TOPSECRETBYTES"
    artifact = IsolatedArtifact(path="a", data=secret)
    assert "TOPSECRET" not in repr(artifact)
    assert artifact.model_dump() == {"path": "a"}
    assert "TOPSECRET" not in artifact.model_dump_json()
    raw = wire(
        stdout_b64=b64(secret),
        stderr_b64=b64(secret),
        artifacts=[{"path": "out.txt", "data_b64": b64(secret)}],
    )
    parsed = decode_result_wire(raw, REQUESTED)
    assert parsed.stdout == secret and parsed.artifacts[0].data == secret
    assert "TOPSECRET" not in repr(parsed)
    assert "TOPSECRET" not in parsed.model_dump_json()
    assert set(parsed.model_dump()) == {
        "missing_paths",
        "claimed_child_return_code",
        "claimed_status",
        "error_code",
    }


def test_validation_failures_do_not_echo_raw_values():
    with pytest.raises(ValueError) as info:
        IsolatedTextFile(path="SECRETPATH" + BS + "x", content="x")
    assert "SECRETPATH" not in str(info.value)
    with pytest.raises(ValueError) as info:
        parse_isolated_job(job_json_with(Q + "SECRETBODY" + BS + "u0000" + Q))
    assert "SECRETBODY" not in str(info.value)


# ---------------------------------------------------------------- bootstrap: AST and digest only

TREE = ast.parse(BOOTSTRAP_SOURCE)
ALLOWED_IMPORTS = {
    "base64",
    "binascii",
    "codecs",
    "json",
    "os",
    "re",
    "select",
    "signal",
    "stat",
    "subprocess",
    "sys",
    "time",
}


def test_bootstrap_digest_pin_and_text_shape():
    assert BOOTSTRAP_SHA256 == hashlib.sha256(BOOTSTRAP_SOURCE.encode("utf-8")).hexdigest()
    assert len(BOOTSTRAP_SHA256) == 64 and BOOTSTRAP_SHA256 == BOOTSTRAP_SHA256.lower()
    assert BOOTSTRAP_SOURCE.isascii()
    assert chr(0x2014) not in BOOTSTRAP_SOURCE
    assert isinstance(BOOTSTRAP_SOURCE, str)


def test_bootstrap_imports_are_stdlib_only():
    names = set()
    for node in ast.walk(TREE):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    assert names <= ALLOWED_IMPORTS
    assert "review_boundary" not in names and "pydantic" not in names


def test_bootstrap_has_no_import_time_effects_and_no_dynamic_execution():
    for node in TREE.body[:-1]:
        assert isinstance(node, (ast.Import, ast.Assign, ast.FunctionDef, ast.ClassDef))
    last = TREE.body[-1]
    assert isinstance(last, ast.If)
    assert ast.unparse(last.test) == "__name__ == '__main__'"
    calls = [n for n in ast.walk(TREE) if isinstance(n, ast.Call)]
    called = {n.func.id for n in calls if isinstance(n.func, ast.Name)}
    methods = {n.func.attr for n in calls if isinstance(n.func, ast.Attribute)}
    assert not called & {"eval", "exec", "compile", "__import__", "open"}
    assert not methods & {"system", "popen"}
    assert not methods & {"check_output", "check_call", "getoutput", "getstatusoutput"}


def test_bootstrap_constants_and_child_launch_shape():
    consts = {}
    for node in TREE.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            consts[node.targets[0].id] = node.value.value
    assert consts["WORKDIR"] == "/workspace"
    assert consts["PROTOCOL"] == WIRE_PROTOCOL
    assert consts["MAX_INPUT"] == 8388608
    assert consts["MAX_DEPTH"] == 16
    assert consts["MAX_OBSERVER"] == 512
    assert consts["MAX_STREAM"] == 65536
    assert consts["MAX_ARTIFACT_TOTAL"] == 262144
    assert 0 < consts["CHILD_TIMEOUT"] < 30
    popen = [
        n
        for n in ast.walk(TREE)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "Popen"
    ]
    assert len(popen) == 1
    keywords = {k.arg: k.value for k in popen[0].keywords}
    assert isinstance(keywords["shell"], ast.Constant) and keywords["shell"].value is False
    assert isinstance(keywords["start_new_session"], ast.Constant)
    assert keywords["start_new_session"].value is True
    assert ast.unparse(keywords["cwd"]) == "WORKDIR"
    assert "DEVNULL" in ast.unparse(keywords["stdin"])
    assert popen[0].args and ast.unparse(popen[0].args[0]) == "argv"


def test_bootstrap_uses_descriptor_relative_nofollow_and_bounded_process_control():
    attrs = {n.attr for n in ast.walk(TREE) if isinstance(n, ast.Attribute)}
    assert {
        "O_DIRECTORY",
        "O_NOFOLLOW",
        "O_EXCL",
        "O_CREAT",
        "O_NONBLOCK",
        "S_ISREG",
        "S_ISDIR",
        "killpg",
        "monotonic",
        "select",
        "fstat",
        "mkdir",
    } <= attrs
    dir_fd_uses = [
        k
        for n in ast.walk(TREE)
        if isinstance(n, ast.Call)
        for k in n.keywords
        if k.arg == "dir_fd"
    ]
    assert len(dir_fd_uses) >= 5
    functions = {n.name for n in TREE.body if isinstance(n, ast.FunctionDef)}
    assert {"parse_input", "stage", "read_artifact", "run_child", "emit", "main"} <= functions
    emits = [
        n
        for n in ast.walk(TREE)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "emit"
    ]
    assert len(emits) == 1


def _func(name):
    return next(n for n in TREE.body if isinstance(n, ast.FunctionDef) and n.name == name)


def test_bootstrap_encode_envelope_is_utf8_canonical_by_ast():
    func = _func("encode_envelope")
    encodes = [
        n
        for n in ast.walk(func)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "encode"
    ]
    assert len(encodes) == 1
    assert [ast.unparse(a) for a in encodes[0].args] == ["'utf-8'"]
    dumps = [
        n
        for n in ast.walk(func)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "dumps"
    ]
    assert len(dumps) == 1
    keywords = {k.arg: ast.unparse(k.value) for k in dumps[0].keywords}
    assert keywords["ensure_ascii"] == "False"
    assert keywords["allow_nan"] == "False"
    assert keywords["sort_keys"] == "True"
    assert keywords["separators"] == "(',', ':')"


def _envelope_calls(node):
    return [
        n
        for n in ast.walk(node)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "envelope"
    ]


def test_bootstrap_error_envelopes_list_every_requested_path_as_missing():
    # Structural AST check only. This is not runtime evidence.
    run = _func("run")
    calls = _envelope_calls(run)
    errors = [c for c in calls if ast.unparse(c.args[0]) == "'error'"]
    completed = [c for c in calls if ast.unparse(c.args[0]) == "'completed'"]
    assert len(errors) >= 6 and len(completed) == 1
    assert {ast.unparse(c.args[-1]) for c in errors} == {"collect"}
    marker = next(
        n for n in run.body if isinstance(n, ast.Assign) and ast.unparse(n) == "root_fd = None"
    )
    raises = [n for n in ast.walk(run) if isinstance(n, ast.Raise)]
    assert raises and all(n.lineno < marker.lineno for n in raises)
    assert "PARSED[:] = collect" in ast.unparse(run)
    assert {ast.unparse(c.args[-1]) for c in _envelope_calls(_func("main"))} == {"PARSED"}
    emit_calls = _envelope_calls(_func("emit"))
    assert emit_calls and all(ast.unparse(c.args[-1]) != "()" for c in emit_calls)


def test_bootstrap_forced_pipe_drain_never_reports_completed():
    run_child = _func("run_child")
    grace = [
        n
        for n in ast.walk(run_child)
        if isinstance(n, ast.If) and "EXIT_GRACE" in ast.unparse(n.test)
    ]
    assert len(grace) == 1
    assert [ast.unparse(n) for n in grace[0].body if isinstance(n, ast.Assign)] == [
        "code = 'child_timeout'"
    ]
    assert any(isinstance(n, ast.Break) for n in grace[0].body)
    assert "completed" not in ast.unparse(run_child)
    source = ast.unparse(_func("run"))
    assert source.index("if code is not None") < source.index("collect_all")


def test_bootstrap_observer_write_is_bounded_loop_on_shared_deadline():
    feed = _func("feed_observer")
    text = ast.unparse(feed)
    for needle in (
        "'child_timeout'",
        "'child_start_failed'",
        "deadline",
        "select.select",
        "time.monotonic()",
    ):
        assert needle in text
    assert any(isinstance(n, ast.While) for n in ast.walk(feed))
    assert "view = view[count:]" in text
    assert "feed_observer(proc, observer, deadline)" in ast.unparse(_func("run_child"))
