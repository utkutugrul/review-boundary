import copy
import hashlib
import json

import pytest
from pydantic import ValidationError

from review_boundary import isolated_verifier as v
from review_boundary.isolated_runner import POLICY_SHA256, IsolatedExecution, IsolationConfig
from review_boundary.isolation_payload import (
    IsolatedArtifact,
    artifact_digest,
    artifact_manifest,
    encode_observer_input,
)

NONCE = "0123456789abcdef0123456789abcdef"
SECRET_SOURCE = b"print('SECRET_MARKER_SOURCE')"

# Independently supplied canonical sum-echo-v1-contract.json bytes and their hash.
# This is schema/plumbing identity only, not an authenticity claim.
PINNED_CONTRACT_SHA256 = "ad4e173c111f811a2ccf5c59a0d1de50011749e65651538d25cf557256c68297"
PINNED_CONTRACT_BYTES = (
    b'{"binding_id":"sum-echo-v1","hash":{"algorithm":"sha256","canonical_json":'
    b"\"sorted_keys,separators(',',':'),ensure_ascii=False,allow_nan=False\"},"
    b'"input":{"keys":["nonce","pairs","schema_version"],"max_bytes":512,'
    b'"nonce":"secrets.token_hex(16)","pair_count":3,"pair_range":[-1000,1000],'
    b'"pair_type":"int"},"job":{"argv":["/usr/local/bin/python3.11","-I",'
    b'"candidate.py"],"artifact_encoding":"utf-8","artifact_max_bytes":65536,'
    b'"artifact_path":"candidate.py","collect_paths":[],"files":["candidate.py"]},'
    b'"output":{"keys":["nonce","schema_version","sums"],"max_bytes":512,'
    b'"max_depth":16,"sum_count":3,"sum_range":[-2147483648,2147483647],'
    b'"sum_type":"int32"},"schema_version":1,"scope":"plumbing_calibration_only"}'
)


def config(name="ctx"):
    return IsolationConfig(
        docker_executable="/usr/bin/docker",
        context_config_directory="/tmp/ctx-dir",
        context_name=name,
    )


def static_execution(**over):
    # Static metadata only: it has no origin record, so it carries no authority.
    values = {
        "execution_id": "a" * 32,
        "status": "completed",
        "job_started": True,
        "runtime_kind": "synthetic",
        "cleanup": "confirmed",
        "config_sha256": "b" * 64,
        "source_sha256": "c" * 64,
    }
    values.update(over)
    return IsolatedExecution(**values)


def artifact(data=SECRET_SOURCE, path="candidate.py"):
    return IsolatedArtifact(path=path, data=data)


def wire(nonce=NONCE, sums=(1, 2, 3), **over):
    body = {"schema_version": 1, "nonce": nonce, "sums": list(sums)}
    body.update(over)
    return json.dumps(body).encode()


def fail_if_called(*args, **kwargs):
    raise AssertionError("runtime seam must not be reached")


# Contract specification pin


def test_contract_hash_is_pinned_to_independent_canonical_bytes():
    assert hashlib.sha256(PINNED_CONTRACT_BYTES).hexdigest() == PINNED_CONTRACT_SHA256
    assert v.CONTRACT_SHA256 == PINNED_CONTRACT_SHA256
    # The static expected bytes are themselves canonical and equal the code-owned spec.
    parsed = json.loads(PINNED_CONTRACT_BYTES)
    reencoded = json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    assert reencoded == PINNED_CONTRACT_BYTES
    assert v.CONTRACT_SPEC == parsed
    assert v._canonical(v.CONTRACT_SPEC) == PINNED_CONTRACT_BYTES
    assert v.CONTRACT_SHA256 != POLICY_SHA256
    assert v.OBSERVER_ARGV == ("/usr/local/bin/python3.11", "-I", "candidate.py")


def test_single_static_binding_map():
    assert set(v._BINDINGS) == {"sum-echo-v1"}
    assert v._BINDINGS["sum-echo-v1"] == PINNED_CONTRACT_SHA256
    with pytest.raises(TypeError):
        v._BINDINGS["other-v1"] = PINNED_CONTRACT_SHA256
    with pytest.raises(TypeError):
        del v._BINDINGS["sum-echo-v1"]


# Pure challenge, parser and comparator


def test_challenge_shape_and_host_math():
    seen = set()
    for _ in range(25):
        challenge = v._new_challenge()
        seen.add(challenge.nonce)
        assert len(challenge.nonce) == 32 and challenge.nonce == challenge.nonce.lower()
        assert len(challenge.pairs) == 3
        for (left, right), total in zip(challenge.pairs, challenge.sums, strict=True):
            assert -1000 <= left <= 1000 and -1000 <= right <= 1000
            assert total == left + right
        body = json.loads(challenge.wire)
        assert set(body) == {"schema_version", "nonce", "pairs"}
        assert body["pairs"] == [list(pair) for pair in challenge.pairs]
        assert len(challenge.wire) <= 512 and b" " not in challenge.wire
    assert len(seen) == 25
    assert "nonce" not in repr(challenge) and challenge.nonce not in repr(challenge)


@pytest.mark.parametrize(
    "raw",
    [
        wire(),
        b" \n\t\r" + wire() + b"\r\n ",
        wire(sums=(3000, -3000, 0)),
        wire(sums=(-(2**31), 2**31 - 1, 0)),
    ],
)
def test_parser_accepts_complete_responses(raw):
    nonce, sums = v._parse_response(raw)
    assert nonce == NONCE and len(sums) == 3


def test_parser_size_boundary():
    base = wire()
    assert v._parse_response(base + b" " * (512 - len(base)))[0] == NONCE
    with pytest.raises(v._ParseError):
        v._parse_response(base + b" " * (513 - len(base)))


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"   ",
        b"\xef\xbb\xbf" + wire(),
        wire()[:-1] + b"\x00}",
        b"\xff\xfe",
        b'{"schema_version":1,"schema_version":1,"nonce":"%s","sums":[1,2,3]}' % NONCE.encode(),
        wire(extra=1),
        b'{"schema_version":1,"nonce":"%s"}' % NONCE.encode(),
        wire(schema_version=True),
        wire(schema_version=2),
        b'{"schema_version":1.0,"nonce":"%s","sums":[1,2,3]}' % NONCE.encode(),
        wire(schema_version="1"),
        wire(nonce=NONCE.upper()),
        wire(nonce=NONCE[:-1]),
        wire(nonce=5),
        wire(sums=(1, 2)),
        wire(sums=(1, 2, 3, 4)),
        wire(sums=(True, 2, 3)),
        b'{"schema_version":1,"nonce":"%s","sums":[1.0,2,3]}' % NONCE.encode(),
        b'{"schema_version":1,"nonce":"%s","sums":[1e2,2,3]}' % NONCE.encode(),
        wire(sums=("1", 2, 3)),
        wire(sums=(2**31, 2, 3)),
        wire(sums=(-(2**31) - 1, 2, 3)),
        b'{"schema_version":1,"nonce":"%s","sums":[NaN,2,3]}' % NONCE.encode(),
        b'{"schema_version":1,"nonce":"%s","sums":[Infinity,2,3]}' % NONCE.encode(),
        wire() + b"x",
        wire() + wire(),
        b"\x0b" + wire(),
        b"[" * 17 + b"]" * 17,
        b"[]",
        b'{"passed":true}',
        b'{"passed":true,"status":"established_pass","verdict":"matched"}',
        b"true",
        b"null",
    ],
)
def test_parser_rejects_everything_else(raw):
    with pytest.raises(v._ParseError):
        v._parse_response(raw)


def test_parser_rejects_non_bytes():
    with pytest.raises(v._ParseError):
        v._parse_response(wire().decode())
    with pytest.raises(v._ParseError):
        v._parse_response(bytearray(wire()))


def test_comparator_math_including_wrong_wellformed_values():
    challenge = v._new_challenge()
    good = (challenge.nonce, challenge.sums)
    assert v._matches(good, challenge.nonce, challenge.sums)
    other_nonce = "f" * 32 if challenge.nonce != "f" * 32 else "e" * 32
    assert not v._matches((other_nonce, challenge.sums), challenge.nonce, challenge.sums)
    off_by_one = (challenge.sums[0] + 1, *challenge.sums[1:])
    assert not v._matches((challenge.nonce, off_by_one), challenge.nonce, challenge.sums)
    assert not v._matches((challenge.nonce, (3000, 3000, 3000)), challenge.nonce, challenge.sums)
    parsed = v._parse_response(wire(nonce=challenge.nonce, sums=(3000, 3000, 3000)))
    assert not v._matches(parsed, challenge.nonce, challenge.sums)


@pytest.mark.parametrize(
    "data",
    [b"\xef\xbb\xbfprint(1)", b"a\x00b", b"\xff", b"\xed\xa0\x80", b"x" * 65537],
)
def test_source_validation_rejects(data):
    with pytest.raises(ValueError):
        v._source_text(data)


def test_source_validation_accepts_bounds():
    assert v._source_text(b"") == ""
    assert v._source_text("héllo".encode()) == "héllo"
    assert len(v._source_text(b"x" * 65536)) == 65536


# Pure reason classification on shared public metadata (grants no authority)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"runtime_kind": "synthetic"}, "observation_binding_mismatch"),
        (
            {
                "runtime_kind": "real",
                "status": "not_started",
                "job_started": False,
                "cleanup": "not_needed",
                "error_code": "image_unavailable",
            },
            "observation_unsupported",
        ),
        (
            {
                "runtime_kind": "real",
                "status": "error",
                "job_started": False,
                "cleanup": "not_needed",
                "error_code": "policy_mismatch",
            },
            "observation_unsupported",
        ),
        (
            {"runtime_kind": "real", "status": "error", "error_code": "execution_timeout"},
            "observation_incomplete",
        ),
        (
            {"runtime_kind": "real", "status": "error", "error_code": "container_oom"},
            "observation_incomplete",
        ),
        (
            {
                "runtime_kind": "real",
                "status": "error",
                "error_code": "cleanup_failed",
                "cleanup": "failed",
            },
            "cleanup_unconfirmed",
        ),
        ({"runtime_kind": "real", "cleanup": "failed"}, "cleanup_unconfirmed"),
        ({"runtime_kind": "real", "cleanup": "not_needed"}, "cleanup_unconfirmed"),
        ({"runtime_kind": "real", "job_started": False}, "observation_incomplete"),
        ({"runtime_kind": "real", "error_code": "malformed_result"}, "observation_incomplete"),
        ({"runtime_kind": "real"}, None),
    ],
)
def test_observation_problem_classification(values, expected):
    assert v._observation_problem(static_execution(**values)) == expected


def test_observation_problem_rejects_non_execution_objects():
    for value in (None, {"status": "completed"}, object()):
        assert v._observation_problem(value) == "observation_binding_mismatch"


# Pure observer-input identity and shared-context comparison (metadata only, no authority)


def test_wrapped_observer_input_digest_differs_from_raw_challenge_digest():
    challenge = v._new_challenge()
    job = v._observer_job(SECRET_SOURCE)
    wrapped = v._observer_input_digest(job, challenge.wire)
    assert wrapped == hashlib.sha256(encode_observer_input(job, challenge.wire)).hexdigest()
    assert wrapped != hashlib.sha256(challenge.wire).hexdigest()
    assert wrapped == v._observer_input_digest(job, challenge.wire)
    other = v._observer_job(b"print(1)")
    assert v._observer_input_digest(other, challenge.wire) != wrapped
    assert v._observer_input_digest(job, v._new_challenge().wire) != wrapped


def test_observer_job_is_fixed_and_validates_source():
    job = v._observer_job(SECRET_SOURCE)
    assert job.argv == v.OBSERVER_ARGV and job.collect_paths == ()
    assert [item.path for item in job.files] == ["candidate.py"]
    with pytest.raises(ValueError):
        v._observer_job(b"\xff")


CONTEXT_FIELDS = [
    "config_sha256",
    "daemon_sha256",
    "image_sha256",
    "policy_sha256",
    "bootstrap_sha256",
]


def context_pair(**observation_over):
    wrapped = "9" * 64
    shared = {
        "config_sha256": "b" * 64,
        "daemon_sha256": "1" * 64,
        "image_sha256": "2" * 64,
        "policy_sha256": "3" * 64,
        "bootstrap_sha256": "4" * 64,
    }
    origin = static_execution(runtime_kind="real", **shared)
    values = {"execution_id": "d" * 32, "input_sha256": wrapped, "runtime_kind": "real"}
    values.update(shared)
    values.update(observation_over)
    return static_execution(**values), origin, wrapped


def test_context_helper_accepts_only_fully_equal_metadata_and_grants_nothing():
    observation, origin, wrapped = context_pair()
    assert v._context_problem(observation, origin, wrapped) is None
    # Static metadata equality is not a verdict and the origin stays unbound.
    result = v.verify_isolated_execution(config(), "sum-echo-v1", origin, artifact())
    assert (result.verdict, result.reason) == ("not_established", "not_live")


@pytest.mark.parametrize("name", CONTEXT_FIELDS)
def test_context_helper_rejects_different_shared_fields(name):
    observation, origin, wrapped = context_pair(**{name: "7" * 64})
    assert v._context_problem(observation, origin, wrapped) == "observation_binding_mismatch"


@pytest.mark.parametrize("name", CONTEXT_FIELDS)
def test_context_helper_rejects_missing_observation_fields(name):
    observation, origin, wrapped = context_pair(**{name: None})
    assert v._context_problem(observation, origin, wrapped) == "observation_binding_mismatch"


@pytest.mark.parametrize("name", CONTEXT_FIELDS)
def test_context_helper_rejects_missing_origin_fields(name):
    observation, origin, wrapped = context_pair()
    origin = origin.model_copy(update={name: None})
    assert v._context_problem(observation, origin, wrapped) == "observation_binding_mismatch"


def test_context_helper_rejects_raw_challenge_digest_and_wrong_input():
    challenge = v._new_challenge()
    job = v._observer_job(SECRET_SOURCE)
    wrapped = v._observer_input_digest(job, challenge.wire)
    raw = hashlib.sha256(challenge.wire).hexdigest()
    good, origin, _ = context_pair(input_sha256=wrapped)
    assert v._context_problem(good, origin, wrapped) is None
    assert v._context_problem(good, origin, raw) == "observation_binding_mismatch"
    bad, origin, _ = context_pair(input_sha256=raw)
    assert v._context_problem(bad, origin, wrapped) == "observation_binding_mismatch"
    none_input, origin, _ = context_pair(input_sha256=None)
    assert v._context_problem(none_input, origin, wrapped) == "observation_binding_mismatch"


def test_context_helper_requires_fresh_observation_and_real_objects():
    same_id, origin, wrapped = context_pair(execution_id="a" * 32)
    assert v._context_problem(same_id, origin, wrapped) == "observation_binding_mismatch"
    observation, origin, wrapped = context_pair()
    for value in (None, {"status": "completed"}, object()):
        assert v._context_problem(value, origin, wrapped) == "observation_binding_mismatch"
        assert v._context_problem(observation, value, wrapped) == "observation_binding_mismatch"


@pytest.mark.parametrize(
    ("problem", "code", "expected"),
    [
        ("complete", "origin_binding_mismatch", "observation_binding_mismatch"),
        ("complete", "artifact_mismatch", "observation_binding_mismatch"),
        ("complete", "not_live", "observation_binding_mismatch"),
        ("complete", "observation_binding_mismatch", "observation_binding_mismatch"),
        ("complete", "cleanup_unconfirmed", "cleanup_unconfirmed"),
        ("incomplete", "origin_binding_mismatch", "observation_incomplete"),
        ("unsupported", "origin_incomplete", "observation_unsupported"),
        ("cleanup", "observation_binding_mismatch", "cleanup_unconfirmed"),
        ("synthetic", "cleanup_unconfirmed", "observation_binding_mismatch"),
    ],
)
def test_guard_reason_keeps_error_metadata_classes(problem, code, expected):
    observations = {
        "complete": static_execution(runtime_kind="real"),
        "incomplete": static_execution(
            runtime_kind="real", status="error", error_code="execution_timeout"
        ),
        "unsupported": static_execution(
            runtime_kind="real",
            status="not_started",
            job_started=False,
            cleanup="not_needed",
            error_code="image_unavailable",
        ),
        "cleanup": static_execution(runtime_kind="real", cleanup="failed"),
        "synthetic": static_execution(),
    }
    assert v._guard_reason(observations[problem], v._OriginError(code)) == expected
    assert v._guard_reason(static_execution(runtime_kind="real"), None) == (
        "observation_binding_mismatch"
    )


# Public verifier: no authority from unbound inputs


@pytest.mark.parametrize(
    ("binding", "label"),
    [
        ("other-v1", "other-v1"),
        ("SUM-ECHO-V1", "SUM-ECHO-V1"),
        ("Sum.Echo_v2", "Sum.Echo_v2"),
        ("", "unrecognized"),
        ("sum-echo-v1\n", "unrecognized"),
        ("x" * 500, "unrecognized"),
        ("bad\nid", "unrecognized"),
        ("\ud800", "unrecognized"),
        (None, "unrecognized"),
        (5, "unrecognized"),
        (b"x", "unrecognized"),
    ],
)
def test_unknown_binding_stops_before_effects(monkeypatch, binding, label):
    monkeypatch.setattr(v, "_require_live_origin", fail_if_called)
    monkeypatch.setattr(v, "_run_isolated_observation", fail_if_called)
    monkeypatch.setattr(v, "_require_bound_observation", fail_if_called)
    monkeypatch.setattr(v, "_observation_stdout", fail_if_called)
    monkeypatch.setattr(v, "_new_challenge", fail_if_called)
    result = v.verify_isolated_execution(config(), binding, static_execution(), artifact())
    assert (result.verdict, result.reason) == ("not_established", "unknown_binding")
    assert result.contract_sha256 == v.CONTRACT_SHA256 and result.policy_sha256 == POLICY_SHA256
    assert result.origin_execution_id is None and result.observation_execution_id is None
    assert result.binding_id == label


def copies_of(execution):
    # Saved JSON reloaded through strict JSON validation, as the runner requires.
    reloaded = IsolatedExecution.model_validate_json(execution.model_dump_json())
    return [
        execution,
        copy.copy(execution),
        copy.deepcopy(execution),
        execution.model_copy(),
        execution.model_copy(deep=True),
        execution.model_copy(update={"cleanup": "confirmed", "runtime_kind": "real"}),
        reloaded,
    ]


def test_unbound_execution_objects_have_no_authority():
    for candidate in copies_of(static_execution()):
        result = v.verify_isolated_execution(config(), "sum-echo-v1", candidate, artifact())
        assert (result.verdict, result.reason) == ("not_established", "not_live")
        assert result.observation_execution_id is None
        assert result.observation_output_sha256 is None


def test_mutated_artifact_config_and_inputs_stay_not_established():
    cases = [
        (config("other"), static_execution(), artifact()),
        (config(), static_execution(), artifact(path="other.py")),
        (config(), static_execution(), artifact(data=b"\xff")),
        (config(), static_execution(), artifact(data=b"x" * 10)),
        ({"docker_executable": "/usr/bin/docker"}, static_execution(), artifact()),
        (config(), {"passed": True}, artifact()),
        (config(), None, artifact()),
        (config(), static_execution(), None),
        (config(), static_execution(), {"path": "candidate.py", "data": b"x"}),
    ]
    for cfg, execution, art in cases:
        result = v.verify_isolated_execution(cfg, "sum-echo-v1", execution, art)
        assert result.verdict == "not_established"
        assert result.reason == "not_live"


def test_forged_passed_json_has_no_authority():
    forged = b'{"passed":true,"verdict":"established_pass","binding":"sum-echo-v1"}'
    result = v.verify_isolated_execution(
        config(), "sum-echo-v1", static_execution(), artifact(data=forged)
    )
    assert result.verdict == "not_established"
    with pytest.raises(v._ParseError):
        v._parse_response(forged)


def test_origin_errors_map_to_fixed_reasons_without_leaks(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("/secret/host/path TOKEN")

    monkeypatch.setattr(v, "_require_live_origin", boom)
    result = v.verify_isolated_execution(config(), "sum-echo-v1", static_execution(), artifact())
    assert (result.verdict, result.reason) == ("not_established", "not_live")
    assert "secret" not in repr(result) and "TOKEN" not in result.model_dump_json()

    def stale(*args, **kwargs):
        raise v._OriginError("cleanup_unconfirmed")

    monkeypatch.setattr(v, "_require_live_origin", stale)
    result = v.verify_isolated_execution(config(), "sum-echo-v1", static_execution(), artifact())
    assert result.reason == "cleanup_unconfirmed"


def test_unexpected_programming_errors_propagate(monkeypatch):
    def bug(*args, **kwargs):
        raise KeyError("programming bug")

    monkeypatch.setattr(v, "_require_live_origin", bug)
    with pytest.raises(KeyError):
        v.verify_isolated_execution(config(), "sum-echo-v1", static_execution(), artifact())


def test_source_hash_comes_from_origin_not_artifact_bytes(monkeypatch):
    # Negative-only control flow: the observation seam refuses, so no verdict is reachable.
    def refuse(*args, **kwargs):
        raise v._OriginError("observation_binding_mismatch")

    monkeypatch.setattr(v, "_require_live_origin", lambda *args: object())
    monkeypatch.setattr(v, "_run_isolated_observation", refuse)
    data = SECRET_SOURCE
    result = v.verify_isolated_execution(
        config(), "sum-echo-v1", static_execution(), artifact(data)
    )
    assert (result.verdict, result.reason) == ("not_established", "observation_binding_mismatch")
    assert result.source_sha256 == "c" * 64
    assert result.source_sha256 != hashlib.sha256(data).hexdigest()
    assert result.artifact_sha256 == hashlib.sha256(data).hexdigest()
    assert result.config_sha256 == "b" * 64 and result.origin_execution_id == "a" * 32
    assert result.observation_execution_id is None and result.observation_output_sha256 is None


@pytest.mark.parametrize("missing", ["config_sha256", "source_sha256"])
def test_incomplete_origin_hashes_are_not_established(monkeypatch, missing):
    monkeypatch.setattr(v, "_require_live_origin", lambda *args: object())
    monkeypatch.setattr(v, "_run_isolated_observation", fail_if_called)
    monkeypatch.setattr(v, "_new_challenge", fail_if_called)
    execution = static_execution(**{missing: None})
    result = v.verify_isolated_execution(config(), "sum-echo-v1", execution, artifact())
    assert (result.verdict, result.reason) == ("not_established", "origin_binding_mismatch")
    assert result.source_sha256 is None and result.artifact_sha256 is None


@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_interrupts_are_not_swallowed(monkeypatch, signal):
    def interrupt(*args, **kwargs):
        raise signal()

    monkeypatch.setattr(v, "_require_live_origin", interrupt)
    with pytest.raises(signal):
        v.verify_isolated_execution(config(), "sum-echo-v1", static_execution(), artifact())


def test_original_execution_is_not_mutated():
    execution = static_execution()
    before = execution.model_dump_json()
    v.verify_isolated_execution(config(), "sum-echo-v1", execution, artifact())
    assert execution.model_dump_json() == before


# Guard ordering. Sentinels and static observations only make the guard refuse; no verdict
# is ever manufactured here.


def arrange_observation(monkeypatch, observation, guard):
    calls = {"run": [], "guard": []}
    sentinel = object()
    origin = static_execution()

    def run(cfg, job, observer_input, proof):
        calls["run"].append((job, observer_input, proof))
        return observation

    def refuse(cfg, seen, proof, observer_input):
        calls["guard"].append((seen, proof, observer_input))
        guard()

    monkeypatch.setattr(v, "_require_live_origin", lambda *args: sentinel)
    monkeypatch.setattr(v, "_run_isolated_observation", run)
    monkeypatch.setattr(v, "_require_bound_observation", refuse)
    monkeypatch.setattr(v, "_observation_stdout", fail_if_called)
    monkeypatch.setattr(v, "_parse_response", fail_if_called)
    monkeypatch.setattr(v, "_matches", fail_if_called)
    return calls, sentinel, origin


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("not_live", "observation_binding_mismatch"),
        ("origin_incomplete", "observation_binding_mismatch"),
        ("origin_binding_mismatch", "observation_binding_mismatch"),
        ("artifact_mismatch", "observation_binding_mismatch"),
        ("artifact_invalid", "observation_binding_mismatch"),
        ("observation_binding_mismatch", "observation_binding_mismatch"),
        ("cleanup_unconfirmed", "cleanup_unconfirmed"),
    ],
)
def test_guard_rejection_precedes_stdout_and_comparison(monkeypatch, code, expected):
    observation = static_execution(runtime_kind="real", execution_id="d" * 32)

    def reject():
        raise v._OriginError(code)

    calls, sentinel, origin = arrange_observation(monkeypatch, observation, reject)
    result = v.verify_isolated_execution(config(), "sum-echo-v1", origin, artifact())
    assert (result.verdict, result.reason) == ("not_established", expected)
    assert result.observation_execution_id is None and result.observation_output_sha256 is None
    # The guard saw the exact observation, the opaque proof and the same raw challenge wire.
    ((job, wire_sent, proof),) = calls["run"]
    ((seen, guard_proof, guard_wire),) = calls["guard"]
    assert seen is observation and guard_proof is sentinel and proof is sentinel
    assert guard_wire == wire_sent
    assert result.observation_input_sha256 == hashlib.sha256(wire_sent).hexdigest()
    wrapped = hashlib.sha256(encode_observer_input(job, wire_sent)).hexdigest()
    assert result.observation_input_sha256 != wrapped
    assert result.artifact_sha256 == artifact_digest(artifact())
    assert result.source_sha256 == "c" * 64


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"runtime_kind": "synthetic"}, "observation_binding_mismatch"),
        ({"status": "error", "error_code": "execution_timeout"}, "observation_incomplete"),
        ({"status": "error", "error_code": "container_oom"}, "observation_incomplete"),
        (
            {
                "status": "not_started",
                "job_started": False,
                "cleanup": "not_needed",
                "error_code": "image_unavailable",
            },
            "observation_unsupported",
        ),
        ({"cleanup": "failed"}, "cleanup_unconfirmed"),
        ({"cleanup": "not_needed"}, "cleanup_unconfirmed"),
    ],
)
def test_guard_rejection_preserves_observation_error_classification(monkeypatch, values, expected):
    merged = {"runtime_kind": "real", "execution_id": "d" * 32}
    merged.update(values)
    observation = static_execution(**merged)

    def reject():
        raise v._OriginError("origin_binding_mismatch")

    calls, _, origin = arrange_observation(monkeypatch, observation, reject)
    result = v.verify_isolated_execution(config(), "sum-echo-v1", origin, artifact())
    assert (result.verdict, result.reason) == ("not_established", expected)
    assert len(calls["guard"]) == 1


def test_guard_seam_errors_are_fixed_and_unexpected_errors_propagate(monkeypatch):
    observation = static_execution(runtime_kind="real", execution_id="d" * 32)

    def seam_error():
        raise RuntimeError("/secret/host/path TOKEN")

    _, _, origin = arrange_observation(monkeypatch, observation, seam_error)
    result = v.verify_isolated_execution(config(), "sum-echo-v1", origin, artifact())
    assert (result.verdict, result.reason) == ("not_established", "observation_binding_mismatch")
    assert "secret" not in repr(result) and "TOKEN" not in result.model_dump_json()

    def bug():
        raise KeyError("programming bug")

    _, _, origin = arrange_observation(monkeypatch, observation, bug)
    with pytest.raises(KeyError):
        v.verify_isolated_execution(config(), "sum-echo-v1", origin, artifact())


def test_actual_guard_rejects_sentinel_proof_and_static_observation(monkeypatch):
    # Only the opaque proof and the returned observation are static sentinels. The real
    # private guard is left in place, so no behavioral verdict can be reached.
    observation = static_execution(runtime_kind="real", execution_id="d" * 32)
    monkeypatch.setattr(v, "_require_live_origin", lambda *args: object())
    monkeypatch.setattr(v, "_run_isolated_observation", lambda *args: observation)
    monkeypatch.setattr(v, "_observation_stdout", fail_if_called)
    monkeypatch.setattr(v, "_parse_response", fail_if_called)
    result = v.verify_isolated_execution(config(), "sum-echo-v1", static_execution(), artifact())
    assert result.verdict == "not_established"
    assert result.reason in {"observation_binding_mismatch", "cleanup_unconfirmed"}
    assert result.observation_execution_id is None and result.observation_output_sha256 is None


# Result model strictness and report content


def base_result(**over):
    values = {"binding_id": "sum-echo-v1", "verdict": "not_established", "reason": "not_live"}
    values.update(over)
    return v.VerificationResult(**values)


def test_result_fields_are_exactly_the_closed_set():
    result = base_result()
    assert set(result.model_dump()) == {
        "schema_version",
        "report_family",
        "binding_id",
        "contract_sha256",
        "policy_sha256",
        "verdict",
        "reason",
        "origin_execution_id",
        "observation_execution_id",
        "config_sha256",
        "source_sha256",
        "artifact_sha256",
        "observation_input_sha256",
        "observation_output_sha256",
        "scope",
        "publication",
    }
    assert result.scope == "plumbing_calibration_only"
    assert result.publication == "not_established" and result.schema_version == 1
    assert result.report_family == "isolated_verification"


@pytest.mark.parametrize(
    "over",
    [
        {"schema_version": True},
        {"schema_version": "1"},
        {"schema_version": 1.0},
        {"schema_version": 2},
        {"extra_field": 1},
        {"binding_id": "x" * 81},
        {"binding_id": "bad id"},
        {"binding_id": ""},
        {"verdict": "passed"},
        {"reason": "other"},
        {"contract_sha256": "A" * 64},
        {"contract_sha256": "0" * 64},
        {"policy_sha256": "0" * 64},
        {"origin_execution_id": "G" * 32},
        {"origin_execution_id": "a" * 31},
        {"config_sha256": "a" * 63},
        {"scope": "general"},
        {"publication": "published"},
        {"verdict": "established_pass"},
        {"verdict": "established_pass", "reason": "matched"},
        {"verdict": "established_fail", "reason": "behavior_mismatch"},
        {"verdict": "established_pass", "reason": "behavior_mismatch"},
        {"reason": "matched"},
        {"reason": "unknown_binding", "origin_execution_id": "a" * 32},
    ],
)
def test_result_model_rejects_invalid_values(over):
    with pytest.raises(ValidationError):
        base_result(**over)


def test_result_model_bypasses_cannot_add_authority():
    result = base_result()
    with pytest.raises(ValidationError):
        result.model_copy(update={"verdict": "established_pass", "reason": "matched"})
    with pytest.raises(ValidationError):
        result.model_copy(update={"unexpected": 1})
    with pytest.raises(ValidationError):
        v.VerificationResult.model_construct(
            binding_id="sum-echo-v1", verdict="established_pass", reason="matched"
        )
    with pytest.raises(ValidationError):
        v.VerificationResult.model_validate_json(
            b'{"schema_version":"1","binding_id":"sum-echo-v1",'
            b'"verdict":"not_established","reason":"not_live"}'
        )
    with pytest.raises(ValidationError):
        result.reason = "matched"
    assert result.model_copy(update={"reason": "artifact_invalid"}).reason == "artifact_invalid"


def test_report_does_not_leak_challenge_source_or_streams():
    challenge = v._new_challenge()
    result = v.verify_isolated_execution(config(), "sum-echo-v1", static_execution(), artifact())
    text = repr(result) + result.model_dump_json() + str(result.model_dump())
    for needle in (
        "SECRET_MARKER",
        "candidate.py",
        "python3.11",
        "/tmp/ctx-dir",
        "pairs",
        "sums",
        "stdout",
        "stderr",
        "expected",
        "argv",
        "challenge",
        challenge.nonce,
    ):
        assert needle not in text


# Closed invocation wrapper (data validation only, never live authority)


def manifest_execution(**over):
    values = {"artifact_manifest": artifact_manifest((artifact(),))}
    values.update(over)
    return static_execution(**values)


def bound_result(**over):
    values = {
        "binding_id": "sum-echo-v1",
        "verdict": "not_established",
        "reason": "observation_binding_mismatch",
        "origin_execution_id": "a" * 32,
        "config_sha256": "b" * 64,
        "source_sha256": "c" * 64,
        "artifact_sha256": artifact_digest(artifact()),
        "observation_input_sha256": "e" * 64,
    }
    values.update(over)
    return v.VerificationResult(**values)


def report(execution=None, result=None):
    return v.IsolatedInvocationReport(
        execution=manifest_execution() if execution is None else execution,
        verification_result=result,
    )


def established(**over):
    values = {
        "verdict": "established_pass",
        "reason": "matched",
        "observation_execution_id": "d" * 32,
        "observation_output_sha256": "f" * 64,
    }
    values.update(over)
    return bound_result(**values)


def real_execution(**over):
    values = {"runtime_kind": "real"}
    values.update(over)
    return manifest_execution(**values)


@pytest.mark.parametrize("bound", [False, True])
def test_invocation_report_strict_json_roundtrip(bound):
    original = report(result=bound_result() if bound else None)
    tree = original.model_dump(mode="json")
    assert set(tree) == {"schema_version", "report_family", "execution", "verification_result"}
    assert tree["schema_version"] == 1 and tree["report_family"] == "isolated_invocation"
    assert (tree["verification_result"] is not None) is bound
    loaded = v.IsolatedInvocationReport.model_validate_json(json.dumps(tree))
    assert loaded.model_dump(mode="json") == tree
    assert loaded.model_dump_json() == original.model_dump_json()


def test_invocation_report_requires_explicit_verification_slot():
    tree = report().model_dump(mode="json")
    del tree["verification_result"]
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_validate_json(json.dumps(tree))
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport(execution=manifest_execution())


@pytest.mark.parametrize("version", [True, False, 1.0, "1", 2, 0, None])
def test_invocation_report_rejects_inexact_versions(version):
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport(
            schema_version=version, execution=manifest_execution(), verification_result=None
        )
    tree = report().model_dump(mode="json")
    tree["schema_version"] = version
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_validate_json(json.dumps(tree))


def test_invocation_report_is_closed_and_strict():
    tree = report(result=bound_result()).model_dump(mode="json")
    for family in ("isolated_execution", "isolated_verification", "other"):
        changed = {**tree, "report_family": family}
        with pytest.raises(ValidationError):
            v.IsolatedInvocationReport.model_validate_json(json.dumps(changed))
    for extra in ("verified", "verdict", "authority", "live"):
        changed = {**tree, extra: True}
        with pytest.raises(ValidationError):
            v.IsolatedInvocationReport.model_validate_json(json.dumps(changed))
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport(
            execution=manifest_execution(), verification_result=None, extra_field=1
        )
    nested = copy.deepcopy(tree)
    nested["execution"]["unexpected"] = 1
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_validate_json(json.dumps(nested))
    nested = copy.deepcopy(tree)
    nested["execution"]["schema_version"] = True
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_validate_json(json.dumps(nested))
    nested = copy.deepcopy(tree)
    nested["verification_result"]["verdict"] = "established_pass"
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_validate_json(json.dumps(nested))
    nested = copy.deepcopy(tree)
    nested["verification_result"]["schema_version"] = "1"
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_validate_json(json.dumps(nested))
    with pytest.raises(ValidationError):
        report().verification_result = None


@pytest.mark.parametrize(
    ("execution_over", "result_over"),
    [
        ({}, {"origin_execution_id": "9" * 32}),
        ({}, {"config_sha256": "1" * 64}),
        ({}, {"source_sha256": "1" * 64}),
        ({"policy_sha256": "1" * 64}, {}),
        ({}, {"artifact_sha256": "1" * 64}),
        ({"artifact_manifest": ()}, {}),
        ({}, {"observation_execution_id": "a" * 32}),
    ],
)
def test_invocation_report_rejects_supplied_metadata_mismatches(execution_over, result_over):
    with pytest.raises(ValidationError, match="does not match its execution"):
        report(manifest_execution(**execution_over), bound_result(**result_over))


def test_invocation_report_rejects_artifact_metadata_for_other_path():
    other = artifact(path="other.py")
    execution = static_execution(artifact_manifest=artifact_manifest((other,)))
    with pytest.raises(ValidationError, match="does not match its execution"):
        report(execution, bound_result(artifact_sha256=artifact_digest(other)))


def test_invocation_report_preserves_missing_origin_metadata_for_not_established():
    bare = static_execution(config_sha256=None, source_sha256=None, policy_sha256=None)
    unbound = base_result()
    kept = v.IsolatedInvocationReport(execution=bare, verification_result=unbound)
    assert kept.execution.config_sha256 is None and kept.execution.source_sha256 is None
    assert kept.verification_result == unbound
    # Supplied result metadata may exceed what an unknown origin recorded; nothing is invented.
    partial = v.IsolatedInvocationReport(
        execution=bare, verification_result=bound_result(artifact_sha256=None)
    )
    tree = partial.model_dump(mode="json")
    assert tree["execution"]["config_sha256"] is None and tree["execution"]["source_sha256"] is None
    assert tree["verification_result"]["config_sha256"] == "b" * 64
    reloaded = v.IsolatedInvocationReport.model_validate_json(json.dumps(tree))
    assert reloaded.model_dump(mode="json") == tree
    # Unknown binding records keep no execution metadata at all.
    unknown = v.verify_isolated_execution(config(), "other-v1", bare, artifact())
    assert v.IsolatedInvocationReport(execution=bare, verification_result=unknown)


@pytest.mark.parametrize(
    "execution_over",
    [
        {},
        {"runtime_kind": "synthetic"},
        {"runtime_kind": "real", "cleanup": "not_needed"},
        {"runtime_kind": "real", "cleanup": "failed"},
        {"runtime_kind": "real", "status": "error"},
        {"runtime_kind": "real", "job_started": False},
        {"runtime_kind": "real", "error_code": "execution_timeout"},
        {"runtime_kind": "real", "config_sha256": None},
        {"runtime_kind": "real", "source_sha256": None},
        {"runtime_kind": "real", "policy_sha256": None},
        {"runtime_kind": "real", "artifact_manifest": ()},
    ],
)
def test_fabricated_established_records_are_invalid_outer_inputs(execution_over):
    execution = manifest_execution(**execution_over)
    with pytest.raises(ValidationError):
        report(execution, established())
    with pytest.raises(ValidationError):
        report(execution, established(verdict="established_fail", reason="behavior_mismatch"))


def test_established_records_need_complete_artifact_and_origin_evidence():
    # Missing candidate metadata cannot match the claimed artifact digest.
    with pytest.raises(ValidationError, match="does not match its execution"):
        report(real_execution(artifact_manifest=()), established())
    # Synthetic or incomplete origin evidence is rejected as an established record.
    with pytest.raises(ValidationError, match="origin evidence"):
        report(manifest_execution(), established())
    with pytest.raises(ValidationError, match="origin evidence"):
        report(real_execution(cleanup="not_needed"), established())
    # Duplicate candidate metadata is never a single complete origin record.
    duplicated = artifact_manifest((artifact(),)) * 2
    with pytest.raises(ValidationError):
        report(real_execution(artifact_manifest=duplicated), established())


def test_invocation_report_bypasses_cannot_add_authority():
    current = report()
    with pytest.raises(ValidationError):
        current.model_copy(update={"verification_result": established()})
    with pytest.raises(ValidationError):
        current.model_copy(update={"unexpected": 1})
    with pytest.raises(ValidationError):
        v.IsolatedInvocationReport.model_construct(
            execution=manifest_execution(), verification_result=established()
        )
    assert current.model_copy(update={"verification_result": bound_result()}).verification_result


def test_invocation_report_does_not_leak_private_bytes():
    execution = manifest_execution()
    execution._stdout = b"SECRET_STREAM_OUT"
    execution._stderr = b"SECRET_STREAM_ERR"
    challenge = v._new_challenge()
    wrapper = report(execution, bound_result())
    text = repr(wrapper) + wrapper.model_dump_json() + str(wrapper.model_dump())
    text += json.dumps(wrapper.model_dump(mode="json"))
    for needle in (
        "SECRET_MARKER",
        "SECRET_STREAM",
        SECRET_SOURCE.decode(),
        "/tmp/ctx-dir",
        "python3.11",
        "argv",
        "challenge",
        "stdin" + "_data",
        challenge.nonce,
        challenge.wire.decode(),
    ):
        assert needle not in text
    assert execution.command_stdout == b"SECRET_STREAM_OUT"


def test_invocation_report_does_not_mutate_the_original_execution():
    execution = manifest_execution()
    before = execution.model_dump_json()
    wrapper = report(execution, bound_result())
    wrapper.model_dump_json()
    v.IsolatedInvocationReport.model_validate_json(wrapper.model_dump_json())
    assert execution.model_dump_json() == before
    assert "verification_result" not in execution.model_dump()
    assert "verification_result" not in type(execution).model_fields
    assert set(execution.model_dump()) == set(manifest_execution().model_dump())


def test_loaded_invocation_report_confers_no_live_authority():
    wrapper = report(real_execution(), bound_result())
    loaded = v.IsolatedInvocationReport.model_validate_json(wrapper.model_dump_json())
    for candidate in (loaded.execution, wrapper.execution, loaded.execution.model_copy()):
        result = v.verify_isolated_execution(config(), "sum-echo-v1", candidate, artifact())
        assert (result.verdict, result.reason) == ("not_established", "not_live")
        assert result.observation_execution_id is None
    # The carried verification record is data only: the verifier never reads it back.
    assert loaded.verification_result.verdict == "not_established"


@pytest.mark.parametrize(
    ("verdict", "reason"),
    [("established_pass", "matched"), ("established_fail", "behavior_mismatch")],
)
def test_recorded_established_shapes_roundtrip_as_data_only(monkeypatch, verdict, reason):
    # Fixed public format vectors only. No private seal, origin or gate is involved.
    public = {
        "daemon_sha256": "1" * 64,
        "image_sha256": "2" * 64,
        "bootstrap_sha256": "4" * 64,
        "input_sha256": "9" * 64,
    }
    with monkeypatch.context() as patched:
        for name in (
            "_require_live_origin",
            "_require_bound_observation",
            "_run_isolated_observation",
            "_observation_stdout",
        ):
            patched.setattr(v, name, fail_if_called)
        wrapper = report(real_execution(**public), established(verdict=verdict, reason=reason))
        tree = wrapper.model_dump(mode="json")
        loaded = v.IsolatedInvocationReport.model_validate_json(json.dumps(tree))
        assert loaded.model_dump(mode="json") == tree
    # Actual guards are restored. The recorded label stays data and grants nothing.
    assert (loaded.verification_result.verdict, loaded.verification_result.reason) == (
        verdict,
        reason,
    )
    for candidate in (loaded.execution, loaded.execution.model_copy()):
        result = v.verify_isolated_execution(config(), "sum-echo-v1", candidate, artifact())
        assert (result.verdict, result.reason) == ("not_established", "not_live")
