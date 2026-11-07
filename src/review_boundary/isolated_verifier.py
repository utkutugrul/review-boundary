"""Static sum-echo-v1 observer for isolated execution (plumbing calibration only).

Every candidate and container byte is adversarial and is never executed or
imported on the host. The host generates a fresh public challenge, computes the
reference sums itself and only compares a strictly parsed response. A verdict is
reachable only through the runner's live-origin and sealed-observation seams.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator

from .isolated_runner import (
    POLICY_SHA256,
    IsolatedExecution,
    IsolationConfig,
    _observation_stdout,
    _OriginError,
    _require_bound_observation,
    _require_live_origin,
    _run_isolated_observation,
)
from .isolation_payload import (
    IsolatedArtifact,
    IsolatedJob,
    IsolatedTextFile,
    artifact_digest,
    encode_observer_input,
)
from .repository_cases import FrozenModel

BINDING_ID = "sum-echo-v1"
UNRECOGNIZED_BINDING = "unrecognized"
OBSERVER_ARGV = ("/usr/local/bin/python3.11", "-I", "candidate.py")
CANDIDATE_PATH = "candidate.py"
MAX_SOURCE_BYTES = 65536
MAX_WIRE_BYTES = 512
PAIR_COUNT = 3
PAIR_MIN = -1000
PAIR_MAX = 1000
INT32_MIN = -2147483648
INT32_MAX = 2147483647
MAX_JSON_DEPTH = 16

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ExecutionId = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
BindingLabel = Annotated[
    str, Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
]
Reason = Literal[
    "matched",
    "behavior_mismatch",
    "unknown_binding",
    "not_live",
    "origin_incomplete",
    "origin_binding_mismatch",
    "artifact_mismatch",
    "artifact_invalid",
    "observation_unsupported",
    "observation_incomplete",
    "observation_binding_mismatch",
    "malformed_response",
    "cleanup_unconfirmed",
]
_VERDICTS = {"matched": "established_pass", "behavior_mismatch": "established_fail"}
_ORIGIN_REASONS = frozenset(
    {
        "not_live",
        "origin_incomplete",
        "origin_binding_mismatch",
        "artifact_mismatch",
        "artifact_invalid",
        "observation_binding_mismatch",
        "cleanup_unconfirmed",
    }
)
# Public identities the observation must share with its originating execution.
# source_sha256 is deliberately absent: the runner's private guard owns that chain.
_SHARED_CONTEXT = (
    "config_sha256",
    "daemon_sha256",
    "image_sha256",
    "policy_sha256",
    "bootstrap_sha256",
)
_BINDING_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}")
_NONCE_RE = re.compile(r"[0-9a-f]{32}")
_BOM = b"\xef\xbb\xbf"
# Expected, safe failure classes of the runner seams. Anything else is a
# programming error and propagates. _OriginError is handled before these.
_SEAM_ERRORS = (ValueError, TypeError, AttributeError, RuntimeError)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


CONTRACT_SPEC: dict[str, Any] = {
    "binding_id": BINDING_ID,
    "schema_version": 1,
    "scope": "plumbing_calibration_only",
    "job": {
        "argv": list(OBSERVER_ARGV),
        "files": [CANDIDATE_PATH],
        "collect_paths": [],
        "artifact_path": CANDIDATE_PATH,
        "artifact_encoding": "utf-8",
        "artifact_max_bytes": MAX_SOURCE_BYTES,
    },
    "input": {
        "keys": ["nonce", "pairs", "schema_version"],
        "nonce": "secrets.token_hex(16)",
        "pair_count": PAIR_COUNT,
        "pair_type": "int",
        "pair_range": [PAIR_MIN, PAIR_MAX],
        "max_bytes": MAX_WIRE_BYTES,
    },
    "output": {
        "keys": ["nonce", "schema_version", "sums"],
        "sum_count": PAIR_COUNT,
        "sum_type": "int32",
        "sum_range": [INT32_MIN, INT32_MAX],
        "max_bytes": MAX_WIRE_BYTES,
        "max_depth": MAX_JSON_DEPTH,
    },
    "hash": {
        "algorithm": "sha256",
        "canonical_json": "sorted_keys,separators(',',':'),ensure_ascii=False,allow_nan=False",
    },
}
CONTRACT_SHA256 = _sha256(_canonical(CONTRACT_SPEC))

# The single code-owned, read-only binding map. No plugin, callable, import path,
# config override or caller-supplied expected output can extend it.
_BINDINGS = MappingProxyType({BINDING_ID: CONTRACT_SHA256})


def _exact_version(value: Any) -> Any:
    if type(value) is not int or value != 1:
        raise ValueError("Expected exact schema version 1")
    return value


class VerificationResult(FrozenModel):
    schema_version: Literal[1] = 1
    report_family: Literal["isolated_verification"] = "isolated_verification"
    binding_id: BindingLabel
    contract_sha256: Hash = CONTRACT_SHA256
    policy_sha256: Hash = POLICY_SHA256
    verdict: Literal["established_pass", "established_fail", "not_established"]
    reason: Reason
    origin_execution_id: ExecutionId | None = None
    observation_execution_id: ExecutionId | None = None
    config_sha256: Hash | None = None
    source_sha256: Hash | None = None
    artifact_sha256: Hash | None = None
    observation_input_sha256: Hash | None = None
    observation_output_sha256: Hash | None = None
    scope: Literal["plumbing_calibration_only"] = "plumbing_calibration_only"
    publication: Literal["not_established"] = "not_established"

    _version = field_validator("schema_version", mode="before")(_exact_version)

    @model_validator(mode="after")
    def _consistent(self) -> VerificationResult:
        if self.contract_sha256 != CONTRACT_SHA256 or self.policy_sha256 != POLICY_SHA256:
            raise ValueError("Unexpected contract or policy hash")
        if self.verdict != _VERDICTS.get(self.reason, "not_established"):
            raise ValueError("Verdict and reason are inconsistent")
        metadata = (
            self.origin_execution_id,
            self.observation_execution_id,
            self.config_sha256,
            self.source_sha256,
            self.artifact_sha256,
            self.observation_input_sha256,
            self.observation_output_sha256,
        )
        if self.verdict != "not_established" and any(item is None for item in metadata):
            raise ValueError("A verdict requires complete binding metadata")
        if self.reason == "unknown_binding" and any(item is not None for item in metadata):
            raise ValueError("An unknown binding carries no execution metadata")
        return self

    def model_copy(self, *, update: Any = None, deep: bool = False) -> VerificationResult:
        values = {name: getattr(self, name) for name in type(self).model_fields}
        values.update(update or {})
        return type(self).model_validate(values)

    @classmethod
    def model_construct(cls, _fields_set: Any = None, **values: Any) -> VerificationResult:
        return cls.model_validate(values)


def _candidate_metadata(execution: IsolatedExecution) -> list[Any]:
    return [item for item in execution.artifact_manifest if item.path == CANDIDATE_PATH]


class IsolatedInvocationReport(FrozenModel):
    """Closed outer data tree: the unmodified execution plus an optional verification.

    This is data validation only. A loaded report carries no live authority and its
    verification_result is never accepted as evidence by any runner seam.
    """

    schema_version: Literal[1] = 1
    report_family: Literal["isolated_invocation"] = "isolated_invocation"
    execution: IsolatedExecution
    verification_result: VerificationResult | None

    _version = field_validator("schema_version", mode="before")(_exact_version)

    @model_validator(mode="after")
    def _consistent(self) -> IsolatedInvocationReport:
        result = self.verification_result
        if result is None:
            return self
        execution = self.execution
        mismatch = "Verification metadata does not match its execution"
        if (
            result.origin_execution_id is not None
            and result.origin_execution_id != execution.execution_id
        ):
            raise ValueError(mismatch)
        if result.observation_execution_id == execution.execution_id:
            raise ValueError(mismatch)
        for name in ("config_sha256", "source_sha256", "policy_sha256"):
            claimed, actual = getattr(result, name), getattr(execution, name)
            if claimed is not None and actual is not None and claimed != actual:
                raise ValueError(mismatch)
        candidates = _candidate_metadata(execution)
        if result.artifact_sha256 is not None and not any(
            item.sha256 == result.artifact_sha256 for item in candidates
        ):
            raise ValueError(mismatch)
        if result.verdict != "not_established":
            if _BINDINGS.get(result.binding_id) != result.contract_sha256:
                raise ValueError("Established record lacks a known binding")
            if (
                execution.runtime_kind != "real"
                or execution.status != "completed"
                or not execution.job_started
                or execution.error_code is not None
                or execution.cleanup != "confirmed"
                or execution.config_sha256 is None
                or execution.source_sha256 is None
                or execution.policy_sha256 is None
                or len(candidates) != 1
            ):
                raise ValueError("Established record lacks complete origin evidence")
        return self

    def model_copy(self, *, update: Any = None, deep: bool = False) -> IsolatedInvocationReport:
        values = {name: getattr(self, name) for name in type(self).model_fields}
        values.update(update or {})
        return type(self).model_validate(values)

    @classmethod
    def model_construct(cls, _fields_set: Any = None, **values: Any) -> IsolatedInvocationReport:
        return cls.model_validate(values)


# Pure challenge, parser and comparator helpers (static bytes and host values only).


@dataclass(frozen=True)
class _Challenge:
    nonce: str = field(repr=False)
    pairs: tuple[tuple[int, int], ...] = field(repr=False)
    sums: tuple[int, ...] = field(repr=False)
    wire: bytes = field(repr=False)


def _challenge_wire(nonce: str, pairs: tuple[tuple[int, int], ...]) -> bytes:
    wire = _canonical(
        {"schema_version": 1, "nonce": nonce, "pairs": [list(pair) for pair in pairs]}
    )
    if len(wire) > MAX_WIRE_BYTES:
        raise ValueError("Challenge exceeds its bound")
    return wire


def _new_challenge() -> _Challenge:
    # Controller-only generation: never reachable from candidate or container data.
    nonce = secrets.token_hex(16)
    pairs = tuple(
        (secrets.randbelow(2001) - 1000, secrets.randbelow(2001) - 1000) for _ in range(PAIR_COUNT)
    )
    sums = tuple(left + right for left, right in pairs)
    return _Challenge(nonce, pairs, sums, _challenge_wire(nonce, pairs))


class _ParseError(ValueError):
    pass


def _reject_constant(_: str) -> Any:
    raise _ParseError("Nonfinite JSON constant")


def _reject_float(_: str) -> Any:
    raise _ParseError("Expected an integer")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ParseError("Duplicate key")
        result[key] = value
    return result


def _depth_within_bound(text: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                return False
        elif char in "]}":
            depth -= 1
    return True


def _parse_response(raw: bytes) -> tuple[str, tuple[int, ...]]:
    """Strictly parse one complete child response into (nonce, sums)."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_WIRE_BYTES:
        raise _ParseError("Invalid response size")
    if raw.startswith(_BOM) or b"\0" in raw:
        raise _ParseError("Unsupported response bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise _ParseError("Invalid UTF-8") from None
    if not _depth_within_bound(text):
        raise _ParseError("Response is nested too deeply")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError):
        raise _ParseError("Invalid JSON") from None
    if type(value) is not dict or set(value) != {"schema_version", "nonce", "sums"}:
        raise _ParseError("Unexpected response keys")
    version, nonce, sums = value["schema_version"], value["nonce"], value["sums"]
    if type(version) is not int or version != 1:
        raise _ParseError("Unexpected version")
    if type(nonce) is not str or not _NONCE_RE.fullmatch(nonce):
        raise _ParseError("Unexpected nonce")
    if (
        type(sums) is not list
        or len(sums) != PAIR_COUNT
        or any(type(item) is not int or not INT32_MIN <= item <= INT32_MAX for item in sums)
    ):
        raise _ParseError("Unexpected sums")
    return nonce, tuple(sums)


def _matches(response: tuple[str, tuple[int, ...]], nonce: str, sums: tuple[int, ...]) -> bool:
    return response[0] == nonce and response[1] == tuple(sums)


def _source_text(data: Any) -> str:
    if type(data) is not bytes or len(data) > MAX_SOURCE_BYTES:
        raise ValueError("Invalid candidate source")
    if data.startswith(_BOM) or b"\0" in data:
        raise ValueError("Invalid candidate source")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Invalid candidate source") from None


def _observer_job(data: Any) -> IsolatedJob:
    """Build the fixed observer job around exactly the candidate source bytes."""
    return IsolatedJob(
        schema_version=1,
        argv=OBSERVER_ARGV,
        files=(IsolatedTextFile(path=CANDIDATE_PATH, content=_source_text(data)),),
        collect_paths=(),
    )


def _observer_input_digest(job: IsolatedJob, challenge_wire: bytes) -> str:
    """SHA256 of the wrapped observer wire. Differs from SHA256(challenge_wire)."""
    return _sha256(encode_observer_input(job, challenge_wire))


def _observation_problem(execution: Any) -> str | None:
    """Classify shared public observation metadata. This grants no authority.

    Only the frozen shared fields are used. The sealed _observation_stdout seam
    validates the actual runtime, gate and inspection bindings.
    """
    if type(execution) is not IsolatedExecution:
        return "observation_binding_mismatch"
    if execution.runtime_kind != "real":
        return "observation_binding_mismatch"
    if execution.cleanup == "failed" or execution.error_code == "cleanup_failed":
        return "cleanup_unconfirmed"
    if execution.status == "not_started":
        return "observation_unsupported"
    if execution.status == "error":
        return "observation_incomplete" if execution.job_started else "observation_unsupported"
    if execution.cleanup != "confirmed":
        return "cleanup_unconfirmed"
    if not execution.job_started or execution.error_code is not None:
        return "observation_incomplete"
    return None


def _context_problem(observation: Any, origin: Any, expected_input_sha256: str) -> str | None:
    """Compare public observation identities with the originating execution.

    Pure metadata comparison that grants no authority: returning None only means
    the shared public fields agree. Missing or different fields never compare equal.
    """
    mismatch = "observation_binding_mismatch"
    if type(observation) is not IsolatedExecution or type(origin) is not IsolatedExecution:
        return mismatch
    if observation.execution_id == origin.execution_id:
        return mismatch
    if observation.input_sha256 is None or observation.input_sha256 != expected_input_sha256:
        return mismatch
    for name in _SHARED_CONTEXT:
        seen, expected = getattr(observation, name), getattr(origin, name)
        if seen is None or expected is None or seen != expected:
            return mismatch
    return None


def _guard_reason(observation: Any, error: Any) -> str:
    """Fixed reason for a rejected binding guard, keeping real error metadata classes."""
    problem = _observation_problem(observation)
    if problem is not None:
        return problem
    if getattr(error, "code", None) == "cleanup_unconfirmed":
        return "cleanup_unconfirmed"
    return "observation_binding_mismatch"


def _safe_label(value: Any) -> str:
    if type(value) is str and _BINDING_RE.fullmatch(value):
        return value
    return UNRECOGNIZED_BINDING


def _origin_reason(error: _OriginError) -> str:
    code = getattr(error, "code", None)
    return code if code in _ORIGIN_REASONS else "not_live"


def _result(label: str, reason: str, **metadata: Any) -> VerificationResult:
    return VerificationResult(
        binding_id=label,
        verdict=_VERDICTS.get(reason, "not_established"),
        reason=reason,
        **metadata,
    )


def verify_isolated_execution(
    config: IsolationConfig,
    binding_id: str,
    live_execution: IsolatedExecution,
    artifact: IsolatedArtifact,
) -> VerificationResult:
    label = _safe_label(binding_id)
    if type(binding_id) is not str or binding_id not in _BINDINGS:
        return _result(label, "unknown_binding")

    metadata: dict[str, Any] = {}
    try:
        origin = _require_live_origin(config, live_execution, artifact)
        origin_id = live_execution.execution_id
        config_sha = live_execution.config_sha256
        source_sha = live_execution.source_sha256
        artifact_sha = artifact_digest(artifact)
    except _OriginError as error:
        return _result(label, _origin_reason(error))
    except _SEAM_ERRORS:
        return _result(label, "not_live")
    # Origin job/source state digest and candidate artifact bytes are distinct.
    if config_sha is None or source_sha is None:
        return _result(label, "origin_binding_mismatch")
    metadata.update(
        origin_execution_id=origin_id,
        config_sha256=config_sha,
        source_sha256=source_sha,
        artifact_sha256=artifact_sha,
    )

    try:
        job = _observer_job(artifact.data)
    except (ValueError, TypeError):
        return _result(label, "artifact_invalid", **metadata)

    challenge = _new_challenge()
    # Public correlation digest of the raw challenge only.
    metadata["observation_input_sha256"] = _sha256(challenge.wire)
    try:
        # Wrapped observer wire identity, compared independently with the observation.
        expected_input_sha = _observer_input_digest(job, challenge.wire)
    except _SEAM_ERRORS:
        return _result(label, "observation_incomplete", **metadata)
    try:
        observation = _run_isolated_observation(config, job, challenge.wire, origin)
    except _OriginError as error:
        return _result(label, _origin_reason(error), **metadata)
    except _SEAM_ERRORS:
        return _result(label, "observation_incomplete", **metadata)

    # The private guard runs before any sealed stdout read or behavioral comparison.
    try:
        _require_bound_observation(config, observation, origin, challenge.wire)
    except _OriginError as error:
        return _result(label, _guard_reason(observation, error), **metadata)
    except _SEAM_ERRORS:
        return _result(label, _guard_reason(observation, None), **metadata)

    problem = _observation_problem(observation) or _context_problem(
        observation, live_execution, expected_input_sha
    )
    if problem is not None:
        return _result(label, problem, **metadata)

    try:
        stdout = _observation_stdout(observation)
    except _OriginError as error:
        return _result(label, _origin_reason(error), **metadata)
    except _SEAM_ERRORS:
        return _result(label, "observation_binding_mismatch", **metadata)
    if type(stdout) is not bytes:
        return _result(label, "observation_binding_mismatch", **metadata)
    metadata["observation_execution_id"] = observation.execution_id
    metadata["observation_output_sha256"] = _sha256(stdout)

    try:
        response = _parse_response(stdout)
    except _ParseError:
        return _result(label, "malformed_response", **metadata)
    reason = (
        "matched" if _matches(response, challenge.nonce, challenge.sums) else "behavior_mismatch"
    )
    return _result(label, reason, **metadata)
