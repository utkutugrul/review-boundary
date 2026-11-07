"""Digest-bound repository adjudication artifacts and pure post-run application.

An adjudication artifact carries only digests, decisions, issue mappings and
reasons. It never stores prompts, model responses, findings text or access
details. Application re-derives every score from a trusted observation snapshot
and the evaluator suite; edited report rows can never supply semantics.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator

from .provenance import json_digest
from .repository_cases import (
    REPOSITORY_SCORING_VERSION,
    FrozenModel,
    RepositoryCase,
    case_digest,
)
from .repository_world import (
    FindingAdjudication,
    RepositoryLimits,
    RepositoryReview,
    RepositoryWorld,
    RepositoryWorldSnapshot,
    ReviewAdjudication,
    finding_digest,
    review_digest,
    score_repository_world,
)

ADJUDICATION_SCHEMA_VERSION = 1
TEMPLATE_REASON = "Awaiting evaluator adjudication."
MAX_FINDING_DECISIONS = 32768
MAX_REVIEW_DECISIONS = 4096
MAX_FAILURE_SLOTS = 32768
FAILURE_EVIDENCE_FILENAME = "repository-failures.json"

Slot = tuple[str, str, int]

# The only row fields that adjudication may change. Everything else must be
# reproduced exactly from the trusted observation.
ADJUDICATION_KEYS = frozenset(
    {
        "target_issues_adjudicated",
        "correct_findings",
        "false_positives",
        "unknown_findings",
        "additional_valid_findings",
        "semantic_passed",
        "review_adjudication",
        "findings",
    }
)


class RepositoryAdjudicationArtifact(FrozenModel):
    schema_version: Literal[1]
    adjudication_kind: Literal["repository"]
    source_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    finding_decisions: tuple[FindingAdjudication, ...] = Field(max_length=MAX_FINDING_DECISIONS)
    review_decisions: tuple[ReviewAdjudication, ...] = Field(max_length=MAX_REVIEW_DECISIONS)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_schema_version(cls, value):
        # JSON true, 1.0 and 1e0 compare equal to 1 but are different documents.
        if type(value) is not int:
            raise ValueError("schema_version must be the integer 1")
        return value


class TrustedRepositoryObservation(FrozenModel):
    """Evaluator-authored row identity plus the frozen world needed for rescoring."""

    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer: str = Field(min_length=1, max_length=512)
    epoch: int = Field(ge=1, le=10)
    source_row_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    write_requests_seen: int = Field(ge=0, le=100000)
    snapshot: RepositoryWorldSnapshot | None = None


class RepositoryFailureSlot(FrozenModel):
    """One explicit native-provider failure, without a fabricated world snapshot."""

    case_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reviewer: str = Field(min_length=1, max_length=512)
    epoch: int = Field(ge=1, le=10)
    error_code: Literal["provider_error"]
    source_row_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RepositoryFailureEvidence(FrozenModel):
    """Trusted local run evidence, separate from the report and Inspect snapshots.

    The caller must trust the supplied log directory and this runner-authored
    artifact. Digest bindings establish consistency, not who authored the files.
    Only provider failures that happen outside Inspect are supported. An invalid
    evaluation log never becomes acceptable merely by labeling it a failure.
    """

    schema_version: Literal[1]
    evidence_kind: Literal["repository_provider_failures"]
    run_id: str = Field(min_length=1, max_length=512)
    source_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    world_limits_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    failures: tuple[RepositoryFailureSlot, ...] = Field(min_length=1, max_length=MAX_FAILURE_SLOTS)

    @field_validator("schema_version", mode="before")
    @classmethod
    def integer_schema_version(cls, value):
        if type(value) is not int:
            raise ValueError("schema_version must be the integer 1")
        return value


def _strict(model, value):
    if isinstance(value, model):
        return value
    return model.model_validate_json(json.dumps(value, allow_nan=False))


def canonical_report_digest(report: Mapping) -> str:
    """Hash the parsed report, so whitespace and key order cannot change identity."""
    if not isinstance(report, Mapping):
        raise ValueError("A report must be a JSON object.")  # noqa: TRY004
    return json_digest(report)


@dataclass(frozen=True)
class _RowIdentity:
    index: int
    slot: Slot
    case: RepositoryCase
    review_sha256: str | None
    finding_sha256: frozenset[str]


def _row_identities(report, cases: Sequence[RepositoryCase]) -> tuple[_RowIdentity, ...]:
    if (
        not isinstance(report, Mapping)
        or type(report.get("schema_version")) is not int
        or report["schema_version"] != 1
        or report.get("report_kind") != "repository"
        or not isinstance(report.get("rows"), list)
        or not isinstance(report.get("metadata"), Mapping)
    ):
        raise ValueError("Adjudication requires a schema 1 repository report.")
    by_digest = {case_digest(case): case for case in cases}
    if len(by_digest) != len(cases):
        raise ValueError("Repository cases must have unique immutable digests.")
    if report["metadata"].get("suite_sha256") != json_digest([case_digest(c) for c in cases]):
        raise ValueError("Report does not bind to the supplied evaluator suite.")
    metadata = report["metadata"]
    rows = report["rows"]
    reviewers = metadata.get("reviewers")
    epochs = metadata.get("epochs")
    if (
        metadata.get("run_kind") != "model"
        or metadata.get("scoring_version") != REPOSITORY_SCORING_VERSION
        or type(metadata.get("expected_count")) is not int
        or metadata["expected_count"] != len(rows)
        or type(metadata.get("case_count")) is not int
        or metadata["case_count"] != len(cases)
        or not isinstance(reviewers, list)
        or not reviewers
        or any(not isinstance(value, str) or not value for value in reviewers)
        or len(set(reviewers)) != len(reviewers)
        or type(epochs) is not int
        or not 1 <= epochs <= 10
    ):
        raise ValueError("Adjudication requires a complete native model report contract.")
    _strict(RepositoryLimits, metadata.get("world_limits"))
    identities, slots = [], set()
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError("Report rows must be objects.")  # noqa: TRY004
        digest = row.get("case_sha256")
        case = by_digest.get(digest) if isinstance(digest, str) else None
        reviewer, epoch = row.get("reviewer"), row.get("epoch")
        if (
            case is None
            or row.get("case_id") != case.case_id
            or not isinstance(reviewer, str)
            or type(epoch) is not int
        ):
            raise ValueError("Report row does not bind to the supplied evaluator suite.")
        slot = (digest, reviewer, epoch)
        if slot in slots:
            raise ValueError("Report contains a duplicate reviewer slot.")
        slots.add(slot)
        review_hash, finding_hashes = None, frozenset()
        # A row that records any failure never receives semantic judgment.
        if not row.get("error") and row.get("review") is not None:
            review = _strict(RepositoryReview, row["review"])
            review_hash = review_digest(review)
            finding_hashes = frozenset(finding_digest(f) for f in review.findings)
            recorded = row.get("findings")
            if not isinstance(recorded, list):
                raise ValueError("Report row findings do not match its recorded review.")
            recorded_hashes = []
            for item in recorded:
                if (
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("finding_sha256"), str)
                    or finding_digest(item.get("finding")) != item["finding_sha256"]
                ):
                    raise ValueError("Report row findings do not match its recorded review.")
                recorded_hashes.append(item["finding_sha256"])
            if len(recorded_hashes) != len(set(recorded_hashes)) or set(recorded_hashes) != set(
                finding_hashes
            ):
                raise ValueError("Report row findings do not match its recorded review.")
        identities.append(_RowIdentity(index, slot, case, review_hash, finding_hashes))
    recorded_slots = {row.slot for row in identities}
    expected_slots = {
        (case_digest(case), reviewer, epoch)
        for case in cases
        for reviewer in reviewers
        for epoch in range(1, epochs + 1)
    }
    declared_slots = metadata.get("expected_slots")
    if not isinstance(declared_slots, list):
        raise ValueError(  # noqa: TRY004
            "Repository report is missing its declared sample slots."
        )
    normalized_declared = set()
    for item in declared_slots:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"case_sha256", "reviewer", "epoch"}
            or not isinstance(item["case_sha256"], str)
            or not isinstance(item["reviewer"], str)
            or type(item["epoch"]) is not int
        ):
            raise ValueError("Repository report has an invalid declared sample slot.")
        normalized_declared.add((item["case_sha256"], item["reviewer"], item["epoch"]))
    if (
        len(normalized_declared) != len(declared_slots)
        or recorded_slots != expected_slots
        or normalized_declared != expected_slots
    ):
        raise ValueError("Repository report sample coverage does not match its declaration.")
    expected_summary = {
        "recorded": len(rows),
        "expected": metadata["expected_count"],
        "completed": sum(bool(row.get("completed")) for row in rows),
        "rubric_passed": sum(bool(row.get("rubric_passed")) for row in rows),
        "semantically_adjudicated": sum(row.get("semantic_passed") is not None for row in rows),
        "unknown_findings": sum(row.get("unknown_findings", 0) for row in rows),
        "errors": sum(bool(row.get("error")) for row in rows),
    }
    summary = report.get("summary")
    if (
        not isinstance(summary, Mapping)
        or set(summary) != set(expected_summary)
        or any(
            type(summary[key]) is not int or summary[key] != value
            for key, value in expected_summary.items()
        )
    ):
        raise ValueError("Repository report summary does not match its rows.")
    return tuple(identities)


def export_adjudication_template(
    report: Mapping, cases: Sequence[RepositoryCase]
) -> RepositoryAdjudicationArtifact:
    """Create an all-unknown template for each unique recorded finding and review."""
    if isinstance(report.get("metadata"), Mapping) and "adjudication" in report["metadata"]:
        raise ValueError("Source report is already adjudicated.")
    findings, reviews = set(), set()
    for row in _row_identities(report, cases):
        digest = case_digest(row.case)
        if row.review_sha256 is not None:
            reviews.add((digest, row.review_sha256))
            findings.update((digest, value) for value in row.finding_sha256)
    return RepositoryAdjudicationArtifact(
        schema_version=ADJUDICATION_SCHEMA_VERSION,
        adjudication_kind="repository",
        source_report_sha256=canonical_report_digest(report),
        finding_decisions=tuple(
            FindingAdjudication(
                case_sha256=case,
                finding_sha256=value,
                decision="unknown",
                reason=TEMPLATE_REASON,
            )
            for case, value in sorted(findings)
        ),
        review_decisions=tuple(
            ReviewAdjudication(
                case_sha256=case,
                review_sha256=value,
                decision="unknown",
                reason=TEMPLATE_REASON,
            )
            for case, value in sorted(reviews)
        ),
    )


def _unique(items: Iterable, key: Callable) -> dict:
    seen = {}
    for item in items:
        identity = key(item)
        if identity in seen:
            raise ValueError(
                "Conflicting adjudication decisions for one digest."
                if seen[identity] != item
                else "Duplicate adjudication decision."
            )
        seen[identity] = item
    return seen


def _json_type_exact(left, right) -> bool:
    """Compare canonical JSON values without Python's bool/int/float coercions."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            type(key) is str and _json_type_exact(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_type_exact(first, second) for first, second in zip(left, right, strict=True)
        )
    if left is None or isinstance(left, (str, bool, int, float)):
        try:
            json.dumps(left, allow_nan=False)
        except (TypeError, ValueError):
            return False
        return left == right
    return False


def _trusted_failure_slots(
    report: Mapping,
    cases: Sequence[RepositoryCase],
    evidence,
    limits: RepositoryLimits,
) -> frozenset[Slot]:
    """Validate independent local failure evidence against exact generated rows."""
    from .repository_runner import repository_error_rows

    artifact = _strict(RepositoryFailureEvidence, evidence)
    identities = _row_identities(report, cases)
    metadata = report["metadata"]
    if (
        metadata.get("run_finished") is not True
        or artifact.run_id != metadata.get("run_id")
        or artifact.source_report_sha256 != canonical_report_digest(report)
        or artifact.suite_sha256 != metadata.get("suite_sha256")
        or artifact.world_limits_sha256 != json_digest(limits.model_dump(mode="json"))
        or not _json_type_exact(metadata["world_limits"], limits.model_dump(mode="json"))
    ):
        raise ValueError("Provider failure evidence does not bind to this completed run.")
    declared = {}
    for record in artifact.failures:
        slot = (record.case_sha256, record.reviewer, record.epoch)
        if slot in declared:
            raise ValueError("Provider failure evidence contains a duplicate sample slot.")
        declared[slot] = record
    failed_reviewers = {slot[1] for slot in declared}
    if not failed_reviewers <= set(metadata["reviewers"]):
        raise ValueError("Provider failure evidence contains an undeclared reviewer.")
    expected = {}
    for reviewer in sorted(failed_reviewers):
        for source in repository_error_rows(
            tuple(cases), reviewer, metadata["epochs"], "provider_error"
        ):
            slot = (source["case_sha256"], source["reviewer"], source["epoch"])
            expected[slot] = source
    if set(declared) != set(expected):
        raise ValueError("Provider failure evidence must cover complete failed reviewer blocks.")
    source_by_slot = {row.slot: report["rows"][row.index] for row in identities}
    for slot, source in expected.items():
        original = source_by_slot[slot]
        if declared[slot].source_row_sha256 != json_digest(original) or not _json_type_exact(
            original, source
        ):
            raise ValueError(
                "Provider failure evidence does not match the exact failed sample rows."
            )
    return frozenset(declared)


def repository_failure_evidence(
    report: Mapping, cases: Sequence[RepositoryCase], failed_reviewers: Sequence[str]
) -> RepositoryFailureEvidence:
    """Build a separate artifact only for canonical, complete native provider failures.

    This function is called by the trusted runner after its final report is
    written. It does not make an arbitrary report or caller a trusted author.
    """
    identities = _row_identities(report, cases)
    reviewers = tuple(failed_reviewers)
    if not reviewers or len(set(reviewers)) != len(reviewers):
        raise ValueError("Failed reviewers must be nonempty and unique.")
    metadata = report["metadata"]
    limits = _strict(RepositoryLimits, metadata["world_limits"])
    artifact = RepositoryFailureEvidence(
        schema_version=1,
        evidence_kind="repository_provider_failures",
        run_id=metadata.get("run_id"),
        source_report_sha256=canonical_report_digest(report),
        suite_sha256=metadata["suite_sha256"],
        world_limits_sha256=json_digest(limits.model_dump(mode="json")),
        failures=tuple(
            RepositoryFailureSlot(
                case_sha256=row.slot[0],
                reviewer=row.slot[1],
                epoch=row.slot[2],
                error_code="provider_error",
                source_row_sha256=json_digest(report["rows"][row.index]),
            )
            for row in identities
            if row.slot[1] in reviewers
        ),
    )
    _trusted_failure_slots(report, cases, artifact, limits)
    return artifact


def write_repository_failure_evidence(
    report_path: Path,
    cases: Sequence[RepositoryCase],
    failed_reviewers: Sequence[str],
    log_directory: Path,
) -> Path:
    """Write an exclusive private sidecar next to the runner's trusted logs."""
    from .json_input import MAX_REPORT_BYTES, read_json_object
    from .repository_runner import _path_without_symlinks

    report = read_json_object(report_path)
    artifact = repository_failure_evidence(report, cases, failed_reviewers)
    document = json.dumps(artifact.model_dump(mode="json"), indent=2) + "\n"
    if len(document.encode("utf-8")) > MAX_REPORT_BYTES:
        raise ValueError("Provider failure evidence exceeds the file size limit.")
    directory = _path_without_symlinks(log_directory, "provider failure log directory")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    return write_new_text(
        directory / FAILURE_EVIDENCE_FILENAME, document, "provider failure evidence"
    )


def validate_adjudication(
    adjudication,
    report: Mapping,
    cases: Sequence[RepositoryCase],
    *,
    require_complete: bool = False,
) -> RepositoryAdjudicationArtifact:
    """Fail closed unless every decision binds to this report, suite, and rubric."""
    artifact = _strict(RepositoryAdjudicationArtifact, adjudication)
    if artifact.source_report_sha256 != canonical_report_digest(report):
        raise ValueError("Adjudication binds to a different or modified source report.")
    rows = _row_identities(report, cases)
    known_cases = {case_digest(case): case for case in cases}
    findings = _unique(artifact.finding_decisions, lambda d: (d.case_sha256, d.finding_sha256))
    reviews = _unique(artifact.review_decisions, lambda d: (d.case_sha256, d.review_sha256))
    recorded_findings = {
        (case_digest(row.case), value) for row in rows for value in row.finding_sha256
    }
    recorded_reviews = {
        (case_digest(row.case), row.review_sha256) for row in rows if row.review_sha256
    }
    for decision in (*findings.values(), *reviews.values()):
        if decision.case_sha256 not in known_cases:
            raise ValueError("Adjudication refers to an unknown case digest.")
    if not set(findings) <= recorded_findings:
        raise ValueError("Adjudication refers to a finding digest absent from the report.")
    if not set(reviews) <= recorded_reviews:
        raise ValueError("Adjudication refers to a review digest absent from the report.")
    for decision in findings.values():
        issues = {issue.issue_id: issue for issue in known_cases[decision.case_sha256].issues}
        if decision.issue_id is None:
            continue
        if decision.decision == "unknown":
            raise ValueError("Unknown finding decisions cannot carry an issue mapping.")
        if decision.issue_id not in issues:
            raise ValueError("Adjudication maps a finding to an unknown issue.")
        if decision.decision == "supported" and issues[decision.issue_id].expectation != "present":
            raise ValueError("A supported finding cannot map to an absent issue.")
    if require_complete and (
        set(findings) != recorded_findings or set(reviews) != recorded_reviews
    ):
        raise ValueError("Adjudication does not cover every recorded finding and review.")
    return artifact


def adjudicate_observation(
    case: RepositoryCase,
    observation: TrustedRepositoryObservation,
    limits: RepositoryLimits,
    source_row: Mapping,
    finding_decisions: Sequence[FindingAdjudication] = (),
    review_decision: ReviewAdjudication | None = None,
) -> dict:
    """Pure application: rescore a trusted snapshot, then confirm the row matches it."""
    trusted = _strict(TrustedRepositoryObservation, observation)
    if (
        trusted.case_sha256 != case_digest(case)
        or trusted.source_row_sha256 != json_digest(source_row)
        or trusted.snapshot is None
    ):
        raise ValueError("Source row does not bind to its trusted scorer observation.")
    world = RepositoryWorld.from_snapshot(case, trusted.snapshot, expected_limits=limits)
    writes = trusted.write_requests_seen
    base = score_repository_world(case, world, write_requests=writes)
    if any(
        key not in source_row or not _json_type_exact(source_row[key], value)
        for key, value in base.items()
    ):
        raise ValueError("Source row does not match its trusted observation.")
    result = score_repository_world(
        case, world, finding_decisions, review_decision, write_requests=writes
    )
    if any(
        not _json_type_exact(result[key], base[key]) for key in base if key not in ADJUDICATION_KEYS
    ):
        raise ValueError("Adjudication changed a field outside the semantic judgment.")
    return {**source_row, **{key: result[key] for key in ADJUDICATION_KEYS}}


def apply_repository_adjudication(
    report: Mapping,
    cases: Sequence[RepositoryCase],
    adjudication,
    observations: Mapping[Slot, TrustedRepositoryObservation],
    limits: RepositoryLimits,
    *,
    failure_evidence: RepositoryFailureEvidence | Mapping | None = None,
) -> tuple[list[dict], dict]:
    """Return new rows and metadata. The source report is never modified."""
    artifact = validate_adjudication(adjudication, report, cases)
    if "adjudication" in report["metadata"]:
        raise ValueError("Source report is already adjudicated.")
    failed_slots = (
        _trusted_failure_slots(report, cases, failure_evidence, limits)
        if failure_evidence is not None
        else frozenset()
    )
    if failed_slots.intersection(observations):
        raise ValueError("A provider failure slot conflicts with a trusted scorer observation.")
    identities = _row_identities(report, cases)
    declared_slots = {row.slot for row in identities}
    if set(observations) - declared_slots:
        raise ValueError("A trusted scorer observation refers to an undeclared report slot.")
    if failure_evidence is not None and not declared_slots - failed_slots:
        raise ValueError("Provider failure evidence requires at least one native observation.")
    findings = {(d.case_sha256, d.finding_sha256): d for d in artifact.finding_decisions}
    reviews = {(d.case_sha256, d.review_sha256): d for d in artifact.review_decisions}
    rows, adjudicated = list(report["rows"]), 0
    for row in identities:
        case_hash = case_digest(row.case)
        if row.slot in failed_slots:
            continue
        if row.slot not in observations:
            raise ValueError("A trusted scorer observation is missing for a report row.")
        observation = _strict(TrustedRepositoryObservation, observations[row.slot])
        source_row = report["rows"][row.index]
        if (
            observation.case_sha256 != case_hash
            or observation.reviewer != row.slot[1]
            or observation.epoch != row.slot[2]
            or observation.source_row_sha256 != json_digest(source_row)
        ):
            raise ValueError("Source row does not bind to its trusted scorer observation.")
        if row.review_sha256 is None:
            continue
        rows[row.index] = adjudicate_observation(
            row.case,
            observation,
            limits,
            source_row,
            [
                findings[(case_hash, value)]
                for value in sorted(row.finding_sha256)
                if (case_hash, value) in findings
            ],
            reviews.get((case_hash, row.review_sha256)),
        )
        adjudicated += 1
    metadata = {
        **report["metadata"],
        "adjudication": {
            "source_report_sha256": artifact.source_report_sha256,
            "artifact_sha256": json_digest(artifact.model_dump(mode="json")),
            "finding_decisions": len(artifact.finding_decisions),
            "review_decisions": len(artifact.review_decisions),
            "rows_adjudicated": adjudicated,
            "semantic_method": "explicit_evaluator_adjudication_only",
        },
    }
    if failure_evidence is not None:
        metadata["adjudication"]["failure_evidence_sha256"] = json_digest(
            _strict(RepositoryFailureEvidence, failure_evidence).model_dump(mode="json")
        )
    return rows, metadata


def observations_from_logs(
    logs: Iterable, cases: Sequence[RepositoryCase]
) -> tuple[dict[Slot, TrustedRepositoryObservation], RepositoryLimits]:
    """Extract frozen world snapshots from trusted Inspect logs, once per declared slot."""
    from .repository_runner import repository_rows_from_logs

    logs = tuple(logs)
    if not logs:
        raise ValueError("No Inspect logs were supplied.")
    by_digest = {case_digest(case): case for case in cases}
    sample_by_slot = {}
    limits: RepositoryLimits | None = None
    for log in logs:
        metadata = getattr(log.eval, "metadata", None)
        if not isinstance(metadata, Mapping) or "world_limits" not in metadata:
            raise ValueError("Inspect log does not record its trusted world limits.")
        current = _strict(RepositoryLimits, metadata["world_limits"])
        if limits is not None and current != limits:
            raise ValueError("Inspect logs disagree about their world limits.")
        limits = current
        for sample in log.samples or []:
            if not isinstance(sample.metadata, Mapping) or "case" not in sample.metadata:
                raise ValueError("Repository sample is missing its immutable case metadata.")
            logged = _strict(RepositoryCase, sample.metadata["case"])
            digest = case_digest(logged)
            if by_digest.get(digest) != logged or type(sample.epoch) is not int:
                raise ValueError("Repository sample does not match the declared suite.")
            slot = (digest, log.eval.model, sample.epoch)
            if slot in sample_by_slot:
                raise ValueError("Repository observation is duplicate or missing.")
            sample_by_slot[slot] = sample
    if limits is None:
        raise ValueError("No Inspect logs were supplied.")
    reviewers = list(dict.fromkeys(log.eval.model for log in logs))
    recorded_epochs = {
        sample.epoch for log in logs for sample in log.samples or [] if type(sample.epoch) is int
    }
    if not recorded_epochs or min(recorded_epochs) != 1 or max(recorded_epochs) > 10:
        raise ValueError("Repository logs have invalid epoch coverage.")
    trusted_rows = repository_rows_from_logs(logs, cases, reviewers, max(recorded_epochs))
    observations: dict[Slot, TrustedRepositoryObservation] = {}
    for row in trusted_rows:
        slot = (row["case_sha256"], row["reviewer"], row["epoch"])
        sample = sample_by_slot.get(slot)
        if sample is None:
            raise ValueError("Repository observation is duplicate or missing.")
        snapshot = (sample.store or {}).get("repository_world")
        parsed_snapshot = None
        if row["error"] is None:
            if not isinstance(snapshot, dict):
                raise ValueError("Repository observation is duplicate or missing.")
            parsed_snapshot = _strict(RepositoryWorldSnapshot, snapshot)
        observations[slot] = TrustedRepositoryObservation(
            case_sha256=row["case_sha256"],
            reviewer=row["reviewer"],
            epoch=row["epoch"],
            source_row_sha256=json_digest(row),
            write_requests_seen=row["write_requests_seen"],
            snapshot=parsed_snapshot,
        )
    return observations, limits


def write_new_text(path, text: str, label: str) -> Path:
    """Create a new regular file without following symlinks or replacing anything."""
    output, _ = _write_new_text_owned(path, text, label)
    return output


def _write_new_text_owned(path, text: str, label: str) -> tuple[Path, tuple[int, int]]:
    """Return the created descriptor's device/inode identity for transactional cleanup."""
    from .repository_runner import _path_without_symlinks

    output = _path_without_symlinks(Path(path), label)
    output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    identity = None
    stream = None
    try:
        descriptor = os.open(output, flags, 0o600)
        try:
            identity = os.fstat(descriptor)
        except BaseException:
            # Preserve the created inode for exact cleanup even when the public
            # fstat wrapper itself fails. os.stat(fd) is the same descriptor,
            # never a second pathname lookup.
            try:
                identity = os.stat(descriptor)
            except (OSError, TypeError, ValueError):
                pass
            raise
        if not stat.S_ISREG(identity.st_mode):
            raise ValueError(f"{label} must be a regular file")
        # Keep ownership of the descriptor so every fdopen/write/close failure
        # has one cleanup path and cannot strand a live descriptor.
        stream = os.fdopen(descriptor, "w", encoding="utf-8", closefd=False)
        stream.write(text)
        stream.close()
        stream = None
        owned_descriptor = descriptor
        descriptor = None
        # close(2) may release the number even when it reports an error. Drop
        # ownership before calling it so cleanup cannot close a reused fd.
        os.close(owned_descriptor)
    except BaseException:
        if identity is None and descriptor is not None:
            try:
                identity = os.stat(descriptor)
            except BaseException:  # noqa: BLE001
                # Without descriptor identity, pathname cleanup would be unsafe.
                identity = None
        if stream is not None:
            try:
                stream.close()
            except BaseException:  # noqa: BLE001
                # Cleanup must not replace the original fdopen/write/close failure.
                stream = None
        if identity is not None:
            try:
                current = output.lstat()
                if (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino):
                    output.unlink()
            except OSError:
                # Cleanup must not mask the triggering operation's exception.
                current = None
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise
    return output, (identity.st_dev, identity.st_ino)


def _read_logs(paths: Sequence) -> list:
    from inspect_ai.log import list_eval_logs, read_eval_log

    names = []
    for path in paths:
        if path.is_dir():
            names.extend(info.name for info in list_eval_logs(str(path)))
        else:
            names.append(str(path))
    if not names:
        raise ValueError("No Inspect logs were found.")
    return [read_eval_log(name) for name in names]


def _read_failure_evidence(paths: Sequence) -> RepositoryFailureEvidence | None:
    """Read only the fixed sidecar in explicitly supplied trusted log directories.

    Treating a directory as trusted is the caller's local-input decision, just
    as it is for Inspect logs. No artifact beside an untrusted report is loaded.
    A sidecar never authorizes ignoring a contradictory native Inspect log.
    """
    from .json_input import MAX_REPORT_BYTES, parse_json_object
    from .repository_runner import _path_without_symlinks

    found = []
    for path in paths:
        if path.is_dir():
            candidate = path / FAILURE_EVIDENCE_FILENAME
            # lexists also detects dangling links rather than silently ignoring them.
            if os.path.lexists(candidate):
                found.append(_path_without_symlinks(candidate, "provider failure evidence"))
    if len(found) > 1:
        raise ValueError("Only one provider failure evidence artifact may be supplied.")
    if not found:
        return None
    path = found[0]
    initial = path.lstat()
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > MAX_REPORT_BYTES:
        raise ValueError("Provider failure evidence must be a bounded regular file.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        current = os.fstat(descriptor)
        selected = path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or not stat.S_ISREG(selected.st_mode)
            or current.st_size > MAX_REPORT_BYTES
            or (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino)
            or (selected.st_dev, selected.st_ino) != (current.st_dev, current.st_ino)
        ):
            raise ValueError("Provider failure evidence changed or exceeded its file bound.")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_REPORT_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Provider failure evidence exceeds its file bound.")
    return _strict(RepositoryFailureEvidence, parse_json_object(raw))


def export_adjudication_command(args) -> int:
    from .json_input import read_json_object
    from .repository_runner import load_suite

    report = read_json_object(args.report)
    template = export_adjudication_template(report, load_suite(args.suite))
    write_new_text(
        args.output,
        json.dumps(template.model_dump(mode="json"), indent=2) + "\n",
        "adjudication template",
    )
    print(
        f"Adjudication template: {len(template.finding_decisions)} findings, "
        f"{len(template.review_decisions)} reviews, all unknown"
    )
    return 0


def apply_adjudication_command(args) -> int:
    from .json_input import read_json_object
    from .repository_runner import _path_without_symlinks, load_suite, write_repository_report

    output = _path_without_symlinks(args.output, "adjudication output")
    if output.exists():
        raise ValueError("Adjudication output must be a new directory")
    report = read_json_object(args.report)
    cases = load_suite(args.suite)
    adjudication = read_json_object(args.adjudication)
    failure_evidence = _read_failure_evidence(args.logs)
    logs = _read_logs(args.logs)
    if failure_evidence is not None:
        failed_reviewers = {record.reviewer for record in failure_evidence.failures}
        if any(log.eval.model in failed_reviewers for log in logs):
            raise ValueError("Provider failure evidence conflicts with supplied Inspect logs.")
    observations, limits = observations_from_logs(logs, cases)
    if report.get("metadata", {}).get("world_limits") != limits.model_dump(mode="json"):
        raise ValueError("Report world limits do not match the trusted logs.")
    rows, metadata = apply_repository_adjudication(
        report, cases, adjudication, observations, limits, failure_evidence=failure_evidence
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    artifact = _strict(RepositoryAdjudicationArtifact, adjudication)
    write_new_text(
        output / "adjudication.json",
        json.dumps(artifact.model_dump(mode="json"), indent=2) + "\n",
        "adjudication artifact",
    )
    path = write_repository_report(rows, output, metadata)
    print("Adjudicated repository report: " + str(path.parent.resolve() / "report.json"))
    return 0
