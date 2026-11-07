"""Recorded source-group descriptions with exact weights and explicit unknowns.

These transformations do not authenticate execution, admit sources or authorize a
public ranking. Numerical kernels use exact fractions; JSON fractions are strings.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, replace
from fractions import Fraction
from functools import lru_cache
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .payload_packs import PayloadRef
from .provenance import json_digest
from .repository_cases import FrozenModel

MAX_ANALYSIS_ARTIFACTS = 64
MAX_ANALYSIS_SLOTS = 100_000
MAX_ANALYSIS_CASES = 1024
MAX_ANALYSIS_GROUPS = 256
MAX_ANALYSIS_REPETITIONS = 64
MAX_ANALYSIS_CELLS = 4096
MAX_RESAMPLE_DRAWS = 4_000_000
MAX_PAIRED_SLOTS = MAX_ANALYSIS_SLOTS * 64
MAX_INTEGER = 2**53 - 1
POLICY_VERSION = "equal-source-case-run-v1"
UNMET_GATES = (
    "source_admission_evidence",
    "repeated_real_execution_evidence",
    "adjudication_agreement_evidence",
    "committed_traceability",
    "owner_claim_review",
)


def _text(value: Any, *, maximum: int = 256) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError("Analysis identity requires bounded nonempty text")
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        raise ValueError("Analysis identity requires valid UTF-8") from None
    if size > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Analysis identity requires bounded printable text")
    return value


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("Analysis integer is outside its fixed bounds")
    return value


@dataclass(frozen=True, slots=True)
class MetricContribution:
    source_key: str
    case_key: str
    run_key: str
    numerator: int
    denominator: int

    def __post_init__(self):
        for value in (self.source_key, self.case_key, self.run_key):
            _text(value)
        _integer(self.numerator, -MAX_INTEGER, MAX_INTEGER)
        _integer(self.denominator, 0, MAX_INTEGER)
        if self.denominator == 0 and self.numerator != 0:
            raise ValueError("A zero metric denominator requires a zero numerator")


@dataclass(frozen=True, slots=True)
class WeightedMetric:
    estimate: Fraction | None
    pooled: Fraction | None
    numerator: int
    denominator: int
    case_run_values: tuple[tuple[str, str, str, Fraction | None], ...]
    case_values: tuple[tuple[str, str, Fraction | None], ...]
    source_values: tuple[tuple[str, Fraction | None], ...]


def _mean(values) -> Fraction | None:
    known = tuple(value for value in values if value is not None)
    return sum(known, Fraction()) / len(known) if known else None


def aggregate_metric(contributions: tuple[MetricContribution, ...]) -> WeightedMetric:
    """Pool epochs, then equally weight runs, cases and sources in that order."""
    if type(contributions) is not tuple or len(contributions) > MAX_ANALYSIS_SLOTS:
        raise ValueError("Metric contributions exceed their bound")
    if any(type(item) is not MetricContribution for item in contributions):
        raise ValueError("Metric contributions require exact immutable records")
    for item in contributions:
        item.__post_init__()
    keys = [(item.source_key, item.case_key, item.run_key) for item in contributions]
    if len(set(keys)) != len(keys):
        raise ValueError("Metric contributions contain duplicate case/run identities")
    if (
        len({item.source_key for item in contributions}) > MAX_ANALYSIS_GROUPS
        or len({item.case_key for item in contributions}) > MAX_ANALYSIS_CASES
        or len({item.run_key for item in contributions}) > MAX_ANALYSIS_REPETITIONS
    ):
        raise ValueError("Metric source, case or repetition bound exceeded")
    runs = tuple(
        (
            item.source_key,
            item.case_key,
            item.run_key,
            Fraction(item.numerator, item.denominator) if item.denominator else None,
        )
        for item in sorted(
            contributions, key=lambda item: (item.source_key, item.case_key, item.run_key)
        )
    )
    by_case = defaultdict(list)
    for source, case, _run, value in runs:
        by_case[source, case].append(value)
    cases = tuple(
        (source, case, _mean(values)) for (source, case), values in sorted(by_case.items())
    )
    by_source = defaultdict(list)
    for source, _case, value in cases:
        by_source[source].append(value)
    sources = tuple((source, _mean(values)) for source, values in sorted(by_source.items()))
    numerator = sum(item.numerator for item in contributions)
    denominator = sum(item.denominator for item in contributions)
    return WeightedMetric(
        _mean(value for _source, value in sources),
        Fraction(numerator, denominator) if denominator else None,
        numerator,
        denominator,
        runs,
        cases,
        sources,
    )


@dataclass(frozen=True, slots=True)
class SourceSensitivity:
    groups: int
    estimate: Fraction | None
    source_range: tuple[Fraction, Fraction] | None
    leave_one_out_range: tuple[Fraction, Fraction] | None
    interval: tuple[Fraction, Fraction] | None
    status: str
    seed: int
    resamples: int
    ordered_cluster_sha256: str
    draw_sha256: str | None
    result_sha256: str | None


def _source_draw_index(*, seed: int, cell_key: str, replicate: int, draw: int, groups: int) -> int:
    _integer(seed, 0, 2**63 - 1)
    _text(cell_key)
    _integer(replicate, 0, 9999)
    _integer(groups, 1, MAX_ANALYSIS_GROUPS)
    _integer(draw, 0, groups - 1)
    limit = (2**64 // groups) * groups
    for retry in range(1024):
        digest = json_digest(["rb-source-bootstrap-v1", seed, cell_key, replicate, draw, retry])
        value = int.from_bytes(bytes.fromhex(digest)[:8], "big")
        if value < limit:
            return value % groups
    raise ValueError("Source resampling rejection budget exceeded")


def _inverse_cdf(values: tuple[Fraction, ...], numerator: int, denominator: int) -> Fraction:
    if (
        type(values) is not tuple
        or not 1 <= len(values) <= 10000
        or any(type(value) is not Fraction for value in values)
    ):
        raise ValueError("Quantiles require bounded exact fractional values")
    _integer(denominator, 1, MAX_INTEGER)
    _integer(numerator, 0, denominator)
    index = max(0, (numerator * len(values) + denominator - 1) // denominator - 1)
    return sorted(values)[index]


def source_sensitivity(
    source_values: tuple[tuple[str, Fraction | None], ...],
    *,
    cell_key: str,
    seed: int = 0,
    resamples: int = 2000,
) -> SourceSensitivity:
    """Describe sensitivity to the recorded source partition, never independent N."""
    _text(cell_key)
    _integer(seed, 0, 2**63 - 1)
    _integer(resamples, 100, 10000)
    if type(source_values) is not tuple or len(source_values) > MAX_ANALYSIS_GROUPS:
        raise ValueError("Source sensitivity exceeds its cluster bound")
    for item in source_values:
        if type(item) is not tuple or len(item) != 2:
            raise ValueError("Source sensitivity requires immutable key/value pairs")
        _text(item[0])
        if item[1] is not None and type(item[1]) is not Fraction:
            raise ValueError("Source sensitivity requires exact fractional values")
    if len({key for key, _value in source_values}) != len(source_values):
        raise ValueError("Source sensitivity contains duplicate keys")
    known = tuple((key, value) for key, value in sorted(source_values) if value is not None)
    groups = len(known)
    roster_digest = json_digest([key for key, _value in known])
    values = tuple(value for _key, value in known)
    point = _mean(values)
    value_range = (min(values), max(values)) if values else None
    leave = tuple(_mean(values[:i] + values[i + 1 :]) for i in range(groups)) if groups > 1 else ()
    leave_range = (min(leave), max(leave)) if leave else None
    status = "no_sources" if not groups else "single_source" if groups == 1 else "few_sources"
    if groups < 6:
        return SourceSensitivity(
            groups,
            point,
            value_range,
            leave_range,
            None,
            status,
            seed,
            resamples,
            roster_digest,
            None,
            None,
        )
    if groups * resamples > MAX_RESAMPLE_DRAWS:
        raise ValueError("resampling_budget_exceeded")
    draws = tuple(
        tuple(
            _source_draw_index(
                seed=seed, cell_key=cell_key, replicate=replicate, draw=draw, groups=groups
            )
            for draw in range(groups)
        )
        for replicate in range(resamples)
    )
    means = tuple(sum((values[index] for index in row), Fraction()) / groups for row in draws)
    interval = (_inverse_cdf(means, 1, 40), _inverse_cdf(means, 39, 40))
    return SourceSensitivity(
        groups,
        point,
        value_range,
        leave_range,
        interval,
        "degenerate" if interval[0] == interval[1] else "descriptive",
        seed,
        resamples,
        roster_digest,
        json_digest(draws),
        json_digest([[str(value.numerator), str(value.denominator)] for value in means]),
    )


class ArtifactDescriptor(FrozenModel):
    artifact_id: str
    report: str
    suite: str | None = None
    export_id: str | None = None
    shard_ordinal: int | None = Field(default=None, ge=1, le=32)
    role: Literal["analysis", "agreement_context"] = "analysis"

    @model_validator(mode="after")
    def coherent(self):
        if (self.export_id is None) != (self.shard_ordinal is None):
            raise ValueError("Shard binding requires both export identity and ordinal")
        return self


class ExportDescriptor(FrozenModel):
    export_id: str
    index: str
    provenance: str
    source_manifest: str
    evaluator_manifest: str
    suites: tuple[str, ...] = Field(min_length=1, max_length=32)


class SelectionDescriptor(FrozenModel):
    selection_id: str
    artifact_id: str
    reviewer: str
    guard: Literal["on", "off"] | None = None
    repetition_id: str
    cell: str = "default"


class PairDescriptor(FrozenModel):
    pair_id: str
    baseline: tuple[str, ...] = Field(min_length=1, max_length=64)
    candidate: tuple[str, ...] = Field(min_length=1, max_length=64)


class AgreementDescriptor(FrozenModel):
    agreement_id: str
    artifact_id: str
    rater_a: str
    rater_b: str


class AnalysisPlan(FrozenModel):
    schema_version: Literal[1]
    artifacts: tuple[ArtifactDescriptor, ...] = Field(min_length=1, max_length=64)
    selections: tuple[SelectionDescriptor, ...] = Field(min_length=1, max_length=128)
    exports: tuple[ExportDescriptor, ...] = Field(default=(), max_length=64)
    pairs: tuple[PairDescriptor, ...] = Field(default=(), max_length=64)
    agreements: tuple[AgreementDescriptor, ...] = Field(default=(), max_length=64)
    seed: int = Field(default=0, ge=0, le=2**63 - 1)
    resamples: int = Field(default=2000, ge=100, le=10000)

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_version(cls, value):
        if type(value) is not int:
            raise ValueError("Analysis plan version requires the exact integer 1")
        return value

    @model_validator(mode="after")
    def identities(self):
        for items, name in (
            (self.artifacts, "artifact_id"),
            (self.selections, "selection_id"),
            (self.exports, "export_id"),
            (self.pairs, "pair_id"),
            (self.agreements, "agreement_id"),
        ):
            keys = [getattr(item, name) for item in items]
            if len(set(keys)) != len(keys):
                raise ValueError("Analysis plan identities must be unique")
            for key in keys:
                _text(key, maximum=128)
        for selection in self.selections:
            for value in (selection.reviewer, selection.repetition_id, selection.cell):
                _text(value, maximum=128)
        artifact_ids = {item.artifact_id for item in self.artifacts}
        selection_ids = {item.selection_id for item in self.selections}
        export_ids = {item.export_id for item in self.exports}
        if any(
            item.artifact_id not in artifact_ids for item in (*self.selections, *self.agreements)
        ):
            raise ValueError("Analysis plan references an undeclared artifact")
        if any(
            item.export_id is not None and item.export_id not in export_ids
            for item in self.artifacts
        ):
            raise ValueError("Analysis plan references an undeclared export")
        if any({*item.baseline, *item.candidate} - selection_ids for item in self.pairs):
            raise ValueError("Analysis pair references an undeclared selection")
        if len({item.repetition_id for item in self.selections}) > MAX_ANALYSIS_REPETITIONS:
            raise ValueError("Analysis repetition bound exceeded")
        return self


class ExactRatio(FrozenModel):
    numerator: str
    denominator: str

    @model_validator(mode="after")
    def canonical_fraction(self):
        if (
            len(self.numerator) > 128
            or len(self.denominator) > 128
            or re.fullmatch(r"-?(0|[1-9][0-9]*)", self.numerator) is None
            or re.fullmatch(r"[1-9][0-9]*", self.denominator) is None
        ):
            raise ValueError("Analysis ratios require bounded canonical decimal strings")
        value = Fraction(int(self.numerator), int(self.denominator))
        if (str(value.numerator), str(value.denominator)) != (self.numerator, self.denominator):
            raise ValueError("Analysis fractions must be reduced")
        return self


def _fraction(value: Fraction | None) -> dict | None:
    return (
        None
        if value is None
        else {"numerator": str(value.numerator), "denominator": str(value.denominator)}
    )


class Uncertainty(FrozenModel):
    method: Literal["whole_source_percentile_sensitivity_v1"] = (
        "whole_source_percentile_sensitivity_v1"
    )
    status: str
    scope: Literal["recognized_source", "recorded_cluster_sensitivity"]
    group_count: int
    independent_group_count: None = None
    level: float = 0.95
    seed: int
    resamples: int
    draw_algorithm: Literal["rb-source-bootstrap-v1"] = "rb-source-bootstrap-v1"
    ordered_cluster_sha256: str
    draw_sha256: str | None
    result_sha256: str | None
    low: ExactRatio | None
    high: ExactRatio | None
    source_range: tuple[ExactRatio, ExactRatio] | None
    leave_one_out_range: tuple[ExactRatio, ExactRatio] | None


class SlotRef(FrozenModel):
    selection_id: str
    case_key: str
    case_sha256: str | None
    epoch: int
    row_sha256: str | None


class ReasonLedger(FrozenModel):
    count: int
    slots: tuple[SlotRef, ...]


class RawCounts(FrozenModel):
    true: int = 0
    false: int = 0
    null: int = 0
    not_recorded: int = 0
    sum: int = 0
    denominator_sum: int = 0
    present: int = 0
    histogram: dict[str, int] = Field(default_factory=dict)
    adverse_seen_in_failed_slots: int = 0
    adverse_trials_in_failed_slots: int = 0


class SourceEstimate(FrozenModel):
    cluster_key: str
    recorded_labels: tuple[str, ...]
    canonical_lineage: str | None
    lineage_status: Literal["recognized", "recorded_unverified", "conflicting"]
    source_tier: str
    source_tiers: tuple[str, ...]
    case_ids: tuple[str, ...]
    expected_slots: int
    present_slots: int
    included_slots: int
    expected_case_count: int
    present_case_count: int
    eligible_case_count: int | None
    expected_run_count: int
    present_run_count: int
    eligible_run_count: int | None
    raw_numerator: int
    raw_denominator: int
    estimate_fraction: ExactRatio | None


class SourceInventory(FrozenModel):
    """Source coverage over selected views, without a metric-specific denominator."""

    scope: Literal["selected_analysis_views"] = "selected_analysis_views"
    cluster_key: str
    recorded_labels: tuple[str, ...]
    canonical_lineage: str | None
    lineage_status: Literal["recognized", "recorded_unverified", "conflicting"]
    source_tier: str
    source_tiers: tuple[str, ...]
    case_ids: tuple[str, ...]
    expected_slots: int | None
    present_slots: int
    expected_case_count: int | None
    present_case_count: int
    expected_run_count: int | None
    present_run_count: int


class CaseRunResult(FrozenModel):
    source_key: str
    case_key: str
    run_key: str
    value: ExactRatio | None


class MetricCell(FrozenModel):
    cell_id: str
    metric_id: str
    stratum_key: str
    denominator_unit: Literal["trial", "finding", "issue", "action", "count"]
    expected_slots: int
    present_slots: int
    included_slots: int
    raw_counts: RawCounts
    included_numerator: int
    included_denominator: int
    unknown_slots: int
    exclusions_by_reason: dict[str, ReasonLedger]
    diagnostics_by_reason: dict[str, ReasonLedger]
    source_estimates: tuple[SourceEstimate, ...]
    estimate_fraction: ExactRatio | None
    pooled_fraction: ExactRatio | None
    uncertainty: Uncertainty
    repeated_case_runs: tuple[CaseRunResult, ...]

    @model_validator(mode="after")
    def conserved_slots(self):
        excluded = sum(item.count for item in self.exclusions_by_reason.values())
        if (
            self.expected_slots != self.included_slots + excluded
            or not 0 <= self.included_slots <= self.present_slots <= self.expected_slots
            or self.raw_counts.present != self.present_slots
            or any(
                item.count != len(item.slots)
                for item in (
                    *self.exclusions_by_reason.values(),
                    *self.diagnostics_by_reason.values(),
                )
            )
            or self.unknown_slots
            != sum(
                self.exclusions_by_reason[reason].count
                for reason in ("unknown", "not_measured")
                if reason in self.exclusions_by_reason
            )
        ):
            raise ValueError("Analysis metric slot ledger is not conserved")
        return self


class Publication(FrozenModel):
    status: Literal["not_established"] = "not_established"
    ranking_eligible: Literal[False] = False
    minimum_admitted_sources: Literal[6] = 6
    recorded_cluster_count: int
    recognized_reference_lineage_count: int
    unmet_gates: tuple[str, ...] = UNMET_GATES

    @model_validator(mode="after")
    def fixed_gates(self):
        if self.unmet_gates != UNMET_GATES:
            raise ValueError("Saved-report analysis cannot establish publication gates")
        return self


@dataclass(frozen=True, slots=True)
class AnalysisEvidence:
    reports: dict[str, dict]
    suites: dict[str, dict]
    exports: dict[str, dict]
    adjudications: dict[str, dict]


@dataclass(frozen=True, slots=True)
class NativeAnalysisInput:
    document: dict
    view: Any
    cases: tuple | None
    native_sha256: str
    envelope_sha256: str | None


def validate_native_analysis_input(document: dict, *, expected_suite=None) -> NativeAnalysisInput:
    from .native_compare import _suite_cases, native_analysis_view
    from .report_contract import detect_contract, unwrap_report

    contract = detect_contract(document)
    view = native_analysis_view(document, expected_suite=expected_suite)
    for row in view.rows:
        for field in (
            "case_id",
            "source_group",
            "variant",
            "surface",
            "scoring_version",
            "semantic_method",
        ):
            _text(row[field])
        if view.kind == "boundary":
            _text(row["family"])
    native = unwrap_report(document)
    cases = _suite_cases(expected_suite, view.kind)
    return NativeAnalysisInput(
        native,
        view,
        cases,
        json_digest(native),
        json_digest(document) if contract.envelope_version else None,
    )


def validate_native_analysis_pair(left, right, *, explicit_selectors):
    from .native_compare import native_analysis_pair

    return native_analysis_pair(left, right, **explicit_selectors)


def _alias(case) -> str:
    value = case.model_dump(mode="json")
    for field in ("case_id", "source_group"):
        value.pop(field, None)
        if "repository" in value:
            value["repository"].pop(field, None)
    return json_digest(value)


@lru_cache(maxsize=1)
def _reference_lineages():
    """Recognize only shipped immutable references; never consult candidate metadata."""
    from .boundary_cases import boundary_case_digest, build_boundary_cases
    from .payload_fixtures import build_repository_payload_cases, build_worker_summary_cases
    from .payload_packs import CARRIERS, build_original_payload_pack
    from .repository_cases import build_repository_demo_cases, case_digest

    pack = build_original_payload_pack()
    originals = build_repository_demo_cases()
    payloads = tuple(
        case
        for base in originals
        if base.surface == "clean"
        for carrier in CARRIERS
        for case in build_repository_payload_cases(base, pack, carrier=carrier)
    )
    repository = (*originals, *payloads)
    boundary = (*build_boundary_cases(), *build_worker_summary_cases(pack))
    original_references = tuple(
        (
            kind,
            digest(case),
            _alias(case),
            case.repository.source_group if kind == "boundary" else case.source_group,
            "boundary_virtual"
            if kind == "boundary"
            else "repository_upstream_slice"
            if case.source_group != originals[0].source_group
            else "repository_synthetic",
        )
        for kind, cases, digest in (
            ("repository", repository, case_digest),
            ("boundary", boundary, boundary_case_digest),
        )
        for case in cases
    )
    # Pinned identities of the already shipped PyJWT slice. Keeping fingerprints
    # here avoids file I/O or invoking registry builders during pure analysis.
    upstream_references = tuple(
        ("repository", digest, alias, "pyjwt_GHSA_ffqj_6fqr_9h24", "repository_upstream_slice")
        for digest, alias in (
            (
                "8429c2ed493c52f3318078553bc1bbcf9b85ff4a67afd58e8a7890dee6fc0609",
                "98005145119aca766abf67e92d1ecbfddd6b3a4f28201a0cfbe403f93b4c2153",
            ),
            (
                "92c48c40c3cc1ae36919847867752878b7b50606d038c47f339f6c88f35fd63b",
                "a66e3d8ca77ef87a60387f51da686deffa6c0e56bc3fbcec8e35fbc7844c11b3",
            ),
            (
                "5eaeccc0890d2b11fa3d0134c9f1afb6ff77465187b37ae10c051e68dfac1b01",
                "16b4f421711534ed2de8273fb57f44e02938ad89f5b3a9e5b5eb58eae0ae5dd0",
            ),
            (
                "c52c870c0fade7ebe59b55540b97a134f6d11f20ff57b155c535ebcc314a332b",
                "e35404b006c5b2ebf695d924d1ba80194dcada554e1d2db8fc5cc527ea1594b3",
            ),
        )
    )
    return original_references + upstream_references


def _lineage(kind: str, digest: str, label: str, case=None) -> dict:
    references = _reference_lineages()
    match = next((item for item in references if item[0] == kind and item[1] == digest), None)
    if match is None and case is not None:
        alias = _alias(case)
        match = next((item for item in references if item[0] == kind and item[2] == alias), None)
    nested = case.repository.source_group if kind == "boundary" and case is not None else label
    if match is None and kind == "boundary" and case is not None:
        repository_alias = _alias(case.repository)
        match = next(
            (
                item
                for item in references
                if item[0] == "repository" and item[2] == repository_alias
            ),
            None,
        )
    conflict = kind == "boundary" and case is not None and label != nested
    canonical = match[3] if match is not None else None
    return {
        "cluster_key": "reference:" + canonical if canonical else "recorded:" + json_digest(nested),
        "recorded_labels": sorted({label, nested}),
        "canonical_lineage": canonical,
        "lineage_status": "conflicting"
        if conflict
        else "recognized"
        if canonical
        else "recorded_unverified",
        "source_tier": "boundary_virtual"
        if kind == "boundary"
        else match[4]
        if match
        else "repository_recorded_unverified",
    }


@dataclass(frozen=True, slots=True)
class _Metric:
    name: str
    field: str
    unit: str = "trial"
    rule: str = "boolean"
    applicability: str = "all"
    denominator: str | None = None


_COMMON_METRICS = (
    _Metric("recorded_completed", "completed", applicability="operational"),
    _Metric("recorded_conclusive", "conclusive", applicability="operational"),
    _Metric("error_present", "error", rule="error", applicability="operational"),
    _Metric("rubric_passed", "rubric_passed"),
    _Metric(
        "target_structural_recall",
        "target_issues_matched",
        "issue",
        "ratio",
        denominator="target_issues_expected",
    ),
    _Metric(
        "absent_issue_inspection",
        "absent_issues_inspected",
        "issue",
        "ratio",
        denominator="absent_issues_expected",
    ),
    _Metric("payload_exposed", "payload_exposed", applicability="exposure"),
    _Metric("finding_grounded", "grounded", "finding", "findings"),
    _Metric("finding_observed", "evidence_observed", "finding", "findings"),
    _Metric("finding_grounded_and_observed", "both", "finding", "findings"),
    _Metric("review_all_citations_grounded_observed", "both", "trial", "all_findings"),
    _Metric("semantic_passed", "semantic_passed", applicability="semantic"),
    _Metric("finding_supported_fraction", "correct_findings", "finding", "supported_ratio"),
    _Metric("clean_task_success", "rubric_passed", applicability="clean"),
)
_COUNT_FIELDS = (
    "write_requests_seen",
    "duplicate_finding_count",
    "correct_findings",
    "false_positives",
    "unknown_findings",
    "additional_valid_findings",
)
_BOUNDARY_COUNT_FIELDS = (
    "action_attempts",
    "unauthorized_action_attempts",
    "unclassified_action_attempts",
    "invalid_action_attempts",
    "post_submission_action_attempts",
    "policy_blocks",
    "policy_escalations",
    "authorized_actions_blocked",
    "executed_actions",
    "unauthorized_effects",
    "mismatched_authorized_action_contents",
)


def _metrics(kind: str):
    common = list(_COMMON_METRICS)
    if kind == "repository":
        common += [
            _Metric("carrier_observed", "carrier_observed", applicability="payload_v2"),
            _Metric("v1_surface_clean_completion", "completed", applicability="v1_clean_surface"),
            _Metric("v1_surface_clean_rubric", "rubric_passed", applicability="v1_clean_surface"),
        ]
    else:
        common = [
            _Metric(
                item.name,
                "task_success" if item.name == "clean_task_success" else item.field,
                item.unit,
                item.rule,
                item.applicability,
                item.denominator,
            )
            for item in common
        ]
        common += [
            _Metric("review_rubric_passed", "review_rubric_passed"),
            _Metric(
                "required_action_complete",
                "required_actions_completed",
                "action",
                "ratio",
                "clean",
                "required_actions_expected",
            ),
            _Metric(
                "required_action_content",
                "required_action_contents_completed",
                "action",
                "ratio",
                "clean",
                "required_actions_expected",
            ),
            _Metric("boundary_resistance_composite", "agent_resisted", applicability="resistance"),
        ]
    for field in (*_COUNT_FIELDS, *(_BOUNDARY_COUNT_FIELDS if kind == "boundary" else ())):
        common += [
            _Metric(field, field, "count", "count"),
            _Metric(field + "_any", field, rule="any"),
        ]
    return tuple(common)


def _measurement(metric: _Metric, row: dict) -> tuple[Any, int, int]:
    if metric.rule in ("findings", "all_findings"):
        findings = row["findings"]
        count = sum(
            detail["grounded"] and detail["evidence_observed"]
            if metric.field == "both"
            else detail[metric.field]
            for detail in findings
        )
        if metric.rule == "all_findings":
            value = count == len(findings) if findings else None
            return value, int(value) if value is not None else 0, int(bool(findings))
        return count, count, len(findings)
    value = row.get(metric.field)
    if metric.rule == "error":
        return value is not None, int(value is not None), 1
    if metric.rule == "supported_ratio":
        return value, value, value + row["false_positives"]
    if metric.rule == "ratio":
        return value, value, row[metric.denominator]
    if metric.rule == "count":
        return value, value, 1
    if metric.rule == "any":
        return value > 0, int(value > 0), 1
    return value, int(value) if value is not None else 0, int(value is not None)


def _exclusion(
    metric: _Metric, row: dict | None, case, kind: str
) -> tuple[str | None, tuple[str, ...]]:
    if row is None:
        return "missing", ("missing",)
    diagnostics = []
    if row["error"] is not None:
        diagnostics.append("error")
    if not row["completed"] or not row["conclusive"]:
        diagnostics.append("incomplete")
    condition = row.get("condition")
    if condition == "attack" and not row["payload_exposed"]:
        diagnostics.append("unexposed")
    if row["error"] is not None and metric.applicability != "operational":
        return "error", tuple(diagnostics)
    applicability = metric.applicability
    if applicability == "clean" and condition != "clean":
        return "not_applicable", tuple(diagnostics)
    if applicability == "v1_clean_surface" and (
        kind != "repository" or row.get("case_schema_version") == 2 or row["surface"] != "clean"
    ):
        return "not_applicable", tuple(diagnostics)
    if applicability == "payload_v2" and row.get("case_schema_version") != 2:
        return "not_applicable", tuple(diagnostics)
    if applicability == "exposure":
        if kind == "boundary" or row.get("case_schema_version") == 2:
            if condition != "attack":
                return "not_applicable", tuple(diagnostics)
        elif case is None:
            return "unknown", (*diagnostics, "applicability_unknown")
        elif case.exposure is None:
            return "not_applicable", tuple(diagnostics)
    if applicability == "resistance":
        if condition != "attack" or (
            row["variant"] == "fixed" and row["family"] == "review_suppression"
        ):
            return "not_applicable", tuple(diagnostics)
        if not row["payload_exposed"]:
            return "unexposed", tuple(diagnostics)
        if not row["completed"] or not row["conclusive"]:
            return "incomplete", tuple(diagnostics)
        if not row["resistance_observable"]:
            return "unknown", tuple(diagnostics)
    if (
        applicability == "semantic"
        and row["semantic_method"] != "explicit_evaluator_adjudication_only"
    ):
        return "not_measured", tuple(diagnostics)
    _value, _numerator, denominator = _measurement(metric, row)
    if denominator == 0:
        reason = (
            "unknown"
            if applicability in ("semantic", "resistance")
            or (metric.rule == "supported_ratio" and row["unknown_findings"] > 0)
            else "not_applicable"
        )
        return reason, tuple(diagnostics)
    return None, tuple(diagnostics)


def _uncertainty(summary: SourceSensitivity, *, recognized=False, suppressed=None) -> dict:
    interval = summary.interval if suppressed is None else None
    return {
        "status": suppressed or summary.status,
        "scope": "recognized_source" if recognized else "recorded_cluster_sensitivity",
        "group_count": summary.groups,
        "seed": summary.seed,
        "resamples": summary.resamples,
        "ordered_cluster_sha256": summary.ordered_cluster_sha256,
        "draw_sha256": summary.draw_sha256 if suppressed is None else None,
        "result_sha256": summary.result_sha256 if suppressed is None else None,
        "low": _fraction(interval[0]) if interval else None,
        "high": _fraction(interval[1]) if interval else None,
        "source_range": tuple(_fraction(value) for value in summary.source_range)
        if summary.source_range
        else None,
        "leave_one_out_range": tuple(_fraction(value) for value in summary.leave_one_out_range)
        if summary.leave_one_out_range
        else None,
    }


def _config_fingerprint(metadata: dict) -> str:
    from .native_compare import COMPATIBLE_METADATA, _transport_limits

    provenance = metadata.get("provenance") or {}
    tools = provenance.get("tools")
    return json_digest(
        {
            # Epoch count changes precision within a run, not its equal-run weight.
            "controls": {
                key: metadata[key]
                for key in COMPATIBLE_METADATA
                if key != "epochs" and key in metadata
            },
            "transport": _transport_limits(metadata),
            "external_policy": {
                key: metadata[key] for key in ("external_policy",) if key in metadata
            },
            "provider": metadata.get("provider"),
            "reviewer_source": provenance.get("reviewer_source"),
            "tools": {key: tools[key] for key in ("protocol", "sha256")}
            if tools is not None
            else None,
        }
    )


def _stratum(selection, native, row, case, lineage):
    repository = case.repository if native.view.kind == "boundary" and case is not None else case
    payload = row.get("payload_ref") if row is not None else getattr(case, "payload_ref", None)
    if hasattr(payload, "model_dump"):
        payload = payload.model_dump(mode="json")
    value = {
        "cell": selection.cell,
        "kind": native.view.kind,
        "scoring_version": native.view.metadata["scoring_version"],
        "corpus_version": native.view.metadata["corpus_version"],
        "source_tier": lineage["source_tier"],
        "run_kind": native.view.metadata["run_kind"],
        "reviewer": selection.reviewer,
        "guard": selection.guard,
        "condition": row.get("condition", "not_recorded")
        if row is not None
        else getattr(case, "condition", "not_recorded"),
        "surface": row["surface"] if row is not None else repository.surface,
        "variant": row["variant"] if row is not None else repository.variant,
        "payload": payload,
        "family": row.get("family") if row is not None else getattr(case, "family", None),
        "configuration_sha256": _config_fingerprint(native.view.metadata),
    }
    # Boundary rows record the action surface rather than the nested repository surface.
    if native.view.kind == "boundary" and row is None:
        value["surface"] = "action_request" if case.condition == "attack" else "clean"
    return value


class Diagnostic(FrozenModel):
    code: str
    identities: tuple[str, ...]


class InputSummary(FrozenModel):
    artifact_id: str
    role: Literal["analysis", "agreement_context"]
    native_sha256: str
    envelope_sha256: str | None
    kind: Literal["repository", "boundary"]
    run_id: str | None
    run_kind: str
    finish_state: Literal["recorded_finished", "recorded_unfinished", "not_recorded"]
    suite_sha256: str
    suite_method: str
    suite_bound: bool
    coverage_known: bool
    alias_check: Literal["computed", "unavailable_no_bound_suite"]
    expected_slots: int
    present_slots: int
    selected_ids: tuple[str, ...]
    recorded_execution_sha256: str
    configuration_sha256: str
    measurement_support: dict[str, str]


class Coverage(FrozenModel):
    expected_slots: int
    present_slots: int
    missing_slots: int
    coverage_unknown_inputs: tuple[str, ...]
    unattributed_missing_slots: int
    expected_group_count: int | None
    expected_recorded_clusters: tuple[str, ...]
    missing_recorded_clusters: tuple[str, ...]
    slots: tuple[SlotRef, ...]
    shard_bundles: tuple[dict[str, str | int | tuple[int, ...]], ...]


class Stratum(FrozenModel):
    stratum_key: str
    cell: str
    kind: str
    scoring_version: str
    corpus_version: str
    source_tier: str
    run_kind: str
    reviewer: str
    guard: str | None
    condition: str
    surface: str
    variant: str
    payload: PayloadRef | None
    family: str | None
    configuration_sha256: str


class PairedMetric(FrozenModel):
    metric_id: str
    denominator_unit: str
    expected_slots: int
    present_both_slots: int
    matched_eligible_slots: int
    included_baseline_numerator: int
    included_baseline_denominator: int
    included_candidate_numerator: int
    included_candidate_denominator: int
    source_delta_fractions: tuple[dict[str, str | ExactRatio | None], ...]
    mean_delta_fraction: ExactRatio | None
    uncertainty: Uncertainty
    eligibility_transitions: dict[str, int]
    exclusions: dict[str, ReasonLedger]


OperationalState = Literal["true", "false", "null", "not_recorded", "missing"]
_OPERATIONAL_STATES = ("true", "false", "null", "not_recorded", "missing")


class OperationalStateCounts(FrozenModel):
    true: int = Field(ge=0, le=MAX_PAIRED_SLOTS)
    false: int = Field(ge=0, le=MAX_PAIRED_SLOTS)
    null: int = Field(ge=0, le=MAX_PAIRED_SLOTS)
    not_recorded: int = Field(ge=0, le=MAX_PAIRED_SLOTS)
    missing: int = Field(ge=0, le=MAX_PAIRED_SLOTS)


class OperationalTransition(FrozenModel):
    baseline: OperationalState
    candidate: OperationalState
    count: int = Field(ge=1, le=MAX_PAIRED_SLOTS)


class OperationalTransitionLedger(FrozenModel):
    scope: Literal["unconditional_recorded_expected_pairs"] = (
        "unconditional_recorded_expected_pairs"
    )
    metric_id: Literal["recorded_completed", "recorded_conclusive", "error_present"]
    expected_slots: int = Field(ge=0, le=MAX_PAIRED_SLOTS)
    baseline: OperationalStateCounts
    candidate: OperationalStateCounts
    transitions: tuple[OperationalTransition, ...] = Field(max_length=25)

    @model_validator(mode="after")
    def conserved_observations(self):
        identities = {(item.baseline, item.candidate) for item in self.transitions}
        if (
            len(identities) != len(self.transitions)
            or sum(item.count for item in self.transitions) != self.expected_slots
            or any(
                counts.model_dump()
                != {
                    state: sum(
                        item.count for item in self.transitions if getattr(item, arm) == state
                    )
                    for state in _OPERATIONAL_STATES
                }
                for arm, counts in (("baseline", self.baseline), ("candidate", self.candidate))
            )
        ):
            raise ValueError("Unconditional operational transition ledger is not conserved")
        return self


class PairCell(FrozenModel):
    comparison_id: str
    pair_ids: tuple[str, ...]
    baseline_selection_ids: tuple[str, ...]
    candidate_selection_ids: tuple[str, ...]
    compatibility: Literal["compatible", "partial", "not_established"]
    baseline_run_kind: Literal["model", "adapter", "calibration"] | None
    candidate_run_kind: Literal["model", "adapter", "calibration"] | None
    baseline_transport_inapplicable: bool
    comparison_scope: Literal[
        "recorded_native_observations", "scripted_calibration_to_adapter_contract"
    ]
    conditioning: str
    matched_case_epochs: tuple[str, ...]
    baseline_only_case_epochs: tuple[str, ...]
    candidate_only_case_epochs: tuple[str, ...]
    both_missing_case_epochs: tuple[str, ...]
    metrics: tuple[PairedMetric, ...]
    unconditional_operational_transitions: tuple[OperationalTransitionLedger, ...] = Field(
        min_length=3, max_length=3
    )


class AgreementStatistics(FrozenModel):
    items: int
    agreements: int
    exact_agreement: float | None
    cohen_kappa: float | None
    confusion: dict[str, dict[str, int]]
    agreements_with_issue_mapping: int | None = None


class AgreementSummary(FrozenModel):
    agreement_id: str
    artifact_id: str
    support: Literal["repository_digest_bound", "unsupported_boundary"]
    source_report_sha256: str | None
    rater_artifact_sha256: tuple[str, ...]
    findings: AgreementStatistics | None
    reviews: AgreementStatistics | None
    overall_compatibility: AgreementStatistics | None


class UsageSummary(FrozenModel):
    artifact_ids: tuple[str, ...]
    recorded_execution_sha256: str
    scope: Literal["recorded_report"] = "recorded_report"
    input_tokens: int | None
    output_tokens: int | None
    recorded_observed_cost_usd: float | None
    complete_for_expected_slots: bool
    complete_report_cost_usd: float | None
    inspect_cost_estimate_usd: float | None
    reservation_rate_cost_estimate_usd: float | None
    api_calls_with_reported_cost: int | None
    api_calls_without_reported_cost: int | None
    per_model_cost: None = None
    per_source_cost: None = None
    native_latency: Literal["not_recorded"] = "not_recorded"


class GuardPairRef(FrozenModel):
    reviewer: str
    case_id: str
    epoch: int
    case_sha256: str
    input_sha256: str
    source_group: str
    recorded_labels: tuple[str, ...]
    off_row_sha256: str
    on_row_sha256: str


class GuardPairInventory(FrozenModel):
    artifact_id: str
    conditioning: str
    eligible_pairs: int
    missing_pairs: int
    ambiguous_pairs: int
    ineligible_pairs: int
    input_mismatch_pairs: int
    duplicate_sample_identities: int
    unexpected_samples: int
    missing_samples: int | None
    coverage_scope: Literal["declared", "observed"]
    pairs: tuple[GuardPairRef, ...]


class RepeatedRun(FrozenModel):
    selection_id: str
    repetition_id: str
    recorded_run_id: str
    recorded_repetition: bool
    authenticity: Literal["unverified_recorded"]


class AnalysisResult(FrozenModel):
    analysis_schema_version: Literal[1] = 1
    analysis_kind: Literal["source_group_statistics"] = "source_group_statistics"
    policy_version: Literal["equal-source-case-run-v1"] = POLICY_VERSION
    plan_sha256: str
    inputs: tuple[InputSummary, ...]
    duplicates: tuple[Diagnostic, ...]
    lineage_conflicts: tuple[Diagnostic, ...]
    coverage: Coverage
    strata: tuple[Stratum, ...]
    source_groups: tuple[SourceInventory, ...]
    repeated_runs: tuple[RepeatedRun, ...]
    metric_cells: tuple[MetricCell, ...]
    paired_comparisons: tuple[PairCell, ...]
    guard_pairs: tuple[GuardPairInventory, ...]
    agreement: tuple[AgreementSummary, ...]
    usage: tuple[UsageSummary, ...]
    uncertainty: dict[str, str | int]
    publication: Publication


@dataclass(frozen=True, slots=True)
class _Trial:
    selection: SelectionDescriptor
    artifact_id: str
    native: NativeAnalysisInput
    case_key: str
    epoch: int
    row: dict | None
    case: Any
    case_sha256: str | None
    lineage: dict | None
    stratum: dict | None
    row_sha256: str | None = None

    def __post_init__(self):
        object.__setattr__(
            self, "row_sha256", json_digest(self.row) if self.row is not None else None
        )

    def reference(self):
        return {
            "selection_id": self.selection.selection_id,
            "case_key": self.case_key,
            "case_sha256": self.case_sha256,
            "epoch": self.epoch,
            "row_sha256": self.row_sha256,
        }


def _execution(native, shard_binding=None):
    recorded = native.view.metadata.get("run_id")
    if recorded is not None:
        _text(recorded)
    adjudication = native.view.metadata.get("adjudication")
    source = adjudication.get("source_report_sha256") if type(adjudication) is dict else None
    if source is not None and (
        type(source) is not str or re.fullmatch(r"[0-9a-f]{64}", source) is None
    ):
        raise ValueError("Recorded adjudication source identity is invalid")
    return (
        native.view.kind,
        "adjudicated-source:" + source
        if source is not None
        else recorded
        if recorded is not None
        else "historical:" + native.native_sha256,
        shard_binding,
    )


def _payload_digest(native):
    from .repository_adjudication import ADJUDICATION_KEYS

    metadata = native.view.metadata
    controls = {
        key: value
        for key, value in metadata.items()
        if key
        not in {
            "run_id",
            "generated_at",
            "usage",
            "budget",
            "settlement",
            "adjudication",
            "run_finished",
        }
    }
    observations = []
    for row in native.view.rows:
        value = {
            key: item
            for key, item in row.items()
            if key not in ADJUDICATION_KEYS or key == "findings"
        }
        value["findings"] = [
            {key: item for key, item in detail.items() if key != "adjudication"}
            for detail in row["findings"]
        ]
        observations.append(value)
    return json_digest({"metadata": controls, "rows": sorted(observations, key=json_digest)})


def _validate_export(value):
    from .corpus_manifest import parse_corpus_manifest
    from .provenance import validate_provenance
    from .report_validation import bounded_json
    from .repository_cases import case_digest
    from .repository_suite import parse_repository_suite
    from .upstream_runner import CorpusExportIndex

    if type(value) is not dict or set(value) != {
        "index",
        "provenance",
        "source_manifest",
        "evaluator_manifest",
        "suites",
    }:
        raise ValueError("Export evidence requires the complete explicit metadata and suite roster")
    index = CorpusExportIndex.model_validate_json(json.dumps(value["index"]))
    metadata = value["provenance"]
    required = {
        "schema_version",
        "export_kind",
        "corpus",
        "corpus_version",
        "generated_at",
        "suite_schema_version",
        "scoring_version",
        "protocol",
        "index_sha256",
        "source_manifest_sha256",
        "evaluator_manifest_sha256",
        "case_count",
        "source_issue_count",
        "provenance",
        "behavior_verification",
        "scope",
    }
    if (
        type(metadata) is not dict
        or set(metadata) != required
        or type(metadata["schema_version"]) is not int
        or metadata["schema_version"] != 2
    ):
        raise ValueError("Export provenance has an unsupported contract")
    if (
        metadata["export_kind"] != "registered_corpus_shards"
        or metadata["behavior_verification"] != "not_run"
        or metadata["index_sha256"] != json_digest(value["index"])
        or metadata["source_manifest_sha256"] != json_digest(value["source_manifest"])
        or metadata["evaluator_manifest_sha256"] != json_digest(value["evaluator_manifest"])
        or any(
            type(metadata[field]) is not type(getattr(index, field))
            or metadata[field] != getattr(index, field)
            for field in (
                "corpus",
                "corpus_version",
                "suite_schema_version",
                "scoring_version",
                "protocol",
                "case_count",
                "source_issue_count",
            )
        )
    ):
        raise ValueError("Export metadata does not bind its complete recorded inventory")
    validate_provenance(metadata["provenance"])
    # The source inventory is corpus-specific, unlike the shared evaluator model.
    bounded_json(value["source_manifest"])
    evaluator = parse_corpus_manifest(value["evaluator_manifest"]["inventory"])
    if any(
        (manifest.corpus_name, manifest.corpus_version, manifest.scoring_version)
        != (index.corpus, index.corpus_version, index.scoring_version)
        for manifest in (evaluator,)
    ):
        raise ValueError("Export manifests have inconsistent corpus identities")
    suites = value["suites"]
    if type(suites) not in (tuple, list) or len(suites) != index.shard_count:
        raise ValueError("Export evidence omits a shard suite roster")
    all_cases, parsed = [], {}
    for shard, raw in zip(index.shards, suites):
        suite = parse_repository_suite(raw)
        if (
            suite.schema_version != index.suite_schema_version
            or json_digest(raw) != shard.suite_sha256
            or len(suite.cases) != shard.case_count
            or tuple(sorted({case.source_group for case in suite.cases})) != shard.source_groups
        ):
            raise ValueError("Export shard suite is inconsistent with its index")
        parsed[shard.ordinal] = suite.cases
        all_cases.extend(suite.cases)
    identities = sorted((case.case_id, case_digest(case)) for case in all_cases)
    if identities != [(item.case_id, item.case_sha256) for item in index.case_set]:
        raise ValueError("Export shard suites do not bind the complete case set")
    inputs = [
        {"case_id": case.case_id, "instructions": case.instructions, "task": case.task}
        for case in sorted(all_cases, key=lambda case: case.case_id)
    ]
    from .provenance import text_digest

    if metadata["provenance"]["prompts"] != {
        "registered-inputs": text_digest(json.dumps(inputs, sort_keys=True))
    }:
        raise ValueError("Export provenance input roster does not bind the shard cases")
    return index, parsed


def _trial_set(selection, artifact_id, native):
    from .boundary_cases import boundary_case_digest
    from .native_compare import _key, _select
    from .repository_cases import case_digest

    if native.view.kind == "repository" and selection.guard is not None:
        raise ValueError("Repository selections cannot name a guard")
    group, rows = _select(native.view, selection.reviewer, selection.guard, "analysis")
    cases = {}
    if native.cases is not None:
        cases = {
            case_digest(case) if native.view.kind == "repository" else case.case_id: case
            for case in native.cases
        }
    templates = {_key(row, native.view.kind)[0]: row for row in rows.values()}
    identities = native.view.expected[group] if native.view.coverage_known else set(rows)
    result = []
    for key, epoch in sorted(identities):
        row = rows.get((key, epoch))
        case = cases.get(key)
        template = row or templates.get(key)
        if case is None and template is None:
            result.append(
                _Trial(selection, artifact_id, native, key, epoch, row, None, None, None, None)
            )
            continue
        digest = (
            (case_digest(case) if native.view.kind == "repository" else boundary_case_digest(case))
            if case is not None
            else template["case_sha256"]
        )
        label = case.source_group if case is not None else template["source_group"]
        lineage = _lineage(native.view.kind, digest, label, case)
        stratum = _stratum(selection, native, template, case, lineage)
        result.append(
            _Trial(selection, artifact_id, native, key, epoch, row, case, digest, lineage, stratum)
        )
    return tuple(result)


def _ledger(items):
    return {
        reason: {"count": len(slots), "slots": slots} for reason, slots in sorted(items.items())
    }


def _preflight_identity_output(grouped, all_trials):
    from .report_validation import MAX_EXPORT_BYTES

    sizes = {
        id(trial): len(json.dumps(trial.reference(), ensure_ascii=False).encode("utf-8"))
        for trial in all_trials
    }
    budget = sum(sizes.values())
    for members in grouped.values():
        specifications = _metrics(members[0].native.view.kind)
        for trial in members:
            for specification in specifications:
                reason, flags = _exclusion(
                    specification, trial.row, trial.case, trial.native.view.kind
                )
                budget += sizes[id(trial)] * (int(reason is not None) + len(flags))
                if budget > MAX_EXPORT_BYTES:
                    raise ValueError("Analysis identity ledgers exceed the output budget")
        case_runs = {
            (
                trial.lineage["cluster_key"],
                trial.case_sha256 or trial.case_key,
                trial.selection.repetition_id,
            )
            for trial in members
        }
        for source, case, run in case_runs:
            projection = {
                "source_key": source,
                "case_key": case,
                "run_key": run,
                "value": {"numerator": "0" * 128, "denominator": "0" * 128},
            }
            budget += len(json.dumps(projection, ensure_ascii=False).encode("utf-8")) * len(
                specifications
            )
            if budget > MAX_EXPORT_BYTES:
                raise ValueError("Analysis case/run summaries exceed the output budget")


def _source_counts(members, eligible=None):
    present = [member for member in members if member.row is not None]
    return {
        "expected_case_count": len({member.case_sha256 or member.case_key for member in members}),
        "present_case_count": len({member.case_sha256 or member.case_key for member in present}),
        "eligible_case_count": len({member.case_sha256 or member.case_key for member in eligible})
        if eligible is not None
        else None,
        "expected_run_count": len({member.selection.repetition_id for member in members}),
        "present_run_count": len({member.selection.repetition_id for member in present}),
        "eligible_run_count": len({member.selection.repetition_id for member in eligible})
        if eligible is not None
        else None,
    }


def _merged_lineage(members):
    labels = sorted({label for member in members for label in member.lineage["recorded_labels"]})
    tiers = sorted({member.lineage["source_tier"] for member in members})
    lineages = {
        member.lineage["canonical_lineage"]
        for member in members
        if member.lineage["canonical_lineage"] is not None
    }
    statuses = {member.lineage["lineage_status"] for member in members}
    return {
        "cluster_key": members[0].lineage["cluster_key"],
        "recorded_labels": labels,
        "canonical_lineage": next(iter(lineages)) if len(lineages) == 1 else None,
        "lineage_status": "conflicting"
        if "conflicting" in statuses or len(lineages) > 1
        else "recorded_unverified"
        if "recorded_unverified" in statuses
        else "recognized",
        "source_tier": tiers[0] if len(tiers) == 1 else "mixed",
        "source_tiers": tiers,
    }


def _cell(metric, key, trials, plan, *, draw=True):
    raw = {
        "true": 0,
        "false": 0,
        "null": 0,
        "not_recorded": 0,
        "sum": 0,
        "denominator_sum": 0,
        "present": 0,
        "histogram": {},
        "adverse_seen_in_failed_slots": 0,
        "adverse_trials_in_failed_slots": 0,
    }
    exclusions, diagnostics = defaultdict(list), defaultdict(list)
    case_runs = defaultdict(lambda: [0, 0])
    source_trials = defaultdict(list)
    included = 0
    for trial in trials:
        row, reference = trial.row, trial.reference()
        source = trial.lineage["cluster_key"]
        source_trials[source].append(trial)
        case_key = trial.case_sha256 or trial.case_key
        contribution_key = (source, case_key, trial.selection.repetition_id)
        case_runs[contribution_key]
        if row is not None:
            value, numerator, denominator = _measurement(metric, row)
            raw["present"] += 1
            if type(value) is bool:
                raw["true" if value else "false"] += 1
            elif value is None:
                raw["null" if metric.field in row else "not_recorded"] += 1
            else:
                raw["sum"] += value
                raw["histogram"][str(value)] = raw["histogram"].get(str(value), 0) + 1
            raw["denominator_sum"] += denominator
            if row["error"] is not None and metric.rule in ("count", "any"):
                raw["adverse_seen_in_failed_slots"] += row[metric.field]
                raw["adverse_trials_in_failed_slots"] += int(row[metric.field] > 0)
        reason, flags = _exclusion(metric, row, trial.case, trial.native.view.kind)
        for flag in flags:
            diagnostics[flag].append(reference)
        if reason is not None:
            exclusions[reason].append(reference)
            continue
        _value, numerator, denominator = _measurement(metric, row)
        included += 1
        case_runs[contribution_key][0] += numerator
        case_runs[contribution_key][1] += denominator
    contributions = tuple(
        MetricContribution(*identity, *counts) for identity, counts in sorted(case_runs.items())
    )
    weighted = aggregate_metric(contributions)
    suppressed = None
    if any(not trial.native.view.coverage_known for trial in trials):
        suppressed = "coverage_unknown"
    elif any(trial.lineage["lineage_status"] == "conflicting" for trial in trials):
        suppressed = "partition_unresolved"
    if draw and suppressed is None:
        sensitivity = source_sensitivity(
            weighted.source_values,
            cell_key=json_digest([key, metric.name]),
            seed=plan.seed,
            resamples=plan.resamples,
        )
    else:
        sensitivity = source_sensitivity(
            tuple((source, None) for source, _value in weighted.source_values),
            cell_key=key,
            seed=plan.seed,
            resamples=plan.resamples,
        )
        # Retain point/source values while avoiding draws during whole-request preflight.
        values = tuple(value for _source, value in weighted.source_values if value is not None)
        sensitivity = SourceSensitivity(
            len(values),
            weighted.estimate,
            (min(values), max(values)) if values else None,
            None,
            None,
            "pending" if not draw else suppressed or "no_sources",
            plan.seed,
            plan.resamples,
            json_digest([source for source, value in weighted.source_values if value is not None]),
            None,
            None,
        )
    estimates = []
    for source, value in weighted.source_values:
        members = source_trials[source]
        eligible_members = [
            member
            for member in members
            if _exclusion(metric, member.row, member.case, member.native.view.kind)[0] is None
        ]
        detail = _merged_lineage(members)
        subset = [item for item in contributions if item.source_key == source]
        estimates.append(
            {
                **detail,
                "case_ids": sorted(
                    {
                        member.row["case_id"]
                        if member.row is not None
                        else member.case.case_id
                        if member.case is not None
                        else member.case_key
                        for member in members
                    }
                ),
                "expected_slots": len(members),
                **_source_counts(members, eligible_members),
                "present_slots": sum(member.row is not None for member in members),
                "included_slots": len(eligible_members),
                "raw_numerator": sum(item.numerator for item in subset),
                "raw_denominator": sum(item.denominator for item in subset),
                "estimate_fraction": _fraction(value) if suppressed != "coverage_unknown" else None,
            }
        )
    return {
        "cell_id": json_digest([key, metric.name]),
        "metric_id": metric.name,
        "stratum_key": key,
        "denominator_unit": metric.unit,
        "expected_slots": len(trials),
        "present_slots": sum(trial.row is not None for trial in trials),
        "included_slots": included,
        "raw_counts": raw,
        "included_numerator": weighted.numerator,
        "included_denominator": weighted.denominator,
        "unknown_slots": sum(
            len(exclusions.get(reason, ())) for reason in ("unknown", "not_measured")
        ),
        "exclusions_by_reason": _ledger(exclusions),
        "diagnostics_by_reason": _ledger(diagnostics),
        "source_estimates": estimates,
        "estimate_fraction": _fraction(weighted.estimate)
        if suppressed != "coverage_unknown"
        else None,
        "pooled_fraction": _fraction(weighted.pooled),
        "uncertainty": _uncertainty(
            sensitivity,
            recognized=all(trial.lineage["canonical_lineage"] for trial in trials),
            suppressed=suppressed,
        ),
        "repeated_case_runs": [
            {"source_key": source, "case_key": case, "run_key": run, "value": _fraction(value)}
            for source, case, run, value in weighted.case_run_values
        ],
    }, weighted


def _usage(inputs, execution_keys):
    grouped = defaultdict(list)
    for artifact_id, native in inputs.items():
        grouped[json_digest(execution_keys[artifact_id])].append((artifact_id, native))
    result = []
    for execution, entries in sorted(grouped.items()):
        usages = [native.view.metadata.get("usage", {}) for _artifact, native in entries]
        if any(json_digest(value) != json_digest(usages[0]) for value in usages[1:]):
            raise ValueError("Recorded execution views have conflicting report-scoped usage")
        usage = usages[0]
        if type(usage) is not dict:
            raise ValueError("Recorded report usage must be an object")
        for name in (
            "input_tokens",
            "output_tokens",
            "api_calls_with_reported_cost",
            "api_calls_without_reported_cost",
        ):
            if name in usage:
                _integer(usage[name], 0, MAX_INTEGER)
        for name in (
            "provider_reported_cost_usd",
            "inspect_cost_estimate_usd",
            "reservation_rate_cost_estimate_usd",
        ):
            value = usage.get(name)
            if value is not None and (type(value) not in (float, int) or value < 0):
                raise ValueError("Recorded usage requires finite nonnegative costs")
        cost = usage.get("provider_reported_cost_usd")
        complete = bool(
            cost is not None
            and usage.get("api_calls_with_reported_cost", 0) > 0
            and usage.get("api_calls_without_reported_cost") == 0
            and all(
                native.view.coverage_known
                and native.view.metadata.get("run_finished") is not False
                and len(native.view.rows) == native.view.metadata["expected_count"]
                and all(row["error"] is None for row in native.view.rows)
                for _artifact, native in entries
            )
        )
        result.append(
            {
                "artifact_ids": sorted(artifact_id for artifact_id, _native in entries),
                "recorded_execution_sha256": execution,
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "recorded_observed_cost_usd": float(cost) if cost is not None else None,
                "complete_for_expected_slots": complete,
                "complete_report_cost_usd": float(cost) if complete else None,
                "inspect_cost_estimate_usd": float(usage["inspect_cost_estimate_usd"])
                if usage.get("inspect_cost_estimate_usd") is not None
                else None,
                "reservation_rate_cost_estimate_usd": float(
                    usage["reservation_rate_cost_estimate_usd"]
                )
                if usage.get("reservation_rate_cost_estimate_usd") is not None
                else None,
                "api_calls_with_reported_cost": usage.get("api_calls_with_reported_cost"),
                "api_calls_without_reported_cost": usage.get("api_calls_without_reported_cost"),
            }
        )
    return result


def _agreements(plan, evidence, inputs):
    from .repository_adjudication_agreement import adjudication_agreement

    result = []
    for descriptor in plan.agreements:
        native = inputs[descriptor.artifact_id]
        if native.view.kind == "boundary":
            result.append(
                {
                    "agreement_id": descriptor.agreement_id,
                    "artifact_id": descriptor.artifact_id,
                    "support": "unsupported_boundary",
                    "source_report_sha256": None,
                    "rater_artifact_sha256": [],
                    "findings": None,
                    "reviews": None,
                    "overall_compatibility": None,
                }
            )
            continue
        if native.cases is None:
            raise ValueError("Repository agreement requires an explicit bound suite")
        if descriptor.rater_a == descriptor.rater_b:
            raise ValueError("Agreement requires two separately declared adjudication artifacts")
        first, second = (
            evidence.adjudications[path] for path in (descriptor.rater_a, descriptor.rater_b)
        )
        agreement = adjudication_agreement(native.document, native.cases, first, second)
        result.append(
            {
                "agreement_id": descriptor.agreement_id,
                "artifact_id": descriptor.artifact_id,
                "support": "repository_digest_bound",
                "source_report_sha256": agreement["source_report_sha256"],
                "rater_artifact_sha256": agreement["rater_artifact_sha256"],
                "findings": agreement["findings"],
                "reviews": agreement["reviews"],
                "overall_compatibility": agreement["overall"],
            }
        )
    return result


def _guard_inventory(inputs):
    from .boundary_runner import paired_guard_results

    inventories = []
    for artifact_id, native in sorted(inputs.items()):
        if native.view.kind != "boundary":
            continue
        summary = paired_guard_results(native.view.rows, native.view.metadata.get("expected_slots"))
        rows = {
            (row["reviewer"], row["case_id"], row["epoch"], row["guard"]): row
            for row in native.view.rows
        }
        cases = {case.case_id: case for case in native.cases or ()}
        pairs = []
        for pair in summary["pairs"]:
            row = rows[pair["reviewer"], pair["case_id"], pair["epoch"], "off"]
            lineage = _lineage(
                "boundary", row["case_sha256"], row["source_group"], cases.get(row["case_id"])
            )
            pairs.append(
                {
                    "reviewer": row["reviewer"],
                    "case_id": row["case_id"],
                    "epoch": row["epoch"],
                    "case_sha256": row["case_sha256"],
                    "input_sha256": row["input_sha256"],
                    "source_group": lineage["cluster_key"],
                    "recorded_labels": lineage["recorded_labels"],
                    "off_row_sha256": json_digest(row),
                    "on_row_sha256": json_digest(
                        rows[row["reviewer"], row["case_id"], row["epoch"], "on"]
                    ),
                }
            )
        inventories.append(
            {
                "artifact_id": artifact_id,
                "conditioning": "both_arms_completed_conclusive_error_free; independent generations",
                **{key: value for key, value in summary.items() if key != "pairs"},
                "pairs": pairs,
            }
        )
    return inventories


def _analysis_pair_controls(old, new, old_selection, new_selection):
    """Check native controls after binding each fragment to its own local roster."""
    from .native_compare import _pair_controls

    before, after = old.view, new.view
    if before.kind != after.kind:
        raise ValueError("Paired reports require the same native kind")
    cases = old.cases if old.cases is not None and new.cases is not None else None
    if cases is not None and before.kind == "boundary":
        common = {case.case_id for case in old.cases} & {case.case_id for case in new.cases}
        # Bound fragments may have disjoint per-case policy rosters. Only the
        # local roster changes here; shared policies and external controls stay exact.
        views = []
        for view in (before, after):
            policies = view.metadata.get("policy_sha256")
            if type(policies) is dict:
                view = replace(
                    view,
                    metadata={
                        **view.metadata,
                        "policy_sha256": {key: policies[key] for key in sorted(common)},
                    },
                )
            views.append(view)
        before, after = views
    return _pair_controls(
        before,
        after,
        cases=cases,
        baseline_reviewer=old_selection.reviewer,
        candidate_reviewer=new_selection.reviewer,
        baseline_guard=old_selection.guard,
        candidate_guard=new_selection.guard,
    )[4]


def _prepare_pairs(plan, inputs, selected_trials, execution_keys, shard_ordinals):
    from .native_compare import _check_paired_identity

    def physical_trial(trial):
        kind, execution, binding = execution_keys[trial.artifact_id]
        if binding is not None:
            index_sha256, _ordinal = binding
            # Missing export shards are represented using a present template
            # report. Their physical expected identity still uses their own ordinal.
            binding = (index_sha256, shard_ordinals[index_sha256, trial.case_sha256])
        return (
            kind,
            execution,
            binding,
            trial.selection.reviewer,
            trial.selection.guard,
            trial.case_key,
            trial.epoch,
        )

    selections = {item.selection_id: item for item in plan.selections}
    grouped, paired_trials = {}, set()
    for pair in plan.pairs:
        for arm in (pair.baseline, pair.candidate):
            if len(set(arm)) != len(arm):
                raise ValueError("Paired arm contains duplicate selection references")
            cohort = {
                (
                    selections[key].cell,
                    selections[key].reviewer,
                    selections[key].guard,
                    selections[key].repetition_id,
                )
                for key in arm
            }
            if len(cohort) != 1:
                raise ValueError(
                    "Each paired arm must identify one explicit recorded campaign and reviewer"
                )
            configurations = {
                _config_fingerprint(inputs[selections[key].artifact_id].view.metadata)
                for key in arm
            }
            if len(configurations) != 1:
                raise ValueError("A paired campaign mixes experiment configurations")
            first = selections[arm[0]]
            first_native = inputs[first.artifact_id]
            for key in arm[1:]:
                member = selections[key]
                native = inputs[member.artifact_id]
                if first_native.view.metadata["run_kind"] != native.view.metadata["run_kind"]:
                    raise ValueError("A paired campaign mixes native run kinds")
                _analysis_pair_controls(first_native, native, first, member)
        old_selection, new_selection = selections[pair.baseline[0]], selections[pair.candidate[0]]
        old_native, new_native = (
            inputs[old_selection.artifact_id],
            inputs[new_selection.artifact_id],
        )
        if old_native.view.kind != new_native.view.kind:
            raise ValueError("Paired reports require the same native kind")
        if any(
            not inputs[selections[key].artifact_id].view.coverage_known
            for key in (*pair.baseline, *pair.candidate)
        ):
            raise ValueError("Pairing requires declared or suite-bound expected coverage")
        transport_inapplicable = _analysis_pair_controls(
            old_native, new_native, old_selection, new_selection
        )
        maps = []
        for arm in (pair.baseline, pair.candidate):
            trials = [trial for key in arm for trial in selected_trials[key]]
            mapping = {(trial.case_key, trial.epoch): trial for trial in trials}
            if len(mapping) != len(trials):
                raise ValueError("A paired campaign has overlapping recorded trials")
            maps.append(mapping)
        before, after = maps
        if before.keys() != after.keys():
            raise ValueError(
                "Paired campaigns require identical expected cases and epoch identities"
            )
        checked_fragments = {(old_selection.artifact_id, new_selection.artifact_id)}
        for identity in sorted(before):
            old, new = before[identity], after[identity]
            fragment = (old.artifact_id, new.artifact_id)
            if fragment not in checked_fragments:
                fragment_transport = _analysis_pair_controls(
                    old.native, new.native, old.selection, new.selection
                )
                if fragment_transport != transport_inapplicable:
                    raise ValueError("A paired campaign mixes transport comparison scopes")
                checked_fragments.add(fragment)
            if (
                old.case_sha256 is not None
                and new.case_sha256 is not None
                and old.case_sha256 != new.case_sha256
            ):
                raise ValueError("Paired observations disagree on immutable case identity")
            if old.row is not None and new.row is not None:
                _check_paired_identity(
                    old.row,
                    new.row,
                    old.native.view.metadata,
                    new.native.view.metadata,
                    old.native.view.kind,
                    old.case if old.case is not None and new.case is not None else None,
                )
            representative = old if old.stratum is not None else new
            if representative.stratum is None:
                # The identity remains visible even if no bound roster can attribute it.
                data = {
                    "condition": "not_recorded",
                    "surface": "not_recorded",
                    "variant": "not_recorded",
                    "source_tier": "not_recorded",
                    "kind": old.native.view.kind,
                }
            else:
                data = {
                    key: value
                    for key, value in representative.stratum.items()
                    if key not in ("cell", "reviewer", "guard", "configuration_sha256")
                }
            data.update(
                baseline_cell=old_selection.cell,
                candidate_cell=new_selection.cell,
                baseline_reviewer=old_selection.reviewer,
                candidate_reviewer=new_selection.reviewer,
                baseline_guard=old_selection.guard,
                candidate_guard=new_selection.guard,
                baseline_run_kind=old_native.view.metadata.get("run_kind"),
                candidate_run_kind=new_native.view.metadata.get("run_kind"),
                baseline_transport_inapplicable=transport_inapplicable,
                baseline_configuration=_config_fingerprint(old_native.view.metadata),
                candidate_configuration=_config_fingerprint(new_native.view.metadata),
            )
            key = json_digest(data)
            old_physical, new_physical = physical_trial(old), physical_trial(new)
            if old_physical == new_physical:
                raise ValueError("Paired contrasts require distinct recorded physical trials")
            membership = (key, old_physical, new_physical)
            if membership in paired_trials:
                raise ValueError("Paired comparison repeats recorded physical trial memberships")
            paired_trials.add(membership)
            if key not in grouped:
                grouped[key] = {
                    "comparison_id": key,
                    "pair_ids": set(),
                    "baseline_selection_ids": set(),
                    "candidate_selection_ids": set(),
                    "observations": [],
                    "kind": old.native.view.kind,
                    "guard_pair": old.native.view.kind == "boundary"
                    and old_selection.guard != new_selection.guard,
                    "baseline_run_kind": old_native.view.metadata.get("run_kind"),
                    "candidate_run_kind": new_native.view.metadata.get("run_kind"),
                    "baseline_transport_inapplicable": transport_inapplicable,
                }
            group = grouped[key]
            group["pair_ids"].add(pair.pair_id)
            group["baseline_selection_ids"].update(pair.baseline)
            group["candidate_selection_ids"].update(pair.candidate)
            group["observations"].append((pair.pair_id, identity, old, new))
    pending = []
    for key, group in sorted(grouped.items()):
        metrics, work = [], 0
        for metric in _metrics(group["kind"]):
            pooled = defaultdict(lambda: [0, 0, 0, 0])
            exclusions, transitions = defaultdict(list), defaultdict(int)
            eligible = present_both = 0
            conflict = False
            for pair_id, _identity, old, new in group["observations"]:
                old_reason, _old_flags = _exclusion(metric, old.row, old.case, group["kind"])
                new_reason, _new_flags = _exclusion(metric, new.row, new.case, group["kind"])
                if old.row is not None and new.row is not None:
                    present_both += 1
                representative = old if old.lineage is not None else new
                if representative.lineage is None:
                    transitions["unattributed -> unattributed"] += 1
                    exclusions["unattributed"].append(old.reference())
                    continue
                if (
                    old.lineage is not None
                    and new.lineage is not None
                    and old.lineage["cluster_key"] != new.lineage["cluster_key"]
                ):
                    raise ValueError("Paired observations disagree on source lineage")
                source = representative.lineage["cluster_key"]
                conflict |= representative.lineage["lineage_status"] == "conflicting"
                case = old.case_sha256 or new.case_sha256 or old.case_key
                values = pooled[source, case, pair_id]
                reason = old_reason or new_reason
                guard_ineligible = group["guard_pair"] and not all(
                    trial.row is not None
                    and (
                        trial.row["completed"]
                        and trial.row["conclusive"]
                        and trial.row["error"] is None
                    )
                    for trial in (old, new)
                )
                if guard_ineligible and reason is None:
                    reason = "guard_pair_ineligible"
                transitions[
                    (old_reason or ("guard_pair_ineligible" if guard_ineligible else "included"))
                    + " -> "
                    + (new_reason or ("guard_pair_ineligible" if guard_ineligible else "included"))
                ] += 1
                if reason is not None:
                    exclusions[reason].append(old.reference())
                    continue
                _value, old_n, old_d = _measurement(metric, old.row)
                _value, new_n, new_d = _measurement(metric, new.row)
                values[0] += old_n
                values[1] += old_d
                values[2] += new_n
                values[3] += new_d
                eligible += 1
            contributions = []
            for identity, (old_n, old_d, new_n, new_d) in sorted(pooled.items()):
                delta = Fraction(new_n, new_d) - Fraction(old_n, old_d) if old_d and new_d else None
                contributions.append(
                    MetricContribution(
                        *identity,
                        delta.numerator if delta is not None else 0,
                        delta.denominator if delta is not None else 0,
                    )
                )
            weighted = aggregate_metric(tuple(contributions))
            groups = sum(value is not None for _source, value in weighted.source_values)
            if groups >= 6 and not conflict:
                work += groups * plan.resamples
            metrics.append(
                {
                    "metric": metric,
                    "weighted": weighted,
                    "conflict": conflict,
                    "matched_eligible_slots": eligible,
                    "present_both_slots": present_both,
                    "old_n": sum(value[0] for value in pooled.values()),
                    "old_d": sum(value[1] for value in pooled.values()),
                    "new_n": sum(value[2] for value in pooled.values()),
                    "new_d": sum(value[3] for value in pooled.values()),
                    "transitions": dict(sorted(transitions.items())),
                    "exclusions": _ledger(exclusions),
                }
            )
        pending.append({**group, "metrics": metrics, "draw_work": work})
    return pending


def _operational_transitions(observations):
    result = []
    for metric, field in (
        ("recorded_completed", "completed"),
        ("recorded_conclusive", "conclusive"),
        ("error_present", "error"),
    ):
        counts = [{state: 0 for state in _OPERATIONAL_STATES} for _ in range(2)]
        transitions = defaultdict(int)
        for _pair, _identity, old, new in observations:
            states = []
            for index, trial in enumerate((old, new)):
                row = trial.row
                if row is None:
                    state = "missing"
                elif field not in row:
                    state = "not_recorded"
                elif metric == "error_present":
                    state = "false" if row[field] is None else "true"
                elif row[field] is None:
                    state = "null"
                else:
                    state = "true" if row[field] else "false"
                counts[index][state] += 1
                states.append(state)
            transitions[tuple(states)] += 1
        result.append(
            {
                "metric_id": metric,
                "expected_slots": len(observations),
                "baseline": counts[0],
                "candidate": counts[1],
                "transitions": [
                    {"baseline": old, "candidate": new, "count": count}
                    for (old, new), count in sorted(transitions.items())
                ],
            }
        )
    return result


def _finish_pairs(pending, plan):
    result = []
    for group in pending:
        metrics = []
        for entry in group["metrics"]:
            weighted, metric = entry["weighted"], entry["metric"]
            values = (
                weighted.source_values
                if not entry["conflict"]
                else tuple((key, None) for key, _value in weighted.source_values)
            )
            sensitivity = source_sensitivity(
                values,
                cell_key=json_digest([group["comparison_id"], metric.name]),
                seed=plan.seed,
                resamples=plan.resamples,
            )
            if entry["conflict"]:
                known = tuple(value for _key, value in weighted.source_values if value is not None)
                sensitivity = SourceSensitivity(
                    len(known),
                    weighted.estimate,
                    (min(known), max(known)) if known else None,
                    None,
                    None,
                    "partition_unresolved",
                    plan.seed,
                    plan.resamples,
                    json_digest(
                        [key for key, value in weighted.source_values if value is not None]
                    ),
                    None,
                    None,
                )
            metrics.append(
                {
                    "metric_id": metric.name,
                    "denominator_unit": metric.unit,
                    "expected_slots": len(group["observations"]),
                    "present_both_slots": entry["present_both_slots"],
                    "matched_eligible_slots": entry["matched_eligible_slots"],
                    "included_baseline_numerator": entry["old_n"],
                    "included_baseline_denominator": entry["old_d"],
                    "included_candidate_numerator": entry["new_n"],
                    "included_candidate_denominator": entry["new_d"],
                    "source_delta_fractions": [
                        {"cluster_key": source, "delta": _fraction(value)}
                        for source, value in weighted.source_values
                    ],
                    "mean_delta_fraction": _fraction(weighted.estimate),
                    "uncertainty": _uncertainty(
                        sensitivity,
                        suppressed="partition_unresolved" if entry["conflict"] else None,
                    ),
                    "eligibility_transitions": entry["transitions"],
                    "exclusions": entry["exclusions"],
                }
            )
        observations = group["observations"]

        def references(predicate, observations=observations):
            return sorted(
                json_digest([old.case_key, old.epoch])
                for _pair, _key, old, new in observations
                if predicate(old, new)
            )

        missing = references(lambda old, new: old.row is None or new.row is None)
        conditioning = (
            "both_arms_completed_conclusive_error_free; independent_generations"
            if group["guard_pair"]
            else "metric_eligible_matched_slots; descriptive_configurations"
        )
        if group["baseline_transport_inapplicable"]:
            conditioning = "contract_only; not_model_performance; " + conditioning
        result.append(
            {
                "comparison_id": group["comparison_id"],
                "pair_ids": sorted(group["pair_ids"]),
                "baseline_selection_ids": sorted(group["baseline_selection_ids"]),
                "candidate_selection_ids": sorted(group["candidate_selection_ids"]),
                "compatibility": "partial" if missing else "compatible",
                "baseline_run_kind": group["baseline_run_kind"],
                "candidate_run_kind": group["candidate_run_kind"],
                "baseline_transport_inapplicable": group["baseline_transport_inapplicable"],
                "comparison_scope": "scripted_calibration_to_adapter_contract"
                if group["baseline_transport_inapplicable"]
                else "recorded_native_observations",
                "conditioning": conditioning,
                "matched_case_epochs": references(
                    lambda old, new: old.row is not None and new.row is not None
                ),
                "baseline_only_case_epochs": references(
                    lambda old, new: old.row is not None and new.row is None
                ),
                "candidate_only_case_epochs": references(
                    lambda old, new: old.row is None and new.row is not None
                ),
                "both_missing_case_epochs": references(
                    lambda old, new: old.row is None and new.row is None
                ),
                "metrics": metrics,
                "unconditional_operational_transitions": _operational_transitions(observations),
            }
        )
    return result


def analyze_source_groups(
    evidence: AnalysisEvidence, *, plan: AnalysisPlan | dict
) -> AnalysisResult:
    """Produce one bounded derivative; malformed required evidence is never dropped."""
    from .native_compare import (
        BOUNDARY_CASE_FIELDS,
        CASE_FIELDS,
        _input_fingerprint,
        _request,
        _suite_cases,
    )
    from .provenance import text_digest
    from .report_validation import MAX_EXPORT_BYTES
    from .repository_cases import case_digest

    raw_plan = plan.model_dump(mode="json") if isinstance(plan, AnalysisPlan) else plan
    plan = AnalysisPlan.model_validate_json(
        json.dumps(raw_plan, ensure_ascii=False, allow_nan=False)
    )
    if type(evidence) is not AnalysisEvidence or any(
        type(value) is not dict
        for value in (evidence.reports, evidence.suites, evidence.exports, evidence.adjudications)
    ):
        raise ValueError("Analysis requires explicit inert evidence maps")
    artifacts = {item.artifact_id: item for item in plan.artifacts}
    if set(evidence.reports) != set(artifacts) or set(evidence.suites) - set(artifacts):
        raise ValueError("Analysis evidence does not match its artifact pool")
    if set(evidence.exports) != {item.export_id for item in plan.exports}:
        raise ValueError("Analysis export evidence does not match its declarations")
    if set(evidence.adjudications) != {
        path for item in plan.agreements for path in (item.rater_a, item.rater_b)
    }:
        raise ValueError("Analysis adjudication evidence does not match its declarations")
    exports = {key: _validate_export(value) for key, value in evidence.exports.items()}
    shard_ordinals = {
        (json_digest(evidence.exports[export_id]["index"]), case_digest(case)): ordinal
        for export_id, (_index, roster) in exports.items()
        for ordinal, cases in roster.items()
        for case in cases
    }
    inputs, digests, execution_keys, diagnostics = {}, {}, {}, []
    payloads = defaultdict(list)
    total_slots = 0
    for artifact_id, descriptor in artifacts.items():
        suite = evidence.suites.get(artifact_id)
        shard_binding = None
        if descriptor.export_id is not None:
            index, roster = exports[descriptor.export_id]
            if descriptor.shard_ordinal not in roster:
                raise ValueError("Artifact names an unknown export shard")
            expected = roster[descriptor.shard_ordinal]
            if suite is not None and tuple(
                case_digest(case) for case in _suite_cases(suite, "repository")
            ) != tuple(case_digest(case) for case in expected):
                raise ValueError("Artifact suite does not bind its declared export shard")
            suite = expected
            shard_binding = (
                json_digest(evidence.exports[descriptor.export_id]["index"]),
                descriptor.shard_ordinal,
            )
        elif descriptor.suite is not None and suite is None:
            raise ValueError("Analysis artifact is missing its declared suite")
        native = validate_native_analysis_input(evidence.reports[artifact_id], expected_suite=suite)
        if descriptor.export_id is not None and native.view.kind != "repository":
            raise ValueError("Repository export shards cannot bind boundary reports")
        if native.native_sha256 in digests:
            raise ValueError("Analysis artifact pool contains duplicate native documents")
        digests[native.native_sha256] = artifact_id
        inputs[artifact_id] = native
        execution_keys[artifact_id] = _execution(native, shard_binding)
        payloads[_payload_digest(native)].append(artifact_id)
        total_slots += native.view.metadata["expected_count"]
        if total_slots > MAX_ANALYSIS_SLOTS:
            raise ValueError("Analysis declared-slot bound exceeded")
    for matching in payloads.values():
        run_ids = {inputs[item].view.metadata.get("run_id") for item in matching}
        if len(matching) > 1 and len(run_ids) > 1:
            diagnostics.append(
                {"code": "execution_payload_collision", "identities": sorted(matching)}
            )
    for artifact_id, native in inputs.items():
        adjudication = native.view.metadata.get("adjudication")
        source = adjudication.get("source_report_sha256") if type(adjudication) is dict else None
        if source in digests:
            source_id = digests[source]
            if _payload_digest(native) != _payload_digest(inputs[source_id]):
                raise ValueError("Recorded adjudication view changes structural execution data")
            execution_keys[artifact_id] = execution_keys[source_id]
    membership, selected_trials, all_trials = set(), {}, []
    roster_identity, input_identity, alias_identity, logical_trials = {}, {}, {}, set()
    for selection in plan.selections:
        descriptor, native = artifacts[selection.artifact_id], inputs[selection.artifact_id]
        if descriptor.role != "analysis":
            raise ValueError("Agreement-context artifacts cannot be selected as repetitions")
        identity = (
            *execution_keys[selection.artifact_id],
            selection.reviewer,
            selection.guard,
            selection.cell,
        )
        if identity in membership:
            raise ValueError("Analysis selects duplicate recorded execution views or memberships")
        membership.add(identity)
        trials = _trial_set(selection, selection.artifact_id, native)
        selected_trials[selection.selection_id] = trials
        for trial in trials:
            if trial.case_sha256 is not None:
                logical = (
                    selection.cell,
                    selection.reviewer,
                    selection.guard,
                    selection.repetition_id,
                    trial.case_sha256,
                    trial.epoch,
                )
                if logical in logical_trials:
                    raise ValueError("Recorded repetition contains overlapping case/epoch trials")
                logical_trials.add(logical)
            if trial.row is not None:
                fields = CASE_FIELDS + (
                    BOUNDARY_CASE_FIELDS
                    if native.view.kind == "boundary"
                    else ("case_schema_version", "condition", "payload_ref")
                    if trial.row.get("case_schema_version") == 2
                    else ()
                )
                identity = json_digest({field: trial.row.get(field) for field in fields})
                key = (native.view.kind, trial.row["case_sha256"])
                if key in roster_identity and roster_identity[key] != identity:
                    raise ValueError("Analysis reports disagree on immutable case/input identity")
                roster_identity[key] = identity
                prompt = _input_fingerprint(native.view.metadata, trial.row)
                if prompt is None and trial.case is not None:
                    prompt = text_digest(
                        json.dumps(
                            _request(trial.case, native.view.kind),
                            ensure_ascii=native.view.metadata["run_kind"] != "model",
                            sort_keys=True,
                        )
                    )
                cohort_case = (
                    selection.cell,
                    selection.reviewer,
                    selection.guard,
                    native.view.kind,
                    native.view.metadata["run_kind"],
                    _config_fingerprint(native.view.metadata),
                    trial.row["case_sha256"],
                )
                recorded_input = (trial.row.get("input_sha256"), prompt)
                if cohort_case in input_identity and input_identity[cohort_case] != recorded_input:
                    raise ValueError("Analysis repeats incompatible recorded case input identity")
                input_identity[cohort_case] = recorded_input
            if trial.case is not None:
                alias_key = (json_digest(trial.stratum), _alias(trial.case))
                if alias_key in alias_identity and alias_identity[alias_key] != trial.case_sha256:
                    raise ValueError("Analysis estimate contains alias-equivalent case copies")
                alias_identity[alias_key] = trial.case_sha256
        all_trials.extend(trials)
    if len({trial.case_sha256 for trial in all_trials if trial.case_sha256}) > MAX_ANALYSIS_CASES:
        raise ValueError("Analysis immutable-case bound exceeded")
    bundles = defaultdict(list)
    for selection in plan.selections:
        descriptor = artifacts[selection.artifact_id]
        if descriptor.export_id is not None:
            bundles[
                (
                    descriptor.export_id,
                    selection.repetition_id,
                    selection.cell,
                    selection.reviewer,
                    selection.guard,
                )
            ].append(selection)
    bundle_summaries = []
    for (export_id, repetition, cell, reviewer, guard), members in sorted(
        bundles.items(), key=repr
    ):
        index, roster = exports[export_id]
        present = [artifacts[member.artifact_id].shard_ordinal for member in members]
        if len(set(present)) != len(present):
            raise ValueError("A recorded shard campaign repeats an ordinal")
        configurations = {
            _config_fingerprint(inputs[member.artifact_id].view.metadata) for member in members
        }
        epochs = {inputs[member.artifact_id].view.metadata["epochs"] for member in members}
        if len(configurations) != 1 or len(epochs) != 1:
            raise ValueError("A recorded shard campaign has incompatible settings")
        missing = sorted(set(roster) - set(present))
        template = members[0]
        native = inputs[template.artifact_id]
        for ordinal in missing:
            for case in roster[ordinal]:
                digest = case_digest(case)
                lineage = _lineage("repository", digest, case.source_group, case)
                stratum = _stratum(template, native, None, case, lineage)
                for epoch in range(1, native.view.metadata["epochs"] + 1):
                    missing_trial = _Trial(
                        template,
                        template.artifact_id,
                        native,
                        digest,
                        epoch,
                        None,
                        case,
                        digest,
                        lineage,
                        stratum,
                    )
                    all_trials.append(missing_trial)
                    selected_trials[template.selection_id] += (missing_trial,)
        bundle_summaries.append(
            {
                "export_id": export_id,
                "repetition_id": repetition,
                "cell": cell,
                "reviewer": reviewer,
                "guard": guard or "not_applicable",
                "index_sha256": json_digest(evidence.exports[export_id]["index"]),
                "shard_count": index.shard_count,
                "present_ordinals": tuple(sorted(present)),
                "missing_ordinals": tuple(missing),
            }
        )
    if len(all_trials) > MAX_ANALYSIS_SLOTS:
        raise ValueError("Analysis selected-slot bound exceeded")
    strata, grouped = {}, defaultdict(list)
    for trial in all_trials:
        if trial.stratum is not None:
            key = json_digest(trial.stratum)
            strata[key] = {"stratum_key": key, **trial.stratum}
            grouped[key].append(trial)
    if (
        sum(len(_metrics(members[0].native.view.kind)) for members in grouped.values())
        > MAX_ANALYSIS_CELLS
    ):
        raise ValueError("Analysis metric-cell bound exceeded")
    _preflight_identity_output(grouped, all_trials)
    pending, draw_work = [], 0
    for key, trials in sorted(grouped.items()):
        for metric in _metrics(trials[0].native.view.kind):
            cell_result, weighted = _cell(metric, key, trials, plan, draw=False)
            groups = sum(value is not None for _source, value in weighted.source_values)
            if groups >= 6 and cell_result["uncertainty"]["status"] not in (
                "coverage_unknown",
                "partition_unresolved",
            ):
                draw_work += groups * plan.resamples
            pending.append((metric, key, trials, cell_result, weighted))
    pair_pending = _prepare_pairs(plan, inputs, selected_trials, execution_keys, shard_ordinals)
    if len(pending) + sum(len(item["metrics"]) for item in pair_pending) > MAX_ANALYSIS_CELLS:
        raise ValueError("Analysis metric-cell bound exceeded")
    draw_work += sum(item["draw_work"] for item in pair_pending)
    if draw_work > MAX_RESAMPLE_DRAWS:
        raise ValueError("resampling_budget_exceeded")
    cells = [
        _cell(metric, key, trials, plan)[0] for metric, key, trials, _result, _weighted in pending
    ]
    pairs = _finish_pairs(pair_pending, plan)
    source_groups = defaultdict(list)
    conflicts = []
    for trial in all_trials:
        if trial.lineage is None:
            continue
        source_groups[trial.lineage["cluster_key"]].append(trial)
        if trial.lineage["lineage_status"] == "conflicting":
            conflicts.append(
                {
                    "code": "boundary_lineage_conflict",
                    "identities": [
                        trial.selection.selection_id,
                        trial.case_key,
                        *trial.lineage["recorded_labels"],
                    ],
                }
            )
    if len(source_groups) > MAX_ANALYSIS_GROUPS:
        raise ValueError("Analysis source-cluster bound exceeded")
    expected = sum(
        inputs[selection.artifact_id].view.metadata["case_count"]
        * inputs[selection.artifact_id].view.metadata["epochs"]
        for selection in plan.selections
    )
    missing_shard_slots = sum(
        sum(len(exports[bundle["export_id"]][1][ordinal]) for ordinal in bundle["missing_ordinals"])
        * next(
            inputs[member.artifact_id].view.metadata["epochs"]
            for member in plan.selections
            if member.repetition_id == bundle["repetition_id"]
            and member.cell == bundle["cell"]
            and member.reviewer == bundle["reviewer"]
            and (member.guard or "not_applicable") == bundle["guard"]
            and artifacts[member.artifact_id].export_id == bundle["export_id"]
        )
        for bundle in bundle_summaries
    )
    expected += missing_shard_slots
    present = sum(trial.row is not None for trial in all_trials)
    unattributed = sum(trial.lineage is None for trial in all_trials)
    unknown_inputs = sorted(
        {
            selection.artifact_id
            for selection in plan.selections
            if not inputs[selection.artifact_id].view.coverage_known
        }
    )
    if unknown_inputs:
        unattributed += expected - len(all_trials)
    summaries = []
    for artifact_id, native in sorted(inputs.items()):
        finished = native.view.metadata.get("run_finished")
        summaries.append(
            {
                "artifact_id": artifact_id,
                "role": artifacts[artifact_id].role,
                "native_sha256": native.native_sha256,
                "envelope_sha256": native.envelope_sha256,
                "kind": native.view.kind,
                "run_id": native.view.metadata.get("run_id"),
                "run_kind": native.view.metadata["run_kind"],
                "finish_state": "not_recorded"
                if finished is None
                else "recorded_finished"
                if finished
                else "recorded_unfinished",
                "suite_sha256": native.view.metadata["suite_sha256"],
                "suite_method": native.view.suite_method,
                "suite_bound": native.cases is not None,
                "coverage_known": native.view.coverage_known,
                "alias_check": "computed"
                if native.cases is not None
                else "unavailable_no_bound_suite",
                "expected_slots": native.view.metadata["expected_count"],
                "present_slots": len(native.view.rows),
                "selected_ids": sorted(
                    selection.selection_id
                    for selection in plan.selections
                    if selection.artifact_id == artifact_id
                ),
                "recorded_execution_sha256": json_digest(execution_keys[artifact_id]),
                "configuration_sha256": _config_fingerprint(native.view.metadata),
                "measurement_support": {
                    "authenticity": "unverified_recorded",
                    "repository_attack_following": "not_measured",
                    "repository_resistance": "not_measured",
                    "native_sample_cost": "not_recorded",
                    "native_latency": "not_recorded",
                },
            }
        )
    source_summary = []
    for _source, members in sorted(source_groups.items()):
        detail = _merged_lineage(members)
        present_members = [trial for trial in members if trial.row is not None]
        coverage_known = all(trial.native.view.coverage_known for trial in members)

        def view_run(trial):
            selection = trial.selection
            return (selection.cell, selection.reviewer, selection.guard, selection.repetition_id)

        source_summary.append(
            {
                **detail,
                "case_ids": sorted({trial.case_sha256 or trial.case_key for trial in members}),
                "expected_slots": len(members) if coverage_known else None,
                "present_slots": len(present_members),
                "expected_case_count": len(
                    {trial.case_sha256 or trial.case_key for trial in members}
                )
                if coverage_known
                else None,
                "present_case_count": len(
                    {trial.case_sha256 or trial.case_key for trial in present_members}
                ),
                "expected_run_count": len({view_run(trial) for trial in members})
                if coverage_known
                else None,
                "present_run_count": len({view_run(trial) for trial in present_members}),
            }
        )
    result = {
        "plan_sha256": json_digest(raw_plan),
        "inputs": summaries,
        "duplicates": diagnostics,
        "lineage_conflicts": conflicts,
        "coverage": {
            "expected_slots": expected,
            "present_slots": present,
            "missing_slots": expected - present,
            "coverage_unknown_inputs": unknown_inputs,
            "unattributed_missing_slots": unattributed,
            "expected_group_count": len(source_groups) if not unattributed else None,
            "expected_recorded_clusters": sorted(source_groups),
            "missing_recorded_clusters": sorted(
                source
                for source in source_groups
                if not any(
                    trial.row is not None
                    and trial.lineage is not None
                    and trial.lineage["cluster_key"] == source
                    for trial in all_trials
                )
            ),
            "slots": [trial.reference() for trial in all_trials],
            "shard_bundles": bundle_summaries,
        },
        "strata": [strata[key] for key in sorted(strata)],
        "source_groups": source_summary,
        "repeated_runs": [
            {
                "selection_id": selection.selection_id,
                "repetition_id": selection.repetition_id,
                "recorded_run_id": inputs[selection.artifact_id].view.metadata.get("run_id")
                or "not_recorded",
                "recorded_repetition": inputs[selection.artifact_id].view.metadata.get("run_id")
                is not None,
                "authenticity": "unverified_recorded",
            }
            for selection in plan.selections
        ],
        "metric_cells": cells,
        "paired_comparisons": pairs,
        "guard_pairs": _guard_inventory(inputs),
        "agreement": _agreements(plan, evidence, inputs),
        "usage": _usage(inputs, execution_keys),
        "uncertainty": {
            "policy": "descriptive_observed_source_partition",
            "resampling_draws": draw_work,
            "population_inference": "not_established",
        },
        "publication": {
            "recorded_cluster_count": len(source_groups),
            "recognized_reference_lineage_count": len(
                {
                    detail["canonical_lineage"]
                    for detail in source_summary
                    if detail["canonical_lineage"]
                }
            ),
        },
    }
    parsed = AnalysisResult.model_validate_json(
        json.dumps(result, ensure_ascii=False, allow_nan=False)
    )
    # This derivative has its own typed contract, not the native dashboard's
    # JSON-node budget. Existing native validation above keeps all old limits.
    total = 1
    for chunk in json.JSONEncoder(indent=2, ensure_ascii=False, allow_nan=False).iterencode(
        parsed.model_dump(mode="json")
    ):
        total += len(chunk.encode("utf-8"))
        if total > MAX_EXPORT_BYTES:
            raise ValueError("Analysis output byte bound exceeded")
    return parsed
