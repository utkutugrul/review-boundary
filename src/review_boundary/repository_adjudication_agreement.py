"""Optional inter-rater agreement between two complete repository adjudications.

Only decision labels are compared. Unknown is an explicit label, never a pass or fail,
and incomplete or mismatched artifacts are rejected instead of being aligned.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from fractions import Fraction

from .provenance import json_digest
from .repository_adjudication import validate_adjudication, write_new_text
from .repository_cases import RepositoryCase

LABELS = ("supported", "rejected", "unknown")


def _statistics(pairs: Sequence[tuple[str, str]]) -> dict:
    count = len(pairs)
    confusion = {first: dict.fromkeys(LABELS, 0) for first in LABELS}
    for first, second in pairs:
        confusion[first][second] += 1
    agreements = sum(confusion[label][label] for label in LABELS)
    if not count:
        return {
            "items": 0,
            "agreements": 0,
            "exact_agreement": None,
            "cohen_kappa": None,
            "confusion": confusion,
        }
    observed = Fraction(agreements, count)
    expected = sum(
        Fraction(sum(confusion[label].values()), count)
        * Fraction(sum(row[label] for row in confusion.values()), count)
        for label in LABELS
    )
    # Two raters who each use one identical label have no variance to correct for.
    kappa = None if expected == 1 else float((observed - expected) / (1 - expected))
    return {
        "items": count,
        "agreements": agreements,
        "exact_agreement": float(observed),
        "cohen_kappa": None if kappa is None else round(kappa, 6),
        "confusion": confusion,
    }


def adjudication_agreement(report: Mapping, cases: Sequence[RepositoryCase], first, second) -> dict:
    """Compare two artifacts that each cover every recorded finding and review."""
    one = validate_adjudication(first, report, cases, require_complete=True)
    two = validate_adjudication(second, report, cases, require_complete=True)
    findings = {(d.case_sha256, d.finding_sha256): d for d in one.finding_decisions}
    other_findings = {(d.case_sha256, d.finding_sha256): d for d in two.finding_decisions}
    reviews = {(d.case_sha256, d.review_sha256): d for d in one.review_decisions}
    other_reviews = {(d.case_sha256, d.review_sha256): d for d in two.review_decisions}
    if (
        one.source_report_sha256 != two.source_report_sha256
        or findings.keys() != other_findings.keys()
        or reviews.keys() != other_reviews.keys()
    ):
        raise ValueError("Adjudications do not cover an identical digest set.")
    if not findings and not reviews:
        raise ValueError("There are no recorded decisions to compare.")
    finding_pairs = [(findings[k].decision, other_findings[k].decision) for k in sorted(findings)]
    review_pairs = [(reviews[k].decision, other_reviews[k].decision) for k in sorted(reviews)]
    statistics = _statistics(finding_pairs)
    statistics["agreements_with_issue_mapping"] = sum(
        findings[key].decision == other_findings[key].decision
        and findings[key].issue_id == other_findings[key].issue_id
        for key in findings
    )
    return {
        "schema_version": 1,
        "agreement_kind": "repository",
        "source_report_sha256": one.source_report_sha256,
        "rater_artifact_sha256": [
            json_digest(artifact.model_dump(mode="json")) for artifact in (one, two)
        ],
        "compared": "decision labels only; reasons and issue mappings are not scored",
        "findings": statistics,
        "reviews": _statistics(review_pairs),
        "overall": _statistics([*finding_pairs, *review_pairs]),
    }


def agreement_command(args) -> int:
    from .json_input import read_json_object
    from .repository_runner import load_suite

    first, second = args.rater_a, args.rater_b
    if first.resolve() == second.resolve():
        raise ValueError("Agreement needs two different adjudication files")
    result = adjudication_agreement(
        read_json_object(args.report),
        load_suite(args.suite),
        read_json_object(first),
        read_json_object(second),
    )
    text = json.dumps(result, indent=2) + "\n"
    if args.output is not None:
        write_new_text(args.output, text, "agreement output")
    overall = result["overall"]
    kappa = "undefined" if overall["cohen_kappa"] is None else f"{overall['cohen_kappa']:.3f}"
    print(
        f"Agreement over {overall['items']} decisions: "
        f"exact {overall['exact_agreement']:.3f}, Cohen kappa {kappa}"
    )
    return 0
