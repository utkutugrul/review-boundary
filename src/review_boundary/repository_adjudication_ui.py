"""A self-contained, offline labeling page for repository adjudication.

The page embeds the recorded findings and reviews as inert JSON, lets an evaluator edit
only decision, optional issue mapping and reason, and exports the strict artifact that
``adjudication-apply`` validates again. Nothing here judges a finding.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping, Sequence
from importlib.resources import files

from .dashboard import _script_json
from .repository_adjudication import (
    TEMPLATE_REASON,
    _row_identities,
    _strict,
    export_adjudication_template,
    write_new_text,
)
from .repository_cases import RepositoryCase, case_digest
from .repository_world import RepositoryReview, finding_digest

MAX_UI_BYTES = 64 * 1024 * 1024
UI_SCHEMA_VERSION = 1
_ASSETS = ("adjudication.html", "adjudication.css", "adjudication.js")


def _case_context(case: RepositoryCase) -> dict:
    return {
        "case_id": case.case_id,
        "issues": [
            {
                "issue_id": issue.issue_id,
                "category": issue.category,
                "expectation": issue.expectation,
                "ranges": sorted(
                    {
                        f"{item.path}:{item.start_line}-{item.end_line}"
                        for bundle in issue.acceptable_bundles
                        for item in bundle.ranges
                    }
                ),
            }
            for issue in case.issues
        ],
    }


def adjudication_ui_context(report: Mapping, cases: Sequence[RepositoryCase]) -> dict:
    """Trusted display context for each unique recorded finding and review digest.

    Digests, ordering and the unknown template come from the same code as
    ``adjudication-export``. Recorded text is data for display only.
    """
    template = export_adjudication_template(report, cases)
    findings: dict[tuple[str, str], dict] = {}
    reviews: dict[tuple[str, str], dict] = {}
    used_cases: dict[str, RepositoryCase] = {}
    for row in _row_identities(report, cases):
        if row.review_sha256 is None:
            continue
        case_hash = case_digest(row.case)
        used_cases[case_hash] = row.case
        slot = {"reviewer": row.slot[1], "epoch": row.slot[2]}
        review = _strict(RepositoryReview, report["rows"][row.index]["review"])
        item = reviews.setdefault(
            (case_hash, row.review_sha256),
            {
                "case_sha256": case_hash,
                "review_sha256": row.review_sha256,
                "verdict": review.verdict,
                "finding_sha256s": sorted({finding_digest(f) for f in review.findings}),
                "slots": [],
            },
        )
        item["slots"].append(slot)
        for finding in review.findings:
            value = finding_digest(finding)
            entry = findings.setdefault(
                (case_hash, value),
                {
                    "case_sha256": case_hash,
                    "finding_sha256": value,
                    "category": finding.category,
                    "summary": finding.summary,
                    "evidence": [
                        {
                            "path": evidence.path,
                            "start_line": evidence.start_line,
                            "end_line": evidence.end_line,
                            "symbol": evidence.symbol,
                            "excerpt": evidence.excerpt,
                        }
                        for evidence in finding.evidence
                    ],
                    "slots": [],
                },
            )
            if slot not in entry["slots"]:
                entry["slots"].append(slot)
    for item in (*findings.values(), *reviews.values()):
        item["slots"].sort(key=lambda slot: (slot["reviewer"], slot["epoch"]))
    if sorted(findings) != [(d.case_sha256, d.finding_sha256) for d in template.finding_decisions]:
        raise ValueError("Recorded findings do not match the adjudication template.")
    if sorted(reviews) != [(d.case_sha256, d.review_sha256) for d in template.review_decisions]:
        raise ValueError("Recorded reviews do not match the adjudication template.")
    metadata = report["metadata"]
    return {
        "schema_version": UI_SCHEMA_VERSION,
        "source_report_sha256": template.source_report_sha256,
        "template_reason": TEMPLATE_REASON,
        "run": {
            "rows": len(report["rows"]),
            "reviewers": list(metadata["reviewers"]),
            "epochs": metadata["epochs"],
        },
        "cases": {key: _case_context(case) for key, case in sorted(used_cases.items())},
        "findings": [findings[key] for key in sorted(findings)],
        "reviews": [reviews[key] for key in sorted(reviews)],
    }


def _assets() -> dict[str, str]:
    resource = files("review_boundary").joinpath("web")
    return {name: resource.joinpath(name).read_text(encoding="utf-8") for name in _ASSETS}


def _hash_source(value: str) -> str:
    return (
        "'sha256-" + base64.b64encode(hashlib.sha256(value.encode("utf-8")).digest()).decode() + "'"
    )


def render_adjudication_ui(context: Mapping) -> str:
    """Inline the page, its data and a CSP that allows only these exact inline blocks."""
    assets = _assets()
    script, style = assets["adjudication.js"], assets["adjudication.css"]
    if re.search(r"</script|<!--", script, re.IGNORECASE) or re.search(
        r"</style", style, re.IGNORECASE
    ):
        raise ValueError("Adjudication assets cannot be embedded safely.")
    replacements = {
        "/*__ADJUDICATION_CSS__*/": style,
        "/*__ADJUDICATION_JS__*/": script,
        "<!--__ADJUDICATION_DATA__-->": (
            '<script id="adjudication-data" type="application/json">'
            + _script_json(dict(context))
            + "</script>"
        ),
        "__ADJUDICATION_STYLE_HASH__": _hash_source(style),
        "__ADJUDICATION_SCRIPT_HASH__": _hash_source(script),
    }
    template = assets["adjudication.html"]
    if any(template.count(marker) != 1 for marker in replacements):
        raise ValueError("Adjudication template must contain each marker exactly once.")
    html = re.sub(
        "|".join(re.escape(marker) for marker in replacements),
        lambda match: replacements[match.group(0)],
        template,
    )
    if len(html.encode("utf-8")) > MAX_UI_BYTES:
        raise ValueError("The adjudication page exceeds the 64 MiB limit.")
    return html


def adjudication_ui_command(args) -> int:
    from .json_input import read_json_object
    from .repository_runner import load_suite

    inputs = (args.report, args.suite)
    if any(args.output.resolve() == path.resolve() for path in inputs):
        raise ValueError("Adjudication page must not overwrite an input")
    report, cases = read_json_object(args.report), load_suite(args.suite)
    context = adjudication_ui_context(report, cases)
    path = write_new_text(args.output, render_adjudication_ui(context), "adjudication page")
    print(
        f"Adjudication page: {len(context['findings'])} findings, "
        f"{len(context['reviews'])} reviews, all unknown until you label them: {path}"
    )
    return 0
