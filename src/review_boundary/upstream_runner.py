"""Export an inspectable upstream suite and optional offline behavior evidence."""

import json
from datetime import UTC, datetime

from .corpus_registry import get_corpus
from .provenance import experiment_provenance, json_digest
from .repository_runner import PROTOCOL
from .repository_suite import RepositorySuite
from .repository_world import tool_schemas


def export_upstream(args) -> int:
    corpus = get_corpus(args.corpus)
    output = args.output
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Corpus output must be a new or empty directory")
    source = corpus.source_manifest()
    cases = corpus.build_cases()
    evaluator = corpus.evaluator_manifest()
    suite = RepositorySuite(schema_version=1, cases=cases).model_dump(mode="json")
    verification = corpus.verify_behavior() if args.verify else None
    metadata = {
        "schema_version": 1,
        "corpus_version": corpus.corpus_version,
        "generated_at": datetime.now(UTC).isoformat(),
        "suite_sha256": json_digest(suite),
        "evaluator_manifest_sha256": json_digest(evaluator),
        "case_count": len(cases),
        "source_issue_count": len({case.source_group for case in cases}),
        "source": source,
        "provenance": experiment_provenance(
            {
                f"input-{index}": json.dumps(
                    {"instructions": case.instructions, "task": case.task},
                    sort_keys=True,
                )
                for index, case in enumerate(cases)
            },
            tool_schemas(),
            protocol=PROTOCOL,
        ),
        "behavior_verification": "not_run"
        if verification is None
        else "passed"
        if verification["reproduced"]
        else "failed",
        "scope": corpus.scope,
    }
    output.mkdir(parents=True, exist_ok=True)
    for filename, value in (
        ("suite.json", suite),
        ("provenance.json", metadata),
        ("evaluator_manifest.json", evaluator),
    ):
        (output / filename).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    if verification is not None:
        (output / "verification.json").write_text(json.dumps(verification, indent=2) + "\n")
    print("Upstream suite: " + str((output / "suite.json").resolve()))
    print("Behavior verification: " + metadata["behavior_verification"])
    return 2 if verification is not None and not verification["reproduced"] else 0
