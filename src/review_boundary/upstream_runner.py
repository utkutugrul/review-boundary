"""Export registered suites without deriving source admission from exported metadata."""

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from .corpus_manifest import Sha256, Text, parse_corpus_manifest
from .corpus_registry import checked_registered_cases, get_corpus, registration_suite_contract
from .corpus_sharding import (
    MAX_CORPUS_CASES,
    MAX_CORPUS_SHARDS,
    MAX_EXPORT_BYTES,
    MAX_SOURCE_GROUPS,
)
from .provenance import experiment_provenance, json_digest
from .repository_cases import FrozenModel, ShortText, case_digest
from .repository_suite import MAX_REPOSITORY_SUITE_CASES, RepositorySuite, RepositorySuiteV2
from .repository_world import tool_schemas


class CorpusExportCaseIdentity(FrozenModel):
    case_id: ShortText
    case_sha256: Sha256


class CorpusExportShard(FrozenModel):
    ordinal: int = Field(ge=1, le=MAX_CORPUS_SHARDS)
    suite_path: str
    suite_sha256: Sha256
    case_count: int = Field(ge=1, le=MAX_REPOSITORY_SUITE_CASES)
    source_groups: tuple[ShortText, ...] = Field(
        min_length=1, max_length=MAX_REPOSITORY_SUITE_CASES
    )

    @model_validator(mode="after")
    def ordinal_path(self):
        if self.suite_path != f"shards/{self.ordinal:04d}/suite.json":
            raise ValueError("Shard paths must use their ordinal only")
        if tuple(sorted(set(self.source_groups))) != self.source_groups:
            raise ValueError("Shard source groups must be unique and sorted")
        return self


class CorpusExportIndex(FrozenModel):
    """An export fingerprint. Its data does not authenticate or admit any source."""

    schema_version: Literal[1]
    corpus: Text
    corpus_version: Text
    suite_schema_version: Literal[1, 2]
    scoring_version: Text
    protocol: Text
    case_set: tuple[CorpusExportCaseIdentity, ...] = Field(
        min_length=1, max_length=MAX_CORPUS_CASES
    )
    case_set_sha256: Sha256
    case_count: int = Field(ge=1, le=MAX_CORPUS_CASES)
    source_groups: tuple[ShortText, ...] = Field(min_length=1, max_length=MAX_SOURCE_GROUPS)
    source_issue_count: int = Field(ge=1, le=MAX_SOURCE_GROUPS)
    shards: tuple[CorpusExportShard, ...] = Field(min_length=1, max_length=MAX_CORPUS_SHARDS)
    shard_count: int = Field(ge=1, le=MAX_CORPUS_SHARDS)
    behavior_verification: Literal["not_run"]

    @field_validator("schema_version", "suite_schema_version", mode="before")
    @classmethod
    def exact_integer_versions(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("Export index versions must be exact integers")
        return value

    @model_validator(mode="after")
    def complete_export_identity(self):
        identities = [(item.case_id, item.case_sha256) for item in self.case_set]
        groups = tuple(sorted(set(self.source_groups)))
        shard_groups = tuple(group for shard in self.shards for group in shard.source_groups)
        if (
            identities != sorted(identities)
            or len({item.case_id for item in self.case_set}) != len(self.case_set)
            or len(self.case_set) != self.case_count
            or json_digest(identities) != self.case_set_sha256
            or groups != self.source_groups
            or len(groups) != self.source_issue_count
            or len(self.shards) != self.shard_count
            or tuple(shard.ordinal for shard in self.shards)
            != tuple(range(1, self.shard_count + 1))
            or sum(shard.case_count for shard in self.shards) != self.case_count
            or len(shard_groups) != len(set(shard_groups))
            or set(shard_groups) != set(groups)
        ):
            raise ValueError("Export index must describe one complete case and source-group set")
        return self


def _json_text(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + "\n"


def _checked_evaluator(corpus) -> dict:
    evaluator = corpus.evaluator_manifest()
    if type(evaluator) is not dict or type(evaluator.get("inventory")) is not dict:
        raise ValueError("Registered evaluator inventory is unavailable")
    inventory = parse_corpus_manifest(evaluator["inventory"])
    if (
        inventory.corpus_name != corpus.name
        or inventory.corpus_version != corpus.corpus_version
        or inventory.scoring_version != corpus.scoring_version
    ):
        raise ValueError("Registered evaluator inventory identity does not match")
    return evaluator


def _new_shard_directory(output) -> Path:
    from .repository_runner import _path_without_symlinks

    given = Path(output)
    if ".." in given.parts:
        raise ValueError("Corpus shard output must not contain '..' components")
    root = _path_without_symlinks(given, "output", runner_label="Corpus shards")
    if os.path.lexists(root):
        raise ValueError("Corpus shard output already exists; it is never overwritten")
    if not root.parent.is_dir():
        raise ValueError("Corpus shard output parent must be an existing directory")
    return root


def _write_shards(root: Path, files: dict[str, str]) -> None:
    """Use exclusive creation and preserve paths whose inode or ancestor was replaced."""
    from .repository_adjudication import _write_new_text_owned
    from .suite_contribution import _identity, _remove_created, _still_owned

    ancestors = [(parent, _identity(parent)) for parent in root.parents]
    created_files = []
    created_directories = []

    def unchanged():
        return all(
            _still_owned(path, identity) for path, identity in ancestors + created_directories
        )

    try:
        os.mkdir(root, 0o700)
        created_directories.append((root, _identity(root)))
        for relative, text in files.items():
            if not unchanged():
                raise ValueError("Corpus shard output directory changed during creation")
            path = root / relative
            for directory in reversed(path.parent.relative_to(root).parents):
                child = root / directory
                if child != root and not any(child == item[0] for item in created_directories):
                    os.mkdir(child, 0o700)
                    created_directories.append((child, _identity(child)))
            if path.parent != root and not any(
                path.parent == item[0] for item in created_directories
            ):
                os.mkdir(path.parent, 0o700)
                created_directories.append((path.parent, _identity(path.parent)))
            if not unchanged():
                raise ValueError("Corpus shard output directory changed during creation")
            created_files.append(_write_new_text_owned(path, text, "corpus shard export file"))
    except BaseException:
        if all(_still_owned(path, identity) for path, identity in ancestors):
            _remove_created(created_files, created_directories)
        raise


def _export_sharded(corpus, output: Path, source, cases, evaluator, contract) -> int:
    from .corpus_sharding import plan_corpus_shards

    root = _new_shard_directory(output)
    plan = plan_corpus_shards(cases)
    identities = tuple(
        CorpusExportCaseIdentity(case_id=case.case_id, case_sha256=case_digest(case))
        for case in sorted(cases, key=lambda case: case.case_id)
    )
    index = CorpusExportIndex(
        schema_version=1,
        corpus=corpus.name,
        corpus_version=corpus.corpus_version,
        suite_schema_version=contract.schema_version,
        scoring_version=contract.scoring_version,
        protocol=contract.protocol,
        case_set=identities,
        case_set_sha256=plan.case_set_sha256,
        case_count=plan.case_count,
        source_groups=plan.source_groups,
        source_issue_count=len(plan.source_groups),
        shards=tuple(
            CorpusExportShard(
                ordinal=shard.ordinal,
                suite_path=f"shards/{shard.ordinal:04d}/suite.json",
                suite_sha256=shard.suite_sha256,
                case_count=len(shard.suite.cases),
                source_groups=shard.source_groups,
            )
            for shard in plan.shards
        ),
        shard_count=len(plan.shards),
        behavior_verification="not_run",
    ).model_dump(mode="json")
    metadata = {
        "schema_version": 2,
        "export_kind": "registered_corpus_shards",
        "corpus": corpus.name,
        "corpus_version": corpus.corpus_version,
        "generated_at": datetime.now(UTC).isoformat(),
        "suite_schema_version": contract.schema_version,
        "scoring_version": contract.scoring_version,
        "protocol": contract.protocol,
        "index_sha256": json_digest(index),
        "source_manifest_sha256": json_digest(source),
        "evaluator_manifest_sha256": json_digest(evaluator),
        "case_count": len(cases),
        "source_issue_count": len(plan.source_groups),
        "provenance": experiment_provenance(
            {
                "registered-inputs": json.dumps(
                    [
                        {
                            "case_id": case.case_id,
                            "instructions": case.instructions,
                            "task": case.task,
                        }
                        for case in sorted(cases, key=lambda case: case.case_id)
                    ],
                    sort_keys=True,
                )
            },
            tool_schemas(),
            protocol=contract.protocol,
        ),
        "behavior_verification": "not_run",
        "scope": corpus.scope,
    }
    files = {
        "index.json": _json_text(index),
        "provenance.json": _json_text(metadata),
        "source_manifest.json": _json_text(source),
        "evaluator_manifest.json": _json_text(evaluator),
        **{
            f"shards/{shard.ordinal:04d}/suite.json": _json_text(
                shard.suite.model_dump(mode="json")
            )
            for shard in plan.shards
        },
    }
    if sum(len(text.encode("utf-8")) for text in files.values()) > MAX_EXPORT_BYTES:
        raise ValueError("Corpus shard export exceeds the 64 MiB aggregate output limit")
    _write_shards(root, files)
    print("Upstream shard index: " + str(root / "index.json"))
    print("Behavior verification: not_run")
    return 0


def export_upstream(args) -> int:
    sharded = getattr(args, "shard", False)
    if sharded and args.verify:
        raise ValueError("Sharded corpus exports do not support --verify")
    corpus = get_corpus(args.corpus)
    if corpus.suite_schema_version == 2 and args.verify:
        raise ValueError("Version 2 corpus exports do not have a reviewed --verify binding")
    output = args.output
    if not sharded and output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("Corpus output must be a new or empty directory")
    source = corpus.source_manifest()
    cases = checked_registered_cases(corpus)
    evaluator = _checked_evaluator(corpus)
    contract = registration_suite_contract(corpus, cases)
    if sharded:
        return _export_sharded(corpus, output, source, cases, evaluator, contract)
    suite_model = RepositorySuiteV2 if contract.schema_version == 2 else RepositorySuite
    suite = suite_model(schema_version=contract.schema_version, cases=cases).model_dump(mode="json")
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
            protocol=contract.protocol,
        ),
        "behavior_verification": "not_run"
        if verification is None
        else "passed"
        if verification["reproduced"]
        else "failed",
        "scope": corpus.scope,
    }
    if contract.schema_version == 2:
        metadata.update(
            schema_version=2,
            export_kind="registered_corpus_suite",
            corpus=corpus.name,
            suite_schema_version=2,
            scoring_version=contract.scoring_version,
            protocol=contract.protocol,
        )
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
