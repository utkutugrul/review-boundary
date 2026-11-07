"""Layered, evaluator-only validation of repository suite files.

Every layer reports ``passed``, ``failed``, ``inventory_only`` or ``not_requested``. A layer that was not asked
for, or whose prerequisite failed, never reports success. Passing every layer is not corpus
admission. Manifest hashes and authority claims are descriptive and never authenticate a
source, and no split label is evidence of independence or of training non-exposure.

Suites, manifests and splits are data. Nothing here imports, executes or evaluates candidate
code, setup files or tests. The only code that can run is the registered bundled oracle, and
only for ``--verify`` after the suite is bound exactly to that registered corpus. The JSON
Schema comes solely from ``repository_suite_schema``; no candidate schema or external
reference is ever accepted.

Leakage rules inspect the reviewer-visible fields only: instructions, task, PR text, file
paths and file contents. Reported text never echoes candidate content.

* Opaque ``case_id``, ``source_group`` and ``issue_id`` strings must not appear. Matching is
  case-insensitive and treats ``_`` and ``-`` alike; generic labels and project names are allowed.
* From supplied or registered manifests, advisory aliases, advisory URLs,
  pinned revisions, artifact source URLs, oracle identifiers and the oracle hash must not
  appear. Generic words such as vulnerable, fixed or authorization and project identity are
  never flagged.
* Path carrier rules, matched case-insensitively on reviewer paths: a ``.git`` component;
  an ``evaluator``, ``evaluators``, ``reference_patch`` or ``reference-patch`` directory; a
  file named ``evaluator_manifest.json`` or ``oracle.json``; and a ``.patch`` or ``.diff``
  file whose name starts with reference, oracle, gold, solution, expected or fix.
"""

import hashlib
import itertools
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import jsonschema
from pydantic import Field, ValidationError, field_validator

from .corpus_manifest import CorpusManifest, parse_corpus_manifest
from .corpus_registry import corpus_names, get_corpus
from .json_input import read_json_object
from .provenance import HARNESS_FILES, json_digest
from .repository_cases import FrozenModel, case_digest
from .repository_suite import parse_repository_suite, repository_suite_schema

RESULT_SCHEMA_VERSION = 1
MAX_MESSAGES = 20
MAX_MESSAGE_CHARS = 200
MAX_MANIFESTS = 32
MAX_FIXTURE_FILES = 1024
LAYER_NAMES = (
    "safe_json",
    "json_schema",
    "runtime_parser",
    "leakage",
    "source_group_split",
    "provenance_license",
    "bundled_behavior",
    "installed_package",
)
NOTES = (
    "Passing validation does not establish corpus admission.",
    "Source authenticity is unverified for externally supplied metadata.",
    "Manifest hashes and authority claims are descriptive and never authenticate sources.",
    (
        "External oracle identity and sandbox claims are unverified declarations; "
        "candidate oracle code is neither read nor executed."
    ),
    "Split labels are declarations; independence and training non-exposure are not inferred.",
)
_SAFE_PART = re.compile(r"[A-Za-z0-9_]{1,32}")
_WRAPPER_KEYS = frozenset(
    {"schema_version", "scope", "inventory", "inventory_sha256", "authority", "layers"}
)
_CARRIER_DIRECTORIES = {
    ".git": "git_metadata",
    "evaluator": "evaluator_directory",
    "evaluators": "evaluator_directory",
    "reference_patch": "reference_patch_directory",
    "reference-patch": "reference_patch_directory",
}
_CARRIER_FILES = {
    "evaluator_manifest.json": "evaluator_manifest_file",
    "oracle.json": "oracle_file",
}
_PATCH_FILE = re.compile(
    r"(?:reference|oracle|gold|solution|expected|fix)(?:[._-].*)?\.(?:patch|diff)"
)
_PUBLIC_LABELS = frozenset({"vulnerable", "fixed", "authorization"})

_Group = Annotated[str, Field(min_length=1, max_length=256)]


class _Partitions(FrozenModel):
    development: tuple[_Group, ...] = Field(max_length=256)
    held_out: tuple[_Group, ...] = Field(max_length=256)


class _Splits(FrozenModel):
    schema_version: Literal[1]
    partitions: _Partitions

    @field_validator("schema_version", mode="before")
    @classmethod
    def exact_integer_version(cls, value: Any) -> Any:
        if type(value) is not int:
            raise ValueError("schema_version must be the exact integer 1")
        return value


class _Layer:
    __slots__ = ("messages", "omitted", "status")

    def __init__(self):
        self.status = "not_requested"
        self.messages: list[str] = []
        self.omitted = 0

    def note(self, text: str) -> None:
        if len(self.messages) >= MAX_MESSAGES:
            self.omitted += 1
        else:
            self.messages.append(text[:MAX_MESSAGE_CHARS])

    def begin(self) -> None:
        self.status = "passed"

    def fail(self, text: str) -> None:
        self.status = "failed"
        self.note(text)

    def skip(self, text: str) -> None:
        self.status = "not_requested"
        self.note(text)

    def inventory_only(self, text: str) -> None:
        if self.status != "failed":
            self.status = "inventory_only"
        self.note(text)

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "messages": list(self.messages),
            "omitted_messages": self.omitted,
        }


@dataclass(frozen=True)
class _Binding:
    registration: Any
    inventory: CorpusManifest | None
    bound: bool
    messages: tuple[str, ...]


def _norm(text: str) -> str:
    return text.casefold().replace("_", "-")


def _location(parts) -> str:
    text = "$"
    for part in parts:
        if isinstance(part, int):
            text += f"[{part}]"
        elif part == "<unknown field>" or (isinstance(part, str) and _SAFE_PART.fullmatch(part)):
            text += "." + part
        else:
            text += ".<key>"
    return text


def _error_lines(exc: ValidationError) -> list[str]:
    """Describe validation failures by location and fixed message, never by input value."""
    lines = []
    for error in exc.errors(include_url=False, include_context=False, include_input=False):
        location = list(error["loc"])
        if error["type"] == "extra_forbidden" and location:
            location[-1] = "<unknown field>"
        lines.append(f"{_location(location)}: {str(error['msg'])[:120]}")
    return lines


def _read_message(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError | UnicodeDecodeError):
        return "Input is not valid UTF-8 JSON."
    if isinstance(exc, ValueError):
        text = str(exc)
        if text.startswith("JSON ") and len(text) <= 120:
            return text
        return "Input could not be parsed as a bounded JSON object."
    return "Input file could not be read as a regular file."


def _strict_json(model, value):
    return model.model_validate_json(json.dumps(value, allow_nan=False))


def _require_local_refs(node, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("Schema nesting exceeds the limit.")
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("$ref", "$dynamicRef") and not (
                isinstance(value, str) and value.startswith("#")
            ):
                raise ValueError("External schema references are not accepted.")
            if key == "$id":
                raise ValueError("Schema identifiers are not accepted.")
            _require_local_refs(value, depth + 1)
    elif isinstance(node, list):
        for value in node:
            _require_local_refs(value, depth + 1)


def _run_schema(layer: _Layer, data: dict) -> None:
    try:
        version = data.get("schema_version", 1)
        schema = (
            repository_suite_schema()
            if type(version) is int and version == 1
            else repository_suite_schema(schema_version=version)
        )
        _require_local_refs(schema)
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
    except (jsonschema.SchemaError, ValueError):
        layer.fail("The derived repository suite schema is not usable.")
        return
    layer.begin()
    for error in itertools.islice(validator.iter_errors(data), MAX_MESSAGES + 1):
        layer.fail(f"{_location(error.absolute_path)}: violates schema keyword {error.validator!r}")


def _read_suite(layers: dict, path: Path):
    safe, schema, runtime = layers["safe_json"], layers["json_schema"], layers["runtime_parser"]
    try:
        data = read_json_object(path)
    except (OSError, ValueError) as exc:
        safe.fail(_read_message(exc))
        for layer in (schema, runtime):
            layer.skip("Not run: the suite file was not readable as bounded safe JSON.")
        return None
    safe.begin()
    _run_schema(schema, data)
    try:
        suite = parse_repository_suite(data)
    except ValidationError as exc:
        for line in _error_lines(exc):
            runtime.fail(line)
        return None
    except (ValueError, TypeError):
        runtime.fail("Suite failed strict runtime parsing.")
        return None
    runtime.begin()
    return suite


def _carrier_rules(path: str) -> list[str]:
    parts = [part.casefold() for part in PurePosixPath(path).parts]
    if not parts:
        return []
    rules = {_CARRIER_DIRECTORIES[part] for part in parts[:-1] if part in _CARRIER_DIRECTORIES}
    name = parts[-1]
    if name == ".git":
        rules.add("git_metadata")
    if name in _CARRIER_FILES:
        rules.add(_CARRIER_FILES[name])
    if _PATCH_FILE.fullmatch(name):
        rules.add("reference_patch_file")
    return sorted(rules)


def _check_leakage(layer: _Layer, suite, manifests: list, incomplete: bool) -> None:
    layer.begin()
    if incomplete:
        layer.fail(
            "Evaluator metadata for the leakage check is unavailable; the check is incomplete."
        )
    needles: dict[str, str] = {}
    public_labels = set(_PUBLIC_LABELS)
    for manifest in manifests:
        if manifest.upstream_url:
            project = PurePosixPath(urlsplit(manifest.upstream_url).path).name.removesuffix(".git")
            if project:
                public_labels.add(_norm(project))

    def add(kind: str, value) -> None:
        if isinstance(value, str) and value:
            if kind in {"case_id", "source_group", "issue_id"} and _norm(value) in public_labels:
                return
            needles.setdefault(_norm(value), kind)

    for case in suite.cases:
        add("case_id", case.case_id)
        add("source_group", case.source_group)
        for issue in case.issues:
            add("issue_id", issue.issue_id)
    for manifest in manifests:
        for alias in manifest.aliases:
            add("advisory_alias", alias)
        add("reference_url", manifest.advisory_url)
        if manifest.revisions is not None:
            add("reference_revision", manifest.revisions.vulnerable)
            add("reference_revision", manifest.revisions.fixed)
        for artifact in manifest.artifacts:
            add("reference_url", artifact.source_url)
        add("oracle_identifier", manifest.oracle.oracle_id)
        add("oracle_identifier", manifest.oracle.sha256)
    for index, case in enumerate(suite.cases):
        texts = [("instructions", case.instructions), ("task", case.task), ("pr", case.pr)]
        untrusted_text = getattr(case.exposure, "untrusted_text", None)
        if untrusted_text is not None:
            texts.append(("exposure.untrusted_text", untrusted_text))
        for number, file in enumerate(case.files):
            for rule in _carrier_rules(file.path):
                layer.fail(f"case {index}: files[{number}].path matches the {rule} carrier rule.")
            texts.append((f"files[{number}].path", file.path))
            texts.append((f"files[{number}].content", file.content))
        for label, text in texts:
            haystack = _norm(text)
            for kind in sorted({kind for needle, kind in needles.items() if needle in haystack}):
                layer.fail(f"case {index}: {label} contains evaluator-only {kind} text.")
    if manifests:
        layer.note("Checked suite identifiers and supplied or registered manifest metadata.")
    else:
        layer.note(
            "Checked suite identifiers and path rules only; no manifest metadata was available."
        )


def _load_splits(path: Path):
    try:
        document = read_json_object(path)
    except (OSError, ValueError) as exc:
        return None, ["splits: " + _read_message(exc)]
    try:
        return _strict_json(_Splits, document), []
    except ValidationError as exc:
        return None, ["splits: " + line for line in _error_lines(exc)]
    except (ValueError, TypeError):
        return None, ["splits: invalid shape."]


def _check_splits(layer, suite, splits, split_failures, manifests, incomplete) -> None:
    layer.begin()
    for message in split_failures:
        layer.fail(message)
    if incomplete:
        layer.fail("A requested manifest was invalid, so its split could not be checked.")
    groups = {case.source_group for case in suite.cases}
    declared: dict[str, str] = {}
    if splits is not None:
        partitions = {
            "development": splits.partitions.development,
            "held_out": splits.partitions.held_out,
        }
        names = [group for items in partitions.values() for group in items]
        if len(names) != len(set(names)):
            layer.fail("A source group appears more than once in the split assignment.")
        for split, items in partitions.items():
            for group in items:
                declared.setdefault(group, split)
        unknown = len(set(names) - groups)
        if unknown:
            layer.fail(f"{unknown} split source group(s) are absent from this suite.")
    from_manifests: dict[str, str] = {}
    conflicts = 0
    for manifest in manifests:
        if from_manifests.setdefault(manifest.source_group, manifest.split) != manifest.split:
            conflicts += 1
    if conflicts:
        layer.fail(f"{conflicts} manifest(s) assign conflicting splits to one source group.")
    if splits is not None:
        mismatched = sum(
            1
            for group, split in from_manifests.items()
            if group in declared and declared[group] != split
        )
        if mismatched:
            layer.fail(f"{mismatched} manifest split(s) disagree with the splits file.")
    else:
        declared = from_manifests
    if splits is not None or manifests:
        missing = len(groups - declared.keys())
        if missing:
            layer.fail(f"{missing} suite source group(s) have no split assignment.")
    layer.note(
        "Split labels are declarations. Independence and training non-exposure are not inferred."
    )


def _load_manifest(path: Path):
    try:
        document = read_json_object(path)
    except (OSError, ValueError) as exc:
        return None, [_read_message(exc)]
    inventory = document
    if "inventory" in document:
        inventory = document["inventory"]
        if (
            set(document) != _WRAPPER_KEYS
            or type(document["schema_version"]) is not int
            or document["schema_version"] != 1
            or document["scope"] != "evaluator_only"
            or not isinstance(inventory, dict)
            or not isinstance(document["authority"], dict)
            or not isinstance(document["layers"], dict)
            or not isinstance(document["inventory_sha256"], str)
        ):
            return None, ["Evaluator manifest wrapper has an unexpected shape."]
        try:
            digest = json_digest(inventory)
        except (ValueError, TypeError):
            return None, ["Evaluator inventory could not be represented as canonical UTF-8 JSON."]
        if document["inventory_sha256"] != digest:
            return None, ["Declared inventory digest does not match the inventory."]
    try:
        return parse_corpus_manifest(inventory), []
    except ValidationError as exc:
        return None, _error_lines(exc)
    except ValueError:
        return None, ["Manifest must be a JSON object."]


def _load_manifests(paths: tuple):
    manifests, failures = [], []
    for index, path in enumerate(paths):
        manifest, messages = _load_manifest(Path(path))
        if manifest is None:
            failures.extend(f"manifest {index}: {message}" for message in messages)
        else:
            manifests.append((index, manifest))
    return manifests, failures


def _bind_registry(name: str, suite) -> _Binding:
    registration = get_corpus(name)
    try:
        cases = registration.build_cases()
        inventory = parse_corpus_manifest(registration.evaluator_manifest()["inventory"])
    except (ValueError, OSError, KeyError, TypeError):
        return _Binding(
            registration,
            None,
            False,
            ("The registered corpus could not be verified against its code anchors.",),
        )
    registered = {case.case_id: case_digest(case) for case in cases}
    supplied = {case.case_id: case_digest(case) for case in suite.cases}
    differ = sum(
        1 for key, value in supplied.items() if key in registered and registered[key] != value
    )
    missing = len(registered.keys() - supplied.keys())
    extra = len(supplied.keys() - registered.keys())
    if differ or missing or extra:
        message = (
            "Suite case digests do not match the registered corpus "
            f"({differ} differ, {missing} missing, {extra} extra)."
        )
        return _Binding(registration, inventory, False, (message,))
    return _Binding(registration, inventory, True, ())


def _check_case(layer: _Layer, index: int, case, manifest: CorpusManifest, stats: dict) -> None:
    files = {file.path: file.content for file in case.files}
    mappings = [item for item in manifest.slice_mappings if item.variant == case.variant]
    expected = {item.reviewer_path for item in mappings} | set(manifest.synthetic_reviewer_paths)
    if expected != set(files):
        layer.fail(
            f"case {index}: reviewer paths differ from the manifest inventory "
            f"({len(expected - files.keys())} missing, {len(files.keys() - expected)} extra)."
        )
        return
    artifacts = {(item.variant, item.path): item for item in manifest.artifacts}
    bad = 0
    for mapping in mappings:
        artifact = artifacts.get((mapping.variant, mapping.artifact_path)) or artifacts.get(
            ("shared", mapping.artifact_path)
        )
        if artifact is None:
            bad += 1
        elif mapping.transformation == "adapted":
            stats["adapted"] += 1
        else:
            raw = files[mapping.reviewer_path].encode("utf-8")
            if len(raw) != artifact.size or hashlib.sha256(raw).hexdigest() != artifact.sha256:
                bad += 1
            else:
                stats["verbatim"] += 1
                stats["observed"].add((manifest.source_group, artifact.variant, artifact.path))
    if bad:
        layer.fail(
            f"case {index}: {bad} verbatim artifact(s) differ from the declared hash or size."
        )


def _check_inventory(layer: _Layer, suite, manifests: list) -> int:
    by_group: dict[str, list] = {}
    for manifest in manifests:
        by_group.setdefault(manifest.source_group, []).append(manifest)
    duplicate = sum(1 for items in by_group.values() if len(items) > 1)
    if duplicate:
        layer.fail(f"{duplicate} source group(s) are covered by more than one manifest.")
    groups = {case.source_group for case in suite.cases}
    missing = len(groups - by_group.keys())
    extra = len(by_group.keys() - groups)
    if missing:
        layer.fail(f"{missing} suite source group(s) are not covered by a manifest.")
    if extra:
        layer.fail(f"{extra} manifest source group(s) are absent from the suite.")
    stats = {"verbatim": 0, "adapted": 0, "observed": set()}
    for index, case in enumerate(suite.cases):
        items = by_group.get(case.source_group)
        if items and len(items) == 1:
            _check_case(layer, index, case, items[0], stats)
    layer.note(
        f"{stats['verbatim']} verbatim file(s) matched declared hash and size; "
        f"{stats['adapted']} adapted file mapping(s) are declared and unverified."
    )
    declared = {
        (manifest.source_group, item.variant, item.path)
        for manifest in manifests
        for item in manifest.artifacts
    }
    return len(declared - stats["observed"])


def _check_provenance(layer, suite, external, failures, binding, covering) -> None:
    layer.begin()
    for message in failures:
        layer.fail(message)
    if binding is not None:
        for message in binding.messages:
            layer.fail(message)
        if binding.inventory is not None:
            registered = binding.inventory.model_dump(mode="json")
            for index, manifest in external:
                if manifest.model_dump(mode="json") != registered:
                    layer.fail(
                        f"manifest {index}: supplied metadata differs from the registered manifest."
                    )
    if not (binding is not None and not binding.bound and not external):
        unverified = _check_inventory(layer, suite, covering)
        if unverified:
            if binding is not None and binding.bound and layer.status == "passed":
                layer.note(
                    f"{unverified} artifact(s) outside reviewer files were checked by the "
                    "registered corpus byte verifier."
                )
            else:
                layer.inventory_only(
                    f"Inventory only: {unverified} declared artifact(s), including unmapped "
                    "licenses/notices, have no comparable bytes here. Their bytes and provenance "
                    "are unverified."
                )
    layer.note(
        "Source authenticity is unverified for supplied manifests; "
        "hashes and authority claims are descriptive only."
    )


def _run_behavior(layer: _Layer, registration):
    try:
        result = registration.verify_behavior()
    except Exception:  # noqa: BLE001
        layer.fail("The bundled behavior check could not complete.")
        return {"reproduced": False}
    reproduced = isinstance(result, dict) and result.get("reproduced") is True
    if reproduced:
        layer.begin()
        layer.note("The bundled behavior oracle reproduced the expected behavior.")
    else:
        layer.fail("The bundled behavior check did not reproduce the expected behavior.")
    return {"reproduced": reproduced}


def _fixture_files(root: Path):
    found, irregular = set(), 0
    for directory, names, files in os.walk(root, followlinks=False):
        base = Path(directory)
        irregular += sum(1 for name in names if (base / name).is_symlink())
        for name in files:
            path = base / name
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                irregular += 1
            found.add(path.relative_to(root).as_posix())
        if len(found) > MAX_FIXTURE_FILES:
            irregular += 1
            break
    return found, irregular


def _check_installed_package(layer: _Layer, registration) -> None:
    layer.begin()
    base = Path(__file__).resolve().parent
    missing = 0
    for name in HARNESS_FILES:
        try:
            regular = stat.S_ISREG((base / name).lstat().st_mode)
        except OSError:
            regular = False
        missing += not regular
    if missing:
        layer.fail(f"{missing} bundled runtime file(s) are missing or not regular files.")
    try:
        root, declared = registration.package_inventory()
        expected = set(declared)
        found, irregular = _fixture_files(Path(root))
    except (KeyError, ValueError, OSError, TypeError):
        layer.fail("The bundled fixture inventory could not be derived or verified.")
        return
    if irregular or found != expected:
        layer.fail(
            f"Bundled fixtures differ from the verified inventory ({len(expected - found)} missing, "
            f"{len(found - expected)} extra, {irregular} irregular)."
        )
    layer.note(
        "Checked the installed runtime files and fixture inventory only; no archive was built."
    )


def _check_options(manifests, splits_path, corpus_name, verify, check_package, schema_only) -> None:
    if len(manifests) > MAX_MANIFESTS:
        raise ValueError(f"At most {MAX_MANIFESTS} manifests may be supplied")
    if corpus_name is not None and (
        not isinstance(corpus_name, str) or corpus_name not in corpus_names()
    ):
        raise ValueError("Unknown upstream corpus")
    if schema_only and (
        manifests or splits_path is not None or corpus_name is not None or verify or check_package
    ):
        raise ValueError(
            "--schema-only cannot be combined with --manifest, --splits, --corpus, --verify "
            "or --check-package"
        )
    if (verify or check_package) and corpus_name is None:
        raise ValueError("--verify and --check-package require --corpus")


def _result(layers, suite, schema_only, corpus, behavior, bundled) -> dict:
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "valid": all(layer.status != "failed" for layer in layers.values()),
        "mode": "schema_only" if schema_only else "full",
        "layers": {name: layer.as_dict() for name, layer in layers.items()},
        "suite": None
        if suite is None
        else {
            "case_count": len(suite.cases),
            "source_group_count": len({case.source_group for case in suite.cases}),
            "suite_sha256": json_digest(suite.model_dump(mode="json")),
        },
        "corpus": corpus,
        "behavior": behavior,
        "admission": "not_established",
        "source_authenticity": "unverified_for_external_metadata",
        "bundled_bytes": "anchored_verified" if bundled else "not_checked",
        "independence": "not_inferred",
        "notes": list(NOTES),
    }


def validate_suite(
    suite_path,
    *,
    manifest_paths=(),
    splits_path=None,
    corpus_name=None,
    verify=False,
    check_package=False,
    schema_only=False,
) -> dict:
    """Return a bounded JSON-safe result. Invalid input is reported, never raised.

    Only contradictory or unknown options raise ValueError.
    """
    manifest_paths = tuple(manifest_paths)
    _check_options(manifest_paths, splits_path, corpus_name, verify, check_package, schema_only)
    layers = {name: _Layer() for name in LAYER_NAMES}
    suite = _read_suite(layers, Path(suite_path))
    if schema_only or suite is None:
        reason = (
            "Not requested: schema-only mode."
            if schema_only
            else "Not run: the suite did not pass strict parsing."
        )
        for name in LAYER_NAMES[3:]:
            layers[name].skip(reason)
        return _result(layers, suite, schema_only, None, None, False)

    external, failures = _load_manifests(manifest_paths)
    splits, split_failures = (None, []) if splits_path is None else _load_splits(Path(splits_path))
    binding = _bind_registry(corpus_name, suite) if corpus_name is not None else None
    registered = binding.inventory if binding is not None else None
    known = [manifest for _, manifest in external] + ([registered] if registered else [])
    _check_leakage(
        layers["leakage"],
        suite,
        known,
        bool(failures) or (binding is not None and registered is None),
    )
    covering = [manifest for _, manifest in external]
    if (
        binding is not None
        and binding.bound
        and binding.inventory.source_group not in {manifest.source_group for manifest in covering}
    ):
        covering.append(binding.inventory)
    if splits_path is None and not covering and not failures:
        layers["source_group_split"].skip("Not requested: no splits file or manifest supplied.")
    else:
        _check_splits(
            layers["source_group_split"], suite, splits, split_failures, covering, bool(failures)
        )
    provenance = layers["provenance_license"]
    if not manifest_paths and corpus_name is None:
        provenance.skip("Not requested: no manifest or corpus supplied.")
    else:
        _check_provenance(provenance, suite, external, failures, binding, covering)

    allowed = (
        binding is not None
        and binding.bound
        and provenance.status == "passed"
        and all(layers[name].status != "failed" for name in LAYER_NAMES[:6])
    )
    blocked = "Blocked: requires an exact binding to the registered corpus; nothing was executed."
    behavior = None
    for name, requested in (("bundled_behavior", verify), ("installed_package", check_package)):
        layer = layers[name]
        if not requested:
            layer.skip("Not requested.")
        elif not allowed:
            layer.fail(blocked)
        elif name == "bundled_behavior":
            behavior = _run_behavior(layer, binding.registration)
        else:
            _check_installed_package(layer, binding.registration)
    corpus = None if binding is None else {"name": corpus_name, "bound_to_registry": binding.bound}
    return _result(layers, suite, False, corpus, behavior, registered is not None)


def _new_output_path(value) -> Path:
    """Refuse symlinked or existing outputs before any validation work starts."""
    from .repository_runner import _path_without_symlinks

    output = _path_without_symlinks(Path(value), "validation output")
    if os.path.lexists(output):
        raise ValueError("The validation output path already exists; it is never overwritten.")
    return output


def _emit(value: dict, output: Path | None) -> Path | None:
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output is None:
        print(text, end="")
        return None
    from .repository_adjudication import write_new_text

    return write_new_text(output, text, "validation output")


def validate_suite_command(args) -> int:
    output = None if args.output is None else _new_output_path(args.output)
    result = validate_suite(
        args.suite,
        manifest_paths=tuple(args.manifest or ()),
        splits_path=args.splits,
        corpus_name=args.corpus,
        verify=args.verify,
        check_package=args.check_package,
        schema_only=args.schema_only,
    )
    written = _emit(result, output)
    if written is not None:
        print("Validation result: " + str(written))
        print("Valid: " + str(result["valid"]).lower())
    return 0 if result["valid"] else 2


def suite_schema_command(args) -> int:
    output = None if args.output is None else _new_output_path(args.output)
    written = _emit(
        repository_suite_schema(schema_version=getattr(args, "schema_version", 1)), output
    )
    if written is not None:
        print("Suite schema: " + str(written))
    return 0
