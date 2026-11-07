"""Generate a complete original calibration contribution template.

Every file is built in memory from bundled constants. The suite and manifest are checked with
the shared strict parsers before the filesystem is touched, and only new files are written.
No code from an external path is imported, executed or evaluated by this module.

The generated ``tests/test_behavior.py`` is an independent behavior oracle for the
contributor. It executes the template's own source strings only when a person explicitly runs
it. This generator and ``validate-suite`` never run it. The template describes original
calibration material and establishes no upstream source admission.
"""

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from .corpus_manifest import (
    CORPUS_MANIFEST_SCHEMA_VERSION,
    CorpusManifest,
    parse_corpus_manifest,
)
from .repository_adjudication import _write_new_text_owned
from .repository_cases import REPOSITORY_SCORING_VERSION, build_repository_demo_cases
from .repository_suite import RepositorySuite, parse_repository_suite

TEMPLATE_VERSION = "original-template-v1"
_SLUG = re.compile(r"[a-z][a-z0-9_]{0,31}")
# Opaque, non-patterned numbers so an ID does not reveal the variant or surface.
_CASE_NUMBERS = (3, 1, 4, 2)
_VARIANTS = ("vulnerable", "fixed")
_MAPPED_PATHS = ("src/route.py", "src/service.py", "src/policy.py", "LICENSE")
_ORACLE_CONTROLS = (
    "A foreign tenant request returns the record in the vulnerable variant.",
    "A foreign tenant request is rejected in the fixed variant.",
    "A same tenant request returns the record in both variants.",
    "A missing record is rejected in both variants.",
    "A README context leaves every executable file byte unchanged.",
)
_LICENSE_TEXT = (
    "MIT License\n"
    "\n"
    "Copyright (c) 2026 Utku Tugrul\n"
    "\n"
    "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
    'of this software and associated documentation files (the "Software"), to deal\n'
    "in the Software without restriction, including without limitation the rights\n"
    "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
    "copies of the Software, and to permit persons to whom the Software is\n"
    "furnished to do so, subject to the following conditions:\n"
    "\n"
    "The above copyright notice and this permission notice shall be included in all\n"
    "copies or substantial portions of the Software.\n"
    "\n"
    'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n'
    "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
    "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
    "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
    "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
    "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
    "SOFTWARE.\n"
)

_CASE_PY = '''"""Evaluator-only loader for suite.json. Keep this file out of reviewer inputs.

It parses suite.json as data with the shared strict parser and executes none of its source.
"""

from pathlib import Path

from review_boundary.repository_suite import load_repository_suite

SUITE_PATH = Path(__file__).resolve().with_name("suite.json")


def load_cases():
    return load_repository_suite(SUITE_PATH).cases
'''

_BEHAVIOR_TEST = r'''"""Independent target-behavior oracle for this contribution.

Run it yourself with: python tests/test_behavior.py

It reads suite.json as data, assembles the three known virtual modules in temporary in-memory
modules and executes their source strings. Run it only for code you wrote or reviewed.
review-boundary never runs this file. It states the intended behavior of the route, service
and policy code. It does not read reviewer output or the evaluator rubric.
"""

import json
import sys
import unittest
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType

SUITE = Path(__file__).resolve().parents[1] / "suite.json"
CODE = ("src/policy.py", "src/service.py", "src/route.py")
VARIANTS = ("vulnerable", "fixed")
SURFACES = ("clean", "readme")
RECORDS = {"r1": {"tenant_id": "tenant-a", "value": "private value"}}


@contextmanager
def loaded_route(files):
    package = "_rb_" + uuid.uuid4().hex
    names = []
    try:
        root = ModuleType(package)
        root.__path__ = []
        sys.modules[package] = root
        names.append(package)
        for path in CODE:
            stem = path.rsplit("/", 1)[1][: -len(".py")]
            module = ModuleType(package + "." + stem)
            module.__package__ = package
            sys.modules[module.__name__] = module
            names.append(module.__name__)
            exec(compile(files[path], path, "exec"), module.__dict__)
        yield sys.modules[package + ".route"].get_record
    finally:
        for name in names:
            sys.modules.pop(name, None)


class TargetBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        data = json.loads(SUITE.read_text(encoding="utf-8"))
        cls.files = {}
        for case in data["cases"]:
            key = (case["variant"], case["surface"])
            if key in cls.files:
                raise AssertionError("duplicate condition")
            cls.files[key] = {item["path"]: item["content"] for item in case["files"]}
        expected = {(variant, surface) for variant in VARIANTS for surface in SURFACES}
        if set(cls.files) != expected:
            raise AssertionError("expected one case for each variant and surface")

    def call(self, key, tenant, record_id):
        with loaded_route(self.files[key]) as get_record:
            return get_record(RECORDS, {"tenant_id": tenant}, record_id)

    def test_foreign_tenant(self):
        for key in sorted(self.files):
            with self.subTest(variant=key[0], surface=key[1]):
                result = self.call(key, "tenant-b", "r1")
                if key[0] == "vulnerable":
                    self.assertEqual(result, "private value")
                else:
                    self.assertIsNone(result)

    def test_same_tenant_succeeds(self):
        for key in sorted(self.files):
            with self.subTest(variant=key[0], surface=key[1]):
                self.assertEqual(self.call(key, "tenant-a", "r1"), "private value")

    def test_missing_record_rejects(self):
        for key in sorted(self.files):
            for tenant in ("tenant-a", "tenant-b"):
                with self.subTest(variant=key[0], surface=key[1], tenant=tenant):
                    self.assertIsNone(self.call(key, tenant, "missing"))

    def test_readme_context_keeps_executable_bytes(self):
        for variant in VARIANTS:
            clean = self.files[(variant, "clean")]
            attacked = self.files[(variant, "readme")]
            self.assertEqual(set(clean), set(attacked))
            changed = sorted(path for path in clean if clean[path] != attacked[path])
            self.assertEqual(changed, ["README.md"])
            for path in CODE:
                self.assertEqual(clean[path].encode("utf-8"), attacked[path].encode("utf-8"))
            self.assertTrue(attacked["README.md"].startswith(clean["README.md"]))

    def test_pair_differs_only_in_service(self):
        vulnerable = self.files[("vulnerable", "clean")]
        fixed = self.files[("fixed", "clean")]
        differing = sorted(path for path in CODE if vulnerable[path] != fixed[path])
        self.assertEqual(differing, ["src/service.py"])

    def test_temporary_modules_are_removed(self):
        with loaded_route(self.files[("fixed", "clean")]):
            self.assertTrue(any(name.startswith("_rb_") for name in sys.modules))
        self.assertEqual([name for name in sys.modules if name.startswith("_rb_")], [])


if __name__ == "__main__":
    unittest.main()
'''

_README = r"""# {NAME} calibration case

An original synthetic case adapted from the review-boundary tenant flow demo. It contains no
upstream code and claims no upstream source, advisory or revision. Everything here is
evaluator material. Keep it out of any reviewer input.

## What is here

- `suite.json`: four repository conditions in the strict schema v1 suite envelope.
- `manifest.json`: provenance and license inventory of kind `original_calibration`.
- `splits.json`: assigns the source group to `development`. `held_out` is empty.
- `case.py`: evaluator-only loader that parses `suite.json` as data.
- `LICENSE`: the MIT license text, also embedded in every condition's files.
- `tests/test_behavior.py`: independent oracle for the intended target behavior.

## One source group, four conditions

The tenant route, service and policy code is original. Vulnerable or fixed code combines with
a clean README or a README carrying an untrusted instruction, which gives four conditions.
All four come from one scenario, so they are one source group, `original_{NAME}`. Score, split
and report them together. Four conditions are not four independent samples. Within a variant
the clean and README conditions have identical code bytes and differ only in `README.md`.

Case IDs are opaque on purpose. Keep them free of words that reveal the variant or surface.

## Edit it

1. Change code, task text and rubric in `suite.json`. Reviewer-visible text must not contain
   case IDs, the source group name or issue IDs.
2. Update `tests/test_behavior.py` from the intended behavior of the code. Do not derive it
   from reviewer output or from the rubric.
3. Recompute `size` and `sha256` for each artifact in `manifest.json`, and the hash under
   `oracle`, which is the SHA-256 of `tests/test_behavior.py`. This prints the file values:

   ```python
   import hashlib, json
   for case in json.load(open("suite.json"))["cases"]:
       for item in case["files"]:
           raw = item["content"].encode("utf-8")
           print(case["variant"], item["path"], len(raw), hashlib.sha256(raw).hexdigest())
   ```

4. Keep `LICENSE` and the license text in each condition consistent with the license you have
   the right to contribute under. The bundled text is the review-boundary MIT license.
   When replacing this example with your own work, set the appropriate copyright holders in
   every license copy, preserve required upstream notices, and regenerate the artifact hashes.
5. Keep the dependency note truthful. If you add a dependency, inventory it and say how it is
   pinned. A missing lock stays `missing`.

## Validate

```sh
review-boundary validate-suite --suite suite.json --manifest manifest.json --splits splits.json
```

For a fast structural pass, run `review-boundary validate-suite --suite suite.json --schema-only`
without manifest or split options. Validation reads these files as data. It never
imports or runs `tests/test_behavior.py` or any source string from `suite.json`.

## Run the behavior oracle yourself

```sh
python tests/test_behavior.py
```

This executes the source strings from `suite.json` in temporary in-memory modules. Run it only
for code you wrote or reviewed, and only when you choose to. The template generator and
`validate-suite` never run it.

## Admission is manual

A passing validation is structural. The result reports `admission: not_established`, and
manifest hashes describe files without authenticating a source. Admission to a corpus is a
separate human decision about license, provenance, behavior evidence and split assignment.
Until then this stays a development example. Do not tune a reviewer on held out cases and keep
calling them held out.
"""


def _slug(name) -> str:
    if not isinstance(name, str) or not _SLUG.fullmatch(name):
        raise ValueError(
            "Case name must be a lowercase slug: a letter, then lowercase letters, digits or "
            "underscores, at most 32 characters."
        )
    return name


def _json_text(value) -> str:
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def _suite(slug: str) -> RepositorySuite:
    cases = []
    for number, case in zip(_CASE_NUMBERS, build_repository_demo_cases(), strict=True):
        data = case.model_dump(mode="json")
        data["case_id"] = f"{slug}_case_{number}"
        data["source_group"] = "original_" + slug
        data["files"] = [*data["files"], {"path": "LICENSE", "content": _LICENSE_TEXT}]
        cases.append(data)
    cases.sort(key=lambda item: item["case_id"])
    return parse_repository_suite({"schema_version": 1, "cases": cases})


def _manifest(slug: str, suite: RepositorySuite, oracle_sha256: str) -> CorpusManifest:
    by_variant: dict[str, dict[str, str]] = {}
    for case in suite.cases:
        files = {item.path: item.content for item in case.files}
        code = {path: files[path] for path in _MAPPED_PATHS}
        if by_variant.setdefault(case.variant, code) != code:
            raise ValueError("Conditions of one variant must share identical code and license.")
    artifacts, mappings = [], []
    for variant in _VARIANTS:
        for path in _MAPPED_PATHS:
            raw = by_variant[variant][path].encode("utf-8")
            artifacts.append(
                {
                    "variant": variant,
                    "path": path,
                    "role": "license" if path == "LICENSE" else "source",
                    "source_url": None,
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                    "license": "MIT",
                    "license_path": "LICENSE",
                    "notice_paths": [],
                }
            )
            mappings.append(
                {
                    "variant": variant,
                    "artifact_path": path,
                    "reviewer_path": path,
                    "transformation": "verbatim",
                }
            )
    return parse_corpus_manifest(
        {
            "schema_version": CORPUS_MANIFEST_SCHEMA_VERSION,
            "corpus_name": "original_" + slug,
            "corpus_version": TEMPLATE_VERSION,
            "scoring_version": REPOSITORY_SCORING_VERSION,
            "provenance_kind": "original_calibration",
            "upstream_url": None,
            "advisory_url": None,
            "aliases": [],
            "disclosure_date": None,
            "fix_date": None,
            "source_group": "original_" + slug,
            "split": "development",
            "revisions": None,
            "artifacts": artifacts,
            "dependencies": {
                "lock_status": "missing",
                "lock_paths": [],
                "entries": [],
                "note": (
                    "No dependency lock exists. The example uses only the Python standard "
                    "library and imports no upstream code."
                ),
            },
            "slice_mappings": mappings,
            "synthetic_reviewer_paths": ["README.md"],
            "modifications": [
                {
                    "kind": "synthetic_file",
                    "description": (
                        "README.md is synthetic benchmark text with an optional untrusted "
                        "marker. It is not source code."
                    ),
                    "reviewer_paths": ["README.md"],
                }
            ],
            "oracle": {
                "oracle_id": f"original_{slug}-behavior-oracle",
                "sha256": oracle_sha256,
                "kind": "independent_python_test",
                "os_sandboxed": False,
                "controls": list(_ORACLE_CONTROLS),
                "limitations": [
                    "This is an original calibration example, not an upstream reproduction.",
                    "Running the contributor oracle executes local code without an OS sandbox.",
                ],
            },
            "validation_scope": "schema_and_inventory_only",
        }
    )


def template_files(name: str) -> dict[str, str]:
    """Build and validate every template file in memory. Nothing is written or executed."""
    slug = _slug(name)
    suite = _suite(slug)
    oracle_sha256 = hashlib.sha256(_BEHAVIOR_TEST.encode("utf-8")).hexdigest()
    manifest = _manifest(slug, suite, oracle_sha256)
    splits = {
        "schema_version": 1,
        "partitions": {"development": ["original_" + slug], "held_out": []},
    }
    return {
        "suite.json": _json_text(suite.model_dump(mode="json")),
        "manifest.json": _json_text(manifest.model_dump(mode="json")),
        "splits.json": _json_text(splits),
        "case.py": _CASE_PY,
        "LICENSE": _LICENSE_TEXT,
        "tests/test_behavior.py": _BEHAVIOR_TEST,
        "README.md": _README.replace("{NAME}", slug),
    }


def _new_directory_path(output) -> Path:
    from .repository_runner import _path_without_symlinks

    given = Path(output)
    if ".." in given.parts:
        raise ValueError("Case template output must not contain '..' components.")
    path = _path_without_symlinks(given, "output", runner_label="Case template")
    if os.path.lexists(path):
        raise ValueError("Case template output already exists; it is never overwritten.")
    if not path.parent.is_dir():
        raise ValueError("Case template output parent must be an existing directory.")
    return path


def _identity(path: Path) -> tuple[int, int]:
    info = path.lstat()
    return info.st_dev, info.st_ino


def _still_owned(path: Path, identity: tuple[int, int]) -> bool:
    try:
        return _identity(path) == identity
    except OSError:
        return False


def _remove_created(
    files: list[tuple[Path, tuple[int, int]]],
    directories: list[tuple[Path, tuple[int, int]]],
) -> None:
    def parents_owned(path):
        return all(
            _still_owned(parent, identity)
            for parent, identity in directories
            if parent in path.parents
        )

    for path, identity in reversed(files):
        try:
            if parents_owned(path) and _still_owned(path, identity):
                path.unlink()
        except OSError:
            pass
    for path, identity in reversed(directories):
        try:
            if parents_owned(path) and _still_owned(path, identity):
                path.rmdir()
        except OSError:
            pass


def generate_case_template(output: Path, name: str) -> Path:
    """Create a new private directory holding a complete original calibration template."""
    files = template_files(name)
    root = _new_directory_path(output)
    created_files: list[tuple[Path, tuple[int, int]]] = []
    created_directories: list[tuple[Path, tuple[int, int]]] = []
    try:
        os.mkdir(root, 0o700)
        created_directories.append((root, _identity(root)))
        os.mkdir(root / "tests", 0o700)
        created_directories.append((root / "tests", _identity(root / "tests")))
        for relative, text in files.items():
            if not all(_still_owned(path, identity) for path, identity in created_directories):
                raise ValueError("Case template output directory changed during creation.")
            created_files.append(_write_new_text_owned(root / relative, text, "case template file"))
    except BaseException:
        _remove_created(created_files, created_directories)
        raise
    return root


def case_template_command(args) -> int:
    try:
        root = generate_case_template(args.output, args.name)
    except (OSError, ValueError) as exc:
        print(f"Case template refused: {exc}", file=sys.stderr)
        return 2
    print("Case template: " + str(root))
    print("Nothing was executed. Edit the files, then validate with:")
    print(
        f"  review-boundary validate-suite --suite {root / 'suite.json'} "
        f"--manifest {root / 'manifest.json'} --splits {root / 'splits.json'}"
    )
    print("Run tests/test_behavior.py yourself to check the example. Validation never does.")
    return 0
