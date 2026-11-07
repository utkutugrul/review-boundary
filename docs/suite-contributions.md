# Suite contributions

How to propose a repository case or suite and what the tools do and do not establish.

## Export the schema

```sh
review-boundary suite-schema --output suite.schema.json
```

The JSON Schema is derived from the Pydantic model graph, so there is no second hand-written
schema. It cannot express every rule. Python cross-field checks in `RepositoryCase` and the
suite envelope stay authoritative, and a file can satisfy the schema yet fail them.

## Validator layers

```sh
review-boundary validate-suite --suite suite.json [--manifest manifest.json]... \
  [--splits splits.json] [--corpus pyjwt] [--verify] [--check-package] [--schema-only] \
  [--output result.json]
```

Each layer reports `passed`, `failed`, `inventory_only` or `not_requested`. A skipped layer never reports
success.

| Layer | Checks |
| --- | --- |
| `safe_json` | Bounded regular file, no duplicate keys, finite numbers, bounded nesting. |
| `json_schema` | The exported schema. |
| `runtime_parser` | The strict runtime models and their cross-field invariants. |
| `leakage` | Evaluator-only identifiers, URLs, revisions and oracle identity absent from reviewer-visible text and paths. |
| `source_group_split` | Every source group has exactly one split, and manifests agree with the splits file. |
| `provenance_license` | Manifest coverage, reviewer paths, and size and SHA-256 of verbatim files. Unmapped or adapted artifacts remain `inventory_only` unless independently verified by a registered corpus. |
| `bundled_behavior` | Only with `--corpus` and `--verify`: the registered oracle. |
| `installed_package` | Only with `--corpus` and `--check-package`: installed runtime files and bundled fixtures. |

`--schema-only` runs only the first three layers and cannot be combined with the other options.
Suites, manifests and splits are read as data. The validator never imports or runs candidate
source, setup files or tests.

## Source groups and splits

A source group is one upstream issue or one original scenario. Its vulnerable and fixed
variants and every context condition belong to one group, so they must share one split. Four
conditions produce four trials but one independent source group. `splits.json` has this shape:

```json
{"schema_version": 1, "partitions": {"development": ["my_group"], "held_out": []}}
```

Split labels are declarations. The tools do not infer independence or that a case was never
seen in training. Do not tune a reviewer on a `held_out` group and keep the label.

## Inventory is not admission

A manifest inventories artifacts, hashes, licenses, mappings, synthetic files, modifications,
dependency lock status and oracle identity. Matching a declared hash to reviewer bytes proves
internal consistency. External hashes alone authenticate no upstream source; source
authenticity stays unverified for supplied metadata. Every
result reports `admission: not_established`. Admission is a manual decision about license,
provenance, behavior evidence and split assignment.

The manifest `provenance_kind` is `exact_upstream`, `adapted_upstream` or
`original_calibration`. An original manifest declares null upstream URLs, revisions and dates
and no aliases, so it never carries invented upstream pins.

License and notice artifacts may stay evaluator-only. They do not have to expose evaluator
answers in reviewer inputs. When no comparable bytes are available, their declarations remain
`inventory_only`, never a successful byte or provenance check. Licenses are recorded per
artifact, including separate per-file license and notice paths where the root license differs.

Oracle kind, source digest, controls, limitations and OS sandbox status are declarations in
external manifests; the validator does not read or run an external oracle. Python, Node and
Rust oracle identities can be inventoried without adding executors. Missing lock files stay
explicitly `missing`; a source or build script in the inventory does not authorize execution.
An upstream file larger than the runtime file cap can be inventoried, but needs a declared
adaptation or a future schema version before it can appear in a runnable suite.

## Registry verification scope

`--verify` and `--check-package` need `--corpus NAME` and run only when the suite digests match
that registered corpus exactly. `--verify` runs the registered bundled oracle. `--check-package`
checks the installed runtime files and bundled fixture inventory and builds no archive. Neither
runs supplied code, and neither applies to a contributed suite that is not registered. Corpus
names come from a static registry, never from a manifest field.

## Original template workflow

```sh
review-boundary case-template --output ./my-case --name my_case
```

`--name` is a lowercase slug (a letter, then lowercase letters, digits or underscores, at most
32 characters) and defaults to `example`. The output must be a new directory in an existing
parent with no symlink components. It is created private (mode 0700), files are written
exclusively with mode 0600, and failed-run cleanup checks recorded device/inode identities.
It removes only still-owned files and empty directories, preserving replacements and unknown
contents. The generator validates
everything in memory first and loads no external code.

The template is a complete original calibration case based on the tenant flow demo. It has
`suite.json`, `manifest.json`, `splits.json`, an evaluator-only `case.py`, `LICENSE`,
`tests/test_behavior.py` and a README that explains editing, validation and manual admission.
Case IDs are opaque and the four conditions form one group, `original_<name>`.

`tests/test_behavior.py` is an independent behavior oracle. It executes the template's own
source strings in temporary in-memory modules, but only when you run
`python tests/test_behavior.py`. The generator and `validate-suite` never run it.

## Runtime authority

Runners parse suites with the same strict parser used here. A manifest, splits file, README
claim or validation result never changes scoring, and a validated suite is not trusted
beyond what the runtime models enforce.

## The 32-case limit

Suite schema v1 allows 1 through 32 cases. The limit is fixed and is not raised in place. For
a larger corpus, split it into several suites by source group so no group is divided. A higher
limit needs a new schema version with adversarial tests for size and memory bounds.
