# Corpus research metadata and registered exports

The production registry contains only `pyjwt`. A candidate catalog records local research
metadata. Parsing it does not fetch source, load a runtime, select code, run an oracle,
register a corpus, establish source independence, or decide admission. New real-source
admissions and the six-group benchmark requirement remain open.

Validate and summarize a local catalog:

```sh
review-boundary candidate-catalog --input candidates.json
review-boundary candidate-catalog --input candidates.json --output new-summary.json
```

The optional output must be a new JSON file. The input must be a bounded regular JSON file
of at most 256 KiB, with exact integer `schema_version: 1` and at most 64 unique records.
Unknown fields and execution or admission statuses are refused. Errors do not echo catalog
content. The summary states `admission: not_established`,
`authenticity: unverified_metadata`, and `independence: not_inferred`.

Each record has `candidate_id`, `upstream_url`, nullable `advisory_url`, `aliases`,
`language`, nullable `proposed_source_group`, nullable full-SHA `comparison_revision` and
`selected_change_revision`, `metadata_status`, `runtime_status`, `license_status`,
`disposition`, `evidence_urls`, and `note`. Status vocabularies describe research:

| Field | Values |
| --- | --- |
| `metadata_status` | `unknown`, `researched` |
| `runtime_status` | `unknown`, `requirements_recorded`, `unavailable` |
| `license_status` | `unknown`, `notices_pending`, `inventory_recorded` |
| `disposition` | `research`, `held`, `deferred`, `rejected` |

Revision names do not assert reproduced vulnerable or fixed behavior. A proposed group or
alias does not prove independence. No catalog is automatically loaded by corpus export or
suite validation.

## Registered suite versions

The existing export command retains its default single-suite behavior:

```sh
review-boundary corpus-export --corpus pyjwt --output new-export
review-boundary corpus-export --corpus pyjwt --verify --output new-verified-export
```

A static trusted registration must build an exact tuple of 1 to 1,024 supported cases.
Export reparses the cases, rejects duplicate IDs and mixed versions, and checks the declared
suite schema and scoring contract. Evaluator inventory name, corpus version, and scoring
version must match the registration before output. These consistency checks do not create
independent source authentication or admission.

The default suite cap remains 32. Version 1 preserves its case order, suite serialization,
output names, metadata schema, explicit verification callback, and exit results. An actual
new run naturally has a new timestamp and harness fingerprint. A failed explicit behavior
check writes its result and exits with status 2; a callback exception fails before output.

Version 2 registration dispatch is supported by the software, with suite schema 2,
`repository-payload-v1` scoring, and `reviewboundary.repository-jsonl/2`. Its export metadata
uses schema 2 and explicitly identifies suite schema, scoring, and protocol. There is no
production version 2 registration or reviewed version 2 verification binding in this
increment. Version 2 `--verify` is refused before builder, manifest, or oracle callbacks in
corpus export. Validator behavior verification also refuses version 2 registrations.

## Explicit source-group sharding

```sh
review-boundary corpus-export --corpus pyjwt --shard --output new-sharded-export
```

Sharding requires a new directory whose parent already exists. It sorts unchanged source
groups, sorts case IDs within each group, and packs whole groups into ordinary suites of at
most 32 cases. A 33-case source group is refused. Cases from one group, including their
matched conditions and code variants, never cross shards. The global bounds are 1,024
cases, 256 source groups, 32 shards, and 64 MiB for all serialized output including root
metadata. Every bound is checked before creating the output directory.

Output paths use ordinals:

```text
new-sharded-export/
  index.json
  provenance.json
  source_manifest.json
  evaluator_manifest.json
  shards/0001/suite.json
  shards/0002/suite.json
```

The index uses schema 1 and binds the registered corpus and version, suite/scoring/protocol
contract, sorted full case-ID and case-digest identity, complete case-set digest, ordered
shard paths and digests, and the unique source-group set for the entire export. Counts are
global counts; sharding does not increase independent source groups. The root source and
evaluator manifests are preserved as supplied by the registration. No per-shard admission
or inventory is fabricated. The schema 2 provenance metadata fingerprints the complete
export, using one canonical aggregate input fingerprint for large case sets. Hashes
identify exported content and do not authenticate a newly supplied source.

Each shard is a normal bounded suite accepted by repository suite loaders and existing
repository runner/CI suite-file options. Those options take a `suite.json` path; they do not
load an export index or combine shards automatically. A partial shard fails
`validate-suite --corpus pyjwt`, which continues to require the entire exact registered
case-ID and case-digest set. A one-shard export that contains the complete registered set
retains the same binding rule.

`--shard --verify` is refused before any builder, manifest, oracle, or output operation.
Sharded exports record `behavior_verification: not_run`. The writer refuses collisions and
symlinks and cleans up only paths whose file and ancestor identities are still owned by
the invocation.

## Held generic transforms

`corpus-export` has no generic payload-pack or carrier flags. No arbitrary upstream
transformation or derived-suite verification is introduced here. Future transforms need
separate review of source lineage, notices, unchanged executable bytes where required,
language/path-specific comment handling, and exact derived-suite behavior evidence.
Running a base oracle cannot establish that a transformed suite is verified or admitted.
