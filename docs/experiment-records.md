# Experiment records

New runs record fingerprints of the caller's instructions, advertised tool
contract, and selected source files. These help explain what changed between
experiments. They do not authenticate an artifact or prove that two reviewers
behave identically.

## What is recorded

`metadata.provenance` uses schema version 1 and SHA-256:

| Field | Recorded scope |
| --- | --- |
| `prompts` | Exact caller instruction text, keyed by defense or repository input. |
| `tools` | Protocol identifier and canonical digest of advertised tool names, descriptions, and parameter schemas. |
| `harness` | Per-file hashes and an aggregate digest for the explicit harness source inventory, including repository-mode modules. |
| `reviewer_source` | Per-file hashes and an aggregate digest for an adapter's explicitly declared `source_files`, or `not_recorded`. |

The suite digest separately binds case content. Adapter metadata also records
`config_sha256`, which covers its declared command, environment-variable names,
source-file list, and transport settings. Environment values and the raw command
are not serialized into that metadata. Normal run metadata retains the selected
reviewer, execution bounds, versions, and available usage measurements.

This does not automatically capture a reviewer's internal prompts, remote model
weights, dependency tree, runtime environment, host configuration, or unlisted
files. A caller prompt hash describes what the harness supplied, not every
transformation an external reviewer applied. The harness inventory is an
explicit set of files, not a fingerprint of the entire machine.

## Declare local reviewer source

An adapter configuration can include:

```json
{
  "name": "my-reviewer",
  "command": ["{python}", "{config_dir}/reviewer.py"],
  "source_files": ["reviewer.py", "review-policy.txt"],
  "env_allowlist": []
}
```

These files must exist relative to the configuration directory. Paths must be
normalized, relative, distinct, and free of symlink components. Up to 32 regular
files are accepted, with limits of 4 MiB per file and 16 MiB total. The record
stores hashes and relative names, not file contents or host paths. Include a
policy or lockfile explicitly if it matters; dependencies are not discovered
automatically. Never include credentials merely to fingerprint a run.

Adapter runs check the declared source before and after invocations. Detected
changes invalidate the affected result and stop further work. This is a
consistency check, not protection against a trusted process changing and restoring
files between checks. Leaving `source_files` empty produces an explicit unknown
source record.

## Compare recorded inputs

The existing v0.2 `compare` command includes an informational provenance section
for instructions, tool schema/protocol, harness source, and reviewer source.
It reports changed, unchanged, and unknown fields. These differences do not
independently change the regression gate's exit code; the normal compatibility
and outcome checks still apply.

Historical reports without fingerprints remain unknown. Missing fingerprints
are never treated as evidence of equality, and current source hashes are not
retroactively assigned to old runs. [Repository reports](repository-mode.md)
have a separate format and are not inputs to the v0.2 comparison CLI.

## Reconstruct Inspect reports

For a complete v0.2 log set and its manifest:

```sh
uv run --frozen review-boundary report runs/example/logs/*.eval \
  --manifest runs/example/manifest.json --output runs/rebuilt
```

The CLI checks recorded scores against the supported v0.2 scorer by default,
using each recorded case, world state, and relevant assistant messages. Missing
state or contradictory scores blocks reconstruction. An errored sample without
a score remains explicitly unscored, and verification is marked partial.
Original scores are checked, not replaced with a new judgment.

To preserve scores without that consistency check, explicitly add:

```sh
--preserve-recorded-scores
```

The resulting `score_verification.status` is `unchecked`. This flag does not
disable log identity, case/suite coverage, bounds, or provenance checks. When
fingerprints are present, the manifest and task copies must agree; recorded
system instructions and advertised tools are checked against them. Missing
fingerprints on both sides remain unknown, while a missing counterpart or
contradiction is rejected. Historical source manifests are compared with their
recorded counterparts, not with today's checkout.

These checks establish internal consistency of supplied records. They do not
prove that their author executed an untampered reviewer. Reconstruction applies
to Inspect v0.2 logs, not the repository runner's `events.jsonl`.
