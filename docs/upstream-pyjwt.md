# Pinned upstream case: token key formats

This corpus preserves the complete `jwt` package from two immutable PyJWT
revisions. It covers one source issue in four conditions: vulnerable or fixed
code, each with a normal README or a misleading approval instruction. It does
not represent four independent vulnerabilities or a complete repository audit.

The issue is [GHSA-ffqj-6fqr-9h24](https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24).
The package snapshots are [24b29adf](https://github.com/jpadilla/pyjwt/tree/24b29adfebcb4f057a3cef5aaf35653bc0c1c8cc)
and [9c528670](https://github.com/jpadilla/pyjwt/tree/9c528670c455b8d948aff95ed50e22940d1ad3fc).
Source files remain unchanged. Their hashes, licenses and the additional MIT
notice for the attributed PEM recognizer are retained in the packaged
[source manifest](../src/review_boundary/fixtures/upstream/pyjwt/manifest.json).

## Reproduce and export

```sh
uv run --frozen --extra upstream review-boundary corpus-export \
  --corpus pyjwt --verify --output runs/upstream-pyjwt
```

The command writes:

- `suite.json`, accepted by `repository-run-adapter --suite`;
- `provenance.json`, with source revisions, hashes and the verification status;
- `verification.json`, with separate observations from both revisions.

Without `--verify`, export requires no cryptographic dependency and records
`behavior_verification: not_run`. A failed behavior check returns exit code 2.
Existing nonempty output directories are never overwritten.

## What the behavior check establishes

The task explicitly assumes that an application supplies a trusted OpenSSH
Ed25519 or ECDSA P-256 public key, permits HS256 alongside its asymmetric
algorithm, and does not bind keys to algorithms elsewhere. The attacker controls
token bytes. These assumptions are visible to the reviewer.

An independent oracle constructs HMAC signatures with Python's standard library.
It generates ephemeral test keys in memory and runs each complete package in a
separate process. Both forged token formats are accepted by the pre-fix snapshot
and rejected with `InvalidKeyError` by the fixed snapshot. Eight controls per
revision cover valid HMAC, wrong-key rejection, valid EdDSA/ES256, mixed allowlists,
and asymmetric-only rejection of HMAC tokens. The result records Python and
cryptography versions, package hashes and the oracle hash.

Execution uses an empty environment, temporary staging, Python audit hooks and
resource limits. The check verifies that Python network access, file writes and
reads outside staging/interpreter roots are rejected. This is not an OS sandbox
and does not contain arbitrary native code. No upstream installation scripts
run, and no private keys are written into result files.

## Evaluate a reviewer

```sh
uv run --frozen review-boundary repository-run-adapter \
  --suite runs/upstream-pyjwt/suite.json \
  --adapter path/to/your-reviewer.json \
  --output runs/upstream-review
```

Use a reviewer capable of inspecting an unfamiliar package. The bundled tenant
reference scripts do not support this corpus. The evaluator's suite and oracle
must not be supplied to the reviewer as context. Its tools expose package code,
license notices, the review task and README, without the advisory, expected
findings, oracle or issue rubric.

The rubric follows HMAC selection, key preparation and format detection across
files. Matching it establishes structural coverage, not semantic correctness;
semantic judgments remain unjudged without independent adjudication. The cases
are public development material. Group all four conditions under the same source
issue when estimating uncertainty or creating future held-out sets.
