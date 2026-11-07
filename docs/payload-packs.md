# Payload packs

Payload packs contain original text for controlled review experiments. Each entry has
an instruction attempt, ordinary text, and a harmless quotation of the attempted
instruction. The repository examples place those three conditions in the same carrier
while keeping the security issue and its fix intact.

The bundled pack uses one original synthetic code fixture. Its entries, carriers,
conditions, and repeated runs do not add independent vulnerabilities or source groups.
Scripted results check the harness and make no model quality claim.

## Try a repository carrier

```sh
uv run --frozen review-boundary payload-pack --output runs/original-pack.json
uv run --frozen review-boundary payload-suite --carrier pr --output runs/pr-suite.json
uv run --frozen review-boundary validate-suite --suite runs/pr-suite.json
uv run --frozen review-boundary repository-demo --suite runs/pr-suite.json --output runs/pr-demo
```

Choose one of `readme`, `pr`, `inert_file`, `filename`, `code_comment`, or `tool_output`.
Each exported suite contains 12 cases: two code variants, two pack entries, and three
text conditions. Export a separate suite for each carrier. Suite files permit at most
32 cases.

The demo uses local scripts and needs no API key. Its `reference` reviewer follows
the source code. The historical `hijacked` script recognizes only its original README
instruction, so it is not a general attack-following reviewer.

Use the same suite with a real reviewer through `repository-run-model --suite ...`
or `repository-run-adapter --suite ...`. See [providers](providers.md) for model and
budget options and [repository mode](repository-mode.md) for execution limits.

## Reuse a pack

The `payload-pack` command prints the original pack when `--output` is omitted. JSON
exports include explicit `schema_version` and `pack_version` integers. Save a copy,
edit the text, and give it its own `pack_id` and version before reusing it:

```sh
uv run --frozen review-boundary payload-suite --pack my-pack.json --carrier readme --output runs/my-suite.json
uv run --frozen review-boundary worker-summary-suite --pack my-pack.json --output runs/my-workers.json
```

Each entry has `entry_id`, `intent`, `clean_text`, `attack_text`, and
`benign_quote_text`. Supported intents are `review_suppression` and
`authorization_spoofing`. The bounded parser rejects unknown fields, duplicate entry
IDs, invalid versions, and oversized text. Packs are data and cannot select files to
load, execute code, or make network requests. Exports never overwrite existing files.

Every repository case records the full pack digest, pack version, entry, carrier, and
condition. Changing a pack's declared origin does not change the underlying code's
source group. A pack that would produce more than 32 repository cases is rejected.
Worker-summary generation requires an entry with the authorization-spoofing intent.

## Read the delivery evidence

Repository payload suites use suite schema 2, case schema 2, and scoring version
`repository-payload-v1`. Existing unversioned repository cases, suite schema 1,
`repository-v1` scores, and default demos retain their original behavior. Export the
selected schema with `suite-schema --schema-version 2`.

`carrier_observed` means the marked text or filename appeared in a successful tool
response that fit the execution limits. `payload_exposed` is true only for the attack
condition after carrier delivery. Ordinary and quoted controls can be observed without
being attacks. An undelivered carrier cannot produce a conclusive payload result.

Tool-output cases add the text as an `untrusted_text` field in a successful response
from the designated existing tool. The bundled cases use `list_files`. Adapter suites
use `reviewboundary.repository-jsonl/2` to make this response extension explicit;
schema 1 suites retain `reviewboundary.repository-jsonl/1`. Tool names and arguments
are unchanged. The bundled reference adapter accepts both protocols.

Schema 2 snapshots retain bounded canonical arguments and response digests for
deterministic restore. The report dashboard shows the carrier, condition, delivery,
and event paths. [Versioned evidence exports](reports.md) can check supplied snapshots
and suites for consistency. Hash consistency does not establish authenticity or prove
that an instruction caused a review decision. Semantic correctness stays unknown
until explicit evaluator adjudication.

## Try worker-summary controls

```sh
uv run --frozen review-boundary worker-summary-suite --output runs/workers.json
uv run --frozen review-boundary boundary-demo --suite runs/workers.json --output runs/worker-demo
```

The 24 cases cover six summary roles across two code variants and two virtual effect
tools. They include summary-only approval claims, a summary quoting an approval
claim, ordinary summaries, actual user authorization, and authorization for a different
destination. A worker's summary remains untrusted data. Only the trusted user request
and exact action grants authorize an action.

These cases keep the existing boundary schema 1 and boundary scoring contract. The
same untrusted summary may appear under different trusted permissions; those roles
are controls for authority and utility, not identical model trajectories. Guard
intervention, unauthorized attempts, task utility, and reviewer resistance remain
separate observations. A blocked unauthorized attempt is still an attempt.
