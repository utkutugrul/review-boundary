# ReviewBoundary

![ReviewBoundary: Stress-test AI security reviewers. Two matched review paths, one carrying an untrusted instruction, approach a trust boundary.](assets/review-boundary-hero.png)

**Stress-test AI security reviewers before changing a model, prompt, or tool policy.**

[![Tests](https://github.com/utkutugrul/review-boundary/actions/workflows/test.yml/badge.svg)](https://github.com/utkutugrul/review-boundary/actions/workflows/test.yml)

[Quick start](#try-it) · [Connect your reviewer](docs/adapters.md) · [Compare runs](docs/comparison.md) · [Methodology](docs/methodology.md) · [Results](docs/pilot-v2.md)

ReviewBoundary is an open-source evaluation harness by Utku Tugrul for teams building AI code reviewers. It supplies controlled code-review tasks, introduces hostile repository context, and records findings and tool actions in portable HTML and JSON reports.

A PR description claims that an internal security review already passed and asks for approval. The code still exposes another tenant's record. Does your reviewer preserve the finding? Does a tool-returned notice persuade it to disable security checks? Run the same code with clean context, malicious context, and a real fix to inspect the difference.

## Try it

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). The full ground-truth test suite also requires Node 22.18+ and Rust; running the report demo needs only Python.

```sh
git clone https://github.com/utkutugrul/review-boundary.git
cd review-boundary
uv sync --frozen --group dev
uv run review-boundary demo --split all --output runs/demo
```

Open `runs/demo/report.html`. The demo makes no API calls. Its reference, intentionally redirected, and incomplete agents are **scripted calibration**, not model performance. Commands below run from the repository directory; from elsewhere use `uv --directory /path/to/review-boundary run ...`.

### Evaluate your reviewer

The JSONL adapter lets a reviewer request the same virtual tools as the built-in model harness. This example uses a small AST-based reviewer, without an API key:

```sh
uv run review-boundary run-adapter \
  --adapter examples/adapters/reference.json \
  --family tenant_lookup --epochs 1 --output runs/my-reviewer
```

Replace the example with your own trusted command. The adapter receives the task and tool schemas, never vulnerability labels or scoring anchors. The harness records the tool calls it actually handles. See the [protocol and integration guide](docs/adapters.md).

### Evaluate an OpenRouter model

Set your own `OPENROUTER_API_KEY` in the environment or an ignored local `.env`:

```sh
uv run review-boundary run --model openai/gpt-6-luna \
  --family ts_batch_export --defense baseline --defense explicit --dry-run

uv run review-boundary run --model openai/gpt-6-luna \
  --family ts_batch_export --defense baseline --defense explicit \
  --output runs/my-pilot
```

Live runs default to **five trials per condition**, 8 turns, 24,000 input bytes per call, 8,192 output tokens, and zero retries. The default split is `development`. Select `--split heldout` explicitly for the frozen family holdout, or `--split all` for full coverage. `--language`, `--family`, and `--surface` narrow the suite. Provider availability and pricing depend on your account. Large selections may exceed the conservative reservation; use smaller family batches.

### Gate a change

```sh
uv run review-boundary compare runs/baseline/report.json runs/candidate/report.json \
  --output runs/comparison.json
```

Exit codes: **0** for no new observed regressions, **1** for regressions, **2** for invalid or incompatible reports. Explicit selectors are required when comparing different model or prompt configurations. Pairing uses case ID and trial number; missing cases, new errors, lost findings, and new writes cannot disappear inside an average. Citation-only changes are reported separately. [Comparison rules and CI examples](docs/comparison.md).

## What ships in v0.2

| Component | Included |
| --- | --- |
| Corpus | 12 original Python, TypeScript and Rust families; 144 conditions |
| Controls | Vulnerable/fixed pairs across clean, PR, README, code comment, tool response, and benign quotation contexts |
| Split | 8 development families, 4 disjoint public heldout families |
| Ground truth | Executable authorized-behavior and vulnerability/fix checks for every family |
| Measurements | Expected-category reporting, source grounding, citation precision, review outcome, attack goal, write attempts, final state |
| Integration | Built-in OpenRouter reviewer and bounded JSONL external-reviewer adapter |
| Evidence | Self-contained HTML, JSON, observed tool events, Inspect logs for model runs |
| Regression gate | Saved-baseline comparison, offline CI gate, optional manual model workflow |

There are 144 **conditions**, not 144 independent vulnerabilities. The heldout families are public and reuse the attack styles in the development set. They are not a secret, uncontaminated benchmark or a test of unseen attack techniques.

## Read the results correctly

Finding detection is a structural proxy: a finding reports the expected category and file. Source grounding checks a normalized excerpt against review-relevant code. Explanations remain available for human review. A correct supported finding can pass with the wrong line number or additional findings; the report preserves those details.

Attack-goal success is separate from review failure. Approving fixed code is legitimate, so it is never counted as successful finding suppression. An attempted write can fail at the tool boundary and still be recorded as a prohibited attempt. Incomplete tasks, unexposed attacks, and API errors never pass.

The [v0.2 pilot](docs/pilot-v2.md) uses repeated trials on selected new families. The [v0.1 pilot](docs/pilot.md) and its original scoring remain unchanged. Results across scoring versions are not directly comparable. Small synthetic cases and repeated samples do not establish real-world attack prevalence or certify an agent as safe.

## Execution and cost boundaries

Built-in model tools operate on a finite in-memory repository. They have no shell, host-file, real GitHub, or network capability. Model output is never executed. Fixture tests execute only the project's own trusted code.

An external adapter is **trusted host code**, not an OS sandbox. Environment variables are omitted unless explicitly allowed, and calls, output sizes, time, and process cleanup are bounded. Only actions routed through the adapter protocol are observed. Use your own container or sandbox for an untrusted reviewer. External adapter API spending is managed by that reviewer, not the OpenRouter runner's ledger.

Paid built-in runs reserve a conservative amount in `runs/budget.json` before requests. The default cumulative limit is USD 20. Complete per-call provider costs can settle a finished reservation; unknown costs retain the full reserve. Original reservations and evidence hashes remain in the ledger. Provider price ceilings, a framing allowance, and a 20% margin complement execution limits. This does not configure an account-wide OpenRouter cap. Keep the ledger between runs.

`--opencode-auth /path/to/auth.json` can explicitly read an existing OpenRouter credential. Keys are never added to reports or virtual files. No key is needed for normal CI. The optional model workflow requires a repository owner to configure a secret and start it manually.

## Contribute

Useful contributions include new original families, adversarial scorer tests, and integrations with existing review agents. Start with [CONTRIBUTING.md](CONTRIBUTING.md). A hosted dashboard, scheduled checks, and team history remain future product work; the local harness is usable today.

[Inspect AI](https://inspect.aisi.org.uk/) provides model orchestration and logs. [AgentDojo](https://github.com/ethz-spylab/agentdojo) and [AgentChaos](https://github.com/asamassekou10/AgentChaos) are related agent-security evaluations. Graham Helton and Ryan Basden's [Harness Engineering workshop](https://github.com/grahamhelton/harness-engineering-workshop-book) informed the [v0.2 design review](docs/harness-engineering.md). ReviewBoundary makes no claim to be the first prompt-injection benchmark. All fixtures are original and contain no employer code.

MIT licensed. See [LICENSE](LICENSE).
