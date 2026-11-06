# Model providers

ReviewBoundary supports OpenRouter, native OpenAI, and native Anthropic through Inspect's existing providers. Select one provider per run and pass that provider's model IDs. Scoring and corpus versions remain `0.2.0`; adding a provider does not rewrite earlier baselines.

| Provider | CLI selection | Credential environment variable | Fixed endpoint | Inspect model prefix |
| --- | --- | --- | --- | --- |
| OpenRouter | `--provider openrouter` or omitted | `OPENROUTER_API_KEY` | `https://openrouter.ai/api/v1` | `openrouter/` |
| OpenAI | `--provider openai` | `OPENAI_API_KEY` | `https://api.openai.com/v1` | `openai/` |
| Anthropic | `--provider anthropic` | `ANTHROPIC_API_KEY` | `https://api.anthropic.com` | `anthropic/` |

For OpenRouter, retain the catalog's publisher/model identifier. For native OpenAI or Anthropic, use the native model ID without an Inspect, Azure, Bedrock, or Vertex prefix. Native IDs containing `/` are rejected because Inspect uses those prefixes to select alternative services.

## Credentials and routing

Set only the selected provider's API credential through your environment or the CLI's local `.env` loading. The runner validates the selected native key before model construction. The explicit `--opencode-auth` loader remains an OpenRouter option; it is not a native OpenAI or Anthropic credential loader.

Provider and authentication overrides are rejected by name, without echoing their values. These include the selected provider's custom base URL variables, alternative cloud-service credentials and endpoints, and Inspect model override variables. OpenAI organization/project overrides are rejected as well. Anthropic OAuth, profile, and federation overrides are unsupported: notably, installed Inspect checks `ANTHROPIC_AUTH_TOKEN` before its native API-key path, so that variable must be unset for a native-key run. Other providers' ordinary API keys may coexist without being selected.

The runner pins official endpoint URLs. It does not accept arbitrary model arguments, custom endpoints, cloud service prefixes, or fallback authentication from the native CLI. This restriction concerns provider selection and authentication; it is not a network sandbox for the host process.

## Native pricing files

Native OpenAI and Anthropic runs require `--pricing-file`, including dry runs. The file is a local operator-supplied quote for every selected model. It records the provider, an official HTTPS pricing-source URL, the date checked, and numeric USD prices per million tokens. It is validated and hashed; its contents are not automatically fetched or price-verified.

Start from this template, replace the placeholders, and use JSON numbers for prices. The template intentionally will not run until you supply a real model ID, date, and verified rates:

```json
{
  "schema_version": 1,
  "provider": "openai",
  "source": "https://openai.com/api/pricing/",
  "as_of": "YYYY-MM-DD",
  "models": {
    "YOUR_NATIVE_MODEL_ID": {
      "input_usd_per_million": "REPLACE_WITH_VERIFIED_NUMBER",
      "output_usd_per_million": "REPLACE_WITH_VERIFIED_NUMBER"
    }
  }
}
```

For Anthropic, set `provider` to `anthropic` and cite the appropriate official Anthropic or Claude pricing page. Consult [OpenAI pricing](https://openai.com/api/pricing/) or [Anthropic pricing documentation](https://platform.claude.com/docs/en/about-claude/pricing). Confirm rates and applicable tiers for the exact model and account before running. A dated file is provenance, not a guarantee that prices are still current.

Each model entry requires positive finite `input_usd_per_million` and `output_usd_per_million` values. Optional `cache_write_usd_per_million` and `cache_read_usd_per_million` fields record applicable positive cache rates. Unknown fields, duplicate JSON keys, wrong providers, missing models, malformed dates, future dates, nonfinite values, and unsupported source domains fail validation. Files are limited to 65,536 bytes.

The reservation uses the largest quoted input, cache-write, or cache-read rate across all selected models, and the largest quoted output rate. Include the highest applicable cache-write rate when the provider offers multiple write tiers. Optional CLI `--prompt-price-cap` and `--completion-price-cap` values provide additional admission ceilings: a quote above a ceiling is rejected. These flags do not replace a native pricing file.

**Native APIs do not enforce OpenRouter's `max_price` routing policy.** Native quotes and admission ceilings are local reservation assumptions. They are recorded as such, and no OpenRouter routing fields are sent to native APIs. Understated or outdated quotes can understate real charges.

OpenRouter retains its existing defaults of `$0.15` input and `$0.60` output per million tokens, live catalog validation, and provider-routing price ceilings. It rejects a native pricing file. These default ceilings select admissible routes; they are not claims about the current price of any particular model.

## Preview a run

After preparing a verified pricing file, inspect the selected cases, bounds, provider policy, and reservation without using a credential or making a model request:

```sh
uv run review-boundary run \
  --provider openai \
  --model YOUR_NATIVE_MODEL_ID \
  --pricing-file openai-pricing.json \
  --family tenant_lookup --surface clean --epochs 1 \
  --budget 20 --dry-run
```

For Anthropic, change the provider, model ID, and pricing-file path. Removing `--dry-run` starts a paid evaluation and requires the selected API key. Choose a new output directory for each run. The standard live default remains five epochs when `--epochs` is omitted; the example reduces the initial scope explicitly.

The multi-file repository contract uses the same provider and accounting flags:

```sh
uv run review-boundary repository-run-model \
  --provider anthropic \
  --model YOUR_NATIVE_MODEL_ID \
  --pricing-file anthropic-pricing.json \
  --epochs 1 \
  --output runs/repository-model \
  --budget 20 --dry-run
```

Repository dry runs also avoid credential loading, ledger writes, model
construction, and output creation. OpenRouter dry runs still validate the
selected model against the public live catalog.

## Request controls and accounting

The same virtual tools, caller contracts, read-only instructions, scoring rules, generation-turn bounds, and input/output limits apply to all three providers. Inspect prompt-cache configuration is explicitly disabled. SDK retries and Inspect generation retries are zero. Streaming is disabled using each provider's actual parameter name: `stream` for OpenRouter and `streaming` for native OpenAI/Anthropic. Provider-side automatic caching can still exist; the runner does not claim to disable an implicit server cache.

Native OpenAI also disables background responses and response storage, and sets `reasoning_summary="none"` in Inspect generation configuration. The latter avoids Inspect's otherwise automatic reasoning-summary capability probe, which would issue an additional API request outside the evaluation's generation loop. Inspect selects its Chat Completions or Responses integration according to the model; both are exercised in mocked transport tests.

The manifest records provider identity, endpoint, native IDs, credential variable name, pricing provenance and file digest, effective reservation rates, admission ceilings, and request policy. It does not contain the credential value. Direct-provider cost estimates are estimates. Unknown billed cost retains the reservation; token counts multiplied by declared prices must not be treated as provider-reported billing or used to release a reservation. See [the accounting methodology](methodology.md).

## Validation status

Provider tests use real installed Inspect and SDK integrations with `httpx2.MockTransport`, synthetic credentials, and synthetic responses. They assert the outbound endpoint, native model ID, authentication, tool-call conversion, token bounds, absence of explicit prompt-cache markers, and one-call behavior under SDK errors. They cover OpenRouter, OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages. Configuration tests check price provenance and rejection of alternate authentication and routing settings.

These checks make no paid calls and do not establish live model availability, account permissions, current prices, or production success. The user-approved native-provider validation for this release is keyless. Refer to [Inspect's model integration documentation](https://inspect.aisi.org.uk/models.html) for upstream provider behavior; ReviewBoundary deliberately exposes a narrower configuration surface.
