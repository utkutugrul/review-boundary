"""Offline provider plans with native endpoints and explicit pricing provenance."""

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import date
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

PROVIDERS = ("openrouter", "openai", "anthropic")
ENDPOINTS = {
    "openrouter": "https://openrouter.ai/api/v1",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
}
KEY_VARIABLES = {
    "openrouter": "OPENROUTER_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}
OVERRIDE_VARIABLES = {
    "openrouter": ("OPENROUTER_BASE_URL",),
    "openai": (
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "OPENAI_API_TYPE",
        "OPENAI_API_VERSION",
        "OPENAI_AUTH_TOKEN",
        "OPENAI_ACCESS_TOKEN",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "AZURE_OPENAI_API_KEY",
        "AZUREAI_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_BASE_URL",
        "AZUREAI_OPENAI_BASE_URL",
        "AZURE_OPENAI_AD_TOKEN",
        "AZUREAI_OPENAI_API_VERSION",
        "BEDROCK_OPENAI_API_KEY",
        "BEDROCK_OPENAI_BASE_URL",
        "AWS_BEDROCK_BASE_URL",
        "AWS_BEARER_TOKEN_BEDROCK",
    ),
    "anthropic": (
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_PROFILE",
        "ANTHROPIC_CONFIG_DIR",
        "ANTHROPIC_IDENTITY_TOKEN",
        "ANTHROPIC_IDENTITY_TOKEN_FILE",
        "ANTHROPIC_FEDERATION_RULE_ID",
        "ANTHROPIC_ORGANIZATION_ID",
        "ANTHROPIC_BEDROCK_BASE_URL",
        "BEDROCK_ANTHROPIC_BASE_URL",
        "ANTHROPIC_VERTEX_BASE_URL",
        "VERTEX_ANTHROPIC_BASE_URL",
        "ANTHROPIC_VERTEX_REGION",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "AZUREAI_ANTHROPIC_API_KEY",
        "AZURE_ANTHROPIC_API_KEY",
        "AZUREAI_ANTHROPIC_BASE_URL",
        "AZURE_ANTHROPIC_BASE_URL",
        "AZURE_ANTHROPIC_ENDPOINT",
    ),
}
COMMON_OVERRIDES = (
    "INSPECT_EVAL_MODEL_BASE_URL",
    "INSPECT_MODEL_BASE_URL",
    "INSPECT_EVAL_MODEL_ARGS",
    "INSPECT_MODEL_API_KEY",
)


def _rate(value, label: str) -> float:
    try:
        valid = type(value) in (int, float) and math.isfinite(value) and value > 0
    except OverflowError:
        valid = False
    if not valid:
        raise ValueError(f"{label} must be a positive finite USD-per-million-token number")
    return float(value)


def _model_id(provider: str, model_id: str) -> str:
    pattern = r"[A-Za-z0-9][A-Za-z0-9._:@+/-]{0,255}"
    if not isinstance(model_id, str) or re.fullmatch(pattern, model_id) is None:
        raise ValueError("Model IDs must be bounded provider-native identifiers")
    if provider != "openrouter" and "/" in model_id:
        raise ValueError("Native model IDs must not contain provider or cloud-service prefixes")
    if "//" in model_id or model_id.endswith("/"):
        raise ValueError("Model IDs must not contain empty path segments")
    return model_id


@dataclass(frozen=True)
class ModelQuote:
    input_usd_per_million: float
    output_usd_per_million: float
    cache_write_usd_per_million: float | None = None
    cache_read_usd_per_million: float | None = None

    @property
    def reservation_input_rate(self) -> float:
        return max(
            self.input_usd_per_million,
            self.cache_write_usd_per_million or 0,
            self.cache_read_usd_per_million or 0,
        )


@dataclass(frozen=True)
class ProviderPlan:
    name: str
    model_ids: tuple[str, ...]
    prompt_price_cap: float
    completion_price_cap: float
    quotes: tuple[tuple[str, ModelQuote], ...] = ()
    pricing_source: str = "openrouter_catalog"
    pricing_as_of: str | None = None
    pricing_sha256: str | None = None
    admission_input_cap: float | None = None
    admission_output_cap: float | None = None

    @property
    def api_key_env(self) -> str:
        return KEY_VARIABLES[self.name]

    @property
    def base_url(self) -> str:
        return ENDPOINTS[self.name]

    def inspect_model_id(self, model_id: str) -> str:
        if model_id not in self.model_ids:
            raise ValueError("Model was not included in this provider plan")
        return f"{self.name}/{model_id}"

    def validate_environment(self, environ: Mapping[str, str], *, require_key: bool = True) -> None:
        """Validate an explicit environment without returning or recording credential values."""
        overridden = [
            name
            for name in (*COMMON_OVERRIDES, *OVERRIDE_VARIABLES[self.name])
            if environ.get(name)
        ]
        if overridden:
            raise ValueError("Unset provider/auth overrides: " + ", ".join(sorted(overridden)))
        key = environ.get(self.api_key_env)
        if require_key and (not isinstance(key, str) or not key.strip()):
            raise ValueError(f"Set {self.api_key_env} for the selected provider")

    def model_args(self) -> dict:
        """Return only non-secret SDK arguments; GenerateConfig controls cache_prompt=False."""
        arguments = {"base_url": self.base_url, "max_retries": 0}
        if self.name == "openrouter":
            arguments.update(
                stream=False,
                provider={
                    "require_parameters": True,
                    "allow_fallbacks": False,
                    "max_price": {
                        "prompt": self.prompt_price_cap,
                        "completion": self.completion_price_cap,
                        "request": 0,
                    },
                },
            )
        else:
            arguments["streaming"] = False
            if self.name == "openai":
                arguments.update(background=False, responses_store=False)
        return arguments

    def to_metadata(self) -> dict:
        return {
            "name": self.name,
            "inspect_prefix": self.name,
            "api_key_env": self.api_key_env,
            "base_url": self.base_url,
            "model_ids": list(self.model_ids),
            "pricing": {
                "source": self.pricing_source,
                "as_of": self.pricing_as_of,
                "file_sha256": self.pricing_sha256,
                "models": {model: asdict(quote) for model, quote in self.quotes},
                "verification": (
                    "Caller must validate the live OpenRouter catalog separately"
                    if self.name == "openrouter"
                    else "Operator-supplied quote; recorded, not automatically price-verified"
                ),
            },
            "reservation_rates": {
                "input_usd_per_million": self.prompt_price_cap,
                "output_usd_per_million": self.completion_price_cap,
            },
            "admission_caps": {
                "input_usd_per_million": self.admission_input_cap,
                "output_usd_per_million": self.admission_output_cap,
            },
            "remote_price_ceiling_enforced": self.name == "openrouter",
            "request_policy": {
                "cache_prompt": False,
                "sdk_retries": 0,
                "streaming": False,
                "native_endpoint_only": self.name != "openrouter",
                **({"reasoning_summary": "none"} if self.name == "openai" else {}),
            },
        }


def _load_quotes(path: Path, provider: str, model_ids: tuple[str, ...]) -> tuple:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Pricing file contains duplicate JSON keys")
            result[key] = value
        return result

    if path.stat().st_size > 65536:
        raise ValueError("Pricing file exceeds 65536 bytes")
    raw = path.read_bytes()
    try:
        content = json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeDecodeError, RecursionError) as error:
        raise ValueError("Pricing file must contain valid JSON without duplicate keys") from error
    required = {"schema_version", "provider", "source", "as_of", "models"}
    if not isinstance(content, dict) or set(content) != required:
        raise ValueError(
            "Pricing file requires exactly schema_version, provider, source, as_of, models"
        )
    if type(content["schema_version"]) is not int or content["schema_version"] != 1:
        raise ValueError("Pricing schema_version must be 1")
    if content["provider"] != provider:
        raise ValueError("Pricing provider does not match the selected provider")
    source = content["source"]
    if not isinstance(source, str) or len(source) > 2048:
        raise ValueError("Pricing source must be an official HTTPS source URL")
    try:
        url = urlsplit(source)
        domains = ("openai.com",) if provider == "openai" else ("anthropic.com", "claude.com")
        official = any(
            url.hostname == domain or (url.hostname or "").endswith("." + domain)
            for domain in domains
        )
        valid_source = (
            url.scheme == "https"
            and official
            and not url.username
            and not url.password
            and url.port in (None, 443)
        )
    except ValueError:
        valid_source = False
    if not valid_source:
        raise ValueError("Pricing source must be an official HTTPS source URL")
    as_of = content["as_of"]
    if not isinstance(as_of, str) or re.fullmatch(r"\d{4}-\d{2}-\d{2}", as_of) is None:
        raise ValueError("Pricing as_of must be an ISO calendar date")
    try:
        quoted_on = date.fromisoformat(as_of)
    except ValueError as error:
        raise ValueError("Pricing as_of must be an ISO calendar date") from error
    if quoted_on > date.today():
        raise ValueError("Pricing as_of must not be in the future")
    models = content["models"]
    if not isinstance(models, dict) or not models:
        raise ValueError("Pricing models must be a nonempty object")
    quotes = {}
    mandatory = {"input_usd_per_million", "output_usd_per_million"}
    optional = {"cache_write_usd_per_million", "cache_read_usd_per_million"}
    for model, prices in models.items():
        _model_id(provider, model)
        if (
            not isinstance(prices, dict)
            or not mandatory <= prices.keys()
            or prices.keys() - mandatory - optional
        ):
            raise ValueError(
                "Each model quote requires input/output prices and only supported cache prices"
            )
        quotes[model] = ModelQuote(**{key: _rate(value, key) for key, value in prices.items()})
    if set(model_ids) - quotes.keys():
        raise ValueError("Pricing file must quote every selected model")
    return (
        tuple((model, quotes[model]) for model in model_ids),
        source,
        as_of,
        sha256(raw).hexdigest(),
    )


def prepare_provider(
    name: str,
    model_ids: Sequence[str],
    *,
    prompt_price_cap: float | None = None,
    completion_price_cap: float | None = None,
    pricing_file: str | Path | None = None,
) -> ProviderPlan:
    """Build an offline plan. Native providers require a dated quote, even with caps."""
    if name not in PROVIDERS:
        raise ValueError("Provider must be openrouter, openai, or anthropic")
    if isinstance(model_ids, (str, bytes)) or not model_ids or len(model_ids) > 128:
        raise ValueError("Select between 1 and 128 provider-native model IDs")
    selected = tuple(dict.fromkeys(_model_id(name, model) for model in model_ids))
    input_cap = None if prompt_price_cap is None else _rate(prompt_price_cap, "Input cap")
    output_cap = None if completion_price_cap is None else _rate(completion_price_cap, "Output cap")
    if name == "openrouter":
        if pricing_file is not None:
            raise ValueError(
                "OpenRouter uses its live catalog; pricing files are for native providers"
            )
        return ProviderPlan(
            name,
            selected,
            input_cap or 0.15,
            output_cap or 0.60,
            admission_input_cap=input_cap or 0.15,
            admission_output_cap=output_cap or 0.60,
        )
    if pricing_file is None:
        raise ValueError(
            "Native providers require --pricing-file with a dated quote for every model"
        )
    quotes, source, as_of, digest = _load_quotes(Path(pricing_file), name, selected)
    input_rate = max(quote.reservation_input_rate for _, quote in quotes)
    output_rate = max(quote.output_usd_per_million for _, quote in quotes)
    if input_cap is not None and input_rate > input_cap:
        raise ValueError("Quoted input/cache rate exceeds the configured input admission cap")
    if output_cap is not None and output_rate > output_cap:
        raise ValueError("Quoted output rate exceeds the configured output admission cap")
    return ProviderPlan(
        name,
        selected,
        input_rate,
        output_rate,
        quotes,
        source,
        as_of,
        digest,
        input_cap,
        output_cap,
    )
