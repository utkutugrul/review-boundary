"""Provider configuration and real SDK transports tested without network access or real keys."""

import json
from hashlib import sha256

import httpx2
import pytest
from anthropic import APIStatusError as AnthropicStatusError
from inspect_ai.model import ChatMessageUser, GenerateConfig, get_model
from inspect_ai.tool import ToolInfo
from openai import APIStatusError as OpenAIStatusError

from review_boundary.providers import (
    COMMON_OVERRIDES,
    ENDPOINTS,
    OVERRIDE_VARIABLES,
    PROVIDERS,
    prepare_provider,
)


def pricing(tmp_path, provider="openai", models=None, **updates):
    content = {
        "schema_version": 1,
        "provider": provider,
        "source": (
            "https://openai.com/api/pricing/"
            if provider == "openai"
            else "https://platform.claude.com/docs/en/about-claude/pricing"
        ),
        "as_of": "2026-01-01",
        "models": models
        if models is not None
        else {"native-model": {"input_usd_per_million": 1, "output_usd_per_million": 2}},
        **updates,
    }
    path = tmp_path / "pricing.json"
    path.write_text(json.dumps(content))
    return path


def plan_for(tmp_path, provider, model="native-model"):
    if provider == "openrouter":
        return prepare_provider(provider, [model])
    return prepare_provider(
        provider,
        [model],
        pricing_file=pricing(
            tmp_path,
            provider,
            {model: {"input_usd_per_million": 1, "output_usd_per_million": 2}},
        ),
    )


def test_openrouter_defaults_and_nonsecret_metadata():
    plan = prepare_provider("openrouter", ["qwen/qwen3-8b", "qwen/qwen3-8b"])
    assert plan.model_ids == ("qwen/qwen3-8b",)
    assert plan.inspect_model_id(plan.model_ids[0]) == "openrouter/qwen/qwen3-8b"
    assert (plan.prompt_price_cap, plan.completion_price_cap) == (0.15, 0.60)
    assert plan.model_args()["provider"]["max_price"] == {
        "prompt": 0.15,
        "completion": 0.60,
        "request": 0,
    }
    assert plan.model_args()["provider"]["allow_fallbacks"] is False
    assert plan.model_args()["max_retries"] == 0
    assert plan.to_metadata()["remote_price_ceiling_enforced"] is True
    assert "api_key" not in plan.model_args()
    with pytest.raises(ValueError, match="not included"):
        plan.inspect_model_id("other/model")


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_native_quote_required_even_with_caps(provider):
    with pytest.raises(ValueError, match="pricing-file"):
        prepare_provider(provider, ["native-model"], prompt_price_cap=5, completion_price_cap=10)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
def test_native_worst_quoted_rates_and_provenance(tmp_path, provider):
    path = pricing(
        tmp_path,
        provider,
        {
            "first": {
                "input_usd_per_million": 1,
                "output_usd_per_million": 4,
                "cache_write_usd_per_million": 3,
            },
            "second": {
                "input_usd_per_million": 2,
                "output_usd_per_million": 6,
                "cache_read_usd_per_million": 0.5,
            },
        },
    )
    plan = prepare_provider(
        provider,
        ["first", "second"],
        pricing_file=path,
        prompt_price_cap=10,
        completion_price_cap=20,
    )
    assert (plan.prompt_price_cap, plan.completion_price_cap) == (3, 6)
    metadata = plan.to_metadata()
    assert metadata["pricing"]["file_sha256"] == sha256(path.read_bytes()).hexdigest()
    assert metadata["pricing"]["as_of"] == "2026-01-01"
    assert metadata["admission_caps"]["input_usd_per_million"] == 10
    assert metadata["remote_price_ceiling_enforced"] is False
    if provider == "openai":
        assert metadata["request_policy"]["reasoning_summary"] == "none"
    assert plan.model_args()["streaming"] is False
    assert plan.model_args()["base_url"] == ENDPOINTS[provider]
    assert "provider" not in plan.model_args()
    assert "max_price" not in json.dumps(plan.model_args())
    with pytest.raises(ValueError, match="input/cache"):
        prepare_provider(provider, ["first"], pricing_file=path, prompt_price_cap=2)
    with pytest.raises(ValueError, match="output"):
        prepare_provider(provider, ["second"], pricing_file=path, completion_price_cap=5)


@pytest.mark.parametrize("provider", ["openai", "anthropic"])
@pytest.mark.parametrize(
    "model",
    [
        "azure/deployment",
        "bedrock/claude",
        "vertex/model",
        "openai/gpt-4.1",
        "anthropic/claude",
        "a/b",
    ],
)
def test_native_ids_cannot_select_alternative_services(provider, model):
    with pytest.raises(ValueError, match="prefixes"):
        prepare_provider(provider, [model])


@pytest.mark.parametrize(
    "models",
    [
        [],
        "model",
        [""],
        ["a\nb"],
        ["https://elsewhere.test/model"],
        ["../model"],
        ["model/"],
        ["a//b"],
    ],
)
def test_invalid_ids(models):
    with pytest.raises(ValueError):
        prepare_provider("openrouter", models)


@pytest.mark.parametrize("value", [True, 0, -1, float("nan"), float("inf"), "1"])
def test_invalid_price_caps(value):
    with pytest.raises(ValueError, match="positive finite"):
        prepare_provider("openrouter", ["a/b"], prompt_price_cap=value)


@pytest.mark.parametrize("provider", PROVIDERS)
def test_only_selected_native_key_and_no_environment_overrides(tmp_path, provider):
    plan = plan_for(tmp_path, provider)
    plan.validate_environment({plan.api_key_env: "synthetic-key"})
    plan.validate_environment({}, require_key=False)
    with pytest.raises(ValueError, match=plan.api_key_env):
        plan.validate_environment({"UNRELATED_API_KEY": "never-display-me"})
    for variable in (*OVERRIDE_VARIABLES[provider], *COMMON_OVERRIDES):
        with pytest.raises(ValueError) as error:
            plan.validate_environment(
                {plan.api_key_env: "synthetic-key", variable: "never-display-me"}
            )
        assert variable in str(error.value)
        assert "never-display-me" not in str(error.value)
        assert "synthetic-key" not in str(error.value)


@pytest.mark.parametrize(
    "updates",
    [
        {"schema_version": True},
        {"schema_version": 2},
        {"provider": "anthropic"},
        {"as_of": "not-a-date"},
        {"as_of": "2026-02-30"},
        {"as_of": "2999-01-01"},
        {"source": "https://openai.com.evil.test/pricing"},
        {"source": "http://openai.com/api/pricing/"},
        {"source": "https://hidden:credential@openai.com/api/pricing/"},
        {"source": "https://openai.com:9999/api/pricing/"},
        {"models": {}},
        {"unknown": "ignored-field"},
        {"models": {"other": {"input_usd_per_million": 1, "output_usd_per_million": 2}}},
        {"models": {"native-model": {"input_usd_per_million": 1}}},
        {"models": {"native-model": {"input_usd_per_million": True, "output_usd_per_million": 2}}},
        {
            "models": {
                "native-model": {
                    "input_usd_per_million": 1,
                    "output_usd_per_million": 2,
                    "request_price": 3,
                }
            }
        },
    ],
)
def test_invalid_quotes_fail_closed(tmp_path, updates):
    path = pricing(tmp_path, **updates)
    with pytest.raises(ValueError):
        prepare_provider("openai", ["native-model"], pricing_file=path)


def test_duplicate_and_large_pricing_files_rejected(tmp_path):
    path = tmp_path / "pricing.json"
    path.write_text('{"provider":"openai","provider":"anthropic"}')
    with pytest.raises(ValueError, match="valid JSON"):
        prepare_provider("openai", ["native-model"], pricing_file=path)
    path.write_text(" " * 65537)
    with pytest.raises(ValueError, match="65536"):
        prepare_provider("openai", ["native-model"], pricing_file=path)


def test_openrouter_native_catalog_names_and_quote_rejection(tmp_path):
    assert (
        prepare_provider("openrouter", ["openrouter/auto"]).inspect_model_id("openrouter/auto")
        == "openrouter/openrouter/auto"
    )
    with pytest.raises(ValueError, match="live catalog"):
        prepare_provider("openrouter", ["a/b"], pricing_file=pricing(tmp_path))


@pytest.fixture
def isolated_provider_environment(monkeypatch):
    for variable in (
        *COMMON_OVERRIDES,
        *(item for variables in OVERRIDE_VARIABLES.values() for item in variables),
        "OPENAI_SAFETY_IDENTIFIER",
    ):
        monkeypatch.delenv(variable, raising=False)
    # Tests always pass this synthetic credential explicitly to get_model.
    return "synthetic-key-no-network"


def completion_response(provider, model, responses_api=False):
    if provider == "anthropic":
        return {
            "id": "msg_synthetic",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [{"type": "tool_use", "id": "call_1", "name": "read_pr", "input": {}}],
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "usage": {"input_tokens": 12, "output_tokens": 5},
        }
    if responses_api:
        return {
            "id": "resp_synthetic",
            "object": "response",
            "created_at": 0,
            "status": "completed",
            "error": None,
            "incomplete_details": None,
            "model": model,
            "output": [
                {
                    "type": "function_call",
                    "id": "fc_1",
                    "call_id": "call_1",
                    "name": "read_pr",
                    "arguments": "{}",
                    "status": "completed",
                }
            ],
            "parallel_tool_calls": False,
            "tool_choice": "auto",
            "tools": [],
            "usage": {"input_tokens": 12, "output_tokens": 5, "total_tokens": 17},
        }
    return {
        "id": "chatcmpl_synthetic",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "read_pr", "arguments": "{}"},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17},
    }


@pytest.mark.parametrize(
    "provider,model_id,responses_api",
    [
        ("openrouter", "anthropic/claude-sonnet-4-5", False),
        ("openai", "gpt-4.1-mini", False),
        ("openai", "gpt-5-mini", True),
        ("anthropic", "claude-sonnet-4-5", False),
    ],
)
async def test_real_inspect_sdk_requests_use_native_transport_and_bounds(
    tmp_path, isolated_provider_environment, provider, model_id, responses_api
):
    plan = plan_for(tmp_path, provider, model_id)
    requests = []

    def respond(request):
        requests.append(request)
        return httpx2.Response(200, json=completion_response(provider, model_id, responses_api))

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(respond), trust_env=False)
    config = GenerateConfig(
        max_tokens=256, max_retries=0, cache_prompt=False, reasoning_summary="none"
    )
    model = get_model(
        plan.inspect_model_id(model_id),
        api_key=isolated_provider_environment,
        config=config,
        memoize=False,
        http_client=client,
        **plan.model_args(),
    )
    try:
        result = await model.api.generate(
            [ChatMessageUser(content="Read the synthetic pull request.")],
            [
                ToolInfo(
                    name="read_pr",
                    description="Read the pull request.",
                    parameters={"type": "object", "properties": {}, "required": []},
                )
            ],
            "auto",
            config,
        )
        output = result[0] if isinstance(result, tuple) else result
        assert not isinstance(output, Exception), str(output)
        assert output.message.tool_calls[0].function == "read_pr"
        assert output.usage.input_tokens == 12
        assert len(requests) == 1
        request = requests[0]
        expected_suffix = (
            "/messages"
            if provider == "anthropic"
            else ("/responses" if responses_api else "/chat/completions")
        )
        expected_url = plan.base_url + ("/v1" if provider == "anthropic" else "") + expected_suffix
        assert str(request.url) == expected_url
        body = json.loads(request.content)
        assert body["model"] == model_id
        assert (
            body.get("max_output_tokens", body.get("max_completion_tokens", body.get("max_tokens")))
            == 256
        )
        assert body.get("stream", False) is False
        assert "cache_control" not in json.dumps(body)
        assert "prompt_cache_options" not in body
        assert model.api.client.max_retries == 0
        if provider == "anthropic":
            assert model.api.client.api_key == isolated_provider_environment
            assert model.api.client.auth_token is None
            supplied_key = request.headers.get("x-api-key") or request.headers.get(
                "authorization", ""
            ).removeprefix("Bearer ")
            assert supplied_key == isolated_provider_environment
        else:
            assert request.headers["authorization"] == "Bearer " + isolated_provider_environment
        if provider == "openrouter":
            assert body["provider"]["max_price"] == plan.model_args()["provider"]["max_price"]
        else:
            assert "provider" not in body
            assert "max_price" not in body
        if responses_api:
            assert body["store"] is False
            assert body.get("background", False) is False
    finally:
        await model.api.aclose()


@pytest.mark.parametrize(
    "provider,model_id", [("openai", "gpt-4.1-mini"), ("anthropic", "claude-sonnet-4-5")]
)
async def test_native_sdk_errors_do_not_retry_or_become_fake_success(
    tmp_path, isolated_provider_environment, provider, model_id
):
    plan = plan_for(tmp_path, provider, model_id)
    requests = []

    def refuse(request):
        requests.append(request)
        return httpx2.Response(
            500,
            json={
                "error": {
                    "type": "api_error",
                    "message": "synthetic-provider-error: " + isolated_provider_environment,
                    "code": "server_error",
                }
            },
        )

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(refuse), trust_env=False)
    config = GenerateConfig(
        max_tokens=128, max_retries=0, cache_prompt=False, reasoning_summary="none"
    )
    model = get_model(
        plan.inspect_model_id(model_id),
        api_key=isolated_provider_environment,
        config=config,
        memoize=False,
        http_client=client,
        **plan.model_args(),
    )
    try:
        try:
            result = await model.api.generate(
                [ChatMessageUser(content="Synthetic failure test.")], [], "auto", config
            )
            failure = result[0] if isinstance(result, tuple) else result
        except (OpenAIStatusError, AnthropicStatusError) as error:
            failure = error
        assert isinstance(failure, Exception)
        assert "synthetic-provider-error" in str(failure)
        # Raw SDK errors retain reflected secrets; the runner's model guard must redact them.
        assert isolated_provider_environment in str(failure)
        assert len(requests) == 1
    finally:
        await model.api.aclose()
