"""Verify credential redaction before SDK outcomes enter persistent Inspect logs."""

import json
import traceback
import zipfile
from types import SimpleNamespace

import httpx2
import pytest
from inspect_ai import eval_async
from inspect_ai.event import ModelEvent
from inspect_ai.log import read_eval_log
from inspect_ai.log._samples import track_active_model_event
from inspect_ai.model import GenerateConfig, ModelOutput
from inspect_ai.model._model_call import ModelCall, ModelRequestId
from inspect_ai.tool import ToolCall
from openai import AuthenticationError
from pydantic import BaseModel, ConfigDict, PrivateAttr

from review_boundary import model_safety
from review_boundary.cases import build_cases
from review_boundary.providers import COMMON_OVERRIDES, OVERRIDE_VARIABLES, prepare_provider
from review_boundary.report import rows_from_logs
from review_boundary.task import review_boundary

SECRET = "synthetic-redaction-key-DO-NOT-USE"


@pytest.fixture
def native_plan(tmp_path, monkeypatch):
    for name in (
        *COMMON_OVERRIDES,
        *(name for names in OVERRIDE_VARIABLES.values() for name in names),
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("OPENAI_SAFETY_IDENTIFIER", raising=False)

    def build(provider="openai", model=None):
        model = model or ("gpt-4.1-mini" if provider == "openai" else "claude-sonnet-4-5")
        source = (
            "https://openai.com/api/pricing/"
            if provider == "openai"
            else "https://platform.claude.com/docs/en/about-claude/pricing"
        )
        path = tmp_path / f"{provider}-pricing.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "provider": provider,
                    "source": source,
                    "as_of": "2026-01-01",
                    "models": {model: {"input_usd_per_million": 1, "output_usd_per_million": 2}},
                }
            )
        )
        plan = prepare_provider(provider, [model], pricing_file=path)
        monkeypatch.setenv(plan.api_key_env, SECRET)
        return plan

    return build


def sdk_error():
    request = httpx2.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx2.Response(401, request=request)
    return AuthenticationError(
        "private-driver-message " + SECRET, response=response, body={"message": SECRET}
    )


def install_fake_api(monkeypatch, generate):
    model = SimpleNamespace(api=SimpleNamespace(generate=generate))
    captured = {}

    def build(*args, **kwargs):
        captured.update(kwargs)
        return model

    monkeypatch.setattr(model_safety, "get_model", build)
    return model, captured


def test_nested_fields_bytes_sets_and_private_state_are_handled():
    class Envelope(BaseModel):
        model_config = ConfigDict(extra="allow")
        label: str
        _provider_state: str = PrivateAttr(default="preserve-private-conversation-state")

    envelope = Envelope(label=SECRET, extra={SECRET: [SECRET.encode(), bytearray(SECRET.encode())]})
    output = ModelOutput.from_content("synthetic", "echo: " + SECRET)
    output.message.tool_calls = [
        ToolCall(id="call_1", function="read_file", arguments={"path": SECRET}, parse_error=SECRET)
    ]
    output.metadata = {
        "nested": envelope,
        "tuple": (SECRET,),
        "set": {SECRET},
        "frozen": frozenset([SECRET]),
    }
    call = ModelCall(request={SECRET: ["before " + SECRET]}, response={"nested": {"body": SECRET}})
    clean_output, clean_call = model_safety._clean((output, call), SECRET)
    assert isinstance(clean_output, ModelOutput)
    assert isinstance(clean_call, ModelCall)
    assert clean_output.completion == "echo: [REDACTED]"
    assert isinstance(clean_output.message.tool_calls[0], ToolCall)
    assert clean_output.message.tool_calls[0].arguments == {"path": "[REDACTED]"}
    assert clean_output.message.tool_calls[0].parse_error == "[REDACTED]"
    assert output.message.tool_calls[0].arguments == {"path": SECRET}
    assert clean_output.metadata["nested"]._provider_state == "preserve-private-conversation-state"
    assert clean_output.metadata["nested"].label == "[REDACTED]"
    assert clean_output.metadata["nested"].extra == {
        "[REDACTED]": [b"[REDACTED]", bytearray(b"[REDACTED]")]
    }
    assert clean_output.metadata["tuple"] == ("[REDACTED]",)
    assert clean_output.metadata["set"] == {"[REDACTED]"}
    assert clean_output.metadata["frozen"] == frozenset(["[REDACTED]"])
    assert clean_call.request == {"[REDACTED]": ["before [REDACTED]"]}
    assert clean_call.response == {"nested": {"body": "[REDACTED]"}}
    assert SECRET in output.completion
    assert call.response["nested"]["body"] == SECRET


async def test_raised_sdk_exception_has_no_original_chain(native_plan, monkeypatch):
    async def generate(**kwargs):
        raise sdk_error()

    _, captured = install_fake_api(monkeypatch, generate)
    plan = native_plan()
    guarded = model_safety.guarded_model(plan, plan.model_ids[0])
    assert captured["api_key"] == SECRET
    with pytest.raises(model_safety.ProviderRequestError) as failure:
        await guarded.api.generate()
    assert "AuthenticationError" in str(failure.value)
    assert failure.value.__cause__ is None
    assert failure.value.__context__ is None
    formatted = "".join(traceback.format_exception(failure.value))
    assert SECRET not in formatted
    assert "private-driver-message" not in formatted
    assert not hasattr(failure.value, "response")


async def test_returned_sdk_exception_and_call_are_scrubbed(native_plan, monkeypatch):
    original_error = sdk_error()

    async def generate(**kwargs):
        return original_error, ModelCall(
            request={"prompt": SECRET}, response={"error": SECRET}, error=True
        )

    install_fake_api(monkeypatch, generate)
    plan = native_plan()
    result, call = await model_safety.guarded_model(plan, plan.model_ids[0]).api.generate()
    assert isinstance(result, model_safety.ProviderRequestError)
    assert result is not original_error
    assert result.__cause__ is result.__context__ is None
    assert SECRET not in str(result)
    assert SECRET not in call.model_dump_json()
    assert call.error is True


async def test_partial_call_attached_before_raise_is_scrubbed(native_plan, monkeypatch):
    event = ModelEvent(
        model="synthetic",
        input=[],
        tools=[],
        tool_choice="auto",
        config=GenerateConfig(),
        output=ModelOutput.from_content("synthetic", ""),
    )

    async def generate(**kwargs):
        event.call = ModelCall(request={"prompt": "normal"}, response={"error": SECRET}, error=True)
        event.request_ids = [ModelRequestId(id=SECRET, header="x-request-id", status=401)]
        raise sdk_error()

    install_fake_api(monkeypatch, generate)
    plan = native_plan()
    model = model_safety.guarded_model(plan, plan.model_ids[0])
    with track_active_model_event(event), pytest.raises(model_safety.ProviderRequestError):
        await model.api.generate()
    assert event.call.response == {"error": "[REDACTED]"}
    assert event.request_ids[0].id == "[REDACTED]"
    assert SECRET not in event.model_dump_json()


def test_constructor_exception_is_generic_and_not_chained(native_plan, monkeypatch):
    def fail(*args, **kwargs):
        raise sdk_error()

    monkeypatch.setattr(model_safety, "get_model", fail)
    plan = native_plan()
    with pytest.raises(model_safety.ProviderRequestError, match="initialization") as failure:
        model_safety.guarded_model(plan, plan.model_ids[0])
    assert failure.value.__cause__ is failure.value.__context__ is None
    assert SECRET not in "".join(traceback.format_exception(failure.value))
    assert "private-driver-message" not in str(failure.value)


async def test_key_is_bound_before_constructor_and_environment_changes(native_plan, monkeypatch):
    plan = native_plan()

    def build(*args, **kwargs):
        captured_key = kwargs["api_key"]
        monkeypatch.setenv(plan.api_key_env, "different-synthetic-key")

        async def generate(**kwargs):
            return ModelOutput.from_content("synthetic", captured_key)

        return SimpleNamespace(api=SimpleNamespace(generate=generate))

    monkeypatch.setattr(model_safety, "get_model", build)
    model = model_safety.guarded_model(plan, plan.model_ids[0])
    assert (await model.api.generate()).completion == "[REDACTED]"


def test_no_model_is_constructed_without_selected_key(native_plan, monkeypatch):
    plan = native_plan()
    monkeypatch.delenv(plan.api_key_env)
    monkeypatch.setattr(
        model_safety, "get_model", lambda *args, **kwargs: pytest.fail("constructed without a key")
    )
    with pytest.raises(ValueError, match=plan.api_key_env):
        model_safety.guarded_model(plan, plan.model_ids[0])


async def test_opaque_output_fails_without_stringifying_private_data(native_plan, monkeypatch):
    class Opaque:
        def __str__(self):
            return SECRET

        __repr__ = __str__

    async def generate(**kwargs):
        output = ModelOutput.from_content("synthetic", "normal")
        output.metadata = {"opaque": Opaque()}
        return output

    install_fake_api(monkeypatch, generate)
    plan = native_plan()
    with pytest.raises(model_safety.ProviderRequestError) as failure:
        await model_safety.guarded_model(plan, plan.model_ids[0]).api.generate()
    assert SECRET not in "".join(traceback.format_exception(failure.value))
    assert failure.value.__context__ is None


def tool_response(provider, model_id, function, arguments, number, responses_api=False):
    if provider == "anthropic":
        return {
            "id": f"msg_{number}",
            "type": "message",
            "role": "assistant",
            "model": model_id,
            "content": [
                {"type": "text", "text": "echo " + SECRET},
                {"type": "tool_use", "id": f"call_{number}", "name": function, "input": arguments},
            ],
            "stop_reason": "tool_use",
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }
    if responses_api:
        return {
            "id": f"resp_{number}",
            "object": "response",
            "created_at": 0,
            "status": "completed",
            "error": None,
            "incomplete_details": None,
            "model": model_id,
            "output": [
                {
                    "type": "message",
                    "id": f"msg_{number}",
                    "role": "assistant",
                    "status": "completed",
                    "content": [
                        {"type": "output_text", "text": "echo " + SECRET, "annotations": []}
                    ],
                },
                {
                    "type": "function_call",
                    "id": f"fc_{number}",
                    "call_id": f"call_{number}",
                    "name": function,
                    "arguments": json.dumps(arguments),
                    "status": "completed",
                },
            ],
            "parallel_tool_calls": False,
            "tool_choice": "auto",
            "tools": [],
            "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
        }
    return {
        "id": f"chatcmpl_{number}",
        "object": "chat.completion",
        "created": 0,
        "model": model_id,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "echo " + SECRET,
                    "tool_calls": [
                        {
                            "id": f"call_{number}",
                            "type": "function",
                            "function": {"name": function, "arguments": json.dumps(arguments)},
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    }


@pytest.mark.parametrize(
    "provider,model_id,responses_api",
    [
        ("openai", "gpt-4.1-mini", False),
        ("openai", "gpt-5-mini", True),
        ("anthropic", "claude-sonnet-4-5", False),
    ],
)
@pytest.mark.parametrize("status", [200, 401])
async def test_real_inspect_logs_do_not_retain_echoed_key(
    tmp_path, native_plan, monkeypatch, provider, model_id, responses_api, status
):
    plan = native_plan(provider, model_id)
    case = next(
        case for case in build_cases(language="python") if case.id == "tenant_lookup/fixed/clean"
    )
    commands = [
        ("read_pr", {}),
        ("read_file", {"path": "README.md"}),
        ("read_file", {"path": case.source_path}),
        ("submit_review", {"verdict": "approve", "findings": []}),
    ]
    requests = []

    def respond(request):
        requests.append(request)
        if status != 200:
            return httpx2.Response(
                status,
                json={
                    "type": "error",
                    "error": {
                        "type": "authentication_error",
                        "message": "private-driver-message " + SECRET,
                        "code": "invalid_api_key",
                    },
                },
            )
        function, arguments = commands[len(requests) - 1]
        return httpx2.Response(
            200,
            json=tool_response(
                provider, model_id, function, arguments, len(requests), responses_api
            ),
        )

    client = httpx2.AsyncClient(transport=httpx2.MockTransport(respond), trust_env=False)
    real_get_model = model_safety.get_model

    def build(*args, **kwargs):
        return real_get_model(*args, http_client=client, **kwargs)

    monkeypatch.setattr(model_safety, "get_model", build)
    model = model_safety.guarded_model(plan, plan.model_ids[0])
    directory = tmp_path / "logs"
    try:
        logs = await eval_async(
            review_boundary(
                cases=[case],
                max_turns=6,
                max_output_tokens=256,
                reasoning_summary="none" if provider == "openai" else None,
            ),
            model=model,
            log_dir=str(directory),
            max_samples=1,
            log_model_api=True,
        )
        assert len(logs) == 1
        rows = rows_from_logs(logs)
        assert rows[0]["passed"] is (status == 200)
        assert len(requests) == (4 if status == 200 else 1)
        assert SECRET not in logs[0].model_dump_json()
        assert SECRET not in read_eval_log(logs[0].location).model_dump_json()
        assert "api_key" not in logs[0].eval.model_args
        if status != 200:
            assert logs[0].samples[0].error
            assert "private-driver-message" not in logs[0].samples[0].error.message
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    for name in archive.namelist():
                        assert SECRET.encode() not in archive.read(name), name
            else:
                assert SECRET.encode() not in path.read_bytes(), path.name
    finally:
        await model.api.aclose()
