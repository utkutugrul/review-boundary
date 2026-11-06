"""Keep credential-bearing provider failures out of evaluation logs and reports."""

import os
from copy import copy
from dataclasses import fields, is_dataclass
from functools import wraps

from inspect_ai.log._samples import _active_model_event
from inspect_ai.model import get_model
from pydantic import BaseModel


class ProviderRequestError(RuntimeError):
    """A provider failed; its untrusted response body is intentionally omitted."""


def _failure(error, secret, operation="request"):
    name = type(error).__name__.replace(secret, "[REDACTED]") if secret else type(error).__name__
    return ProviderRequestError(f"Provider {operation} failed ({name}); details withheld")


def _clean(value, secret):
    if isinstance(value, Exception):
        return _failure(value, secret)
    if isinstance(value, str):
        return value.replace(secret, "[REDACTED]") if secret else value
    if isinstance(value, (bytes, bytearray)):
        return value.replace(secret.encode(), b"[REDACTED]") if secret else value
    if isinstance(value, BaseModel):
        # Preserve SDK/Inspect private state while replacing all serializable fields.
        # Revalidating model_dump() would drop private conversation-state attributes.
        clean_fields = {
            name: _clean(getattr(value, name), secret) for name in type(value).model_fields
        }
        clean_fields.update(
            {name: _clean(item, secret) for name, item in (value.model_extra or {}).items()}
        )
        return value.model_copy(update=clean_fields)
    if is_dataclass(value) and not isinstance(value, type):
        # Inspect ToolCall is a Pydantic dataclass rather than a BaseModel.
        clean_value = copy(value)
        for field in fields(value):
            object.__setattr__(clean_value, field.name, _clean(getattr(value, field.name), secret))
        return clean_value
    if isinstance(value, tuple):
        return tuple(_clean(item, secret) for item in value)
    if isinstance(value, list):
        return [_clean(item, secret) for item in value]
    if isinstance(value, dict):
        return {_clean(key, secret): _clean(item, secret) for key, item in value.items()}
    if isinstance(value, (set, frozenset)):
        return type(value)(_clean(item, secret) for item in value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    # Do not let a later serializer stringify an opaque object carrying a secret.
    raise ProviderRequestError("Provider returned an unsupported payload type")


def _clean_partial_call(secret):
    """Scrub a call that Inspect attached to its event before the provider raised.

    Anthropic updates this context-local ModelCall before returning or raising.
    There is no public accessor; tests cover this narrow Inspect integration.
    """
    event = _active_model_event.get()
    if event is None:
        return
    try:
        event.call = _clean(event.call, secret)
        event.request_ids = _clean(event.request_ids, secret)
    except Exception:
        # Missing call detail is preferable to leaking an unrecognized payload.
        event.call = None
        event.request_ids = None
        raise


def guarded_model(plan, model_id):
    """Wrap this fresh ModelAPI instance before Inspect records an API outcome.

    Successful payloads keep their schema but scrub an echoed credential. Failed
    requests retain the exception type, never provider bodies or original exception
    chains. Execution limits and retries remain configured by the provider and task.
    """
    plan.validate_environment(os.environ)
    secret = os.environ.get(plan.api_key_env, "").strip()
    failure = None
    try:
        # api_key is Inspect's explicit, non-model_args parameter and is not logged.
        model = get_model(
            plan.inspect_model_id(model_id), api_key=secret, memoize=False, **plan.model_args()
        )
    except Exception as error:  # noqa: BLE001 - redact every SDK construction failure
        failure = _failure(error, secret, "initialization")
    if failure is not None:
        # Raise outside the except block so the SDK exception is not retained as context.
        raise failure from None
    original = model.api.generate

    @wraps(original)
    async def generate(*args, **kwargs):
        failure = None
        result = None
        try:
            try:
                result = _clean(await original(*args, **kwargs), secret)
            except Exception as error:  # noqa: BLE001 - provider and serializer errors may echo keys
                failure = _failure(error, secret)
        finally:
            try:
                _clean_partial_call(secret)
            except Exception as error:  # noqa: BLE001 - fail closed if event sanitization fails
                failure = _failure(error, secret)
        if failure is not None:
            raise failure from None
        return result

    model.api.generate = generate
    return model
