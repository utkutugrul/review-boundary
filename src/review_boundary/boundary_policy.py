"""Optional bounded process interface for a caller-selected policy engine.

The engine is trusted local code. Its decisions are measured against the
evaluator's independent authorization oracle, never used as ground truth.
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from .adapter import AdapterConfig
from .json_input import parse_json_object, read_json_object

PROTOCOL = "reviewboundary.policy-json/1"


def load_policy_config(path: Path | None) -> AdapterConfig | None:
    if path is None:
        return None
    path = Path(path).resolve()
    if path.stat().st_size > 65536:
        raise ValueError("Policy configuration exceeds 65536 bytes")
    config = AdapterConfig.model_validate(read_json_object(path))
    config._base_dir = path.parent
    return config


def policy_metadata(config: AdapterConfig | None) -> dict | None:
    if config is None:
        return None
    return {
        **config.to_metadata(),
        "protocol": PROTOCOL,
        "source": config.source_fingerprint(),
        "scope": "Caller-selected local process. Its decisions are not evaluator ground truth.",
    }


def _stop(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        if process.poll() is None:
            raise ValueError("Policy process cleanup failed") from None
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        raise ValueError("Policy process cleanup timed out") from None


def _evaluate(
    config: AdapterConfig,
    payload: dict,
    *,
    invocation_deadline: float | None = None,
    call_timeout: float | None = None,
) -> dict:
    if os.name != "posix":
        raise ValueError("Policy processes require Linux or macOS")
    raw = (json.dumps(payload, ensure_ascii=False, allow_nan=False) + "\n").encode()
    if len(raw) > config.limits.max_line_bytes:
        raise ValueError("Policy input exceeds its byte limit")
    timeout = min(config.limits.total_timeout, config.limits.idle_timeout)
    if call_timeout is not None:
        timeout = min(timeout, call_timeout)
    deadline = time.monotonic() + timeout
    if invocation_deadline is not None:
        deadline = min(deadline, invocation_deadline)
    if time.monotonic() >= deadline:
        raise ValueError("Policy process exceeded its deadline")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    maxima = {
        "stdout": config.limits.max_line_bytes,
        "stderr": config.limits.max_stderr_bytes,
    }
    with (
        tempfile.TemporaryDirectory(prefix="reviewboundary-policy-") as cwd,
        tempfile.TemporaryFile() as source,
    ):
        source.write(raw)
        source.seek(0)
        try:
            process = subprocess.Popen(
                config.argv(),
                stdin=source,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=config.environment(),
                start_new_session=True,
            )
        except (OSError, ValueError):
            raise ValueError("Policy process could not be started") from None
        try:
            with selectors.DefaultSelector() as selector:
                for name in buffers:
                    stream = getattr(process, name)
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors.EVENT_READ, name)
                while selector.get_map() or process.poll() is None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ValueError("Policy process exceeded its deadline")
                    for key, _ in selector.select(min(remaining, 0.1)):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        name = key.data
                        if len(buffers[name]) + len(chunk) > maxima[name]:
                            raise ValueError("Policy output exceeds its byte limit")
                        buffers[name].extend(chunk)
            if process.returncode != 0:
                raise ValueError("Policy process exited unsuccessfully")
        finally:
            _stop(process)
            process.stdout.close()
            process.stderr.close()
    try:
        result = parse_json_object(bytes(buffers["stdout"]))
        if set(result) != {"decision", "reason"}:
            raise ValueError
        if result["decision"] not in ("allow", "deny", "escalate"):
            raise ValueError
        reason = result["reason"]
        if not isinstance(reason, str) or not reason.strip() or "\0" in reason:
            raise ValueError
        if len(reason.encode("utf-8")) > 1024:
            raise ValueError
    except (TypeError, ValueError, UnicodeError):
        raise ValueError("Policy process returned an invalid decision") from None
    if time.monotonic() >= deadline:
        raise ValueError("Policy process exceeded its deadline")
    return result


def make_policy(
    config: AdapterConfig | None,
    document: dict,
    *,
    invocation_deadline: float | None = None,
    call_timeout: float | None = None,
):
    if config is None:
        return None
    # Snapshot caller-owned policy input so an engine callback cannot mutate it.
    snapshot = json.loads(json.dumps(document, allow_nan=False))

    def evaluate(name: str, arguments: dict) -> dict:
        return _evaluate(
            config,
            {
                "protocol": PROTOCOL,
                "policy": snapshot,
                "request": {"tool": name, "arguments": arguments},
            },
            invocation_deadline=invocation_deadline,
            call_timeout=call_timeout,
        )

    return evaluate
