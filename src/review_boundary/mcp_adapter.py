"""Connect a trusted local MCP reviewer to the evaluator's bounded JSONL tools.

The private socket is a local transport, not an operating-system sandbox.
Only requests forwarded to the evaluator are observed by the benchmark.
"""

from __future__ import annotations

import argparse
import asyncio
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from .adapter import AdapterConfig, AdapterLimits, _parse_json

MAX_FRAME = 1048576
SOCKET_ENV = "RB_MCP_SOCKET"
TOKEN_ENV = "RB_MCP_TOKEN"


class BridgeError(ValueError):
    """A bounded transport failed; messages never include request contents."""


def encode_frame(value: dict, maximum: int = MAX_FRAME) -> bytes:
    try:
        data = (json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n").encode()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise BridgeError("Invalid bridge JSON") from None
    if len(data) > maximum:
        raise BridgeError("Bridge frame limit exceeded")
    return data


def decode_frame(line: bytes, maximum: int = MAX_FRAME) -> dict:
    if not line or len(line) > maximum or not line.endswith(b"\n"):
        raise BridgeError("Invalid bridge frame")
    try:
        value = _parse_json(line.decode("utf-8"))
        if not isinstance(value, dict):
            raise TypeError()
        encode_frame(value, maximum)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise BridgeError("Invalid bridge JSON") from None
    return value


async def read_frame(reader: asyncio.StreamReader, maximum: int, timeout: float) -> dict:
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
    except (ValueError, TimeoutError):
        raise BridgeError("Bridge read failed or exceeded its deadline") from None
    return decode_frame(line, maximum)


async def stdin_reader() -> tuple[asyncio.StreamReader, asyncio.ReadTransport]:
    reader = asyncio.StreamReader(limit=MAX_FRAME)
    transport, _ = await asyncio.get_running_loop().connect_read_pipe(
        lambda: asyncio.StreamReaderProtocol(reader), sys.stdin.buffer
    )
    return reader, transport


def validate_start(value: dict) -> tuple[dict, list[dict], AdapterLimits]:
    required = {"type", "protocol", "invocation_id", "instructions", "task", "tools", "limits"}
    if set(value) not in (required, required | {"source_path"}) or value["type"] != "start":
        raise BridgeError("Invalid evaluator start message")
    task = {}
    for key in ("instructions", "task", "source_path"):
        if key in value:
            text = value[key]
            if not isinstance(text, str) or not text or "\0" in text or len(text) > 24000:
                raise BridgeError("Invalid public task")
            task[key] = text
    tools = value["tools"]
    if not isinstance(tools, list) or not 1 <= len(tools) <= 64:
        raise BridgeError("Invalid advertised tool list")
    names = set()
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {"name", "description", "parameters"}:
            raise BridgeError("Invalid advertised tool")
        name = tool["name"]
        if (
            not isinstance(name, str)
            or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", name)
            or name in names
            or name == "get_review_task"
            or not isinstance(tool["description"], str)
            or not isinstance(tool["parameters"], dict)
        ):
            raise BridgeError("Invalid advertised tool")
        names.add(name)
    if "submit_review" not in names:
        raise BridgeError("The evaluator must advertise submit_review")
    return task, tools, AdapterLimits.model_validate(value["limits"])


class MCPRelay:
    def __init__(self, reader: asyncio.StreamReader, start: dict):
        self.reader = reader
        self.task, self.tools, self.limits = validate_start(start)
        self.token = secrets.token_hex(32)
        self.lock = asyncio.Lock()
        self.requests = self.calls = 0
        self.submitted = False
        self.failed = asyncio.Event()
        self.writers: set[asyncio.StreamWriter] = set()

    def fail(self) -> None:
        self.failed.set()

    async def request(self, message: dict) -> dict:
        self.requests += 1
        if self.requests > self.limits.max_calls + 16:
            raise BridgeError("Bridge request limit exceeded")
        operation = message.get("operation")
        if operation == "describe" and set(message) == {"token", "operation"}:
            return {"ok": True, "task": self.task, "tools": self.tools}
        if operation == "fault" and set(message) == {"token", "operation"}:
            raise BridgeError("MCP transport failed")
        if operation != "call" or set(message) != {"token", "operation", "name", "arguments"}:
            raise BridgeError("Invalid bridge operation")
        name, arguments = message["name"], message["arguments"]
        if not isinstance(name, str) or len(name) > 128 or not isinstance(arguments, dict):
            raise BridgeError("Invalid tool call")
        if self.submitted:
            raise BridgeError("Tool call after submission")
        self.calls += 1
        if self.calls > self.limits.max_calls:
            raise BridgeError("Bridge call limit exceeded")
        call_id = f"mcp-{self.calls}"
        outgoing = {"type": "call", "id": call_id, "tool": name, "arguments": arguments}
        sys.stdout.buffer.write(encode_frame(outgoing, self.limits.max_line_bytes))
        sys.stdout.buffer.flush()
        result = await read_frame(self.reader, self.limits.max_line_bytes, self.limits.idle_timeout)
        if result.get("type") != "result" or result.get("id") != call_id:
            raise BridgeError("Unexpected evaluator response")
        if type(result.get("ok")) is not bool:
            raise BridgeError("Invalid evaluator result")
        if result["ok"]:
            if set(result) != {"type", "id", "ok", "result"}:
                raise BridgeError("Invalid evaluator result")
            if name == "submit_review":
                stop = await read_frame(
                    self.reader, self.limits.max_line_bytes, self.limits.idle_timeout
                )
                if stop != {"type": "stop", "reason": "review_submitted"}:
                    raise BridgeError("Invalid evaluator stop")
                self.submitted = True
            return {"ok": True, "result": result["result"]}
        if set(result) != {"type", "id", "ok", "error"}:
            raise BridgeError("Invalid evaluator error")
        return {"ok": False, "error": {"code": "invalid_arguments"}}

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self.writers) >= 8:
            writer.close()
            await writer.wait_closed()
            return
        self.writers.add(writer)
        authenticated = False
        try:
            while not self.failed.is_set():
                # EOF from a normally closed MCP client does not itself invalidate a run.
                line = await asyncio.wait_for(reader.readline(), self.limits.idle_timeout)
                if not line:
                    return
                message = decode_frame(line)
                token = message.get("token")
                if not isinstance(token, str) or not hmac.compare_digest(token, self.token):
                    return
                authenticated = True
                async with self.lock:
                    response = await self.request(message)
                writer.write(encode_frame(response))
                await asyncio.wait_for(writer.drain(), self.limits.idle_timeout)
        except (BridgeError, ValueError, TimeoutError, OSError):
            if authenticated:
                self.fail()
        finally:
            self.writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def close(self):
        for writer in tuple(self.writers):
            writer.close()
        await asyncio.gather(
            *(writer.wait_closed() for writer in tuple(self.writers)), return_exceptions=True
        )


async def run_mcp_adapter(config: AdapterConfig) -> int:
    reader, input_transport = await stdin_reader()
    process = None
    relay = None
    tasks = []
    try:
        start = await read_frame(reader, MAX_FRAME, config.limits.idle_timeout)
        relay = MCPRelay(reader, start)
        source = config.source_fingerprint()
        # A short path also works on systems with a small Unix-socket path limit.
        with TemporaryDirectory(prefix="rb-mcp-", dir="/tmp") as directory:
            socket = str(Path(directory) / "relay.sock")
            server = await asyncio.start_unix_server(relay.serve, path=socket, limit=MAX_FRAME)
            os.chmod(socket, 0o600)
            env = config.environment()
            env.update({SOCKET_ENV: socket, TOKEN_ENV: relay.token})
            async with server:
                process = await asyncio.create_subprocess_exec(
                    *config.argv(),
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=directory,
                )

                async def drain_stderr():
                    total = 0
                    while chunk := await process.stderr.read(4096):
                        total += len(chunk)
                        if total > min(
                            config.limits.max_stderr_bytes, relay.limits.max_stderr_bytes
                        ):
                            relay.fail()
                            return

                stderr = asyncio.create_task(drain_stderr())
                exited = asyncio.create_task(process.wait())
                failed = asyncio.create_task(relay.failed.wait())
                tasks = [stderr, exited, failed]
                timeout = min(config.limits.total_timeout, relay.limits.total_timeout)
                done, _ = await asyncio.wait(
                    [exited, failed], timeout=timeout, return_when=asyncio.FIRST_COMPLETED
                )
                if exited not in done or relay.failed.is_set() or process.returncode != 0:
                    raise BridgeError("MCP reviewer failed or exceeded its deadline")
                await asyncio.wait_for(stderr, min(config.limits.shutdown_timeout, 2.0))
                if relay.failed.is_set() or config.source_fingerprint() != source:
                    raise BridgeError("MCP reviewer source changed or transport failed")
                if not relay.submitted:
                    sys.stdout.buffer.write(encode_frame({"type": "done"}))
                    sys.stdout.buffer.flush()
                    stop = await read_frame(reader, MAX_FRAME, relay.limits.idle_timeout)
                    if stop != {"type": "stop", "reason": "missing_submission"}:
                        raise BridgeError("Invalid evaluator stop")
                return 0
    finally:
        if relay is not None:
            await relay.close()
        if process is not None and process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), 0.3)
            except (TimeoutError, ProcessLookupError):
                if process.returncode is None:
                    process.kill()
                    await process.wait()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        input_transport.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Bridge a trusted MCP reviewer to virtual tools")
    parser.add_argument("--reviewer", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        return asyncio.run(run_mcp_adapter(AdapterConfig.from_file(args.reviewer)))
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - redact all entry-point failures
        # Do not echo task text, paths, command arguments, credentials or raw exceptions.
        print("MCP reviewer bridge failed.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
