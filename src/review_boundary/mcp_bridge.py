"""MCP stdio facade for a single evaluator-owned virtual review session."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from contextlib import suppress

from .mcp_adapter import (
    MAX_FRAME,
    SOCKET_ENV,
    TOKEN_ENV,
    BridgeError,
    decode_frame,
    encode_frame,
    read_frame,
    stdin_reader,
)


class SocketClient:
    def __init__(self, reader, writer, token):
        self.reader, self.writer, self.token = reader, writer, token
        self.lock = asyncio.Lock()
        self.poisoned = False

    def poison(self) -> None:
        # Once a request has been written, cancellation can leave its reply queued.
        # End this session rather than attributing that reply to a later tool call.
        self.poisoned = True
        with suppress(OSError, RuntimeError):
            self.writer.write(encode_frame({"token": self.token, "operation": "fault"}))
        self.writer.close()

    async def request(self, operation: str, **values) -> dict:
        async with self.lock:
            if self.poisoned:
                raise BridgeError("MCP session is no longer usable")
            try:
                self.writer.write(
                    encode_frame({"token": self.token, "operation": operation, **values})
                )
                await asyncio.wait_for(self.writer.drain(), 30.0)
                return await read_frame(self.reader, MAX_FRAME, 600.0)
            except (asyncio.CancelledError, ValueError, OSError, TimeoutError):
                self.poison()
                raise


class BoundedInput:
    """Fail the session on malformed MCP messages instead of hiding attempted calls."""

    def __init__(self, reader, relay):
        self.reader, self.relay = reader, relay

    def __aiter__(self):
        return self

    async def __anext__(self):
        from mcp.types import JSONRPCMessage

        try:
            line = await self.reader.readline()
            if not line:
                raise StopAsyncIteration
            value = decode_frame(line)
            JSONRPCMessage.model_validate(value)
            if value.get("method") == "tools/call":
                params = value.get("params")
                if not isinstance(params, dict) or not isinstance(params.get("name"), str):
                    raise BridgeError("Invalid MCP tool call")
                if "arguments" in params and not isinstance(params["arguments"], dict):
                    raise BridgeError("Invalid MCP tool arguments")
            return line.decode("utf-8")
        except StopAsyncIteration:
            raise
        except (ValueError, UnicodeError, OSError, TimeoutError):
            with suppress(ValueError, OSError, TimeoutError):
                await self.relay.request("fault")
            raise BridgeError("Invalid MCP input") from None


async def run_bridge() -> None:
    from mcp.server.lowlevel import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import CallToolResult, TextContent, Tool

    socket, token = os.environ.get(SOCKET_ENV), os.environ.get(TOKEN_ENV)
    if not socket or not token:
        raise BridgeError("Missing private session configuration")
    reader, writer = await asyncio.open_unix_connection(socket, limit=MAX_FRAME)
    relay = SocketClient(reader, writer, token)
    input_transport = None
    try:
        description = await relay.request("describe")
        if description.get("ok") is not True:
            raise BridgeError("Session unavailable")
        server = Server("review-boundary", version="1")

        @server.list_tools()
        async def list_tools():
            return [
                Tool(
                    name="get_review_task",
                    description="Read the trusted caller instructions and review task.",
                    inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
                ),
                *[
                    Tool(name=t["name"], description=t["description"], inputSchema=t["parameters"])
                    for t in description["tools"]
                ],
            ]

        @server.call_tool(validate_input=False)
        async def call_tool(name, arguments):
            # The evaluator is authoritative. In particular, malformed effect arguments
            # must reach its attempt accounting rather than disappearing in SDK checks.
            if name == "get_review_task":
                if arguments:
                    return CallToolResult(
                        content=[TextContent(type="text", text="Unexpected task arguments")],
                        isError=True,
                    )
                return description["task"]
            try:
                response = await relay.request("call", name=name, arguments=arguments)
            except (ValueError, OSError, TimeoutError):
                return CallToolResult(
                    content=[TextContent(type="text", text="Evaluator session unavailable")],
                    isError=True,
                )
            if response.get("ok") is not True:
                return CallToolResult(
                    content=[TextContent(type="text", text="Tool arguments rejected by evaluator")],
                    isError=True,
                )
            result = response["result"]
            # Structured results preserve objects; other legacy results remain JSON text.
            return CallToolResult(
                content=[TextContent(type="text", text=json.dumps(result, ensure_ascii=False))],
                structuredContent=result if isinstance(result, dict) else None,
            )

        std_input, input_transport = await stdin_reader()
        async with stdio_server(stdin=BoundedInput(std_input, relay)) as (incoming, outgoing):
            await server.run(incoming, outgoing, server.create_initialization_options())
    finally:
        writer.close()
        await writer.wait_closed()
        if input_transport:
            input_transport.close()


def main() -> int:
    try:
        asyncio.run(run_bridge())
        return 0
    except (Exception, KeyboardInterrupt):  # noqa: BLE001 - redact SDK and transport failures
        print(
            "MCP bridge failed. Install the mcp extra and start it through an evaluator session.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
