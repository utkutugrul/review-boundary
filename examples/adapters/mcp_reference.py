"""Keyless MCP reviewer for the bundled original tenant fixture only.

This example consumes the same public task and tool responses as another MCP
client. It is a transport calibration, not a general security reviewer.
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from review_boundary.repository_runner import scripted_submission


async def call(session, name, **arguments):
    result = await session.call_tool(name, arguments)
    if result.isError:
        raise ValueError("Evaluator rejected tool call")
    value = result.structuredContent
    if value is None:
        value = json.loads(result.content[0].text)
    if value.get("status", "ok") != "ok":
        raise ValueError("Virtual operation failed")
    return value


async def main():
    connection = StdioServerParameters(
        command=sys.executable,
        args=["-m", "review_boundary.mcp_bridge"],
        env={name: os.environ[name] for name in ("RB_MCP_SOCKET", "RB_MCP_TOKEN")},
    )
    async with stdio_client(connection) as streams, ClientSession(*streams) as session:
        await session.initialize()
        task = await call(session, "get_review_task")
        tools = {tool.name for tool in (await session.list_tools()).tools}
        await call(session, "read_pr")
        cursor, paths = 0, []
        while cursor is not None:
            page = await call(session, "list_files", cursor=cursor)
            paths.extend(item["path"] for item in page["files"])
            next_cursor = page["next_cursor"]
            if next_cursor is not None and next_cursor <= cursor:
                raise ValueError("File listing did not advance")
            cursor = next_cursor
        files = {}
        for path in paths:
            start, lines = 1, []
            while start is not None:
                page = await call(
                    session, "read_file", path=path, start_line=start, end_line=start + 79
                )
                for line in page["lines"]:
                    if line["line"] != len(lines) + 1:
                        raise ValueError("Source range was not contiguous")
                    lines.append(line["text"])
                next_line = page["next_line"]
                if next_line is not None and next_line <= start:
                    raise ValueError("Source reading did not advance")
                start = next_line
            files[path] = "\n".join(lines)
        review = scripted_submission(files)
        if "read_action_request" in tools:
            await call(session, "read_action_request")
            # Boundary tasks describe their approved actions in trusted caller text.
            # The evaluator's labels, hidden policy and issue rubric remain absent.
            for line in task["instructions"].splitlines():
                if line.startswith("Authorized report actions: "):
                    actions, _ = json.JSONDecoder().raw_decode(
                        line.removeprefix("Authorized report actions: ")
                    )
                    for action in actions:
                        name = action["tool"]
                        field = "path" if name == "save_report" else "url"
                        await call(
                            session,
                            name,
                            **{
                                field: action["target"],
                                "content": json.dumps(review, ensure_ascii=False),
                            },
                        )
        await call(session, "submit_review", **review)


if __name__ == "__main__":
    asyncio.run(main())
