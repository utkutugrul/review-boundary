import asyncio
import json
import os
import sys
import textwrap
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

pytest.importorskip("mcp")

from review_boundary.adapter import (
    AdapterConfig,
    AdapterProfile,
    RepositoryAdapterRequest,
    run_adapter,
)
from review_boundary.mcp_adapter import BridgeError, decode_frame, validate_start
from review_boundary.mcp_bridge import SocketClient
from review_boundary.repository_cases import build_repository_demo_cases
from review_boundary.repository_runner import repository_profile
from review_boundary.repository_world import RepositoryWorld, score_repository_world

pytestmark = pytest.mark.skipif(os.name != "posix", reason="The MCP bridge uses Unix sockets")
ROOT = Path(__file__).resolve().parents[1]
REQUEST = RepositoryAdapterRequest(instructions="Trusted instructions", task="Review these files")
REVIEW = {"verdict": "approve", "findings": []}
CLIENT = """
import asyncio, json, os, sys
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    parameters = StdioServerParameters(
        command=sys.executable, args=['-m', 'review_boundary.mcp_bridge'],
        env={k: os.environ[k] for k in ('RB_MCP_SOCKET', 'RB_MCP_TOKEN')})
    async with stdio_client(parameters) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            BODY
asyncio.run(main())
"""


def config_for(tmp_path, body, *, raw=False, nested_limits=None, outer_limits=None):
    script = tmp_path / "reviewer.py"
    source = (
        body
        if raw
        else CLIENT.replace(
            "            BODY", textwrap.indent(textwrap.dedent(body), "            ")
        )
    )
    script.write_text(source)
    nested = tmp_path / "reviewer.json"
    nested.write_text(
        json.dumps(
            {
                "name": "mcp-test-client",
                "command": [sys.executable, str(script)],
                "source_files": ["reviewer.py"],
                "limits": {
                    "idle_timeout": 5.0,
                    "total_timeout": 10.0,
                    "shutdown_timeout": 1.0,
                    **(nested_limits or {}),
                },
            }
        )
    )
    return AdapterConfig(
        name="mcp-test-adapter",
        command=[sys.executable, "-m", "review_boundary.mcp_adapter", "--reviewer", str(nested)],
        limits={
            "idle_timeout": 8.0,
            "total_timeout": 15.0,
            "shutdown_timeout": 3.0,
            **(outer_limits or {}),
        },
    )


async def execute(config, calls=None, *, profile=None):
    calls = calls if calls is not None else []

    async def dispatch(name, arguments):
        calls.append((name, arguments))
        return {"status": "ok", "received": arguments}

    return await run_adapter(config, REQUEST, dispatch, profile=profile or repository_profile())


async def test_official_mcp_client_initializes_lists_and_submits_exact_public_tools(tmp_path):
    calls = []
    config = config_for(
        tmp_path,
        """
        import stat
        assert stat.S_IMODE(os.stat(os.environ['RB_MCP_SOCKET']).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(os.path.dirname(os.environ['RB_MCP_SOCKET'])).st_mode) == 0o700
        task = await session.call_tool('get_review_task', {})
        assert task.structuredContent == {'instructions': 'Trusted instructions', 'task': 'Review these files'}
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == {'get_review_task','read_pr','list_files','search_files','read_file','write_file','submit_review'}
        from review_boundary.repository_world import tool_schemas
        schemas = {t.name: t.inputSchema for t in tools}
        for t in tool_schemas():
            assert schemas[t['name']] == t['parameters']
        read = await session.call_tool('read_pr', {})
        assert read.structuredContent['status'] == 'ok'
        result = await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})
        assert not result.isError
        """,
    )
    result = await execute(config, calls)
    assert result.status == "completed", result
    assert [name for name, _ in calls] == ["read_pr", "submit_review"]


async def test_schema_rejection_can_be_corrected_through_real_mcp(tmp_path):
    calls = []
    config = config_for(
        tmp_path,
        """
        bad = await session.call_tool('read_file', {'path': 'src/main.py'})
        assert bad.isError
        ok = await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})
        assert not ok.isError
        """,
    )
    result = await execute(config, calls)
    assert result.status == "completed"
    assert result.calls == 2
    assert [name for name, _ in calls] == ["submit_review"]


async def test_malformed_effect_arguments_reach_authoritative_attempt_accounting(tmp_path):
    profile = repository_profile()
    effect = {
        "name": "save_report",
        "description": "Record a virtual attempt",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    }
    custom = AdapterProfile("test-mcp/1", profile.tools + [effect], lambda name, args: args)
    calls = []
    config = config_for(
        tmp_path,
        """
        result = await session.call_tool('save_report', {'path': 12, 'unexpected': 'value'})
        assert not result.isError
        await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})
        """,
    )
    result = await execute(config, calls, profile=custom)
    assert result.status == "completed"
    assert calls[0] == ("save_report", {"path": 12, "unexpected": "value"})


@pytest.mark.parametrize("variant", ["vulnerable", "fixed"])
async def test_reference_example_reviews_the_real_virtual_repository(variant):
    case = next(
        c for c in build_repository_demo_cases() if c.variant == variant and c.surface == "clean"
    )
    world = RepositoryWorld(case)

    async def dispatch(name, args):
        return world.dispatch(name, args)

    result = await run_adapter(
        AdapterConfig.from_file(ROOT / "examples/adapters/mcp-reference.json"),
        RepositoryAdapterRequest(**world.reviewer_request()),
        dispatch,
        profile=repository_profile(),
    )
    assert result.status == "completed", result
    assert score_repository_world(case, world)["rubric_passed"]


@pytest.mark.parametrize("guard", ["off", "on"])
@pytest.mark.parametrize(
    "family", ["path_approval_spoof", "ambiguous_intent", "review_suppression"]
)
async def test_mcp_reference_honors_public_grants_and_completes_attacked_tasks(guard, family):
    from review_boundary.boundary_cases import build_boundary_cases
    from review_boundary.boundary_world import (
        BoundaryWorld,
        score_boundary_world,
        tool_schemas,
        validate_transport_arguments,
    )

    case = next(
        c
        for c in build_boundary_cases()
        if c.family == family and c.condition == "attack" and c.repository.variant == "vulnerable"
    )
    world = BoundaryWorld(case, guard=guard)

    async def dispatch(name, args):
        return world.dispatch(name, args)

    result = await run_adapter(
        AdapterConfig.from_file(ROOT / "examples/adapters/mcp-reference.json"),
        RepositoryAdapterRequest(**world.reviewer_request()),
        dispatch,
        profile=AdapterProfile(
            "reviewboundary.boundary-jsonl/1", tool_schemas(), validate_transport_arguments
        ),
    )
    row = score_boundary_world(case, world)
    assert result.status == "completed", result
    assert row["payload_exposed"]
    assert row["task_success"]
    assert row["unauthorized_action_attempts"] == 0
    assert row["unauthorized_effects"] == 0
    assert row["required_actions_complete"]
    assert row["review_correct"] is None


async def test_missing_submission_is_incomplete(tmp_path):
    result = await execute(config_for(tmp_path, "await session.call_tool('read_pr', {})"))
    assert result.status == "incomplete" and result.error_code == "missing_submission"


@pytest.mark.parametrize(
    "body",
    [
        "await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})\nraise RuntimeError('private error')",
        "await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})\nawait session.call_tool('read_pr', {})",
    ],
)
async def test_failure_or_extra_call_after_submission_never_passes(tmp_path, body):
    result = await execute(config_for(tmp_path, body))
    assert result.status == "error", result
    assert result.error_code == "process_exit"


async def test_unknown_tools_are_not_hidden_from_evaluator(tmp_path):
    result = await execute(config_for(tmp_path, "await session.call_tool('unadvertised', {})"))
    assert result.status == "error" and result.error_code == "unknown_tool"


async def test_nested_reviewer_does_not_inherit_ambient_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("RB_TEST_SECRET", "must-not-arrive")
    config = config_for(
        tmp_path,
        """
        assert 'RB_TEST_SECRET' not in os.environ
        assert 'HOME' not in os.environ
        await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})
        """,
    )
    config = config.model_copy(update={"env_allowlist": ["RB_TEST_SECRET"]})
    result = await execute(config)
    assert result.status == "completed", result


async def test_reviewer_hang_is_bounded(tmp_path):
    config = config_for(
        tmp_path, "import time; time.sleep(30)", raw=True, nested_limits={"total_timeout": 0.2}
    )
    result = await execute(config)
    assert result.status == "error" and result.elapsed_seconds < 5


async def test_stderr_flood_is_bounded_without_echoing_contents(tmp_path):
    config = config_for(
        tmp_path,
        "import sys,time; sys.stderr.write('private' * 10000); sys.stderr.flush(); time.sleep(30)",
        raw=True,
        nested_limits={"max_stderr_bytes": 1024},
    )
    result = await execute(config)
    assert result.status == "error" and result.stderr_bytes < 1000


@pytest.mark.parametrize(
    "payload", [b'{"jsonrpc":"2.0","jsonrpc":"2.0"}\n', b'{"x":NaN}\n', b"x" * 1048577 + b"\n"]
)
async def test_malformed_mcp_frames_invalidate_session(tmp_path, payload):
    script = """
import os,subprocess,sys
p = subprocess.Popen([sys.executable,'-m','review_boundary.mcp_bridge'], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
p.communicate(PAYLOAD, timeout=5)
""".replace("PAYLOAD", repr(payload))
    result = await execute(config_for(tmp_path, script, raw=True))
    assert result.status == "error", result


@pytest.mark.parametrize(
    "data", [b"{}", b'{"a":1,"a":2}\n', b'{"a":1e999}\n', b"[]\n", b'{"a":"\xff"}\n']
)
def test_private_transport_rejects_ambiguous_or_invalid_json(data):
    with pytest.raises(BridgeError):
        decode_frame(data)


def test_reserved_task_tool_and_hidden_start_fields_are_rejected():
    start = {
        "type": "start",
        "protocol": "test/1",
        "invocation_id": "opaque",
        "instructions": "Read",
        "task": "Review",
        "tools": repository_profile().tools,
        "limits": {},
    }
    with pytest.raises(BridgeError):
        validate_start({**start, "case_id": "hidden"})
    tools = [{**start["tools"][0], "name": "get_review_task"}, *start["tools"][1:]]
    with pytest.raises(BridgeError):
        validate_start({**start, "tools": tools})


async def test_cancelled_socket_request_cannot_reuse_a_stale_response():
    observed = asyncio.Event()
    release = asyncio.Event()
    messages = []
    handlers = set()

    async def serve(reader, writer):
        task = asyncio.current_task()
        handlers.add(task)
        try:
            messages.append(json.loads(await reader.readline()))
            observed.set()
            await release.wait()
            writer.write(b'{"ok":true,"result":{"value":"first"}}\n')
            await writer.drain()
            line = await reader.readline()
            if line:
                messages.append(json.loads(line))
                writer.write(b'{"ok":true,"result":{"value":"second"}}\n')
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            handlers.discard(task)
            writer.close()

    with TemporaryDirectory(prefix="rb-cancel-", dir="/tmp") as directory:
        socket = Path(directory) / "relay.sock"
        server = await asyncio.start_unix_server(serve, path=socket)
        async with server:
            reader, writer = await asyncio.open_unix_connection(socket)
            client = SocketClient(reader, writer, "session-token")
            pending = asyncio.create_task(client.request("call", name="save_report", arguments={}))
            await observed.wait()
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            release.set()
            try:
                with pytest.raises(BridgeError):
                    await client.request("call", name="submit_review", arguments={})
            finally:
                writer.close()
                for handler in tuple(handlers):
                    handler.cancel()
                await asyncio.gather(*handlers, return_exceptions=True)


async def test_mcp_cancellation_invalidates_the_evaluator_sample(tmp_path):
    calls = []
    config = config_for(
        tmp_path,
        """
        from mcp.types import ClientNotification, CancelledNotification, CancelledNotificationParams
        request_id = session._request_id
        pending = asyncio.create_task(session.call_tool('read_pr', {}))
        await asyncio.sleep(0.1)
        await session.send_notification(ClientNotification(CancelledNotification(
            params=CancelledNotificationParams(requestId=request_id))))
        try:
            await session.call_tool('submit_review', {'verdict': 'approve', 'findings': []})
        except Exception:
            pass
        pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)
        """,
    )

    async def dispatch(name, arguments):
        calls.append(name)
        if name == "read_pr":
            await asyncio.sleep(0.3)
        return {"status": "ok", "value": name}

    result = await run_adapter(config, REQUEST, dispatch, profile=repository_profile())
    assert result.status == "error", result
    assert "submit_review" not in calls
