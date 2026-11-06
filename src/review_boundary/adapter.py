"""Bounded JSONL transport for a user-selected, trusted local reviewer process.

This is a protocol adapter, not an operating-system sandbox. Only calls routed
through ``dispatch`` are observed by the evaluation world.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import signal
import sys
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

from .world import Review

PROTOCOL = "reviewboundary.jsonl/1"
Dispatch = Callable[[str, dict[str, Any]], Awaitable[Any]]


class AdapterLimits(BaseModel):
    """Transport limits, independent of the reviewer's own API spending limits."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)
    max_calls: int = Field(default=64, ge=1, le=1000)
    max_line_bytes: int = Field(default=65536, ge=4096, le=1048576)
    max_stderr_bytes: int = Field(default=65536, ge=1024, le=1048576)
    idle_timeout: float = Field(default=30.0, ge=0.05, le=600.0)
    total_timeout: float = Field(default=120.0, ge=0.05, le=3600.0)
    shutdown_timeout: float = Field(default=2.0, ge=0.05, le=10.0)


class AdapterConfig(BaseModel):
    """Explicit opt-in to execute a command. Environment values are never serialized."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, hide_input_in_errors=True)
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    command: list[str] = Field(min_length=1, max_length=64)
    env_allowlist: list[str] = Field(default_factory=list, max_length=64)
    source_files: list[str] = Field(default_factory=list, max_length=32)
    limits: AdapterLimits = Field(default_factory=AdapterLimits)
    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    @field_validator("command")
    @classmethod
    def command_arguments(cls, value: list[str]) -> list[str]:
        if any(not part or "\0" in part or len(part) > 16384 for part in value):
            raise ValueError("Command arguments must be nonempty bounded strings without NULs.")
        return value

    @field_validator("env_allowlist")
    @classmethod
    def environment_names(cls, value: list[str]) -> list[str]:
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in value):
            raise ValueError("Environment allowlist entries must be exact variable names.")
        if len(set(value)) != len(value):
            raise ValueError("Environment allowlist entries must be unique.")
        return value

    @field_validator("source_files")
    @classmethod
    def source_names(cls, value: list[str]) -> list[str]:
        from .provenance import source_path

        if len(set(value)) != len(value):
            raise ValueError("Reviewer source files must be distinct")
        return [source_path(path) for path in value]

    def source_fingerprint(self) -> dict:
        from .provenance import source_fingerprint

        return source_fingerprint(self._base_dir, self.source_files)

    @classmethod
    def from_file(cls, path: str | Path) -> AdapterConfig:
        path = Path(path).resolve()
        if path.stat().st_size > 65536:
            raise ValueError("Adapter configuration exceeds 65536 bytes.")
        config = cls.model_validate(_parse_json(path.read_text(encoding="utf-8")))
        config._base_dir = path.parent
        return config

    def argv(self) -> list[str]:
        # No shell expansion. These two placeholders are simple literal substitutions.
        argv = [
            item.replace("{python}", sys.executable).replace("{config_dir}", str(self._base_dir))
            for item in self.command
        ]
        executable = shutil.which(argv[0])
        if executable is None:
            raise ValueError("Adapter executable could not be resolved.")
        # Preserve a virtualenv's executable symlink so its package environment works.
        argv[0] = str(Path(executable).absolute())
        return argv

    def environment(self) -> dict[str, str]:
        # Deliberately omit HOME, PYTHONPATH, proxy settings, and every API credential.
        env = {"PATH": os.defpath, "LANG": "C.UTF-8"}
        env.update({name: os.environ[name] for name in self.env_allowlist if name in os.environ})
        return env

    def to_metadata(self) -> dict[str, Any]:
        canonical = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"))
        return {
            "name": self.name,
            "protocol": PROTOCOL,
            "config_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "limits": self.limits.model_dump(),
            "env_allowlist": list(self.env_allowlist),
            "observation_scope": "protocol_tool_calls_only",
            "os_sandboxed": False,
        }


@dataclass(frozen=True, slots=True)
class AdapterRequest:
    """Only trusted task text and the public source path belong in the start message.

    Construct this explicitly. Never pass Case objects, case IDs, expected labels,
    injection locations, split names, or finding anchors to an external reviewer.
    """

    instructions: str
    task: str
    source_path: str

    def __post_init__(self) -> None:
        for field, limit in (("instructions", 24000), ("task", 24000), ("source_path", 512)):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or "\0" in value or len(value) > limit:
                raise ValueError(f"Invalid adapter request {field}.")


@dataclass(frozen=True, slots=True)
class RepositoryAdapterRequest:
    """A repository review starts without evaluator labels or a privileged source file."""

    instructions: str
    task: str

    def __post_init__(self) -> None:
        for field in ("instructions", "task"):
            value = getattr(self, field)
            if not isinstance(value, str) or not value or "\0" in value or len(value) > 24000:
                raise ValueError(f"Invalid repository adapter request {field}.")


@dataclass(frozen=True)
class AdapterProfile:
    """A runner-owned tool contract, never loaded from reviewer-controlled configuration."""

    protocol: str
    tools: list[dict[str, Any]]
    validate_arguments: Callable[[str, dict], dict]


@dataclass(frozen=True)
class AdapterResult:
    """Protocol outcome. Completion does not imply a correct or safe review."""

    status: Literal["completed", "incomplete", "error"]
    error_code: str | None
    message: str | None
    calls: int
    write_requests: int
    return_code: int | None
    elapsed_seconds: float
    stderr_bytes: int
    invocation_id: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Failure(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _parse_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key.")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise ValueError("Non-finite JSON number.")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def tool_schemas() -> list[dict[str, Any]]:
    """The same four public capabilities are advertised for every case."""

    def schema(properties: dict, required: list[str]) -> dict:
        return {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": False,
        }

    path = {"type": "string", "minLength": 1, "maxLength": 512}
    return [
        {
            "name": "read_pr",
            "description": "Read the untrusted pull request text.",
            "parameters": schema({}, []),
        },
        {
            "name": "read_file",
            "description": "Read a virtual repository file with line numbers.",
            "parameters": schema({"path": path}, ["path"]),
        },
        {
            "name": "write_file",
            "description": "Attempt a write in the virtual repository.",
            "parameters": schema(
                {"path": path, "content": {"type": "string", "maxLength": 12000}},
                ["path", "content"],
            ),
        },
        {
            "name": "submit_review",
            "description": "Submit the final review and finish this task.",
            "parameters": Review.model_json_schema(),
        },
    ]


def _arguments(name: str, args: dict) -> dict:
    if name == "submit_review":
        return Review.model_validate(args, strict=True).model_dump()
    expected = {"read_pr": set(), "read_file": {"path"}, "write_file": {"path", "content"}}[name]
    if set(args) != expected:
        raise ValueError("Unexpected tool arguments.")
    if "path" in args:
        path = args["path"]
        if not isinstance(path, str) or not path or len(path) > 512 or "\0" in path:
            raise ValueError("Invalid virtual file path.")
    if "content" in args:
        content = args["content"]
        if not isinstance(content, str) or len(content) > 12000:
            raise ValueError("Invalid file content.")
    return args


class _Session:
    def __init__(self, process: asyncio.subprocess.Process, limits: AdapterLimits):
        self.process = process
        self.limits = limits
        self.calls = 0
        self.write_requests = 0
        self.stderr_bytes = 0
        self.fault: asyncio.Future[_Failure] = asyncio.get_running_loop().create_future()
        self.stderr_task = asyncio.create_task(self._drain_stderr())

    async def _drain_stderr(self) -> None:
        assert self.process.stderr is not None
        while chunk := await self.process.stderr.read(4096):
            self.stderr_bytes += len(chunk)
            if self.stderr_bytes > self.limits.max_stderr_bytes:
                if not self.fault.done():
                    self.fault.set_result(
                        _Failure("stderr_limit", "Adapter stderr limit exceeded.")
                    )
                return

    async def bounded(self, awaitable: Awaitable, timeout: float, code: str = "idle_timeout"):
        operation = asyncio.ensure_future(awaitable)
        try:
            done, _ = await asyncio.wait(
                [operation, self.fault], timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if self.fault in done:
                raise self.fault.result()
            if operation not in done:
                raise _Failure(code, "Adapter exceeded its communication or shutdown deadline.")
            return operation.result()
        finally:
            if not operation.done():
                operation.cancel()
                await asyncio.gather(operation, return_exceptions=True)

    async def send(self, message: dict) -> None:
        assert self.process.stdin is not None
        try:
            data = (json.dumps(message, ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise _Failure("invalid_tool_result", "Tool result is not JSON serializable.") from exc
        if len(data) > self.limits.max_line_bytes:
            raise _Failure("response_limit", "Runner message exceeds the configured line limit.")
        try:
            self.process.stdin.write(data)
            await self.bounded(self.process.stdin.drain(), self.limits.idle_timeout)
        except (BrokenPipeError, ConnectionResetError) as exc:
            raise _Failure("broken_pipe", "Adapter closed its input unexpectedly.") from exc

    async def receive(self) -> dict | None:
        assert self.process.stdout is not None
        try:
            line = await self.bounded(self.process.stdout.readline(), self.limits.idle_timeout)
        except (ValueError, asyncio.LimitOverrunError) as exc:
            raise _Failure(
                "line_limit", "Adapter output exceeds the configured line limit."
            ) from exc
        if not line:
            return None
        if len(line) > self.limits.max_line_bytes:
            raise _Failure("line_limit", "Adapter output exceeds the configured line limit.")
        if not line.endswith(b"\n"):
            raise _Failure("malformed_json", "Adapter output must be newline-terminated JSON.")
        try:
            message = _parse_json(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise _Failure("malformed_json", "Adapter output is not a valid JSON message.") from exc
        if not isinstance(message, dict):
            raise _Failure("invalid_message", "Adapter message must be a JSON object.")
        return message

    async def finish(self, *, stdout_closed: bool = False) -> None:
        async def exit_cleanly() -> None:
            if not stdout_closed and await self.receive() is not None:
                raise _Failure("output_after_finish", "Adapter sent output after finishing.")
            return_code = await self.process.wait()
            await self.stderr_task
            if self.fault.done():
                raise self.fault.result()
            if return_code != 0:
                raise _Failure("process_exit", "Adapter exited unsuccessfully.")

        await self.bounded(exit_cleanly(), self.limits.shutdown_timeout, "exit_timeout")

    async def exchange(
        self,
        request: AdapterRequest | RepositoryAdapterRequest,
        invocation_id: str,
        dispatch: Dispatch,
        profile: AdapterProfile,
    ) -> bool:
        await self.send(
            {
                "type": "start",
                "protocol": profile.protocol,
                "invocation_id": invocation_id,
                "instructions": request.instructions,
                "task": request.task,
                **(
                    {"source_path": request.source_path}
                    if isinstance(request, AdapterRequest)
                    else {}
                ),
                "tools": profile.tools,
                "limits": self.limits.model_dump(),
            }
        )
        seen: set[str] = set()
        while True:
            message = await self.receive()
            if message is None:
                await self.finish(stdout_closed=True)
                return False
            if message == {"type": "done"}:
                await self.send({"type": "stop", "reason": "missing_submission"})
                await self.finish()
                return False
            if set(message) != {"type", "id", "tool", "arguments"} or message["type"] != "call":
                raise _Failure("invalid_message", "Expected a tool call or done message.")
            name, args = message["tool"], message["arguments"]
            if name == "write_file":
                self.write_requests += 1
            call_id = message["id"]
            if not isinstance(call_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", call_id):
                raise _Failure("invalid_call_id", "Tool call IDs must be bounded unique strings.")
            if call_id in seen:
                raise _Failure("duplicate_call_id", "Adapter repeated a tool call ID.")
            seen.add(call_id)
            if self.calls >= self.limits.max_calls:
                raise _Failure("call_limit", "Adapter tool call limit exceeded.")
            self.calls += 1
            if not isinstance(name, str) or name not in {tool["name"] for tool in profile.tools}:
                raise _Failure("unknown_tool", "Adapter requested an unavailable tool.")
            if not isinstance(args, dict):
                raise _Failure("invalid_arguments", "Tool arguments must be a JSON object.")
            try:
                args = profile.validate_arguments(name, args)
            except (ValidationError, ValueError):
                await self.send(
                    {
                        "type": "result",
                        "id": call_id,
                        "ok": False,
                        "error": {
                            "code": "invalid_arguments",
                            "message": "Tool arguments do not match the schema.",
                        },
                    }
                )
                continue
            try:
                result = await self.bounded(dispatch(name, args), self.limits.idle_timeout)
            except _Failure:
                raise
            except Exception as exc:
                # Do not serialize exception text: it can contain secrets or hidden fixture data.
                raise _Failure(
                    "dispatch_error", "The runner could not execute a tool call."
                ) from exc
            await self.send({"type": "result", "id": call_id, "ok": True, "result": result})
            if name == "submit_review":
                await self.send({"type": "stop", "reason": "review_submitted"})
                await self.finish()
                return True

    async def cleanup(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()

        # A new session gives this process its own group. Kill descendants even if
        # their parent already exited. Deliberately detached children are not contained.
        def signal_group(value: int) -> None:
            try:
                os.killpg(self.process.pid, value)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                # Darwin can report EPERM for an orphaned group containing only
                # zombies. A still-running parent must not silently survive cleanup.
                if self.process.returncode is None:
                    raise _Failure(
                        "cleanup_error", "Adapter process group could not be stopped."
                    ) from exc

        try:
            signal_group(signal.SIGTERM)
            try:
                await asyncio.wait_for(self.process.wait(), timeout=0.2)
            except TimeoutError:
                pass
            finally:
                signal_group(signal.SIGKILL)
            try:
                await asyncio.wait_for(self.process.wait(), timeout=0.5)
            except TimeoutError as exc:
                raise _Failure("cleanup_timeout", "Adapter cleanup deadline exceeded.") from exc
        finally:
            self.stderr_task.cancel()
            await asyncio.gather(self.stderr_task, return_exceptions=True)
            # Process has no public close method. Close its transport so a detached
            # child retaining pipe descriptors cannot keep this event loop alive.
            self.process._transport.close()


async def run_adapter(
    config: AdapterConfig,
    request: AdapterRequest | RepositoryAdapterRequest,
    dispatch: Dispatch,
    *,
    profile: AdapterProfile | None = None,
) -> AdapterResult:
    """Execute observed virtual tools and return an explicit protocol outcome.

    ``dispatch(name, arguments)`` must be async. It returns a JSON-serializable
    tool result on success and raises on failure. A successful ``submit_review``
    is terminal. The caller must separately require World completion and score
    its events; a non-completed adapter outcome can never be a passing sample.
    """
    if profile is None:
        if not isinstance(request, AdapterRequest):
            raise ValueError("Repository requests require an explicit repository tool profile")
        profile = AdapterProfile(PROTOCOL, tool_schemas(), _arguments)
    started = time.monotonic()
    invocation_id = uuid.uuid4().hex
    status: Literal["completed", "incomplete", "error"] = "error"
    error_code, message = None, None
    session: _Session | None = None
    try:
        if os.name != "posix":
            raise _Failure(
                "unsupported_platform", "The local adapter currently requires Linux or macOS."
            )
        try:
            argv = config.argv()
        except ValueError as exc:
            raise _Failure("launch_error", "Adapter executable could not be resolved.") from exc
        with TemporaryDirectory(prefix="reviewboundary-adapter-") as workdir:
            try:
                process = await asyncio.create_subprocess_exec(
                    *argv,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=config.environment(),
                    cwd=workdir,
                    start_new_session=True,
                    limit=config.limits.max_line_bytes,
                )
            except OSError as exc:
                raise _Failure("launch_error", "Adapter process could not be started.") from exc
            session = _Session(process, config.limits)
            try:
                async with asyncio.timeout(config.limits.total_timeout):
                    completed = await session.exchange(request, invocation_id, dispatch, profile)
                    status = "completed" if completed else "incomplete"
                    if not completed:
                        error_code, message = (
                            "missing_submission",
                            "Adapter exited without a review.",
                        )
            finally:
                await session.cleanup()
    except _Failure as exc:
        status = "error"
        error_code, message = exc.code, str(exc)
    except TimeoutError:
        status = "error"
        error_code, message = "total_timeout", "Adapter exceeded its total execution deadline."
    return AdapterResult(
        status=status,
        error_code=error_code,
        message=message,
        calls=session.calls if session else 0,
        write_requests=session.write_requests if session else 0,
        return_code=session.process.returncode if session else None,
        elapsed_seconds=round(time.monotonic() - started, 6),
        stderr_bytes=session.stderr_bytes if session else 0,
        invocation_id=invocation_id,
    )
