# Pure isolation payload models, strict codecs and the contained bootstrap source.
# Importing this module has no side effects. The bootstrap text is data only: it is
# never imported, compiled or executed by this module.

import base64
import codecs
import hashlib
import json
import re
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, field_validator, model_validator

from .repository_cases import FrozenModel

WIRE_PROTOCOL = "reviewboundary.isolated/1"

BOOTSTRAP_SOURCE = """import base64
import binascii
import codecs
import json
import os
import re
import select
import signal
import stat
import subprocess
import sys
import time

PROTOCOL = 'reviewboundary.isolated/1'
WORKDIR = '/workspace'
MAX_INPUT = 8388608
MAX_DEPTH = 16
MAX_ARGV = 64
MAX_ARG_BYTES = 4096
MAX_ARGV_TOTAL = 32768
MAX_FILES = 64
MAX_FILE = 65536
MAX_SOURCE_TOTAL = 4194304
MAX_COLLECT = 4
MAX_OBSERVER = 512
MAX_STREAM = 65536
MAX_ARTIFACT_TOTAL = 262144
MAX_RESULT = 2097152
MAX_PATH = 512
MAX_PART = 128
CHILD_TIMEOUT = 20.0
EXIT_GRACE = 0.5
KILL_WAIT = 2.0
CODES = (
    'invalid_input',
    'child_start_failed',
    'child_output_overflow',
    'child_timeout',
    'artifact_collection_failed',
)
NUL = chr(0)
BOM_CHAR = chr(65279)
QUOTE = chr(34)
BS = chr(92)
BS2 = BS + BS
TOKEN = re.compile(
    QUOTE + '[^' + QUOTE + BS2 + ']*(?:' + BS2 + '.[^' + QUOTE + BS2 + ']*)*' + QUOTE
    + '|[' + BS + '[' + BS + ']{}]'
)
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
PARSED = []


class Fail(Exception):
    pass


def has_control(text):
    for char in text:
        code = ord(char)
        if code < 32 or code == 127 or 128 <= code <= 159:
            return True
    return False


def sane(text):
    if NUL in text:
        raise Fail('invalid_input')
    try:
        text.encode('utf-8')
    except UnicodeEncodeError:
        raise Fail('invalid_input')


def scan_depth(text):
    depth = 0
    for match in TOKEN.finditer(text):
        token = match.group()
        if token == '[' or token == '{':
            depth += 1
            if depth > MAX_DEPTH + 1:
                raise Fail('invalid_input')
        elif token == ']' or token == '}':
            depth -= 1


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise Fail('invalid_input')
        result[key] = value
    return result


def reject_number(value):
    raise Fail('invalid_input')


def walk(root):
    stack = [root]
    while stack:
        item = stack.pop()
        if type(item) is str:
            sane(item)
        elif type(item) is dict:
            for key, value in item.items():
                sane(key)
                stack.append(value)
        elif type(item) is list:
            stack.extend(item)
        elif item is None or type(item) is int:
            continue
        else:
            raise Fail('invalid_input')


def parse_json(raw, maximum):
    if type(raw) is not bytes or len(raw) > maximum or raw.startswith(codecs.BOM_UTF8):
        raise Fail('invalid_input')
    try:
        text = raw.decode('utf-8')
    except UnicodeDecodeError:
        raise Fail('invalid_input')
    scan_depth(text)
    try:
        obj = json.loads(
            text,
            object_pairs_hook=pairs,
            parse_constant=reject_number,
            parse_float=reject_number,
        )
    except Fail:
        raise
    except Exception:
        raise Fail('invalid_input')
    walk(obj)
    return obj


def exact(obj, keys):
    if type(obj) is not dict or set(obj) != keys:
        raise Fail('invalid_input')


def decode_b64(value, maximum):
    if type(value) is not str or not value.isascii():
        raise Fail('invalid_input')
    if len(value) > 4 * ((maximum + 2) // 3) or len(value) % 4:
        raise Fail('invalid_input')
    try:
        data = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise Fail('invalid_input')
    if len(data) > maximum or base64.b64encode(data).decode('ascii') != value:
        raise Fail('invalid_input')
    return data


def check_path(path):
    if type(path) is not str or not path or len(path.encode('utf-8')) > MAX_PATH:
        raise Fail('invalid_input')
    for part in path.split('/'):
        if (
            not part
            or part in ('.', '..')
            or len(part.encode('utf-8')) > MAX_PART
            or BS in part
            or ':' in part
            or has_control(part)
            or part == '.git'
            or part == '.env'
            or part.startswith('.env.')
        ):
            raise Fail('invalid_input')


def check_set(paths):
    seen = set(paths)
    if len(seen) != len(paths):
        raise Fail('invalid_input')
    for path in paths:
        parts = path.split('/')
        for index in range(1, len(parts)):
            if '/'.join(parts[:index]) in seen:
                raise Fail('invalid_input')


def parse_input(raw):
    obj = parse_json(raw, MAX_INPUT)
    exact(obj, {'schema_version', 'protocol', 'job', 'observer_input_b64'})
    if type(obj['schema_version']) is not int or obj['schema_version'] != 1:
        raise Fail('invalid_input')
    if obj['protocol'] != PROTOCOL:
        raise Fail('invalid_input')
    job = obj['job']
    exact(job, {'argv', 'files', 'collect_paths'})
    argv = job['argv']
    if type(argv) is not list or not 1 <= len(argv) <= MAX_ARGV:
        raise Fail('invalid_input')
    total = 0
    for arg in argv:
        if type(arg) is not str or not arg or has_control(arg):
            raise Fail('invalid_input')
        size = len(arg.encode('utf-8'))
        if size > MAX_ARG_BYTES:
            raise Fail('invalid_input')
        total += size
    if total > MAX_ARGV_TOTAL:
        raise Fail('invalid_input')
    entries = job['files']
    if type(entries) is not list or len(entries) > MAX_FILES:
        raise Fail('invalid_input')
    files = []
    source_total = 0
    for entry in entries:
        exact(entry, {'path', 'data_b64'})
        path = entry['path']
        check_path(path)
        data = decode_b64(entry['data_b64'], MAX_FILE)
        text = data.decode('utf-8')
        if NUL in text or text.startswith(BOM_CHAR):
            raise Fail('invalid_input')
        source_total += len(data)
        files.append((path, data))
    if source_total > MAX_SOURCE_TOTAL:
        raise Fail('invalid_input')
    check_set([item[0] for item in files])
    collect = job['collect_paths']
    if type(collect) is not list or len(collect) > MAX_COLLECT:
        raise Fail('invalid_input')
    for path in collect:
        check_path(path)
    check_set(collect)
    raw_observer = obj['observer_input_b64']
    observer = None if raw_observer is None else decode_b64(raw_observer, MAX_OBSERVER)
    return argv, files, collect, observer


def read_stdin():
    chunks = []
    total = 0
    while True:
        chunk = os.read(0, 1048576)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_INPUT:
            raise Fail('invalid_input')
        chunks.append(chunk)
    return b''.join(chunks)


def check_dir(fd, is_root):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise Fail('invalid_input')
    owner = os.geteuid()
    if info.st_uid != owner and not (is_root and info.st_uid == 0):
        raise Fail('invalid_input')


def open_chain(root_fd, parts):
    opened = []
    fd = root_fd
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            opened.append(fd)
            check_dir(fd, False)
    except BaseException:
        for item in opened:
            os.close(item)
        raise
    return fd, opened


def stage(root_fd, files):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for path, data in files:
        parts = path.split('/')
        parent, opened = open_chain(root_fd, parts[:-1])
        try:
            file_fd = os.open(parts[-1], flags, 0o600, dir_fd=parent)
            try:
                if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                    raise Fail('invalid_input')
                view = memoryview(data)
                while view:
                    count = os.write(file_fd, view)
                    view = view[count:]
            finally:
                os.close(file_fd)
        finally:
            for item in opened:
                os.close(item)


def read_artifact(root_fd, path):
    parts = path.split('/')
    opened = []
    fd = root_fd
    try:
        for part in parts[:-1]:
            try:
                fd = os.open(part, DIR_FLAGS, dir_fd=fd)
            except FileNotFoundError:
                return None
            opened.append(fd)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        try:
            file_fd = os.open(parts[-1], flags, dir_fd=fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                raise Fail('artifact_collection_failed')
            chunks = []
            total = 0
            while True:
                chunk = os.read(file_fd, MAX_FILE + 1 - total)
                if not chunk:
                    break
                total += len(chunk)
                chunks.append(chunk)
                if total > MAX_FILE:
                    raise Fail('artifact_collection_failed')
            return b''.join(chunks)
        finally:
            os.close(file_fd)
    finally:
        for item in opened:
            os.close(item)


def collect_all(root_fd, paths):
    artifacts = []
    missing = []
    total = 0
    for path in paths:
        data = read_artifact(root_fd, path)
        if data is None:
            missing.append(path)
            continue
        total += len(data)
        if total > MAX_ARTIFACT_TOTAL:
            raise Fail('artifact_collection_failed')
        artifacts.append((path, data))
    return artifacts, missing


def kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=KILL_WAIT)
    except Exception:
        pass


def feed_observer(proc, observer, deadline):
    # Bounded select/write loop on the shared child deadline. Returns a fixed code or None.
    fd = proc.stdin.fileno()
    result = None
    try:
        os.set_blocking(fd, False)
        view = memoryview(observer)
        while view:
            now = time.monotonic()
            if now >= deadline:
                result = 'child_timeout'
                break
            ready = select.select([], [fd], [], min(0.1, deadline - now))[1]
            if not ready:
                continue
            try:
                count = os.write(fd, view)
            except BlockingIOError:
                continue
            view = view[count:]
    except OSError:
        result = 'child_start_failed'
    try:
        proc.stdin.close()
    except OSError:
        pass
    return result


def run_child(argv, observer):
    try:
        proc = subprocess.Popen(
            argv,
            cwd=WORKDIR,
            stdin=subprocess.DEVNULL if observer is None else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )
    except Exception:
        raise Fail('child_start_failed')
    deadline = time.monotonic() + CHILD_TIMEOUT
    if observer is not None:
        failed = feed_observer(proc, observer, deadline)
        if failed is not None:
            kill_group(proc)
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
            return failed, None, b'', b''
    out = bytearray()
    err = bytearray()
    buffers = {proc.stdout.fileno(): out, proc.stderr.fileno(): err}
    for fd in buffers:
        os.set_blocking(fd, False)
    open_fds = set(buffers)
    exited_at = None
    code = None
    finished = False
    try:
        while True:
            now = time.monotonic()
            if exited_at is None and proc.poll() is not None:
                exited_at = now
            if not open_fds and exited_at is not None:
                break
            if exited_at is not None and now - exited_at > EXIT_GRACE:
                code = 'child_timeout'
                break
            if now >= deadline:
                code = 'child_timeout'
                break
            wait = min(0.1, deadline - now)
            if open_fds:
                ready = select.select(sorted(open_fds), [], [], wait)[0]
            else:
                time.sleep(wait)
                ready = []
            for fd in ready:
                buf = buffers[fd]
                try:
                    chunk = os.read(fd, MAX_STREAM + 1 - len(buf))
                except BlockingIOError:
                    continue
                if not chunk:
                    open_fds.discard(fd)
                    continue
                buf.extend(chunk)
                if len(buf) > MAX_STREAM:
                    code = 'child_output_overflow'
                    break
            if code is not None:
                break
        finished = True
    finally:
        if not finished or code is not None or open_fds or proc.poll() is None:
            kill_group(proc)
        for stream in (proc.stdout, proc.stderr):
            try:
                stream.close()
            except OSError:
                pass
    rc = proc.returncode
    if code is None and (rc is None or not -255 <= rc <= 255):
        code = 'child_timeout'
    return code, rc, bytes(out[:MAX_STREAM]), bytes(err[:MAX_STREAM])


def b64(data):
    return base64.b64encode(data).decode('ascii')


def envelope(status, code, rc, out, err, artifacts, missing):
    return {
        'schema_version': 1,
        'protocol': PROTOCOL,
        'status': status,
        'error_code': code,
        'claimed_child_return_code': rc,
        'stdout_b64': b64(out),
        'stderr_b64': b64(err),
        'artifacts': [{'path': p, 'data_b64': b64(d)} for p, d in artifacts],
        'missing_artifacts': list(missing),
    }


def encode_envelope(env):
    return json.dumps(
        env, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False
    ).encode('utf-8')


def emit(env):
    data = encode_envelope(env)
    if len(data) > MAX_RESULT:
        paths = [item['path'] for item in env['artifacts']] + list(env['missing_artifacts'])
        data = encode_envelope(
            envelope('error', 'artifact_collection_failed', None, b'', b'', (), paths)
        )
    view = memoryview(data)
    while view:
        try:
            count = os.write(1, view)
        except OSError:
            return
        view = view[count:]


def fail_code(exc):
    if exc.args and exc.args[0] in CODES:
        return exc.args[0]
    return 'invalid_input'


def run():
    try:
        argv, files, collect, observer = parse_input(read_stdin())
    except Fail:
        raise
    except Exception:
        raise Fail('invalid_input')
    PARSED[:] = collect
    root_fd = None
    try:
        try:
            os.chdir(WORKDIR)
            root_fd = os.open(WORKDIR, DIR_FLAGS)
            check_dir(root_fd, True)
            stage(root_fd, files)
        except Fail as exc:
            return envelope('error', fail_code(exc), None, b'', b'', (), collect)
        except Exception:
            return envelope('error', 'invalid_input', None, b'', b'', (), collect)
        try:
            code, rc, out, err = run_child(argv, observer)
        except Fail as exc:
            return envelope('error', fail_code(exc), None, b'', b'', (), collect)
        except Exception:
            return envelope('error', 'child_start_failed', None, b'', b'', (), collect)
        if code is not None:
            return envelope('error', code, None, out, err, (), collect)
        try:
            artifacts, missing = collect_all(root_fd, collect)
        except Exception:
            return envelope('error', 'artifact_collection_failed', rc, out, err, (), collect)
        return envelope('completed', None, rc, out, err, artifacts, missing)
    finally:
        if root_fd is not None:
            os.close(root_fd)


def main():
    try:
        env = run()
    except Fail as exc:
        code = exc.args[0] if exc.args and exc.args[0] in CODES else 'invalid_input'
        env = envelope('error', code, None, b'', b'', (), PARSED)
    except BaseException:
        env = envelope('error', 'invalid_input', None, b'', b'', (), PARSED)
    emit(env)


if __name__ == '__main__':
    main()
"""

BOOTSTRAP_SHA256 = hashlib.sha256(BOOTSTRAP_SOURCE.encode("utf-8")).hexdigest()

_MAX_JOB_JSON = 8388608
_MAX_INPUT_WIRE = 8388608
_MAX_RESULT_WIRE = 2097152
_MAX_DEPTH = 16
_MAX_ARGV = 64
_MAX_ARG_BYTES = 4096
_MAX_ARGV_TOTAL = 32768
_MAX_FILES = 64
_MAX_FILE = 65536
_MAX_SOURCE_TOTAL = 4194304
_MAX_COLLECT = 4
_MAX_OBSERVER = 512
_MAX_STREAM = 65536
_MAX_ARTIFACT = 65536
_MAX_ARTIFACT_TOTAL = 262144
_MAX_PATH = 512
_MAX_PART = 128

_JOB_ERROR = "Invalid isolated job."
_RESULT_ERROR = "Invalid isolated result."
_ARTIFACT_ERROR = "Invalid isolated artifact."
_FIELD_ERROR = "Invalid isolation field."

_QUOTE = chr(34)
_BS = chr(92)
_BS2 = _BS + _BS
_TOKEN = re.compile(
    _QUOTE
    + "[^"
    + _QUOTE
    + _BS2
    + "]*(?:"
    + _BS2
    + ".[^"
    + _QUOTE
    + _BS2
    + "]*)*"
    + _QUOTE
    + "|["
    + _BS
    + "["
    + _BS
    + "]{}]"
)
_NUL = chr(0)
_BOM_CHAR = chr(0xFEFF)
_SHA_RE = re.compile("[0-9a-f]{64}")

ErrorCode = Literal[
    "invalid_input",
    "child_start_failed",
    "child_output_overflow",
    "child_timeout",
    "artifact_collection_failed",
]
_ERROR_CODES = (
    "invalid_input",
    "child_start_failed",
    "child_output_overflow",
    "child_timeout",
    "artifact_collection_failed",
)


def _exact_one(value: object) -> object:
    if type(value) is not int or value != 1:
        raise ValueError("Unsupported schema version.")
    return value


SchemaVersion = Annotated[Literal[1], BeforeValidator(_exact_one)]
ReturnCode = Annotated[int, Field(strict=True, ge=-255, le=255)]


def _utf8(text: str) -> bytes:
    if type(text) is not str:
        raise ValueError(_FIELD_ERROR)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        pass
    raise ValueError(_FIELD_ERROR)


def _has_control(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 or 0x80 <= ord(c) <= 0x9F for c in text)


def _check_path(value: str) -> str:
    encoded = _utf8(value)
    if not value or len(encoded) > _MAX_PATH:
        raise ValueError(_FIELD_ERROR)
    for part in value.split("/"):
        if (
            not part
            or part in (".", "..")
            or len(_utf8(part)) > _MAX_PART
            or _BS in part
            or ":" in part
            or _has_control(part)
            or part == ".git"
            or part == ".env"
            or part.startswith(".env.")
        ):
            raise ValueError(_FIELD_ERROR)
    return value


def _check_path_set(paths: list[str] | tuple[str, ...]) -> None:
    seen = set(paths)
    if len(seen) != len(paths):
        raise ValueError(_FIELD_ERROR)
    for path in paths:
        parts = path.split("/")
        if any("/".join(parts[:i]) in seen for i in range(1, len(parts))):
            raise ValueError(_FIELD_ERROR)


def _check_source(value: str) -> str:
    if len(value) > _MAX_FILE:
        raise ValueError(_FIELD_ERROR)
    encoded = _utf8(value)
    if len(encoded) > _MAX_FILE or _NUL in value or value.startswith(_BOM_CHAR):
        raise ValueError(_FIELD_ERROR)
    return value


class IsolatedTextFile(FrozenModel):
    path: str
    content: str

    @field_validator("path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return _check_path(value)

    @field_validator("content")
    @classmethod
    def check_content(cls, value: str) -> str:
        return _check_source(value)


class IsolatedJob(FrozenModel):
    schema_version: SchemaVersion
    argv: tuple[str, ...]
    files: tuple[IsolatedTextFile, ...]
    collect_paths: tuple[str, ...]

    @field_validator("argv")
    @classmethod
    def check_argv(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not 1 <= len(value) <= _MAX_ARGV:
            raise ValueError(_FIELD_ERROR)
        total = 0
        for arg in value:
            size = len(_utf8(arg))
            if not arg or size > _MAX_ARG_BYTES or _has_control(arg):
                raise ValueError(_FIELD_ERROR)
            total += size
        if total > _MAX_ARGV_TOTAL:
            raise ValueError(_FIELD_ERROR)
        return value

    @field_validator("files")
    @classmethod
    def check_files(cls, value: tuple[IsolatedTextFile, ...]) -> tuple[IsolatedTextFile, ...]:
        if len(value) > _MAX_FILES:
            raise ValueError(_FIELD_ERROR)
        if sum(len(_utf8(item.content)) for item in value) > _MAX_SOURCE_TOTAL:
            raise ValueError(_FIELD_ERROR)
        _check_path_set([item.path for item in value])
        return value

    @field_validator("collect_paths")
    @classmethod
    def check_collect(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > _MAX_COLLECT:
            raise ValueError(_FIELD_ERROR)
        for path in value:
            _check_path(path)
        _check_path_set(value)
        return value


class IsolatedArtifact(FrozenModel):
    path: str
    data: bytes = Field(repr=False, exclude=True)

    @field_validator("path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return _check_path(value)

    @field_validator("data")
    @classmethod
    def check_data(cls, value: bytes) -> bytes:
        if len(value) > _MAX_ARTIFACT:
            raise ValueError(_FIELD_ERROR)
        return value


class ArtifactMetadata(FrozenModel):
    path: str
    byte_count: Annotated[int, Field(strict=True, ge=0, le=_MAX_ARTIFACT)]
    sha256: str

    @field_validator("path")
    @classmethod
    def check_path(cls, value: str) -> str:
        return _check_path(value)

    @field_validator("sha256")
    @classmethod
    def check_sha(cls, value: str) -> str:
        if _SHA_RE.fullmatch(value) is None:
            raise ValueError(_FIELD_ERROR)
        return value


class ParsedContainerResult(FrozenModel):
    # Everything here is an untrusted observation and never a verdict.
    stdout: bytes = Field(repr=False, exclude=True)
    stderr: bytes = Field(repr=False, exclude=True)
    artifacts: tuple[IsolatedArtifact, ...] = Field(repr=False, exclude=True)
    missing_paths: tuple[str, ...]
    claimed_child_return_code: ReturnCode | None
    claimed_status: Literal["completed", "error"]
    error_code: ErrorCode | None

    @model_validator(mode="after")
    def check_shape(self) -> "ParsedContainerResult":
        if self.claimed_status == "completed":
            if self.error_code is not None or self.claimed_child_return_code is None:
                raise ValueError(_FIELD_ERROR)
        elif self.error_code is None:
            raise ValueError(_FIELD_ERROR)
        if len(self.stdout) > _MAX_STREAM or len(self.stderr) > _MAX_STREAM:
            raise ValueError(_FIELD_ERROR)
        if len(self.artifacts) > _MAX_COLLECT or len(self.missing_paths) > _MAX_COLLECT:
            raise ValueError(_FIELD_ERROR)
        if sum(len(item.data) for item in self.artifacts) > _MAX_ARTIFACT_TOTAL:
            raise ValueError(_FIELD_ERROR)
        for path in self.missing_paths:
            _check_path(path)
        _check_path_set([item.path for item in self.artifacts] + list(self.missing_paths))
        return self


def _guarded(message: str, function: Any, *args: Any) -> Any:
    # Raising outside the except block keeps raw inputs and nested tracebacks out.
    result = None
    try:
        result = function(*args)
    except (ValueError, TypeError, AttributeError, RecursionError, OverflowError):
        result = None
    if result is None:
        raise ValueError(message)
    return result


def _canonical(tree: Any) -> bytes:
    return json.dumps(
        tree, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64_decode(value: object, maximum: int) -> bytes:
    if type(value) is not str or not value.isascii():
        raise ValueError(_RESULT_ERROR)
    if len(value) > 4 * ((maximum + 2) // 3) or len(value) % 4:
        raise ValueError(_RESULT_ERROR)
    data = base64.b64decode(value, validate=True)
    if len(data) > maximum or _b64(data) != value:
        raise ValueError(_RESULT_ERROR)
    return data


def _walk_strings(root: Any) -> None:
    stack = [root]
    while stack:
        item = stack.pop()
        if type(item) is str:
            if _NUL in item:
                raise ValueError(_FIELD_ERROR)
            _utf8(item)
        elif type(item) is dict:
            for key, value in item.items():
                _utf8(key)
                if _NUL in key:
                    raise ValueError(_FIELD_ERROR)
                stack.append(value)
        elif type(item) is list:
            stack.extend(item)
        elif item is None or type(item) is int:
            continue
        else:
            raise ValueError(_FIELD_ERROR)


def _no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError(_FIELD_ERROR)
        result[key] = value
    return result


def _reject_number(value: str) -> Any:
    raise ValueError(_FIELD_ERROR)


def _strict_json(raw: bytes, maximum: int) -> Any:
    if type(raw) is not bytes or len(raw) > maximum or raw.startswith(codecs.BOM_UTF8):
        raise ValueError(_FIELD_ERROR)
    text = raw.decode("utf-8")
    depth = 0
    for match in _TOKEN.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > _MAX_DEPTH + 1:
                raise ValueError(_FIELD_ERROR)
        elif token in ("]", "}"):
            depth -= 1
    tree = json.loads(
        text,
        object_pairs_hook=_no_duplicates,
        parse_constant=_reject_number,
        parse_float=_reject_number,
    )
    _walk_strings(tree)
    return tree


def _rebuild_job(job: IsolatedJob) -> IsolatedJob:
    # Re-run every validator so model_construct or model_copy results are not trusted.
    if type(job) is not IsolatedJob or type(job.files) is not tuple:
        raise ValueError(_JOB_ERROR)
    files = tuple(IsolatedTextFile(path=item.path, content=item.content) for item in job.files)
    return IsolatedJob(
        schema_version=job.schema_version,
        argv=job.argv,
        files=files,
        collect_paths=job.collect_paths,
    )


def _rebuild_artifact(artifact: IsolatedArtifact) -> IsolatedArtifact:
    if type(artifact) is not IsolatedArtifact:
        raise ValueError(_ARTIFACT_ERROR)
    return IsolatedArtifact(path=artifact.path, data=artifact.data)


def _parse_job(raw: bytes) -> IsolatedJob:
    _strict_json(raw, _MAX_JOB_JSON)
    return IsolatedJob.model_validate_json(raw, strict=True)


def _encode_input(job: IsolatedJob, observer: bytes | None) -> bytes:
    checked = _rebuild_job(job)
    if observer is not None and (type(observer) is not bytes or len(observer) > _MAX_OBSERVER):
        raise ValueError(_JOB_ERROR)
    tree = {
        "schema_version": 1,
        "protocol": WIRE_PROTOCOL,
        "job": {
            "argv": list(checked.argv),
            "files": [
                {"path": item.path, "data_b64": _b64(item.content.encode("utf-8"))}
                for item in checked.files
            ],
            "collect_paths": list(checked.collect_paths),
        },
        "observer_input_b64": None if observer is None else _b64(observer),
    }
    wire = _canonical(tree)
    if len(wire) > _MAX_INPUT_WIRE:
        raise ValueError(_JOB_ERROR)
    return wire


def _decode_result(raw: bytes, job: IsolatedJob) -> ParsedContainerResult:
    checked = _rebuild_job(job)
    tree = _strict_json(raw, _MAX_RESULT_WIRE)
    keys = {
        "schema_version",
        "protocol",
        "status",
        "error_code",
        "claimed_child_return_code",
        "stdout_b64",
        "stderr_b64",
        "artifacts",
        "missing_artifacts",
    }
    if type(tree) is not dict or set(tree) != keys:
        raise ValueError(_RESULT_ERROR)
    if type(tree["schema_version"]) is not int or tree["schema_version"] != 1:
        raise ValueError(_RESULT_ERROR)
    if tree["protocol"] != WIRE_PROTOCOL:
        raise ValueError(_RESULT_ERROR)
    status = tree["status"]
    if type(status) is not str or status not in ("completed", "error"):
        raise ValueError(_RESULT_ERROR)
    code = tree["error_code"]
    if code is not None and (type(code) is not str or code not in _ERROR_CODES):
        raise ValueError(_RESULT_ERROR)
    rc = tree["claimed_child_return_code"]
    if rc is not None and (type(rc) is not int or not -255 <= rc <= 255):
        raise ValueError(_RESULT_ERROR)
    stdout = _b64_decode(tree["stdout_b64"], _MAX_STREAM)
    stderr = _b64_decode(tree["stderr_b64"], _MAX_STREAM)
    entries = tree["artifacts"]
    missing = tree["missing_artifacts"]
    if type(entries) is not list or len(entries) > _MAX_COLLECT:
        raise ValueError(_RESULT_ERROR)
    if type(missing) is not list or len(missing) > _MAX_COLLECT:
        raise ValueError(_RESULT_ERROR)
    artifacts = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"path", "data_b64"}:
            raise ValueError(_RESULT_ERROR)
        data = _b64_decode(entry["data_b64"], _MAX_ARTIFACT)
        artifacts.append(IsolatedArtifact(path=entry["path"], data=data))
    if any(type(path) is not str for path in missing):
        raise ValueError(_RESULT_ERROR)
    found = [item.path for item in artifacts]
    requested = set(checked.collect_paths)
    everything = found + missing
    if len(set(everything)) != len(everything) or not set(everything) <= requested:
        raise ValueError(_RESULT_ERROR)
    if set(everything) != requested:
        raise ValueError(_RESULT_ERROR)
    return ParsedContainerResult(
        stdout=stdout,
        stderr=stderr,
        artifacts=tuple(artifacts),
        missing_paths=tuple(missing),
        claimed_child_return_code=rc,
        claimed_status=status,
        error_code=code,
    )


def _job_digest(job: IsolatedJob) -> str:
    checked = _rebuild_job(job)
    return hashlib.sha256(_canonical(checked.model_dump(mode="json"))).hexdigest()


def _artifact_digest(artifact: IsolatedArtifact) -> str:
    return hashlib.sha256(_rebuild_artifact(artifact).data).hexdigest()


def _manifest(artifacts: tuple[IsolatedArtifact, ...]) -> tuple[ArtifactMetadata, ...]:
    if type(artifacts) is not tuple or len(artifacts) > _MAX_COLLECT:
        raise ValueError(_ARTIFACT_ERROR)
    rebuilt = tuple(_rebuild_artifact(item) for item in artifacts)
    _check_path_set([item.path for item in rebuilt])
    if sum(len(item.data) for item in rebuilt) > _MAX_ARTIFACT_TOTAL:
        raise ValueError(_ARTIFACT_ERROR)
    return tuple(
        ArtifactMetadata(
            path=item.path,
            byte_count=len(item.data),
            sha256=hashlib.sha256(item.data).hexdigest(),
        )
        for item in rebuilt
    )


def parse_isolated_job(raw: bytes) -> IsolatedJob:
    return _guarded(_JOB_ERROR, _parse_job, raw)


def encode_command_input(job: IsolatedJob) -> bytes:
    # Ordinary jobs never carry child stdin: the observer field is always null.
    return _guarded(_JOB_ERROR, _encode_input, job, None)


def encode_observer_input(job: IsolatedJob, observer_input: bytes) -> bytes:
    # Internal host-controller seam. Not an arbitrary caller input channel.
    if type(observer_input) is not bytes or len(observer_input) > _MAX_OBSERVER:
        raise ValueError(_JOB_ERROR)
    return _guarded(_JOB_ERROR, _encode_input, job, observer_input)


def decode_result_wire(raw: bytes, job: IsolatedJob) -> ParsedContainerResult:
    return _guarded(_RESULT_ERROR, _decode_result, raw, job)


def job_digest(job: IsolatedJob) -> str:
    return _guarded(_JOB_ERROR, _job_digest, job)


def artifact_digest(artifact: IsolatedArtifact) -> str:
    return _guarded(_ARTIFACT_ERROR, _artifact_digest, artifact)


def artifact_manifest(artifacts: tuple[IsolatedArtifact, ...]) -> tuple[ArtifactMetadata, ...]:
    return _guarded(_ARTIFACT_ERROR, _manifest, artifacts)
