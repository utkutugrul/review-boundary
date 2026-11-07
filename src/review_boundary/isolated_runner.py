"""Opt-in fixed-policy local container execution with explicit evidence limits.

Container bytes are untrusted. Saved reports and synthetic drivers never carry
live execution authority. Runtime controls require a fresh complete gate.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field, PrivateAttr, field_validator

from .isolation_payload import (
    BOOTSTRAP_SHA256,
    BOOTSTRAP_SOURCE,
    ArtifactMetadata,
    IsolatedArtifact,
    IsolatedJob,
    IsolatedTextFile,
    ParsedContainerResult,
    artifact_digest,
    artifact_manifest,
    decode_result_wire,
    encode_command_input,
    encode_observer_input,
    parse_isolated_job,
)
from .json_input import parse_json_object
from .repository_cases import FrozenModel

Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ErrorCode = Literal[
    "invalid_config",
    "invalid_job",
    "unsupported_platform",
    "client_unavailable",
    "context_unavailable",
    "remote_endpoint",
    "daemon_unavailable",
    "daemon_changed",
    "image_unavailable",
    "image_mismatch",
    "lock_busy",
    "recovery_required",
    "probe_failed",
    "probe_timeout",
    "create_failed",
    "ownership_mismatch",
    "policy_mismatch",
    "start_failed",
    "transport_error",
    "input_overflow",
    "output_overflow",
    "execution_timeout",
    "container_oom",
    "container_failed",
    "malformed_result",
    "artifact_incomplete",
    "cleanup_failed",
    "cancelled",
    "internal_error",
]
OriginCode = Literal[
    "not_live",
    "origin_incomplete",
    "origin_binding_mismatch",
    "artifact_mismatch",
    "artifact_invalid",
    "observation_binding_mismatch",
    "cleanup_unconfirmed",
]
POLICY = "isolated-command-v1"
INTERPRETER = "/usr/local/bin/python3.11"
PLATFORM = "linux/arm64/v8"
HOSTNAME = "review-boundary"
IMAGE_REFERENCE = "docker.io/library/python@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79"
IMAGE_ID = "sha256:31afb5c02f25b87e006154aaa615a394ab6b955b0f9d48c02612e6c7357b3b52"
_IMAGE_STORE_TARGET = IMAGE_REFERENCE.rsplit("@", 1)[1]
IMAGE_CONFIG_SHA256 = "ce40de6262dc78143654555ae32c5adcdaa4856edc06e346ac658fedac5ce7b3"
_IMAGE_ENV = (
    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG=C.UTF-8",
    "GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D",
    "PYTHON_VERSION=3.11.18",
    "PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290",
)
_EFFECTIVE_ENV = tuple(
    sorted(
        (
            "PATH=/usr/local/bin:/usr/bin:/bin",
            "LANG=C.UTF-8",
            "HOME=/nonexistent",
            "HOSTNAME=" + HOSTNAME,
            *_IMAGE_ENV[2:],
        )
    )
)
_TMPFS = {
    "/workspace": "rw,exec,nosuid,nodev,size=16777216,nr_inodes=4096,uid=65532,gid=65532,mode=0700",
    "/tmp": "rw,noexec,nosuid,nodev,size=8388608,nr_inodes=1024,uid=65532,gid=65532,mode=0700",
}
_LIMITS = {
    "cpu_nanos": 500000000,
    "memory": 268435456,
    "memory_swap": 268435456,
    "pids": 32,
    "nofile": 256,
    "core": 0,
    "fsize": 8388608,
    "shm": 1048576,
    "probe_seconds": 30,
    "candidate_seconds": 30,
    "emergency_seconds": 5,
    "total_seconds": 65,
    "input_wire": 8388608,
    "result_wire": 2097152,
    "driver_stderr": 65536,
}
_TRUSTED = (
    "host_controller",
    "docker_daemon",
    "linux_kernel",
    "approved_image",
    "container_runtime",
)
_REAL_AUTHORITY = object()


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _create_arguments(name: str, nonce: str, cidfile: Path) -> tuple[str, ...]:
    return (
        "container",
        "create",
        "--pull=never",
        "--platform",
        PLATFORM,
        "--name",
        name,
        "--hostname",
        HOSTNAME,
        "--label",
        "reviewboundary.owner=" + nonce,
        "--cidfile",
        str(cidfile),
        "--network",
        "none",
        "--read-only",
        "--user",
        "65532:65532",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--cpus",
        "0.5",
        "--memory",
        "268435456",
        "--memory-swap",
        "268435456",
        "--pids-limit",
        "32",
        "--ulimit",
        "nofile=256:256",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        "fsize=8388608:8388608",
        "--tmpfs",
        "/workspace:" + _TMPFS["/workspace"],
        "--tmpfs",
        "/tmp:" + _TMPFS["/tmp"],
        "--shm-size",
        "1048576",
        "--ipc",
        "private",
        "--cgroupns",
        "private",
        "--log-driver",
        "none",
        "--no-healthcheck",
        "--entrypoint",
        INTERPRETER,
        "--workdir",
        "/workspace",
        *sum((("--env", item) for item in _EFFECTIVE_ENV), ()),
        "--init",
        "--stop-signal",
        "SIGKILL",
        "--stop-timeout",
        "1",
        "--interactive",
        IMAGE_REFERENCE,
        "-I",
        "-c",
        BOOTSTRAP_SOURCE,
    )


# Fixed harmless calibrations, never evaluated or imported on the host.
_CONFIGURATION_PROBE = r"""
import json,os,resource,socket,sys
from pathlib import Path
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
cg=Path('/sys/fs/cgroup')
def read(name): return (cg/name).read_text().strip()
def blocked(family,address):
    s=socket.socket(family,socket.SOCK_DGRAM)
    try:
        s.connect(address)
        return False
    except OSError:
        return True
    finally:
        s.close()
try:
    Path('/reviewboundary-readonly-probe').write_text('x')
    readonly=False
except OSError as exc:
    readonly=exc.errno==30
mounts=Path('/proc/mounts').read_text().splitlines()
mountmap={x.split()[1]:x.split()[3].split(',') for x in mounts}
workspace=os.statvfs('/workspace');temp=os.statvfs('/tmp')
result={'uid':os.getuid(),'gid':os.getgid(),'caps':[status.get(k,'').strip() for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb')],
 'nnp':status.get('NoNewPrivs','').strip(),'seccomp':status.get('Seccomp','').strip(),
 'readonly':readonly,'cpu':read('cpu.max'),'memory':read('memory.max'),'swap':read('memory.swap.max'),'pids':read('pids.max'),
 'workspace_bytes':workspace.f_blocks*workspace.f_frsize,'workspace_inodes':workspace.f_files,
 'temp_bytes':temp.f_blocks*temp.f_frsize,'temp_inodes':temp.f_files,
 'workspace_mount':mountmap.get('/workspace',[]),'temp_mount':mountmap.get('/tmp',[]),
 'shm_bytes':os.statvfs('/dev/shm').f_blocks*os.statvfs('/dev/shm').f_frsize,
 'ulimits':{k:list(resource.getrlimit(v)) for k,v in [('nofile',resource.RLIMIT_NOFILE),('core',resource.RLIMIT_CORE),('fsize',resource.RLIMIT_FSIZE)]},
 'environment':dict(os.environ),'interfaces':sorted(x.name for x in Path('/sys/class/net').iterdir()),
 'ipv4_blocked':blocked(socket.AF_INET,('198.51.100.1',9)),
 'ipv6_blocked':blocked(socket.AF_INET6,('2001:db8::1',9)),
 'socket_absent':not Path('/var/run/docker.sock').exists(),
 'pid1_init':'docker-init' in Path('/proc/1/cmdline').read_bytes().decode(errors='replace'),
 'python':list(sys.version_info[:2]),'isolated':sys.flags.isolated==1}
print(json.dumps(result,separators=(',',':')))
"""
_CPU_PROBE = r"""
import json,time
from pathlib import Path
def counters(): return dict(x.split() for x in Path('/sys/fs/cgroup/cpu.stat').read_text().splitlines())
a=counters();end=time.process_time()+0.2
while time.process_time()<end: pass
b=counters()
print(json.dumps({'throttled':int(b['nr_throttled'])-int(a['nr_throttled']),'usec':int(b['throttled_usec'])-int(a['throttled_usec'])}))
"""
_MEMORY_PROBE = r"""
import json,subprocess,sys
from pathlib import Path
def counter(): return dict(x.split() for x in Path('/sys/fs/cgroup/memory.events').read_text().splitlines())
a=counter();p=subprocess.run([sys.executable,'-I','-c','x=bytearray(300*1024*1024);print(len(x))'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);b=counter()
print(json.dumps({'child_exit':p.returncode,'oom_kill':int(b['oom_kill'])-int(a['oom_kill'])}))
"""
_PID_PROBE = r"""
import errno,json,subprocess,sys
from pathlib import Path
children=[];limited=False;at_limit=0
try:
    for i in range(40):
        try: children.append(subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(5)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
        except OSError as exc:
            limited=exc.errno==errno.EAGAIN;at_limit=int(Path('/sys/fs/cgroup/pids.current').read_text());break
finally:
    for p in children: p.kill()
    for p in children: p.wait()
print(json.dumps({'limited':limited,'current':at_limit,'created':len(children)}))
"""
_TMPFS_PROBE = r"""
import errno,json,os
from pathlib import Path
result={}
for root,limit,inodes in [('/workspace',16*1024*1024,4096),('/tmp',8*1024*1024,1024)]:
    files=[];full=False;inode_full=False
    try:
        for i in range(3):
            p=Path(root)/('bytes-'+str(i));files.append(p)
            try:
                with p.open('wb') as f:
                    for n in range(128): f.write(b'x'*65536)
            except OSError as exc:
                full=exc.errno==errno.ENOSPC;break
    finally:
        for p in files: p.unlink(missing_ok=True)
    files=[]
    try:
        for i in range(inodes+2):
            p=Path(root)/('inode-'+str(i))
            try: p.touch();files.append(p)
            except OSError as exc:
                inode_full=exc.errno==errno.ENOSPC;break
    finally:
        for p in files: p.unlink(missing_ok=True)
    result[root]={'bytes_full':full,'inodes_full':inode_full}
print(json.dumps(result))
"""
_REAP_PROBE = r"""
import json,subprocess,sys,time
from pathlib import Path
code='import os,time; p=os.fork(); print(p,flush=True) if p else None; time.sleep(0.03) if not p else None; os._exit(0)'
p=subprocess.run([sys.executable,'-I','-c',code],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
child=int(p.stdout);end=time.monotonic()+0.5
while Path('/proc/'+str(child)).exists() and time.monotonic()<end: time.sleep(0.01)
print(json.dumps({'reaped':not Path('/proc/'+str(child)).exists()}))
"""
_HEADROOM_PROBE = r"""
import json,sys
from pathlib import Path
files=sorted(Path('/workspace').glob('data-*.txt'))
size=sum(p.stat().st_size for p in files)+Path('/workspace/probe.py').stat().st_size
value=json.dumps({'source_bytes':size,'file_count':len(files)+1},separators=(',',':'))
sys.stdout.write(value+' '*(65535-len(value))+'\n')
sys.stderr.write('x'*65536)
"""
_PROBES = (
    ("configuration", _CONFIGURATION_PROBE, None, 6.0),
    ("input_headroom", _HEADROOM_PROBE, None, 5.0),
    ("cpu", _CPU_PROBE, None, 3.0),
    ("memory", _MEMORY_PROBE, None, 4.0),
    ("pids", _PID_PROBE, None, 4.0),
    ("tmpfs", _TMPFS_PROBE, None, 5.0),
    ("stdout_overflow", "import os;os.write(1,b'x'*65537)", None, 2.0),
    ("stderr_overflow", "import os;os.write(2,b'x'*65537)", None, 2.0),
    (
        "stdin_null",
        "import json,sys;print(json.dumps({'empty':sys.stdin.buffer.read()==b''}))",
        None,
        2.0,
    ),
    (
        "stdin_observer",
        "import json,sys;print(json.dumps({'exact':sys.stdin.buffer.read()==b'probe-input'}))",
        b"probe-input",
        2.0,
    ),
    ("reaping", _REAP_PROBE, None, 3.0),
    ("wall", "import time;time.sleep(60)", None, 0.5),
)


_PROBE_COMPARISON_VERSION = "isolation-controls-v2"
_TOP_TEMPLATE = ("container", "top", "<owned-cid>", "-eo", "pid,ppid,comm")
_POLICY_MANIFEST = {
    "policy": POLICY,
    "limits": _LIMITS,
    "tmpfs": _TMPFS,
    "image": IMAGE_ID,
    "requested_image_reference": IMAGE_REFERENCE,
    "image_bindings": {
        "creation_reference": IMAGE_REFERENCE,
        "container_image": _IMAGE_STORE_TARGET,
        "config_image": IMAGE_REFERENCE,
        "selected_manifest_digest": IMAGE_ID,
        "selected_manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
        "selected_manifest_platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
    },
    "image_config_sha256": IMAGE_CONFIG_SHA256,
    "platform": PLATFORM,
    "interpreter": INTERPRETER,
    "hostname": HOSTNAME,
    "environment": _EFFECTIVE_ENV,
    "bootstrap": BOOTSTRAP_SHA256,
    "create_template": _create_arguments("<owned-name>", "<owned-nonce>", Path("/controller/cid")),
    "progress_template": _TOP_TEMPLATE,
    "comparison_version": _PROBE_COMPARISON_VERSION,
    "probes": tuple(
        {
            "id": name,
            "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "stdin_sha256": hashlib.sha256(stdin).hexdigest() if stdin is not None else None,
            "execution_seconds": seconds,
        }
        for name, source, stdin, seconds in _PROBES
    ),
}
POLICY_SHA256 = _digest(_POLICY_MANIFEST)


def _exact_version(value):
    if type(value) is not int or value != 1:
        raise ValueError("Expected exact schema version 1")
    return value


def _operator_path(value: str) -> str:
    if (
        not value
        or not Path(value).is_absolute()
        or ".." in Path(value).parts
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ValueError("Expected an explicit absolute operator path")
    try:
        if len(value.encode("utf-8")) > 4096:
            raise ValueError("Operator path exceeds its bound")
    except UnicodeError:
        raise ValueError("Expected a valid operator path") from None
    return value


class IsolationConfig(FrozenModel):
    schema_version: Literal[1] = 1
    policy: Literal["isolated-command-v1"] = POLICY
    docker_executable: str
    context_config_directory: str
    context_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
    image_profile: Literal["python311-arm64-v1"] = "python311-arm64-v1"

    _version = field_validator("schema_version", mode="before")(_exact_version)
    _paths = field_validator("docker_executable", "context_config_directory")(_operator_path)


class CheckResult(FrozenModel):
    check_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    status: Literal["passed", "failed", "not_tested"]


class ProbeDefinition(FrozenModel):
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    source_sha256: Hash
    observer_input_sha256: Hash | None = None
    execution_limit_ms: int = Field(ge=1, le=30000)


_REQUIRED_PROBES = tuple(
    ProbeDefinition(
        probe_id=item["id"],
        source_sha256=item["source_sha256"],
        observer_input_sha256=item["stdin_sha256"],
        execution_limit_ms=int(item["execution_seconds"] * 1000),
    )
    for item in _POLICY_MANIFEST["probes"]
)


class IsolationCapabilities(FrozenModel):
    schema_version: Literal[1] = 1
    report_family: Literal["isolation_capabilities"] = "isolation_capabilities"
    policy: Literal["isolated-command-v1"] = POLICY
    status: Literal["supported", "unsupported", "error"]
    error_code: ErrorCode | None = None
    daemon_sha256: Hash | None = None
    image_sha256: Hash | None = None
    config_sha256: Hash | None = None
    bootstrap_sha256: Hash = BOOTSTRAP_SHA256
    policy_sha256: Hash = POLICY_SHA256
    checks: tuple[CheckResult, ...] = ()
    comparison_version: Literal["isolation-controls-v2"] = _PROBE_COMPARISON_VERSION
    required_probes: tuple[ProbeDefinition, ...] = _REQUIRED_PROBES
    requested_image_reference: str = IMAGE_REFERENCE
    image_config_sha256: Hash = IMAGE_CONFIG_SHA256
    image_platform: Literal["linux/arm64/v8"] = PLATFORM
    vm_host_sharing: Literal["operator_attested", "not_established"] = "not_established"
    elapsed_ms: int = Field(default=0, ge=0)
    runtime_kind: Literal["real", "synthetic"]
    publication: Literal["not_established"] = "not_established"

    _version = field_validator("schema_version", mode="before")(_exact_version)


class DriverFacts(FrozenModel):
    stdin_bytes: int = Field(default=0, ge=0, le=8388608)
    stdout_bytes: int = Field(default=0, ge=0, le=2097152)
    stderr_bytes: int = Field(default=0, ge=0, le=65536)
    elapsed_ms: int = Field(default=0, ge=0)
    client_return_code: int | None = None
    daemon_exit_code: int | None = None
    daemon_oom_killed: bool = False
    input_complete: bool = False
    host_exchange_timeout: bool = False
    child_progress_observed: bool = False


class ContainerObservation(FrozenModel):
    authority: Literal["untrusted_container"] = "untrusted_container"
    claimed_status: Literal["completed", "error"]
    claimed_error_code: str | None
    claimed_child_return_code: int | None
    stdout_bytes: int = Field(ge=0, le=65536)
    stderr_bytes: int = Field(ge=0, le=65536)
    stdout_sha256: Hash
    stderr_sha256: Hash
    missing_artifact_count: int = Field(ge=0, le=4)


class IsolatedExecution(FrozenModel):
    schema_version: Literal[1] = 1
    report_family: Literal["isolated_execution"] = "isolated_execution"
    execution_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    policy: Literal["isolated-command-v1"] = POLICY
    status: Literal["completed", "not_started", "error"]
    error_code: ErrorCode | None = None
    job_started: bool
    runtime_kind: Literal["real", "synthetic"]
    input_sha256: Hash | None = None
    config_sha256: Hash | None = None
    source_sha256: Hash | None = None
    bootstrap_sha256: Hash | None = BOOTSTRAP_SHA256
    image_sha256: Hash | None = None
    daemon_sha256: Hash | None = None
    policy_sha256: Hash | None = POLICY_SHA256
    probe: IsolationCapabilities | None = None
    inspections: tuple[CheckResult, ...] = ()
    driver: DriverFacts = Field(default_factory=DriverFacts)
    container_observation: ContainerObservation | None = None
    artifact_manifest: tuple[ArtifactMetadata, ...] = ()
    cleanup: Literal["confirmed", "failed", "not_needed"]
    vm_host_sharing: Literal["operator_attested", "not_established"] = "not_established"
    verification: Literal["not_established"] = "not_established"
    publication: Literal["not_established"] = "not_established"
    trusted_components: tuple[str, ...] = _TRUSTED
    _artifacts: tuple[IsolatedArtifact, ...] = PrivateAttr(default=())
    _stdout: bytes = PrivateAttr(default=b"")
    _stderr: bytes = PrivateAttr(default=b"")
    _origin: _LiveRecord | None = PrivateAttr(default=None)

    _version = field_validator("schema_version", mode="before")(_exact_version)

    @property
    def collected_artifacts(self) -> tuple[IsolatedArtifact, ...]:
        return self._artifacts

    @property
    def command_stdout(self) -> bytes:
        """Bounded untrusted data, never a behavioral verdict or live proof."""
        return self._stdout

    @property
    def command_stderr(self) -> bytes:
        """Bounded untrusted data, excluded from ordinary report serialization."""
        return self._stderr

    def to_report(self) -> dict:
        return self.model_dump(mode="json")


class _OriginError(ValueError):
    def __init__(self, code: OriginCode):
        super().__init__("Live isolated execution binding was not established")
        self.code = code


@dataclass(frozen=True)
class _LiveRecord:
    reference: weakref.ReferenceType
    metadata_sha256: str
    config_sha256: str
    artifact_bindings: tuple[tuple[str, int, str], ...]
    stdout_sha256: str
    stderr_sha256: str
    kind: Literal["command", "observation"]
    authority: object
    config: IsolationConfig
    origin: _LiveOriginProof | None = None
    observer_input: bytes | None = None


@dataclass(frozen=True)
class _LiveOriginProof:
    execution: IsolatedExecution
    artifact: IsolatedArtifact
    record: _LiveRecord


def _checked_record(execution: IsolatedExecution, *, observation: bool = False) -> _LiveRecord:
    if type(execution) is not IsolatedExecution or execution._origin is None:
        raise _OriginError("not_live")
    record = execution._origin
    if (
        record.authority is not _REAL_AUTHORITY
        or record.reference() is not execution
        or execution.runtime_kind != "real"
    ):
        raise _OriginError("not_live")
    if record.metadata_sha256 != _digest(execution.to_report()):
        raise _OriginError("origin_binding_mismatch")
    if execution.cleanup != "confirmed":
        raise _OriginError("cleanup_unconfirmed")
    if (
        execution.status != "completed"
        or not execution.job_started
        or execution.probe is None
        or execution.probe.status != "supported"
        or execution.probe.runtime_kind != "real"
    ):
        raise _OriginError("origin_incomplete")
    bindings = tuple((x.path, len(x.data), artifact_digest(x)) for x in execution._artifacts)
    if (
        bindings != record.artifact_bindings
        or hashlib.sha256(execution._stdout).hexdigest() != record.stdout_sha256
        or hashlib.sha256(execution._stderr).hexdigest() != record.stderr_sha256
    ):
        raise _OriginError("origin_binding_mismatch")
    if observation and record.kind != "observation":
        raise _OriginError("observation_binding_mismatch")
    return record


def _require_live_origin(
    config: IsolationConfig, execution: IsolatedExecution, artifact: IsolatedArtifact
) -> _LiveOriginProof:
    record = _checked_record(execution)
    if (
        type(config) is not IsolationConfig
        or _digest(config.model_dump(mode="json")) != record.config_sha256
    ):
        raise _OriginError("origin_binding_mismatch")
    if type(artifact) is not IsolatedArtifact or artifact.path != "candidate.py":
        raise _OriginError("artifact_invalid")
    try:
        artifact.data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise _OriginError("artifact_invalid") from None
    binding = (artifact.path, len(artifact.data), artifact_digest(artifact))
    if binding not in record.artifact_bindings:
        raise _OriginError("artifact_mismatch")
    return _LiveOriginProof(execution, artifact, record)


def _source_digest(job: IsolatedJob) -> str:
    return _digest(
        {x.path: hashlib.sha256(x.content.encode("utf-8")).hexdigest() for x in job.files}
    )


def _observer_job(origin: _LiveOriginProof) -> IsolatedJob:
    return IsolatedJob(
        schema_version=1,
        argv=(INTERPRETER, "-I", "candidate.py"),
        files=(
            IsolatedTextFile(path="candidate.py", content=origin.artifact.data.decode("utf-8")),
        ),
        collect_paths=(),
    )


def _require_bound_observation(
    config: IsolationConfig,
    observation: IsolatedExecution,
    origin: _LiveOriginProof,
    observer_input: bytes,
) -> None:
    if (
        type(origin) is not _LiveOriginProof
        or type(observer_input) is not bytes
        or len(observer_input) > 512
    ):
        raise _OriginError("observation_binding_mismatch")
    checked = _require_live_origin(config, origin.execution, origin.artifact)
    record = _checked_record(observation, observation=True)
    if (
        checked.record is not origin.record
        or record.origin is not origin
        or record.observer_input != observer_input
        or record.config != config
    ):
        raise _OriginError("observation_binding_mismatch")
    expected_job = _observer_job(origin)
    expected_wire = encode_observer_input(expected_job, observer_input)
    if (
        observation.input_sha256 != hashlib.sha256(expected_wire).hexdigest()
        or observation.source_sha256 != _source_digest(expected_job)
        or any(
            getattr(observation, name) != getattr(origin.execution, name)
            for name in (
                "config_sha256",
                "daemon_sha256",
                "image_sha256",
                "policy_sha256",
                "bootstrap_sha256",
            )
        )
    ):
        raise _OriginError("observation_binding_mismatch")


def _observation_stdout(execution: IsolatedExecution) -> bytes:
    record = _checked_record(execution, observation=True)
    if record.origin is None or record.observer_input is None:
        raise _OriginError("observation_binding_mismatch")
    _require_bound_observation(record.config, execution, record.origin, record.observer_input)
    return execution._stdout


def probe_isolation(config: IsolationConfig) -> IsolationCapabilities:
    return _probe_public(config)


def run_isolated_job(config: IsolationConfig, job: IsolatedJob) -> IsolatedExecution:
    return _run_public(config, job)


def _run_isolated_observation(
    config: IsolationConfig, job: IsolatedJob, observer_input: bytes, origin: _LiveOriginProof
) -> IsolatedExecution:
    if type(origin) is not _LiveOriginProof:
        raise _OriginError("not_live")
    checked = _require_live_origin(config, origin.execution, origin.artifact)
    if checked.record is not origin.record:
        raise _OriginError("origin_binding_mismatch")
    if (
        job.argv != (INTERPRETER, "-I", "candidate.py")
        or job.collect_paths
        or len(job.files) != 1
        or job.files[0].path != "candidate.py"
        or job.files[0].content.encode("utf-8") != origin.artifact.data
        or type(observer_input) is not bytes
        or len(observer_input) > 512
    ):
        raise _OriginError("observation_binding_mismatch")
    return _run_public(config, job, observer_input=observer_input, origin=origin)


class _Failure(Exception):
    def __init__(self, code: ErrorCode):
        super().__init__("Isolated execution did not establish the required controls")
        self.code = code


def _json_bytes(raw: bytes, maximum: int = 1048576) -> dict:
    if len(raw) > maximum or b"\0" in raw or raw.startswith(b"\xef\xbb\xbf"):
        raise ValueError("Invalid bounded JSON")
    raw.decode("utf-8", errors="strict")
    value = parse_json_object(raw)

    def walk(item, depth=0):
        if depth > 16:
            raise ValueError("Invalid bounded JSON")
        if isinstance(item, dict):
            for child in item.values():
                walk(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                walk(child, depth + 1)

    walk(value)
    return value


def _open_parent(path: Path) -> tuple[int, str]:
    path = path if path.is_absolute() else Path.cwd() / path
    if ".." in path.parts or not path.name:
        raise ValueError("Expected a bounded local file")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def _read_local(path: Path, maximum: int) -> bytes:
    parent, name = _open_parent(path)
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("Expected a bounded regular file")
        parts, count = [], 0
        while True:
            chunk = os.read(fd, min(65536, maximum + 1 - count))
            if not chunk:
                break
            parts.append(chunk)
            count += len(chunk)
            if count > maximum:
                raise ValueError("Expected a bounded regular file")
        return b"".join(parts)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _write_exclusive(path: Path, raw: bytes, maximum: int) -> None:
    if len(raw) > maximum:
        raise ValueError("Output exceeded its bound")
    parent, name = _open_parent(path)
    fd = None
    try:
        fd = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent
        )
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("No output progress")
            view = view[count:]
        os.fsync(fd)
        os.fsync(parent)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _private_directory(path: Path) -> None:
    fresh = False
    try:
        os.mkdir(path, 0o700)
        fresh = True
    except FileExistsError:
        pass
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise _Failure("invalid_config")
        if fresh:
            os.fsync(fd)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class _CommandResult:
    stdout: bytes
    stderr: bytes
    return_code: int
    stdin_bytes: int = 0


class _HostDeadline(_Failure):
    def __init__(self):
        super().__init__("execution_timeout")


class _WallProgress:
    def __init__(self, driver, identity: str):
        self.driver, self.identity = driver, identity
        self.observed = False

    def observe(self, deadline: float) -> None:
        if self.observed:
            return
        try:
            result = self.driver.command(
                ("container", "top", self.identity, "-eo", "pid,ppid,comm"),
                min(deadline, time.monotonic() + 0.2),
                limit=4096,
            )
            if result.return_code:
                return
            rows = result.stdout.decode("ascii").splitlines()
            if (
                not rows
                or len(rows) > 33
                or rows[0].split() not in (["PID", "PPID", "COMMAND"], ["PID", "PPID", "CMD"])
            ):
                return
            processes = []
            for row in rows[1:]:
                parts = row.split()
                if len(parts) != 3 or not parts[0].isdigit() or not parts[1].isdigit():
                    return
                pid, parent = int(parts[0]), int(parts[1])
                if not 0 < pid < 2147483648 or not 0 <= parent < 2147483648:
                    return
                processes.append((pid, parent, parts[2]))
            if len({x[0] for x in processes}) != len(processes):
                return
            init = {pid for pid, _parent, comm in processes if comm == "docker-init"}
            bootstrap = {
                pid for pid, parent, comm in processes if parent in init and comm == "python3.11"
            }
            self.observed = (
                len(init) == 1
                and len(bootstrap) == 1
                and any(
                    parent in bootstrap and comm == "python3.11" for _pid, parent, comm in processes
                )
            )
        except (OSError, ValueError, UnicodeError, _Failure):
            self.observed = False


class _Process:
    """Bounded concurrent pipe I/O; caller contains the container before close."""

    def __init__(self, argv: list[str], environment: dict[str, str]):
        self.stdin_bytes = 0
        self.input_complete = False
        try:
            self.process = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                cwd="/",
                start_new_session=True,
            )
        except OSError:
            raise _Failure("client_unavailable") from None

    def exchange(
        self,
        raw: bytes,
        deadline: float,
        stdout_limit: int,
        stderr_limit: int = 65536,
        *,
        progress: _WallProgress | None = None,
    ) -> _CommandResult:
        if len(raw) > 8388608:
            raise _Failure("input_overflow")
        process = self.process
        outputs = {"stdout": bytearray(), "stderr": bytearray()}
        sent = 0
        with selectors.DefaultSelector() as selector:
            for name in ("stdout", "stderr"):
                stream = getattr(process, name)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            if raw:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _HostDeadline()
                if self.input_complete and progress is not None:
                    progress.observe(deadline)
                for key, _event in selector.select(min(remaining, 0.05)):
                    stream, name = key.fileobj, key.data
                    if name == "stdin":
                        try:
                            count = os.write(stream.fileno(), raw[sent : sent + 65536])
                            sent += count
                            self.stdin_bytes = sent
                        except BrokenPipeError:
                            selector.unregister(stream)
                            stream.close()
                            continue
                        except BlockingIOError:
                            continue
                        if sent == len(raw):
                            selector.unregister(stream)
                            stream.close()
                            self.input_complete = True
                    else:
                        try:
                            chunk = os.read(stream.fileno(), 65536)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(stream)
                            continue
                        limit = stdout_limit if name == "stdout" else stderr_limit
                        if len(outputs[name]) + len(chunk) > limit:
                            raise _Failure("output_overflow")
                        outputs[name].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _HostDeadline()
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                raise _HostDeadline() from None
        return _CommandResult(bytes(outputs["stdout"]), bytes(outputs["stderr"]), code, sent)

    def close(self, deadline: float) -> None:
        try:
            if self.process.poll() is None:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=max(0.001, deadline - time.monotonic()))
        except (OSError, subprocess.TimeoutExpired):
            raise _Failure("cleanup_failed") from None
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                if stream is not None:
                    stream.close()


class _DockerDriver:
    """Only fixed builtin CLI commands using an absolute trusted binary."""

    runtime_kind = "real"

    def __init__(self, config: IsolationConfig, client_config: Path):
        self.config = config
        self.client_config = client_config
        self.endpoint: str | None = None
        self.environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        self.daemon_sha256: str | None = None

    def _argv(self, args: tuple[str, ...], *, context: bool = False) -> list[str]:
        if context:
            if args[:2] != ("context", "inspect"):
                raise _Failure("invalid_config")
            return [
                self.config.docker_executable,
                "--config",
                self.config.context_config_directory,
                *args,
            ]
        if self.endpoint is None:
            raise _Failure("context_unavailable")
        allowed = {
            ("info",),
            ("image", "inspect"),
            ("container", "create"),
            ("container", "inspect"),
            ("container", "start"),
            ("container", "wait"),
            ("container", "kill"),
            ("container", "rm"),
            ("container", "ls"),
            ("container", "top"),
        }
        if not any(args[: len(prefix)] == prefix for prefix in allowed):
            raise _Failure("invalid_config")
        return [
            self.config.docker_executable,
            "--config",
            str(self.client_config),
            "--host",
            self.endpoint,
            *args,
        ]

    def command(
        self, args: tuple[str, ...], deadline: float, *, context: bool = False, limit: int = 1048576
    ) -> _CommandResult:
        process = _Process(self._argv(args, context=context), self.environment)
        try:
            return process.exchange(b"", deadline, limit)
        finally:
            process.close(min(deadline + 0.1, time.monotonic() + 0.2))

    def prepare(self, deadline: float) -> tuple[str, str]:
        try:
            executable = os.stat(self.config.docker_executable, follow_symlinks=False)
            if not stat.S_ISREG(executable.st_mode) or not os.access(
                self.config.docker_executable, os.X_OK
            ):
                raise _Failure("client_unavailable")
            selected = self.command(
                (
                    "context",
                    "inspect",
                    self.config.context_name,
                    "--format",
                    "{{json .Endpoints.docker}}",
                ),
                deadline,
                context=True,
                limit=16384,
            )
            if selected.return_code:
                raise _Failure("context_unavailable")
            endpoint = _json_bytes(selected.stdout, 16384)
            host = endpoint.get("Host")
            if type(host) is not str:
                raise _Failure("remote_endpoint")
            parsed = urlsplit(host)
            if (
                parsed.scheme != "unix"
                or parsed.netloc
                or not parsed.path.startswith("/")
                or parsed.query
                or parsed.fragment
                or "%" in parsed.path
                or any(ord(c) < 32 for c in host)
                or endpoint.get("SkipTLSVerify") is True
            ):
                raise _Failure("remote_endpoint")
            self.endpoint = host
            daemon = self.daemon_identity(deadline)
            image = self.command(
                (
                    "image",
                    "inspect",
                    "--platform",
                    PLATFORM,
                    IMAGE_REFERENCE,
                    "--format",
                    "{{json .}}",
                ),
                deadline,
            )
            if image.return_code:
                raise _Failure("image_unavailable")
            _validate_image(_json_bytes(image.stdout))
            self.daemon_sha256 = daemon
            return daemon, IMAGE_ID.removeprefix("sha256:")
        except _Failure:
            raise
        except (OSError, ValueError, TypeError, UnicodeError):
            raise _Failure("invalid_config") from None

    def daemon_identity(self, deadline: float) -> str:
        result = self.command(("info", "--format", "{{json .}}"), deadline)
        if result.return_code:
            raise _Failure("daemon_unavailable")
        value = _json_bytes(result.stdout)
        selected = {
            key: value.get(key)
            for key in (
                "ID",
                "ServerVersion",
                "OSType",
                "Architecture",
                "KernelVersion",
                "CgroupVersion",
                "CgroupDriver",
                "SecurityOptions",
            )
        }
        if (
            not selected["ID"]
            or selected["OSType"] != "linux"
            or selected["Architecture"] not in ("aarch64", "arm64")
            or str(selected["CgroupVersion"]) != "2"
            or not any("seccomp" in str(item) for item in (selected["SecurityOptions"] or []))
        ):
            raise _Failure("unsupported_platform")
        return _digest(selected)

    def inspect(self, identity: str, deadline: float) -> dict | None:
        result = self.command(
            ("container", "inspect", identity, "--format", "{{json .}}"), deadline
        )
        if result.return_code:
            return None
        return _json_bytes(result.stdout)

    def absent(self, identity: str, deadline: float) -> bool:
        result = self.command(
            (
                "container",
                "ls",
                "--all",
                "--no-trunc",
                "--filter",
                "id=" + identity,
                "--format",
                "{{.ID}}",
            ),
            deadline,
            limit=4096,
        )
        return result.return_code == 0 and not result.stdout.strip()

    def attach(self, identity: str) -> _Process:
        return _Process(
            self._argv(("container", "start", "--attach", "--interactive", identity)),
            self.environment,
        )


def _validate_image(value: dict) -> None:
    descriptor = value.get("Descriptor", {})
    platform = descriptor.get("platform", {})
    if (
        value.get("Id") != IMAGE_ID
        or descriptor.get("digest") != IMAGE_ID
        or descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
        or platform != {"architecture": "arm64", "os": "linux", "variant": "v8"}
        or value.get("Os") != "linux"
        or value.get("Architecture") != "arm64"
        or _digest(value.get("Config")) != IMAGE_CONFIG_SHA256
    ):
        raise _Failure("image_mismatch")
    config = value["Config"]
    if config != {"Env": list(_IMAGE_ENV), "Cmd": ["python3"]}:
        raise _Failure("image_mismatch")


def _owned(value: dict, name: str, nonce: str, identity: str | None = None) -> str:
    config = value.get("Config")
    descriptor = value.get("ImageManifestDescriptor")
    if (
        type(config) is not dict
        or type(config.get("Labels")) is not dict
        or type(descriptor) is not dict
    ):
        raise _Failure("ownership_mismatch")
    found = value.get("Id")
    if (
        type(found) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", found)
        or (identity is not None and found != identity)
        or value.get("Name") != "/" + name
        or value.get("Image") != _IMAGE_STORE_TARGET
        or config.get("Image") != IMAGE_REFERENCE
        or descriptor.get("digest") != IMAGE_ID
        or descriptor.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
        or descriptor.get("platform") != {"architecture": "arm64", "os": "linux", "variant": "v8"}
        or config["Labels"].get("reviewboundary.owner") != nonce
    ):
        raise _Failure("ownership_mismatch")
    return found


def _validate_container(value: dict, name: str, nonce: str, identity: str) -> None:
    _owned(value, name, nonce, identity)
    config, host = value.get("Config", {}), value.get("HostConfig", {})
    expected = {
        "ReadonlyRootfs": True,
        "Privileged": False,
        "NetworkMode": "none",
        "PidMode": "",
        "IpcMode": "private",
        "CgroupnsMode": "private",
        "NanoCpus": 500000000,
        "Memory": 268435456,
        "MemorySwap": 268435456,
        "PidsLimit": 32,
        "ShmSize": 1048576,
        "AutoRemove": False,
        "Init": True,
        "PublishAllPorts": False,
    }
    if any(type(host.get(k)) is not type(v) or host.get(k) != v for k, v in expected.items()):
        raise _Failure("policy_mismatch")
    if (
        host.get("CapDrop") != ["ALL"]
        or host.get("CapAdd") not in (None, [])
        or set(host.get("SecurityOpt") or []) != {"no-new-privileges"}
        or host.get("Tmpfs") != _TMPFS
        or host.get("LogConfig", {}).get("Type") != "none"
        or host.get("LogConfig", {}).get("Config") not in ({}, None)
        or host.get("RestartPolicy", {}).get("Name") not in ("no", "")
        or any(
            host.get(key)
            for key in (
                "Binds",
                "Mounts",
                "Devices",
                "DeviceRequests",
                "PortBindings",
                "ExtraHosts",
                "VolumesFrom",
                "Links",
            )
        )
        or value.get("Mounts") not in ([], None)
    ):
        raise _Failure("policy_mismatch")
    limits = {
        item.get("Name"): (item.get("Soft"), item.get("Hard")) for item in host.get("Ulimits", [])
    }
    if limits != {"nofile": (256, 256), "core": (0, 0), "fsize": (8388608, 8388608)}:
        raise _Failure("policy_mismatch")
    environment = config.get("Env")
    if (
        not isinstance(environment, list)
        or len(environment) != len(set(environment))
        or sorted(environment) != list(_EFFECTIVE_ENV)
        or config.get("Entrypoint") != [INTERPRETER]
        or config.get("Cmd") != ["-I", "-c", BOOTSTRAP_SOURCE]
        or config.get("User") != "65532:65532"
        or config.get("Hostname") != HOSTNAME
        or config.get("Domainname") not in (None, "")
        or config.get("WorkingDir") != "/workspace"
        or config.get("Image") != IMAGE_REFERENCE
        or config.get("StopSignal") != "SIGKILL"
        or config.get("StopTimeout") != 1
        or config.get("Healthcheck", {}).get("Test") != ["NONE"]
        or config.get("Volumes")
        or config.get("ExposedPorts")
        or value.get("NetworkSettings", {}).get("Ports")
    ):
        raise _Failure("policy_mismatch")


class _Journal:
    """Atomic bounded private state under a stable persistent lock inode."""

    def __init__(self, root: Path, daemon: str):
        import fcntl

        _private_directory(root)
        self.path = root / daemon
        self.lock = self.file = self.directory = None
        self.data = {}
        fresh = False
        try:
            try:
                os.mkdir(self.path, 0o700)
                fresh = True
            except FileExistsError:
                pass
            self.directory = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(self.directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise _Failure("recovery_required")
            if fresh:
                parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(parent)
                finally:
                    os.close(parent)
            flags = os.O_RDWR | os.O_NOFOLLOW
            self.lock = os.open(
                "lock",
                flags | (os.O_CREAT | os.O_EXCL if fresh else 0),
                0o600,
                dir_fd=self.directory,
            )
            self._check_file(self.lock)
            try:
                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise _Failure("lock_busy") from None
            if fresh:
                os.fsync(self.lock)
                os.fsync(self.directory)
                self.store("idle")
            else:
                self.file = os.open("journal.json", flags, dir_fd=self.directory)
                self._check_file(self.file)
                raw = os.read(self.file, 16385)
                value = _json_bytes(raw, 16384)
                if (
                    type(value.get("schema_version")) is not int
                    or value.get("schema_version") != 1
                    or value.get("state") != "idle"
                ):
                    raise _Failure("recovery_required")
                self.data = value
                with os.scandir(self.directory) as entries:
                    if any(entry.name.startswith(".journal-") for entry in entries):
                        raise _Failure("recovery_required")
        except _Failure:
            self.close()
            raise
        except (OSError, ValueError, TypeError):
            self.close()
            raise _Failure("recovery_required") from None

    def _check_file(self, fd: int) -> None:
        value = os.fstat(fd)
        if (
            not stat.S_ISREG(value.st_mode)
            or value.st_uid != os.getuid()
            or stat.S_IMODE(value.st_mode) != 0o600
            or value.st_nlink != 1
        ):
            raise _Failure("recovery_required")

    def _check_names(self):
        held_directory = os.fstat(self.directory)
        named_directory = self.path.lstat()
        named_lock = os.stat("lock", dir_fd=self.directory, follow_symlinks=False)
        held_lock = os.fstat(self.lock)
        if (named_directory.st_dev, named_directory.st_ino) != (
            held_directory.st_dev,
            held_directory.st_ino,
        ) or (named_lock.st_dev, named_lock.st_ino) != (held_lock.st_dev, held_lock.st_ino):
            raise _Failure("recovery_required")
        if self.file is None:
            try:
                os.stat("journal.json", dir_fd=self.directory, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise _Failure("recovery_required")
        if self.file is not None:
            self._check_file(self.file)
            current = os.stat("journal.json", dir_fd=self.directory, follow_symlinks=False)
            held = os.fstat(self.file)
            if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                raise _Failure("recovery_required")
            if os.pread(self.file, 16385, 0) != _canonical(self.data):
                raise _Failure("recovery_required")

    def store(self, state: str, **facts) -> None:
        if state not in ("idle", "creating", "created", "blocked"):
            raise _Failure("recovery_required")
        self._check_names()
        raw = _canonical({"schema_version": 1, "state": state, **facts})
        if len(raw) > 16384:
            raise _Failure("recovery_required")
        pending = ".journal-" + uuid.uuid4().hex
        fd = os.open(
            pending,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=self.directory,
        )
        adopted = False
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise _Failure("recovery_required")
                view = view[count:]
            os.fsync(fd)
            self._check_names()
            expected = os.fstat(fd)
            os.replace(
                pending, "journal.json", src_dir_fd=self.directory, dst_dir_fd=self.directory
            )
            named = os.stat("journal.json", dir_fd=self.directory, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (expected.st_dev, expected.st_ino):
                raise _Failure("recovery_required")
            previous = self.file
            self.file = fd
            adopted = True
            if previous is not None:
                os.close(previous)
            self.data = {"schema_version": 1, "state": state, **facts}
            os.fsync(self.directory)
        finally:
            if not adopted:
                os.close(fd)
            # Any failed pending file is retained. A future constructor blocks on it.

    def close(self) -> None:
        for name in ("file", "lock", "directory"):
            fd = getattr(self, name, None)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)


@dataclass(frozen=True)
class _ContainerOutcome:
    error_code: ErrorCode | None
    started: bool
    parsed: ParsedContainerResult | None
    checks: tuple[CheckResult, ...]
    facts: DriverFacts
    cleanup: Literal["confirmed", "failed", "not_needed"]
    host_deadline: bool = False
    input_complete: bool = False
    child_progress: bool = False


def _discard_cidfile(path: Path, identity: str) -> None:
    parent, name = _open_parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        try:
            held = os.fstat(fd)
            if (
                not stat.S_ISREG(held.st_mode)
                or held.st_uid != os.getuid()
                or held.st_nlink != 1
                or os.read(fd, 129).strip() != identity.encode("ascii")
            ):
                raise _Failure("recovery_required")
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                raise _Failure("recovery_required")
            os.unlink(name, dir_fd=parent)
            os.fsync(parent)
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def _cleanup(
    driver,
    journal: _Journal,
    name: str,
    nonce: str,
    identity: str | None,
    handle,
    deadline: float,
    *,
    cidfile: Path,
    creation_confirmed: bool,
) -> bool:
    success = False
    try:
        if driver.daemon_identity(deadline) != driver.daemon_sha256:
            raise _Failure("daemon_changed")
        value = driver.inspect(identity or name, deadline)
        if value is None:
            if identity is None:
                result = driver.command(
                    (
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        "name=^/" + name + "$",
                        "--format",
                        "{{.ID}}",
                    ),
                    deadline,
                    limit=4096,
                )
                absent = result.return_code == 0 and not result.stdout.strip()
            else:
                absent = driver.absent(identity, deadline)
            if not absent:
                raise _Failure("cleanup_failed")
        else:
            identity = _owned(value, name, nonce, identity)
            if value.get("State", {}).get("Running") is True:
                result = driver.command(
                    ("container", "kill", "--signal", "SIGKILL", identity), deadline, limit=4096
                )
                if result.return_code:
                    raise _Failure("cleanup_failed")
            while True:
                value = driver.inspect(identity, deadline)
                if value is None or type(value.get("State", {}).get("Running")) is not bool:
                    raise _Failure("cleanup_failed")
                _owned(value, name, nonce, identity)
                if not value["State"]["Running"]:
                    break
                if time.monotonic() >= deadline:
                    raise _Failure("cleanup_failed")
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        # Client completion precedes every idle commit, including already-absent containers.
        if handle is not None:
            handle.close(deadline)
            handle = None
        if value is not None:
            removed = driver.command(
                ("container", "rm", "--volumes", identity), deadline, limit=4096
            )
            if removed.return_code or not driver.absent(identity, deadline):
                raise _Failure("cleanup_failed")
        if not creation_confirmed or identity is None:
            # A request may still finish after a disconnected client observed absence.
            raise _Failure("recovery_required")
        _discard_cidfile(cidfile, identity)
        journal.store("idle", last_nonce=nonce, last_container_id=identity, cleanup="confirmed")
        success = True
    except (Exception, KeyboardInterrupt):  # noqa: BLE001
        try:
            journal.store("blocked", nonce=nonce, name=name, container_id=identity)
        except Exception:  # noqa: BLE001
            success = False
    finally:
        if handle is not None:
            try:
                handle.close(deadline)
            except Exception:  # noqa: BLE001
                success = False
    return success


def _execute_container(
    driver,
    journal: _Journal,
    directory: Path,
    job: IsolatedJob,
    raw: bytes,
    deadline: float,
    total_deadline: float,
    *,
    execution_seconds: float | None = None,
    wall_control: bool = False,
) -> _ContainerOutcome:
    began = time.monotonic()
    nonce = uuid.uuid4().hex
    name = "reviewboundary-" + nonce
    cidfile = directory / (nonce + ".cid")
    identity, handle, parsed = None, None, None
    started = False
    checks = []
    error = None
    facts = DriverFacts()
    cancelled = None
    intent = False
    creation_confirmed = False
    host_deadline = False
    progress = None
    phase = "setup"
    try:
        if time.monotonic() >= deadline:
            raise _Failure("execution_timeout")
        journal.store(
            "creating", nonce=nonce, name=name, image=IMAGE_ID, daemon_sha256=driver.daemon_sha256
        )
        intent = True
        created = driver.command(_create_arguments(name, nonce, cidfile), deadline, limit=4096)
        if created.return_code:
            raise _Failure("create_failed")
        claimed_identity = created.stdout.strip().decode("ascii")
        if not re.fullmatch(r"[0-9a-f]{64}", claimed_identity):
            raise _Failure("ownership_mismatch")
        if _read_local(cidfile, 128).strip().decode("ascii") != claimed_identity:
            raise _Failure("ownership_mismatch")
        identity = claimed_identity
        creation_confirmed = True
        journal.store(
            "created",
            nonce=nonce,
            name=name,
            container_id=identity,
            image=IMAGE_ID,
            daemon_sha256=driver.daemon_sha256,
        )
        before = driver.inspect(identity, deadline)
        if before is None:
            raise _Failure("policy_mismatch")
        _validate_container(before, name, nonce, identity)
        checks.append(CheckResult(check_id="before_start", status="passed"))
        if driver.daemon_identity(deadline) != driver.daemon_sha256:
            raise _Failure("daemon_changed")
        handle = driver.attach(identity)
        while True:
            after = driver.inspect(identity, deadline)
            if after is None:
                raise _Failure("start_failed")
            _validate_container(after, name, nonce, identity)
            state = after.get("State", {})
            if state.get("Running") is True:
                break
            if state.get("Status") != "created" or time.monotonic() >= deadline:
                raise _Failure("start_failed")
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        checks.append(CheckResult(check_id="after_start", status="passed"))
        # No job bytes are sent until the actual started container policy matches.
        started = True
        exchange_deadline = (
            min(deadline, time.monotonic() + execution_seconds)
            if execution_seconds is not None
            else deadline
        )
        progress = _WallProgress(driver, identity) if wall_control else None
        phase = "exchange"
        response = handle.exchange(raw, exchange_deadline, 2097152, 65536, progress=progress)
        phase = "wait"
        if response.stdin_bytes != len(raw):
            raise _Failure("transport_error")
        waited = driver.command(("container", "wait", identity), deadline, limit=64)
        if waited.return_code or not re.fullmatch(rb"[0-9]{1,3}\s*", waited.stdout):
            raise _Failure("container_failed")
        after = driver.inspect(identity, deadline)
        if after is None:
            raise _Failure("policy_mismatch")
        _validate_container(after, name, nonce, identity)
        state = after.get("State", {})
        if (
            state.get("Running") is not False
            or type(state.get("OOMKilled")) is not bool
            or type(state.get("ExitCode")) is not int
            or state["ExitCode"] != int(waited.stdout)
        ):
            raise _Failure("policy_mismatch")
        checks.append(CheckResult(check_id="after_wait", status="passed"))
        facts = DriverFacts(
            stdin_bytes=response.stdin_bytes,
            stdout_bytes=len(response.stdout),
            stderr_bytes=len(response.stderr),
            client_return_code=response.return_code,
            daemon_exit_code=state["ExitCode"],
            daemon_oom_killed=state["OOMKilled"],
        )
        if response.return_code or state["ExitCode"]:
            raise _Failure("container_failed")
        try:
            parsed = decode_result_wire(response.stdout, job)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise _Failure("malformed_result") from None
        if state["OOMKilled"]:
            raise _Failure("container_oom")
        if parsed.claimed_status != "completed":
            code = {
                "child_output_overflow": "output_overflow",
                "child_timeout": "execution_timeout",
            }
            raise _Failure(code.get(parsed.error_code, "container_failed"))
        if parsed.missing_paths:
            raise _Failure("artifact_incomplete")
        if parsed.claimed_child_return_code != 0:
            raise _Failure("container_failed")
    except _HostDeadline:
        error = "execution_timeout"
        host_deadline = phase == "exchange" and bool(getattr(handle, "input_complete", False))
    except _Failure as exc:
        error = exc.code
    except (KeyboardInterrupt, SystemExit) as exc:
        cancelled = exc
        error = "cancelled"
    except Exception:  # noqa: BLE001
        error = "internal_error"
    finally:
        if intent:
            cleanup_deadline = min(total_deadline, time.monotonic() + 5)
            clean = _cleanup(
                driver,
                journal,
                name,
                nonce,
                identity,
                handle,
                cleanup_deadline,
                cidfile=cidfile,
                creation_confirmed=creation_confirmed,
            )
            cleanup = "confirmed" if clean else "failed"
            if not clean:
                error = "cleanup_failed"
        else:
            cleanup = "not_needed"
    if cancelled is not None:
        raise cancelled
    elapsed = int((time.monotonic() - began) * 1000)
    if time.monotonic() > deadline and error is None:
        error = "execution_timeout"
    input_complete = bool(getattr(handle, "input_complete", False))
    child_progress = bool(progress and progress.observed)
    facts = facts.model_copy(
        update={
            "elapsed_ms": elapsed,
            "input_complete": input_complete,
            "host_exchange_timeout": host_deadline,
            "child_progress_observed": child_progress,
            "stdin_bytes": min(8388608, getattr(handle, "stdin_bytes", facts.stdin_bytes)),
        }
    )
    return _ContainerOutcome(
        error,
        started,
        parsed,
        tuple(checks),
        facts,
        cleanup,
        host_deadline,
        input_complete,
        child_progress,
    )


def _probe_value(name: str, outcome: _ContainerOutcome) -> bool:
    if outcome.cleanup != "confirmed" or len(outcome.checks) < 2:
        return False
    if name == "wall":
        return (
            outcome.error_code == "execution_timeout"
            and outcome.host_deadline
            and outcome.input_complete
            and outcome.child_progress
        )
    if name in ("stdout_overflow", "stderr_overflow"):
        return (
            outcome.error_code == "output_overflow"
            and outcome.parsed is not None
            and outcome.parsed.error_code == "child_output_overflow"
        )
    if (
        outcome.error_code is not None
        and not (name == "memory" and outcome.error_code == "container_oom")
    ) or outcome.parsed is None:
        return False
    try:
        value = _json_bytes(outcome.parsed.stdout, 65536 if name == "input_headroom" else 16384)
        if name == "input_headroom":
            return (
                value == {"source_bytes": 4194304, "file_count": 64}
                and all(type(value.get(k)) is int for k in ("source_bytes", "file_count"))
                and len(outcome.parsed.stdout) == 65536
                and len(outcome.parsed.stderr) == 65536
                and len(outcome.parsed.artifacts) == 4
                and all(len(item.data) == 65536 for item in outcome.parsed.artifacts)
            )
        if name == "configuration":
            expected = {
                "uid": 65532,
                "gid": 65532,
                "nnp": "1",
                "seccomp": "2",
                "readonly": True,
                "cpu": "50000 100000",
                "memory": "268435456",
                "swap": "0",
                "pids": "32",
                "workspace_bytes": 16777216,
                "workspace_inodes": 4096,
                "temp_bytes": 8388608,
                "temp_inodes": 1024,
                "shm_bytes": 1048576,
                "interfaces": ["lo"],
                "ipv4_blocked": True,
                "ipv6_blocked": True,
                "socket_absent": True,
                "pid1_init": True,
                "python": [3, 11],
                "isolated": True,
            }
            if any(
                type(value.get(k)) is not type(v) or value.get(k) != v for k, v in expected.items()
            ):
                return False
            return (
                value.get("caps") == ["0000000000000000"] * 5
                and value.get("ulimits")
                == {"nofile": [256, 256], "core": [0, 0], "fsize": [8388608, 8388608]}
                and sorted(k + "=" + v for k, v in value.get("environment", {}).items())
                == list(_EFFECTIVE_ENV)
                and {"rw", "nosuid", "nodev"} <= set(value.get("workspace_mount", []))
                and "noexec" not in value.get("workspace_mount", [])
                and {"rw", "nosuid", "nodev", "noexec"} <= set(value.get("temp_mount", []))
            )
        if name == "cpu":
            return (
                type(value.get("throttled")) is int
                and value["throttled"] > 0
                and type(value.get("usec")) is int
                and value["usec"] > 0
            )
        if name == "memory":
            return (
                outcome.facts.daemon_exit_code == 0
                and outcome.parsed.claimed_status == "completed"
                and outcome.parsed.claimed_child_return_code == 0
                and (
                    value.get("child_exit") == -9
                    and type(value.get("oom_kill")) is int
                    and value["oom_kill"] > 0
                )
            )
        if name == "pids":
            return (
                value.get("limited") is True
                and type(value.get("current")) is int
                and value.get("current") == 32
                and type(value.get("created")) is int
                and 1 <= value["created"] <= 31
            )
        if name == "tmpfs":
            return value == {
                root: {"bytes_full": True, "inodes_full": True} for root in ("/workspace", "/tmp")
            } and all(type(flag) is bool for row in value.values() for flag in row.values())
        return (
            value
            == {
                "stdin_null": {"empty": True},
                "stdin_observer": {"exact": True},
                "reaping": {"reaped": True},
            }[name]
        )
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False


@dataclass(frozen=True)
class _FreshGate:
    report: IsolationCapabilities
    config_sha256: str
    daemon_sha256: str
    image_sha256: str
    invocation: str


class _RunContext:
    def __init__(
        self, config: IsolationConfig, deadline: float, driver=None, state_root: Path | None = None
    ):
        if os.name != "posix":
            raise _Failure("unsupported_platform")
        default = Path("/private/tmp" if sys.platform == "darwin" else "/tmp")
        self.root = state_root or default / ("reviewboundary-isolation-" + str(os.getuid()))
        _private_directory(self.root)
        client = self.root / "client"
        _private_directory(client)
        config_path = client / "config.json"
        expected = _canonical({"auths": {}, "credsStore": "", "credHelpers": {}, "proxies": {}})
        try:
            _write_exclusive(config_path, expected, 4096)
        except FileExistsError:
            if _read_local(config_path, 4096) != expected:
                raise _Failure("invalid_config") from None
        self.driver = driver if driver is not None else _DockerDriver(config, client)
        self.daemon, self.image = self.driver.prepare(deadline)
        daemons = self.root / "daemons"
        _private_directory(daemons)
        self.journal = _Journal(daemons, self.daemon)
        self.invocation = uuid.uuid4().hex
        self.directory = self.journal.path / ("run-" + self.invocation)
        try:
            os.mkdir(self.directory, 0o700)
            self.directory_identity = self.directory.lstat()
            os.fsync(self.journal.directory)
        except BaseException:
            self.journal.close()
            raise

    def close(self) -> bool:
        success = True
        try:
            current = self.directory.lstat()
            expected = self.directory_identity
            if (current.st_dev, current.st_ino) != (expected.st_dev, expected.st_ino):
                raise _Failure("recovery_required")
            os.rmdir(self.directory.name, dir_fd=self.journal.directory)
            os.fsync(self.journal.directory)
        except (OSError, _Failure):
            success = False
            try:
                retained = {
                    k: v
                    for k, v in self.journal.data.items()
                    if k not in ("schema_version", "state")
                }
                retained.setdefault("nonce", self.invocation)
                self.journal.store("blocked", **retained)
            except (OSError, _Failure):
                success = False
        finally:
            self.journal.close()
        return success


def _control_job(name: str, script: str) -> IsolatedJob:
    files = (IsolatedTextFile(path="probe.py", content=script),)
    collect = ()
    if name == "input_headroom":
        padded = script + "\n#" + "x" * (65536 - len(script.encode("utf-8")) - 2)
        files = (IsolatedTextFile(path="probe.py", content=padded),) + tuple(
            IsolatedTextFile(path=f"data-{index:02d}.txt", content="x" * 65536)
            for index in range(63)
        )
        collect = tuple(f"data-{index:02d}.txt" for index in range(4))
    return IsolatedJob(
        schema_version=1, argv=(INTERPRETER, "-I", "probe.py"), files=files, collect_paths=collect
    )


def _gate(
    config: IsolationConfig,
    context: _RunContext,
    began: float,
    deadline: float,
    total_deadline: float,
    real: bool,
) -> _FreshGate:
    checks = []
    error = None
    for name, script, stdin, seconds in _PROBES:
        if time.monotonic() >= deadline:
            error = "probe_timeout"
            checks.append(CheckResult(check_id=name, status="not_tested"))
            break
        job = _control_job(name, script)
        wire = encode_command_input(job) if stdin is None else encode_observer_input(job, stdin)
        outcome = _execute_container(
            context.driver,
            context.journal,
            context.directory,
            job,
            wire,
            deadline,
            total_deadline,
            execution_seconds=seconds,
            wall_control=name == "wall",
        )
        passed = _probe_value(name, outcome)
        checks.append(CheckResult(check_id=name, status="passed" if passed else "failed"))
        if not passed:
            error = "cleanup_failed" if outcome.cleanup == "failed" else "probe_failed"
            break
    for name, *_rest in _PROBES[len(checks) :]:
        checks.append(CheckResult(check_id=name, status="not_tested"))
    if len(checks) != len(_PROBES) or any(item.status != "passed" for item in checks):
        error = error or "probe_failed"
    if time.monotonic() > deadline:
        error = "probe_timeout"
    if error is None and context.driver.daemon_identity(deadline) != context.daemon:
        error = "daemon_changed"
    report = IsolationCapabilities(
        status="unsupported" if error else "supported",
        error_code=error,
        daemon_sha256=context.daemon,
        image_sha256=context.image,
        config_sha256=_digest(config.model_dump(mode="json")),
        checks=tuple(checks),
        elapsed_ms=int((time.monotonic() - began) * 1000),
        runtime_kind="real" if real else "synthetic",
        vm_host_sharing="operator_attested",
    )
    return _FreshGate(
        report, report.config_sha256, context.daemon, context.image, context.invocation
    )


def _validate_arguments(config: IsolationConfig, job: IsolatedJob | None = None) -> None:
    try:
        if type(config) is not IsolationConfig:
            raise ValueError("Invalid config")
        IsolationConfig.model_validate_json(_canonical(config.model_dump(mode="json")))
        if job is not None:
            if type(job) is not IsolatedJob:
                raise ValueError("Invalid job")
            parse_isolated_job(_canonical(job.model_dump(mode="json")))
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("Expected strict bounded isolation configuration and job") from None


def _seal(
    execution: IsolatedExecution,
    config: IsolationConfig,
    *,
    kind: str,
    origin: _LiveOriginProof | None = None,
    observer_input: bytes | None = None,
) -> None:
    if kind == "observation":
        if origin is None or observer_input is None:
            raise _OriginError("observation_binding_mismatch")
        checked = _require_live_origin(config, origin.execution, origin.artifact)
        if checked.record is not origin.record:
            raise _OriginError("observation_binding_mismatch")
    bindings = tuple((x.path, len(x.data), artifact_digest(x)) for x in execution._artifacts)
    execution._origin = _LiveRecord(
        weakref.ref(execution),
        _digest(execution.to_report()),
        _digest(config.model_dump(mode="json")),
        bindings,
        hashlib.sha256(execution._stdout).hexdigest(),
        hashlib.sha256(execution._stderr).hexdigest(),
        kind,
        _REAL_AUTHORITY,
        config,
        origin,
        observer_input,
    )
    if kind == "observation":
        _require_bound_observation(config, execution, origin, observer_input)


def _run_pipeline(
    config: IsolationConfig,
    job: IsolatedJob,
    *,
    driver=None,
    state_root: Path | None = None,
    authority=None,
    observer_input: bytes | None = None,
    origin: _LiveOriginProof | None = None,
) -> IsolatedExecution:
    _validate_arguments(config, job)
    began = time.monotonic()
    total_deadline = began + 65
    wire = (
        encode_command_input(job)
        if observer_input is None
        else encode_observer_input(job, observer_input)
    )
    real = authority is _REAL_AUTHORITY and driver is None
    context = None
    gate = None
    outcome = None
    error = None
    try:
        context = _RunContext(config, began + 30, driver, state_root)
        real = real and type(context.driver) is _DockerDriver
        gate = _gate(config, context, began, began + 30, total_deadline, real)
        if gate.report.status != "supported":
            raise _Failure(gate.report.error_code or "probe_failed")
        if (
            gate.invocation != context.invocation
            or gate.config_sha256 != _digest(config.model_dump(mode="json"))
            or gate.report.bootstrap_sha256 != BOOTSTRAP_SHA256
            or gate.report.policy_sha256 != POLICY_SHA256
        ):
            raise _Failure("probe_failed")
        if origin is not None:
            _require_live_origin(config, origin.execution, origin.artifact)
            if (
                context.daemon != origin.execution.daemon_sha256
                or context.image != origin.execution.image_sha256
            ):
                raise _Failure("daemon_changed")
        outcome = _execute_container(
            context.driver,
            context.journal,
            context.directory,
            job,
            wire,
            min(total_deadline - 5, time.monotonic() + 30),
            total_deadline,
        )
        error = outcome.error_code
    except _Failure as exc:
        error = exc.code
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001
        error = "internal_error"
    finally:
        if context is not None and not context.close():
            error = "cleanup_failed"
    parsed = outcome.parsed if outcome else None
    observation = None
    if parsed is not None:
        observation = ContainerObservation(
            claimed_status=parsed.claimed_status,
            claimed_error_code=parsed.error_code,
            claimed_child_return_code=parsed.claimed_child_return_code,
            stdout_bytes=len(parsed.stdout),
            stderr_bytes=len(parsed.stderr),
            stdout_sha256=hashlib.sha256(parsed.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(parsed.stderr).hexdigest(),
            missing_artifact_count=len(parsed.missing_paths),
        )
    artifacts = parsed.artifacts if parsed is not None else ()
    execution = IsolatedExecution(
        execution_id=uuid.uuid4().hex,
        status="completed"
        if error is None and outcome
        else ("error" if outcome and outcome.started else "not_started"),
        error_code=error,
        job_started=bool(outcome and outcome.started),
        runtime_kind="real" if real else "synthetic",
        input_sha256=hashlib.sha256(wire).hexdigest(),
        config_sha256=_digest(config.model_dump(mode="json")),
        source_sha256=_source_digest(job),
        image_sha256=context.image if context else None,
        daemon_sha256=context.daemon if context else None,
        probe=gate.report if gate else None,
        inspections=outcome.checks if outcome else (),
        driver=outcome.facts
        if outcome
        else DriverFacts(elapsed_ms=int((time.monotonic() - began) * 1000)),
        container_observation=observation,
        artifact_manifest=artifact_manifest(artifacts),
        cleanup=outcome.cleanup
        if outcome
        else ("failed" if error == "cleanup_failed" else "not_needed"),
        vm_host_sharing="operator_attested" if context else "not_established",
    )
    execution._artifacts = artifacts
    execution._stdout = parsed.stdout if parsed else b""
    execution._stderr = parsed.stderr if parsed else b""
    if real and execution.status == "completed" and execution.cleanup == "confirmed":
        _seal(
            execution,
            config,
            kind="observation" if origin is not None else "command",
            origin=origin,
            observer_input=observer_input,
        )
    return execution


def _run_public(
    config: IsolationConfig,
    job: IsolatedJob,
    *,
    observer_input: bytes | None = None,
    origin: _LiveOriginProof | None = None,
) -> IsolatedExecution:
    return _run_pipeline(
        config, job, authority=_REAL_AUTHORITY, observer_input=observer_input, origin=origin
    )


def _run_with_driver(
    config: IsolationConfig, job: IsolatedJob, driver, *, state_root: Path
) -> IsolatedExecution:
    """Private unit seam: synthetic unconditionally, never a live authority token."""
    return _run_pipeline(config, job, driver=driver, state_root=state_root)


def _probe_public(config: IsolationConfig) -> IsolationCapabilities:
    _validate_arguments(config)
    began = time.monotonic()
    context = None
    report = None
    code = None
    try:
        context = _RunContext(config, began + 30)
        report = _gate(config, context, began, began + 30, began + 35, True).report
    except _Failure as exc:
        code = exc.code
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:  # noqa: BLE001
        code = "internal_error"
    finally:
        if context is not None and not context.close():
            code = "cleanup_failed"
    if report is not None and code is None:
        return report
    return IsolationCapabilities(
        status="unsupported",
        error_code=code or "internal_error",
        runtime_kind="real",
        config_sha256=_digest(config.model_dump(mode="json")),
        elapsed_ms=int((time.monotonic() - began) * 1000),
    )


def _load_config(path: Path) -> IsolationConfig:
    return IsolationConfig.model_validate_json(
        _canonical(_json_bytes(_read_local(path, 65536), 65536))
    )


def _new_output(path: Path) -> None:
    parent, name = _open_parent(path)
    try:
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise ValueError("Expected a new output file")
    finally:
        os.close(parent)


def isolation_probe_command(args) -> int:
    try:
        config = _load_config(args.config)
        _new_output(args.output)
        if args.dry_run:
            print("Isolation arguments validated; runtime capability remains untested.")
            return 0
        result = probe_isolation(config)
        _write_exclusive(args.output, _canonical(result.model_dump(mode="json")) + b"\n", 2097152)
        return 0 if result.status == "supported" else 1
    except (OSError, ValueError, TypeError, RecursionError):
        print(
            "Isolation refused: expected strict local configuration and a new bounded output.",
            file=sys.stderr,
        )
        return 2


def isolated_run_command(args) -> int:
    try:
        config = _load_config(args.config)
        job = parse_isolated_job(_read_local(args.job, 8388608))
        _validate_arguments(config, job)
        _new_output(args.output)
        if args.binding not in (None, "sum-echo-v1"):
            raise ValueError("Unknown static binding")
        if args.dry_run:
            print("Isolation arguments validated; no container or provider action was performed.")
            return 0
        result = run_isolated_job(config, job)
        from .isolated_verifier import IsolatedInvocationReport

        verified = None
        if args.binding is not None:
            from .isolated_verifier import verify_isolated_execution

            artifact = next(
                (x for x in result.collected_artifacts if x.path == "candidate.py"), None
            )
            verified = verify_isolated_execution(config, args.binding, result, artifact)
        document = IsolatedInvocationReport(execution=result, verification_result=verified)
        _write_exclusive(args.output, _canonical(document.model_dump(mode="json")) + b"\n", 2097152)
        return (
            0
            if result.status == "completed"
            and (verified is None or verified.verdict == "established_pass")
            else 1
        )
    except (OSError, ValueError, TypeError, RecursionError):
        print(
            "Isolation refused: expected strict local job data and a new bounded output.",
            file=sys.stderr,
        )
        return 2
