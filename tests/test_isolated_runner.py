"""Pure/controller tests with synthetic transport only, never a Docker process."""

import base64
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from review_boundary import isolated_runner as r
from review_boundary.isolation_payload import IsolatedJob, IsolatedTextFile

EXPECTED_INDEX_ID = "sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79"
EXPECTED_IMAGE_REFERENCE = "docker.io/library/python@" + EXPECTED_INDEX_ID


def config():
    return r.IsolationConfig(
        docker_executable="/trusted/docker",
        context_config_directory="/trusted/context",
        context_name="review-boundary-eval",
    )


def job():
    return IsolatedJob(
        schema_version=1,
        argv=("/usr/local/bin/python3.11", "-I", "candidate.py"),
        files=(IsolatedTextFile(path="candidate.py", content="PRIVATE_SOURCE_SENTINEL"),),
        collect_paths=("candidate.py",),
    )


@pytest.fixture(autouse=True)
def no_real_process(monkeypatch):
    def reject(*args, **kwargs):
        raise AssertionError(
            "Real subprocess execution is forbidden in isolated controller unit tests"
        )

    monkeypatch.setattr(r.subprocess, "Popen", reject)
    for name in (
        "system",
        "popen",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "posix_spawn",
        "posix_spawnp",
    ):
        if hasattr(os, name):
            monkeypatch.setattr(os, name, reject)


def valid_inspect(name, nonce, identity):
    return {
        "Id": identity,
        "Name": "/" + name,
        "Image": EXPECTED_INDEX_ID,
        "ImageManifestDescriptor": {
            "digest": r.IMAGE_ID,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
        },
        "Config": {
            "Labels": {"reviewboundary.owner": nonce},
            "Env": list(r._EFFECTIVE_ENV),
            "Entrypoint": [r.INTERPRETER],
            "Cmd": ["-I", "-c", r.BOOTSTRAP_SOURCE],
            "User": "65532:65532",
            "Hostname": r.HOSTNAME,
            "WorkingDir": "/workspace",
            "Image": EXPECTED_IMAGE_REFERENCE,
            "StopSignal": "SIGKILL",
            "StopTimeout": 1,
            "Healthcheck": {"Test": ["NONE"]},
        },
        "HostConfig": {
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
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
            "Tmpfs": dict(r._TMPFS),
            "LogConfig": {"Type": "none", "Config": {}},
            "RestartPolicy": {"Name": "no"},
            "Ulimits": [
                {"Name": "nofile", "Soft": 256, "Hard": 256},
                {"Name": "core", "Soft": 0, "Hard": 0},
                {"Name": "fsize", "Soft": 8388608, "Hard": 8388608},
            ],
        },
        "State": {"Status": "created", "Running": False, "ExitCode": 0, "OOMKilled": False},
        "Mounts": [],
        "NetworkSettings": {"Ports": {}},
    }


def configuration_stdout():
    value = {
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
        "caps": ["0000000000000000"] * 5,
        "ulimits": {"nofile": [256, 256], "core": [0, 0], "fsize": [8388608, 8388608]},
        "environment": dict(x.split("=", 1) for x in r._EFFECTIVE_ENV),
        "workspace_mount": ["rw", "nosuid", "nodev"],
        "temp_mount": ["rw", "nosuid", "nodev", "noexec"],
    }
    return json.dumps(value).encode()


class FakeHandle:
    def __init__(self, driver, identity):
        self.driver, self.identity = driver, identity
        self.stdin_bytes = 0
        self.input_complete = False

    def exchange(self, raw, deadline, stdout_limit, stderr_limit, *, progress=None):
        d = self.driver
        d.events.append("input")
        self.stdin_bytes = len(raw)
        self.input_complete = True
        data = json.loads(raw)
        argv = data["job"]["argv"]
        staged = {
            item["path"]: base64.b64decode(item["data_b64"]).decode()
            for item in data["job"]["files"]
        }
        script = staged.get("probe.py") if argv == [r.INTERPRETER, "-I", "probe.py"] else None
        name = next(
            (
                name
                for name, source, _stdin, _seconds in r._PROBES
                if script is not None
                and (source == script or (name == "input_headroom" and script.startswith(source)))
            ),
            None,
        )
        if name is not None and name == d.failed_probe:
            stdout = b"{}"
        elif name == "configuration":
            stdout = configuration_stdout()
        elif name == "input_headroom":
            value = b'{"source_bytes":4194304,"file_count":64}'
            stdout = value + b" " * (65536 - len(value))
        elif name == "cpu":
            stdout = b'{"throttled":1,"usec":1000}'
        elif name == "memory":
            stdout = b'{"child_exit":-9,"oom_kill":1}'
        elif name == "pids":
            stdout = b'{"limited":true,"current":32,"created":28}'
        elif name == "tmpfs":
            stdout = b'{"/workspace":{"bytes_full":true,"inodes_full":true},"/tmp":{"bytes_full":true,"inodes_full":true}}'
        elif name == "stdin_null":
            assert data["observer_input_b64"] is None
            stdout = b'{"empty":true}'
        elif name == "stdin_observer":
            assert base64.b64decode(data["observer_input_b64"]) == b"probe-input"
            stdout = b'{"exact":true}'
        elif name == "reaping":
            stdout = b'{"reaped":true}'
        elif name == "wall":
            if progress is not None:
                progress.observed = True
            raise r._HostDeadline()
        elif name in ("stdout_overflow", "stderr_overflow"):
            stdout = b""
        else:
            stdout = d.candidate_stdout
            d.candidate_runs += 1
            if d.candidate_error:
                raise r._Failure(d.candidate_error)
        files = {x["path"]: x["data_b64"] for x in data["job"]["files"]}
        artifacts = [
            {"path": path, "data_b64": files[path]}
            for path in data["job"]["collect_paths"]
            if path in files
        ]
        result = {
            "schema_version": 1,
            "protocol": "reviewboundary.isolated/1",
            "status": "completed",
            "error_code": None,
            "claimed_child_return_code": 0,
            "stdout_b64": base64.b64encode(stdout).decode(),
            "stderr_b64": "",
            "artifacts": artifacts,
            "missing_artifacts": [],
        }
        if name is None:
            result["stderr_b64"] = base64.b64encode(d.candidate_stderr).decode()
        if name == "input_headroom":
            result["stderr_b64"] = base64.b64encode(b"x" * 65536).decode()
        if name in ("stdout_overflow", "stderr_overflow") and name != d.failed_probe:
            result.update(status="error", error_code="child_output_overflow")
        value = d.containers[self.identity]
        value["State"].update(Status="exited", Running=False)
        if d.malformed_candidate and name is None:
            wire = b'{"pass":true}'
        else:
            wire = json.dumps(result).encode()
        return r._CommandResult(wire, b"", 0, len(raw))

    def close(self, deadline):
        self.driver.events.append("client_close")


class FakeDriver:
    runtime_kind = "real"  # A dishonest backend label must never mint a real token.

    def __init__(self):
        self.daemon_sha256 = "d" * 64
        self.containers = {}
        self.events = []
        self.calls = []
        self.candidate_runs = 0
        self.candidate_stdout = b'{"pass":true}'
        self.candidate_stderr = b""
        self.candidate_error = None
        self.failed_probe = None
        self.cleanup_failure = False
        self.policy_mutation = None
        self.malformed_candidate = False
        self.count = 0

    def prepare(self, deadline):
        return self.daemon_sha256, r.IMAGE_ID[7:]

    def daemon_identity(self, deadline):
        return self.daemon_sha256

    def command(self, args, deadline, **kwargs):
        self.calls.append(args)
        if args[:2] == ("container", "create"):
            self.count += 1
            identity = format(self.count, "064x")
            name = args[args.index("--name") + 1]
            nonce = args[args.index("--label") + 1].split("=", 1)[1]
            cidfile = Path(args[args.index("--cidfile") + 1])
            cidfile.write_text(identity)
            self.containers[identity] = valid_inspect(name, nonce, identity)
            self.events.append("create")
            return r._CommandResult(identity.encode(), b"", 0)
        if args[:2] == ("container", "wait"):
            return r._CommandResult(b"0\n", b"", 0)
        if args[:2] == ("container", "kill"):
            self.events.append("kill")
            self.containers[args[-1]]["State"].update(Status="exited", Running=False)
            return r._CommandResult(b"", b"", 0)
        if args[:2] == ("container", "rm"):
            self.events.append("remove")
            if self.cleanup_failure:
                return r._CommandResult(b"", b"", 1)
            self.containers.pop(args[-1])
            return r._CommandResult(b"", b"", 0)
        if args[:2] == ("container", "ls"):
            return r._CommandResult(b"", b"", 0)
        raise AssertionError(args)

    def inspect(self, identity, deadline):
        self.events.append("inspect")
        value = self.containers.get(identity)
        if value is None:
            value = next((x for x in self.containers.values() if x["Name"] == "/" + identity), None)
        value = copy.deepcopy(value)
        if value is not None and self.policy_mutation:
            self.policy_mutation(value)
        return value

    def absent(self, identity, deadline):
        return identity not in self.containers

    def attach(self, identity):
        self.events.append("attach")
        self.containers[identity]["State"].update(Status="running", Running=True)
        return FakeHandle(self, identity)


def run_fake(tmp_path, driver=None):
    return r._run_with_driver(
        config(), job(), driver or FakeDriver(), state_root=tmp_path / "state"
    )


def test_full_controller_fake_flow_is_explicitly_synthetic_and_not_live(tmp_path):
    driver = FakeDriver()
    result = run_fake(tmp_path, driver)
    assert result.status == "completed", result.error_code
    assert result.probe.status == "supported"
    assert len(result.probe.checks) == len(r._PROBES)
    assert result.runtime_kind == result.probe.runtime_kind == "synthetic"
    assert result.image_sha256 == result.probe.image_sha256 == r.IMAGE_ID.removeprefix("sha256:")
    assert result.cleanup == "confirmed" and not driver.containers
    assert driver.candidate_runs == 1
    assert result.collected_artifacts[0].data == b"PRIVATE_SOURCE_SENTINEL"
    with pytest.raises(r._OriginError, match="not established") as exc:
        r._require_live_origin(config(), result, result.collected_artifacts[0])
    assert exc.value.code == "not_live"
    with pytest.raises(r._OriginError):
        r._observation_stdout(result)


@pytest.mark.parametrize("failed_probe", [name for name, *_ in r._PROBES])
def test_failed_fresh_control_never_starts_the_candidate(tmp_path, failed_probe):
    driver = FakeDriver()
    driver.failed_probe = failed_probe
    result = run_fake(tmp_path, driver)
    assert result.status == "not_started" and result.job_started is False
    assert result.error_code in ("probe_failed", "probe_timeout")
    assert driver.candidate_runs == 0
    assert not driver.containers


@pytest.mark.parametrize("error", ["output_overflow", "execution_timeout", "transport_error"])
def test_candidate_transport_failure_stops_container_before_client_drain(tmp_path, error):
    driver = FakeDriver()
    driver.candidate_error = error
    result = run_fake(tmp_path, driver)
    assert result.status == "error" and result.error_code == error
    assert result.cleanup == "confirmed" and not driver.containers
    tail = driver.events
    last_kill = max(i for i, event in enumerate(tail) if event == "kill")
    assert tail.index("client_close", last_kill) > last_kill
    assert tail.index("remove", last_kill) > last_kill


def test_cleanup_failure_blocks_next_invocation_without_deleting_unrelated_container(tmp_path):
    driver = FakeDriver()
    driver.cleanup_failure = True
    result = run_fake(tmp_path, driver)
    assert result.error_code == "cleanup_failed" and not result.job_started
    assert len(driver.containers) == 1
    driver.cleanup_failure = False
    result = run_fake(tmp_path, driver)
    assert result.error_code == "recovery_required" and not result.job_started
    assert len(driver.containers) == 1


@pytest.mark.parametrize(
    "mutate",
    [
        lambda v: v["HostConfig"].update(Privileged=True),
        lambda v: v["HostConfig"].update(NetworkMode="host"),
        lambda v: v["HostConfig"].update(MemorySwap=-1),
        lambda v: v["Config"]["Env"].append("HTTP_PROXY=untrusted"),
        lambda v: v["Config"].update(Entrypoint=["/bin/sh"]),
        lambda v: v.update(Mounts=[{"Source": "/host", "Destination": "/workspace"}]),
        lambda v: v["HostConfig"].update(CgroupnsMode="host"),
        lambda v: v["Config"].update(Hostname="unexpected-daemon-hostname"),
        lambda v: v["Config"].update(Healthcheck={"Test": ["CMD", "untrusted"]}),
    ],
)
def test_policy_mismatch_prevents_any_input(tmp_path, mutate):
    driver = FakeDriver()
    driver.policy_mutation = mutate
    result = run_fake(tmp_path, driver)
    assert result.status == "not_started" and result.job_started is False
    assert "input" not in driver.events
    assert not driver.containers


def test_forged_pass_json_is_not_a_protocol_or_verification_authority(tmp_path):
    driver = FakeDriver()
    driver.malformed_candidate = True
    result = run_fake(tmp_path, driver)
    assert result.error_code == "malformed_result" and result.verification == "not_established"
    assert result.cleanup == "confirmed"


def test_default_report_contains_no_source_streams_environment_or_artifact_bytes(tmp_path):
    driver = FakeDriver()
    driver.candidate_stdout = b"PRIVATE_STDOUT_SENTINEL"
    result = run_fake(tmp_path, driver)
    text = json.dumps(result.to_report())
    assert "PRIVATE_SOURCE_SENTINEL" not in text and "PRIVATE_STDOUT_SENTINEL" not in text
    assert "GPG_KEY" not in text and "/trusted/context" not in text
    assert result.verification == result.publication == "not_established"
    assert (
        result.artifact_manifest[0].sha256 == hashlib.sha256(b"PRIVATE_SOURCE_SENTINEL").hexdigest()
    )


@pytest.mark.parametrize("version", [True, 1.0, "1", 2])
def test_exact_config_integer_version(version):
    with pytest.raises(ValidationError):
        r.IsolationConfig(**(config().model_dump() | {"schema_version": version}))


@pytest.mark.parametrize(
    "extra", ["stdin", "env", "docker_flags", "gate_receipt", "driver", "state_root"]
)
def test_config_has_no_override_or_authority_fields(extra):
    with pytest.raises(ValidationError):
        r.IsolationConfig(**(config().model_dump() | {extra: "untrusted"}))


def test_fixed_docker_argv_has_no_shell_pull_mount_or_env_inheritance(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "NEVER_SERIALIZE")
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted")
    driver = r._DockerDriver(config(), Path("/private/client"))
    driver.endpoint = "unix:///private/task.sock"
    args = r._create_arguments("reviewboundary-" + "a" * 32, "a" * 32, Path("/private/cid"))
    argv = driver._argv(args)
    assert argv[0] == "/trusted/docker" and "--pull=never" in argv
    assert "--host" in argv and "--context" not in argv
    assert "--mount" not in argv and "--volume" not in argv
    assert "NEVER_SERIALIZE" not in repr((argv, driver.environment))
    assert driver.environment == {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    for forbidden in [("login",), ("pull", "image"), ("build", "."), ("container", "prune")]:
        with pytest.raises(r._Failure):
            driver._argv(forbidden)


def test_journal_uses_stable_flock_inode_and_retains_uncertain_intent(tmp_path):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    first = r._Journal(root, "a" * 64)
    inode = os.fstat(first.lock).st_ino
    with pytest.raises(r._Failure) as exc:
        r._Journal(root, "a" * 64)
    assert exc.value.code == "lock_busy"
    first.store("creating", name="one-exact-owned-name", nonce="a" * 32)
    first.close()
    with pytest.raises(r._Failure) as exc:
        r._Journal(root, "a" * 64)
    assert exc.value.code == "recovery_required"
    assert (root / ("a" * 64) / "lock").stat().st_ino == inode


def test_replaced_journal_node_is_not_overwritten_or_removed(tmp_path):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    journal = r._Journal(root, "b" * 64)
    path = journal.path / "journal.json"
    path.rename(journal.path / "original-retained.json")
    path.write_text("REPLACEMENT")
    with pytest.raises(r._Failure):
        journal.store("idle")
    journal.close()
    assert path.read_text() == "REPLACEMENT"
    assert (journal.path / "original-retained.json").exists()


def test_descriptor_file_helpers_refuse_symlinks_fifos_and_existing_outputs(tmp_path):
    target = tmp_path / "target"
    target.write_text("KEEP")
    alias = tmp_path / "alias"
    alias.symlink_to(target)
    with pytest.raises(OSError):
        r._read_local(alias, 16)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError):
        r._read_local(fifo, 16)
    with pytest.raises(FileExistsError):
        r._write_exclusive(target, b"REPLACE", 16)
    assert target.read_text() == "KEEP" and alias.is_symlink()


def test_driver_command_uses_mocked_transport_and_fixed_byte_deadline_bounds(monkeypatch):
    seen = []

    class Transport:
        def __init__(self, argv, environment):
            seen.append((argv, environment))

        def exchange(self, raw, deadline, stdout_limit, stderr_limit=65536):
            seen.append((raw, deadline, stdout_limit, stderr_limit))
            return r._CommandResult(b"{}", b"", 0)

        def close(self, deadline):
            seen.append("closed")

    monkeypatch.setattr(r, "_Process", Transport)
    driver = r._DockerDriver(config(), Path("/private/client"))
    driver.endpoint = "unix:///private/task.sock"
    assert driver.command(("info",), 123.0, limit=1024).stdout == b"{}"
    assert seen[1] == (b"", 123.0, 1024, 65536) and seen[-1] == "closed"


def test_process_concurrent_io_and_overflow_use_mocked_popen_pipes(monkeypatch):
    class Popen:
        def __init__(self, *args, **kwargs):
            self.input_read, input_write = os.pipe()
            output_read, output_write = os.pipe()
            error_read, error_write = os.pipe()
            os.write(output_write, b"observed")
            os.close(output_write)
            os.close(error_write)
            self.stdin = os.fdopen(input_write, "wb", buffering=0)
            self.stdout = os.fdopen(output_read, "rb", buffering=0)
            self.stderr = os.fdopen(error_read, "rb", buffering=0)
            self.pid = -1

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(r.subprocess, "Popen", Popen)
    process = r._Process(["/trusted/docker"], {})
    result = process.exchange(b"input", r.time.monotonic() + 1, 64)
    assert result.stdout == b"observed" and result.stdin_bytes == 5
    assert os.read(process.process.input_read, 5) == b"input"
    os.close(process.process.input_read)
    process.close(r.time.monotonic() + 1)
    process = r._Process(["/trusted/docker"], {})
    with pytest.raises(r._Failure) as exc:
        process.exchange(b"", r.time.monotonic() + 1, 2)
    assert exc.value.code == "output_overflow"
    os.close(process.process.input_read)
    process.close(r.time.monotonic() + 1)


def test_cli_dry_run_performs_no_runtime_or_output_action(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text(config().model_dump_json())
    job_path = tmp_path / "job.json"
    job_path.write_text(job().model_dump_json())
    output = tmp_path / "new.json"
    monkeypatch.setattr(r, "run_isolated_job", lambda *args: pytest.fail("runtime action"))
    monkeypatch.setattr(r, "probe_isolation", lambda *args: pytest.fail("runtime action"))
    args = SimpleNamespace(
        config=config_path, job=job_path, output=output, dry_run=True, binding=None
    )
    assert r.isolated_run_command(args) == 0
    assert r.isolation_probe_command(args) == 0
    assert not output.exists()


def test_saved_and_model_copied_synthetic_reports_cannot_gain_origin(tmp_path):
    result = run_fake(tmp_path)
    loaded = r.IsolatedExecution.model_validate_json(json.dumps(result.to_report()))
    for item in (loaded, result.model_copy(), result.model_copy(update={"runtime_kind": "real"})):
        with pytest.raises(r._OriginError) as exc:
            r._observation_stdout(item)
        assert exc.value.code == "not_live"


def test_command_stream_properties_are_bounded_untrusted_data_only(tmp_path):
    driver = FakeDriver()
    driver.candidate_stdout = b"a" * 65536
    driver.candidate_stderr = b"b" * 65536
    result = run_fake(tmp_path, driver)
    assert result.command_stdout == driver.candidate_stdout
    assert result.command_stderr == driver.candidate_stderr
    assert result.runtime_kind == "synthetic" and result.verification == "not_established"
    text = json.dumps(result.to_report())
    assert "command_stdout" not in text and "command_stderr" not in text
    assert "a" * 1024 not in text and "b" * 1024 not in text
    assert "command_stdout" not in repr(result) and "command_stderr" not in repr(result)
    with pytest.raises(r._OriginError):
        r._observation_stdout(result)


def test_missing_or_malformed_streams_stay_unavailable_data(tmp_path):
    driver = FakeDriver()
    driver.malformed_candidate = True
    result = run_fake(tmp_path, driver)
    assert result.command_stdout == result.command_stderr == b""


def test_malformed_created_id_recovers_only_exact_owned_name(tmp_path):
    driver = FakeDriver()
    original = driver.command

    def command(args, deadline, **kwargs):
        result = original(args, deadline, **kwargs)
        if args[:2] == ("container", "create"):
            return r._CommandResult(b"malformed-id", b"", 0)
        return result

    driver.command = command
    result = run_fake(tmp_path, driver)
    assert result.job_started is False and not driver.containers
    removed = [args[-1] for args in driver.calls if args[:2] == ("container", "rm")]
    assert removed and all(len(identity) == 64 for identity in removed)
    assert not any("malformed-id" in args for args in driver.calls)


def test_hostname_and_environment_are_fixed_code_owned_policy():
    args = r._create_arguments("reviewboundary-" + "f" * 32, "f" * 32, Path("/private/cid"))
    assert args[args.index("--hostname") + 1] == "review-boundary"
    assert "HOSTNAME=review-boundary" in args
    assert "HOSTNAME=review-boundary" in r._EFFECTIVE_ENV
    assert r._IMAGE_ENV == (
        "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG=C.UTF-8",
        "GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D",
        "PYTHON_VERSION=3.11.18",
        "PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290",
    )
    assert r._digest({"Env": list(r._IMAGE_ENV), "Cmd": ["python3"]}) == r.IMAGE_CONFIG_SHA256


@pytest.mark.parametrize("damaged", [b"", b'{"state":', b'{"schema_version":1,"state":"created"}'])
def test_existing_empty_torn_or_nonidle_journal_never_admits_a_job(tmp_path, damaged):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    journal = r._Journal(root, "e" * 64)
    path = journal.path / "journal.json"
    inode = os.fstat(journal.lock).st_ino
    journal.close()
    path.write_bytes(damaged)
    with pytest.raises(r._Failure) as exc:
        r._Journal(root, "e" * 64)
    assert exc.value.code == "recovery_required"
    assert path.read_bytes() == damaged
    assert (path.parent / "lock").stat().st_ino == inode


@pytest.mark.parametrize("failure", ["write", "file_sync", "directory_sync"])
def test_atomic_journal_failure_retains_uncertainty_and_stable_lock(tmp_path, monkeypatch, failure):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    journal = r._Journal(root, "c" * 64)
    journal.store(
        "created", nonce="a" * 32, name="reviewboundary-" + "a" * 32, container_id="b" * 64
    )
    path = journal.path / "journal.json"
    previous = path.read_bytes()
    inode = os.fstat(journal.lock).st_ino
    write, sync = r.os.write, r.os.fsync

    def bad_write(fd, data):
        if failure == "write":
            raise OSError("injected write failure")
        return write(fd, data)

    def bad_sync(fd):
        directory = r.stat.S_ISDIR(os.fstat(fd).st_mode)
        if (failure == "file_sync" and not directory) or (
            failure == "directory_sync" and directory
        ):
            raise OSError("injected fsync failure")
        return sync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(r.os, "write", bad_write)
        patch.setattr(r.os, "fsync", bad_sync)
        with pytest.raises(OSError):
            journal.store(
                "blocked", nonce="a" * 32, name="reviewboundary-" + "a" * 32, container_id="b" * 64
            )
    journal.close()
    assert path.read_bytes() == previous or json.loads(path.read_bytes())["state"] == "blocked"
    with pytest.raises(r._Failure) as exc:
        r._Journal(root, "c" * 64)
    assert exc.value.code == "recovery_required"
    assert (path.parent / "lock").stat().st_ino == inode


def test_pending_atomic_transition_blocks_even_if_previous_journal_was_idle(tmp_path, monkeypatch):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    journal = r._Journal(root, "f" * 64)
    old = (journal.path / "journal.json").read_bytes()
    with monkeypatch.context() as patch:
        patch.setattr(r.os, "write", lambda *args: (_ for _ in ()).throw(OSError("injected")))
        with pytest.raises(OSError):
            journal.store("creating", nonce="a" * 32)
    journal.close()
    assert (root / ("f" * 64) / "journal.json").read_bytes() == old
    with pytest.raises(r._Failure):
        r._Journal(root, "f" * 64)


def test_absent_container_client_close_failure_cannot_commit_idle(tmp_path):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    journal = r._Journal(root, "a" * 64)
    nonce, identity = "b" * 32, "c" * 64
    journal.store("created", nonce=nonce, container_id=identity)
    cidfile = tmp_path / "owned.cid"
    cidfile.write_text(identity)

    class Handle:
        def close(self, deadline):
            raise r._Failure("cleanup_failed")

    driver = FakeDriver()
    assert not r._cleanup(
        driver,
        journal,
        "reviewboundary-" + nonce,
        nonce,
        identity,
        Handle(),
        r.time.monotonic() + 1,
        cidfile=cidfile,
        creation_confirmed=True,
    )
    assert journal.data["state"] == "blocked" and cidfile.exists()
    journal.close()
    with pytest.raises(r._Failure):
        r._Journal(root, "a" * 64)


def test_unknown_create_stays_blocked_after_momentary_absence(tmp_path):
    root = tmp_path / "daemons"
    root.mkdir(mode=0o700)
    journal = r._Journal(root, "a" * 64)
    nonce = "b" * 32
    journal.store("creating", nonce=nonce, name="reviewboundary-" + nonce)
    driver = FakeDriver()
    original = driver.command

    def command(args, deadline, **kwargs):
        result = original(args, deadline, **kwargs)
        if args[:2] == ("container", "ls"):
            driver.containers["c" * 64] = valid_inspect("reviewboundary-" + nonce, nonce, "c" * 64)
        return result

    driver.command = command
    assert not r._cleanup(
        driver,
        journal,
        "reviewboundary-" + nonce,
        nonce,
        None,
        None,
        r.time.monotonic() + 1,
        cidfile=tmp_path / "unknown.cid",
        creation_confirmed=False,
    )
    assert journal.data["state"] == "blocked" and "c" * 64 in driver.containers
    assert not any(args[:2] == ("container", "rm") for args in driver.calls)
    journal.close()


def test_transient_state_has_no_256_invocation_lifetime_exhaustion(tmp_path):
    root = tmp_path / "state"
    for _ in range(260):
        context = r._RunContext(config(), r.time.monotonic() + 1, FakeDriver(), root)
        assert context.close()
    daemon = root / "daemons" / ("d" * 64)
    assert {x.name for x in daemon.iterdir()} == {"lock", "journal.json"}
    assert {x.name for x in (root / "client").iterdir()} == {"config.json"}


def test_every_internal_probe_is_an_exact_valid_staged_job():
    for name, script, _stdin, _seconds in r._PROBES:
        value = r._control_job(name, script)
        assert value.argv == (r.INTERPRETER, "-I", "probe.py")
        assert all("\n" not in arg for arg in value.argv)
        r.parse_isolated_job(value.model_dump_json().encode())
    headroom = r._control_job("input_headroom", r._HEADROOM_PROBE)
    assert len(headroom.files) == 64
    assert sum(len(x.content.encode()) for x in headroom.files) == 4194304


@pytest.mark.parametrize(
    "host,delivered,progress,expected",
    [
        (False, False, False, False),
        (False, True, True, False),
        (True, False, True, False),
        (True, True, False, False),
        (True, True, True, True),
    ],
)
def test_wall_predicate_requires_all_synthetic_controller_evidence(
    host, delivered, progress, expected
):
    outcome = r._ContainerOutcome(
        "execution_timeout",
        True,
        None,
        (
            r.CheckResult(check_id="before_start", status="passed"),
            r.CheckResult(check_id="after_start", status="passed"),
        ),
        r.DriverFacts(),
        "confirmed",
        host,
        delivered,
        progress,
    )
    assert r._probe_value("wall", outcome) is expected


@pytest.mark.parametrize(
    "table,expected",
    [
        (b"PID PPID COMMAND\n100 1 docker-init\n101 100 python3.11\n102 101 python3.11\n", True),
        (b"PID PPID COMMAND\n100 1 docker-init\n101 100 python3.11\n102 1 python3.11\n", False),
        (b"PID PPID COMMAND\n100 1 docker-init\n101 100 python3.11\n102 101 shell\n", False),
        (b"PID PPID COMMAND\n100 1 docker-init\n100 100 python3.11\n", False),
    ],
)
def test_fixed_top_progress_requires_expected_owned_process_ancestry(table, expected):
    class Driver:
        def command(self, args, deadline, **kwargs):
            assert args == ("container", "top", "a" * 64, "-eo", "pid,ppid,comm")
            assert kwargs["limit"] == 4096
            return r._CommandResult(table, b"", 0)

    progress = r._WallProgress(Driver(), "a" * 64)
    progress.observe(r.time.monotonic() + 1)
    assert progress.observed is expected


def test_whole_container_oom_alone_never_proves_child_memory_limit():
    outcome = r._ContainerOutcome(
        "container_oom",
        True,
        None,
        (
            r.CheckResult(check_id="before_start", status="passed"),
            r.CheckResult(check_id="after_start", status="passed"),
        ),
        r.DriverFacts(daemon_oom_killed=True),
        "confirmed",
    )
    assert r._probe_value("memory", outcome) is False


def test_policy_fingerprint_binds_create_controls_progress_and_comparison():
    manifest = r._POLICY_MANIFEST
    assert r.POLICY_SHA256 == r._digest(manifest)
    assert manifest["progress_template"][-1] == "pid,ppid,comm"
    assert [x["id"] for x in manifest["probes"]] == [x[0] for x in r._PROBES]
    changed = dict(manifest, comparison_version="changed")
    assert r._digest(changed) != r.POLICY_SHA256
    assert "--pull=never" in manifest["create_template"]
    assert manifest["image_bindings"] == {
        "creation_reference": EXPECTED_IMAGE_REFERENCE,
        "container_image": EXPECTED_INDEX_ID,
        "config_image": EXPECTED_IMAGE_REFERENCE,
        "selected_manifest_digest": r.IMAGE_ID,
        "selected_manifest_media_type": "application/vnd.oci.image.manifest.v1+json",
        "selected_manifest_platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
    }
    changed = copy.deepcopy(manifest)
    changed["image_bindings"]["container_image"] = r.IMAGE_ID
    assert r._digest(changed) != r.POLICY_SHA256


def test_bound_observation_rejects_foreign_or_synthetic_proofs(tmp_path):
    result = run_fake(tmp_path)
    with pytest.raises(r._OriginError):
        r._require_bound_observation(config(), result, object(), b"input")
    with pytest.raises(r._OriginError):
        r._observation_stdout(result.model_copy())


def test_cancel_during_create_cleans_exact_name_and_keeps_uncertainty_blocked(tmp_path):
    driver = FakeDriver()
    original = driver.command

    def interrupted(args, deadline, **kwargs):
        result = original(args, deadline, **kwargs)
        if args[:2] == ("container", "create"):
            raise KeyboardInterrupt()
        return result

    driver.command = interrupted
    with pytest.raises(KeyboardInterrupt):
        run_fake(tmp_path, driver)
    assert not driver.containers and driver.count == 1
    driver.command = original
    result = run_fake(tmp_path, driver)
    assert result.error_code == "recovery_required" and driver.count == 1


def test_daemon_identity_change_never_sends_candidate_or_removes_foreign_daemon_state(tmp_path):
    driver = FakeDriver()
    driver.daemon_identity = lambda deadline: "e" * 64
    result = run_fake(tmp_path, driver)
    assert result.job_started is False and "input" not in driver.events
    assert result.error_code == "cleanup_failed"
    assert not any(args[:2] == ("container", "rm") for args in driver.calls)


@pytest.mark.parametrize(
    "host",
    [
        "tcp://127.0.0.1:2375",
        "ssh://operator@machine",
        "unix://machine/socket",
        "unix:///socket?override=1",
    ],
)
def test_prepare_rejects_remote_or_ambiguous_endpoints_without_lifecycle(tmp_path, host):
    executable = tmp_path / "docker"
    executable.write_text("never executed")
    executable.chmod(0o700)
    cfg = config().model_copy(update={"docker_executable": str(executable)})
    driver = r._DockerDriver(cfg, tmp_path)
    calls = []

    def command(args, deadline, **kwargs):
        calls.append(args)
        return r._CommandResult(json.dumps({"Host": host, "SkipTLSVerify": False}).encode(), b"", 0)

    driver.command = command
    with pytest.raises(r._Failure) as exc:
        driver.prepare(r.time.monotonic() + 1)
    assert exc.value.code == "remote_endpoint" and len(calls) == 1


@pytest.mark.parametrize("alter", ["missing", "index_id", "descriptor_index", "env", "platform"])
def test_prepare_rejects_unavailable_or_mismatched_pinned_image(tmp_path, alter):
    executable = tmp_path / "docker"
    executable.write_text("never executed")
    executable.chmod(0o700)
    cfg = config().model_copy(update={"docker_executable": str(executable)})
    driver = r._DockerDriver(cfg, tmp_path)
    image = {
        "Id": r.IMAGE_ID,
        "Descriptor": {
            "digest": r.IMAGE_ID,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "platform": {"architecture": "arm64", "os": "linux", "variant": "v8"},
        },
        "Os": "linux",
        "Architecture": "arm64",
        "Config": {"Env": list(r._IMAGE_ENV), "Cmd": ["python3"]},
    }
    if alter == "index_id":
        image["Id"] = EXPECTED_INDEX_ID
    if alter == "descriptor_index":
        image["Descriptor"]["digest"] = EXPECTED_INDEX_ID
    if alter == "env":
        image["Config"]["Env"].append("HTTP_PROXY=untrusted")
    if alter == "platform":
        image["Descriptor"]["platform"]["architecture"] = "amd64"

    def command(args, deadline, **kwargs):
        if args[:2] == ("context", "inspect"):
            value = {"Host": "unix:///private/task.sock", "SkipTLSVerify": False}
        elif args[:1] == ("info",):
            value = {
                "ID": "fixed-daemon",
                "ServerVersion": "29.5.2",
                "OSType": "linux",
                "Architecture": "arm64",
                "KernelVersion": "fixed",
                "CgroupVersion": "2",
                "CgroupDriver": "cgroupfs",
                "SecurityOptions": ["name=seccomp,profile=builtin"],
            }
        else:
            assert args[:2] == ("image", "inspect")
            if alter == "missing":
                return r._CommandResult(b"", b"", 1)
            value = image
        return r._CommandResult(json.dumps(value).encode(), b"", 0)

    driver.command = command
    with pytest.raises(r._Failure) as exc:
        driver.prepare(r.time.monotonic() + 1)
    assert exc.value.code == ("image_unavailable" if alter == "missing" else "image_mismatch")


@pytest.mark.parametrize("binding", [None, "sum-echo-v1"])
def test_cli_output_roundtrips_typed_invocation_without_mutating_execution(
    tmp_path, monkeypatch, binding
):
    from review_boundary.isolated_verifier import IsolatedInvocationReport

    result = run_fake(tmp_path)
    before = result.to_report()
    cfg = tmp_path / "config.json"
    cfg.write_text(config().model_dump_json())
    source = tmp_path / "job.json"
    source.write_text(job().model_dump_json())
    output = tmp_path / "output.json"
    monkeypatch.setattr(r, "run_isolated_job", lambda *args: result)
    args = SimpleNamespace(config=cfg, job=source, output=output, dry_run=False, binding=binding)
    assert r.isolated_run_command(args) == (0 if binding is None else 1)
    loaded = IsolatedInvocationReport.model_validate_json(output.read_bytes())
    assert loaded.report_family == "isolated_invocation"
    assert loaded.execution.to_report() == before == result.to_report()
    assert (loaded.verification_result is None) == (binding is None)
    with pytest.raises(r._OriginError):
        r._observation_stdout(loaded.execution)


def test_pid_policy_uses_valid_implicit_private_namespace_selection():
    args = r._create_arguments("reviewboundary-" + "a" * 32, "a" * 32, Path("/private/cid"))
    assert "--pid" not in args
    assert not any(arg.startswith("--pid=") for arg in args)
    value = valid_inspect("reviewboundary-" + "a" * 32, "a" * 32, "b" * 64)
    assert value["HostConfig"]["PidMode"] == ""
    r._validate_container(value, "reviewboundary-" + "a" * 32, "a" * 32, "b" * 64)
    assert value["HostConfig"]["Init"] is True
    assert value["HostConfig"]["PidsLimit"] == 32


@pytest.mark.parametrize("pid_mode", ["host", "container:" + "b" * 64, "private", None, 0, False])
def test_pid_normalization_rejects_shared_invalid_or_unknown_modes_before_input(tmp_path, pid_mode):
    driver = FakeDriver()
    driver.policy_mutation = lambda value: value["HostConfig"].update(PidMode=pid_mode)
    result = run_fake(tmp_path, driver)
    assert result.status == "not_started" and result.job_started is False
    assert "input" not in driver.events and driver.candidate_runs == 0
    assert not driver.containers


def test_pid_normalization_rejects_missing_mode():
    value = valid_inspect("reviewboundary-" + "a" * 32, "a" * 32, "b" * 64)
    del value["HostConfig"]["PidMode"]
    with pytest.raises(r._Failure) as exc:
        r._validate_container(value, "reviewboundary-" + "a" * 32, "a" * 32, "b" * 64)
    assert exc.value.code == "policy_mismatch"


def test_image_roles_use_exact_immutable_index_reference_and_selected_manifest():
    name, nonce, identity = "reviewboundary-" + "a" * 32, "a" * 32, "b" * 64
    args = r._create_arguments(name, nonce, Path("/private/cid"))
    assert args[-4] == EXPECTED_IMAGE_REFERENCE
    assert args[args.index("--platform") + 1] == "linux/arm64/v8"
    assert "--pull=never" in args
    assert r.IMAGE_ID not in args and EXPECTED_INDEX_ID not in args
    value = valid_inspect(name, nonce, identity)
    assert r._owned(value, name, nonce, identity) == identity
    r._validate_container(value, name, nonce, identity)


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda v: v.update(Image=r.IMAGE_ID), id="container-selected-manifest"),
        pytest.param(lambda v: v.update(Image="sha256:" + "0" * 64), id="container-foreign"),
        pytest.param(lambda v: v.pop("Image"), id="container-missing"),
        pytest.param(lambda v: v["Config"].update(Image=r.IMAGE_ID), id="config-selected-manifest"),
        pytest.param(lambda v: v["Config"].update(Image=EXPECTED_INDEX_ID), id="config-bare-index"),
        pytest.param(
            lambda v: v["Config"].update(Image="python@" + EXPECTED_INDEX_ID),
            id="config-familiar-alias",
        ),
        pytest.param(
            lambda v: v["Config"].update(
                Image="index.docker.io/library/python@" + EXPECTED_INDEX_ID
            ),
            id="config-registry-alias",
        ),
        pytest.param(lambda v: v["Config"].update(Image="python:3.11"), id="config-tag"),
        pytest.param(lambda v: v["Config"].pop("Image"), id="config-image-missing"),
        pytest.param(lambda v: v.update(Config=None), id="config-null"),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].update(digest=EXPECTED_INDEX_ID),
            id="manifest-index",
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].update(digest="sha256:" + "0" * 64),
            id="manifest-foreign",
        ),
        pytest.param(lambda v: v.pop("ImageManifestDescriptor"), id="manifest-missing"),
        pytest.param(lambda v: v.update(ImageManifestDescriptor=None), id="manifest-null"),
        pytest.param(lambda v: v.update(ImageManifestDescriptor=r.IMAGE_ID), id="manifest-string"),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].pop("digest"), id="manifest-digest-missing"
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].update(
                mediaType="application/vnd.oci.image.index.v1+json"
            ),
            id="manifest-index-media-type",
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].pop("mediaType"),
            id="manifest-media-type-missing",
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].pop("platform"), id="manifest-platform-missing"
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"].update(platform=None),
            id="manifest-platform-null",
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"]["platform"].update(architecture="amd64"),
            id="manifest-platform-architecture",
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"]["platform"].pop("variant"),
            id="manifest-variant-missing",
        ),
        pytest.param(
            lambda v: v["ImageManifestDescriptor"]["platform"].update(variant="v9"),
            id="manifest-variant-alternate",
        ),
    ],
)
def test_image_role_mismatch_blocks_input_and_cannot_authorize_cleanup(tmp_path, mutate):
    driver = FakeDriver()
    driver.policy_mutation = mutate
    result = run_fake(tmp_path, driver)
    assert result.status == "not_started" and result.job_started is False
    assert result.error_code == "cleanup_failed" and result.cleanup == "failed"
    assert all(event not in driver.events for event in ("attach", "input", "kill", "remove"))
    assert driver.candidate_runs == 0 and len(driver.containers) == driver.count == 1
    following = run_fake(tmp_path, driver)
    assert following.error_code == "recovery_required" and following.job_started is False
    assert len(driver.containers) == driver.count == 1


@pytest.mark.parametrize("alter", ["identity", "name", "nonce"])
def test_image_roles_still_require_exact_container_ownership(alter):
    name, nonce, identity = "reviewboundary-" + "a" * 32, "a" * 32, "b" * 64
    value = valid_inspect(name, nonce, identity)
    if alter == "identity":
        value["Id"] = "c" * 64
    elif alter == "name":
        value["Name"] = "/reviewboundary-" + "d" * 32
    else:
        value["Config"]["Labels"]["reviewboundary.owner"] = "e" * 32
    with pytest.raises(r._Failure) as exc:
        r._owned(value, name, nonce, identity)
    assert exc.value.code == "ownership_mismatch"


def test_tmpfs_serialization_explicitly_enables_workspace_exec_and_keeps_temp_noexec():
    args = r._create_arguments("reviewboundary-" + "a" * 32, "a" * 32, Path("/private/cid"))
    mounts = dict(
        args[index + 1].split(":", 1)
        for index, argument in enumerate(args)
        if argument == "--tmpfs"
    )
    assert set(mounts) == {"/workspace", "/tmp"}
    workspace, temp = (set(mounts[path].split(",")) for path in ("/workspace", "/tmp"))
    assert {"rw", "exec", "nosuid", "nodev"} <= workspace
    assert "noexec" not in workspace
    assert {"rw", "noexec", "nosuid", "nodev"} <= temp
    assert "exec" not in temp
    policy_mounts = dict(
        r._POLICY_MANIFEST["create_template"][index + 1].split(":", 1)
        for index, argument in enumerate(r._POLICY_MANIFEST["create_template"])
        if argument == "--tmpfs"
    )
    assert mounts == policy_mounts == r._POLICY_MANIFEST["tmpfs"]


@pytest.mark.parametrize("mount", ["workspace_mount", "temp_mount"])
def test_tmpfs_effective_noexec_policy_still_rejects_mismatches(tmp_path, monkeypatch, mount):
    value = json.loads(configuration_stdout())
    if mount == "workspace_mount":
        value[mount].append("noexec")
    else:
        value[mount].remove("noexec")
    wire = json.dumps(value).encode()
    monkeypatch.setattr(__name__ + ".configuration_stdout", lambda: wire)
    driver = FakeDriver()
    result = run_fake(tmp_path, driver)
    assert result.probe.checks[0].check_id == "configuration"
    assert result.probe.checks[0].status == "failed"
    assert result.error_code == "probe_failed" and result.job_started is False
    assert driver.candidate_runs == 0 and driver.count == 1
    assert result.cleanup == "not_needed" and not driver.containers
    assert driver.events.count("remove") == 1
