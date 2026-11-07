# Isolated command execution

This opt-in mode runs explicitly supplied files and commands in a fixed local Docker container. It is a command primitive. The existing repository and action-boundary reviewers still use their original virtual tools. A shell-capable model reviewer is a separate integration.

Every invocation checks the selected local runtime, runs a complete fresh set of harmless controls, and validates the actual container policy before sending job bytes. A missing, failed or late control stops the job. Saved probe reports cannot bypass this check. Pure and mocked tests check controller behavior; actual runtime enforcement requires the real local probes. VM host-sharing assumptions remain explicitly separate.

The initial profile is the pinned official Python 3.11 image for `linux/arm64/v8`. It must already be staged locally. The controller never pulls or builds an image, changes your Docker context, forwards API credentials, mounts a host directory, or enables container networking. Missing images or unsupported runtime options produce an explicit unsupported result.

## Operator configuration

Use an absolute trusted Docker executable and an explicit existing local context store. Example `isolation-config.json`:

```json
{
  "schema_version": 1,
  "policy": "isolated-command-v1",
  "docker_executable": "/usr/bin/docker",
  "context_config_directory": "/absolute/path/to/task-docker-config",
  "context_name": "review-boundary-eval",
  "image_profile": "python311-arm64-v1"
}
```

Use your installed executable's absolute path. The selected context must resolve to a local Unix socket. Only the fixed approved image/profile is supported; configuration cannot add Docker flags, environment values, mounts, callbacks or larger limits. The requested index digest and selected platform image identity are checked separately.

Creation uses the exact pinned index reference with the explicit platform. Container inspection must bind `Image` to that index, `Config.Image` to the full immutable reference, and `ImageManifestDescriptor` to the selected manifest digest, media type and exact approved platform. Reports retain the selected manifest identity in `image_sha256`. These distinct bindings require real local validation; missing or different metadata stops the job before input is sent.

Validate arguments without running a container or creating a report:

```sh
review-boundary isolation-probe --config isolation-config.json --output new-probe.json --dry-run
```

Run the complete harmless local capability check:

```sh
review-boundary isolation-probe --config isolation-config.json --output new-probe.json
```

This includes actual policy inspections and bounded CPU, memory, process, tmpfs, output, stdin, reaping and wall-time controls, plus staging 4 MiB of input and collecting the maximum bounded outputs. The wall control requires observed child progress and a distinct host deadline; a container timeout claim or unrelated OOM cannot pass a resource check. A successful report describes that invocation; the next job must run its own fresh check. It does not certify escape resistance.

## Supply a bounded job

A job is data. It contains an argv array, explicit UTF-8 files, and up to four paths to collect. There is no shell expansion or directory copy. Ordinary child stdin is closed.

```json
{
  "schema_version": 1,
  "argv": ["/usr/local/bin/python3.11", "-I", "-c", "print('ready')"],
  "files": [],
  "collect_paths": []
}
```

```sh
review-boundary isolated-run --config isolation-config.json --job job.json --output new-execution.json
```

Files stay in container tmpfs. Bounds are 64 files, 64 KiB per file and 4 MiB total; four collected files, 64 KiB each; and 64 KiB for each command output stream. Canonical relative paths are required. Traversal, symlinks, `.git`, dotenv paths, duplicate paths and conflicting ancestor paths are refused. The controller does not copy git history, dependencies, hidden tests or reference fixes automatically.

The fixed container hostname and `HOSTNAME` environment value are `review-boundary`; the complete effective environment is checked rather than inherited from the host. The fixed policy uses a nonroot user, read-only root, no capabilities, no-new-privileges, required seccomp, private namespaces, network none, 0.5 CPU, 256 MiB memory with no swap, and a 32-process cap. Workspace tmpfs is 16 MiB; temporary tmpfs is 8 MiB. The complete probe budget is 30 seconds, the command phase is 30 seconds, and emergency cleanup has five additional seconds. An incomplete check fails closed rather than increasing limits.

One controller job runs per daemon. The durable journal uses an atomic bounded replacement under a stable lock; an existing empty, missing or damaged record requires recovery. Successful runs retire only their registered private transient files, so ordinary use has no lifetime invocation cap. Creation intent and exact container ownership are recorded before creation. Cleanup removes only that exact owned container and confirms absence. Uncertain cleanup retains its recovery record and blocks another job on the daemon. An operator must inspect the retained state before recovery. The controller never prunes containers or automatically removes partial report files.

## Optional plumbing calibration

`--binding sum-echo-v1` checks one narrow behavior of an originating collected `candidate.py` artifact. The original job must complete and collect that file. Its contents must be valid UTF-8. For example, the original job can stage the file and print a readiness message without executing it.

The outside controller chooses a fresh public nonce and three small integer pairs. A new isolated invocation runs only the submitted `candidate.py` using the approved absolute Python interpreter with `-I`. It receives those pairs through the observer-owned input channel and must return exactly one JSON object with the same nonce and three integer sums. Expected sums stay in the host controller.

Results distinguish `established_pass`, `established_fail` and `not_established`. A complete, well-formed wrong response fails this calibration. Malformed output, an infrastructure failure or uncertain cleanup remains unestablished. Candidate pass flags, pytest output, saved execution JSON and copied model objects cannot authorize a live verdict. The nonce correlates the response; it does not establish authenticity or general correctness.

This is original plumbing calibration, not a new vulnerability source, model-security score or public benchmark result. No arbitrary uploaded observer, callable or reference implementation is supported.

## Reports and limits

`isolated-run` writes a closed version-1 `isolated_invocation` envelope with `execution` and a nullable `verification_result`. The separate version-1 execution record distinguishes host driver facts, fresh probe and inspection results, untrusted container claims, artifact counts/digests and cleanup. Default reports omit raw command arguments, file contents, streams, host environment, daemon stderr and calibration inputs. Trusted Python callers can access `collected_artifacts`, `command_stdout` and `command_stderr` as bounded untrusted data in the live result object. Those properties are excluded from default reports and do not authorize a verdict. Reloading a saved report does not restore live authority.

Container framing, claimed child exits and every returned byte remain untrusted. Completion alone does not establish a correct review. Source admission, independent adjudication, public ranking, provider spending and the existing report/scoring versions are unchanged.
