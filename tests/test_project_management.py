"""Meaningful positive and single-field negative management contract checks."""

import importlib.util
import io
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "project_management", ROOT / "scripts/check_project_management.py"
)
management = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(management)
NOW = datetime(2026, 11, 7, 20, tzinfo=UTC)
UNSUPPORTED_DEPENDENCY_URLS = (
    "http://github.com/other/repo/issues/5",
    "github.com/other/repo/issues/5",
    "HTTPS://github.com/other/repo/issues/5",
    "https://github.com/other/repo/pull/5",
    f"http://github.com/{management.REPOSITORY}/issues/11",
    f"github.com/{management.REPOSITORY}/issues/11",
    f"HTTPS://github.com/{management.REPOSITORY}/issues/11",
    f"https://github.com/{management.REPOSITORY}/pull/11",
    "https://github.com/other/repo/issues/5",
    f"https://GITHUB.COM/{management.REPOSITORY}/issues/11",
    f"prefix{management.ISSUE_URL}11",
    f"{management.ISSUE_URL}0",
    f"{management.ISSUE_URL}011",
    *(
        f"{management.ISSUE_URL}11{suffix}"
        for suffix in ("/extra", "?x=1", "#5", "bad", ".5", ",bad")
    ),
)


def registered_tasks():
    return management.plan_tasks((ROOT / management.PLAN).read_text())


def snapshot():
    return {
        "repository": management.REPOSITORY,
        "observed_at": NOW.isoformat(),
        "issue": {
            "number": 14,
            "html_url": management.ISSUE_URL + "14",
            "state": "open",
            "title": "Implement fresh workflow sessions",
            "assignee": {"login": "utkutugrul"},
            "labels": [
                {"name": name}
                for name in (
                    "symphony",
                    "dispatch:enabled",
                    "status:ready",
                    "owner:codex",
                    "review:claude",
                )
            ],
            "body": (
                "## Goal\nImplement a scoped change.\n## Ownership\n"
                "Implementation lead: Codex\nIndependent reviewer: Claude\n## Dependencies\n#11 and #12\n"
                "## Acceptance criteria\n- [ ] Preserve two fresh sessions.\n"
                "## Validation\nRun the scoped checks.\n## Delivery\nA reviewable PR.\n"
            ),
        },
        "dependencies": [
            {"number": n, "html_url": management.ISSUE_URL + str(n), "state": "closed"}
            for n in (11, 12)
        ],
    }


def test_real_repository_management_contract_is_consistent():
    assert management.check_repo(ROOT)


def test_actual_json_frontmatter_shape_is_a_map_and_preserves_prompt():
    config = management.workflow_config((ROOT / "WORKFLOW.md").read_text())
    management.check_config(config)
    assert config["tracker"]["kind"] == "github"


@pytest.mark.parametrize(
    "field,change,message",
    [
        ("labels", lambda v: v["tracker"].update(required_labels=["symphony"]), "dispatch:enabled"),
        ("token", lambda v: v["tracker"]["provider"].update(token="literal-token"), "GITHUB_TOKEN"),
        ("concurrency", lambda v: v["agent"].update(max_concurrent_agents=True), "concurrency"),
        ("sandbox", lambda v: v["codex"].update(thread_sandbox="danger-full-access"), "sandbox"),
        ("agent", lambda v: v["codex"].update(command="claude app-server"), "Codex app-server"),
    ],
)
def test_one_workflow_change_is_rejected_after_positive_control(field, change, message):
    config = management.workflow_config((ROOT / "WORKFLOW.md").read_text())
    management.check_config(config)
    change(config)
    with pytest.raises(management.ManagementError, match=message):
        management.check_config(config)


@pytest.mark.parametrize(
    "text,message",
    [
        ('---\n{"tracker":1,"tracker":2}\n---\nTask', "duplicate"),
        ("---\n{}\nTask", "closing"),
        ("---\n{}\n---\n", "empty"),
    ],
)
def test_malformed_frontmatter_is_not_silently_accepted(text, message):
    with pytest.raises(management.ManagementError, match=message):
        management.workflow_config(text)


def test_plan_acceptance_dependency_and_role_controls_are_genuine():
    tasks = management.plan_tasks((ROOT / management.PLAN).read_text())
    management.check_tasks(tasks)
    for field, value, message in [
        ("acceptance", [], "acceptance"),
        ("reviewer", tasks[0]["owner"], "distinct"),
        ("dependencies", ["missing-task"], "missing"),
    ]:
        changed = deepcopy(tasks)
        changed[0][field] = value
        with pytest.raises(management.ManagementError, match=message):
            management.check_tasks(changed)


def test_plan_cycle_is_rejected():
    tasks = management.plan_tasks((ROOT / management.PLAN).read_text())
    management.check_tasks(tasks)
    tasks[0]["dependencies"] = [tasks[1]["id"]]
    tasks[1]["dependencies"] = [tasks[0]["id"]]
    with pytest.raises(management.ManagementError, match="cycle"):
        management.check_tasks(tasks)


def test_local_link_positive_then_missing_target(tmp_path, monkeypatch):
    monkeypatch.setattr(management, "DOCUMENTS", ("map.md",))
    (tmp_path / "target.md").write_text("# Target\n")
    (tmp_path / "map.md").write_text("[Target](target.md)\n")
    management.check_links(tmp_path)
    (tmp_path / "target.md").unlink()
    with pytest.raises(management.ManagementError, match="broken local link"):
        management.check_links(tmp_path)


def test_local_links_cannot_escape_repository(tmp_path, monkeypatch):
    monkeypatch.setattr(management, "DOCUMENTS", ("map.md",))
    (tmp_path / "map.md").write_text("[Outside](../outside.md)\n")
    with pytest.raises(management.ManagementError, match="escapes"):
        management.check_links(tmp_path)


def test_supplied_ready_issue_requires_all_actual_dependency_records():
    value = snapshot()
    assert management.check_issue_snapshot(value, now=NOW) == 14
    value["dependencies"].pop()
    with pytest.raises(management.ManagementError, match="every actual dependency"):
        management.check_issue_snapshot(value, now=NOW)


@pytest.mark.parametrize(
    "change,message",
    [
        (lambda v: v["dependencies"][0].update(state="open"), "still open/unknown"),
        (lambda v: v["issue"]["labels"].append("status:blocked"), "exactly one"),
        (lambda v: v["issue"].update(labels=["symphony", "status:ready"]), "dispatch labels"),
        (lambda v: v["issue"].update(assignee={"login": "invented-bot"}), "human assignee"),
        (
            lambda v: v["issue"].update(
                body=v["issue"]["body"].replace("## Acceptance criteria", "## Missing criteria")
            ),
            "Acceptance criteria",
        ),
        (
            lambda v: v.update(observed_at=(NOW - timedelta(seconds=301)).isoformat()),
            "stale/future",
        ),
        (lambda v: v.update(observed_at=(NOW + timedelta(seconds=6)).isoformat()), "stale/future"),
        (
            lambda v: v["dependencies"][0].update(
                html_url="https://github.com/other/repo/issues/11"
            ),
            "same-repository",
        ),
        (lambda v: v["issue"].update(pull_request={}), "open issue"),
    ],
)
def test_single_snapshot_change_fails_after_genuine_positive(change, message):
    value = snapshot()
    management.check_issue_snapshot(value, now=NOW)
    change(value)
    with pytest.raises(management.ManagementError, match=message):
        management.check_issue_snapshot(value, now=NOW)


def test_blocked_with_dispatch_is_refused_even_with_closed_dependencies():
    value = snapshot()
    management.check_issue_snapshot(value, now=NOW)
    value["issue"]["labels"] = [
        item for item in value["issue"]["labels"] if item["name"] != "status:ready"
    ] + [{"name": "status:blocked"}]
    with pytest.raises(management.ManagementError, match="must lose dispatch"):
        management.check_issue_snapshot(value, now=NOW)


@pytest.mark.parametrize("terminal_state", ["closed_issue", "done_label"])
def test_other_completed_records_do_not_change_live_terminal_refusal(terminal_state):
    tasks = registered_tasks()
    tasks[0]["status"] = "done"
    management.check_tasks(tasks)
    value = snapshot()
    assert (
        management.check_live_claim(
            value, expected_issue=14, manual_claims=[], tasks=tasks, now=NOW
        )
        == 14
    )
    if terminal_state == "closed_issue":
        value["issue"]["state"] = "closed"
        message = "only an open issue"
    else:
        value["issue"]["labels"] = [
            item for item in value["issue"]["labels"] if item["name"] != "status:ready"
        ] + [{"name": "status:done"}]
        message = "unsupported status label"
    with pytest.raises(management.ManagementError, match=message):
        management.check_live_claim(
            value, expected_issue=14, manual_claims=[], tasks=tasks, now=NOW
        )


def test_reopened_live_issue_cannot_dispatch_completed_registered_task():
    tasks = registered_tasks()
    value = snapshot()
    assert (
        management.check_live_claim(
            value, expected_issue=14, manual_claims=[], tasks=tasks, now=NOW
        )
        == 14
    )
    registered = next(task for task in tasks if task["id"] == "process-14")
    registered["status"] = "done"
    management.check_tasks(tasks)
    with pytest.raises(management.ManagementError, match="completed plan task"):
        management.check_live_claim(
            value, expected_issue=14, manual_claims=[], tasks=tasks, now=NOW
        )
    registered["status"] = "ready"
    assert (
        management.check_live_claim(
            value, expected_issue=14, manual_claims=[], tasks=tasks, now=NOW
        )
        == 14
    )


def test_unknown_cost_or_model_claim_is_not_added_by_checker(capsys):
    assert management.main(["--repo", str(ROOT)]) == 0
    output = capsys.readouterr().out
    assert "dispatch NOT checked" in output
    assert "model" not in output.lower()


def test_snapshot_bound_is_checked_before_json_decode(tmp_path):
    path = tmp_path / "oversize.json"
    path.write_bytes(b" " * (management.MAX_INPUT + 1))
    with pytest.raises(management.ManagementError, match="256 KiB"):
        management.read_text(path)


def test_duplicate_dependency_and_empty_acceptance_have_specific_refusals():
    value = snapshot()
    management.check_issue_snapshot(value, now=NOW)
    value["dependencies"].append(deepcopy(value["dependencies"][0]))
    with pytest.raises(management.ManagementError, match="duplicate dependency"):
        management.check_issue_snapshot(value, now=NOW)
    value = snapshot()
    value["issue"]["body"] = value["issue"]["body"].replace(
        "- [ ] Preserve two fresh sessions.", "No concrete criterion."
    )
    with pytest.raises(management.ManagementError, match="concrete checklist"):
        management.check_issue_snapshot(value, now=NOW)


def test_none_dependencies_with_actual_explanatory_sentence_are_supported():
    value = snapshot()
    management.check_issue_snapshot(value, now=NOW)
    value["issue"]["body"] = value["issue"]["body"].replace(
        "#11 and #12", "None. Existing work may continue in its current isolated workspace."
    )
    value["dependencies"] = []
    assert management.check_issue_snapshot(value, now=NOW) == 14


def test_none_cannot_hide_a_real_dependency():
    value = snapshot()
    value["issue"]["body"] = value["issue"]["body"].replace("#11 and #12", "None. See #11.")
    with pytest.raises(management.ManagementError, match="conflicts"):
        management.check_issue_snapshot(value, now=NOW)


@pytest.mark.parametrize(
    "references",
    [
        "#11 and #12",
        f"{management.ISSUE_URL}11 and {management.ISSUE_URL}12",
        f"[Core]({management.ISSUE_URL}11) and #12",
        f"[Core]({management.ISSUE_URL}11) and [Native]({management.ISSUE_URL}12)",
        f"<{management.ISSUE_URL}11> and <{management.ISSUE_URL}12>",
        f"- {management.ISSUE_URL}11\n- {management.ISSUE_URL}12",
        "#11, #12.",
    ],
)
def test_supported_dependency_references_keep_exact_plan_binding(references):
    value = snapshot()
    value["issue"]["body"] = value["issue"]["body"].replace("#11 and #12", references)
    owners, dependencies = management.issue_contract(value["issue"]["body"])
    assert owners == {"owner": "Codex", "reviewer": "Claude"}
    assert dependencies == {11, 12}
    assert (
        management.check_live_claim(
            value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
        )
        == 14
    )


@pytest.mark.parametrize(
    "unsupported",
    [
        "other/repo#5",
        "other/repo.#5",
        "other/repo-#5",
        "GH-5",
        "gh-5",
        f"{management.REPOSITORY}#5",
        "repo#5",
        "#0",
        "#05",
    ],
)
@pytest.mark.parametrize("prefix", ["#11 and #12", "None.", ""])
def test_unsupported_dependency_references_are_never_silently_dropped(unsupported, prefix):
    value = snapshot()
    assert management.check_issue_snapshot(value, now=NOW) == 14
    if prefix != "#11 and #12":
        value["dependencies"] = []
    value["issue"]["body"] = value["issue"]["body"].replace(
        "#11 and #12", f"{prefix} {unsupported}".strip()
    )
    with pytest.raises(management.ManagementError, match="unsupported issue-reference"):
        management.check_issue_snapshot(value, now=NOW)


@pytest.mark.parametrize("unsupported", ["other/repo#5", "GH-5"])
def test_live_fetch_refuses_unsupported_dependencies_before_any_dependency_request(unsupported):
    requests = []
    value = fetch_fixture(fake_http_records(), requests)
    assert management.check_issue_snapshot(value, now=NOW) == 14
    records = fake_http_records()
    records[14]["body"] = records[14]["body"].replace("#11 and #12", f"#11 and #12, {unsupported}")
    requests.clear()
    with pytest.raises(management.ManagementError, match="unsupported issue-reference"):
        fetch_fixture(records, requests)
    assert [request[0] for request in requests] == [
        f"https://api.github.com/repos/{management.REPOSITORY}/issues/14"
    ]


@pytest.mark.parametrize("unsupported", UNSUPPORTED_DEPENDENCY_URLS)
@pytest.mark.parametrize("context", ["alone", "supported", "none"])
def test_unsupported_dependency_urls_are_refused_as_whole_tokens(unsupported, context):
    records = fake_http_records()
    prefix = "None." if context == "none" else "#11 and #12"
    records[14]["body"] = records[14]["body"].replace("#11 and #12", prefix)
    requests = []
    value = fetch_fixture(records, requests)
    assert management.check_issue_snapshot(value, now=NOW) == 14
    owners, dependencies = management.issue_contract(value["issue"]["body"])
    assert owners == {"owner": "Codex", "reviewer": "Claude"}
    assert dependencies == (set() if context == "none" else {11, 12})
    if context != "none":
        assert (
            management.check_live_claim(
                value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
            )
            == 14
        )

    changed = unsupported if context == "alone" else f"{prefix} {unsupported}"
    records[14]["body"] = records[14]["body"].replace(prefix, changed)
    message = (
        "issue Dependencies: unsupported issue-reference form; use bare #N or canonical issue URLs"
    )
    # The snapshot and the real fetch path must refuse before asking for any
    # dependency, even when a supported prefix or None would otherwise pass.
    value["issue"]["body"] = records[14]["body"]
    with pytest.raises(management.ManagementError) as caught:
        management.check_issue_snapshot(value, now=NOW)
    assert str(caught.value) == message
    requests.clear()
    with pytest.raises(management.ManagementError) as caught:
        fetch_fixture(records, requests)
    assert str(caught.value) == message
    assert [request[0] for request in requests] == [
        f"https://api.github.com/repos/{management.REPOSITORY}/issues/14"
    ]


def test_unreviewed_hook_and_unknown_status_are_rejected():
    config = management.workflow_config((ROOT / "WORKFLOW.md").read_text())
    management.check_config(config)
    config["hooks"]["after_run"] = "unexpected command"
    with pytest.raises(management.ManagementError, match="unreviewed executable hooks"):
        management.check_config(config)
    value = snapshot()
    management.check_issue_snapshot(value, now=NOW)
    value["issue"]["labels"].append("status:unrecognized")
    with pytest.raises(management.ManagementError, match="unsupported status"):
        management.check_issue_snapshot(value, now=NOW)


def test_live_claim_has_positive_control_and_refuses_manual_owner():
    value = snapshot()
    assert (
        management.check_live_claim(
            value, tasks=registered_tasks(), expected_issue=14, manual_claims=[10, 11, 12], now=NOW
        )
        == 14
    )
    with pytest.raises(management.ManagementError, match="manual owner still active"):
        management.check_live_claim(
            value, tasks=registered_tasks(), expected_issue=14, manual_claims=[14], now=NOW
        )


def test_live_claim_cannot_authorize_a_different_issue_workspace():
    value = snapshot()
    management.check_live_claim(
        value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
    )
    with pytest.raises(management.ManagementError, match="workspace issue mismatch"):
        management.check_live_claim(
            value, tasks=registered_tasks(), expected_issue=15, manual_claims=[], now=NOW
        )


def test_before_run_cannot_drop_live_claim_gate():
    config = management.workflow_config((ROOT / "WORKFLOW.md").read_text())
    management.check_config(config)
    config["hooks"]["before_run"] = "rtk proxy python3 scripts/check_project_management.py --repo ."
    with pytest.raises(management.ManagementError, match="live-claim"):
        management.check_config(config)


def test_unbound_manual_workspace_cannot_run_live_gate(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "manual-checkout"
    workspace.mkdir()
    tasks = management.check_repo(ROOT)
    monkeypatch.setattr(management, "check_repo", lambda root: tasks)
    assert management.main(["--repo", str(workspace), "--require-live-claim"]) == 1
    assert "actual native GH-N" in capsys.readouterr().err


def fake_http_records():
    value = snapshot()
    records = {14: value["issue"]}
    records.update({item["number"]: item for item in value["dependencies"]})
    return records


def fetch_fixture(records, requests=None, clock=lambda: 0):
    def open_url(request, timeout):
        if requests is not None:
            requests.append(
                (request.full_url, request.method, request.get_header("Authorization"), timeout)
            )
        return io.BytesIO(json.dumps(records[int(request.full_url.rsplit("/", 1)[1])]).encode())

    return management.fetch_live_snapshot(
        14, token="fixture-token", open_url=open_url, clock=clock, now=NOW
    )


@pytest.fixture
def cli_workspace(tmp_path, monkeypatch):
    workspace = tmp_path / "GH-14"
    (workspace / management.PLAN).parent.mkdir(parents=True)
    (workspace / management.PLAN).write_text((ROOT / management.PLAN).read_text())
    tasks = registered_tasks()
    monkeypatch.setattr(management, "check_repo", lambda root: tasks)
    return workspace


@pytest.fixture
def live_transport(monkeypatch):
    records = fake_http_records()
    previous = object()
    state = {"handler": previous}
    changes, requests = [], []
    fake_signal = SimpleNamespace(SIGALRM=1, ITIMER_REAL=2)
    fake_signal.getitimer = lambda kind: (0.0, 0.0)

    def handler(kind, value):
        old = state["handler"]
        state["handler"] = value
        changes.append(("handler", kind, value))
        return old

    fake_signal.signal = handler
    fake_signal.setitimer = lambda kind, seconds: changes.append(("timer", kind, seconds))

    def open_url(request, timeout):
        number = int(request.full_url.rsplit("/", 1)[1])
        requests.append(number)
        return io.BytesIO(json.dumps(records[number]).encode())

    monkeypatch.setattr(management, "signal", fake_signal)
    monkeypatch.setattr(
        management, "build_opener", lambda *handlers: SimpleNamespace(open=open_url)
    )
    return SimpleNamespace(
        records=records, state=state, changes=changes, requests=requests, previous=previous
    )


def test_cli_distinguishes_offline_snapshot_from_live_fetch(
    cli_workspace, live_transport, tmp_path, monkeypatch, capsys
):
    value = snapshot()
    value["observed_at"] = datetime.now(UTC).isoformat()
    path = tmp_path / "offline-fixture.json"
    path.write_text(json.dumps(value))
    monkeypatch.delenv("SYMPHONY_GITHUB_TOKEN", raising=False)
    args = ["--repo", str(cli_workspace)]
    assert management.main([*args, "--issue-snapshot", str(path)]) == 0
    offline = capsys.readouterr()
    assert "offline snapshot GH-14" in offline.out
    assert "does not authenticate" in offline.out
    assert "does not authorize promotion" in offline.out
    assert not offline.err and not live_transport.requests

    assert management.main([*args, "--require-live-claim"]) == 1
    missing_auth = capsys.readouterr()
    assert "explicit SYMPHONY_GITHUB_TOKEN" in missing_auth.err
    assert not missing_auth.out and not live_transport.requests

    monkeypatch.setenv("SYMPHONY_GITHUB_TOKEN", "fixture-token")
    assert management.main([*args, "--require-live-claim"]) == 0
    live = capsys.readouterr()
    assert "live GitHub fetch GH-14" in live.out
    assert "does not authorize promotion" in live.out
    assert "offline snapshot" not in live.out and not live.err
    assert live_transport.requests == [14, 11, 12]
    assert live_transport.state["handler"] is live_transport.previous


@pytest.mark.parametrize("live_first", [False, True])
@pytest.mark.parametrize("existing_snapshot", [False, True])
def test_cli_mixed_modes_are_refused_before_file_auth_or_network_access(
    cli_workspace, tmp_path, monkeypatch, capsys, live_first, existing_snapshot
):
    value = snapshot()
    value["observed_at"] = datetime.now(UTC).isoformat()
    path = tmp_path / "offline-fixture.json"
    path.write_text(json.dumps(value))
    args = ["--repo", str(cli_workspace)]
    assert management.main([*args, "--issue-snapshot", str(path)]) == 0
    capsys.readouterr()
    if not existing_snapshot:
        path.unlink()

    def forbidden(*args, **kwargs):
        raise AssertionError("conflicting modes must be refused before any input or auth access")

    monkeypatch.setattr(management, "check_repo", forbidden)
    monkeypatch.setattr(management, "read_text", forbidden)
    monkeypatch.setattr(management, "fetch_live_snapshot", forbidden)
    monkeypatch.setattr(management, "os", SimpleNamespace(environ=SimpleNamespace(get=forbidden)))
    flags = ["--issue-snapshot", str(path)]
    flags = ["--require-live-claim", *flags] if live_first else [*flags, "--require-live-claim"]
    with pytest.raises(SystemExit) as error:
        management.main([*args, *flags])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert "not allowed with argument" in output.err
    assert "--issue-snapshot" in output.err and "--require-live-claim" in output.err
    assert not output.out


@pytest.mark.parametrize("interrupted_decode", [1, 2, 3])
def test_live_decode_deadline_preserves_fixed_diagnostic_and_restores_timer(
    live_transport, monkeypatch, interrupted_decode
):
    value = management.fetch_live_snapshot(14, token="fixture-token", clock=lambda: 0, now=NOW)
    assert management.check_issue_snapshot(value, now=NOW) == 14
    original_decode = management.decode_json
    calls = 0

    def interrupted(text):
        nonlocal calls
        calls += 1
        if calls == interrupted_decode:
            live_transport.state["handler"](1, None)
        return original_decode(text)

    monkeypatch.setattr(management, "decode_json", interrupted)
    with pytest.raises(management.ManagementError) as error:
        management.fetch_live_snapshot(14, token="fixture-token", clock=lambda: 0, now=NOW)
    assert str(error.value) == "live GitHub: absolute ten-second deadline exceeded"
    assert calls == interrupted_decode
    assert live_transport.changes[-2:] == [
        ("timer", 2, 0),
        ("handler", 1, live_transport.previous),
    ]
    assert live_transport.state["handler"] is live_transport.previous


@pytest.mark.parametrize(
    "raw",
    [
        b'{"untrusted-response":',
        b'{"untrusted-duplicate":1,"untrusted-duplicate":2}',
        b'{"untrusted-nonfinite":NaN}',
        b'{"untrusted-encoding":"\xff"}',
    ],
)
def test_live_invalid_json_keeps_duplicate_keys_and_response_contents_redacted(raw):
    value = fetch_fixture(fake_http_records())
    assert management.check_issue_snapshot(value, now=NOW) == 14
    requests = []

    def open_url(request, timeout):
        requests.append(request.full_url)
        return io.BytesIO(raw)

    with pytest.raises(management.ManagementError) as error:
        management.fetch_live_snapshot(
            14, token="fixture-token", open_url=open_url, clock=lambda: 0, now=NOW
        )
    assert str(error.value) == "live GitHub: invalid JSON response; details omitted"
    assert error.value.__suppress_context__
    assert requests == [f"https://api.github.com/repos/{management.REPOSITORY}/issues/14"]


def test_live_gate_uses_fixed_get_ids_and_explicit_credential_without_network():
    requests = []
    value = fetch_fixture(fake_http_records(), requests)
    assert (
        management.check_live_claim(
            value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
        )
        == 14
    )
    assert [item[0] for item in requests] == [
        f"https://api.github.com/repos/{management.REPOSITORY}/issues/{n}" for n in (14, 11, 12)
    ]
    assert all(
        method == "GET" and key == "Bearer fixture-token" and timeout == 5
        for _, method, key, timeout in requests
    )


@pytest.mark.parametrize(
    "problem,message",
    [("wrong_issue", "identity mismatch"), ("open_dependency", "still open/unknown")],
)
def test_live_single_response_fault_after_genuine_positive(problem, message):
    records = fake_http_records()
    value = fetch_fixture(records)
    management.check_live_claim(
        value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
    )
    if problem == "wrong_issue":
        records[14]["number"] = 999
        with pytest.raises(management.ManagementError, match=message):
            fetch_fixture(records)
    else:
        records[11]["state"] = "open"
        value = fetch_fixture(records)
        with pytest.raises(management.ManagementError, match=message):
            management.check_live_claim(
                value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
            )


def test_live_body_and_deadline_bounds_after_positive_control():
    fetch_fixture(fake_http_records())
    with pytest.raises(management.ManagementError, match="64 KiB"):
        management.fetch_live_snapshot(
            14,
            token="fixture-token",
            open_url=lambda request, timeout: io.BytesIO(b"x" * 65537),
            clock=lambda: 0,
            now=NOW,
        )
    ticks = iter((0, 0, 11))
    with pytest.raises(management.ManagementError, match="deadline"):
        fetch_fixture(fake_http_records(), clock=lambda: next(ticks))


def test_live_missing_token_redirect_and_transport_failure_are_value_free():
    fetch_fixture(fake_http_records())
    with pytest.raises(management.ManagementError, match="explicit SYMPHONY_GITHUB_TOKEN"):
        management.fetch_live_snapshot(14, token="")
    with pytest.raises(management.ManagementError, match="redirects"):
        management._NoRedirect().redirect_request(
            None, None, 302, "", {}, "https://elsewhere.invalid"
        )

    def failed(request, timeout):
        raise management.URLError("fixture-token must never be printed")

    with pytest.raises(management.ManagementError) as error:
        management.fetch_live_snapshot(
            14, token="fixture-token", open_url=failed, clock=lambda: 0, now=NOW
        )
    assert "fixture-token" not in str(error.value)
    assert "bounded request failed" in str(error.value)


def test_cli_positive_claim_binds_workspace_before_single_identity_fault(
    tmp_path, monkeypatch, capsys
):
    workspace = tmp_path / "GH-14"
    (workspace / management.PLAN).parent.mkdir(parents=True)
    (workspace / management.PLAN).write_text((ROOT / management.PLAN).read_text())
    value = snapshot()
    value["observed_at"] = datetime.now(UTC).isoformat()
    path = tmp_path / "actual-format-fixture.json"
    path.write_text(json.dumps(value))
    tasks = management.plan_tasks((ROOT / management.PLAN).read_text())
    monkeypatch.setattr(management, "check_repo", lambda root: tasks)
    assert management.main(["--repo", str(workspace), "--issue-snapshot", str(path)]) == 0
    assert "GH-14" in capsys.readouterr().out
    value["issue"]["number"] = 15
    value["issue"]["html_url"] = management.ISSUE_URL + "15"
    path.write_text(json.dumps(value))
    assert management.main(["--repo", str(workspace), "--issue-snapshot", str(path)]) == 1
    assert "workspace issue mismatch" in capsys.readouterr().err


def test_manual_claim_denial_happens_before_auth_or_network(tmp_path, monkeypatch, capsys):
    workspace = tmp_path / "GH-10"
    (workspace / management.PLAN).parent.mkdir(parents=True)
    (workspace / management.PLAN).write_text((ROOT / management.PLAN).read_text())
    tasks = management.plan_tasks((ROOT / management.PLAN).read_text())
    monkeypatch.setattr(management, "check_repo", lambda root: tasks)

    def forbidden(*args, **kwargs):
        raise AssertionError("manual issue must not reach credential/network boundary")

    monkeypatch.setattr(management, "os", SimpleNamespace(environ=SimpleNamespace(get=forbidden)))
    monkeypatch.setattr(management, "fetch_live_snapshot", forbidden)
    assert management.main(["--repo", str(workspace), "--require-live-claim"]) == 1
    assert "manual owner still active" in capsys.readouterr().err


@pytest.mark.parametrize("change", ["removed_dependency", "added_dependency", "switched_roles"])
def test_live_claim_cannot_change_the_versioned_task_contract(change):
    value = snapshot()
    tasks = registered_tasks()
    assert (
        management.check_live_claim(
            value, tasks=tasks, expected_issue=14, manual_claims=[], now=NOW
        )
        == 14
    )
    if change == "removed_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#11 and #12", "None.")
        value["dependencies"] = []
    elif change == "added_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#11 and #12", "#11, #12 and #15")
        value["dependencies"].append(
            {"number": 15, "html_url": management.ISSUE_URL + "15", "state": "closed"}
        )
    else:
        value["issue"]["body"] = value["issue"]["body"].replace(
            "Implementation lead: Codex\nIndependent reviewer: Claude",
            "Implementation lead: Claude\nIndependent reviewer: Codex",
        )
        value["issue"]["labels"] = [
            {"name": name}
            for name in (
                "symphony",
                "dispatch:enabled",
                "status:ready",
                "owner:claude",
                "review:codex",
            )
        ]
    # Each changed record is internally consistent. Only its conflict with the
    # repository plan should refuse the otherwise dispatchable claim.
    assert management.check_issue_snapshot(value, now=NOW) == 14
    with pytest.raises(management.ManagementError, match="versioned plan"):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=14, manual_claims=[], now=NOW
        )


@pytest.mark.parametrize(
    "change,message",
    [
        ("removed_report_dependency", "versioned plan"),
        ("added_native_dependency", "versioned plan"),
        ("switched_roles", "versioned plan"),
        ("open_report_dependency", "still open/unknown"),
        ("backlog_off", "explicit dispatch labels"),
    ],
)
def test_workflow_dashboard_claim_keeps_roles_dependencies_and_promotion_gate(change, message):
    # Only an explicit offline plan reopening can exercise a delivered task's live claim.
    value = snapshot()
    value["issue"].update(
        number=32,
        html_url=management.ISSUE_URL + "32",
        title="Render a standalone workflow report dashboard",
        body=value["issue"]["body"]
        .replace("#11 and #12", "#13 and #28")
        .replace(
            "Preserve two fresh sessions.", "Render a validated report with escaped unknowns."
        ),
    )
    value["dependencies"] = [
        {"number": n, "html_url": management.ISSUE_URL + str(n), "state": "closed"}
        for n in (13, 28)
    ]
    tasks = registered_tasks()
    with pytest.raises(management.ManagementError, match="completed plan task"):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=32, manual_claims=[10], now=NOW
        )
    next(task for task in tasks if task["id"] == "workflow-dashboard")["status"] = "ready"
    assert (
        management.check_live_claim(
            value, tasks=tasks, expected_issue=32, manual_claims=[10], now=NOW
        )
        == 32
    )
    if change == "removed_report_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#13 and #28", "#13")
        value["dependencies"].pop()
    elif change == "added_native_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#13 and #28", "#13, #28 and #12")
        value["dependencies"].append(
            {"number": 12, "html_url": management.ISSUE_URL + "12", "state": "closed"}
        )
    elif change == "switched_roles":
        value["issue"]["body"] = value["issue"]["body"].replace(
            "Implementation lead: Codex\nIndependent reviewer: Claude",
            "Implementation lead: Claude\nIndependent reviewer: Codex",
        )
        value["issue"]["labels"] = [
            {"name": name}
            for name in (
                "symphony",
                "dispatch:enabled",
                "status:ready",
                "owner:claude",
                "review:codex",
            )
        ]
    elif change == "open_report_dependency":
        value["dependencies"][1]["state"] = "open"
    else:
        value["issue"]["labels"] = [
            {"name": name}
            for name in ("symphony", "status:backlog", "owner:codex", "review:claude")
        ]
    if change not in {"open_report_dependency", "backlog_off"}:
        assert management.check_issue_snapshot(value, now=NOW) == 32
    with pytest.raises(management.ManagementError, match=message):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=32, manual_claims=[10], now=NOW
        )


@pytest.mark.parametrize(
    "change,message",
    [
        ("removed_review_dependency", "versioned plan"),
        ("added_native_dependency", "versioned plan"),
        ("switched_roles", "versioned plan"),
        ("open_review_dependency", "still open/unknown"),
        ("backlog_off", "explicit dispatch labels"),
    ],
)
def test_service_store_claim_keeps_roles_dependencies_and_promotion_gate(change, message):
    # Only an explicit offline plan reopening can exercise a delivered task's live claim.
    value = snapshot()
    value["issue"].update(
        number=36,
        html_url=management.ISSUE_URL + "36",
        title="Add a standalone durable service job store",
        body=value["issue"]["body"]
        .replace("#11 and #12", "#13")
        .replace("Preserve two fresh sessions.", "Preserve durable unknown job states."),
    )
    value["dependencies"] = [
        {"number": 13, "html_url": management.ISSUE_URL + "13", "state": "closed"}
    ]
    tasks = registered_tasks()
    with pytest.raises(management.ManagementError, match="completed plan task"):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=36, manual_claims=[10], now=NOW
        )
    next(task for task in tasks if task["id"] == "service-store-contract")["status"] = "ready"
    assert (
        management.check_live_claim(
            value, tasks=tasks, expected_issue=36, manual_claims=[10], now=NOW
        )
        == 36
    )
    if change == "removed_review_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#13", "None.")
        value["dependencies"].clear()
    elif change == "added_native_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#13", "#13 and #12")
        value["dependencies"].append(
            {"number": 12, "html_url": management.ISSUE_URL + "12", "state": "closed"}
        )
    elif change == "switched_roles":
        value["issue"]["body"] = value["issue"]["body"].replace(
            "Implementation lead: Codex\nIndependent reviewer: Claude",
            "Implementation lead: Claude\nIndependent reviewer: Codex",
        )
        value["issue"]["labels"] = [
            {"name": name}
            for name in (
                "symphony",
                "dispatch:enabled",
                "status:ready",
                "owner:claude",
                "review:codex",
            )
        ]
    elif change == "open_review_dependency":
        value["dependencies"][0]["state"] = "open"
    else:
        value["issue"]["labels"] = [
            {"name": name}
            for name in ("symphony", "status:backlog", "owner:codex", "review:claude")
        ]
    if change not in {"open_review_dependency", "backlog_off"}:
        assert management.check_issue_snapshot(value, now=NOW) == 36
    with pytest.raises(management.ManagementError, match=message):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=36, manual_claims=[10], now=NOW
        )


@pytest.mark.parametrize(
    "change,message",
    [
        ("removed_review_dependency", "versioned plan"),
        ("added_native_dependency", "versioned plan"),
        ("switched_roles", "versioned plan"),
        ("open_review_dependency", "still open/unknown"),
        ("backlog_off", "explicit dispatch labels"),
        ("wrong_workspace", "workspace issue mismatch"),
        ("manual_claim", "manual owner"),
    ],
)
def test_host_vm_source_claim_keeps_review_dependency_and_separate_custody(change, message):
    value = snapshot()
    value["issue"].update(
        number=40,
        html_url=management.ISSUE_URL + "40",
        title="Prepare finite Host and VM validation operators",
        body=value["issue"]["body"]
        .replace("#11 and #12", "#13")
        .replace("Preserve two fresh sessions.", "Prepare only finite Host and VM Sources."),
    )
    value["dependencies"] = [
        {"number": 13, "html_url": management.ISSUE_URL + "13", "state": "closed"}
    ]
    tasks = registered_tasks()
    native = deepcopy(next(task for task in tasks if task["id"] == "native-12"))
    assert (
        management.check_live_claim(
            value, tasks=tasks, expected_issue=40, manual_claims=[10], now=NOW
        )
        == 40
    )
    expected_issue, claims = 40, [10]
    if change == "removed_review_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#13", "None.")
        value["dependencies"].clear()
    elif change == "added_native_dependency":
        value["issue"]["body"] = value["issue"]["body"].replace("#13", "#13 and #12")
        value["dependencies"].append(
            {"number": 12, "html_url": management.ISSUE_URL + "12", "state": "closed"}
        )
    elif change == "switched_roles":
        value["issue"]["body"] = value["issue"]["body"].replace(
            "Implementation lead: Codex\nIndependent reviewer: Claude",
            "Implementation lead: Claude\nIndependent reviewer: Codex",
        )
        value["issue"]["labels"] = [
            {"name": name}
            for name in (
                "symphony",
                "dispatch:enabled",
                "status:ready",
                "owner:claude",
                "review:codex",
            )
        ]
    elif change == "open_review_dependency":
        value["dependencies"][0]["state"] = "open"
    elif change == "backlog_off":
        value["issue"]["labels"] = [
            {"name": name}
            for name in ("symphony", "status:backlog", "owner:codex", "review:claude")
        ]
    elif change == "wrong_workspace":
        expected_issue = 12
    else:
        claims.append(40)
    if change not in {"open_review_dependency", "backlog_off"}:
        assert management.check_issue_snapshot(value, now=NOW) == 40
    with pytest.raises(management.ManagementError, match=message):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=expected_issue, manual_claims=claims, now=NOW
        )
    assert next(task for task in tasks if task["id"] == "native-12") == native


@pytest.mark.parametrize(
    "change,message",
    [
        ("removed_report", "versioned plan"),
        ("added_native", "versioned plan"),
        ("switched_roles", "versioned plan"),
        ("open_13", "still open/unknown"),
        ("open_28", "still open/unknown"),
        ("open_32", "still open/unknown"),
        ("backlog_off", "explicit dispatch labels"),
        ("wrong_workspace", "workspace issue mismatch"),
        ("manual_claim", "manual owner"),
    ],
)
def test_workflow_cli_claim_keeps_saved_data_dependencies_and_custody(change, message):
    value = snapshot()
    value["issue"].update(
        number=42,
        html_url=management.ISSUE_URL + "42",
        body=value["issue"]["body"].replace("#11 and #12", "#13, #28 and #32"),
    )
    value["dependencies"] = [
        {"number": n, "html_url": management.ISSUE_URL + str(n), "state": "closed"}
        for n in (13, 28, 32)
    ]
    tasks = registered_tasks()
    with pytest.raises(management.ManagementError, match="completed plan task"):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=42, manual_claims=[10], now=NOW
        )
    next(task for task in tasks if task["id"] == "workflow-dashboard-cli")["status"] = "ready"
    assert (
        management.check_live_claim(
            value, tasks=tasks, expected_issue=42, manual_claims=[10], now=NOW
        )
        == 42
    )
    expected_issue, claims = 42, [10]
    if change == "removed_report":
        value["issue"]["body"] = value["issue"]["body"].replace("#13, #28 and #32", "#13 and #32")
        value["dependencies"].pop(1)
    elif change == "added_native":
        value["issue"]["body"] = value["issue"]["body"].replace(
            "#13, #28 and #32", "#13, #28, #32 and #12"
        )
        value["dependencies"].append(
            {"number": 12, "html_url": management.ISSUE_URL + "12", "state": "closed"}
        )
    elif change == "switched_roles":
        value["issue"]["body"] = value["issue"]["body"].replace(
            "Implementation lead: Codex\nIndependent reviewer: Claude",
            "Implementation lead: Claude\nIndependent reviewer: Codex",
        )
        value["issue"]["labels"] = [
            {"name": name}
            for name in (
                "symphony",
                "dispatch:enabled",
                "status:ready",
                "owner:claude",
                "review:codex",
            )
        ]
    elif change.startswith("open_"):
        next(row for row in value["dependencies"] if row["number"] == int(change[5:]))["state"] = (
            "open"
        )
    elif change == "backlog_off":
        value["issue"]["labels"] = [
            {"name": name}
            for name in ("symphony", "status:backlog", "owner:codex", "review:claude")
        ]
    elif change == "wrong_workspace":
        expected_issue = 40
    else:
        claims.append(42)
    if change not in {"open_13", "open_28", "open_32", "backlog_off"}:
        assert management.check_issue_snapshot(value, now=NOW) == 42
    with pytest.raises(management.ManagementError, match=message):
        management.check_live_claim(
            value, tasks=tasks, expected_issue=expected_issue, manual_claims=claims, now=NOW
        )


def test_live_aggregate_bound_has_genuine_below_cap_control():
    records = fake_http_records()
    records[14]["body"] = records[14]["body"].replace("#11 and #12", "#11, #12, #15 and #16")
    for number in (15, 16):
        records[number] = {
            "number": number,
            "html_url": management.ISSUE_URL + str(number),
            "state": "closed",
        }
    for number in (14, 11, 12, 15):
        records[number]["padding"] = "x" * 58000
    value = fetch_fixture(records)
    assert management.check_issue_snapshot(value, now=NOW) == 14
    records[16]["padding"] = "x" * 58000
    with pytest.raises(management.ManagementError, match="256 KiB aggregate"):
        fetch_fixture(records)


def test_real_transport_branch_owns_and_restores_absolute_deadline_without_network(monkeypatch):
    records = fake_http_records()
    changes = []
    previous = object()
    state = {"handler": previous}
    fake_signal = SimpleNamespace(SIGALRM=1, ITIMER_REAL=2)
    fake_signal.getitimer = lambda kind: (0.0, 0.0)

    def handler(kind, value):
        old = state["handler"]
        state["handler"] = value
        changes.append(("handler", kind, value))
        return old

    fake_signal.signal = handler
    fake_signal.setitimer = lambda kind, seconds: changes.append(("timer", kind, seconds))

    def open_url(request, timeout):
        return io.BytesIO(json.dumps(records[int(request.full_url.rsplit("/", 1)[1])]).encode())

    monkeypatch.setattr(management, "signal", fake_signal)
    monkeypatch.setattr(
        management, "build_opener", lambda *handlers: SimpleNamespace(open=open_url)
    )
    value = management.fetch_live_snapshot(14, token="fixture-token", clock=lambda: 0, now=NOW)
    assert (
        management.check_live_claim(
            value, tasks=registered_tasks(), expected_issue=14, manual_claims=[], now=NOW
        )
        == 14
    )
    assert ("timer", 2, 10) in changes and ("timer", 2, 0) in changes
    assert state["handler"] is previous
