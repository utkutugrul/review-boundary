"""Check local contracts; live mode uses explicit, read-only GitHub requests."""

import argparse
import json
import os
import re
import signal
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

REPOSITORY = "utkutugrul/review-boundary"
ISSUE_URL = f"https://github.com/{REPOSITORY}/issues/"
STATUSES = {"backlog", "ready", "active", "review", "blocked"}
FIELDS = {
    "id",
    "title",
    "issue",
    "owner",
    "reviewer",
    "status",
    "dependencies",
    "acceptance",
    "validation",
    "evidence",
}
PLAN = "docs/exec-plans/active/symphony-management.md"
DOCUMENTS = (
    "AGENTS.md",
    "ARCHITECTURE.md",
    "WORKFLOW.md",
    "docs/PLANS.md",
    PLAN,
    "docs/symphony-operations.md",
)
SECTIONS = ("Goal", "Ownership", "Dependencies", "Acceptance criteria", "Validation", "Delivery")
MAX_INPUT = 256 * 1024


class ManagementError(ValueError):
    """An actionable contract refusal without dumping supplied task bodies."""


def require(condition, message):
    if not condition:
        raise ManagementError(message)


def read_text(path):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    require(len(raw) <= MAX_INPUT, f"{Path(path).name}: exceeds 256 KiB")
    return raw.decode("utf-8")


def _pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, f"JSON: duplicate field {key[:80]}")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ManagementError("JSON: nonfinite values are not allowed")


def decode_json(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_nonfinite)


def workflow_config(text):
    lines = text.splitlines()
    require(lines and lines[0] == "---", "WORKFLOW.md: missing opening ---")
    require("---" in lines[1:], "WORKFLOW.md: missing closing ---")
    end = lines.index("---", 1)
    require(any(line.strip() for line in lines[end + 1 :]), "WORKFLOW.md: prompt is empty")
    value = decode_json("\n".join(lines[1:end]))
    require(type(value) is dict, "WORKFLOW.md: front matter must be a JSON/YAML map")
    return value


def check_config(value):
    require(
        type(value) is dict and set(value) == {"tracker", "workspace", "hooks", "agent", "codex"},
        "workflow: retain exactly the reviewed configuration sections",
    )
    tracker = value.get("tracker", {})
    require(
        type(tracker) is dict
        and set(tracker)
        == {"kind", "provider", "active_states", "terminal_states", "required_labels"},
        "workflow.tracker: retain exactly the reviewed fields",
    )
    require(tracker.get("kind") == "github", "workflow: use the native github tracker")
    require(
        tracker.get("provider") == {"repo": REPOSITORY, "token": "$SYMPHONY_GITHUB_TOKEN"},
        "workflow.provider: use the fixed repository and $SYMPHONY_GITHUB_TOKEN reference",
    )
    require(tracker.get("active_states") == ["open"], "workflow: active_states must be open")
    require(
        tracker.get("terminal_states") == ["closed"], "workflow: terminal_states must be closed"
    )
    require(
        tracker.get("required_labels") == ["symphony", "dispatch:enabled"],
        "workflow: require symphony and dispatch:enabled labels",
    )
    require(
        value.get("workspace") == {"root": "$SYMPHONY_WORKSPACE_ROOT"},
        "workflow: use the dedicated $SYMPHONY_WORKSPACE_ROOT",
    )
    agent = value.get("agent", {})
    require(
        type(agent) is dict
        and type(agent.get("max_concurrent_agents")) is int
        and agent["max_concurrent_agents"] == 2,
        "workflow: concurrency must remain two",
    )
    require(
        type(agent.get("max_turns")) is int and 1 <= agent["max_turns"] <= 10,
        "workflow: max_turns must be an integer from 1 to 10",
    )
    codex = value.get("codex", {})
    require(
        codex
        == {
            "command": "rtk proxy codex app-server",
            "approval_policy": "never",
            "thread_sandbox": "workspace-write",
        },
        "workflow.codex: retain the reviewed Codex app-server/sandbox configuration",
    )
    hooks = value.get("hooks", {})
    require(
        type(hooks) is dict and set(hooks) == {"after_create", "before_run"},
        "workflow.hooks: no unreviewed executable hooks",
    )
    require(
        type(hooks) is dict
        and hooks.get("after_create")
        == f"rtk proxy git clone --single-branch --branch main https://github.com/{REPOSITORY}.git .",
        "workflow.after_create: clone public main into a fresh issue workspace",
    )
    require(
        hooks.get("before_run")
        == "rtk proxy python3 scripts/check_project_management.py --repo . --require-live-claim",
        "workflow.before_run: require the reviewed live-claim gate",
    )


def plan_contract(text):
    fence = chr(96) * 3
    blocks = re.findall(
        re.escape(fence) + r"json task-contract\n(.*?)\n" + re.escape(fence), text, flags=re.DOTALL
    )
    require(len(blocks) == 1, "active plan: expected exactly one json task-contract block")
    value = decode_json(blocks[0])
    require(
        type(value) is dict and set(value) == {"tasks", "manual_claims"},
        "active plan: expected tasks and explicit manual_claims",
    )
    claims = value["manual_claims"]
    require(
        type(claims) is list
        and len(claims) <= 32
        and all(type(number) is int and number > 0 for number in claims)
        and len(set(claims)) == len(claims),
        "active plan: invalid manual claim numbers",
    )
    return value


def plan_tasks(text):
    return plan_contract(text)["tasks"]


def issue_number(url):
    require(
        type(url) is str
        and len(url) <= 200
        and re.fullmatch(re.escape(ISSUE_URL) + r"[1-9]\d*", url),
        "task issue: use an actual same-repository issue URL",
    )
    return int(url.rsplit("/", 1)[1])


def check_tasks(tasks):
    require(type(tasks) is list and 1 <= len(tasks) <= 32, "plan: require 1 to 32 tasks")
    by_id = {}
    for task in tasks:
        require(type(task) is dict and set(task) == FIELDS, "task: fields must match the contract")
        task_id = task["id"]
        require(
            type(task_id) is str and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", task_id),
            "task.id: use a bounded lowercase identifier",
        )
        require(task_id not in by_id, f"task {task_id}: duplicate id")
        by_id[task_id] = task
        require(
            type(task["title"]) is str and 0 < len(task["title"].strip()) <= 240,
            f"task {task_id}: title is empty or too long",
        )
        require(
            task["owner"] in ("Codex", "Claude")
            and task["reviewer"] in ("Codex", "Claude")
            and task["owner"] != task["reviewer"],
            f"task {task_id}: assign distinct Codex/Claude owner and reviewer",
        )
        require(
            type(task["status"]) is str and task["status"] in STATUSES,
            f"task {task_id}: unsupported status",
        )
        if task["issue"] is None:
            require(
                task["status"] in {"backlog", "blocked"},
                f"task {task_id}: pending issue cannot be ready/active/review",
            )
        else:
            issue_number(task["issue"])
        for field in ("acceptance", "validation", "evidence"):
            items = task[field]
            require(
                type(items) is list
                and len(items) <= 32
                and (items or field == "evidence")
                and all(type(item) is str and 0 < len(item.strip()) <= 2048 for item in items),
                f"task {task_id}: {field} must contain bounded meaningful text",
            )
        dependencies = task["dependencies"]
        require(
            type(dependencies) is list
            and len(dependencies) <= 32
            and all(type(item) is str for item in dependencies)
            and len(set(dependencies)) == len(dependencies),
            f"task {task_id}: dependencies must be distinct task ids",
        )
    visiting, visited = set(), set()

    def visit(task_id):
        require(task_id not in visiting, f"task {task_id}: dependency cycle")
        if task_id in visited:
            return
        visiting.add(task_id)
        for dependency in by_id[task_id]["dependencies"]:
            require(dependency in by_id, f"task {task_id}: dependency {dependency} is missing")
            visit(dependency)
        visiting.remove(task_id)
        visited.add(task_id)

    for task_id in by_id:
        visit(task_id)


def check_links(root):
    root = Path(root).resolve()
    for name in DOCUMENTS:
        text = read_text(root / name)
        for match in re.finditer(r"\[[^\]\n]+\]\(([^)\n]+)\)", text):
            href = match.group(1).strip("<>")
            parsed = urlsplit(href)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            target = (root / name).parent / unquote(parsed.path)
            resolved = target.resolve()
            require(
                resolved == root or root in resolved.parents,
                f"{name}: local link escapes the repository",
            )
            require(resolved.exists(), f"{name}: broken local link to {parsed.path}")


def check_repo(root):
    root = Path(root).resolve()
    require(
        len(read_text(root / "AGENTS.md").splitlines()) < 100,
        "AGENTS.md: keep the map under 100 lines",
    )
    check_config(workflow_config(read_text(root / "WORKFLOW.md")))
    tasks = plan_tasks(read_text(root / PLAN))
    check_tasks(tasks)
    numbers = [issue_number(task["issue"]) for task in tasks if task["issue"] is not None]
    require(len(numbers) == len(set(numbers)), "plan: issue identity is assigned twice")
    claims = plan_contract(read_text(root / PLAN))["manual_claims"]
    require(set(claims) <= set(numbers), "plan: manual claim lacks a registered issue")
    check_links(root)
    return tasks


def issue_contract(body):
    require(
        type(body) is str and len(body.encode("utf-8")) <= 65536,
        "issue body: expected at most 64 KiB",
    )
    headings = list(re.finditer(r"^##\s+(.+?)\s*$", body, re.MULTILINE))
    sections = {}
    for index, heading in enumerate(headings):
        name = heading.group(1)
        if name in SECTIONS:
            require(name not in sections, f"issue: duplicate {name} heading")
            end = headings[index + 1].start() if index + 1 < len(headings) else len(body)
            sections[name] = body[heading.end() : end].strip()
    for name in SECTIONS:
        require(bool(sections.get(name)), f"issue: add nonempty {name} section")
    owners = {}
    for field, label in (("owner", "Implementation lead"), ("reviewer", "Independent reviewer")):
        matches = re.findall(
            r"^\s*(?:[-*]\s*)?" + label + r":\s*(Codex|Claude)\s*$",
            sections["Ownership"],
            re.MULTILINE,
        )
        require(len(matches) == 1, f"issue Ownership: add one {label}: Codex or Claude line")
        owners[field] = matches[0]
    require(owners["owner"] != owners["reviewer"], "issue Ownership: reviewer must be independent")
    require(
        re.search(r"^\s*[-*]\s+\[[ xX]\]\s+\S", sections["Acceptance criteria"], re.MULTILINE),
        "issue Acceptance criteria: add a concrete checklist",
    )
    text = sections["Dependencies"]
    urls = re.findall(r"https://github\.com/[^/\s)]+/[^/\s)]+/issues/\d+", text)
    require(
        all(url.startswith(ISSUE_URL) for url in urls),
        "issue Dependencies: only this repository is supported",
    )
    dependencies = {issue_number(url) for url in urls}
    bare_reference = r"(?<![\w/.-])#([1-9]\d*)\b"
    require(
        not re.search(r"#\d|\bGH-\d+\b", re.sub(bare_reference, "", text), re.IGNORECASE),
        "issue Dependencies: unsupported issue-reference form; use bare #N or canonical issue URLs",
    )
    dependencies.update(int(n) for n in re.findall(bare_reference, text))
    require(
        dependencies or re.match(r"^None(?:[.\s]|$)", text, re.IGNORECASE),
        "issue Dependencies: use None or explicit same-repository issue references",
    )
    require(
        not (dependencies and re.match(r"^None(?:[.\s]|$)", text, re.IGNORECASE)),
        "issue Dependencies: None conflicts with explicit issue references",
    )
    return owners, dependencies


def check_issue_snapshot(value, *, now=None):
    require(
        type(value) is dict
        and set(value) == {"repository", "observed_at", "issue", "dependencies"},
        "snapshot: expected repository, observed_at, issue and dependencies",
    )
    require(value["repository"] == REPOSITORY, "snapshot: wrong repository")
    observed = value["observed_at"]
    require(type(observed) is str and len(observed) <= 64, "snapshot: invalid observation time")
    try:
        observed = datetime.fromisoformat(observed)
    except ValueError as error:
        raise ManagementError("snapshot: use an actual timezone-aware observation time") from error
    require(observed.tzinfo is not None, "snapshot: observation time needs a timezone")
    now = now or datetime.now(UTC)
    age = (now - observed).total_seconds()
    require(-5 <= age <= 300, "snapshot: stale/future data; fetch actual issues again")
    issue = value["issue"]
    require(
        type(issue) is dict and type(issue.get("number")) is int and issue["number"] > 0,
        "snapshot issue: require a positive issue number",
    )
    require(issue_number(issue.get("html_url")) == issue["number"], "snapshot issue: URL mismatch")
    require(
        issue.get("state") == "open" and "pull_request" not in issue,
        "snapshot: only an open issue can dispatch",
    )
    require(
        type(issue.get("title")) is str and bool(issue["title"].strip()),
        "snapshot issue: title is required",
    )
    require(
        type(issue.get("assignee")) is dict and issue["assignee"].get("login") == "utkutugrul",
        "snapshot issue: human assignee must be utkutugrul",
    )
    raw_labels = issue.get("labels")
    require(type(raw_labels) is list and len(raw_labels) <= 64, "snapshot issue: invalid labels")
    labels = set()
    for item in raw_labels:
        name = item.get("name") if type(item) is dict else item
        require(type(name) is str and len(name) <= 100, "snapshot issue: invalid label name")
        labels.add(name.strip().lower())
    status = {label for label in labels if label.startswith("status:")}
    require(status <= {"status:" + name for name in STATUSES}, "snapshot: unsupported status label")
    require(len(status) == 1, "snapshot: require exactly one status label")
    require(
        {"symphony", "dispatch:enabled"} <= labels, "snapshot: explicit dispatch labels missing"
    )
    require(
        status <= {"status:ready", "status:active"},
        "snapshot: blocked/backlog/review must lose dispatch:enabled",
    )
    owners, expected = issue_contract(issue.get("body"))
    for field, prefix in (("owner", "owner:"), ("reviewer", "review:")):
        actual = {label for label in labels if label.startswith(prefix)}
        require(
            actual == {prefix + owners[field].lower()}, f"snapshot: {field} role label mismatch"
        )
    require(issue["number"] not in expected, "snapshot: issue cannot depend on itself")
    dependencies = value["dependencies"]
    require(
        type(dependencies) is list and len(dependencies) <= 32,
        "snapshot: dependencies must be a bounded list",
    )
    seen = set()
    for dependency in dependencies:
        require(
            type(dependency) is dict and type(dependency.get("number")) is int,
            "snapshot dependency: missing issue number",
        )
        number = dependency["number"]
        require(number not in seen, "snapshot: duplicate dependency")
        require(number in expected, "snapshot: unexpected dependency response")
        require(
            issue_number(dependency.get("html_url")) == number,
            "snapshot dependency: wrong repository/URL",
        )
        require(dependency.get("state") == "closed", f"dependency GH-{number}: still open/unknown")
        seen.add(number)
    require(seen == expected, "snapshot: fetch every actual dependency before dispatch")
    return issue["number"]


def check_live_claim(value, *, expected_issue, manual_claims, tasks, now=None):
    number = check_issue_snapshot(value, now=now)
    require(
        type(expected_issue) is int and number == expected_issue,
        "live claim: workspace issue mismatch",
    )
    require(
        number not in manual_claims,
        f"live claim GH-{number}: manual owner still active; explicit handoff required",
    )
    registered = {issue_number(task["issue"]): task for task in tasks if task["issue"] is not None}
    require(number in registered, "live claim: issue is not registered in the active plan")
    task = registered[number]
    owners, dependencies = issue_contract(value["issue"]["body"])
    require(
        owners == {field: task[field] for field in ("owner", "reviewer")},
        "live claim: roles differ from the versioned plan",
    )
    by_id = {entry["id"]: entry for entry in tasks}
    planned_dependencies = set()
    for dependency in task["dependencies"]:
        entry = by_id[dependency]
        require(
            entry["issue"] is not None,
            "live claim: a planned dependency has no registered issue",
        )
        planned_dependencies.add(issue_number(entry["issue"]))
    require(
        dependencies == planned_dependencies,
        "live claim: dependencies differ from the versioned plan",
    )
    return number


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise ManagementError("live GitHub: redirects are refused")


@contextmanager
def _live_deadline(enabled):
    if not enabled:
        yield
        return
    require(
        all(hasattr(signal, name) for name in ("SIGALRM", "ITIMER_REAL", "setitimer")),
        "live GitHub: standalone POSIX deadline support is required",
    )
    require(
        signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
        "live GitHub: another process timer is already active",
    )

    def expired(_signum, _frame):
        raise ManagementError("live GitHub: absolute ten-second deadline exceeded")

    try:
        previous = signal.signal(signal.SIGALRM, expired)
    except ValueError:
        raise ManagementError(
            "live GitHub: run this gate as a standalone main-thread process"
        ) from None
    try:
        signal.setitimer(signal.ITIMER_REAL, 10)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def fetch_live_snapshot(number, *, token, open_url=None, clock=time.monotonic, now=None):
    """One read-only bounded fixed-host fetch; explicit credential only."""
    require(type(number) is int and 0 < number <= 2**53 - 1, "live GitHub: invalid issue number")
    require(
        type(token) is str
        and 1 <= len(token) <= 4096
        and token.isascii()
        and not any(ord(char) <= 32 or ord(char) == 127 for char in token),
        "live GitHub: set a valid explicit SYMPHONY_GITHUB_TOKEN",
    )
    real_transport = open_url is None
    if real_transport:
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        open_url = opener.open
    with _live_deadline(real_transport):
        began = clock()
        observed = now or datetime.now(UTC)
        total = 0

        def fetch(current):
            nonlocal total
            remaining = 10 - (clock() - began)
            require(remaining > 0, "live GitHub: aggregate deadline exceeded")
            request = Request(
                f"https://api.github.com/repos/{REPOSITORY}/issues/{current}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "ReviewBoundary-Symphony-gate",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                method="GET",
            )
            try:
                with open_url(request, timeout=min(5, remaining)) as response:
                    raw = response.read(65537)
            except HTTPError as error:
                raise ManagementError(
                    f"live GitHub: HTTP {error.code}; no response details retained"
                ) from None
            except (URLError, TimeoutError, OSError):
                raise ManagementError(
                    "live GitHub: bounded request failed; no details retained"
                ) from None
            require(len(raw) <= 65536, "live GitHub: response exceeds 64 KiB")
            total += len(raw)
            require(total <= MAX_INPUT, "live GitHub: responses exceed 256 KiB aggregate")
            require(clock() - began <= 10, "live GitHub: aggregate deadline exceeded")
            try:
                value = decode_json(raw.decode("utf-8"))
            except (ValueError, UnicodeError):
                raise ManagementError(
                    "live GitHub: invalid JSON response; details omitted"
                ) from None
            require(
                type(value) is dict
                and type(value.get("number")) is int
                and value["number"] == current,
                "live GitHub: response issue identity mismatch",
            )
            require(
                value.get("html_url") == ISSUE_URL + str(current),
                "live GitHub: response repository/URL mismatch",
            )
            return value

        actual = fetch(number)
        _, dependencies = issue_contract(actual.get("body"))
        require(
            len(dependencies) <= 32 and number not in dependencies,
            "live GitHub: invalid dependency roster",
        )
        issue = {
            key: actual.get(key)
            for key in ("number", "html_url", "state", "title", "body", "labels", "assignee")
        }
        if "pull_request" in actual:
            issue["pull_request"] = {}
        observed_dependencies = []
        for dependency in sorted(dependencies):
            actual_dependency = fetch(dependency)
            observed_dependencies.append(
                {key: actual_dependency.get(key) for key in ("number", "html_url", "state")}
            )
        return {
            "repository": REPOSITORY,
            "observed_at": observed.isoformat(),
            "issue": issue,
            "dependencies": observed_dependencies,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--issue-snapshot", type=Path)
    parser.add_argument("--require-live-claim", action="store_true")
    args = parser.parse_args(argv)
    try:
        tasks = check_repo(args.repo)
        if args.issue_snapshot or args.require_live_claim:
            workspace = Path(args.repo).resolve()
            match = re.fullmatch(r"GH-([1-9]\d*)", workspace.name)
            require(match is not None, "live claim: use the actual native GH-N issue workspace")
            expected_issue = int(match.group(1))
            require(
                expected_issue
                in {issue_number(task["issue"]) for task in tasks if task["issue"] is not None},
                "live claim: workspace issue is not registered in the active plan",
            )
            claims = plan_contract(read_text(workspace / PLAN))["manual_claims"]
            require(
                expected_issue not in claims,
                f"live claim GH-{expected_issue}: manual owner still active; explicit handoff required",
            )
            if args.issue_snapshot:
                data = decode_json(read_text(args.issue_snapshot))
            else:
                data = fetch_live_snapshot(
                    expected_issue, token=os.environ.get("SYMPHONY_GITHUB_TOKEN", "")
                )
            number = check_live_claim(
                data, expected_issue=expected_issue, manual_claims=claims, tasks=tasks
            )
            print(f"Repository contracts OK; supplied GH-{number} data passes live-claim checks.")
            print("This does not authenticate GitHub data or authorize promotion.")
        else:
            print(f"Repository contracts OK ({len(tasks)} tasks); dispatch NOT checked.")
        return 0
    except (ManagementError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"project management: {str(error)[:1000]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
