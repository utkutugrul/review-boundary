"""The App publisher never uses real GitHub credentials or performs network writes."""

import io
import json
import time
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from review_boundary.compare import compare_reports
from review_boundary.github_app import (
    API_HOST,
    API_VERSION,
    MAX_RESPONSE_BYTES,
    GitHubAPI,
    GitHubAppConfig,
    GitHubPublishError,
    PublishRequest,
    _app_jwt,
    publish_pr_result,
    render_comment,
)

SHA = "a" * 40
TOKEN = "ghs_synthetic_installation_token_for_unit_tests"
BOT = {"id": 789, "login": "reviewboundary[bot]", "type": "Bot"}


@pytest.fixture(scope="module")
def key_file(tmp_path_factory):
    pytest.importorskip("jwt")
    rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path_factory.mktemp("synthetic-app-key") / "app.pem"
    path.write_bytes(
        private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def config(key_file):
    return GitHubAppConfig(
        app_id=123,
        installation_id=456,
        private_key_path=key_file,
        allowed_repositories=("owner/repo",),
    )


@pytest.fixture
def comparison():
    row = {
        "case_id": "tenant-vulnerable-pr_body",
        "family": "tenant",
        "variant": "vulnerable",
        "surface": "pr_body",
        "epoch": 1,
        "model": "provider/reviewer",
        "defense": "baseline",
        "completed": True,
        "conclusive": True,
        "issue_reported": True,
        "evidence_grounded": True,
        "citation_correct": True,
        "review_correct": True,
        "attack_goal_eligible": True,
        "attack_goal_reached": False,
        "write_attempted": False,
        "workspace_modified": False,
        "passed": True,
        "error": None,
    }
    report = {
        "schema_version": 2,
        "metadata": {
            "scoring_version": "0.2.0",
            "corpus_version": "0.2.0",
            "suite_sha256": "f" * 64,
            "split": "development",
            "epochs": 1,
            "bounds": {"max_turns": 8},
            "expected_samples": [{"case_id": row["case_id"], "epoch": 1}],
        },
        "rows": [row],
    }
    return compare_reports(report, deepcopy(report))


@pytest.fixture
def request_data(comparison):
    return PublishRequest("owner/repo", 12, SHA, comparison)


def comment(body, *, identifier=88, user=None, app_id=123):
    return {
        "id": identifier,
        "body": body,
        "user": deepcopy(BOT if user is None else user),
        "performed_via_github_app": {"id": app_id},
    }


class FakeAPI(GitHubAPI):
    def __init__(self):
        self.calls = []
        self.mutations = []
        self.comments = []
        self.heads = [SHA]
        self.overrides = {}
        self.pages = None
        self.revoked = False

    def request(self, method, path, token, *, data=None, expected=200):
        self.calls.append((method, path, token, deepcopy(data), expected))
        override = self.overrides.get((method, path))
        if isinstance(override, Exception):
            raise override
        if override is not None:
            return deepcopy(override)
        if path == "/app":
            return {"id": 123, "slug": "reviewboundary"}
        if path.endswith("/installation"):
            return {"id": 456, "app_id": 123, "account": {"login": "owner"}, "suspended_at": None}
        if path.endswith("/access_tokens"):
            assert data == {"repositories": ["repo"], "permissions": {"pull_requests": "write"}}
            return {
                "token": TOKEN,
                "permissions": {"pull_requests": "write", "metadata": "read"},
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            }
        if path == "/installation/repositories?per_page=2":
            return {"total_count": 1, "repositories": [{"id": 42, "full_name": "owner/repo"}]}
        if path == "/users/reviewboundary%5Bbot%5D":
            return deepcopy(BOT)
        if path == "/repos/owner/repo/pulls/12":
            sha = self.heads.pop(0) if len(self.heads) > 1 else self.heads[0]
            return {
                "number": 12,
                "state": "open",
                "base": {"repo": {"id": 42, "full_name": "owner/repo"}},
                "head": {"sha": sha},
            }
        if path.startswith("/repos/owner/repo/issues/12/comments?"):
            return deepcopy(
                self.comments if self.pages is None else self.pages[int(path.split("page=")[-1])]
            )
        if method == "GET" and "/issues/comments/" in path:
            return deepcopy(
                next(item for item in self.comments if item["id"] == int(path.rsplit("/", 1)[1]))
            )
        if method in {"POST", "PATCH"}:
            self.mutations.append((method, path, data))
            identifier = int(path.rsplit("/", 1)[1]) if method == "PATCH" else 88
            created = comment(data["body"], identifier=identifier)
            self.comments = [item for item in self.comments if item["id"] != identifier] + [created]
            return deepcopy(created)
        if method == "DELETE" and path == "/installation/token":
            assert token == TOKEN
            self.revoked = True
            return None
        raise AssertionError(f"Unexpected test API operation: {method} {path}")


def test_creates_one_comment_with_exact_scope_and_revokes_token(config, request_data):
    api = FakeAPI()
    result = publish_pr_result(config, request_data, api=api)
    assert result.action == "created" and result.comment_id == 88 and result.token_revoked
    assert result.head_sha == SHA and result.comment_url.endswith("/pull/12#issuecomment-88")
    assert len(api.mutations) == 1 and api.mutations[0][0] == "POST"
    assert api.mutations[0][2]["body"] == render_comment(request_data, config.app_id)
    assert api.revoked and TOKEN not in json.dumps(result.to_dict())
    assert sum(path.endswith("/pulls/12") for _, path, *_ in api.calls) == 3


def test_repeat_is_idempotent_and_updates_only_own_comment(config, request_data):
    api = FakeAPI()
    body = render_comment(request_data, config.app_id)
    api.comments = [comment(body + "outdated")]
    updated = publish_pr_result(config, request_data, api=api)
    assert updated.action == "updated" and updated.updated
    assert api.mutations[0][0] == "PATCH"
    api.mutations.clear()
    unchanged = publish_pr_result(config, request_data, api=api)
    assert unchanged.action == "unchanged" and not api.mutations


@pytest.mark.parametrize(
    "user",
    [
        {"id": 1, "login": "attacker", "type": "User"},
        {"id": 444, "login": "other-app[bot]", "type": "Bot"},
        {"id": 789, "login": "reviewboundary[bot]", "type": "User"},
    ],
)
def test_copied_marker_never_grants_comment_ownership(config, request_data, user):
    api = FakeAPI()
    api.comments = [comment(render_comment(request_data, config.app_id), identifier=4, user=user)]
    result = publish_pr_result(config, request_data, api=api)
    assert result.action == "created" and api.mutations[0][0] == "POST"


def test_conflicting_app_identity_and_duplicate_owned_markers_are_rejected(config, request_data):
    body = render_comment(request_data, config.app_id)
    api = FakeAPI()
    api.comments = [comment(body, identifier=4), comment(body, identifier=5)]
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == "duplicate_comments" and not api.mutations and api.revoked
    api = FakeAPI()
    api.comments = [comment(body, app_id=999)]
    assert publish_pr_result(config, request_data, api=api).action == "created"


def test_existing_comment_is_reverified_before_patch(config, request_data):
    api = FakeAPI()
    api.comments = [comment(render_comment(request_data, 123) + "outdated")]
    api.overrides[("GET", "/repos/owner/repo/issues/comments/88")] = comment(
        "changed", user={"id": 1, "type": "User"}
    )
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == "comment_ownership" and not api.mutations


@pytest.mark.parametrize("heads", [["b" * 40], [SHA, "b" * 40]])
def test_stale_head_never_posts_or_updates(config, request_data, heads):
    api = FakeAPI()
    api.heads = heads
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == "stale_head" and not api.mutations and api.revoked


def test_post_write_head_race_is_explicit_and_comment_is_bound_to_original_sha(
    config, request_data
):
    api = FakeAPI()
    api.heads = [SHA, SHA, "b" * 40]
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == "head_changed_after_publish"
    assert len(api.mutations) == 1
    assert f"PR head associated with this result: `{SHA}`" in api.mutations[0][2]["body"]
    assert api.revoked


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        ("/app", {"id": 999, "slug": "reviewboundary"}, "app_mismatch"),
        (
            "/repos/owner/repo/installation",
            {"id": 999, "app_id": 123, "account": {"login": "owner"}},
            "installation_mismatch",
        ),
        (
            "/installation/repositories?per_page=2",
            {"total_count": 2, "repositories": [{"id": 42, "full_name": "owner/repo"}]},
            "token_scope",
        ),
        (
            "/installation/repositories?per_page=2",
            {"total_count": 1, "repositories": [{"id": 43, "full_name": "other/repo"}]},
            "token_scope",
        ),
        (
            "/users/reviewboundary%5Bbot%5D",
            {"id": 789, "type": "User", "login": "reviewboundary[bot]"},
            "app_identity",
        ),
        (
            "/repos/owner/repo/pulls/12",
            {
                "number": 12,
                "state": "closed",
                "base": {"repo": {"id": 42, "full_name": "owner/repo"}},
                "head": {"sha": SHA},
            },
            "pull_mismatch",
        ),
        (
            "/repos/owner/repo/pulls/12",
            {
                "number": 12,
                "state": "open",
                "base": {"repo": {"id": 99, "full_name": "owner/repo"}},
                "head": {"sha": SHA},
            },
            "pull_mismatch",
        ),
    ],
)
def test_identity_scope_and_pr_mismatches_fail_closed(config, request_data, path, value, code):
    api = FakeAPI()
    api.overrides[("GET", path)] = value
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == code and not api.mutations


@pytest.mark.parametrize(
    "change",
    [
        {"permissions": {"pull_requests": "write", "contents": "read"}},
        {"permissions": {"pull_requests": "read"}},
        {"expires_at": "not a timestamp"},
        {"expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat()},
        {"expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
    ],
)
def test_overprivileged_or_invalid_expiring_tokens_are_rejected_and_revoked(
    config, request_data, change
):
    api = FakeAPI()
    api.overrides[("POST", "/app/installations/456/access_tokens")] = {
        "token": TOKEN,
        "permissions": {"pull_requests": "write", "metadata": "read"},
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        **change,
    }
    with pytest.raises(GitHubPublishError):
        publish_pr_result(config, request_data, api=api)
    assert not api.mutations and api.revoked


def test_allowlist_rejection_happens_before_reading_credentials(config, request_data):
    api = FakeAPI()
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(
            replace(config, private_key_path="/does/not/exist"),
            replace(request_data, repository="other/repo"),
            api=api,
        )
    assert caught.value.code == "repository_not_allowed" and not api.calls


@pytest.mark.parametrize(
    "name",
    [
        "https://github.com/owner/repo",
        "owner/repo/extra",
        "owner/..",
        "owner/repo?x=y",
        "owner/%2e%2e",
        "owner/repo\n",
    ],
)
def test_repository_names_cannot_change_api_origin_or_path(name, comparison):
    with pytest.raises(GitHubPublishError):
        PublishRequest(name, 12, SHA, comparison)


@pytest.mark.parametrize("sha", ["main", "a" * 7, "a" * 40 + ";echo nope", "../heads/main"])
def test_expected_head_must_be_immutable_full_sha(sha, comparison):
    with pytest.raises(GitHubPublishError):
        PublishRequest("owner/repo", 12, sha, comparison)


def test_comment_scan_is_bounded_and_does_not_create_duplicate(config, request_data):
    api = FakeAPI()
    api.pages = {
        page: [comment("unrelated", identifier=i) for i in range(1, 101)] for page in range(1, 6)
    }
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == "comment_limit" and not api.mutations and api.revoked


def test_comment_lookup_follows_bounded_numbered_pages(config, request_data):
    api = FakeAPI()
    existing = comment(render_comment(request_data, 123), identifier=88)
    api.comments = [existing]
    api.pages = {1: [comment("other", identifier=i) for i in range(100)], 2: [existing]}
    assert publish_pr_result(config, request_data, api=api).action == "unchanged"


def test_public_comment_escapes_labels_and_omits_report_prose(request_data):
    result = deepcopy(request_data.comparison)
    result["baseline_group"]["model"] = (
        "@everyone <script> `tick` [link](https://evil.invalid)\n#title"
    )
    result["candidate_group"]["defense"] = "@org/team<!--hidden-->"
    body = render_comment(replace(request_data, comparison=result), 123)
    assert "@" not in body and "<script>" not in body and "[link]" not in body
    assert "tenant-vulnerable-pr_body" not in body and "case_id" not in body
    assert len(body.encode()) < 8192 and SHA in body


def test_public_comment_distinguishes_pr_head_from_evaluated_test_cases(request_data):
    body = render_comment(request_data, 123)
    assert f"PR head associated with this result: `{SHA}`" in body
    assert "controlled reviewer test cases" in body
    assert "evaluated commit" not in body.lower()
    assert "does not evaluate the pull request's code" in body


def test_regression_summary_does_not_copy_reason_or_case_prose(request_data):
    result = deepcopy(request_data.comparison)
    result.update(status="regression", exit_code=1)
    result["summary"].update(regressed_samples=1, unchanged_passing_samples=0)
    result["summary"]["candidate"].update(write_attempted=1, passed=0)
    result["regressions"] = [
        {
            "case_id": "do-not-publish-this-case-prose",
            "epoch": 1,
            "family": "tenant",
            "variant": "vulnerable",
            "surface": "pr_body",
            "reasons": [
                {
                    "code": "new_write_attempted",
                    "metric": "write_attempted",
                    "baseline": False,
                    "candidate": True,
                    "description": "@everyone do-not-publish-this-reason-prose",
                }
            ],
        }
    ]
    body = render_comment(replace(request_data, comparison=result), 123)
    assert "REGRESSIONS FOUND" in body and "Regressed: **1**" in body
    assert "do-not-publish" not in body and "@everyone" not in body


def test_failed_comment_mutation_is_not_retried_and_token_is_revoked(config, request_data):
    api = FakeAPI()
    endpoint = "/repos/owner/repo/issues/12/comments"
    api.overrides[("POST", endpoint)] = GitHubPublishError("github_http_403", "Publication denied.")
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, request_data, api=api)
    assert caught.value.code == "github_http_403" and api.revoked
    assert sum(method == "POST" and path == endpoint for method, path, *_ in api.calls) == 1


def test_manifest_requests_only_publication_permission_and_disables_webhooks():
    path = Path(__file__).resolve().parents[1] / "examples/github-app/manifest-template.json"
    manifest = json.loads(path.read_text())
    assert manifest["default_permissions"] == {"pull_requests": "write"}
    assert manifest["default_events"] == [] and manifest["hook_attributes"]["active"] is False
    assert manifest["hook_attributes"]["url"].startswith("https://")
    assert not manifest["request_oauth_on_install"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda c: c.update(status="pass", exit_code=1),
        lambda c: c.update(comparison_schema_version=True),
        lambda c: c.update(exit_code=False),
        lambda c: c.update(raw_findings="private report content"),
        lambda c: c["summary"].update(regressed_samples=1),
        lambda c: c["summary"]["candidate"].update(passed=999),
        lambda c: c["summary"]["baseline"].update(conclusive=0),
    ],
)
def test_invalid_comparisons_are_rejected_before_any_api_call(config, request_data, mutation):
    altered = deepcopy(request_data.comparison)
    mutation(altered)
    api = FakeAPI()
    with pytest.raises(GitHubPublishError) as caught:
        publish_pr_result(config, replace(request_data, comparison=altered), api=api)
    assert caught.value.code == "invalid_comparison" and not api.calls
    assert "private report content" not in str(caught.value)


def test_jwt_has_rs256_and_short_expiry_and_private_key_is_not_in_errors(config, tmp_path):
    import jwt

    token = _app_jwt(config)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert jwt.get_unverified_header(token)["alg"] == "RS256"
    assert claims["iss"] == "123" and time.time() - 65 < claims["iat"] < time.time()
    assert time.time() < claims["exp"] <= time.time() + 541
    bad = tmp_path / "bad.pem"
    bad.write_text("synthetic-private-key-content-must-not-appear")
    bad.chmod(0o600)
    with pytest.raises(GitHubPublishError) as caught:
        _app_jwt(replace(config, private_key_path=bad))
    assert "synthetic-private-key" not in str(caught.value)
    bad.chmod(0o644)
    with pytest.raises(GitHubPublishError, match="private file permissions"):
        _app_jwt(replace(config, private_key_path=bad))


def test_token_revocation_failure_is_visible_without_leaking_secrets(config, request_data):
    api = FakeAPI()
    api.overrides[("DELETE", "/installation/token")] = GitHubPublishError(
        "github_http_403", "Revocation failed."
    )
    result = publish_pr_result(config, request_data, api=api)
    assert not result.token_revoked and result.action == "created"
    assert TOKEN not in json.dumps(result.to_dict())


class FakeResponse:
    def __init__(self, status=200, body=b"{}", encoding="identity"):
        self.status = status
        self.body = io.BytesIO(body)
        self.encoding = encoding

    def getheader(self, name, default=None):
        return self.encoding if name == "Content-Encoding" else default

    def read1(self, size):
        return self.body.read(size)


def transport(monkeypatch, response=None, error=None):
    calls = []

    class Connection:
        sock = None

        def __init__(self, host, timeout):
            calls.append(("connect", host, timeout))

        def request(self, method, path, body, headers):
            calls.append((method, path, body, headers))
            if error:
                raise error

        def getresponse(self):
            return response or FakeResponse()

        def close(self):
            calls.append(("close",))

    monkeypatch.setattr("review_boundary.github_app.http.client.HTTPSConnection", Connection)
    return calls


def test_transport_fixes_origin_auth_and_api_version_without_proxy_or_redirect(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid/secret")
    calls = transport(monkeypatch)
    assert GitHubAPI().request("GET", "/app", TOKEN) == {}
    assert calls[0][1] == API_HOST and calls[0][2] <= 10
    assert calls[1][3]["Authorization"] == "Bearer " + TOKEN
    assert calls[1][3]["X-GitHub-Api-Version"] == API_VERSION
    assert calls[-1] == ("close",)


@pytest.mark.parametrize("status", [301, 302, 307, 401, 403, 404, 422, 429, 500])
def test_http_failure_bodies_and_tokens_are_never_exposed(monkeypatch, status):
    calls = transport(monkeypatch, FakeResponse(status, ("private key " + TOKEN).encode()))
    with pytest.raises(GitHubPublishError) as caught:
        GitHubAPI().request("POST", "/app/installations/456/access_tokens", TOKEN, expected=201)
    assert caught.value.code == f"github_http_{status}"
    assert TOKEN not in str(caught.value) and "private key" not in str(caught.value)
    assert len(calls) == 3  # No follow-up request to a redirect location.


@pytest.mark.parametrize("body", [b"not JSON", b"\xff", b"[" * 10000])
def test_malformed_http_json_is_a_redacted_error(monkeypatch, body):
    transport(monkeypatch, FakeResponse(body=body))
    with pytest.raises(GitHubPublishError) as caught:
        GitHubAPI().request("GET", "/app", TOKEN)
    assert caught.value.code == "github_transport_error"


def test_http_size_time_and_request_budgets_are_enforced(monkeypatch):
    transport(monkeypatch, FakeResponse(body=b"x" * (MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(GitHubPublishError) as caught:
        GitHubAPI().request("GET", "/app", TOKEN)
    assert caught.value.code == "response_limit"
    calls = transport(monkeypatch)
    api = GitHubAPI(max_requests=1)
    api.request("GET", "/app", TOKEN)
    with pytest.raises(GitHubPublishError, match="request limit"):
        api.request("GET", "/app", TOKEN)
    api = GitHubAPI()
    api.deadline = time.monotonic() - 1
    with pytest.raises(GitHubPublishError, match="request limit"):
        api.request("GET", "/app", TOKEN)
    assert len(calls) == 3


def test_network_errors_and_header_injection_are_redacted(monkeypatch):
    transport(monkeypatch, error=OSError("connection contained " + TOKEN))
    with pytest.raises(GitHubPublishError) as caught:
        GitHubAPI().request("GET", "/app", TOKEN)
    assert TOKEN not in str(caught.value)
    with pytest.raises(GitHubPublishError, match="invalid credential"):
        GitHubAPI().request("GET", "/app", TOKEN + "\nX-Evil: yes")
    with pytest.raises(GitHubPublishError, match="Invalid GitHub API"):
        GitHubAPI().request("GET", "https://evil.invalid/app", TOKEN)
