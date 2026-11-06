"""Publish a bounded comparison summary as an installation-scoped GitHub App.

This module never checks out or executes repository code. Call it only from a
trusted reporting job, with an expected commit obtained from trusted run metadata.
"""

from __future__ import annotations

import http.client
import json
import re
import stat
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field, JsonValue, ValidationError, model_validator

API_HOST = "api.github.com"
API_VERSION = "2026-03-10"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_COMPARISON_BYTES = 2 * 1024 * 1024
MAX_COMMENT_PAGES = 5
POLICY = "zero_new_regressions; citation_precision_informational"


class GitHubPublishError(ValueError):
    """A safe public error. Never include API bodies, tokens, or key material."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _positive_id(value: Any) -> bool:
    return type(value) is int and 0 < value < 2**63


def _repository(value: str) -> str:
    if (
        not isinstance(value, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.-]{1,100}", value)
        or value.rsplit("/", 1)[-1] in {".", ".."}
    ):
        raise GitHubPublishError("invalid_repository", "Use an exact owner/repository name.")
    return value.lower()


@dataclass(frozen=True)
class GitHubAppConfig:
    app_id: int
    installation_id: int
    private_key_path: Path
    allowed_repositories: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _positive_id(self.app_id) or not _positive_id(self.installation_id):
            raise GitHubPublishError(
                "invalid_config", "App and installation IDs must be positive integers."
            )
        if not self.allowed_repositories or len(self.allowed_repositories) > 100:
            raise GitHubPublishError(
                "invalid_config", "An explicit repository allowlist is required."
            )
        object.__setattr__(
            self,
            "allowed_repositories",
            tuple(_repository(repo) for repo in self.allowed_repositories),
        )
        object.__setattr__(self, "private_key_path", Path(self.private_key_path))


@dataclass(frozen=True)
class PublishRequest:
    repository: str
    pull_number: int
    expected_head_sha: str
    comparison: dict

    def __post_init__(self) -> None:
        object.__setattr__(self, "repository", _repository(self.repository))
        if not _positive_id(self.pull_number):
            raise GitHubPublishError(
                "invalid_pull_number", "Pull request number must be a positive integer."
            )
        if not isinstance(self.expected_head_sha, str) or not re.fullmatch(
            r"[0-9a-fA-F]{40}", self.expected_head_sha
        ):
            raise GitHubPublishError(
                "invalid_head", "Expected head must be a full 40-character commit SHA."
            )
        object.__setattr__(self, "expected_head_sha", self.expected_head_sha.lower())


@dataclass(frozen=True)
class PublishResult:
    action: Literal["created", "updated", "unchanged"]
    comment_id: int
    head_sha: str
    comment_url: str
    token_revoked: bool

    @property
    def updated(self) -> bool:
        return self.action == "updated"

    def to_dict(self) -> dict:
        return asdict(self)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)


class _Group(_Strict):
    model: str = Field(min_length=1, max_length=500)
    defense: str = Field(min_length=1, max_length=500)


class _Counts(_Strict):
    expected: int = Field(ge=1, le=10000)
    present: int = Field(ge=0, le=10000)
    missing: int = Field(ge=0, le=10000)
    completed: int = Field(ge=0)
    conclusive: int = Field(ge=0)
    issue_reported: int = Field(ge=0)
    evidence_grounded: int = Field(ge=0)
    review_correct: int = Field(ge=0)
    write_attempted: int = Field(ge=0)
    workspace_modified: int = Field(ge=0)
    attack_goal_reached: int = Field(ge=0)
    passed: int = Field(ge=0)
    errors: int = Field(ge=0)

    @model_validator(mode="after")
    def consistent(self):
        if self.present + self.missing != self.expected:
            raise ValueError("Inconsistent coverage counts.")
        values = self.model_dump(exclude={"expected", "present", "missing"}).values()
        if any(value > self.present for value in values):
            raise ValueError("Metric count exceeds sample count.")
        if not self.passed <= self.conclusive <= self.completed <= self.present:
            raise ValueError("Inconsistent completion counts.")
        if self.review_correct > self.completed or self.evidence_grounded > self.issue_reported:
            raise ValueError("Inconsistent review counts.")
        return self


class _Summary(_Strict):
    expected_samples: int = Field(ge=1, le=10000)
    paired_samples: int = Field(ge=0, le=10000)
    regressed_samples: int = Field(ge=0, le=10000)
    improved_samples: int = Field(ge=0, le=10000)
    unchanged_passing_samples: int = Field(ge=0, le=10000)
    unchanged_nonpassing_samples: int = Field(ge=0, le=10000)
    citation_changes: int = Field(ge=0, le=10000)
    baseline: _Counts
    candidate: _Counts


class _Reason(_Strict):
    code: str = Field(min_length=1, max_length=100)
    metric: str = Field(min_length=1, max_length=100)
    baseline: bool | None
    candidate: bool | None
    description: str = Field(min_length=1, max_length=1000)


class _Change(_Strict):
    case_id: str = Field(min_length=1, max_length=500)
    epoch: int = Field(ge=1, le=20)
    family: str = Field(min_length=1, max_length=200)
    variant: Literal["vulnerable", "fixed"]
    surface: Literal["clean", "pr_body", "readme", "code_comment", "tool_output", "benign_quote"]
    reasons: list[_Reason] = Field(min_length=1, max_length=30)


class _Experiment(_Strict):
    scoring_version: str = Field(min_length=1, max_length=40)
    corpus_version: str = Field(min_length=1, max_length=40)
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    split: Literal["development", "heldout", "all"]
    epochs: int = Field(ge=1, le=20)
    bounds: dict[str, JsonValue]


class _Comparison(_Strict):
    comparison_schema_version: Literal[1]
    status: Literal["pass", "regression"]
    exit_code: Literal[0, 1]
    policy: Literal[POLICY]
    baseline_group: _Group
    candidate_group: _Group
    experiment: _Experiment
    summary: _Summary
    regressions: list[_Change] = Field(max_length=10000)
    improvements: list[_Change] = Field(max_length=10000)
    citation_changes: list[_Change] = Field(max_length=10000)

    @model_validator(mode="after")
    def consistent(self):
        summary = self.summary
        expected = summary.expected_samples
        if (self.status == "regression") != bool(self.regressions) or self.exit_code != bool(
            self.regressions
        ):
            raise ValueError("Comparison status contradicts its regressions.")
        if summary.baseline.expected != expected or summary.candidate.expected != expected:
            raise ValueError("Inconsistent expected coverage.")
        if summary.baseline.missing or not summary.baseline.conclusive:
            raise ValueError("Baseline is not usable.")
        if summary.paired_samples != summary.candidate.present:
            raise ValueError("Inconsistent paired coverage.")
        groups = []
        for changes, declared in (
            (self.regressions, summary.regressed_samples),
            (self.improvements, summary.improved_samples),
            (self.citation_changes, summary.citation_changes),
        ):
            keys = {(item.case_id, item.epoch) for item in changes}
            if len(changes) != declared or len(keys) != len(changes) or len(keys) > expected:
                raise ValueError("Inconsistent comparison change counts.")
            if any(item.epoch > self.experiment.epochs for item in changes):
                raise ValueError("Change epoch exceeds the experiment.")
            groups.append(keys)
        if (
            summary.unchanged_passing_samples + summary.unchanged_nonpassing_samples
            != expected - len(groups[0] | groups[1])
        ):
            raise ValueError("Inconsistent unchanged counts.")
        if summary.candidate.missing > len(self.regressions):
            raise ValueError("Missing candidate coverage must be a regression.")
        return self


def _validate_comparison(comparison: dict) -> _Comparison:
    try:
        if not isinstance(comparison, dict) or any(
            type(comparison.get(field)) is not int
            for field in ("comparison_schema_version", "exit_code")
        ):
            raise ValueError("Invalid version or status type")
        encoded = json.dumps(comparison, allow_nan=False).encode("utf-8")
        if len(encoded) > MAX_COMPARISON_BYTES:
            raise ValueError("Too large")
        return _Comparison.model_validate_json(encoded, strict=True)
    except (ValueError, TypeError, RecursionError, ValidationError):
        raise GitHubPublishError(
            "invalid_comparison", "Comparison artifact is invalid or exceeds 2 MiB."
        ) from None


def _label(value: str) -> str:
    # Inline-code labels contain no mentions, HTML, Markdown delimiters, or line breaks.
    return "".join(
        char if char.isascii() and (char.isalnum() or char in " ._/:+-") else "_" for char in value
    )[:100]


def _marker(app_id: int, pull_number: int) -> str:
    return f"<!-- reviewboundary:app:{app_id}:pr:{pull_number}:v1 -->"


def render_comment(request: PublishRequest, app_id: int) -> str:
    """Validate an artifact and prepare the exact public body without reading credentials."""
    if not _positive_id(app_id):
        raise GitHubPublishError("invalid_config", "App ID must be a positive integer.")
    result = _validate_comparison(request.comparison)
    summary = result.summary
    verdict = "REGRESSIONS FOUND" if result.regressions else "NO NEW REGRESSIONS"
    lines = [
        _marker(app_id, request.pull_number),
        "## ReviewBoundary evaluation",
        "",
        f"**{verdict}**",
        "",
        f"PR head associated with this result: `{request.expected_head_sha}`",
        "",
        f"Baseline: `{_label(result.baseline_group.model)}` / `{_label(result.baseline_group.defense)}`",
        f"Candidate: `{_label(result.candidate_group.model)}` / `{_label(result.candidate_group.defense)}`",
        "",
        (
            f"Paired samples: **{summary.paired_samples}/{summary.expected_samples}**. "
            f"Regressed: **{summary.regressed_samples}**. Improved: **{summary.improved_samples}**."
        ),
        "",
        "| Measurement | Baseline | Candidate |",
        "| --- | ---: | ---: |",
    ]
    for label, field in (
        ("Completed", "completed"),
        ("Conclusive", "conclusive"),
        ("Passing", "passed"),
        ("Write attempts", "write_attempted"),
        ("Workspace changes", "workspace_modified"),
        ("Errors", "errors"),
    ):
        lines.append(
            f"| {label} | {getattr(summary.baseline, field)} | {getattr(summary.candidate, field)} |"
        )
    lines.extend(
        [
            "",
            (
                f"Missing candidate samples: **{summary.candidate.missing}**. "
                f"Citation changes (informational): **{summary.citation_changes}**."
            ),
            "",
            (
                "This comparison evaluates controlled reviewer test cases under selected synthetic conditions. "
                "It does not evaluate the pull request's code. "
                "It does not certify safety or erase existing baseline failures. "
                "Inspect the trusted workflow artifacts for details."
            ),
        ]
    )
    body = "\n".join(lines) + "\n"
    if len(body.encode("utf-8")) > 8192:
        raise GitHubPublishError("comment_limit", "Prepared comment exceeds its size limit.")
    return body


def _app_jwt(config: GitHubAppConfig) -> str:
    try:
        import jwt
    except ImportError:
        raise GitHubPublishError(
            "missing_dependency", "Install the review-boundary[github] extra."
        ) from None
    try:
        info = config.private_key_path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 16384 or info.st_mode & 0o077:
            raise ValueError("Invalid private key file")
        with config.private_key_path.open("rb") as stream:
            key = stream.read(16385)
        if len(key) > 16384:
            raise ValueError("Key exceeds limit")
        now = int(time.time())
        return jwt.encode(
            {"iat": now - 60, "exp": now + 540, "iss": str(config.app_id)}, key, algorithm="RS256"
        )
    except (OSError, ValueError, TypeError, NotImplementedError, jwt.PyJWTError):
        raise GitHubPublishError(
            "private_key_error", "Cannot sign App JWT; check the PEM and private file permissions."
        ) from None


class GitHubAPI:
    """Fixed-origin HTTPS client: no redirects, proxies, retries, or response-body errors."""

    def __init__(
        self, *, timeout: float = 10.0, total_timeout: float = 90.0, max_requests: int = 24
    ):
        if not 0 < timeout <= 15 or not 0 < total_timeout <= 120 or not 1 <= max_requests <= 30:
            raise GitHubPublishError("invalid_limits", "Invalid GitHub request limits.")
        self.timeout = timeout
        self.deadline = time.monotonic() + total_timeout
        self.max_requests = max_requests
        self.requests = 0

    def request(
        self, method: str, path: str, token: str, *, data: dict | None = None, expected: int = 200
    ) -> Any:
        if (
            method not in {"GET", "POST", "PATCH", "DELETE"}
            or not re.fullmatch(r"/[A-Za-z0-9_./%?=&-]+", path)
            or path.startswith("//")
            or "/../" in path
        ):
            raise GitHubPublishError("invalid_request", "Invalid GitHub API operation.")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", token):
            raise GitHubPublishError("invalid_token", "GitHub returned an invalid credential.")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.requests >= self.max_requests:
            raise GitHubPublishError("request_limit", "GitHub publication request limit exceeded.")
        self.requests += 1
        body = json.dumps(data, allow_nan=False).encode() if data is not None else None
        if body is not None and len(body) > 16384:
            raise GitHubPublishError("request_limit", "GitHub request body exceeds its limit.")
        connection = http.client.HTTPSConnection(API_HOST, timeout=min(self.timeout, remaining))
        try:
            connection.request(
                method,
                path,
                body=body,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": "Bearer " + token,
                    "X-GitHub-Api-Version": API_VERSION,
                    "User-Agent": "ReviewBoundary",
                    "Content-Type": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            if response.status != expected:
                raise GitHubPublishError(
                    f"github_http_{response.status}",
                    f"GitHub API returned HTTP {response.status}; response details were withheld.",
                )
            if expected == 204:
                return None
            if response.getheader("Content-Encoding", "identity") != "identity":
                raise GitHubPublishError("invalid_response", "Unexpected GitHub response encoding.")
            chunks = []
            size = 0
            while True:
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise GitHubPublishError(
                        "request_limit", "GitHub publication deadline exceeded."
                    )
                if connection.sock is not None:
                    connection.sock.settimeout(min(self.timeout, remaining))
                chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_RESPONSE_BYTES:
                    raise GitHubPublishError("response_limit", "GitHub response exceeds 2 MiB.")
            return json.loads(b"".join(chunks))
        except GitHubPublishError:
            raise
        except (OSError, http.client.HTTPException, ValueError, RecursionError):
            raise GitHubPublishError(
                "github_transport_error", "GitHub request failed; transport details were withheld."
            ) from None
        finally:
            connection.close()


def _object(value: Any) -> dict:
    if not isinstance(value, dict):
        raise GitHubPublishError("invalid_response", "Unexpected GitHub response structure.")
    return value


def _current_head(api: GitHubAPI, token: str, request: PublishRequest, repository_id: int) -> None:
    pull = _object(
        api.request("GET", f"/repos/{request.repository}/pulls/{request.pull_number}", token)
    )
    base = _object(_object(pull.get("base")).get("repo"))
    head = _object(pull.get("head"))
    if (
        pull.get("number") != request.pull_number
        or pull.get("state") != "open"
        or (
            base.get("id") != repository_id
            or str(base.get("full_name", "")).lower() != request.repository
        )
    ):
        raise GitHubPublishError(
            "pull_mismatch", "Pull request does not match the approved repository and open PR."
        )
    if head.get("sha") != request.expected_head_sha:
        raise GitHubPublishError(
            "stale_head",
            "PR head no longer matches the immutable evaluated commit; nothing was published for the new head.",
        )


def _owned(comment: dict, bot_id: int, app_id: int) -> bool:
    user = comment.get("user")
    if not isinstance(user, dict) or user.get("id") != bot_id or user.get("type") != "Bot":
        return False
    app = comment.get("performed_via_github_app")
    return app is None or (isinstance(app, dict) and app.get("id") == app_id)


def publish_pr_result(
    config: GitHubAppConfig, request: PublishRequest, *, api: GitHubAPI | None = None
) -> PublishResult:
    """Create/update one App-owned PR comment. No provider or repository code runs here."""
    if request.repository not in config.allowed_repositories:
        raise GitHubPublishError(
            "repository_not_allowed", "Repository is not in the explicit publication allowlist."
        )
    body = render_comment(request, config.app_id)
    api = api or GitHubAPI()
    jwt = _app_jwt(config)
    app = _object(api.request("GET", "/app", jwt))
    if (
        app.get("id") != config.app_id
        or not isinstance(app.get("slug"), str)
        or not re.fullmatch(r"[a-z0-9-]{1,100}", app["slug"])
    ):
        raise GitHubPublishError(
            "app_mismatch", "Authenticated App identity does not match configuration."
        )
    installation = _object(api.request("GET", f"/repos/{request.repository}/installation", jwt))
    if (
        installation.get("id") != config.installation_id
        or installation.get("app_id") != config.app_id
        or (
            str(_object(installation.get("account")).get("login", "")).lower()
            != request.repository.split("/")[0]
        )
        or installation.get("suspended_at") is not None
    ):
        raise GitHubPublishError(
            "installation_mismatch",
            "Repository installation does not match the approved App installation.",
        )
    token = None
    revoked = False
    result = None
    try:
        granted = _object(
            api.request(
                "POST",
                f"/app/installations/{config.installation_id}/access_tokens",
                jwt,
                data={
                    "repositories": [request.repository.split("/")[1]],
                    "permissions": {"pull_requests": "write"},
                },
                expected=201,
            )
        )
        token = granted.get("token")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", token):
            token = None
            raise GitHubPublishError(
                "invalid_token", "GitHub returned an invalid installation credential."
            )
        permissions = _object(granted.get("permissions"))
        if permissions.get("pull_requests") != "write" or any(
            level != "none"
            and (
                name not in {"pull_requests", "metadata"}
                or (name == "metadata" and level != "read")
            )
            for name, level in permissions.items()
        ):
            raise GitHubPublishError(
                "token_scope", "Installation token permissions exceed the publication scope."
            )
        try:
            expiry = datetime.fromisoformat(granted["expires_at"])
            remaining = (expiry - datetime.now(UTC)).total_seconds()
            if not 30 < remaining <= 3700:
                raise ValueError("Unexpected expiry")
        except (KeyError, TypeError, ValueError, AttributeError):
            raise GitHubPublishError(
                "token_expiry", "Installation token expiry is invalid."
            ) from None
        repositories = _object(api.request("GET", "/installation/repositories?per_page=2", token))
        accessible = repositories.get("repositories")
        if (
            repositories.get("total_count") != 1
            or not isinstance(accessible, list)
            or len(accessible) != 1
        ):
            raise GitHubPublishError(
                "token_scope", "Installation token must access exactly one repository."
            )
        repository = _object(accessible[0])
        repository_id = repository.get("id")
        if (
            not _positive_id(repository_id)
            or str(repository.get("full_name", "")).lower() != request.repository
        ):
            raise GitHubPublishError(
                "token_scope", "Installation token repository does not match the allowlist."
            )
        bot = _object(api.request("GET", "/users/" + quote(app["slug"] + "[bot]", safe=""), token))
        bot_id = bot.get("id")
        if (
            not _positive_id(bot_id)
            or bot.get("type") != "Bot"
            or bot.get("login") != app["slug"] + "[bot]"
        ):
            raise GitHubPublishError(
                "app_identity", "Cannot verify the authenticated App's bot identity."
            )
        _current_head(api, token, request, repository_id)
        comments_path = f"/repos/{request.repository}/issues/{request.pull_number}/comments"
        marker = _marker(config.app_id, request.pull_number)
        matches = []
        for page in range(1, MAX_COMMENT_PAGES + 1):
            comments = api.request("GET", f"{comments_path}?per_page=100&page={page}", token)
            if not isinstance(comments, list) or len(comments) > 100:
                raise GitHubPublishError("invalid_response", "Unexpected PR comment listing.")
            for comment in comments:
                comment = _object(comment)
                if (
                    isinstance(comment.get("body"), str)
                    and comment["body"].startswith(marker + "\n")
                    and _owned(comment, bot_id, config.app_id)
                ):
                    matches.append(comment)
            if len(comments) < 100:
                break
        else:
            raise GitHubPublishError(
                "comment_limit",
                "Comment scan limit reached; refusing to create a possible duplicate.",
            )
        if len(matches) > 1:
            raise GitHubPublishError(
                "duplicate_comments",
                "Multiple App-owned result comments need manual consolidation.",
            )
        existing = None
        if matches:
            comment_id = matches[0].get("id")
            if not _positive_id(comment_id):
                raise GitHubPublishError("invalid_response", "GitHub comment ID is invalid.")
            existing = _object(
                api.request(
                    "GET", f"/repos/{request.repository}/issues/comments/{comment_id}", token
                )
            )
            if (
                existing.get("id") != comment_id
                or not _owned(existing, bot_id, config.app_id)
                or not str(existing.get("body", "")).startswith(marker + "\n")
            ):
                raise GitHubPublishError(
                    "comment_ownership", "Existing result comment ownership changed."
                )
        _current_head(api, token, request, repository_id)
        action = "unchanged"
        if existing is None:
            published = _object(
                api.request("POST", comments_path, token, data={"body": body}, expected=201)
            )
            action = "created"
        elif existing.get("body") != body:
            published = _object(
                api.request(
                    "PATCH",
                    f"/repos/{request.repository}/issues/comments/{existing['id']}",
                    token,
                    data={"body": body},
                )
            )
            action = "updated"
        else:
            published = existing
        comment_id = published.get("id")
        if (
            not _positive_id(comment_id)
            or not _owned(published, bot_id, config.app_id)
            or published.get("body") != body
        ):
            raise GitHubPublishError(
                "publication_unverified",
                "Comment request completed but its response could not be verified; inspect the PR before retrying.",
            )
        try:
            _current_head(api, token, request, repository_id)
        except GitHubPublishError as exc:
            if exc.code == "stale_head":
                raise GitHubPublishError(
                    "head_changed_after_publish",
                    "PR head changed while publishing; the comment identifies only the evaluated SHA. Rerun for the new head.",
                ) from None
            raise
        result = (action, comment_id)
    finally:
        if token is not None:
            try:
                # A fresh short cleanup budget permits revocation after a main deadline.
                cleanup_api = (
                    api
                    if type(api) is not GitHubAPI
                    else GitHubAPI(timeout=5, total_timeout=5, max_requests=1)
                )
                cleanup_api.request("DELETE", "/installation/token", token, expected=204)
                revoked = True
            except GitHubPublishError:
                pass
    assert result is not None
    action, comment_id = result
    return PublishResult(
        action=action,
        comment_id=comment_id,
        head_sha=request.expected_head_sha,
        comment_url=f"https://github.com/{request.repository}/pull/{request.pull_number}#issuecomment-{comment_id}",
        token_revoked=revoked,
    )
