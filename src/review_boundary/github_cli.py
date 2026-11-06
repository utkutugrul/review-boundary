"""Credential-free preview and explicitly scoped GitHub App publication commands."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

from .github_app import (
    MAX_COMPARISON_BYTES,
    GitHubAppConfig,
    GitHubPublishError,
    PublishRequest,
    publish_pr_result,
    render_comment,
)

MAX_CONFIG_BYTES = 16384
CONFIG_FIELDS = {"app_id", "installation_id", "private_key_path", "allowed_repositories"}


class _InputError(ValueError):
    """Input error with a fixed message that cannot expose a file's contents."""


def add_commands(subparsers) -> None:
    for name, description in (
        ("github-preview", "Validate and preview a GitHub App comment without credentials"),
        ("github-publish", "Publish a comparison using a configured GitHub App installation"),
    ):
        parser = subparsers.add_parser(name, help=description)
        parser.add_argument("--repository", required=True, help="Exact approved owner/repository")
        parser.add_argument("--pull-number", type=int, required=True)
        parser.add_argument(
            "--expected-head", required=True, help="Immutable full evaluated commit SHA"
        )
        parser.add_argument("--comparison", type=Path, required=True)
        if name == "github-preview":
            parser.add_argument("--app-id", type=int, required=True)
            parser.add_argument(
                "--output", type=Path, help="New Markdown file; existing files are preserved"
            )
        else:
            parser.add_argument(
                "--config",
                type=Path,
                required=True,
                help="Trusted JSON App IDs, PEM path, and exact repository allowlist",
            )


def _path_without_symlinks(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    for component in (*reversed(path.parents), path):
        try:
            if stat.S_ISLNK(component.lstat().st_mode):
                raise _InputError(
                    "Symlink paths are not accepted for publication inputs or preview output."
                )
        except FileNotFoundError:
            continue
    return path


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _InputError("JSON objects must not contain duplicate keys.")
        result[key] = value
    return result


def _invalid_constant(value):
    raise _InputError("Non-finite JSON numbers are not accepted.")


def _read_json(value: str | Path, limit: int) -> dict:
    try:
        path = _path_without_symlinks(value)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise _InputError("Input must be a regular JSON file within its size limit.")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
                raise _InputError("Input changed or exceeded its size limit.")
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise _InputError("Input exceeds its size limit.")
        result = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        if not isinstance(result, dict):
            raise _InputError("Input must be a JSON object.")
        return result
    except _InputError:
        raise
    except (OSError, ValueError, RecursionError):
        raise _InputError(
            "Cannot read a valid bounded JSON input; file contents were withheld."
        ) from None


def _config(value: str | Path) -> GitHubAppConfig:
    data = _read_json(value, MAX_CONFIG_BYTES)
    if set(data) != CONFIG_FIELDS:
        raise _InputError(
            "App config must contain only app_id, installation_id, private_key_path, and allowed_repositories."
        )
    key_path = data["private_key_path"]
    allowlist = data["allowed_repositories"]
    if (
        not isinstance(key_path, str)
        or not key_path
        or len(key_path) > 4096
        or (any(ord(char) < 32 for char in key_path) or not Path(key_path).is_absolute())
    ):
        raise _InputError("App config must name an absolute private-key path.")
    if (
        not isinstance(allowlist, list)
        or not allowlist
        or not all(isinstance(item, str) for item in allowlist)
    ):
        raise _InputError("App config must provide an explicit list of allowed repositories.")
    return GitHubAppConfig(**data)


def _write_preview(value: str | Path, body: str) -> None:
    try:
        path = _path_without_symlinks(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags, 0o644), "w", encoding="utf-8") as stream:
            stream.write(body)
    except _InputError:
        raise
    except (OSError, ValueError):
        raise _InputError(
            "Preview output must be a new writable file; existing files are preserved."
        ) from None


def handle_command(args) -> int:
    try:
        if args.command not in {"github-preview", "github-publish"}:
            raise _InputError("Unsupported GitHub command.")
        request = PublishRequest(
            repository=args.repository,
            pull_number=args.pull_number,
            expected_head_sha=args.expected_head,
            comparison=_read_json(args.comparison, MAX_COMPARISON_BYTES),
        )
        if args.command == "github-preview":
            body = render_comment(request, args.app_id)
            if args.output is None:
                print(body, end="")
            else:
                _write_preview(args.output, body)
                print("Preview written.")
            return 0
        config = _config(args.config)
        if request.repository not in config.allowed_repositories:
            raise GitHubPublishError(
                "repository_not_allowed", "Repository is not in the explicit publication allowlist."
            )
        result = publish_pr_result(config, request)
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    except GitHubPublishError as exc:
        print(f"Error [{exc.code}]: {exc}", file=sys.stderr)
        return 2
    except _InputError as exc:
        print(f"Error [invalid_input]: {exc}", file=sys.stderr)
        return 2
