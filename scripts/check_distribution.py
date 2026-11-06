from __future__ import annotations

import argparse
import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

PRIVATE_DIRECTORIES = frozenset({"dist", "dist-check", "logs", "reports", "runs"})
PRIVATE_DIRECTORY_KEYS = frozenset(name.casefold() for name in PRIVATE_DIRECTORIES)


def _fail(message: str) -> None:
    raise SystemExit(message)


def _canonical_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name or name.startswith("/"):
        _fail(f"Distribution contains a non-canonical member path: {name!r}")
    parts = tuple(name.split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        _fail(f"Distribution contains a non-canonical member path: {name!r}")
    if PurePosixPath(name).is_absolute() or PurePosixPath(*parts).as_posix() != name:
        _fail(f"Distribution contains a non-canonical member path: {name!r}")
    return parts


def _payload_parts(
    name: str,
    *,
    source_distribution: bool,
    expected_root: str | None = None,
) -> tuple[str, ...]:
    parts = _canonical_parts(name)
    if not source_distribution:
        return parts
    root = expected_root or parts[0]
    if parts[0] != root:
        _fail(f"Source distribution contains a member outside its expected root {root!r}: {name!r}")
    return parts[1:]


def _assert_public(
    names: list[str],
    *,
    source_distribution: bool,
    expected_root: str | None = None,
) -> None:
    inferred_root = expected_root
    if source_distribution and inferred_root is None and names:
        inferred_root = _canonical_parts(names[0])[0]

    for name in names:
        payload = _payload_parts(
            name,
            source_distribution=source_distribution,
            expected_root=inferred_root,
        )
        private = sorted(part for part in payload if part.casefold() in PRIVATE_DIRECTORY_KEYS)
        if private:
            _fail(f"Distribution contains a private output path: {name}")

        environment_parts = [part for part in payload if part.casefold().startswith(".env")]
        allowed_example = source_distribution and payload == (".env.example",)
        if environment_parts and not allowed_example:
            _fail(f"Distribution contains a sensitive environment path: {name}")

        if not source_distribution and payload[-1].casefold().endswith(".pth"):
            _fail(f"Wheel contains a prohibited .pth file: {name}")


def _expected_sdist_root(path: Path) -> str:
    suffix = ".tar.gz"
    if not path.name.endswith(suffix) or path.name == suffix:
        _fail(f"Unexpected source distribution filename: {path.name}")
    return path.name[: -len(suffix)]


def _read_sdist_package(path: Path) -> dict[str, bytes]:
    expected_root = _expected_sdist_root(path)
    package: dict[str, bytes] = {}
    seen: set[str] = set()
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        _assert_public(
            [member.name for member in members],
            source_distribution=True,
            expected_root=expected_root,
        )
        for member in members:
            if member.name in seen:
                _fail(f"Source distribution contains a duplicate member: {member.name}")
            seen.add(member.name)
            payload = _payload_parts(
                member.name,
                source_distribution=True,
                expected_root=expected_root,
            )
            if member.isdir():
                continue
            if not member.isreg():
                _fail(f"Source distribution contains an unsafe tar member: {member.name}")
            if payload[:2] != ("src", "review_boundary"):
                continue
            relative = "/".join(payload[2:])
            if not relative:
                _fail("Source distribution package contains an empty file path.")
            extracted = archive.extractfile(member)
            if extracted is None:
                _fail(f"Could not read source distribution member: {member.name}")
            package[relative] = extracted.read()
    return package


def _read_wheel_package(path: Path) -> dict[str, bytes]:
    package: dict[str, bytes] = {}
    seen: set[str] = set()
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        _assert_public(
            [member.filename for member in members],
            source_distribution=False,
        )
        for member in members:
            name = member.filename
            if name in seen:
                _fail(f"Wheel contains a duplicate member: {name}")
            seen.add(name)
            payload = _payload_parts(name, source_distribution=False)
            unix_mode = member.external_attr >> 16
            file_type = stat.S_IFMT(unix_mode)
            if member.is_dir() or file_type not in {0, stat.S_IFREG}:
                _fail(f"Wheel contains a non-regular member: {name}")
            if member.flag_bits & 0x1:
                _fail(f"Wheel contains an encrypted member: {name}")
            if payload[0] != "review_boundary":
                continue
            relative = "/".join(payload[1:])
            if not relative:
                _fail("Wheel package contains an empty file path.")
            package[relative] = archive.read(member)
    return package


def _assert_package_parity(source: dict[str, bytes], wheel: dict[str, bytes]) -> None:
    if not source or not wheel:
        _fail("Expected review_boundary package files in both distributions.")
    missing = sorted(source.keys() - wheel.keys())
    extra = sorted(wheel.keys() - source.keys())
    changed = sorted(name for name in source.keys() & wheel.keys() if source[name] != wheel[name])
    if missing or extra or changed:
        details = []
        if missing:
            details.append(f"missing from wheel: {', '.join(missing)}")
        if extra:
            details.append(f"only in wheel: {', '.join(extra)}")
        if changed:
            details.append(f"content differs: {', '.join(changed)}")
        _fail("Wheel package does not match the source distribution: " + "; ".join(details))


def check_directory(directory: Path) -> None:
    source = tuple(directory.glob("*.tar.gz"))
    wheels = tuple(directory.glob("*.whl"))
    if len(source) != 1 or len(wheels) != 1:
        _fail("Expected exactly one source distribution and one wheel.")
    _assert_package_parity(_read_sdist_package(source[0]), _read_wheel_package(wheels[0]))


def main() -> None:
    parser = argparse.ArgumentParser(description="Check built distribution file selection.")
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    check_directory(args.directory)


if __name__ == "__main__":
    main()
