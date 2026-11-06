import importlib.util
import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest


def load_checker():
    path = Path(__file__).parents[1] / "scripts" / "check_distribution.py"
    spec = importlib.util.spec_from_file_location("check_distribution", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_pair(
    directory: Path,
    *,
    source_files: dict[str, bytes] | None = None,
    wheel_files: dict[str, bytes] | None = None,
) -> tuple[Path, Path]:
    source_files = source_files or {"__init__.py": b"VERSION = 'test'\n"}
    wheel_files = wheel_files or dict(source_files)
    source = directory / "review_boundary-0.3.0.tar.gz"
    wheel = directory / "review_boundary-0.3.0-py3-none-any.whl"
    with tarfile.open(source, "w:gz") as archive:
        for relative, content in source_files.items():
            info = tarfile.TarInfo(f"review_boundary-0.3.0/src/review_boundary/{relative}")
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    with zipfile.ZipFile(wheel, "w") as archive:
        for relative, content in wheel_files.items():
            archive.writestr(f"review_boundary/{relative}", content)
    return source, wheel


@pytest.mark.parametrize("source_distribution", [False, True])
@pytest.mark.parametrize("directory", ["runs", "RuNs", "DIST-CHECK", "Logs", "REPORTS"])
def test_checker_rejects_private_output_directories(source_distribution, directory):
    checker = load_checker()
    prefix = "review_boundary-0.3.0/" if source_distribution else ""
    with pytest.raises(SystemExit, match="private output path"):
        checker._assert_public(
            [f"{prefix}{directory}/artifact.txt"],
            source_distribution=source_distribution,
        )


@pytest.mark.parametrize(
    "name",
    [
        "/review_boundary/file.py",
        "../review_boundary/file.py",
        "review_boundary/../file.py",
        "review_boundary/./file.py",
        "review_boundary//file.py",
        "review_boundary\\file.py",
    ],
)
def test_checker_rejects_non_canonical_member_paths(name):
    checker = load_checker()
    with pytest.raises(SystemExit, match="non-canonical member path"):
        checker._assert_public([name], source_distribution=False)


def test_checker_requires_exact_sdist_root():
    checker = load_checker()
    with pytest.raises(SystemExit, match="outside its expected root"):
        checker._assert_public(
            ["other-root/src/review_boundary/__init__.py"],
            source_distribution=True,
            expected_root="review_boundary-0.3.0",
        )


def test_checker_allows_only_the_root_sdist_environment_example():
    checker = load_checker()
    checker._assert_public(
        ["review_boundary-0.3.0/.env.example"],
        source_distribution=True,
    )


@pytest.mark.parametrize(
    ("name", "source_distribution"),
    [
        ("review_boundary-0.3.0/.env", True),
        ("review_boundary-0.3.0/.ENV.EXAMPLE", True),
        ("review_boundary-0.3.0/config/.env.example", True),
        ("review_boundary/.env.example", False),
        ("review_boundary/.env.production", False),
    ],
)
def test_checker_rejects_sensitive_environment_paths(name, source_distribution):
    checker = load_checker()
    with pytest.raises(SystemExit, match="sensitive environment path"):
        checker._assert_public([name], source_distribution=source_distribution)


@pytest.mark.parametrize("name", ["bootstrap.pth", "review_boundary/BOOTSTRAP.PTH"])
def test_checker_rejects_wheel_pth_files(name):
    checker = load_checker()
    with pytest.raises(SystemExit, match="prohibited .pth"):
        checker._assert_public([name], source_distribution=False)


@pytest.mark.parametrize(
    "member_type",
    [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE],
)
def test_checker_rejects_unsafe_tar_member_types(tmp_path, member_type):
    checker = load_checker()
    source, _ = write_pair(tmp_path)
    with tarfile.open(source, "w:gz") as archive:
        info = tarfile.TarInfo("review_boundary-0.3.0/src/review_boundary/link")
        info.type = member_type
        info.linkname = "target"
        archive.addfile(info)
    with pytest.raises(SystemExit, match="unsafe tar member"):
        checker.check_directory(tmp_path)


def test_checker_rejects_wheel_symlinks(tmp_path):
    checker = load_checker()
    _, wheel = write_pair(tmp_path)
    info = zipfile.ZipInfo("review_boundary/__init__.py")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(info, "target")
    with pytest.raises(SystemExit, match="non-regular member"):
        checker.check_directory(tmp_path)


@pytest.mark.parametrize(
    ("source_files", "wheel_files", "message"),
    [
        (
            {"__init__.py": b"same", "only_source.py": b"source"},
            {"__init__.py": b"same"},
            "missing from wheel",
        ),
        (
            {"__init__.py": b"same"},
            {"__init__.py": b"same", "only_wheel.py": b"wheel"},
            "only in wheel",
        ),
        (
            {"__init__.py": b"source"},
            {"__init__.py": b"wheel"},
            "content differs",
        ),
    ],
)
def test_checker_requires_complete_byte_identical_package(
    tmp_path, source_files, wheel_files, message
):
    checker = load_checker()
    write_pair(tmp_path, source_files=source_files, wheel_files=wheel_files)
    with pytest.raises(SystemExit, match=message):
        checker.check_directory(tmp_path)


def test_checker_accepts_matching_safe_distributions(tmp_path):
    checker = load_checker()
    write_pair(
        tmp_path,
        source_files={"__init__.py": b"same", "fixtures/data.json": b"{}\n"},
    )
    checker.check_directory(tmp_path)
