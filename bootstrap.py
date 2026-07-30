#!/usr/bin/env python3
"""Fetch and run one exact verifier commit outside every local worktree."""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Final


VERIFIER_REPOSITORY: Final = "Glimmer2077/sanhuo-q7-verifier"
COMMIT_PATTERN: Final = re.compile(r"^[0-9a-f]{40}$")
MAX_ARCHIVE_BYTES: Final = 8 * 1024 * 1024
MAX_ARCHIVE_FILES: Final = 32
MAX_ARCHIVE_EXPANDED_BYTES: Final = 16 * 1024 * 1024
ARCHIVE_FILES: Final = {
    ".gitignore",
    "README.md",
    "bootstrap.py",
    "isolated_driver.py",
    "sanhuo-q7.sb",
    "tests/test_bootstrap.py",
    "tests/test_isolated_driver.py",
    "tests/test_verifier.py",
    "verifier.py",
}
RUNTIME_FILES: Final = {
    "isolated_driver.py",
    "sanhuo-q7.sb",
    "verifier.py",
}


class BootstrapError(RuntimeError):
    """Raised when an exact trusted verifier snapshot cannot be established."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise BootstrapError(message)


def require_apple_isolated_python() -> None:
    executable = Path(sys.executable).resolve()
    developer_root = Path("/Applications/Xcode.app/Contents/Developer").resolve()
    _require(sys.flags.isolated == 1, "bootstrap must run with Python -I")
    _require(
        executable == developer_root or developer_root in executable.parents,
        "bootstrap must run with Apple Xcode Python",
    )


def _download_archive(commit: str, destination: Path) -> None:
    url = (
        "https://codeload.github.com/"
        f"{VERIFIER_REPOSITORY}/tar.gz/{commit}"
    )
    result = subprocess.run(
        [
            "/usr/bin/curl",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--output",
            str(destination),
            url,
        ],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "HOME": str(destination.parent),
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        timeout=120,
    )
    _require(
        result.returncode == 0,
        "could not download the exact verifier commit",
    )
    _require(
        destination.is_file()
        and not destination.is_symlink()
        and destination.stat().st_size <= MAX_ARCHIVE_BYTES,
        "verifier archive is missing or too large",
    )


def extract_exact_snapshot(archive_path: Path, destination: Path) -> dict[str, str]:
    """Validate the closed repository archive and extract only runtime files."""

    _require(not destination.exists(), "trusted snapshot already exists")
    destination.mkdir(mode=0o700)
    observed_files: set[str] = set()
    runtime_payloads: dict[str, bytes] = {}
    prefix: str | None = None
    expanded_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            _require(
                len(members) <= MAX_ARCHIVE_FILES,
                "verifier archive has too many entries",
            )
            for member in members:
                path = PurePosixPath(member.name)
                _require(
                    not path.is_absolute() and ".." not in path.parts,
                    "verifier archive contains path traversal",
                )
                _require(
                    not member.issym()
                    and not member.islnk()
                    and not member.isdev()
                    and not member.isfifo(),
                    "verifier archive contains an indirect or special entry",
                )
                if not path.parts:
                    continue
                if prefix is None:
                    prefix = path.parts[0]
                _require(path.parts[0] == prefix, "verifier archive prefix drift")
                relative = PurePosixPath(*path.parts[1:])
                if not relative.parts or member.isdir():
                    continue
                relative_name = relative.as_posix()
                _require(
                    member.isfile() and relative_name in ARCHIVE_FILES,
                    "verifier archive contains an unexpected file",
                )
                _require(
                    relative_name not in observed_files,
                    "verifier archive contains a duplicate file",
                )
                observed_files.add(relative_name)
                expanded_bytes += member.size
                _require(
                    expanded_bytes <= MAX_ARCHIVE_EXPANDED_BYTES,
                    "verifier archive expands beyond its limit",
                )
                if relative_name in RUNTIME_FILES:
                    stream = archive.extractfile(member)
                    _require(stream is not None, "runtime file cannot be read")
                    runtime_payloads[relative_name] = stream.read()
    except (OSError, tarfile.TarError) as exc:
        raise BootstrapError("verifier archive is invalid") from exc
    _require(observed_files == ARCHIVE_FILES, "verifier archive file set drift")
    _require(set(runtime_payloads) == RUNTIME_FILES, "runtime file set drift")
    closure: dict[str, str] = {}
    for relative_name in sorted(runtime_payloads):
        output = destination / relative_name
        _require(output.parent == destination, "runtime path escaped snapshot")
        payload = runtime_payloads[relative_name]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(output, flags, 0o400)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                _require(written > 0, "runtime file write was incomplete")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        closure[relative_name] = hashlib.sha256(payload).hexdigest()
    destination.chmod(0o500)
    return closure


def snapshot_closure(root: Path) -> dict[str, str]:
    _require(root.is_dir() and not root.is_symlink(), "snapshot root is invalid")
    observed: dict[str, str] = {}
    for entry in os.scandir(root):
        _require(
            entry.name in RUNTIME_FILES and entry.is_file(follow_symlinks=False),
            "trusted snapshot contains an unexpected entry",
        )
        path = Path(entry.path)
        mode = stat.S_IMODE(entry.stat(follow_symlinks=False).st_mode)
        _require(mode & 0o222 == 0, "trusted snapshot file became writable")
        observed[entry.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    _require(set(observed) == RUNTIME_FILES, "trusted snapshot file set drift")
    return dict(sorted(observed.items()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one exact Sanhuo Q7 verifier commit"
    )
    parser.add_argument("--verifier-commit", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("prepare", "verify"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--target-commit", required=True)
        subparser.add_argument("--tool-workspace", type=Path, required=True)
        if command == "prepare":
            subparser.add_argument("--output-directory", type=Path, required=True)
        else:
            subparser.add_argument("--review-directory", type=Path, required=True)
            subparser.add_argument("--output", type=Path, required=True)
    return parser


def _publish(staged: Path, destination: Path) -> None:
    _require(not destination.exists(), "final output already exists")
    _require(
        destination.parent.is_dir() and not destination.parent.is_symlink(),
        "final output parent is invalid",
    )
    os.rename(staged, destination)


def main(argv: list[str] | None = None) -> int:
    require_apple_isolated_python()
    arguments = _parser().parse_args(argv)
    _require(
        COMMIT_PATTERN.fullmatch(arguments.verifier_commit) is not None,
        "verifier commit is invalid",
    )
    with tempfile.TemporaryDirectory(
        prefix="sanhuo-q7-bootstrap-",
        dir="/private/tmp",
    ) as temporary:
        root = Path(temporary)
        archive = root / "verifier.tar.gz"
        trusted_root = root / "trusted"
        _download_archive(arguments.verifier_commit, archive)
        expected_closure = extract_exact_snapshot(archive, trusted_root)
        staged = root / ("review-output" if arguments.command == "prepare" else "result.json")
        command = [
            sys.executable,
            "-I",
            str(trusted_root / "verifier.py"),
            "--verifier-commit",
            arguments.verifier_commit,
            arguments.command,
            "--target-commit",
            arguments.target_commit,
            "--tool-workspace",
            str(arguments.tool_workspace.resolve()),
        ]
        if arguments.command == "prepare":
            destination = arguments.output_directory.resolve()
            command.extend(["--output-directory", str(staged)])
        else:
            destination = arguments.output.resolve()
            command.extend(
                [
                    "--review-directory",
                    str(arguments.review_directory.resolve()),
                    "--output",
                    str(staged),
                ]
            )
        result = subprocess.run(
            command,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": str(Path.home()),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "SANHUO_Q7_TRUSTED_BOOTSTRAP": "1",
                "SANHUO_Q7_VERIFIER_COMMIT": arguments.verifier_commit,
                "SANHUO_Q7_TRUSTED_ROOT": str(trusted_root),
            },
        )
        _require(
            result.returncode == 0,
            result.stderr.decode("utf-8", errors="replace").strip()
            or "trusted verifier failed",
        )
        _require(
            snapshot_closure(trusted_root) == expected_closure,
            "trusted verifier changed while it was running",
        )
        _require(staged.exists(), "trusted verifier did not create staged output")
        _publish(staged, destination)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BootstrapError as exc:
        print(f"Q7 bootstrap failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
