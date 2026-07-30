from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

import bootstrap


class BootstrapTests(unittest.TestCase):
    def archive(self, path: Path, *, extra: str | None = None) -> None:
        with tarfile.open(path, mode="w:gz") as archive:
            for relative in sorted(bootstrap.ARCHIVE_FILES):
                payload = f"{relative}\n".encode("utf-8")
                member = tarfile.TarInfo(f"repo-commit/{relative}")
                member.size = len(payload)
                member.mode = 0o644
                archive.addfile(member, io.BytesIO(payload))
            if extra is not None:
                payload = b"malicious"
                member = tarfile.TarInfo(f"repo-commit/{extra}")
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    def test_exact_archive_extracts_only_read_only_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "verifier.tar.gz"
            self.archive(archive)
            output = root / "trusted"

            expected = bootstrap.extract_exact_snapshot(archive, output)

            self.assertEqual(set(expected), bootstrap.RUNTIME_FILES)
            self.assertEqual(bootstrap.snapshot_closure(output), expected)
            self.assertEqual(
                {path.name for path in output.iterdir()},
                bootstrap.RUNTIME_FILES,
            )

    def test_archive_rejects_ignored_or_unexpected_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "verifier.tar.gz"
            self.archive(archive, extra="json.pyc")

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "unexpected file",
            ):
                bootstrap.extract_exact_snapshot(archive, root / "trusted")

    def test_archive_rejects_runtime_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "verifier.tar.gz"
            with tarfile.open(archive, mode="w:gz") as handle:
                for relative in sorted(bootstrap.ARCHIVE_FILES):
                    member = tarfile.TarInfo(f"repo-commit/{relative}")
                    if relative == "verifier.py":
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/tmp/replacement.py"
                        handle.addfile(member)
                    else:
                        payload = relative.encode("utf-8")
                        member.size = len(payload)
                        handle.addfile(member, io.BytesIO(payload))

            with self.assertRaisesRegex(
                bootstrap.BootstrapError,
                "indirect or special",
            ):
                bootstrap.extract_exact_snapshot(archive, root / "trusted")


if __name__ == "__main__":
    unittest.main()
