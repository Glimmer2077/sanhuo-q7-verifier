from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import verifier


class TrustedVerifierTests(unittest.TestCase):
    def run_git(self, repository: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(repository), *arguments],
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "HOME": str(repository.parent),
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1",
            },
        )
        return result.stdout.decode("utf-8").strip()

    def matrix_evidence(self) -> dict[str, dict[str, object]]:
        return {
            candidate: {
                "audit_report_sha256": "1" * 64,
                "audit_file_sha256": "2" * 64,
                "manifest_sha256": "3" * 64,
                "firmware_sha256": "4" * 64,
                "elf_sha256": "5" * 64,
                "elf_semantic_sha256": "6" * 64,
                "gate_evidence_sha256": {
                    f"Q{index}": f"{index + 7:x}"[-1] * 64
                    for index in range(7)
                },
            }
            for candidate in verifier.CANDIDATES
        }

    def approved_report(
        self,
        role: str,
        *,
        target_commit: str = "a" * 40,
        verifier_commit: str = "b" * 40,
    ) -> dict[str, object]:
        evidence = self.matrix_evidence()
        return {
            "schema": "sanhuo.motion_phase2_external_ai_review.v1",
            "role": role,
            "challenge": verifier.review_challenge(
                role=role,
                target_commit=target_commit,
                verifier_commit=verifier_commit,
                evidence=evidence,
            ),
            "review_instance_id": f"{role}-unique-instance",
            "reviewed_commit_sha": target_commit,
            "candidates": evidence,
            "decision": "passed",
            "reviewed_areas": {
                area: True for area in verifier.REVIEWED_AREAS
            },
            "covered": ["检查了精确提交、可信验签器和四候选证据"],
            "not_covered": ["未直接检查真实硬件"],
            "known_risks": ["外部 AI 身份仍为自述"],
            "attestations": {
                item: True for item in verifier.ATTESTATIONS
            },
            "findings": [],
        }

    def test_git_environment_is_minimal_and_disables_replacements(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = verifier.git_environment(Path(temporary))

        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("PYTHONPATH", environment)
        self.assertNotIn("GIT_OBJECT_DIRECTORY", environment)
        self.assertNotIn("GIT_ALTERNATE_OBJECT_DIRECTORIES", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertEqual(set(environment), verifier.GIT_ENVIRONMENT_FIELDS)

    def test_target_checkout_uses_exact_local_commit_not_dirty_worktree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            self.run_git(source, "init", "--quiet")
            self.run_git(source, "config", "user.name", "Q7 test")
            self.run_git(source, "config", "user.email", "q7@example.invalid")
            (source / "tracked.txt").write_text("baseline\n", encoding="utf-8")
            self.run_git(source, "add", "tracked.txt")
            self.run_git(source, "commit", "--quiet", "-m", "baseline")
            baseline_commit = self.run_git(source, "rev-parse", "HEAD")

            (source / "tracked.txt").write_text("target\n", encoding="utf-8")
            self.run_git(source, "add", "tracked.txt")
            self.run_git(source, "commit", "--quiet", "-m", "target")
            target_commit = self.run_git(source, "rev-parse", "HEAD")

            (source / "tracked.txt").write_text("dirty\n", encoding="utf-8")
            (source / "untracked.txt").write_text("untracked\n", encoding="utf-8")

            checkout = root / "checkout"
            git_dir = root / "target.git"
            git_home = root / "git-home"
            git_home.mkdir()
            verifier.create_target_checkout(
                target_commit=target_commit,
                target_repository=source,
                required_commits=(baseline_commit,),
                checkout=checkout,
                git_dir=git_dir,
                home=git_home,
            )

            self.assertEqual(
                (checkout / "tracked.txt").read_text(encoding="utf-8"),
                "target\n",
            )
            self.assertFalse((checkout / "untracked.txt").exists())
            self.run_git(
                checkout,
                "cat-file",
                "-e",
                f"{baseline_commit}^{{commit}}",
            )
            self.assertNotIn(
                str(source.resolve()),
                (git_dir / "config").read_text(encoding="utf-8"),
            )

    def test_target_checkout_rejects_non_git_workspace_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            git_home = root / "git-home"
            git_home.mkdir()

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "not a regular Git worktree",
            ):
                verifier.create_target_checkout(
                    target_commit="a" * 40,
                    target_repository=source,
                    checkout=root / "checkout",
                    git_dir=root / "target.git",
                    home=git_home,
                )

            self.assertFalse((root / "checkout").exists())
            self.assertFalse((root / "target.git").exists())

    def test_sandbox_has_no_network_devices_or_credentials(self) -> None:
        command = verifier.sandbox_command(
            checkout=Path("/tmp/checkout"),
            git_dir=Path("/tmp/target.git"),
            cache=Path("/tmp/cache"),
            trusted_root=Path("/tmp/trusted"),
            runtime_home=Path("/tmp/runtime-home"),
            test_python=Path("/tmp/test-python"),
            test_user_site_root=Path("/tmp/test-user-site"),
            homebrew_root=Path("/opt/homebrew"),
            host_cxx=Path("/usr/bin/c++"),
            tool_roots=(
                Path("/tmp/python"),
                Path("/tmp/platformio"),
                Path("/tmp/idf"),
                Path("/tmp/espressif"),
            ),
        )

        self.assertEqual(command[:2], ["sandbox-exec", "-f"])
        self.assertIn(
            str((Path("/tmp/trusted") / "sanhuo-q7.sb").resolve()),
            command,
        )
        self.assertNotIn("sh", command)
        self.assertNotIn("-c", command)
        self.assertIn("CHECKOUT=/private/tmp/checkout", " ".join(command))
        self.assertIn("GIT_DIR=/private/tmp/target.git", " ".join(command))
        self.assertIn("CACHE=/private/tmp/cache", " ".join(command))
        self.assertIn("RUNTIME_HOME=/private/tmp/runtime-home", " ".join(command))
        self.assertIn(
            "SANHUO_MATRIX_TEST_PYTHON=/private/tmp/test-python",
            command,
        )
        self.assertIn(
            "SANHUO_Q7_TEST_USER_SITE_ROOT=/private/tmp/test-user-site",
            command,
        )
        self.assertIn(
            str((Path("/tmp/trusted") / "isolated_driver.py").resolve()),
            command,
        )

    def test_sandbox_profile_never_allows_network_or_device_tree(self) -> None:
        profile = (Path(__file__).parents[1] / "sanhuo-q7.sb").read_text(
            encoding="utf-8"
        )

        self.assertIn("(deny default)", profile)
        self.assertNotIn("(allow network", profile)
        self.assertIn('(deny file-read*\n  (subpath "/Users")', profile)
        self.assertIn(
            '(require-not (subpath (param "RUNTIME_HOME")))',
            profile,
        )
        self.assertIn('(subpath "/dev"))', profile)
        self.assertNotIn('(allow file-read*\n  (subpath "/dev")', profile)
        self.assertIn('(subpath (param "GIT_DIR"))', profile)
        self.assertNotIn('(allow file-write*\n  (subpath (param "GIT_DIR"))', profile)
        self.assertNotIn(
            '(allow file-write*\n  (subpath (param "CHECKOUT"))',
            profile,
        )
        self.assertIn('(literal "/dev/null")', profile)
        self.assertIn('(literal "/dev/urandom")', profile)

    @unittest.skipUnless(
        sys.platform == "darwin"
        and Path("/usr/bin/sandbox-exec").is_file(),
        "requires the macOS sandbox used by the verifier",
    )
    def test_sandbox_runtime_home_cleanup_keeps_sibling_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            secret = root / "operator-secret.txt"
            secret.write_text("must stay unreadable", encoding="utf-8")
            paths = {
                name: root / name
                for name in ("checkout", "git", "cache", "runtime")
            }
            for path in paths.values():
                path.mkdir()
            (paths["runtime"] / "tmp").mkdir()
            profile = (Path(__file__).parents[1] / "sanhuo-q7.sb").resolve()
            python_root = Path(sys.executable).resolve().parent.parent
            command = [
                "/usr/bin/sandbox-exec",
                "-f",
                str(profile),
                "-D",
                f"CHECKOUT={paths['checkout']}",
                "-D",
                f"GIT_DIR={paths['git']}",
                "-D",
                f"CACHE={paths['cache']}",
                "-D",
                f"TRUSTED_ROOT={profile.parent}",
                "-D",
                f"RUNTIME_HOME={paths['runtime']}",
                "-D",
                f"PYTHON_ROOT={python_root}",
                "-D",
                f"PLATFORMIO_ROOT={paths['cache']}",
                "-D",
                f"IDF_ROOT={paths['cache']}",
                "-D",
                f"ESPRESSIF_ROOT={paths['cache']}",
                "-D",
                f"TEST_USER_SITE_ROOT={paths['cache']}",
                "/usr/bin/env",
                "-i",
                f"TMPDIR={paths['runtime'] / 'tmp'}",
                str(Path(sys.executable).resolve()),
                "-c",
                (
                    "from pathlib import Path\n"
                    "import tempfile\n"
                    "handle=tempfile.TemporaryDirectory(prefix='sandbox-test-')\n"
                    f"secret=Path({json.dumps(str(secret))})\n"
                    "try:\n"
                    "    secret.read_text(encoding='utf-8')\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('sibling temp file became readable')\n"
                    "handle.cleanup()\n"
                ),
            ]
            result = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            self.assertEqual(
                result.returncode,
                0,
                result.stderr.decode("utf-8", errors="replace"),
            )

    def test_only_the_four_fixed_candidates_are_run(self) -> None:
        self.assertEqual(
            verifier.CANDIDATES,
            ("MF-P2", "MF-T0", "MF-T1", "MF-T2"),
        )
        self.assertEqual(
            verifier.TARGET_REQUIRED_COMMITS,
            ("8ae75f9a4082094784ac4b8f466d1466dd5ab5f2",),
        )
        self.assertEqual(
            verifier.container_actions(),
            [
                (candidate, action)
                for candidate in verifier.CANDIDATES
                for action in ("build", "qualify", "audit")
            ],
        )

    def test_reports_are_snapshotted_before_untrusted_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for role in verifier.ROLES:
                (root / f"{role}-review.json").write_text(
                    json.dumps(
                        {
                            "role": role,
                            "decision": "passed",
                        }
                    ),
                    encoding="utf-8",
                )
            snapshots = verifier.snapshot_reports(root)
            (root / "primary-review.json").write_text(
                '{"role":"primary","decision":"changes_requested"}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "report changed after it was captured",
            ):
                verifier.assert_report_snapshots_unchanged(root, snapshots)

    def test_report_snapshot_rejects_symlink_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.json"
            target.write_text("{}", encoding="utf-8")
            (root / "primary-review.json").symlink_to(target)
            (root / "verifier-review.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "cannot be a symbolic link",
            ):
                verifier.snapshot_reports(root)

    def test_duplicate_json_field_is_rejected_before_execution(self) -> None:
        payload = b'{"schema":"x","schema":"y"}'

        with self.assertRaisesRegex(
            verifier.VerificationError,
            "duplicate field",
        ):
            verifier.load_closed_json(payload, label="primary")

    def test_changes_requested_is_rejected_before_matrix_runner(self) -> None:
        primary = self.approved_report("primary")
        primary["decision"] = "changes_requested"

        with self.assertRaisesRegex(
            verifier.VerificationError,
            "decision is not passed",
        ):
            verifier.prevalidate_reports(
                {
                    "primary": primary,
                    "verifier": self.approved_report("verifier"),
                },
                target_commit="a" * 40,
            )

    def test_review_challenge_binds_trusted_verifier_commit(self) -> None:
        evidence = self.matrix_evidence()

        first = verifier.review_challenge(
            role="primary",
            target_commit="a" * 40,
            verifier_commit="b" * 40,
            evidence=evidence,
        )
        second = verifier.review_challenge(
            role="primary",
            target_commit="a" * 40,
            verifier_commit="c" * 40,
            evidence=evidence,
        )

        self.assertNotEqual(first, second)

    def test_prompt_templates_are_inert_and_bind_both_commits(self) -> None:
        bundle = verifier.build_review_prompt_bundle(
            target_commit="a" * 40,
            verifier_commit_sha="b" * 40,
            evidence=self.matrix_evidence(),
        )

        self.assertEqual(bundle["reviewed_commit_sha"], "a" * 40)
        self.assertEqual(bundle["verifier_commit_sha"], "b" * 40)
        primary = bundle["prompts"]["primary"]["report_template"]
        checking = bundle["prompts"]["verifier"]["report_template"]
        self.assertEqual(primary["decision"], "changes_requested")
        self.assertTrue(
            all(value is False for value in primary["attestations"].values())
        )
        self.assertNotEqual(primary["challenge"], checking["challenge"])

    def test_prevalidation_requires_same_evidence_for_both_reports(self) -> None:
        reports = {
            "primary": self.approved_report("primary"),
            "verifier": self.approved_report("verifier"),
        }
        reports["verifier"]["candidates"]["MF-T2"]["elf_sha256"] = "f" * 64

        with self.assertRaisesRegex(
            verifier.VerificationError,
            "same matrix evidence",
        ):
            verifier.prevalidate_reports(
                reports,
                target_commit="a" * 40,
            )

    def test_blocking_finding_rejects_final_verification(self) -> None:
        report = self.approved_report("primary")
        report["findings"] = [
            {
                "severity": "medium",
                "title": "仍有阻塞问题",
                "file": "README.md",
                "line": 1,
                "description": "当前提交仍可能错误通过。",
                "recommendation": "修复后重新审查。",
            }
        ]

        with self.assertRaisesRegex(
            verifier.VerificationError,
            "contains blocking findings",
        ):
            verifier.validate_review_report(
                report,
                expected_role="primary",
                target_commit="a" * 40,
                verifier_commit="b" * 40,
                evidence=self.matrix_evidence(),
                tracked_files={"README.md"},
            )

    def test_matrix_result_propagates_review_risks(self) -> None:
        reports = {
            "primary": self.approved_report("primary"),
            "verifier": self.approved_report("verifier"),
        }
        reports["primary"]["findings"] = [
            {
                "severity": "low",
                "title": "交接文字可更清楚",
                "file": "README.md",
                "line": 1,
                "description": "不影响离线结论。",
                "recommendation": "后续改善措辞。",
            }
        ]

        result = verifier.make_matrix_result(
            target_commit="a" * 40,
            verifier_commit="b" * 40,
            evidence=self.matrix_evidence(),
            reports=reports,
            tracked_files={"README.md"},
        )

        self.assertTrue(result["offline_qualified"])
        self.assertIn("外部 AI 身份仍为自述", result["known_risks"])
        self.assertEqual(
            result["non_blocking_findings"][0]["title"],
            "交接文字可更清楚",
        )
        self.assertFalse(result["hardware_authorized"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "primary-review.json").write_bytes(
                b"x" * (verifier.MAX_REPORT_BYTES + 1)
            )
            (root / "verifier-review.json").write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "is too large",
            ):
                verifier.snapshot_reports(root)

    def test_hardware_authority_is_always_false(self) -> None:
        result = verifier.qualification_result(
            commit="a" * 40,
            evidence_sha256="b" * 64,
            review_receipt_sha256="c" * 64,
        )

        self.assertTrue(result["offline_qualified"])
        self.assertFalse(result["hardware_test_eligible"])
        self.assertFalse(result["flashable"])
        self.assertFalse(result["hardware_authorized"])
        self.assertEqual(result["hardware_commands"], [])


if __name__ == "__main__":
    unittest.main()
