from __future__ import annotations

import copy
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

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
                    f"Q{index}": f"{index + 7:x}"[-1] * 64 for index in range(7)
                },
                "gate_semantic_summary": {
                    f"Q{index}": {"validated": True} for index in range(7)
                },
            }
            for candidate in verifier.CANDIDATES
        }

    def test_runtime_manifest_changes_only_fresh_evidence_fields(self) -> None:
        hardware_state = {
            "eligible": False,
            "flashable": False,
            "authorized": False,
            "commands": [],
        }
        tracked = {
            "schema": "sanhuo.motion_phase2c_screen_candidate.v1",
            "candidate_id": "MF-T0-H1A",
            "parent_candidate_id": "MF-T0",
            "state": "screen_design",
            "scenario": "h0_plus_h1a_20s",
            "duration_ms": 20_000,
            "parent_q7": {"offline_qualified": True},
            "parent_evidence": {"schedule_sha256": "a" * 64},
            "screen_schedule": {"commands": 434, "sha256": "b" * 64},
            "builds": {
                "clean_builds": 0,
                "report_sha256": None,
                "reproducible": None,
                "status": "not_run",
            },
            "gate_results": {f"Q{index}": "not_run" for index in range(8)},
            "known_limits": ["design only"],
            "offline_qualified": False,
            "hardware_state": hardware_state,
        }
        runtime = {
            **copy.deepcopy(tracked),
            "schema": "sanhuo.motion_phase2c_screen_candidate_runtime.v1",
            "state": "research_only",
            "known_limits": [
                "Q7 independent phase2c-h1a review is still blocked",
                "offline H1-A evidence does not prove physical robot stability",
                "H1-A cannot prove 60-second or full-system stability",
            ],
            "toolchain_lock_sha256": "c" * 64,
            "source_sha256": "d" * 64,
            "firmware": {"sha256": "e" * 64},
            "elf": {"sha256": "f" * 64},
            "resources": {},
            "firmware_capabilities": {},
            "build_tool_capabilities": {
                "network": False,
                "serial": False,
                "flash": False,
                "reset": False,
                "playback": False,
                "motion": False,
            },
        }
        verifier._validate_runtime_manifest_static_binding(
            candidate="MF-T0-H1A",
            runtime_manifest=runtime,
            tracked_manifest=tracked,
        )

        runtime["parent_candidate_id"] = "MF-T1"
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "tracked static field",
        ):
            verifier._validate_runtime_manifest_static_binding(
                candidate="MF-T0-H1A",
                runtime_manifest=runtime,
                tracked_manifest=tracked,
            )

    def test_precheck_reports_and_summary_are_directly_validated(self) -> None:
        gate_reports = {
            gate: {
                "schema": "sanhuo.motion_phase2c_gate_report.v1",
                "candidate_id": "MF-T0-H1A",
                "gate": gate,
                "status": "passed",
                "evidence": {"gate": gate, "index": index},
                "evidence_sha256": verifier.sha256_json(
                    {"gate": gate, "index": index}
                ),
                "covered": ["direct evidence"],
                "not_covered": [],
            }
            for index, gate in enumerate(verifier.GATES)
        }
        manifest_gates = {
            gate: {
                "status": "passed",
                "report_sha256": gate_reports[gate]["evidence_sha256"],
            }
            for gate in verifier.GATES
        }
        manifest_gates["Q7"] = {
            "status": "blocked",
            "report_sha256": None,
        }
        summary_gates = copy.deepcopy(manifest_gates)
        summary_gates["Q7"]["reason"] = (
            "independent phase2c-h1a review credential is absent"
        )
        summary = {
            "schema": "sanhuo.motion_phase2c_qualification_summary.v1",
            "candidate_id": "MF-T0-H1A",
            "precheck_status": "passed",
            "gate_results": summary_gates,
            "q7_receipt_sha256": None,
            "review_mode": None,
            "assurance_limitations": [
                "Q7 independent phase2c-h1a review has not produced a trusted receipt"
            ],
            "known_risks": [
                "offline H1-A evidence is not hardware or 60-second qualification"
            ],
            "non_blocking_findings": [],
            "offline_qualified": False,
            "hardware_test_eligible": False,
            "flashable": False,
            "hardware_authorized": False,
            "hardware_commands": [],
        }
        arguments = {
            "candidate": "MF-T0-H1A",
            "gate_reports": gate_reports,
            "summary": summary,
            "audit_gates": {
                gate: gate_reports[gate]["evidence_sha256"] for gate in verifier.GATES
            },
            "manifest_gates": manifest_gates,
            "build": {},
            "trusted_elf": {},
            "trusted_q0": {},
            "tracked_manifest": {},
        }

        with mock.patch.object(
            verifier,
            "_validate_gate_semantics",
            return_value={"validated": True},
        ):
            verifier._validate_precheck_artifacts(**arguments)

        tampered_reports = copy.deepcopy(gate_reports)
        tampered_reports["Q3"]["covered"] = []
        with mock.patch.object(
            verifier,
            "_validate_gate_semantics",
            return_value={"validated": True},
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "Q3 report is invalid",
            ):
                verifier._validate_precheck_artifacts(
                    **{**arguments, "gate_reports": tampered_reports}
                )

        tampered_summary = copy.deepcopy(summary)
        tampered_summary["hardware_authorized"] = True
        with mock.patch.object(
            verifier,
            "_validate_gate_semantics",
            return_value={"validated": True},
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "qualification summary is invalid",
            ):
                verifier._validate_precheck_artifacts(
                    **{**arguments, "summary": tampered_summary}
                )

        tampered_raw = copy.deepcopy(gate_reports)
        tampered_raw["Q2"]["evidence"]["index"] = 999
        with mock.patch.object(
            verifier,
            "_validate_gate_semantics",
            return_value={"validated": True},
        ):
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "raw evidence hash drift",
            ):
                verifier._validate_precheck_artifacts(
                    **{**arguments, "gate_reports": tampered_raw}
                )

    def test_q2_semantics_require_all_12_locked_screen_tests(self) -> None:
        counts = {
            "collected": 12,
            "executed": 12,
            "passed": 12,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        }
        summary = verifier._validate_gate_semantics(
            candidate="MF-T0-H1A",
            gate="Q2",
            evidence={
                "tests": {
                    "path": (
                        "firmware/sanhuo-stackchan-idf/tests/"
                        "test_motion_firmware_matrix_phase2c_screen.py"
                    ),
                    "expected_tests": 12,
                    "counts": counts,
                    "python_executable_sha256": "1" * 64,
                    "normalized_stdout_sha256": "2" * 64,
                    "summary": "12 passed in <elapsed>",
                },
                "compiler_contract": "C++17 warnings-as-errors ASan UBSan",
                "firmware_compiler_warning_counts": [0, 0],
                "build_report_sha256": "3" * 64,
            },
            build={"report_sha256": "3" * 64, "reproducibility": {}},
            trusted_elf={},
            trusted_q0={},
            tracked_manifest={},
        )

        self.assertEqual(summary["tests"], 12)

    @unittest.skip("Phase 2B remains covered by immutable verifier commit 1d9c0a2")
    def test_p2_q3_binds_exact_public_trajectory_identity(self) -> None:
        properties = {
            "schema": "sanhuo.motion_phase2_q3_properties.v1",
            "cases": 10_000,
            "seed": 53_361,
            "tick_jumps_ms": [20, 40, 100, 250],
            "boundary_cases": 3_114,
            "reversal_cases": 9_992,
            "start_equals_end_cases": 951,
            "p2_mapping_checks": 10_000,
            "transport_candidate_checks": 30_000,
            "deterministic": True,
            "hardware_used": False,
            "maximum_t1_hold_error_raw": 2,
            "maximum_t2_proxy_error_raw": 2,
            "maximum_t2_segment_ms": 390,
            "raw_envelope": {
                "pan": [360, 560],
                "tilt": [620, 754],
            },
            "trace_sha256": (
                "4ff0768cd5e4be26c85080c822abc78dafab4fe4645bafcefda46a9106196078"
            ),
        }
        properties["report_sha256"] = verifier.sha256_json(properties)
        evidence = {
            "randomized_properties": properties,
            "public_target_count": 58,
            "public_targets_sha256": (
                "e188788005e5f262de294788e61a17c56a492239f1445779d87c40d45b111117"
            ),
            "system_duration_ms": 60_000,
            "first": {"at_ms": 0, "yaw_tenths": 0, "pitch_tenths": 0},
            "last": {
                "at_ms": 58_140,
                "yaw_tenths": 0,
                "pitch_tenths": 0,
            },
            "yaw_tenths_range": [-350, 350],
            "pitch_tenths_range": [-120, 140],
            "header_sha256": (
                "6eb9f679f65b47e140c0f1cd69a08b04b42c5be78240257030289c3090f9e007"
            ),
        }

        summary = verifier._validate_gate_semantics(
            candidate="MF-T0-H1A",
            gate="Q3",
            evidence=evidence,
            build={},
            trusted_elf={},
            trusted_q0={},
        )

        self.assertEqual(summary["cases"], 10_000)
        changed_properties = copy.deepcopy(evidence)
        changed_properties["randomized_properties"]["seed"] = 53_362
        changed_payload = dict(changed_properties["randomized_properties"])
        changed_payload.pop("report_sha256")
        changed_properties["randomized_properties"]["report_sha256"] = (
            verifier.sha256_json(changed_payload)
        )
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "Q3 property evidence is invalid",
        ):
            verifier._validate_gate_semantics(
                candidate="MF-P2",
                gate="Q3",
                evidence=changed_properties,
                build={},
                trusted_elf={},
                trusted_q0={},
            )

        too_early = copy.deepcopy(evidence)
        too_early["last"]["at_ms"] = 56_999
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "MF-P2 Q3 public target semantics drift",
        ):
            verifier._validate_gate_semantics(
                candidate="MF-P2",
                gate="Q3",
                evidence=too_early,
                build={},
                trusted_elf={},
                trusted_q0={},
            )

        changed_middle_target = copy.deepcopy(evidence)
        changed_middle_target["header_sha256"] = "2" * 64
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "MF-P2 Q3 public target semantics drift",
        ):
            verifier._validate_gate_semantics(
                candidate="MF-P2",
                gate="Q3",
                evidence=changed_middle_target,
                build={},
                trusted_elf={},
                trusted_q0={},
            )

    @unittest.skip("Phase 2B remains covered by immutable verifier commit 1d9c0a2")
    def test_transport_q3_binds_complete_frozen_schedule_identity(self) -> None:
        properties = {
            "schema": "sanhuo.motion_phase2_q3_properties.v1",
            "cases": 10_000,
            "seed": 53_361,
            "tick_jumps_ms": [20, 40, 100, 250],
            "boundary_cases": 3_114,
            "reversal_cases": 9_992,
            "start_equals_end_cases": 951,
            "p2_mapping_checks": 10_000,
            "transport_candidate_checks": 30_000,
            "deterministic": True,
            "hardware_used": False,
            "maximum_t1_hold_error_raw": 2,
            "maximum_t2_proxy_error_raw": 2,
            "maximum_t2_segment_ms": 390,
            "raw_envelope": {
                "pan": [360, 560],
                "tilt": [620, 754],
            },
            "trace_sha256": (
                "4ff0768cd5e4be26c85080c822abc78dafab4fe4645bafcefda46a9106196078"
            ),
        }
        properties["report_sha256"] = verifier.sha256_json(properties)
        counts = {
            "collected": 6,
            "executed": 6,
            "passed": 6,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "xfailed": 0,
            "xpassed": 0,
        }
        evidence = {
            "randomized_properties": properties,
            "schedule_sha256": (
                "a5f5b9dff057cbc3182d0ad8f5ba7c6b9c48da2a4f34e5d81d2f5000408a5446"
            ),
            "source": {
                "baseline_commit": "8ae75f9a4082094784ac4b8f466d1466dd5ab5f2",
                "replay_input_sha256": (
                    "7dad9594f0a97a7cba825d05f6e49905f40ded8d3182c471b088c9650b0bf259"
                ),
                "trace_sha256": (
                    "1fa69975f34bbe56173cd54b3d2ec3f2523c879389a6d67544b50b69a8e9c71f"
                ),
                "trajectory_table_sha256": (
                    "85637c041d099b1a647924e90d39fee363085982a8d3206382ca9b34b224c3d4"
                ),
            },
            "parameters": {
                "ack_budget_ms": 25,
                "automatic_retry": False,
                "pan_error_threshold_raw": 3,
                "pan_linear_error_raw": None,
                "pan_max_segment_ms": None,
                "pan_strategy": "adaptive_hold",
                "runtime_override": False,
                "speed": 0,
                "tick_ms": 20,
                "tilt_strategy": "every_changed_raw",
            },
            "metrics": {
                "final_pan_raw": 459,
                "final_tilt_raw": 678,
                "mandatory_boundaries": 47,
                "mandatory_boundaries_preserved": True,
                "max_pan_proxy_error_raw": 2,
                "max_pan_segment_ms": 20,
                "pan_transactions": 661,
                "theoretical_uart_bytes": 20_672,
                "tilt_transactions": 427,
                "total_transactions": 1_088,
            },
            "property_test": {
                "paths": ["locked-q3-suite.py"],
                "returncode": 0,
                "expected_tests": 6,
                "counts": counts,
                "python_executable_sha256": "1" * 64,
                "normalized_stdout_sha256": "2" * 64,
                "summary": "6 passed",
            },
        }

        verifier._validate_gate_semantics(
            candidate="MF-T1",
            gate="Q3",
            evidence=evidence,
            build={},
            trusted_elf={},
            trusted_q0={},
        )

        changed_source = copy.deepcopy(evidence)
        changed_source["source"]["trace_sha256"] = "3" * 64
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "MF-T1 Q3 schedule semantics drift",
        ):
            verifier._validate_gate_semantics(
                candidate="MF-T1",
                gate="Q3",
                evidence=changed_source,
                build={},
                trusted_elf={},
                trusted_q0={},
            )

    def test_phase2c_q3_binds_screen_prefix_and_reversal(self) -> None:
        tracked = {
            "parent_evidence": {"schedule_sha256": "1" * 64},
            "screen_schedule": {
                "commands": 434,
                "parent_prefix_sha256": "2" * 64,
                "sha256": "3" * 64,
            },
        }
        evidence = {
            "screen_schedule_sha256": "3" * 64,
            "parent_schedule_sha256": "1" * 64,
            "parent_prefix_sha256": "2" * 64,
            "metrics": {
                "command_count": 434,
                "contains_known_reversal": True,
                "last_command_at_ms": 19_400,
            },
            "parameters": {
                "ack_budget_ms": 25,
                "audio": False,
                "automatic_reset": False,
                "automatic_retry": False,
                "face": False,
                "full_timeline": False,
                "runtime_override": False,
                "tick_ms": 20,
                "uac": False,
            },
            "known_reversal": [
                {
                    "axis": "pan",
                    "at_ms": 17_100,
                    "source_at_ms": 17_100,
                },
                {
                    "axis": "tilt",
                    "at_ms": 17_100,
                    "source_at_ms": 17_100,
                },
            ],
        }
        summary = verifier._validate_gate_semantics(
            candidate="MF-T0-H1A",
            gate="Q3",
            evidence=evidence,
            build={"reproducibility": {}},
            trusted_elf={},
            trusted_q0={},
            tracked_manifest=tracked,
        )
        self.assertEqual(summary["known_reversal_at_ms"], 17_100)

        tampered = copy.deepcopy(evidence)
        tampered["known_reversal"][0]["at_ms"] = 16_900
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "Q3 screen-prefix semantics drift",
        ):
            verifier._validate_gate_semantics(
                candidate="MF-T0-H1A",
                gate="Q3",
                evidence=tampered,
                build={"reproducibility": {}},
                trusted_elf={},
                trusted_q0={},
                tracked_manifest=tracked,
            )

        t2_tracked = copy.deepcopy(tracked)
        t2_tracked["screen_schedule"]["commands"] = 206
        t2_evidence = copy.deepcopy(evidence)
        t2_evidence["metrics"]["command_count"] = 206
        t2_evidence["known_reversal"] = [
            {
                "axis": "tilt",
                "at_ms": 17_100,
                "source_at_ms": 17_100,
            }
        ]
        t2_summary = verifier._validate_gate_semantics(
            candidate="MF-T2-H1A",
            gate="Q3",
            evidence=t2_evidence,
            build={"reproducibility": {}},
            trusted_elf={},
            trusted_q0={},
            tracked_manifest=t2_tracked,
        )
        self.assertEqual(t2_summary["commands"], 206)

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
                review_session_nonce="d" * 64,
                evidence=evidence,
            ),
            "review_instance_id": f"{role}-unique-instance",
            "reviewed_commit_sha": target_commit,
            "candidates": evidence,
            "decision": "passed",
            "reviewed_areas": {area: True for area in verifier.REVIEWED_AREAS},
            "covered": ["检查了精确提交、可信验签器和四候选证据"],
            "not_covered": ["未直接检查真实硬件"],
            "known_risks": ["外部 AI 身份仍为自述"],
            "attestations": {item: True for item in verifier.ATTESTATIONS},
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

    def test_trusted_command_failure_is_bounded_and_terminal_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(verifier.VerificationError) as raised:
                verifier._run_trusted(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import sys;"
                            "sys.stderr.buffer.write(b'\\x1b[31m' + b'x' * 5000);"
                            "raise SystemExit(1)"
                        ),
                    ],
                    cwd=None,
                    environment={
                        "HOME": temporary,
                        "PATH": "/usr/bin:/bin",
                    },
                )

        detail = str(raised.exception)
        self.assertNotIn("\x1b", detail)
        encoded = detail.split("stderr_tail_hex=", 1)[1]
        self.assertEqual(
            len(bytes.fromhex(encoded)),
            verifier.MAX_TRUSTED_FAILURE_EXCERPT_BYTES,
        )

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

    def test_pristine_idf_snapshot_excludes_ignored_python_and_git_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "idf"
            source.mkdir()
            self.run_git(source, "init", "--quiet")
            self.run_git(source, "config", "user.name", "Q7 test")
            self.run_git(source, "config", "user.email", "q7@example.invalid")
            (source / ".gitignore").write_text("*.pyc\n", encoding="utf-8")
            (source / "tools").mkdir()
            (source / "tools/idf.py").write_text(
                "print('trusted idf')\n",
                encoding="utf-8",
            )
            (source / "tools/idf-link.py").symlink_to("idf.py")
            self.run_git(
                source,
                "add",
                ".gitignore",
                "tools/idf.py",
                "tools/idf-link.py",
            )
            self.run_git(source, "commit", "--quiet", "-m", "idf")
            commit = self.run_git(source, "rev-parse", "HEAD")
            tree = self.run_git(source, "rev-parse", "HEAD^{tree}")
            (source / "tools/json.pyc").write_bytes(b"ignored attack")
            destination = root / "pristine"
            git_home = root / "git-home"
            git_home.mkdir()

            closure = verifier.create_pristine_idf_snapshot(
                source_root=source,
                destination=destination,
                expected_commit=commit,
                expected_tree=tree,
                temporary_root=root,
                home=git_home,
            )

            self.assertTrue((destination / "tools/idf.py").is_file())
            self.assertEqual(
                (destination / "tools/idf-link.py").resolve(),
                (destination / "tools/idf.py").resolve(),
            )
            self.assertFalse((destination / "tools/json.pyc").exists())
            self.assertFalse((destination / ".git").exists())
            self.assertEqual(verifier._directory_closure(destination), closure)

    def test_sandbox_has_no_network_devices_or_credentials(self) -> None:
        command = verifier.sandbox_command(
            checkout=Path("/tmp/checkout"),
            git_dir=Path("/tmp/target.git"),
            cache=Path("/tmp/cache"),
            trusted_root=Path("/tmp/trusted"),
            runtime_home=Path("/tmp/runtime-home"),
            output_root=Path("/tmp/output"),
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
            lifecycle_token="com.sanhuo.q7.0123456789abcdef0123456789abcdef",
            driver_mode="action",
            candidate="MF-T0-H1A",
            action="build",
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
        self.assertIn("OUTPUT_ROOT=/private/tmp/output", " ".join(command))
        self.assertIn(
            "LIFECYCLE_TOKEN=com.sanhuo.q7.0123456789abcdef0123456789abcdef",
            " ".join(command),
        )
        self.assertIn(
            "ACTION_ARTIFACT_ROOT=/private/tmp/output/artifacts/MF-T0-H1A",
            " ".join(command),
        )
        self.assertIn(
            "ACTION_BINARY_ROOT=/private/tmp/output/binaries/MF-T0-H1A",
            " ".join(command),
        )
        self.assertIn(
            "ACTION_OUTPUT_00=/private/tmp/output/artifacts/MF-T0-H1A/build-report.json",
            " ".join(command),
        )
        self.assertIn(
            "SANHUO_MATRIX_TEST_PYTHON=/private/tmp/test-python",
            command,
        )
        self.assertIn(
            "SANHUO_Q7_TEST_USER_SITE_ROOT=/private/tmp/test-user-site",
            command,
        )
        self.assertIn(
            "PLATFORMIO_PLATFORM_LOCK=/private/tmp/platformio/platforms.lock",
            " ".join(command),
        )
        self.assertIn(
            "PLATFORMIO_PACKAGE_LOCK=/private/tmp/platformio/packages.lock",
            " ".join(command),
        )
        self.assertIn(
            str((Path("/tmp/trusted") / "isolated_driver.py").resolve()),
            command,
        )
        driver_index = command.index(
            str((Path("/tmp/trusted") / "isolated_driver.py").resolve())
        )
        self.assertEqual(command[driver_index - 2 : driver_index], ["-I", "-S"])
        qualify_command = verifier.sandbox_command(
            checkout=Path("/tmp/checkout"),
            git_dir=Path("/tmp/target.git"),
            cache=Path("/tmp/cache"),
            trusted_root=Path("/tmp/trusted"),
            runtime_home=Path("/tmp/runtime-home"),
            output_root=Path("/tmp/output"),
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
            lifecycle_token="com.sanhuo.q7.0123456789abcdef0123456789abcdef",
            driver_mode="action",
            candidate="MF-T0-H1A",
            action="qualify",
        )
        self.assertIn(
            "ACTION_ARTIFACT_ROOT=/private/tmp/runtime-home/unused-artifacts",
            " ".join(qualify_command),
        )
        for filename in (
            "manifest.generated.json",
            "qualification-summary.json",
            *(f"q{index}-report.json" for index in range(7)),
        ):
            self.assertIn(
                f"/private/tmp/output/artifacts/MF-T0-H1A/{filename}",
                " ".join(qualify_command),
            )

    def test_sandbox_profile_never_allows_network_or_device_tree(self) -> None:
        profile = (Path(__file__).parents[1] / "sanhuo-q7.sb").read_text(
            encoding="utf-8"
        )

        self.assertIn("(deny default)", profile)
        self.assertNotIn("(allow network", profile)
        self.assertIn("(allow file-read*)", profile)
        deny_read = profile.split("(deny file-read*", 1)[1].split(
            "(allow file-read*", 1
        )[0]
        for closed_root in (
            "/Applications",
            "/Library",
            "/Network",
            "/Users",
            "/Volumes",
            "/cores",
            "/dev",
            "/home",
            "/opt",
            "/private",
        ):
            self.assertIn(f'(subpath "{closed_root}")', deny_read)
        self.assertNotIn('(subpath "/private/etc")', profile)
        self.assertNotIn('(subpath "/private/var")', profile)
        self.assertNotIn('(allow file-read*\n  (subpath "/dev")', profile)
        self.assertIn('(subpath (param "GIT_DIR"))', profile)
        self.assertIn('(subpath (param "SEALED_INPUT"))', profile)
        self.assertNotIn('(allow file-write*\n  (subpath (param "GIT_DIR"))', profile)
        self.assertNotIn(
            '(allow file-write*\n  (subpath (param "SEALED_INPUT"))',
            profile,
        )
        self.assertIn('(literal (param "PLATFORMIO_PLATFORM_LOCK"))', profile)
        self.assertIn('(literal (param "PLATFORMIO_PACKAGE_LOCK"))', profile)
        self.assertNotIn(
            '(allow file-write*\n  (subpath (param "CHECKOUT"))',
            profile,
        )
        self.assertIn("(allow process-exec\n", profile)
        self.assertIn('(subpath (param "EXEC_PYTHON_ROOT"))', profile)
        self.assertIn('(subpath (param "RUNTIME_HOME"))', profile)
        self.assertNotIn(
            '(subpath (param "CHECKOUT"))\n  (subpath',
            profile.split("(allow process-exec", 1)[1].split(")", 1)[0],
        )
        self.assertNotIn(
            '(subpath (param "CACHE"))',
            profile.split("(allow process-exec", 1)[1].split("(allow process-fork)", 1)[
                0
            ],
        )
        self.assertIn('(subpath (param "ACTION_ARTIFACT_ROOT"))', profile)
        self.assertIn('(subpath (param "ACTION_BINARY_ROOT"))', profile)
        self.assertIn('(subpath (param "XCODE_FRAMEWORKS"))', profile)
        self.assertIn('(subpath (param "XCODE_SHARED_FRAMEWORKS"))', profile)
        self.assertIn('(subpath (param "EXEC_HOMEBREW_OPENSSL"))', profile)
        self.assertIn('(literal "/private/etc/paths")', profile)
        self.assertIn('(subpath "/private/etc/paths.d")', profile)
        self.assertNotIn('(subpath "/opt/homebrew")', profile)
        self.assertIn('(literal "/dev/null")', profile)
        self.assertIn('(literal "/dev/urandom")', profile)

    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
        "requires the macOS sandbox used by the verifier",
    )
    def test_sandbox_runtime_home_cleanup_keeps_sibling_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            secret = root / "operator-secret.txt"
            secret.write_text("must stay unreadable", encoding="utf-8")
            paths = {
                name: root / name
                for name in ("checkout", "git", "cache", "runtime", "output")
            }
            for path in paths.values():
                path.mkdir()
            (paths["runtime"] / "tmp").mkdir()
            action_artifacts = paths["output"] / "artifacts/MF-T0-H1A"
            action_binaries = paths["output"] / "binaries/MF-T0-H1A"
            prior_artifacts = paths["output"] / "artifacts/MF-T1-H1A"
            action_artifacts.mkdir(parents=True)
            action_binaries.mkdir(parents=True)
            prior_artifacts.mkdir(parents=True)
            untrusted_executable = paths["checkout"] / "untrusted-tool"
            untrusted_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            untrusted_executable.chmod(0o755)
            protected_input = paths["cache"] / "platforms/espressif32/platform.py"
            protected_input.parent.mkdir(parents=True)
            protected_input.write_text("locked", encoding="utf-8")
            platform_lock = paths["cache"] / "platforms.lock"
            package_lock = paths["cache"] / "packages.lock"
            profile = (Path(__file__).parents[1] / "sanhuo-q7.sb").resolve()
            python_root = Path(sys.executable).resolve().parent.parent
            developer_root = Path(
                "/Applications/Xcode.app/Contents/Developer"
            ).resolve()
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
                f"OUTPUT_ROOT={paths['output']}",
                "-D",
                "LIFECYCLE_TOKEN=com.sanhuo.q7.0123456789abcdef0123456789abcdef",
                "-D",
                f"ACTION_ARTIFACT_ROOT={paths['runtime'] / 'unused-artifacts'}",
                "-D",
                f"ACTION_BINARY_ROOT={paths['runtime'] / 'unused-binaries'}",
                *[
                    item
                    for index in range(verifier.MAX_ACTION_OUTPUT_FILES)
                    for item in (
                        "-D",
                        (
                            f"ACTION_OUTPUT_{index:02d}="
                            f"{action_artifacts / 'current.json'}"
                            if index == 0
                            else (
                                f"ACTION_OUTPUT_{index:02d}="
                                f"{paths['runtime'] / f'unused-output-{index:02d}'}"
                            )
                        ),
                    )
                ],
                "-D",
                f"SEALED_INPUT={paths['cache']}",
                "-D",
                f"XCODE_ROOT={developer_root}",
                "-D",
                (
                    "XCODE_SHARED_FRAMEWORKS="
                    "/Applications/Xcode.app/Contents/SharedFrameworks"
                ),
                "-D",
                "XCODE_FRAMEWORKS=/Applications/Xcode.app/Contents/Frameworks",
                "-D",
                (
                    "EXEC_HOMEBREW_OPENSSL="
                    "/opt/homebrew/Cellar/openssl@3/3.6.3/lib"
                ),
                "-D",
                (
                    "EXEC_HOMEBREW_PYTHON="
                    "/opt/homebrew/Cellar/python@3.11/3.11.14_3"
                ),
                "-D",
                f"PYTHON_ROOT={python_root}",
                "-D",
                f"PLATFORMIO_ROOT={paths['cache']}",
                "-D",
                f"PLATFORMIO_PLATFORM_LOCK={platform_lock}",
                "-D",
                f"PLATFORMIO_PACKAGE_LOCK={package_lock}",
                "-D",
                f"IDF_ROOT={paths['cache']}",
                "-D",
                f"ESPRESSIF_ROOT={paths['cache']}",
                "-D",
                f"TEST_USER_SITE_ROOT={paths['cache']}",
                "-D",
                f"TEST_GLOBAL_SITE_ROOT={paths['cache']}",
                *[
                    item
                    for name in (
                        "EXEC_PYTHON_ROOT",
                        "EXEC_PIO_PLATFORM",
                        "EXEC_PIO_FRAMEWORK",
                        "EXEC_PIO_XTENSA",
                        "EXEC_PIO_RISCV",
                        "EXEC_PIO_ESPTOOL",
                        "EXEC_PIO_SCONS",
                        "EXEC_IDF_ROOT",
                        "EXEC_IDF_PYTHON",
                        "EXEC_IDF_XTENSA",
                        "EXEC_HOMEBREW_CMAKE",
                        "EXEC_HOMEBREW_NINJA",
                    )
                    for item in ("-D", f"{name}={python_root}")
                ],
                "/usr/bin/env",
                "-i",
                f"TMPDIR={paths['runtime'] / 'tmp'}",
                f"DEVELOPER_DIR={developer_root}",
                "PYTHONFAULTHANDLER=1",
                str(Path(sys.executable).resolve()),
                "-c",
                (
                    "from pathlib import Path\n"
                    "import subprocess, tempfile\n"
                    "handle=tempfile.TemporaryDirectory(prefix='sandbox-test-')\n"
                    f"secret=Path({json.dumps(str(secret))})\n"
                    "try:\n"
                    "    secret.read_text(encoding='utf-8')\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('sibling temp file became readable')\n"
                    "try:\n"
                    "    Path('/private/etc/hosts').read_text(encoding='utf-8')\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('unlisted host data became readable')\n"
                    "Path('/private/etc/paths').read_text(encoding='utf-8')\n"
                    "paths_d=Path('/private/etc/paths.d')\n"
                    "if not paths_d.is_dir() or not list(paths_d.iterdir()):\n"
                    "    raise RuntimeError('fixed system PATH inputs are unreadable')\n"
                    "xcode=subprocess.run(\n"
                    "    ['/usr/bin/xcrun', '--find', 'xcodebuild'],\n"
                    "    check=False, stdout=subprocess.PIPE,\n"
                    "    stderr=subprocess.PIPE,\n"
                    ")\n"
                    "if xcode.returncode != 0:\n"
                    "    raise RuntimeError('xcrun cannot locate locked Xcode')\n"
                    "git=subprocess.run(\n"
                    "    ['/usr/bin/git', '--version'],\n"
                    "    check=False, stdout=subprocess.PIPE,\n"
                    "    stderr=subprocess.PIPE,\n"
                    ")\n"
                    "if git.returncode != 0:\n"
                    "    raise RuntimeError(\n"
                    "        'git cannot use locked Xcode: '\n"
                    "        + git.stderr.decode('utf-8', errors='replace')\n"
                    "    )\n"
                    "ssl_check=subprocess.run(\n"
                    "    [\n"
                    "        '/opt/homebrew/opt/python@3.11/bin/python3.11',\n"
                    "        '-c',\n"
                    "        \"import ssl; assert ssl.OPENSSL_VERSION.startswith('OpenSSL 3.6.3')\",\n"
                    "    ],\n"
                    "    check=False, stdout=subprocess.PIPE,\n"
                    "    stderr=subprocess.PIPE,\n"
                    ")\n"
                    "if ssl_check.returncode != 0:\n"
                    "    raise RuntimeError(\n"
                    "        'locked Homebrew OpenSSL runtime is unavailable: '\n"
                    "        + ssl_check.stderr.decode('utf-8', errors='replace')\n"
                    "    )\n"
                    "try:\n"
                    "    Path(\n"
                    "        '/opt/homebrew/Cellar/openssl@3/3.6.3/include/openssl/ssl.h'\n"
                    "    ).read_bytes()\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('adjacent OpenSSL headers became readable')\n"
                    f"platform_lock=Path({json.dumps(str(platform_lock))})\n"
                    "platform_lock.write_text('ephemeral', encoding='utf-8')\n"
                    f"package_lock=Path({json.dumps(str(package_lock))})\n"
                    "package_lock.write_text('ephemeral', encoding='utf-8')\n"
                    f"tool_input=Path({json.dumps(str(protected_input))})\n"
                    "try:\n"
                    "    tool_input.write_text('tampered', encoding='utf-8')\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('PlatformIO input became writable')\n"
                    "platform_lock.unlink()\n"
                    "platform_lock.symlink_to(tool_input)\n"
                    "try:\n"
                    "    platform_lock.write_text('tampered', encoding='utf-8')\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('lock symlink escaped exact write rule')\n"
                    "if tool_input.read_text(encoding='utf-8') != 'locked':\n"
                    "    raise RuntimeError('PlatformIO input changed through lock')\n"
                    f"current=Path({json.dumps(str(action_artifacts / 'current.json'))})\n"
                    "current.write_text('current', encoding='utf-8')\n"
                    f"prior=Path({json.dumps(str(prior_artifacts / 'old.json'))})\n"
                    "try:\n"
                    "    prior.write_text('tampered', encoding='utf-8')\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('another candidate became writable')\n"
                    f"untrusted=Path({json.dumps(str(untrusted_executable))})\n"
                    "try:\n"
                    "    subprocess.run([str(untrusted)], check=False)\n"
                    "except PermissionError:\n"
                    "    pass\n"
                    "else:\n"
                    "    raise RuntimeError('reviewed checkout became executable')\n"
                    f"generated=Path({json.dumps(str(paths['runtime'] / 'generated-tool'))})\n"
                    "generated.write_text('#!/bin/sh\\nexit 0\\n', encoding='utf-8')\n"
                    "generated.chmod(0o700)\n"
                    "if generated.read_text(encoding='utf-8') != '#!/bin/sh\\nexit 0\\n':\n"
                    "    raise RuntimeError('runtime output could not be read back')\n"
                    "if subprocess.run([str(generated)], check=False).returncode != 0:\n"
                    "    raise RuntimeError('generated sandbox test could not execute')\n"
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
                (
                    result.stdout.decode("utf-8", errors="replace")
                    + result.stderr.decode("utf-8", errors="replace")
                ),
            )

    def test_only_the_three_fixed_phase2c_candidates_are_run(self) -> None:
        self.assertEqual(
            verifier.CANDIDATES,
            ("MF-T0-H1A", "MF-T1-H1A", "MF-T2-H1A"),
        )
        self.assertEqual(
            verifier.TARGET_REQUIRED_COMMITS,
            (
                "8ae75f9a4082094784ac4b8f466d1466dd5ab5f2",
                "e9b8675944742cb729883ca767f5a5a98b773954",
            ),
        )
        self.assertEqual(
            verifier.container_actions(),
            [
                (candidate, action)
                for candidate in verifier.CANDIDATES
                for action in ("build", "qualify", "audit")
            ],
        )

    def test_sealed_snapshot_is_independent_from_abandoned_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime_output = root / "runtime-output"
            runtime_output.mkdir()
            artifact = runtime_output / "artifact.json"
            artifact.write_text('{"state":"complete"}\n', encoding="utf-8")
            sealed = root / "sealed"

            with artifact.open("r+b", buffering=0) as escaped_process_handle:
                verifier._copy_regular_tree(runtime_output, sealed)
                escaped_process_handle.seek(0)
                escaped_process_handle.write(b'{"state":"tampered"}\n')

            self.assertEqual(
                (sealed / "artifact.json").read_text(encoding="utf-8"),
                '{"state":"complete"}\n',
            )
            (runtime_output / "indirect").symlink_to(artifact)
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "indirect or special",
            ):
                verifier._copy_regular_tree(
                    runtime_output,
                    root / "rejected",
                )

    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
        "requires the macOS sandbox used by the verifier",
    )
    def test_lifecycle_token_finds_and_kills_detached_sandbox_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output = root / "output"
            output.mkdir()
            control = root / "control"
            control.mkdir()
            ready = control / "ready"
            trigger = control / "trigger"
            artifact = output / "artifact.json"
            lifecycle_token = "com.sanhuo.q7.fedcba9876543210fedcba9876543210"
            python_executable = Path(
                "/Applications/Xcode.app/Contents/Developer/usr/bin/python3"
            )
            profile = "\n".join(
                [
                    "(version 1)",
                    "(deny default)",
                    (
                        "(allow process-exec "
                        '(subpath "/Applications/Xcode.app/Contents/Developer"))'
                    ),
                    "(allow process-fork)",
                    "(allow signal)",
                    "(allow sysctl-read)",
                    (
                        "(allow mach-lookup "
                        f'(global-name "{lifecycle_token}"))'
                    ),
                    "(allow file-read*)",
                    (
                        "(allow file-write* "
                        f'(subpath "{output}") '
                        f'(subpath "{control}") '
                        '(literal "/dev/null"))'
                    ),
                ]
            )
            detached_writer = "\n".join(
                [
                    "import os, time",
                    "from pathlib import Path",
                    f"artifact=Path({json.dumps(str(artifact))})",
                    f"ready=Path({json.dumps(str(ready))})",
                    f"trigger=Path({json.dumps(str(trigger))})",
                    "if os.fork(): os._exit(0)",
                    "os.setsid()",
                    "if os.fork(): os._exit(0)",
                    "handle=artifact.open('w+b', buffering=0)",
                    "handle.write(b'complete')",
                    "os.fsync(handle.fileno())",
                    "ready.write_text(str(os.getpid()), encoding='utf-8')",
                    "while not trigger.exists():",
                    "    time.sleep(0.01)",
                    "handle.seek(0)",
                    "handle.write(b'tampered')",
                    "os.fsync(handle.fileno())",
                    "handle.close()",
                ]
            )
            launched = subprocess.run(
                [
                    "/usr/bin/sandbox-exec",
                    "-p",
                    profile,
                    str(python_executable),
                    "-I",
                    "-c",
                    detached_writer,
                ],
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )
            self.assertEqual(launched.returncode, 0)

            deadline = time.monotonic() + 5
            while not ready.is_file() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.is_file(), "detached writer did not become ready")
            detached_pid = int(ready.read_text(encoding="utf-8"))

            try:
                self.assertTrue(
                    verifier._process_has_sandbox_lifecycle_token(
                        detached_pid,
                        lifecycle_token,
                        artifact,
                    )
                )
                terminated = verifier._terminate_sandbox_lifecycle_processes(
                    lifecycle_token,
                    artifact,
                )
                self.assertIn(detached_pid, {identity.pid for identity in terminated})

                deadline = time.monotonic() + 5
                while verifier._process_identity(detached_pid) is not None:
                    if time.monotonic() >= deadline:
                        self.fail("detached sandbox writer survived lifecycle cleanup")
                    time.sleep(0.01)
                trigger.write_text("continue", encoding="utf-8")
                self.assertEqual(
                    artifact.read_bytes(),
                    b"complete",
                )
            finally:
                try:
                    os.kill(detached_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
        "requires the macOS sandbox used by the verifier",
    )
    def test_lifecycle_token_survives_nested_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            control = root / "control"
            control.mkdir()
            ready = control / "ready"
            trigger = control / "trigger"
            lifecycle_token = "com.sanhuo.q7.0123456789abcdef0123456789abcdef"
            profile = "\n".join(
                [
                    "(version 1)",
                    "(deny default)",
                    "(allow process-exec)",
                    "(allow sysctl-read)",
                    "(allow file-read*)",
                    f'(allow file-write* (subpath "{control}"))',
                    (
                        "(allow mach-lookup "
                        f'(global-name "{lifecycle_token}"))'
                    ),
                ]
            )
            nested = "\n".join(
                [
                    "(version 1)",
                    "(deny default)",
                    "(allow sysctl-read)",
                    "(allow file-read*)",
                    f'(allow file-write* (subpath "{control}"))',
                ]
            )
            script = "\n".join(
                [
                    "import ctypes, json, os, time",
                    "from pathlib import Path",
                    f"ready=Path({json.dumps(str(ready))})",
                    f"trigger=Path({json.dumps(str(trigger))})",
                    f"nested={json.dumps(nested)}",
                    "library=ctypes.CDLL('/usr/lib/libsandbox.dylib')",
                    "error=ctypes.c_char_p()",
                    (
                        "result=library.sandbox_init("
                        "nested.encode(), 0, ctypes.byref(error))"
                    ),
                    (
                        "ready.write_text(json.dumps({"
                        "'pid': os.getpid(), 'result': result, "
                        "'error': error.value.decode() if error.value else ''"
                        "}), encoding='utf-8')"
                    ),
                    "while not trigger.exists():",
                    "    time.sleep(0.01)",
                ]
            )
            process = subprocess.Popen(
                [
                    "/usr/bin/sandbox-exec",
                    "-p",
                    profile,
                    str(Path(sys.executable).resolve()),
                    "-I",
                    "-c",
                    script,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.is_file() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.is_file())
                nested_result = json.loads(ready.read_text(encoding="utf-8"))
                self.assertEqual(
                    nested_result["result"],
                    -1,
                )
                self.assertEqual(nested_result["error"], "Operation not permitted")
                self.assertTrue(
                    verifier._process_has_sandbox_lifecycle_token(
                        nested_result["pid"],
                        lifecycle_token,
                        ready,
                    )
                )
            finally:
                trigger.write_text("continue", encoding="utf-8")
                process.wait(timeout=5)

    @unittest.skipUnless(
        sys.platform == "darwin" and Path("/usr/bin/sandbox-exec").is_file(),
        "requires macOS sandbox process inspection",
    )
    def test_lifecycle_identity_excludes_unrelated_sandboxes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            probe = Path(temporary) / "never-created-probe"
            self.assertEqual(
                verifier._sandbox_lifecycle_processes(
                    "com.sanhuo.q7.abcdef0123456789abcdef0123456789",
                    probe,
                ),
                (),
            )

    def test_sandboxed_trusted_command_rejects_a_detached_descendant(self) -> None:
        identity = verifier.ProcessIdentity(
            pid=1234,
            start_seconds=100,
            start_microseconds=200,
        )
        completed = subprocess.CompletedProcess(
            args=["sandbox-exec"],
            returncode=0,
            stdout=b"ok",
            stderr=b"",
        )
        with (
            mock.patch.object(verifier, "_run_trusted", return_value=completed),
            mock.patch.object(
                verifier,
                "_terminate_sandbox_lifecycle_processes",
                return_value=(identity,),
            ),
            self.assertRaisesRegex(
                verifier.VerificationError,
                "left sandbox descendants running",
            ),
        ):
            verifier._run_sandboxed_trusted(
                ["sandbox-exec"],
                lifecycle_token=(
                    "com.sanhuo.q7.0123456789abcdef0123456789abcdef"
                ),
                lifecycle_probe=Path("/tmp/runtime/lifecycle-probe"),
                cwd=Path("/tmp"),
                environment={},
            )

    def test_persistent_snapshot_excludes_temporary_build_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "output"
            artifacts = output / "artifacts/MF-T0-H1A"
            binaries = output / "binaries/MF-T0-H1A"
            run_tree = artifacts / "run-12345"
            run_tree.mkdir(parents=True)
            binaries.mkdir(parents=True)
            (run_tree / "temporary-object.o").write_bytes(b"x" * 1024)
            (artifacts / "build-report.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            (binaries / "firmware.bin").write_bytes(b"bin")
            (binaries / "firmware.elf").write_bytes(b"elf")
            sealed = root / "sealed-output"

            verifier._snapshot_persistent_matrix_output(output, sealed)

            self.assertFalse(
                (sealed / "artifacts/MF-T0-H1A/run-12345").exists()
            )
            self.assertTrue(
                (sealed / "artifacts/MF-T0-H1A/build-report.json").is_file()
            )
            self.assertEqual(
                (sealed / "binaries/MF-T0-H1A/firmware.elf").read_bytes(),
                b"elf",
            )

    def test_trusted_action_delta_rejects_cross_stage_changes(self) -> None:
        build_files = {
            path.format(candidate="MF-T0-H1A"): "a" * 64
            for path in verifier.ACTION_ADDED_FILES["build"]
        }
        receipt = verifier._validate_action_delta(
            candidate="MF-T0-H1A",
            action="build",
            before={},
            after=build_files,
        )
        self.assertEqual(receipt["added_files"], sorted(build_files))

        unexpected = dict(build_files)
        unexpected["artifacts/MF-T0-H1A/q0-report.json"] = "b" * 64
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "file delta drift",
        ):
            verifier._validate_action_delta(
                candidate="MF-T0-H1A",
                action="build",
                before={},
                after=unexpected,
            )

        qualify_files = {
            path.format(candidate="MF-T0-H1A"): "c" * 64
            for path in verifier.ACTION_ADDED_FILES["qualify"]
        }
        tampered_before = dict(build_files)
        tampered_before["artifacts/MF-T0-H1A/build-report.json"] = "d" * 64
        with self.assertRaisesRegex(
            verifier.VerificationError,
            "changed prior persistent evidence",
        ):
            verifier._validate_action_delta(
                candidate="MF-T0-H1A",
                action="qualify",
                before=build_files,
                after={**tampered_before, **qualify_files},
            )

    def test_operator_review_directory_cannot_overlap_readable_roots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            readable = root / "workspace"
            review = readable / "reviews"
            review.mkdir(parents=True)

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "overlaps",
            ):
                verifier.assert_operator_directory_isolated(
                    review,
                    forbidden_roots=(readable,),
                    must_exist=True,
                )

    def test_unpinned_toolchain_lock_is_rejected_before_any_executable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir="/private/tmp") as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            lock_path = checkout / verifier.TOOLCHAIN_LOCK_RELATIVE_PATH
            lock_path.parent.mkdir(parents=True)
            lock_path.write_text("{}\n", encoding="utf-8")
            missing = root / "must-not-run"
            inputs = verifier.RuntimeInputs(
                python_root=missing,
                platformio_root=missing,
                cache_root=missing,
                idf_root=missing,
                espressif_root=missing,
                test_python=missing,
                test_user_site_root=missing,
                homebrew_root=missing,
                host_cxx=missing,
            )

            with self.assertRaisesRegex(
                verifier.VerificationError,
                "not pinned",
            ):
                verifier.prevalidate_runtime_inputs(
                    checkout=checkout,
                    inputs=inputs,
                    git_home=root,
                )

    def test_review_challenge_is_idempotent_for_same_immutable_tuple(self) -> None:
        arguments = {
            "role": "primary",
            "target_commit": "a" * 40,
            "verifier_commit": "b" * 40,
            "review_session_nonce": "d" * 64,
            "evidence": self.matrix_evidence(),
        }

        self.assertEqual(
            verifier.review_challenge(**arguments),
            verifier.review_challenge(**arguments),
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
            review_session_nonce="d" * 64,
            evidence=evidence,
        )
        second = verifier.review_challenge(
            role="primary",
            target_commit="a" * 40,
            verifier_commit="c" * 40,
            review_session_nonce="d" * 64,
            evidence=evidence,
        )

        self.assertNotEqual(first, second)
        third = verifier.review_challenge(
            role="primary",
            target_commit="a" * 40,
            verifier_commit="b" * 40,
            review_session_nonce="e" * 64,
            evidence=evidence,
        )
        self.assertNotEqual(first, third)

    def test_prompt_templates_are_inert_and_bind_both_commits(self) -> None:
        bundle = verifier.build_review_prompt_bundle(
            target_commit="a" * 40,
            verifier_commit_sha="b" * 40,
            review_session_nonce="d" * 64,
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

    def test_review_bundle_reconstructs_exact_rendered_prompt_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "review"
            evidence = self.matrix_evidence()
            bundle = verifier.build_review_prompt_bundle(
                target_commit="a" * 40,
                verifier_commit_sha="b" * 40,
                review_session_nonce="d" * 64,
                evidence=evidence,
            )
            verifier.write_prompt_bundle(output, bundle)

            loaded = verifier.load_review_bundle(
                output,
                target_commit="a" * 40,
                verifier_commit_sha="b" * 40,
            )
            self.assertEqual(loaded, bundle)

            (output / "primary-prompt.md").write_text(
                "weakened prompt\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                verifier.VerificationError,
                "rendered prompt bytes drift",
            ):
                verifier.load_review_bundle(
                    output,
                    target_commit="a" * 40,
                    verifier_commit_sha="b" * 40,
                )

    def test_prevalidation_requires_same_evidence_for_both_reports(self) -> None:
        reports = {
            "primary": self.approved_report("primary"),
            "verifier": self.approved_report("verifier"),
        }
        reports["verifier"]["candidates"]["MF-T2-H1A"]["elf_sha256"] = "f" * 64

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
                review_session_nonce="d" * 64,
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
            review_session_nonce="d" * 64,
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
