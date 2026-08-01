from __future__ import annotations

import hashlib
import inspect
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import isolated_driver


class IsolatedDriverTests(unittest.TestCase):
    def test_phase2c_p2_h1a_profile_is_fixed(self) -> None:
        self.assertEqual(
            isolated_driver.CANDIDATES,
            ("MF-P2-H1A",),
        )
        self.assertEqual(isolated_driver.CLI.name, "cli_phase2c_p2.py")

    def test_driver_uses_fixed_actions_without_shell(self) -> None:
        commands = isolated_driver.matrix_commands()

        self.assertEqual(len(commands), 3)
        self.assertEqual(
            commands[0][-1:],
            ["build"],
        )
        self.assertEqual(
            commands[-1][-1:],
            ["audit"],
        )
        self.assertTrue(all(isinstance(command, list) for command in commands))
        self.assertTrue(all("sh" not in command[:1] for command in commands))

    def test_trusted_q5_harness_executes_fixed_p2_runtime_core(self) -> None:
        source = isolated_driver.TRUSTED_Q5_HARNESS_SOURCE

        self.assertIn('#include "phase2c_p2_executor.h"', source)
        self.assertIn('#include "phase2c_p2_observer_core.h"', source)
        self.assertIn("kTrustedTargets", source)
        self.assertIn("p2::executeScreen(", source)
        self.assertIn("failure_indices_covered", source)
        self.assertIn("post_failure_targets", source)
        self.assertNotIn("phase2c_p2_screen_executor.cpp", source)

    def test_trusted_p2_targets_digest_is_fixed(self) -> None:
        self.assertEqual(
            isolated_driver._trusted_targets_sha256(),
            "db843ff1200e942ce50b12178a897478dead0a07fe4aaca4fcd7691c4bfb1e58",
        )

    def test_trusted_result_is_captured_before_target_harness_runs(self) -> None:
        source = inspect.getsource(
            isolated_driver.trusted_q5_executor_evidence
        )

        self.assertLess(
            source.index("trusted_evidence ="),
            source.index("target_stdout = _run_checked("),
        )
        self.assertLess(
            source.index("trusted_executable.read_bytes()"),
            source.index("target_stdout = _run_checked("),
        )

    def test_target_q5_rebuild_uses_target_relative_compile_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary) / "checkout"

            layout = isolated_driver._target_q5_build_layout(checkout)

        self.assertEqual(
            layout["project_root"],
            checkout / "firmware/sanhuo-stackchan-idf",
        )
        self.assertEqual(
            layout["payload_root"],
            Path("tools/motion_firmware_matrix/payloads/P2-H1A/src"),
        )
        self.assertEqual(
            layout["source"],
            Path("tests/host/motion_matrix/phase2c_p2_screen_executor.cpp"),
        )

    def test_relative_q5_compile_is_stable_across_checkout_paths(self) -> None:
        host_cxx = Path("/usr/bin/c++")
        if not host_cxx.is_file():
            self.skipTest("Apple host compiler is unavailable")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def compile_fixture(name: str) -> str:
                project_root = root / name / "firmware/sanhuo-stackchan-idf"
                payload_root = project_root / "tools/payloads"
                source = project_root / "tests/host/harness.cpp"
                generated_root = root / f"generated-{name}"
                payload_root.mkdir(parents=True)
                source.parent.mkdir(parents=True)
                generated_root.mkdir()
                (payload_root / "payload.h").write_text(
                    "#pragma once\ninline int payload_value() { return 7; }\n",
                    encoding="utf-8",
                )
                (generated_root / "generated.h").write_text(
                    "#pragma once\ninline int generated_value() { return 5; }\n",
                    encoding="utf-8",
                )
                source.write_text(
                    '#include <cassert>\n#include "payload.h"\n'
                    '#include "generated.h"\nint main() {\n'
                    "  assert(payload_value() + generated_value() == 12);\n"
                    "  return 0;\n}\n",
                    encoding="utf-8",
                )
                executable = generated_root / "q5-harness"
                with mock.patch.object(
                    isolated_driver,
                    "_closed_environment",
                    return_value={
                        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                        "TMPDIR": str(root),
                    },
                ):
                    isolated_driver._compile_q5_harness(
                        host_cxx=host_cxx,
                        payload_root=Path("tools/payloads"),
                        include_root=generated_root,
                        source=Path("tests/host/harness.cpp"),
                        executable=executable,
                        cwd=project_root,
                    )
                return hashlib.sha256(executable.read_bytes()).hexdigest()

            first = compile_fixture("short")
            second = compile_fixture("a-much-longer-checkout-location")

        self.assertEqual(first, second)

    def test_trusted_capability_derivation_rejects_missing_motion(self) -> None:
        p2_symbols = {
            "uart_write_bytes",
            "M5StackChan_Class::begin()",
            "Motion::move(int, int, int)",
            "SCSCL::WritePos(unsigned char, unsigned short, unsigned short, unsigned char)",
            "waitForArm",
            "runH0",
            "M5StackChan_Class::getBatteryVoltage()",
        }

        capabilities = isolated_driver.derive_capabilities(
            "MF-P2-H1A",
            p2_symbols,
        )

        self.assertTrue(capabilities["motion"])
        self.assertTrue(capabilities["uart"])
        self.assertTrue(capabilities["ina226"])
        self.assertFalse(capabilities["usb"])
        with self.assertRaisesRegex(RuntimeError, "motion capability is absent"):
            isolated_driver.derive_capabilities(
                "MF-P2-H1A",
                {"uart_write_bytes", "executeCandidate()"},
            )

    def test_driver_puts_platformio_state_inside_runtime_home(self) -> None:
        environment = {
            "SANHUO_Q7_RUNTIME_HOME": "/tmp/runtime",
            "SANHUO_Q7_OUTPUT_ROOT": "/tmp/output",
            "SANHUO_Q7_CHECKOUT": "/tmp/checkout",
            "SANHUO_Q7_PLATFORMIO_ROOT": "/tmp/locked-platformio",
            "SANHUO_Q7_IDF_ROOT": "/tmp/idf",
            "SANHUO_Q7_ESPRESSIF_ROOT": "/tmp/espressif",
            "SANHUO_Q7_TEST_PYTHON": "/tmp/python",
            "SANHUO_Q7_TEST_USER_SITE_ROOT": "/tmp/site",
            "SANHUO_Q7_HOMEBREW_ROOT": "/opt/homebrew",
            "SANHUO_Q7_HOST_CXX": "/usr/bin/c++",
            "SANHUO_Q7_CACHE": "/tmp/cache",
            "SANHUO_Q7_PLATFORMIO_EXECUTABLE": "/tmp/platformio",
        }

        with mock.patch.dict(os.environ, environment, clear=True):
            closed = isolated_driver._closed_environment()

        self.assertEqual(
            closed["SANHUO_MATRIX_PLATFORMIO_RUNTIME_ROOT"],
            "/tmp/runtime/platformio-core",
        )
        self.assertEqual(
            closed["SANHUO_MATRIX_PLATFORMIO_ROOT"],
            "/tmp/locked-platformio",
        )
        self.assertEqual(
            closed["DEVELOPER_DIR"],
            "/Applications/Xcode.app/Contents/Developer",
        )
        self.assertEqual(
            closed["SANHUO_MATRIX_IDF_SOURCE_MODE"],
            "trusted_pristine_snapshot_v1",
        )
        self.assertEqual(
            closed["PLATFORMIO_SETTING_CHECK_PLATFORMIO_INTERVAL"],
            "2147483647",
        )
        self.assertNotIn("PYTHONPATH", closed)

    def test_failure_detail_is_bounded_and_terminal_safe(self) -> None:
        raw = b"\x1b[31mboom\n" + (b"x" * 5000)

        encoded = isolated_driver._failure_output_tail_hex(
            raw,
            limit=isolated_driver.MAX_SINGLE_FAILURE_EXCERPT_BYTES,
        )

        self.assertNotIn("\x1b", encoded)
        self.assertEqual(
            bytes.fromhex(encoded),
            raw[-isolated_driver.MAX_SINGLE_FAILURE_EXCERPT_BYTES :],
        )
        detail = isolated_driver._failure_stream_detail(b"", raw)
        self.assertLessEqual(len(detail), 1600)

    def test_nested_failure_preserves_child_excerpt_head_and_tail(self) -> None:
        nested = b"ASSERTION-HEAD\n" + (b"x" * 1000) + b"\nSUMMARY-TAIL"
        stderr = (
            b"trusted child failed: stdout_tail_hex="
            + nested.hex().encode("ascii")
            + b"; command_returncode=1\n"
        )

        detail = isolated_driver._failure_stream_detail(b"", stderr)

        head_match = re.search(r"nested_head_hex=([0-9a-f]+)", detail)
        tail_match = re.search(r"nested_tail_hex=([0-9a-f]+)", detail)
        self.assertIsNotNone(head_match)
        self.assertIsNotNone(tail_match)
        assert head_match is not None and tail_match is not None
        self.assertTrue(bytes.fromhex(head_match.group(1)).startswith(b"ASSERTION-HEAD"))
        self.assertTrue(bytes.fromhex(tail_match.group(1)).endswith(b"SUMMARY-TAIL"))
        self.assertLessEqual(len(detail), 1600)

    def test_q5_json_rejects_duplicates_and_oversize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"schema":1,"schema":2}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "repeats field"):
                isolated_driver._load_q5_json(
                    duplicate,
                    label="duplicate fixture",
                )

            oversized = root / "oversized.json"
            oversized.write_bytes(
                b"x" * (isolated_driver.MAX_Q5_EVIDENCE_BYTES + 1)
            )
            with self.assertRaisesRegex(RuntimeError, "size boundary"):
                isolated_driver._load_q5_json(
                    oversized,
                    label="oversized fixture",
                )

    def test_runtime_layout_has_no_writable_toolchain_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            output = root / "output"
            cli = root / "cli_phase2c.py"
            cli.write_text("# fixture\n", encoding="utf-8")
            with (
                mock.patch.object(isolated_driver, "CLI", cli),
                mock.patch.dict(
                    os.environ,
                    {
                        "SANHUO_Q7_RUNTIME_HOME": str(runtime),
                        "SANHUO_Q7_OUTPUT_ROOT": str(output),
                    },
                    clear=True,
                ),
            ):
                isolated_driver.prepare_runtime_layout()

            self.assertTrue((runtime / "platformio-core/cache").is_dir())
            self.assertTrue((output / "artifacts").is_dir())
            self.assertTrue((output / "binaries").is_dir())
            self.assertFalse((runtime / "platformio-core/platforms").exists())
            self.assertFalse((runtime / "platformio-core/packages").exists())


if __name__ == "__main__":
    unittest.main()
