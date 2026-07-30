from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import isolated_driver


class IsolatedDriverTests(unittest.TestCase):
    def test_driver_uses_fixed_actions_without_shell(self) -> None:
        commands = isolated_driver.matrix_commands()

        self.assertEqual(len(commands), 12)
        self.assertEqual(
            commands[0][-3:],
            ["build", "--candidate", "MF-P2"],
        )
        self.assertEqual(
            commands[-1][-3:],
            ["audit", "--candidate", "MF-T2"],
        )
        self.assertTrue(all(isinstance(command, list) for command in commands))
        self.assertTrue(all("sh" not in command[:1] for command in commands))

    def test_trusted_capability_derivation_rejects_missing_motion(self) -> None:
        p2_symbols = {
            "uart_write_bytes",
            "M5StackChan_Class::begin",
            "Motion::move(int, int, int)",
            "SCSCL::WritePos",
            "M5StackChan_Class::getBatteryVoltage",
        }

        capabilities = isolated_driver.derive_capabilities("MF-P2", p2_symbols)

        self.assertTrue(capabilities["motion"])
        self.assertTrue(capabilities["uart"])
        self.assertTrue(capabilities["ina226"])
        self.assertFalse(capabilities["usb"])
        with self.assertRaisesRegex(RuntimeError, "motion capability is absent"):
            isolated_driver.derive_capabilities(
                "MF-T0",
                {"uart_write_bytes", "executeCandidate()"},
            )

    def test_driver_puts_platformio_state_inside_runtime_home(self) -> None:
        environment = {
            "SANHUO_Q7_RUNTIME_HOME": "/tmp/runtime",
            "SANHUO_Q7_CHECKOUT": "/tmp/checkout",
            "SANHUO_Q7_PLATFORMIO_ROOT": "/tmp/locked-platformio",
            "SANHUO_Q7_PLATFORMIO_BINDINGS_ROOT": "/tmp/readonly-bindings",
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
            closed["SANHUO_MATRIX_PLATFORMIO_BINDINGS_ROOT"],
            "/tmp/readonly-bindings",
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
        self.assertLessEqual(len(detail), 500)

    def test_runtime_layout_has_no_writable_toolchain_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            cli = root / "cli_phase2.py"
            cli.write_text("# fixture\n", encoding="utf-8")
            with (
                mock.patch.object(isolated_driver, "CLI", cli),
                mock.patch.dict(
                    os.environ,
                    {
                        "SANHUO_Q7_RUNTIME_HOME": str(runtime),
                    },
                    clear=True,
                ),
            ):
                isolated_driver.prepare_runtime_layout()

            self.assertTrue((runtime / "platformio-core/cache").is_dir())
            self.assertFalse((runtime / "platformio-core/platforms").exists())
            self.assertFalse((runtime / "platformio-core/packages").exists())


if __name__ == "__main__":
    unittest.main()
