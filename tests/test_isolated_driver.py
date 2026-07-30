from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
