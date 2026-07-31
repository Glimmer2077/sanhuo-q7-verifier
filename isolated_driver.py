#!/usr/bin/env python3
"""Trusted single-action driver executed inside the macOS sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import sys
from pathlib import Path


CANDIDATES = ("MF-T0-H1A", "MF-T1-H1A", "MF-T2-H1A")
ACTIONS = ("build", "qualify", "audit")
CLI = Path(
    os.environ.get("SANHUO_Q7_CHECKOUT", "/workspace")
    + "/firmware/sanhuo-stackchan-idf/"
    "tools/motion_firmware_matrix/cli_phase2c.py"
)
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_SINGLE_FAILURE_EXCERPT_BYTES = 768
MAX_SPLIT_FAILURE_EXCERPT_BYTES = 320
MAX_Q5_EVIDENCE_BYTES = 1024 * 1024
XCODE_DEVELOPER_ROOT = "/Applications/Xcode.app/Contents/Developer"
SCREEN_COMMAND_FIELDS = {
    "at_ms",
    "axis",
    "raw",
    "move_time_ms",
    "speed",
    "source_at_ms",
}
SCREEN_PARAMETERS = {
    "tick_ms": 20,
    "ack_budget_ms": 25,
    "automatic_retry": False,
    "automatic_reset": False,
    "runtime_override": False,
    "audio": False,
    "face": False,
    "uac": False,
    "full_timeline": False,
}
SCREEN_SAFETY = {
    "h0_position_commands": 0,
    "fresh_boot_nonce_required": True,
    "arm_count_maximum": 1,
    "second_arm_rejected": True,
    "safe_center_attempts_maximum": 1,
    "terminal_after_run": True,
}
SCREEN_HARDWARE_STATE = {
    "eligible": False,
    "flashable": False,
    "authorized": False,
    "commands": [],
}
EXPECTED_SCREEN = {
    "MF-T0-H1A": {
        "parent": "MF-T0",
        "commands": 434,
        "parent_schedule_sha256": (
            "9d149895eadeadf8ec7cfbe0daf49546bc295ee7e47b4c11b23f57bfaebc3e16"
        ),
        "parent_prefix_sha256": (
            "16655c6ce70560200fcccbc16f095d5c2987e8ce391289e0b88eb7e54061409a"
        ),
        "screen_schedule_sha256": (
            "d1be05a76ad4215f77040ce1d74bb03e4a261972c2a51f304feb093632965a09"
        ),
        "generated_schedule_sha256": (
            "49f7aa126e54002a7582a85e902f77aae195bbef47575309908ce675d93e2615"
        ),
        "exact_schedule_digest": "cf4b03ceed04f267",
    },
    "MF-T1-H1A": {
        "parent": "MF-T1",
        "commands": 364,
        "parent_schedule_sha256": (
            "a5f5b9dff057cbc3182d0ad8f5ba7c6b9c48da2a4f34e5d81d2f5000408a5446"
        ),
        "parent_prefix_sha256": (
            "57264b28dbe7ed1d6585c1c168e4ad29a22770bb344827e80ab3157ac6e46591"
        ),
        "screen_schedule_sha256": (
            "977fd922894c418c7243f6d51279bb96ce5a104b204620b936d9cfed5f1a32ab"
        ),
        "generated_schedule_sha256": (
            "c70201872683b93dbdb76d0408821ecc0f472376d1f48be01651fc72530e2094"
        ),
        "exact_schedule_digest": "da60445e04ff8ae0",
    },
    "MF-T2-H1A": {
        "parent": "MF-T2",
        "commands": 206,
        "parent_schedule_sha256": (
            "8901cab39fc053ea1973da43613682a292c81397bead54c41878185b240f886e"
        ),
        "parent_prefix_sha256": (
            "344637cbaa79d31ed0f6de77abd45a3de9d95b5e31492803deb3a0b6c81b1efa"
        ),
        "screen_schedule_sha256": (
            "61f6f1cc37b88e3e9b8f184b4d6eaec0a7cc69e3559eef2e118c4ff7531259c6"
        ),
        "generated_schedule_sha256": (
            "82274788f96edaa3a2aa5acc5b39fba9bd477f57f08cc5fef137a9a3eacb6ddb"
        ),
        "exact_schedule_digest": "6c37fe14f947e64c",
    },
}
EXPECTED_REVERSAL_AXES = {
    "MF-T0-H1A": {"pan", "tilt"},
    "MF-T1-H1A": {"pan", "tilt"},
    "MF-T2-H1A": {"tilt"},
}
TRUSTED_Q5_HARNESS_SOURCE = r'''#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>

#include "motion_matrix_generated_schedule.h"
#include "phase2c_screen_executor.h"

#ifdef sanhuoVerifierRequire
#undef sanhuoVerifierRequire
#endif

void sanhuoVerifierRequire(bool condition) {
  if (!condition) {
    std::abort();
  }
}

namespace {

using sanhuo::motion_matrix::core::ExecutionError;
using sanhuo::motion_matrix::core::SafeCenterResult;
using sanhuo::motion_matrix::core::SendResult;
using sanhuo::motion_matrix::GeneratedCommand;
using sanhuo::motion_matrix::screen::ScreenExecutionResult;

constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

uint64_t mix(uint64_t digest, uint64_t value) {
  for (unsigned index = 0; index < 8; ++index) {
    digest ^= value & 0xFFU;
    digest *= kFnvPrime;
    value >>= 8;
  }
  return digest;
}

bool sameCommand(const GeneratedCommand &left, const GeneratedCommand &right) {
  return left.at_ms == right.at_ms && left.servo_id == right.servo_id &&
         left.raw == right.raw && left.move_time_ms == right.move_time_ms &&
         left.speed == right.speed;
}

uint64_t exactScheduleDigest() {
  uint64_t digest = kFnvOffset;
  for (const auto &command : sanhuo::motion_matrix::kGeneratedCommands) {
    digest = mix(digest, command.at_ms);
    digest = mix(digest, command.servo_id);
    digest = mix(digest, command.raw);
    digest = mix(digest, command.move_time_ms);
    digest = mix(digest, command.speed);
  }
  return digest;
}

}  // namespace

int main() {
  static_assert(sanhuo::motion_matrix::kGeneratedCommands.size() > 0U);
  const auto &commands = sanhuo::motion_matrix::kGeneratedCommands;
  const std::size_t count = commands.size();
  {
    std::size_t sent = 0;
    std::size_t center_attempts = 0;
    std::size_t duration_waits = 0;
    const std::array<GeneratedCommand, 1> final_center_commands = {
        commands.front()};
    const auto outcome = sanhuo::motion_matrix::screen::executeScreen(
        final_center_commands, sanhuo::motion_matrix::kScreenDurationMs,
        [](uint32_t) {},
        [&sent](const GeneratedCommand &command) {
          sanhuoVerifierRequire(sameCommand(command, commands.front()));
          ++sent;
          return SendResult{ExecutionError::kAccepted, 6U};
        },
        [&center_attempts]() {
          ++center_attempts;
          return SafeCenterResult{
              false, 1U, SendResult{ExecutionError::kAckTruncated, 0U}};
        },
        [&duration_waits](uint32_t) { ++duration_waits; });
    sanhuoVerifierRequire(outcome.result == ScreenExecutionResult::kCenterFailed);
    sanhuoVerifierRequire(outcome.state.completed);
    sanhuoVerifierRequire(outcome.state.safe_stop_latched);
    sanhuoVerifierRequire(outcome.state.errors == 1U);
    sanhuoVerifierRequire(outcome.state.first_error ==
                          ExecutionError::kAckTruncated);
    sanhuoVerifierRequire(outcome.state.safe_center_commands == 1U);
    sanhuoVerifierRequire(outcome.safe_center_attempts == 1U);
    sanhuoVerifierRequire(sent == 1U);
    sanhuoVerifierRequire(center_attempts == 1U);
    sanhuoVerifierRequire(duration_waits == 1U);
  }
  std::size_t healthy_runs = 0;
  std::size_t fault_runs = 0;
  std::size_t safe_stops = 0;
  std::size_t minimum_sent = count;
  std::size_t maximum_sent = 0;
  std::size_t post_failure_performance_writes = 0;
  std::size_t safe_center_attempts_maximum = 0;
  for (std::size_t seed = 0; seed < 100U; ++seed) {
    for (std::size_t repeat = 0; repeat < 2U; ++repeat) {
      (void)repeat;
      {
        std::size_t sent = 0;
        std::size_t wait_index = 0;
        std::size_t center_attempts = 0;
        std::size_t duration_waits = 0;
        const auto outcome = sanhuo::motion_matrix::screen::executeScreen(
            commands, sanhuo::motion_matrix::kScreenDurationMs,
            [&wait_index](uint32_t at_ms) {
              sanhuoVerifierRequire(wait_index < commands.size());
              sanhuoVerifierRequire(at_ms == commands[wait_index].at_ms);
              ++wait_index;
            },
            [&sent](const GeneratedCommand &command) {
              sanhuoVerifierRequire(sent < commands.size());
              sanhuoVerifierRequire(sameCommand(command, commands[sent]));
              ++sent;
              return SendResult{ExecutionError::kAccepted, 6U};
            },
            [&center_attempts]() {
              ++center_attempts;
              return SafeCenterResult{
                  true, 2U, SendResult{ExecutionError::kAccepted, 6U}};
            },
            [&duration_waits](uint32_t duration_ms) {
              sanhuoVerifierRequire(
                  duration_ms == sanhuo::motion_matrix::kScreenDurationMs);
              ++duration_waits;
            });
        sanhuoVerifierRequire(outcome.state.completed);
        sanhuoVerifierRequire(!outcome.state.safe_stop_latched);
        sanhuoVerifierRequire(outcome.state.retries == 0U);
        sanhuoVerifierRequire(sent == count);
        sanhuoVerifierRequire(center_attempts == 1U);
        sanhuoVerifierRequire(outcome.safe_center_attempts == 1U);
        sanhuoVerifierRequire(duration_waits == 1U);
        sanhuoVerifierRequire(wait_index == count);
        ++healthy_runs;
      }
      {
        const std::size_t failure_index = (seed * 97U) % count;
        std::size_t sent = 0;
        std::size_t wait_index = 0;
        std::size_t post_failure = 0;
        std::size_t center_attempts = 0;
        std::size_t duration_waits = 0;
        bool failure_observed = false;
        const auto outcome = sanhuo::motion_matrix::screen::executeScreen(
            commands, sanhuo::motion_matrix::kScreenDurationMs,
            [&wait_index](uint32_t at_ms) {
              sanhuoVerifierRequire(wait_index < commands.size());
              sanhuoVerifierRequire(at_ms == commands[wait_index].at_ms);
              ++wait_index;
            },
            [&](const GeneratedCommand &command) {
              if (failure_observed) {
                ++post_failure;
              }
              const std::size_t current = sent;
              sanhuoVerifierRequire(current < commands.size());
              sanhuoVerifierRequire(sameCommand(command, commands[current]));
              ++sent;
              if (current == failure_index) {
                failure_observed = true;
                return SendResult{ExecutionError::kFeedbackCollision, 0U};
              }
              return SendResult{ExecutionError::kAccepted, 6U};
            },
            [&center_attempts]() {
              ++center_attempts;
              return SafeCenterResult{
                  true, 2U, SendResult{ExecutionError::kAccepted, 6U}};
            },
            [&duration_waits](uint32_t) { ++duration_waits; });
        sanhuoVerifierRequire(!outcome.state.completed);
        sanhuoVerifierRequire(outcome.state.safe_stop_latched);
        sanhuoVerifierRequire(outcome.state.first_error ==
                              ExecutionError::kFeedbackCollision);
        sanhuoVerifierRequire(outcome.state.errors == 1U);
        sanhuoVerifierRequire(outcome.state.retries == 0U);
        sanhuoVerifierRequire(sent == failure_index + 1U);
        sanhuoVerifierRequire(post_failure == 0U);
        sanhuoVerifierRequire(center_attempts == 1U);
        sanhuoVerifierRequire(outcome.safe_center_attempts == 1U);
        sanhuoVerifierRequire(outcome.state.safe_center_commands == 2U);
        sanhuoVerifierRequire(duration_waits == 0U);
        sanhuoVerifierRequire(wait_index == failure_index + 1U);
        ++fault_runs;
        ++safe_stops;
        minimum_sent = std::min(minimum_sent, sent);
        maximum_sent = std::max(maximum_sent, sent);
        post_failure_performance_writes += post_failure;
        safe_center_attempts_maximum =
            std::max(safe_center_attempts_maximum, center_attempts);
      }
    }
  }
  std::cout << "TRUSTED_PHASE2C_Q5 candidate="
            << sanhuo::motion_matrix::kCandidateId << " events=" << count
            << " schedule_digest=" << std::hex << std::setw(16)
            << std::setfill('0') << exactScheduleDigest() << std::dec
            << " healthy_runs=" << healthy_runs
            << " fault_runs=" << fault_runs << " safe_stops=" << safe_stops
            << " min_sent=" << minimum_sent << " max_sent=" << maximum_sent
            << " post_failure_performance_writes="
            << post_failure_performance_writes
            << " safe_center_attempts_maximum="
            << safe_center_attempts_maximum << " passed=1\n";
  return 0;
}
'''
_TRUSTED_Q5_OUTPUT = re.compile(
    rb"^TRUSTED_PHASE2C_Q5 candidate=(MF-T[012]-H1A) events=(\d+) "
    rb"schedule_digest=([0-9a-f]{16}) healthy_runs=(\d+) "
    rb"fault_runs=(\d+) safe_stops=(\d+) min_sent=(\d+) max_sent=(\d+) "
    rb"post_failure_performance_writes=(\d+) "
    rb"safe_center_attempts_maximum=(\d+) passed=1\n$"
)


def matrix_commands() -> list[list[str]]:
    """Describe the fixed matrix without executing it."""

    return [
        [sys.executable, str(CLI), action, "--candidate", candidate]
        for candidate in CANDIDATES
        for action in ACTIONS
    ]


def selected_matrix_command() -> tuple[str, str, list[str]]:
    candidate = os.environ.get("SANHUO_Q7_CANDIDATE")
    action = os.environ.get("SANHUO_Q7_ACTION")
    if candidate not in CANDIDATES or action not in ACTIONS:
        raise RuntimeError("trusted action selection is invalid")
    return (
        candidate,
        action,
        [sys.executable, str(CLI), action, "--candidate", candidate],
    )


def _symbol_contains(symbols: set[str], marker: str) -> bool:
    return any(marker in symbol for symbol in symbols)


def derive_capabilities(
    candidate: str,
    symbols: set[str],
) -> dict[str, bool]:
    """Derive the small fixed capability set from the current ELF."""

    if candidate not in CANDIDATES or not symbols:
        raise RuntimeError("ELF executable symbol evidence is missing")
    uart = _symbol_contains(symbols, "uart_write_bytes")
    required_motion = (
        "sendStrict",
        "attemptSafeCenter",
        "waitForArm",
        "runH0",
    )
    required_transport = ("uart_write_bytes", "usb_serial_jtag_read_bytes")
    if not all(
        _symbol_contains(symbols, marker)
        for marker in required_motion + required_transport
    ):
        raise RuntimeError(f"{candidate} motion capability is absent")
    return {
        "uart": True,
        "motion": True,
        "audio": any(
            _symbol_contains(symbols, marker)
            for marker in (
                "Speaker_Class::begin(",
                "Speaker_Class::play",
                "AudioFileSource::read(",
                "i2s_channel_write(",
            )
        ),
        "usb": True,
        "face": any(
            _symbol_contains(symbols, marker)
            for marker in ("FaceRenderer", "MouthRenderer", "lv_obj_")
        ),
        "ina226": False,
    }


def _closed_environment() -> dict[str, str]:
    runtime_home = os.environ["SANHUO_Q7_RUNTIME_HOME"]
    output_root = os.environ["SANHUO_Q7_OUTPUT_ROOT"]
    checkout = os.environ["SANHUO_Q7_CHECKOUT"]
    platformio_root = os.environ["SANHUO_Q7_PLATFORMIO_ROOT"]
    idf_root = os.environ["SANHUO_Q7_IDF_ROOT"]
    espressif_root = os.environ["SANHUO_Q7_ESPRESSIF_ROOT"]
    test_python = os.environ["SANHUO_Q7_TEST_PYTHON"]
    test_user_site_root = os.environ["SANHUO_Q7_TEST_USER_SITE_ROOT"]
    homebrew_root = os.environ["SANHUO_Q7_HOMEBREW_ROOT"]
    host_cxx = os.environ["SANHUO_Q7_HOST_CXX"]
    return {
        "HOME": runtime_home,
        "PATH": (
            f"{espressif_root}/tools/xtensa-esp-elf/"
            "esp-14.2.0_20260121/xtensa-esp-elf/bin:"
            f"{espressif_root}/python_env/"
            "idf5.5_py3.11_env/bin:/opt/homebrew/bin:/usr/bin:/bin"
        ),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "DEVELOPER_DIR": XCODE_DEVELOPER_ROOT,
        "TMPDIR": f"{runtime_home}/tmp",
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PLATFORMIO_CORE_DIR": f"{runtime_home}/platformio-core",
        "PLATFORMIO_SETTING_ENABLE_TELEMETRY": "no",
        "PLATFORMIO_SETTING_CHECK_PLATFORMIO_INTERVAL": "2147483647",
        "PLATFORMIO_SETTING_CHECK_PRUNE_SYSTEM_THRESHOLD": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "SANHUO_Q7_CHECKOUT": checkout,
        "SANHUO_Q7_RUNTIME_HOME": runtime_home,
        "SANHUO_Q7_PLATFORMIO_ROOT": platformio_root,
        "SANHUO_Q7_IDF_ROOT": idf_root,
        "SANHUO_Q7_ESPRESSIF_ROOT": espressif_root,
        "SANHUO_Q7_TEST_PYTHON": test_python,
        "SANHUO_Q7_TEST_USER_SITE_ROOT": test_user_site_root,
        "SANHUO_Q7_HOMEBREW_ROOT": homebrew_root,
        "SANHUO_Q7_HOST_CXX": host_cxx,
        "SANHUO_MATRIX_ARTIFACT_ROOT": f"{output_root}/artifacts",
        "SANHUO_MATRIX_BINARY_ROOT": f"{output_root}/binaries",
        "SANHUO_MATRIX_SOURCE_CACHE_ROOT": (f"{os.environ['SANHUO_Q7_CACHE']}/sources"),
        "SANHUO_MATRIX_PLATFORMIO_ROOT": platformio_root,
        "SANHUO_MATRIX_PLATFORMIO_EXECUTABLE": os.environ[
            "SANHUO_Q7_PLATFORMIO_EXECUTABLE"
        ],
        "SANHUO_MATRIX_PLATFORMIO_RUNTIME_ROOT": (f"{runtime_home}/platformio-core"),
        "SANHUO_MATRIX_IDF_ROOT": idf_root,
        "SANHUO_MATRIX_IDF_SOURCE_MODE": "trusted_pristine_snapshot_v1",
        "SANHUO_MATRIX_ESPRESSIF_ROOT": espressif_root,
        "SANHUO_MATRIX_TEST_PYTHON": test_python,
        "SANHUO_MATRIX_TEST_USER_SITE_ROOT": test_user_site_root,
        "SANHUO_MATRIX_HOMEBREW_ROOT": homebrew_root,
        "SANHUO_MATRIX_HOST_CXX": host_cxx,
    }


def prepare_runtime_layout() -> None:
    if not CLI.is_file():
        raise RuntimeError("target Q7 CLI is missing")
    runtime_home = Path(os.environ["SANHUO_Q7_RUNTIME_HOME"])
    output_root = Path(os.environ["SANHUO_Q7_OUTPUT_ROOT"])
    (output_root / "artifacts").mkdir(parents=True, exist_ok=True)
    (output_root / "binaries").mkdir(parents=True, exist_ok=True)
    (runtime_home / "platformio-core/cache").mkdir(parents=True, exist_ok=True)


def _process_group_still_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError as exc:
        raise RuntimeError("trusted process group could not be inspected") from exc
    return True


def _failure_output_tail_hex(output: bytes, *, limit: int) -> str:
    """Encode a bounded failure tail without relaying terminal control bytes."""

    return output[-limit:].hex()


def _failure_stream_detail(stdout: bytes, stderr: bytes) -> str:
    limit = (
        MAX_SPLIT_FAILURE_EXCERPT_BYTES
        if stdout and stderr
        else MAX_SINGLE_FAILURE_EXCERPT_BYTES
    )
    return (
        "stdout_tail_hex="
        f"{_failure_output_tail_hex(stdout, limit=limit)}; "
        "stderr_tail_hex="
        f"{_failure_output_tail_hex(stderr, limit=limit)}"
    )


def _run_checked(command: list[str], *, cwd: Path, timeout: int) -> bytes:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=_closed_environment(),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        raise
    if len(stdout) > MAX_COMMAND_OUTPUT_BYTES:
        raise RuntimeError("trusted command stdout exceeded the limit")
    if len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
        raise RuntimeError("trusted command stderr exceeded the limit")
    if process.returncode != 0:
        raise RuntimeError(
            f"trusted command failed; returncode={process.returncode}; "
            f"{_failure_stream_detail(stdout, stderr)}"
        )
    if _process_group_still_exists(process.pid):
        os.killpg(process.pid, signal.SIGKILL)
        raise RuntimeError("target command left same-session processes running")
    return stdout


def run_selected_action() -> dict[str, object]:
    candidate, action, command = selected_matrix_command()
    stdout = _run_checked(
        command,
        cwd=Path(os.environ["SANHUO_Q7_CHECKOUT"]),
        timeout=3600,
    )
    return {
        "schema": "sanhuo.trusted_q7_isolated_action.v1",
        "status": "passed",
        "candidate": candidate,
        "action": action,
        "returncode": 0,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "network": False,
        "hardware_devices": False,
    }


def _elf_tools(candidate: str) -> tuple[Path, Path]:
    if candidate not in CANDIDATES:
        raise RuntimeError("trusted ELF candidate is invalid")
    root = (
        Path(os.environ["SANHUO_Q7_ESPRESSIF_ROOT"])
        / "tools/xtensa-esp-elf/esp-14.2.0_20260121/"
        "xtensa-esp-elf/bin"
    )
    prefix = "xtensa-esp-elf"
    return root / f"{prefix}-objcopy", root / f"{prefix}-nm"


def trusted_elf_evidence() -> dict[str, dict[str, object]]:
    """Recompute ELF evidence from the sealed, read-only final snapshot."""

    sealed_root = Path(os.environ["SANHUO_Q7_SEALED_INPUT"])
    candidate_root = sealed_root / "output/binaries"
    scratch_root = Path(os.environ["SANHUO_Q7_RUNTIME_HOME"]) / "tmp"
    evidence: dict[str, dict[str, object]] = {}
    for candidate in CANDIDATES:
        elf = candidate_root / candidate / "firmware.elf"
        if not elf.is_file() or elf.is_symlink():
            raise RuntimeError(f"{candidate} current ELF is missing or indirect")
        objcopy, nm_tool = _elf_tools(candidate)
        stripped = scratch_root / f"{candidate}.semantic.elf"
        if stripped.exists() or stripped.is_symlink():
            raise RuntimeError("trusted semantic ELF output already exists")
        _run_checked(
            [str(objcopy), "--strip-all", str(elf), str(stripped)],
            cwd=scratch_root,
            timeout=120,
        )
        try:
            semantic_sha256 = hashlib.sha256(stripped.read_bytes()).hexdigest()
        finally:
            stripped.unlink(missing_ok=True)
        symbol_output = _run_checked(
            [str(nm_tool), "-C", "--defined-only", str(elf)],
            cwd=scratch_root,
            timeout=120,
        )
        symbols: set[str] = set()
        for line in symbol_output.decode("utf-8", errors="replace").splitlines():
            fields = line.strip().split(maxsplit=2)
            if len(fields) == 3:
                symbols.add(fields[2])
        evidence[candidate] = {
            "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
            "elf_semantic_sha256": semantic_sha256,
            "firmware_capabilities": derive_capabilities(candidate, symbols),
        }
    return evidence


def _reject_duplicate_json_fields(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise RuntimeError(f"trusted Q5 JSON repeats field: {key}")
        value[key] = item
    return value


def _load_q5_json(path: Path, *, label: str) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"{label} is missing or indirect")
    size = path.stat().st_size
    if size <= 0 or size > MAX_Q5_EVIDENCE_BYTES:
        raise RuntimeError(f"{label} exceeds the fixed size boundary")
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_json_fields,
            parse_constant=lambda item: (_ for _ in ()).throw(
                RuntimeError(f"{label} contains invalid number: {item}")
            ),
        )
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"{label} is not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{label} is not valid JSON") from exc
    if type(value) is not dict:
        raise RuntimeError(f"{label} must be one JSON object")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _sha256_field(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeError(f"{label} SHA256 is invalid")
    return value


def _validated_exact_schedule(
    candidate: str,
    q3_report: dict[str, object],
    tracked_manifest: dict[str, object],
) -> dict[str, object]:
    if candidate not in EXPECTED_SCREEN:
        raise RuntimeError("trusted Q5 candidate is invalid")
    expected = EXPECTED_SCREEN[candidate]
    if (
        set(q3_report)
        != {
            "schema",
            "candidate_id",
            "gate",
            "status",
            "evidence",
            "evidence_sha256",
            "covered",
            "not_covered",
        }
        or q3_report.get("schema") != "sanhuo.motion_phase2c_gate_report.v1"
        or q3_report.get("candidate_id") != candidate
        or q3_report.get("gate") != "Q3"
        or q3_report.get("status") != "passed"
    ):
        raise RuntimeError(f"{candidate} Q3 report identity drift")
    evidence = q3_report.get("evidence")
    if type(evidence) is not dict or set(evidence) != {
        "screen_schedule_sha256",
        "parent_schedule_sha256",
        "parent_prefix_sha256",
        "commands",
        "metrics",
        "parameters",
        "known_reversal",
    }:
        raise RuntimeError(f"{candidate} Q3 exact schedule fields drift")
    if q3_report.get("evidence_sha256") != _sha256_json(evidence):
        raise RuntimeError(f"{candidate} Q3 evidence hash drift")
    commands = evidence.get("commands")
    if type(commands) is not list or len(commands) != expected["commands"]:
        raise RuntimeError(f"{candidate} Q3 exact schedule count drift")
    previous_time = -1
    normalized: list[dict[str, object]] = []
    for index, command in enumerate(commands):
        if type(command) is not dict or set(command) != SCREEN_COMMAND_FIELDS:
            raise RuntimeError(f"{candidate} Q3 command {index} fields drift")
        at_ms = command.get("at_ms")
        raw = command.get("raw")
        move_time_ms = command.get("move_time_ms")
        speed = command.get("speed")
        source_at_ms = command.get("source_at_ms")
        if (
            type(at_ms) is not int
            or not previous_time <= at_ms < 20_000
            or command.get("axis") not in {"pan", "tilt"}
            or type(raw) is not int
            or not 0 <= raw <= 1000
            or type(move_time_ms) is not int
            or not 0 < move_time_ms <= 400
            or type(speed) is not int
            or speed != 0
            or type(source_at_ms) is not int
            or source_at_ms < 0
        ):
            raise RuntimeError(f"{candidate} Q3 command {index} value drift")
        previous_time = at_ms
        normalized.append(dict(command))
    reversal = [
        {
            "index": index,
            "at_ms": command["at_ms"],
            "source_at_ms": command["source_at_ms"],
            "axis": command["axis"],
            "raw": command["raw"],
        }
        for index, command in enumerate(normalized)
        if command["at_ms"] == 17_100 or command["source_at_ms"] == 17_100
    ]
    metrics = {
        "command_count": len(normalized),
        "pan_transactions": sum(command["axis"] == "pan" for command in normalized),
        "tilt_transactions": sum(
            command["axis"] == "tilt" for command in normalized
        ),
        "last_command_at_ms": normalized[-1]["at_ms"],
        "contains_known_reversal": True,
    }
    if (
        {item["axis"] for item in reversal} != EXPECTED_REVERSAL_AXES[candidate]
        or evidence.get("known_reversal") != reversal
        or evidence.get("metrics") != metrics
        or evidence.get("parameters") != SCREEN_PARAMETERS
    ):
        raise RuntimeError(f"{candidate} Q3 exact schedule semantics drift")
    prefix_sha256 = _sha256_json(normalized)
    if (
        evidence.get("parent_prefix_sha256") != prefix_sha256
        or prefix_sha256 != expected["parent_prefix_sha256"]
        or evidence.get("parent_schedule_sha256")
        != expected["parent_schedule_sha256"]
    ):
        raise RuntimeError(f"{candidate} Q3 exact schedule hash drift")
    parent_evidence = tracked_manifest.get("parent_evidence")
    tracked_schedule = tracked_manifest.get("screen_schedule")
    if (
        tracked_manifest.get("candidate_id") != candidate
        or tracked_manifest.get("parent_candidate_id") != expected["parent"]
        or tracked_manifest.get("scenario") != "h0_plus_h1a_20s"
        or tracked_manifest.get("duration_ms") != 20_000
        or tracked_manifest.get("hardware_state") != SCREEN_HARDWARE_STATE
        or type(parent_evidence) is not dict
        or evidence.get("parent_schedule_sha256")
        != parent_evidence.get("schedule_sha256")
        or type(tracked_schedule) is not dict
        or tracked_schedule.get("commands") != len(normalized)
        or tracked_schedule.get("parent_prefix_sha256") != prefix_sha256
        or tracked_schedule.get("contains_known_reversal") is not True
    ):
        raise RuntimeError(f"{candidate} tracked schedule binding drift")
    screen = {
        "schema": "sanhuo.motion_phase2c_screen.v1",
        "candidate_id": candidate,
        "parent_candidate_id": expected["parent"],
        "scenario": "h0_plus_h1a_20s",
        "duration_ms": 20_000,
        "parent_schedule_sha256": evidence["parent_schedule_sha256"],
        "parent_prefix_sha256": prefix_sha256,
        "parent_q7": tracked_manifest.get("parent_q7"),
        "parameters": SCREEN_PARAMETERS,
        "commands": normalized,
        "metrics": metrics,
        "safety": SCREEN_SAFETY,
        "hardware_state": SCREEN_HARDWARE_STATE,
    }
    screen_sha256 = _sha256_json(screen)
    if (
        evidence.get("screen_schedule_sha256") != screen_sha256
        or tracked_schedule.get("sha256") != screen_sha256
        or screen_sha256 != expected["screen_schedule_sha256"]
    ):
        raise RuntimeError(f"{candidate} complete screen schedule hash drift")
    generated_schedule_sha256 = hashlib.sha256(
        _render_exact_schedule_header(
            candidate,
            {"commands": normalized},
        )
    ).hexdigest()
    exact_schedule_digest = _exact_schedule_digest(normalized)
    if (
        generated_schedule_sha256 != expected["generated_schedule_sha256"]
        or exact_schedule_digest != expected["exact_schedule_digest"]
    ):
        raise RuntimeError(f"{candidate} verifier-owned schedule identity drift")
    return {
        "commands": normalized,
        "parent_prefix_sha256": prefix_sha256,
        "screen_schedule_sha256": screen_sha256,
        "generated_schedule_sha256": generated_schedule_sha256,
        "exact_schedule_digest": exact_schedule_digest,
    }


def _render_exact_schedule_header(
    candidate: str,
    schedule: dict[str, object],
) -> bytes:
    commands = schedule["commands"]
    if type(commands) is not list or candidate not in EXPECTED_SCREEN:
        raise RuntimeError("trusted Q5 schedule render input is invalid")
    lines = [
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstdint>",
        "",
        "namespace sanhuo::motion_matrix {",
        "struct GeneratedCommand {",
        "  uint32_t at_ms;",
        "  uint8_t servo_id;",
        "  uint16_t raw;",
        "  uint16_t move_time_ms;",
        "  uint16_t speed;",
        "};",
        f'inline constexpr char kCandidateId[] = "{candidate}";',
        (
            "inline constexpr char kParentCandidateId[] = "
            f'"{EXPECTED_SCREEN[candidate]["parent"]}";'
        ),
        'inline constexpr char kScenarioId[] = "h0_plus_h1a_20s";',
        "inline constexpr uint32_t kScreenDurationMs = 20000U;",
        f"inline constexpr std::array<GeneratedCommand, {len(commands)}> "
        "kGeneratedCommands = {{",
    ]
    for command in commands:
        if type(command) is not dict:
            raise RuntimeError("trusted Q5 schedule command is invalid")
        servo_id = 1 if command["axis"] == "pan" else 2
        lines.append(
            "  GeneratedCommand{"
            f"{command['at_ms']}U, {servo_id}U, {command['raw']}U, "
            f"{command['move_time_ms']}U, {command['speed']}U"
            "},"
        )
    lines.extend(["}};", "}  // namespace sanhuo::motion_matrix", ""])
    return "\n".join(lines).encode("utf-8")


def _exact_schedule_digest(commands: object) -> str:
    if type(commands) is not list:
        raise RuntimeError("trusted Q5 schedule digest input is invalid")
    digest = 1469598103934665603
    for command in commands:
        if type(command) is not dict:
            raise RuntimeError("trusted Q5 schedule digest command is invalid")
        servo_id = 1 if command["axis"] == "pan" else 2
        for value in (
            command["at_ms"],
            servo_id,
            command["raw"],
            command["move_time_ms"],
            command["speed"],
        ):
            for _ in range(8):
                digest ^= value & 0xFF
                digest = (digest * 1099511628211) & 0xFFFFFFFFFFFFFFFF
                value >>= 8
    return f"{digest:016x}"


def _target_q5_host_executor(
    candidate: str,
    q5_report: dict[str, object],
) -> dict[str, object]:
    if (
        q5_report.get("schema") != "sanhuo.motion_phase2c_gate_report.v1"
        or q5_report.get("candidate_id") != candidate
        or q5_report.get("gate") != "Q5"
        or q5_report.get("status") != "passed"
    ):
        raise RuntimeError(f"{candidate} target Q5 report identity drift")
    evidence = q5_report.get("evidence")
    if type(evidence) is not dict or q5_report.get("evidence_sha256") != _sha256_json(
        evidence
    ):
        raise RuntimeError(f"{candidate} target Q5 evidence hash drift")
    host = evidence.get("host_executor")
    if (
        evidence.get("candidate_id") != candidate
        or evidence.get("events_per_run") != EXPECTED_SCREEN[candidate]["commands"]
        or type(host) is not dict
    ):
        raise RuntimeError(f"{candidate} target Q5 host evidence drift")
    for field in (
        "harness_source_sha256",
        "shared_executor_core_sha256",
        "screen_adapter_sha256",
        "generated_schedule_sha256",
        "compiler_sha256",
        "executable_sha256",
        "stdout_sha256",
    ):
        _sha256_field(host.get(field), label=f"{candidate} target Q5 {field}")
    return host


def _compile_q5_harness(
    *,
    host_cxx: Path,
    payload_root: Path,
    include_root: Path,
    source: Path,
    executable: Path,
    cwd: Path,
) -> None:
    _run_checked(
        [
            str(host_cxx),
            "-std=c++17",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
            "-I",
            str(include_root),
            "-I",
            str(payload_root),
            str(source),
            "-o",
            str(executable),
        ],
        cwd=cwd,
        timeout=120,
    )


def _target_q5_build_layout(checkout: Path) -> dict[str, Path]:
    project_root = checkout / "firmware/sanhuo-stackchan-idf"
    return {
        "project_root": project_root,
        "payload_root": Path("tools/motion_firmware_matrix/payloads/PT"),
        "source": Path(
            "tests/host/motion_matrix/phase2c_screen_executor.cpp"
        ),
    }


def trusted_q5_executor_evidence() -> dict[str, dict[str, object]]:
    """Execute exact Q3 schedules, then reproduce the target Q5 artifacts."""

    checkout = Path(os.environ["SANHUO_Q7_CHECKOUT"])
    target_layout = _target_q5_build_layout(checkout)
    project_root = target_layout["project_root"]
    payload_root = project_root / target_layout["payload_root"]
    core = payload_root / "phase2_executor_core.h"
    adapter = payload_root / "phase2c_screen_executor.h"
    target_harness = project_root / target_layout["source"]
    if not core.is_file() or core.is_symlink():
        raise RuntimeError("target Phase 2C executor core is missing or indirect")
    if not adapter.is_file() or adapter.is_symlink():
        raise RuntimeError("target Phase 2C screen adapter is missing or indirect")
    if not target_harness.is_file() or target_harness.is_symlink():
        raise RuntimeError("target Phase 2C Q5 harness is missing or indirect")
    scratch = Path(os.environ["SANHUO_Q7_RUNTIME_HOME"]) / "tmp"
    host_cxx = Path(os.environ["SANHUO_Q7_HOST_CXX"])
    if not host_cxx.is_absolute() or not host_cxx.is_file() or host_cxx.is_symlink():
        raise RuntimeError("trusted Q5 compiler is missing or indirect")
    sealed_root = Path(os.environ["SANHUO_Q7_SEALED_INPUT"])
    artifact_root = sealed_root / "output/artifacts"
    tracked_root = (
        checkout
        / "firmware/sanhuo-stackchan-idf/candidates/motion-firmware-matrix"
    )
    expected_maximum = {
        "MF-T0-H1A": 434,
        "MF-T1-H1A": 364,
        "MF-T2-H1A": 200,
    }
    core_sha256 = hashlib.sha256(core.read_bytes()).hexdigest()
    adapter_sha256 = hashlib.sha256(adapter.read_bytes()).hexdigest()
    target_source_sha256 = hashlib.sha256(target_harness.read_bytes()).hexdigest()
    compiler_sha256 = hashlib.sha256(host_cxx.read_bytes()).hexdigest()
    evidence: dict[str, dict[str, object]] = {}
    for candidate in CANDIDATES:
        q3_report = _load_q5_json(
            artifact_root / candidate / "q3-report.json",
            label=f"{candidate} sealed Q3 report",
        )
        q5_report = _load_q5_json(
            artifact_root / candidate / "q5-report.json",
            label=f"{candidate} sealed Q5 report",
        )
        tracked_manifest = _load_q5_json(
            tracked_root / candidate / "manifest.json",
            label=f"{candidate} tracked manifest",
        )
        schedule = _validated_exact_schedule(
            candidate,
            q3_report,
            tracked_manifest,
        )
        target_host = _target_q5_host_executor(candidate, q5_report)
        header = _render_exact_schedule_header(candidate, schedule)
        header_sha256 = hashlib.sha256(header).hexdigest()
        if (
            header_sha256 != schedule["generated_schedule_sha256"]
            or target_host["shared_executor_core_sha256"] != core_sha256
            or target_host["screen_adapter_sha256"] != adapter_sha256
            or target_host["harness_source_sha256"] != target_source_sha256
            or target_host["compiler_sha256"] != compiler_sha256
            or target_host["generated_schedule_sha256"] != header_sha256
        ):
            raise RuntimeError(f"{candidate} target Q5 source identity drift")

        trusted_root = scratch / f"trusted-q5-{candidate}"
        if trusted_root.exists() or trusted_root.is_symlink():
            raise RuntimeError("trusted Q5 exact-schedule scratch already exists")
        trusted_root.mkdir(mode=0o700)
        trusted_header = trusted_root / "motion_matrix_generated_schedule.h"
        trusted_source = trusted_root / "trusted_phase2c_q5.cpp"
        trusted_executable = trusted_root / "trusted-phase2c-q5"
        trusted_header.write_bytes(header)
        trusted_source.write_text(TRUSTED_Q5_HARNESS_SOURCE, encoding="utf-8")
        _compile_q5_harness(
            host_cxx=host_cxx,
            payload_root=payload_root,
            include_root=trusted_root,
            source=trusted_source,
            executable=trusted_executable,
            cwd=trusted_root,
        )
        stdout = _run_checked(
            [str(trusted_executable)],
            cwd=trusted_root,
            timeout=120,
        )
        matched = _TRUSTED_Q5_OUTPUT.fullmatch(stdout)
        if matched is None:
            raise RuntimeError("trusted Q5 harness output format drift")
        observed_candidate = matched.group(1).decode("ascii")
        count = int(matched.group(2))
        observed_digest = matched.group(3).decode("ascii")
        values = [int(item) for item in matched.groups()[3:]]
        expected = [count, 200, 200, 200, 1, expected_maximum[candidate], 0, 1]
        exact_digest = _exact_schedule_digest(schedule["commands"])
        if (
            observed_candidate != candidate
            or count != EXPECTED_SCREEN[candidate]["commands"]
            or observed_digest != exact_digest
            or exact_digest != schedule["exact_schedule_digest"]
            or [count, *values] != expected
        ):
            raise RuntimeError("trusted Q5 exact-schedule semantics drift")
        trusted_harness_source_sha256 = hashlib.sha256(
            trusted_source.read_bytes()
        ).hexdigest()
        trusted_executable_sha256 = hashlib.sha256(
            trusted_executable.read_bytes()
        ).hexdigest()
        trusted_stdout_sha256 = hashlib.sha256(stdout).hexdigest()

        # Everything above is captured in verifier memory before target code runs.
        target_root = scratch / f"target-q5-rebuild-{candidate}"
        if target_root.exists() or target_root.is_symlink():
            raise RuntimeError("target Q5 rebuild scratch already exists")
        target_root.mkdir(mode=0o700)
        (target_root / "motion_matrix_generated_schedule.h").write_bytes(header)
        target_executable = target_root / "phase2c-screen-executor"
        _compile_q5_harness(
            host_cxx=host_cxx,
            payload_root=target_layout["payload_root"],
            include_root=target_root,
            source=target_layout["source"],
            executable=target_executable,
            cwd=project_root,
        )
        target_executable_sha256 = hashlib.sha256(
            target_executable.read_bytes()
        ).hexdigest()
        if target_executable_sha256 != target_host["executable_sha256"]:
            raise RuntimeError(f"{candidate} target Q5 executable rebuild drift")
        target_stdout = _run_checked(
            [str(target_executable)],
            cwd=target_root,
            timeout=120,
        )
        target_stdout_sha256 = hashlib.sha256(target_stdout).hexdigest()
        if target_stdout_sha256 != target_host["stdout_sha256"]:
            raise RuntimeError(f"{candidate} target Q5 stdout rebuild drift")
        evidence[candidate] = {
            "candidate_id": candidate,
            "events_per_run": count,
            "healthy_runs": values[0],
            "fault_runs": values[1],
            "feedback_collision_safe_stops": values[2],
            "feedback_collision_min_sent": values[3],
            "feedback_collision_max_sent": values[4],
            "post_failure_performance_writes": values[5],
            "safe_center_attempts_maximum": values[6],
            "screen_schedule_sha256": schedule["screen_schedule_sha256"],
            "parent_prefix_sha256": schedule["parent_prefix_sha256"],
            "generated_schedule_sha256": header_sha256,
            "exact_schedule_digest": exact_digest,
            "shared_executor_core_sha256": core_sha256,
            "screen_adapter_sha256": adapter_sha256,
            "trusted_harness_source_sha256": trusted_harness_source_sha256,
            "target_harness_source_sha256": target_source_sha256,
            "compiler_sha256": compiler_sha256,
            "executable_sha256": trusted_executable_sha256,
            "stdout_sha256": trusted_stdout_sha256,
            "target_executable_sha256": target_executable_sha256,
            "target_stdout_sha256": target_stdout_sha256,
        }
    return evidence


def main() -> int:
    mode = os.environ.get("SANHUO_Q7_DRIVER_MODE", "action")
    prepare_runtime_layout()
    if mode == "action":
        summary = run_selected_action()
    elif mode == "evidence":
        q5_executor = trusted_q5_executor_evidence()
        summary = {
            "schema": "sanhuo.trusted_q7_elf_evidence.v1",
            "status": "passed",
            "elf_evidence": trusted_elf_evidence(),
            "q5_executor_evidence": q5_executor,
            "network": False,
            "hardware_devices": False,
        }
    else:
        raise RuntimeError("trusted driver mode is invalid")
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"trusted isolated run failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
