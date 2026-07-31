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
XCODE_DEVELOPER_ROOT = "/Applications/Xcode.app/Contents/Developer"
TRUSTED_Q5_HARNESS_SOURCE = r'''#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

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
using sanhuo::motion_matrix::screen::ScreenExecutionResult;

struct Command {
  uint32_t at_ms = 0;
};

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    return 2;
  }
  const std::size_t count = std::strtoul(argv[1], nullptr, 10);
  if (count == 0U) {
    return 2;
  }
  std::vector<Command> commands(count);
  for (std::size_t index = 0; index < count; ++index) {
    commands[index].at_ms = static_cast<uint32_t>(index * 20U);
  }
  {
    std::size_t sent = 0;
    std::size_t center_attempts = 0;
    std::size_t duration_waits = 0;
    const std::vector<Command> final_center_commands = {commands.front()};
    const auto outcome = sanhuo::motion_matrix::screen::executeScreen(
        final_center_commands, 20000U, [](uint32_t) {},
        [&sent](const Command &) {
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
        std::size_t center_attempts = 0;
        std::size_t duration_waits = 0;
        const auto outcome = sanhuo::motion_matrix::screen::executeScreen(
            commands, 20000U, [](uint32_t) {},
            [&sent](const Command &) {
              ++sent;
              return SendResult{ExecutionError::kAccepted, 6U};
            },
            [&center_attempts]() {
              ++center_attempts;
              return SafeCenterResult{
                  true, 2U, SendResult{ExecutionError::kAccepted, 6U}};
            },
            [&duration_waits](uint32_t duration_ms) {
              sanhuoVerifierRequire(duration_ms == 20000U);
              ++duration_waits;
            });
        sanhuoVerifierRequire(outcome.state.completed);
        sanhuoVerifierRequire(!outcome.state.safe_stop_latched);
        sanhuoVerifierRequire(outcome.state.retries == 0U);
        sanhuoVerifierRequire(sent == count);
        sanhuoVerifierRequire(center_attempts == 1U);
        sanhuoVerifierRequire(outcome.safe_center_attempts == 1U);
        sanhuoVerifierRequire(duration_waits == 1U);
        ++healthy_runs;
      }
      {
        const std::size_t failure_index = (seed * 97U) % count;
        std::size_t sent = 0;
        std::size_t post_failure = 0;
        std::size_t center_attempts = 0;
        std::size_t duration_waits = 0;
        bool failure_observed = false;
        const auto outcome = sanhuo::motion_matrix::screen::executeScreen(
            commands, 20000U, [](uint32_t) {},
            [&](const Command &) {
              if (failure_observed) {
                ++post_failure;
              }
              const std::size_t current = sent++;
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
  std::cout << "TRUSTED_PHASE2C_Q5 events=" << count
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
    rb"^TRUSTED_PHASE2C_Q5 events=(\d+) healthy_runs=(\d+) "
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


def trusted_q5_executor_evidence() -> dict[str, dict[str, object]]:
    """Compile verifier-owned code against the target core and adapter."""

    checkout = Path(os.environ["SANHUO_Q7_CHECKOUT"])
    payload_root = (
        checkout
        / "firmware/sanhuo-stackchan-idf/tools/"
        "motion_firmware_matrix/payloads/PT"
    )
    core = payload_root / "phase2_executor_core.h"
    adapter = payload_root / "phase2c_screen_executor.h"
    target_harness = (
        checkout
        / "firmware/sanhuo-stackchan-idf/tests/host/motion_matrix/"
        "phase2c_screen_executor.cpp"
    )
    if not core.is_file() or core.is_symlink():
        raise RuntimeError("target Phase 2C executor core is missing or indirect")
    if not adapter.is_file() or adapter.is_symlink():
        raise RuntimeError("target Phase 2C screen adapter is missing or indirect")
    if not target_harness.is_file() or target_harness.is_symlink():
        raise RuntimeError("target Phase 2C Q5 harness is missing or indirect")
    scratch = Path(os.environ["SANHUO_Q7_RUNTIME_HOME"]) / "tmp"
    source = scratch / "trusted_phase2c_q5.cpp"
    executable = scratch / "trusted-phase2c-q5"
    if source.exists() or source.is_symlink() or executable.exists():
        raise RuntimeError("trusted Q5 scratch output already exists")
    source.write_text(TRUSTED_Q5_HARNESS_SOURCE, encoding="utf-8")
    host_cxx = Path(os.environ["SANHUO_Q7_HOST_CXX"])
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
            str(payload_root),
            str(source),
            "-o",
            str(executable),
        ],
        cwd=scratch,
        timeout=120,
    )
    executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
    source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
    identities = {
        "shared_executor_core_sha256": hashlib.sha256(
            core.read_bytes()
        ).hexdigest(),
        "screen_adapter_sha256": hashlib.sha256(
            adapter.read_bytes()
        ).hexdigest(),
        "trusted_harness_source_sha256": source_sha256,
        "target_harness_source_sha256": hashlib.sha256(
            target_harness.read_bytes()
        ).hexdigest(),
        "compiler_sha256": hashlib.sha256(host_cxx.read_bytes()).hexdigest(),
        "executable_sha256": executable_sha256,
    }
    expected_maximum = {
        "MF-T0-H1A": 434,
        "MF-T1-H1A": 364,
        "MF-T2-H1A": 200,
    }
    command_counts = {
        "MF-T0-H1A": 434,
        "MF-T1-H1A": 364,
        "MF-T2-H1A": 206,
    }
    evidence: dict[str, dict[str, object]] = {}
    for candidate in CANDIDATES:
        count = command_counts[candidate]
        stdout = _run_checked(
            [str(executable), str(count)],
            cwd=scratch,
            timeout=120,
        )
        matched = _TRUSTED_Q5_OUTPUT.fullmatch(stdout)
        if matched is None:
            raise RuntimeError("trusted Q5 harness output format drift")
        values = [int(item) for item in matched.groups()]
        expected = [count, 200, 200, 200, 1, expected_maximum[candidate], 0, 1]
        if values != expected:
            raise RuntimeError("trusted Q5 shared executor semantics drift")
        evidence[candidate] = {
            "candidate_id": candidate,
            "events_per_run": count,
            "healthy_runs": values[1],
            "fault_runs": values[2],
            "feedback_collision_safe_stops": values[3],
            "feedback_collision_min_sent": values[4],
            "feedback_collision_max_sent": values[5],
            "post_failure_performance_writes": values[6],
            "safe_center_attempts_maximum": values[7],
            **identities,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        }
    executable.unlink()
    source.unlink()
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
