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


CANDIDATES = ("MF-P2-H1A",)
ACTIONS = ("build", "qualify", "audit")
CLI = Path(
    os.environ.get("SANHUO_Q7_CHECKOUT", "/workspace")
    + "/firmware/sanhuo-stackchan-idf/"
    "tools/motion_firmware_matrix/cli_phase2c_p2.py"
)
CLI_MODULE = "motion_firmware_matrix.cli_phase2c_p2"
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
# The original T0-T2 fixtures below remain only for regression tests of the
# hardened parsers. The live action matrix is fixed by CANDIDATES and the P2
# overrides near the end of this module; these fixtures are never dispatched.
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

# This verifier commit is a fixed one-candidate profile.  The older Phase 2C
# schedule helpers above remain inert; the live profile is deliberately bound
# to the exact public P2 target list and the P2 runtime cores below.
TRUSTED_TARGETS = (
    {"at_ms": 0, "yaw_tenths": 0, "pitch_tenths": 0},
    {"at_ms": 1060, "yaw_tenths": 0, "pitch_tenths": -110},
    {"at_ms": 1620, "yaw_tenths": 0, "pitch_tenths": 0},
    {"at_ms": 6260, "yaw_tenths": 350, "pitch_tenths": 0},
    {"at_ms": 9640, "yaw_tenths": -350, "pitch_tenths": 0},
    {"at_ms": 12700, "yaw_tenths": 350, "pitch_tenths": 0},
    {"at_ms": 12880, "yaw_tenths": -350, "pitch_tenths": 0},
    {"at_ms": 13060, "yaw_tenths": 350, "pitch_tenths": 0},
    {"at_ms": 13240, "yaw_tenths": -350, "pitch_tenths": 0},
    {"at_ms": 13420, "yaw_tenths": 0, "pitch_tenths": 0},
    {"at_ms": 13600, "yaw_tenths": -350, "pitch_tenths": 0},
    {"at_ms": 16080, "yaw_tenths": -350, "pitch_tenths": 0},
    {"at_ms": 16580, "yaw_tenths": 0, "pitch_tenths": 140},
    {"at_ms": 17080, "yaw_tenths": 350, "pitch_tenths": 0},
    {"at_ms": 17580, "yaw_tenths": 0, "pitch_tenths": -120},
    {"at_ms": 18080, "yaw_tenths": -350, "pitch_tenths": 0},
    {"at_ms": 18440, "yaw_tenths": 0, "pitch_tenths": 0},
    {"at_ms": 18580, "yaw_tenths": 0, "pitch_tenths": 0},
    {"at_ms": 18880, "yaw_tenths": 0, "pitch_tenths": 0},
    {"at_ms": 19380, "yaw_tenths": 0, "pitch_tenths": 0},
)
TRUSTED_TARGETS_SHA256 = (
    "db843ff1200e942ce50b12178a897478dead0a07fe4aaca4fcd7691c4bfb1e58"
)
TRUSTED_CONTRACT_SHA256 = (
    "3348118754bd19605d51804da783e97ddc9abc26114cb8f53408bd9825f58798"
)
TRUSTED_Q5_HARNESS_SOURCE = r'''#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <iostream>

#include "phase2c_p2_executor.h"
#include "phase2c_p2_observer_core.h"

namespace {

namespace p2 = sanhuo::motion_matrix::p2;

struct Target {
  uint32_t at_ms;
  int yaw_tenths;
  int pitch_tenths;
};

constexpr std::array<Target, 20> kTrustedTargets = {{
    {0, 0, 0},       {1060, 0, -110},  {1620, 0, 0},
    {6260, 350, 0},  {9640, -350, 0},  {12700, 350, 0},
    {12880, -350, 0},{13060, 350, 0}, {13240, -350, 0},
    {13420, 0, 0},   {13600, -350, 0},{16080, -350, 0},
    {16580, 0, 140}, {17080, 350, 0}, {17580, 0, -120},
    {18080, -350, 0},{18440, 0, 0},   {18580, 0, 0},
    {18880, 0, 0},   {19380, 0, 0},
}};

struct Metrics {
  std::size_t failure_index = 0;
  std::size_t dispatched = 0;
  std::size_t post_failure_targets = 0;
  std::size_t center_attempts = 0;
  uint32_t virtual_ms = 0;
  bool failed = false;
};

p2::ScreenOutcome run(uint32_t seed, bool inject_failure, Metrics* metrics) {
  assert(metrics != nullptr);
  metrics->failure_index = (static_cast<std::size_t>(seed) * 37U) % 20U;
  std::size_t wait_index = 0;
  return p2::executeScreen(
      kTrustedTargets, 20000U,
      [metrics, seed, &wait_index](uint32_t at_ms) {
        const uint32_t jitter = (seed * 17U + wait_index * 13U) % 7U;
        const uint32_t sparse = (seed + wait_index) % 41U == 0U ? 40U : 0U;
        const uint32_t blocked = (seed + wait_index) % 67U == 0U ? 100U : 0U;
        metrics->virtual_ms = std::max(metrics->virtual_ms,
                                       at_ms + jitter + sparse + blocked);
        ++wait_index;
        return !metrics->failed;
      },
      [metrics, inject_failure](const Target&) {
        if (metrics->failed) {
          ++metrics->post_failure_targets;
        }
        if (inject_failure && metrics->dispatched == metrics->failure_index) {
          metrics->failed = true;
        }
        ++metrics->dispatched;
      },
      [metrics]() { return metrics->failed; },
      [metrics]() {
        ++metrics->center_attempts;
        return true;
      },
      [metrics]() {
        ++metrics->center_attempts;
        return true;
      });
}

void verifyObserver() {
  p2::ObserverCore observer;
  observer.authorizeWrites(100U);
  observer.observePerformanceWrite(120U, 1U, 459U, 1, 0U, 0U);
  observer.observePerformanceWrite(240U, 2U, 678U, 0, 1U, 0U);
  assert(observer.failureLatched());
  assert(!observer.writesAllowed());
  assert(observer.snapshot().first_error_at_ms == 140U);
  assert(observer.snapshot().first_error_class == p2::AckClass::kNoReply);
  assert(observer.beginFailureCenter());
  assert(!observer.beginFailureCenter());
  observer.observeSafeCenterWrite(250U, 1U, 459U, 1, 0U, 0U);
  observer.observeSafeCenterWrite(260U, 2U, 678U, 1, 0U, 0U);
  observer.finishSafeCenter(true);
  assert(observer.snapshot().safe_center_succeeded);
}

}  // namespace

int main() {
  verifyObserver();
  std::size_t healthy_runs = 0;
  std::size_t fault_runs = 0;
  uint32_t failure_indices_covered = 0;
  std::size_t post_failure_targets = 0;
  std::size_t safe_center_attempts_maximum = 0;
  for (uint32_t seed = 0; seed < 100U; ++seed) {
    for (uint32_t repeat = 0; repeat < 2U; ++repeat) {
      Metrics healthy;
      const auto healthy_outcome = run(seed, false, &healthy);
      assert(healthy_outcome.result == p2::ScreenResult::kCompleted);
      assert(healthy_outcome.targets_dispatched == 20U);
      assert(healthy.center_attempts == 1U);
      ++healthy_runs;

      Metrics fault;
      const auto fault_outcome = run(seed + repeat * 100U, true, &fault);
      assert(fault_outcome.result == p2::ScreenResult::kMotionFailed);
      assert(fault_outcome.targets_dispatched == fault.failure_index + 1U);
      assert(fault.center_attempts == 1U);
      failure_indices_covered |= 1U << fault.failure_index;
      post_failure_targets += fault.post_failure_targets;
      safe_center_attempts_maximum = std::max(
          safe_center_attempts_maximum, fault.center_attempts);
      ++fault_runs;
    }
  }
  assert(healthy_runs == 200U && fault_runs == 200U);
  assert(failure_indices_covered == ((1U << 20U) - 1U));
  assert(post_failure_targets == 0U);
  assert(safe_center_attempts_maximum == 1U);
  std::cout << "TRUSTED_PHASE2C_P2_Q5 candidate=MF-P2-H1A"
            << " healthy_runs=" << healthy_runs << " fault_runs=" << fault_runs
            << " failure_indices_covered=" << failure_indices_covered
            << " post_failure_targets=" << post_failure_targets
            << " safe_center_attempts_maximum="
            << safe_center_attempts_maximum << " passed=1\n";
  return 0;
}
'''
_TRUSTED_Q5_OUTPUT = re.compile(
    rb"^TRUSTED_PHASE2C_P2_Q5 candidate=MF-P2-H1A healthy_runs=(\d+) "
    rb"fault_runs=(\d+) failure_indices_covered=(\d+) "
    rb"post_failure_targets=(\d+) safe_center_attempts_maximum=(\d+) "
    rb"passed=1\n$"
)


def matrix_commands() -> list[list[str]]:
    """Describe the fixed matrix without executing it."""

    return [
        [sys.executable, "-m", CLI_MODULE, action]
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
        [sys.executable, "-m", CLI_MODULE, action],
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
    required_motion = (
        "M5StackChan_Class::begin",
        "Motion::move(",
        "SCSCL::WritePos",
        "waitForArm",
        "runH0",
    )
    if not all(
        _symbol_contains(symbols, marker)
        for marker in required_motion
    ):
        raise RuntimeError(f"{candidate} motion capability is absent")
    if not _symbol_contains(symbols, "uart_write_bytes"):
        raise RuntimeError(f"{candidate} UART capability is absent")
    if not _symbol_contains(symbols, "M5StackChan_Class::getBatteryVoltage"):
        raise RuntimeError("P2 INA226 capability is absent")
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
        "usb": any(
            _symbol_contains(symbols, marker)
            for marker in (
                "TinyUSBDriver",
                "USBCDC::begin(",
                "USBDeviceClass::begin(",
                "tud_task(",
            )
        ),
        "face": any(
            _symbol_contains(symbols, marker)
            for marker in ("FaceRenderer", "MouthRenderer", "lv_obj_")
        ),
        "ina226": True,
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
        cwd=CLI.parents[1],
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
        Path(os.environ["SANHUO_Q7_PLATFORMIO_ROOT"])
        / "packages/toolchain-xtensa-esp32s3/bin"
    )
    prefix = "xtensa-esp32s3-elf"
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


def _legacy_trusted_q5_executor_evidence() -> dict[str, dict[str, object]]:
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


def _trusted_targets_sha256() -> str:
    return _sha256_json(list(TRUSTED_TARGETS))


def _render_p2_targets_header() -> bytes:
    lines = [
        "#pragma once",
        "",
        "#include <array>",
        "#include <cstdint>",
        "",
        "struct PublicTarget {",
        "  uint32_t at_ms;",
        "  int yaw_tenths;",
        "  int pitch_tenths;",
        "};",
        "",
        'inline constexpr char kCandidateId[] = "MF-P2-H1A";',
        'inline constexpr char kParentCandidateId[] = "MF-P2";',
        'inline constexpr char kScenarioId[] = "h0_plus_h1a_20s";',
        "inline constexpr uint32_t kScreenDurationMs = 20000U;",
        "inline constexpr std::array<PublicTarget, 20> kPublicTargets = {{",
    ]
    for target in TRUSTED_TARGETS:
        lines.append(
            "    PublicTarget{"
            f"{target['at_ms']}U, {target['yaw_tenths']}, "
            f"{target['pitch_tenths']}"
            "},"
        )
    lines.extend(["}};", ""])
    return "\n".join(lines).encode("utf-8")


def _target_q5_build_layout(checkout: Path) -> dict[str, Path]:
    project_root = checkout / "firmware/sanhuo-stackchan-idf"
    return {
        "project_root": project_root,
        "payload_root": Path(
            "tools/motion_firmware_matrix/payloads/P2-H1A/src"
        ),
        "source": Path(
            "tests/host/motion_matrix/phase2c_p2_screen_executor.cpp"
        ),
    }


_TARGET_P2_TRACE = re.compile(
    rb"^PHASE2C_P2_RUN candidate=MF-P2-H1A seed=(\d+) repeat=(\d+) "
    rb"mode=(healthy|fault) failure_index=(-?\d+) targets_dispatched=(\d+) "
    rb"targets_after_failure=(\d+) safe_center_attempts=(\d+) "
    rb"automatic_retries=(\d+) maximum_lateness_ms=(\d+) "
    rb"virtual_end_ms=(\d+) trace=([0-9a-f]{16})$"
)


def _validate_target_p2_trace(stdout: bytes) -> dict[str, object]:
    lines = stdout.splitlines()
    if len(lines) != 400 or not stdout.endswith(b"\n"):
        raise RuntimeError("target P2 Q5 trace run count drift")
    signatures: dict[tuple[int, bytes], tuple[object, ...]] = {}
    failure_indices: set[int] = set()
    maximum_lateness = 0
    for line_index, line in enumerate(lines):
        matched = _TARGET_P2_TRACE.fullmatch(line)
        if matched is None:
            raise RuntimeError("target P2 Q5 trace format drift")
        (
            seed_text,
            repeat_text,
            mode,
            failure_text,
            dispatched_text,
            after_text,
            center_text,
            retry_text,
            lateness_text,
            virtual_text,
            trace_text,
        ) = matched.groups()
        seed = int(seed_text)
        repeat = int(repeat_text)
        failure_index = int(failure_text)
        dispatched = int(dispatched_text)
        after_failure = int(after_text)
        center_attempts = int(center_text)
        retries = int(retry_text)
        lateness = int(lateness_text)
        virtual_end = int(virtual_text)
        expected_mode = b"healthy" if line_index % 2 == 0 else b"fault"
        if (
            seed != line_index // 4
            or repeat != (line_index // 2) % 2
            or mode != expected_mode
            or after_failure != 0
            or center_attempts != 1
            or retries != 0
        ):
            raise RuntimeError("target P2 Q5 trace ordering or safety drift")
        if mode == b"healthy":
            if failure_index != -1 or dispatched != 20 or virtual_end < 20_000:
                raise RuntimeError("target P2 Q5 healthy trace drift")
        else:
            if not 0 <= failure_index < 20 or dispatched != failure_index + 1:
                raise RuntimeError("target P2 Q5 fault trace drift")
            failure_indices.add(failure_index)
        signature = (
            failure_index,
            dispatched,
            after_failure,
            center_attempts,
            retries,
            lateness,
            virtual_end,
            trace_text.decode("ascii"),
        )
        key = (seed, mode)
        if key in signatures and signatures[key] != signature:
            raise RuntimeError("target P2 Q5 repeat is nondeterministic")
        signatures.setdefault(key, signature)
        maximum_lateness = max(maximum_lateness, lateness)
    if failure_indices != set(range(20)):
        raise RuntimeError("target P2 Q5 failure coverage drift")
    return {
        "healthy_runs": 200,
        "fault_runs": 200,
        "failure_indices_covered": list(range(20)),
        "post_failure_targets": 0,
        "safe_center_attempts_maximum": 1,
        "maximum_lateness_ms": maximum_lateness,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
    }


def _p2_q5_report(report: dict[str, object]) -> tuple[dict[str, object], dict[str, object]]:
    if (
        set(report)
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
        or report.get("schema") != "sanhuo.motion_phase2c_p2_gate_report.v1"
        or report.get("candidate_id") != "MF-P2-H1A"
        or report.get("gate") != "Q5"
        or report.get("status") != "passed"
    ):
        raise RuntimeError("target P2 Q5 report identity drift")
    evidence = report.get("evidence")
    if type(evidence) is not dict or report.get("evidence_sha256") != _sha256_json(
        evidence
    ):
        raise RuntimeError("target P2 Q5 evidence hash drift")
    host = evidence.get("host_executor")
    if type(host) is not dict:
        raise RuntimeError("target P2 Q5 host identity is missing")
    for field in (
        "harness_source_sha256",
        "executor_core_sha256",
        "observer_core_sha256",
        "generated_targets_sha256",
        "compiler_sha256",
        "executable_sha256",
    ):
        _sha256_field(host.get(field), label=f"target P2 Q5 {field}")
    return evidence, host


def trusted_q5_executor_evidence() -> dict[str, dict[str, object]]:
    """Run a verifier-owned P2 harness, then reproduce the target Q5 harness."""

    checkout = Path(os.environ["SANHUO_Q7_CHECKOUT"])
    layout = _target_q5_build_layout(checkout)
    project_root = layout["project_root"]
    payload_root = project_root / layout["payload_root"]
    target_harness = project_root / layout["source"]
    executor_core = payload_root / "phase2c_p2_executor.h"
    observer_core = payload_root / "phase2c_p2_observer_core.h"
    for path, label in (
        (target_harness, "target P2 Q5 harness"),
        (executor_core, "target P2 executor core"),
        (observer_core, "target P2 observer core"),
    ):
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f"{label} is missing or indirect")
    if _trusted_targets_sha256() != TRUSTED_TARGETS_SHA256:
        raise RuntimeError("trusted P2 target list drift")
    header = _render_p2_targets_header()
    header_sha256 = hashlib.sha256(header).hexdigest()
    if header_sha256 != "fc8cef85af58ab7b7c5728b8a8a2f08e7cc86a8572aadd2e70bacf830c1c747c":
        raise RuntimeError("trusted P2 generated target header drift")

    sealed_root = Path(os.environ["SANHUO_Q7_SEALED_INPUT"])
    q3 = _load_q5_json(
        sealed_root / "output/artifacts/MF-P2-H1A/q3-report.json",
        label="sealed P2 Q3 report",
    )
    q5 = _load_q5_json(
        sealed_root / "output/artifacts/MF-P2-H1A/q5-report.json",
        label="sealed P2 Q5 report",
    )
    q3_evidence = q3.get("evidence")
    if (
        q3.get("schema") != "sanhuo.motion_phase2c_p2_gate_report.v1"
        or q3.get("candidate_id") != "MF-P2-H1A"
        or q3.get("gate") != "Q3"
        or q3.get("status") != "passed"
        or type(q3_evidence) is not dict
        or q3.get("evidence_sha256") != _sha256_json(q3_evidence)
        or q3_evidence.get("targets") != list(TRUSTED_TARGETS)
        or q3_evidence.get("targets_sha256") != TRUSTED_TARGETS_SHA256
        or q3_evidence.get("contract_sha256") != TRUSTED_CONTRACT_SHA256
    ):
        raise RuntimeError("target P2 Q3 exact target binding drift")
    target_q5, target_host = _p2_q5_report(q5)

    scratch = Path(os.environ["SANHUO_Q7_RUNTIME_HOME"]) / "tmp"
    host_cxx = Path(os.environ["SANHUO_Q7_HOST_CXX"])
    if not host_cxx.is_absolute() or not host_cxx.is_file() or host_cxx.is_symlink():
        raise RuntimeError("trusted P2 Q5 compiler is missing or indirect")
    compiler_sha256 = hashlib.sha256(host_cxx.read_bytes()).hexdigest()
    source_hashes = {
        "executor_core_sha256": hashlib.sha256(executor_core.read_bytes()).hexdigest(),
        "observer_core_sha256": hashlib.sha256(observer_core.read_bytes()).hexdigest(),
        "harness_source_sha256": hashlib.sha256(target_harness.read_bytes()).hexdigest(),
    }
    if (
        target_host.get("compiler_sha256") != compiler_sha256
        or target_host.get("generated_targets_sha256") != header_sha256
        or any(target_host.get(field) != value for field, value in source_hashes.items())
    ):
        raise RuntimeError("target P2 Q5 source identity drift")

    trusted_root = scratch / "trusted-q5-MF-P2-H1A"
    if trusted_root.exists() or trusted_root.is_symlink():
        raise RuntimeError("trusted P2 Q5 scratch already exists")
    trusted_root.mkdir(mode=0o700)
    trusted_source = trusted_root / "trusted_phase2c_p2_q5.cpp"
    trusted_executable = trusted_root / "trusted-phase2c-p2-q5"
    trusted_source.write_text(TRUSTED_Q5_HARNESS_SOURCE, encoding="utf-8")
    _compile_q5_harness(
        host_cxx=host_cxx,
        payload_root=payload_root,
        include_root=trusted_root,
        source=trusted_source,
        executable=trusted_executable,
        cwd=trusted_root,
    )
    trusted_stdout = _run_checked(
        [str(trusted_executable)], cwd=trusted_root, timeout=120
    )
    matched = _TRUSTED_Q5_OUTPUT.fullmatch(trusted_stdout)
    if matched is None or [int(value) for value in matched.groups()] != [
        200,
        200,
        (1 << 20) - 1,
        0,
        1,
    ]:
        raise RuntimeError("trusted P2 Q5 semantics drift")
    trusted_evidence = {
        "trusted_harness_source_sha256": hashlib.sha256(
            trusted_source.read_bytes()
        ).hexdigest(),
        "trusted_executable_sha256": hashlib.sha256(
            trusted_executable.read_bytes()
        ).hexdigest(),
        "trusted_stdout_sha256": hashlib.sha256(trusted_stdout).hexdigest(),
    }

    target_root = scratch / "target-q5-rebuild-MF-P2-H1A"
    if target_root.exists() or target_root.is_symlink():
        raise RuntimeError("target P2 Q5 rebuild scratch already exists")
    target_root.mkdir(mode=0o700)
    (target_root / "motion_matrix_public_targets.h").write_bytes(header)
    target_executable = target_root / "phase2c-p2-screen-executor"
    _compile_q5_harness(
        host_cxx=host_cxx,
        payload_root=payload_root,
        include_root=target_root,
        source=target_harness,
        executable=target_executable,
        cwd=project_root,
    )
    target_executable_sha256 = hashlib.sha256(
        target_executable.read_bytes()
    ).hexdigest()
    if target_executable_sha256 != target_host.get("executable_sha256"):
        raise RuntimeError("target P2 Q5 executable rebuild drift")
    target_stdout = _run_checked(
        [str(target_executable)], cwd=target_root, timeout=120
    )
    trace = _validate_target_p2_trace(target_stdout)
    if (
        trace["stdout_sha256"] != target_q5.get("all_seed_traces_sha256")
        or trace["maximum_lateness_ms"] != target_q5.get("maximum_lateness_ms")
        or target_q5.get("healthy_runs") != 200
        or target_q5.get("fault_runs") != 200
        or target_q5.get("failure_indices_covered") != list(range(20))
        or target_q5.get("post_failure_targets") != 0
        or target_q5.get("safe_center_attempts_maximum") != 1
        or target_q5.get("automatic_retry") is not False
        or target_q5.get("automatic_reset") is not False
        or target_q5.get("deterministic") is not True
        or target_q5.get("hardware_used") is not False
        or target_q5.get("target_count") != 20
        or target_q5.get("virtual_clock_duration_ms") != 20_000
    ):
        raise RuntimeError("target P2 Q5 summary disagrees with reproduced trace")
    return {
        "MF-P2-H1A": {
            "candidate_id": "MF-P2-H1A",
            "targets_sha256": TRUSTED_TARGETS_SHA256,
            "contract_sha256": TRUSTED_CONTRACT_SHA256,
            "healthy_runs": 200,
            "fault_runs": 200,
            "failure_indices_covered": list(range(20)),
            "post_failure_targets": 0,
            "safe_center_attempts_maximum": 1,
            "target_trace_sha256": trace["stdout_sha256"],
            "target_executable_sha256": target_executable_sha256,
            "compiler_sha256": compiler_sha256,
            **source_hashes,
            **trusted_evidence,
        }
    }


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
