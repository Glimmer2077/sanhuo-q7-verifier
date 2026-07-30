#!/usr/bin/env python3
"""Trusted single-action driver executed inside the macOS sandbox."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path


CANDIDATES = ("MF-P2", "MF-T0", "MF-T1", "MF-T2")
ACTIONS = ("build", "qualify", "audit")
CLI = Path(
    os.environ.get("SANHUO_Q7_CHECKOUT", "/workspace")
    + "/firmware/sanhuo-stackchan-idf/"
    "tools/motion_firmware_matrix/cli_phase2.py"
)
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_SINGLE_FAILURE_EXCERPT_BYTES = 180
MAX_SPLIT_FAILURE_EXCERPT_BYTES = 80
XCODE_DEVELOPER_ROOT = "/Applications/Xcode.app/Contents/Developer"


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
    if candidate == "MF-P2":
        required_motion = (
            "M5StackChan_Class::begin",
            "Motion::move(",
            "SCSCL::WritePos",
        )
        ina226 = _symbol_contains(
            symbols,
            "M5StackChan_Class::getBatteryVoltage",
        )
        if not ina226:
            raise RuntimeError("P2 INA226 capability is absent")
    else:
        required_motion = ("sendStrict(", "executeCandidate()")
        ina226 = False
    if not all(_symbol_contains(symbols, marker) for marker in required_motion):
        raise RuntimeError(f"{candidate} motion capability is absent")
    if not uart:
        raise RuntimeError(f"{candidate} UART capability is absent")
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
        "ina226": ina226,
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
        "PLATFORMIO_SETTING_CHECK_PLATFORMIO_INTERVAL": "0",
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
    if candidate == "MF-P2":
        root = (
            Path(os.environ["SANHUO_Q7_PLATFORMIO_ROOT"])
            / "packages/toolchain-xtensa-esp32s3/bin"
        )
        prefix = "xtensa-esp32s3-elf"
    else:
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


def main() -> int:
    mode = os.environ.get("SANHUO_Q7_DRIVER_MODE", "action")
    prepare_runtime_layout()
    if mode == "action":
        summary = run_selected_action()
    elif mode == "evidence":
        summary = {
            "schema": "sanhuo.trusted_q7_elf_evidence.v1",
            "status": "passed",
            "elf_evidence": trusted_elf_evidence(),
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
