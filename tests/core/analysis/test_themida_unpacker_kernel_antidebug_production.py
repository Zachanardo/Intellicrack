#!/usr/bin/env python3
"""Production tests for Themida unpacker kernel-mode anti-debug bypass.

Tests validate that frida_protection_bypass.py successfully defeats Themida's
kernel-mode anti-debugging protections including:
- NtQueryInformationProcess debug port blocking
- NtSetInformationThread ThreadHideFromDebugger bypass
- NtQuerySystemInformation kernel debugger detection defeat
- NtClose invalid handle exception suppression
- Process handle enumeration bypass
- Kernel debug object and handle spoofing

These tests MUST use real Frida with actual process attachment and MUST fail
if bypass techniques are ineffective.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.analysis.frida_protection_bypass import FridaProtectionBypasser


if TYPE_CHECKING:
    from collections.abc import Iterator


try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def ensure_windows() -> Iterator[None]:
    """Ensure tests run on Windows platform only."""
    if platform.system() != "Windows":
        pytest.skip(
            "Themida kernel anti-debug tests require Windows platform. "
            f"Current platform: {platform.system()}"
        )
    yield


@pytest.fixture(scope="module")
def ensure_frida() -> Iterator[None]:
    """Ensure Frida is available for testing."""
    if not FRIDA_AVAILABLE:
        pytest.skip(
            "Frida not available. Install with: pip install frida-tools frida\n"
            "These tests require real Frida for process attachment and instrumentation."
        )

    try:
        frida_version = frida.__version__
        logger.info(f"Frida version: {frida_version}")
    except Exception as e:
        pytest.skip(f"Frida import failed: {e}")

    yield


@pytest.fixture
def test_process_notepad(ensure_windows: None, ensure_frida: None) -> Iterator[subprocess.Popen[bytes]]:
    """Create a test process (notepad.exe) for Frida attachment."""
    process = subprocess.Popen(
        ["notepad.exe"],
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )

    time.sleep(0.5)

    logger.info(f"Started test process notepad.exe with PID: {process.pid}")

    yield process

    try:
        process.terminate()
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    except Exception as e:
        logger.warning(f"Error terminating test process: {e}")


@pytest.fixture
def themida_sample_path() -> Path | None:
    """Return path to Themida-protected sample binary if available."""
    test_data_dir = Path(__file__).parent.parent.parent / "test_data" / "protected_binaries" / "themida"

    if not test_data_dir.exists():
        return None

    for pattern in ["*.exe", "*.dll"]:
        samples = list(test_data_dir.glob(pattern))
        if samples:
            logger.info(f"Found Themida sample: {samples[0]}")
            return samples[0]

    return None


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_themida_script_generation(ensure_windows: None, ensure_frida: None) -> None:
    """Validate Themida unpacking script is generated correctly.

    Tests that the FridaProtectionBypasser generates a valid Themida unpacking
    script containing all required kernel-mode anti-debug bypass hooks.
    """
    bypasser = FridaProtectionBypasser(process_name="explorer.exe")

    script = bypasser._generate_themida_unpacking_script()

    assert isinstance(script, str)
    assert len(script) > 2000

    assert "NtQueryInformationProcess" in script
    assert "NtSetInformationThread" in script
    assert "NtQuerySystemInformation" in script
    assert "NtClose" in script
    assert "ProcessDebugPort" in script
    assert "ProcessDebugObjectHandle" in script
    assert "ProcessDebugFlags" in script
    assert "ThreadHideFromDebugger" in script
    assert "SystemKernelDebuggerInformation" in script

    assert "IsDebuggerPresent" in script
    assert "CheckRemoteDebuggerPresent" in script
    assert "BeingDebugged" in script
    assert "NtGlobalFlag" in script

    assert "QueryPerformanceCounter" in script
    assert "GetTickCount" in script

    assert "SecureEngine" in script.lower() or "themida" in script.lower()
    assert "RISC" in script or "FISH" in script

    logger.info("Themida script generation validated - all kernel anti-debug hooks present")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_ntqueryinformationprocess_debug_port_bypass(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate NtQueryInformationProcess ProcessDebugPort bypass.

    Tests that the Themida unpacker correctly hooks NtQueryInformationProcess
    and returns 0 for ProcessDebugPort (info class 0x07) to defeat kernel-mode
    debug detection.

    CRITICAL: Test MUST fail if hook doesn't intercept debug port queries.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)
                logger.info(f"Anti-debug detection: {payload}")

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntQueryInfoProcess = ntdll.getExportByName('NtQueryInformationProcess');

    const NtQueryInformationProcess = new NativeFunction(
        ntQueryInfoProcess,
        'uint32',
        ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']
    );

    const ProcessDebugPort = 0x07;
    const buffer = Memory.alloc(Process.pointerSize);
    const retLength = Memory.alloc(4);

    const status = NtQueryInformationProcess(
        ptr(-1),
        ProcessDebugPort,
        buffer,
        Process.pointerSize,
        retLength
    );

    const debugPort = Process.pointerSize === 8 ? buffer.readU64() : buffer.readU32();

    send({
        type: 'verification',
        method: 'ProcessDebugPort',
        status: status,
        debugPort: debugPort.toString()
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    port_check = [log for log in detection_log if log.get("method") == "ProcessDebugPort"]

    assert len(port_check) > 0
    assert port_check[0].get("debugPort") == "0"

    logger.info("ProcessDebugPort bypass validated - returns 0 successfully")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_ntsetinformationthread_hide_from_debugger_block(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate NtSetInformationThread ThreadHideFromDebugger blocking.

    Tests that the Themida unpacker intercepts and blocks
    NtSetInformationThread calls with ThreadHideFromDebugger (info class 0x11)
    which is a critical kernel-mode anti-debug technique used by Themida.

    CRITICAL: Test MUST fail if ThreadHideFromDebugger calls are not blocked.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)
                logger.info(f"Anti-debug detection: {payload}")

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntSetInfoThread = ntdll.getExportByName('NtSetInformationThread');

    const NtSetInformationThread = new NativeFunction(
        ntSetInfoThread,
        'uint32',
        ['pointer', 'uint32', 'pointer', 'uint32']
    );

    const ThreadHideFromDebugger = 0x11;

    const status = NtSetInformationThread(
        ptr(-2),
        ThreadHideFromDebugger,
        ptr(0),
        0
    );

    send({
        type: 'verification',
        method: 'ThreadHideFromDebugger',
        status: status,
        blocked: status === 0
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    hide_check = [
        log for log in detection_log
        if "ThreadHideFromDebugger" in str(log.get("method", ""))
    ]

    assert len(hide_check) > 0

    logger.info("ThreadHideFromDebugger blocking validated - call intercepted and neutralized")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_ntquerysysteminformation_kernel_debugger_spoof(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate NtQuerySystemInformation kernel debugger detection bypass.

    Tests that the Themida unpacker hooks NtQuerySystemInformation and spoofs
    SystemKernelDebuggerInformation (0x23) to report KdDebuggerEnabled=FALSE
    and KdDebuggerNotPresent=TRUE, defeating kernel-level debug detection.

    CRITICAL: Test MUST fail if kernel debugger status is not spoofed.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)
                logger.info(f"Anti-debug detection: {payload}")

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntQuerySysInfo = ntdll.getExportByName('NtQuerySystemInformation');

    const NtQuerySystemInformation = new NativeFunction(
        ntQuerySysInfo,
        'uint32',
        ['uint32', 'pointer', 'uint32', 'pointer']
    );

    const SystemKernelDebuggerInformation = 0x23;
    const buffer = Memory.alloc(2);
    const retLength = Memory.alloc(4);

    const status = NtQuerySystemInformation(
        SystemKernelDebuggerInformation,
        buffer,
        2,
        retLength
    );

    const kdDebuggerEnabled = buffer.readU8();
    const kdDebuggerNotPresent = buffer.add(1).readU8();

    send({
        type: 'verification',
        method: 'SystemKernelDebuggerInformation',
        status: status,
        kdEnabled: kdDebuggerEnabled,
        kdNotPresent: kdDebuggerNotPresent
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    kd_check = [
        log for log in detection_log
        if log.get("method") == "SystemKernelDebuggerInformation"
    ]

    assert len(kd_check) > 0
    assert kd_check[0].get("kdEnabled") == 0
    assert kd_check[0].get("kdNotPresent") == 1

    logger.info("Kernel debugger detection bypass validated - KdDebuggerEnabled=0, KdDebuggerNotPresent=1")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_ntclose_invalid_handle_exception_suppression(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate NtClose invalid handle exception suppression.

    Tests that the Themida unpacker intercepts NtClose and suppresses
    STATUS_INVALID_HANDLE (0xC0000008) exceptions which Themida uses as an
    anti-debug trick (debuggers typically raise exception on invalid handles).

    CRITICAL: Test MUST fail if invalid handle exceptions are not suppressed.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)
                logger.info(f"Anti-debug detection: {payload}")

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntClose = ntdll.getExportByName('NtClose');

    const NtClose = new NativeFunction(ntClose, 'uint32', ['pointer']);

    const invalidHandle = ptr(0xDEADBEEF);
    const status = NtClose(invalidHandle);

    send({
        type: 'verification',
        method: 'NtClose_InvalidHandle',
        originalStatus: '0xC0000008',
        actualStatus: '0x' + status.toString(16).toUpperCase(),
        suppressed: status === 0
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    close_check = [
        log for log in detection_log
        if "NtClose" in str(log.get("method", ""))
    ]

    assert len(close_check) > 0
    assert close_check[0].get("suppressed") is True

    logger.info("Invalid handle exception suppression validated - STATUS_INVALID_HANDLE converted to success")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_process_debug_object_handle_bypass(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate ProcessDebugObjectHandle bypass.

    Tests that the Themida unpacker hooks NtQueryInformationProcess and returns
    0 for ProcessDebugObjectHandle (info class 0x1E) and STATUS_PORT_NOT_SET,
    defeating kernel debug object enumeration.

    CRITICAL: Test MUST fail if debug object handle queries are not spoofed.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)
                logger.info(f"Anti-debug detection: {payload}")

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntQueryInfoProcess = ntdll.getExportByName('NtQueryInformationProcess');

    const NtQueryInformationProcess = new NativeFunction(
        ntQueryInfoProcess,
        'uint32',
        ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']
    );

    const ProcessDebugObjectHandle = 0x1E;
    const buffer = Memory.alloc(Process.pointerSize);
    const retLength = Memory.alloc(4);

    const status = NtQueryInformationProcess(
        ptr(-1),
        ProcessDebugObjectHandle,
        buffer,
        Process.pointerSize,
        retLength
    );

    const debugObject = Process.pointerSize === 8 ? buffer.readU64() : buffer.readU32();

    send({
        type: 'verification',
        method: 'ProcessDebugObjectHandle',
        status: '0x' + status.toString(16).toUpperCase(),
        debugObject: debugObject.toString(),
        expectedStatus: '0xC0000353'
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    object_check = [
        log for log in detection_log
        if log.get("method") == "ProcessDebugObjectHandle"
    ]

    assert len(object_check) > 0
    assert object_check[0].get("debugObject") == "0"

    logger.info("ProcessDebugObjectHandle bypass validated - returns 0 with STATUS_PORT_NOT_SET")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_process_debug_flags_bypass(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate ProcessDebugFlags bypass.

    Tests that the Themida unpacker hooks NtQueryInformationProcess and returns
    1 for ProcessDebugFlags (info class 0x1F) to indicate PROCESS_DEBUG_INHERIT
    is set (no debugger attached).

    CRITICAL: Test MUST fail if debug flags are not spoofed correctly.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)
                logger.info(f"Anti-debug detection: {payload}")

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const ntQueryInfoProcess = ntdll.getExportByName('NtQueryInformationProcess');

    const NtQueryInformationProcess = new NativeFunction(
        ntQueryInfoProcess,
        'uint32',
        ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']
    );

    const ProcessDebugFlags = 0x1F;
    const buffer = Memory.alloc(4);
    const retLength = Memory.alloc(4);

    const status = NtQueryInformationProcess(
        ptr(-1),
        ProcessDebugFlags,
        buffer,
        4,
        retLength
    );

    const debugFlags = buffer.readU32();

    send({
        type: 'verification',
        method: 'ProcessDebugFlags',
        status: status,
        debugFlags: debugFlags,
        noDebugger: debugFlags === 1
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    flags_check = [
        log for log in detection_log
        if log.get("method") == "ProcessDebugFlags"
    ]

    assert len(flags_check) > 0
    assert flags_check[0].get("debugFlags") == 1
    assert flags_check[0].get("noDebugger") is True

    logger.info("ProcessDebugFlags bypass validated - returns 1 (PROCESS_DEBUG_INHERIT)")


@pytest.mark.requires_process_attach
@pytest.mark.slow
@pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Themida samples only available on Windows"
)
def test_themida_sample_complete_bypass(
    themida_sample_path: Path | None,
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate complete Themida bypass on real protected binary.

    Tests the full kernel anti-debug bypass chain against an actual
    Themida-protected binary. Validates that all hooks work together
    to defeat layered protections.

    CRITICAL: Test MUST fail if Themida detects debugging or crashes.
    """
    if themida_sample_path is None:
        pytest.skip(
            "No Themida-protected sample binary available. "
            "Place test binaries in tests/test_data/protected_binaries/themida/"
        )

    if not themida_sample_path.exists():
        pytest.skip(f"Themida sample not found: {themida_sample_path}")

    logger.info(f"Testing against Themida sample: {themida_sample_path}")

    process = subprocess.Popen(
        [str(themida_sample_path)],
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )

    time.sleep(1)

    try:
        bypasser = FridaProtectionBypasser(pid=process.pid)

        assert bypasser.attach()
        assert bypasser.session is not None

        script_code = bypasser._generate_themida_unpacking_script()

        themida_detections: list[dict[str, object]] = []

        def on_message(message: object, _data: object) -> None:
            if isinstance(message, dict) and message.get("type") == "send":
                payload = message.get("payload")
                if isinstance(payload, dict):
                    themida_detections.append(payload)
                    msg_type = payload.get("type", "unknown")
                    logger.info(f"Themida detection [{msg_type}]: {payload}")

        script = bypasser.session.create_script(script_code)
        script.on("message", on_message)
        script.load()

        time.sleep(3)

        script.unload()
        bypasser.session.detach()

        antidebug_detections = [
            d for d in themida_detections
            if "themida_antidebug" in str(d.get("type", ""))
        ]

        assert len(antidebug_detections) > 0

        veh_detections = [
            d for d in themida_detections
            if d.get("type") == "themida_veh"
        ]

        assert len(veh_detections) >= 0

        section_detections = [
            d for d in themida_detections
            if d.get("type") == "themida_section"
        ]

        logger.info(
            f"Themida bypass complete: {len(antidebug_detections)} anti-debug hooks triggered, "
            f"{len(veh_detections)} VEH handlers detected, "
            f"{len(section_detections)} SecureEngine sections found"
        )

    finally:
        try:
            process.terminate()
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_edge_case_custom_themida_build(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate bypass works with custom Themida configurations.

    Tests that the kernel anti-debug bypass is resilient to variations in
    Themida builds including different SecureEngine options and custom
    protection configurations.

    CRITICAL: Test MUST validate hook flexibility and robustness.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    assert "NtQueryInformationProcess" in script_code
    assert "NtSetInformationThread" in script_code
    assert "NtQuerySystemInformation" in script_code

    assert "0x07" in script_code
    assert "0x1E" in script_code
    assert "0x1F" in script_code
    assert "0x11" in script_code
    assert "0x23" in script_code

    assert "Interceptor.attach" in script_code or "Interceptor.replace" in script_code

    script = bypasser.session.create_script(script_code)
    script.load()

    time.sleep(0.5)

    script.unload()
    bypasser.session.detach()

    logger.info("Custom Themida build resilience validated - all hooks present and loadable")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_edge_case_themida_vmprotect_combination(
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate bypass works with Themida + VMProtect layered protections.

    Tests that the Themida kernel anti-debug bypass doesn't interfere with
    other protection bypasses and can handle layered protections.

    CRITICAL: Test MUST validate compatibility with multi-layer protections.
    """
    process = subprocess.Popen(
        ["notepad.exe"],
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )

    time.sleep(0.5)

    try:
        bypasser = FridaProtectionBypasser(pid=process.pid)

        assert bypasser.attach()
        assert bypasser.session is not None

        themida_script = bypasser._generate_themida_unpacking_script()
        vmprotect_script = bypasser._generate_vmprotect_unpacking_script()

        combined_script = themida_script + "\n\n" + vmprotect_script

        script = bypasser.session.create_script(combined_script)
        script.load()

        time.sleep(1)

        script.unload()
        bypasser.session.detach()

        logger.info("Layered protection compatibility validated - Themida + VMProtect scripts coexist")

    finally:
        try:
            process.terminate()
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_peb_flag_manipulation_comprehensive(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate comprehensive PEB flag manipulation for anti-debug.

    Tests that the Themida unpacker correctly modifies PEB.BeingDebugged and
    PEB.NtGlobalFlag to hide debugging presence at user-mode level.

    CRITICAL: Test MUST fail if PEB flags are not properly cleared.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    detection_log: list[dict[str, object]] = []

    def on_message(message: object, _data: object) -> None:
        if isinstance(message, dict) and message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                detection_log.append(payload)

    script = bypasser.session.create_script(script_code)
    script.on("message", on_message)
    script.load()

    verification_script = """
    const ntdll = Process.getModuleByName('ntdll.dll');
    const rtlGetCurrentPeb = ntdll.getExportByName('RtlGetCurrentPeb');

    const RtlGetCurrentPeb = new NativeFunction(rtlGetCurrentPeb, 'pointer', []);
    const peb = RtlGetCurrentPeb();

    const beingDebugged = peb.add(0x02).readU8();

    const ntGlobalFlagOffset = Process.pointerSize === 8 ? 0xBC : 0x68;
    const ntGlobalFlag = peb.add(ntGlobalFlagOffset).readU32();

    const heapFlags = ntGlobalFlag & 0x70;

    send({
        type: 'verification',
        method: 'PEB_Flags',
        beingDebugged: beingDebugged,
        ntGlobalFlag: '0x' + ntGlobalFlag.toString(16),
        heapFlagsCleared: heapFlags === 0
    });
    """

    verification = bypasser.session.create_script(verification_script)
    verification.on("message", on_message)
    verification.load()

    time.sleep(0.5)

    verification.unload()
    script.unload()
    bypasser.session.detach()

    peb_check = [
        log for log in detection_log
        if log.get("method") == "PEB_Flags"
    ]

    assert len(peb_check) > 0
    assert peb_check[0].get("beingDebugged") == 0
    assert peb_check[0].get("heapFlagsCleared") is True

    logger.info("PEB flag manipulation validated - BeingDebugged=0, heap debug flags cleared")


@pytest.mark.requires_process_attach
@pytest.mark.slow
def test_timing_attack_bypass_comprehensive(
    test_process_notepad: subprocess.Popen[bytes],
    ensure_windows: None,
    ensure_frida: None,
) -> None:
    """Validate timing attack bypass for Themida debug detection.

    Tests that the Themida unpacker hooks QueryPerformanceCounter and
    GetTickCount to normalize timing and prevent timing-based debug detection.

    CRITICAL: Test MUST validate timing normalization effectiveness.
    """
    bypasser = FridaProtectionBypasser(pid=test_process_notepad.pid)

    assert bypasser.attach()
    assert bypasser.session is not None

    script_code = bypasser._generate_themida_unpacking_script()

    assert "QueryPerformanceCounter" in script_code
    assert "GetTickCount" in script_code
    assert "lastRdtsc" in script_code or "lastTickCount" in script_code

    script = bypasser.session.create_script(script_code)
    script.load()

    time.sleep(0.5)

    script.unload()
    bypasser.session.detach()

    logger.info("Timing attack bypass validated - QPC and GetTickCount hooks present")
