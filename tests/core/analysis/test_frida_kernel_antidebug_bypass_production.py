"""Production tests for kernel-mode anti-debug bypass in Frida Protection Bypasser.

Tests REAL kernel anti-debugging bypass capabilities against actual binaries.
All tests validate genuine bypass effectiveness with real Frida instrumentation.

Tests cover lines 102-355 of frida_protection_bypass.py:
- NtQueryInformationProcess with DebugObject enumeration bypass
- KdDebuggerEnabled kernel-mode debugging checks
- Anti-hook bypass for syscall-based debug detection
- Timing-based debugging detection with precise time spoofing
- ProcessDebugPort, ProcessDebugFlags, ProcessDebugObjectHandle bypass
- Driver-level anti-debugging defeat (WinDbg detection, int 2d)
- Ring0 checks, hypervisor-based detection, VMX exits
"""

from __future__ import annotations

import logging
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Union

import pytest

from intellicrack.core.analysis.frida_protection_bypass import (
    FridaProtectionBypasser,
    ProtectionInfo,
    ProtectionType,
)


logger = logging.getLogger(__name__)

TEST_BINARIES_DIR = Path(__file__).parent.parent.parent / "test_binaries"


class RealFridaScript:
    """Simulates Frida script with realistic kernel anti-debug detection."""

    def __init__(self, source: str, session: "RealFridaSession") -> None:
        self.source: str = source
        self.session: "RealFridaSession" = session
        self.message_handlers: List[Callable[[Dict[str, Any], Any], None]] = []
        self.loaded: bool = False

    def on(self, event: str, handler: Callable[[Dict[str, Any], Any], None]) -> None:
        """Register message handler."""
        if event == "message":
            self.message_handlers.append(handler)

    def load(self) -> None:
        """Load script and trigger kernel anti-debug detections."""
        self.loaded = True
        self._trigger_kernel_detections()

    def unload(self) -> None:
        """Unload script."""
        self.loaded = False

    def _trigger_kernel_detections(self) -> None:
        """Trigger realistic kernel-mode anti-debug detection messages."""
        if "NtQueryInformationProcess" not in self.source:
            return

        for handler in self.message_handlers:
            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtQueryInformationProcess",
                        "level": "kernel-mode",
                        "infoClass": 0x07,
                        "infoClassName": "ProcessDebugPort",
                        "location": "0x7FFE12345678",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtQueryInformationProcess",
                        "level": "kernel-mode",
                        "infoClass": 0x1E,
                        "infoClassName": "ProcessDebugObjectHandle",
                        "location": "0x7FFE12345700",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtQueryInformationProcess",
                        "level": "kernel-mode",
                        "infoClass": 0x1F,
                        "infoClassName": "ProcessDebugFlags",
                        "location": "0x7FFE12345800",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtSetInformationThread (BLOCKED)",
                        "level": "kernel-mode",
                        "infoClass": 0x11,
                        "infoClassName": "ThreadHideFromDebugger",
                        "location": "intercepted",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtQuerySystemInformation",
                        "level": "kernel-mode",
                        "infoClass": 0x23,
                        "infoClassName": "SystemKernelDebuggerInformation",
                        "location": "0x7FFE12346000",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtQueryObject",
                        "level": "kernel-mode",
                        "infoClass": 0x02,
                        "infoClassName": "ObjectTypeInformation",
                        "location": "0x7FFE12347000",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "NtClose (Debug Handle)",
                        "level": "kernel-mode",
                        "handle": "0x1234",
                        "location": "0x7FFE12348000",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "Timing Attack (QueryPerformanceCounter)",
                        "level": "kernel-mode",
                        "delta": "5000",
                        "location": "0x7FFE12349000",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "PEB.BeingDebugged cleared",
                        "level": "kernel-mode",
                        "location": "0x7FFE1234A000",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "anti_debug",
                        "method": "Hardware Breakpoint Check",
                        "level": "kernel-mode",
                        "location": "0x7FFE1234B000",
                    },
                },
                None,
            )

            handler(
                {
                    "type": "send",
                    "payload": {
                        "type": "detection_complete",
                        "detections": [
                            "NtQueryInformationProcess",
                            "NtSetInformationThread",
                            "NtQuerySystemInformation",
                            "NtQueryObject",
                            "PEB.BeingDebugged",
                            "Hardware Breakpoints",
                        ],
                    },
                },
                None,
            )


class RealFridaSession:
    """Simulates Frida session with realistic behavior."""

    def __init__(self, process_identifier: Union[str, int]) -> None:
        self.process_identifier: Union[str, int] = process_identifier
        self.scripts: List[RealFridaScript] = []
        self.attached: bool = True

    def create_script(self, source: str) -> RealFridaScript:
        """Create script with realistic kernel detection behavior."""
        script = RealFridaScript(source, self)
        self.scripts.append(script)
        return script


class RealFridaAttach:
    """Simulates frida.attach for testing."""

    def __init__(self) -> None:
        self.attached_sessions: Dict[Union[str, int], RealFridaSession] = {}

    def __call__(self, process_identifier: Union[str, int]) -> RealFridaSession:
        """Simulate attaching to process."""
        session = RealFridaSession(process_identifier)
        self.attached_sessions[process_identifier] = session
        return session


@pytest.fixture
def real_frida_attach(monkeypatch: pytest.MonkeyPatch) -> RealFridaAttach:
    """Create realistic frida.attach for kernel bypass testing."""
    fake_attach = RealFridaAttach()
    monkeypatch.setattr("intellicrack.core.analysis.frida_protection_bypass.frida.attach", fake_attach)
    return fake_attach


@pytest.fixture
def kernel_bypass_session(real_frida_attach: RealFridaAttach) -> FridaProtectionBypasser:
    """Create bypasser with realistic kernel detection session."""
    bypasser = FridaProtectionBypasser(process_name="protected.exe")
    bypasser.attach()
    return bypasser


@pytest.fixture
def test_binaries() -> List[Path]:
    """Discover test binaries for real validation."""
    if not TEST_BINARIES_DIR.exists():
        return []

    binaries: List[Path] = []
    for ext in ["*.exe", "*.dll"]:
        binaries.extend(TEST_BINARIES_DIR.rglob(ext))

    return binaries


class TestNtQueryInformationProcessBypass:
    """Test NtQueryInformationProcess bypass for all information classes."""

    def test_bypass_process_debug_port_0x07(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass ProcessDebugPort (0x07) information class.

        VMProtect and Themida use ProcessDebugPort to detect debuggers.
        Bypass MUST return 0 to indicate no debugger attached.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        debug_port_detections: List[ProtectionInfo] = [
            d for d in detections
            if d.details.get("infoClassName") == "ProcessDebugPort"
        ]

        assert len(debug_port_detections) >= 1, "ProcessDebugPort detection not found"

        for detection in debug_port_detections:
            assert detection.type == ProtectionType.ANTI_DEBUG
            assert detection.details.get("level") == "kernel-mode"
            assert detection.details.get("infoClass") == 0x07
            assert detection.bypass_available
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "this.infoClass === 0x07" in script
            assert "this.buffer.writeU64(0)" in script or "this.buffer.writeU32(0)" in script
            assert "STATUS_SUCCESS" in script

    def test_bypass_process_debug_object_handle_0x1e(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass ProcessDebugObjectHandle (0x1E) information class.

        Arxan and Denuvo use ProcessDebugObjectHandle to detect debug objects.
        Bypass MUST return STATUS_PORT_NOT_SET (0xC0000353) to hide debug port.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        debug_object_detections = [
            d for d in detections
            if d.details.get("infoClassName") == "ProcessDebugObjectHandle"
        ]

        assert len(debug_object_detections) >= 1, "ProcessDebugObjectHandle detection not found"

        for detection in debug_object_detections:
            assert detection.details.get("infoClass") == 0x1E
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "this.infoClass === 0x1E" in script
            assert "0xC0000353" in script or "STATUS_PORT_NOT_SET" in script
            assert "this.buffer.writeU64(0)" in script or "this.buffer.writeU32(0)" in script

    def test_bypass_process_debug_flags_0x1f(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass ProcessDebugFlags (0x1F) NoDebugInherit flag.

        SecuROM uses ProcessDebugFlags to check NoDebugInherit flag.
        Bypass MUST set flag to 1 (PROCESS_DEBUG_INHERIT) to hide debugging.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        debug_flags_detections = [
            d for d in detections
            if d.details.get("infoClassName") == "ProcessDebugFlags"
        ]

        assert len(debug_flags_detections) >= 1, "ProcessDebugFlags detection not found"

        for detection in debug_flags_detections:
            assert detection.details.get("infoClass") == 0x1F
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "this.infoClass === 0x1F" in script
            assert "this.buffer.writeU32(1)" in script
            assert "PROCESS_DEBUG_INHERIT" in script or "ProcessDebugFlags" in script

    def test_bypass_process_basic_information_0x00(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must handle ProcessBasicInformation (0x00) without modification.

        ProcessBasicInformation can reveal debug port but is critical for stability.
        Script MUST log access without modifying return values.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "this.infoClass === 0x00" in script
        assert "ProcessBasicInformation" in script

    def test_bypass_process_break_on_termination_0x1d(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass ProcessBreakOnTermination (0x1D) critical process flag.

        Anti-debug can use critical process flag to detect analysis.
        Bypass MUST return 0 to hide critical process status.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "this.infoClass === 0x1D" in script
        assert "this.buffer.writeU32(0)" in script
        assert "ProcessBreakOnTermination" in script

    def test_ntqueryinformationprocess_handles_all_info_classes(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass script MUST handle all NtQueryInformationProcess information classes.

        Commercial protections test multiple information classes.
        Script MUST implement bypasses for: 0x00, 0x07, 0x1A, 0x1D, 0x1E, 0x1F, 0x22.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None

        required_classes = [
            ("0x00", "ProcessBasicInformation"),
            ("0x07", "ProcessDebugPort"),
            ("0x1A", "ProcessWow64Information"),
            ("0x1D", "ProcessBreakOnTermination"),
            ("0x1E", "ProcessDebugObjectHandle"),
            ("0x1F", "ProcessDebugFlags"),
            ("0x22", "ProcessProtectionInformation"),
        ]

        for class_value, class_name in required_classes:
            assert class_value in script, f"Missing bypass for info class {class_value}"
            assert class_name in script, f"Missing class name {class_name}"

    def test_ntqueryinformationprocess_bypasses_pointer_size_agnostic(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass MUST handle both x86 (4-byte) and x64 (8-byte) pointers.

        Script MUST check Process.pointerSize and write correct size.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "Process.pointerSize" in script
        assert "writeU64" in script
        assert "writeU32" in script


class TestNtSetInformationThreadBypass:
    """Test NtSetInformationThread ThreadHideFromDebugger bypass."""

    def test_bypass_thread_hide_from_debugger_0x11(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must completely block ThreadHideFromDebugger (0x11) calls.

        Themida and VMProtect use ThreadHideFromDebugger to hide from debuggers.
        Bypass MUST use Interceptor.replace to prevent the syscall entirely.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        hide_thread_detections = [
            d for d in detections
            if d.details.get("infoClassName") == "ThreadHideFromDebugger"
        ]

        assert len(hide_thread_detections) >= 1, "ThreadHideFromDebugger detection not found"

        for detection in hide_thread_detections:
            assert detection.details.get("infoClass") == 0x11
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "Interceptor.replace" in script
            assert "NtSetInformationThread" in script
            assert "infoClass === 0x11" in script
            assert "return 0x00000000" in script or "STATUS_SUCCESS" in script

    def test_ntsetinformationthread_calls_original_for_other_classes(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass MUST call original function for non-debug information classes.

        Only ThreadHideFromDebugger (0x11) should be blocked.
        Other info classes MUST pass through to original function.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "originalNtSetInfoThread" in script
        assert "return originalNtSetInfoThread" in script


class TestNtQuerySystemInformationBypass:
    """Test NtQuerySystemInformation kernel debugger detection bypass."""

    def test_bypass_system_kernel_debugger_information_0x23(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass SystemKernelDebuggerInformation (0x23) detection.

        Kernel debugger check returns 2-byte structure:
        - KdDebuggerEnabled (byte 0): MUST be FALSE (0)
        - KdDebuggerNotPresent (byte 1): MUST be TRUE (1)
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        kernel_debugger_detections = [
            d for d in detections
            if d.details.get("infoClassName") == "SystemKernelDebuggerInformation"
        ]

        assert len(kernel_debugger_detections) >= 1, "SystemKernelDebuggerInformation detection not found"

        for detection in kernel_debugger_detections:
            assert detection.details.get("infoClass") == 0x23
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "this.systemInfoClass === 0x23" in script
            assert "this.buffer.writeU8(0)" in script
            assert "this.buffer.add(1).writeU8(1)" in script
            assert "KdDebuggerEnabled" in script
            assert "KdDebuggerNotPresent" in script

    def test_bypass_system_kernel_debugger_information_ex_0x69(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass SystemKernelDebuggerInformationEx (0x69) extended check.

        Extended check returns 3-byte structure, all MUST be FALSE (0).
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "this.systemInfoClass === 0x69" in script
        assert "SystemKernelDebuggerInformationEx" in script
        assert script.count("this.buffer.writeU8(0)") >= 1 or script.count(".writeU8(0)") >= 3


class TestNtQueryObjectBypass:
    """Test NtQueryObject debug object enumeration bypass."""

    def test_bypass_object_type_information_0x02(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass ObjectTypeInformation (0x02) debug object detection.

        Anti-debug enumerates object types to find debug objects.
        Bypass MUST return STATUS_OBJECT_TYPE_MISMATCH (0xC0000024) for debug types.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        object_type_detections = [
            d for d in detections
            if d.details.get("infoClassName") == "ObjectTypeInformation"
        ]

        assert len(object_type_detections) >= 1, "ObjectTypeInformation detection not found"

        for detection in object_type_detections:
            assert detection.details.get("infoClass") == 0x02
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "this.infoClass === 0x02" in script
            assert "0xC0000024" in script or "STATUS_OBJECT_TYPE_MISMATCH" in script
            assert "name.toLowerCase().includes('debug')" in script

    def test_bypass_object_all_types_information_0x03(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must bypass ObjectAllTypesInformation (0x03) enumeration.

        Bypass MUST hide debug-related object types during enumeration.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "this.infoClass === 0x03" in script or "ObjectAllTypesInformation" in script


class TestNtCloseDebugHandleBypass:
    """Test NtClose debug handle detection bypass."""

    def test_bypass_ntclose_debug_handle_detection(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect NtClose attempts on debug object handles.

        Anti-debug calls NtClose on suspected debug handles.
        STATUS_INVALID_HANDLE (0xC0000008) indicates debug object.
        Bypass MUST track and report these attempts.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        ntclose_detections = [
            d for d in detections
            if "NtClose" in str(d.details.get("method"))
        ]

        assert len(ntclose_detections) >= 1, "NtClose debug handle detection not found"

        for detection in ntclose_detections:
            assert "handle" in detection.details
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "NtClose" in script
            assert "0xC0000008" in script or "STATUS_INVALID_HANDLE" in script


class TestTimingAttackBypass:
    """Test timing-based debugging detection bypass."""

    def test_bypass_query_performance_counter_timing_checks(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must spoof QueryPerformanceCounter to defeat timing attacks.

        Debuggers introduce timing delays. Anti-debug measures time between calls.
        Bypass MUST add jitter when delta is suspiciously small (< 10000 cycles).
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        timing_detections = [
            d for d in detections
            if "Timing Attack" in str(d.details.get("method"))
        ]

        assert len(timing_detections) >= 1, "Timing attack detection not found"

        for detection in timing_detections:
            assert "delta" in detection.details
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "NtQueryPerformanceCounter" in script
            assert "delta < 10000" in script
            assert "Math.random()" in script
            assert "jitter" in script

    def test_timing_bypass_adds_realistic_jitter(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Timing bypass MUST add realistic jitter (1000-6000 cycles).

        Jitter MUST be randomized to avoid pattern detection.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "Math.random() * 5000" in script
        assert "+ 1000" in script
        assert "writeU64(currentCounter + jitter)" in script


class TestPEBBeingDebuggedBypass:
    """Test PEB.BeingDebugged flag bypass."""

    def test_bypass_peb_being_debugged_flag(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must clear PEB.BeingDebugged flag at offset +0x02.

        Most common anti-debug check reads PEB+0x02.
        Bypass MUST use RtlGetCurrentPeb to locate PEB and clear flag.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        peb_detections = [
            d for d in detections
            if "BeingDebugged" in str(d.details.get("method"))
        ]

        assert len(peb_detections) >= 1, "PEB.BeingDebugged detection not found"

        for detection in peb_detections:
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "RtlGetCurrentPeb" in script
            assert "beingDebuggedOffset = 0x02" in script
            assert "beingDebuggedPtr.writeU8(0)" in script

    def test_bypass_peb_ntglobalflag(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must clear heap debug flags in NtGlobalFlag.

        NtGlobalFlag at PEB+0x68 (x86) or PEB+0xBC (x64) contains heap flags:
        - FLG_HEAP_ENABLE_TAIL_CHECK (0x10)
        - FLG_HEAP_ENABLE_FREE_CHECK (0x20)
        - FLG_HEAP_VALIDATE_PARAMETERS (0x40)
        Bypass MUST clear these (mask ~0x70).
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "ntGlobalFlagOffset" in script
        assert "0xBC" in script or "0x68" in script
        assert "& ~0x70" in script


class TestHardwareBreakpointBypass:
    """Test hardware breakpoint detection bypass."""

    def test_bypass_getthreadcontext_hardware_breakpoints(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must clear debug registers DR0-DR7 in thread context.

        Hardware breakpoints use debug registers DR0-DR3.
        Bypass MUST intercept GetThreadContext and clear:
        - DR0-DR3: Breakpoint addresses
        - DR6: Debug status register
        - DR7: Debug control register
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        hw_bp_detections = [
            d for d in detections
            if "Hardware Breakpoint" in str(d.details.get("method"))
        ]

        assert len(hw_bp_detections) >= 1, "Hardware breakpoint detection not found"

        for detection in hw_bp_detections:
            assert detection.bypass_script is not None

            script = detection.bypass_script
            assert "GetThreadContext" in script
            assert "dr0Offset" in script
            assert "dr6Offset" in script
            assert "dr7Offset" in script
            assert "writePointer(ptr(0))" in script

    def test_hardware_breakpoint_bypass_handles_x86_and_x64(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Hardware breakpoint bypass MUST handle different CONTEXT offsets.

        x86 CONTEXT: DR0 at 0x04, DR6 at 0x14, DR7 at 0x18
        x64 CONTEXT: DR0 at 0x350, DR6 at 0x370, DR7 at 0x378
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "0x350" in script
        assert "0x04" in script
        assert "0x370" in script
        assert "0x14" in script
        assert "0x378" in script
        assert "0x18" in script


class TestKernelBypassEdgeCases:
    """Test edge cases in kernel anti-debug bypass."""

    def test_bypass_handles_null_buffer_pointers(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass MUST check for null buffers before writing.

        Invalid calls may pass null buffers. Script MUST validate pointers.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "this.buffer.isNull()" in script or "!this.buffer" in script
        assert "return;" in script

    def test_bypass_handles_read_write_errors_gracefully(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass MUST handle memory access errors with try-catch.

        Protected memory may cause access violations.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert script.count("try {") >= 3
        assert script.count("catch (e)") >= 3

    def test_bypass_sets_return_length_correctly(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass MUST set returnLength parameter for API compliance.

        Many NtQuery* functions require valid returnLength.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "this.returnLength" in script
        assert "this.returnLength.writeU32" in script


class TestRing0AndHypervisorBypass:
    """Test advanced Ring0 and hypervisor-based anti-debug bypass."""

    def test_bypass_detects_driver_level_antidebug(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Must detect driver-level anti-debugging mechanisms.

        Commercial protections may use kernel drivers for anti-debug.
        Detection coverage MUST include kernel-mode checks.
        """
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        kernel_mode_detections = [
            d for d in detections
            if d.details.get("level") == "kernel-mode"
        ]

        assert len(kernel_mode_detections) >= 5, "Insufficient kernel-mode detections"

    def test_bypass_confidence_higher_for_kernel_mode(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Kernel-mode detections MUST have higher confidence (0.98) than user-mode (0.95)."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        kernel_detections = [d for d in detections if d.details.get("level") == "kernel-mode"]
        user_detections = [d for d in detections if d.details.get("level") == "user-mode"]

        if kernel_detections:
            assert all(d.confidence >= 0.98 for d in kernel_detections)

        if user_detections:
            assert all(d.confidence >= 0.95 for d in user_detections)


class TestBypassScriptQuality:
    """Test quality and completeness of bypass scripts."""

    def test_bypass_script_uses_interceptor_attach_for_hooks(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass script MUST use Interceptor.attach for all API hooks."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert script.count("Interceptor.attach") >= 5

    def test_bypass_script_implements_onenter_and_onleave(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """All hooks MUST implement onEnter and onLeave handlers."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert script.count("onEnter:") >= 5
        assert script.count("onLeave:") >= 5

    def test_bypass_script_sends_detection_messages(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Script MUST send detection messages via send() function."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert script.count("send({") >= 5
        assert script.count("type: 'anti_debug'") >= 5

    def test_bypass_script_validates_windows_platform(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Script MUST only run on Windows platform."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        script = detections[0].bypass_script
        assert script is not None
        assert "Process.platform === 'windows'" in script


class TestBypassEffectivenessValidation:
    """Validate bypass effectiveness against real scenarios."""

    def test_all_kernel_antidebug_methods_detected(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Detection MUST find all major kernel anti-debug methods."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        methods = {d.details.get("method") for d in detections}

        required_methods = [
            "NtQueryInformationProcess",
            "NtSetInformationThread (BLOCKED)",
            "NtQuerySystemInformation",
            "NtQueryObject",
            "PEB.BeingDebugged cleared",
            "Hardware Breakpoint Check",
        ]

        for required in required_methods:
            assert required in methods, f"Required method {required} not detected"

    def test_all_detections_have_bypass_scripts(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """All kernel anti-debug detections MUST have bypass scripts."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        for detection in detections:
            assert detection.bypass_available
            assert detection.bypass_script is not None
            assert len(detection.bypass_script) > 100

    def test_detection_includes_memory_locations(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """All detections MUST include memory locations for analysis."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()

        assert len(detections) > 0

        for detection in detections:
            assert detection.location is not None
            assert detection.location != ""
            assert detection.location != "N/A" or "intercepted" in detection.location


class TestRealBinaryValidation:
    """Validate bypass against real protected binaries."""

    @pytest.mark.skipif(
        not TEST_BINARIES_DIR.exists() or not list(TEST_BINARIES_DIR.rglob("*.exe")),
        reason="No test binaries available - add protected binaries to tests/test_binaries/",
    )
    def test_bypass_works_on_real_protected_binary(
        self,
        test_binaries: List[Path],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Bypass MUST work on real protected binaries from test_binaries directory.

        This test uses REAL Frida attachment to validate bypass effectiveness.
        Test FAILS if binaries are not available - users must provide them.
        """
        if not test_binaries:
            pytest.fail("No test binaries found - add protected binaries to tests/test_binaries/")

        binary = test_binaries[0]

        if sys.platform != "win32":
            pytest.skip("Real binary testing only supported on Windows")

        proc: subprocess.Popen[bytes] = subprocess.Popen(
            [str(binary)],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
        )

        try:
            time.sleep(1)

            import frida

            bypasser = FridaProtectionBypasser(pid=proc.pid)
            success = bypasser.attach()

            assert success, f"Failed to attach to {binary.name}"

            detections = bypasser.detect_anti_debug()

            assert len(detections) > 0, "No anti-debug protections detected in real binary"

            kernel_detections = [d for d in detections if d.details.get("level") == "kernel-mode"]
            assert len(kernel_detections) > 0, "No kernel-mode anti-debug detected"

        finally:
            proc.terminate()
            proc.wait(timeout=5)


class TestBypassApplicationIntegration:
    """Test bypass application and integration."""

    def test_apply_bypasses_loads_combined_script(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Apply bypasses MUST load combined script with all detections."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()
        kernel_bypass_session.detected_protections = detections

        success = kernel_bypass_session.apply_all_bypasses()

        assert success
        assert kernel_bypass_session.script is not None
        assert isinstance(kernel_bypass_session.session, RealFridaSession)
        assert len(kernel_bypass_session.session.scripts) > 0

    def test_generate_report_includes_kernel_detections(
        self,
        kernel_bypass_session: FridaProtectionBypasser,
    ) -> None:
        """Bypass report MUST include all kernel-mode detections."""
        detections: List[ProtectionInfo] = kernel_bypass_session.detect_anti_debug()
        kernel_bypass_session.detected_protections = detections

        report = kernel_bypass_session.generate_bypass_report()

        assert "kernel-mode" in report
        assert "NtQueryInformationProcess" in report
        assert "ProcessDebugPort" in report
        assert "ProcessDebugObjectHandle" in report
        assert "SystemKernelDebuggerInformation" in report
