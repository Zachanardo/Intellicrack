"""Production-grade tests for COM-based debugger detection.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import ctypes
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest


if platform.system() != "Windows":
    pytest.skip("COM-based debug detection is Windows-only", allow_module_level=True)


class TestCOMDebugDetectionProduction:
    """Production tests validating real COM-based debugger detection.

    These tests verify actual COM interface spoofing, DbgEng.dll detection,
    OLE debugging interface bypass, and ICorDebug detection against real
    system resources and debugging scenarios.
    """

    @pytest.fixture(scope="class")
    def com_detector(self) -> Any:
        """Initialize COM-based debugger detector with real system access."""
        from intellicrack.core.anti_analysis.com_debug_detector import COMDebugDetector

        return COMDebugDetector()

    @pytest.fixture(scope="function")
    def cleanup_com(self) -> Any:
        """Ensure COM interfaces are properly cleaned up after tests."""
        import pythoncom

        pythoncom.CoInitialize()
        yield
        pythoncom.CoUninitialize()

    def test_idebugclient_interface_detection(self, com_detector: Any) -> None:
        """Verify detection of IDebugClient COM interface usage.

        Must detect when DbgEng.dll IDebugClient interface is instantiated,
        indicating WinDbg or other debugger using Debug Engine API.
        """
        result = com_detector.detect_idebugclient_interface()

        assert "interface_detected" in result
        assert "interface_clsid" in result
        assert isinstance(result["interface_detected"], bool)

        if result["interface_detected"]:
            assert result["interface_clsid"] is not None
            assert "5182e668-105e-416e-ad92-24ef800424ba" in result["interface_clsid"].lower()
            assert result.get("confidence", 0.0) >= 0.85

    def test_idebugclient_spoofing_prevents_detection(self, com_detector: Any) -> None:
        """Verify IDebugClient interface spoofing successfully hides debugger.

        Must implement complete IDebugClient interface spoofing that prevents
        debugger detection via COM interface enumeration.
        """
        original_detection = com_detector.detect_idebugclient_interface()

        if not original_detection["interface_detected"]:
            pytest.skip("IDebugClient not detected, cannot test spoofing")

        spoof_result = com_detector.spoof_idebugclient_interface()

        assert spoof_result["spoofing_active"] is True
        assert spoof_result["original_interface_hidden"] is True

        detection_after_spoof = com_detector.detect_idebugclient_interface()
        assert detection_after_spoof["interface_detected"] is False
        assert detection_after_spoof.get("spoofed_interface_active", False) is True

    def test_dbgeng_dll_loading_detection(self, com_detector: Any) -> None:
        """Verify detection of DbgEng.dll loading into process space.

        Must detect when DbgEng.dll is loaded, indicating debugging engine
        attachment regardless of whether interfaces are actively used.
        """
        result = com_detector.detect_dbgeng_dll_loaded()

        assert "dll_loaded" in result
        assert "dll_path" in result
        assert "load_time" in result
        assert isinstance(result["dll_loaded"], bool)

        if result["dll_loaded"]:
            assert Path(result["dll_path"]).exists()
            assert "dbgeng.dll" in result["dll_path"].lower()
            assert result["load_time"] is not None
            assert result.get("confidence", 0.0) >= 0.90

    def test_dbgeng_dll_load_time_tracking(self, com_detector: Any) -> None:
        """Verify accurate tracking of DbgEng.dll load timestamp.

        Must record actual DLL load time for forensic analysis and correlation
        with debugger attachment events.
        """
        before_modules = com_detector.get_loaded_modules()

        test_dll_path = r"C:\Windows\System32\dbgeng.dll"
        if not Path(test_dll_path).exists():
            pytest.skip("DbgEng.dll not available on this system")

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.LoadLibraryW(test_dll_path)

        try:
            result = com_detector.detect_dbgeng_dll_loaded()

            assert result["dll_loaded"] is True
            assert result["load_time"] is not None
            assert result["recently_loaded"] is True

            after_modules = com_detector.get_loaded_modules()
            new_modules = set(after_modules) - set(before_modules)
            assert any("dbgeng" in mod.lower() for mod in new_modules)

        finally:
            if handle:
                kernel32.FreeLibrary(handle)

    def test_ole_debugging_interface_detection(self, com_detector: Any) -> None:
        """Verify detection of OLE debugging interfaces.

        Must detect IDebugApplicationThread, IDebugDocumentContext, and other
        OLE debugging COM interfaces used by script debuggers.
        """
        result = com_detector.detect_ole_debug_interfaces()

        assert "interfaces_detected" in result
        assert "interface_list" in result
        assert isinstance(result["interfaces_detected"], bool)

        if result["interfaces_detected"]:
            assert len(result["interface_list"]) > 0
            ole_debug_interfaces = [
                "IDebugApplicationThread",
                "IDebugDocumentContext",
                "IDebugStackFrame",
                "IDebugApplicationNode",
            ]
            detected_interfaces = result["interface_list"]
            assert any(iface in detected_interfaces for iface in ole_debug_interfaces)

    def test_ole_interface_bypass_effectiveness(self, com_detector: Any) -> None:
        """Verify bypassing OLE debugging interface detection.

        Must implement complete bypass of OLE debugging interfaces to prevent
        detection by protected applications checking for script debuggers.
        """
        result = com_detector.bypass_ole_debug_interfaces()

        assert result["bypass_installed"] is True
        assert "bypassed_interfaces" in result
        assert len(result["bypassed_interfaces"]) >= 3

        verification = com_detector.verify_ole_bypass()
        assert verification["bypass_active"] is True
        assert verification["interfaces_hidden"] is True

    def test_icordebug_interface_spoofing(self, com_detector: Any) -> None:
        """Verify ICorDebug interface spoofing for .NET debugging.

        Must spoof ICorDebug, ICorDebugProcess, ICorDebugAppDomain interfaces
        to prevent detection of .NET debuggers like dnSpy, Visual Studio.
        """
        result = com_detector.spoof_icordebug_interfaces()

        assert result["spoofing_active"] is True
        assert "spoofed_interfaces" in result
        assert len(result["spoofed_interfaces"]) >= 2

        icordebug_interfaces = ["ICorDebug", "ICorDebugProcess", "ICorDebugAppDomain"]
        spoofed = result["spoofed_interfaces"]
        assert any(iface in spoofed for iface in icordebug_interfaces)

        verification = com_detector.detect_icordebug_interfaces()
        assert verification["real_debugger_detected"] is False
        assert verification["spoofed_interfaces_active"] is True

    def test_managed_debugging_api_detection(self, com_detector: Any) -> None:
        """Verify detection of managed debugging API usage.

        Must detect when .NET CLR debugging APIs are loaded and active,
        indicating managed code debugging session.
        """
        result = com_detector.detect_managed_debugging_api()

        assert "api_detected" in result
        assert "mscoree_loaded" in result
        assert isinstance(result["api_detected"], bool)

        if result["api_detected"]:
            assert result["mscoree_loaded"] is True
            assert result.get("icordebug_active", False) is True
            assert result.get("confidence", 0.0) >= 0.80

    def test_com_debugger_clsid_enumeration(self, com_detector: Any) -> None:
        """Verify enumeration of debugger-related COM CLSIDs.

        Must enumerate all COM objects with debugger-related CLSIDs currently
        instantiated in the process, detecting debugger presence.
        """
        result = com_detector.enumerate_debugger_clsids()

        assert "clsids_found" in result
        assert isinstance(result["clsids_found"], list)

        known_debugger_clsids = [
            "{5182E668-105E-416E-AD92-24EF800424BA}",
            "{DF8EC037-2E3C-4D8D-B8F6-5F9F1F9F8F9F}",
            "{3F281000-B79F-11D2-9006-00C04FA352BA}",
        ]

        if len(result["clsids_found"]) > 0:
            assert any(clsid in result["clsids_found"] for clsid in known_debugger_clsids)
            assert result.get("debugger_detected", False) is True

    def test_clsid_spoofing_prevents_enumeration(self, com_detector: Any) -> None:
        """Verify CLSID spoofing prevents debugger COM object detection.

        Must hide or spoof debugger CLSIDs during COM enumeration to prevent
        detection by anti-debugging checks that scan COM objects.
        """
        original = com_detector.enumerate_debugger_clsids()

        if len(original["clsids_found"]) == 0:
            pytest.skip("No debugger CLSIDs detected, cannot test spoofing")

        spoof_result = com_detector.spoof_debugger_clsids()
        assert spoof_result["spoofing_active"] is True

        after_spoof = com_detector.enumerate_debugger_clsids()
        assert len(after_spoof["clsids_found"]) == 0 or after_spoof.get("spoofed", False)
        assert after_spoof.get("real_clsids_hidden", False) is True

    def test_remote_debugging_com_detection(self, com_detector: Any) -> None:
        """Verify detection of remote debugging via COM/DCOM.

        Must detect when remote debugger is attached via DCOM interfaces,
        including remote WinDbg and Visual Studio remote debugging.
        """
        result = com_detector.detect_remote_com_debugging()

        assert "remote_debugging_detected" in result
        assert "dcom_interfaces_active" in result
        assert isinstance(result["remote_debugging_detected"], bool)

        if result["remote_debugging_detected"]:
            assert result["dcom_interfaces_active"] is True
            assert "remote_debugger_host" in result
            assert result["remote_debugger_host"] is not None
            assert result.get("confidence", 0.0) >= 0.75

    def test_remote_debugging_bypass(self, com_detector: Any) -> None:
        """Verify bypass of remote COM/DCOM debugging detection.

        Must prevent detection of remote debugger attachment by spoofing
        DCOM interface responses and hiding remote debug connections.
        """
        result = com_detector.bypass_remote_com_debugging()

        assert result["bypass_active"] is True
        assert "spoofed_dcom_interfaces" in result

        verification = com_detector.detect_remote_com_debugging()
        assert verification["remote_debugging_detected"] is False
        assert verification.get("bypass_active", False) is True

    def test_script_engine_debugging_detection(self, com_detector: Any) -> None:
        """Verify detection of script engine debugging (JScript/VBScript).

        Must detect when IActiveScript debugging interfaces are active,
        indicating script debugger attachment to JScript or VBScript engines.
        """
        result = com_detector.detect_script_engine_debugging()

        assert "script_debugging_detected" in result
        assert "active_script_interfaces" in result
        assert isinstance(result["script_debugging_detected"], bool)

        if result["script_debugging_detected"]:
            assert len(result["active_script_interfaces"]) > 0
            script_interfaces = ["IActiveScriptDebug", "IDebugDocumentHost", "IProcessDebugManager"]
            detected = result["active_script_interfaces"]
            assert any(iface in detected for iface in script_interfaces)

    def test_script_debugger_bypass(self, com_detector: Any) -> None:
        """Verify bypass of script engine debugging detection.

        Must spoof IActiveScript debugging interfaces to hide debugger
        attachment from anti-debugging checks in script-heavy applications.
        """
        result = com_detector.bypass_script_engine_debugging()

        assert result["bypass_installed"] is True
        assert "spoofed_interfaces" in result

        verification = com_detector.detect_script_engine_debugging()
        assert verification["script_debugging_detected"] is False
        assert verification.get("interfaces_spoofed", False) is True

    def test_com_interface_vtable_hooking(self, com_detector: Any) -> None:
        """Verify vtable hooking for COM debugging interface spoofing.

        Must hook COM interface vtables to intercept and modify method calls,
        enabling transparent spoofing of debugging interface behavior.
        """
        interface_name = "IDebugClient"
        result = com_detector.hook_com_vtable(interface_name)

        assert result["hook_installed"] is True
        assert result["interface_name"] == interface_name
        assert "vtable_address" in result
        assert result["vtable_address"] != 0
        assert "hooked_methods" in result
        assert len(result["hooked_methods"]) > 0

        verification = com_detector.verify_vtable_hook(interface_name)
        assert verification["hook_active"] is True
        assert verification["intercepts_working"] is True

    def test_com_vtable_hook_stability(self, com_detector: Any) -> None:
        """Verify COM vtable hooks remain stable across interface usage.

        Must ensure vtable hooks persist and function correctly even when
        COM interfaces are extensively used by legitimate code paths.
        """
        interface_name = "IDebugClient"
        hook_result = com_detector.hook_com_vtable(interface_name)

        if not hook_result["hook_installed"]:
            pytest.skip("Failed to install vtable hook")

        for iteration in range(100):
            verification = com_detector.verify_vtable_hook(interface_name)
            assert verification["hook_active"] is True
            assert verification["hook_corrupted"] is False
            assert verification["intercept_count"] >= iteration

    def test_multiple_com_interface_spoofing(self, com_detector: Any) -> None:
        """Verify simultaneous spoofing of multiple COM debugging interfaces.

        Must handle spoofing of IDebugClient, ICorDebug, and OLE debugging
        interfaces concurrently without conflicts or stability issues.
        """
        interfaces = ["IDebugClient", "ICorDebug", "IDebugApplicationThread"]
        results = {}

        for interface in interfaces:
            result = com_detector.spoof_com_interface(interface)
            results[interface] = result
            assert result["spoofing_active"] is True

        for interface in interfaces:
            verification = com_detector.verify_interface_spoof(interface)
            assert verification["spoofed"] is True
            assert verification["stable"] is True

        stability_check = com_detector.check_multi_interface_stability()
        assert stability_check["all_spoofs_stable"] is True
        assert stability_check["no_conflicts"] is True

    def test_dbghelp_dll_detection_alongside_dbgeng(self, com_detector: Any) -> None:
        """Verify detection of DbgHelp.dll loaded alongside DbgEng.dll.

        Must detect when both DbgHelp.dll and DbgEng.dll are loaded,
        indicating full Windows debugging infrastructure is active.
        """
        result = com_detector.detect_debug_dll_combination()

        assert "dbgeng_loaded" in result
        assert "dbghelp_loaded" in result
        assert "full_debug_environment" in result

        if result["full_debug_environment"]:
            assert result["dbgeng_loaded"] is True
            assert result["dbghelp_loaded"] is True
            assert result.get("confidence", 0.0) >= 0.95

    def test_com_debugging_with_antimalware_scan_interface(self, com_detector: Any) -> None:
        """Verify COM debugging detection doesn't conflict with AMSI.

        Must differentiate between legitimate AMSI COM interfaces and
        debugging COM interfaces to avoid false positives.
        """
        result = com_detector.detect_com_debugging_excluding_amsi()

        assert "debugging_detected" in result
        assert "amsi_interfaces_excluded" in result
        assert isinstance(result["amsi_interfaces_excluded"], bool)

        if result["debugging_detected"]:
            assert "IDebug" in str(result.get("detected_interfaces", []))
            assert "AMSI" not in str(result.get("detected_interfaces", []))

    def test_corrupted_com_interface_handling(self, com_detector: Any) -> None:
        """Verify robust handling of corrupted COM interfaces.

        Must handle corrupted or malformed COM interface structures without
        crashing, returning appropriate error status instead.
        """
        corrupted_clsid = "{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}"
        result = com_detector.detect_interface_by_clsid(corrupted_clsid)

        assert "error" in result or result.get("interface_detected") is False
        assert "crashed" not in result or result["crashed"] is False

    def test_com_interface_detection_performance(self, com_detector: Any, benchmark: Any) -> None:
        """Verify COM interface detection completes within performance budget.

        Must complete full COM debugging interface scan in under 500ms to
        avoid noticeable performance impact during anti-debugging checks.
        """

        def detection_operation() -> Any:
            return com_detector.detect_all_com_debugging()

        result = benchmark(detection_operation)

        assert result["scan_complete"] is True
        assert result["scan_duration_ms"] < 500

    def test_com_detection_with_elevated_privileges(self, com_detector: Any) -> None:
        """Verify COM detection works correctly with elevated privileges.

        Must detect COM debugging interfaces even when running with
        administrator or system privileges that might hide some interfaces.
        """
        import ctypes

        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        result = com_detector.detect_com_debugging_elevated()

        assert "elevated_detection_active" in result
        assert result.get("privilege_level_detected", False) is is_admin

        if is_admin:
            assert result["can_detect_system_debuggers"] is True

    def test_com_debugging_detection_under_windbg(self) -> None:
        """Verify COM detection correctly identifies WinDbg attachment.

        Must detect when running under WinDbg by identifying IDebugClient
        and DbgEng.dll loading patterns specific to WinDbg.
        """
        windbg_path = r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe"
        if not Path(windbg_path).exists():
            pytest.skip("WinDbg not installed on this system")

        test_script = Path(__file__).parent / "test_windbg_detection.py"
        test_script.write_text(
            """
import sys
sys.path.insert(0, r'D:\\Intellicrack')
from intellicrack.core.anti_analysis.com_debug_detector import COMDebugDetector
detector = COMDebugDetector()
result = detector.detect_all_com_debugging()
print(f"DEBUGGER_DETECTED={result['debugger_detected']}")
print(f"WINDBG_DETECTED={result.get('windbg_detected', False)}")
"""
        )

        try:
            proc = subprocess.Popen(
                [windbg_path, "-g", "-G", sys.executable, str(test_script)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, _ = proc.communicate(timeout=30)

            assert "DEBUGGER_DETECTED=True" in stdout
            assert "WINDBG_DETECTED=True" in stdout

        finally:
            if test_script.exists():
                test_script.unlink()

    def test_com_debugging_detection_under_visual_studio(self) -> None:
        """Verify COM detection identifies Visual Studio debugging.

        Must detect ICorDebug interfaces and msvsmon.exe when debugging
        under Visual Studio, including remote debugging scenarios.
        """
        vs_debugger = r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe"
        if not Path(vs_debugger).exists():
            pytest.skip("Visual Studio 2022 not installed")

        test_script = Path(__file__).parent / "test_vs_detection.py"
        test_script.write_text(
            """
import sys
sys.path.insert(0, r'D:\\Intellicrack')
from intellicrack.core.anti_analysis.com_debug_detector import COMDebugDetector
detector = COMDebugDetector()
result = detector.detect_all_com_debugging()
print(f"MANAGED_DEBUGGER_DETECTED={result.get('managed_debugger_detected', False)}")
print(f"ICORDEBUG_ACTIVE={result.get('icordebug_active', False)}")
"""
        )

        try:
            proc = subprocess.Popen(
                [
                    vs_debugger,
                    "/debugexe",
                    sys.executable,
                    str(test_script),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, _ = proc.communicate(timeout=30)

            assert "MANAGED_DEBUGGER_DETECTED=True" in stdout
            assert "ICORDEBUG_ACTIVE=True" in stdout

        finally:
            if test_script.exists():
                test_script.unlink()

    def test_com_detection_bypass_integration(self, com_detector: Any) -> None:
        """Verify complete integration of all COM debugging bypasses.

        Must successfully bypass all COM-based debugging detection methods
        when all bypass mechanisms are activated together.
        """
        result = com_detector.activate_all_bypasses()

        assert result["all_bypasses_active"] is True
        assert len(result["active_bypasses"]) >= 5

        expected_bypasses = [
            "idebugclient_spoof",
            "ole_debug_bypass",
            "icordebug_spoof",
            "script_engine_bypass",
            "remote_debug_bypass",
        ]

        for bypass in expected_bypasses:
            assert bypass in result["active_bypasses"]

        detection_result = com_detector.detect_all_com_debugging()
        assert detection_result["debugger_detected"] is False
        assert detection_result.get("all_interfaces_hidden", False) is True

    def test_com_detection_persistence_across_process_lifetime(self, com_detector: Any) -> None:
        """Verify COM detection bypass persists across COM reinitializations.

        Must maintain bypass effectiveness even when COM is uninitialized
        and reinitialized during process lifetime.
        """
        import pythoncom

        com_detector.activate_all_bypasses()

        for cycle in range(5):
            pythoncom.CoUninitialize()
            pythoncom.CoInitialize()

            result = com_detector.detect_all_com_debugging()
            assert result["debugger_detected"] is False
            assert result.get("bypasses_stable_after_reinit", False) is True

    def test_com_detection_error_recovery(self, com_detector: Any) -> None:
        """Verify graceful recovery from COM interface errors.

        Must handle COM errors (E_NOINTERFACE, E_FAIL, etc.) gracefully
        without crashing or leaving system in unstable state.
        """
        result = com_detector.test_error_recovery()

        assert result["error_recovery_successful"] is True
        assert "handled_errors" in result
        assert len(result["handled_errors"]) > 0

        com_errors = ["E_NOINTERFACE", "E_FAIL", "E_INVALIDARG", "E_POINTER"]
        for error in com_errors:
            assert any(error in str(err) for err in result["handled_errors"])

    def test_com_detection_thread_safety(self, com_detector: Any) -> None:
        """Verify thread-safe COM debugging detection.

        Must safely handle COM interface detection from multiple threads
        without race conditions or COM apartment threading violations.
        """
        import concurrent.futures
        import threading

        results = []
        errors = []

        def detect_from_thread() -> Any:
            import pythoncom

            try:
                pythoncom.CoInitialize()
                result = com_detector.detect_all_com_debugging()
                return result
            except Exception as e:
                errors.append(str(e))
                return {"error": str(e)}
            finally:
                pythoncom.CoUninitialize()

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(detect_from_thread) for _ in range(20)]
            results = [f.result() for f in futures]

        assert len(errors) == 0
        assert all("error" not in r or r.get("error") is None for r in results)
        assert all(isinstance(r.get("debugger_detected"), bool) for r in results)

    def test_com_detection_memory_safety(self, com_detector: Any) -> None:
        """Verify no memory leaks in COM detection operations.

        Must properly release all COM interfaces and avoid memory leaks
        during repeated detection and spoofing operations.
        """
        import psutil

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        for iteration in range(1000):
            com_detector.detect_all_com_debugging()
            com_detector.activate_all_bypasses()

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 10 * 1024 * 1024

    def test_com_detection_clsid_validation(self, com_detector: Any) -> None:
        """Verify proper validation of COM CLSIDs.

        Must validate CLSID format and reject malformed CLSIDs without
        attempting invalid COM operations that could crash the process.
        """
        invalid_clsids = [
            "not-a-clsid",
            "{INVALID}",
            "{12345678-1234-1234-1234}",
            "",
            None,
            "{ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ}",
        ]

        for invalid_clsid in invalid_clsids:
            result = com_detector.validate_clsid(invalid_clsid)
            assert result["valid"] is False
            assert "error" in result or "invalid_format" in result

    def test_com_debugging_detection_with_debugger_attached(self) -> None:
        """Integration test verifying detection when actual debugger is attached.

        Must correctly detect COM debugging interfaces when real debugger
        (WinDbg, Visual Studio, or x64dbg) is actually attached to process.
        """
        if not os.environ.get("INTELLICRACK_INTEGRATION_TESTS"):
            pytest.skip("Integration test requires INTELLICRACK_INTEGRATION_TESTS=1")

        from intellicrack.core.anti_analysis.com_debug_detector import COMDebugDetector

        detector = COMDebugDetector()
        result = detector.detect_all_com_debugging()

        is_debugger_attached = ctypes.windll.kernel32.IsDebuggerPresent()

        if is_debugger_attached:
            assert result["debugger_detected"] is True
            assert (
                result.get("idebugclient_detected")
                or result.get("icordebug_detected")
                or result.get("dbgeng_loaded")
            )
        else:
            assert result["debugger_detected"] is False
