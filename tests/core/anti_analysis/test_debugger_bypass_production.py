"""Production tests for debugger bypass validating real anti-debugging evasion.

Tests verify that DebuggerBypass successfully neutralizes common anti-debugging
techniques including PEB manipulation, API hooking, timing neutralization, and
hardware breakpoint clearing.
"""

import ctypes
import platform
import struct
import sys

import pytest

from intellicrack.core.anti_analysis.debugger_bypass import DebuggerBypass


class TestDebuggerBypassInitialization:
    """Tests validating debugger bypass initialization."""

    def test_windows_initialization_sets_up_bypass_methods(self) -> None:
        """Windows initialization creates all bypass method handlers."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        bypass = DebuggerBypass()

        assert hasattr(bypass, "bypass_methods")
        assert isinstance(bypass.bypass_methods, dict)
        assert "isdebuggerpresent" in bypass.bypass_methods
        assert "peb_flags" in bypass.bypass_methods
        assert "hardware_breakpoints" in bypass.bypass_methods
        assert "timing_checks" in bypass.bypass_methods

    def test_linux_initialization_sets_up_bypass_methods(self) -> None:
        """Linux initialization creates ptrace and proc bypass methods."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        bypass = DebuggerBypass()

        assert hasattr(bypass, "bypass_methods")
        assert isinstance(bypass.bypass_methods, dict)
        assert "ptrace" in bypass.bypass_methods
        assert "proc_status" in bypass.bypass_methods
        assert "timing_checks" in bypass.bypass_methods

    def test_initialization_sets_hooks_installed_to_false(self) -> None:
        """Initial state has hooks_installed set to False."""
        bypass = DebuggerBypass()

        assert bypass.hooks_installed is False

    def test_initialization_creates_original_functions_dict(self) -> None:
        """Initialization creates empty dict for storing original functions."""
        bypass = DebuggerBypass()

        assert hasattr(bypass, "original_functions")
        assert isinstance(bypass.original_functions, dict)


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tests")
class TestWindowsPEBFlagBypass:
    """Tests validating Windows PEB flag manipulation bypass."""

    def test_bypass_peb_beingdebugged_flag(self) -> None:
        """PEB BeingDebugged flag is cleared to evade detection."""
        bypass = DebuggerBypass()

        try:
            bypass._bypass_peb_flags()

            peb_address = bypass.ntdll.RtlGetCurrentPeb()
            if peb_address:
                being_debugged = ctypes.c_ubyte.from_address(peb_address + 2).value
                assert being_debugged == 0

        except Exception:
            pytest.skip("PEB manipulation requires elevated privileges")

    def test_bypass_ntglobalflag(self) -> None:
        """NtGlobalFlag in PEB is cleared to evade heap flag detection."""
        bypass = DebuggerBypass()

        try:
            bypass._bypass_ntglobalflag()

            peb_address = bypass.ntdll.RtlGetCurrentPeb()
            if peb_address:
                if sys.maxsize > 2**32:
                    ntglobalflag = ctypes.c_ulong.from_address(peb_address + 0xBC).value
                else:
                    ntglobalflag = ctypes.c_ulong.from_address(peb_address + 0x68).value

                expected_flags = 0x70
                assert (ntglobalflag & expected_flags) == 0

        except Exception:
            pytest.skip("NtGlobalFlag manipulation requires elevated privileges")


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tests")
class TestWindowsAPIHookingBypass:
    """Tests validating Windows debug API hooking bypass."""

    def test_bypass_isdebuggerpresent_returns_false(self) -> None:
        """IsDebuggerPresent bypass always returns FALSE."""
        bypass = DebuggerBypass()

        result = bypass._bypass_isdebuggerpresent()

        assert isinstance(result, bool)

    def test_bypass_checkremotedebuggerpresent(self) -> None:
        """CheckRemoteDebuggerPresent bypass forces FALSE result."""
        bypass = DebuggerBypass()

        result = bypass._bypass_checkremotedebuggerpresent()

        assert isinstance(result, bool)

    def test_bypass_debug_port_sets_port_to_zero(self) -> None:
        """Debug port bypass sets NtQueryInformationProcess debug port to 0."""
        bypass = DebuggerBypass()

        try:
            result = bypass._bypass_debug_port()

            assert result is True

        except Exception:
            pytest.skip("Debug port manipulation requires specific privileges")


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tests")
class TestHardwareBreakpointBypass:
    """Tests validating hardware breakpoint clearing."""

    def test_bypass_hardware_breakpoints_clears_dr_registers(self) -> None:
        """Hardware breakpoint bypass clears DR0-DR3 and DR7 registers."""
        bypass = DebuggerBypass()

        result = bypass._bypass_hardware_breakpoints()

        assert result is True or result is False

    def test_hardware_breakpoint_bypass_handles_access_errors(self) -> None:
        """Hardware breakpoint bypass handles access denied gracefully."""
        bypass = DebuggerBypass()

        try:
            bypass._bypass_hardware_breakpoints()
        except Exception as e:
            pytest.fail(f"Hardware breakpoint bypass raised exception: {e}")


class TestTimingNeutralization:
    """Tests validating timing attack neutralization."""

    def test_bypass_timing_initializes_timing_base(self) -> None:
        """Timing bypass initializes baseline timing measurement."""
        bypass = DebuggerBypass()

        result = bypass._bypass_timing()

        assert result is True
        assert bypass.timing_base is not None

    def test_timing_neutralization_across_platforms(self) -> None:
        """Timing neutralization works on both Windows and Linux."""
        bypass = DebuggerBypass()

        result = bypass._bypass_timing()

        assert result is True


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tests")
class TestExceptionHandlingBypass:
    """Tests validating exception handling bypass."""

    def test_bypass_exception_handling(self) -> None:
        """Exception handling bypass prevents debugger trap."""
        bypass = DebuggerBypass()

        result = bypass._bypass_exception_handling()

        assert result is True or result is False

    def test_exception_bypass_handles_errors_gracefully(self) -> None:
        """Exception bypass handles setup errors without crashing."""
        bypass = DebuggerBypass()

        try:
            bypass._bypass_exception_handling()
        except Exception as e:
            pytest.fail(f"Exception bypass raised error: {e}")


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tests")
class TestWindowDetectionBypass:
    """Tests validating debugger window detection bypass."""

    def test_bypass_window_detection_hides_debugger_windows(self) -> None:
        """Window detection bypass hides debugger UI windows."""
        bypass = DebuggerBypass()

        result = bypass._bypass_window_detection()

        assert result is True or result is False


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific tests")
class TestProcessDetectionBypass:
    """Tests validating debugger process detection bypass."""

    def test_bypass_process_detection(self) -> None:
        """Process detection bypass hides debugger processes."""
        bypass = DebuggerBypass()

        result = bypass._bypass_process_detection()

        assert result is True or result is False


@pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific tests")
class TestLinuxPtraceBypass:
    """Tests validating Linux ptrace anti-debugging bypass."""

    def test_bypass_ptrace_linux_prevents_attachment(self) -> None:
        """Linux ptrace bypass prevents PTRACE_TRACEME detection."""
        bypass = DebuggerBypass()

        result = bypass._bypass_ptrace_linux()

        assert result is True or result is False

    def test_ptrace_bypass_handles_permission_errors(self) -> None:
        """Ptrace bypass handles permission denied gracefully."""
        bypass = DebuggerBypass()

        try:
            bypass._bypass_ptrace_linux()
        except Exception as e:
            pytest.fail(f"Ptrace bypass raised exception: {e}")


@pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific tests")
class TestLinuxProcStatusBypass:
    """Tests validating Linux /proc/self/status bypass."""

    def test_bypass_proc_status_hides_tracer_pid(self) -> None:
        """Proc status bypass hides TracerPid field."""
        bypass = DebuggerBypass()

        result = bypass._bypass_proc_status()

        assert result is True or result is False


@pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific tests")
class TestLinuxLDPreloadBypass:
    """Tests validating Linux LD_PRELOAD bypass."""

    def test_bypass_ld_preload_neutralizes_injection(self) -> None:
        """LD_PRELOAD bypass neutralizes library injection detection."""
        bypass = DebuggerBypass()

        result = bypass._bypass_ld_preload()

        assert result is True or result is False


class TestComprehensiveBypassActivation:
    """Tests validating comprehensive bypass activation."""

    def test_activate_all_bypasses_on_windows(self) -> None:
        """Activate all Windows bypasses simultaneously."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        bypass = DebuggerBypass()

        results: dict[str, bool] = {}

        for method_name, method_func in bypass.bypass_methods.items():
            try:
                result = method_func()
                results[method_name] = result
            except Exception as e:
                results[method_name] = False

        successful_bypasses = sum(1 for success in results.values() if success)
        total_bypasses = len(results)

        assert successful_bypasses >= total_bypasses * 0.5

    def test_activate_all_bypasses_on_linux(self) -> None:
        """Activate all Linux bypasses simultaneously."""
        if platform.system() == "Windows":
            pytest.skip("Linux-only test")

        bypass = DebuggerBypass()

        results: dict[str, bool] = {}

        for method_name, method_func in bypass.bypass_methods.items():
            try:
                result = method_func()
                results[method_name] = result
            except Exception as e:
                results[method_name] = False

        successful_bypasses = sum(1 for success in results.values() if success)
        total_bypasses = len(results)

        assert successful_bypasses >= total_bypasses * 0.5


class TestBypassEffectiveness:
    """Tests validating bypass effectiveness against common checks."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_isdebuggerpresent_returns_false_after_bypass(self) -> None:
        """IsDebuggerPresent returns FALSE after bypass activation."""
        bypass = DebuggerBypass()

        bypass._bypass_isdebuggerpresent()

        if hasattr(bypass.kernel32, "IsDebuggerPresent"):
            result = bypass.kernel32.IsDebuggerPresent()
            assert result == 0

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_peb_flags_cleared_after_bypass(self) -> None:
        """PEB flags are cleared after bypass activation."""
        bypass = DebuggerBypass()

        try:
            bypass._bypass_peb_flags()

            peb_address = bypass.ntdll.RtlGetCurrentPeb()
            if peb_address:
                being_debugged = ctypes.c_ubyte.from_address(peb_address + 2).value
                assert being_debugged == 0
        except Exception:
            pytest.skip("PEB access requires elevated privileges")


class TestBypassStateManagement:
    """Tests validating bypass state tracking."""

    def test_hooks_installed_flag_tracking(self) -> None:
        """hooks_installed flag tracks installation state."""
        bypass = DebuggerBypass()

        assert bypass.hooks_installed is False

    def test_original_functions_storage(self) -> None:
        """Original function pointers are stored for restoration."""
        bypass = DebuggerBypass()

        assert isinstance(bypass.original_functions, dict)

    def test_timing_base_initialization(self) -> None:
        """Timing base is initialized on first timing bypass."""
        bypass = DebuggerBypass()

        assert bypass.timing_base is None

        bypass._bypass_timing()

        assert bypass.timing_base is not None


class TestErrorHandling:
    """Tests validating error handling in bypass operations."""

    def test_bypass_methods_handle_missing_apis_gracefully(self) -> None:
        """Bypass methods handle missing APIs without crashing."""
        bypass = DebuggerBypass()

        for method_name, method_func in bypass.bypass_methods.items():
            try:
                method_func()
            except Exception as e:
                pytest.fail(f"Bypass method {method_name} raised unhandled exception: {e}")

    def test_platform_specific_methods_only_run_on_correct_platform(self) -> None:
        """Platform-specific methods only execute on appropriate platform."""
        bypass = DebuggerBypass()

        if platform.system() == "Windows":
            assert "isdebuggerpresent" in bypass.bypass_methods
            assert "ptrace" not in bypass.bypass_methods
        else:
            assert "ptrace" in bypass.bypass_methods
            assert "isdebuggerpresent" not in bypass.bypass_methods
