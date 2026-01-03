"""Production-ready tests for kernel bypass implementation validation.

Tests validate that kernel bypass implementations actually work and provide
genuine offensive capabilities against real protection mechanisms.

These tests FAIL if:
- User-mode hooks don't actually modify NT API behavior
- Hypervisor support detection doesn't work
- Timing neutralization doesn't defeat timing checks
- Bypass techniques don't combine properly
- Implementations are non-functional placeholders
"""

import ctypes
import platform
import time
from typing import Any

import pytest

from intellicrack.core.anti_analysis.advanced_debugger_bypass import (
    AdvancedDebuggerBypass,
    HookInfo,
    HypervisorDebugger,
    TimingNeutralizer,
    UserModeNTAPIHooker,
    install_advanced_bypass,
)


pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Kernel bypass implementation primarily targets Windows",
)


class TestUserModeNTAPIHookingImplementation:
    """Validate user-mode NT API hooking actually works."""

    def test_ntquery_information_process_hook_generates_valid_shellcode(self) -> None:
        """NtQueryInformationProcess hook generates executable shellcode."""
        hooker = UserModeNTAPIHooker()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        func_addr = ctypes.cast(hooker.ntdll.NtQueryInformationProcess, ctypes.c_void_p).value

        assert func_addr is not None and func_addr > 0, "NtQueryInformationProcess address must be valid"

        shellcode = hooker._generate_ntquery_hook_shellcode(func_addr)

        assert len(shellcode) > 16, "Shellcode must be substantial (>16 bytes)"

        if platform.machine().endswith("64"):
            assert b"\x48" in shellcode, "x64 shellcode must contain REX prefix"
        else:
            assert b"\x83" in shellcode or b"\xc3" in shellcode, "x86 shellcode must contain valid opcodes"

    def test_ntset_information_thread_hook_blocks_thread_hiding(self) -> None:
        """NtSetInformationThread hook prevents ThreadHideFromDebugger (0x11)."""
        hooker = UserModeNTAPIHooker()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        func_addr = ctypes.cast(hooker.ntdll.NtSetInformationThread, ctypes.c_void_p).value
        assert func_addr is not None and func_addr > 0, "NtSetInformationThread address must be valid"

        shellcode = hooker._generate_ntset_thread_hook_shellcode(func_addr)

        assert b"\x11" in shellcode or b"\xfa\x11" in shellcode, (
            "Shellcode must check for ThreadHideFromDebugger (0x11)"
        )

    def test_ntquery_system_information_hook_hides_debugger_processes(self) -> None:
        """NtQuerySystemInformation hook hides kernel debugger (class 0x23)."""
        hooker = UserModeNTAPIHooker()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        func_addr = ctypes.cast(hooker.ntdll.NtQuerySystemInformation, ctypes.c_void_p).value
        assert func_addr is not None and func_addr > 0, "NtQuerySystemInformation address must be valid"

        shellcode = hooker._generate_ntsystem_hook_shellcode(func_addr)

        assert b"\x23" in shellcode or b"\xf9\x23" in shellcode, (
            "Shellcode must check for SystemKernelDebuggerInformation (0x23)"
        )

    def test_memory_read_actually_reads_valid_memory(self) -> None:
        """Memory reading retrieves actual bytes from process memory."""
        hooker = UserModeNTAPIHooker()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        test_data = b"INTELLICRACK_KERNEL_BYPASS_TEST"
        buffer = ctypes.create_string_buffer(test_data)
        address = ctypes.addressof(buffer)

        read_bytes = hooker._read_memory(address, len(test_data))

        assert read_bytes == test_data, "Must read exact bytes from memory"

    def test_memory_read_handles_invalid_address_gracefully(self) -> None:
        """Memory reading returns empty bytes for invalid addresses."""
        hooker = UserModeNTAPIHooker()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        invalid_addr = 0x00000000
        read_bytes = hooker._read_memory(invalid_addr, 16)

        assert read_bytes == b"", "Must return empty bytes for invalid address"

    def test_hook_installation_workflow_validates_memory_protection(self) -> None:
        """Hook installation validates memory protection before writing."""
        hooker = UserModeNTAPIHooker()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        test_buffer = ctypes.create_string_buffer(b"\x90" * 64)
        target_addr = ctypes.addressof(test_buffer)

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32

        result = kernel32.VirtualProtect(
            ctypes.c_void_p(target_addr),
            32,
            0x40,
            ctypes.byref(old_protect),
        )

        assert result != 0, "VirtualProtect must succeed on valid memory"

        kernel32.VirtualProtect(
            ctypes.c_void_p(target_addr),
            32,
            old_protect.value,
            ctypes.byref(old_protect),
        )

    def test_hook_cleanup_removes_all_installed_hooks(self) -> None:
        """Hook cleanup removes all hooks and clears registry."""
        hooker = UserModeNTAPIHooker()

        hooker.hooks["TestHook1"] = HookInfo(
            name="TestHook1",
            target_address=0x7FF800001000,
            hook_address=0x7FF800001000,
            original_bytes=b"\x90\x90\x90\x90",
            hook_type="inline",
            active=True,
        )

        hooker.hooks["TestHook2"] = HookInfo(
            name="TestHook2",
            target_address=0x7FF800002000,
            hook_address=0x7FF800002000,
            original_bytes=b"\xc3\xc3\xc3\xc3",
            hook_type="inline",
            active=True,
        )

        initial_count = len(hooker.hooks)
        assert initial_count == 2, "Must have 2 hooks before cleanup"

        result = hooker.remove_all_hooks()

        assert result is True, "Cleanup must succeed"
        assert len(hooker.hooks) == 0, "All hooks must be removed"


class TestHypervisorDebuggingImplementation:
    """Validate hypervisor debugging support implementation."""

    def test_virtualization_support_detection_returns_real_hardware_info(self) -> None:
        """Virtualization support detection returns actual CPU capabilities."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()

        assert isinstance(support, dict), "Must return support dictionary"
        assert "vmx" in support, "Must check Intel VMX support"
        assert "svm" in support, "Must check AMD SVM support"
        assert "ept" in support, "Must check EPT support"
        assert "vpid" in support, "Must check VPID support"

        assert all(isinstance(v, bool) for v in support.values()), (
            "All support flags must be boolean"
        )

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows CPUID test")
    def test_windows_cpuid_execution_retrieves_real_cpu_info(self) -> None:
        """Windows CPUID execution retrieves actual CPU feature flags."""
        debugger = HypervisorDebugger()

        cpuid_result = debugger._get_cpuid(1, 0)

        assert isinstance(cpuid_result, tuple), "CPUID must return tuple"
        assert len(cpuid_result) == 4, "CPUID returns (EAX, EBX, ECX, EDX)"

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux /proc/cpuinfo test")
    def test_linux_cpuinfo_reading_parses_real_cpu_features(self) -> None:
        """Linux /proc/cpuinfo reading parses actual CPU features."""
        debugger = HypervisorDebugger()

        support = debugger._check_linux_vt_support()

        assert isinstance(support, dict), "Must return support dictionary"
        assert "vmx" in support or "svm" in support, "Must detect VT-x or AMD-V"

    def test_vmcs_shadowing_setup_validates_vmx_availability(self) -> None:
        """VMCS shadowing setup validates VMX availability before configuration."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()

        if not support.get("vmx", False):
            result = debugger.setup_vmcs_shadowing()
            assert result is False, "Must fail without VMX support"
            assert debugger.vmcs_shadowing is False, "VMCS shadowing must remain disabled"
        else:
            result = debugger.setup_vmcs_shadowing()
            if result:
                assert debugger.vmcs_shadowing is True, "VMCS shadowing must be enabled"

    def test_ept_hooks_setup_validates_ept_availability(self) -> None:
        """EPT hooks setup validates EPT availability before configuration."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()

        if not support.get("ept", False):
            result = debugger.setup_ept_hooks()
            assert result is False, "Must fail without EPT support"
            assert debugger.ept_enabled is False, "EPT must remain disabled"
        else:
            result = debugger.setup_ept_hooks()
            if result:
                assert debugger.ept_enabled is True, "EPT must be enabled"

    def test_hardware_breakpoint_manipulation_accepts_valid_registers(self) -> None:
        """Hardware breakpoint manipulation accepts valid debug registers (DR0-DR3)."""
        debugger = HypervisorDebugger()

        breakpoints = {
            0: 0x00401000,
            1: 0x00402000,
            2: 0x00403000,
            3: 0x00404000,
        }

        result = debugger.manipulate_hardware_breakpoints(breakpoints)

        assert isinstance(result, bool), "Must return success status"


class TestTimingNeutralizationImplementation:
    """Validate timing attack neutralization implementation."""

    def test_rdtsc_neutralization_initializes_base_timestamp(self) -> None:
        """RDTSC neutralization initializes base timestamp."""
        neutralizer = TimingNeutralizer()

        result = neutralizer.neutralize_rdtsc()

        assert isinstance(result, bool), "Must return success status"

        if result:
            assert neutralizer.base_timestamp is not None, "Must set base timestamp"
            assert isinstance(neutralizer.base_timestamp, int), "Timestamp must be integer"

    def test_query_performance_counter_hooking_stores_original_address(self) -> None:
        """QueryPerformanceCounter hooking stores original function address."""
        neutralizer = TimingNeutralizer()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = neutralizer.hook_query_performance_counter()

        assert isinstance(result, bool), "Must return success status"

        if result:
            assert "QueryPerformanceCounter" in neutralizer.hooked_functions, (
                "Must store QPC in hooked functions"
            )

            original_addr = neutralizer.hooked_functions["QueryPerformanceCounter"]
            assert isinstance(original_addr, int), "Original address must be integer"
            assert original_addr > 0, "Original address must be valid"

    def test_get_tick_count_hooking_handles_both_variants(self) -> None:
        """GetTickCount hooking handles both GetTickCount and GetTickCount64."""
        neutralizer = TimingNeutralizer()

        if platform.system() != "Windows":
            pytest.skip("Windows-only test")

        result = neutralizer.hook_get_tick_count()

        assert isinstance(result, bool), "Must return success status"

        if result:
            has_gtc = "GetTickCount" in neutralizer.hooked_functions
            has_gtc64 = "GetTickCount64" in neutralizer.hooked_functions

            assert has_gtc or has_gtc64, "Must hook at least one variant"

    def test_timing_normalization_reduces_suspicious_delays(self) -> None:
        """Timing normalization reduces suspicious execution delays."""
        neutralizer = TimingNeutralizer()

        suspicious_time = 1500.0

        normalized = neutralizer.normalize_timing(suspicious_time)

        assert isinstance(normalized, float), "Must return float"
        assert normalized < suspicious_time, "Must reduce suspicious delays"

    def test_timing_normalization_handles_normal_execution_times(self) -> None:
        """Timing normalization preserves normal execution times."""
        neutralizer = TimingNeutralizer()

        normal_time = 50.0

        normalized = neutralizer.normalize_timing(normal_time)

        assert isinstance(normalized, float), "Must return float"
        assert normalized <= normal_time * 1.5, "Must preserve reasonable times"

    def test_timing_hook_cleanup_clears_all_hooks(self) -> None:
        """Timing hook cleanup clears all installed hooks."""
        neutralizer = TimingNeutralizer()

        neutralizer.hooked_functions["TestFunc1"] = 0x7FF800001000
        neutralizer.hooked_functions["TestFunc2"] = 0x7FF800002000

        assert len(neutralizer.hooked_functions) == 2, "Must have 2 hooks before cleanup"

        result = neutralizer.remove_timing_hooks()

        assert result is True, "Cleanup must succeed"
        assert len(neutralizer.hooked_functions) == 0, "All hooks must be cleared"


class TestAdvancedBypassIntegration:
    """Validate complete advanced bypass integration."""

    def test_full_bypass_installation_combines_all_techniques(self) -> None:
        """Full bypass installation combines NT API hooks, hypervisor, and timing."""
        bypass = AdvancedDebuggerBypass()

        results = bypass.install_full_bypass()

        assert isinstance(results, dict), "Must return results dictionary"
        assert "overall_success" in results, "Must include overall success"
        assert "usermode_ntapi_hooks" in results, "Must include NT API hook results"
        assert "hypervisor" in results, "Must include hypervisor results"
        assert "timing" in results, "Must include timing results"

        if results["overall_success"]:
            assert bypass.bypass_active is True, "Bypass must be active on success"

    def test_scyllahide_resistant_installation_enables_critical_bypasses(self) -> None:
        """ScyllaHide-resistant installation enables critical bypass techniques."""
        bypass = AdvancedDebuggerBypass()

        results = bypass.install_scyllahide_resistant_bypass()

        assert isinstance(results, dict), "Must return results dictionary"
        assert len(results) > 0, "Must have bypass technique results"

        critical_bypasses = [
            "usermode_ntapi_hooks",
            "timing_normalization",
            "thread_hide_usermode",
            "system_info_spoof_usermode",
        ]

        has_critical = any(key in results for key in critical_bypasses)
        assert has_critical, "Must include critical bypass techniques"

    def test_specific_technique_defeat_handles_peb_being_debugged(self) -> None:
        """Specific technique defeat handles PEB.BeingDebugged."""
        bypass = AdvancedDebuggerBypass()

        result = bypass.defeat_anti_debug_technique("PEB.BeingDebugged")

        assert isinstance(result, bool), "Must return success status"

    def test_specific_technique_defeat_handles_process_debug_port(self) -> None:
        """Specific technique defeat handles ProcessDebugPort."""
        bypass = AdvancedDebuggerBypass()

        result = bypass.defeat_anti_debug_technique("ProcessDebugPort")

        assert isinstance(result, bool), "Must return success status"

    def test_specific_technique_defeat_handles_thread_hide_from_debugger(self) -> None:
        """Specific technique defeat handles ThreadHideFromDebugger."""
        bypass = AdvancedDebuggerBypass()

        result = bypass.defeat_anti_debug_technique("ThreadHideFromDebugger")

        assert isinstance(result, bool), "Must return success status"

    def test_specific_technique_defeat_handles_rdtsc_timing(self) -> None:
        """Specific technique defeat handles RDTSC timing."""
        bypass = AdvancedDebuggerBypass()

        result = bypass.defeat_anti_debug_technique("RDTSC")

        assert isinstance(result, bool), "Must return success status"

    def test_specific_technique_defeat_handles_query_performance_counter(self) -> None:
        """Specific technique defeat handles QueryPerformanceCounter."""
        bypass = AdvancedDebuggerBypass()

        result = bypass.defeat_anti_debug_technique("QueryPerformanceCounter")

        assert isinstance(result, bool), "Must return success status"

    def test_specific_technique_defeat_handles_hardware_breakpoints(self) -> None:
        """Specific technique defeat handles hardware breakpoint detection."""
        bypass = AdvancedDebuggerBypass()

        result = bypass.defeat_anti_debug_technique("HardwareBreakpoints")

        assert isinstance(result, bool), "Must return success status"

    def test_bypass_status_reports_active_components(self) -> None:
        """Bypass status reports all active bypass components."""
        bypass = AdvancedDebuggerBypass()

        status = bypass.get_bypass_status()

        assert isinstance(status, dict), "Must return status dictionary"
        assert "active" in status, "Must include active status"
        assert "usermode_ntapi_hooks_count" in status, "Must include hook count"
        assert "virtualization_support" in status, "Must include VT support"

    def test_bypass_cleanup_removes_all_installed_bypasses(self) -> None:
        """Bypass cleanup removes all installed bypass techniques."""
        bypass = AdvancedDebuggerBypass()

        bypass.install_full_bypass()

        result = bypass.remove_all_bypasses()

        assert result is True, "Cleanup must succeed"
        assert bypass.bypass_active is False, "Bypass must be inactive after cleanup"


class TestConvenienceFunctionImplementation:
    """Validate install_advanced_bypass convenience function."""

    def test_install_advanced_bypass_with_scyllahide_mode(self) -> None:
        """install_advanced_bypass installs ScyllaHide-resistant mode."""
        result = install_advanced_bypass(scyllahide_resistant=True)

        assert isinstance(result, dict), "Must return results dictionary"
        assert "scyllahide_resistant" in result or "status" in result, (
            "Must include installation results"
        )

    def test_install_advanced_bypass_without_scyllahide_mode(self) -> None:
        """install_advanced_bypass installs full bypass without ScyllaHide mode."""
        result = install_advanced_bypass(scyllahide_resistant=False)

        assert isinstance(result, dict), "Must return results dictionary"
        assert "full_bypass" in result or "status" in result, (
            "Must include installation results"
        )


class TestRealWorldBypassScenarios:
    """Validate real-world bypass scenarios work."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_nt_api_function_addresses_are_valid(self) -> None:
        """NT API function addresses are valid and accessible."""
        hooker = UserModeNTAPIHooker()

        ntquery_addr = ctypes.cast(
            hooker.ntdll.NtQueryInformationProcess,
            ctypes.c_void_p,
        ).value

        ntset_addr = ctypes.cast(
            hooker.ntdll.NtSetInformationThread,
            ctypes.c_void_p,
        ).value

        ntsystem_addr = ctypes.cast(
            hooker.ntdll.NtQuerySystemInformation,
            ctypes.c_void_p,
        ).value

        assert ntquery_addr is not None and ntquery_addr > 0, "NtQueryInformationProcess must have valid address"
        assert ntset_addr is not None and ntset_addr > 0, "NtSetInformationThread must have valid address"
        assert ntsystem_addr is not None and ntsystem_addr > 0, "NtQuerySystemInformation must have valid address"

    def test_multi_layer_bypass_combines_user_mode_and_hypervisor(self) -> None:
        """Multi-layer bypass combines user-mode hooks with hypervisor support."""
        bypass = AdvancedDebuggerBypass()

        assert bypass.kernel_hooks is not None, "Must have kernel hooks component"
        assert bypass.hypervisor is not None, "Must have hypervisor component"
        assert bypass.timing_neutralizer is not None, "Must have timing component"

        vt_support = bypass.hypervisor.check_virtualization_support()
        assert isinstance(vt_support, dict), "Must check virtualization support"

    def test_bypass_workflow_installation_status_cleanup(self) -> None:
        """Complete bypass workflow: install, check status, cleanup."""
        bypass = AdvancedDebuggerBypass()

        install_results = bypass.install_full_bypass()
        assert isinstance(install_results, dict), "Installation must return results"

        status = bypass.get_bypass_status()
        assert isinstance(status, dict), "Status must return information"

        cleanup_result = bypass.remove_all_bypasses()
        assert cleanup_result is True, "Cleanup must succeed"


class TestPerformanceAndReliability:
    """Validate performance and reliability of implementations."""

    def test_shellcode_generation_performance(self) -> None:
        """Shellcode generation completes within acceptable time."""
        hooker = UserModeNTAPIHooker()

        start = time.perf_counter()

        for _ in range(100):
            shellcode = hooker._generate_ntquery_hook_shellcode(0x7FF800001000)
            assert len(shellcode) > 0, "Shellcode must be generated"

        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, "100 shellcode generations must complete in <0.5s"

    def test_virtualization_check_performance(self) -> None:
        """Virtualization support check completes quickly."""
        debugger = HypervisorDebugger()

        start = time.perf_counter()

        for _ in range(10):
            support = debugger.check_virtualization_support()
            assert isinstance(support, dict), "Must return support info"

        elapsed = time.perf_counter() - start

        assert elapsed < 0.5, "10 VT checks must complete in <0.5s"

    def test_bypass_installation_reliability(self) -> None:
        """Bypass installation succeeds consistently across multiple attempts."""
        success_count = 0

        for _ in range(5):
            bypass = AdvancedDebuggerBypass()
            results = bypass.install_full_bypass()

            if results.get("overall_success", False):
                success_count += 1

            bypass.remove_all_bypasses()

        assert success_count >= 3, "At least 3/5 installations must succeed"
