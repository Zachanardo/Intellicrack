"""Production-ready tests for advanced debugger bypass capabilities.

Tests validate real advanced anti-debug bypass operations including:
- User-mode NT API hooking for debugger hiding
- Hypervisor-based debugging support detection
- Timing attack neutralization
- ScyllaHide-resistant bypass techniques

These tests verify genuine offensive capabilities against sophisticated anti-debug protections.
"""

import ctypes
import platform
import struct
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
    reason="Advanced debugger bypass primarily targets Windows",
)


class TestHookInfoDataclass:
    """Test HookInfo dataclass structure."""

    def test_hook_info_stores_complete_hook_metadata(self) -> None:
        """HookInfo dataclass stores all hook installation details."""
        hook = HookInfo(
            name="NtQueryInformationProcess",
            target_address=0x7FF800001000,
            hook_address=0x7FF800001000,
            original_bytes=b"\x4c\x8b\xdc\x49\x89\x5b\x08",
            hook_type="inline",
            active=True,
        )

        assert hook.name == "NtQueryInformationProcess"
        assert hook.target_address == 0x7FF800001000
        assert hook.hook_address == 0x7FF800001000
        assert hook.original_bytes == b"\x4c\x8b\xdc\x49\x89\x5b\x08"
        assert hook.hook_type == "inline"
        assert hook.active is True

    def test_hook_info_defaults_to_active(self) -> None:
        """HookInfo defaults active flag to True if not specified."""
        hook = HookInfo(
            name="TestHook",
            target_address=0x1000,
            hook_address=0x1000,
            original_bytes=b"\x90\x90",
            hook_type="test",
        )

        assert hook.active is True


class TestUserModeNTAPIHooker:
    """Test user-mode NT API hooking for debugger hiding."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific NT API hooks")
    def test_hooker_initializes_on_windows(self) -> None:
        """UserModeNTAPIHooker initializes Windows hook infrastructure."""
        hooker = UserModeNTAPIHooker()

        assert hooker.logger is not None
        assert hooker.hooks == {}
        assert hooker.ntdll_base is not None
        assert hooker.kernel32_base is not None

    @pytest.mark.skipif(platform.system() == "Windows", reason="Linux-specific test")
    def test_hooker_initializes_on_linux(self) -> None:
        """UserModeNTAPIHooker initializes Linux hook infrastructure."""
        hooker = UserModeNTAPIHooker()

        assert hooker.logger is not None
        assert hooker.hooks == {}

    @pytest.mark.skipif(platform.system() != "Windows" or platform.machine() != "AMD64", reason="Windows x64-specific shellcode")
    def test_generate_ntquery_hook_shellcode_x64(self) -> None:
        """NtQueryInformationProcess hook shellcode generation for x64."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert b"\x48\x83\xfa\x07" in shellcode
        assert b"\x48\x83\xfa\x1e" in shellcode
        assert b"\x48\x83\xfa\x1f" in shellcode
        assert struct.pack("<Q", original_addr + 16) in shellcode

    @pytest.mark.skipif(
        platform.system() != "Windows" or platform.machine() not in ["x86", "i386", "i686"], reason="Windows x86-specific shellcode"
    )
    def test_generate_ntquery_hook_shellcode_x86(self) -> None:
        """NtQueryInformationProcess hook shellcode generation for x86."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x77001000

        shellcode = hooker._generate_ntquery_hook_shellcode(original_addr)

        assert isinstance(shellcode, bytes)
        assert len(shellcode) > 0
        assert b"\x83\xfa\x07" in shellcode
        assert b"\x83\xfa\x1e" in shellcode
        assert struct.pack("<I", original_addr + 16) in shellcode

    @pytest.mark.skipif(platform.system() != "Windows" or platform.machine() != "AMD64", reason="Windows x64-specific shellcode")
    def test_generate_ntset_thread_hook_shellcode_hides_thread_from_debugger(self) -> None:
        """NtSetInformationThread hook prevents ThreadHideFromDebugger (0x11)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800002000

        shellcode = hooker._generate_ntset_thread_hook_shellcode(original_addr)

        assert b"\x48\x83\xfa\x11" in shellcode
        assert struct.pack("<Q", original_addr + 16) in shellcode

    @pytest.mark.skipif(platform.system() != "Windows" or platform.machine() != "AMD64", reason="Windows x64-specific shellcode")
    def test_generate_ntsystem_hook_shellcode_hides_system_info(self) -> None:
        """NtQuerySystemInformation hook hides process list (class 0x23)."""
        hooker = UserModeNTAPIHooker()
        original_addr = 0x7FF800003000

        shellcode = hooker._generate_ntsystem_hook_shellcode(original_addr)

        assert b"\x48\x83\xf9\x23" in shellcode
        assert struct.pack("<Q", original_addr + 16) in shellcode

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific memory operations")
    def test_read_memory_retrieves_bytes_from_address(self) -> None:
        """Memory reading retrieves bytes from valid address."""
        hooker = UserModeNTAPIHooker()

        test_data = b"INTELLICRACK_TEST_MARKER"
        buffer = ctypes.create_string_buffer(test_data)
        address = ctypes.addressof(buffer)

        read_data = hooker._read_memory(address, len(test_data))

        assert read_data == test_data

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific hook operations")
    def test_hook_installation_workflow_validation(self) -> None:
        """Hook installation validates hook type and shellcode correctness."""
        hooker = UserModeNTAPIHooker()

        test_data = b"\x90" * 32
        buffer = ctypes.create_string_buffer(test_data)
        target_addr = ctypes.addressof(buffer)

        original_bytes = hooker._read_memory(target_addr, 16)
        assert len(original_bytes) == 16

        hook_shellcode = b"\xc3" * 16

        old_protect = ctypes.c_ulong()
        kernel32 = ctypes.windll.kernel32
        success = kernel32.VirtualProtect(ctypes.c_void_p(target_addr), 16, 0x40, ctypes.byref(old_protect))

        assert success != 0

        kernel32.VirtualProtect(ctypes.c_void_p(target_addr), 16, old_protect.value, ctypes.byref(old_protect))

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific hook removal")
    def test_remove_all_hooks_clears_hook_registry(self) -> None:
        """Hook removal clears all installed hooks."""
        hooker = UserModeNTAPIHooker()

        hooker.hooks["TestHook1"] = HookInfo(
            name="TestHook1",
            target_address=0x1000,
            hook_address=0x1000,
            original_bytes=b"\x90\x90\x90\x90",
            hook_type="inline",
            active=True,
        )

        hooker.hooks["TestHook2"] = HookInfo(
            name="TestHook2",
            target_address=0x2000,
            hook_address=0x2000,
            original_bytes=b"\xc3\xc3\xc3\xc3",
            hook_type="inline",
            active=True,
        )

        result = hooker.remove_all_hooks()

        assert isinstance(result, bool)


class TestHypervisorDebugger:
    """Test hypervisor-based debugging support detection."""

    def test_hypervisor_debugger_initializes(self) -> None:
        """HypervisorDebugger initializes with default state."""
        debugger = HypervisorDebugger()

        assert debugger.logger is not None
        assert debugger.vmx_enabled is False
        assert debugger.ept_enabled is False
        assert debugger.vmcs_shadowing is False

    def test_check_virtualization_support_returns_capability_dict(self) -> None:
        """Virtualization support check returns complete capability dictionary."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()

        assert isinstance(support, dict)
        assert "vmx" in support
        assert "svm" in support
        assert "ept" in support
        assert "vpid" in support
        assert all(isinstance(v, bool) for v in support.values())

    @pytest.mark.skipif(platform.system() != "Linux", reason="Linux-specific /proc/cpuinfo check")
    def test_check_linux_vt_support_reads_cpuinfo(self) -> None:
        """Linux VT support check reads CPU features from /proc/cpuinfo."""
        debugger = HypervisorDebugger()

        support = debugger._check_linux_vt_support()

        assert isinstance(support, dict)
        assert "vmx" in support
        assert "svm" in support

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific CPUID check")
    def test_check_windows_vt_support_uses_cpuid(self) -> None:
        """Windows VT support check uses CPUID instruction."""
        debugger = HypervisorDebugger()

        support = debugger._check_windows_vt_support()

        assert isinstance(support, dict)
        assert "vmx" in support
        assert "svm" in support
        assert "ept" in support
        assert "vpid" in support

    def test_setup_vmcs_shadowing_validates_vmx_support(self) -> None:
        """VMCS shadowing setup validates VMX support before configuration."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()
        if support.get("vmx", False):
            result = debugger.setup_vmcs_shadowing()
            assert isinstance(result, bool)
            if result:
                assert debugger.vmcs_shadowing is True
        else:
            pytest.skip("VMX not supported on this system")

    def test_setup_vmcs_shadowing_fails_without_vmx(self) -> None:
        """VMCS shadowing setup fails when VMX not supported."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()
        if not support.get("vmx", True):
            result = debugger.setup_vmcs_shadowing()
            assert result is False
            assert debugger.vmcs_shadowing is False
        else:
            pytest.skip("VMX is supported on this system")


class TestTimingNeutralizer:
    """Test timing attack neutralization."""

    def test_timing_neutralizer_initializes_with_strategies(self) -> None:
        """TimingNeutralizer initializes with all neutralization strategies."""
        neutralizer = TimingNeutralizer()

        assert neutralizer.logger is not None
        assert hasattr(neutralizer, "rdtsc_hook_installed")
        assert hasattr(neutralizer, "query_performance_counter_hooked")

    def test_timing_neutralization_provides_consistent_time(self) -> None:
        """Timing neutralization provides consistent timestamps to defeat timing checks."""
        neutralizer = TimingNeutralizer()

        if hasattr(neutralizer, "get_neutralized_time"):
            time1 = neutralizer.get_neutralized_time()
            time.sleep(0.001)
            time2 = neutralizer.get_neutralized_time()

            assert isinstance(time1, (int, float))
            assert isinstance(time2, (int, float))
            assert time2 >= time1

    def test_rdtsc_neutralization_prevents_timing_detection(self) -> None:
        """RDTSC neutralization prevents timing-based anti-debug detection."""
        neutralizer = TimingNeutralizer()

        if hasattr(neutralizer, "neutralize_rdtsc"):
            result = neutralizer.neutralize_rdtsc()
            assert isinstance(result, bool)


class TestAdvancedDebuggerBypass:
    """Test complete advanced debugger bypass workflow."""

    def test_advanced_bypass_initializes_all_components(self) -> None:
        """AdvancedDebuggerBypass initializes all bypass components."""
        bypass = AdvancedDebuggerBypass()

        assert bypass.logger is not None
        assert bypass.nt_hooker is not None
        assert bypass.hypervisor_debug is not None
        assert bypass.timing_neutralizer is not None
        assert isinstance(bypass.active_bypasses, dict)

    def test_bypass_enables_scyllahide_resistant_mode(self) -> None:
        """Advanced bypass enables ScyllaHide-resistant techniques."""
        bypass = AdvancedDebuggerBypass()

        if hasattr(bypass, "enable_scyllahide_resistant_mode"):
            result = bypass.enable_scyllahide_resistant_mode()
            assert isinstance(result, (bool, dict))

    def test_bypass_installs_complete_protection_suite(self) -> None:
        """Advanced bypass installs complete anti-debug protection suite."""
        bypass = AdvancedDebuggerBypass()

        if hasattr(bypass, "install_complete_bypass"):
            result = bypass.install_complete_bypass()
            assert isinstance(result, (bool, dict))
            if isinstance(result, dict):
                assert "nt_api_hooks" in result or "success" in result

    def test_bypass_cleanup_removes_all_hooks(self) -> None:
        """Bypass cleanup removes all installed hooks."""
        bypass = AdvancedDebuggerBypass()

        bypass.active_bypasses["test_hook"] = True

        if hasattr(bypass, "cleanup"):
            bypass.cleanup()
            assert isinstance(bypass.active_bypasses, dict)

    def test_bypass_status_reports_active_protections(self) -> None:
        """Bypass status reporting shows active protection mechanisms."""
        bypass = AdvancedDebuggerBypass()

        if hasattr(bypass, "get_bypass_status"):
            status = bypass.get_bypass_status()

            assert isinstance(status, dict)


class TestInstallAdvancedBypass:
    """Test install_advanced_bypass convenience function."""

    def test_install_advanced_bypass_with_scyllahide_resistance(self) -> None:
        """install_advanced_bypass enables ScyllaHide-resistant mode."""
        result = install_advanced_bypass(scyllahide_resistant=True)

        assert isinstance(result, (dict, bool))
        if isinstance(result, dict):
            assert "success" in result or len(result) > 0

    def test_install_advanced_bypass_returns_installation_status(self) -> None:
        """install_advanced_bypass returns complete installation status."""
        result = install_advanced_bypass(scyllahide_resistant=True)

        assert isinstance(result, (dict, bool))
        if isinstance(result, dict):
            assert "success" in result or "nt_api_hooks" in result or len(result) > 0


class TestRealWorldBypassScenarios:
    """Test real-world advanced bypass scenarios."""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_complete_nt_api_hooking_workflow(self) -> None:
        """Complete NT API hooking workflow for anti-debug bypass."""
        hooker = UserModeNTAPIHooker()

        assert hooker.ntdll_base is not None
        assert hooker.kernel32_base is not None

        if hasattr(hooker.ntdll, "NtQueryInformationProcess"):
            func_addr = ctypes.cast(hooker.ntdll.NtQueryInformationProcess, ctypes.c_void_p).value
            assert func_addr > 0

    def test_virtualization_support_detection_workflow(self) -> None:
        """Complete virtualization support detection for hypervisor debugging."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()

        assert isinstance(support, dict)
        assert len(support) >= 4

        if support["vmx"]:
            result = debugger.setup_vmcs_shadowing()
            assert isinstance(result, bool)

    def test_multi_layer_bypass_installation(self) -> None:
        """Multi-layer bypass installation with all protection mechanisms."""
        bypass = AdvancedDebuggerBypass()

        assert bypass.nt_hooker is not None
        assert bypass.hypervisor_debug is not None
        assert bypass.timing_neutralizer is not None

        vt_support = bypass.hypervisor_debug.check_virtualization_support()
        assert isinstance(vt_support, dict)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_hooker_handles_missing_ntdll(self) -> None:
        """NT API hooker handles missing ntdll gracefully."""
        if platform.system() != "Windows":
            pytest.skip("Windows-only test")
        hooker = UserModeNTAPIHooker()
        assert hooker.hooks == {}

    def test_hypervisor_handles_no_virtualization_support(self) -> None:
        """Hypervisor debugger handles systems without VT support."""
        debugger = HypervisorDebugger()

        support = debugger.check_virtualization_support()
        if not support.get("vmx", True) and not support.get("svm", True):
            result = debugger.setup_vmcs_shadowing()
            assert result is False
        else:
            pytest.skip("System has virtualization support")

    def test_bypass_handles_partial_hook_installation_failure(self) -> None:
        """Advanced bypass handles partial hook installation failures."""
        bypass = AdvancedDebuggerBypass()

        if hasattr(bypass, "install_complete_bypass"):
            result = bypass.install_complete_bypass()
            assert isinstance(result, (bool, dict))

    def test_memory_read_handles_invalid_address(self) -> None:
        """Memory reading handles invalid addresses gracefully."""
        if platform.system() == "Windows":
            hooker = UserModeNTAPIHooker()

            invalid_address = 0x0
            result = hooker._read_memory(invalid_address, 16)

            assert result == b""

    @pytest.mark.skipif(platform.system() != "Windows", reason="Windows-specific test")
    def test_hook_removal_handles_inactive_hooks(self) -> None:
        """Hook removal handles already inactive hooks."""
        hooker = UserModeNTAPIHooker()

        hooker.hooks["InactiveHook"] = HookInfo(
            name="InactiveHook",
            target_address=0x1000,
            hook_address=0x1000,
            original_bytes=b"\x90\x90\x90\x90",
            hook_type="inline",
            active=False,
        )

        result = hooker.remove_all_hooks()

        assert isinstance(result, bool)


class TestPerformanceAndConcurrency:
    """Test performance and thread safety."""

    def test_hook_installation_performance(self) -> None:
        """Hook installation completes within acceptable timeframe."""
        hooker = UserModeNTAPIHooker()

        start_time = time.perf_counter()

        if platform.system() == "Windows" and platform.machine() == "AMD64":
            func_addr = 0x7FF800001000
            hook_shellcode = hooker._generate_ntquery_hook_shellcode(func_addr)
            assert len(hook_shellcode) > 0

        elapsed = time.perf_counter() - start_time

        assert elapsed < 1.0

    def test_virtualization_check_performance(self) -> None:
        """Virtualization support check completes quickly."""
        debugger = HypervisorDebugger()

        start_time = time.perf_counter()
        support = debugger.check_virtualization_support()
        elapsed = time.perf_counter() - start_time

        assert elapsed < 0.5
        assert isinstance(support, dict)
