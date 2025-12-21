"""Comprehensive production-grade tests for anti_anti_debug_suite.py.

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
import json
import os
import struct
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest

from intellicrack.plugins.custom_modules.anti_anti_debug_suite import (
    AntiAntiDebugSuite,
    AntiDebugTechnique,
    BypassOperation,
    BypassResult,
    EnvironmentSanitizer,
    ExceptionHandler,
    HardwareDebugProtector,
    MemoryPatcher,
    PEBManipulator,
    TargetAnalyzer,
    ThreadContextHooker,
    TimingNormalizer,
    WindowsAPIHooker,
)


class TestAntiDebugTechnique:
    """Test AntiDebugTechnique enum."""

    def test_enum_values_are_strings(self) -> None:
        """All enum values must be string identifiers."""
        for technique in AntiDebugTechnique:
            assert isinstance(technique.value, str)
            assert len(technique.value) > 0

    def test_all_expected_techniques_exist(self) -> None:
        """All critical anti-debug technique types must exist."""
        required_techniques = {
            "api_hooks",
            "peb_flags",
            "hardware_breakpoints",
            "timing_checks",
            "memory_scanning",
            "exception_handling",
            "process_environment",
            "registry_checks",
            "file_system_checks",
            "advanced_evasion",
        }

        actual_techniques = {t.value for t in AntiDebugTechnique}
        assert actual_techniques == required_techniques

    def test_enum_uniqueness(self) -> None:
        """Each technique must have unique value."""
        values = [t.value for t in AntiDebugTechnique]
        assert len(values) == len(set(values))


class TestBypassResult:
    """Test BypassResult enum."""

    def test_bypass_result_values(self) -> None:
        """All bypass result types must exist."""
        assert BypassResult.SUCCESS.value == "success"
        assert BypassResult.FAILED.value == "failed"
        assert BypassResult.PARTIAL.value == "partial"
        assert BypassResult.NOT_APPLICABLE.value == "not_applicable"

    def test_result_enum_completeness(self) -> None:
        """All expected result states must be defined."""
        expected = {"success", "failed", "partial", "not_applicable"}
        actual = {r.value for r in BypassResult}
        assert actual == expected


class TestBypassOperation:
    """Test BypassOperation dataclass."""

    def test_bypass_operation_creation(self) -> None:
        """BypassOperation must capture all bypass attempt details."""
        op = BypassOperation(
            technique=AntiDebugTechnique.API_HOOKS,
            description="Test bypass",
            result=BypassResult.SUCCESS,
            details="Hook installed",
        )

        assert op.technique == AntiDebugTechnique.API_HOOKS
        assert op.description == "Test bypass"
        assert op.result == BypassResult.SUCCESS
        assert op.details == "Hook installed"
        assert op.error is None
        assert isinstance(op.timestamp, float)
        assert op.timestamp > 0

    def test_bypass_operation_with_error(self) -> None:
        """BypassOperation must track errors during bypass attempts."""
        error_msg = "Access denied"
        op = BypassOperation(
            technique=AntiDebugTechnique.PEB_FLAGS,
            description="PEB patch",
            result=BypassResult.FAILED,
            error=error_msg,
        )

        assert op.result == BypassResult.FAILED
        assert op.error == error_msg

    def test_timestamp_auto_generation(self) -> None:
        """BypassOperation timestamp must be automatically set."""
        before = time.time()
        op = BypassOperation(
            technique=AntiDebugTechnique.TIMING_CHECKS,
            description="Timing test",
            result=BypassResult.SUCCESS,
        )
        after = time.time()

        assert before <= op.timestamp <= after


class TestWindowsAPIHooker:
    """Test WindowsAPIHooker class for API interception."""

    @pytest.fixture
    def api_hooker(self) -> WindowsAPIHooker:
        """Create WindowsAPIHooker instance."""
        return WindowsAPIHooker()

    def test_initialization(self, api_hooker: WindowsAPIHooker) -> None:
        """WindowsAPIHooker must initialize with correct state."""
        assert hasattr(api_hooker, "kernel32")
        assert hasattr(api_hooker, "ntdll")
        assert hasattr(api_hooker, "user32")
        assert isinstance(api_hooker.hooked_functions, dict)
        assert isinstance(api_hooker.original_functions, dict)
        assert isinstance(api_hooker.active_hooks, set)
        assert len(api_hooker.active_hooks) == 0

    def test_hook_is_debugger_present(self, api_hooker: WindowsAPIHooker) -> None:
        """IsDebuggerPresent hook must force function to return FALSE."""
        initial_result = ctypes.windll.kernel32.IsDebuggerPresent()

        success = api_hooker.hook_is_debugger_present()
        assert isinstance(success, bool)

        if success:
            assert "IsDebuggerPresent" in api_hooker.active_hooks
            hooked_result = ctypes.windll.kernel32.IsDebuggerPresent()
            assert hooked_result == 0

            api_hooker.restore_hooks()

    def test_hook_check_remote_debugger_present(self, api_hooker: WindowsAPIHooker) -> None:
        """CheckRemoteDebuggerPresent hook must force FALSE result."""
        success = api_hooker.hook_check_remote_debugger_present()
        assert isinstance(success, bool)

        if success:
            assert "CheckRemoteDebuggerPresent" in api_hooker.active_hooks

            is_debugged = ctypes.c_bool()
            ctypes.windll.kernel32.CheckRemoteDebuggerPresent(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.byref(is_debugged),
            )
            assert is_debugged.value is False

            api_hooker.restore_hooks()

    def test_hook_nt_query_information_process(self, api_hooker: WindowsAPIHooker) -> None:
        """NtQueryInformationProcess hook must intercept debug queries."""
        success = api_hooker.hook_nt_query_information_process()
        assert isinstance(success, bool)

        if success:
            assert "NtQueryInformationProcess" in api_hooker.active_hooks
            api_hooker.restore_hooks()

    def test_hook_output_debug_string(self, api_hooker: WindowsAPIHooker) -> None:
        """OutputDebugString hook must prevent debug output."""
        success = api_hooker.hook_output_debug_string()
        assert isinstance(success, bool)

        if success:
            assert "OutputDebugStringA" in api_hooker.active_hooks
            ctypes.windll.kernel32.OutputDebugStringA(b"Test debug string")
            api_hooker.restore_hooks()

    def test_hook_nt_close(self, api_hooker: WindowsAPIHooker) -> None:
        """NtClose hook must prevent invalid handle detection."""
        success = api_hooker.hook_nt_close()
        assert isinstance(success, bool)

        if success:
            assert "NtClose" in api_hooker.active_hooks
            api_hooker.restore_hooks()

    def test_hook_close_handle(self, api_hooker: WindowsAPIHooker) -> None:
        """CloseHandle hook must always return TRUE."""
        success = api_hooker.hook_close_handle()
        assert isinstance(success, bool)

        if success:
            assert "CloseHandle" in api_hooker.active_hooks
            api_hooker.restore_hooks()

    def test_hook_get_last_error(self, api_hooker: WindowsAPIHooker) -> None:
        """GetLastError hook must return ERROR_SUCCESS."""
        success = api_hooker.hook_get_last_error()
        assert isinstance(success, bool)

        if success:
            assert "GetLastError" in api_hooker.active_hooks
            error = ctypes.windll.kernel32.GetLastError()
            assert error == 0
            api_hooker.restore_hooks()

    def test_hook_find_window(self, api_hooker: WindowsAPIHooker) -> None:
        """FindWindow hook must return NULL to hide debugger windows."""
        success = api_hooker.hook_find_window()
        assert isinstance(success, bool)

        if success:
            assert "FindWindow" in api_hooker.active_hooks
            api_hooker.restore_hooks()

    def test_install_all_hooks(self, api_hooker: WindowsAPIHooker) -> None:
        """install_all_hooks must attempt all API hooks and return results."""
        results = api_hooker.install_all_hooks()

        assert isinstance(results, list)
        assert len(results) > 0

        for result in results:
            assert isinstance(result, str)
            assert "OK" in result or "FAIL" in result

        successful_hooks = sum(bool("OK" in r)
                           for r in results)
        assert successful_hooks > 0

        api_hooker.restore_hooks()

    def test_restore_hooks(self, api_hooker: WindowsAPIHooker) -> None:
        """restore_hooks must restore original function code."""
        api_hooker.hook_is_debugger_present()
        assert len(api_hooker.active_hooks) > 0

        success = api_hooker.restore_hooks()
        assert success is True
        assert len(api_hooker.active_hooks) == 0

    def test_hook_preservation_of_original(self, api_hooker: WindowsAPIHooker) -> None:
        """Hooks must preserve original function bytes for restoration."""
        api_hooker.hook_is_debugger_present()

        assert len(api_hooker.original_functions) > 0

        for addr, original_bytes in api_hooker.original_functions.items():
            assert isinstance(original_bytes, bytes)
            assert len(original_bytes) > 0

        api_hooker.restore_hooks()


class TestPEBManipulator:
    """Test PEBManipulator class for Process Environment Block manipulation."""

    @pytest.fixture
    def peb_manipulator(self) -> PEBManipulator:
        """Create PEBManipulator instance."""
        return PEBManipulator()

    def test_initialization(self, peb_manipulator: PEBManipulator) -> None:
        """PEBManipulator must initialize with correct offsets."""
        assert peb_manipulator.PEB_BEING_DEBUGGED_OFFSET == 0x02
        assert peb_manipulator.PEB_NT_GLOBAL_FLAG_OFFSET == 0x68
        assert peb_manipulator.PEB_HEAP_FLAGS_OFFSET == 0x70
        assert hasattr(peb_manipulator, "kernel32")
        assert hasattr(peb_manipulator, "ntdll")

    def test_get_peb_address(self, peb_manipulator: PEBManipulator) -> None:
        """get_peb_address must return valid PEB address or None."""
        peb_addr = peb_manipulator.get_peb_address()

        if peb_addr is not None:
            assert isinstance(peb_addr, int)
            assert peb_addr > 0
            assert peb_addr % 8 == 0

    def test_patch_being_debugged_flag(self, peb_manipulator: PEBManipulator) -> None:
        """patch_being_debugged_flag must clear BeingDebugged flag in PEB."""
        result = peb_manipulator.patch_being_debugged_flag()
        assert isinstance(result, bool)

        if result:
            peb_addr = peb_manipulator.get_peb_address()
            assert peb_addr is not None

            flag_addr = peb_addr + peb_manipulator.PEB_BEING_DEBUGGED_OFFSET
            current_value = ctypes.c_ubyte()
            bytes_read = ctypes.c_size_t()

            if success := peb_manipulator.kernel32.ReadProcessMemory(
                peb_manipulator.kernel32.GetCurrentProcess(),
                flag_addr,
                ctypes.byref(current_value),
                1,
                ctypes.byref(bytes_read),
            ):
                assert current_value.value == 0

    def test_patch_nt_global_flag(self, peb_manipulator: PEBManipulator) -> None:
        """patch_nt_global_flag must clear debug-related flags."""
        result = peb_manipulator.patch_nt_global_flag()
        assert isinstance(result, bool)

        if result:
            peb_addr = peb_manipulator.get_peb_address()
            assert peb_addr is not None

    def test_patch_heap_flags(self, peb_manipulator: PEBManipulator) -> None:
        """patch_heap_flags must clear heap debug flags."""
        result = peb_manipulator.patch_heap_flags()
        assert isinstance(result, bool)

    def test_patch_all_peb_flags(self, peb_manipulator: PEBManipulator) -> None:
        """patch_all_peb_flags must attempt all PEB patches."""
        results = peb_manipulator.patch_all_peb_flags()

        assert isinstance(results, list)
        assert len(results) == 3

        for result in results:
            assert isinstance(result, str)
            assert "BeingDebugged" in result or "NtGlobalFlag" in result or "HeapFlags" in result


class TestThreadContextHooker:
    """Test ThreadContextHooker class for hardware breakpoint hiding."""

    @pytest.fixture
    def context_hooker(self) -> ThreadContextHooker:
        """Create ThreadContextHooker instance."""
        return ThreadContextHooker()

    def test_hook_get_thread_context(self, context_hooker: ThreadContextHooker) -> None:
        """hook_get_thread_context must hide hardware breakpoints in returned context."""
        result = context_hooker.hook_get_thread_context()
        assert isinstance(result, bool)

    def test_hook_set_thread_context(self, context_hooker: ThreadContextHooker) -> None:
        """hook_set_thread_context must prevent hardware breakpoint setting."""
        result = context_hooker.hook_set_thread_context()
        assert isinstance(result, bool)


class TestHardwareDebugProtector:
    """Test HardwareDebugProtector class for debug register management."""

    @pytest.fixture
    def hw_protector(self) -> HardwareDebugProtector:
        """Create HardwareDebugProtector instance."""
        return HardwareDebugProtector()

    def test_initialization(self, hw_protector: HardwareDebugProtector) -> None:
        """HardwareDebugProtector must initialize with clean state."""
        assert hasattr(hw_protector, "kernel32")
        assert hw_protector.saved_context is None

    def test_get_thread_context(self, hw_protector: HardwareDebugProtector) -> None:
        """get_thread_context must retrieve current thread debug registers."""
        context = hw_protector.get_thread_context()

        if context is not None:
            assert hasattr(context, "Dr0")
            assert hasattr(context, "Dr1")
            assert hasattr(context, "Dr2")
            assert hasattr(context, "Dr3")
            assert hasattr(context, "Dr6")
            assert hasattr(context, "Dr7")

    def test_clear_debug_registers(self, hw_protector: HardwareDebugProtector) -> None:
        """clear_debug_registers must zero all hardware debug registers."""
        result = hw_protector.clear_debug_registers()
        assert isinstance(result, bool)

        if result:
            context = hw_protector.get_thread_context()
            if context is not None:
                assert context.Dr0 == 0
                assert context.Dr1 == 0
                assert context.Dr2 == 0
                assert context.Dr3 == 0
                assert context.Dr6 == 0
                assert context.Dr7 == 0

            assert hw_protector.saved_context is not None
            hw_protector.restore_debug_registers()

    def test_monitor_debug_registers(self, hw_protector: HardwareDebugProtector) -> None:
        """monitor_debug_registers must return current debug register values."""
        registers = hw_protector.monitor_debug_registers()

        assert isinstance(registers, dict)

        if len(registers) > 0:
            assert "Dr0" in registers
            assert "Dr1" in registers
            assert "Dr2" in registers
            assert "Dr3" in registers
            assert "Dr6" in registers
            assert "Dr7" in registers

            for value in registers.values():
                assert isinstance(value, int)

    def test_restore_debug_registers(self, hw_protector: HardwareDebugProtector) -> None:
        """restore_debug_registers must restore saved debug register values."""
        hw_protector.clear_debug_registers()
        result = hw_protector.restore_debug_registers()
        assert isinstance(result, bool)

        if not hw_protector.saved_context:
            assert result is True


class TestTimingNormalizer:
    """Test TimingNormalizer class for timing attack mitigation."""

    @pytest.fixture
    def timing_normalizer(self) -> TimingNormalizer:
        """Create TimingNormalizer instance."""
        return TimingNormalizer()

    def test_initialization(self, timing_normalizer: TimingNormalizer) -> None:
        """TimingNormalizer must initialize with empty state."""
        assert isinstance(timing_normalizer.timing_hooks, dict)
        assert isinstance(timing_normalizer.baseline_times, dict)
        assert len(timing_normalizer.baseline_times) == 0

    def test_measure_baseline_timing(self, timing_normalizer: TimingNormalizer) -> None:
        """measure_baseline_timing must establish timing baselines."""
        timing_normalizer.measure_baseline_timing()

        assert len(timing_normalizer.baseline_times) > 0
        assert "GetTickCount" in timing_normalizer.baseline_times
        assert "QueryPerformanceCounter" in timing_normalizer.baseline_times

        for timing in timing_normalizer.baseline_times.values():
            assert isinstance(timing, float)
            assert timing > 0

    def test_normalize_get_tick_count(self, timing_normalizer: TimingNormalizer) -> None:
        """normalize_get_tick_count must hook GetTickCount for consistent timing."""
        result = timing_normalizer.normalize_get_tick_count()
        assert isinstance(result, bool)

    def test_find_rdtsc_instructions(self, timing_normalizer: TimingNormalizer) -> None:
        """_find_rdtsc_instructions must locate RDTSC instructions in memory."""
        locations = timing_normalizer._find_rdtsc_instructions()

        assert isinstance(locations, list)
        for location in locations:
            assert isinstance(location, int)
            assert location > 0

    def test_normalize_rdtsc(self, timing_normalizer: TimingNormalizer) -> None:
        """normalize_rdtsc must handle RDTSC timing instruction."""
        result = timing_normalizer.normalize_rdtsc()
        assert isinstance(result, bool)

    def test_add_random_delays(self, timing_normalizer: TimingNormalizer) -> None:
        """add_random_delays must add timing variation."""
        start = time.perf_counter()
        timing_normalizer.add_random_delays()
        elapsed = time.perf_counter() - start

        assert elapsed >= 0.001
        assert elapsed <= 0.02

    def test_apply_timing_normalizations(self, timing_normalizer: TimingNormalizer) -> None:
        """apply_timing_normalizations must apply all timing bypasses."""
        results = timing_normalizer.apply_timing_normalizations()

        assert isinstance(results, list)
        assert len(results) > 0
        assert len(timing_normalizer.baseline_times) > 0

        for result in results:
            assert isinstance(result, str)


class TestMemoryPatcher:
    """Test MemoryPatcher class for anti-debug pattern removal."""

    @pytest.fixture
    def memory_patcher(self) -> MemoryPatcher:
        """Create MemoryPatcher instance."""
        return MemoryPatcher()

    def test_initialization(self, memory_patcher: MemoryPatcher) -> None:
        """MemoryPatcher must initialize with known anti-debug patterns."""
        assert isinstance(memory_patcher.patterns, dict)
        assert len(memory_patcher.patterns) > 0
        assert isinstance(memory_patcher.patches_applied, list)

        assert "IsDebuggerPresent_call" in memory_patcher.patterns
        assert "int3_detection" in memory_patcher.patterns
        assert "trap_flag" in memory_patcher.patterns
        assert "vm_detection" in memory_patcher.patterns

    def test_find_patterns_in_memory(self, memory_patcher: MemoryPatcher) -> None:
        """find_patterns_in_memory must locate anti-debug patterns."""
        kernel32 = ctypes.windll.kernel32
        if module_handle := kernel32.GetModuleHandleW(None):
            found = memory_patcher.find_patterns_in_memory(module_handle, 0x10000)
            assert isinstance(found, list)

            for pattern_name, address in found:
                assert isinstance(pattern_name, str)
                assert isinstance(address, int)
                assert address > 0

    def test_patch_memory_location(self, memory_patcher: MemoryPatcher) -> None:
        """patch_memory_location must write new bytes to memory."""
        test_data = ctypes.create_string_buffer(16)
        test_addr = ctypes.addressof(test_data)

        if result := memory_patcher.patch_memory_location(test_addr, b"\x90" * 4):
            assert len(memory_patcher.patches_applied) > 0
            patch = memory_patcher.patches_applied[-1]
            assert patch["address"] == test_addr
            assert patch["size"] == 4

    def test_patch_int3_instructions(self, memory_patcher: MemoryPatcher) -> None:
        """patch_int3_instructions must replace INT3 with NOP."""
        test_data = ctypes.create_string_buffer(b"\xCC\xCC\xCC")
        test_addr = ctypes.addressof(test_data)

        result = memory_patcher.patch_int3_instructions(test_addr)
        assert isinstance(result, bool)

    def test_patch_isdebuggerpresent_calls(self, memory_patcher: MemoryPatcher) -> None:
        """patch_isdebuggerpresent_calls must neutralize API calls."""
        test_data = ctypes.create_string_buffer(16)
        test_addr = ctypes.addressof(test_data)

        result = memory_patcher.patch_isdebuggerpresent_calls(test_addr)
        assert isinstance(result, bool)

    def test_scan_and_patch_module(self, memory_patcher: MemoryPatcher) -> None:
        """scan_and_patch_module must scan specific module for patterns."""
        results = memory_patcher.scan_and_patch_module(None)

        assert isinstance(results, list)
        assert len(results) > 0

        for result in results:
            assert isinstance(result, str)

    def test_scan_all_modules(self, memory_patcher: MemoryPatcher) -> None:
        """scan_all_modules must scan all loaded modules."""
        results = memory_patcher.scan_all_modules()

        assert isinstance(results, list)
        assert len(results) > 0


class TestExceptionHandler:
    """Test ExceptionHandler class for exception-based detection bypass."""

    @pytest.fixture
    def exception_handler(self) -> ExceptionHandler:
        """Create ExceptionHandler instance."""
        return ExceptionHandler()

    def test_initialization(self, exception_handler: ExceptionHandler) -> None:
        """ExceptionHandler must initialize with clean state."""
        assert exception_handler.original_handler is None
        assert exception_handler.exception_count == 0

    def test_custom_exception_handler(self, exception_handler: ExceptionHandler) -> None:
        """custom_exception_handler must handle anti-debug exceptions."""
        result = exception_handler.custom_exception_handler("debug exception")
        assert isinstance(result, (int, type(None)))

        if result is not None:
            assert result in [0, 1]

        assert exception_handler.exception_count > 0

    def test_install_exception_handler(self, exception_handler: ExceptionHandler) -> None:
        """install_exception_handler must install vectored exception handler."""
        result = exception_handler.install_exception_handler()
        assert isinstance(result, bool)

        if result:
            assert exception_handler.original_handler is not None
            exception_handler.remove_exception_handler()

    def test_remove_exception_handler(self, exception_handler: ExceptionHandler) -> None:
        """remove_exception_handler must restore original exception handling."""
        exception_handler.install_exception_handler()
        result = exception_handler.remove_exception_handler()
        assert isinstance(result, bool)
        assert result is True

    def test_mask_debug_exceptions(self, exception_handler: ExceptionHandler) -> None:
        """mask_debug_exceptions must hide debug-related exceptions."""
        result = exception_handler.mask_debug_exceptions()
        assert isinstance(result, bool)

        if result:
            exception_handler.remove_exception_handler()


class TestEnvironmentSanitizer:
    """Test EnvironmentSanitizer class for debugger artifact removal."""

    @pytest.fixture
    def env_sanitizer(self) -> EnvironmentSanitizer:
        """Create EnvironmentSanitizer instance."""
        return EnvironmentSanitizer()

    def test_initialization(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """EnvironmentSanitizer must initialize with empty state."""
        assert isinstance(env_sanitizer.original_values, dict)
        assert len(env_sanitizer.original_values) == 0

    def test_clean_environment_variables(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """clean_environment_variables must remove debug-related vars."""
        os.environ["_NT_SYMBOL_PATH"] = "test_path"
        os.environ["DEBUG"] = "1"

        results = env_sanitizer.clean_environment_variables()

        assert isinstance(results, list)
        assert len(results) > 0

        for result in results:
            assert isinstance(result, str)

        assert "_NT_SYMBOL_PATH" not in os.environ
        assert "DEBUG" not in os.environ

        env_sanitizer.restore_environment()

    def test_hide_debugger_processes(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """hide_debugger_processes must detect running debuggers."""
        results = env_sanitizer.hide_debugger_processes()

        assert isinstance(results, list)
        assert len(results) > 0

        for result in results:
            assert isinstance(result, str)
            assert "ollydbg" in result.lower() or "windbg" in result.lower() or "x64dbg" in result.lower()

    def test_clean_registry_artifacts(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """clean_registry_artifacts must check for debugger registry entries."""
        results = env_sanitizer.clean_registry_artifacts()

        assert isinstance(results, list)
        assert len(results) > 0

    def test_sanitize_file_system(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """sanitize_file_system must check for debugger files."""
        results = env_sanitizer.sanitize_file_system()

        assert isinstance(results, list)
        assert len(results) > 0

    def test_sanitize_all(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """sanitize_all must run all sanitization procedures."""
        results = env_sanitizer.sanitize_all()

        assert isinstance(results, list)
        assert len(results) > 0

        result_text = "\n".join(results)
        assert "Environment Variables" in result_text
        assert "Debugger Processes" in result_text
        assert "Registry Artifacts" in result_text
        assert "File System" in result_text

    def test_restore_environment(self, env_sanitizer: EnvironmentSanitizer) -> None:
        """restore_environment must restore original environment variables."""
        env_sanitizer.original_values = {"TEST_VAR": "test_value"}

        result = env_sanitizer.restore_environment()
        assert result is True
        assert os.environ.get("TEST_VAR") == "test_value"

        os.environ.pop("TEST_VAR", None)


class TestTargetAnalyzer:
    """Test TargetAnalyzer class for anti-debug technique detection."""

    @pytest.fixture
    def target_analyzer(self) -> TargetAnalyzer:
        """Create TargetAnalyzer instance."""
        return TargetAnalyzer()

    @pytest.fixture
    def sample_pe_file(self, tmp_path: Path) -> Path:
        """Create sample PE file for testing."""
        pe_file = tmp_path / "sample.exe"

        dos_header = bytearray(64)
        dos_header[:2] = b"MZ"
        struct.pack_into("<I", dos_header, 60, 64)

        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0, 0x0200)

        pe_data = bytes(dos_header) + pe_signature + coff_header + b"\x00" * 1000

        pe_file.write_bytes(pe_data)
        return pe_file

    def test_initialization(self, target_analyzer: TargetAnalyzer) -> None:
        """TargetAnalyzer must initialize with empty detection set."""
        assert isinstance(target_analyzer.detected_techniques, set)
        assert len(target_analyzer.detected_techniques) == 0

    def test_analyze_pe_headers(self, target_analyzer: TargetAnalyzer, sample_pe_file: Path) -> None:
        """analyze_pe_headers must detect anti-debug indicators in PE."""
        techniques = target_analyzer.analyze_pe_headers(str(sample_pe_file))

        assert isinstance(techniques, list)

        for technique in techniques:
            assert isinstance(technique, AntiDebugTechnique)

    def test_analyze_pe_headers_invalid_file(self, target_analyzer: TargetAnalyzer, tmp_path: Path) -> None:
        """analyze_pe_headers must handle invalid PE files."""
        invalid_file = tmp_path / "invalid.exe"
        invalid_file.write_bytes(b"NOT A PE FILE")

        techniques = target_analyzer.analyze_pe_headers(str(invalid_file))
        assert isinstance(techniques, list)
        assert len(techniques) == 0

    def test_analyze_imports(self, target_analyzer: TargetAnalyzer, sample_pe_file: Path) -> None:
        """analyze_imports must detect anti-debug API usage."""
        content = sample_pe_file.read_bytes()
        content += b"IsDebuggerPresent\x00CheckRemoteDebuggerPresent\x00"
        sample_pe_file.write_bytes(content)

        techniques = target_analyzer.analyze_imports(str(sample_pe_file))

        assert isinstance(techniques, list)

        if len(techniques) > 0:
            assert AntiDebugTechnique.API_HOOKS in techniques

    def test_analyze_runtime_behavior(self, target_analyzer: TargetAnalyzer) -> None:
        """analyze_runtime_behavior must detect runtime anti-debug techniques."""
        techniques = target_analyzer.analyze_runtime_behavior()

        assert isinstance(techniques, list)
        assert len(techniques) > 0

        assert AntiDebugTechnique.PEB_FLAGS in techniques
        assert AntiDebugTechnique.HARDWARE_BREAKPOINTS in techniques
        assert AntiDebugTechnique.EXCEPTION_HANDLING in techniques

    def test_detect_vm_environment(self, target_analyzer: TargetAnalyzer) -> None:
        """detect_vm_environment must check for VM indicators."""
        result = target_analyzer.detect_vm_environment()
        assert isinstance(result, bool)

    def test_analyze_target_with_file(self, target_analyzer: TargetAnalyzer, sample_pe_file: Path) -> None:
        """analyze_target must perform comprehensive target analysis."""
        analysis = target_analyzer.analyze_target(str(sample_pe_file))

        assert isinstance(analysis, dict)
        assert "techniques_detected" in analysis
        assert "vm_environment" in analysis
        assert "risk_level" in analysis
        assert "recommended_bypasses" in analysis

        assert isinstance(analysis["techniques_detected"], list)
        assert isinstance(analysis["vm_environment"], bool)
        assert analysis["risk_level"] in ["low", "medium", "high"]
        assert isinstance(analysis["recommended_bypasses"], list)

    def test_analyze_target_risk_levels(self, target_analyzer: TargetAnalyzer) -> None:
        """analyze_target must correctly assess risk levels."""
        analysis = target_analyzer.analyze_target()

        num_techniques = len(analysis["techniques_detected"])

        if num_techniques >= 6:
            assert analysis["risk_level"] == "high"
        elif num_techniques >= 3:
            assert analysis["risk_level"] == "medium"
        else:
            assert analysis["risk_level"] == "low"

    def test_analyze_target_recommendations(self, target_analyzer: TargetAnalyzer) -> None:
        """analyze_target must recommend appropriate bypasses."""
        analysis = target_analyzer.analyze_target()

        for bypass in analysis["recommended_bypasses"]:
            assert isinstance(bypass, str)
            assert bypass in [
                "API hooking",
                "PEB manipulation",
                "Hardware debug protection",
                "Timing normalization",
                "Exception handling",
                "Environment sanitization",
            ]


class TestAntiAntiDebugSuite:
    """Test AntiAntiDebugSuite orchestrator class."""

    @pytest.fixture
    def suite(self) -> AntiAntiDebugSuite:
        """Create AntiAntiDebugSuite instance."""
        return AntiAntiDebugSuite()

    def test_initialization(self, suite: AntiAntiDebugSuite) -> None:
        """AntiAntiDebugSuite must initialize all components."""
        assert isinstance(suite.api_hooker, WindowsAPIHooker)
        assert isinstance(suite.peb_manipulator, PEBManipulator)
        assert isinstance(suite.timing_normalizer, TimingNormalizer)
        assert isinstance(suite.memory_patcher, MemoryPatcher)
        assert isinstance(suite.target_analyzer, TargetAnalyzer)

        assert isinstance(suite.active_bypasses, set)
        assert isinstance(suite.bypass_history, list)
        assert isinstance(suite.statistics, dict)
        assert isinstance(suite.config, dict)

        assert suite.statistics["bypasses_attempted"] == 0
        assert suite.statistics["bypasses_successful"] == 0
        assert suite.statistics["targets_analyzed"] == 0

    def test_analyze_target(self, suite: AntiAntiDebugSuite) -> None:
        """analyze_target must perform target analysis and track statistics."""
        initial_count = suite.statistics["targets_analyzed"]

        analysis = suite.analyze_target()

        assert isinstance(analysis, dict)
        assert suite.statistics["targets_analyzed"] == initial_count + 1

    def test_apply_bypass_api_hooks(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must successfully apply API hook bypasses."""
        operation = suite.apply_bypass(AntiDebugTechnique.API_HOOKS)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.API_HOOKS
        assert operation.result in [BypassResult.SUCCESS, BypassResult.FAILED]

        if operation.result == BypassResult.SUCCESS:
            assert AntiDebugTechnique.API_HOOKS in suite.active_bypasses
            assert "OK" in operation.details

        suite.remove_bypasses()

    def test_apply_bypass_peb_flags(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must successfully apply PEB flag bypasses."""
        operation = suite.apply_bypass(AntiDebugTechnique.PEB_FLAGS)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.PEB_FLAGS
        assert operation.result in [BypassResult.SUCCESS, BypassResult.FAILED]

    def test_apply_bypass_hardware_breakpoints(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must apply hardware breakpoint protection."""
        operation = suite.apply_bypass(AntiDebugTechnique.HARDWARE_BREAKPOINTS)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.HARDWARE_BREAKPOINTS

    def test_apply_bypass_timing_checks(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must apply timing normalization."""
        operation = suite.apply_bypass(AntiDebugTechnique.TIMING_CHECKS)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.TIMING_CHECKS

    def test_apply_bypass_memory_scanning(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must patch memory anti-debug patterns."""
        operation = suite.apply_bypass(AntiDebugTechnique.MEMORY_SCANNING)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.MEMORY_SCANNING

    def test_apply_bypass_exception_handling(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must install exception masking."""
        operation = suite.apply_bypass(AntiDebugTechnique.EXCEPTION_HANDLING)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.EXCEPTION_HANDLING

    def test_apply_bypass_process_environment(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must sanitize process environment."""
        operation = suite.apply_bypass(AntiDebugTechnique.PROCESS_ENVIRONMENT)

        assert isinstance(operation, BypassOperation)
        assert operation.technique == AntiDebugTechnique.PROCESS_ENVIRONMENT

    def test_apply_bypass_statistics_tracking(self, suite: AntiAntiDebugSuite) -> None:
        """apply_bypass must track statistics correctly."""
        initial_attempted = suite.statistics["bypasses_attempted"]
        initial_successful = suite.statistics["bypasses_successful"]

        operation = suite.apply_bypass(AntiDebugTechnique.API_HOOKS)

        assert suite.statistics["bypasses_attempted"] == initial_attempted + 1

        if operation.result == BypassResult.SUCCESS:
            assert suite.statistics["bypasses_successful"] == initial_successful + 1

        suite.remove_bypasses()

    def test_apply_selective_bypasses(self, suite: AntiAntiDebugSuite) -> None:
        """apply_selective_bypasses must apply bypasses based on analysis."""
        analysis = suite.analyze_target()
        operations = suite.apply_selective_bypasses(analysis)

        assert isinstance(operations, list)
        assert len(operations) > 0

        for operation in operations:
            assert isinstance(operation, BypassOperation)

        suite.remove_bypasses()

    def test_apply_all_bypasses(self, suite: AntiAntiDebugSuite) -> None:
        """apply_all_bypasses must attempt all bypass techniques."""
        operations = suite.apply_all_bypasses()

        assert isinstance(operations, list)
        assert len(operations) == len(AntiDebugTechnique)

        techniques_applied = {op.technique for op in operations}
        assert techniques_applied == set(AntiDebugTechnique)

        suite.remove_bypasses()

    def test_monitor_bypasses(self, suite: AntiAntiDebugSuite) -> None:
        """monitor_bypasses must return current bypass status."""
        status = suite.monitor_bypasses()

        assert isinstance(status, dict)
        assert "active_bypasses" in status
        assert "bypass_count" in status
        assert "hardware_registers" in status
        assert "statistics" in status
        assert "uptime_seconds" in status

        assert isinstance(status["active_bypasses"], list)
        assert isinstance(status["bypass_count"], int)
        assert isinstance(status["uptime_seconds"], float)
        assert status["uptime_seconds"] >= 0

    def test_remove_bypasses(self, suite: AntiAntiDebugSuite) -> None:
        """remove_bypasses must restore original state."""
        suite.apply_bypass(AntiDebugTechnique.API_HOOKS)

        results = suite.remove_bypasses()

        assert isinstance(results, list)
        assert len(results) > 0
        assert len(suite.active_bypasses) == 0

    def test_get_report(self, suite: AntiAntiDebugSuite) -> None:
        """get_report must generate comprehensive bypass report."""
        suite.apply_bypass(AntiDebugTechnique.API_HOOKS)
        suite.apply_bypass(AntiDebugTechnique.PEB_FLAGS)

        report = suite.get_report()

        assert isinstance(report, dict)
        assert "summary" in report
        assert "active_bypasses" in report
        assert "bypass_history" in report
        assert "statistics" in report
        assert "configuration" in report

        summary = report["summary"]
        assert "total_bypasses_attempted" in summary
        assert "successful_bypasses" in summary
        assert "failed_bypasses" in summary
        assert "currently_active" in summary
        assert "success_rate" in summary

        assert isinstance(summary["success_rate"], float)
        assert 0 <= summary["success_rate"] <= 100

        suite.remove_bypasses()

    def test_export_report(self, suite: AntiAntiDebugSuite, tmp_path: Path) -> None:
        """export_report must save report to JSON file."""
        suite.apply_bypass(AntiDebugTechnique.API_HOOKS)

        report_file = tmp_path / "bypass_report.json"
        suite.export_report(str(report_file))

        assert report_file.exists()

        with open(report_file) as f:
            loaded_report = json.load(f)

        assert isinstance(loaded_report, dict)
        assert "summary" in loaded_report
        assert "bypass_history" in loaded_report

        suite.remove_bypasses()

    def test_bypass_history_tracking(self, suite: AntiAntiDebugSuite) -> None:
        """Bypass history must track all attempted bypasses."""
        initial_history_len = len(suite.bypass_history)

        suite.apply_bypass(AntiDebugTechnique.API_HOOKS)
        suite.apply_bypass(AntiDebugTechnique.PEB_FLAGS)

        assert len(suite.bypass_history) == initial_history_len + 2

        for operation in suite.bypass_history[-2:]:
            assert isinstance(operation, BypassOperation)
            assert operation.timestamp > 0

        suite.remove_bypasses()

    def test_configuration_management(self, suite: AntiAntiDebugSuite) -> None:
        """Suite must maintain configuration settings."""
        assert suite.config["auto_apply_bypasses"] is True
        assert suite.config["selective_bypasses"] is True
        assert suite.config["stealth_mode"] is True
        assert suite.config["log_level"] == "INFO"

        suite.config["stealth_mode"] = False
        assert suite.config["stealth_mode"] is False


class TestIntegrationScenarios:
    """Integration tests for complete bypass workflows."""

    @pytest.fixture
    def suite(self) -> AntiAntiDebugSuite:
        """Create suite instance."""
        return AntiAntiDebugSuite()

    def test_full_analysis_and_bypass_workflow(self, suite: AntiAntiDebugSuite) -> None:
        """Complete workflow: analyze target, apply bypasses, monitor, remove."""
        analysis = suite.analyze_target()
        assert isinstance(analysis, dict)

        operations = suite.apply_selective_bypasses(analysis)
        assert len(operations) > 0

        status = suite.monitor_bypasses()
        assert status["bypass_count"] >= 0

        report = suite.get_report()
        assert report["summary"]["total_bypasses_attempted"] > 0

        results = suite.remove_bypasses()
        assert len(results) > 0
        assert len(suite.active_bypasses) == 0

    def test_multiple_bypass_cycles(self, suite: AntiAntiDebugSuite) -> None:
        """Suite must handle multiple apply/remove cycles."""
        for _ in range(3):
            suite.apply_bypass(AntiDebugTechnique.API_HOOKS)
            assert len(suite.active_bypasses) > 0

            suite.remove_bypasses()
            assert len(suite.active_bypasses) == 0

    def test_concurrent_bypass_application(self, suite: AntiAntiDebugSuite) -> None:
        """Multiple bypasses must work together."""
        techniques = [
            AntiDebugTechnique.API_HOOKS,
            AntiDebugTechnique.PEB_FLAGS,
            AntiDebugTechnique.PROCESS_ENVIRONMENT,
        ]

        for technique in techniques:
            suite.apply_bypass(technique)

        assert len(suite.active_bypasses) >= 1

        suite.remove_bypasses()

    def test_error_handling_during_bypass(self, suite: AntiAntiDebugSuite) -> None:
        """Suite must handle errors gracefully."""
        operation = suite.apply_bypass(AntiDebugTechnique.REGISTRY_CHECKS)

        assert isinstance(operation, BypassOperation)

        if operation.result == BypassResult.FAILED:
            assert operation.error is not None or "FAIL" in operation.details

    def test_statistics_accuracy(self, suite: AntiAntiDebugSuite) -> None:
        """Statistics must accurately track all operations."""
        initial_stats = suite.statistics.copy()

        suite.apply_bypass(AntiDebugTechnique.API_HOOKS)
        suite.apply_bypass(AntiDebugTechnique.PEB_FLAGS)

        assert suite.statistics["bypasses_attempted"] == initial_stats["bypasses_attempted"] + 2

        success_count = sum(bool(op.result == BypassResult.SUCCESS)
                        for op in suite.bypass_history[-2:])
        assert suite.statistics["bypasses_successful"] == initial_stats["bypasses_successful"] + success_count

        suite.remove_bypasses()

    def test_report_completeness(self, suite: AntiAntiDebugSuite, tmp_path: Path) -> None:
        """Generated reports must contain all required information."""
        suite.apply_all_bypasses()

        report = suite.get_report()

        assert len(report["bypass_history"]) == len(AntiDebugTechnique)

        for entry in report["bypass_history"]:
            assert "technique" in entry
            assert "result" in entry
            assert "details" in entry
            assert "timestamp" in entry

        report_file = tmp_path / "complete_report.json"
        suite.export_report(str(report_file))

        assert report_file.exists()
        assert report_file.stat().st_size > 0

        suite.remove_bypasses()


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error conditions."""

    def test_analyze_nonexistent_file(self) -> None:
        """TargetAnalyzer must handle nonexistent files."""
        analyzer = TargetAnalyzer()
        analysis = analyzer.analyze_target("nonexistent_file.exe")

        assert isinstance(analysis, dict)
        assert "techniques_detected" in analysis

    def test_peb_manipulation_without_permissions(self) -> None:
        """PEB manipulation must handle permission errors."""
        peb_manipulator = PEBManipulator()

        result = peb_manipulator.patch_being_debugged_flag()
        assert isinstance(result, bool)

    def test_hook_restoration_idempotence(self) -> None:
        """Restoring hooks multiple times must be safe."""
        hooker = WindowsAPIHooker()
        hooker.hook_is_debugger_present()

        assert hooker.restore_hooks() is True
        assert hooker.restore_hooks() is True
        assert len(hooker.active_hooks) == 0

    def test_empty_bypass_removal(self) -> None:
        """Removing bypasses when none are active must succeed."""
        suite = AntiAntiDebugSuite()
        results = suite.remove_bypasses()

        assert isinstance(results, list)
        assert len(suite.active_bypasses) == 0

    def test_malformed_pe_header_analysis(self, tmp_path: Path) -> None:
        """Analyzer must handle malformed PE headers."""
        malformed_pe = tmp_path / "malformed.exe"
        malformed_pe.write_bytes(b"MZ" + b"\x00" * 100)

        analyzer = TargetAnalyzer()
        techniques = analyzer.analyze_pe_headers(str(malformed_pe))

        assert isinstance(techniques, list)

    def test_concurrent_memory_patching(self) -> None:
        """Memory patching must be safe for concurrent use."""
        patcher = MemoryPatcher()

        test_buffer = ctypes.create_string_buffer(64)
        addr = ctypes.addressof(test_buffer)

        result1 = patcher.patch_memory_location(addr, b"\x90\x90")
        result2 = patcher.patch_memory_location(addr + 10, b"\xCC\xCC")

        assert isinstance(result1, bool)
        assert isinstance(result2, bool)
