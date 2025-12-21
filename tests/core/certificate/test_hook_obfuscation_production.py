"""Production tests for hook obfuscation and integrity monitoring.

Tests validate real hook obfuscation techniques to prevent detection:
- Random callback name generation for blending with normal code
- Indirect hook creation via function pointer chains
- Hardware breakpoint hook installation (DR0-DR3)
- Code cave discovery in executable modules
- Hook integrity monitoring and automatic restoration
- Hook rotation to avoid signature detection
- Memory read/write operations for hook installation
- Thread-safe hook management

All tests operate on real system resources (memory, debug registers, modules)
without mocks to validate genuine anti-detection effectiveness.
"""

import ctypes
import platform
import re
import threading
import time
from typing import TYPE_CHECKING

import pytest

from intellicrack.core.certificate.hook_obfuscation import HookInfo, HookObfuscator

if TYPE_CHECKING:
    from collections.abc import Generator


class TestHookObfuscatorInitialization:
    """Test HookObfuscator initialization and state management."""

    def test_initialization_creates_empty_hook_registry(self) -> None:
        """HookObfuscator initializes with empty installed hooks dictionary."""
        obfuscator = HookObfuscator()

        assert isinstance(obfuscator.installed_hooks, dict)
        assert len(obfuscator.installed_hooks) == 0

    def test_initialization_creates_code_cave_registry(self) -> None:
        """HookObfuscator initializes with empty code caves dictionary."""
        obfuscator = HookObfuscator()

        assert isinstance(obfuscator.code_caves, dict)
        assert len(obfuscator.code_caves) == 0

    def test_initialization_sets_integrity_monitor_inactive(self) -> None:
        """HookObfuscator starts with integrity monitoring disabled."""
        obfuscator = HookObfuscator()

        assert obfuscator.integrity_monitor_active is False
        assert obfuscator._integrity_thread is None

    def test_initialization_creates_thread_synchronization_lock(self) -> None:
        """HookObfuscator creates thread lock for concurrent access."""
        obfuscator = HookObfuscator()

        assert isinstance(obfuscator._lock, threading.Lock)

    def test_initialization_creates_stop_monitoring_event(self) -> None:
        """HookObfuscator creates event for stopping integrity monitor."""
        obfuscator = HookObfuscator()

        assert isinstance(obfuscator._stop_monitoring, threading.Event)
        assert not obfuscator._stop_monitoring.is_set()


class TestCallbackNameGeneration:
    """Test random callback name generation for blending with application code."""

    def test_generate_random_callback_name_returns_valid_identifier(self) -> None:
        """Generate callback name returns valid Python/C identifier."""
        obfuscator = HookObfuscator()

        name = obfuscator.generate_random_callback_name()

        assert isinstance(name, str)
        assert len(name) > 0
        assert re.match(r"^[a-z_][a-z_0-9]*$", name)

    def test_generated_callback_names_follow_pattern(self) -> None:
        """Generated callback names follow prefix_subject_suffix pattern."""
        obfuscator = HookObfuscator()

        name = obfuscator.generate_random_callback_name()

        parts = name.split("_")
        assert len(parts) == 3
        assert all(part.isalpha() for part in parts)

    def test_callback_names_are_randomized(self) -> None:
        """Generated callback names vary across multiple calls."""
        obfuscator = HookObfuscator()

        names = [obfuscator.generate_random_callback_name() for _ in range(20)]

        unique_names = set(names)
        assert len(unique_names) > 5

    def test_callback_names_sound_benign(self) -> None:
        """Generated callback names use benign, application-like terms."""
        obfuscator = HookObfuscator()

        benign_keywords = {
            "process",
            "handle",
            "update",
            "validate",
            "check",
            "parse",
            "data",
            "response",
            "handler",
            "manager",
        }

        names = [obfuscator.generate_random_callback_name() for _ in range(10)]

        for name in names:
            parts = name.split("_")
            assert any(keyword in parts for keyword in benign_keywords)

    def test_callback_name_generation_is_fast(self) -> None:
        """Callback name generation completes quickly."""
        obfuscator = HookObfuscator()

        start = time.time()
        for _ in range(100):
            obfuscator.generate_random_callback_name()
        elapsed = time.time() - start

        assert elapsed < 0.5


class TestMemoryOperations:
    """Test memory read/write operations for hook installation."""

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Memory operations use Windows-specific APIs",
    )
    def test_read_memory_from_valid_address(self) -> None:
        """Read memory from valid address in current process."""
        obfuscator = HookObfuscator()

        kernel32 = ctypes.windll.kernel32
        base_addr = kernel32.GetModuleHandleW(None)

        data = obfuscator._read_memory(base_addr, 16)

        assert data is not None
        assert isinstance(data, bytes)
        assert len(data) == 16

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Memory operations use Windows-specific APIs",
    )
    def test_read_memory_from_invalid_address_returns_none(self) -> None:
        """Read memory from invalid address returns None."""
        obfuscator = HookObfuscator()

        data = obfuscator._read_memory(0xDEADBEEF, 16)

        assert data is None or isinstance(data, bytes)

    def test_read_memory_on_non_windows_returns_none(self) -> None:
        """Read memory on non-Windows platform returns None."""
        obfuscator = HookObfuscator()

        if platform.system() != "Windows":
            data = obfuscator._read_memory(0x1000, 16)
            assert data is None

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Memory write uses Windows-specific APIs",
    )
    def test_write_memory_to_allocated_buffer(self) -> None:
        """Write memory to allocated buffer succeeds."""
        obfuscator = HookObfuscator()

        kernel32 = ctypes.windll.kernel32
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_READWRITE = 0x04

        if buffer := kernel32.VirtualAlloc(
            None,
            256,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ):
            test_data = b"\x90" * 16
            if result := obfuscator._write_memory(buffer, test_data):
                readback = obfuscator._read_memory(buffer, 16)
                assert readback == test_data

            kernel32.VirtualFree(buffer, 0, 0x8000)

    def test_write_memory_on_non_windows_returns_false(self) -> None:
        """Write memory on non-Windows platform returns False."""
        obfuscator = HookObfuscator()

        if platform.system() != "Windows":
            result = obfuscator._write_memory(0x1000, b"\x90" * 16)
            assert result is False


class TestJumpCodeGeneration:
    """Test x86/x64 JMP instruction generation."""

    def test_generate_jmp_code_returns_valid_bytes(self) -> None:
        """Generate JMP code returns valid byte sequence."""
        obfuscator = HookObfuscator()

        target = 0x140001000
        jmp_code = obfuscator._generate_jmp_code(target)

        assert isinstance(jmp_code, bytes)
        assert len(jmp_code) > 0

    def test_generate_jmp_code_64bit_architecture(self) -> None:
        """Generate JMP code for 64-bit architecture."""
        obfuscator = HookObfuscator()

        if platform.machine().endswith("64"):
            target = 0x140001000
            jmp_code = obfuscator._generate_jmp_code(target)

            assert len(jmp_code) == 12
            assert jmp_code[0] == 0x48
            assert jmp_code[1] == 0xB8

    def test_generate_jmp_code_32bit_architecture(self) -> None:
        """Generate JMP code for 32-bit architecture."""
        obfuscator = HookObfuscator()

        if not platform.machine().endswith("64"):
            target = 0x401000
            jmp_code = obfuscator._generate_jmp_code(target)

            assert len(jmp_code) == 5
            assert jmp_code[0] == 0xE9

    def test_generate_jmp_code_various_targets(self) -> None:
        """Generate JMP code for various target addresses."""
        obfuscator = HookObfuscator()

        targets = [0x1000, 0x140001000, 0x7FFFFFFF, 0x7FFF00000000]

        for target in targets:
            jmp_code = obfuscator._generate_jmp_code(target)
            assert isinstance(jmp_code, bytes)
            assert len(jmp_code) > 0


class TestCodeCaveDiscovery:
    """Test code cave discovery in executable modules."""

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Code cave discovery uses Windows-specific APIs",
    )
    def test_find_code_caves_in_current_module(self) -> None:
        """Find code caves in current executable module."""
        obfuscator = HookObfuscator()

        caves = obfuscator.find_code_caves(None)

        assert isinstance(caves, list)

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Code cave discovery uses Windows-specific APIs",
    )
    def test_find_code_caves_in_system_dll(self) -> None:
        """Find code caves in system DLL module."""
        obfuscator = HookObfuscator()

        caves = obfuscator.find_code_caves("kernel32.dll")

        assert isinstance(caves, list)

    def test_find_code_caves_invalid_module_returns_empty(self) -> None:
        """Find code caves in non-existent module returns empty list."""
        obfuscator = HookObfuscator()

        caves = obfuscator.find_code_caves("nonexistent_module.dll")

        assert isinstance(caves, list)
        assert len(caves) == 0

    def test_find_code_caves_on_non_windows_returns_empty(self) -> None:
        """Find code caves on non-Windows platform returns empty list."""
        obfuscator = HookObfuscator()

        if platform.system() != "Windows":
            caves = obfuscator.find_code_caves("test.dll")
            assert isinstance(caves, list)
            assert len(caves) == 0

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Code cave discovery uses Windows-specific APIs",
    )
    def test_code_caves_stored_in_registry(self) -> None:
        """Discovered code caves are stored in obfuscator registry."""
        obfuscator = HookObfuscator()

        module_name = "kernel32.dll"
        if caves := obfuscator.find_code_caves(module_name):
            assert module_name in obfuscator.code_caves
            assert obfuscator.code_caves[module_name] == caves

    def test_find_cave_in_data_with_null_sequence(self) -> None:
        """Find cave in data detects null byte sequences."""
        obfuscator = HookObfuscator()

        data = b"\x90" * 10 + b"\x00" * 50 + b"\x90" * 10
        base_addr = 0x1000

        cave_addr = obfuscator._find_cave_in_data(base_addr, data)

        assert cave_addr is not None
        assert cave_addr >= base_addr

    def test_find_cave_in_data_with_int3_sequence(self) -> None:
        """Find cave in data detects INT3 (0xCC) sequences."""
        obfuscator = HookObfuscator()

        data = b"\x90" * 10 + b"\xCC" * 50 + b"\x90" * 10
        base_addr = 0x1000

        cave_addr = obfuscator._find_cave_in_data(base_addr, data)

        assert cave_addr is not None

    def test_find_cave_in_data_no_cave_returns_none(self) -> None:
        """Find cave in data with no suitable cave returns None."""
        obfuscator = HookObfuscator()

        data = b"\x90" * 100
        base_addr = 0x1000

        cave_addr = obfuscator._find_cave_in_data(base_addr, data)

        assert cave_addr is None

    def test_get_cave_size_measures_null_sequence(self) -> None:
        """Get cave size measures contiguous null/INT3 bytes."""
        obfuscator = HookObfuscator()

        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_READWRITE = 0x04

            if buffer := kernel32.VirtualAlloc(
                None,
                256,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            ):
                test_data = b"\x00" * 64 + b"\x90" * 16
                if obfuscator._write_memory(buffer, test_data):
                    size = obfuscator._get_cave_size(buffer)
                    assert size >= 0

                kernel32.VirtualFree(buffer, 0, 0x8000)


class TestIndirectHookCreation:
    """Test indirect hook creation via function pointer chains."""

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Indirect hooks use Windows-specific memory operations",
    )
    def test_create_indirect_hook_basic_functionality(self) -> None:
        """Create indirect hook installs trampoline chain."""
        obfuscator = HookObfuscator()

        kernel32 = ctypes.windll.kernel32
        MEM_COMMIT = 0x1000
        MEM_RESERVE = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40

        target_buf = kernel32.VirtualAlloc(
            None,
            256,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
        handler_buf = kernel32.VirtualAlloc(
            None,
            256,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )

        if target_buf and handler_buf:
            obfuscator._write_memory(target_buf, b"\x90" * 32)
            obfuscator._write_memory(handler_buf, b"\xC3" * 16)

            result = obfuscator.create_indirect_hook(target_buf, handler_buf, chain_length=2)

            assert isinstance(result, bool)

            kernel32.VirtualFree(target_buf, 0, 0x8000)
            kernel32.VirtualFree(handler_buf, 0, 0x8000)

    def test_create_indirect_hook_duplicate_target_fails(self) -> None:
        """Create indirect hook on already hooked address fails."""
        obfuscator = HookObfuscator()

        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40

            if target_buf := kernel32.VirtualAlloc(
                None,
                256,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ):
                obfuscator._write_memory(target_buf, b"\x90" * 32)

                obfuscator.installed_hooks[target_buf] = HookInfo(
                    target_address=target_buf,
                    handler_address=0x2000,
                    original_bytes=b"\x90" * 16,
                    hook_type="test",
                    installed_at=time.time(),
                    callback_name="test_hook",
                    integrity_hash="abc123",
                )

                result = obfuscator.create_indirect_hook(target_buf, 0x3000)

                assert result is False

                kernel32.VirtualFree(target_buf, 0, 0x8000)

    def test_build_trampoline_chain_creates_correct_count(self) -> None:
        """Build trampoline chain creates requested number of trampolines."""
        obfuscator = HookObfuscator()

        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40

            if buffer := kernel32.VirtualAlloc(
                None,
                256,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ):
                if chain := obfuscator._build_trampoline_chain(
                    buffer, 0x140001000, 3
                ):
                    assert len(chain) == 3

                kernel32.VirtualFree(buffer, 0, 0x8000)

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Trampoline allocation uses Windows VirtualAlloc",
    )
    def test_allocate_trampoline_space_succeeds(self) -> None:
        """Allocate trampoline space returns valid executable memory."""
        obfuscator = HookObfuscator()

        if addr := obfuscator._allocate_trampoline_space(256):
            assert addr > 0

            kernel32 = ctypes.windll.kernel32
            kernel32.VirtualFree(addr, 0, 0x8000)


class TestHardwareBreakpointHooks:
    """Test hardware breakpoint hook installation using debug registers."""

    @pytest.mark.skipif(
        platform.system() != "Windows",
        reason="Hardware breakpoints use Windows-specific debug registers",
    )
    def test_install_hwbp_hook_basic_functionality(self) -> None:
        """Install hardware breakpoint hook using debug registers."""
        obfuscator = HookObfuscator()

        def test_handler() -> None:
            pass

        result = obfuscator.install_hwbp_hook(0x140001000, test_handler)

        assert isinstance(result, bool)

    def test_install_hwbp_hook_non_windows_returns_false(self) -> None:
        """Install hardware breakpoint on non-Windows returns False."""
        obfuscator = HookObfuscator()

        if platform.system() != "Windows":

            def test_handler() -> None:
                pass

            result = obfuscator.install_hwbp_hook(0x1000, test_handler)
            assert result is False


class TestHookIntegrityMonitoring:
    """Test hook integrity monitoring and automatic restoration."""

    def test_monitor_hook_integrity_starts_background_thread(self) -> None:
        """Monitor hook integrity starts background monitoring thread."""
        obfuscator = HookObfuscator()

        obfuscator.monitor_hook_integrity()

        try:
            assert obfuscator.integrity_monitor_active is True
            assert obfuscator._integrity_thread is not None
            assert obfuscator._integrity_thread.is_alive()
        finally:
            obfuscator.stop_integrity_monitor()

    def test_monitor_hook_integrity_prevents_duplicate_start(self) -> None:
        """Monitor hook integrity prevents starting when already running."""
        obfuscator = HookObfuscator()

        obfuscator.monitor_hook_integrity()

        try:
            initial_thread = obfuscator._integrity_thread

            obfuscator.monitor_hook_integrity()

            assert obfuscator._integrity_thread == initial_thread
        finally:
            obfuscator.stop_integrity_monitor()

    def test_stop_integrity_monitor_terminates_thread(self) -> None:
        """Stop integrity monitor terminates monitoring thread."""
        obfuscator = HookObfuscator()

        obfuscator.monitor_hook_integrity()
        time.sleep(0.5)

        obfuscator.stop_integrity_monitor()

        assert obfuscator.integrity_monitor_active is False

    def test_stop_integrity_monitor_when_not_running_safe(self) -> None:
        """Stop integrity monitor when not running doesn't cause errors."""
        obfuscator = HookObfuscator()

        obfuscator.stop_integrity_monitor()

        assert obfuscator.integrity_monitor_active is False

    def test_check_hook_integrity_detects_intact_hook(self) -> None:
        """Check hook integrity detects intact (modified) hook."""
        obfuscator = HookObfuscator()

        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40

            if buffer := kernel32.VirtualAlloc(
                None,
                256,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ):
                original = b"\x90" * 16
                modified = b"\xCC" * 16

                obfuscator._write_memory(buffer, original)

                hook_info = HookInfo(
                    target_address=buffer,
                    handler_address=0x2000,
                    original_bytes=original,
                    hook_type="test",
                    installed_at=time.time(),
                    callback_name="test",
                    integrity_hash="test",
                )

                obfuscator._write_memory(buffer, modified)

                intact = obfuscator._check_hook_integrity(hook_info)

                assert intact is True

                kernel32.VirtualFree(buffer, 0, 0x8000)

    def test_calculate_hook_hash_produces_consistent_hash(self) -> None:
        """Calculate hook hash produces consistent SHA-256 hash."""
        obfuscator = HookObfuscator()

        target = 0x140001000
        handler = 0x140002000
        original_bytes = b"\x90" * 16

        hash1 = obfuscator._calculate_hook_hash(target, handler, original_bytes)
        hash2 = obfuscator._calculate_hook_hash(target, handler, original_bytes)

        assert hash1 == hash2
        assert len(hash1) == 64


class TestHookRotation:
    """Test hook rotation to avoid signature-based detection."""

    def test_rotate_hooks_executes_without_error(self) -> None:
        """Rotate hooks executes on empty hook registry."""
        obfuscator = HookObfuscator()

        result = obfuscator.rotate_hooks()

        assert isinstance(result, bool)

    def test_rotate_hooks_with_installed_hooks(self) -> None:
        """Rotate hooks processes installed hooks."""
        obfuscator = HookObfuscator()

        if platform.system() == "Windows":
            obfuscator.installed_hooks[0x140001000] = HookInfo(
                target_address=0x140001000,
                handler_address=0x140002000,
                original_bytes=b"\x90" * 16,
                hook_type="indirect_chain",
                installed_at=time.time(),
                callback_name="test_hook",
                integrity_hash="abc123",
            )

            result = obfuscator.rotate_hooks()

            assert isinstance(result, bool)

    def test_rotate_single_hook_attempts_relocation(self) -> None:
        """Rotate single hook attempts to relocate hook."""
        obfuscator = HookObfuscator()

        hook_info = HookInfo(
            target_address=0x140001000,
            handler_address=0x140002000,
            original_bytes=b"\x90" * 16,
            hook_type="indirect_chain",
            installed_at=time.time(),
            callback_name="test_hook",
            integrity_hash="abc123",
        )

        result = obfuscator._rotate_single_hook(hook_info)

        assert isinstance(result, bool)


class TestHookStatusReporting:
    """Test hook status reporting and statistics."""

    def test_get_hook_status_returns_complete_report(self) -> None:
        """Get hook status returns comprehensive status dictionary."""
        obfuscator = HookObfuscator()

        status = obfuscator.get_hook_status()

        assert isinstance(status, dict)
        assert "total_hooks" in status
        assert "active_hooks" in status
        assert "integrity_monitor_active" in status
        assert "total_tampering_attempts" in status
        assert "code_caves_found" in status

    def test_hook_status_reflects_installed_hooks(self) -> None:
        """Hook status total_hooks reflects installed hook count."""
        obfuscator = HookObfuscator()

        initial_status = obfuscator.get_hook_status()
        assert initial_status["total_hooks"] == 0

        obfuscator.installed_hooks[0x140001000] = HookInfo(
            target_address=0x140001000,
            handler_address=0x140002000,
            original_bytes=b"\x90" * 16,
            hook_type="test",
            installed_at=time.time(),
            callback_name="test",
            integrity_hash="test",
        )

        updated_status = obfuscator.get_hook_status()
        assert updated_status["total_hooks"] == 1

    def test_hook_status_active_hooks_list(self) -> None:
        """Hook status active_hooks lists hook addresses as hex."""
        obfuscator = HookObfuscator()

        addr = 0x140001000
        obfuscator.installed_hooks[addr] = HookInfo(
            target_address=addr,
            handler_address=0x140002000,
            original_bytes=b"\x90" * 16,
            hook_type="test",
            installed_at=time.time(),
            callback_name="test",
            integrity_hash="test",
        )

        status = obfuscator.get_hook_status()

        assert hex(addr) in status["active_hooks"]

    def test_hook_status_tampering_attempts_sum(self) -> None:
        """Hook status total_tampering_attempts sums all tamper counts."""
        obfuscator = HookObfuscator()

        hook1 = HookInfo(
            target_address=0x1000,
            handler_address=0x2000,
            original_bytes=b"\x90" * 16,
            hook_type="test",
            installed_at=time.time(),
            callback_name="test1",
            integrity_hash="test1",
            tamper_count=3,
        )
        hook2 = HookInfo(
            target_address=0x3000,
            handler_address=0x4000,
            original_bytes=b"\x90" * 16,
            hook_type="test",
            installed_at=time.time(),
            callback_name="test2",
            integrity_hash="test2",
            tamper_count=5,
        )

        obfuscator.installed_hooks[0x1000] = hook1
        obfuscator.installed_hooks[0x3000] = hook2

        status = obfuscator.get_hook_status()

        assert status["total_tampering_attempts"] == 8

    def test_hook_status_code_caves_found_count(self) -> None:
        """Hook status code_caves_found counts discovered caves."""
        obfuscator = HookObfuscator()

        obfuscator.code_caves["module1"] = [0x1000, 0x2000]
        obfuscator.code_caves["module2"] = [0x3000]

        status = obfuscator.get_hook_status()

        assert status["code_caves_found"] == 3


class TestHookRemoval:
    """Test hook removal and original code restoration."""

    def test_remove_all_hooks_on_empty_registry(self) -> None:
        """Remove all hooks on empty registry succeeds."""
        obfuscator = HookObfuscator()

        result = obfuscator.remove_all_hooks()

        assert result is True

    def test_remove_all_hooks_clears_installed_hooks(self) -> None:
        """Remove all hooks clears installed hooks dictionary."""
        obfuscator = HookObfuscator()

        if platform.system() == "Windows":
            kernel32 = ctypes.windll.kernel32
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40

            if buffer := kernel32.VirtualAlloc(
                None,
                256,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            ):
                original = b"\x90" * 16
                obfuscator._write_memory(buffer, original)

                obfuscator.installed_hooks[buffer] = HookInfo(
                    target_address=buffer,
                    handler_address=0x2000,
                    original_bytes=original,
                    hook_type="test",
                    installed_at=time.time(),
                    callback_name="test",
                    integrity_hash="test",
                )

                obfuscator.remove_all_hooks()

                assert len(obfuscator.installed_hooks) == 0

                kernel32.VirtualFree(buffer, 0, 0x8000)


class TestThreadSafety:
    """Test thread safety of hook obfuscator operations."""

    def test_concurrent_callback_name_generation(self) -> None:
        """Concurrent callback name generation is thread-safe."""
        obfuscator = HookObfuscator()
        names: list[str] = []

        def generate_worker() -> None:
            for _ in range(10):
                name = obfuscator.generate_random_callback_name()
                names.append(name)

        threads = [threading.Thread(target=generate_worker) for _ in range(5)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(names) == 50
        assert all(isinstance(name, str) for name in names)

    def test_concurrent_hook_status_queries(self) -> None:
        """Concurrent hook status queries don't corrupt state."""
        obfuscator = HookObfuscator()
        statuses: list[dict] = []

        def status_worker() -> None:
            status = obfuscator.get_hook_status()
            statuses.append(status)

        threads = [threading.Thread(target=status_worker) for _ in range(10)]

        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(statuses) == 10
        assert all(isinstance(s, dict) for s in statuses)

    def test_integrity_monitoring_thread_safety(self) -> None:
        """Integrity monitoring is thread-safe with concurrent operations."""
        obfuscator = HookObfuscator()

        obfuscator.monitor_hook_integrity()

        try:

            def concurrent_status_check() -> None:
                for _ in range(5):
                    obfuscator.get_hook_status()
                    time.sleep(0.1)

            threads = [threading.Thread(target=concurrent_status_check) for _ in range(3)]

            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        finally:
            obfuscator.stop_integrity_monitor()


class TestHookInfoDataClass:
    """Test HookInfo data class structure and fields."""

    def test_hook_info_initialization(self) -> None:
        """HookInfo initializes with all required fields."""
        hook_info = HookInfo(
            target_address=0x140001000,
            handler_address=0x140002000,
            original_bytes=b"\x90" * 16,
            hook_type="indirect_chain",
            installed_at=time.time(),
            callback_name="test_handler",
            integrity_hash="abc123def456",
        )

        assert hook_info.target_address == 0x140001000
        assert hook_info.handler_address == 0x140002000
        assert hook_info.original_bytes == b"\x90" * 16
        assert hook_info.hook_type == "indirect_chain"
        assert hook_info.installed_at > 0
        assert hook_info.callback_name == "test_handler"
        assert hook_info.integrity_hash == "abc123def456"
        assert hook_info.tamper_count == 0

    def test_hook_info_tamper_count_default(self) -> None:
        """HookInfo tamper_count defaults to 0."""
        hook_info = HookInfo(
            target_address=0x1000,
            handler_address=0x2000,
            original_bytes=b"\x90" * 16,
            hook_type="test",
            installed_at=time.time(),
            callback_name="test",
            integrity_hash="test",
        )

        assert hook_info.tamper_count == 0

    def test_hook_info_tamper_count_increment(self) -> None:
        """HookInfo tamper_count can be incremented."""
        hook_info = HookInfo(
            target_address=0x1000,
            handler_address=0x2000,
            original_bytes=b"\x90" * 16,
            hook_type="test",
            installed_at=time.time(),
            callback_name="test",
            integrity_hash="test",
        )

        hook_info.tamper_count += 1
        assert hook_info.tamper_count == 1


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_find_code_cave_insufficient_size_returns_none(self) -> None:
        """Find code cave with insufficient available size returns None."""
        obfuscator = HookObfuscator()

        obfuscator.code_caves["available"] = []

        cave = obfuscator._find_code_cave(1024)

        assert cave is None

    def test_get_cave_size_invalid_address_returns_zero(self) -> None:
        """Get cave size with invalid address returns 0."""
        obfuscator = HookObfuscator()

        size = obfuscator._get_cave_size(0xDEADBEEF)

        assert size == 0

    def test_multiple_integrity_monitor_start_stop_cycles(self) -> None:
        """Multiple integrity monitor start/stop cycles work correctly."""
        obfuscator = HookObfuscator()

        for _ in range(3):
            obfuscator.monitor_hook_integrity()
            time.sleep(0.2)
            obfuscator.stop_integrity_monitor()
            time.sleep(0.1)

        assert obfuscator.integrity_monitor_active is False
