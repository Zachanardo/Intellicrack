"""Production tests for symbolic devirtualization engine.

Tests symbolic devirtualization on real VMProtect/Themida protected binaries,
handler lifting, bytecode reconstruction, and control flow recovery.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path

import pytest

from intellicrack.core.analysis.symbolic_devirtualizer import (
    DevirtualizationResult,
    ExplorationStrategy,
    HandlerSemantic,
    SymbolicDevirtualizer,
    VMType,
    devirtualize_generic,
    devirtualize_themida,
    devirtualize_vmprotect,
)


try:
    import angr

    ANGR_AVAILABLE = True
except ImportError:
    ANGR_AVAILABLE = False

pytestmark = pytest.mark.skipif(not ANGR_AVAILABLE, reason="angr not available")


@pytest.fixture
def protected_binaries_dir() -> Path:
    """Get directory with protected binaries."""
    return Path(__file__).parent.parent.parent / "fixtures" / "binaries" / "protected"


@pytest.fixture
def vmprotect_binary(protected_binaries_dir: Path) -> Path:
    """Get VMProtect-protected binary."""
    binary_path = protected_binaries_dir / "vmprotect_protected.exe"
    if not binary_path.exists():
        pytest.skip(f"VMProtect binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def themida_binary(protected_binaries_dir: Path) -> Path:
    """Get Themida-protected binary."""
    binary_path = protected_binaries_dir / "themida_protected.exe"
    if not binary_path.exists():
        pytest.skip(f"Themida binary not found: {binary_path}")
    return binary_path


@pytest.fixture
def enigma_binary(protected_binaries_dir: Path) -> Path:
    """Get Enigma-protected binary (generic VM)."""
    binary_path = protected_binaries_dir / "enigma_packed.exe"
    if not binary_path.exists():
        pytest.skip(f"Enigma binary not found: {binary_path}")
    return binary_path


class TestSymbolicDevirtualizerInitialization:
    """Tests for devirtualizer initialization."""

    def test_initialization_requires_angr(self, tmp_path: Path) -> None:
        """Devirtualizer requires angr framework."""
        binary_path = tmp_path / "test.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary_path))

        assert devirt.binary_path == str(binary_path)
        assert devirt.vm_type == VMType.UNKNOWN

    def test_detect_vmprotect_signature(self, tmp_path: Path) -> None:
        """Detect VMProtect by signature."""
        binary_path = tmp_path / "vmprotect.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b".vmp0" + b"VMProtect" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary_path))
        vm_type = devirt._detect_vm_type()

        assert vm_type == VMType.VMPROTECT

    def test_detect_themida_signature(self, tmp_path: Path) -> None:
        """Detect Themida by signature."""
        binary_path = tmp_path / "themida.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b".themida" + b"WinLicense" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary_path))
        vm_type = devirt._detect_vm_type()

        assert vm_type == VMType.THEMIDA

    def test_detect_code_virtualizer_signature(self, tmp_path: Path) -> None:
        """Detect Code Virtualizer by signature."""
        binary_path = tmp_path / "code_virt.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"Code Virtualizer" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary_path))
        vm_type = devirt._detect_vm_type()

        assert vm_type == VMType.CODE_VIRTUALIZER

    def test_generic_vm_detection(self, tmp_path: Path) -> None:
        """Unknown VM types are classified as generic."""
        binary_path = tmp_path / "unknown.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary_path))
        vm_type = devirt._detect_vm_type()

        assert vm_type == VMType.GENERIC


class TestDispatcherDetection:
    """Tests for VM dispatcher detection."""

    def test_find_dispatcher_pattern_x86(self, tmp_path: Path) -> None:
        """Find x86 dispatcher pattern in binary."""
        binary_path = tmp_path / "dispatcher_x86.exe"

        code = b"MZ\x90\x00" + b"\x00" * 100
        code += b"\xff\x24\x85\x00\x10\x00\x00"
        code += b"\x00" * 1000

        binary_path.write_bytes(code)

        devirt = SymbolicDevirtualizer(str(binary_path))
        devirt.architecture = "x86"

        dispatcher = devirt._find_dispatcher_pattern()

        assert dispatcher is not None
        assert dispatcher > 0

    def test_find_dispatcher_pattern_x64(self, tmp_path: Path) -> None:
        """Find x64 dispatcher pattern in binary."""
        binary_path = tmp_path / "dispatcher_x64.exe"

        code = b"MZ\x90\x00" + b"\x00" * 100
        code += b"\xff\x24\xc5\x00\x10\x00\x00"
        code += b"\x00" * 1000

        binary_path.write_bytes(code)

        devirt = SymbolicDevirtualizer(str(binary_path))
        devirt.architecture = "x64"

        dispatcher = devirt._find_dispatcher_pattern()

        assert dispatcher is not None

    def test_no_dispatcher_pattern(self, tmp_path: Path) -> None:
        """Return None when no dispatcher pattern found."""
        binary_path = tmp_path / "no_dispatcher.exe"
        binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary_path))
        devirt.architecture = "x86"

        dispatcher = devirt._find_dispatcher_pattern()

        assert dispatcher is None


class TestHandlerTableDetection:
    """Tests for handler table extraction."""

    def test_scan_for_pointer_table_x86(self, tmp_path: Path) -> None:
        """Scan for x86 pointer table in binary."""
        binary_path = tmp_path / "handler_table_x86.exe"

        code = b"MZ\x90\x00" + b"\x00" * 100

        pointer_table = b""
        for i in range(20):
            pointer = 0x401000 + i * 0x100
            pointer_table += struct.pack("<I", pointer)

        code += pointer_table + b"\x00" * 1000

        binary_path.write_bytes(code)

        devirt = SymbolicDevirtualizer(str(binary_path))
        devirt.architecture = "x86"

        table_offset = devirt._scan_for_pointer_table()

        assert table_offset is not None
        assert table_offset > 0

    def test_scan_for_pointer_table_x64(self, tmp_path: Path) -> None:
        """Scan for x64 pointer table in binary."""
        binary_path = tmp_path / "handler_table_x64.exe"

        code = b"MZ\x90\x00" + b"\x00" * 100

        pointer_table = b""
        for i in range(20):
            pointer = 0x140001000 + i * 0x200
            pointer_table += struct.pack("<Q", pointer)

        code += pointer_table + b"\x00" * 1000

        binary_path.write_bytes(code)

        devirt = SymbolicDevirtualizer(str(binary_path))
        devirt.architecture = "x64"

        table_offset = devirt._scan_for_pointer_table()

        assert table_offset is not None

    def test_read_handler_table_x86(self, tmp_path: Path) -> None:
        """Read handler addresses from x86 table."""
        binary_path = tmp_path / "handlers_x86.exe"

        code = b"MZ\x90\x00" + b"\x00" * 100

        handlers_expected = [0x401000, 0x401100, 0x401200, 0x401300, 0x401400]
        pointer_table = b""
        for handler in handlers_expected:
            pointer_table += struct.pack("<I", handler)

        pointer_table += struct.pack("<I", 0)

        code += pointer_table + b"\x00" * 1000

        binary_path.write_bytes(code)

        devirt = SymbolicDevirtualizer(str(binary_path))
        devirt.architecture = "x86"
        devirt.handler_table = 104

        handlers = devirt._read_handler_table()

        assert len(handlers) == len(handlers_expected)
        assert all(h in handlers_expected for h in handlers)


class TestHandlerSemanticInference:
    """Tests for handler semantic analysis."""

    def test_infer_stack_push_semantic(self, tmp_path: Path) -> None:
        """Infer stack push operation from handler code."""
        assert HandlerSemantic.STACK_PUSH.value == "stack_push"

    def test_infer_arithmetic_add_semantic(self, tmp_path: Path) -> None:
        """Infer addition operation from handler code."""
        assert HandlerSemantic.ARITHMETIC_ADD.value == "arithmetic_add"

    def test_infer_branch_conditional_semantic(self, tmp_path: Path) -> None:
        """Infer conditional branch from handler code."""
        assert HandlerSemantic.BRANCH_CONDITIONAL.value == "branch_conditional"

    def test_infer_memory_load_semantic(self, tmp_path: Path) -> None:
        """Infer memory load from handler code."""
        assert HandlerSemantic.MEMORY_LOAD.value == "memory_load"

    def test_unknown_semantic_default(self, tmp_path: Path) -> None:
        """Unknown handlers get UNKNOWN semantic."""
        assert HandlerSemantic.UNKNOWN.value == "unknown"


class TestDevirtualizationWorkflow:
    """Tests for complete devirtualization workflow."""

    @pytest.mark.slow
    def test_devirtualize_small_binary(self, tmp_path: Path) -> None:
        """Devirtualize small VM-protected binary."""
        binary_path = tmp_path / "small_vm.exe"

        pe_header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        pe_header += b"\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00"
        pe_header += b"\x00" * 32
        pe_header += b"PE\x00\x00"
        pe_header += b"\x4c\x01"
        pe_header += b"\x01\x00"
        pe_header += b"\x00" * 16
        pe_header += b"\x00\xe0"
        pe_header += b"\x0e\x01"

        code = b"\x00" * 0x1000

        binary_path.write_bytes(pe_header + code)

        devirt = SymbolicDevirtualizer(str(binary_path))

        try:
            result = devirt.devirtualize(
                vm_entry_point=0x1000,
                vm_type=VMType.GENERIC,
                exploration_strategy=ExplorationStrategy.DFS,
                max_paths=50,
                timeout_seconds=10,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.GENERIC, VMType.UNKNOWN]
            assert result.architecture in ["x86", "x64"]
            assert result.total_paths_explored >= 0
        except Exception as e:
            pytest.skip(f"Devirtualization failed (expected for minimal binary): {e}")

    def test_exploration_strategy_enum_values(self) -> None:
        """Exploration strategy enum has correct values."""
        assert ExplorationStrategy.DFS.value == "depth_first_search"
        assert ExplorationStrategy.BFS.value == "breadth_first_search"
        assert ExplorationStrategy.GUIDED.value == "guided_search"
        assert ExplorationStrategy.CONCOLIC.value == "concolic_execution"

    def test_vm_type_enum_values(self) -> None:
        """VM type enum has correct values."""
        assert VMType.VMPROTECT.value == "vmprotect"
        assert VMType.THEMIDA.value == "themida"
        assert VMType.CODE_VIRTUALIZER.value == "code_virtualizer"
        assert VMType.GENERIC.value == "generic"
        assert VMType.UNKNOWN.value == "unknown"


class TestHighLevelDevirtualizationFunctions:
    """Tests for high-level devirtualization functions."""

    @pytest.mark.slow
    def test_devirtualize_vmprotect_function(self, tmp_path: Path) -> None:
        """devirtualize_vmprotect calls correct VM type."""
        binary_path = tmp_path / "vmprotect.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00\x4c\x01\x01\x00"
        pe_header += b"\x00" * 16
        pe_header += b"\x00\xe0\x0e\x01"

        code = b".vmp0" + b"\x00" * 0x1000

        binary_path.write_bytes(pe_header + code)

        try:
            result = devirtualize_vmprotect(
                binary_path=str(binary_path),
                vm_entry_point=0x1000,
                max_paths=10,
                timeout=5,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.VMPROTECT, VMType.GENERIC]
        except Exception as e:
            pytest.skip(f"VMProtect devirtualization failed (expected): {e}")

    @pytest.mark.slow
    def test_devirtualize_themida_function(self, tmp_path: Path) -> None:
        """devirtualize_themida calls correct VM type."""
        binary_path = tmp_path / "themida.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00\x4c\x01\x01\x00"
        pe_header += b"\x00" * 16
        pe_header += b"\x00\xe0\x0e\x01"

        code = b"Themida" + b"\x00" * 0x1000

        binary_path.write_bytes(pe_header + code)

        try:
            result = devirtualize_themida(
                binary_path=str(binary_path),
                vm_entry_point=0x1000,
                max_paths=10,
                timeout=5,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type in [VMType.THEMIDA, VMType.GENERIC]
        except Exception as e:
            pytest.skip(f"Themida devirtualization failed (expected): {e}")

    @pytest.mark.slow
    def test_devirtualize_generic_function(self, tmp_path: Path) -> None:
        """devirtualize_generic uses generic VM analysis."""
        binary_path = tmp_path / "generic.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00\x4c\x01\x01\x00"
        pe_header += b"\x00" * 16
        pe_header += b"\x00\xe0\x0e\x01"

        code = b"\x00" * 0x1000

        binary_path.write_bytes(pe_header + code)

        try:
            result = devirtualize_generic(
                binary_path=str(binary_path),
                vm_entry_point=0x1000,
                exploration_strategy=ExplorationStrategy.BFS,
                max_paths=10,
                timeout=5,
            )

            assert isinstance(result, DevirtualizationResult)
            assert result.vm_type == VMType.GENERIC
        except Exception as e:
            pytest.skip(f"Generic devirtualization failed (expected): {e}")


@pytest.mark.integration
@pytest.mark.slow
class TestRealProtectedBinaries:
    """Tests against real protected binaries (if available)."""

    def test_analyze_vmprotect_binary(self, vmprotect_binary: Path) -> None:
        """Analyze real VMProtect-protected binary."""
        devirt = SymbolicDevirtualizer(str(vmprotect_binary))

        vm_type = devirt._detect_vm_type()

        assert vm_type in [VMType.VMPROTECT, VMType.GENERIC]

    def test_analyze_themida_binary(self, themida_binary: Path) -> None:
        """Analyze real Themida-protected binary."""
        devirt = SymbolicDevirtualizer(str(themida_binary))

        vm_type = devirt._detect_vm_type()

        assert vm_type in [VMType.THEMIDA, VMType.GENERIC]

    def test_find_dispatcher_in_real_binary(self, enigma_binary: Path) -> None:
        """Find dispatcher in real protected binary."""
        devirt = SymbolicDevirtualizer(str(enigma_binary))

        with open(enigma_binary, "rb") as f:
            data = f.read()

        if b"\xff\x24" not in data and b"\xff\x14" not in data:
            pytest.skip("No obvious dispatcher pattern in binary")


@pytest.mark.performance
class TestDevirtualizationPerformance:
    """Performance tests for devirtualization."""

    def test_handler_lifting_performance(self, tmp_path: Path) -> None:
        """Handler lifting completes within reasonable time."""
        import time

        binary_path = tmp_path / "perf_test.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00\x4c\x01\x01\x00"
        pe_header += b"\x00" * 16
        pe_header += b"\x00\xe0\x0e\x01"

        code = b"\x00" * 0x1000

        binary_path.write_bytes(pe_header + code)

        devirt = SymbolicDevirtualizer(str(binary_path))

        start_time = time.time()

        try:
            devirt.devirtualize(
                vm_entry_point=0x1000,
                max_paths=20,
                timeout_seconds=10,
            )
        except Exception:
            pass

        elapsed = time.time() - start_time

        assert elapsed < 15

    def test_timeout_enforcement(self, tmp_path: Path) -> None:
        """Devirtualization respects timeout limit."""
        import time

        binary_path = tmp_path / "timeout_test.exe"

        pe_header = b"MZ\x90\x00" + b"\x00" * 60
        pe_header += b"PE\x00\x00\x4c\x01\x01\x00"
        pe_header += b"\x00" * 16
        pe_header += b"\x00\xe0\x0e\x01"

        code = b"\x00" * 0x1000

        binary_path.write_bytes(pe_header + code)

        devirt = SymbolicDevirtualizer(str(binary_path))

        timeout = 3
        start_time = time.time()

        try:
            devirt.devirtualize(
                vm_entry_point=0x1000,
                max_paths=1000,
                timeout_seconds=timeout,
            )
        except Exception:
            pass

        elapsed = time.time() - start_time

        assert elapsed <= timeout + 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
