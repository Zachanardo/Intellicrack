"""Tests for symbolic execution-based devirtualization engine."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from intellicrack.core.analysis.symbolic_devirtualizer import (
    SymbolicDevirtualizer,
    ExplorationStrategy,
    VMType,
    HandlerSemantic,
    DevirtualizationResult,
    devirtualize_vmprotect,
    devirtualize_themida,
    devirtualize_generic,
)


@pytest.fixture
def mock_binary_path(tmp_path):
    binary = tmp_path / "test_binary.exe"
    binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)
    return str(binary)


@pytest.fixture
def mock_angr_project():
    with patch('intellicrack.core.analysis.symbolic_devirtualizer.ANGR_AVAILABLE', True):
        with patch('intellicrack.core.analysis.symbolic_devirtualizer.angr') as mock_angr:
            mock_project = Mock()
            mock_project.arch.bits = 64
            mock_angr.Project.return_value = mock_project
            yield mock_project


class TestSymbolicDevirtualizer:
    def test_initialization_requires_angr(self, mock_binary_path):
        with patch('intellicrack.core.analysis.symbolic_devirtualizer.ANGR_AVAILABLE', False):
            with pytest.raises(ImportError, match="angr framework required"):
                SymbolicDevirtualizer(mock_binary_path)

    def test_initialization_with_angr(self, mock_binary_path, mock_angr_project):
        devirt = SymbolicDevirtualizer(mock_binary_path)
        assert devirt.binary_path == mock_binary_path
        assert devirt.vm_type == VMType.UNKNOWN
        assert devirt.architecture == "unknown"

    def test_detect_vm_type_vmprotect(self, mock_binary_path, mock_angr_project, tmp_path):
        binary = tmp_path / "vmprotect.exe"
        binary.write_bytes(b"MZ\x90\x00" + b".vmp0" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary))
        vm_type = devirt._detect_vm_type()
        assert vm_type == VMType.VMPROTECT

    def test_detect_vm_type_themida(self, mock_binary_path, mock_angr_project, tmp_path):
        binary = tmp_path / "themida.exe"
        binary.write_bytes(b"MZ\x90\x00" + b"Themida" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary))
        vm_type = devirt._detect_vm_type()
        assert vm_type == VMType.THEMIDA

    def test_find_dispatcher_pattern_x86(self, mock_binary_path, mock_angr_project, tmp_path):
        binary = tmp_path / "dispatcher.exe"
        binary.write_bytes(b"MZ\x90\x00" + b"\xff\x24\x85\x00\x00\x00\x00" + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary))
        devirt.architecture = "x86"
        dispatcher = devirt._find_dispatcher_pattern()
        assert dispatcher is not None

    def test_scan_for_pointer_table(self, mock_binary_path, mock_angr_project, tmp_path):
        binary = tmp_path / "handler_table.exe"

        pointer_table = b""
        for i in range(20):
            pointer_table += (0x401000 + i * 0x100).to_bytes(4, 'little')

        binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100 + pointer_table + b"\x00" * 1000)

        devirt = SymbolicDevirtualizer(str(binary))
        devirt.architecture = "x86"
        table_offset = devirt._scan_for_pointer_table()
        assert table_offset is not None

    @patch('intellicrack.core.analysis.symbolic_devirtualizer.angr')
    def test_lift_handler_symbolic(self, mock_angr, mock_binary_path, mock_angr_project):
        devirt = SymbolicDevirtualizer(mock_binary_path)
        devirt.project = mock_angr_project

        mock_state = Mock()
        mock_state.registers.load = Mock(return_value=Mock(symbolic=True))
        mock_state.solver.constraints = []

        mock_simgr = Mock()
        mock_simgr.active = []
        mock_simgr.deadended = [mock_state]

        mock_angr_project.factory.call_state.return_value = mock_state
        mock_angr_project.factory.simgr.return_value = mock_simgr
        mock_angr_project.arch.register_names = {0: 'eax', 1: 'ebx'}

        mock_block = Mock()
        mock_block.capstone.insns = [Mock(mnemonic='push', op_str='eax')]
        mock_angr_project.factory.block.return_value = mock_block

        handler = devirt._lift_handler_symbolic(0x401000)

        assert handler is not None
        assert handler.semantic == HandlerSemantic.STACK_PUSH

    def test_infer_handler_semantic_push(self, mock_binary_path, mock_angr_project):
        devirt = SymbolicDevirtualizer(mock_binary_path)
        devirt.project = mock_angr_project

        mock_insn = Mock()
        mock_insn.mnemonic = 'push'
        mock_block = Mock()
        mock_block.capstone.insns = [mock_insn]
        mock_angr_project.factory.block.return_value = mock_block

        semantic = devirt._infer_handler_semantic(0x401000, [], [])
        assert semantic == HandlerSemantic.STACK_PUSH

    def test_infer_handler_semantic_add(self, mock_binary_path, mock_angr_project):
        devirt = SymbolicDevirtualizer(mock_binary_path)
        devirt.project = mock_angr_project

        mock_insn = Mock()
        mock_insn.mnemonic = 'add'
        mock_block = Mock()
        mock_block.capstone.insns = [mock_insn]
        mock_angr_project.factory.block.return_value = mock_block

        semantic = devirt._infer_handler_semantic(0x401000, [], [])
        assert semantic == HandlerSemantic.ARITHMETIC_ADD

    def test_translate_handler_to_native(self, mock_binary_path, mock_angr_project):
        devirt = SymbolicDevirtualizer(mock_binary_path)
        devirt.project = mock_angr_project

        native_code, assembly = devirt._translate_handler_to_native(
            0x401000,
            HandlerSemantic.STACK_PUSH,
            []
        )

        assert native_code == b'\x50'
        assert assembly == ["push eax"]

    def test_calculate_handler_confidence(self, mock_binary_path, mock_angr_project):
        devirt = SymbolicDevirtualizer(mock_binary_path)

        confidence = devirt._calculate_handler_confidence(
            HandlerSemantic.ARITHMETIC_ADD,
            [('reg_eax', Mock())],
            [Mock()],
            b'\x01\xd8'
        )

        assert confidence > 50.0
        assert confidence <= 100.0

    @patch('intellicrack.core.analysis.symbolic_devirtualizer.angr')
    def test_devirtualize_integration(self, mock_angr, mock_binary_path, mock_angr_project):
        mock_angr.Project.return_value = mock_angr_project
        mock_angr.options.SYMBOLIC = 'symbolic'
        mock_angr.options.TRACK_CONSTRAINTS = 'track_constraints'
        mock_angr.options.SYMBOLIC_WRITE_ADDRESSES = 'symbolic_write'

        devirt = SymbolicDevirtualizer(mock_binary_path)
        devirt.vm_dispatcher = 0x401000
        devirt.handler_table = 0x402000

        mock_state = Mock()
        mock_state.addr = 0x403000
        mock_state.history.bbl_addrs = [0x401000, 0x402000]
        mock_state.history.depth = 1

        mock_simgr = Mock()
        mock_simgr.active = []
        mock_simgr.deadended = [mock_state]
        mock_simgr.found = []
        mock_angr_project.factory.call_state.return_value = mock_state
        mock_angr_project.factory.simgr.return_value = mock_simgr

        with patch.object(devirt, '_extract_handler_addresses', return_value=[]):
            with patch.object(devirt, '_detect_vm_type', return_value=VMType.GENERIC):
                with patch.object(devirt, '_find_dispatcher_symbolic', return_value=0x401000):
                    with patch.object(devirt, '_find_handler_table_symbolic', return_value=0x402000):
                        result = devirt.devirtualize(
                            0x401000,
                            exploration_strategy=ExplorationStrategy.DFS,
                            max_paths=10,
                            timeout_seconds=5
                        )

        assert isinstance(result, DevirtualizationResult)
        assert result.vm_entry_point == 0x401000
        assert result.architecture in ["x86", "x64"]


class TestExplorationStrategies:
    def test_exploration_strategies_enum(self):
        assert ExplorationStrategy.DFS.value == "depth_first_search"
        assert ExplorationStrategy.BFS.value == "breadth_first_search"
        assert ExplorationStrategy.GUIDED.value == "guided_search"
        assert ExplorationStrategy.CONCOLIC.value == "concolic_execution"


class TestVMTypeDetection:
    def test_vm_types_enum(self):
        assert VMType.VMPROTECT.value == "vmprotect"
        assert VMType.THEMIDA.value == "themida"
        assert VMType.CODE_VIRTUALIZER.value == "code_virtualizer"
        assert VMType.GENERIC.value == "generic"
        assert VMType.UNKNOWN.value == "unknown"


class TestHandlerSemantics:
    def test_handler_semantic_enum(self):
        assert HandlerSemantic.STACK_PUSH.value == "stack_push"
        assert HandlerSemantic.ARITHMETIC_ADD.value == "arithmetic_add"
        assert HandlerSemantic.BRANCH_CONDITIONAL.value == "branch_conditional"


class TestConvenienceFunctions:
    @patch('intellicrack.core.analysis.symbolic_devirtualizer.SymbolicDevirtualizer')
    def test_devirtualize_vmprotect(self, mock_devirt_class, mock_binary_path):
        mock_instance = Mock()
        mock_result = Mock(spec=DevirtualizationResult)
        mock_instance.devirtualize.return_value = mock_result
        mock_devirt_class.return_value = mock_instance

        result = devirtualize_vmprotect(mock_binary_path, 0x401000)

        mock_devirt_class.assert_called_once_with(mock_binary_path)
        mock_instance.devirtualize.assert_called_once_with(
            0x401000,
            VMType.VMPROTECT,
            ExplorationStrategy.GUIDED,
            500,
            300
        )
        assert result == mock_result

    @patch('intellicrack.core.analysis.symbolic_devirtualizer.SymbolicDevirtualizer')
    def test_devirtualize_themida(self, mock_devirt_class, mock_binary_path):
        mock_instance = Mock()
        mock_result = Mock(spec=DevirtualizationResult)
        mock_instance.devirtualize.return_value = mock_result
        mock_devirt_class.return_value = mock_instance

        result = devirtualize_themida(mock_binary_path, 0x401000, max_paths=100)

        mock_devirt_class.assert_called_once_with(mock_binary_path)
        mock_instance.devirtualize.assert_called_once_with(
            0x401000,
            VMType.THEMIDA,
            ExplorationStrategy.GUIDED,
            100,
            300
        )
        assert result == mock_result

    @patch('intellicrack.core.analysis.symbolic_devirtualizer.SymbolicDevirtualizer')
    def test_devirtualize_generic(self, mock_devirt_class, mock_binary_path):
        mock_instance = Mock()
        mock_result = Mock(spec=DevirtualizationResult)
        mock_instance.devirtualize.return_value = mock_result
        mock_devirt_class.return_value = mock_instance

        result = devirtualize_generic(
            mock_binary_path,
            0x401000,
            exploration_strategy=ExplorationStrategy.BFS,
            max_paths=200,
            timeout=600
        )

        mock_devirt_class.assert_called_once_with(mock_binary_path)
        mock_instance.devirtualize.assert_called_once_with(
            0x401000,
            VMType.GENERIC,
            ExplorationStrategy.BFS,
            200,
            600
        )
        assert result == mock_result
