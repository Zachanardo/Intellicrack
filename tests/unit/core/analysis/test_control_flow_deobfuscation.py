"""Unit tests for control flow deobfuscation engine.

Tests the comprehensive control flow deobfuscation capabilities including:
- Dispatcher detection
- Control flow unflattening
- Opaque predicate detection and removal
- Bogus block detection
- CFG recovery and patching

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

try:
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False

from intellicrack.core.analysis.control_flow_deobfuscation import (
    BasicBlock,
    ControlFlowDeobfuscator,
    DeobfuscationResult,
    DispatcherInfo,
)


class TestBasicBlock(unittest.TestCase):
    """Test BasicBlock dataclass."""

    def test_basic_block_creation(self):
        """Test creating a basic block."""
        block = BasicBlock(
            address=0x401000,
            size=20,
            instructions=[{"disasm": "mov eax, ebx"}],
            successors=[0x401014],
            predecessors=[],
            block_type="sequential",
        )

        self.assertEqual(block.address, 0x401000)
        self.assertEqual(block.size, 20)
        self.assertEqual(len(block.instructions), 1)
        self.assertEqual(len(block.successors), 1)
        self.assertFalse(block.is_dispatcher)
        self.assertEqual(block.state_variable_refs, [])

    def test_dispatcher_block_flags(self):
        """Test dispatcher-specific flags."""
        block = BasicBlock(
            address=0x401000,
            size=50,
            instructions=[],
            successors=[0x401100, 0x401200, 0x401300],
            predecessors=[],
            block_type="branch",
            is_dispatcher=True,
        )

        self.assertTrue(block.is_dispatcher)
        self.assertEqual(len(block.successors), 3)


class TestDispatcherInfo(unittest.TestCase):
    """Test DispatcherInfo dataclass."""

    def test_dispatcher_info_creation(self):
        """Test creating dispatcher information."""
        dispatcher = DispatcherInfo(
            dispatcher_address=0x401000,
            state_variable_location=0x403000,
            state_variable_type="global",
            controlled_blocks=[0x401100, 0x401200, 0x401300],
            case_mappings={0: 0x401100, 1: 0x401200, 2: 0x401300},
            switch_type="OLLVM",
        )

        self.assertEqual(dispatcher.dispatcher_address, 0x401000)
        self.assertEqual(dispatcher.state_variable_type, "global")
        self.assertEqual(len(dispatcher.controlled_blocks), 3)
        self.assertEqual(len(dispatcher.case_mappings), 3)
        self.assertEqual(dispatcher.switch_type, "OLLVM")


@unittest.skipIf(not NETWORKX_AVAILABLE, "NetworkX not available")
class TestControlFlowDeobfuscator(unittest.TestCase):
    """Test ControlFlowDeobfuscator class."""

    def setUp(self):
        """Set up test fixtures."""
        self.test_binary = Path("test_binary.exe")

    @patch("intellicrack.core.analysis.control_flow_deobfuscation.lief")
    def test_initialization(self, mock_lief):
        """Test deobfuscator initialization."""
        with patch.object(Path, "exists", return_value=True):
            mock_binary = Mock()
            mock_binary.header.machine_type = "IMAGE_FILE_MACHINE_AMD64"
            mock_lief.parse.return_value = mock_binary

            deobf = ControlFlowDeobfuscator(self.test_binary)

            self.assertEqual(deobf.binary_path, self.test_binary)
            self.assertEqual(deobf.architecture, "x86_64")

    @patch("intellicrack.core.analysis.control_flow_deobfuscation.lief")
    def test_initialization_file_not_found(self, mock_lief):
        """Test initialization with non-existent file."""
        with self.assertRaises(FileNotFoundError):
            ControlFlowDeobfuscator(Path("nonexistent.exe"))

    def test_classify_block(self):
        """Test basic block classification."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                ret_block = [{"disasm": "ret"}]
                self.assertEqual(deobf._classify_block(ret_block), "return")

                call_block = [{"disasm": "call sub_401000"}]
                self.assertEqual(deobf._classify_block(call_block), "call")

                jmp_block = [{"disasm": "jmp 0x401000"}]
                self.assertEqual(deobf._classify_block(jmp_block), "branch")

                seq_block = [{"disasm": "mov eax, ebx"}]
                self.assertEqual(deobf._classify_block(seq_block), "sequential")

                empty_block = []
                self.assertEqual(deobf._classify_block(empty_block), "empty")

    def test_calculate_block_complexity(self):
        """Test block complexity calculation."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                simple_block = [{"disasm": "mov eax, ebx"}, {"disasm": "add eax, 1"}]
                complexity = deobf._calculate_block_complexity(simple_block)
                self.assertEqual(complexity, 2.0)

                call_block = [{"disasm": "call sub_401000"}]
                complexity = deobf._calculate_block_complexity(call_block)
                self.assertGreater(complexity, 1.0)

                complex_block = [
                    {"disasm": "call sub_401000"},
                    {"disasm": "je 0x401100"},
                    {"disasm": "mul eax"},
                ]
                complexity = deobf._calculate_block_complexity(complex_block)
                self.assertGreater(complexity, 5.0)

    def test_is_terminator_block(self):
        """Test terminator block detection."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                ret_block = [{"disasm": "mov eax, 0", "offset": 0}, {"disasm": "ret", "offset": 2}]
                self.assertTrue(deobf._is_terminator_block(ret_block))

                jmp_block = [{"disasm": "jmp 0x401000", "offset": 0}]
                self.assertFalse(deobf._is_terminator_block(jmp_block))

                normal_block = [{"disasm": "mov eax, ebx", "offset": 0}]
                self.assertFalse(deobf._is_terminator_block(normal_block))

                empty_block = []
                self.assertFalse(deobf._is_terminator_block(empty_block))

    def test_is_dispatcher_block(self):
        """Test dispatcher block detection."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                cfg = nx.DiGraph()

                dispatcher_block = BasicBlock(
                    address=0x401000,
                    size=50,
                    instructions=[
                        {"disasm": "cmp eax, 10"},
                        {"disasm": "jmp [rax*4 + 0x403000]"},
                    ],
                    successors=[0x401100, 0x401200, 0x401300, 0x401400, 0x401500],
                    predecessors=[0x401100, 0x401200, 0x401300],
                    block_type="branch",
                )

                self.assertTrue(deobf._is_dispatcher_block(dispatcher_block, cfg))

                normal_block = BasicBlock(
                    address=0x401100,
                    size=20,
                    instructions=[{"disasm": "mov eax, ebx"}],
                    successors=[0x401120],
                    predecessors=[0x401000],
                    block_type="sequential",
                )

                self.assertFalse(deobf._is_dispatcher_block(normal_block, cfg))

    def test_extract_state_assignment(self):
        """Test state variable assignment extraction."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                dispatcher = DispatcherInfo(
                    dispatcher_address=0x401000,
                    state_variable_location=0x403000,
                    state_variable_type="global",
                    controlled_blocks=[],
                    case_mappings={},
                    switch_type="OLLVM",
                )

                block_with_assignment = BasicBlock(
                    address=0x401100,
                    size=20,
                    instructions=[
                        {"disasm": "mov eax, 5", "offset": 0x401100},
                        {"disasm": "mov [rbp-8], 0x42", "offset": 0x401103},
                    ],
                    successors=[],
                    predecessors=[],
                    block_type="sequential",
                )

                result = deobf._extract_state_assignment(block_with_assignment, dispatcher)
                self.assertIsNotNone(result)

                block_without_assignment = BasicBlock(
                    address=0x401200,
                    size=10,
                    instructions=[{"disasm": "add eax, ebx", "offset": 0x401200}],
                    successors=[],
                    predecessors=[],
                    block_type="sequential",
                )

                result = deobf._extract_state_assignment(block_without_assignment, dispatcher)
                self.assertIsNone(result)

    def test_classify_dispatcher_type(self):
        """Test dispatcher type classification."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                ollvm_block = BasicBlock(
                    address=0x401000,
                    size=100,
                    instructions=[
                        {"disasm": "cmovne eax, ebx"},
                        {"disasm": "cmovg ecx, edx"},
                    ],
                    successors=[i for i in range(0x401100, 0x401200, 10)],
                    predecessors=[],
                    block_type="branch",
                )
                self.assertEqual(deobf._classify_dispatcher_type(ollvm_block), "OLLVM")

                tigress_block = BasicBlock(
                    address=0x402000,
                    size=50,
                    instructions=[{"disasm": "switch (eax)"}],
                    successors=[0x402100, 0x402200],
                    predecessors=[],
                    block_type="branch",
                )
                self.assertEqual(deobf._classify_dispatcher_type(tigress_block), "Tigress")

                vmprotect_block = BasicBlock(
                    address=0x403000,
                    size=200,
                    instructions=[{"disasm": "jmp [rax*4]"}],
                    successors=[i for i in range(0x403100, 0x403300, 8)],
                    predecessors=[],
                    block_type="branch",
                )
                self.assertEqual(deobf._classify_dispatcher_type(vmprotect_block), "VMProtect")

    def test_calculate_deobfuscation_metrics(self):
        """Test deobfuscation metrics calculation."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                original_cfg = nx.DiGraph()
                for i in range(10):
                    original_cfg.add_node(0x401000 + i * 0x10)
                for i in range(9):
                    original_cfg.add_edge(0x401000 + i * 0x10, 0x401000 + (i + 1) * 0x10)

                deobf_cfg = nx.DiGraph()
                for i in range(5):
                    deobf_cfg.add_node(0x401000 + i * 0x10)
                for i in range(4):
                    deobf_cfg.add_edge(0x401000 + i * 0x10, 0x401000 + (i + 1) * 0x10)

                metrics = deobf._calculate_deobfuscation_metrics(original_cfg, deobf_cfg)

                self.assertEqual(metrics["original_blocks"], 10)
                self.assertEqual(metrics["deobfuscated_blocks"], 5)
                self.assertEqual(metrics["blocks_removed"], 5)
                self.assertEqual(metrics["original_edges"], 9)
                self.assertEqual(metrics["deobfuscated_edges"], 4)
                self.assertIn("complexity_reduction", metrics)

    def test_calculate_confidence_score(self):
        """Test confidence score calculation."""
        with patch.object(Path, "exists", return_value=True):
            with patch("intellicrack.core.analysis.control_flow_deobfuscation.lief"):
                deobf = ControlFlowDeobfuscator(self.test_binary)

                dispatchers = [
                    DispatcherInfo(
                        dispatcher_address=0x401000,
                        state_variable_location=0x403000,
                        state_variable_type="global",
                        controlled_blocks=[],
                        case_mappings={},
                        switch_type="OLLVM",
                    )
                ]
                opaque_predicates = [{"address": 0x401100, "type": "self_comparison"}]
                bogus_blocks = [0x401200, 0x401300]
                metrics = {
                    "original_blocks": 10,
                    "deobfuscated_blocks": 5,
                    "blocks_removed": 5,
                }

                confidence = deobf._calculate_confidence_score(
                    dispatchers, opaque_predicates, bogus_blocks, metrics
                )

                self.assertGreater(confidence, 0.0)
                self.assertLessEqual(confidence, 1.0)

                no_findings_confidence = deobf._calculate_confidence_score([], [], [], {})
                self.assertEqual(no_findings_confidence, 0.0)


class TestDeobfuscationResult(unittest.TestCase):
    """Test DeobfuscationResult dataclass."""

    @unittest.skipIf(not NETWORKX_AVAILABLE, "NetworkX not available")
    def test_result_creation(self):
        """Test creating a deobfuscation result."""
        original_cfg = nx.DiGraph()
        original_cfg.add_edge(0x401000, 0x401010)

        deobf_cfg = nx.DiGraph()
        deobf_cfg.add_edge(0x401000, 0x401020)

        dispatcher = DispatcherInfo(
            dispatcher_address=0x401000,
            state_variable_location=0x403000,
            state_variable_type="stack",
            controlled_blocks=[0x401010, 0x401020],
            case_mappings={0: 0x401010, 1: 0x401020},
            switch_type="OLLVM",
        )

        result = DeobfuscationResult(
            original_cfg=original_cfg,
            deobfuscated_cfg=deobf_cfg,
            dispatcher_info=[dispatcher],
            removed_blocks=[0x401030],
            recovered_edges=[(0x401000, 0x401020)],
            opaque_predicates=[],
            patch_info=[],
            confidence=0.85,
            metrics={"blocks_removed": 1},
        )

        self.assertEqual(len(result.dispatcher_info), 1)
        self.assertEqual(len(result.removed_blocks), 1)
        self.assertEqual(len(result.recovered_edges), 1)
        self.assertEqual(result.confidence, 0.85)


if __name__ == "__main__":
    unittest.main()
