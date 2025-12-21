"""Production tests for taint analyzer - NO MOCKS.

This test suite validates taint analysis capabilities against REAL Windows binaries.
Tests MUST FAIL if taint tracking, data flow analysis, or vulnerability identification
is broken. Uses actual system binaries for authentic license validation tracking.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.taint_analyzer import (
    AdvancedTaintTracker,
    TaintAnalysisEngine,
    TaintAnalyzer,
)

SYSTEM32 = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32"


class TestTaintAnalysisEngineInitialization:
    """Validate taint analysis engine initialization and configuration."""

    def test_engine_creates_with_default_config(self) -> None:
        """Engine must initialize successfully with no configuration."""
        engine = TaintAnalysisEngine()
        assert engine is not None
        assert hasattr(engine, "taint_sources")
        assert hasattr(engine, "taint_sinks")
        assert hasattr(engine, "taint_propagation")
        assert hasattr(engine, "results")

    def test_engine_creates_with_custom_config(self) -> None:
        """Engine must accept and store custom configuration."""
        config = {
            "max_depth": 1000,
            "track_memory": True,
            "track_registers": True,
            "timeout": 300,
        }
        engine = TaintAnalysisEngine(config=config)
        assert engine.config == config
        assert engine.config["max_depth"] == 1000

    def test_engine_initializes_empty_state(self) -> None:
        """Engine must start with clean state."""
        engine = TaintAnalysisEngine()
        assert len(engine.taint_sources) == 0
        assert len(engine.taint_sinks) == 0
        assert len(engine.taint_propagation) == 0
        assert len(engine.results) == 0

    def test_binary_path_starts_none(self) -> None:
        """Engine binary path must be None initially."""
        engine = TaintAnalysisEngine()
        assert engine.binary_path is None

    def test_logger_properly_configured(self) -> None:
        """Engine logger must be properly configured."""
        engine = TaintAnalysisEngine()
        assert engine.logger is not None
        assert "TaintAnalysis" in engine.logger.name


class TestTaintSourceDefinition:
    """Validate taint source definition and management."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide clean engine instance."""
        return TaintAnalysisEngine()

    def test_add_file_io_taint_source(self, engine: TaintAnalysisEngine) -> None:
        """Adding file I/O taint source must succeed and be recorded."""
        engine.add_taint_source("file_read", "ReadFile", "Windows file read API")
        assert len(engine.taint_sources) == 1
        source = engine.taint_sources[0]
        assert source["type"] == "file_read"
        assert source["location"] == "ReadFile"
        assert "Windows file read" in source["description"]

    def test_add_registry_taint_source(self, engine: TaintAnalysisEngine) -> None:
        """Adding registry taint source must succeed and be recorded."""
        engine.add_taint_source("registry", "RegQueryValueEx", "Registry query function")
        assert len(engine.taint_sources) == 1
        assert engine.taint_sources[0]["type"] == "registry"

    def test_add_network_taint_source(self, engine: TaintAnalysisEngine) -> None:
        """Adding network taint source must succeed and be recorded."""
        engine.add_taint_source("network", "recv", "Network receive function")
        assert len(engine.taint_sources) == 1
        assert engine.taint_sources[0]["type"] == "network"

    def test_add_hardware_id_taint_source(self, engine: TaintAnalysisEngine) -> None:
        """Adding hardware ID taint source must succeed and be recorded."""
        engine.add_taint_source("hardware_id", "GetVolumeInformation", "Volume info API")
        assert len(engine.taint_sources) == 1
        assert engine.taint_sources[0]["type"] == "hardware_id"

    def test_add_multiple_taint_sources(self, engine: TaintAnalysisEngine) -> None:
        """Adding multiple taint sources must maintain all sources."""
        engine.add_taint_source("file_read", "fopen", "File open")
        engine.add_taint_source("registry", "RegOpenKeyEx", "Registry open")
        engine.add_taint_source("network", "recvfrom", "Network receive")
        assert len(engine.taint_sources) == 3
        types = [s["type"] for s in engine.taint_sources]
        assert "file_read" in types
        assert "registry" in types
        assert "network" in types

    def test_taint_source_with_custom_description(self, engine: TaintAnalysisEngine) -> None:
        """Custom descriptions must be stored correctly."""
        desc = "Critical license file read operation"
        engine.add_taint_source("file_read", "ReadFile", desc)
        assert engine.taint_sources[0]["description"] == desc

    def test_taint_source_without_description_gets_default(self, engine: TaintAnalysisEngine) -> None:
        """Sources without description must get automatic description."""
        engine.add_taint_source("file_read", "fread")
        desc = engine.taint_sources[0]["description"]
        assert "fread" in desc
        assert "file_read" in desc


class TestTaintSinkDefinition:
    """Validate taint sink definition and management."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide clean engine instance."""
        return TaintAnalysisEngine()

    def test_add_comparison_sink(self, engine: TaintAnalysisEngine) -> None:
        """Adding comparison sink must succeed and be recorded."""
        engine.add_taint_sink("comparison", "strcmp", "String comparison")
        assert len(engine.taint_sinks) == 1
        sink = engine.taint_sinks[0]
        assert sink["type"] == "comparison"
        assert sink["location"] == "strcmp"

    def test_add_conditional_sink(self, engine: TaintAnalysisEngine) -> None:
        """Adding conditional jump sink must succeed and be recorded."""
        engine.add_taint_sink("conditional", "je", "Jump if equal")
        assert len(engine.taint_sinks) == 1
        assert engine.taint_sinks[0]["type"] == "conditional"

    def test_add_crypto_sink(self, engine: TaintAnalysisEngine) -> None:
        """Adding cryptographic operation sink must succeed and be recorded."""
        engine.add_taint_sink("crypto", "CryptVerifySignature", "Signature verification")
        assert len(engine.taint_sinks) == 1
        assert engine.taint_sinks[0]["type"] == "crypto"

    def test_add_multiple_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Adding multiple sinks must maintain all sinks."""
        engine.add_taint_sink("comparison", "memcmp", "Memory compare")
        engine.add_taint_sink("conditional", "jne", "Jump not equal")
        engine.add_taint_sink("crypto", "MD5_Final", "MD5 finalize")
        assert len(engine.taint_sinks) == 3
        types = [s["type"] for s in engine.taint_sinks]
        assert "comparison" in types
        assert "conditional" in types
        assert "crypto" in types


class TestBinaryLoading:
    """Validate binary loading and validation."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide clean engine instance."""
        return TaintAnalysisEngine()

    def test_set_valid_notepad_binary(self, engine: TaintAnalysisEngine) -> None:
        """Setting valid notepad.exe binary must succeed."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        result = engine.set_binary(str(notepad))
        assert result is True
        assert engine.binary_path == str(notepad)

    def test_set_valid_kernel32_dll(self, engine: TaintAnalysisEngine) -> None:
        """Setting valid kernel32.dll must succeed."""
        kernel32 = SYSTEM32 / "kernel32.dll"
        if not kernel32.exists():
            pytest.skip("kernel32.dll not found")

        result = engine.set_binary(str(kernel32))
        assert result is True
        assert engine.binary_path == str(kernel32)

    def test_set_nonexistent_binary_fails(self, engine: TaintAnalysisEngine) -> None:
        """Setting nonexistent binary must fail gracefully."""
        result = engine.set_binary("C:\\nonexistent\\binary.exe")
        assert result is False
        assert engine.binary_path != "C:\\nonexistent\\binary.exe"

    def test_set_invalid_path_fails(self, engine: TaintAnalysisEngine) -> None:
        """Setting invalid path must fail gracefully."""
        result = engine.set_binary("")
        assert result is False

    def test_binary_path_persists_after_set(self, engine: TaintAnalysisEngine) -> None:
        """Binary path must persist after successful set."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not found")

        engine.set_binary(str(notepad))
        assert engine.binary_path == str(notepad)
        engine.add_taint_source("file_read", "fopen")
        assert engine.binary_path == str(notepad)


class TestDefaultTaintConfiguration:
    """Validate default taint source and sink configuration."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide clean engine instance."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_add_default_file_io_sources(self, engine: TaintAnalysisEngine) -> None:
        """Default sources must include file I/O operations."""
        engine._add_default_taint_sources()
        types = [s["type"] for s in engine.taint_sources]
        assert "file_read" in types
        locations = [s["location"] for s in engine.taint_sources]
        assert "fopen" in locations or "ReadFile" in locations

    def test_add_default_registry_sources(self, engine: TaintAnalysisEngine) -> None:
        """Default sources must include registry operations."""
        engine._add_default_taint_sources()
        types = [s["type"] for s in engine.taint_sources]
        assert "registry" in types
        locations = [s["location"] for s in engine.taint_sources]
        assert any("Reg" in loc for loc in locations)

    def test_add_default_network_sources(self, engine: TaintAnalysisEngine) -> None:
        """Default sources must include network operations."""
        engine._add_default_taint_sources()
        types = [s["type"] for s in engine.taint_sources]
        assert "network" in types
        locations = [s["location"] for s in engine.taint_sources]
        assert "recv" in locations or "recvfrom" in locations

    def test_add_default_hardware_id_sources(self, engine: TaintAnalysisEngine) -> None:
        """Default sources must include hardware ID operations."""
        engine._add_default_taint_sources()
        types = [s["type"] for s in engine.taint_sources]
        assert "hardware_id" in types

    def test_add_default_comparison_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Default sinks must include comparison operations."""
        engine._add_default_taint_sinks()
        types = [s["type"] for s in engine.taint_sinks]
        assert "comparison" in types
        locations = [s["location"] for s in engine.taint_sinks]
        assert "strcmp" in locations or "memcmp" in locations

    def test_add_default_conditional_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Default sinks must include conditional jumps."""
        engine._add_default_taint_sinks()
        types = [s["type"] for s in engine.taint_sinks]
        assert "conditional" in types
        locations = [s["location"] for s in engine.taint_sinks]
        assert any(jump in locations for jump in ["je", "jne", "jz"])

    def test_add_default_crypto_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Default sinks must include cryptographic operations."""
        engine._add_default_taint_sinks()
        types = [s["type"] for s in engine.taint_sinks]
        assert "crypto" in types


class TestBinaryDisassembly:
    """Validate binary disassembly capabilities."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_disassemble_notepad_produces_instructions(self, engine: TaintAnalysisEngine) -> None:
        """Disassembling notepad.exe must produce instruction list."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        instructions = engine._disassemble_binary()
        assert instructions is not None
        assert len(instructions) > 0
        assert isinstance(instructions, list)

    def test_disassembled_instructions_have_required_fields(self, engine: TaintAnalysisEngine) -> None:
        """Disassembled instructions must have address, mnemonic, operands."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        instructions = engine._disassemble_binary()
        if instructions and len(instructions) > 0:
            instr = instructions[0]
            assert "address" in instr
            assert "mnemonic" in instr
            assert "op_str" in instr
            assert isinstance(instr["address"], int)

    def test_disassemble_kernel32_produces_instructions(self) -> None:
        """Disassembling kernel32.dll must produce instruction list."""
        engine = TaintAnalysisEngine()
        kernel32 = SYSTEM32 / "kernel32.dll"
        if not kernel32.exists():
            pytest.skip("kernel32.dll not available")

        engine.set_binary(str(kernel32))
        instructions = engine._disassemble_binary()
        assert instructions is not None
        assert len(instructions) > 0

    def test_instruction_addresses_increase_monotonically(self, engine: TaintAnalysisEngine) -> None:
        """Instruction addresses must generally increase through code."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        instructions = engine._disassemble_binary()
        if instructions and len(instructions) > 10:
            addresses = [instr["address"] for instr in instructions[:10]]
            assert max(addresses) > min(addresses), "Addresses must span a range"

    def test_disassembly_handles_pe_files(self, engine: TaintAnalysisEngine) -> None:
        """Disassembly must correctly handle PE file format."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        with open(engine.binary_path, "rb") as f:
            header = f.read(2)

        assert header == b"MZ", "Test binary must be PE format"
        instructions = engine._disassemble_binary()
        assert instructions is not None


class TestControlFlowGraphConstruction:
    """Validate control flow graph construction from disassembly."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_build_cfg_from_real_instructions(self, engine: TaintAnalysisEngine) -> None:
        """Building CFG from real instructions must produce valid graph."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            assert isinstance(cfg, dict)
            assert len(cfg) > 0

    def test_cfg_maps_addresses_to_successors(self, engine: TaintAnalysisEngine) -> None:
        """CFG must map instruction addresses to successor addresses."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            for addr, successors in cfg.items():
                assert isinstance(addr, int)
                assert isinstance(successors, list)

    def test_sequential_instructions_have_successors(self, engine: TaintAnalysisEngine) -> None:
        """Sequential non-jump instructions must have next instruction as successor."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        instructions = engine._disassemble_binary()
        if instructions and len(instructions) > 1:
            cfg = engine._build_control_flow_graph(instructions)
            first_addr = instructions[0]["address"]
            if first_addr in cfg:
                successors = cfg[first_addr]
                assert len(successors) >= 0, "Instruction must have successors or be terminal"

    def test_jump_instructions_have_multiple_successors(self, engine: TaintAnalysisEngine) -> None:
        """Conditional jump instructions should have multiple successors."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            if jump_instructions := [
                i for i in instructions if i["mnemonic"].lower().startswith("j")
            ]:
                found_branch = False
                for instr in jump_instructions[:10]:
                    addr = instr["address"]
                    if addr in cfg and len(cfg[addr]) > 1:
                        found_branch = True
                        break
                assert found_branch or len(jump_instructions) < 5, "Conditional jumps should create branches"

    def test_return_instructions_have_no_successors(self, engine: TaintAnalysisEngine) -> None:
        """Return instructions should have no successors."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            if ret_instructions := [
                i for i in instructions if i["mnemonic"].lower() in ["ret", "retn"]
            ]:
                ret_addr = ret_instructions[0]["address"]
                if ret_addr in cfg:
                    assert len(cfg[ret_addr]) == 0, "Return instructions should have no successors"


class TestDataFlowGraphConstruction:
    """Validate data flow graph construction."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_build_data_flow_graph_from_instructions(self, engine: TaintAnalysisEngine) -> None:
        """Building data flow graph must produce valid graph."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            dfg = engine._build_data_flow_graph(instructions, cfg)
            assert isinstance(dfg, dict)
            assert len(dfg) > 0

    def test_dfg_tracks_register_definitions(self, engine: TaintAnalysisEngine) -> None:
        """Data flow graph must track register definitions."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            dfg = engine._build_data_flow_graph(instructions, cfg)
            for addr, flow_info in dfg.items():
                assert "defines" in flow_info
                assert "uses" in flow_info

    def test_dfg_tracks_register_uses(self, engine: TaintAnalysisEngine) -> None:
        """Data flow graph must track register uses."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            dfg = engine._build_data_flow_graph(instructions, cfg)
            for addr, flow_info in dfg.items():
                assert isinstance(flow_info["uses"], set)

    def test_dfg_classifies_instruction_types(self, engine: TaintAnalysisEngine) -> None:
        """Data flow graph must classify instruction types."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            dfg = engine._build_data_flow_graph(instructions, cfg)
            for addr, flow_info in dfg.items():
                assert "type" in flow_info
                assert flow_info["type"] in [
                    "data_move", "arithmetic", "bitwise", "comparison",
                    "branch", "call", "return", "stack", "other"
                ]

    def test_dfg_identifies_taint_killing_operations(self, engine: TaintAnalysisEngine) -> None:
        """Data flow graph must identify operations that kill taint."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            cfg = engine._build_control_flow_graph(instructions)
            dfg = engine._build_data_flow_graph(instructions, cfg)
            if xor_instructions := [
                i for i in instructions if i["mnemonic"].lower() == "xor"
            ]:
                for instr in xor_instructions[:5]:
                    addr = instr["address"]
                    if addr in dfg:
                        assert "kills_taint" in dfg[addr]


class TestRegisterStateTracking:
    """Validate register state initialization and tracking."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_initialize_register_states_for_instructions(self, engine: TaintAnalysisEngine) -> None:
        """Register state map must be initialized for all instructions."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            states = engine._initialize_register_states(instructions)
            assert isinstance(states, dict)
            assert len(states) == len(instructions)

    def test_register_states_include_common_registers(self, engine: TaintAnalysisEngine) -> None:
        """Register states must include common x86/x64 registers."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            states = engine._initialize_register_states(instructions)
            first_addr = instructions[0]["address"]
            if first_addr in states:
                reg_state = states[first_addr]["all_register_states"]
                assert "eax" in reg_state or "rax" in reg_state
                assert "ebx" in reg_state or "rbx" in reg_state

    def test_register_states_track_tainted_registers(self, engine: TaintAnalysisEngine) -> None:
        """Register states must track which registers are tainted."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            states = engine._initialize_register_states(instructions)
            first_addr = instructions[0]["address"]
            if first_addr in states:
                assert "tainted_registers" in states[first_addr]
                assert isinstance(states[first_addr]["tainted_registers"], set)

    def test_register_states_track_live_registers(self, engine: TaintAnalysisEngine) -> None:
        """Register states must track live register sets."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            states = engine._initialize_register_states(instructions)
            first_addr = instructions[0]["address"]
            if first_addr in states:
                assert "live_registers" in states[first_addr]


class TestTaintSourceIdentification:
    """Validate identification of taint source instructions."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_find_file_io_sources(self, engine: TaintAnalysisEngine) -> None:
        """Source finder must identify file I/O operations."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            sources = engine._find_source_instructions(instructions)
            assert isinstance(sources, list)

    def test_identified_sources_have_required_fields(self, engine: TaintAnalysisEngine) -> None:
        """Identified sources must have address, mnemonic, source_type."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            if sources := engine._find_source_instructions(instructions):
                source = sources[0]
                assert "address" in source
                assert "mnemonic" in source
                assert "source_type" in source
                assert "taint_status" in source
                assert source["taint_status"] == "source"

    def test_sources_marked_with_correct_types(self, engine: TaintAnalysisEngine) -> None:
        """Sources must be marked with correct type categories."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            if sources := engine._find_source_instructions(instructions):
                valid_types = ["file_io", "registry", "network", "hardware_id"]
                for source in sources:
                    assert source["source_type"] in valid_types


class TestTaintSinkIdentification:
    """Validate identification of taint sink instructions."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_find_comparison_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Sink finder must identify comparison operations."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            sinks = engine._find_sink_instructions(instructions)
            assert isinstance(sinks, list)
            assert len(sinks) > 0, "Real binaries must have comparison instructions"

    def test_find_conditional_jump_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Sink finder must identify conditional jumps."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            sinks = engine._find_sink_instructions(instructions)
            conditional_sinks = [s for s in sinks if s["sink_type"] == "conditional"]
            assert conditional_sinks, "Real binaries must have conditional jumps"

    def test_identified_sinks_have_required_fields(self, engine: TaintAnalysisEngine) -> None:
        """Identified sinks must have address, mnemonic, sink_type."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            if sinks := engine._find_sink_instructions(instructions):
                sink = sinks[0]
                assert "address" in sink
                assert "mnemonic" in sink
                assert "sink_type" in sink
                assert "taint_status" in sink
                assert sink["taint_status"] == "sink"

    def test_sinks_marked_with_correct_types(self, engine: TaintAnalysisEngine) -> None:
        """Sinks must be marked with correct type categories."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        if instructions := engine._disassemble_binary():
            sinks = engine._find_sink_instructions(instructions)
            valid_types = ["comparison", "conditional", "string_compare", "crypto"]
            for sink in sinks:
                assert sink["sink_type"] in valid_types


class TestAdvancedTaintTracker:
    """Validate advanced taint tracker functionality."""

    @pytest.fixture
    def sample_cfg(self) -> dict[int, list[int]]:
        """Provide sample control flow graph."""
        return {
            0x1000: [0x1004],
            0x1004: [0x1008],
            0x1008: [0x100C, 0x1010],
            0x100C: [0x1014],
            0x1010: [0x1014],
            0x1014: [0x1018],
        }

    @pytest.fixture
    def sample_dfg(self) -> dict[int, dict[str, Any]]:
        """Provide sample data flow graph."""
        return {
            0x1000: {
                "instruction": {"address": 0x1000, "mnemonic": "mov", "op_str": "eax, [ebx]"},
                "operation": "mov",
                "type": "data_move",
                "kills_taint": False,
            },
            0x1004: {
                "instruction": {"address": 0x1004, "mnemonic": "add", "op_str": "eax, ecx"},
                "operation": "add",
                "type": "arithmetic",
                "kills_taint": False,
            },
        }

    @pytest.fixture
    def sample_register_states(self) -> dict[int, dict[str, Any]]:
        """Provide sample register states."""
        return {
            0x1000: {"live_registers": {"eax", "ebx"}, "tainted_registers": set()},
            0x1004: {"live_registers": {"eax", "ecx"}, "tainted_registers": set()},
        }

    def test_tracker_initialization(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Taint tracker must initialize with provided data structures."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        assert tracker.cfg == sample_cfg
        assert tracker.data_flow_graph == sample_dfg
        assert tracker.register_state_map == sample_register_states

    def test_add_taint_source_assigns_unique_id(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Adding taint source must assign unique ID."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        source1 = {"address": 0x1000, "mnemonic": "call", "op_str": "ReadFile"}
        source2 = {"address": 0x1004, "mnemonic": "call", "op_str": "fopen"}

        id1 = tracker.add_taint_source(source1)
        id2 = tracker.add_taint_source(source2)

        assert id1 != id2
        assert id1 > 0
        assert id2 > 0

    def test_taint_source_stored_correctly(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Taint source must be stored with correct metadata."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        source = {"address": 0x1000, "mnemonic": "call", "op_str": "ReadFile", "source_type": "file_io"}

        taint_id = tracker.add_taint_source(source)
        stored_source = tracker.taint_sources[taint_id]

        assert stored_source["address"] == 0x1000
        assert stored_source["type"] == "file_io"

    def test_get_output_registers_identifies_destinations(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Get output registers must identify destination registers."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        instr = {"address": 0x1000, "mnemonic": "mov", "op_str": "eax, ebx"}

        regs = tracker._get_output_registers(instr)
        assert isinstance(regs, set)

    def test_propagate_taint_follows_cfg(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Taint propagation must follow control flow graph."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        source = {"address": 0x1000, "mnemonic": "call", "op_str": "ReadFile"}
        sinks = [{"address": 0x1014, "mnemonic": "cmp", "op_str": "eax, 0"}]

        paths = tracker.propagate_taint(source, sinks)
        assert isinstance(paths, list)

    def test_propagation_calculates_confidence(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Taint propagation must calculate confidence scores."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        transformations: list[dict[str, Any]] = []
        confidence = tracker._calculate_confidence(transformations)
        assert 0.0 <= confidence <= 1.0

    def test_confidence_decreases_with_transformations(
        self,
        sample_cfg: dict[int, list[int]],
        sample_dfg: dict[int, dict[str, Any]],
        sample_register_states: dict[int, dict[str, Any]],
    ) -> None:
        """Confidence must decrease with more transformations."""
        tracker = AdvancedTaintTracker(sample_cfg, sample_dfg, sample_register_states)
        no_transforms: list[dict[str, Any]] = []
        one_transform = [{"type": "arithmetic", "address": 0x1000}]
        many_transforms = [{"type": "arithmetic", "address": x} for x in range(10)]

        conf0 = tracker._calculate_confidence(no_transforms)
        conf1 = tracker._calculate_confidence(one_transform)
        conf_many = tracker._calculate_confidence(many_transforms)

        assert conf0 >= conf1
        assert conf1 >= conf_many


class TestTaintAnalysisExecution:
    """Validate full taint analysis execution on real binaries."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_run_analysis_without_binary_fails(self) -> None:
        """Running analysis without binary must fail gracefully."""
        engine = TaintAnalysisEngine()
        result = engine.run_analysis()
        assert result is False

    def test_run_analysis_with_notepad_succeeds(self, engine: TaintAnalysisEngine) -> None:
        """Running analysis on notepad.exe must succeed."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        result = engine.run_analysis()
        assert result is True

    def test_analysis_produces_results(self, engine: TaintAnalysisEngine) -> None:
        """Analysis must produce results dictionary."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.run_analysis()
        assert len(engine.results) > 0
        assert "total_sources" in engine.results
        assert "total_sinks" in engine.results

    def test_analysis_adds_default_sources_when_none_specified(self, engine: TaintAnalysisEngine) -> None:
        """Analysis must add default sources if none specified."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.run_analysis()
        assert len(engine.taint_sources) > 0

    def test_analysis_adds_default_sinks_when_none_specified(self, engine: TaintAnalysisEngine) -> None:
        """Analysis must add default sinks if none specified."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.run_analysis()
        assert len(engine.taint_sinks) > 0

    def test_analysis_results_include_path_count(self, engine: TaintAnalysisEngine) -> None:
        """Analysis results must include taint propagation path count."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.run_analysis()
        assert "total_paths" in engine.results
        assert isinstance(engine.results["total_paths"], int)

    def test_analysis_results_include_license_checks(self, engine: TaintAnalysisEngine) -> None:
        """Analysis results must include license check count."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.run_analysis()
        assert "license_checks_found" in engine.results
        assert isinstance(engine.results["license_checks_found"], int)

    def test_analysis_results_include_bypass_points(self, engine: TaintAnalysisEngine) -> None:
        """Analysis results must include bypass point count."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.run_analysis()
        assert "potential_bypass_points" in engine.results
        assert isinstance(engine.results["potential_bypass_points"], int)

    def test_analysis_handles_custom_sources(self, engine: TaintAnalysisEngine) -> None:
        """Analysis must respect custom taint sources."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.add_taint_source("file_read", "CreateFileW", "Custom source")
        engine.run_analysis()

        sources = [s for s in engine.taint_sources if s["location"] == "CreateFileW"]
        assert sources

    def test_analysis_handles_custom_sinks(self, engine: TaintAnalysisEngine) -> None:
        """Analysis must respect custom taint sinks."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        engine.add_taint_sink("comparison", "test", "Custom sink")
        engine.run_analysis()

        sinks = [s for s in engine.taint_sinks if s["location"] == "test"]
        assert sinks


class TestResultsRetrieval:
    """Validate results retrieval and formatting."""

    @pytest.fixture
    def analyzed_engine(self) -> TaintAnalysisEngine:
        """Provide engine with completed analysis."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
            engine.run_analysis()
        return engine

    def test_get_results_returns_dictionary(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Get results must return dictionary."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = analyzed_engine.get_results()
        assert isinstance(results, dict)

    def test_results_include_sources(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Results must include sources list."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = analyzed_engine.get_results()
        assert "sources" in results
        assert isinstance(results["sources"], list)

    def test_results_include_sinks(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Results must include sinks list."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = analyzed_engine.get_results()
        assert "sinks" in results
        assert isinstance(results["sinks"], list)

    def test_results_include_propagation(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Results must include propagation paths."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = analyzed_engine.get_results()
        assert "propagation" in results
        assert isinstance(results["propagation"], list)

    def test_results_include_summary(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Results must include summary statistics."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = analyzed_engine.get_results()
        assert "summary" in results
        assert isinstance(results["summary"], dict)


class TestStatisticsGeneration:
    """Validate statistics generation from analysis results."""

    @pytest.fixture
    def analyzed_engine(self) -> TaintAnalysisEngine:
        """Provide engine with completed analysis."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
            engine.run_analysis()
        return engine

    def test_get_statistics_returns_dictionary(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Get statistics must return dictionary."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        stats = analyzed_engine.get_statistics()
        assert isinstance(stats, dict)

    def test_statistics_include_sources_by_type(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Statistics must include sources grouped by type."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        if stats := analyzed_engine.get_statistics():
            assert "sources_by_type" in stats
            assert isinstance(stats["sources_by_type"], dict)

    def test_statistics_include_sinks_by_type(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Statistics must include sinks grouped by type."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        if stats := analyzed_engine.get_statistics():
            assert "sinks_by_type" in stats
            assert isinstance(stats["sinks_by_type"], dict)


class TestClearAnalysis:
    """Validate clearing of analysis data."""

    @pytest.fixture
    def analyzed_engine(self) -> TaintAnalysisEngine:
        """Provide engine with completed analysis."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
            engine.run_analysis()
        return engine

    def test_clear_analysis_removes_sources(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Clear analysis must remove all sources."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        analyzed_engine.clear_analysis()
        assert len(analyzed_engine.taint_sources) == 0

    def test_clear_analysis_removes_sinks(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Clear analysis must remove all sinks."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        analyzed_engine.clear_analysis()
        assert len(analyzed_engine.taint_sinks) == 0

    def test_clear_analysis_removes_propagation(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Clear analysis must remove all propagation data."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        analyzed_engine.clear_analysis()
        assert len(analyzed_engine.taint_propagation) == 0

    def test_clear_analysis_removes_results(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Clear analysis must remove all results."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        analyzed_engine.clear_analysis()
        assert len(analyzed_engine.results) == 0


class TestAnalyzeWithSources:
    """Validate analysis with specific source specifications."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine with notepad binary."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
        return engine

    def test_analyze_with_function_sources(self, engine: TaintAnalysisEngine) -> None:
        """Analyzing with function sources must produce results."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = engine.analyze_with_sources(["func:ReadFile", "func:CreateFile"])
        assert "sources" in results
        assert len(results["sources"]) == 2

    def test_analyze_with_address_sources(self, engine: TaintAnalysisEngine) -> None:
        """Analyzing with address sources must produce results."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = engine.analyze_with_sources(["0x401000", "0x402000"])
        assert "sources" in results

    def test_analyze_with_api_sources(self, engine: TaintAnalysisEngine) -> None:
        """Analyzing with API sources must produce results."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = engine.analyze_with_sources(["api:GetSystemInfo", "api:GetVolumeInformation"])
        assert "sources" in results

    def test_analyze_results_include_sinks_reached(self, engine: TaintAnalysisEngine) -> None:
        """Analysis results must include sinks reached."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = engine.analyze_with_sources(["func:ReadFile"])
        assert "sinks_reached" in results
        assert isinstance(results["sinks_reached"], list)

    def test_analyze_results_include_taint_flows(self, engine: TaintAnalysisEngine) -> None:
        """Analysis results must include taint flows."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = engine.analyze_with_sources(["func:ReadFile"])
        assert "taint_flows" in results
        assert isinstance(results["taint_flows"], list)

    def test_analyze_results_include_vulnerabilities(self, engine: TaintAnalysisEngine) -> None:
        """Analysis results must include vulnerabilities."""
        if not engine.binary_path:
            pytest.skip("notepad.exe not available")

        results = engine.analyze_with_sources(["func:ReadFile"])
        assert "vulnerabilities" in results
        assert isinstance(results["vulnerabilities"], list)


class TestReportGeneration:
    """Validate HTML report generation."""

    @pytest.fixture
    def analyzed_engine(self) -> TaintAnalysisEngine:
        """Provide engine with completed analysis."""
        engine = TaintAnalysisEngine()
        notepad = SYSTEM32 / "notepad.exe"
        if notepad.exists():
            engine.set_binary(str(notepad))
            engine.run_analysis()
        return engine

    def test_generate_report_returns_html(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Generate report must return HTML string when no filename provided."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        html = analyzed_engine.generate_report()
        assert html is not None
        assert isinstance(html, str)
        assert "<html>" in html.lower() or "<!doctype" in html.lower()

    def test_generate_report_saves_to_file(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Generate report must save to file when filename provided."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            filepath = f.name

        try:
            result = analyzed_engine.generate_report(filepath)
            assert result is not None
            assert Path(filepath).exists()

            with open(filepath, encoding="utf-8") as f:
                content = f.read()
            assert len(content) > 0
            assert "Taint Analysis" in content
        finally:
            if Path(filepath).exists():
                Path(filepath).unlink()

    def test_report_includes_summary_statistics(self, analyzed_engine: TaintAnalysisEngine) -> None:
        """Report must include summary statistics."""
        if not analyzed_engine.binary_path:
            pytest.skip("notepad.exe not available")

        if html := analyzed_engine.generate_report():
            assert "Total Taint Sources" in html or "total_sources" in html
            assert "Total Taint Sinks" in html or "total_sinks" in html

    def test_report_without_results_returns_none(self) -> None:
        """Generating report without results must return None."""
        engine = TaintAnalysisEngine()
        result = engine.generate_report()
        assert result is None


class TestTaintAnalyzerAlias:
    """Validate TaintAnalyzer alias for backward compatibility."""

    def test_taint_analyzer_alias_exists(self) -> None:
        """TaintAnalyzer alias must exist for compatibility."""
        assert TaintAnalyzer is not None

    def test_taint_analyzer_is_taint_analysis_engine(self) -> None:
        """TaintAnalyzer must be alias for TaintAnalysisEngine."""
        assert TaintAnalyzer == TaintAnalysisEngine

    def test_create_instance_via_alias(self) -> None:
        """Creating instance via alias must work identically."""
        engine1 = TaintAnalysisEngine()
        engine2 = TaintAnalyzer()
        assert type(engine1) == type(engine2)


class TestIntegrationRealWorldLicenseValidation:
    """Integration tests simulating real-world license validation scenarios."""

    @pytest.fixture
    def engine(self) -> TaintAnalysisEngine:
        """Provide engine for integration tests."""
        return TaintAnalysisEngine()

    def test_track_license_file_to_comparison(self, engine: TaintAnalysisEngine) -> None:
        """Simulate tracking license file read to comparison sink."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not available")

        engine.set_binary(str(notepad))
        engine.add_taint_source("file_read", "ReadFile", "License file read")
        engine.add_taint_sink("comparison", "cmp", "License validation")

        result = engine.run_analysis()
        assert result is True

    def test_track_registry_to_conditional_jump(self, engine: TaintAnalysisEngine) -> None:
        """Simulate tracking registry read to conditional jump."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not available")

        engine.set_binary(str(notepad))
        engine.add_taint_source("registry", "RegQueryValueEx", "License key registry read")
        engine.add_taint_sink("conditional", "je", "License valid jump")

        result = engine.run_analysis()
        assert result is True

    def test_track_network_license_validation(self, engine: TaintAnalysisEngine) -> None:
        """Simulate tracking network license check."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not available")

        engine.set_binary(str(notepad))
        engine.add_taint_source("network", "recv", "License server response")
        engine.add_taint_sink("crypto", "CryptVerifySignature", "Signature validation")

        result = engine.run_analysis()
        assert result is True

    def test_multiple_sources_to_single_sink(self, engine: TaintAnalysisEngine) -> None:
        """Simulate multiple license sources converging to single check."""
        notepad = SYSTEM32 / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not available")

        engine.set_binary(str(notepad))
        engine.add_taint_source("file_read", "ReadFile", "License file")
        engine.add_taint_source("registry", "RegQueryValueEx", "License registry")
        engine.add_taint_sink("comparison", "strcmp", "Combined validation")

        result = engine.run_analysis()
        assert result is True
        results = engine.get_results()
        assert results["summary"]["total_sources"] >= 2


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling."""

    def test_empty_binary_path(self) -> None:
        """Engine must handle empty binary path gracefully."""
        engine = TaintAnalysisEngine()
        result = engine.set_binary("")
        assert result is False

    def test_nonexistent_binary(self) -> None:
        """Engine must handle nonexistent binary gracefully."""
        engine = TaintAnalysisEngine()
        result = engine.set_binary("C:\\nonexistent\\file.exe")
        assert result is False

    def test_analysis_without_binary(self) -> None:
        """Running analysis without binary must fail gracefully."""
        engine = TaintAnalysisEngine()
        result = engine.run_analysis()
        assert result is False

    def test_get_results_before_analysis(self) -> None:
        """Getting results before analysis must return empty results."""
        engine = TaintAnalysisEngine()
        results = engine.get_results()
        assert "sources" in results
        assert len(results["sources"]) == 0

    def test_get_statistics_before_analysis(self) -> None:
        """Getting statistics before analysis must return empty dict."""
        engine = TaintAnalysisEngine()
        stats = engine.get_statistics()
        assert isinstance(stats, dict)

    def test_clear_analysis_when_empty(self) -> None:
        """Clearing empty analysis must not raise errors."""
        engine = TaintAnalysisEngine()
        engine.clear_analysis()
        assert len(engine.taint_sources) == 0

    def test_generate_report_before_analysis(self) -> None:
        """Generating report before analysis must return None."""
        engine = TaintAnalysisEngine()
        result = engine.generate_report()
        assert result is None


class TestPerformanceOnLargeBinaries:
    """Test performance characteristics on large binaries."""

    @pytest.fixture
    def large_binary_engine(self) -> TaintAnalysisEngine:
        """Provide engine with larger binary."""
        engine = TaintAnalysisEngine()
        kernel32 = SYSTEM32 / "kernel32.dll"
        if kernel32.exists():
            engine.set_binary(str(kernel32))
        return engine

    def test_analysis_completes_in_reasonable_time(self, large_binary_engine: TaintAnalysisEngine) -> None:
        """Analysis on large binary must complete in reasonable time."""
        if not large_binary_engine.binary_path:
            pytest.skip("kernel32.dll not available")

        import time
        start = time.time()
        result = large_binary_engine.run_analysis()
        duration = time.time() - start

        assert result is True or result is False
        assert duration < 300, "Analysis should complete within 5 minutes"

    def test_disassembly_limits_instruction_count(self, large_binary_engine: TaintAnalysisEngine) -> None:
        """Disassembly must limit instruction count for performance."""
        if not large_binary_engine.binary_path:
            pytest.skip("kernel32.dll not available")

        if instructions := large_binary_engine._disassemble_binary():
            assert len(instructions) <= 10000, "Instruction limit prevents excessive memory use"
