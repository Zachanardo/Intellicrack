"""Production tests for AI integration in hex viewer.

Tests validate REAL AI functionality for binary analysis:
- Binary context extraction (entropy, strings, structure hints)
- Pattern recognition in protected binaries
- Edit suggestion generation for license bypasses
- Semantic search in binary data
- Integration with LLM backends

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.hexview.ai_bridge import AIBinaryBridge, BinaryContextBuilder, AIFeatureType


@pytest.fixture
def pe_header_sample() -> bytes:
    """Create realistic PE header with licensing strings."""
    pe_header = bytearray(b"MZ" + b"\x90" * 58 + b"\x00\x00\x00\x00")
    pe_header += b"PE\x00\x00"
    pe_header += struct.pack("<H", 0x14C)
    pe_header += struct.pack("<H", 3)
    pe_header += b"\x00" * 12
    pe_header += b"Trial expired\x00"
    pe_header += b"Enter license key: \x00"
    pe_header += b"Registration failed\x00"
    pe_header += b"\xFF" * 100
    return bytes(pe_header)


@pytest.fixture
def vmprotect_sample() -> bytes:
    """Create realistic VMProtect-protected binary sample."""
    data = bytearray(512)
    data[0:2] = b"MZ"
    data[10:30] = b"VMProtect by Oreans"
    data[50:70] = b"\xE8\x00\x00\x00\x00\x5D\x81\xED" + b"\x90" * 12
    data[100:120] = b"License validation"
    data[150:200] = bytes(range(256))[:50]
    for i in range(250, 350):
        data[i] = (i * 37) % 256
    return bytes(data)


@pytest.fixture
def encrypted_data_sample() -> bytes:
    """Create realistic encrypted data segment."""
    data = bytearray(256)
    for i in range(256):
        data[i] = (i * 73 + 29) % 256
    return bytes(data)


@pytest.fixture
def context_builder() -> BinaryContextBuilder:
    """Create context builder instance."""
    return BinaryContextBuilder()


@pytest.fixture
def ai_bridge() -> AIBinaryBridge:
    """Create AI bridge instance without model manager."""
    return AIBinaryBridge(model_manager=None)


class TestBinaryContextBuilder:
    """Test binary context extraction capabilities."""

    def test_entropy_calculation_low_entropy(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder calculates low entropy for repeated data."""
        low_entropy_data = b"\x00" * 1024
        entropy = context_builder._calculate_entropy(low_entropy_data)

        assert entropy == 0.0
        assert entropy < 1.0

    def test_entropy_calculation_high_entropy(self, context_builder: BinaryContextBuilder, encrypted_data_sample: bytes) -> None:
        """Context builder calculates high entropy for encrypted data."""
        entropy = context_builder._calculate_entropy(encrypted_data_sample)

        assert entropy > 7.0
        assert 0.0 <= entropy <= 8.0

    def test_string_extraction_ascii(self, context_builder: BinaryContextBuilder, pe_header_sample: bytes) -> None:
        """Context builder extracts ASCII strings from binary data."""
        strings = context_builder._extract_strings(pe_header_sample, min_length=4)

        string_values = [s["value"] for s in strings]

        assert "Trial expired" in string_values
        assert "Enter license key: " in string_values
        assert "Registration failed" in string_values

        for string_info in strings:
            assert "offset" in string_info
            assert "size" in string_info
            assert "encoding" in string_info
            assert string_info["encoding"] in ("ASCII", "UTF-16LE")

    def test_string_extraction_utf16(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder extracts UTF-16 strings from Windows binaries."""
        utf16_data = "License Key Required".encode("utf-16-le") + b"\x00\x00"
        padding = b"\x00" * 50
        binary_data = padding + utf16_data + padding

        strings = context_builder._extract_strings(binary_data, min_length=4)

        string_values = [s["value"] for s in strings if s["encoding"] == "UTF-16LE"]
        assert len(string_values) > 0
        assert any("License" in val or "Key" in val or "Required" in val for val in string_values)

    def test_file_signature_detection_pe(self, context_builder: BinaryContextBuilder, pe_header_sample: bytes) -> None:
        """Context builder detects PE file signature."""
        hints = context_builder._detect_structure_hints(pe_header_sample)

        signature_hints = [h for h in hints if h["type"] == "file_signature"]

        assert len(signature_hints) > 0
        assert signature_hints[0]["description"] == "PE/DOS Executable"
        assert signature_hints[0]["offset"] == 0

    def test_file_signature_detection_elf(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder detects ELF file signature."""
        elf_header = b"\x7fELF" + b"\x00" * 100
        hints = context_builder._detect_structure_hints(elf_header)

        signature_hints = [h for h in hints if h["type"] == "file_signature"]

        assert len(signature_hints) > 0
        assert signature_hints[0]["description"] == "ELF Executable"

    def test_length_prefix_detection(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder detects length-prefixed data structures."""
        length_value = 50
        data_after_length = b"A" * length_value
        binary_data = struct.pack("<H", length_value) + data_after_length + b"\x00" * 50

        hints = context_builder._detect_structure_hints(binary_data)

        length_hints = [h for h in hints if h["type"] == "length_prefix"]

        assert len(length_hints) > 0
        assert any(h["value"] == length_value for h in length_hints)

    def test_repeating_pattern_detection(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder detects repeating patterns in binary data."""
        pattern = b"\xDE\xAD\xBE\xEF"
        repeated_data = pattern * 10
        binary_data = b"\x00" * 100 + repeated_data + b"\x00" * 100

        patterns = context_builder._detect_repeating_patterns(binary_data)

        assert len(patterns) > 0
        pattern_found = any(
            p["pattern_size"] == len(pattern) and p["repeat_count"] >= 3
            for p in patterns
        )
        assert pattern_found

    def test_data_interpretation_integers(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder interprets data as various integer types."""
        test_value_32 = 0x12345678
        test_value_16 = 0x1234
        data = struct.pack("<I", test_value_32) + struct.pack("<H", test_value_16) + b"\x00" * 10

        interpretations = context_builder._interpret_common_types(data)

        assert "uint32_le" in interpretations
        assert interpretations["uint32_le"] == test_value_32
        assert "int32_le" in interpretations

    def test_data_interpretation_floats(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder interprets data as floating point."""
        test_float = 3.14159
        data = struct.pack("<f", test_float) + b"\x00" * 10

        interpretations = context_builder._interpret_common_types(data)

        assert "float_le" in interpretations
        assert abs(interpretations["float_le"] - test_float) < 0.001

    def test_data_interpretation_timestamps(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder interprets Unix timestamps correctly."""
        unix_time = 1700000000
        data = struct.pack("<I", unix_time) + b"\x00" * 10

        interpretations = context_builder._interpret_common_types(data)

        assert "unix_timestamp" in interpretations
        assert "2023" in interpretations["unix_timestamp"]

    def test_complete_context_build(self, context_builder: BinaryContextBuilder, vmprotect_sample: bytes) -> None:
        """Context builder creates complete context for VMProtect binary."""
        context = context_builder.build_context(
            vmprotect_sample,
            offset=0,
            size=len(vmprotect_sample),
            include_entropy=True,
            include_strings=True,
            include_structure_hints=True,
        )

        assert "offset" in context
        assert context["offset"] == 0
        assert "size" in context
        assert context["size"] == len(vmprotect_sample)
        assert "entropy" in context
        assert "strings" in context
        assert len(context["strings"]) > 0
        assert "structure_hints" in context
        assert "interpretations" in context
        assert "hex_representation" in context
        assert "ascii_representation" in context

    def test_entropy_segmentation(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder segments data by entropy levels."""
        low_entropy = b"\x00" * 64
        high_entropy = bytes((i * 73 + 29) % 256 for i in range(64))
        data = low_entropy + high_entropy + low_entropy

        segments = context_builder._segment_by_entropy(data, block_size=64)

        assert len(segments) == 3
        assert segments[0]["entropy"] < 1.0
        assert segments[0]["high_entropy"] is False
        assert segments[1]["entropy"] > 7.0
        assert segments[1]["high_entropy"] is True


class TestAIBinaryBridge:
    """Test AI binary bridge functionality."""

    def test_initialization_without_llm(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge initializes correctly without LLM backend."""
        assert ai_bridge.context_builder is not None
        assert isinstance(ai_bridge.context_builder, BinaryContextBuilder)

    def test_analyze_binary_region_fallback(self, ai_bridge: AIBinaryBridge, pe_header_sample: bytes) -> None:
        """AI bridge provides fallback analysis when no LLM available."""
        result = ai_bridge.analyze_binary_region(
            pe_header_sample,
            offset=0,
            size=len(pe_header_sample),
            query="Find license check strings",
        )

        assert "patterns" in result
        assert "data_meaning" in result
        assert "anomalies" in result
        assert "summary" in result
        assert isinstance(result["patterns"], list)
        assert isinstance(result["anomalies"], list)

    def test_suggest_edits_fallback(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge provides edit suggestions in fallback mode."""
        license_check = b"\x74\x10"
        data = b"\x90" * 50 + license_check + b"\x90" * 50

        result = ai_bridge.suggest_edits(
            data,
            offset=0,
            size=len(data),
            edit_intent="Patch license check to always succeed",
        )

        assert "edit_type" in result
        assert "offset" in result
        assert "explanation" in result
        assert "consequences" in result

    def test_identify_patterns_empty_list(self, ai_bridge: AIBinaryBridge, vmprotect_sample: bytes) -> None:
        """AI bridge identifies patterns in protected binary."""
        patterns = ai_bridge.identify_patterns(
            vmprotect_sample,
            offset=0,
            size=len(vmprotect_sample),
            known_patterns=[
                {"name": "VMProtect", "description": "VMProtect signature"},
                {"name": "License Check", "description": "License validation routine"},
            ],
        )

        assert isinstance(patterns, list)

    def test_search_binary_semantic_fallback(self, ai_bridge: AIBinaryBridge, pe_header_sample: bytes) -> None:
        """AI bridge performs semantic search in fallback mode."""
        results = ai_bridge.search_binary_semantic(
            pe_header_sample,
            query="Find trial expiration messages",
            start_offset=0,
            end_offset=len(pe_header_sample),
        )

        assert isinstance(results, list)

    def test_analyze_binary_patterns_file(self, ai_bridge: AIBinaryBridge, tmp_path: Path) -> None:
        """AI bridge analyzes patterns in actual file."""
        test_file = tmp_path / "test_binary.exe"
        pe_data = b"MZ" + b"\x90" * 100
        pe_data += b"License Key: "
        pe_data += b"\x00" * 50
        pe_data += b"Trial Version"
        test_file.write_bytes(pe_data)

        result = ai_bridge.analyze_binary_patterns(str(test_file))

        assert result["status"] == "success"
        assert "confidence" in result
        assert result["confidence"] > 0.0
        assert "patterns_identified" in result
        assert "entropy" in result
        assert "strings_found" in result
        assert result["file_size"] > 0

    def test_analyze_binary_patterns_nonexistent_file(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge handles nonexistent file gracefully."""
        result = ai_bridge.analyze_binary_patterns("D:\\nonexistent\\file.exe")

        assert "error" in result
        assert "File not found" in result["error"]
        assert result["confidence"] == 0.0

    def test_context_builder_hex_truncation(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder truncates large hex representations."""
        large_data = b"\xAA" * 2048
        hex_repr = context_builder._format_hex_representation(large_data)

        assert "..." in hex_repr
        assert len(hex_repr) < len(large_data) * 3

    def test_context_builder_ascii_truncation(self, context_builder: BinaryContextBuilder) -> None:
        """Context builder truncates large ASCII representations."""
        large_data = b"A" * 2048
        ascii_repr = context_builder._format_ascii_representation(large_data)

        assert "..." in ascii_repr
        assert len(ascii_repr) < len(large_data)

    def test_prompt_building_analysis(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge builds proper analysis prompts."""
        context = {
            "offset": 0,
            "size": 100,
            "entropy": 4.5,
            "hex_representation": "4D 5A 90 00",
            "ascii_representation": "MZ..",
            "strings": [{"offset": 0, "value": "Test", "encoding": "ASCII", "size": 4}],
            "structure_hints": [{"type": "file_signature", "description": "PE", "offset": 0}],
            "interpretations": {"uint32_le": 0x12345678},
        }

        prompt = ai_bridge._build_analysis_prompt(context, "Analyze this binary")

        assert "Binary Data Analysis" in prompt
        assert "offset" in prompt.lower()
        assert "entropy" in prompt.lower()
        assert "hex representation" in prompt.lower()
        assert "Analyze this binary" in prompt

    def test_prompt_building_edit_suggestion(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge builds proper edit suggestion prompts."""
        context = {
            "offset": 100,
            "size": 50,
            "entropy": 3.2,
            "hex_representation": "74 10 E8",
            "ascii_representation": "t..",
            "strings": [],
            "structure_hints": [],
            "interpretations": {},
        }

        prompt = ai_bridge._build_edit_prompt(context, "NOP the jump instruction")

        assert "Binary Data Edit Suggestion" in prompt
        assert "NOP the jump instruction" in prompt
        assert "edit suggestion" in prompt.lower()

    def test_response_parsing_analysis(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge parses analysis responses correctly."""
        response = '''{
            "patterns": [{"start_offset": 10, "end_offset": 20, "pattern_type": "license_check"}],
            "data_meaning": "License validation routine",
            "anomalies": [{"start_offset": 30, "end_offset": 35, "description": "Encrypted data"}],
            "summary": "Binary contains license protection"
        }'''

        data = b"\x90" * 100
        result = ai_bridge._parse_analysis_response(response, data, offset=0)

        assert len(result["patterns"]) == 1
        assert result["patterns"][0]["start_offset"] == 10
        assert len(result["anomalies"]) == 1
        assert "license" in result["data_meaning"].lower()

    def test_response_parsing_edit_suggestion(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge parses edit suggestion responses correctly."""
        response = '''{
            "edit_type": "nop_instruction",
            "offset": 5,
            "original_bytes": "74 10",
            "new_bytes": "90 90",
            "explanation": "Replace conditional jump with NOPs",
            "consequences": "License check always passes"
        }'''

        data = b"\x90\x90\x90\x90\x90\x74\x10\x90\x90"
        result = ai_bridge._parse_edit_response(response, data, offset=0)

        assert result["edit_type"] == "nop_instruction"
        assert result["offset"] == 5
        assert result["original_bytes_raw"] == b"\x74\x10"
        assert result["new_bytes_raw"] == b"\x90\x90"
        assert result["bytes_match"] is True

    def test_response_parsing_pattern_identification(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge parses pattern identification responses correctly."""
        response = '''{
            "identified_patterns": [
                {
                    "pattern_name": "VMProtect",
                    "start_offset": 0,
                    "end_offset": 20,
                    "confidence": 0.95,
                    "explanation": "VMProtect signature detected"
                }
            ]
        }'''

        data = b"\x90" * 100
        patterns = ai_bridge._parse_pattern_response(response, data, offset=0)

        assert len(patterns) == 1
        assert patterns[0]["pattern_name"] == "VMProtect"
        assert patterns[0]["confidence"] == 0.95

    def test_response_parsing_semantic_search(self, ai_bridge: AIBinaryBridge) -> None:
        """AI bridge parses semantic search responses correctly."""
        response = '''{
            "matches": [
                {
                    "start_offset": 10,
                    "end_offset": 30,
                    "relevance_score": 0.88,
                    "explanation": "License key string found"
                }
            ]
        }'''

        data = b"\x90" * 100
        matches = ai_bridge._parse_search_response(response, data, offset=0)

        assert len(matches) == 1
        assert matches[0]["start_offset"] == 10
        assert matches[0]["relevance_score"] == 0.88
        assert "matched_bytes" in matches[0]


class TestAIIntegrationWorkflows:
    """Test complete AI-assisted workflows."""

    def test_license_check_identification_workflow(self, ai_bridge: AIBinaryBridge) -> None:
        """Complete workflow: identify license check in binary."""
        license_routine = b"\x83\x7D\xFC\x00"
        license_routine += b"\x74\x10"
        license_routine += b"\xEB\x05"
        binary_data = b"\x90" * 100 + license_routine + b"\x90" * 100

        analysis = ai_bridge.analyze_binary_region(
            binary_data,
            offset=0,
            size=len(binary_data),
            query="Find conditional jumps that might be license checks",
        )

        assert "patterns" in analysis or "summary" in analysis

    def test_vmprotect_detection_workflow(self, ai_bridge: AIBinaryBridge, vmprotect_sample: bytes) -> None:
        """Complete workflow: detect VMProtect protection."""
        patterns = ai_bridge.identify_patterns(
            vmprotect_sample,
            offset=0,
            size=len(vmprotect_sample),
            known_patterns=[
                {"name": "VMProtect", "description": "VMProtect by Oreans signature"},
            ],
        )

        assert isinstance(patterns, list)

    def test_encryption_detection_workflow(self, ai_bridge: AIBinaryBridge, encrypted_data_sample: bytes) -> None:
        """Complete workflow: detect encrypted data segments."""
        context = ai_bridge.context_builder.build_context(
            encrypted_data_sample,
            offset=0,
            size=len(encrypted_data_sample),
            include_entropy=True,
            include_strings=False,
            include_structure_hints=False,
        )

        assert context["entropy"] > 7.0

        segments = context["entropy_segments"]
        high_entropy_segments = [s for s in segments if s["high_entropy"]]
        assert len(high_entropy_segments) > 0
