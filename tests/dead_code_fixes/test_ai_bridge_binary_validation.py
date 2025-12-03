"""Tests for binary_data pattern validation in ai_bridge.py.

This tests that the binary_data parameter is properly used to validate
AI-suggested patterns, edits, and search results against actual binary content.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    pass


class TestAIBridgeBinaryValidation:
    """Test suite for AI bridge binary validation functionality."""

    def test_ai_bridge_import(self) -> None:
        """Verify AIBinaryBridge can be imported."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        assert AIBinaryBridge is not None

    def test_parse_analysis_response_validates_patterns(self) -> None:
        """Test that pattern validation adds 'validated' field."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x4D\x5A\x90\x00\x03\x00\x00\x00"
        offset = 0

        response = json.dumps({
            "patterns": [
                {
                    "hex_pattern": "4D 5A 90 00",
                    "start_offset": 0,
                    "end_offset": 4,
                    "description": "DOS header signature",
                }
            ],
            "anomalies": [],
            "data_meaning": "PE executable header",
            "summary": "Windows executable",
        })

        result = bridge._parse_analysis_response(response, binary_data, offset)

        assert "patterns" in result
        assert len(result["patterns"]) == 1
        assert result["patterns"][0].get("validated") is True

    def test_parse_analysis_response_invalid_pattern(self) -> None:
        """Test that non-matching patterns are marked as not validated."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x4D\x5A\x90\x00\x03\x00\x00\x00"
        offset = 0

        response = json.dumps({
            "patterns": [
                {
                    "hex_pattern": "FF FF FF FF",
                    "start_offset": 0,
                    "end_offset": 4,
                    "description": "Wrong pattern",
                }
            ],
            "anomalies": [],
        })

        result = bridge._parse_analysis_response(response, binary_data, offset)

        assert result["patterns"][0].get("validated") is False

    def test_parse_edit_response_validates_bytes_match(self) -> None:
        """Test that edit suggestions validate original bytes."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x74\x05\x90\x90\x90"
        offset = 0

        response = json.dumps({
            "offset": 0,
            "original_bytes": "74 05",
            "new_bytes": "EB 05",
            "explanation": "Patch JZ to JMP",
            "consequences": "Always takes branch",
        })

        result = bridge._parse_edit_response(response, binary_data, offset)

        assert result.get("bytes_match") is True
        assert result.get("original_bytes_raw") == b"\x74\x05"

    def test_parse_edit_response_mismatch_detected(self) -> None:
        """Test that byte mismatches are detected and reported."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x75\x05\x90\x90\x90"
        offset = 0

        response = json.dumps({
            "offset": 0,
            "original_bytes": "74 05",
            "new_bytes": "EB 05",
            "explanation": "Patch JZ to JMP",
            "consequences": "Always takes branch",
        })

        result = bridge._parse_edit_response(response, binary_data, offset)

        assert result.get("bytes_match") is False
        assert "actual_bytes" in result

    def test_parse_pattern_response_validates_hex_bytes(self) -> None:
        """Test that identified patterns are validated against binary."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x55\x8B\xEC\x83\xEC\x10"
        offset = 0

        response = json.dumps({
            "identified_patterns": [
                {
                    "hex_bytes": "55 8B EC",
                    "start_offset": 0,
                    "end_offset": 3,
                    "pattern_type": "function_prologue",
                }
            ]
        })

        result = bridge._parse_pattern_response(response, binary_data, offset)

        assert len(result) == 1
        assert result[0].get("validated") is True

    def test_parse_search_response_includes_matched_bytes(self) -> None:
        """Test that search results include actual matched bytes."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x00\x00\x00LICENSE\x00\x00\x00"
        offset = 0

        response = json.dumps({
            "matches": [
                {
                    "start_offset": 3,
                    "end_offset": 10,
                    "description": "License string",
                    "relevance_score": 0.9,
                }
            ]
        })

        result = bridge._parse_search_response(response, binary_data, offset)

        assert len(result) == 1
        assert "matched_bytes" in result[0]
        assert result[0]["matched_bytes"] == "4c4943454e5345"

    def test_offset_adjustment_with_validation(self) -> None:
        """Test that offsets are properly adjusted during validation."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x4D\x5A\x90\x00"
        base_offset = 1000

        response = json.dumps({
            "patterns": [
                {
                    "hex_pattern": "4D 5A",
                    "start_offset": 0,
                    "end_offset": 2,
                }
            ],
            "anomalies": [],
        })

        result = bridge._parse_analysis_response(response, binary_data, base_offset)

        assert result["patterns"][0]["start_offset"] == 1000
        assert result["patterns"][0].get("validated") is True

    def test_empty_binary_data_handling(self) -> None:
        """Test handling when binary_data is empty."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        response = json.dumps({
            "patterns": [
                {
                    "hex_pattern": "4D 5A",
                    "start_offset": 0,
                }
            ],
            "anomalies": [],
        })

        result = bridge._parse_analysis_response(response, b"", 0)

        assert "validated" not in result["patterns"][0] or result["patterns"][0]["validated"] is False

    def test_malformed_hex_pattern_handling(self) -> None:
        """Test handling of malformed hex patterns."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x4D\x5A\x90\x00"

        response = json.dumps({
            "patterns": [
                {
                    "hex_pattern": "ZZ XX",
                    "start_offset": 0,
                }
            ],
            "anomalies": [],
        })

        result = bridge._parse_analysis_response(response, binary_data, 0)

        assert result["patterns"][0].get("validated") is False

    def test_parse_response_with_invalid_json(self) -> None:
        """Test handling of invalid JSON responses."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        result = bridge._parse_analysis_response("not valid json", b"\x00", 0)

        assert "patterns" in result
        assert len(result["patterns"]) == 0

    def test_offset_out_of_bounds_handling(self) -> None:
        """Test handling when pattern offset is out of bounds."""
        from intellicrack.hexview.ai_bridge import AIBinaryBridge

        bridge = AIBinaryBridge()

        binary_data = b"\x4D\x5A"

        response = json.dumps({
            "patterns": [
                {
                    "hex_pattern": "4D 5A 90 00",
                    "start_offset": 0,
                }
            ],
            "anomalies": [],
        })

        result = bridge._parse_analysis_response(response, binary_data, 0)

        assert result["patterns"][0].get("validated") is False
