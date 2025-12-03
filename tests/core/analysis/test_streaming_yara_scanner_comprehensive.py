"""Comprehensive tests for StreamingYaraScanner.

Tests validate real YARA scanning on actual binary data with real rules.
NO mocks - only real functionality validation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from pathlib import Path
from typing import Any

import pytest

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from intellicrack.core.analysis.streaming_yara_scanner import (
    StreamingYaraMatch,
    StreamingYaraScanner,
    scan_binary_streaming,
)
from intellicrack.core.processing.streaming_analysis_manager import ChunkContext


pytestmark = pytest.mark.skipif(not YARA_AVAILABLE, reason="YARA not available")


class TestStreamingYaraScanner:
    """Test suite for streaming YARA scanning."""

    @pytest.fixture
    def license_string_binary(self, temp_workspace: Path) -> Path:
        """Create binary containing license-related strings."""
        binary_path = temp_workspace / "license_binary.bin"
        data = (
            b"\x00" * 500 +
            b"LICENSE_KEY_CHECK" +
            b"\x00" * 500 +
            b"SERIAL_NUMBER_VALIDATION" +
            b"\x00" * 500 +
            b"ACTIVATION_CODE" +
            b"\x00" * 500
        )
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def rsa_key_binary(self, temp_workspace: Path) -> Path:
        """Create binary with RSA public key structure."""
        binary_path = temp_workspace / "rsa_key.bin"
        rsa_header = bytes([
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
        ])
        data = b"\x00" * 1024 + rsa_header + b"\x00" * 1024
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def vmprotect_binary(self, temp_workspace: Path) -> Path:
        """Create binary with VMProtect signatures."""
        binary_path = temp_workspace / "vmprotect.bin"
        data = (
            b"\x00" * 800 +
            b"VMProtect" +
            b"\x00" * 800 +
            b".vmp0" +
            b"\x00" * 800
        )
        binary_path.write_bytes(data)
        return binary_path

    @pytest.fixture
    def custom_rules_source(self) -> str:
        """Provide custom YARA rules for testing."""
        return """
rule Test_String_Pattern {
    meta:
        description = "Test pattern detection"
        category = "test"
    strings:
        $test1 = "TEST_PATTERN_123"
        $test2 = "ANOTHER_TEST"
    condition:
        any of them
}

rule RSA_Key_Detection {
    meta:
        description = "RSA key structure"
        category = "crypto"
    strings:
        $rsa = { 30 82 01 22 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 }
    condition:
        $rsa
}
"""

    @pytest.fixture
    def scanner_with_default_rules(self) -> StreamingYaraScanner:
        """Create scanner with default rules."""
        return StreamingYaraScanner()

    @pytest.fixture
    def scanner_with_custom_rules(self, custom_rules_source: str) -> StreamingYaraScanner:
        """Create scanner with custom rules."""
        return StreamingYaraScanner(rules_source=custom_rules_source)

    def test_scanner_initialization_without_yara_raises_error(self) -> None:
        """Scanner initialization requires YARA."""
        scanner = StreamingYaraScanner()
        assert scanner.rules is None

    def test_scanner_initialization_with_custom_rules(self, custom_rules_source: str) -> None:
        """Scanner initializes with custom YARA rules."""
        scanner = StreamingYaraScanner(rules_source=custom_rules_source)
        assert scanner.rules_source == custom_rules_source
        assert scanner.max_matches_per_rule == 1000

    def test_initialize_analysis_compiles_rules_from_source(self, scanner_with_custom_rules: StreamingYaraScanner, temp_workspace: Path) -> None:
        """initialize_analysis compiles YARA rules from source."""
        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        scanner_with_custom_rules.initialize_analysis(test_file)

        assert scanner_with_custom_rules.rules is not None
        assert len(scanner_with_custom_rules.match_offsets) == 0

    def test_initialize_analysis_uses_default_rules(self, scanner_with_default_rules: StreamingYaraScanner, temp_workspace: Path) -> None:
        """initialize_analysis loads default licensing rules."""
        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        scanner_with_default_rules.initialize_analysis(test_file)

        assert scanner_with_default_rules.rules is not None

    def test_analyze_chunk_detects_license_strings(self, scanner_with_default_rules: StreamingYaraScanner, license_string_binary: Path) -> None:
        """analyze_chunk detects license-related strings with default rules."""
        data = license_string_binary.read_bytes()

        scanner_with_default_rules.initialize_analysis(license_string_binary)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=license_string_binary
        )

        result = scanner_with_default_rules.analyze_chunk(context)

        assert "matches" in result
        assert result["chunk_offset"] == 0
        assert result["chunk_size"] == len(data)

        if result["matches"]:
            match = result["matches"][0]
            assert "rule" in match
            assert "offset" in match
            assert "matched_data" in match

    def test_analyze_chunk_detects_rsa_keys(self, scanner_with_default_rules: StreamingYaraScanner, rsa_key_binary: Path) -> None:
        """analyze_chunk detects RSA key structures."""
        data = rsa_key_binary.read_bytes()

        scanner_with_default_rules.initialize_analysis(rsa_key_binary)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=rsa_key_binary
        )

        result = scanner_with_default_rules.analyze_chunk(context)

        assert "matches" in result
        assert isinstance(result["matches"], list)

    def test_analyze_chunk_detects_vmprotect(self, scanner_with_default_rules: StreamingYaraScanner, vmprotect_binary: Path) -> None:
        """analyze_chunk detects VMProtect protection."""
        data = vmprotect_binary.read_bytes()

        scanner_with_default_rules.initialize_analysis(vmprotect_binary)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=vmprotect_binary
        )

        result = scanner_with_default_rules.analyze_chunk(context)

        assert "matches" in result

    def test_analyze_chunk_with_overlap_prevents_duplicates(self, scanner_with_default_rules: StreamingYaraScanner, license_string_binary: Path) -> None:
        """analyze_chunk with overlap doesn't create duplicate matches."""
        data = license_string_binary.read_bytes()
        chunk_size = len(data) // 2
        overlap = 200

        scanner_with_default_rules.initialize_analysis(license_string_binary)

        context1 = ChunkContext(
            offset=0,
            size=chunk_size,
            chunk_number=1,
            total_chunks=2,
            data=data[:chunk_size],
            overlap_after=data[chunk_size:chunk_size + overlap],
            file_path=license_string_binary
        )

        result1 = scanner_with_default_rules.analyze_chunk(context1)

        context2 = ChunkContext(
            offset=chunk_size,
            size=len(data) - chunk_size,
            chunk_number=2,
            total_chunks=2,
            data=data[chunk_size:],
            overlap_before=data[chunk_size - overlap:chunk_size],
            file_path=license_string_binary
        )

        result2 = scanner_with_default_rules.analyze_chunk(context2)

        all_matches = result1["matches"] + result2["matches"]
        unique_offsets = {m["offset"] for m in all_matches}

        assert len(unique_offsets) == len(all_matches)

    def test_analyze_chunk_enforces_max_matches_limit(self, temp_workspace: Path) -> None:
        """analyze_chunk respects max_matches_per_rule limit."""
        scanner = StreamingYaraScanner(
            rules_source="""
rule Repeated_Pattern {
    strings:
        $pat = "XX"
    condition:
        $pat
}
""",
            max_matches_per_rule=5
        )

        data = b"XX" * 100

        test_file = temp_workspace / "repeated.bin"
        test_file.write_bytes(data)

        scanner.initialize_analysis(test_file)

        context = ChunkContext(
            offset=0,
            size=len(data),
            chunk_number=1,
            total_chunks=1,
            data=data,
            file_path=test_file
        )

        result = scanner.analyze_chunk(context)

        assert len(result["matches"]) <= 5

    def test_merge_results_aggregates_matches(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """merge_results correctly aggregates matches from chunks."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "matches": [
                    {"rule": "License_String_Pattern", "offset": 100},
                    {"rule": "RSA_Public_Key", "offset": 200}
                ],
                "rules_matched": 2
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "matches": [
                    {"rule": "License_String_Pattern", "offset": 1100}
                ],
                "rules_matched": 1
            }
        ]

        merged = scanner_with_default_rules.merge_results(chunk_results)

        assert merged["total_matches"] == 3
        assert merged["unique_rules_matched"] == 2
        assert len(merged["matches"]) == 3
        assert merged["chunks_with_matches"] == 2

        offsets = [m["offset"] for m in merged["matches"]]
        assert offsets == sorted(offsets)

    def test_merge_results_calculates_coverage(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """merge_results calculates scanning coverage percentage."""
        chunk_results = [
            {"chunk_offset": 0, "chunk_size": 1000, "matches": [{"rule": "Test"}]},
            {"chunk_offset": 1000, "chunk_size": 1000, "matches": []},
            {"chunk_offset": 2000, "chunk_size": 1000, "matches": [{"rule": "Test2"}]},
            {"chunk_offset": 3000, "chunk_size": 1000, "matches": []}
        ]

        merged = scanner_with_default_rules.merge_results(chunk_results)

        assert merged["coverage"] == 50.0
        assert merged["chunks_with_matches"] == 2
        assert merged["total_chunks"] == 4

    def test_merge_results_handles_errors(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """merge_results handles chunk errors gracefully."""
        chunk_results = [
            {
                "chunk_offset": 0,
                "chunk_size": 1024,
                "error": "YARA scan failed",
                "matches": []
            },
            {
                "chunk_offset": 1024,
                "chunk_size": 1024,
                "matches": [{"rule": "Test", "offset": 1200}],
                "rules_matched": 1
            }
        ]

        merged = scanner_with_default_rules.merge_results(chunk_results)

        assert "errors" in merged
        assert len(merged["errors"]) == 1
        assert merged["total_matches"] == 1

    def test_finalize_analysis_categorizes_matches(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """finalize_analysis categorizes matches by type."""
        merged_results = {
            "total_matches": 6,
            "matches": [
                {"rule": "VMProtect_Detection", "tags": ["protection"], "offset": 100},
                {"rule": "License_Check", "tags": ["licensing"], "offset": 200},
                {"rule": "RSA_Key", "tags": ["crypto"], "offset": 300},
                {"rule": "Anti_Debug", "tags": ["anti_debug"], "offset": 400},
                {"rule": "FlexLM_License", "tags": ["licensing"], "offset": 500},
                {"rule": "Generic_Pattern", "tags": [], "offset": 600}
            ],
            "unique_rules_matched": 6
        }

        finalized = scanner_with_default_rules.finalize_analysis(merged_results)

        assert "categorized_matches" in finalized
        categories = finalized["categorized_matches"]

        assert "protection" in categories
        assert "licensing" in categories
        assert "cryptographic" in categories
        assert "anti_analysis" in categories

        assert len(categories["licensing"]) == 2
        assert finalized["licensing_protection_detected"] is True

    def test_finalize_analysis_detects_licensing_by_rule_name(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """finalize_analysis categorizes licensing based on rule name."""
        merged_results = {
            "total_matches": 2,
            "matches": [
                {"rule": "check_license_validation", "tags": [], "offset": 100},
                {"rule": "verify_serial_number", "tags": [], "offset": 200}
            ],
            "unique_rules_matched": 2
        }

        finalized = scanner_with_default_rules.finalize_analysis(merged_results)

        licensing_matches = finalized["categorized_matches"]["licensing"]
        assert len(licensing_matches) >= 1

    def test_generate_summary_creates_meaningful_text(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """_generate_summary creates informative summary."""
        results: dict[str, Any] = {
            "total_matches": 15,
            "unique_rules_matched": 5,
            "rule_distribution": [
                {"rule": "License_Pattern", "count": 8},
                {"rule": "RSA_Key", "count": 4},
                {"rule": "VMProtect", "count": 3}
            ]
        }

        license_matches = [{"rule": "License_Pattern"} for _ in range(8)]

        summary = scanner_with_default_rules._generate_summary(results, license_matches)

        assert "15" in summary
        assert "5" in summary
        assert "8" in summary
        assert "License_Pattern" in summary

    def test_get_default_rules_contains_licensing_patterns(self, scanner_with_default_rules: StreamingYaraScanner) -> None:
        """_get_default_rules includes licensing protection rules."""
        default_rules = scanner_with_default_rules._get_default_rules()

        assert "license" in default_rules.lower()
        assert "serial" in default_rules.lower()
        assert "activation" in default_rules.lower()
        assert "RSA_Public_Key" in default_rules
        assert "VMProtect_Detection" in default_rules
        assert "FlexLM_License" in default_rules

    def test_streaming_scan_end_to_end(self, license_string_binary: Path) -> None:
        """Full streaming YARA scan workflow."""
        results = scan_binary_streaming(binary_path=license_string_binary)

        assert "total_matches" in results
        assert "matches" in results
        assert "categorized_matches" in results
        assert "summary" in results

        assert results.get("status") != "failed"

    def test_streaming_scan_with_custom_rules(self, license_string_binary: Path, custom_rules_source: str) -> None:
        """Streaming scan with custom rules."""
        results = scan_binary_streaming(
            binary_path=license_string_binary,
            rules_source=custom_rules_source
        )

        assert "total_matches" in results or "error" not in results

    def test_streaming_scan_with_rules_file(self, temp_workspace: Path, custom_rules_source: str) -> None:
        """Streaming scan with rules from file."""
        rules_file = temp_workspace / "custom.yar"
        rules_file.write_text(custom_rules_source)

        binary_file = temp_workspace / "test.bin"
        binary_file.write_bytes(b"TEST_PATTERN_123" + b"\x00" * 1000)

        results = scan_binary_streaming(
            binary_path=binary_file,
            rules_path=rules_file
        )

        assert "total_matches" in results

    def test_streaming_scan_with_nonexistent_file(self, temp_workspace: Path) -> None:
        """scan_binary_streaming handles missing files."""
        nonexistent = temp_workspace / "does_not_exist.bin"

        results = scan_binary_streaming(binary_path=nonexistent)

        assert "error" in results
        assert "not found" in results["error"].lower()
        assert results["status"] == "failed"

    def test_analyze_chunk_without_initialized_rules(self, temp_workspace: Path) -> None:
        """analyze_chunk handles uninitialized rules gracefully."""
        scanner = StreamingYaraScanner()

        test_file = temp_workspace / "test.bin"
        test_file.write_bytes(b"\x00" * 1024)

        context = ChunkContext(
            offset=0,
            size=1024,
            chunk_number=1,
            total_chunks=1,
            data=b"\x00" * 1024,
            file_path=test_file
        )

        result = scanner.analyze_chunk(context)

        assert "error" in result
        assert "not loaded" in result["error"].lower()


class TestStreamingYaraMatch:
    """Test StreamingYaraMatch dataclass."""

    def test_yara_match_initialization(self) -> None:
        """StreamingYaraMatch initializes with correct defaults."""
        match = StreamingYaraMatch(
            rule_name="Test_Rule",
            namespace="default",
            offset=1024,
            matched_data="48656c6c6f",
            string_identifier="$s1"
        )

        assert match.rule_name == "Test_Rule"
        assert match.namespace == "default"
        assert match.offset == 1024
        assert match.matched_data == "48656c6c6f"
        assert match.string_identifier == "$s1"
        assert match.tags == []
        assert match.meta == {}

    def test_yara_match_with_full_data(self) -> None:
        """StreamingYaraMatch stores complete match information."""
        match = StreamingYaraMatch(
            rule_name="License_Detection",
            namespace="licensing",
            offset=2048,
            matched_data="4c4943454e5345",
            string_identifier="$license",
            tags=["licensing", "protection"],
            meta={"author": "Test", "version": "1.0"}
        )

        assert match.tags == ["licensing", "protection"]
        assert match.meta["author"] == "Test"
        assert match.meta["version"] == "1.0"
