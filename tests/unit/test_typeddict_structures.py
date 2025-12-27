"""Unit tests for TypedDict structures across the codebase.

Copyright (C) 2025 Zachary Flint
This file is part of Intellicrack.

Tests validate that TypedDict structures properly define expected types
and that they can be used with runtime validation utilities.
"""

from typing import Any

import pytest

try:
    from intellicrack.ai.script_generation_agent import (
        BinaryFormatNetworkResult,
        NetworkAnalysisResult,
        NetworkCodeAnalysisResult,
        NetworkStringsResult,
    )
    from intellicrack.core.analysis.radare2_enhanced_integration import AnalysisTimingStats, CachedResult, PerformanceStats
    from intellicrack.plugins.custom_modules.intellicrack_core_engine import ScriptMetadataDict
    from intellicrack.utils.type_safety import ensure_dict, ensure_list, get_typed_item, validate_type
    TYPEDDICT_IMPORTS_AVAILABLE = True
except ImportError:
    TYPEDDICT_IMPORTS_AVAILABLE = False
    BinaryFormatNetworkResult = None
    NetworkAnalysisResult = None
    NetworkCodeAnalysisResult = None
    NetworkStringsResult = None
    AnalysisTimingStats = None
    CachedResult = None
    PerformanceStats = None
    ScriptMetadataDict = None
    ensure_dict = None
    ensure_list = None
    get_typed_item = None
    validate_type = None


pytestmark = pytest.mark.skipif(
    not TYPEDDICT_IMPORTS_AVAILABLE,
    reason="TypedDict modules not available"
)


class TestAnalysisTimingStatsTypedDict:
    """Tests for AnalysisTimingStats TypedDict from radare2_enhanced_integration.py."""

    def test_valid_analysis_timing_stats_structure(self) -> None:
        """Test that valid AnalysisTimingStats structure can be created."""
        stats: AnalysisTimingStats = {
            "times": [0.5, 1.2, 0.8],
            "successes": 5,
            "failures": 1,
        }

        assert stats["times"] == [0.5, 1.2, 0.8]
        assert stats["successes"] == 5
        assert stats["failures"] == 1

    def test_analysis_timing_stats_with_empty_times(self) -> None:
        """Test AnalysisTimingStats with empty times list."""
        stats: AnalysisTimingStats = {
            "times": [],
            "successes": 0,
            "failures": 0,
        }

        assert stats["times"] == []
        assert stats["successes"] == 0

    def test_runtime_validation_of_timing_stats_fields(self) -> None:
        """Test runtime validation of AnalysisTimingStats fields using type_safety utilities."""
        stats: dict[str, Any] = {
            "times": [0.5, 1.2, 0.8],
            "successes": 5,
            "failures": 1,
        }

        times = get_typed_item(stats, "times", list)
        assert all(isinstance(t, float) for t in times)

        successes = get_typed_item(stats, "successes", int)
        assert successes == 5

    def test_runtime_validation_catches_invalid_times_type(self) -> None:
        """Test that runtime validation catches incorrect times type."""
        invalid_stats: dict[str, Any] = {
            "times": "not a list",
            "successes": 5,
            "failures": 1,
        }

        with pytest.raises(TypeError, match="Expected key 'times' to be list"):
            get_typed_item(invalid_stats, "times", list)


class TestCachedResultTypedDict:
    """Tests for CachedResult TypedDict from radare2_enhanced_integration.py."""

    def test_valid_cached_result_structure(self) -> None:
        """Test that valid CachedResult structure can be created."""
        import time

        cached: CachedResult = {
            "result": {"status": "success", "data": [1, 2, 3]},
            "timestamp": time.time(),
        }

        assert "status" in cached["result"]
        assert cached["result"]["status"] == "success"
        assert isinstance(cached["timestamp"], float)

    def test_cached_result_with_complex_nested_data(self) -> None:
        """Test CachedResult with complex nested result data."""
        cached: CachedResult = {
            "result": {
                "analysis_type": "static",
                "findings": [
                    {"address": 0x1000, "severity": "high"},
                    {"address": 0x2000, "severity": "medium"},
                ],
                "metadata": {"binary_hash": "abc123"},
            },
            "timestamp": 1704067200.0,
        }

        assert len(cached["result"]["findings"]) == 2
        assert cached["result"]["findings"][0]["address"] == 0x1000

    def test_runtime_validation_of_cached_result(self) -> None:
        """Test runtime validation of CachedResult fields."""
        data: dict[str, Any] = {
            "result": {"key": "value"},
            "timestamp": 1704067200.0,
        }

        result = ensure_dict(data["result"])
        assert result == {"key": "value"}

        timestamp = get_typed_item(data, "timestamp", float)
        assert timestamp == 1704067200.0


class TestPerformanceStatsTypedDict:
    """Tests for PerformanceStats TypedDict from radare2_enhanced_integration.py."""

    def test_valid_performance_stats_structure(self) -> None:
        """Test that valid PerformanceStats structure can be created."""
        timing_stats: AnalysisTimingStats = {
            "times": [0.5, 1.0],
            "successes": 3,
            "failures": 0,
        }

        perf_stats: PerformanceStats = {
            "analysis_times": {"static_analysis": timing_stats},
            "cache_hits": 50,
            "cache_misses": 10,
            "errors_handled": 2,
            "recoveries_successful": 1,
        }

        assert perf_stats["cache_hits"] == 50
        assert perf_stats["analysis_times"]["static_analysis"]["successes"] == 3

    def test_performance_stats_with_multiple_analysis_types(self) -> None:
        """Test PerformanceStats with multiple analysis types."""
        perf_stats: PerformanceStats = {
            "analysis_times": {
                "static": {"times": [0.1], "successes": 1, "failures": 0},
                "dynamic": {"times": [2.5, 3.0], "successes": 2, "failures": 1},
                "vulnerability": {"times": [1.0, 1.5, 2.0], "successes": 3, "failures": 0},
            },
            "cache_hits": 100,
            "cache_misses": 20,
            "errors_handled": 5,
            "recoveries_successful": 4,
        }

        assert len(perf_stats["analysis_times"]) == 3
        assert perf_stats["analysis_times"]["dynamic"]["failures"] == 1

    def test_runtime_validation_of_performance_stats(self) -> None:
        """Test runtime validation of PerformanceStats fields."""
        data: dict[str, Any] = {
            "analysis_times": {"test": {"times": [], "successes": 0, "failures": 0}},
            "cache_hits": 10,
            "cache_misses": 5,
            "errors_handled": 0,
            "recoveries_successful": 0,
        }

        cache_hits = get_typed_item(data, "cache_hits", int)
        assert cache_hits == 10

        analysis_times = ensure_dict(data["analysis_times"])
        assert "test" in analysis_times


class TestNetworkStringsResultTypedDict:
    """Tests for NetworkStringsResult TypedDict from script_generation_agent.py."""

    def test_valid_network_strings_result_structure(self) -> None:
        """Test that valid NetworkStringsResult structure can be created."""
        result: NetworkStringsResult = {
            "strings": ["http://example.com", "api.service.com"],
            "endpoints": ["https://api.example.com/v1"],
            "protocols": ["HTTP", "HTTPS"],
            "count": 3,
        }

        assert len(result["strings"]) == 2
        assert result["count"] == 3

    def test_network_strings_result_with_empty_data(self) -> None:
        """Test NetworkStringsResult with empty data (no network activity detected)."""
        result: NetworkStringsResult = {
            "strings": [],
            "endpoints": [],
            "protocols": [],
            "count": 0,
        }

        assert result["count"] == 0
        assert not result["strings"]

    def test_runtime_validation_of_network_strings_result(self) -> None:
        """Test runtime validation of NetworkStringsResult fields."""
        data: dict[str, Any] = {
            "strings": ["test.com"],
            "endpoints": [],
            "protocols": ["TCP"],
            "count": 1,
        }

        strings = ensure_list(data["strings"])
        assert strings == ["test.com"]

        count = get_typed_item(data, "count", int)
        assert count == 1


class TestNetworkCodeAnalysisResultTypedDict:
    """Tests for NetworkCodeAnalysisResult TypedDict from script_generation_agent.py."""

    def test_valid_network_code_analysis_result(self) -> None:
        """Test that valid NetworkCodeAnalysisResult structure can be created."""
        result: NetworkCodeAnalysisResult = {
            "apis": ["socket", "connect", "send", "recv"],
            "found": True,
        }

        assert len(result["apis"]) == 4
        assert result["found"] is True

    def test_network_code_analysis_result_no_apis_found(self) -> None:
        """Test NetworkCodeAnalysisResult when no network APIs found."""
        result: NetworkCodeAnalysisResult = {
            "apis": [],
            "found": False,
        }

        assert not result["apis"]
        assert result["found"] is False

    def test_runtime_validation_of_network_code_result(self) -> None:
        """Test runtime validation of NetworkCodeAnalysisResult fields."""
        data: dict[str, Any] = {
            "apis": ["WinHttpOpen", "InternetConnect"],
            "found": True,
        }

        apis = ensure_list(data["apis"])
        assert "WinHttpOpen" in apis

        found = validate_type(data["found"], bool, "found")
        assert found is True


class TestBinaryFormatNetworkResultTypedDict:
    """Tests for BinaryFormatNetworkResult TypedDict from script_generation_agent.py."""

    def test_valid_binary_format_network_result(self) -> None:
        """Test that valid BinaryFormatNetworkResult structure can be created."""
        result: BinaryFormatNetworkResult = {
            "has_network": True,
            "endpoints": ["192.168.1.1:8080", "api.example.com:443"],
            "protocols": ["TCP", "UDP", "HTTP"],
            "indicators": ["TLS handshake", "Certificate pinning detected"],
        }

        assert result["has_network"] is True
        assert len(result["endpoints"]) == 2
        assert "TCP" in result["protocols"]

    def test_binary_format_no_network_indicators(self) -> None:
        """Test BinaryFormatNetworkResult with no network indicators."""
        result: BinaryFormatNetworkResult = {
            "has_network": False,
            "endpoints": [],
            "protocols": [],
            "indicators": [],
        }

        assert result["has_network"] is False

    def test_runtime_validation_of_binary_format_result(self) -> None:
        """Test runtime validation of BinaryFormatNetworkResult fields."""
        data: dict[str, Any] = {
            "has_network": True,
            "endpoints": ["test.com"],
            "protocols": ["HTTPS"],
            "indicators": ["SSL"],
        }

        has_network = validate_type(data["has_network"], bool, "has_network")
        assert has_network is True

        indicators = ensure_list(data["indicators"])
        assert "SSL" in indicators


class TestNetworkAnalysisResultTypedDict:
    """Tests for NetworkAnalysisResult TypedDict from script_generation_agent.py."""

    def test_valid_network_analysis_result(self) -> None:
        """Test that valid NetworkAnalysisResult structure can be created."""
        result: NetworkAnalysisResult = {
            "has_network": True,
            "binary_path": "C:\\target\\app.exe",
            "binary_size": 1048576,
            "endpoints": ["https://license.server.com/validate"],
            "protocols": ["HTTPS", "TLS 1.3"],
            "network_apis": ["WinHttpOpen", "WinHttpSendRequest"],
            "strings_found": ["license.server.com", "activation"],
            "imports_found": ["winhttp.dll", "ws2_32.dll"],
            "confidence": 0.95,
        }

        assert result["has_network"] is True
        assert result["binary_size"] == 1048576
        assert result["confidence"] == 0.95

    def test_network_analysis_result_offline_binary(self) -> None:
        """Test NetworkAnalysisResult for offline binary."""
        result: NetworkAnalysisResult = {
            "has_network": False,
            "binary_path": "C:\\target\\offline.exe",
            "binary_size": 524288,
            "endpoints": [],
            "protocols": [],
            "network_apis": [],
            "strings_found": [],
            "imports_found": [],
            "confidence": 0.0,
        }

        assert result["has_network"] is False
        assert result["confidence"] == 0.0

    def test_runtime_validation_of_full_network_result(self) -> None:
        """Test comprehensive runtime validation of NetworkAnalysisResult."""
        data: dict[str, Any] = {
            "has_network": True,
            "binary_path": "/path/to/binary",
            "binary_size": 100000,
            "endpoints": ["example.com"],
            "protocols": ["HTTP"],
            "network_apis": ["socket"],
            "strings_found": ["host"],
            "imports_found": ["libc.so"],
            "confidence": 0.85,
        }

        binary_path = get_typed_item(data, "binary_path", str)
        assert binary_path == "/path/to/binary"

        binary_size = get_typed_item(data, "binary_size", int)
        assert binary_size == 100000

        confidence = get_typed_item(data, "confidence", float)
        assert 0.0 <= confidence <= 1.0

    def test_runtime_validation_catches_invalid_confidence(self) -> None:
        """Test that runtime validation catches non-float confidence."""
        data: dict[str, Any] = {
            "confidence": "high",
        }

        with pytest.raises(TypeError, match="Expected key 'confidence' to be float"):
            get_typed_item(data, "confidence", float)


class TestScriptMetadataDictTypedDict:
    """Tests for ScriptMetadataDict TypedDict from intellicrack_core_engine.py."""

    def test_valid_script_metadata_structure(self) -> None:
        """Test that valid ScriptMetadataDict structure can be created."""
        metadata: ScriptMetadataDict = {
            "name": "License Bypass Script",
            "version": "1.0.0",
            "description": "Bypasses license validation in target application",
            "author": "Intellicrack",
            "capabilities": ["license_bypass", "registry_manipulation"],
            "dependencies": ["frida", "capstone"],
        }

        assert metadata["name"] == "License Bypass Script"
        assert "license_bypass" in metadata["capabilities"]

    def test_script_metadata_with_empty_capabilities(self) -> None:
        """Test ScriptMetadataDict with empty capabilities and dependencies."""
        metadata: ScriptMetadataDict = {
            "name": "Basic Script",
            "version": "0.1.0",
            "description": "Minimal script",
            "author": "Unknown",
            "capabilities": [],
            "dependencies": [],
        }

        assert not metadata["capabilities"]
        assert not metadata["dependencies"]

    def test_runtime_validation_of_script_metadata(self) -> None:
        """Test runtime validation of ScriptMetadataDict fields."""
        data: dict[str, Any] = {
            "name": "Test Script",
            "version": "2.0.0",
            "description": "Test description",
            "author": "Tester",
            "capabilities": ["test_cap"],
            "dependencies": ["dep1"],
        }

        name = get_typed_item(data, "name", str)
        assert name == "Test Script"

        capabilities = ensure_list(data["capabilities"])
        assert capabilities == ["test_cap"]

    def test_runtime_validation_catches_invalid_name_type(self) -> None:
        """Test that runtime validation catches non-string name."""
        data: dict[str, Any] = {
            "name": 12345,
        }

        with pytest.raises(TypeError, match="Expected key 'name' to be str"):
            get_typed_item(data, "name", str)

    def test_script_metadata_for_ghidra_script(self) -> None:
        """Test ScriptMetadataDict for Ghidra analysis script."""
        metadata: ScriptMetadataDict = {
            "name": "Protection Analyzer",
            "version": "1.2.0",
            "description": "Analyzes binary protection mechanisms using Ghidra",
            "author": "Intellicrack Team",
            "capabilities": [
                "protection_detection",
                "control_flow_analysis",
                "decompilation",
            ],
            "dependencies": ["ghidra", "pyhidra"],
        }

        assert "protection_detection" in metadata["capabilities"]
        assert "ghidra" in metadata["dependencies"]

    def test_script_metadata_for_frida_script(self) -> None:
        """Test ScriptMetadataDict for Frida hook script."""
        metadata: ScriptMetadataDict = {
            "name": "Runtime License Interceptor",
            "version": "3.0.0",
            "description": "Intercepts and modifies license validation at runtime",
            "author": "Intellicrack",
            "capabilities": [
                "function_hooking",
                "memory_manipulation",
                "api_interception",
                "return_value_spoofing",
            ],
            "dependencies": ["frida", "frida-tools"],
        }

        assert len(metadata["capabilities"]) == 4
        assert "frida" in metadata["dependencies"]


class TestTypedDictIntegrationWithEnsureFunctions:
    """Integration tests for TypedDicts with ensure_* validation functions."""

    def test_ensure_dict_validates_nested_typeddict_data(self) -> None:
        """Test that ensure_dict properly validates nested TypedDict-like data."""
        outer_data: dict[str, Any] = {
            "inner_result": {
                "strings": ["test"],
                "endpoints": [],
                "protocols": [],
                "count": 1,
            }
        }

        inner = ensure_dict(outer_data["inner_result"])
        assert inner["count"] == 1

    def test_ensure_list_validates_typeddict_list_fields(self) -> None:
        """Test that ensure_list properly validates list fields in TypedDict."""
        data: dict[str, Any] = {
            "capabilities": ["cap1", "cap2", "cap3"],
            "not_a_list": {"key": "value"},
        }

        caps = ensure_list(data["capabilities"])
        assert len(caps) == 3

        with pytest.raises(TypeError, match="to be list, got dict"):
            ensure_list(data["not_a_list"])

    def test_get_typed_item_with_default_for_missing_typeddict_field(self) -> None:
        """Test get_typed_item with defaults for potentially missing TypedDict fields."""
        data: dict[str, Any] = {
            "name": "Test",
        }

        name = get_typed_item(data, "name", str)
        assert name == "Test"

        version = get_typed_item(data, "version", str, default="0.0.0")
        assert version == "0.0.0"

    def test_validate_type_for_typeddict_boolean_fields(self) -> None:
        """Test validate_type for boolean fields common in TypedDicts."""
        assert validate_type(True, bool) is True
        assert validate_type(False, bool) is False

        with pytest.raises(TypeError):
            validate_type(1, bool)

        with pytest.raises(TypeError):
            validate_type("true", bool)

    def test_validate_type_for_typeddict_numeric_fields(self) -> None:
        """Test validate_type for numeric fields in TypedDicts."""
        assert validate_type(42, int) == 42
        assert validate_type(3.14, float) == 3.14

        with pytest.raises(TypeError):
            validate_type(42, float)

        with pytest.raises(TypeError):
            validate_type("100", int)


class TestTypedDictEdgeCases:
    """Edge case tests for TypedDict structures."""

    def test_analysis_timing_stats_with_large_times_list(self) -> None:
        """Test AnalysisTimingStats with large list of timing data."""
        times = [0.1 * i for i in range(1000)]

        stats: AnalysisTimingStats = {
            "times": times,
            "successes": 900,
            "failures": 100,
        }

        assert len(stats["times"]) == 1000
        assert stats["successes"] + stats["failures"] == 1000

    def test_network_analysis_with_long_strings(self) -> None:
        """Test NetworkAnalysisResult with very long endpoint URLs."""
        long_endpoint = "https://" + "a" * 2000 + ".com/path/to/endpoint"

        result: NetworkAnalysisResult = {
            "has_network": True,
            "binary_path": "test.exe",
            "binary_size": 0,
            "endpoints": [long_endpoint],
            "protocols": [],
            "network_apis": [],
            "strings_found": [],
            "imports_found": [],
            "confidence": 0.5,
        }

        assert len(result["endpoints"][0]) > 2000

    def test_script_metadata_with_unicode_characters(self) -> None:
        """Test ScriptMetadataDict with unicode characters."""
        metadata: ScriptMetadataDict = {
            "name": "Скрипт Анализа",
            "version": "1.0.0",
            "description": "分析二进制文件的脚本",
            "author": "開発者",
            "capabilities": ["分析", "検出"],
            "dependencies": [],
        }

        assert metadata["name"] == "Скрипт Анализа"
        assert "分析" in metadata["capabilities"]

    def test_cached_result_with_very_old_timestamp(self) -> None:
        """Test CachedResult with very old timestamp (cache expiration edge case)."""
        cached: CachedResult = {
            "result": {"status": "expired"},
            "timestamp": 0.0,
        }

        assert cached["timestamp"] == 0.0

    def test_performance_stats_with_zero_cache_activity(self) -> None:
        """Test PerformanceStats with no cache activity."""
        stats: PerformanceStats = {
            "analysis_times": {},
            "cache_hits": 0,
            "cache_misses": 0,
            "errors_handled": 0,
            "recoveries_successful": 0,
        }

        assert stats["cache_hits"] == 0
        assert not stats["analysis_times"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
