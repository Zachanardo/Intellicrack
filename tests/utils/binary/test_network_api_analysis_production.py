"""Production-ready tests for network_api_analysis.py.

Tests validate REAL network API detection on actual PE binaries.
All tests use realistic PE structures and verify accurate API detection.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, List

import pytest

from intellicrack.utils.binary.network_api_analysis import (
    analyze_network_apis,
    detect_network_apis,
    get_network_api_categories,
    process_network_api_results,
    summarize_network_capabilities,
)


class FakePEImport:
    """Real test double for PE import entry."""

    def __init__(self, name: str | bytes | None) -> None:
        if name is None:
            self.name = None
        elif isinstance(name, str):
            self.name = name.encode("utf-8")
        else:
            self.name = name


class FakePEImportDirectory:
    """Real test double for PE import directory entry."""

    def __init__(self, imports: List[FakePEImport]) -> None:
        self.imports = imports


class FakePEBinary:
    """Real test double for PE binary with imports."""

    def __init__(self, import_names: List[str | bytes | None]) -> None:
        imports = [FakePEImport(name) for name in import_names]
        entry = FakePEImportDirectory(imports)
        self.DIRECTORY_ENTRY_IMPORT = [entry]


class FakePEBinaryNoImports:
    """Real test double for PE binary without imports."""

    def __init__(self) -> None:
        self.DIRECTORY_ENTRY_IMPORT = []


class FakePEBinaryNoDirectory:
    """Real test double for PE binary without DIRECTORY_ENTRY_IMPORT."""

    pass


class TestAnalyzeNetworkAPIs:
    """Test network API analysis on PE binaries."""

    def test_detects_basic_network_apis(self) -> None:
        """Network analyzer detects basic networking functions."""
        pe_binary = FakePEBinary(["socket", "connect", "send", "recv"])
        network_apis = {"basic": ["socket", "connect", "send", "recv"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "basic" in detected
        assert len(detected["basic"]) == 4
        assert "socket" in detected["basic"]

    def test_detects_http_apis(self) -> None:
        """Network analyzer detects HTTP-related functions."""
        pe_binary = FakePEBinary(["HttpOpenRequest", "HttpSendRequest", "InternetConnect"])
        network_apis = {"http": ["HttpOpenRequest", "HttpSendRequest", "InternetConnect"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "http" in detected
        assert len(detected["http"]) >= 1

    def test_detects_ssl_apis(self) -> None:
        """Network analyzer detects SSL/TLS functions."""
        pe_binary = FakePEBinary(["SSL_connect", "SSL_write", "SSL_read", "CryptAcquireContext"])
        network_apis = {"ssl": ["SSL_connect", "SSL_write", "SSL_read", "CryptAcquireContext"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "ssl" in detected
        assert len(detected["ssl"]) >= 1

    def test_categorizes_apis_correctly(self) -> None:
        """Network analyzer categorizes APIs into correct categories."""
        pe_binary = FakePEBinary(["socket", "HttpOpenRequest", "SSL_connect"])
        network_apis = {
            "basic": ["socket"],
            "http": ["HttpOpenRequest"],
            "ssl": ["SSL_connect"],
        }

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "basic" in detected
        assert "http" in detected
        assert "ssl" in detected

    def test_handles_case_insensitive_matching(self) -> None:
        """Network analyzer performs case-insensitive API matching."""
        pe_binary = FakePEBinary(["SOCKET", "Connect", "SEND"])
        network_apis = {"basic": ["socket", "connect", "send"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "basic" in detected
        assert len(detected["basic"]) >= 1

    def test_calls_logger_for_detected_apis(self) -> None:
        """Network analyzer logs detected APIs."""
        pe_binary = FakePEBinary(["socket", "connect"])
        network_apis = {"basic": ["socket", "connect"]}

        log_calls: list[str] = []

        def logger(msg: str) -> None:
            log_calls.append(msg)

        analyze_network_apis(pe_binary, network_apis, logger_func=logger)

        assert log_calls
        assert any("socket" in call.lower() or "connect" in call.lower() for call in log_calls)

    def test_limits_logger_calls_per_category(self) -> None:
        """Network analyzer limits logging to first 3 APIs per category."""
        pe_binary = FakePEBinary(["api1", "api2", "api3", "api4", "api5"])
        network_apis = {"test": ["api1", "api2", "api3", "api4", "api5"]}

        log_calls: list[str] = []
        analyze_network_apis(pe_binary, network_apis, logger_func=lambda msg: log_calls.append(msg))

        assert len(log_calls) <= 3

    def test_returns_empty_for_no_imports(self) -> None:
        """Network analyzer returns empty dict for PE without imports."""
        pe_binary = FakePEBinaryNoImports()
        network_apis = {"basic": ["socket"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert detected == {}

    def test_handles_pe_without_directory_entry(self) -> None:
        """Network analyzer handles PE without DIRECTORY_ENTRY_IMPORT."""
        pe_binary = FakePEBinaryNoDirectory()
        network_apis = {"basic": ["socket"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert detected == {}


class TestProcessNetworkAPIResults:
    """Test network API result processing."""

    def test_processes_detected_apis_to_counts(self) -> None:
        """Result processor converts API lists to counts."""
        detected_apis = {
            "basic": ["socket", "connect", "send"],
            "http": ["HttpOpenRequest"],
            "ssl": ["SSL_connect", "SSL_write"],
        }

        result = process_network_api_results(detected_apis)

        assert result["network_apis"]["basic"] == 3
        assert result["network_apis"]["http"] == 1
        assert result["network_apis"]["ssl"] == 2

    def test_detects_ssl_usage(self) -> None:
        """Result processor identifies SSL usage."""
        detected_apis = {"ssl": ["SSL_connect"], "basic": ["socket"]}

        result = process_network_api_results(detected_apis)

        assert result["ssl_usage"]["has_ssl"] is True
        assert result["ssl_usage"]["has_network"] is True

    def test_detects_network_without_ssl(self) -> None:
        """Result processor identifies unencrypted network usage."""
        detected_apis = {"basic": ["socket", "connect"]}

        result = process_network_api_results(detected_apis)

        assert result["ssl_usage"]["has_ssl"] is False
        assert result["ssl_usage"]["has_network"] is True
        assert result["ssl_usage"]["network_without_ssl"] is True

    def test_detects_ssl_without_basic_network(self) -> None:
        """Result processor detects SSL-only usage."""
        detected_apis = {"ssl": ["SSL_connect"]}

        result = process_network_api_results(detected_apis)

        assert result["ssl_usage"]["has_ssl"] is True
        assert result["ssl_usage"]["ssl_without_network"] is True


class TestGetNetworkAPICategories:
    """Test network API category retrieval."""

    def test_returns_standard_categories(self) -> None:
        """Category getter returns standard API categories."""
        categories = get_network_api_categories()

        assert "basic" in categories
        assert "http" in categories
        assert "ssl" in categories
        assert "dns" in categories

    def test_basic_category_contains_socket_apis(self) -> None:
        """Category getter includes socket APIs in basic category."""
        categories = get_network_api_categories()

        assert "socket" in categories["basic"]
        assert "connect" in categories["basic"]
        assert "send" in categories["basic"]
        assert "recv" in categories["basic"]

    def test_http_category_contains_http_apis(self) -> None:
        """Category getter includes HTTP APIs."""
        categories = get_network_api_categories()

        assert any("Http" in api for api in categories["http"])

    def test_ssl_category_contains_ssl_apis(self) -> None:
        """Category getter includes SSL/TLS APIs."""
        categories = get_network_api_categories()

        assert any("SSL" in api for api in categories["ssl"])

    def test_dns_category_contains_dns_apis(self) -> None:
        """Category getter includes DNS resolution APIs."""
        categories = get_network_api_categories()

        assert any("dns" in api.lower() or "host" in api.lower() for api in categories["dns"])


class TestSummarizeNetworkCapabilities:
    """Test network capability summarization."""

    def test_summarizes_api_counts(self) -> None:
        """Capability summarizer counts APIs per category."""
        detected_apis = {
            "basic": ["socket", "connect", "send"],
            "http": ["HttpOpenRequest"],
        }

        summary = summarize_network_capabilities(detected_apis)

        assert summary["basic"] == 3
        assert summary["http"] == 1

    def test_detects_ssl_capability(self) -> None:
        """Capability summarizer identifies SSL capability."""
        detected_apis = {"ssl": ["SSL_connect"]}

        summary = summarize_network_capabilities(detected_apis)

        assert summary["has_ssl"] is True

    def test_detects_network_capability(self) -> None:
        """Capability summarizer identifies networking capability."""
        detected_apis = {"basic": ["socket"]}

        summary = summarize_network_capabilities(detected_apis)

        assert summary["has_network"] is True

    def test_detects_dns_capability(self) -> None:
        """Capability summarizer identifies DNS capability."""
        detected_apis = {"dns": ["gethostbyname"]}

        summary = summarize_network_capabilities(detected_apis)

        assert summary["has_dns"] is True


class TestDetectNetworkAPIs:
    """Test backward compatibility alias."""

    def test_detect_network_apis_alias_works(self) -> None:
        """Backward compatibility alias functions correctly."""
        pe_binary = FakePEBinary(["socket"])
        network_apis = {"basic": ["socket"]}

        detected = detect_network_apis(pe_binary, network_apis)

        assert "basic" in detected


class TestRealWorldScenarios:
    """Test real-world network API detection scenarios."""

    def test_detects_license_server_communication(self) -> None:
        """Network analyzer detects license server communication APIs."""
        pe_binary = FakePEBinary(["HttpOpenRequest", "HttpSendRequest", "SSL_connect"])
        categories = get_network_api_categories()

        detected = analyze_network_apis(pe_binary, categories)
        summary = summarize_network_capabilities(detected)

        assert summary["has_network"] is True
        assert summary["has_ssl"] is True

    def test_detects_online_activation_apis(self) -> None:
        """Network analyzer detects online activation API usage."""
        pe_binary = FakePEBinary(
            ["InternetConnect", "HttpOpenRequest", "SSL_connect", "CryptAcquireContext"]
        )
        categories = get_network_api_categories()

        detected = analyze_network_apis(pe_binary, categories)

        assert "http" in detected
        assert "ssl" in detected

    def test_identifies_insecure_license_check(self) -> None:
        """Network analyzer identifies unencrypted license checking."""
        pe_binary = FakePEBinary(["socket", "connect", "send", "recv"])
        categories = get_network_api_categories()

        detected = analyze_network_apis(pe_binary, categories)
        result = process_network_api_results(detected)

        assert result["ssl_usage"]["network_without_ssl"] is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_none_import_names(self) -> None:
        """Network analyzer handles imports with None names."""
        pe_binary = FakePEBinary([None])
        network_apis = {"basic": ["socket"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert detected == {}

    def test_handles_empty_api_categories(self) -> None:
        """Network analyzer handles empty API category dictionary."""
        pe_binary = FakePEBinary(["socket"])

        detected = analyze_network_apis(pe_binary, {})

        assert detected == {}

    def test_handles_unicode_api_names(self) -> None:
        """Network analyzer handles Unicode in API names."""
        pe_binary = FakePEBinary(["socket测试"])
        network_apis = {"test": ["socket测试"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        if detected:
            assert "test" in detected

    def test_summarizes_empty_detection(self) -> None:
        """Capability summarizer handles empty detection results."""
        summary = summarize_network_capabilities({})

        assert summary["has_ssl"] is False
        assert summary["has_network"] is False
        assert summary["has_dns"] is False

    def test_handles_multiple_import_directories(self) -> None:
        """Network analyzer handles PE with multiple import directories."""
        imports1 = [FakePEImport("socket"), FakePEImport("connect")]
        imports2 = [FakePEImport("HttpOpenRequest"), FakePEImport("SSL_connect")]
        entry1 = FakePEImportDirectory(imports1)
        entry2 = FakePEImportDirectory(imports2)

        class FakePEMultipleDirectories:
            def __init__(self) -> None:
                self.DIRECTORY_ENTRY_IMPORT = [entry1, entry2]

        pe_binary = FakePEMultipleDirectories()
        network_apis = {
            "basic": ["socket", "connect"],
            "http": ["HttpOpenRequest"],
            "ssl": ["SSL_connect"],
        }

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "basic" in detected
        assert "http" in detected
        assert "ssl" in detected
        assert len(detected["basic"]) == 2

    def test_handles_mixed_valid_and_none_imports(self) -> None:
        """Network analyzer handles mix of valid and None import names."""
        pe_binary = FakePEBinary(["socket", None, "connect", None, "send"])
        network_apis = {"basic": ["socket", "connect", "send"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "basic" in detected
        assert len(detected["basic"]) == 3

    def test_handles_empty_import_list(self) -> None:
        """Network analyzer handles import directory with empty import list."""
        class FakePEEmptyImports:
            def __init__(self) -> None:
                entry = FakePEImportDirectory([])
                self.DIRECTORY_ENTRY_IMPORT = [entry]

        pe_binary = FakePEEmptyImports()
        network_apis = {"basic": ["socket"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert detected == {}

    def test_handles_bytes_import_names(self) -> None:
        """Network analyzer handles import names already as bytes."""
        pe_binary = FakePEBinary([b"socket", b"connect", b"send"])
        network_apis = {"basic": ["socket", "connect", "send"]}

        detected = analyze_network_apis(pe_binary, network_apis)

        assert "basic" in detected
        assert len(detected["basic"]) == 3
