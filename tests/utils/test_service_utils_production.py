"""Production tests for service URL utilities.

Tests validate service URL retrieval from configuration with proper error
handling and fallback mechanisms.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any
from unittest.mock import MagicMock

import pytest

from intellicrack.core.exceptions import ConfigurationError
from intellicrack.utils.service_utils import get_service_url


class MockConfig:
    """Mock configuration object for testing."""

    def __init__(self, config_data: dict[str, Any]) -> None:
        """Initialize mock config with data."""
        self.config_data = config_data

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        keys = key.split(".")
        value = self.config_data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value if value is not None else default


class TestGetServiceURL:
    """Test get_service_url function with various configurations."""

    def test_get_service_url_returns_configured_url(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url returns URL from configuration when available."""
        config = MockConfig({"service_urls": {"ghidra_server": "http://localhost:13100"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("ghidra_server")

        assert url == "http://localhost:13100"

    def test_get_service_url_uses_fallback_when_not_configured(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url uses fallback URL when service not configured."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        fallback_url = "http://default-server:8080"
        url = get_service_url("unknown_service", fallback=fallback_url)

        assert url == fallback_url

    def test_get_service_url_raises_error_without_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url raises ConfigurationError when no URL and no fallback."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError) as exc_info:
            get_service_url("missing_service")

        assert "missing_service" in str(exc_info.value)
        assert "not configured" in str(exc_info.value).lower()


class TestURLValidation:
    """Test URL format validation."""

    def test_get_service_url_accepts_http_protocol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url accepts HTTP protocol URLs."""
        config = MockConfig({"service_urls": {"test_service": "http://example.com:8080"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("test_service")
        assert url == "http://example.com:8080"

    def test_get_service_url_accepts_https_protocol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url accepts HTTPS protocol URLs."""
        config = MockConfig({"service_urls": {"test_service": "https://secure.example.com"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("test_service")
        assert url == "https://secure.example.com"

    def test_get_service_url_accepts_websocket_protocols(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url accepts WebSocket protocol URLs."""
        ws_urls = {"ws_service": "ws://localhost:9000", "wss_service": "wss://secure-ws.example.com"}

        config = MockConfig({"service_urls": ws_urls})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        assert get_service_url("ws_service") == "ws://localhost:9000"
        assert get_service_url("wss_service") == "wss://secure-ws.example.com"

    def test_get_service_url_accepts_tcp_udp_protocols(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url accepts TCP and UDP protocol URLs."""
        network_urls = {"tcp_service": "tcp://127.0.0.1:5555", "udp_service": "udp://localhost:6666"}

        config = MockConfig({"service_urls": network_urls})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        assert get_service_url("tcp_service") == "tcp://127.0.0.1:5555"
        assert get_service_url("udp_service") == "udp://localhost:6666"

    def test_get_service_url_rejects_invalid_protocol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url rejects URLs with invalid protocols."""
        config = MockConfig({"service_urls": {"bad_service": "ftp://invalid.com"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError) as exc_info:
            get_service_url("bad_service")

        assert "Invalid URL format" in str(exc_info.value)
        assert "bad_service" in str(exc_info.value)

    def test_get_service_url_rejects_url_without_protocol(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url rejects URLs without protocol prefix."""
        config = MockConfig({"service_urls": {"no_protocol_service": "example.com:8080"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError) as exc_info:
            get_service_url("no_protocol_service")

        assert "Invalid URL format" in str(exc_info.value)


class TestConfigurationErrorHandling:
    """Test configuration error handling scenarios."""

    def test_get_service_url_raises_error_when_config_import_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url raises ConfigurationError when config manager import fails."""

        def mock_import_error(*args: Any, **kwargs: Any) -> None:
            raise ImportError("Mock config manager import failure")

        import intellicrack.utils.service_utils

        original_import = __builtins__.__import__

        def custom_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "intellicrack.core.config_manager":
                raise ImportError("Mock import failure")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr("builtins.__import__", custom_import)

        with pytest.raises(ConfigurationError) as exc_info:
            get_service_url("any_service")

        assert "Cannot access configuration" in str(exc_info.value)

    def test_get_service_url_includes_service_name_in_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """ConfigurationError includes service name for debugging."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError) as exc_info:
            get_service_url("critical_service")

        error = exc_info.value
        assert hasattr(error, "service_name") or "critical_service" in str(error)


class TestRealWorldServiceURLs:
    """Test realistic service URL configurations."""

    def test_get_service_url_for_ghidra_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url retrieves Ghidra headless server URL."""
        config = MockConfig({"service_urls": {"ghidra_server": "http://localhost:13100"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("ghidra_server")
        assert url == "http://localhost:13100"
        assert url.startswith("http://")

    def test_get_service_url_for_radare2_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url retrieves radare2 HTTP server URL."""
        config = MockConfig({"service_urls": {"radare2_http": "http://127.0.0.1:9090"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("radare2_http")
        assert url == "http://127.0.0.1:9090"

    def test_get_service_url_for_frida_server(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url retrieves Frida instrumentation server URL."""
        config = MockConfig({"service_urls": {"frida_server": "tcp://192.168.1.100:27042"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("frida_server")
        assert url == "tcp://192.168.1.100:27042"

    def test_get_service_url_for_license_server_emulator(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url retrieves license server emulation endpoint."""
        config = MockConfig({"service_urls": {"license_emulator": "https://localhost:8443/validate"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("license_emulator")
        assert url == "https://localhost:8443/validate"
        assert url.startswith("https://")


class TestFallbackBehavior:
    """Test fallback URL behavior."""

    def test_get_service_url_logs_fallback_usage(self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
        """get_service_url logs when using fallback URL."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("test_service", fallback="http://fallback:9999")

        assert url == "http://fallback:9999"

    def test_get_service_url_prefers_config_over_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url uses configured URL instead of fallback."""
        config = MockConfig({"service_urls": {"test_service": "http://configured:8080"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("test_service", fallback="http://fallback:9999")

        assert url == "http://configured:8080"
        assert url != "http://fallback:9999"

    def test_get_service_url_validates_fallback_url_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url validates fallback URL format."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError, match="Invalid URL format"):
            get_service_url("test_service", fallback="invalid_url_format")


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    def test_get_service_url_with_empty_service_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url handles empty service name."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError):
            get_service_url("")

    def test_get_service_url_with_none_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url handles None as fallback value."""
        config = MockConfig({"service_urls": {}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        with pytest.raises(ConfigurationError):
            get_service_url("missing_service", fallback=None)

    def test_get_service_url_with_url_containing_port(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url handles URLs with explicit port numbers."""
        config = MockConfig(
            {
                "service_urls": {
                    "service1": "http://localhost:8080",
                    "service2": "https://example.com:443",
                    "service3": "tcp://127.0.0.1:5555",
                }
            }
        )

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        assert ":8080" in get_service_url("service1")
        assert ":443" in get_service_url("service2")
        assert ":5555" in get_service_url("service3")

    def test_get_service_url_with_url_containing_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url handles URLs with path components."""
        config = MockConfig(
            {"service_urls": {"api_service": "https://example.com/api/v1/license", "ws_service": "wss://example.com/stream"}}
        )

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        api_url = get_service_url("api_service")
        assert "/api/v1/license" in api_url

        ws_url = get_service_url("ws_service")
        assert "/stream" in ws_url

    def test_get_service_url_with_url_containing_query_params(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url handles URLs with query parameters."""
        config = MockConfig({"service_urls": {"query_service": "http://example.com/api?key=value&param=test"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("query_service")
        assert "?" in url
        assert "key=value" in url


class TestConfigurationKeyFormats:
    """Test different configuration key formats."""

    def test_get_service_url_with_nested_config_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url retrieves URL from nested configuration structure."""
        config = MockConfig({"service_urls": {"analysis": {"ghidra": "http://localhost:13100"}}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("analysis.ghidra")

        assert url == "http://localhost:13100"

    def test_get_service_url_constructs_correct_config_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """get_service_url constructs config key as service_urls.<service_name>."""
        config = MockConfig({"service_urls": {"my_service": "http://example.com"}})

        def mock_get_config() -> MockConfig:
            return config

        import intellicrack.utils.service_utils

        monkeypatch.setattr("intellicrack.utils.service_utils.get_config", mock_get_config)

        url = get_service_url("my_service")
        assert url == "http://example.com"
