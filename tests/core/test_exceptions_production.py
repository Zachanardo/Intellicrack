"""Production tests for custom exception hierarchy.

Tests validate exception initialization, context preservation, and error handling
for all custom exception types in the Intellicrack framework.
"""

import pytest

from intellicrack.core.exceptions import (
    AnalysisError,
    ConfigurationError,
    ExploitationError,
    IntellicrackError,
    NetworkError,
    SecurityError,
    ServiceUnavailableError,
    ToolNotFoundError,
    ValidationError,
)


class TestIntellicrackError:
    """Test base exception class."""

    def test_base_exception_is_exception_subclass(self) -> None:
        """IntellicrackError inherits from Exception."""
        assert issubclass(IntellicrackError, Exception)

    def test_base_exception_can_be_raised(self) -> None:
        """IntellicrackError can be raised and caught."""
        with pytest.raises(IntellicrackError) as exc_info:
            raise IntellicrackError("Test error")

        assert str(exc_info.value) == "Test error"

    def test_base_exception_catches_all_intellicrack_errors(self) -> None:
        """IntellicrackError catches all derived exception types."""
        exceptions = [
            ConfigurationError("config error"),
            ServiceUnavailableError("service error", "test_service"),
            ToolNotFoundError("tool error", "test_tool"),
            ValidationError("validation error"),
            SecurityError("security error"),
            AnalysisError("analysis error"),
            ExploitationError("exploitation error"),
            NetworkError("network error"),
        ]

        for exc in exceptions:
            with pytest.raises(IntellicrackError):
                raise exc


class TestConfigurationError:
    """Test configuration error with context preservation."""

    def test_configuration_error_stores_message(self) -> None:
        """ConfigurationError preserves error message."""
        error = ConfigurationError("Invalid configuration")
        assert str(error) == "Invalid configuration"

    def test_configuration_error_stores_service_name(self) -> None:
        """ConfigurationError stores service name context."""
        error = ConfigurationError(
            "Missing API key",
            service_name="openai_api"
        )
        assert error.service_name == "openai_api"
        assert "Missing API key" in str(error)

    def test_configuration_error_stores_config_key(self) -> None:
        """ConfigurationError stores configuration key that failed."""
        error = ConfigurationError(
            "Invalid value for setting",
            config_key="analysis.timeout"
        )
        assert error.config_key == "analysis.timeout"

    def test_configuration_error_stores_both_contexts(self) -> None:
        """ConfigurationError stores both service name and config key."""
        error = ConfigurationError(
            "Configuration mismatch",
            service_name="license_validator",
            config_key="license.rsa_key_path"
        )
        assert error.service_name == "license_validator"
        assert error.config_key == "license.rsa_key_path"

    def test_configuration_error_allows_none_contexts(self) -> None:
        """ConfigurationError allows None for optional context."""
        error = ConfigurationError("Generic error")
        assert error.service_name is None
        assert error.config_key is None

    def test_configuration_error_is_intellicrack_error(self) -> None:
        """ConfigurationError is subclass of IntellicrackError."""
        assert issubclass(ConfigurationError, IntellicrackError)


class TestServiceUnavailableError:
    """Test service unavailable error."""

    def test_service_unavailable_requires_service_name(self) -> None:
        """ServiceUnavailableError requires service name."""
        error = ServiceUnavailableError(
            "Service not responding",
            service_name="ghidra_bridge"
        )
        assert error.service_name == "ghidra_bridge"

    def test_service_unavailable_stores_url(self) -> None:
        """ServiceUnavailableError stores URL context."""
        error = ServiceUnavailableError(
            "Connection refused",
            service_name="license_server",
            url="https://license.example.com:8443"
        )
        assert error.url == "https://license.example.com:8443"
        assert error.service_name == "license_server"

    def test_service_unavailable_allows_none_url(self) -> None:
        """ServiceUnavailableError allows None URL for non-network services."""
        error = ServiceUnavailableError(
            "Service crashed",
            service_name="binary_analyzer"
        )
        assert error.url is None
        assert error.service_name == "binary_analyzer"

    def test_service_unavailable_error_message_accessible(self) -> None:
        """ServiceUnavailableError message is accessible."""
        error = ServiceUnavailableError(
            "Timeout connecting to service",
            service_name="frida_server",
            url="127.0.0.1:27042"
        )
        assert "Timeout connecting to service" in str(error)


class TestToolNotFoundError:
    """Test tool not found error."""

    def test_tool_not_found_requires_tool_name(self) -> None:
        """ToolNotFoundError requires tool name."""
        error = ToolNotFoundError(
            "radare2 not found in PATH",
            tool_name="radare2"
        )
        assert error.tool_name == "radare2"

    def test_tool_not_found_stores_search_paths(self) -> None:
        """ToolNotFoundError stores searched paths."""
        paths = [
            "C:\\Program Files\\radare2",
            "C:\\tools\\radare2",
            "D:\\bin"
        ]
        error = ToolNotFoundError(
            "Tool not found",
            tool_name="radare2",
            search_paths=paths
        )
        assert error.search_paths == paths
        assert len(error.search_paths) == 3

    def test_tool_not_found_defaults_empty_search_paths(self) -> None:
        """ToolNotFoundError defaults to empty search paths list."""
        error = ToolNotFoundError(
            "Ghidra installation not detected",
            tool_name="ghidra"
        )
        assert error.search_paths == []
        assert isinstance(error.search_paths, list)

    def test_tool_not_found_with_multiple_paths(self) -> None:
        """ToolNotFoundError handles multiple search locations."""
        error = ToolNotFoundError(
            "IDA Pro not found",
            tool_name="ida64.exe",
            search_paths=[
                "C:\\Program Files\\IDA Pro 7.7",
                "C:\\Program Files\\IDA Pro 8.0",
                "C:\\tools\\ida"
            ]
        )
        assert "ida64.exe" == error.tool_name
        assert len(error.search_paths) == 3


class TestValidationError:
    """Test validation error."""

    def test_validation_error_stores_message(self) -> None:
        """ValidationError preserves error message."""
        error = ValidationError("Invalid input format")
        assert "Invalid input format" in str(error)

    def test_validation_error_stores_field_name(self) -> None:
        """ValidationError stores field that failed validation."""
        error = ValidationError(
            "Port must be between 1-65535",
            field_name="port"
        )
        assert error.field_name == "port"

    def test_validation_error_stores_invalid_value(self) -> None:
        """ValidationError stores the invalid value."""
        error = ValidationError(
            "Invalid license key format",
            field_name="license_key",
            value="ABC-123-INVALID"
        )
        assert error.value == "ABC-123-INVALID"
        assert error.field_name == "license_key"

    def test_validation_error_allows_none_contexts(self) -> None:
        """ValidationError allows None for optional contexts."""
        error = ValidationError("Generic validation failure")
        assert error.field_name is None
        assert error.value is None

    def test_validation_error_with_complex_value(self) -> None:
        """ValidationError can store complex value representations."""
        error = ValidationError(
            "Invalid configuration structure",
            field_name="config.analysis.settings",
            value='{"timeout": "invalid", "max_depth": -1}'
        )
        assert "config.analysis.settings" in str(error.field_name)
        assert "invalid" in error.value


class TestSecurityError:
    """Test security error."""

    def test_security_error_can_be_raised(self) -> None:
        """SecurityError can be raised with message."""
        with pytest.raises(SecurityError) as exc_info:
            raise SecurityError("Unauthorized access attempt")

        assert "Unauthorized access attempt" in str(exc_info.value)

    def test_security_error_is_intellicrack_error(self) -> None:
        """SecurityError is subclass of IntellicrackError."""
        assert issubclass(SecurityError, IntellicrackError)

    def test_security_error_in_exception_chain(self) -> None:
        """SecurityError can be part of exception chain."""
        try:
            try:
                raise ValueError("Underlying error")
            except ValueError as e:
                raise SecurityError("Security validation failed") from e
        except SecurityError as exc:
            assert exc.__cause__ is not None
            assert isinstance(exc.__cause__, ValueError)


class TestAnalysisError:
    """Test analysis error."""

    def test_analysis_error_stores_message(self) -> None:
        """AnalysisError preserves error message."""
        error = AnalysisError("Failed to analyze binary")
        assert "Failed to analyze binary" in str(error)

    def test_analysis_error_stores_binary_path(self) -> None:
        """AnalysisError stores path to binary that failed."""
        error = AnalysisError(
            "Protection detection failed",
            binary_path="C:\\targets\\protected.exe"
        )
        assert error.binary_path == "C:\\targets\\protected.exe"

    def test_analysis_error_stores_analysis_type(self) -> None:
        """AnalysisError stores type of analysis that failed."""
        error = AnalysisError(
            "Symbolic execution timeout",
            analysis_type="symbolic_execution"
        )
        assert error.analysis_type == "symbolic_execution"

    def test_analysis_error_stores_both_contexts(self) -> None:
        """AnalysisError stores both binary path and analysis type."""
        error = AnalysisError(
            "VMProtect detection failed",
            binary_path="D:\\samples\\vmprotect_sample.exe",
            analysis_type="protection_detection"
        )
        assert error.binary_path == "D:\\samples\\vmprotect_sample.exe"
        assert error.analysis_type == "protection_detection"

    def test_analysis_error_allows_none_contexts(self) -> None:
        """AnalysisError allows None for optional contexts."""
        error = AnalysisError("Generic analysis failure")
        assert error.binary_path is None
        assert error.analysis_type is None


class TestExploitationError:
    """Test exploitation error."""

    def test_exploitation_error_stores_message(self) -> None:
        """ExploitationError preserves error message."""
        error = ExploitationError("License bypass failed")
        assert "License bypass failed" in str(error)

    def test_exploitation_error_stores_target(self) -> None:
        """ExploitationError stores target information."""
        error = ExploitationError(
            "Keygen generation failed",
            target="Adobe Photoshop 2024"
        )
        assert error.target == "Adobe Photoshop 2024"

    def test_exploitation_error_stores_technique(self) -> None:
        """ExploitationError stores exploitation technique used."""
        error = ExploitationError(
            "Bypass attempt failed",
            technique="license_check_nop"
        )
        assert error.technique == "license_check_nop"

    def test_exploitation_error_stores_both_contexts(self) -> None:
        """ExploitationError stores both target and technique."""
        error = ExploitationError(
            "Hardware ID spoofing failed",
            target="FlexLM License Manager",
            technique="hwid_emulation"
        )
        assert error.target == "FlexLM License Manager"
        assert error.technique == "hwid_emulation"

    def test_exploitation_error_allows_none_contexts(self) -> None:
        """ExploitationError allows None for optional contexts."""
        error = ExploitationError("Generic exploitation failure")
        assert error.target is None
        assert error.technique is None


class TestNetworkError:
    """Test network error."""

    def test_network_error_stores_message(self) -> None:
        """NetworkError preserves error message."""
        error = NetworkError("Connection timeout")
        assert "Connection timeout" in str(error)

    def test_network_error_stores_host(self) -> None:
        """NetworkError stores host information."""
        error = NetworkError(
            "Connection refused",
            host="license.server.com"
        )
        assert error.host == "license.server.com"

    def test_network_error_stores_port(self) -> None:
        """NetworkError stores port number."""
        error = NetworkError(
            "Port unreachable",
            port=8443
        )
        assert error.port == 8443

    def test_network_error_stores_both_host_and_port(self) -> None:
        """NetworkError stores both host and port."""
        error = NetworkError(
            "SSL handshake failed",
            host="192.168.1.100",
            port=443
        )
        assert error.host == "192.168.1.100"
        assert error.port == 443

    def test_network_error_allows_none_contexts(self) -> None:
        """NetworkError allows None for optional contexts."""
        error = NetworkError("Generic network failure")
        assert error.host is None
        assert error.port is None


class TestExceptionInteroperability:
    """Test exception interaction and chaining."""

    def test_exceptions_can_be_chained(self) -> None:
        """Custom exceptions support exception chaining."""
        try:
            try:
                raise ConfigurationError("Invalid config", service_name="test")
            except ConfigurationError as e:
                raise AnalysisError("Analysis failed due to config") from e
        except AnalysisError as exc:
            assert exc.__cause__ is not None
            assert isinstance(exc.__cause__, ConfigurationError)
            assert exc.__cause__.service_name == "test"

    def test_multiple_exception_types_in_try_except(self) -> None:
        """Multiple custom exceptions can be caught distinctly."""
        def raise_config_error() -> None:
            raise ConfigurationError("Config error")

        def raise_network_error() -> None:
            raise NetworkError("Network error")

        with pytest.raises(ConfigurationError):
            raise_config_error()

        with pytest.raises(NetworkError):
            raise_network_error()

    def test_catch_base_exception_for_all_types(self) -> None:
        """Base IntellicrackError catches all custom exceptions."""
        errors = [
            ConfigurationError("config"),
            ServiceUnavailableError("service", "test"),
            ToolNotFoundError("tool", "test"),
            ValidationError("validation"),
            SecurityError("security"),
            AnalysisError("analysis"),
            ExploitationError("exploitation"),
            NetworkError("network"),
        ]

        for error in errors:
            with pytest.raises(IntellicrackError):
                raise error

    def test_exception_context_preserved_in_reraise(self) -> None:
        """Exception context is preserved when re-raising."""
        try:
            try:
                raise ToolNotFoundError(
                    "radare2 missing",
                    tool_name="radare2",
                    search_paths=["C:\\tools", "D:\\bin"]
                )
            except ToolNotFoundError:
                raise
        except ToolNotFoundError as exc:
            assert exc.tool_name == "radare2"
            assert len(exc.search_paths) == 2


class TestExceptionPracticalScenarios:
    """Test practical exception usage scenarios."""

    def test_configuration_error_in_service_initialization(self) -> None:
        """Configuration error during service initialization."""
        def initialize_license_validator() -> None:
            config_key = "license.rsa_public_key"
            raise ConfigurationError(
                f"Missing required configuration: {config_key}",
                service_name="LicenseValidator",
                config_key=config_key
            )

        with pytest.raises(ConfigurationError) as exc_info:
            initialize_license_validator()

        error = exc_info.value
        assert error.service_name == "LicenseValidator"
        assert error.config_key == "license.rsa_public_key"
        assert "Missing required configuration" in str(error)

    def test_analysis_error_during_binary_processing(self) -> None:
        """Analysis error when processing protected binary."""
        binary_path = "C:\\targets\\vmprotect_sample.exe"

        with pytest.raises(AnalysisError) as exc_info:
            raise AnalysisError(
                "Unable to detect protection scheme",
                binary_path=binary_path,
                analysis_type="protection_scanner"
            )

        error = exc_info.value
        assert error.binary_path == binary_path
        assert error.analysis_type == "protection_scanner"

    def test_exploitation_error_during_keygen_generation(self) -> None:
        """Exploitation error when keygen generation fails."""
        with pytest.raises(ExploitationError) as exc_info:
            raise ExploitationError(
                "Failed to reverse RSA key generation algorithm",
                target="Adobe Creative Cloud",
                technique="rsa_keygen_reversal"
            )

        error = exc_info.value
        assert "Adobe Creative Cloud" in error.target
        assert error.technique == "rsa_keygen_reversal"

    def test_network_error_during_license_server_connection(self) -> None:
        """Network error when connecting to license server."""
        with pytest.raises(NetworkError) as exc_info:
            raise NetworkError(
                "License server unreachable",
                host="license.flexera.com",
                port=27000
            )

        error = exc_info.value
        assert error.host == "license.flexera.com"
        assert error.port == 27000

    def test_service_unavailable_during_tool_communication(self) -> None:
        """Service unavailable error when tool communication fails."""
        with pytest.raises(ServiceUnavailableError) as exc_info:
            raise ServiceUnavailableError(
                "Ghidra headless analyzer not responding",
                service_name="ghidra_headless",
                url="http://localhost:13100"
            )

        error = exc_info.value
        assert error.service_name == "ghidra_headless"
        assert "localhost:13100" in error.url
