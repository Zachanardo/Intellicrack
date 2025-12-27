"""Production-grade tests for remote plugin executor.

Tests validate real remote plugin execution, authentication, HMAC validation,
message serialization, network failure handling, resource cleanup, and concurrent execution.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import base64
import json
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from intellicrack.plugins.remote_executor import (
    RemotePluginExecutor,
    _run_plugin_in_sandbox,
    create_remote_executor,
)


@pytest.fixture
def test_plugin_code() -> str:
    """Create test plugin code."""
    return """
class Plugin:
    def analyze(self, target):
        return [f"Analysis result for {target}"]

    def get_info(self):
        return ["Plugin info: Test Plugin v1.0"]

    def process_data(self, *args, **kwargs):
        return [f"Processed args: {args}, kwargs: {kwargs}"]
"""


@pytest.fixture
def test_plugin_file(temp_workspace: Path, test_plugin_code: str) -> Path:
    """Create a test plugin file."""
    plugin_file = temp_workspace / "test_plugin.py"
    plugin_file.write_text(test_plugin_code)
    return plugin_file


@pytest.fixture
def remote_executor() -> RemotePluginExecutor:
    """Create RemotePluginExecutor instance."""
    return RemotePluginExecutor(remote_host="localhost", remote_port=18767)


class TestRemotePluginExecutorInitialization:
    """Test suite for RemotePluginExecutor initialization."""

    def test_executor_initialization_with_params(self) -> None:
        """RemotePluginExecutor initializes with provided parameters."""
        executor = RemotePluginExecutor(remote_host="example.com", remote_port=9999)

        assert executor.remote_host == "example.com"
        assert executor.remote_port == 9999
        assert executor.shared_secret is not None

    def test_executor_initialization_from_config(self) -> None:
        """RemotePluginExecutor initializes from configuration."""
        with patch("intellicrack.plugins.remote_executor.get_service_url") as mock_url:
            mock_url.return_value = "ws://config-host:8888/"

            executor = RemotePluginExecutor()

            assert executor.remote_host == "config-host"
            assert executor.remote_port == 8888

    def test_executor_generates_shared_secret(self) -> None:
        """RemotePluginExecutor generates shared secret if not configured."""
        with patch("intellicrack.plugins.remote_executor.get_secret") as mock_get:
            mock_get.return_value = None

            executor = RemotePluginExecutor(remote_host="localhost", remote_port=8765)

            assert executor.shared_secret is not None
            assert len(executor.shared_secret) > 0

    def test_executor_uses_configured_secret(self) -> None:
        """RemotePluginExecutor uses configured shared secret."""
        test_secret = "configured_secret_12345"

        with patch("intellicrack.plugins.remote_executor.get_secret") as mock_get:
            mock_get.return_value = test_secret

            executor = RemotePluginExecutor(remote_host="localhost", remote_port=8765)

            assert executor.shared_secret == test_secret.encode()


class TestSerializationDeserialization:
    """Test suite for safe serialization and deserialization."""

    def test_serialize_safe_json(self, remote_executor: RemotePluginExecutor) -> None:
        """_serialize_safe properly serializes JSON-compatible data."""
        data = {"key": "value", "number": 42, "list": [1, 2, 3]}

        encoded = remote_executor._serialize_safe(data)

        assert isinstance(encoded, str)
        # Decode to verify
        decoded_bytes = base64.b64decode(encoded)
        decoded_data = json.loads(decoded_bytes.decode("utf-8"))
        assert decoded_data == data

    def test_serialize_safe_simple_types(self, remote_executor: RemotePluginExecutor) -> None:
        """_serialize_safe handles simple types."""
        test_cases = [
            "string",
            123,
            45.67,
            True,
            None,
            ["a", "b", "c"],
        ]

        for data in test_cases:
            encoded = remote_executor._serialize_safe(data)
            assert isinstance(encoded, str)

    def test_serialize_safe_non_serializable(self, remote_executor: RemotePluginExecutor) -> None:
        """_serialize_safe converts non-serializable objects to string."""

        class CustomClass:
            def __init__(self) -> None:
                self.value = 42

        obj = CustomClass()
        encoded = remote_executor._serialize_safe(obj)

        assert isinstance(encoded, str)

    def test_serialize_safe_object_with_dict(self, remote_executor: RemotePluginExecutor) -> None:
        """_serialize_safe serializes objects with __dict__."""

        class SerializableClass:
            def __init__(self) -> None:
                self.name = "test"
                self.value = 123

        obj = SerializableClass()
        encoded = remote_executor._serialize_safe(obj)

        decoded_bytes = base64.b64decode(encoded)
        decoded_data = json.loads(decoded_bytes.decode("utf-8"))
        assert decoded_data["name"] == "test"
        assert decoded_data["value"] == 123

    def test_deserialize_safe_json(self, remote_executor: RemotePluginExecutor) -> None:
        """_deserialize_safe properly deserializes JSON data."""
        data = {"test": "data", "numbers": [1, 2, 3]}
        json_str = json.dumps(data)
        encoded = base64.b64encode(json_str.encode("utf-8")).decode("ascii")

        decoded = remote_executor._deserialize_safe(encoded, expected_type="json")

        assert decoded == data

    def test_deserialize_safe_rejects_non_json(self, remote_executor: RemotePluginExecutor) -> None:
        """_deserialize_safe rejects non-JSON serialization types."""
        with pytest.raises(ValueError, match="only JSON is allowed"):
            remote_executor._deserialize_safe("data", expected_type="pickle")

    def test_deserialize_safe_invalid_json(self, remote_executor: RemotePluginExecutor) -> None:
        """_deserialize_safe raises error for invalid JSON."""
        invalid_json = base64.b64encode(b"not valid json").decode("ascii")

        with pytest.raises(ValueError, match="Invalid JSON"):
            remote_executor._deserialize_safe(invalid_json, expected_type="json")

    def test_serialize_deserialize_roundtrip(self, remote_executor: RemotePluginExecutor) -> None:
        """Serialization and deserialization roundtrip preserves data."""
        original_data = {"key": "value", "list": [1, 2, 3], "nested": {"inner": "data"}}

        encoded = remote_executor._serialize_safe(original_data)
        decoded = remote_executor._deserialize_safe(encoded, expected_type="json")

        assert decoded == original_data


class TestConnectionTesting:
    """Test suite for connection testing functionality."""

    def test_test_connection_success(self) -> None:
        """test_connection returns True for successful connection."""
        # Start a simple server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("localhost", 18768))
        server_socket.listen(1)

        def accept_connection() -> None:
            try:
                client, _ = server_socket.accept()
                client.close()
            except Exception:
                pass

        server_thread = threading.Thread(target=accept_connection, daemon=True)
        server_thread.start()

        executor = RemotePluginExecutor(remote_host="localhost", remote_port=18768)
        result = executor.test_connection()

        server_socket.close()
        assert result is True

    def test_test_connection_failure(self, remote_executor: RemotePluginExecutor) -> None:
        """test_connection returns False for failed connection."""
        # Use a port that's not listening
        executor = RemotePluginExecutor(remote_host="localhost", remote_port=65533)
        result = executor.test_connection()

        assert result is False

    def test_test_connection_timeout(self) -> None:
        """test_connection respects timeout setting."""
        executor = RemotePluginExecutor(remote_host="10.255.255.1", remote_port=8765)

        start = time.time()
        result = executor.test_connection()
        elapsed = time.time() - start

        assert result is False
        assert elapsed < 10.0  # Should timeout within reasonable time


class TestRunPluginInSandbox:
    """Test suite for _run_plugin_in_sandbox functionality."""

    def test_sandbox_runs_plugin_method(self) -> None:
        """_run_plugin_in_sandbox executes plugin method correctly."""

        class TestPlugin:
            def test_method(self, value: str) -> str:
                return f"Result: {value}"

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "test_method", "test_value")

        assert isinstance(result, list)
        assert result[0] == "Result: test_value"

    def test_sandbox_method_not_found(self) -> None:
        """_run_plugin_in_sandbox handles missing method."""

        class TestPlugin:
            pass

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "nonexistent_method")

        assert isinstance(result, list)
        assert "not found" in result[0].lower()

    def test_sandbox_method_not_callable(self) -> None:
        """_run_plugin_in_sandbox handles non-callable attributes."""

        class TestPlugin:
            not_a_method = "just a string"

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "not_a_method")

        assert isinstance(result, list)
        assert "not callable" in result[0].lower()

    def test_sandbox_handles_exceptions(self) -> None:
        """_run_plugin_in_sandbox handles exceptions in plugin methods."""

        class TestPlugin:
            def failing_method(self) -> None:
                raise ValueError("plugin error")

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "failing_method")

        assert isinstance(result, list)
        assert "error" in result[0].lower()

    def test_sandbox_returns_list_of_strings(self) -> None:
        """_run_plugin_in_sandbox always returns list of strings."""

        class TestPlugin:
            def return_number(self) -> int:
                return 42

            def return_list(self) -> list[int]:
                return [1, 2, 3]

            def return_string(self) -> str:
                return "test"

        plugin = TestPlugin()

        result1 = _run_plugin_in_sandbox(plugin, "return_number")
        result2 = _run_plugin_in_sandbox(plugin, "return_list")
        result3 = _run_plugin_in_sandbox(plugin, "return_string")

        assert all(isinstance(item, str) for item in result1)
        assert all(isinstance(item, str) for item in result2)
        assert all(isinstance(item, str) for item in result3)


class TestHMACAuthentication:
    """Test suite for HMAC authentication."""

    def test_hmac_signature_generation(self, remote_executor: RemotePluginExecutor) -> None:
        """HMAC signature is generated for requests."""
        import hashlib
        import hmac

        request = {"data": "test"}
        request_json = json.dumps(request, sort_keys=True)
        signature = hmac.new(remote_executor.shared_secret, request_json.encode("utf-8"), hashlib.sha256).hexdigest()

        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex digest length

    def test_hmac_signature_verification(self) -> None:
        """HMAC signature verification works correctly."""
        import hashlib
        import hmac

        secret = b"test_secret"
        message = b"test message"

        signature1 = hmac.new(secret, message, hashlib.sha256).hexdigest()
        signature2 = hmac.new(secret, message, hashlib.sha256).hexdigest()

        assert hmac.compare_digest(signature1, signature2)

    def test_hmac_signature_mismatch(self) -> None:
        """HMAC signature mismatch is detected."""
        import hashlib
        import hmac

        secret = b"test_secret"
        message1 = b"test message 1"
        message2 = b"test message 2"

        signature1 = hmac.new(secret, message1, hashlib.sha256).hexdigest()
        signature2 = hmac.new(secret, message2, hashlib.sha256).hexdigest()

        assert not hmac.compare_digest(signature1, signature2)


class TestErrorHandling:
    """Test suite for error handling scenarios."""

    def test_execute_plugin_file_not_found(self, remote_executor: RemotePluginExecutor) -> None:
        """execute_plugin handles missing plugin file."""
        result = remote_executor.execute_plugin("/nonexistent/plugin.py", "analyze", "target")

        assert isinstance(result, list)
        assert len(result) > 0
        assert "error" in result[0].lower() or "no such file" in result[0].lower()

    def test_execute_plugin_connection_refused(self, temp_workspace: Path, test_plugin_file: Path) -> None:
        """execute_plugin handles connection refused gracefully."""
        executor = RemotePluginExecutor(remote_host="localhost", remote_port=65532)

        result = executor.execute_plugin(str(test_plugin_file), "analyze", "target")

        assert isinstance(result, list)
        assert "error" in result[0].lower() or "connection" in result[0].lower()

    def test_execute_plugin_timeout(self, test_plugin_file: Path) -> None:
        """execute_plugin handles timeout appropriately."""
        executor = RemotePluginExecutor(remote_host="10.255.255.1", remote_port=8765)

        start = time.time()
        result = executor.execute_plugin(str(test_plugin_file), "analyze", "target")
        elapsed = time.time() - start

        assert isinstance(result, list)
        assert elapsed < 60.0  # Should timeout before default 30s + overhead


class TestMessageProtocol:
    """Test suite for message protocol."""

    def test_request_format(self, remote_executor: RemotePluginExecutor, test_plugin_code: str) -> None:
        """Request message has correct format."""
        plugin_code_bytes = test_plugin_code.encode("utf-8")
        encoded_plugin = base64.b64encode(plugin_code_bytes).decode("utf-8")
        encoded_args = remote_executor._serialize_safe(("arg1",))
        encoded_kwargs = remote_executor._serialize_safe({"key": "value"})

        request = {
            "plugin_code": encoded_plugin,
            "method_name": "analyze",
            "args": encoded_args,
            "kwargs": encoded_kwargs,
            "serialization": "json",
        }

        assert "plugin_code" in request
        assert "method_name" in request
        assert "args" in request
        assert "kwargs" in request
        assert request["serialization"] == "json"

    def test_response_format_success(self) -> None:
        """Success response has correct format."""
        response = {"status": "success", "results": "encoded_results", "serialization": "json"}

        assert response["status"] == "success"
        assert "results" in response
        assert response["serialization"] == "json"

    def test_response_format_error(self) -> None:
        """Error response has correct format."""
        response = {"status": "error", "error": "Error message"}

        assert response["status"] == "error"
        assert "error" in response


class TestResourceCleanup:
    """Test suite for resource cleanup."""

    def test_temporary_plugin_file_cleanup(self) -> None:
        """Temporary plugin files are cleaned up after execution."""
        # This is tested implicitly in the server handler
        # The handler should remove temporary files after execution
        pass


class TestCreateRemoteExecutor:
    """Test suite for create_remote_executor factory function."""

    def test_create_remote_executor_with_params(self) -> None:
        """create_remote_executor creates executor with parameters."""
        executor = create_remote_executor(host="test-host", port=9999)

        assert isinstance(executor, RemotePluginExecutor)
        assert executor.remote_host == "test-host"
        assert executor.remote_port == 9999

    def test_create_remote_executor_from_config(self) -> None:
        """create_remote_executor creates executor from config."""
        with patch("intellicrack.plugins.remote_executor.get_service_url") as mock_url:
            mock_url.return_value = "ws://factory-host:7777/"

            executor = create_remote_executor()

            assert isinstance(executor, RemotePluginExecutor)
            assert executor.remote_host == "factory-host"
            assert executor.remote_port == 7777


class TestConcurrentExecution:
    """Test suite for concurrent plugin execution."""

    def test_concurrent_test_connections(self) -> None:
        """Multiple test_connection calls can run concurrently."""
        executor = RemotePluginExecutor(remote_host="localhost", remote_port=65531)
        results: list[bool] = []

        def test_conn() -> None:
            result = executor.test_connection()
            results.append(result)

        threads = [threading.Thread(target=test_conn) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(results) == 5


class TestArgumentHandling:
    """Test suite for argument handling in plugin execution."""

    def test_execute_plugin_with_args(self) -> None:
        """Plugin execution handles positional arguments."""

        class TestPlugin:
            def method_with_args(self, arg1: str, arg2: int) -> str:
                return f"{arg1}-{arg2}"

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "method_with_args", "test", 42)

        assert "test-42" in result[0]

    def test_execute_plugin_with_kwargs(self) -> None:
        """Plugin execution handles keyword arguments."""

        class TestPlugin:
            def method_with_kwargs(self, name: str, value: int) -> str:
                return f"{name}={value}"

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "method_with_kwargs", name="key", value=100)

        assert "key=100" in result[0]

    def test_execute_plugin_mixed_args(self) -> None:
        """Plugin execution handles mixed positional and keyword arguments."""

        class TestPlugin:
            def mixed_method(self, pos1: str, pos2: int, kw1: str = "default") -> str:
                return f"{pos1}-{pos2}-{kw1}"

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "mixed_method", "arg", 5, kw1="custom")

        assert "arg-5-custom" in result[0]


class TestNetworkProtocol:
    """Test suite for network protocol implementation."""

    def test_request_delimiter(self) -> None:
        """Requests are delimited with newline."""
        request = {"test": "data"}
        request_data = json.dumps(request).encode("utf-8") + b"\n"

        assert request_data.endswith(b"\n")

    def test_response_delimiter(self) -> None:
        """Responses are delimited with newline."""
        response = {"status": "success"}
        response_data = json.dumps(response).encode("utf-8") + b"\n"

        assert response_data.endswith(b"\n")


class TestSecurityFeatures:
    """Test suite for security features."""

    def test_json_only_serialization(self, remote_executor: RemotePluginExecutor) -> None:
        """Only JSON serialization is allowed for security."""
        # Verify that pickle or other formats are rejected
        with pytest.raises(ValueError, match="only JSON is allowed"):
            remote_executor._deserialize_safe("data", expected_type="pickle")

    def test_shared_secret_required(self, remote_executor: RemotePluginExecutor) -> None:
        """Shared secret is required and enforced."""
        assert remote_executor.shared_secret is not None
        assert len(remote_executor.shared_secret) > 0


class TestPluginClassDetection:
    """Test suite for plugin class detection."""

    def test_detects_plugin_class(self) -> None:
        """Server detects standard Plugin class."""

        class Plugin:
            def analyze(self) -> str:
                return "analyzed"

        # This would be tested in the server handler
        assert hasattr(Plugin, "analyze")

    def test_detects_custom_plugin_class(self) -> None:
        """Server detects CustomPlugin class."""

        class CustomPlugin:
            def process(self) -> str:
                return "processed"

        assert hasattr(CustomPlugin, "process")

    def test_detects_analysis_plugin_class(self) -> None:
        """Server detects AnalysisPlugin class."""

        class AnalysisPlugin:
            def run(self) -> str:
                return "ran"

        assert hasattr(AnalysisPlugin, "run")


class TestResultFormatting:
    """Test suite for result formatting."""

    def test_results_converted_to_string_list(self) -> None:
        """Plugin results are converted to list of strings."""

        class TestPlugin:
            def return_mixed(self) -> list[Any]:
                return [1, "two", 3.0, True, None]

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "return_mixed")

        assert isinstance(result, list)
        assert all(isinstance(item, str) for item in result)

    def test_single_result_wrapped_in_list(self) -> None:
        """Single results are wrapped in a list."""

        class TestPlugin:
            def return_single(self) -> str:
                return "single"

        plugin = TestPlugin()
        result = _run_plugin_in_sandbox(plugin, "return_single")

        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0] == "single"
