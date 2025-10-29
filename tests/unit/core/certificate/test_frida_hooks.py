"""Unit tests for Frida certificate hooks module.

This test suite validates the FridaCertificateHooks functionality with comprehensive
coverage of script loading, process attachment, message handling, and RPC operations.
Tests use mocking to avoid dependencies on real processes and Frida runtime.
"""

import pytest
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, mock_open
from typing import Dict, Any

from intellicrack.core.certificate.frida_cert_hooks import (
    FridaCertificateHooks,
    FridaMessage,
    BypassStatus,
)


@pytest.fixture
def hooks():
    """Create FridaCertificateHooks instance for testing."""
    return FridaCertificateHooks()


@pytest.fixture
def mock_frida_session():
    """Create mock Frida session."""
    session = Mock()
    session.on = Mock()
    session.create_script = Mock()
    session.detach = Mock()
    return session


@pytest.fixture
def mock_frida_script():
    """Create mock Frida script."""
    script = Mock()
    script.on = Mock()
    script.load = Mock()
    script.unload = Mock()
    script.exports_sync = {}
    return script


@pytest.fixture
def sample_script_content():
    """Sample JavaScript code for testing."""
    return """
    function bypassSSL() {
        console.log("Bypassing SSL validation");
        return true;
    }

    rpc.exports = {
        getBypassStatus: function() {
            return {active: true, library: "OpenSSL"};
        }
    };
    """


class TestHooksInitialization:
    """Tests for hooks initialization."""

    def test_hooks_initialize_with_defaults(self, hooks):
        """Test hooks instance initializes with default state."""
        assert hooks.session is None
        assert hooks.script is None
        assert hooks.target is None
        assert hooks.messages == []
        assert hooks.intercepted_certificates == []
        assert hooks.bypassed_connections == []
        assert hooks.errors == []
        assert hooks._attached is False
        assert hooks._script_loaded is False

    def test_available_scripts_defined(self, hooks):
        """Test that all expected script types are available."""
        expected_scripts = [
            "winhttp",
            "schannel",
            "openssl",
            "cryptoapi",
            "android",
            "ios",
            "universal",
        ]

        for script in expected_scripts:
            assert script in hooks.AVAILABLE_SCRIPTS


class TestScriptLoading:
    """Tests for script loading functionality."""

    @patch("intellicrack.core.certificate.frida_cert_hooks.Path")
    @patch("builtins.open", new_callable=mock_open, read_data="// Bypass script")
    def test_load_valid_script(self, mock_file, mock_path, hooks):
        """Test loading a valid bypass script."""
        mock_path.return_value.parent = Path("/fake/path")
        hooks.SCRIPT_DIR = Path("/fake/path/scripts")

        script_path = hooks.SCRIPT_DIR / "openssl_bypass.js"
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = True
        mock_path.return_value = mock_path_instance

        with patch.object(
            Path,
            "exists",
            return_value=True,
        ):
            content = hooks.load_script("openssl")

        assert content == "// Bypass script"

    def test_load_unknown_script_raises_error(self, hooks):
        """Test loading unknown script raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            hooks.load_script("nonexistent_library")

        assert "Unknown script" in str(exc_info.value)

    @patch("intellicrack.core.certificate.frida_cert_hooks.Path")
    def test_load_missing_script_file_raises_error(self, mock_path, hooks):
        """Test loading script when file doesn't exist raises FileNotFoundError."""
        mock_path_instance = Mock()
        mock_path_instance.exists.return_value = False
        hooks.SCRIPT_DIR = Mock()
        hooks.SCRIPT_DIR.__truediv__ = Mock(return_value=mock_path_instance)

        with pytest.raises(FileNotFoundError):
            hooks.load_script("openssl")


class TestProcessAttachment:
    """Tests for process attachment."""

    @patch("intellicrack.core.certificate.frida_cert_hooks.frida")
    def test_attach_to_process_by_pid(
        self, mock_frida, hooks, mock_frida_session
    ):
        """Test attaching to process by PID."""
        mock_frida.attach.return_value = mock_frida_session

        success = hooks.attach(1234)

        assert success is True
        assert hooks._attached is True
        assert hooks.session is not None
        assert hooks.target == 1234
        mock_frida.attach.assert_called_once_with(1234)

    @patch("intellicrack.core.certificate.frida_cert_hooks.frida")
    def test_attach_to_process_by_name(
        self, mock_frida, hooks, mock_frida_session
    ):
        """Test attaching to process by name."""
        mock_frida.attach.return_value = mock_frida_session

        success = hooks.attach("target.exe")

        assert success is True
        assert hooks._attached is True
        assert hooks.target == "target.exe"
        mock_frida.attach.assert_called_once_with("target.exe")

    @patch("intellicrack.core.certificate.frida_cert_hooks.frida")
    def test_attach_to_process_by_pid_string(
        self, mock_frida, hooks, mock_frida_session
    ):
        """Test attaching to process by PID as string."""
        mock_frida.attach.return_value = mock_frida_session

        success = hooks.attach("1234")

        assert success is True
        mock_frida.attach.assert_called_once_with(1234)

    @patch("intellicrack.core.certificate.frida_cert_hooks.frida")
    def test_attach_fails_when_process_not_found(self, mock_frida, hooks):
        """Test attach fails gracefully when process doesn't exist."""
        mock_frida.attach.side_effect = mock_frida.ProcessNotFoundError("Not found")
        mock_frida.ProcessNotFoundError = Exception

        success = hooks.attach(9999)

        assert success is False
        assert hooks._attached is False
        assert len(hooks.errors) > 0

    @patch("intellicrack.core.certificate.frida_cert_hooks.frida")
    def test_attach_fails_when_permission_denied(self, mock_frida, hooks):
        """Test attach fails when permission is denied."""
        mock_frida.attach.side_effect = mock_frida.PermissionDeniedError("Access denied")
        mock_frida.PermissionDeniedError = Exception

        success = hooks.attach(1234)

        assert success is False
        assert hooks._attached is False
        assert len(hooks.errors) > 0

    def test_attach_prevents_double_attachment(self, hooks, mock_frida_session):
        """Test that attaching when already attached returns False."""
        hooks._attached = True
        hooks.session = mock_frida_session

        success = hooks.attach(1234)

        assert success is False


class TestScriptInjection:
    """Tests for script injection."""

    @patch("intellicrack.core.certificate.frida_cert_hooks.time")
    def test_inject_script_successfully(
        self, mock_time, hooks, mock_frida_session, mock_frida_script, sample_script_content
    ):
        """Test successful script injection."""
        hooks._attached = True
        hooks.session = mock_frida_session
        mock_frida_session.create_script.return_value = mock_frida_script

        success = hooks.inject_script(sample_script_content)

        assert success is True
        assert hooks._script_loaded is True
        assert hooks.script is not None
        mock_frida_session.create_script.assert_called_once_with(sample_script_content)
        mock_frida_script.on.assert_called_once()
        mock_frida_script.load.assert_called_once()

    def test_inject_script_fails_when_not_attached(self, hooks, sample_script_content):
        """Test script injection fails when not attached to process."""
        success = hooks.inject_script(sample_script_content)

        assert success is False
        assert hooks._script_loaded is False

    @patch("intellicrack.core.certificate.frida_cert_hooks.time")
    def test_inject_script_handles_invalid_operation(
        self, mock_time, hooks, mock_frida_session, sample_script_content
    ):
        """Test script injection handles InvalidOperationError."""
        hooks._attached = True
        hooks.session = mock_frida_session

        import frida
        mock_frida_session.create_script.side_effect = frida.InvalidOperationError("Invalid")

        success = hooks.inject_script(sample_script_content)

        assert success is False
        assert len(hooks.errors) > 0


class TestBypassInjection:
    """Tests for bypass script injection."""

    @patch.object(FridaCertificateHooks, "load_script")
    @patch.object(FridaCertificateHooks, "inject_script")
    def test_inject_universal_bypass(self, mock_inject, mock_load, hooks):
        """Test injecting universal bypass script."""
        mock_load.return_value = "// Universal bypass code"
        mock_inject.return_value = True

        success = hooks.inject_universal_bypass()

        assert success is True
        mock_load.assert_called_once_with("universal")
        mock_inject.assert_called_once_with("// Universal bypass code")

    @patch.object(FridaCertificateHooks, "load_script")
    @patch.object(FridaCertificateHooks, "inject_script")
    def test_inject_specific_bypass_for_openssl(
        self, mock_inject, mock_load, hooks
    ):
        """Test injecting OpenSSL-specific bypass."""
        mock_load.return_value = "// OpenSSL bypass code"
        mock_inject.return_value = True

        success = hooks.inject_specific_bypass("openssl")

        assert success is True
        mock_load.assert_called_once_with("openssl")

    def test_inject_invalid_library_bypass(self, hooks):
        """Test injecting bypass for unknown library."""
        success = hooks.inject_specific_bypass("invalid_lib")

        assert success is False
        assert len(hooks.errors) > 0


class TestMessageHandling:
    """Tests for message handling from Frida scripts."""

    def test_handle_log_message(self, hooks):
        """Test handling log messages from scripts."""
        message = {
            "type": "send",
            "payload": {
                "type": "log",
                "data": {
                    "level": "info",
                    "message": "SSL validation bypassed",
                },
            },
        }

        hooks._on_message(message, None)

        assert len(hooks.messages) == 1
        assert hooks.messages[0].message_type == "log"

    def test_handle_certificate_message(self, hooks):
        """Test handling intercepted certificate data."""
        cert_data = {
            "subject": "CN=example.com",
            "issuer": "CN=Test CA",
            "not_before": "2024-01-01",
            "not_after": "2025-01-01",
        }

        message = {
            "type": "send",
            "payload": {
                "type": "certificate",
                "data": cert_data,
            },
        }

        hooks._on_message(message, None)

        assert len(hooks.intercepted_certificates) == 1
        assert hooks.intercepted_certificates[0] == cert_data

    def test_handle_bypass_success_message(self, hooks):
        """Test handling bypass success notification."""
        message = {
            "type": "send",
            "payload": {
                "type": "bypass_success",
                "library": "WinHTTP",
            },
        }

        hooks._on_message(message, None)

        assert len(hooks.messages) == 1

    def test_handle_bypass_failure_message(self, hooks):
        """Test handling bypass failure notification."""
        message = {
            "type": "send",
            "payload": {
                "type": "bypass_failure",
                "library": "OpenSSL",
                "reason": "Function not found",
            },
        }

        hooks._on_message(message, None)

        assert len(hooks.errors) > 0

    def test_handle_error_message(self, hooks):
        """Test handling script error messages."""
        message = {
            "type": "error",
            "description": "ReferenceError: x is not defined",
            "stack": "at line 42",
            "lineNumber": 42,
            "columnNumber": 10,
        }

        hooks._on_message(message, None)

        assert len(hooks.errors) > 0

    def test_handle_connection_bypassed_message(self, hooks):
        """Test handling bypassed connection notification."""
        conn_data = {
            "url": "https://example.com",
            "method": "GET",
        }

        message = {
            "type": "send",
            "payload": {
                "type": "https_request",
                "data": conn_data,
            },
        }

        hooks._on_message(message, None)

        assert len(hooks.bypassed_connections) == 1


class TestBypassStatus:
    """Tests for bypass status reporting."""

    def test_get_bypass_status_when_not_loaded(self, hooks):
        """Test getting status when no script is loaded."""
        status = hooks.get_bypass_status()

        assert status.active is False
        assert status.library is None
        assert len(status.hooks_installed) == 0

    @patch.object(FridaCertificateHooks, "call_rpc")
    def test_get_bypass_status_via_rpc(self, mock_rpc, hooks):
        """Test getting bypass status via RPC call."""
        hooks._script_loaded = True
        hooks.script = Mock()

        mock_rpc.return_value = {
            "active": True,
            "library": "OpenSSL",
            "platform": "Windows",
            "hooksInstalled": ["SSL_CTX_set_verify", "SSL_get_verify_result"],
            "detectedLibraries": [{"name": "libssl.so", "type": "OpenSSL"}],
        }

        status = hooks.get_bypass_status()

        assert status.active is True
        assert status.library == "OpenSSL"
        assert status.platform == "Windows"
        assert len(status.hooks_installed) == 2


class TestRPCCalls:
    """Tests for RPC function calls."""

    def test_call_rpc_successfully(self, hooks):
        """Test successful RPC function call."""
        hooks._script_loaded = True
        mock_script = Mock()
        mock_script.exports_sync = {
            "getDetectedLibraries": lambda: ["libssl.so", "libcrypto.so"]
        }
        hooks.script = mock_script

        result = hooks.call_rpc("getDetectedLibraries")

        assert result == ["libssl.so", "libcrypto.so"]

    def test_call_rpc_when_script_not_loaded(self, hooks):
        """Test RPC call fails when no script is loaded."""
        with pytest.raises(RuntimeError) as exc_info:
            hooks.call_rpc("someFunction")

        assert "Script not loaded" in str(exc_info.value)

    def test_call_rpc_with_nonexistent_function(self, hooks):
        """Test RPC call fails for undefined function."""
        hooks._script_loaded = True
        hooks.script = Mock()
        hooks.script.exports_sync = {}

        with pytest.raises(RuntimeError) as exc_info:
            hooks.call_rpc("nonexistentFunction")

        assert "RPC function not found" in str(exc_info.value)


class TestDataRetrieval:
    """Tests for retrieving intercepted data."""

    def test_get_intercepted_certificates(self, hooks):
        """Test retrieving intercepted certificates."""
        hooks.intercepted_certificates = [
            {"subject": "CN=test1.com"},
            {"subject": "CN=test2.com"},
        ]

        certs = hooks.get_intercepted_certificates()

        assert len(certs) == 2
        assert certs[0]["subject"] == "CN=test1.com"

    def test_get_bypassed_connections(self, hooks):
        """Test retrieving bypassed connections."""
        hooks.bypassed_connections = [
            {"url": "https://example.com"},
            {"url": "https://test.com"},
        ]

        connections = hooks.get_bypassed_connections()

        assert len(connections) == 2

    def test_get_messages_all(self, hooks):
        """Test retrieving all messages."""
        hooks.messages = [
            FridaMessage(datetime.now(), "log", {}, "info"),
            FridaMessage(datetime.now(), "certificate", {}, "info"),
        ]

        messages = hooks.get_messages()

        assert len(messages) == 2

    def test_get_messages_limited(self, hooks):
        """Test retrieving limited number of recent messages."""
        for i in range(10):
            hooks.messages.append(
                FridaMessage(datetime.now(), f"log{i}", {}, "info")
            )

        messages = hooks.get_messages(count=5)

        assert len(messages) == 5


class TestDetachment:
    """Tests for process detachment and cleanup."""

    def test_detach_from_process(self, hooks, mock_frida_session, mock_frida_script):
        """Test detaching from process."""
        hooks._attached = True
        hooks._script_loaded = True
        hooks.session = mock_frida_session
        hooks.script = mock_frida_script

        success = hooks.detach()

        assert success is True
        assert hooks._attached is False
        assert hooks._script_loaded is False
        assert hooks.session is None
        assert hooks.script is None
        mock_frida_script.unload.assert_called_once()
        mock_frida_session.detach.assert_called_once()

    def test_detach_handles_errors_gracefully(
        self, hooks, mock_frida_session, mock_frida_script
    ):
        """Test detachment handles errors without crashing."""
        hooks._attached = True
        hooks._script_loaded = True
        hooks.session = mock_frida_session
        hooks.script = mock_frida_script

        mock_frida_script.unload.side_effect = Exception("Unload failed")
        mock_frida_session.detach.side_effect = Exception("Detach failed")

        success = hooks.detach()

        assert success is True
        assert hooks._attached is False

    def test_unload_scripts_only(self, hooks, mock_frida_script):
        """Test unloading scripts without detaching."""
        hooks._script_loaded = True
        hooks.script = mock_frida_script

        success = hooks.unload_scripts()

        assert success is True
        assert hooks._script_loaded is False
        mock_frida_script.unload.assert_called_once()

    def test_unload_scripts_when_none_loaded(self, hooks):
        """Test unload_scripts returns False when no scripts loaded."""
        success = hooks.unload_scripts()

        assert success is False


class TestLogManagement:
    """Tests for log and data management."""

    def test_clear_logs(self, hooks):
        """Test clearing all logs and data."""
        hooks.messages = [FridaMessage(datetime.now(), "log", {}, "info")]
        hooks.intercepted_certificates = [{"subject": "CN=test.com"}]
        hooks.bypassed_connections = [{"url": "https://example.com"}]
        hooks.errors = ["Error 1"]

        success = hooks.clear_logs()

        assert success is True
        assert len(hooks.messages) == 0
        assert len(hooks.intercepted_certificates) == 0
        assert len(hooks.bypassed_connections) == 0
        assert len(hooks.errors) == 0


class TestStateChecks:
    """Tests for state checking methods."""

    def test_is_attached_when_attached(self, hooks):
        """Test is_attached returns True when attached."""
        hooks._attached = True

        assert hooks.is_attached() is True

    def test_is_attached_when_not_attached(self, hooks):
        """Test is_attached returns False when not attached."""
        assert hooks.is_attached() is False

    def test_is_script_loaded_when_loaded(self, hooks):
        """Test is_script_loaded returns True when script loaded."""
        hooks._script_loaded = True

        assert hooks.is_script_loaded() is True

    def test_is_script_loaded_when_not_loaded(self, hooks):
        """Test is_script_loaded returns False when not loaded."""
        assert hooks.is_script_loaded() is False


class TestContextManager:
    """Tests for context manager protocol."""

    @patch.object(FridaCertificateHooks, "detach")
    def test_context_manager_detaches_on_exit(self, mock_detach):
        """Test context manager calls detach on exit."""
        with FridaCertificateHooks() as hooks:
            pass

        mock_detach.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
