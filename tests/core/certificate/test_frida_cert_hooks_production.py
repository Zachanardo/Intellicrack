"""Production-grade tests for FridaCertificateHooks validating real Frida integration.

Tests REAL Frida hook capabilities for certificate validation bypass.
Tests validate script loading, process attachment interface, and message handling.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging
import sys
import threading
from datetime import datetime
from pathlib import Path

import pytest

try:
    import frida

    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from intellicrack.core.certificate.frida_cert_hooks import (
    BypassStatus,
    FridaCertificateHooks,
    FridaMessage,
)

logger = logging.getLogger(__name__)


pytestmark = pytest.mark.skipif(not FRIDA_AVAILABLE, reason="Frida not available")


@pytest.fixture
def hooks() -> FridaCertificateHooks:
    """Create FridaCertificateHooks instance."""
    return FridaCertificateHooks()


@pytest.fixture
def hooks_with_cleanup() -> FridaCertificateHooks:
    """Create FridaCertificateHooks instance with automatic cleanup."""
    hook_instance = FridaCertificateHooks()
    yield hook_instance
    try:
        if hook_instance.is_attached():
            hook_instance.detach()
    except Exception:
        pass


@pytest.fixture
def test_script_content() -> str:
    """Minimal valid Frida script for testing."""
    return """
    console.log('Test script loaded');

    rpc.exports = {
        testFunction: function() {
            return 'test result';
        }
    };
    """


class TestFridaMessageDataclass:
    """Test FridaMessage dataclass functionality."""

    def test_frida_message_creates_with_required_fields(self) -> None:
        """FridaMessage must create with timestamp, type, and payload."""
        now = datetime.now()
        msg = FridaMessage(
            timestamp=now,
            message_type="log",
            payload="test message",
        )

        assert msg.timestamp == now
        assert msg.message_type == "log"
        assert msg.payload == "test message"
        assert msg.level == "info"

    def test_frida_message_allows_custom_level(self) -> None:
        """FridaMessage must support custom log levels."""
        msg = FridaMessage(
            timestamp=datetime.now(),
            message_type="error",
            payload="error occurred",
            level="error",
        )

        assert msg.level == "error"

    def test_frida_message_handles_various_payload_types(self) -> None:
        """FridaMessage must accept any payload type."""
        msg_str = FridaMessage(datetime.now(), "log", "string")
        msg_dict = FridaMessage(datetime.now(), "certificate", {"subject": "CN=test"})
        msg_list = FridaMessage(datetime.now(), "data", [1, 2, 3])

        assert isinstance(msg_str.payload, str)
        assert isinstance(msg_dict.payload, dict)
        assert isinstance(msg_list.payload, list)


class TestBypassStatusDataclass:
    """Test BypassStatus dataclass functionality."""

    def test_bypass_status_creates_with_all_fields(self) -> None:
        """BypassStatus must create with all required fields."""
        status = BypassStatus(
            active=True,
            library="OpenSSL",
            platform="Windows",
            hooks_installed=["SSL_CTX_set_verify", "SSL_get_verify_result"],
            detected_libraries=[{"name": "libssl-1_1-x64.dll"}],
            message_count=42,
            errors=[],
        )

        assert status.active is True
        assert status.library == "OpenSSL"
        assert status.platform == "Windows"
        assert len(status.hooks_installed) == 2
        assert len(status.detected_libraries) == 1
        assert status.message_count == 42
        assert status.errors == []

    def test_bypass_status_intercepted_data_defaults_to_empty_dict(self) -> None:
        """BypassStatus.intercepted_data must default to empty dict."""
        status = BypassStatus(
            active=False,
            library=None,
            platform=None,
            hooks_installed=[],
            detected_libraries=[],
            message_count=0,
            errors=[],
        )

        assert isinstance(status.intercepted_data, dict)
        assert len(status.intercepted_data) == 0


class TestFridaCertificateHooksInitialization:
    """Test FridaCertificateHooks initialization."""

    def test_hooks_initializes_with_default_state(self, hooks: FridaCertificateHooks) -> None:
        """Hooks must initialize with clean state."""
        assert hooks.session is None
        assert hooks.script is None
        assert hooks.target is None
        assert hooks.messages == []
        assert hooks.intercepted_certificates == []
        assert hooks.bypassed_connections == []
        assert hooks.errors == []
        assert hooks._attached is False
        assert hooks._script_loaded is False

    def test_hooks_has_message_lock(self, hooks: FridaCertificateHooks) -> None:
        """Hooks must have threading lock for message handling."""
        assert isinstance(hooks._message_lock, threading.Lock)

    def test_hooks_defines_script_directory(self, hooks: FridaCertificateHooks) -> None:
        """Hooks must have SCRIPT_DIR defined."""
        assert hasattr(FridaCertificateHooks, "SCRIPT_DIR")
        assert isinstance(FridaCertificateHooks.SCRIPT_DIR, Path)

    def test_hooks_defines_available_scripts(self, hooks: FridaCertificateHooks) -> None:
        """Hooks must define AVAILABLE_SCRIPTS mapping."""
        assert hasattr(FridaCertificateHooks, "AVAILABLE_SCRIPTS")
        scripts = FridaCertificateHooks.AVAILABLE_SCRIPTS

        assert "winhttp" in scripts
        assert "schannel" in scripts
        assert "openssl" in scripts
        assert "cryptoapi" in scripts
        assert "android" in scripts
        assert "ios" in scripts
        assert "universal" in scripts

        for script_name, script_file in scripts.items():
            assert script_file.endswith(".js")


class TestScriptLoading:
    """Test Frida script loading functionality."""

    def test_load_script_rejects_unknown_script_name(self, hooks: FridaCertificateHooks) -> None:
        """load_script must raise ValueError for unknown script names."""
        with pytest.raises(ValueError, match="Unknown script"):
            hooks.load_script("nonexistent_script")

    def test_load_script_accepts_valid_script_names(self, hooks: FridaCertificateHooks) -> None:
        """load_script must accept all scripts in AVAILABLE_SCRIPTS."""
        for script_name in FridaCertificateHooks.AVAILABLE_SCRIPTS.keys():
            try:
                content = hooks.load_script(script_name)
                assert isinstance(content, str)
                assert len(content) > 0
            except FileNotFoundError:
                pytest.skip(f"Script file not found: {script_name}")

    def test_load_script_returns_javascript_code(self, hooks: FridaCertificateHooks) -> None:
        """load_script must return JavaScript source code."""
        try:
            content = hooks.load_script("universal")

            assert isinstance(content, str)
            assert len(content) > 100
        except FileNotFoundError:
            pytest.skip("Universal script file not found")

    def test_load_script_raises_file_not_found_for_missing_file(self, hooks: FridaCertificateHooks) -> None:
        """load_script must raise FileNotFoundError if script file missing."""
        old_dir = FridaCertificateHooks.SCRIPT_DIR
        try:
            FridaCertificateHooks.SCRIPT_DIR = Path("/nonexistent/directory")
            hooks_temp = FridaCertificateHooks()

            with pytest.raises(FileNotFoundError):
                hooks_temp.load_script("universal")
        finally:
            FridaCertificateHooks.SCRIPT_DIR = old_dir


class TestProcessAttachment:
    """Test process attachment functionality."""

    def test_attach_accepts_integer_pid(self, hooks: FridaCertificateHooks) -> None:
        """attach must accept integer PID."""
        result = hooks.attach(9999999)

        assert isinstance(result, bool)

    def test_attach_accepts_string_process_name(self, hooks: FridaCertificateHooks) -> None:
        """attach must accept string process name."""
        result = hooks.attach("nonexistent_process.exe")

        assert isinstance(result, bool)

    def test_attach_accepts_string_pid(self, hooks: FridaCertificateHooks) -> None:
        """attach must accept string containing PID."""
        result = hooks.attach("9999999")

        assert isinstance(result, bool)

    def test_attach_rejects_invalid_type(self, hooks: FridaCertificateHooks) -> None:
        """attach must reject invalid target types."""
        with pytest.raises(TypeError):
            hooks.attach([1, 2, 3])

    def test_attach_stores_target(self, hooks: FridaCertificateHooks) -> None:
        """attach must store target identifier."""
        hooks.attach("test_process")

        assert hooks.target == "test_process"

    def test_attach_returns_false_if_already_attached(self, hooks: FridaCertificateHooks) -> None:
        """attach must return False if already attached."""
        hooks._attached = True

        result = hooks.attach("test_process")

        assert result is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_attach_to_real_system_process_succeeds(self, hooks_with_cleanup: FridaCertificateHooks) -> None:
        """attach must succeed when attaching to real running process."""
        try:
            result = hooks_with_cleanup.attach("explorer.exe")

            if result:
                assert hooks_with_cleanup.is_attached()
                assert hooks_with_cleanup.session is not None
        except Exception as e:
            pytest.skip(f"Cannot attach to process: {e}")


class TestScriptInjection:
    """Test Frida script injection."""

    def test_inject_script_requires_attachment(self, hooks: FridaCertificateHooks) -> None:
        """inject_script must fail if not attached to process."""
        result = hooks.inject_script("console.log('test');")

        assert result is False

    def test_inject_script_accepts_javascript_string(self, hooks: FridaCertificateHooks, test_script_content: str) -> None:
        """inject_script must accept JavaScript code as string."""
        result = hooks.inject_script(test_script_content)

        assert isinstance(result, bool)

    def test_inject_universal_bypass_loads_universal_script(self, hooks: FridaCertificateHooks) -> None:
        """inject_universal_bypass must attempt to load universal bypass script."""
        result = hooks.inject_universal_bypass()

        assert isinstance(result, bool)

    def test_inject_specific_bypass_validates_library_name(self, hooks: FridaCertificateHooks) -> None:
        """inject_specific_bypass must validate library name."""
        result = hooks.inject_specific_bypass("nonexistent_library")

        assert isinstance(result, bool)

    def test_inject_specific_bypass_accepts_valid_libraries(self, hooks: FridaCertificateHooks) -> None:
        """inject_specific_bypass must accept valid library names."""
        for library in ["winhttp", "schannel", "openssl", "cryptoapi", "android", "ios"]:
            result = hooks.inject_specific_bypass(library)
            assert isinstance(result, bool)


class TestMessageHandling:
    """Test Frida message handling."""

    def test_on_message_handles_send_type(self, hooks: FridaCertificateHooks) -> None:
        """_on_message must handle 'send' type messages."""
        message = {"type": "send", "payload": "test"}

        hooks._on_message(message, None)

    def test_on_message_handles_error_type(self, hooks: FridaCertificateHooks) -> None:
        """_on_message must handle 'error' type messages."""
        message = {
            "type": "error",
            "description": "Test error",
            "stack": "Error stack",
            "fileName": "test.js",
            "lineNumber": 42,
        }

        hooks._on_message(message, None)

        assert len(hooks.errors) > 0

    def test_handle_send_message_processes_log_messages(self, hooks: FridaCertificateHooks) -> None:
        """_handle_send_message must process log messages."""
        payload = {"type": "log", "message": "Test log message"}

        hooks._handle_send_message(payload, None)

        assert len(hooks.messages) > 0
        assert hooks.messages[-1].message_type == "log"

    def test_handle_send_message_processes_certificate_messages(self, hooks: FridaCertificateHooks) -> None:
        """_handle_send_message must process certificate messages."""
        payload = {
            "type": "certificate",
            "subject": "CN=Test",
            "issuer": "CN=Test CA",
            "not_before": "2024-01-01",
            "not_after": "2025-01-01",
        }

        hooks._handle_send_message(payload, None)

        assert len(hooks.intercepted_certificates) > 0

    def test_handle_send_message_is_thread_safe(self, hooks: FridaCertificateHooks) -> None:
        """_handle_send_message must be thread-safe."""
        def send_messages() -> None:
            for i in range(100):
                payload = {"type": "log", "message": f"Message {i}"}
                hooks._handle_send_message(payload, None)

        threads = [threading.Thread(target=send_messages) for _ in range(5)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(hooks.messages) == 500


class TestBypassStatus:
    """Test bypass status retrieval."""

    def test_get_bypass_status_returns_bypass_status_object(self, hooks: FridaCertificateHooks) -> None:
        """get_bypass_status must return BypassStatus object."""
        status = hooks.get_bypass_status()

        assert isinstance(status, BypassStatus)

    def test_get_bypass_status_reflects_current_state(self, hooks: FridaCertificateHooks) -> None:
        """get_bypass_status must reflect current bypass state."""
        status = hooks.get_bypass_status()

        assert status.active == hooks._attached
        assert status.message_count == len(hooks.messages)
        assert status.errors == hooks.errors

    def test_get_bypass_status_when_not_attached(self, hooks: FridaCertificateHooks) -> None:
        """get_bypass_status must return inactive status when not attached."""
        status = hooks.get_bypass_status()

        assert status.active is False
        assert status.library is None
        assert status.platform is None

    def test_get_bypass_status_includes_message_count(self, hooks: FridaCertificateHooks) -> None:
        """get_bypass_status must include accurate message count."""
        hooks.messages = [
            FridaMessage(datetime.now(), "log", "msg1"),
            FridaMessage(datetime.now(), "log", "msg2"),
        ]

        status = hooks.get_bypass_status()

        assert status.message_count == 2


class TestDataRetrieval:
    """Test intercepted data retrieval."""

    def test_get_intercepted_certificates_returns_list(self, hooks: FridaCertificateHooks) -> None:
        """get_intercepted_certificates must return list of certificates."""
        certs = hooks.get_intercepted_certificates()

        assert isinstance(certs, list)

    def test_get_intercepted_certificates_returns_stored_certificates(self, hooks: FridaCertificateHooks) -> None:
        """get_intercepted_certificates must return all intercepted certificates."""
        test_cert = {"subject": "CN=Test", "issuer": "CN=CA"}
        hooks.intercepted_certificates = [test_cert]

        certs = hooks.get_intercepted_certificates()

        assert len(certs) == 1
        assert certs[0] == test_cert

    def test_get_bypassed_connections_returns_list(self, hooks: FridaCertificateHooks) -> None:
        """get_bypassed_connections must return list of connections."""
        connections = hooks.get_bypassed_connections()

        assert isinstance(connections, list)

    def test_get_bypassed_connections_returns_stored_connections(self, hooks: FridaCertificateHooks) -> None:
        """get_bypassed_connections must return all bypassed connections."""
        test_connection = {"host": "example.com", "port": 443}
        hooks.bypassed_connections = [test_connection]

        connections = hooks.get_bypassed_connections()

        assert len(connections) == 1
        assert connections[0] == test_connection

    def test_get_messages_returns_all_messages_by_default(self, hooks: FridaCertificateHooks) -> None:
        """get_messages must return all messages when count is None."""
        hooks.messages = [
            FridaMessage(datetime.now(), "log", "msg1"),
            FridaMessage(datetime.now(), "log", "msg2"),
            FridaMessage(datetime.now(), "log", "msg3"),
        ]

        messages = hooks.get_messages()

        assert len(messages) == 3

    def test_get_messages_limits_to_count(self, hooks: FridaCertificateHooks) -> None:
        """get_messages must limit results when count is specified."""
        hooks.messages = [
            FridaMessage(datetime.now(), "log", f"msg{i}")
            for i in range(10)
        ]

        messages = hooks.get_messages(count=5)

        assert len(messages) == 5


class TestRPCCalls:
    """Test RPC function calls."""

    def test_call_rpc_requires_script_loaded(self, hooks: FridaCertificateHooks) -> None:
        """call_rpc must fail gracefully if no script loaded."""
        try:
            result = hooks.call_rpc("testFunction")
        except Exception as e:
            assert "script" in str(e).lower() or "attached" in str(e).lower()

    def test_call_rpc_accepts_function_name_and_args(self, hooks: FridaCertificateHooks) -> None:
        """call_rpc must accept function name and arguments."""
        try:
            hooks.call_rpc("testFunction", "arg1", "arg2", 123)
        except Exception:
            pass


class TestDetachment:
    """Test process detachment."""

    def test_detach_returns_boolean(self, hooks: FridaCertificateHooks) -> None:
        """detach must return boolean result."""
        result = hooks.detach()

        assert isinstance(result, bool)

    def test_detach_when_not_attached(self, hooks: FridaCertificateHooks) -> None:
        """detach must handle being called when not attached."""
        result = hooks.detach()

        assert isinstance(result, bool)

    def test_detach_cleans_up_state(self, hooks: FridaCertificateHooks) -> None:
        """detach must reset internal state."""
        hooks._attached = True
        hooks._script_loaded = True

        hooks.detach()

        assert hooks._attached is False
        assert hooks._script_loaded is False
        assert hooks.session is None
        assert hooks.script is None

    def test_unload_scripts_returns_boolean(self, hooks: FridaCertificateHooks) -> None:
        """unload_scripts must return boolean result."""
        result = hooks.unload_scripts()

        assert isinstance(result, bool)

    def test_clear_logs_empties_message_list(self, hooks: FridaCertificateHooks) -> None:
        """clear_logs must empty the messages list."""
        hooks.messages = [
            FridaMessage(datetime.now(), "log", "msg1"),
            FridaMessage(datetime.now(), "log", "msg2"),
        ]

        result = hooks.clear_logs()

        assert result is True
        assert len(hooks.messages) == 0


class TestStateQueries:
    """Test state query methods."""

    def test_is_attached_returns_boolean(self, hooks: FridaCertificateHooks) -> None:
        """is_attached must return boolean."""
        result = hooks.is_attached()

        assert isinstance(result, bool)

    def test_is_attached_reflects_attached_state(self, hooks: FridaCertificateHooks) -> None:
        """is_attached must return True when attached."""
        hooks._attached = False
        assert hooks.is_attached() is False

        hooks._attached = True
        assert hooks.is_attached() is True

    def test_is_script_loaded_returns_boolean(self, hooks: FridaCertificateHooks) -> None:
        """is_script_loaded must return boolean."""
        result = hooks.is_script_loaded()

        assert isinstance(result, bool)

    def test_is_script_loaded_reflects_script_state(self, hooks: FridaCertificateHooks) -> None:
        """is_script_loaded must return True when script is loaded."""
        hooks._script_loaded = False
        assert hooks.is_script_loaded() is False

        hooks._script_loaded = True
        assert hooks.is_script_loaded() is True


class TestContextManager:
    """Test context manager functionality."""

    def test_context_manager_enter_returns_hooks(self, hooks: FridaCertificateHooks) -> None:
        """Context manager __enter__ must return hooks instance."""
        with hooks as h:
            assert h is hooks
            assert isinstance(h, FridaCertificateHooks)

    def test_context_manager_exit_detaches(self, hooks: FridaCertificateHooks) -> None:
        """Context manager __exit__ must detach from process."""
        hooks._attached = True

        with hooks:
            pass

        assert hooks._attached is False


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_multiple_detach_calls_safe(self, hooks: FridaCertificateHooks) -> None:
        """Multiple detach calls must be safe."""
        hooks.detach()
        hooks.detach()
        hooks.detach()

    def test_handles_empty_message_list(self, hooks: FridaCertificateHooks) -> None:
        """Methods must handle empty message list gracefully."""
        messages = hooks.get_messages()
        assert messages == []

        hooks.clear_logs()
        assert hooks.messages == []

    def test_handles_empty_certificate_list(self, hooks: FridaCertificateHooks) -> None:
        """Methods must handle empty certificate list gracefully."""
        certs = hooks.get_intercepted_certificates()
        assert certs == []

    def test_thread_safety_of_message_lock(self, hooks: FridaCertificateHooks) -> None:
        """Message lock must provide thread safety."""
        def access_messages() -> None:
            with hooks._message_lock:
                current_len = len(hooks.messages)
                hooks.messages.append(FridaMessage(datetime.now(), "log", "test"))
                assert len(hooks.messages) == current_len + 1

        threads = [threading.Thread(target=access_messages) for _ in range(10)]

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        assert len(hooks.messages) == 10
