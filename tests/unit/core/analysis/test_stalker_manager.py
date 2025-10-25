"""Unit tests for Frida Stalker integration module.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, PropertyMock, call, mock_open, patch

import pytest


class TestStalkerManagerImport(unittest.TestCase):
    """Test import behavior with and without Frida."""

    def test_import_without_frida(self):
        """Test that module handles missing Frida gracefully."""
        import sys

        original_frida = sys.modules.get('frida')
        sys.modules['frida'] = None
        try:
            import importlib
            from intellicrack.core import analysis
            importlib.reload(analysis.stalker_manager)
            self.assertIsNone(analysis.stalker_manager.frida)
        except (ImportError, AttributeError):
            pass
        finally:
            if original_frida:
                sys.modules['frida'] = original_frida


@pytest.fixture
def mock_frida():
    """Create mock Frida module."""
    with patch("intellicrack.core.analysis.stalker_manager.frida") as mock:
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()

        mock_device.spawn.return_value = 12345
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script
        mock_session.is_detached = False

        mock.get_local_device.return_value = mock_device

        yield mock


@pytest.fixture
def temp_binary():
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ\x90\x00")
        temp_path = f.name
    yield temp_path
    try:
        os.unlink(temp_path)
    except Exception:
        pass


@pytest.fixture
def stalker_script_content():
    """Mock Stalker script content."""
    return """
    send({type: 'ready', message: 'Stalker ready'});
    rpc.exports = {
        startStalking: function() {},
        stopStalking: function() {},
        traceFunction: function(module, func) {},
        collectModuleCoverage: function(module) {},
        getStats: function() { return {}; },
        setConfig: function(config) {}
    };
    """


class TestStalkerSession:
    """Test StalkerSession class."""

    def test_init_basic(self, temp_binary, mock_frida):
        """Test basic initialization."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        assert session.binary_path == temp_binary
        assert session.output_dir == os.path.join(os.path.dirname(temp_binary), "stalker_output")
        assert session.pid is None
        assert session._is_active is False
        assert len(session.trace_events) == 0
        assert len(session.api_calls) == 0
        assert len(session.coverage_data) == 0

    def test_init_custom_output_dir(self, temp_binary, mock_frida):
        """Test initialization with custom output directory."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        custom_dir = tempfile.mkdtemp()
        session = StalkerSession(temp_binary, output_dir=custom_dir)

        assert session.output_dir == custom_dir

    def test_init_custom_callback(self, temp_binary, mock_frida):
        """Test initialization with custom message callback."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        callback = Mock()
        session = StalkerSession(temp_binary, message_callback=callback)

        session._log("test message")
        callback.assert_called_once_with("[StalkerSession] test message")

    def test_init_without_frida(self, temp_binary):
        """Test initialization fails gracefully without Frida."""
        with patch("intellicrack.core.analysis.stalker_manager.frida", None):
            from intellicrack.core.analysis.stalker_manager import StalkerSession

            with pytest.raises(ImportError, match="Frida is not installed"):
                StalkerSession(temp_binary)

    def test_on_message_status(self, temp_binary, mock_frida):
        """Test status message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        callback = Mock()
        session = StalkerSession(temp_binary, message_callback=callback)

        message = {"type": "send", "payload": {"type": "status", "message": "Test status"}}
        session._on_message(message, None)

        assert any("Status: Test status" in str(call) for call in callback.call_args_list)

    def test_on_message_ready(self, temp_binary, mock_frida):
        """Test ready message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        callback = Mock()
        session = StalkerSession(temp_binary, message_callback=callback)

        message = {
            "type": "send",
            "payload": {
                "type": "ready",
                "message": "Stalker ready",
                "capabilities": ["tracing", "api_monitoring"],
            },
        }
        session._on_message(message, None)

        assert any("Stalker ready" in str(call) for call in callback.call_args_list)

    def test_on_message_api_call(self, temp_binary, mock_frida):
        """Test API call message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        message = {
            "type": "send",
            "payload": {
                "type": "api_call",
                "data": {
                    "api": "kernel32.dll!CreateFileW",
                    "tid": 1234,
                    "timestamp": 1234567890,
                    "backtrace": ["0x401000"],
                },
                "licensing": True,
            },
        }
        session._on_message(message, None)

        assert len(session.api_calls) == 1
        api_call = session.api_calls[0]
        assert api_call.api_name == "kernel32.dll!CreateFileW"
        assert api_call.thread_id == 1234
        assert api_call.is_licensing_related is True

    def test_on_message_licensing_event(self, temp_binary, mock_frida):
        """Test licensing event message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        message = {
            "type": "send",
            "payload": {
                "type": "licensing_event",
                "data": {
                    "api": "RegQueryValueExW",
                    "caller": {"module": "license.dll", "offset": "0x1000"},
                },
            },
        }
        session._on_message(message, None)

        assert "license.dll:0x1000" in session.licensing_routines

    def test_on_message_progress(self, temp_binary, mock_frida):
        """Test progress message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        message = {
            "type": "send",
            "payload": {
                "type": "progress",
                "instructions": 10000,
                "blocks": 500,
                "coverage_entries": 250,
                "licensing_routines": 10,
            },
        }
        session._on_message(message, None)

        assert session.stats.total_instructions == 10000
        assert session.stats.unique_blocks == 500
        assert session.stats.coverage_entries == 250
        assert session.stats.licensing_routines == 10

    def test_on_message_trace_complete(self, temp_binary, mock_frida):
        """Test trace complete message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        message = {
            "type": "send",
            "payload": {
                "type": "trace_complete",
                "data": {
                    "total_instructions": 50000,
                    "unique_blocks": 2000,
                    "coverage_entries": 1000,
                    "licensing_routines": 25,
                    "api_calls": 500,
                    "coverage": [
                        {
                            "key": "app.exe:0x1000",
                            "module": "app.exe",
                            "offset": "0x1000",
                            "address": "0x401000",
                            "hitCount": 100,
                            "licensing": True,
                        }
                    ],
                    "licensing_functions": ["app.exe:0x1000", "license.dll:0x2000"],
                },
            },
        }

        with patch.object(session, "_save_trace_results"):
            session._on_message(message, None)

        assert session.stats.total_instructions == 50000
        assert len(session.coverage_data) == 1
        assert "app.exe:0x1000" in session.coverage_data
        assert session.coverage_data["app.exe:0x1000"].hit_count == 100
        assert session.coverage_data["app.exe:0x1000"].is_licensing is True

    def test_on_message_function_trace(self, temp_binary, mock_frida):
        """Test function trace message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        message = {
            "type": "send",
            "payload": {
                "type": "function_trace_complete",
                "function": "app.exe!ValidateLicense",
                "trace_length": 500,
                "trace": [
                    {
                        "type": "enter",
                        "address": "0x401000",
                        "module": "app.exe",
                        "offset": "0x1000",
                        "timestamp": 1234567890,
                    }
                ],
            },
        }

        with patch.object(session, "_save_json"):
            session._on_message(message, None)

        assert len(session.trace_events) == 1
        assert session.trace_events[0].event_type == "enter"
        assert session.trace_events[0].address == "0x401000"

    def test_on_message_module_coverage(self, temp_binary, mock_frida):
        """Test module coverage message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)

        message = {
            "type": "send",
            "payload": {
                "type": "module_coverage_complete",
                "module": "license.dll",
                "blocks_covered": 250,
                "coverage_percentage": 75.5,
            },
        }

        with patch.object(session, "_save_json"):
            session._on_message(message, None)

    def test_on_message_error(self, temp_binary, mock_frida):
        """Test error message handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        callback = Mock()
        session = StalkerSession(temp_binary, message_callback=callback)

        message = {"type": "send", "payload": {"type": "error", "message": "Test error"}}
        session._on_message(message, None)

        assert any("Error: Test error" in str(call) for call in callback.call_args_list)

    def test_on_message_script_error(self, temp_binary, mock_frida):
        """Test script error handling."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        callback = Mock()
        session = StalkerSession(temp_binary, message_callback=callback)

        message = {"type": "error", "stack": "Error: Something broke"}
        session._on_message(message, None)

        assert any("Script Error" in str(call) for call in callback.call_args_list)

    def test_start_success(self, temp_binary, mock_frida, stalker_script_content):
        """Test successful session start."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                result = session.start()

        assert result is True
        assert session._is_active is True
        assert session.pid == 12345
        mock_frida.get_local_device.assert_called_once()

    def test_start_missing_script(self, temp_binary, mock_frida):
        """Test start failure when script is missing."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch.object(Path, "exists", return_value=False):
            session = StalkerSession(temp_binary)
            result = session.start()

        assert result is False
        assert session._is_active is False

    def test_start_frida_error(self, temp_binary, mock_frida, stalker_script_content):
        """Test start failure when Frida errors."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        mock_frida.get_local_device.side_effect = Exception("Frida error")

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                result = session.start()

        assert result is False
        assert session._is_active is False

    def test_start_stalking_success(self, temp_binary, mock_frida, stalker_script_content):
        """Test start_stalking success."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                result = session.start_stalking()

        assert result is True
        session.script.exports_sync.start_stalking.assert_called_once()

    def test_start_stalking_not_active(self, temp_binary, mock_frida):
        """Test start_stalking when session not active."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        result = session.start_stalking()

        assert result is False

    def test_stop_stalking_success(self, temp_binary, mock_frida, stalker_script_content):
        """Test stop_stalking success."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                result = session.stop_stalking()

        assert result is True
        session.script.exports_sync.stop_stalking.assert_called_once()

    def test_trace_function_success(self, temp_binary, mock_frida, stalker_script_content):
        """Test trace_function success."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                result = session.trace_function("app.exe", "ValidateLicense")

        assert result is True
        session.script.exports_sync.trace_function.assert_called_once_with("app.exe", "ValidateLicense")

    def test_trace_function_not_active(self, temp_binary, mock_frida):
        """Test trace_function when session not active."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        result = session.trace_function("app.exe", "ValidateLicense")

        assert result is False

    def test_collect_module_coverage_success(self, temp_binary, mock_frida, stalker_script_content):
        """Test collect_module_coverage success."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                result = session.collect_module_coverage("license.dll")

        assert result is True
        session.script.exports_sync.collect_module_coverage.assert_called_once_with("license.dll")

    def test_get_stats_active(self, temp_binary, mock_frida, stalker_script_content):
        """Test get_stats with active session."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                session.script.exports_sync.get_stats.return_value = {
                    "totalInstructions": 1000,
                    "uniqueBlocks": 50,
                    "coverageEntries": 25,
                    "licensingRoutines": 5,
                    "apiCalls": 100,
                }

                stats = session.get_stats()

        assert stats.total_instructions == 1000
        assert stats.unique_blocks == 50
        assert stats.coverage_entries == 25
        assert stats.licensing_routines == 5
        assert stats.api_calls == 100

    def test_get_stats_not_active(self, temp_binary, mock_frida):
        """Test get_stats without active session."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        stats = session.get_stats()

        assert stats.total_instructions == 0

    def test_set_config_success(self, temp_binary, mock_frida, stalker_script_content):
        """Test set_config success."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                config = {"traceInstructions": True, "maxTraceEvents": 500000}
                result = session.set_config(config)

        assert result is True
        session.script.exports_sync.set_config.assert_called_once_with(config)

    def test_get_licensing_routines(self, temp_binary, mock_frida):
        """Test get_licensing_routines."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        session.licensing_routines.add("app.exe:0x1000")
        session.licensing_routines.add("license.dll:0x2000")

        routines = session.get_licensing_routines()

        assert len(routines) == 2
        assert "app.exe:0x1000" in routines
        assert "license.dll:0x2000" in routines

    def test_get_coverage_summary_empty(self, temp_binary, mock_frida):
        """Test get_coverage_summary with no data."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        summary = session.get_coverage_summary()

        assert summary["total_entries"] == 0
        assert summary["top_hotspots"] == []

    def test_get_coverage_summary_with_data(self, temp_binary, mock_frida):
        """Test get_coverage_summary with data."""
        from intellicrack.core.analysis.stalker_manager import CoverageEntry, StalkerSession

        session = StalkerSession(temp_binary)
        session.coverage_data["app.exe:0x1000"] = CoverageEntry(
            module="app.exe", offset="0x1000", address="0x401000", hit_count=100, is_licensing=True
        )
        session.coverage_data["app.exe:0x2000"] = CoverageEntry(
            module="app.exe", offset="0x2000", address="0x402000", hit_count=50, is_licensing=False
        )

        summary = session.get_coverage_summary()

        assert summary["total_entries"] == 2
        assert summary["licensing_entries"] == 1
        assert len(summary["top_hotspots"]) == 2
        assert summary["top_hotspots"][0]["hit_count"] == 100
        assert len(summary["licensing_hotspots"]) == 1

    def test_get_api_summary_empty(self, temp_binary, mock_frida):
        """Test get_api_summary with no data."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        summary = session.get_api_summary()

        assert summary["total_calls"] == 0
        assert summary["unique_apis"] == 0
        assert summary["top_apis"] == []

    def test_get_api_summary_with_data(self, temp_binary, mock_frida):
        """Test get_api_summary with data."""
        from intellicrack.core.analysis.stalker_manager import APICallEvent, StalkerSession

        session = StalkerSession(temp_binary)
        session.api_calls.append(
            APICallEvent(
                api_name="CreateFileW",
                module="kernel32.dll",
                timestamp=1234567890,
                thread_id=1234,
                is_licensing_related=True,
            )
        )
        session.api_calls.append(
            APICallEvent(
                api_name="CreateFileW",
                module="kernel32.dll",
                timestamp=1234567891,
                thread_id=1234,
                is_licensing_related=False,
            )
        )
        session.api_calls.append(
            APICallEvent(
                api_name="RegQueryValueExW",
                module="advapi32.dll",
                timestamp=1234567892,
                thread_id=1234,
                is_licensing_related=True,
            )
        )

        summary = session.get_api_summary()

        assert summary["total_calls"] == 3
        assert summary["unique_apis"] == 2
        assert summary["licensing_calls"] == 2
        assert summary["top_apis"][0]["api"] == "CreateFileW"
        assert summary["top_apis"][0]["count"] == 2

    def test_export_results(self, temp_binary, mock_frida):
        """Test export_results."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        session = StalkerSession(temp_binary)
        session.stats.total_instructions = 1000

        with patch.object(session, "_save_json") as mock_save:
            result_path = session.export_results()

        assert "stalker_results_" in result_path
        assert result_path.endswith(".json")
        mock_save.assert_called_once()

    def test_cleanup(self, temp_binary, mock_frida, stalker_script_content):
        """Test cleanup."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary)
                session.start()
                session.cleanup()

        assert session._is_active is False
        session.session.detach.assert_called_once()

    def test_cleanup_error(self, temp_binary, mock_frida, stalker_script_content):
        """Test cleanup handles errors gracefully."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        callback = Mock()
        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                session = StalkerSession(temp_binary, message_callback=callback)
                session.start()
                session.session.detach.side_effect = Exception("Detach failed")
                session.cleanup()

        assert session._is_active is False
        assert any("Error detaching" in str(call) for call in callback.call_args_list)

    def test_context_manager(self, temp_binary, mock_frida, stalker_script_content):
        """Test context manager."""
        from intellicrack.core.analysis.stalker_manager import StalkerSession

        with patch("builtins.open", mock_open(read_data=stalker_script_content)):
            with patch.object(Path, "exists", return_value=True):
                with StalkerSession(temp_binary) as session:
                    assert session._is_active is True

        assert session._is_active is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
