"""Integration tests for Frida Stalker with frida_analyzer.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

import pytest


class MockMainApp:
    """Mock main application for testing."""

    def __init__(self):
        self.current_binary = None
        self.update_output = MagicMock()
        self.messages = []

    def set_binary(self, path):
        """Set current binary."""
        self.current_binary = path

    def emit_message(self, msg):
        """Emit a message."""
        self.messages.append(msg)
        self.update_output.emit(msg)


@pytest.fixture
def mock_main_app():
    """Create mock main app."""
    return MockMainApp()


@pytest.fixture
def temp_binary():
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ\x90\x00")
        temp_path = f.name
    yield temp_path
    import os

    try:
        os.unlink(temp_path)
    except Exception:
        pass


@pytest.fixture
def mock_stalker_session():
    """Create mock StalkerSession."""
    import sys
    import intellicrack.core.analysis.frida_analyzer

    original_stalker_session = getattr(intellicrack.core.analysis.frida_analyzer, 'StalkerSession', None)

    mock_class = MagicMock()
    mock_instance = MagicMock()
    mock_instance.start.return_value = True
    mock_instance.stop_stalking.return_value = True
    mock_instance.trace_function.return_value = True
    mock_instance.collect_module_coverage.return_value = True
    mock_instance.get_stats.return_value = MagicMock(
        total_instructions=1000, unique_blocks=50, coverage_entries=25, licensing_routines=5, api_calls=100
    )
    mock_instance.get_licensing_routines.return_value = ["app.exe:0x1000", "license.dll:0x2000"]
    mock_class.return_value = mock_instance

    intellicrack.core.analysis.frida_analyzer.StalkerSession = mock_class

    yield mock_class

    if original_stalker_session:
        intellicrack.core.analysis.frida_analyzer.StalkerSession = original_stalker_session


class TestStalkerIntegration:
    """Test Stalker integration with frida_analyzer."""

    def test_start_stalker_session_success(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test starting Stalker session successfully."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        mock_main_app.set_binary(temp_binary)
        result = start_stalker_session(mock_main_app)

        assert result is True
        mock_stalker_session.assert_called_once()
        mock_stalker_session.return_value.start.assert_called_once()

    def test_start_stalker_session_no_binary(self, mock_main_app):
        """Test starting Stalker session without binary."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        result = start_stalker_session(mock_main_app)

        assert result is False
        mock_main_app.update_output.emit.assert_called()
        assert any("No binary loaded" in str(call) for call in mock_main_app.update_output.emit.call_args_list)

    def test_start_stalker_session_module_not_available(self, mock_main_app, temp_binary):
        """Test starting Stalker session when module not available."""
        with patch("intellicrack.core.analysis.frida_analyzer.StalkerSession", None):
            from intellicrack.core.analysis.frida_analyzer import start_stalker_session

            mock_main_app.set_binary(temp_binary)
            result = start_stalker_session(mock_main_app)

            assert result is False
            assert any(
                "not available" in str(call) for call in mock_main_app.update_output.emit.call_args_list
            )

    def test_start_stalker_session_with_custom_output_dir(
        self, mock_main_app, temp_binary, mock_stalker_session
    ):
        """Test starting Stalker session with custom output directory."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        mock_main_app.set_binary(temp_binary)
        custom_dir = "/custom/output"
        result = start_stalker_session(mock_main_app, output_dir=custom_dir)

        assert result is True
        call_args = mock_stalker_session.call_args
        assert call_args.kwargs['binary_path'] == temp_binary
        assert call_args.kwargs['output_dir'] == custom_dir
        assert 'message_callback' in call_args.kwargs

    def test_start_stalker_session_start_failure(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test starting Stalker session when start fails."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session

        mock_stalker_session.return_value.start.return_value = False
        mock_main_app.set_binary(temp_binary)
        result = start_stalker_session(mock_main_app)

        assert result is False

    def test_stop_stalker_session_success(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test stopping Stalker session successfully."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session, stop_stalker_session

        mock_main_app.set_binary(temp_binary)
        mock_stalker_session.return_value.start.return_value = True
        start_result = start_stalker_session(mock_main_app)
        assert start_result is True

        mock_stalker_session.return_value.stop_stalking.return_value = True
        result = stop_stalker_session(mock_main_app)

        assert result is True
        assert mock_stalker_session.return_value.stop_stalking.called

    def test_stop_stalker_session_no_binary(self, mock_main_app):
        """Test stopping Stalker session without binary."""
        from intellicrack.core.analysis.frida_analyzer import stop_stalker_session

        result = stop_stalker_session(mock_main_app)

        assert result is False
        assert any("No binary loaded" in str(call) for call in mock_main_app.update_output.emit.call_args_list)

    def test_stop_stalker_session_no_active_session(self, mock_main_app, temp_binary):
        """Test stopping Stalker session when no active session."""
        from intellicrack.core.analysis.frida_analyzer import stop_stalker_session

        mock_main_app.set_binary(temp_binary)
        result = stop_stalker_session(mock_main_app)

        assert result is False
        calls_str = ' '.join(str(call) for call in mock_main_app.update_output.emit.call_args_list)
        assert "No active" in calls_str or "not found" in calls_str

    def test_trace_function_stalker_success(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test tracing function with Stalker successfully."""
        from intellicrack.core.analysis.frida_analyzer import start_stalker_session, trace_function_stalker

        mock_main_app.set_binary(temp_binary)
        start_stalker_session(mock_main_app)
        result = trace_function_stalker(mock_main_app, "app.exe", "ValidateLicense")

        assert result is True
        mock_stalker_session.return_value.trace_function.assert_called_once_with("app.exe", "ValidateLicense")

    def test_trace_function_stalker_no_binary(self, mock_main_app):
        """Test tracing function without binary."""
        from intellicrack.core.analysis.frida_analyzer import trace_function_stalker

        result = trace_function_stalker(mock_main_app, "app.exe", "ValidateLicense")

        assert result is False
        assert any("No binary loaded" in str(call) for call in mock_main_app.update_output.emit.call_args_list)

    def test_trace_function_stalker_no_active_session(self, mock_main_app, temp_binary):
        """Test tracing function when no active session."""
        from intellicrack.core.analysis.frida_analyzer import trace_function_stalker

        mock_main_app.set_binary(temp_binary)
        result = trace_function_stalker(mock_main_app, "app.exe", "ValidateLicense")

        assert result is False

    def test_collect_module_coverage_stalker_success(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test collecting module coverage with Stalker successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            collect_module_coverage_stalker,
            start_stalker_session,
        )

        mock_main_app.set_binary(temp_binary)
        start_stalker_session(mock_main_app)
        result = collect_module_coverage_stalker(mock_main_app, "license.dll")

        assert result is True
        mock_stalker_session.return_value.collect_module_coverage.assert_called_once_with("license.dll")

    def test_collect_module_coverage_stalker_no_binary(self, mock_main_app):
        """Test collecting module coverage without binary."""
        from intellicrack.core.analysis.frida_analyzer import collect_module_coverage_stalker

        result = collect_module_coverage_stalker(mock_main_app, "license.dll")

        assert result is False

    def test_get_stalker_stats_success(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test getting Stalker stats successfully."""
        from intellicrack.core.analysis.frida_analyzer import get_stalker_stats, start_stalker_session

        mock_main_app.set_binary(temp_binary)
        start_stalker_session(mock_main_app)
        stats = get_stalker_stats(mock_main_app)

        assert stats is not None
        assert stats["total_instructions"] == 1000
        assert stats["unique_blocks"] == 50
        assert stats["coverage_entries"] == 25
        assert stats["licensing_routines"] == 5
        assert stats["api_calls"] == 100

    def test_get_stalker_stats_no_binary(self, mock_main_app):
        """Test getting Stalker stats without binary."""
        from intellicrack.core.analysis.frida_analyzer import get_stalker_stats

        stats = get_stalker_stats(mock_main_app)

        assert stats is None

    def test_get_stalker_stats_no_active_session(self, mock_main_app, temp_binary):
        """Test getting Stalker stats when no active session."""
        from intellicrack.core.analysis.frida_analyzer import get_stalker_stats

        mock_main_app.set_binary(temp_binary)
        stats = get_stalker_stats(mock_main_app)

        assert stats is None

    def test_get_licensing_routines_stalker_success(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test getting licensing routines successfully."""
        from intellicrack.core.analysis.frida_analyzer import (
            get_licensing_routines_stalker,
            start_stalker_session,
        )

        mock_main_app.set_binary(temp_binary)
        start_stalker_session(mock_main_app)
        routines = get_licensing_routines_stalker(mock_main_app)

        assert routines is not None
        assert len(routines) == 2
        assert "app.exe:0x1000" in routines
        assert "license.dll:0x2000" in routines

    def test_get_licensing_routines_stalker_no_binary(self, mock_main_app):
        """Test getting licensing routines without binary."""
        from intellicrack.core.analysis.frida_analyzer import get_licensing_routines_stalker

        routines = get_licensing_routines_stalker(mock_main_app)

        assert routines is None

    def test_get_licensing_routines_stalker_no_active_session(self, mock_main_app, temp_binary):
        """Test getting licensing routines when no active session."""
        from intellicrack.core.analysis.frida_analyzer import get_licensing_routines_stalker

        mock_main_app.set_binary(temp_binary)
        routines = get_licensing_routines_stalker(mock_main_app)

        assert routines is None

    def test_full_workflow(self, mock_main_app, temp_binary, mock_stalker_session):
        """Test complete Stalker workflow."""
        from intellicrack.core.analysis.frida_analyzer import (
            collect_module_coverage_stalker,
            get_licensing_routines_stalker,
            get_stalker_stats,
            start_stalker_session,
            stop_stalker_session,
            trace_function_stalker,
        )

        mock_main_app.set_binary(temp_binary)

        mock_stalker_session.return_value.start.return_value = True
        mock_stalker_session.return_value.trace_function.return_value = True
        mock_stalker_session.return_value.collect_module_coverage.return_value = True
        mock_stalker_session.return_value.stop_stalking.return_value = True

        result = start_stalker_session(mock_main_app)
        assert result is True

        result = trace_function_stalker(mock_main_app, "app.exe", "CheckLicense")
        assert result is True

        result = collect_module_coverage_stalker(mock_main_app, "license.dll")
        assert result is True

        stats = get_stalker_stats(mock_main_app)
        assert stats is not None
        assert stats["total_instructions"] > 0

        routines = get_licensing_routines_stalker(mock_main_app)
        assert routines is not None
        assert len(routines) > 0

        result = stop_stalker_session(mock_main_app)
        assert result is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
