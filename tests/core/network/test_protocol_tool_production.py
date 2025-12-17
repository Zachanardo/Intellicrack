import sys
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest

pytest.importorskip("PyQt6")

from PyQt6.QtCore import Qt
from PyQt6.QtTest import QTest
from PyQt6.QtWidgets import QApplication

from intellicrack.core.network.protocol_tool import (
    ProtocolToolSignals,
    ProtocolToolWindow,
    launch_protocol_tool,
    update_protocol_tool_description,
)


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app
    if ProtocolToolWindow._instance:
        ProtocolToolWindow._instance.close()
        ProtocolToolWindow._instance = None


@pytest.fixture
def protocol_tool_window(qapp: QApplication) -> ProtocolToolWindow:
    if ProtocolToolWindow._instance:
        ProtocolToolWindow._instance.close()
        ProtocolToolWindow._instance = None

    window = ProtocolToolWindow()
    yield window
    window.close()
    ProtocolToolWindow._instance = None


class TestProtocolToolSignals:
    def test_signals_defined(self) -> None:
        signals = ProtocolToolSignals()

        assert hasattr(signals, "tool_launched")
        assert hasattr(signals, "tool_closed")
        assert hasattr(signals, "description_updated")

    def test_signals_emission(self, qtbot: Any) -> None:
        signals = ProtocolToolSignals()

        with qtbot.waitSignal(signals.tool_launched, timeout=1000):
            signals.tool_launched.emit("Test launch")

        with qtbot.waitSignal(signals.tool_closed, timeout=1000):
            signals.tool_closed.emit("Test close")

        with qtbot.waitSignal(signals.description_updated, timeout=1000):
            signals.description_updated.emit("Test update")


class TestProtocolToolWindowInitialization:
    def test_singleton_pattern(self, qapp: QApplication) -> None:
        if ProtocolToolWindow._instance:
            ProtocolToolWindow._instance.close()
            ProtocolToolWindow._instance = None

        window1 = ProtocolToolWindow()
        window2 = ProtocolToolWindow()

        assert window1 is window2
        assert ProtocolToolWindow._instance is window1

        window1.close()
        ProtocolToolWindow._instance = None

    def test_window_title(self, protocol_tool_window: ProtocolToolWindow) -> None:
        assert protocol_tool_window.windowTitle() == "Intellicrack Protocol Tool"

    def test_window_geometry(self, protocol_tool_window: ProtocolToolWindow) -> None:
        geometry = protocol_tool_window.geometry()
        assert geometry.width() == 800
        assert geometry.height() == 600

    def test_ui_components_exist(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        assert hasattr(protocol_tool_window, "title_label")
        assert hasattr(protocol_tool_window, "description_label")
        assert hasattr(protocol_tool_window, "output_text_edit")
        assert hasattr(protocol_tool_window, "input_line_edit")
        assert hasattr(protocol_tool_window, "send_button")
        assert hasattr(protocol_tool_window, "start_analysis_button")
        assert hasattr(protocol_tool_window, "clear_log_button")
        assert hasattr(protocol_tool_window, "close_button")

    def test_output_text_readonly(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        assert protocol_tool_window.output_text_edit.isReadOnly() is True

    def test_initial_description(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        assert "Ready for protocol analysis" in protocol_tool_window.description_label.text()

    def test_input_line_edit_tooltip(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        tooltip = protocol_tool_window.input_line_edit.toolTip()
        assert "analyze" in tooltip.lower()
        assert "parse" in tooltip.lower()
        assert "send" in tooltip.lower()


class TestProtocolToolWindowUserInteraction:
    def test_clear_log_button(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.output_text_edit.append("Test output line 1")
        protocol_tool_window.output_text_edit.append("Test output line 2")

        qtbot.mouseClick(protocol_tool_window.clear_log_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "Test output line 1" not in output_text
        assert "cleared" in output_text.lower()

    def test_send_button_with_input(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("list")

        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "> list" in output_text

    def test_send_button_with_empty_input(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("")

        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "empty" in output_text.lower()

    def test_input_line_edit_return_press(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("list")

        qtbot.keyClick(protocol_tool_window.input_line_edit, Qt.Key.Key_Return)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "> list" in output_text

    def test_input_clears_after_submit(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("test command")

        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        assert protocol_tool_window.input_line_edit.text() == ""


class TestProtocolToolCommandProcessing:
    def test_list_command(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("list")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "Available protocol parsers" in output_text or "PROTOCOLS" in output_text

    def test_unknown_command(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("unknown_command")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ERROR" in output_text or "Unknown command" in output_text

    def test_analyze_command_invalid_hex(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("analyze flexlm INVALID_HEX")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ERROR" in output_text or "Invalid" in output_text

    def test_analyze_command_valid_hex(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("analyze flexlm 48454c4c4f")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ANALYZE" in output_text or "analyze" in output_text

    def test_parse_command_valid_hex(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("parse 48454c4c4f")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "PARSE" in output_text or "parse" in output_text or "Analyzing" in output_text

    def test_parse_command_invalid_hex(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("parse GGGGGG")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ERROR" in output_text or "Invalid" in output_text

    def test_send_command_format(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("send flexlm localhost:27000")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "SEND" in output_text or "send" in output_text or "CONNECT" in output_text

    def test_help_displayed_on_unknown_command(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        protocol_tool_window.input_line_edit.setText("help_me")
        qtbot.mouseClick(protocol_tool_window.send_button, Qt.MouseButton.LeftButton)

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "Available commands" in output_text or "HELP" in output_text


class TestProtocolToolAnalysisButton:
    @patch("intellicrack.core.network.protocol_tool.ProtocolFingerprinter")
    @patch("intellicrack.core.network.protocol_tool.TrafficInterceptionEngine")
    def test_start_analysis_button_executes(
        self,
        mock_interceptor: Mock,
        mock_fingerprinter: Mock,
        protocol_tool_window: ProtocolToolWindow,
        qtbot: Any,
    ) -> None:
        mock_fp_instance = MagicMock()
        mock_fp_instance.detect_protocols.return_value = [
            {"name": "FlexLM", "port": 27000, "confidence": 95, "pattern": "FLEXLM_PATTERN"}
        ]
        mock_fingerprinter.return_value = mock_fp_instance

        mock_interceptor_instance = MagicMock()
        mock_interceptor_instance.capture_license_traffic.return_value = []
        mock_interceptor.return_value = mock_interceptor_instance

        qtbot.mouseClick(
            protocol_tool_window.start_analysis_button, Qt.MouseButton.LeftButton
        )

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "Starting" in output_text or "analysis" in output_text.lower()

    @patch("intellicrack.core.network.protocol_tool.ProtocolFingerprinter")
    @patch("intellicrack.core.network.protocol_tool.TrafficInterceptionEngine")
    def test_start_analysis_displays_detected_protocols(
        self,
        mock_interceptor: Mock,
        mock_fingerprinter: Mock,
        protocol_tool_window: ProtocolToolWindow,
        qtbot: Any,
    ) -> None:
        mock_fp_instance = MagicMock()
        mock_fp_instance.detect_protocols.return_value = [
            {"name": "FlexLM", "port": 27000, "confidence": 95, "pattern": "FLEXLM_PATTERN"},
            {"name": "HASP", "port": 1947, "confidence": 88, "pattern": "HASP_PATTERN"},
        ]
        mock_fingerprinter.return_value = mock_fp_instance

        mock_interceptor_instance = MagicMock()
        mock_interceptor_instance.capture_license_traffic.return_value = []
        mock_interceptor.return_value = mock_interceptor_instance

        qtbot.mouseClick(
            protocol_tool_window.start_analysis_button, Qt.MouseButton.LeftButton
        )

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "FlexLM" in output_text or "flexlm" in output_text.lower()
        assert "HASP" in output_text or "hasp" in output_text.lower()

    @patch("intellicrack.core.network.protocol_tool.ProtocolFingerprinter")
    @patch("intellicrack.core.network.protocol_tool.TrafficInterceptionEngine")
    def test_start_analysis_displays_license_traffic(
        self,
        mock_interceptor: Mock,
        mock_fingerprinter: Mock,
        protocol_tool_window: ProtocolToolWindow,
        qtbot: Any,
    ) -> None:
        mock_fp_instance = MagicMock()
        mock_fp_instance.detect_protocols.return_value = []
        mock_fingerprinter.return_value = mock_fp_instance

        mock_interceptor_instance = MagicMock()
        mock_interceptor_instance.capture_license_traffic.return_value = [
            {"protocol": "FlexLM", "server": "license.server.com:27000"},
            {"protocol": "HASP", "server": "hasp.server.com:1947"},
        ]
        mock_interceptor.return_value = mock_interceptor_instance

        qtbot.mouseClick(
            protocol_tool_window.start_analysis_button, Qt.MouseButton.LeftButton
        )

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "LICENSE" in output_text or "license" in output_text

    @patch("intellicrack.core.network.protocol_tool.ProtocolFingerprinter")
    def test_start_analysis_handles_errors(
        self,
        mock_fingerprinter: Mock,
        protocol_tool_window: ProtocolToolWindow,
        qtbot: Any,
    ) -> None:
        mock_fingerprinter.side_effect = Exception("Analysis error")

        qtbot.mouseClick(
            protocol_tool_window.start_analysis_button, Qt.MouseButton.LeftButton
        )

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ERROR" in output_text or "failed" in output_text.lower()


class TestProtocolToolDescriptionUpdate:
    def test_update_description_method(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        new_description = "Test description update"
        protocol_tool_window.update_description(new_description)

        assert protocol_tool_window.description_label.text() == new_description

    def test_update_description_emits_signal(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        with qtbot.waitSignal(
            ProtocolToolWindow.signals.description_updated, timeout=1000
        ):
            protocol_tool_window.update_description("Signal test")

    def test_update_description_with_app_instance(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        mock_app = MagicMock()
        mock_app.update_output = MagicMock()
        mock_app.update_output.emit = MagicMock()

        protocol_tool_window.app_instance = mock_app
        protocol_tool_window.update_description("With app instance")

        mock_app.update_output.emit.assert_called_once()


class TestProtocolToolWindowCloseEvent:
    def test_close_event_emits_signal(
        self, protocol_tool_window: ProtocolToolWindow, qtbot: Any
    ) -> None:
        with qtbot.waitSignal(ProtocolToolWindow.signals.tool_closed, timeout=1000):
            protocol_tool_window.close()

        assert ProtocolToolWindow._instance is None

    def test_close_event_resets_singleton(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window.close()

        assert ProtocolToolWindow._instance is None


class TestLaunchProtocolTool:
    def test_launch_without_app_instance(self, qapp: QApplication) -> None:
        if ProtocolToolWindow._instance:
            ProtocolToolWindow._instance.close()
            ProtocolToolWindow._instance = None

        window = launch_protocol_tool()

        assert window is not None
        assert isinstance(window, ProtocolToolWindow)
        assert window.isVisible()

        window.close()
        ProtocolToolWindow._instance = None

    def test_launch_with_app_instance(self, qapp: QApplication) -> None:
        if ProtocolToolWindow._instance:
            ProtocolToolWindow._instance.close()
            ProtocolToolWindow._instance = None

        mock_app = MagicMock()
        window = launch_protocol_tool(mock_app)

        assert window.app_instance is mock_app

        window.close()
        ProtocolToolWindow._instance = None

    def test_launch_returns_same_instance_when_already_exists(
        self, qapp: QApplication
    ) -> None:
        if ProtocolToolWindow._instance:
            ProtocolToolWindow._instance.close()
            ProtocolToolWindow._instance = None

        window1 = launch_protocol_tool()
        window2 = launch_protocol_tool()

        assert window1 is window2

        window1.close()
        ProtocolToolWindow._instance = None


class TestUpdateProtocolToolDescription:
    def test_update_description_function(self, qapp: QApplication) -> None:
        if ProtocolToolWindow._instance:
            ProtocolToolWindow._instance.close()
            ProtocolToolWindow._instance = None

        window = ProtocolToolWindow()
        update_protocol_tool_description(description="Function test")

        assert window.description_label.text() == "Function test"

        window.close()
        ProtocolToolWindow._instance = None

    def test_update_description_creates_instance_if_needed(
        self, qapp: QApplication
    ) -> None:
        if ProtocolToolWindow._instance:
            ProtocolToolWindow._instance.close()
            ProtocolToolWindow._instance = None

        update_protocol_tool_description(description="Auto-create test")

        assert ProtocolToolWindow._instance is not None
        assert (
            ProtocolToolWindow._instance.description_label.text() == "Auto-create test"
        )

        ProtocolToolWindow._instance.close()
        ProtocolToolWindow._instance = None


class TestProtocolAnalysisExecution:
    @patch("intellicrack.core.network.protocol_tool.protocols")
    def test_execute_protocol_analysis_flexlm(
        self, mock_protocols: Mock, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        mock_parser_module = MagicMock()
        mock_parser_class = MagicMock()
        mock_parser_instance = MagicMock()

        mock_result = MagicMock()
        mock_result.command = "HELLO"
        mock_result.version = "11.16.2"

        mock_parser_instance.parse_request.return_value = mock_result
        mock_parser_class.return_value = mock_parser_instance
        mock_parser_module.FLEXLMProtocolParser = mock_parser_class

        mock_protocols.get_parser.return_value = mock_parser_module

        protocol_tool_window._execute_protocol_analysis("flexlm", "48454c4c4f")

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ANALYZE" in output_text or "analyze" in output_text

    def test_execute_protocol_analysis_invalid_protocol(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window._execute_protocol_analysis(
            "unknown_protocol", "48454c4c4f"
        )

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "ERROR" in output_text or "Unknown" in output_text

    def test_execute_protocol_analysis_odd_length_hex(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window._execute_protocol_analysis("flexlm", "48454c4c")

        output_text = protocol_tool_window.output_text_edit.toPlainText()

    def test_parse_raw_data_with_detection(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window._parse_raw_data("48454c4c4f")

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "PARSE" in output_text or "parse" in output_text or "Analyzing" in output_text

    def test_send_protocol_command_with_port(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window._send_protocol_command("flexlm", "localhost:27000")

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "SEND" in output_text or "send" in output_text or "CONNECT" in output_text

    def test_send_protocol_command_without_port(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window._send_protocol_command("flexlm", "localhost")

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "SEND" in output_text or "send" in output_text or "CONNECT" in output_text

    def test_list_available_protocols(
        self, protocol_tool_window: ProtocolToolWindow
    ) -> None:
        protocol_tool_window._list_available_protocols()

        output_text = protocol_tool_window.output_text_edit.toPlainText()
        assert "PROTOCOLS" in output_text or "Available" in output_text
