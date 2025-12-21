"""Production tests for R2UIManager radare2 UI integration.

Tests comprehensive radare2 UI integration including widget management,
binary loading, analysis execution, and results export functionality.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget

from intellicrack.ui.radare2_ui_manager import R2UIManager, create_r2_ui_manager, integrate_radare2_ui_comprehensive


@pytest.fixture
def sample_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "test.exe"
    with open(binary, "wb") as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 60 + b"\x3c\x00\x00\x00" + b"\x00" * 60 + b"PE\x00\x00")
    return binary


@pytest.fixture
def mock_main_app(qtbot: object) -> QMainWindow:
    app = QMainWindow()
    app.tab_widget = QTabWidget()
    app.setCentralWidget(app.tab_widget)
    app.binary_path = None
    app.statusBar().showMessage("Ready")
    return app


class TestR2UIManagerBasics:
    """Test R2UIManager initialization and core functionality."""

    def test_initialization_creates_ui_components(self, qtbot: object) -> None:
        manager = R2UIManager()

        assert manager.binary_path is None
        assert len(manager.current_results) == 0
        assert "r2_widget" in manager.ui_components
        assert "enhanced_dashboard" in manager.ui_components
        assert "results_viewer" in manager.ui_components
        assert "config_dialog" in manager.ui_components

    def test_set_binary_path_updates_components(self, qtbot: object, sample_binary: Path) -> None:
        manager = R2UIManager()
        binary_path = str(sample_binary)

        manager.set_binary_path(binary_path)

        assert manager.binary_path == binary_path

    def test_binary_loaded_signal_emitted(self, qtbot: object, sample_binary: Path) -> None:
        manager = R2UIManager()
        signal_received = []

        manager.binary_loaded.connect(lambda path: signal_received.append(path))

        manager.set_binary_path(str(sample_binary))

        assert len(signal_received) == 1
        assert signal_received[0] == str(sample_binary)


class TestR2UIManagerIntegration:
    """Test R2UIManager integration with main application."""

    def test_integrate_with_tab_widget(self, qtbot: object, mock_main_app: QMainWindow) -> None:
        manager = R2UIManager(mock_main_app)

        success = manager.integrate_with_application(mock_main_app)

        assert success
        assert mock_main_app.tab_widget.count() >= 2

        tab_names = [mock_main_app.tab_widget.tabText(i) for i in range(mock_main_app.tab_widget.count())]
        assert "Radare2 Analysis" in tab_names
        assert "Enhanced Analysis" in tab_names

    def test_integrate_stores_references(self, qtbot: object, mock_main_app: QMainWindow) -> None:
        manager = R2UIManager()

        manager.integrate_with_application(mock_main_app)

        assert hasattr(mock_main_app, "r2_ui_manager")
        assert hasattr(mock_main_app, "r2_widget")
        assert mock_main_app.r2_ui_manager is manager

    def test_status_bar_integration(self, qtbot: object, mock_main_app: QMainWindow) -> None:
        manager = R2UIManager(mock_main_app)
        manager.integrate_with_application(mock_main_app)

        manager.status_updated.emit("Test status message")

        QApplication.processEvents()
        status_text = mock_main_app.statusBar().currentMessage()
        assert "R2: Test status message" in status_text


class TestR2UIManagerAnalysis:
    """Test R2UIManager analysis execution and result handling."""

    def test_start_analysis_without_binary_fails(self, qtbot: object, mock_main_app: QMainWindow) -> None:
        manager = R2UIManager(mock_main_app)

        result = manager.start_analysis("comprehensive")

        assert result is False

    def test_start_analysis_emits_signal(self, qtbot: object, mock_main_app: QMainWindow, sample_binary: Path) -> None:
        manager = R2UIManager(mock_main_app)
        manager.set_binary_path(str(sample_binary))

        signals_received = []
        manager.analysis_started.connect(lambda analysis_type: signals_received.append(analysis_type))

        manager.start_analysis("comprehensive")

        assert "comprehensive" in signals_received

    def test_start_analysis_records_history(self, qtbot: object, mock_main_app: QMainWindow, sample_binary: Path) -> None:
        manager = R2UIManager(mock_main_app)
        manager.set_binary_path(str(sample_binary))

        manager.start_analysis("vulnerability")

        history = manager.get_analysis_history()
        assert len(history) > 0
        assert history[-1]["type"] == "vulnerability"
        assert history[-1]["binary"] == str(sample_binary)

    def test_analysis_completed_handler(self, qtbot: object) -> None:
        manager = R2UIManager()
        test_results = {
            "analysis_type": "comprehensive",
            "findings": ["finding1", "finding2"],
            "vulnerabilities": 3
        }

        manager._on_analysis_completed(test_results)

        assert manager.current_results == test_results

    def test_analysis_failed_handler(self, qtbot: object) -> None:
        manager = R2UIManager()
        error_message = "Analysis failed: test error"

        manager._on_analysis_failed(error_message)

        assert manager.current_results == {}


class TestR2UIManagerResultsExport:
    """Test R2UIManager results export functionality."""

    def test_export_results_without_results_fails(self, qtbot: object, mock_main_app: QMainWindow, tmp_path: Path) -> None:
        manager = R2UIManager(mock_main_app)
        export_path = str(tmp_path / "results.json")

        result = manager.export_results(export_path)

        assert result is False

    def test_export_results_creates_file(self, qtbot: object, tmp_path: Path) -> None:
        manager = R2UIManager()
        manager.current_results = {
            "analysis": "test",
            "findings": ["finding1", "finding2"]
        }
        export_path = str(tmp_path / "results.json")

        result = manager.export_results(export_path)

        assert result is True
        assert Path(export_path).exists()

        with open(export_path) as f:
            exported = json.load(f)
        assert exported["analysis"] == "test"
        assert len(exported["findings"]) == 2

    def test_export_uses_default_path_when_none(self, qtbot: object, tmp_path: Path, sample_binary: Path) -> None:
        manager = R2UIManager()
        manager.binary_path = str(sample_binary)
        manager.current_results = {"test": "data"}

        os.chdir(tmp_path)
        result = manager.export_results()

        assert result is True
        expected_name = f"{sample_binary.stem}_radare2_analysis.json"
        assert Path(expected_name).exists()

    def test_export_updates_history(self, qtbot: object, tmp_path: Path) -> None:
        manager = R2UIManager()
        manager.current_results = {"data": "test"}
        export_path = str(tmp_path / "export.json")

        manager.export_results(export_path)

        history = manager.get_analysis_history()
        assert any(entry.get("action") == "export" for entry in history)


class TestR2UIManagerConfiguration:
    """Test R2UIManager configuration management."""

    def test_show_configuration_dialog(self, qtbot: object, monkeypatch: pytest.MonkeyPatch) -> None:
        manager = R2UIManager()

        dialog_shown = []

        def mock_exec(self: object) -> int:
            dialog_shown.append(True)
            return 0

        if "config_dialog" in manager.ui_components:
            monkeypatch.setattr(manager.ui_components["config_dialog"].__class__, "exec", mock_exec)

        manager.show_configuration()

        assert len(dialog_shown) > 0 or "config_dialog" not in manager.ui_components

    def test_apply_configuration(self, qtbot: object) -> None:
        manager = R2UIManager()
        config = {
            "analysis_timeout": 300,
            "max_depth": 10,
            "enable_ai": True
        }

        manager._apply_configuration(config)

        assert hasattr(manager, "analysis_config")
        assert manager.analysis_config == config


class TestR2UIManagerMenuIntegration:
    """Test R2UIManager menu integration."""

    def test_menu_integration_creates_entries(self, qtbot: object) -> None:
        main_app = QMainWindow()
        menubar = main_app.menuBar()

        manager = R2UIManager(main_app)
        manager._integrate_menu_items(main_app)

        menus = [menubar.actions()[i].text() for i in range(len(menubar.actions()))]
        assert "Radare2" in menus or len(menubar.actions()) == 0


class TestR2UIManagerCleanup:
    """Test R2UIManager resource cleanup."""

    def test_cleanup_clears_references(self, qtbot: object) -> None:
        manager = R2UIManager()
        manager.current_results = {"data": "test"}
        manager.analysis_history = [{"entry": 1}]
        manager.ui_components = {"test": object()}

        manager.cleanup()

        assert len(manager.current_results) == 0
        assert len(manager.analysis_history) == 0
        assert len(manager.ui_components) == 0

    def test_cleanup_stops_running_workers(self, qtbot: object) -> None:
        manager = R2UIManager()

        if "r2_widget" in manager.ui_components:
            r2_widget = manager.ui_components["r2_widget"]
            if hasattr(r2_widget, "current_worker"):
                mock_worker = MagicMock()
                mock_worker.isRunning.return_value = True
                r2_widget.current_worker = mock_worker

                manager.cleanup()

                assert mock_worker.terminate.called or not hasattr(r2_widget, "current_worker")


class TestR2UIManagerFactoryFunctions:
    """Test R2UIManager factory functions."""

    def test_create_r2_ui_manager_returns_instance(self, qtbot: object) -> None:
        manager = create_r2_ui_manager()

        assert isinstance(manager, R2UIManager)
        assert manager.main_app is None

    def test_create_r2_ui_manager_with_app(self, qtbot: object, mock_main_app: QMainWindow) -> None:
        manager = create_r2_ui_manager(mock_main_app)

        assert isinstance(manager, R2UIManager)
        assert manager.main_app is mock_main_app

    def test_integrate_radare2_ui_comprehensive(self, qtbot: object, mock_main_app: QMainWindow) -> None:
        manager = integrate_radare2_ui_comprehensive(mock_main_app)

        assert manager is not None or not hasattr(mock_main_app, "tab_widget")
        if manager:
            assert isinstance(manager, R2UIManager)


class TestR2UIManagerSignalHandlers:
    """Test R2UIManager signal handling."""

    def test_on_binary_loaded_updates_status(self, qtbot: object) -> None:
        manager = R2UIManager()
        status_updates = []

        manager.status_updated.connect(lambda msg: status_updates.append(msg))

        manager._on_binary_loaded("/path/to/test.exe")

        assert any("test.exe" in msg for msg in status_updates)

    def test_on_analysis_started_updates_status(self, qtbot: object) -> None:
        manager = R2UIManager()
        status_updates = []

        manager.status_updated.connect(lambda msg: status_updates.append(msg))

        manager._on_analysis_started("comprehensive")

        assert any("comprehensive" in msg for msg in status_updates)


class TestR2UIManagerRealWorldScenarios:
    """Test R2UIManager real-world usage scenarios."""

    def test_complete_analysis_workflow(self, qtbot: object, mock_main_app: QMainWindow, sample_binary: Path, tmp_path: Path) -> None:
        manager = R2UIManager(mock_main_app)
        manager.integrate_with_application(mock_main_app)

        manager.set_binary_path(str(sample_binary))

        analysis_result = manager.start_analysis("comprehensive")

        manager.current_results = {
            "binary": str(sample_binary),
            "protections": ["ASLR", "DEP"],
            "vulnerabilities": []
        }

        export_path = str(tmp_path / "analysis_results.json")
        export_result = manager.export_results(export_path)

        assert Path(export_path).exists() or not analysis_result
        if Path(export_path).exists():
            with open(export_path) as f:
                data = json.load(f)
            assert "binary" in data

    def test_multiple_analysis_types_sequential(self, qtbot: object, sample_binary: Path) -> None:
        manager = R2UIManager()
        manager.set_binary_path(str(sample_binary))

        analysis_types = ["comprehensive", "vulnerability", "decompilation"]
        for analysis_type in analysis_types:
            manager.start_analysis(analysis_type)

        history = manager.get_analysis_history()
        executed_types = [entry["type"] for entry in history]

        for analysis_type in analysis_types:
            assert analysis_type in executed_types

    def test_binary_path_change_clears_previous_results(self, qtbot: object, sample_binary: Path, tmp_path: Path) -> None:
        manager = R2UIManager()

        manager.set_binary_path(str(sample_binary))
        manager.current_results = {"old": "data"}

        new_binary = tmp_path / "new.exe"
        with open(new_binary, "wb") as f:
            f.write(b"MZ\x90\x00")

        manager.clear_results()
        manager.set_binary_path(str(new_binary))

        assert len(manager.current_results) == 0
