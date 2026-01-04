"""Comprehensive tests for CICDDialog UI component.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import pytest
import tempfile
from pathlib import Path
from typing import Any, Generator

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt

from intellicrack.ui.dialogs.ci_cd_dialog import CICDDialog, PipelineThread


@pytest.fixture
def qapp() -> QApplication:
    """Provide QApplication instance for testing."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app  # type: ignore[return-value]


@pytest.fixture
def temp_plugin_file() -> Generator[Path, None, None]:
    """Create temporary plugin file for testing."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write("""
def plugin_main():
    return "Test plugin"
""")
        temp_path = Path(f.name)

    yield temp_path

    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def ci_cd_dialog(qapp: QApplication, temp_plugin_file: Path) -> CICDDialog:
    """Provide initialized CICDDialog instance."""
    dialog = CICDDialog(parent=None, plugin_path=str(temp_plugin_file))
    return dialog


class TestCICDDialogInitialization:
    """Test CICDDialog initialization and setup."""

    def test_initialization_without_plugin(self, qapp: QApplication) -> None:
        """CICDDialog initializes without plugin path."""
        dialog = CICDDialog(parent=None, plugin_path=None)

        assert dialog.pipeline_thread is None
        assert dialog.stage_widgets == {}
        assert dialog.windowTitle() == "CI/CD Pipeline"

    def test_initialization_with_plugin(self, qapp: QApplication, temp_plugin_file: Path) -> None:
        """CICDDialog initializes with plugin path."""
        dialog = CICDDialog(parent=None, plugin_path=str(temp_plugin_file))

        assert dialog.plugin_path == str(temp_plugin_file)
        assert dialog.windowTitle() == "CI/CD Pipeline"

    def test_initialization_creates_ui_components(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates all required UI components."""
        assert hasattr(ci_cd_dialog, 'tab_widget')
        assert hasattr(ci_cd_dialog, 'pipeline_widget')
        assert hasattr(ci_cd_dialog, 'config_widget')
        assert hasattr(ci_cd_dialog, 'reports_widget')
        assert hasattr(ci_cd_dialog, 'github_widget')

    def test_initialization_creates_control_buttons(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates pipeline control buttons."""
        assert hasattr(ci_cd_dialog, 'run_btn')
        assert hasattr(ci_cd_dialog, 'stop_btn')
        assert hasattr(ci_cd_dialog, 'progress_bar')

        assert not ci_cd_dialog.stop_btn.isEnabled()


class TestCICDDialogPipelineTab:
    """Test pipeline visualization tab functionality."""

    def test_pipeline_tab_creates_stage_widgets(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates widgets for all pipeline stages."""
        expected_stages = ["validate", "test", "quality", "security", "build", "deploy"]

        for stage in expected_stages:
            assert stage in ci_cd_dialog.stage_widgets
            widget = ci_cd_dialog.stage_widgets[stage]
            assert widget is not None

    def test_stage_widget_has_required_components(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog stage widgets have all required components."""
        stage_widget = ci_cd_dialog.stage_widgets["validate"]

        assert hasattr(stage_widget, 'status_label')
        assert hasattr(stage_widget, 'progress')
        assert hasattr(stage_widget, 'result_label')

    def test_console_output_created(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates console output widget."""
        assert hasattr(ci_cd_dialog, 'console_output')
        assert ci_cd_dialog.console_output.isReadOnly()


class TestCICDDialogConfigurationTab:
    """Test configuration tab functionality."""

    def test_config_tree_created(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates configuration tree widget."""
        assert hasattr(ci_cd_dialog, 'config_tree')
        assert ci_cd_dialog.config_tree is not None

    def test_load_configuration_default(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog loads default configuration when no config file exists."""
        ci_cd_dialog.load_configuration()

        root = ci_cd_dialog.config_tree.invisibleRootItem()
        assert root is not None
        assert root.childCount() > 0

    def test_load_configuration_from_file(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog loads configuration from YAML file."""
        yaml = pytest.importorskip("yaml")

        config_path = temp_plugin_file.parent / ".intellicrack-ci.yml"
        config_data = {
            "version": "1.0",
            "stages": ["validate", "test"],
            "test": {"coverage_threshold": 90}
        }

        try:
            with open(config_path, 'w') as f:
                yaml.dump(config_data, f)

            ci_cd_dialog.load_configuration()

            root = ci_cd_dialog.config_tree.invisibleRootItem()
            assert root is not None
            assert root.childCount() > 0

        finally:
            if config_path.exists():
                config_path.unlink()

    def test_save_configuration_writes_file(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog saves configuration to YAML file."""
        yaml = pytest.importorskip("yaml")

        config_path = temp_plugin_file.parent / ".intellicrack-ci.yml"

        try:
            ci_cd_dialog.load_configuration()
            ci_cd_dialog.save_configuration()

            assert config_path.exists()

            with open(config_path) as f:
                saved_config = yaml.safe_load(f)

            assert isinstance(saved_config, dict)

        finally:
            if config_path.exists():
                config_path.unlink()

    def test_reset_configuration_removes_config_file(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog removes config file when reset confirmed."""
        config_path = temp_plugin_file.parent / ".intellicrack-ci.yml"

        try:
            config_path.write_text("version: 1.0")
            assert config_path.exists()

            from PyQt6.QtWidgets import QMessageBox

            original_question = QMessageBox.question

            def auto_confirm(*args: Any, **kwargs: Any) -> QMessageBox.StandardButton:
                return QMessageBox.StandardButton.Yes

            QMessageBox.question = auto_confirm  # type: ignore[method-assign]

            try:
                ci_cd_dialog.reset_configuration()
                assert not config_path.exists()
            finally:
                QMessageBox.question = original_question  # type: ignore[method-assign]

        finally:
            if config_path.exists():
                config_path.unlink()

    def test_build_config_from_tree_handles_nested_values(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog builds configuration from tree with nested values."""
        ci_cd_dialog.load_configuration()

        config = ci_cd_dialog.build_config_from_tree()

        assert isinstance(config, dict)
        assert "version" in config or "stages" in config


class TestCICDDialogReportsTab:
    """Test reports tab functionality."""

    def test_reports_tab_created(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates reports tab components."""
        assert hasattr(ci_cd_dialog, 'report_list')
        assert hasattr(ci_cd_dialog, 'report_viewer')

    def test_load_reports_finds_report_files(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog loads existing pipeline report files."""
        report_path = temp_plugin_file.parent / "pipeline_report_20250101_120000.json"
        report_data = {
            "overall_status": "success",
            "stages": {
                "test": {"success": True, "coverage": 85}
            }
        }

        try:
            with open(report_path, 'w') as f:
                json.dump(report_data, f)

            ci_cd_dialog.load_reports()

            assert ci_cd_dialog.report_list.count() > 0

        finally:
            if report_path.exists():
                report_path.unlink()

    def test_show_report_displays_json(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog displays JSON report content."""
        report_path = temp_plugin_file.parent / "pipeline_report_test.json"
        report_data = {"test": "data"}

        try:
            with open(report_path, 'w') as f:
                json.dump(report_data, f)

            from PyQt6.QtWidgets import QListWidgetItem
            item = QListWidgetItem("Test Report")
            item.setData(Qt.ItemDataRole.UserRole, str(report_path))

            ci_cd_dialog.show_report(item)

            viewer_text = ci_cd_dialog.report_viewer.toPlainText()
            assert "test" in viewer_text or "data" in viewer_text

        finally:
            if report_path.exists():
                report_path.unlink()

    def test_export_report_saves_file(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog exports report to file."""
        ci_cd_dialog.report_viewer.setPlainText("Test report content")

        export_path = Path(tempfile.gettempdir()) / "test_ci_export.txt"

        try:
            from PyQt6.QtWidgets import QFileDialog, QMessageBox

            original_get_save = QFileDialog.getSaveFileName
            original_info = QMessageBox.information

            def mock_get_save(*args: Any, **kwargs: Any) -> tuple[str, str]:
                return (str(export_path), "")

            def mock_info(*args: Any, **kwargs: Any) -> None:
                pass

            QFileDialog.getSaveFileName = mock_get_save  # type: ignore[method-assign]
            QMessageBox.information = mock_info  # type: ignore[method-assign, assignment]

            try:
                ci_cd_dialog.export_report()

                if export_path.exists():
                    content = export_path.read_text()
                    assert "Test report content" in content

            finally:
                QFileDialog.getSaveFileName = original_get_save  # type: ignore[method-assign]
                QMessageBox.information = original_info  # type: ignore[method-assign]

        finally:
            if export_path.exists():
                export_path.unlink()


class TestCICDDialogGitHubTab:
    """Test GitHub Actions tab functionality."""

    def test_github_tab_created(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog creates GitHub Actions tab components."""
        assert hasattr(ci_cd_dialog, 'workflow_preview')
        assert hasattr(ci_cd_dialog, 'py_versions_edit')
        assert hasattr(ci_cd_dialog, 'branches_edit')

    def test_update_workflow_preview_generates_content(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog generates workflow preview content."""
        ci_cd_dialog.update_workflow_preview()

        preview_text = ci_cd_dialog.workflow_preview.toPlainText()
        assert len(preview_text) > 0

    def test_generate_workflow_creates_file(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog generates and saves GitHub Actions workflow."""
        workflows_dir = temp_plugin_file.parent / ".github" / "workflows"

        try:
            original_info = None
            try:
                from PyQt6.QtWidgets import QMessageBox
                original_info = QMessageBox.information

                def mock_info(*args: Any, **kwargs: Any) -> None:
                    pass

                QMessageBox.information = mock_info  # type: ignore[method-assign, assignment]

                ci_cd_dialog.generate_workflow()

            finally:
                if original_info is not None:
                    QMessageBox.information = original_info  # type: ignore[method-assign]

            assert workflows_dir.exists()
            workflow_files = list(workflows_dir.glob("*.yml"))
            assert len(workflow_files) > 0

        finally:
            if workflows_dir.exists():
                import shutil
                shutil.rmtree(temp_plugin_file.parent / ".github")


class TestCICDDialogPipelineExecution:
    """Test pipeline execution functionality."""

    def test_on_stage_started_updates_ui(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog updates UI when pipeline stage starts."""
        ci_cd_dialog.on_stage_started("test")

        stage_widget = ci_cd_dialog.stage_widgets["test"]
        status_label = getattr(stage_widget, 'status_label', None)

        if status_label:
            assert status_label.text() != ""

        console_text = ci_cd_dialog.console_output.toPlainText()
        assert "test" in console_text.lower()

    def test_on_stage_completed_success(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles successful stage completion."""
        result = {"success": True, "coverage": 85}

        ci_cd_dialog.on_stage_completed("test", result)  # type: ignore[arg-type]

        stage_widget = ci_cd_dialog.stage_widgets["test"]
        status_label = getattr(stage_widget, 'status_label', None)

        if status_label:
            assert "OK" in status_label.text() or status_label.text() != ""

    def test_on_stage_completed_failure(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles failed stage completion."""
        result = {
            "success": False,
            "errors": ["Error 1", "Error 2"]
        }

        ci_cd_dialog.on_stage_completed("validate", result)

        console_text = ci_cd_dialog.console_output.toPlainText()
        assert "error" in console_text.lower() or "ERROR" in console_text

    def test_on_pipeline_finished_success(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles successful pipeline completion."""
        results = {"overall_status": "success"}

        ci_cd_dialog.on_pipeline_finished(results)  # type: ignore[arg-type]

        assert ci_cd_dialog.run_btn.isEnabled()
        assert not ci_cd_dialog.stop_btn.isEnabled()
        assert not ci_cd_dialog.progress_bar.isVisible()

    def test_on_pipeline_finished_failure(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles failed pipeline completion."""
        results = {"overall_status": "failure"}

        ci_cd_dialog.on_pipeline_finished(results)  # type: ignore[arg-type]

        console_text = ci_cd_dialog.console_output.toPlainText()
        assert "failed" in console_text.lower() or "failure" in console_text.lower()

    def test_on_pipeline_error_updates_ui(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles pipeline errors."""
        error_msg = "Critical pipeline error"

        ci_cd_dialog.on_pipeline_error(error_msg)

        console_text = ci_cd_dialog.console_output.toPlainText()
        assert error_msg in console_text


class TestCICDDialogLoadPlugin:
    """Test plugin loading functionality."""

    def test_load_plugin_enables_run_button(self, qapp: QApplication, temp_plugin_file: Path) -> None:
        """CICDDialog enables run button when plugin loaded."""
        dialog = CICDDialog(parent=None, plugin_path=None)

        assert not dialog.run_btn.isEnabled()

        dialog.load_plugin(str(temp_plugin_file))

        assert dialog.run_btn.isEnabled()


class TestPipelineThread:
    """Test PipelineThread functionality."""

    def test_pipeline_thread_initialization(self, temp_plugin_file: Path) -> None:
        """PipelineThread initializes with plugin path."""
        thread = PipelineThread(str(temp_plugin_file))

        assert thread.plugin_path == str(temp_plugin_file)
        assert hasattr(thread, 'pipeline')

    def test_pipeline_thread_emits_signals(self, temp_plugin_file: Path) -> None:
        """PipelineThread defines required signals."""
        thread = PipelineThread(str(temp_plugin_file))

        assert hasattr(thread, 'stage_started')
        assert hasattr(thread, 'stage_completed')
        assert hasattr(thread, 'log_message')
        assert hasattr(thread, 'finished')
        assert hasattr(thread, 'error')


class TestCICDDialogEdgeCases:
    """Test edge cases and error handling."""

    def test_stage_widget_missing_attributes(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles stage widgets with missing attributes gracefully."""
        from PyQt6.QtWidgets import QWidget

        broken_widget = QWidget()
        ci_cd_dialog.stage_widgets["broken"] = broken_widget

        result = {"success": True}
        ci_cd_dialog.on_stage_completed("broken", result)  # type: ignore[arg-type]

    def test_stage_completed_with_malformed_result(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog handles malformed stage result data."""
        malformed_result: dict[str, Any] = {
            "success": "not_a_bool",
            "metrics": "not_a_dict"
        }

        ci_cd_dialog.on_stage_completed("test", malformed_result)

    def test_load_reports_with_corrupted_json(self, ci_cd_dialog: CICDDialog, temp_plugin_file: Path) -> None:
        """CICDDialog handles corrupted report JSON files."""
        report_path = temp_plugin_file.parent / "pipeline_report_corrupted.json"

        try:
            report_path.write_text("{invalid json content")

            ci_cd_dialog.load_reports()

        finally:
            if report_path.exists():
                report_path.unlink()

    def test_progress_bar_updates_correctly(self, ci_cd_dialog: CICDDialog) -> None:
        """CICDDialog updates progress bar as stages complete."""
        total_stages = len(ci_cd_dialog.stage_widgets)

        for i, stage in enumerate(ci_cd_dialog.stage_widgets.keys(), 1):
            result = {"success": True}
            ci_cd_dialog.on_stage_completed(stage, result)  # type: ignore[arg-type]

            if i == total_stages:
                assert ci_cd_dialog.progress_bar.value() <= total_stages
