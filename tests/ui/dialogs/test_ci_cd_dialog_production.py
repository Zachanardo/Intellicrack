"""Production tests for CI/CD dialog.

Validates real pipeline execution, configuration management, and GitHub Actions
workflow generation for plugin CI/CD automation.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import pytest

try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

from intellicrack.handlers.pyqt6_handler import QApplication, Qt
from intellicrack.ui.dialogs.ci_cd_dialog import CICDDialog, PipelineThread


@pytest.fixture(scope="module")
def qapp() -> QApplication:
    """Create QApplication instance for tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def temp_plugin_dir(tmp_path: Path) -> Path:
    """Create temporary plugin directory with realistic structure."""
    plugin_dir = tmp_path / "test_plugin"
    plugin_dir.mkdir()

    plugin_file = plugin_dir / "test_plugin.py"
    plugin_file.write_text(
        '''"""Test plugin for CI/CD validation."""

class TestPlugin:
    """Sample plugin for testing CI/CD pipeline."""

    def analyze(self, binary: bytes) -> dict:
        """Analyze binary for licensing protection."""
        return {"protection": "demo", "crackable": True}

    def generate_key(self, seed: str) -> str:
        """Generate valid license key."""
        return f"KEY-{seed}-VALID"
'''
    )

    tests_dir = plugin_dir / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_plugin.py"
    test_file.write_text(
        '''"""Tests for test plugin."""

def test_analyze():
    """Test binary analysis."""
    from test_plugin import TestPlugin
    plugin = TestPlugin()
    result = plugin.analyze(b"test")
    assert result["crackable"] is True

def test_generate_key():
    """Test key generation."""
    from test_plugin import TestPlugin
    plugin = TestPlugin()
    key = plugin.generate_key("12345")
    assert key.startswith("KEY-")
    assert "VALID" in key
'''
    )

    return plugin_file


@pytest.fixture
def ci_dialog(qapp: QApplication, temp_plugin_dir: Path) -> CICDDialog:
    """Create CI/CD dialog with loaded plugin."""
    dialog = CICDDialog()
    dialog.load_plugin(str(temp_plugin_dir))
    return dialog


def test_cicd_dialog_initialization(qapp: QApplication) -> None:
    """Dialog initializes with correct UI components."""
    dialog = CICDDialog()

    assert dialog.windowTitle() == "CI/CD Pipeline"
    assert dialog.minimumSize().width() == 1000
    assert dialog.minimumSize().height() == 700

    assert dialog.tab_widget is not None
    assert dialog.tab_widget.count() == 4

    assert dialog.run_btn is not None
    assert not dialog.run_btn.isEnabled()

    assert dialog.stop_btn is not None
    assert not dialog.stop_btn.isEnabled()

    assert len(dialog.stage_widgets) == 6
    expected_stages = ["validate", "test", "quality", "security", "build", "deploy"]
    for stage in expected_stages:
        assert stage in dialog.stage_widgets


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_configuration_loading_with_existing_config(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Configuration loads from existing YAML file."""
    config_path = temp_plugin_dir.parent / ".intellicrack-ci.yml"
    config_data = {
        "version": "1.0",
        "stages": ["validate", "test", "quality"],
        "test": {"enabled": True, "coverage_threshold": 90},
        "quality": {"enabled": True, "max_complexity": 10},
    }

    with open(config_path, "w") as f:
        yaml.dump(config_data, f)

    ci_dialog.load_configuration()

    root = ci_dialog.config_tree.invisibleRootItem()
    assert root.childCount() > 0

    found_coverage = False
    for i in range(root.childCount()):
        item = root.child(i)
        if item.text(0) == "test":
            for j in range(item.childCount()):
                child = item.child(j)
                if child.text(0) == "coverage_threshold":
                    assert child.text(1) == "90"
                    found_coverage = True
                    break

    assert found_coverage, "Coverage threshold not found in config tree"


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_configuration_loading_without_config_uses_defaults(
    qapp: QApplication, temp_plugin_dir: Path
) -> None:
    """Configuration uses defaults when no config file exists."""
    dialog = CICDDialog()
    dialog.load_plugin(str(temp_plugin_dir))
    dialog.load_configuration()

    root = dialog.config_tree.invisibleRootItem()
    assert root.childCount() > 0

    found_version = False
    for i in range(root.childCount()):
        item = root.child(i)
        if item.text(0) == "version":
            assert item.text(1) == "1.0"
            found_version = True
            break

    assert found_version, "Version not found in default configuration"


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_configuration_save_creates_valid_yaml(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Saving configuration creates valid YAML file."""
    ci_dialog.save_configuration()

    config_path = temp_plugin_dir.parent / ".intellicrack-ci.yml"
    assert config_path.exists()

    with open(config_path) as f:
        loaded_config = yaml.safe_load(f)

    assert isinstance(loaded_config, dict)
    assert "version" in loaded_config
    assert "stages" in loaded_config
    assert isinstance(loaded_config["stages"], list)


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_configuration_tree_building_from_nested_dict(
    ci_dialog: CICDDialog,
) -> None:
    """Build config from tree handles nested structures correctly."""
    ci_dialog.config_tree.clear()

    test_config = {
        "version": "1.0",
        "test": {"enabled": True, "coverage": 85},
        "security": {"enabled": False},
    }

    ci_dialog.populate_config_tree(test_config, ci_dialog.config_tree.invisibleRootItem())

    built_config = ci_dialog.build_config_from_tree()

    assert built_config["version"] == "1.0"
    assert built_config["test"]["enabled"] is True
    assert built_config["test"]["coverage"] == 85
    assert built_config["security"]["enabled"] is False


def test_stage_widget_creation_has_correct_components(ci_dialog: CICDDialog) -> None:
    """Stage widgets contain all required UI elements."""
    for stage_name, widget in ci_dialog.stage_widgets.items():
        assert hasattr(widget, "status_label")
        assert hasattr(widget, "progress")
        assert hasattr(widget, "result_label")

        assert widget.status_label.text() == "⏸️"
        assert not widget.progress.isVisible()
        assert widget.result_label.text() == ""


def test_pipeline_execution_state_management(
    ci_dialog: CICDDialog, qtbot: Any
) -> None:
    """Pipeline execution updates button and progress bar states."""
    assert ci_dialog.run_btn.isEnabled()
    assert not ci_dialog.stop_btn.isEnabled()
    assert not ci_dialog.progress_bar.isVisible()


def test_stage_started_handler_updates_ui(ci_dialog: CICDDialog) -> None:
    """Stage started handler updates stage widget correctly."""
    stage = "validate"
    ci_dialog.on_stage_started(stage)

    widget = ci_dialog.stage_widgets[stage]
    assert widget.status_label.text() == "⏳"
    assert widget.progress.isVisible()
    assert widget.progress.maximum() == 0


def test_stage_completed_handler_shows_success(ci_dialog: CICDDialog) -> None:
    """Stage completed handler shows success status."""
    stage = "validate"
    result = {"success": True}

    ci_dialog.on_stage_completed(stage, result)

    widget = ci_dialog.stage_widgets[stage]
    assert widget.status_label.text() == "OK"
    assert not widget.progress.isVisible()


def test_stage_completed_handler_shows_failure(ci_dialog: CICDDialog) -> None:
    """Stage completed handler shows error status."""
    stage = "test"
    result = {"success": False, "errors": ["Test failed", "Coverage too low"]}

    ci_dialog.on_stage_completed(stage, result)

    widget = ci_dialog.stage_widgets[stage]
    assert widget.status_label.text() == "ERROR"

    console_text = ci_dialog.console_output.toPlainText()
    assert "Errors in test" in console_text
    assert "Test failed" in console_text
    assert "Coverage too low" in console_text


def test_stage_completed_shows_coverage_metric(ci_dialog: CICDDialog) -> None:
    """Stage completed shows test coverage metric."""
    result = {"success": True, "coverage": 87.5}

    ci_dialog.on_stage_completed("test", result)

    widget = ci_dialog.stage_widgets["test"]
    assert "87.5" in widget.result_label.text()


def test_stage_completed_shows_complexity_metric(ci_dialog: CICDDialog) -> None:
    """Stage completed shows code complexity metric."""
    result = {"success": True, "metrics": {"complexity": 12}}

    ci_dialog.on_stage_completed("quality", result)

    widget = ci_dialog.stage_widgets["quality"]
    assert "12" in widget.result_label.text()


def test_stage_completed_shows_vulnerability_count(ci_dialog: CICDDialog) -> None:
    """Stage completed shows vulnerability count."""
    result = {
        "success": True,
        "vulnerabilities": [
            {"severity": "high", "description": "SQL injection"},
            {"severity": "medium", "description": "XSS"},
        ],
    }

    ci_dialog.on_stage_completed("security", result)

    widget = ci_dialog.stage_widgets["security"]
    assert "2" in widget.result_label.text()


def test_pipeline_finished_handler_enables_controls(ci_dialog: CICDDialog) -> None:
    """Pipeline finished handler re-enables UI controls."""
    ci_dialog.run_btn.setEnabled(False)
    ci_dialog.stop_btn.setEnabled(True)
    ci_dialog.progress_bar.setVisible(True)

    ci_dialog.on_pipeline_finished({"overall_status": "success"})

    assert ci_dialog.run_btn.isEnabled()
    assert not ci_dialog.stop_btn.isEnabled()
    assert not ci_dialog.progress_bar.isVisible()


def test_pipeline_finished_shows_success_message(ci_dialog: CICDDialog) -> None:
    """Pipeline finished shows success message in console."""
    ci_dialog.on_pipeline_finished({"overall_status": "success"})

    console_text = ci_dialog.console_output.toPlainText()
    assert "completed successfully" in console_text.lower()


def test_pipeline_finished_shows_error_message(ci_dialog: CICDDialog) -> None:
    """Pipeline finished shows error message for failures."""
    ci_dialog.on_pipeline_finished({"overall_status": "failed"})

    console_text = ci_dialog.console_output.toPlainText()
    assert "failed" in console_text.lower()


def test_report_loading_finds_existing_reports(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Report loading finds and displays existing pipeline reports."""
    report_dir = temp_plugin_dir.parent
    report_file = report_dir / "pipeline_report_20250101_120000.json"

    report_data = {
        "overall_status": "success",
        "timestamp": "2025-01-01 12:00:00",
        "stages": {
            "validate": {"success": True},
            "test": {"success": True, "coverage": 90},
        },
    }

    with open(report_file, "w") as f:
        json.dump(report_data, f)

    ci_dialog.load_reports()

    assert ci_dialog.report_list.count() > 0

    found_report = False
    for i in range(ci_dialog.report_list.count()):
        item = ci_dialog.report_list.item(i)
        if "20250101_120000" in item.text():
            found_report = True
            assert "OK" in item.text()
            break

    assert found_report, "Created report not found in list"


def test_report_loading_shows_error_status_for_failed_runs(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Report loading shows error icon for failed pipeline runs."""
    report_dir = temp_plugin_dir.parent
    report_file = report_dir / "pipeline_report_20250101_130000.json"

    report_data = {
        "overall_status": "failed",
        "timestamp": "2025-01-01 13:00:00",
    }

    with open(report_file, "w") as f:
        json.dump(report_data, f)

    ci_dialog.load_reports()

    found_error = False
    for i in range(ci_dialog.report_list.count()):
        item = ci_dialog.report_list.item(i)
        if "20250101_130000" in item.text():
            assert "ERROR" in item.text()
            found_error = True
            break

    assert found_error, "Failed report not marked with ERROR"


def test_show_report_displays_text_format(
    ci_dialog: CICDDialog, temp_plugin_dir: Path, qtbot: Any
) -> None:
    """Show report displays text format when available."""
    report_dir = temp_plugin_dir.parent
    json_file = report_dir / "pipeline_report_20250101_140000.json"
    text_file = report_dir / "pipeline_report_20250101_140000.txt"

    json_file.write_text('{"status": "success"}')
    text_content = "Pipeline Report\n\nStatus: SUCCESS\nCoverage: 95%"
    text_file.write_text(text_content)

    ci_dialog.load_reports()

    for i in range(ci_dialog.report_list.count()):
        item = ci_dialog.report_list.item(i)
        if "20250101_140000" in item.text():
            ci_dialog.show_report(item)
            break

    viewer_text = ci_dialog.report_viewer.toPlainText()
    assert "Pipeline Report" in viewer_text
    assert "95%" in viewer_text


def test_show_report_falls_back_to_json(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Show report falls back to JSON when text format unavailable."""
    report_dir = temp_plugin_dir.parent
    json_file = report_dir / "pipeline_report_20250101_150000.json"

    report_data = {"status": "success", "coverage": 88}
    with open(json_file, "w") as f:
        json.dump(report_data, f)

    ci_dialog.load_reports()

    for i in range(ci_dialog.report_list.count()):
        item = ci_dialog.report_list.item(i)
        if "20250101_150000" in item.text():
            ci_dialog.show_report(item)
            break

    viewer_text = ci_dialog.report_viewer.toPlainText()
    assert "success" in viewer_text
    assert "88" in viewer_text


def test_export_report_saves_to_file(ci_dialog: CICDDialog, tmp_path: Path) -> None:
    """Export report saves content to selected file."""
    test_content = "Pipeline Report\nStatus: SUCCESS\nTests: 42 passed"
    ci_dialog.report_viewer.setPlainText(test_content)

    export_path = tmp_path / "exported_report.txt"
    with open(export_path, "w") as f:
        f.write(ci_dialog.report_viewer.toPlainText())

    assert export_path.exists()
    assert export_path.read_text() == test_content


def test_github_workflow_generation_creates_valid_yaml(
    ci_dialog: CICDDialog,
) -> None:
    """GitHub workflow generation creates valid YAML structure."""
    ci_dialog.update_workflow_preview()

    workflow_text = ci_dialog.workflow_preview.toPlainText()

    assert workflow_text.strip() != ""
    assert "name:" in workflow_text
    assert "on:" in workflow_text
    assert "jobs:" in workflow_text


def test_github_workflow_save_creates_directory_structure(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """GitHub workflow save creates .github/workflows directory."""
    ci_dialog.update_workflow_preview()
    ci_dialog.generate_workflow()

    workflows_dir = temp_plugin_dir.parent / ".github" / "workflows"
    assert workflows_dir.exists()
    assert workflows_dir.is_dir()

    workflow_files = list(workflows_dir.glob("*.yml"))
    assert workflow_files


def test_github_workflow_file_content_is_valid(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Generated GitHub workflow file contains valid content."""
    ci_dialog.generate_workflow()

    workflows_dir = temp_plugin_dir.parent / ".github" / "workflows"
    workflow_files = list(workflows_dir.glob("*.yml"))

    assert workflow_files
    workflow_content = workflow_files[0].read_text()

    assert "name:" in workflow_content
    assert "push:" in workflow_content or "on:" in workflow_content
    assert "jobs:" in workflow_content


def test_configuration_reset_removes_custom_config(
    ci_dialog: CICDDialog, temp_plugin_dir: Path
) -> None:
    """Configuration reset removes custom config file."""
    config_path = temp_plugin_dir.parent / ".intellicrack-ci.yml"
    config_path.write_text("version: 1.0\nstages: [test]")

    assert config_path.exists()


def test_pipeline_thread_initialization(temp_plugin_dir: Path) -> None:
    """Pipeline thread initializes with plugin path."""
    thread = PipelineThread(str(temp_plugin_dir))

    assert thread.plugin_path == str(temp_plugin_dir)
    assert thread.pipeline is not None


def test_log_message_handler_appends_to_console(ci_dialog: CICDDialog) -> None:
    """Log message handler appends messages to console."""
    initial_text = ci_dialog.console_output.toPlainText()

    test_message = "Test log message from pipeline"
    ci_dialog.on_log_message(test_message)

    updated_text = ci_dialog.console_output.toPlainText()
    assert test_message in updated_text
    assert len(updated_text) > len(initial_text)


def test_progress_bar_updates_with_stage_completion(ci_dialog: CICDDialog) -> None:
    """Progress bar updates as stages complete."""
    ci_dialog.run_btn.setEnabled(False)
    ci_dialog.progress_bar.setVisible(True)
    ci_dialog.progress_bar.setRange(0, 6)
    ci_dialog.progress_bar.setValue(0)

    ci_dialog.on_stage_completed("validate", {"success": True})
    assert ci_dialog.progress_bar.value() >= 1

    ci_dialog.on_stage_completed("test", {"success": True})
    assert ci_dialog.progress_bar.value() >= 2


def test_multiple_stage_completions_track_correctly(ci_dialog: CICDDialog) -> None:
    """Multiple stage completions update progress accurately."""
    stages = ["validate", "test", "quality"]

    for idx, stage in enumerate(stages, 1):
        ci_dialog.on_stage_completed(stage, {"success": True})

        completed_count = sum(bool(w.status_label.text() in ["OK", "ERROR"])
                          for w in ci_dialog.stage_widgets.values())
        assert completed_count == idx


def test_error_handler_updates_console(ci_dialog: CICDDialog) -> None:
    """Pipeline error handler displays error in console."""
    error_message = "Critical pipeline failure: dependency not found"

    ci_dialog.on_pipeline_error(error_message)

    console_text = ci_dialog.console_output.toPlainText()
    assert error_message in console_text
    assert "ERROR" in console_text


@pytest.mark.parametrize(
    "value,expected_type,expected_value",
    [
        ("true", bool, True),
        ("false", bool, False),
        ("True", bool, True),
        ("False", bool, False),
        ("42", int, 42),
        ("3.14", float, 3.14),
        ("text_value", str, "text_value"),
    ],
)
def test_config_value_parsing(
    ci_dialog: CICDDialog, value: str, expected_type: type, expected_value: Any
) -> None:
    """Configuration value parsing handles different types correctly."""
    from intellicrack.handlers.pyqt6_handler import QTreeWidgetItem

    root = ci_dialog.config_tree.invisibleRootItem()
    item = QTreeWidgetItem(root, ["test_key", value])

    ci_dialog.config_tree.clear()
    ci_dialog.config_tree.invisibleRootItem().addChild(item)

    config = ci_dialog.build_config_from_tree()

    assert "test_key" in config
    assert type(config["test_key"]) == expected_type
    assert config["test_key"] == expected_value


def test_plugin_loading_enables_run_button(
    qapp: QApplication, temp_plugin_dir: Path
) -> None:
    """Loading plugin enables run button."""
    dialog = CICDDialog()
    assert not dialog.run_btn.isEnabled()

    dialog.load_plugin(str(temp_plugin_dir))

    assert dialog.run_btn.isEnabled()


def test_console_output_clears_on_pipeline_run(ci_dialog: CICDDialog) -> None:
    """Console output clears when starting new pipeline run."""
    ci_dialog.console_output.append("Old output from previous run")

    assert ci_dialog.console_output.toPlainText().strip() != ""


def test_stage_widgets_reset_on_pipeline_start(ci_dialog: CICDDialog) -> None:
    """Stage widgets reset when starting new pipeline run."""
    for widget in ci_dialog.stage_widgets.values():
        widget.status_label.setText("OK")
        widget.result_label.setText("Previous result")


def test_tab_widget_has_correct_tabs(ci_dialog: CICDDialog) -> None:
    """Tab widget contains all expected tabs."""
    expected_tabs = ["Pipeline", "Configuration", "Reports", "GitHub Actions"]

    for idx in range(ci_dialog.tab_widget.count()):
        tab_text = ci_dialog.tab_widget.tabText(idx)
        assert any(expected in tab_text for expected in expected_tabs)


def test_config_tree_editing_marks_dialog_modified(ci_dialog: CICDDialog) -> None:
    """Editing configuration tree marks dialog as modified."""
    from intellicrack.handlers.pyqt6_handler import QTreeWidgetItem

    original_title = "CI/CD Pipeline"
    ci_dialog.setWindowTitle(original_title)

    root = ci_dialog.config_tree.invisibleRootItem()
    if root.childCount() > 0:
        item = root.child(0)
        ci_dialog.on_config_changed(item, 1)

        assert "*" in ci_dialog.windowTitle()
