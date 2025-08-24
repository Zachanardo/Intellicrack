"""CI/CD configuration dialog for plugin development workflows.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import json
import os
from datetime import datetime
from typing import Any

from intellicrack.handlers.pyqt6_handler import (
    QCheckBox,
    QFileDialog,
    QFont,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QProgressBar,
    QPushButton,
    Qt,
    QTabWidget,
    QTextEdit,
    QThread,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.logger import logger

from ...tools.plugin_ci_cd import CICDPipeline, GitHubActionsGenerator
from ..icon_manager import set_button_icon
from .plugin_dialog_base import PluginDialogBase

"""
CI/CD Pipeline Dialog for Intellicrack plugins.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""


try:
    import yaml
except ImportError:
    yaml = None


class PipelineThread(QThread):
    """Thread for running CI/CD pipeline."""

    stage_started = pyqtSignal(str)
    stage_completed = pyqtSignal(str, dict)
    log_message = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, plugin_path: str):
        """Initialize the PipelineThread with default values."""
        super().__init__()
        self.plugin_path = plugin_path
        self.pipeline = CICDPipeline(plugin_path)

    def run(self):
        """Run the pipeline."""
        try:
            # Override pipeline methods to emit signals
            def run_stage_wrapper(stage_name, original_method):
                def wrapper():
                    self.stage_started.emit(stage_name)
                    result = original_method()
                    self.stage_completed.emit(stage_name, result)
                    return result

                return wrapper

            # Wrap each stage method
            for stage in self.pipeline.pipeline_config["stages"]:
                method_name = f"run_{stage}_stage"
                if hasattr(self.pipeline, method_name):
                    original_method = getattr(self.pipeline, method_name)
                    wrapped_method = run_stage_wrapper(stage, original_method)
                    setattr(self.pipeline, method_name, wrapped_method)

            # Run pipeline
            results = self.pipeline.run_pipeline()
            self.finished.emit(results)

        except Exception as e:
            logger.error("Exception in ci_cd_dialog: %s", e)
            self.error.emit(str(e))


class CICDDialog(PluginDialogBase):
    """CI/CD Pipeline Management Dialog."""

    def __init__(self, parent=None, plugin_path=None):
        """Initialize the CICDDialog with default values."""
        self.pipeline_thread = None
        self.stage_widgets = {}
        super().__init__(parent, plugin_path)

    def init_dialog(self):
        """Initialize the CI/CD dialog."""
        self.setWindowTitle("CI/CD Pipeline")
        self.setMinimumSize(1000, 700)
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI."""
        layout = QVBoxLayout(self)

        # Plugin selection (using base class method)
        plugin_layout = self.create_plugin_selection_layout()
        layout.addLayout(plugin_layout)

        # Main content
        self.tab_widget = QTabWidget()

        # Pipeline tab
        self.pipeline_widget = self.create_pipeline_tab()
        self.tab_widget.addTab(self.pipeline_widget, "🚀 Pipeline")

        # Configuration tab
        self.config_widget = self.create_config_tab()
        self.tab_widget.addTab(self.config_widget, "⚙️ Configuration")

        # Reports tab
        self.reports_widget = self.create_reports_tab()
        self.tab_widget.addTab(self.reports_widget, "📊 Reports")

        # GitHub Actions tab
        self.github_widget = self.create_github_tab()
        self.tab_widget.addTab(self.github_widget, "🐙 GitHub Actions")

        layout.addWidget(self.tab_widget)

        # Bottom controls
        control_layout = QHBoxLayout()

        self.run_btn = QPushButton("Run Pipeline")
        self.run_btn.clicked.connect(self.run_pipeline)
        set_button_icon(self.run_btn, "action_run")
        self.run_btn.setEnabled(False)
        control_layout.addWidget(self.run_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.clicked.connect(self.stop_pipeline)
        set_button_icon(self.stop_btn, "action_stop")
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)

        control_layout.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        control_layout.addWidget(self.progress_bar)

        layout.addLayout(control_layout)

    def create_pipeline_tab(self) -> QWidget:
        """Create pipeline visualization tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Pipeline stages
        stages_group = QGroupBox("Pipeline Stages")
        stages_layout = QVBoxLayout(stages_group)

        # Create stage widgets
        stages = ["validate", "test", "quality", "security", "build", "deploy"]
        for stage in stages:
            stage_widget = self.create_stage_widget(stage)
            self.stage_widgets[stage] = stage_widget
            stages_layout.addWidget(stage_widget)

        layout.addWidget(stages_group)

        # Output console
        console_group = QGroupBox("Pipeline Output")
        console_layout = QVBoxLayout(console_group)

        self.console_output = QTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setFont(QFont("Consolas", 9))
        console_layout.addWidget(self.console_output)

        layout.addWidget(console_group)

        return widget

    def create_stage_widget(self, stage: str) -> QWidget:
        """Create widget for a pipeline stage."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)

        # Status indicator
        status_label = QLabel("⏸️")
        status_label.setFixedWidth(30)
        layout.addWidget(status_label)

        # Stage name
        name_label = QLabel(stage.capitalize())
        name_label.setObjectName("stageName")
        layout.addWidget(name_label)

        # Progress
        progress = QProgressBar()
        progress.setFixedHeight(20)
        progress.setVisible(False)
        layout.addWidget(progress)

        # Result label
        result_label = QLabel("")
        result_label.setAlignment(Qt.AlignRight)
        layout.addWidget(result_label)

        # Store references
        widget.status_label = status_label
        widget.progress = progress
        widget.result_label = result_label

        # Style
        widget.setObjectName("pipelineStageIdle")

        return widget

    def create_config_tab(self) -> QWidget:
        """Create configuration tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Configuration tree
        self.config_tree = QTreeWidget()
        self.config_tree.setHeaderLabels(["Setting", "Value"])
        self.config_tree.itemChanged.connect(self.on_config_changed)

        layout.addWidget(self.config_tree)

        # Buttons
        btn_layout = QHBoxLayout()

        save_config_btn = QPushButton("Save Configuration")
        save_config_btn.clicked.connect(self.save_configuration)
        set_button_icon(save_config_btn, "file_save")
        btn_layout.addWidget(save_config_btn)

        reset_btn = QPushButton("Reset to Defaults")
        reset_btn.clicked.connect(self.reset_configuration)
        set_button_icon(reset_btn, "nav_refresh")
        btn_layout.addWidget(reset_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        return widget

    def create_reports_tab(self) -> QWidget:
        """Create reports tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Report list
        list_group = QGroupBox("Pipeline Reports")
        list_layout = QVBoxLayout(list_group)

        self.report_list = QListWidget()
        self.report_list.itemClicked.connect(self.show_report)
        list_layout.addWidget(self.report_list)

        layout.addWidget(list_group)

        # Report viewer
        viewer_group = QGroupBox("Report Details")
        viewer_layout = QVBoxLayout(viewer_group)

        self.report_viewer = QTextEdit()
        self.report_viewer.setReadOnly(True)
        viewer_layout.addWidget(self.report_viewer)

        # Export button
        export_btn = QPushButton("Export Report")
        export_btn.clicked.connect(self.export_report)
        set_button_icon(export_btn, "file_export")
        viewer_layout.addWidget(export_btn)

        layout.addWidget(viewer_group)

        return widget

    def create_github_tab(self) -> QWidget:
        """Create GitHub Actions tab."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Info
        info_label = QLabel(
            "Generate GitHub Actions workflow for continuous integration. "
            "This will create a .github/workflows file for your plugin.",
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Options
        options_group = QGroupBox("Workflow Options")
        options_layout = QVBoxLayout(options_group)

        # Python versions
        py_layout = QHBoxLayout()
        py_layout.addWidget(QLabel("Python Versions:"))
        self.py_versions_edit = QLineEdit("3.8, 3.9, 3.10")
        py_layout.addWidget(self.py_versions_edit)
        options_layout.addLayout(py_layout)

        # Branches
        branch_layout = QHBoxLayout()
        branch_layout.addWidget(QLabel("Trigger Branches:"))
        self.branches_edit = QLineEdit("main, develop")
        branch_layout.addWidget(self.branches_edit)
        options_layout.addLayout(branch_layout)

        # Options checkboxes
        self.upload_artifacts_cb = QCheckBox("Upload build artifacts")
        self.upload_artifacts_cb.setChecked(True)
        options_layout.addWidget(self.upload_artifacts_cb)

        self.coverage_report_cb = QCheckBox("Generate coverage reports")
        self.coverage_report_cb.setChecked(True)
        options_layout.addWidget(self.coverage_report_cb)

        layout.addWidget(options_group)

        # Workflow preview
        preview_group = QGroupBox("Workflow Preview")
        preview_layout = QVBoxLayout(preview_group)

        self.workflow_preview = QTextEdit()
        self.workflow_preview.setFont(QFont("Consolas", 9))
        preview_layout.addWidget(self.workflow_preview)

        layout.addWidget(preview_group)

        # Generate button
        generate_btn = QPushButton("Generate Workflow")
        generate_btn.clicked.connect(self.generate_workflow)
        set_button_icon(generate_btn, "action_generate")
        layout.addWidget(generate_btn)

        return widget

    def load_plugin(self, path: str):
        """Load a plugin for CI/CD."""
        # Call the base class method first
        if not super().load_plugin(path):
            return False

        # Add CI/CD-specific functionality
        self.run_btn.setEnabled(True)

        # Load configuration
        self.load_configuration()

        # Load reports
        self.load_reports()

        # Generate workflow preview
        self.update_workflow_preview()

        return True

    def load_configuration(self):
        """Load pipeline configuration."""
        if not self.plugin_path:
            return

        config_path = os.path.join(
            os.path.dirname(self.plugin_path),
            ".intellicrack-ci.yml",
        )

        if os.path.exists(config_path):
            with open(config_path) as f:
                config = yaml.safe_load(f)
        else:
            # Default config
            config = {
                "version": "1.0",
                "stages": ["validate", "test", "quality", "security", "build", "deploy"],
                "validate": {"enabled": True},
                "test": {"enabled": True, "coverage_threshold": 80},
                "quality": {"enabled": True},
                "security": {"enabled": True},
                "build": {"enabled": True},
                "deploy": {"enabled": True},
            }

        # Populate tree
        self.config_tree.clear()
        self.populate_config_tree(config, self.config_tree.invisibleRootItem())

    def populate_config_tree(self, config: dict[str, Any], parent: QTreeWidgetItem):
        """Populate configuration tree."""
        for key, value in config.items():
            if isinstance(value, dict):
                # Create parent node
                item = QTreeWidgetItem(parent, [key, ""])
                item.setExpanded(True)
                # Recurse
                self.populate_config_tree(value, item)
            else:
                # Create leaf node
                item = QTreeWidgetItem(parent, [key, str(value)])
                item.setFlags(item.flags() | Qt.ItemIsEditable)

    def on_config_changed(self, item: QTreeWidgetItem, column: int):
        """Handle configuration change."""
        _ = item
        if column == 1:  # Value column
            # Mark as modified
            self.setWindowTitle("CI/CD Pipeline *")

    def save_configuration(self):
        """Save pipeline configuration."""
        if not self.plugin_path:
            return

        # Build config from tree
        config = self.build_config_from_tree()

        # Save to file
        config_path = os.path.join(
            os.path.dirname(self.plugin_path),
            ".intellicrack-ci.yml",
        )

        with open(config_path, "w") as f:
            yaml.dump(config, f, default_flow_style=False)

        QMessageBox.information(self, "Saved", "Configuration saved successfully!")
        self.setWindowTitle("CI/CD Pipeline")

    def build_config_from_tree(self) -> dict[str, Any]:
        """Build configuration from tree widget."""
        config = {}

        def process_item(item: QTreeWidgetItem) -> Any:
            if item.childCount() > 0:
                # Branch node
                result = {}
                for i in range(item.childCount()):
                    child = item.child(i)
                    result[child.text(0)] = process_item(child)
                return result
            # Leaf node
            value = item.text(1)
            # Try to parse value
            if value.lower() in ["true", "false"]:
                return value.lower() == "true"
            try:
                return int(value)
            except ValueError as e:
                self.logger.error("Value error in ci_cd_dialog: %s", e)
                try:
                    return float(value)
                except ValueError as e:
                    logger.error("Value error in ci_cd_dialog: %s", e)
                    return value

        # Process root items
        root = self.config_tree.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            config[item.text(0)] = process_item(item)

        return config

    def reset_configuration(self):
        """Reset configuration to defaults."""
        reply = QMessageBox.question(
            self,
            "Reset Configuration",
            "Are you sure you want to reset to default configuration?",
            QMessageBox.Yes | QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            # Remove config file
            if self.plugin_path:
                config_path = os.path.join(
                    os.path.dirname(self.plugin_path),
                    ".intellicrack-ci.yml",
                )
                if os.path.exists(config_path):
                    os.remove(config_path)

            # Reload
            self.load_configuration()

    def load_reports(self):
        """Load existing pipeline reports."""
        if not self.plugin_path:
            return

        self.report_list.clear()
        report_dir = os.path.dirname(self.plugin_path)

        # Find report files
        for file in os.listdir(report_dir):
            if file.startswith("pipeline_report_") and file.endswith(".json"):
                timestamp = file.replace("pipeline_report_", "").replace(".json", "")

                # Load report to get status
                with open(os.path.join(report_dir, file)) as f:
                    report = json.load(f)

                status = report.get("overall_status", "unknown")
                icon = "✅" if status == "success" else "❌"

                item = QListWidgetItem(f"{icon} {timestamp}")
                item.setData(Qt.UserRole, os.path.join(report_dir, file))
                self.report_list.addItem(item)

    def show_report(self, item: QListWidgetItem):
        """Show selected report."""
        report_path = item.data(Qt.UserRole)

        # Also check for text report
        text_path = report_path.replace(".json", ".txt")

        if os.path.exists(text_path):
            with open(text_path) as f:
                self.report_viewer.setPlainText(f.read())
        else:
            with open(report_path) as f:
                report = json.load(f)
                self.report_viewer.setPlainText(json.dumps(report, indent=2))

    def export_report(self):
        """Export current report."""
        content = self.report_viewer.toPlainText()
        if not content:
            QMessageBox.warning(self, "No Report", "No report to export.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Report",
            f"pipeline_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;JSON Files (*.json);;All Files (*.*)",
        )

        if file_path:
            with open(file_path, "w") as f:
                f.write(content)

            QMessageBox.information(self, "Exported", f"Report exported to:\n{file_path}")

    def update_workflow_preview(self):
        """Update GitHub Actions workflow preview."""
        if not self.plugin_path:
            return

        plugin_name = os.path.basename(self.plugin_path).replace(".py", "").replace(".js", "")

        # Generate workflow
        workflow = GitHubActionsGenerator.generate_workflow(plugin_name)
        self.workflow_preview.setPlainText(workflow)

    def generate_workflow(self):
        """Generate and save GitHub Actions workflow."""
        if not self.plugin_path:
            QMessageBox.warning(self, "No Plugin", "Please select a plugin first.")
            return

        # Get workflow content
        workflow = self.workflow_preview.toPlainText()

        # Ask where to save
        plugin_dir = os.path.dirname(self.plugin_path)
        workflows_dir = os.path.join(plugin_dir, ".github", "workflows")

        # Create directory
        os.makedirs(workflows_dir, exist_ok=True)

        # Save workflow
        plugin_name = os.path.basename(self.plugin_path).replace(".py", "").replace(".js", "")
        workflow_path = os.path.join(workflows_dir, f"{plugin_name}-ci.yml")

        with open(workflow_path, "w") as f:
            f.write(workflow)

        QMessageBox.information(
            self,
            "Generated",
            f"GitHub Actions workflow saved to:\n{workflow_path}\n\n"
            "Commit this file to your repository to enable CI/CD.",
        )

    def run_pipeline(self):
        """Run the CI/CD pipeline."""
        if not self.plugin_path:
            return

        # Clear console
        self.console_output.clear()
        self.console_output.append(
            f"🚀 Starting CI/CD pipeline for {os.path.basename(self.plugin_path)}\n"
        )

        # Reset stage widgets
        for stage_widget in self.stage_widgets.values():
            stage_widget.status_label.setText("⏸️")
            stage_widget.progress.setVisible(False)
            stage_widget.result_label.setText("")
            stage_widget.setObjectName("pipelineStageIdle")

        # Update UI
        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, len(self.stage_widgets))
        self.progress_bar.setValue(0)

        # Start pipeline thread
        self.pipeline_thread = PipelineThread(self.plugin_path)
        self.pipeline_thread.stage_started.connect(self.on_stage_started)
        self.pipeline_thread.stage_completed.connect(self.on_stage_completed)
        self.pipeline_thread.log_message.connect(self.on_log_message)
        self.pipeline_thread.finished.connect(self.on_pipeline_finished)
        self.pipeline_thread.error.connect(self.on_pipeline_error)

        self.pipeline_thread.start()

    def stop_pipeline(self):
        """Stop running pipeline."""
        if self.pipeline_thread and self.pipeline_thread.isRunning():
            self.pipeline_thread.terminate()
            self.console_output.append("\n⏹️ Pipeline stopped by user")
            self.on_pipeline_finished({"overall_status": "cancelled"})

    def on_stage_started(self, stage: str):
        """Handle stage started."""
        self.console_output.append(f"\n📦 Running stage: {stage}")

        if stage in self.stage_widgets:
            widget = self.stage_widgets[stage]
            widget.status_label.setText("⏳")
            widget.progress.setVisible(True)
            widget.progress.setRange(0, 0)  # Indeterminate
            widget.setObjectName("pipelineStageRunning")

    def on_stage_completed(self, stage: str, result: dict[str, Any]):
        """Handle stage completed."""
        success = result.get("success", False)

        if stage in self.stage_widgets:
            widget = self.stage_widgets[stage]
            widget.status_label.setText("✅" if success else "❌")
            widget.progress.setVisible(False)

            # Update result label
            if stage == "test" and "coverage" in result:
                widget.result_label.setText(f"Coverage: {result['coverage']}%")
            elif stage == "quality" and "metrics" in result:
                complexity = result["metrics"].get("complexity", 0)
                widget.result_label.setText(f"Complexity: {complexity}")
            elif stage == "security" and "vulnerabilities" in result:
                vuln_count = len(result.get("vulnerabilities", []))
                widget.result_label.setText(f"Issues: {vuln_count}")

            # Update style
            if success:
                widget.setObjectName("pipelineStageSuccess")
            else:
                widget.setObjectName("pipelineStageError")

        # Update progress
        completed = sum(
            1 for w in self.stage_widgets.values() if w.status_label.text() in ["✅", "❌"]
        )
        self.progress_bar.setValue(completed)

        # Log errors
        if not success and result.get("errors"):
            self.console_output.append(f"  ❌ Errors in {stage}:")
            for error in result["errors"]:
                self.console_output.append(f"    - {error}")

    def on_log_message(self, message: str):
        """Handle log message."""
        self.console_output.append(message)

    def on_pipeline_finished(self, results: dict[str, Any]):
        """Handle pipeline finished."""
        # Update UI
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        # Show summary
        status = results.get("overall_status", "unknown")
        if status == "success":
            self.console_output.append("\n✅ Pipeline completed successfully!")
        else:
            self.console_output.append(f"\n❌ Pipeline failed with status: {status}")

        # Reload reports
        self.load_reports()

        # Switch to reports tab
        self.tab_widget.setCurrentWidget(self.reports_widget)

    def on_pipeline_error(self, error: str):
        """Handle pipeline error."""
        self.console_output.append(f"\n❌ Pipeline error: {error}")
        self.on_pipeline_finished({"overall_status": "error"})
