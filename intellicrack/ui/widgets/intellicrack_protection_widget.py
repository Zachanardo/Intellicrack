"""Intellicrack Protection Detection Widget

This widget displays protection detection results from Intellicrack's protection engine
including packers, protectors, compilers, and licensing schemes.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import os

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...ai.ai_assistant_enhanced import IntellicrackAIAssistant
from ...ai.ai_file_tools import get_ai_file_tools
from ...ai.ai_tools import AIAssistant
from ...protection.intellicrack_protection_core import (
    IntellicrackProtectionCore,
    ProtectionAnalysis,
)
from ...utils.logger import get_logger

logger = get_logger(__name__)


class ProtectionAnalysisThread(QThread):
    """Thread for running protection analysis without blocking UI"""

    analysis_complete = pyqtSignal(object)  # ProtectionAnalysis
    analysis_error = pyqtSignal(str)
    analysis_progress = pyqtSignal(str)

    def __init__(self, file_path: str):
        """Initialize protection analysis thread with file path and detection components."""
        super().__init__()
        self.file_path = file_path
        self.detector = IntellicrackProtectionCore()
        self.ai_file_tools = get_ai_file_tools()

    def run(self):
        """Analyze binary file for protections in a background thread.

        Performs protection detection analysis on the specified file,
        emitting progress signals during the process. If license-based
        protections are detected, automatically searches for associated
        license files in the directory.

        Emits:
            analysis_progress: Progress messages during analysis
            analysis_complete: Final ProtectionAnalysis results
            analysis_error: Error message if analysis fails
        """
        try:
            self.analysis_progress.emit(f"Analyzing {os.path.basename(self.file_path)}...")
            analysis = self.detector.detect_protections(self.file_path)

            # Check if license protection was detected
            has_license_protection = False
            if hasattr(analysis, "detections"):
                for detection in analysis.detections:
                    if detection.type.value in ["license", "dongle", "drm"]:
                        has_license_protection = True
                        break

            # Search for license files if relevant
            if has_license_protection:
                self.analysis_progress.emit("Searching for license files...")
                try:
                    binary_dir = os.path.dirname(os.path.abspath(self.file_path))
                    license_file_results = self.ai_file_tools.search_for_license_files(binary_dir)

                    if license_file_results.get("status") == "success":
                        # Add license files to analysis object
                        if not hasattr(analysis, "license_files"):
                            analysis.license_files = []
                        analysis.license_files = license_file_results.get("files_found", [])

                        # Also add summary info
                        analysis.license_file_summary = {
                            "total_found": len(license_file_results.get("files_found", [])),
                            "search_directory": binary_dir,
                            "patterns_matched": license_file_results.get("patterns_matched", []),
                        }
                except Exception as e:
                    logger.warning(f"License file search failed: {e}")

            self.analysis_complete.emit(analysis)
        except Exception as e:
            logger.error("Exception in intellicrack_protection_widget: %s", e)
            self.analysis_error.emit(str(e))


class IntellicrackProtectionWidget(QWidget):
    """Main widget for displaying Intellicrack protection detection results
    """

    # Signals
    protection_detected = pyqtSignal(str, list)  # protection_name, bypass_recommendations
    analysis_requested = pyqtSignal(str)  # file_path

    def __init__(self, parent=None):
        """Initialize protection widget with parent widget, AI assistant components, and UI setup."""
        super().__init__(parent)
        self.current_analysis: ProtectionAnalysis | None = None
        self.analysis_thread: ProtectionAnalysisThread | None = None
        self.ai_assistant = IntellicrackAIAssistant()
        self.ai_tools = AIAssistant()
        self.init_ui()

    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()

        # Header
        header_layout = QHBoxLayout()

        title_label = QLabel("Protection Detection (DIE)")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)

        header_layout.addStretch()

        # Analyze button
        self.analyze_btn = QPushButton("Analyze Binary")
        self.analyze_btn.clicked.connect(self.on_analyze_clicked)
        header_layout.addWidget(self.analyze_btn)

        # Search license files button
        self.search_license_btn = QPushButton("Search License Files")
        self.search_license_btn.clicked.connect(self.search_license_files)
        self.search_license_btn.setEnabled(False)
        header_layout.addWidget(self.search_license_btn)

        # Export button
        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.on_export_clicked)
        self.export_btn.setEnabled(False)
        header_layout.addWidget(self.export_btn)

        # AI Reasoning button
        self.ai_reasoning_btn = QPushButton("AI Reasoning")
        self.ai_reasoning_btn.clicked.connect(self.on_ai_reasoning_clicked)
        self.ai_reasoning_btn.setEnabled(False)
        header_layout.addWidget(self.ai_reasoning_btn)

        # Ask AI button
        self.ask_ai_btn = QPushButton("Ask AI")
        self.ask_ai_btn.clicked.connect(self.on_ask_ai_clicked)
        self.ask_ai_btn.setToolTip("Ask AI questions about the detected protections")
        header_layout.addWidget(self.ask_ai_btn)

        layout.addLayout(header_layout)

        # Main content area with splitter
        splitter = QSplitter(Qt.Horizontal)

        # Left side - Detection results tree
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)

        left_label = QLabel("Detections")
        left_label.setFont(QFont("Arial", 10, QFont.Bold))
        left_layout.addWidget(left_label)

        self.detection_tree = QTreeWidget()
        self.detection_tree.setHeaderLabels(["Detection", "Type", "Version"])
        self.detection_tree.itemSelectionChanged.connect(self.on_detection_selected)
        left_layout.addWidget(self.detection_tree)

        left_widget.setLayout(left_layout)
        splitter.addWidget(left_widget)

        # Right side - Details tabs
        self.details_tabs = QTabWidget()

        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.summary_text, "Summary")

        # Bypass recommendations tab
        self.bypass_text = QTextEdit()
        self.bypass_text.setReadOnly(True)
        self.bypass_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.bypass_text, "Bypass Recommendations")

        # Technical details tab
        self.tech_details_text = QTextEdit()
        self.tech_details_text.setReadOnly(True)
        self.tech_details_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.tech_details_text, "Technical Details")

        # Raw output tab
        self.raw_output_text = QTextEdit()
        self.raw_output_text.setReadOnly(True)
        self.raw_output_text.setFont(QFont("Consolas", 8))
        self.details_tabs.addTab(self.raw_output_text, "Raw Output")

        # AI Reasoning tab
        self.ai_reasoning_text = QTextEdit()
        self.ai_reasoning_text.setReadOnly(True)
        self.ai_reasoning_text.setFont(QFont("Consolas", 9))
        self.details_tabs.addTab(self.ai_reasoning_text, "AI Reasoning")

        splitter.addWidget(self.details_tabs)

        # Set splitter sizes
        splitter.setSizes([300, 500])

        layout.addWidget(splitter)

        # Status bar
        self.status_label = QLabel("Ready to analyze")
        self.status_label.setStyleSheet("QLabel { color: #666; }")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def on_analyze_clicked(self):
        """Handle analyze button click"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary to Analyze",
            "",
            "Executable Files (*.exe *.dll *.sys *.ocx);;All Files (*.*)",
        )

        if file_path:
            self.analyze_file(file_path)

    def analyze_file(self, file_path: str):
        """Analyze a file with DIE"""
        if not os.path.exists(file_path):
            QMessageBox.warning(self, "Error", f"File not found: {file_path}")
            return

        # Disable UI during analysis
        self.analyze_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.status_label.setText(f"Analyzing {os.path.basename(file_path)}...")

        # Clear previous results
        self.clear_results()

        # Start analysis thread
        self.analysis_thread = ProtectionAnalysisThread(file_path)
        self.analysis_thread.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_thread.analysis_error.connect(self.on_analysis_error)
        self.analysis_thread.analysis_progress.connect(self.on_analysis_progress)
        self.analysis_thread.start()

    def on_analysis_complete(self, analysis: ProtectionAnalysis):
        """Handle completed analysis"""
        self.current_analysis = analysis
        self.display_results(analysis)

        # Re-enable UI
        self.analyze_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.ai_reasoning_btn.setEnabled(True)
        self.search_license_btn.setEnabled(True)
        self.status_label.setText("Analysis complete")

        # Emit signal if protections detected
        if analysis.detections:
            for detection in analysis.detections:
                self.protection_detected.emit(
                    detection.name,
                    detection.bypass_recommendations,
                )

    def on_analysis_error(self, error_msg: str):
        """Handle analysis error"""
        QMessageBox.critical(self, "Analysis Error", f"Error during analysis:\n{error_msg}")
        self.analyze_btn.setEnabled(True)
        self.status_label.setText("Analysis failed")

    def on_analysis_progress(self, message: str):
        """Update progress status"""
        self.status_label.setText(message)

    def display_results(self, analysis: ProtectionAnalysis):
        """Display analysis results in the UI"""
        # Populate detection tree
        self.detection_tree.clear()

        # Group detections by type
        detections_by_type = {}
        for detection in analysis.detections:
            det_type = detection.type.value
            if det_type not in detections_by_type:
                detections_by_type[det_type] = []
            detections_by_type[det_type].append(detection)

        # Add to tree
        for det_type, detections in detections_by_type.items():
            # Create type node
            type_item = QTreeWidgetItem(self.detection_tree)
            type_item.setText(0, det_type.upper())
            type_item.setFont(0, QFont("Arial", 9, QFont.Bold))

            # Color code by type
            if det_type == "protector":
                type_item.setForeground(0, QBrush(QColor(200, 0, 0)))
            elif det_type == "packer":
                type_item.setForeground(0, QBrush(QColor(200, 100, 0)))
            elif det_type in ["license", "dongle", "drm"]:
                type_item.setForeground(0, QBrush(QColor(0, 0, 200)))

            # Add detections under type
            for detection in detections:
                det_item = QTreeWidgetItem(type_item)
                det_item.setText(0, detection.name)
                det_item.setText(1, detection.type.value)
                det_item.setText(2, detection.version or "N/A")
                det_item.setData(0, Qt.UserRole, detection)

        # Expand all items
        self.detection_tree.expandAll()

        # Display summary
        self.display_summary(analysis)

        # Display technical details
        self.display_technical_details(analysis)

    def display_summary(self, analysis: ProtectionAnalysis):
        """Display analysis summary"""
        summary_lines = []

        summary_lines.append("=== File Analysis Summary ===\n")
        summary_lines.append(f"File: {os.path.basename(analysis.file_path)}")
        summary_lines.append(f"Full Path: {analysis.file_path}")
        summary_lines.append(f"File Type: {analysis.file_type}")
        summary_lines.append(f"Architecture: {analysis.architecture}")

        if analysis.compiler:
            summary_lines.append(f"Compiler: {analysis.compiler}")

        summary_lines.append("")

        # Status flags
        status_flags = []
        if analysis.is_packed:
            status_flags.append("PACKED")
        if analysis.is_protected:
            status_flags.append("PROTECTED")
        if analysis.has_overlay:
            status_flags.append("HAS OVERLAY")
        if analysis.has_resources:
            status_flags.append("HAS RESOURCES")

        if status_flags:
            summary_lines.append(f"Status: {' | '.join(status_flags)}")
            summary_lines.append("")

        # Detection summary
        if analysis.detections:
            summary_lines.append(f"Total Detections: {len(analysis.detections)}")
            summary_lines.append("")
            summary_lines.append("Detected Protections:")

            for detection in analysis.detections:
                ver_str = f" v{detection.version}" if detection.version else ""
                conf_str = f" ({detection.confidence:.0f}% confidence)" if detection.confidence < 100 else ""
                summary_lines.append(f"  • {detection.name}{ver_str} [{detection.type.value}]{conf_str}")
        else:
            summary_lines.append("No protections detected")

        # License files
        if hasattr(analysis, "license_files") and analysis.license_files:
            summary_lines.append("")
            summary_lines.append(f"License Files Found: {len(analysis.license_files)}")
            for file_info in analysis.license_files[:5]:  # Show up to 5
                summary_lines.append(f"  • {file_info['name']} ({file_info.get('size_str', 'Unknown size')})")

        self.summary_text.setText("\n".join(summary_lines))

    def display_technical_details(self, analysis: ProtectionAnalysis):
        """Display technical details"""
        details_lines = []

        details_lines.append("=== Technical Details ===\n")

        # Entry point
        if analysis.entry_point:
            details_lines.append(f"Entry Point: {analysis.entry_point}")
            details_lines.append("")

        # Sections
        if analysis.sections:
            details_lines.append("Sections:")
            for section in analysis.sections:
                name = section.get("name", "Unknown")
                size = section.get("size", 0)
                entropy = section.get("entropy", 0)
                details_lines.append(f"  • {name}: Size={size}, Entropy={entropy:.2f}")
            details_lines.append("")

        # Imports
        if analysis.imports:
            details_lines.append(f"Imports ({len(analysis.imports)} DLLs):")
            for imp in analysis.imports[:10]:  # Show first 10
                details_lines.append(f"  • {imp}")
            if len(analysis.imports) > 10:
                details_lines.append(f"  ... and {len(analysis.imports) - 10} more")
            details_lines.append("")

        # Metadata
        if analysis.metadata:
            details_lines.append("Metadata:")
            for key, value in analysis.metadata.items():
                details_lines.append(f"  • {key}: {value}")

        self.tech_details_text.setText("\n".join(details_lines))

    def on_detection_selected(self):
        """Handle detection selection in tree"""
        items = self.detection_tree.selectedItems()
        if not items:
            return

        item = items[0]
        detection = item.data(0, Qt.UserRole)

        if detection:
            # Display bypass recommendations
            self.display_bypass_recommendations(detection)

    def display_bypass_recommendations(self, detection):
        """Display bypass recommendations for selected detection"""
        bypass_lines = []

        bypass_lines.append(f"=== Bypass Recommendations for {detection.name} ===\n")

        if detection.bypass_recommendations:
            bypass_lines.append("Recommended approaches:")
            bypass_lines.append("")

            for i, recommendation in enumerate(detection.bypass_recommendations, 1):
                bypass_lines.append(f"{i}. {recommendation}")

            bypass_lines.append("")
            bypass_lines.append("Note: These are general recommendations. Actual bypass methods may vary based on:")
            bypass_lines.append("  • Specific version of the protection")
            bypass_lines.append("  • Target application implementation")
            bypass_lines.append("  • Additional protections present")
            bypass_lines.append("  • Legal and ethical considerations")
        else:
            bypass_lines.append("No specific bypass recommendations available.")
            bypass_lines.append("")
            bypass_lines.append("This protection may require:")
            bypass_lines.append("  • Manual reverse engineering")
            bypass_lines.append("  • Custom tool development")
            bypass_lines.append("  • Advanced analysis techniques")

        self.bypass_text.setText("\n".join(bypass_lines))

        # Switch to bypass tab
        self.details_tabs.setCurrentWidget(self.bypass_text)

    def on_export_clicked(self):
        """Handle export button click"""
        if not self.current_analysis:
            return

        # Get export format
        formats = ["JSON", "Text", "CSV"]
        format_choice, ok = QMessageBox.getItem(
            self,
            "Export Format",
            "Select export format:",
            formats,
            0,
            False,
        )

        if not ok:
            return

        # Get save path
        format_ext = format_choice.lower()
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Analysis Results",
            f"protection_analysis.{format_ext}",
            f"{format_choice} Files (*.{format_ext});;All Files (*.*)",
        )

        if file_path:
            try:
                detector = IntellicrackProtectionCore()
                export_data = detector.export_results(
                    self.current_analysis,
                    format_ext,
                )

                with open(file_path, "w") as f:
                    f.write(export_data)

                QMessageBox.information(
                    self,
                    "Export Complete",
                    f"Results exported to:\n{file_path}",
                )
            except Exception as e:
                logger.error("Exception in intellicrack_protection_widget: %s", e)
                QMessageBox.critical(
                    self,
                    "Export Error",
                    f"Error exporting results:\n{e!s}",
                )

    def clear_results(self):
        """Clear all result displays"""
        self.detection_tree.clear()
        self.summary_text.clear()
        self.bypass_text.clear()
        self.tech_details_text.clear()
        self.raw_output_text.clear()
        self.ai_reasoning_text.clear()
        self.current_analysis = None

    def set_binary_path(self, file_path: str):
        """Set binary path for analysis (called from main UI)"""
        if file_path and os.path.exists(file_path):
            self.analyze_file(file_path)

    def on_ai_reasoning_clicked(self):
        """Handle AI reasoning button click"""
        if not self.current_analysis:
            QMessageBox.warning(self, "No Analysis", "Please analyze a binary first.")
            return

        # Disable button during reasoning
        self.ai_reasoning_btn.setEnabled(False)
        self.status_label.setText("Performing AI reasoning...")

        try:
            # Prepare task data for AI reasoning
            task_data = {
                "type": "protection_detection",
                "file_path": self.current_analysis.file_path,
                "binary_info": {
                    "file_type": self.current_analysis.file_type,
                    "architecture": self.current_analysis.architecture,
                    "is_packed": self.current_analysis.is_packed,
                    "is_protected": self.current_analysis.is_protected,
                    "compiler": self.current_analysis.compiler,
                },
                "patterns": [],
            }

            # Add detection patterns
            if self.current_analysis.detections:
                for detection in self.current_analysis.detections:
                    task_data["patterns"].append({
                        "name": detection.name,
                        "type": detection.type.value,
                        "version": detection.version,
                        "confidence": detection.confidence,
                        "bypass_recommendations": detection.bypass_recommendations,
                    })

            # Add ML results if available
            if hasattr(self.current_analysis, "ml_confidence"):
                task_data["ml_results"] = {
                    "confidence": self.current_analysis.ml_confidence,
                    "predictions": task_data["patterns"],
                }

            # Perform AI reasoning
            reasoning_result = self.ai_assistant.perform_reasoning(task_data)

            # Display reasoning results
            self.display_ai_reasoning(reasoning_result)

            # Enable button
            self.ai_reasoning_btn.setEnabled(True)
            self.status_label.setText("AI reasoning complete")

        except Exception as e:
            logger.error("Error in AI reasoning: %s", e)
            QMessageBox.critical(self, "AI Reasoning Error", f"Error performing AI reasoning:\n{e!s}")
            self.ai_reasoning_btn.setEnabled(True)
            self.status_label.setText("AI reasoning failed")

    def display_ai_reasoning(self, reasoning_result: dict):
        """Display AI reasoning results in the UI"""
        reasoning_lines = []

        reasoning_lines.append("=== AI Reasoning Analysis ===\n")

        # Check for errors
        if reasoning_result.get("error"):
            reasoning_lines.append(f"Error: {reasoning_result['error']}")
            self.ai_reasoning_text.setText("\n".join(reasoning_lines))
            return

        # Display task type and confidence
        reasoning_lines.append(f"Task Type: {reasoning_result.get('task_type', 'Unknown')}")
        reasoning_lines.append(f"Reasoning Confidence: {reasoning_result.get('reasoning_confidence', 0) * 100:.0f}%")
        reasoning_lines.append("")

        # Display evidence
        if reasoning_result.get("evidence"):
            reasoning_lines.append("Evidence Found:")
            for evidence in reasoning_result["evidence"]:
                reasoning_lines.append(f"  • {evidence}")
            reasoning_lines.append("")

        # Display conclusions
        if reasoning_result.get("conclusions"):
            reasoning_lines.append("Conclusions:")
            for conclusion in reasoning_result["conclusions"]:
                reasoning_lines.append(f"  • {conclusion}")
            reasoning_lines.append("")

        # Display next steps
        if reasoning_result.get("next_steps"):
            reasoning_lines.append("Recommended Next Steps:")
            for i, step in enumerate(reasoning_result["next_steps"], 1):
                reasoning_lines.append(f"  {i}. {step}")
            reasoning_lines.append("")

        # Add protection-specific reasoning
        if self.current_analysis.detections:
            reasoning_lines.append("Protection-Specific Analysis:")
            reasoning_lines.append("")

            for detection in self.current_analysis.detections:
                reasoning_lines.append(f"For {detection.name} ({detection.type.value}):")

                # Analyze bypass difficulty
                if detection.bypass_recommendations:
                    reasoning_lines.append("  Bypass Complexity Analysis:")
                    if len(detection.bypass_recommendations) > 3:
                        reasoning_lines.append("    - Multiple bypass approaches available")
                        reasoning_lines.append("    - Suggests well-studied protection scheme")
                    else:
                        reasoning_lines.append("    - Limited bypass options")
                        reasoning_lines.append("    - May require custom approach")

                # Analyze protection type implications
                if detection.type.value == "protector":
                    reasoning_lines.append("  Impact: Code obfuscation and anti-debugging expected")
                elif detection.type.value == "packer":
                    reasoning_lines.append("  Impact: Code unpacking required before analysis")
                elif detection.type.value in ["license", "dongle", "drm"]:
                    reasoning_lines.append("  Impact: License verification bypass needed")

                reasoning_lines.append("")

        # Update the AI reasoning text
        self.ai_reasoning_text.setText("\n".join(reasoning_lines))

        # Switch to AI reasoning tab
        self.details_tabs.setCurrentWidget(self.ai_reasoning_text)

    def search_license_files(self):
        """Search for license files in the current binary's directory"""
        if not self.current_analysis:
            QMessageBox.warning(self, "No Analysis", "Please analyze a binary first")
            return

        try:
            binary_dir = os.path.dirname(os.path.abspath(self.current_analysis.file_path))
            self.status_label.setText("Searching for license files...")

            # Use AI file tools to search
            ai_file_tools = get_ai_file_tools()
            license_file_results = ai_file_tools.search_for_license_files(binary_dir)

            if license_file_results.get("status") == "success":
                files_found = license_file_results.get("files_found", [])

                if files_found:
                    # Display results in a message box
                    message_lines = [f"Found {len(files_found)} potential license files:\n"]
                    for file_info in files_found[:10]:  # Show up to 10
                        message_lines.append(f"• {file_info['name']} ({file_info.get('size_str', 'Unknown size')})")
                        if file_info.get("match_type"):
                            message_lines.append(f"  Type: {file_info['match_type']}")

                    if len(files_found) > 10:
                        message_lines.append(f"\n... and {len(files_found) - 10} more files")

                    QMessageBox.information(self, "License Files Found", "\n".join(message_lines))

                    # Update the analysis object
                    if not hasattr(self.current_analysis, "license_files"):
                        self.current_analysis.license_files = []
                    self.current_analysis.license_files = files_found

                    # Refresh display
                    self.display_summary(self.current_analysis)
                else:
                    QMessageBox.information(self, "No License Files",
                                          f"No license files found in:\n{binary_dir}")
            else:
                error_msg = license_file_results.get("error", "Unknown error")
                QMessageBox.warning(self, "Search Failed", f"License file search failed:\n{error_msg}")

            self.status_label.setText("License file search complete")

        except Exception as e:
            logger.error(f"Error searching for license files: {e}")
            QMessageBox.critical(self, "Error", f"Error searching for license files:\n{e!s}")
            self.status_label.setText("License file search failed")

    def on_ask_ai_clicked(self):
        """Handle Ask AI button click - opens a dialog to ask questions about protections"""
        # Create a custom dialog for asking questions
        dialog = QDialog(self)
        dialog.setWindowTitle("Ask AI about Protections")
        dialog.setMinimumWidth(600)
        dialog.setMinimumHeight(400)

        layout = QVBoxLayout(dialog)

        # Instructions
        instructions = QLabel("Ask questions about binary protections, licensing schemes, or security analysis:")
        layout.addWidget(instructions)

        # Question input
        question_input = QLineEdit()
        question_input.setPlaceholderText("e.g., 'How do I bypass VMProtect?' or 'What is a dongle protection?'")
        layout.addWidget(question_input)

        # Response area
        response_text = QTextEdit()
        response_text.setReadOnly(True)
        layout.addWidget(response_text)

        # Buttons
        button_box = QDialogButtonBox()
        ask_button = QPushButton("Ask")
        close_button = QPushButton("Close")
        button_box.addButton(ask_button, QDialogButtonBox.ActionRole)
        button_box.addButton(close_button, QDialogButtonBox.RejectRole)

        def ask_question():
            question = question_input.text().strip()
            if not question:
                QMessageBox.warning(dialog, "No Question", "Please enter a question.")
                return

            # Disable button during processing
            ask_button.setEnabled(False)
            response_text.append(f"<b>Question:</b> {question}\n")
            response_text.append("<i>AI is thinking...</i>\n")

            try:
                # Add context from current analysis if available
                if self.current_analysis and self.current_analysis.detections:
                    context_parts = []
                    context_parts.append("Current binary analysis context:")
                    for detection in self.current_analysis.detections:
                        context_parts.append(f"- Detected: {detection.name} ({detection.type.value})")
                    context = "\n".join(context_parts) + "\n\n"
                    full_question = context + question
                else:
                    full_question = question

                # Get AI response
                response = self.ai_tools.ask_question(full_question)

                # Clear the "thinking" message and display response
                response_text.clear()
                response_text.append(f"<b>Question:</b> {question}\n")
                response_text.append(f"<b>AI Response:</b>\n{response}")

            except Exception as e:
                logger.error(f"Error asking AI question: {e}")
                response_text.clear()
                response_text.append(f"<b>Question:</b> {question}\n")
                response_text.append(f"<b>Error:</b> {e!s}")
            finally:
                ask_button.setEnabled(True)
                question_input.clear()
                question_input.setFocus()

        # Connect signals
        ask_button.clicked.connect(ask_question)
        close_button.clicked.connect(dialog.reject)
        question_input.returnPressed.connect(ask_question)

        layout.addWidget(button_box)

        # Pre-populate with context-aware suggestions if analysis is available
        if self.current_analysis and self.current_analysis.detections:
            suggestions = []
            for detection in self.current_analysis.detections:
                if detection.type.value == "protector":
                    suggestions.append(f"How can I bypass {detection.name} protection?")
                elif detection.type.value == "packer":
                    suggestions.append(f"What are the best tools to unpack {detection.name}?")
                elif detection.type.value in ["license", "dongle", "drm"]:
                    suggestions.append(f"How does {detection.name} licensing work?")

            if suggestions:
                response_text.append("<b>Suggested questions based on current analysis:</b>")
                for suggestion in suggestions[:3]:  # Show up to 3 suggestions
                    response_text.append(f"• {suggestion}")
                response_text.append("\n<i>Type your question above or click a suggestion to use it.</i>\n")

        dialog.exec()


# Backward compatibility aliases
DIEProtectionWidget = IntellicrackProtectionWidget
DIEAnalysisThread = ProtectionAnalysisThread
