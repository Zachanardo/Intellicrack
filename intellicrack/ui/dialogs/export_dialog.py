"""
ICP Analysis Export Dialog

Provides comprehensive export functionality for ICP analysis results.
Supports multiple export formats including JSON, XML, CSV, and PDF reports.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict, Optional

from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QSpinBox,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from ...utils.logger import get_logger

logger = get_logger(__name__)


class ExportWorker(QThread):
    """Worker thread for export operations"""

    export_completed = pyqtSignal(bool, str)  # success, message
    progress_update = pyqtSignal(int, str)    # progress, status

    def __init__(self, export_config: Dict[str, Any]):
        """Initialize the ExportWorker with default values."""
        super().__init__()
        self.export_config = export_config

    def run(self):
        """Execute export operation"""
        try:
            export_format = self.export_config["format"]
            output_path = self.export_config["output_path"]
            analysis_results = self.export_config["results"]

            self.progress_update.emit(10, "Preparing export data...")

            if export_format == "json":
                self._export_json(output_path, analysis_results)
            elif export_format == "xml":
                self._export_xml(output_path, analysis_results)
            elif export_format == "csv":
                self._export_csv(output_path, analysis_results)
            elif export_format == "pdf":
                self._export_pdf(output_path, analysis_results)
            elif export_format == "html":
                self._export_html(output_path, analysis_results)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")

            self.progress_update.emit(100, "Export completed successfully")
            self.export_completed.emit(True, f"Export completed: {output_path}")

        except Exception as e:
            logger.error(f"Export failed: {e}")
            self.export_completed.emit(False, f"Export failed: {str(e)}")

    def _export_json(self, output_path: str, results: Dict[str, Any]):
        """Export to JSON format"""
        self.progress_update.emit(30, "Formatting JSON data...")

        export_data = {
            "export_info": {
                "timestamp": datetime.now().isoformat(),
                "version": "1.0",
                "format": "json",
                "exported_by": "Intellicrack Protection Engine"
            },
            "analysis_results": results
        }

        self.progress_update.emit(70, "Writing JSON file...")

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

    def _export_xml(self, output_path: str, results: Dict[str, Any]):
        """Export to XML format"""
        self.progress_update.emit(30, "Building XML structure...")

        root = ET.Element("intellicrack_analysis")
        root.set("timestamp", datetime.now().isoformat())
        root.set("version", "1.0")

        # Add file info
        if "file_info" in results:
            file_info = ET.SubElement(root, "file_info")
            for key, value in results["file_info"].items():
                elem = ET.SubElement(file_info, key)
                elem.text = str(value)

        # Add ICP analysis
        if "icp_analysis" in results:
            icp_elem = ET.SubElement(root, "icp_analysis")
            icp_data = results["icp_analysis"]

            if hasattr(icp_data, "__dict__"):
                # Convert analysis object to dict
                icp_dict = {
                    "is_protected": icp_data.is_protected if hasattr(icp_data, "is_protected") else False,
                    "file_type": icp_data.file_type if hasattr(icp_data, "file_type") else "Unknown",
                    "architecture": icp_data.architecture if hasattr(icp_data, "architecture") else "Unknown",
                    "detections": []
                }

                if hasattr(icp_data, "all_detections"):
                    for detection in icp_data.all_detections:
                        det_dict = {
                            "name": detection.name if hasattr(detection, "name") else "Unknown",
                            "type": detection.type if hasattr(detection, "type") else "Unknown",
                            "confidence": detection.confidence if hasattr(detection, "confidence") else 0.0,
                            "version": detection.version if hasattr(detection, "version") else ""
                        }
                        icp_dict["detections"].append(det_dict)

                self._dict_to_xml(icp_elem, icp_dict)

        self.progress_update.emit(70, "Writing XML file...")

        tree = ET.ElementTree(root)
        tree.write(output_path, encoding="utf-8", xml_declaration=True)

    def _dict_to_xml(self, parent: ET.Element, data: Dict[str, Any]):
        """Convert dictionary to XML elements"""
        for key, value in data.items():
            elem = ET.SubElement(parent, str(key))

            if isinstance(value, dict):
                self._dict_to_xml(elem, value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        item_elem = ET.SubElement(elem, "item")
                        self._dict_to_xml(item_elem, item)
                    else:
                        item_elem = ET.SubElement(elem, "item")
                        item_elem.text = str(item)
            else:
                elem.text = str(value)

    def _export_csv(self, output_path: str, results: Dict[str, Any]):
        """Export to CSV format"""
        import csv

        self.progress_update.emit(30, "Preparing CSV data...")

        # Create CSV with detection results
        rows = []

        # Add header
        rows.append([
            "Detection Name", "Type", "Confidence", "Version",
            "File Type", "Architecture", "Protected"
        ])

        # Extract detection data
        if "icp_analysis" in results:
            icp_data = results["icp_analysis"]

            file_type = getattr(icp_data, "file_type", "Unknown")
            architecture = getattr(icp_data, "architecture", "Unknown")
            is_protected = getattr(icp_data, "is_protected", False)

            if hasattr(icp_data, "all_detections"):
                for detection in icp_data.all_detections:
                    rows.append([
                        getattr(detection, "name", "Unknown"),
                        getattr(detection, "type", "Unknown"),
                        f"{getattr(detection, 'confidence', 0.0):.2%}",
                        getattr(detection, "version", ""),
                        file_type,
                        architecture,
                        str(is_protected)
                    ])

        self.progress_update.emit(70, "Writing CSV file...")

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerows(rows)

    def _export_pdf(self, output_path: str, results: Dict[str, Any]):
        """Export to PDF format"""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        except ImportError as e:
            self.logger.error("Import error in export_dialog: %s", e)
            raise ImportError("ReportLab is required for PDF export. Install with: pip install reportlab")

        self.progress_update.emit(30, "Building PDF report...")

        # Choose page size based on export configuration
        page_format = self.export_config.get("page_format", "A4")
        if page_format == "letter":
            pagesize = letter
        else:
            pagesize = A4

        doc = SimpleDocTemplate(output_path, pagesize=pagesize)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.darkblue,
            spaceAfter=30
        )

        story.append(Paragraph("Intellicrack Protection Analysis Report", title_style))
        story.append(Spacer(1, 20))

        # Metadata
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
        story.append(Spacer(1, 20))

        # File Information
        if "file_info" in results:
            story.append(Paragraph("File Information", styles["Heading2"]))

            file_data = []
            for key, value in results["file_info"].items():
                file_data.append([key.replace("_", " ").title(), str(value)])

            file_table = Table(file_data, colWidths=[2*inch, 3*inch])
            file_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.lightgrey),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ("GRID", (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(file_table)
            story.append(Spacer(1, 20))

        # ICP Analysis Results
        if "icp_analysis" in results:
            story.append(Paragraph("Protection Analysis Results", styles["Heading2"]))

            icp_data = results["icp_analysis"]

            # Summary
            summary_text = f"""
            File Type: {getattr(icp_data, 'file_type', 'Unknown')}<br/>
            Architecture: {getattr(icp_data, 'architecture', 'Unknown')}<br/>
            Protected: {'Yes' if getattr(icp_data, 'is_protected', False) else 'No'}<br/>
            """

            story.append(Paragraph(summary_text, styles["Normal"]))
            story.append(Spacer(1, 15))

            # Detections table
            if hasattr(icp_data, "all_detections") and icp_data.all_detections:
                story.append(Paragraph("Detected Protections", styles["Heading3"]))

                detection_data = [["Name", "Type", "Confidence", "Version"]]

                for detection in icp_data.all_detections:
                    detection_data.append([
                        getattr(detection, "name", "Unknown"),
                        getattr(detection, "type", "Unknown"),
                        f"{getattr(detection, 'confidence', 0.0):.1%}",
                        getattr(detection, "version", "N/A")
                    ])

                detection_table = Table(detection_data, colWidths=[2*inch, 1.5*inch, 1*inch, 1*inch])
                detection_table.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.grey),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
                    ("GRID", (0, 0), (-1, -1), 1, colors.black)
                ]))

                story.append(detection_table)

        self.progress_update.emit(70, "Writing PDF file...")
        doc.build(story)

    def _export_html(self, output_path: str, results: Dict[str, Any]):
        """Export to HTML format"""
        self.progress_update.emit(30, "Building HTML report...")

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Intellicrack Protection Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        .info-section {{ background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .detection {{ background: #e8f6f3; border-left: 4px solid #27ae60; padding: 10px; margin: 10px 0; }}
        .high-confidence {{ border-left-color: #e74c3c; background: #fdf2f2; }}
        .medium-confidence {{ border-left-color: #f39c12; background: #fdf6e3; }}
        .low-confidence {{ border-left-color: #95a5a6; background: #f8f9fa; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #bdc3c7; padding: 12px; text-align: left; }}
        th {{ background-color: #34495e; color: white; }}
        tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .timestamp {{ color: #7f8c8d; font-size: 0.9em; }}
        .protected-yes {{ color: #e74c3c; font-weight: bold; }}
        .protected-no {{ color: #27ae60; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Intellicrack Protection Analysis Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

"""

        # File Information
        if "file_info" in results:
            html_content += """
        <h2>File Information</h2>
        <div class="info-section">
            <table>
"""
            for key, value in results["file_info"].items():
                html_content += f"                <tr><td><strong>{key.replace('_', ' ').title()}</strong></td><td>{value}</td></tr>\n"

            html_content += """            </table>
        </div>
"""

        # ICP Analysis
        if "icp_analysis" in results:
            icp_data = results["icp_analysis"]

            file_type = getattr(icp_data, "file_type", "Unknown")
            architecture = getattr(icp_data, "architecture", "Unknown")
            is_protected = getattr(icp_data, "is_protected", False)

            protected_class = "protected-yes" if is_protected else "protected-no"
            protected_text = "Yes" if is_protected else "No"

            html_content += f"""
        <h2>Protection Analysis Results</h2>
        <div class="info-section">
            <p><strong>File Type:</strong> {file_type}</p>
            <p><strong>Architecture:</strong> {architecture}</p>
            <p><strong>Protected:</strong> <span class="{protected_class}">{protected_text}</span></p>
        </div>
"""

            # Detections
            if hasattr(icp_data, "all_detections") and icp_data.all_detections:
                html_content += """
        <h2>Detected Protections</h2>
"""

                for detection in icp_data.all_detections:
                    name = getattr(detection, "name", "Unknown")
                    det_type = getattr(detection, "type", "Unknown")
                    confidence = getattr(detection, "confidence", 0.0)
                    version = getattr(detection, "version", "")

                    # Confidence-based styling
                    if confidence >= 0.8:
                        confidence_class = "high-confidence"
                    elif confidence >= 0.5:
                        confidence_class = "medium-confidence"
                    else:
                        confidence_class = "low-confidence"

                    version_text = f" (v{version})" if version else ""

                    html_content += f"""
        <div class="detection {confidence_class}">
            <h3>{name}{version_text}</h3>
            <p><strong>Type:</strong> {det_type}</p>
            <p><strong>Confidence:</strong> {confidence:.1%}</p>
        </div>
"""

        html_content += """
    </div>
</body>
</html>
"""

        self.progress_update.emit(70, "Writing HTML file...")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)


class ExportDialog(QDialog):
    """Export dialog for ICP analysis results"""

    def __init__(self, analysis_results: Optional[Dict[str, Any]] = None, parent=None):
        """Initialize the ExportDialog with default values."""
        super().__init__(parent)
        self.setWindowTitle("Export ICP Analysis Results")
        self.setModal(True)
        self.resize(600, 500)

        self.analysis_results = analysis_results
        self.export_worker: Optional[ExportWorker] = None

        self.init_ui()

    def init_ui(self):
        """Initialize the user interface"""
        layout = QVBoxLayout()

        # Check if we have results to export
        if not self.analysis_results:
            no_data_label = QLabel("No analysis results available for export.")
            no_data_label.setStyleSheet("color: #e74c3c; font-weight: bold; padding: 20px;")
            layout.addWidget(no_data_label)

            # Close button only
            button_box = QDialogButtonBox(QDialogButtonBox.Close)
            button_box.rejected.connect(self.reject)
            layout.addWidget(button_box)

            self.setLayout(layout)
            return

        # Load export preferences from config
        self.export_prefs = {}
        try:
            from ...config import get_config
            config = get_config()
            self.export_prefs = {
                "format": config.get("export.default_format", "json"),
                "page_format": config.get("export.page_format", "A4"),
                "pretty_format": config.get("export.pretty_format", True),
                "include_timestamp": config.get("export.include_timestamp", True),
                "confidence_threshold": config.get("export.confidence_threshold", 50),
                "include_file_info": config.get("export.include_file_info", True),
                "include_detections": config.get("export.include_detections", True)
            }
            logger.debug("Loaded export preferences from configuration")
        except (ImportError, AttributeError) as e:
            logger.debug(f"Could not load export preferences: {e}")

        # Tab widget for different export options
        tab_widget = QTabWidget()

        # Format selection tab
        format_tab = self._create_format_tab()
        tab_widget.addTab(format_tab, "Export Format")

        # Options tab
        options_tab = self._create_options_tab()
        tab_widget.addTab(options_tab, "Export Options")

        # Preview tab
        preview_tab = self._create_preview_tab()
        tab_widget.addTab(preview_tab, "Preview")

        layout.addWidget(tab_widget)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Status label
        self.status_label = QLabel("Ready to export")
        self.status_label.setStyleSheet("color: #666; padding: 5px;")
        layout.addWidget(self.status_label)

        # Button box
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.start_export)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def _create_format_tab(self) -> QWidget:
        """Create format selection tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Format selection
        format_group = QGroupBox("Export Format")
        format_layout = QVBoxLayout()

        self.format_group = QButtonGroup()

        formats = [
            ("json", "JSON", "JavaScript Object Notation - structured data"),
            ("xml", "XML", "Extensible Markup Language - structured document"),
            ("csv", "CSV", "Comma-Separated Values - spreadsheet compatible"),
            ("html", "HTML", "HTML Report - web browser viewable"),
            ("pdf", "PDF", "PDF Report - professional document format")
        ]

        for format_id, format_name, description in formats:
            radio = QRadioButton(f"{format_name} - {description}")
            radio.setProperty("format_id", format_id)
            self.format_group.addButton(radio)
            format_layout.addWidget(radio)

            # Set default format from preferences
            if format_id == self.export_prefs.get("format", "json"):
                radio.setChecked(True)

        format_group.setLayout(format_layout)
        layout.addWidget(format_group)

        # Output file selection
        output_group = QGroupBox("Output File")
        output_layout = QVBoxLayout()

        file_layout = QHBoxLayout()
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setPlaceholderText("Select output file path...")

        self.browse_output_btn = QPushButton("Browse...")
        self.browse_output_btn.clicked.connect(self.browse_output_file)

        file_layout.addWidget(self.output_path_edit)
        file_layout.addWidget(self.browse_output_btn)
        output_layout.addLayout(file_layout)

        output_group.setLayout(output_layout)
        layout.addWidget(output_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def _create_options_tab(self) -> QWidget:
        """Create export options tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Data selection
        data_group = QGroupBox("Data to Export")
        data_layout = QVBoxLayout()

        self.include_file_info_cb = QCheckBox("Include file information")
        self.include_file_info_cb.setChecked(self.export_prefs.get("include_file_info", True))
        data_layout.addWidget(self.include_file_info_cb)

        self.include_detections_cb = QCheckBox("Include protection detections")
        self.include_detections_cb.setChecked(self.export_prefs.get("include_detections", True))
        data_layout.addWidget(self.include_detections_cb)

        self.include_metadata_cb = QCheckBox("Include analysis metadata")
        self.include_metadata_cb.setChecked(True)
        data_layout.addWidget(self.include_metadata_cb)

        data_group.setLayout(data_layout)
        layout.addWidget(data_group)

        # Export options
        options_group = QGroupBox("Export Options")
        options_layout = QVBoxLayout()

        self.pretty_format_cb = QCheckBox("Pretty format output (where applicable)")
        self.pretty_format_cb.setChecked(self.export_prefs.get("pretty_format", True))
        options_layout.addWidget(self.pretty_format_cb)

        self.include_timestamp_cb = QCheckBox("Include timestamp in export")
        self.include_timestamp_cb.setChecked(self.export_prefs.get("include_timestamp", True))
        options_layout.addWidget(self.include_timestamp_cb)

        # Page format selection for PDF export
        page_format_layout = QHBoxLayout()
        page_format_layout.addWidget(QLabel("PDF page format:"))

        self.page_format_combo = QComboBox()
        self.page_format_combo.addItems(["A4", "Letter"])
        self.page_format_combo.setCurrentText(self.export_prefs.get("page_format", "A4"))
        self.page_format_combo.setToolTip("Choose page size for PDF export:\nA4: International standard (210×297mm)\nLetter: US standard (8.5×11 inches)")
        page_format_layout.addWidget(self.page_format_combo)

        page_format_layout.addStretch()
        options_layout.addLayout(page_format_layout)

        # Confidence filter
        confidence_layout = QHBoxLayout()
        confidence_layout.addWidget(QLabel("Minimum confidence threshold:"))

        self.confidence_threshold_spin = QSpinBox()
        self.confidence_threshold_spin.setRange(0, 100)
        self.confidence_threshold_spin.setValue(self.export_prefs.get("confidence_threshold", 50))
        self.confidence_threshold_spin.setSuffix("%")
        confidence_layout.addWidget(self.confidence_threshold_spin)

        confidence_layout.addStretch()
        options_layout.addLayout(confidence_layout)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        layout.addStretch()
        widget.setLayout(layout)
        return widget

    def _create_preview_tab(self) -> QWidget:
        """Create export preview tab"""
        widget = QWidget()
        layout = QVBoxLayout()

        # Preview controls
        controls_layout = QHBoxLayout()

        self.refresh_preview_btn = QPushButton("Refresh Preview")
        self.refresh_preview_btn.clicked.connect(self.refresh_preview)
        controls_layout.addWidget(self.refresh_preview_btn)

        self.preview_format_combo = QComboBox()
        self.preview_format_combo.addItems(["JSON", "XML", "CSV", "HTML"])
        self.preview_format_combo.currentTextChanged.connect(self.refresh_preview)
        controls_layout.addWidget(self.preview_format_combo)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Preview text
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.preview_text)

        widget.setLayout(layout)

        # Initial preview
        self.refresh_preview()

        return widget

    def browse_output_file(self):
        """Browse for output file"""
        # Get selected format
        selected_format = "json"
        for button in self.format_group.buttons():
            if button.isChecked():
                selected_format = button.property("format_id")
                break

        # File dialog based on format
        filters = {
            "json": "JSON Files (*.json);;All Files (*.*)",
            "xml": "XML Files (*.xml);;All Files (*.*)",
            "csv": "CSV Files (*.csv);;All Files (*.*)",
            "html": "HTML Files (*.html *.htm);;All Files (*.*)",
            "pdf": "PDF Files (*.pdf);;All Files (*.*)"
        }

        file_filter = filters.get(selected_format, "All Files (*.*)")

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Export File",
            f"intellicrack_analysis.{selected_format}",
            file_filter
        )

        if file_path:
            self.output_path_edit.setText(file_path)

    def refresh_preview(self):
        """Refresh export preview"""
        if not self.analysis_results:
            self.preview_text.setPlainText("No analysis results available.")
            return

        try:
            preview_format = self.preview_format_combo.currentText().lower()

            # Create filtered results based on options
            filtered_results = self._filter_results()

            if preview_format == "json":
                preview_data = {
                    "export_info": {
                        "timestamp": datetime.now().isoformat(),
                        "format": "json"
                    },
                    "analysis_results": filtered_results
                }
                preview_text = json.dumps(preview_data, indent=2, default=str)[:2000]

            elif preview_format == "xml":
                # Simplified XML preview
                preview_text = f"""<?xml version="1.0" encoding="UTF-8"?>
<intellicrack_analysis timestamp="{datetime.now().isoformat()}">
    <file_info>
        <!-- File information would be here -->
    </file_info>
    <icp_analysis>
        <!-- Protection analysis results would be here -->
    </icp_analysis>
</intellicrack_analysis>"""

            elif preview_format == "csv":
                preview_text = "Detection Name,Type,Confidence,Version,File Type,Architecture,Protected\n"
                if "icp_analysis" in filtered_results:
                    icp_data = filtered_results["icp_analysis"]
                    if hasattr(icp_data, "all_detections"):
                        for detection in icp_data.all_detections[:5]:  # Preview first 5
                            preview_text += f"{getattr(detection, 'name', 'Unknown')},{getattr(detection, 'type', 'Unknown')},{getattr(detection, 'confidence', 0.0):.2%},...\n"

            elif preview_format == "html":
                preview_text = f"""<!DOCTYPE html>
<html>
<head>
    <title>Intellicrack Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; }}
        .detection {{ background: #f0f0f0; padding: 10px; margin: 5px; }}
    </style>
</head>
<body>
    <h1>Intellicrack Protection Analysis Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    <!-- Analysis results would be here -->
</body>
</html>"""

            else:
                preview_text = "Preview not available for this format"

            # Truncate if too long
            if len(preview_text) > 2000:
                preview_text = preview_text[:2000] + "\n\n... (truncated)"

            self.preview_text.setPlainText(preview_text)

        except Exception as e:
            logger.error("Exception in export_dialog: %s", e)
            self.preview_text.setPlainText(f"Preview error: {str(e)}")

    def _filter_results(self) -> Dict[str, Any]:
        """Filter results based on export options"""
        if not self.analysis_results:
            return {}

        filtered = {}

        # Apply confidence threshold
        confidence_threshold = self.confidence_threshold_spin.value() / 100.0

        # Include file info
        if self.include_file_info_cb.isChecked() and "file_info" in self.analysis_results:
            filtered["file_info"] = self.analysis_results["file_info"]

        # Include detections
        if self.include_detections_cb.isChecked() and "icp_analysis" in self.analysis_results:
            icp_data = self.analysis_results["icp_analysis"]

            # Filter detections by confidence
            if hasattr(icp_data, "all_detections"):
                filtered_detections = []
                for detection in icp_data.all_detections:
                    if getattr(detection, "confidence", 0.0) >= confidence_threshold:
                        filtered_detections.append(detection)

                # Create filtered ICP data
                class FilteredICPData:
                    def __init__(self, original, filtered_detections):
                        self.file_type = getattr(original, "file_type", "Unknown")
                        self.architecture = getattr(original, "architecture", "Unknown")
                        self.is_protected = getattr(original, "is_protected", False)
                        self.all_detections = filtered_detections

                filtered["icp_analysis"] = FilteredICPData(icp_data, filtered_detections)
            else:
                filtered["icp_analysis"] = icp_data

        return filtered

    def start_export(self):
        """Start the export process"""
        # Validate inputs
        if not self.output_path_edit.text():
            QMessageBox.warning(self, "Invalid Output", "Please select an output file path.")
            return

        # Get selected format
        selected_format = "json"
        for button in self.format_group.buttons():
            if button.isChecked():
                selected_format = button.property("format_id")
                break

        # Save export preferences to config
        try:
            from ...config import get_config
            config = get_config()
            export_prefs = {
                "export.default_format": selected_format,
                "export.page_format": self.page_format_combo.currentText(),
                "export.pretty_format": self.pretty_format_cb.isChecked(),
                "export.include_timestamp": self.include_timestamp_cb.isChecked(),
                "export.confidence_threshold": self.confidence_threshold_spin.value(),
                "export.include_file_info": self.include_file_info_cb.isChecked(),
                "export.include_detections": self.include_detections_cb.isChecked()
            }
            config.update(export_prefs)
            logger.debug("Saved export preferences to configuration")
        except (ImportError, AttributeError) as e:
            logger.debug(f"Could not save export preferences: {e}")

        # Create export configuration
        export_config = {
            "format": selected_format,
            "output_path": self.output_path_edit.text(),
            "results": self._filter_results(),
            "page_format": self.page_format_combo.currentText().lower(),
            "options": {
                "pretty_format": self.pretty_format_cb.isChecked(),
                "include_timestamp": self.include_timestamp_cb.isChecked(),
                "confidence_threshold": self.confidence_threshold_spin.value() / 100.0
            }
        }

        # Start export worker
        self.export_worker = ExportWorker(export_config)
        self.export_worker.export_completed.connect(self.on_export_completed)
        self.export_worker.progress_update.connect(self.on_progress_update)

        # Show progress
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting export...")

        # Disable buttons
        for button in self.findChildren(QPushButton):
            button.setEnabled(False)

        self.export_worker.start()

    @pyqtSlot(bool, str)
    def on_export_completed(self, success: bool, message: str):
        """Handle export completion"""
        self.progress_bar.setVisible(False)

        # Re-enable buttons
        for button in self.findChildren(QPushButton):
            button.setEnabled(True)

        if success:
            self.status_label.setText("Export completed successfully")
            QMessageBox.information(self, "Export Successful", message)
            self.accept()
        else:
            self.status_label.setText("Export failed")
            QMessageBox.critical(self, "Export Failed", message)

    @pyqtSlot(int, str)
    def on_progress_update(self, progress: int, status: str):
        """Handle progress updates"""
        self.progress_bar.setValue(progress)
        self.status_label.setText(status)


def main():
    """Test the export dialog"""
    from PyQt6.QtWidgets import QApplication

    app = QApplication([])
    app.setApplicationName("IntellicrackExportTest")

    # Mock analysis results for testing
    class MockDetection:
        def __init__(self, name, det_type, confidence, version=""):
            self.name = name
            self.type = det_type
            self.confidence = confidence
            self.version = version

    class MockICPAnalysis:
        def __init__(self):
            self.file_type = "PE32"
            self.architecture = "x86"
            self.is_protected = True
            self.all_detections = [
                MockDetection("UPX", "Packer", 0.95, "3.96"),
                MockDetection("VMProtect", "Protector", 0.78, "3.5"),
                MockDetection("Anti-Debug", "Protector", 0.65)
            ]

    mock_results = {
        "file_info": {
            "file_path": "/test/sample.exe",
            "file_size": 1024000,
            "md5": "abc123...",
            "sha256": "def456..."
        },
        "icp_analysis": MockICPAnalysis()
    }

    dialog = ExportDialog(mock_results)
    dialog.exec()


if __name__ == "__main__":
    main()
