"""
Comprehensive Report Generator Widget for Intellicrack

This widget provides an advanced reporting system that generates detailed analysis reports
with export capabilities. It integrates with all backend analysis systems to compile
comprehensive reports including binary analysis, protection detection, AI insights,
and exploitation recommendations.
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTextEdit, QPushButton,
    QComboBox, QLabel, QCheckBox, QGroupBox, QScrollArea, QProgressBar,
    QTreeWidget, QTreeWidgetItem, QSplitter, QFrame, QDateTimeEdit,
    QSpinBox, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog,
    QMessageBox, QDialog, QFormLayout, QLineEdit, QTextBrowser
)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, QDateTime, Qt
from PyQt6.QtGui import QFont, QPixmap, QIcon, QPainter, QTextDocument
from pathlib import Path
import json
import datetime
import base64
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class ReportExportWorker(QThread):
    """Background worker for report export operations"""
    
    export_progress = pyqtSignal(int)
    export_completed = pyqtSignal(str, bool)
    section_completed = pyqtSignal(str)
    
    def __init__(self, report_data: Dict[str, Any], export_format: str, output_path: str):
        super().__init__()
        self.report_data = report_data
        self.export_format = export_format
        self.output_path = output_path
        
    def run(self):
        """Execute report export in background"""
        try:
            total_sections = len(self.report_data.get('sections', []))
            
            if self.export_format == 'HTML':
                self._export_html()
            elif self.export_format == 'PDF':
                self._export_pdf()
            elif self.export_format == 'JSON':
                self._export_json()
            elif self.export_format == 'XML':
                self._export_xml()
            
            self.export_completed.emit(self.output_path, True)
            
        except Exception as e:
            logger.error(f"Report export failed: {e}")
            self.export_completed.emit(str(e), False)
    
    def _export_html(self):
        """Export report as HTML"""
        html_content = self._generate_html_report()
        with open(self.output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        self.export_progress.emit(100)
    
    def _export_pdf(self):
        """Export report as PDF"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            
            doc = SimpleDocTemplate(self.output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                alignment=1  # Center
            )
            
            story.append(Paragraph("Intellicrack Analysis Report", title_style))
            story.append(Spacer(1, 12))
            
            # Metadata
            metadata = self.report_data.get('metadata', {})
            story.append(Paragraph(f"Generated: {metadata.get('timestamp', 'Unknown')}", styles['Normal']))
            story.append(Paragraph(f"Binary: {metadata.get('binary_name', 'Unknown')}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Sections
            sections = self.report_data.get('sections', [])
            for i, section in enumerate(sections):
                story.append(Paragraph(section.get('title', 'Section'), styles['Heading2']))
                
                content = section.get('content', '')
                if isinstance(content, dict):
                    content = json.dumps(content, indent=2)
                
                story.append(Paragraph(content, styles['Normal']))
                story.append(Spacer(1, 12))
                
                progress = int((i + 1) / len(sections) * 100)
                self.export_progress.emit(progress)
                self.section_completed.emit(section.get('title', 'Section'))
            
            doc.build(story)
            
        except ImportError:
            # Fallback to HTML-to-PDF if reportlab not available
            html_content = self._generate_html_report()
            with open(self.output_path.replace('.pdf', '.html'), 'w', encoding='utf-8') as f:
                f.write(html_content)
            self.export_progress.emit(100)
    
    def _export_json(self):
        """Export report as JSON"""
        with open(self.output_path, 'w', encoding='utf-8') as f:
            json.dump(self.report_data, f, indent=2, default=str)
        self.export_progress.emit(100)
    
    def _export_xml(self):
        """Export report as XML"""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("intellicrack_report")
        
        # Metadata
        metadata_elem = ET.SubElement(root, "metadata")
        metadata = self.report_data.get('metadata', {})
        for key, value in metadata.items():
            elem = ET.SubElement(metadata_elem, key)
            elem.text = str(value)
        
        # Sections
        sections_elem = ET.SubElement(root, "sections")
        sections = self.report_data.get('sections', [])
        
        for section in sections:
            section_elem = ET.SubElement(sections_elem, "section")
            section_elem.set("title", section.get('title', ''))
            
            content_elem = ET.SubElement(section_elem, "content")
            content = section.get('content', '')
            if isinstance(content, dict):
                content = json.dumps(content, indent=2)
            content_elem.text = content
        
        tree = ET.ElementTree(root)
        tree.write(self.output_path, encoding='utf-8', xml_declaration=True)
        self.export_progress.emit(100)
    
    def _generate_html_report(self) -> str:
        """Generate HTML report content"""
        metadata = self.report_data.get('metadata', {})
        sections = self.report_data.get('sections', [])
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Intellicrack Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; }}
                .metadata {{ background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px; }}
                .section {{ margin: 20px 0; border-left: 4px solid #007ACC; padding-left: 15px; }}
                .section-title {{ color: #007ACC; font-size: 1.2em; font-weight: bold; }}
                .content {{ margin-top: 10px; white-space: pre-wrap; }}
                .table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                .table th, .table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .table th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Intellicrack Analysis Report</h1>
            </div>
            
            <div class="metadata">
                <h2>Report Metadata</h2>
                <p><strong>Generated:</strong> {metadata.get('timestamp', 'Unknown')}</p>
                <p><strong>Binary:</strong> {metadata.get('binary_name', 'Unknown')}</p>
                <p><strong>Analysis Duration:</strong> {metadata.get('analysis_duration', 'Unknown')}</p>
                <p><strong>Total Findings:</strong> {metadata.get('total_findings', 0)}</p>
            </div>
        """
        
        for section in sections:
            html += f"""
            <div class="section">
                <div class="section-title">{section.get('title', 'Section')}</div>
                <div class="content">{self._format_content_for_html(section.get('content', ''))}</div>
            </div>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _format_content_for_html(self, content):
        """Format content for HTML display"""
        if isinstance(content, dict):
            return f"<pre>{json.dumps(content, indent=2)}</pre>"
        elif isinstance(content, list):
            html = "<ul>"
            for item in content:
                html += f"<li>{str(item)}</li>"
            html += "</ul>"
            return html
        else:
            return str(content).replace('\n', '<br>')


class ReportConfigDialog(QDialog):
    """Dialog for configuring report generation parameters"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Report Configuration")
        self.setModal(True)
        self.resize(400, 500)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the configuration dialog UI"""
        layout = QVBoxLayout(self)
        
        # General settings
        general_group = QGroupBox("General Settings")
        general_layout = QFormLayout(general_group)
        
        self.report_title = QLineEdit("Intellicrack Analysis Report")
        self.include_timestamp = QCheckBox("Include Timestamp")
        self.include_timestamp.setChecked(True)
        self.include_metadata = QCheckBox("Include Metadata")
        self.include_metadata.setChecked(True)
        
        general_layout.addRow("Report Title:", self.report_title)
        general_layout.addRow(self.include_timestamp)
        general_layout.addRow(self.include_metadata)
        
        # Section selection
        sections_group = QGroupBox("Sections to Include")
        sections_layout = QVBoxLayout(sections_group)
        
        self.section_checkboxes = {}
        sections = [
            "Binary Information", "Protection Analysis", "Vulnerability Assessment",
            "AI Analysis Results", "Exploitation Recommendations", "Technical Details",
            "Performance Metrics", "Network Analysis", "Memory Analysis", "Summary"
        ]
        
        for section in sections:
            checkbox = QCheckBox(section)
            checkbox.setChecked(True)
            self.section_checkboxes[section] = checkbox
            sections_layout.addWidget(checkbox)
        
        # Export settings
        export_group = QGroupBox("Export Settings")
        export_layout = QFormLayout(export_group)
        
        self.export_format = QComboBox()
        self.export_format.addItems(["HTML", "PDF", "JSON", "XML"])
        
        self.include_charts = QCheckBox("Include Charts/Graphs")
        self.include_charts.setChecked(True)
        self.include_raw_data = QCheckBox("Include Raw Data")
        self.include_raw_data.setChecked(False)
        
        export_layout.addRow("Export Format:", self.export_format)
        export_layout.addRow(self.include_charts)
        export_layout.addRow(self.include_raw_data)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)
        
        button_layout.addWidget(self.ok_button)
        button_layout.addWidget(self.cancel_button)
        
        # Add to main layout
        layout.addWidget(general_group)
        layout.addWidget(sections_group)
        layout.addWidget(export_group)
        layout.addLayout(button_layout)
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get the current configuration"""
        selected_sections = []
        for section, checkbox in self.section_checkboxes.items():
            if checkbox.isChecked():
                selected_sections.append(section)
        
        return {
            'title': self.report_title.text(),
            'include_timestamp': self.include_timestamp.isChecked(),
            'include_metadata': self.include_metadata.isChecked(),
            'selected_sections': selected_sections,
            'export_format': self.export_format.currentText(),
            'include_charts': self.include_charts.isChecked(),
            'include_raw_data': self.include_raw_data.isChecked()
        }


class ComprehensiveReportGenerator(QWidget):
    """
    Comprehensive Report Generator Widget
    
    Provides advanced reporting capabilities for analysis results with multiple
    export formats and customizable content sections.
    """
    
    report_generated = pyqtSignal(str, str)  # report_path, format
    export_started = pyqtSignal(str)  # format
    export_completed = pyqtSignal(str, bool)  # path, success
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.shared_context = None
        self.current_report_data = {}
        self.export_worker = None
        self.setup_ui()
        self.setup_connections()
    
    def setup_ui(self):
        """Setup the comprehensive report generator UI"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        
        title_label = QLabel("Comprehensive Report Generator")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        
        self.refresh_button = QPushButton("Refresh Data")
        self.configure_button = QPushButton("Configure Report")
        self.generate_button = QPushButton("Generate Report")
        self.export_button = QPushButton("Export Report")
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(self.refresh_button)
        header_layout.addWidget(self.configure_button)
        header_layout.addWidget(self.generate_button)
        header_layout.addWidget(self.export_button)
        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Report structure
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        structure_label = QLabel("Report Structure")
        structure_label.setFont(QFont("Arial", 10, QFont.Weight.Bold))
        
        self.structure_tree = QTreeWidget()
        self.structure_tree.setHeaderLabel("Sections")
        
        # Add default structure
        self._setup_default_structure()
        
        left_layout.addWidget(structure_label)
        left_layout.addWidget(self.structure_tree)
        
        # Right panel - Content tabs
        self.content_tabs = QTabWidget()
        
        # Preview tab
        self.preview_tab = QTextBrowser()
        self.content_tabs.addTab(self.preview_tab, "Report Preview")
        
        # Configuration tab
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)
        
        # Report settings
        settings_group = QGroupBox("Report Settings")
        settings_layout = QFormLayout(settings_group)
        
        self.report_title = QLineEdit("Comprehensive Analysis Report")
        self.export_format = QComboBox()
        self.export_format.addItems(["HTML", "PDF", "JSON", "XML"])
        
        settings_layout.addRow("Title:", self.report_title)
        settings_layout.addRow("Format:", self.export_format)
        
        # Data sources
        sources_group = QGroupBox("Data Sources")
        sources_layout = QVBoxLayout(sources_group)
        
        self.source_checkboxes = {}
        sources = [
            "Binary Analysis Results",
            "Protection Detection Results",
            "AI Analysis Insights",
            "Vulnerability Assessment",
            "Exploitation Recommendations",
            "Performance Metrics",
            "Network Analysis",
            "Memory Analysis"
        ]
        
        for source in sources:
            checkbox = QCheckBox(source)
            checkbox.setChecked(True)
            self.source_checkboxes[source] = checkbox
            sources_layout.addWidget(checkbox)
        
        config_layout.addWidget(settings_group)
        config_layout.addWidget(sources_group)
        config_layout.addStretch()
        
        self.content_tabs.addTab(config_widget, "Configuration")
        
        # Statistics tab
        stats_widget = QWidget()
        stats_layout = QVBoxLayout(stats_widget)
        
        self.stats_table = QTableWidget()
        self.stats_table.setColumnCount(2)
        self.stats_table.setHorizontalHeaderLabels(["Metric", "Value"])
        self.stats_table.horizontalHeader().setStretchLastSection(True)
        
        stats_layout.addWidget(self.stats_table)
        
        self.content_tabs.addTab(stats_widget, "Statistics")
        
        # Add panels to splitter
        splitter.addWidget(left_panel)
        splitter.addWidget(self.content_tabs)
        splitter.setSizes([200, 600])
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.status_label = QLabel("Ready")
        
        # Add to main layout
        layout.addLayout(header_layout)
        layout.addWidget(splitter)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.status_label)
        
        # Enable buttons
        self.export_button.setEnabled(False)
    
    def setup_connections(self):
        """Setup signal connections"""
        self.refresh_button.clicked.connect(self.refresh_data)
        self.configure_button.clicked.connect(self.configure_report)
        self.generate_button.clicked.connect(self.generate_report)
        self.export_button.clicked.connect(self.export_report)
        self.structure_tree.itemClicked.connect(self.on_section_selected)
        
        # Data source checkboxes
        for checkbox in self.source_checkboxes.values():
            checkbox.toggled.connect(self.on_data_source_changed)
    
    def _setup_default_structure(self):
        """Setup default report structure"""
        sections = [
            ("Executive Summary", []),
            ("Binary Information", ["Basic Properties", "File Metadata", "Architecture Details"]),
            ("Protection Analysis", ["Detected Protections", "Bypass Strategies", "Difficulty Assessment"]),
            ("Vulnerability Assessment", ["Identified Vulnerabilities", "Risk Assessment", "Exploit Recommendations"]),
            ("AI Analysis", ["Script Generation Results", "Pattern Recognition", "Behavioral Analysis"]),
            ("Technical Details", ["Disassembly Summary", "Function Analysis", "Memory Layout"]),
            ("Performance Metrics", ["Analysis Time", "Resource Usage", "Efficiency Metrics"]),
            ("Recommendations", ["Security Improvements", "Next Steps", "Additional Analysis"])
        ]
        
        for section_name, subsections in sections:
            section_item = QTreeWidgetItem([section_name])
            self.structure_tree.addTopLevelItem(section_item)
            
            for subsection in subsections:
                subsection_item = QTreeWidgetItem([subsection])
                section_item.addChild(subsection_item)
            
            section_item.setExpanded(True)
    
    def set_shared_context(self, context):
        """Set the shared application context"""
        self.shared_context = context
        if context:
            self.refresh_data()
    
    def refresh_data(self):
        """Refresh data from all analysis sources"""
        try:
            self.status_label.setText("Refreshing data...")
            
            # Collect data from various sources
            analysis_data = self._collect_analysis_data()
            protection_data = self._collect_protection_data()
            ai_data = self._collect_ai_data()
            performance_data = self._collect_performance_data()
            
            # Update statistics
            self._update_statistics({
                'analysis': analysis_data,
                'protection': protection_data,
                'ai': ai_data,
                'performance': performance_data
            })
            
            self.status_label.setText("Data refreshed successfully")
            
        except Exception as e:
            logger.error(f"Failed to refresh data: {e}")
            self.status_label.setText(f"Refresh failed: {e}")
    
    def _collect_analysis_data(self) -> Dict[str, Any]:
        """Collect data from analysis orchestrator"""
        if not self.shared_context:
            return {}
        
        try:
            analysis_orchestrator = getattr(self.shared_context, 'analysis_orchestrator', None)
            if not analysis_orchestrator:
                return {}
            
            # Get current analysis results
            return {
                'binary_info': getattr(analysis_orchestrator, 'current_binary_info', {}),
                'function_boundaries': getattr(analysis_orchestrator, 'function_boundaries', []),
                'analysis_results': getattr(analysis_orchestrator, 'analysis_results', {}),
                'processing_stats': getattr(analysis_orchestrator, 'processing_stats', {})
            }
            
        except Exception as e:
            logger.error(f"Failed to collect analysis data: {e}")
            return {}
    
    def _collect_protection_data(self) -> Dict[str, Any]:
        """Collect data from protection analysis"""
        if not self.shared_context:
            return {}
        
        try:
            protection_engine = getattr(self.shared_context, 'protection_engine', None)
            if not protection_engine:
                return {}
            
            return {
                'detected_protections': getattr(protection_engine, 'detected_protections', []),
                'bypass_strategies': getattr(protection_engine, 'bypass_strategies', {}),
                'analysis_confidence': getattr(protection_engine, 'analysis_confidence', 0.0)
            }
            
        except Exception as e:
            logger.error(f"Failed to collect protection data: {e}")
            return {}
    
    def _collect_ai_data(self) -> Dict[str, Any]:
        """Collect data from AI analysis systems"""
        if not self.shared_context:
            return {}
        
        try:
            ai_generator = getattr(self.shared_context, 'ai_script_generator', None)
            if not ai_generator:
                return {}
            
            return {
                'generated_scripts': getattr(ai_generator, 'generated_scripts', []),
                'analysis_insights': getattr(ai_generator, 'analysis_insights', {}),
                'model_performance': getattr(ai_generator, 'model_performance', {})
            }
            
        except Exception as e:
            logger.error(f"Failed to collect AI data: {e}")
            return {}
    
    def _collect_performance_data(self) -> Dict[str, Any]:
        """Collect performance and system metrics"""
        try:
            import psutil
            
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent if hasattr(psutil, 'disk_usage') else 0,
                'process_count': len(psutil.pids()),
                'uptime': datetime.datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to collect performance data: {e}")
            return {}
    
    def _update_statistics(self, data: Dict[str, Any]):
        """Update the statistics table"""
        stats = []
        
        # Analysis statistics
        analysis_data = data.get('analysis', {})
        if analysis_data:
            stats.append(("Functions Identified", len(analysis_data.get('function_boundaries', []))))
            stats.append(("Analysis Tools Used", len(analysis_data.get('analysis_results', {}))))
        
        # Protection statistics
        protection_data = data.get('protection', {})
        if protection_data:
            stats.append(("Protections Detected", len(protection_data.get('detected_protections', []))))
            stats.append(("Bypass Strategies", len(protection_data.get('bypass_strategies', {}))))
            stats.append(("Analysis Confidence", f"{protection_data.get('analysis_confidence', 0):.1%}"))
        
        # AI statistics
        ai_data = data.get('ai', {})
        if ai_data:
            stats.append(("Generated Scripts", len(ai_data.get('generated_scripts', []))))
        
        # Performance statistics
        performance_data = data.get('performance', {})
        if performance_data:
            stats.append(("CPU Usage", f"{performance_data.get('cpu_percent', 0):.1f}%"))
            stats.append(("Memory Usage", f"{performance_data.get('memory_usage', 0):.1f}%"))
        
        # Update table
        self.stats_table.setRowCount(len(stats))
        for i, (metric, value) in enumerate(stats):
            self.stats_table.setItem(i, 0, QTableWidgetItem(str(metric)))
            self.stats_table.setItem(i, 1, QTableWidgetItem(str(value)))
    
    def configure_report(self):
        """Open report configuration dialog"""
        dialog = ReportConfigDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            config = dialog.get_configuration()
            self._apply_configuration(config)
    
    def _apply_configuration(self, config: Dict[str, Any]):
        """Apply report configuration"""
        self.report_title.setText(config.get('title', ''))
        
        format_index = self.export_format.findText(config.get('export_format', 'HTML'))
        if format_index >= 0:
            self.export_format.setCurrentIndex(format_index)
        
        # Update data source selections
        selected_sections = config.get('selected_sections', [])
        for source, checkbox in self.source_checkboxes.items():
            checkbox.setChecked(source in selected_sections)
    
    def generate_report(self):
        """Generate the comprehensive report"""
        try:
            self.status_label.setText("Generating report...")
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            
            # Collect all selected data
            report_data = self._compile_report_data()
            
            # Generate report content
            report_content = self._generate_report_content(report_data)
            
            # Update preview
            self.preview_tab.setHtml(report_content)
            
            # Store report data for export
            self.current_report_data = {
                'metadata': {
                    'title': self.report_title.text(),
                    'timestamp': datetime.datetime.now().isoformat(),
                    'binary_name': report_data.get('binary_info', {}).get('name', 'Unknown'),
                    'analysis_duration': report_data.get('performance', {}).get('duration', 'Unknown'),
                    'total_findings': len(report_data.get('protections', [])) + len(report_data.get('vulnerabilities', []))
                },
                'sections': self._create_report_sections(report_data)
            }
            
            self.progress_bar.setValue(100)
            self.progress_bar.setVisible(False)
            self.export_button.setEnabled(True)
            self.status_label.setText("Report generated successfully")
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            self.progress_bar.setVisible(False)
            self.status_label.setText(f"Generation failed: {e}")
    
    def _compile_report_data(self) -> Dict[str, Any]:
        """Compile data from all selected sources"""
        data = {}
        
        for source, checkbox in self.source_checkboxes.items():
            if not checkbox.isChecked():
                continue
                
            if source == "Binary Analysis Results":
                data['analysis'] = self._collect_analysis_data()
            elif source == "Protection Detection Results":
                data['protection'] = self._collect_protection_data()
            elif source == "AI Analysis Insights":
                data['ai'] = self._collect_ai_data()
            elif source == "Performance Metrics":
                data['performance'] = self._collect_performance_data()
        
        return data
    
    def _generate_report_content(self, data: Dict[str, Any]) -> str:
        """Generate HTML report content"""
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ text-align: center; border-bottom: 2px solid #007ACC; padding-bottom: 20px; }}
                .section {{ margin: 20px 0; }}
                .section-title {{ color: #007ACC; font-size: 18px; font-weight: bold; margin-bottom: 10px; }}
                .subsection {{ margin-left: 20px; margin-bottom: 15px; }}
                .subsection-title {{ color: #0056b3; font-size: 14px; font-weight: bold; }}
                .data-table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
                .data-table th, .data-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .data-table th {{ background-color: #f2f2f2; }}
                .highlight {{ background-color: #fff3cd; padding: 5px; border-radius: 3px; }}
                .warning {{ background-color: #f8d7da; padding: 5px; border-radius: 3px; }}
                .success {{ background-color: #d4edda; padding: 5px; border-radius: 3px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{self.report_title.text()}</h1>
                <p>Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """
        
        # Add sections based on available data
        if 'analysis' in data:
            html += self._generate_analysis_section(data['analysis'])
        
        if 'protection' in data:
            html += self._generate_protection_section(data['protection'])
        
        if 'ai' in data:
            html += self._generate_ai_section(data['ai'])
        
        if 'performance' in data:
            html += self._generate_performance_section(data['performance'])
        
        html += "</body></html>"
        return html
    
    def _generate_analysis_section(self, data: Dict[str, Any]) -> str:
        """Generate analysis results section"""
        return f"""
        <div class="section">
            <div class="section-title">Binary Analysis Results</div>
            <div class="subsection">
                <div class="subsection-title">Functions Identified</div>
                <p>Total functions: {len(data.get('function_boundaries', []))}</p>
            </div>
            <div class="subsection">
                <div class="subsection-title">Analysis Tools</div>
                <p>Tools used: {', '.join(data.get('analysis_results', {}).keys())}</p>
            </div>
        </div>
        """
    
    def _generate_protection_section(self, data: Dict[str, Any]) -> str:
        """Generate protection analysis section"""
        protections = data.get('detected_protections', [])
        protection_list = ', '.join(protections) if protections else 'None detected'
        
        return f"""
        <div class="section">
            <div class="section-title">Protection Analysis</div>
            <div class="subsection">
                <div class="subsection-title">Detected Protections</div>
                <p class="{'warning' if protections else 'success'}">{protection_list}</p>
            </div>
            <div class="subsection">
                <div class="subsection-title">Analysis Confidence</div>
                <p>{data.get('analysis_confidence', 0):.1%}</p>
            </div>
        </div>
        """
    
    def _generate_ai_section(self, data: Dict[str, Any]) -> str:
        """Generate AI analysis section"""
        return f"""
        <div class="section">
            <div class="section-title">AI Analysis Results</div>
            <div class="subsection">
                <div class="subsection-title">Generated Scripts</div>
                <p>Total scripts: {len(data.get('generated_scripts', []))}</p>
            </div>
        </div>
        """
    
    def _generate_performance_section(self, data: Dict[str, Any]) -> str:
        """Generate performance metrics section"""
        return f"""
        <div class="section">
            <div class="section-title">Performance Metrics</div>
            <div class="subsection">
                <div class="subsection-title">System Resource Usage</div>
                <p>CPU: {data.get('cpu_percent', 0):.1f}%</p>
                <p>Memory: {data.get('memory_usage', 0):.1f}%</p>
            </div>
        </div>
        """
    
    def _create_report_sections(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create structured report sections"""
        sections = []
        
        if 'analysis' in data:
            sections.append({
                'title': 'Binary Analysis',
                'content': data['analysis']
            })
        
        if 'protection' in data:
            sections.append({
                'title': 'Protection Analysis',
                'content': data['protection']
            })
        
        if 'ai' in data:
            sections.append({
                'title': 'AI Analysis',
                'content': data['ai']
            })
        
        if 'performance' in data:
            sections.append({
                'title': 'Performance Metrics',
                'content': data['performance']
            })
        
        return sections
    
    def export_report(self):
        """Export the generated report"""
        if not self.current_report_data:
            QMessageBox.warning(self, "Warning", "Please generate a report first.")
            return
        
        export_format = self.export_format.currentText()
        
        # Get export path from user
        file_filter = f"{export_format} Files (*.{export_format.lower()})"
        default_name = f"intellicrack_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.{export_format.lower()}"
        
        file_path, _ = QFileDialog.getSaveFileName(
            self, f"Export {export_format} Report", default_name, file_filter
        )
        
        if not file_path:
            return
        
        # Start export worker
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Exporting {export_format} report...")
        
        self.export_worker = ReportExportWorker(
            self.current_report_data, export_format, file_path
        )
        
        self.export_worker.export_progress.connect(self.progress_bar.setValue)
        self.export_worker.export_completed.connect(self.on_export_completed)
        self.export_worker.section_completed.connect(
            lambda section: self.status_label.setText(f"Exporting: {section}")
        )
        
        self.export_worker.start()
        self.export_started.emit(export_format)
    
    def on_export_completed(self, result: str, success: bool):
        """Handle export completion"""
        self.progress_bar.setVisible(False)
        
        if success:
            self.status_label.setText(f"Export completed: {result}")
            QMessageBox.information(
                self, "Export Complete", 
                f"Report exported successfully to:\n{result}"
            )
            self.export_completed.emit(result, True)
        else:
            self.status_label.setText(f"Export failed: {result}")
            QMessageBox.critical(
                self, "Export Failed", 
                f"Failed to export report:\n{result}"
            )
            self.export_completed.emit(result, False)
    
    def on_section_selected(self, item):
        """Handle section selection in structure tree"""
        section_name = item.text(0)
        self.status_label.setText(f"Selected section: {section_name}")
    
    def on_data_source_changed(self):
        """Handle data source selection change"""
        selected_sources = []
        for source, checkbox in self.source_checkboxes.items():
            if checkbox.isChecked():
                selected_sources.append(source)
        
        self.status_label.setText(f"Selected {len(selected_sources)} data sources")