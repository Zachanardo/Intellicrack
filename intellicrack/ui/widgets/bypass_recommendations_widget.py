"""
Protection Bypass Recommendations Widget

Interactive widget for displaying AI-driven protection bypass recommendations
with categorized views, detailed implementation guidance, and defensive insights.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import webbrowser
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QPixmap, QIcon
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, QTreeWidget, 
    QTreeWidgetItem, QTextEdit, QPushButton, QLabel, QSplitter,
    QGroupBox, QProgressBar, QComboBox, QCheckBox, QSpinBox,
    QMessageBox, QApplication, QScrollArea, QFrame
)

from ...ai.protection_bypass_advisor import (
    ProtectionBypassAdvisor, BypassAnalysisResult, BypassRecommendation,
    RecommendationType, RecommendationPriority, ConfidenceLevel
)
from ...core.analysis.unified_model.model import UnifiedBinaryModel
from ...utils.logger import get_logger

logger = get_logger(__name__)


class BypassAnalysisWorker(QThread):
    """Worker thread for bypass analysis to prevent UI blocking"""
    
    analysis_completed = pyqtSignal(BypassAnalysisResult)
    analysis_failed = pyqtSignal(str)
    progress_updated = pyqtSignal(int, str)
    
    def __init__(self, binary_model: UnifiedBinaryModel):
        super().__init__()
        self.binary_model = binary_model
        self.bypass_advisor = ProtectionBypassAdvisor()
    
    def run(self):
        """Run bypass analysis in background thread"""
        try:
            self.progress_updated.emit(10, "Initializing bypass analysis...")
            
            self.progress_updated.emit(30, "Analyzing protection mechanisms...")
            result = self.bypass_advisor.analyze_and_recommend(self.binary_model)
            
            self.progress_updated.emit(90, "Generating recommendations...")
            
            self.progress_updated.emit(100, "Analysis complete")
            self.analysis_completed.emit(result)
            
        except Exception as e:
            logger.error(f"Bypass analysis failed: {e}", exc_info=True)
            self.analysis_failed.emit(str(e))


class RecommendationCard(QFrame):
    """Individual recommendation card widget"""
    
    def __init__(self, recommendation: BypassRecommendation, parent=None):
        super().__init__(parent)
        self.recommendation = recommendation
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the recommendation card UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                border: 1px solid #ddd;
                border-radius: 8px;
                margin: 5px;
                padding: 10px;
                background-color: #fafafa;
            }
            QFrame:hover {
                border-color: #007acc;
                background-color: #f0f8ff;
            }
        """)
        
        layout = QVBoxLayout(self)
        
        # Header with title and priority
        header_layout = QHBoxLayout()
        
        title_label = QLabel(self.recommendation.title)
        title_font = QFont()
        title_font.setWeight(QFont.Weight.Bold)
        title_font.setPointSize(12)
        title_label.setFont(title_font)
        
        priority_label = QLabel(f"Priority: {self.recommendation.priority.name}")
        priority_label.setStyleSheet(self._get_priority_style())
        
        confidence_label = QLabel(f"Confidence: {self.recommendation.confidence.name}")
        confidence_label.setStyleSheet("color: #666; font-size: 10px;")
        
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(priority_label)
        header_layout.addWidget(confidence_label)
        
        layout.addLayout(header_layout)
        
        # Description
        desc_label = QLabel(self.recommendation.description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #333; margin: 5px 0;")
        layout.addWidget(desc_label)
        
        # Technique and success info
        info_layout = QHBoxLayout()
        
        technique_label = QLabel(f"Technique: {self.recommendation.technique.value}")
        technique_label.setStyleSheet("font-size: 10px; color: #666;")
        
        success_label = QLabel(f"Success Rate: {self.recommendation.success_probability:.1%}")
        success_label.setStyleSheet("font-size: 10px; color: #666;")
        
        time_label = QLabel(f"Est. Time: {self.recommendation.estimated_time}")
        time_label.setStyleSheet("font-size: 10px; color: #666;")
        
        info_layout.addWidget(technique_label)
        info_layout.addWidget(success_label)
        info_layout.addWidget(time_label)
        info_layout.addStretch()
        
        layout.addLayout(info_layout)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        details_btn = QPushButton("View Details")
        details_btn.clicked.connect(self.show_details)
        details_btn.setStyleSheet("QPushButton { background-color: #007acc; color: white; border: none; padding: 5px 10px; border-radius: 3px; }")
        
        if self.recommendation.script_template:
            script_btn = QPushButton("Generate Script")
            script_btn.clicked.connect(self.generate_script)
            script_btn.setStyleSheet("QPushButton { background-color: #28a745; color: white; border: none; padding: 5px 10px; border-radius: 3px; }")
            button_layout.addWidget(script_btn)
        
        button_layout.addWidget(details_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
    
    def _get_priority_style(self) -> str:
        """Get CSS style for priority label"""
        priority_styles = {
            RecommendationPriority.CRITICAL: "background-color: #dc3545; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px;",
            RecommendationPriority.HIGH: "background-color: #fd7e14; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px;",
            RecommendationPriority.MEDIUM: "background-color: #ffc107; color: black; padding: 2px 6px; border-radius: 3px; font-size: 10px;",
            RecommendationPriority.LOW: "background-color: #28a745; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px;",
            RecommendationPriority.INFORMATIONAL: "background-color: #6c757d; color: white; padding: 2px 6px; border-radius: 3px; font-size: 10px;"
        }
        return priority_styles.get(self.recommendation.priority, "")
    
    def show_details(self):
        """Show detailed recommendation information"""
        from .recommendation_details_dialog import RecommendationDetailsDialog
        dialog = RecommendationDetailsDialog(self.recommendation, self)
        dialog.exec()
    
    def generate_script(self):
        """Generate bypass script based on recommendation"""
        if not self.recommendation.script_template:
            QMessageBox.information(self, "Script Generation", "No script template available for this recommendation.")
            return
        
        try:
            # Save script to file
            script_path = Path(f"bypass_script_{self.recommendation.recommendation_id}.js")
            with open(script_path, 'w') as f:
                f.write(self.recommendation.script_template)
            
            QMessageBox.information(self, "Script Generated", f"Bypass script saved to: {script_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Script Generation Failed", f"Failed to generate script: {e}")


class BypassRecommendationsWidget(QWidget):
    """
    Main widget for displaying protection bypass recommendations
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.analysis_result: Optional[BypassAnalysisResult] = None
        self.current_binary_model: Optional[UnifiedBinaryModel] = None
        self.analysis_worker: Optional[BypassAnalysisWorker] = None
        
        self.setup_ui()
        self.setup_connections()
    
    def setup_ui(self):
        """Setup the main UI layout"""
        layout = QVBoxLayout(self)
        
        # Analysis controls
        controls_group = QGroupBox("Analysis Controls")
        controls_layout = QHBoxLayout(controls_group)
        
        self.analyze_btn = QPushButton("Analyze Bypass Opportunities")
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.setStyleSheet("""
            QPushButton {
                background-color: #007acc;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """)
        
        self.export_btn = QPushButton("Export Recommendations")
        self.export_btn.setEnabled(False)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        self.status_label = QLabel("Load a binary to begin analysis")
        self.status_label.setStyleSheet("color: #666; font-style: italic;")
        
        controls_layout.addWidget(self.analyze_btn)
        controls_layout.addWidget(self.export_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self.status_label)
        
        layout.addWidget(controls_group)
        layout.addWidget(self.progress_bar)
        
        # Main content area
        self.content_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - Filters and Overview
        left_panel = self.create_left_panel()
        self.content_splitter.addWidget(left_panel)
        
        # Right panel - Recommendations
        right_panel = self.create_right_panel()
        self.content_splitter.addWidget(right_panel)
        
        self.content_splitter.setSizes([300, 700])
        layout.addWidget(self.content_splitter)
        
        # Initially hide content until analysis is complete
        self.content_splitter.setVisible(False)
    
    def create_left_panel(self) -> QWidget:
        """Create the left panel with filters and overview"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Analysis Overview
        overview_group = QGroupBox("Analysis Overview")
        overview_layout = QVBoxLayout(overview_group)
        
        self.overview_label = QLabel("No analysis performed yet")
        self.overview_label.setWordWrap(True)
        overview_layout.addWidget(self.overview_label)
        
        layout.addWidget(overview_group)
        
        # Filters
        filters_group = QGroupBox("Filters")
        filters_layout = QVBoxLayout(filters_group)
        
        # Recommendation type filter
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Type:"))
        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "All Types",
            "Immediate Bypasses",
            "Strategic Analysis", 
            "Vulnerability Exploits",
            "Tool Recommendations",
            "Educational Content"
        ])
        type_layout.addWidget(self.type_combo)
        filters_layout.addLayout(type_layout)
        
        # Priority filter
        priority_layout = QHBoxLayout()
        priority_layout.addWidget(QLabel("Min Priority:"))
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["All", "Critical", "High", "Medium", "Low"])
        priority_layout.addWidget(self.priority_combo)
        filters_layout.addLayout(priority_layout)
        
        # Confidence filter
        confidence_layout = QHBoxLayout()
        confidence_layout.addWidget(QLabel("Min Confidence:"))
        self.confidence_combo = QComboBox()
        self.confidence_combo.addItems(["All", "Very High", "High", "Medium", "Low"])
        confidence_layout.addWidget(self.confidence_combo)
        filters_layout.addLayout(confidence_layout)
        
        # Show educational content
        self.show_educational_cb = QCheckBox("Show Educational Content")
        self.show_educational_cb.setChecked(True)
        filters_layout.addWidget(self.show_educational_cb)
        
        # Show defensive insights
        self.show_defensive_cb = QCheckBox("Show Defensive Insights")
        self.show_defensive_cb.setChecked(True)
        filters_layout.addWidget(self.show_defensive_cb)
        
        layout.addWidget(filters_group)
        
        # Quick Stats
        stats_group = QGroupBox("Quick Stats")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_label = QLabel("No statistics available")
        self.stats_label.setWordWrap(True)
        stats_layout.addWidget(self.stats_label)
        
        layout.addWidget(stats_group)
        
        layout.addStretch()
        return panel
    
    def create_right_panel(self) -> QWidget:
        """Create the right panel with recommendations"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Recommendations tabs
        self.recommendations_tabs = QTabWidget()
        
        # All Recommendations tab
        self.all_scroll = QScrollArea()
        self.all_widget = QWidget()
        self.all_layout = QVBoxLayout(self.all_widget)
        self.all_scroll.setWidget(self.all_widget)
        self.all_scroll.setWidgetResizable(True)
        self.recommendations_tabs.addTab(self.all_scroll, "All Recommendations")
        
        # Immediate Bypasses tab
        self.immediate_scroll = QScrollArea()
        self.immediate_widget = QWidget()
        self.immediate_layout = QVBoxLayout(self.immediate_widget)
        self.immediate_scroll.setWidget(self.immediate_widget)
        self.immediate_scroll.setWidgetResizable(True)
        self.recommendations_tabs.addTab(self.immediate_scroll, "Immediate Bypasses")
        
        # Strategic Analysis tab
        self.strategic_scroll = QScrollArea()
        self.strategic_widget = QWidget()
        self.strategic_layout = QVBoxLayout(self.strategic_widget)
        self.strategic_scroll.setWidget(self.strategic_widget)
        self.strategic_scroll.setWidgetResizable(True)
        self.recommendations_tabs.addTab(self.strategic_scroll, "Strategic Analysis")
        
        # Vulnerability Exploits tab
        self.vuln_scroll = QScrollArea()
        self.vuln_widget = QWidget()
        self.vuln_layout = QVBoxLayout(self.vuln_widget)
        self.vuln_scroll.setWidget(self.vuln_widget)
        self.vuln_scroll.setWidgetResizable(True)
        self.recommendations_tabs.addTab(self.vuln_scroll, "Vulnerabilities")
        
        # Defensive Insights tab
        self.defensive_scroll = QScrollArea()
        self.defensive_widget = QWidget()
        self.defensive_layout = QVBoxLayout(self.defensive_widget)
        self.defensive_scroll.setWidget(self.defensive_widget)
        self.defensive_scroll.setWidgetResizable(True)
        self.recommendations_tabs.addTab(self.defensive_scroll, "Defensive Insights")
        
        layout.addWidget(self.recommendations_tabs)
        
        return panel
    
    def setup_connections(self):
        """Setup signal connections"""
        self.analyze_btn.clicked.connect(self.start_analysis)
        self.export_btn.clicked.connect(self.export_recommendations)
        
        # Filter connections
        self.type_combo.currentTextChanged.connect(self.apply_filters)
        self.priority_combo.currentTextChanged.connect(self.apply_filters)
        self.confidence_combo.currentTextChanged.connect(self.apply_filters)
        self.show_educational_cb.toggled.connect(self.apply_filters)
        self.show_defensive_cb.toggled.connect(self.apply_filters)
    
    def set_binary_model(self, binary_model: UnifiedBinaryModel):
        """Set the binary model for analysis"""
        self.current_binary_model = binary_model
        self.analyze_btn.setEnabled(True)
        self.status_label.setText(f"Ready to analyze: {binary_model.metadata.filename}")
        
        # Clear previous results
        self.analysis_result = None
        self.content_splitter.setVisible(False)
        self.export_btn.setEnabled(False)
    
    def start_analysis(self):
        """Start bypass analysis in background thread"""
        if not self.current_binary_model:
            QMessageBox.warning(self, "No Binary", "Please load a binary first")
            return
        
        # Disable controls during analysis
        self.analyze_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Starting bypass analysis...")
        
        # Start worker thread
        self.analysis_worker = BypassAnalysisWorker(self.current_binary_model)
        self.analysis_worker.analysis_completed.connect(self.analysis_completed)
        self.analysis_worker.analysis_failed.connect(self.analysis_failed)
        self.analysis_worker.progress_updated.connect(self.update_progress)
        self.analysis_worker.start()
    
    def update_progress(self, progress: int, message: str):
        """Update analysis progress"""
        self.progress_bar.setValue(progress)
        self.status_label.setText(message)
    
    def analysis_completed(self, result: BypassAnalysisResult):
        """Handle completed analysis"""
        self.analysis_result = result
        
        # Re-enable controls
        self.analyze_btn.setEnabled(True)
        self.export_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        
        # Update UI with results
        self.update_overview()
        self.update_stats()
        self.populate_recommendations()
        
        # Show content
        self.content_splitter.setVisible(True)
        
        self.status_label.setText(f"Analysis complete - {len(result.get_all_recommendations())} recommendations generated")
        
        logger.info(f"Bypass analysis completed - {len(result.get_all_recommendations())} recommendations")
    
    def analysis_failed(self, error_message: str):
        """Handle failed analysis"""
        # Re-enable controls
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Analysis failed")
        
        QMessageBox.critical(self, "Analysis Failed", f"Bypass analysis failed:\n{error_message}")
        
        logger.error(f"Bypass analysis failed: {error_message}")
    
    def update_overview(self):
        """Update the analysis overview"""
        if not self.analysis_result:
            return
        
        overview_text = f"""
<b>Binary:</b> {self.analysis_result.binary_hash[:16]}...<br>
<b>Protections Detected:</b> {self.analysis_result.total_protections}<br>
<b>Overall Difficulty:</b> {self.analysis_result.overall_bypass_difficulty.name}<br>
<b>Success Probability:</b> {self.analysis_result.overall_success_probability:.1%}<br>
<br>
<b>Recommended Approach:</b><br>
{self.analysis_result.recommended_approach}
"""
        
        self.overview_label.setText(overview_text)
    
    def update_stats(self):
        """Update quick statistics"""
        if not self.analysis_result:
            return
        
        all_recs = self.analysis_result.get_all_recommendations()
        high_conf_recs = self.analysis_result.get_high_confidence_recommendations(0.7)
        
        immediate_count = len(self.analysis_result.immediate_bypasses)
        strategic_count = len(self.analysis_result.strategic_recommendations)
        vuln_count = len(self.analysis_result.vulnerability_exploits)
        
        stats_text = f"""
<b>Total Recommendations:</b> {len(all_recs)}<br>
<b>High Confidence:</b> {len(high_conf_recs)}<br>
<br>
<b>By Category:</b><br>
• Immediate Bypasses: {immediate_count}<br>
• Strategic Analysis: {strategic_count}<br>
• Vulnerabilities: {vuln_count}<br>
<br>
<b>Protection Assessment:</b><br>
• Strengths: {len(self.analysis_result.protection_strengths)}<br>
• Weaknesses: {len(self.analysis_result.protection_weaknesses)}<br>
• Improvements: {len(self.analysis_result.improvement_suggestions)}
"""
        
        self.stats_label.setText(stats_text)
    
    def populate_recommendations(self):
        """Populate recommendation tabs"""
        if not self.analysis_result:
            return
        
        # Clear existing content
        self.clear_layouts()
        
        # Populate all recommendations
        all_recs = self.analysis_result.get_all_recommendations()
        for rec in all_recs:
            card = RecommendationCard(rec)
            self.all_layout.addWidget(card)
        
        # Populate immediate bypasses
        for rec in self.analysis_result.immediate_bypasses:
            card = RecommendationCard(rec)
            self.immediate_layout.addWidget(card)
        
        # Populate strategic recommendations
        for rec in self.analysis_result.strategic_recommendations:
            card = RecommendationCard(rec)
            self.strategic_layout.addWidget(card)
        
        # Populate vulnerability exploits
        for rec in self.analysis_result.vulnerability_exploits:
            card = RecommendationCard(rec)
            self.vuln_layout.addWidget(card)
        
        # Populate defensive insights
        self.populate_defensive_insights()
        
        # Add stretch to all layouts
        self.all_layout.addStretch()
        self.immediate_layout.addStretch()
        self.strategic_layout.addStretch()
        self.vuln_layout.addStretch()
        self.defensive_layout.addStretch()
    
    def populate_defensive_insights(self):
        """Populate defensive insights tab"""
        if not self.analysis_result:
            return
        
        # Protection strengths
        if self.analysis_result.protection_strengths:
            strengths_group = QGroupBox("Protection Strengths")
            strengths_layout = QVBoxLayout(strengths_group)
            
            for strength in self.analysis_result.protection_strengths:
                label = QLabel(f"• {strength}")
                label.setWordWrap(True)
                label.setStyleSheet("color: #28a745; margin: 2px 0;")
                strengths_layout.addWidget(label)
            
            self.defensive_layout.addWidget(strengths_group)
        
        # Protection weaknesses
        if self.analysis_result.protection_weaknesses:
            weaknesses_group = QGroupBox("Protection Weaknesses")
            weaknesses_layout = QVBoxLayout(weaknesses_group)
            
            for weakness in self.analysis_result.protection_weaknesses:
                label = QLabel(f"• {weakness}")
                label.setWordWrap(True)
                label.setStyleSheet("color: #dc3545; margin: 2px 0;")
                weaknesses_layout.addWidget(label)
            
            self.defensive_layout.addWidget(weaknesses_group)
        
        # Improvement suggestions
        if self.analysis_result.improvement_suggestions:
            improvements_group = QGroupBox("Improvement Suggestions")
            improvements_layout = QVBoxLayout(improvements_group)
            
            for suggestion in self.analysis_result.improvement_suggestions:
                label = QLabel(f"• {suggestion}")
                label.setWordWrap(True)
                label.setStyleSheet("color: #007acc; margin: 2px 0;")
                improvements_layout.addWidget(label)
            
            self.defensive_layout.addWidget(improvements_group)
    
    def clear_layouts(self):
        """Clear all recommendation layouts"""
        for layout in [self.all_layout, self.immediate_layout, self.strategic_layout, 
                      self.vuln_layout, self.defensive_layout]:
            while layout.count():
                child = layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
    
    def apply_filters(self):
        """Apply current filters to recommendations display"""
        # For now, just show/hide tabs based on checkboxes
        # Full filtering implementation would require more complex logic
        
        defensive_tab_index = self.recommendations_tabs.indexOf(self.defensive_scroll)
        if self.show_defensive_cb.isChecked():
            if defensive_tab_index == -1:
                self.recommendations_tabs.addTab(self.defensive_scroll, "Defensive Insights")
        else:
            if defensive_tab_index != -1:
                self.recommendations_tabs.removeTab(defensive_tab_index)
    
    def export_recommendations(self):
        """Export recommendations to file"""
        if not self.analysis_result:
            QMessageBox.warning(self, "No Analysis", "No analysis results to export")
            return
        
        try:
            from PyQt6.QtWidgets import QFileDialog
            
            # Get export format
            file_path, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Export Recommendations",
                f"bypass_recommendations_{self.analysis_result.binary_hash[:8]}.json",
                "JSON files (*.json);;Markdown files (*.md);;HTML files (*.html)"
            )
            
            if not file_path:
                return
            
            # Determine format from extension
            if file_path.endswith('.md'):
                format_type = "markdown"
            elif file_path.endswith('.html'):
                format_type = "html"
            else:
                format_type = "json"
            
            # Get advisor and export
            from ...ai.protection_bypass_advisor import get_protection_bypass_advisor
            advisor = get_protection_bypass_advisor()
            exported_content = advisor.export_recommendations(self.analysis_result, format_type)
            
            # Write to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(exported_content)
            
            QMessageBox.information(self, "Export Successful", f"Recommendations exported to:\n{file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", f"Failed to export recommendations:\n{e}")
            logger.error(f"Export failed: {e}", exc_info=True)