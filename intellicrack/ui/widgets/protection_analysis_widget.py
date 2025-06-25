#!/usr/bin/env python3
"""
Protection Analysis Widget

Enhanced UI widget for displaying advanced ML protection detection results.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGroupBox,
    QTableWidget, QTableWidgetItem, QProgressBar, QPushButton,
    QTextEdit, QSplitter, QTreeWidget, QTreeWidgetItem,
    QMessageBox
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon
import os
from datetime import datetime
from typing import Dict, Any, Optional


class ProtectionAnalysisWidget(QWidget):
    """Widget for displaying ML protection analysis results"""
    
    # Signals
    analysis_requested = pyqtSignal(str)  # file_path
    bypass_requested = pyqtSignal(str, str)  # file_path, protection_type
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_result = None
        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout()
        
        # Title
        title = QLabel("Protection Analysis Results")
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title.setFont(title_font)
        layout.addWidget(title)
        
        # Main content splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side - Overview
        overview_widget = self.create_overview_widget()
        splitter.addWidget(overview_widget)
        
        # Right side - Details
        details_widget = self.create_details_widget()
        splitter.addWidget(details_widget)
        
        splitter.setSizes([400, 600])
        layout.addWidget(splitter)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.analyze_btn = QPushButton("Analyze File")
        self.analyze_btn.clicked.connect(self.on_analyze_clicked)
        button_layout.addWidget(self.analyze_btn)
        
        self.bypass_btn = QPushButton("Generate Bypass Script")
        self.bypass_btn.setEnabled(False)
        self.bypass_btn.clicked.connect(self.on_bypass_clicked)
        button_layout.addWidget(self.bypass_btn)
        
        self.export_btn = QPushButton("Export Report")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.on_export_clicked)
        button_layout.addWidget(self.export_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def create_overview_widget(self) -> QWidget:
        """Create the overview panel"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Protection Summary
        summary_group = QGroupBox("Protection Summary")
        summary_layout = QVBoxLayout()
        
        # Protection type with large font
        self.protection_label = QLabel("No Analysis")
        protection_font = QFont()
        protection_font.setPointSize(16)
        protection_font.setBold(True)
        self.protection_label.setFont(protection_font)
        self.protection_label.setAlignment(Qt.AlignCenter)
        summary_layout.addWidget(self.protection_label)
        
        # Confidence meter
        confidence_layout = QHBoxLayout()
        confidence_layout.addWidget(QLabel("Confidence:"))
        self.confidence_bar = QProgressBar()
        self.confidence_bar.setRange(0, 100)
        self.confidence_bar.setValue(0)
        self.confidence_bar.setTextVisible(True)
        confidence_layout.addWidget(self.confidence_bar)
        summary_layout.addLayout(confidence_layout)
        
        # Protection category
        self.category_label = QLabel("Category: Unknown")
        summary_layout.addWidget(self.category_label)
        
        # Bypass difficulty with color coding
        self.difficulty_label = QLabel("Bypass Difficulty: Unknown")
        self.difficulty_label.setStyleSheet("padding: 5px;")
        summary_layout.addWidget(self.difficulty_label)
        
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Quick Info
        info_group = QGroupBox("Quick Information")
        self.info_tree = QTreeWidget()
        self.info_tree.setHeaderHidden(True)
        self.info_tree.setRootIsDecorated(False)
        info_group_layout = QVBoxLayout()
        info_group_layout.addWidget(self.info_tree)
        info_group.setLayout(info_group_layout)
        layout.addWidget(info_group)
        
        layout.addStretch()
        widget.setLayout(layout)
        return widget
    
    def create_details_widget(self) -> QWidget:
        """Create the details panel"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # Detection Scores
        scores_group = QGroupBox("Detection Scores")
        scores_layout = QVBoxLayout()
        
        self.scores_table = QTableWidget()
        self.scores_table.setColumnCount(3)
        self.scores_table.setHorizontalHeaderLabels(["Protection Scheme", "Score", "Status"])
        self.scores_table.horizontalHeader().setStretchLastSection(True)
        scores_layout.addWidget(self.scores_table)
        
        scores_group.setLayout(scores_layout)
        layout.addWidget(scores_group)
        
        # Features Summary
        features_group = QGroupBox("Features Summary")
        features_layout = QVBoxLayout()
        
        self.features_text = QTextEdit()
        self.features_text.setReadOnly(True)
        self.features_text.setMaximumHeight(150)
        features_layout.addWidget(self.features_text)
        
        features_group.setLayout(features_layout)
        layout.addWidget(features_group)
        
        # Recommendations
        recommendations_group = QGroupBox("Analysis & Recommendations")
        recommendations_layout = QVBoxLayout()
        
        self.recommendations_text = QTextEdit()
        self.recommendations_text.setReadOnly(True)
        recommendations_layout.addWidget(self.recommendations_text)
        
        recommendations_group.setLayout(recommendations_layout)
        layout.addWidget(recommendations_group)
        
        widget.setLayout(layout)
        return widget
    
    def update_analysis_result(self, result: Dict[str, Any]):
        """Update the display with new analysis results"""
        self.current_result = result
        
        if not result.get('success', False):
            self.protection_label.setText("Analysis Failed")
            self.protection_label.setStyleSheet("color: red;")
            self.confidence_bar.setValue(0)
            self.bypass_btn.setEnabled(False)
            self.export_btn.setEnabled(False)
            
            # Show error
            self.recommendations_text.setText(f"Error: {result.get('error', 'Unknown error')}")
            return
        
        # Update protection type
        protection_type = result.get('protection_type', 'Unknown')
        self.protection_label.setText(protection_type)
        
        # Set color based on protection
        if protection_type == "No Protection":
            self.protection_label.setStyleSheet("color: green;")
        elif protection_type in ["Denuvo", "VMProtect", "WinLicense/Themida"]:
            self.protection_label.setStyleSheet("color: red;")
        else:
            self.protection_label.setStyleSheet("color: orange;")
        
        # Update confidence
        confidence = int(result.get('confidence', 0) * 100)
        self.confidence_bar.setValue(confidence)
        
        # Color code confidence bar
        if confidence >= 80:
            self.confidence_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #4CAF50;
                }
            """)
        elif confidence >= 60:
            self.confidence_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #FF9800;
                }
            """)
        else:
            self.confidence_bar.setStyleSheet("""
                QProgressBar::chunk {
                    background-color: #F44336;
                }
            """)
        
        # Update category
        category = result.get('protection_category', 'unknown')
        self.category_label.setText(f"Category: {category.replace('_', ' ').title()}")
        
        # Update difficulty with color
        difficulty = result.get('bypass_difficulty', 'Unknown')
        self.difficulty_label.setText(f"Bypass Difficulty: {difficulty}")
        
        difficulty_colors = {
            "Trivial": "background-color: #81C784; color: black;",
            "Low": "background-color: #AED581; color: black;",
            "Medium": "background-color: #FFD54F; color: black;",
            "High": "background-color: #FF8A65; color: black;",
            "Very High": "background-color: #E57373; color: white;",
            "Extreme": "background-color: #B71C1C; color: white;"
        }
        
        style = difficulty_colors.get(difficulty, "")
        self.difficulty_label.setStyleSheet(f"padding: 5px; border-radius: 3px; {style}")
        
        # Update info tree
        self.info_tree.clear()
        
        # Add file info
        if 'file_path' in result:
            file_item = QTreeWidgetItem(["File", os.path.basename(result['file_path'])])
            self.info_tree.addTopLevelItem(file_item)
        
        # Add features summary
        if 'features_summary' in result:
            features = result['features_summary']
            
            size_item = QTreeWidgetItem(["File Size", f"{features.get('file_size', 0):,} bytes"])
            self.info_tree.addTopLevelItem(size_item)
            
            entropy_item = QTreeWidgetItem(["Entropy", f"{features.get('entropy', 0):.2f}"])
            self.info_tree.addTopLevelItem(entropy_item)
            
            if features.get('has_packing'):
                packing_item = QTreeWidgetItem(["Packing", "Detected"])
                packing_item.setForeground(0, QColor("red"))
                self.info_tree.addTopLevelItem(packing_item)
            
            if features.get('has_anti_debug'):
                antidebug_item = QTreeWidgetItem(["Anti-Debug", "Detected"])
                antidebug_item.setForeground(0, QColor("orange"))
                self.info_tree.addTopLevelItem(antidebug_item)
        
        # Update detection scores table
        self.update_scores_table(result.get('detailed_scores', {}))
        
        # Update features text
        self.update_features_text(result.get('features_summary', {}))
        
        # Update recommendations
        self.update_recommendations(result)
        
        # Enable buttons
        self.bypass_btn.setEnabled(protection_type != "No Protection")
        self.export_btn.setEnabled(True)
    
    def update_scores_table(self, scores: Dict[str, float]):
        """Update the detection scores table"""
        self.scores_table.setRowCount(0)
        
        # Sort by score
        sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        
        for scheme, score in sorted_scores:
            if score > 0.01:  # Only show relevant scores
                row = self.scores_table.rowCount()
                self.scores_table.insertRow(row)
                
                # Scheme name
                scheme_item = QTableWidgetItem(scheme.replace('_', ' ').title())
                self.scores_table.setItem(row, 0, scheme_item)
                
                # Score with color
                score_item = QTableWidgetItem(f"{score:.2f}")
                if score > 0.7:
                    score_item.setForeground(QColor("green"))
                elif score > 0.3:
                    score_item.setForeground(QColor("orange"))
                else:
                    score_item.setForeground(QColor("gray"))
                self.scores_table.setItem(row, 1, score_item)
                
                # Status
                if score > 0.7:
                    status = "High Match"
                    status_color = QColor("green")
                elif score > 0.3:
                    status = "Possible"
                    status_color = QColor("orange")
                else:
                    status = "Low"
                    status_color = QColor("gray")
                
                status_item = QTableWidgetItem(status)
                status_item.setForeground(status_color)
                self.scores_table.setItem(row, 2, status_item)
    
    def update_features_text(self, features: Dict[str, Any]):
        """Update the features summary text"""
        text = []
        
        if features.get('protection_complexity'):
            complexity = features['protection_complexity']
            text.append(f"Protection Complexity: {complexity:.2f}")
            
            if complexity > 0.8:
                text.append("• Highly complex protection scheme")
            elif complexity > 0.5:
                text.append("• Moderate protection complexity")
            else:
                text.append("• Basic protection level")
        
        if features.get('has_packing'):
            text.append("\n• Packing/Encryption detected")
            text.append("  - High entropy sections found")
            text.append("  - Code may be obfuscated")
        
        if features.get('has_anti_debug'):
            text.append("\n• Anti-debugging techniques detected")
            text.append("  - Dynamic analysis may be hindered")
        
        self.features_text.setText("\n".join(text))
    
    def update_recommendations(self, result: Dict[str, Any]):
        """Update recommendations based on analysis"""
        text = []
        
        protection = result.get('protection_type', 'Unknown')
        confidence = result.get('confidence', 0)
        difficulty = result.get('bypass_difficulty', 'Unknown')
        
        # Protection-specific recommendations
        if protection == "No Protection":
            text.append("✓ No licensing protection detected")
            text.append("• The binary appears to be unprotected")
            text.append("• Standard analysis techniques should work")
        
        elif protection == "Sentinel HASP":
            text.append("⚠ Hardware dongle protection detected")
            text.append("\nRecommended approach:")
            text.append("1. Monitor hasp_login API calls")
            text.append("2. Identify feature IDs being checked")
            text.append("3. Consider dongle emulation or API hooking")
            text.append("4. Check for network HASP scenarios")
        
        elif protection == "FlexLM/FlexNet":
            text.append("⚠ Network license manager detected")
            text.append("\nRecommended approach:")
            text.append("1. Locate license.dat or license.lic files")
            text.append("2. Analyze lmgrd daemon communication")
            text.append("3. Consider local license server emulation")
            text.append("4. Check environment variables (LM_LICENSE_FILE)")
        
        elif protection in ["WinLicense/Themida", "VMProtect"]:
            text.append("⛔ Advanced virtualization protection detected")
            text.append("\nThis is a complex protection requiring:")
            text.append("1. Advanced unpacking skills")
            text.append("2. VM architecture understanding")
            text.append("3. Anti-debugging bypass techniques")
            text.append("4. Significant time investment")
        
        elif protection == "Steam CEG":
            text.append("⚠ Steam Custom Executable Generation detected")
            text.append("\nRecommended approach:")
            text.append("1. Use CEG unwrapping tools (Steamless)")
            text.append("2. Patch Steam API checks")
            text.append("3. Consider Steam emulation for testing")
        
        elif protection == "Denuvo":
            text.append("⛔ Denuvo Anti-Tamper detected")
            text.append("\nExtremely complex protection:")
            text.append("• Multiple VM layers")
            text.append("• Hundreds of integrity checks")
            text.append("• Constantly updated")
            text.append("• Professional-level challenge")
        
        else:
            text.append(f"⚠ {protection} detected")
            text.append("\nGeneral approach:")
            text.append("1. Research protection specifics")
            text.append("2. Identify key validation points")
            text.append("3. Use appropriate tools")
        
        # Confidence notes
        text.append(f"\nDetection Confidence: {confidence:.0%}")
        if confidence < 0.7:
            text.append("• Low confidence - manual verification recommended")
        
        # Add model predictions if available
        if 'model_predictions' in result:
            text.append("\nModel Consensus:")
            predictions = result['model_predictions']
            for model, pred in predictions.items():
                text.append(f"• {model}: Class {pred}")
        
        self.recommendations_text.setText("\n".join(text))
    
    def on_analyze_clicked(self):
        """Handle analyze button click"""
        from PyQt5.QtWidgets import QFileDialog
        
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Binary to Analyze",
            "",
            "Executable Files (*.exe *.dll *.so *.dylib);;All Files (*.*)"
        )
        
        if file_path:
            self.analysis_requested.emit(file_path)
    
    def on_bypass_clicked(self):
        """Handle bypass script generation request"""
        if self.current_result:
            file_path = self.current_result.get('file_path', '')
            protection_type = self.current_result.get('protection_type', '')
            
            if file_path and protection_type:
                self.bypass_requested.emit(file_path, protection_type)
    
    def on_export_clicked(self):
        """Export analysis report"""
        if not self.current_result:
            return
        
        from PyQt5.QtWidgets import QFileDialog
        import json
        
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Analysis Report",
            "protection_analysis_report.json",
            "JSON Files (*.json);;Text Files (*.txt)"
        )
        
        if file_path:
            try:
                # Prepare report data
                report = {
                    "analysis_date": str(datetime.now()),
                    "file_analyzed": self.current_result.get('file_path', 'Unknown'),
                    "protection_detected": self.current_result.get('protection_type', 'Unknown'),
                    "confidence": self.current_result.get('confidence', 0),
                    "category": self.current_result.get('protection_category', 'unknown'),
                    "bypass_difficulty": self.current_result.get('bypass_difficulty', 'Unknown'),
                    "detailed_scores": self.current_result.get('detailed_scores', {}),
                    "features_summary": self.current_result.get('features_summary', {}),
                    "model_predictions": self.current_result.get('model_predictions', {})
                }
                
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(report, f, indent=2)
                else:
                    # Text format
                    with open(file_path, 'w') as f:
                        f.write("PROTECTION ANALYSIS REPORT\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(f"Date: {report['analysis_date']}\n")
                        f.write(f"File: {report['file_analyzed']}\n")
                        f.write(f"Protection: {report['protection_detected']}\n")
                        f.write(f"Confidence: {report['confidence']:.2%}\n")
                        f.write(f"Category: {report['category']}\n")
                        f.write(f"Difficulty: {report['bypass_difficulty']}\n")
                        f.write("\nDetailed Analysis available in JSON format.\n")
                
                QMessageBox.information(self, "Export Complete", f"Report saved to {file_path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to export report: {str(e)}")


# Integration helper
def integrate_protection_widget(main_window):
    """Helper to integrate the protection widget into the main window"""
    # This would be called from main_window.py to add the widget
    protection_widget = ProtectionAnalysisWidget(main_window)
    
    # Connect to ML system
    from ...models import get_ml_system
    ml_system = get_ml_system()
    
    def analyze_file(file_path):
        """Analyze file with ML system"""
        result = ml_system.predict(file_path)
        result['file_path'] = file_path
        protection_widget.update_analysis_result(result)
    
    protection_widget.analysis_requested.connect(analyze_file)
    
    return protection_widget