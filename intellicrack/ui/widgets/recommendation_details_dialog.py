"""
Recommendation Details Dialog

Detailed view dialog for protection bypass recommendations showing
implementation steps, code examples, educational content, and risk assessment.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QSyntaxHighlighter, QTextCharFormat, QColor
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QTextEdit, 
    QPushButton, QLabel, QGroupBox, QScrollArea, QWidget,
    QSplitter, QListWidget, QListWidgetItem, QFrame,
    QMessageBox, QFileDialog, QProgressBar, QCheckBox
)

from ...ai.protection_bypass_advisor import BypassRecommendation, BypassRisk
from ...utils.logger import get_logger

logger = get_logger(__name__)


class CodeSyntaxHighlighter(QSyntaxHighlighter):
    """Simple syntax highlighter for code examples"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_highlighting_rules()
    
    def setup_highlighting_rules(self):
        """Setup syntax highlighting rules"""
        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#0000ff"))
        keyword_format.setFontWeight(QFont.Weight.Bold)
        
        keywords = [
            "function", "var", "let", "const", "if", "else", "for", "while",
            "return", "try", "catch", "import", "from", "def", "class",
            "public", "private", "static", "void", "int", "string"
        ]
        
        self.highlighting_rules = []
        for keyword in keywords:
            pattern = f"\\b{keyword}\\b"
            rule = (pattern, keyword_format)
            self.highlighting_rules.append(rule)
        
        # Comments
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#008000"))
        comment_format.setFontItalic(True)
        
        self.highlighting_rules.extend([
            ("//.*", comment_format),
            ("/\\*.*\\*/", comment_format),
            ("#.*", comment_format)
        ])
        
        # Strings
        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#800080"))
        
        self.highlighting_rules.extend([
            ("\".*\"", string_format),
            ("'.*'", string_format)
        ])
    
    def highlightBlock(self, text):
        """Apply highlighting to text block"""
        for pattern, format_obj in self.highlighting_rules:
            import re
            for match in re.finditer(pattern, text):
                start, end = match.span()
                self.setFormat(start, end - start, format_obj)


class ImplementationStepWidget(QFrame):
    """Widget for displaying individual implementation steps"""
    
    def __init__(self, step_number: int, step_text: str, parent=None):
        super().__init__(parent)
        self.step_number = step_number
        self.step_text = step_text
        self.setup_ui()
    
    def setup_ui(self):
        """Setup step widget UI"""
        self.setFrameStyle(QFrame.Shape.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                border: 1px solid #ddd;
                border-radius: 6px;
                margin: 3px;
                padding: 8px;
                background-color: #f9f9f9;
            }
        """)
        
        layout = QHBoxLayout(self)
        
        # Step number
        number_label = QLabel(str(self.step_number))
        number_label.setFixedSize(24, 24)
        number_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        number_label.setStyleSheet("""
            QLabel {
                background-color: #007acc;
                color: white;
                border-radius: 12px;
                font-weight: bold;
                font-size: 12px;
            }
        """)
        
        # Step text
        step_label = QLabel(self.step_text)
        step_label.setWordWrap(True)
        step_label.setStyleSheet("border: none; background: transparent; color: #333;")
        
        layout.addWidget(number_label)
        layout.addWidget(step_label)
        layout.setContentsMargins(5, 5, 5, 5)


class RecommendationDetailsDialog(QDialog):
    """
    Detailed dialog for viewing recommendation implementation details
    """
    
    def __init__(self, recommendation: BypassRecommendation, parent=None):
        super().__init__(parent)
        self.recommendation = recommendation
        self.setup_ui()
        self.populate_content()
    
    def setup_ui(self):
        """Setup the dialog UI"""
        self.setWindowTitle(f"Bypass Recommendation: {self.recommendation.title}")
        self.setModal(True)
        self.resize(900, 700)
        
        layout = QVBoxLayout(self)
        
        # Header with recommendation info
        header_widget = self.create_header()
        layout.addWidget(header_widget)
        
        # Main content tabs
        self.content_tabs = QTabWidget()
        
        # Overview tab
        overview_tab = self.create_overview_tab()
        self.content_tabs.addTab(overview_tab, "Overview")
        
        # Implementation tab
        implementation_tab = self.create_implementation_tab()
        self.content_tabs.addTab(implementation_tab, "Implementation")
        
        # Code Example tab
        if self.recommendation.code_example or self.recommendation.script_template:
            code_tab = self.create_code_tab()
            self.content_tabs.addTab(code_tab, "Code Example")
        
        # Educational tab
        if self.recommendation.educational_notes:
            educational_tab = self.create_educational_tab()
            self.content_tabs.addTab(educational_tab, "Educational Content")
        
        # Security tab
        if self.recommendation.security_implications:
            security_tab = self.create_security_tab()
            self.content_tabs.addTab(security_tab, "Security & Risk")
        
        # Mitigation tab (for developers)
        if self.recommendation.mitigation_advice:
            mitigation_tab = self.create_mitigation_tab()
            self.content_tabs.addTab(mitigation_tab, "Mitigation Advice")
        
        layout.addWidget(self.content_tabs)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        if self.recommendation.script_template:
            self.save_script_btn = QPushButton("Save Script to File")
            self.save_script_btn.clicked.connect(self.save_script_to_file)
            button_layout.addWidget(self.save_script_btn)
        
        self.copy_details_btn = QPushButton("Copy All Details")
        self.copy_details_btn.clicked.connect(self.copy_all_details)
        
        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        self.close_btn.setDefault(True)
        
        button_layout.addWidget(self.copy_details_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)
        
        layout.addLayout(button_layout)
    
    def create_header(self) -> QWidget:
        """Create the header widget with recommendation summary"""
        header = QFrame()
        header.setFrameStyle(QFrame.Shape.StyledPanel)
        header.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #f0f8ff, stop:1 #e6f3ff);
                border: 1px solid #b0d4f1;
                border-radius: 8px;
                padding: 10px;
            }
        """)
        
        layout = QVBoxLayout(header)
        
        # Title and priority
        title_layout = QHBoxLayout()
        
        title_label = QLabel(self.recommendation.title)
        title_font = QFont()
        title_font.setWeight(QFont.Weight.Bold)
        title_font.setPointSize(14)
        title_label.setFont(title_font)
        
        priority_label = QLabel(f"Priority: {self.recommendation.priority.name}")
        priority_label.setStyleSheet(self._get_priority_style())
        
        confidence_label = QLabel(f"Confidence: {self.recommendation.confidence.name}")
        confidence_label.setStyleSheet(self._get_confidence_style())
        
        title_layout.addWidget(title_label)
        title_layout.addStretch()
        title_layout.addWidget(priority_label)
        title_layout.addWidget(confidence_label)
        
        layout.addLayout(title_layout)
        
        # Description
        desc_label = QLabel(self.recommendation.description)
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #333; font-size: 12px; margin: 5px 0;")
        layout.addWidget(desc_label)
        
        # Key metrics
        metrics_layout = QHBoxLayout()
        
        technique_label = QLabel(f"Technique: {self.recommendation.technique.value}")
        success_label = QLabel(f"Success Rate: {self.recommendation.success_probability:.1%}")
        time_label = QLabel(f"Estimated Time: {self.recommendation.estimated_time}")
        skill_label = QLabel(f"Skill Level: {self.recommendation.skill_level}")
        
        for label in [technique_label, success_label, time_label, skill_label]:
            label.setStyleSheet("color: #666; font-size: 11px;")
        
        metrics_layout.addWidget(technique_label)
        metrics_layout.addWidget(success_label)
        metrics_layout.addWidget(time_label)
        metrics_layout.addWidget(skill_label)
        metrics_layout.addStretch()
        
        layout.addLayout(metrics_layout)
        
        return header
    
    def create_overview_tab(self) -> QWidget:
        """Create the overview tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Target information
        if (self.recommendation.target_protection or 
            self.recommendation.target_functions or 
            self.recommendation.target_imports):
            
            target_group = QGroupBox("Target Information")
            target_layout = QVBoxLayout(target_group)
            
            if self.recommendation.target_protection:
                prot_label = QLabel(f"<b>Protection:</b> {self.recommendation.target_protection.name} ({self.recommendation.target_protection.type})")
                prot_label.setWordWrap(True)
                target_layout.addWidget(prot_label)
            
            if self.recommendation.target_functions:
                func_label = QLabel(f"<b>Target Functions:</b> {', '.join(self.recommendation.target_functions[:5])}")
                if len(self.recommendation.target_functions) > 5:
                    func_label.setText(func_label.text() + f" (+{len(self.recommendation.target_functions) - 5} more)")
                func_label.setWordWrap(True)
                target_layout.addWidget(func_label)
            
            if self.recommendation.target_imports:
                imp_label = QLabel(f"<b>Target Imports:</b> {', '.join(self.recommendation.target_imports[:5])}")
                if len(self.recommendation.target_imports) > 5:
                    imp_label.setText(imp_label.text() + f" (+{len(self.recommendation.target_imports) - 5} more)")
                imp_label.setWordWrap(True)
                target_layout.addWidget(imp_label)
            
            layout.addWidget(target_group)
        
        # Prerequisites
        if self.recommendation.prerequisites:
            prereq_group = QGroupBox("Prerequisites")
            prereq_layout = QVBoxLayout(prereq_group)
            
            for prereq in self.recommendation.prerequisites:
                prereq_label = QLabel(f"• {prereq}")
                prereq_label.setWordWrap(True)
                prereq_layout.addWidget(prereq_label)
            
            layout.addWidget(prereq_group)
        
        # Required tools
        if self.recommendation.tools_required:
            tools_group = QGroupBox("Required Tools")
            tools_layout = QVBoxLayout(tools_group)
            
            for tool in self.recommendation.tools_required:
                tool_label = QLabel(f"• {tool}")
                tool_label.setWordWrap(True)
                tools_layout.addWidget(tool_label)
            
            layout.addWidget(tools_group)
        
        # Risk assessment
        risk_group = QGroupBox("Risk Assessment")
        risk_layout = QVBoxLayout(risk_group)
        
        risk_label = QLabel(f"<b>Risk Level:</b> {self.recommendation.risk_level.name}")
        risk_label.setStyleSheet(self._get_risk_style())
        risk_layout.addWidget(risk_label)
        
        risk_desc = self._get_risk_description()
        if risk_desc:
            desc_label = QLabel(risk_desc)
            desc_label.setWordWrap(True)
            desc_label.setStyleSheet("color: #666; font-style: italic;")
            risk_layout.addWidget(desc_label)
        
        layout.addWidget(risk_group)
        
        layout.addStretch()
        return tab
    
    def create_implementation_tab(self) -> QWidget:
        """Create the implementation tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        if self.recommendation.implementation_steps:
            steps_group = QGroupBox("Implementation Steps")
            steps_layout = QVBoxLayout(steps_group)
            
            scroll_area = QScrollArea()
            scroll_widget = QWidget()
            scroll_layout = QVBoxLayout(scroll_widget)
            
            for i, step in enumerate(self.recommendation.implementation_steps, 1):
                step_widget = ImplementationStepWidget(i, step)
                scroll_layout.addWidget(step_widget)
            
            scroll_layout.addStretch()
            scroll_area.setWidget(scroll_widget)
            scroll_area.setWidgetResizable(True)
            
            steps_layout.addWidget(scroll_area)
            layout.addWidget(steps_group)
        else:
            no_steps_label = QLabel("No detailed implementation steps available for this recommendation.")
            no_steps_label.setStyleSheet("color: #666; font-style: italic; padding: 20px;")
            no_steps_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(no_steps_label)
        
        return tab
    
    def create_code_tab(self) -> QWidget:
        """Create the code example tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Code example
        if self.recommendation.code_example:
            example_group = QGroupBox("Code Example")
            example_layout = QVBoxLayout(example_group)
            
            code_edit = QTextEdit()
            code_edit.setPlainText(self.recommendation.code_example)
            code_edit.setReadOnly(True)
            code_edit.setFont(QFont("Consolas", 10))
            
            # Apply syntax highlighting
            highlighter = CodeSyntaxHighlighter(code_edit.document())
            
            example_layout.addWidget(code_edit)
            layout.addWidget(example_group)
        
        # Script template
        if self.recommendation.script_template:
            template_group = QGroupBox("Script Template")
            template_layout = QVBoxLayout(template_group)
            
            script_edit = QTextEdit()
            script_edit.setPlainText(self.recommendation.script_template)
            script_edit.setReadOnly(True)
            script_edit.setFont(QFont("Consolas", 10))
            
            # Apply syntax highlighting
            highlighter = CodeSyntaxHighlighter(script_edit.document())
            
            template_layout.addWidget(script_edit)
            layout.addWidget(template_group)
        
        return tab
    
    def create_educational_tab(self) -> QWidget:
        """Create the educational content tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        educational_group = QGroupBox("Educational Notes")
        educational_layout = QVBoxLayout(educational_group)
        
        for note in self.recommendation.educational_notes:
            note_label = QLabel(f"• {note}")
            note_label.setWordWrap(True)
            note_label.setStyleSheet("color: #333; margin: 5px 0;")
            educational_layout.addWidget(note_label)
        
        layout.addWidget(educational_group)
        
        # Learning resources (if available)
        if self.recommendation.related_cves:
            resources_group = QGroupBox("Related CVEs and Resources")
            resources_layout = QVBoxLayout(resources_group)
            
            for cve in self.recommendation.related_cves:
                cve_label = QLabel(f"• {cve}")
                cve_label.setWordWrap(True)
                resources_layout.addWidget(cve_label)
            
            layout.addWidget(resources_group)
        
        layout.addStretch()
        return tab
    
    def create_security_tab(self) -> QWidget:
        """Create the security implications tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        security_group = QGroupBox("Security Implications")
        security_layout = QVBoxLayout(security_group)
        
        for implication in self.recommendation.security_implications:
            imp_label = QLabel(f"• {implication}")
            imp_label.setWordWrap(True)
            imp_label.setStyleSheet("color: #d63384; margin: 5px 0;")
            security_layout.addWidget(imp_label)
        
        layout.addWidget(security_group)
        
        # Risk warning
        if self.recommendation.risk_level in [BypassRisk.HIGH, BypassRisk.CRITICAL]:
            warning_group = QGroupBox("⚠️ Risk Warning")
            warning_layout = QVBoxLayout(warning_group)
            warning_group.setStyleSheet("QGroupBox { border: 2px solid #dc3545; border-radius: 5px; }")
            
            warning_text = """
<b>High Risk Operation</b><br>
This bypass technique involves high-risk operations that could:
<ul>
<li>Cause application instability or crashes</li>
<li>Trigger security systems or logging</li>
<li>Leave traces of modification</li>
<li>Potentially damage the target system</li>
</ul>
<b>Only use in controlled, authorized testing environments.</b>
"""
            warning_label = QLabel(warning_text)
            warning_label.setWordWrap(True)
            warning_label.setStyleSheet("color: #721c24; background-color: #f8d7da; padding: 10px; border-radius: 3px;")
            warning_layout.addWidget(warning_label)
            
            layout.addWidget(warning_group)
        
        layout.addStretch()
        return tab
    
    def create_mitigation_tab(self) -> QWidget:
        """Create the mitigation advice tab for developers"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        intro_label = QLabel("""
<b>For Software Developers:</b><br>
The following advice can help strengthen your software against this type of bypass attack.
""")
        intro_label.setWordWrap(True)
        intro_label.setStyleSheet("color: #0f5132; background-color: #d1e7dd; padding: 10px; border-radius: 5px; margin-bottom: 10px;")
        layout.addWidget(intro_label)
        
        mitigation_group = QGroupBox("Mitigation Strategies")
        mitigation_layout = QVBoxLayout(mitigation_group)
        
        for advice in self.recommendation.mitigation_advice:
            advice_label = QLabel(f"• {advice}")
            advice_label.setWordWrap(True)
            advice_label.setStyleSheet("color: #333; margin: 5px 0;")
            mitigation_layout.addWidget(advice_label)
        
        layout.addWidget(mitigation_group)
        
        # Best practices
        best_practices = [
            "Implement defense in depth with multiple protection layers",
            "Use runtime integrity checking and anomaly detection",
            "Regular security assessments and penetration testing",
            "Keep protection mechanisms updated with latest techniques",
            "Monitor for bypass attempts in production environments"
        ]
        
        practices_group = QGroupBox("General Best Practices")
        practices_layout = QVBoxLayout(practices_group)
        
        for practice in best_practices:
            practice_label = QLabel(f"• {practice}")
            practice_label.setWordWrap(True)
            practice_label.setStyleSheet("color: #333; margin: 5px 0;")
            practices_layout.addWidget(practice_label)
        
        layout.addWidget(practices_group)
        
        layout.addStretch()
        return tab
    
    def populate_content(self):
        """Populate dialog content"""
        # Content is populated during tab creation
        pass
    
    def _get_priority_style(self) -> str:
        """Get CSS style for priority label"""
        priority_styles = {
            "CRITICAL": "background-color: #dc3545; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;",
            "HIGH": "background-color: #fd7e14; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;",
            "MEDIUM": "background-color: #ffc107; color: black; padding: 3px 8px; border-radius: 4px; font-weight: bold;",
            "LOW": "background-color: #28a745; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;",
            "INFORMATIONAL": "background-color: #6c757d; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;"
        }
        return priority_styles.get(self.recommendation.priority.name, "")
    
    def _get_confidence_style(self) -> str:
        """Get CSS style for confidence label"""
        confidence_styles = {
            "VERY_HIGH": "background-color: #28a745; color: white; padding: 3px 8px; border-radius: 4px;",
            "HIGH": "background-color: #20c997; color: white; padding: 3px 8px; border-radius: 4px;",
            "MEDIUM": "background-color: #ffc107; color: black; padding: 3px 8px; border-radius: 4px;",
            "LOW": "background-color: #fd7e14; color: white; padding: 3px 8px; border-radius: 4px;",
            "VERY_LOW": "background-color: #dc3545; color: white; padding: 3px 8px; border-radius: 4px;"
        }
        return confidence_styles.get(self.recommendation.confidence.name, "")
    
    def _get_risk_style(self) -> str:
        """Get CSS style for risk level"""
        risk_styles = {
            "MINIMAL": "color: #28a745; font-weight: bold;",
            "LOW": "color: #20c997; font-weight: bold;",
            "MEDIUM": "color: #ffc107; font-weight: bold;",
            "HIGH": "color: #fd7e14; font-weight: bold;",
            "CRITICAL": "color: #dc3545; font-weight: bold;"
        }
        return risk_styles.get(self.recommendation.risk_level.name, "")
    
    def _get_risk_description(self) -> str:
        """Get risk level description"""
        risk_descriptions = {
            BypassRisk.MINIMAL: "Very low risk operation with minimal chance of detection or damage.",
            BypassRisk.LOW: "Low risk operation that should be safe in most environments.",
            BypassRisk.MEDIUM: "Moderate risk - use caution and ensure proper authorization.",
            BypassRisk.HIGH: "High risk operation - only use in controlled testing environments.",
            BypassRisk.CRITICAL: "Critical risk - could cause system instability or trigger security responses."
        }
        return risk_descriptions.get(self.recommendation.risk_level, "")
    
    def save_script_to_file(self):
        """Save script template to file"""
        if not self.recommendation.script_template:
            QMessageBox.information(self, "No Script", "No script template available for this recommendation.")
            return
        
        try:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Bypass Script",
                f"bypass_script_{self.recommendation.recommendation_id}.js",
                "JavaScript files (*.js);;Python files (*.py);;All files (*.*)"
            )
            
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.recommendation.script_template)
                
                QMessageBox.information(self, "Script Saved", f"Bypass script saved to:\n{file_path}")
                
        except Exception as e:
            QMessageBox.critical(self, "Save Failed", f"Failed to save script:\n{e}")
            logger.error(f"Script save failed: {e}", exc_info=True)
    
    def copy_all_details(self):
        """Copy all recommendation details to clipboard"""
        try:
            details_text = f"""
BYPASS RECOMMENDATION DETAILS
=============================

Title: {self.recommendation.title}
Type: {self.recommendation.type.value}
Priority: {self.recommendation.priority.name}
Confidence: {self.recommendation.confidence.name}
Technique: {self.recommendation.technique.value}
Success Rate: {self.recommendation.success_probability:.1%}
Estimated Time: {self.recommendation.estimated_time}
Skill Level: {self.recommendation.skill_level}
Risk Level: {self.recommendation.risk_level.name}

DESCRIPTION
-----------
{self.recommendation.description}

"""
            
            if self.recommendation.target_protection:
                details_text += f"""
TARGET PROTECTION
-----------------
Name: {self.recommendation.target_protection.name}
Type: {self.recommendation.target_protection.type}
Confidence: {self.recommendation.target_protection.confidence}

"""
            
            if self.recommendation.implementation_steps:
                details_text += "IMPLEMENTATION STEPS\n"
                details_text += "-------------------\n"
                for i, step in enumerate(self.recommendation.implementation_steps, 1):
                    details_text += f"{i}. {step}\n"
                details_text += "\n"
            
            if self.recommendation.prerequisites:
                details_text += "PREREQUISITES\n"
                details_text += "-------------\n"
                for prereq in self.recommendation.prerequisites:
                    details_text += f"• {prereq}\n"
                details_text += "\n"
            
            if self.recommendation.tools_required:
                details_text += "REQUIRED TOOLS\n"
                details_text += "--------------\n"
                for tool in self.recommendation.tools_required:
                    details_text += f"• {tool}\n"
                details_text += "\n"
            
            if self.recommendation.educational_notes:
                details_text += "EDUCATIONAL NOTES\n"
                details_text += "-----------------\n"
                for note in self.recommendation.educational_notes:
                    details_text += f"• {note}\n"
                details_text += "\n"
            
            if self.recommendation.security_implications:
                details_text += "SECURITY IMPLICATIONS\n"
                details_text += "---------------------\n"
                for impl in self.recommendation.security_implications:
                    details_text += f"• {impl}\n"
                details_text += "\n"
            
            if self.recommendation.mitigation_advice:
                details_text += "MITIGATION ADVICE\n"
                details_text += "-----------------\n"
                for advice in self.recommendation.mitigation_advice:
                    details_text += f"• {advice}\n"
                details_text += "\n"
            
            if self.recommendation.code_example:
                details_text += "CODE EXAMPLE\n"
                details_text += "------------\n"
                details_text += self.recommendation.code_example + "\n\n"
            
            if self.recommendation.script_template:
                details_text += "SCRIPT TEMPLATE\n"
                details_text += "---------------\n"
                details_text += self.recommendation.script_template + "\n\n"
            
            # Copy to clipboard
            from PyQt6.QtWidgets import QApplication
            clipboard = QApplication.clipboard()
            clipboard.setText(details_text)
            
            QMessageBox.information(self, "Copied", "All recommendation details copied to clipboard.")
            
        except Exception as e:
            QMessageBox.critical(self, "Copy Failed", f"Failed to copy details:\n{e}")
            logger.error(f"Copy to clipboard failed: {e}", exc_info=True)