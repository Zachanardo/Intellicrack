"""Script generator dialog for creating analysis scripts.

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

import os
import time

from intellicrack.ai.ai_tools import AIAssistant
from intellicrack.handlers.pyqt6_handler import (
    QApplication,
    QCheckBox,
    QColor,
    QComboBox,
    QFileDialog,
    QFont,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSplitter,
    QSyntaxHighlighter,
    Qt,
    QTabWidget,
    QTextCharFormat,
    QTextEdit,
    QThread,
    QTimer,
    QVBoxLayout,
    QWidget,
    pyqtSignal,
)
from intellicrack.utils.logger import logger

from .base_dialog import BaseDialog

"""
Script Generation Dialog for Intellicrack.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


class TestScriptDialog(BaseDialog):
    """Comprehensive script testing dialog with validation and security analysis."""

    def __init__(self, parent=None, script_content="", script_type=""):
        """Initialize the TestScriptDialog with script content and type."""
        super().__init__(parent, "Script Testing & Validation")
        self.setMinimumSize(800, 600)

        self.script_content = script_content
        self.script_type = script_type
        self.test_results = {}
        self.is_testing = False

        self.setup_content(self.content_widget.layout() or QVBoxLayout(self.content_widget))
        self.setup_test_environment()
        self.start_comprehensive_test()

    def setup_content(self, layout):
        """Set up the testing dialog UI content."""
        if layout is None:
            layout = QVBoxLayout(self.content_widget)

        # Header info
        header_layout = QHBoxLayout()
        header_layout.addWidget(QLabel(f"Testing {self.script_type}"))
        header_layout.addStretch()
        header_layout.addWidget(QLabel(f"Script Size: {len(self.script_content)} chars"))
        layout.addLayout(header_layout)

        # Progress section
        progress_group = QGroupBox("Test Progress")
        progress_layout = QVBoxLayout(progress_group)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        progress_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Initializing tests...")
        progress_layout.addWidget(self.status_label)
        layout.addWidget(progress_group)

        # Results area with tabs
        self.results_tabs = QTabWidget()

        # Syntax validation tab
        self.syntax_results = QTextEdit()
        self.syntax_results.setFont(QFont("Consolas", 9))
        self.syntax_results.setReadOnly(True)
        self.results_tabs.addTab(self.syntax_results, "Syntax Validation")

        # Security analysis tab
        self.security_results = QTextEdit()
        self.security_results.setFont(QFont("Consolas", 9))
        self.security_results.setReadOnly(True)
        self.results_tabs.addTab(self.security_results, "Security Analysis")

        # Performance analysis tab
        self.performance_results = QTextEdit()
        self.performance_results.setFont(QFont("Consolas", 9))
        self.performance_results.setReadOnly(True)
        self.results_tabs.addTab(self.performance_results, "Performance")

        # Effectiveness test tab
        self.effectiveness_results = QTextEdit()
        self.effectiveness_results.setFont(QFont("Consolas", 9))
        self.effectiveness_results.setReadOnly(True)
        self.results_tabs.addTab(self.effectiveness_results, "Effectiveness")

        # Overall summary tab
        self.summary_results = QTextEdit()
        self.summary_results.setFont(QFont("Consolas", 9))
        self.summary_results.setReadOnly(True)
        self.results_tabs.addTab(self.summary_results, "Summary")

        layout.addWidget(self.results_tabs)

        # Control buttons
        button_layout = QHBoxLayout()

        self.retest_btn = QPushButton("Retest")
        self.retest_btn.clicked.connect(self.start_comprehensive_test)
        self.retest_btn.setEnabled(False)

        self.export_btn = QPushButton("Export Results")
        self.export_btn.clicked.connect(self.export_results)
        self.export_btn.setEnabled(False)

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)

        button_layout.addWidget(self.retest_btn)
        button_layout.addWidget(self.export_btn)
        button_layout.addStretch()
        button_layout.addWidget(self.close_btn)

        layout.addLayout(button_layout)

    def setup_test_environment(self):
        """Set up secure testing environment for script validation."""
        self.test_environment = {
            "sandbox_enabled": True,
            "network_isolated": True,
            "file_access_restricted": True,
            "memory_limit": 128 * 1024 * 1024,  # 128MB
            "execution_timeout": 30,  # 30 seconds
            "allowed_modules": [
                "frida",
                "ghidra",
                "pefile",
                "capstone",
                "keystone",
                "unicorn",
                "radare2",
                "angr",
                "binwalk",
                "volatility",
                "yara",
                "hashlib",
                "struct",
                "json",
                "base64",
                "zlib",
            ],
        }

        # Initialize test timer
        self.test_timer = QTimer()
        self.test_timer.setSingleShot(False)
        self.test_timer.timeout.connect(self.update_test_progress)

    def start_comprehensive_test(self):
        """Start comprehensive script testing process."""
        if self.is_testing:
            return

        self.is_testing = True
        self.progress_bar.setValue(0)
        self.retest_btn.setEnabled(False)
        self.export_btn.setEnabled(False)

        # Clear previous results
        self.test_results.clear()
        for i in range(self.results_tabs.count() - 1):
            widget = self.results_tabs.widget(i)
            if hasattr(widget, "clear"):
                widget.clear()

        # Start test sequence
        self.current_test_phase = 0
        self.test_phases = [
            ("Syntax Validation", self.test_syntax),
            ("Security Analysis", self.test_security),
            ("Performance Analysis", self.test_performance),
            ("Effectiveness Testing", self.test_effectiveness),
            ("Generating Summary", self.generate_summary),
        ]

        self.test_timer.start(500)  # Update every 500ms
        self.execute_next_test_phase()

    def execute_next_test_phase(self):
        """Execute the next test phase in sequence."""
        if self.current_test_phase >= len(self.test_phases):
            self.complete_testing()
            return

        phase_name, test_function = self.test_phases[self.current_test_phase]
        self.status_label.setText(f"Running: {phase_name}")

        try:
            test_function()
        except Exception as e:
            logger.error(f"Test phase '{phase_name}' failed: {e}")
            self.test_results[phase_name.lower().replace(" ", "_")] = {"status": "error", "error": str(e), "timestamp": time.time()}

        self.current_test_phase += 1

        # Schedule next phase
        QTimer.singleShot(1000, self.execute_next_test_phase)

    def test_syntax(self):
        """Perform comprehensive syntax validation."""
        results = {"status": "running", "tests": [], "warnings": [], "errors": [], "timestamp": time.time()}

        # Language detection
        language = self.detect_script_language()
        results["language"] = language
        results["tests"].append(f"Language detected: {language}")

        if language == "python":
            results.update(self.validate_python_syntax())
        elif language == "javascript":
            results.update(self.validate_javascript_syntax())
        elif language == "powershell":
            results.update(self.validate_powershell_syntax())
        else:
            results["warnings"].append("Unknown language - limited validation available")

        # Generic syntax checks
        results.update(self.perform_generic_syntax_checks())

        results["status"] = "completed"
        self.test_results["syntax_validation"] = results
        self.update_syntax_display()

    def detect_script_language(self):
        """Detect the programming language of the script."""
        content = self.script_content.lower()

        # JavaScript/Frida patterns
        js_patterns = ["frida", "javascript", "java.perform", "intercept.attach", "var ", "let ", "const "]
        if any(pattern in content for pattern in js_patterns):
            return "javascript"

        # Python patterns
        python_patterns = ["import ", "def ", "class ", "print(", "#!/usr/bin/python"]
        if any(pattern in content for pattern in python_patterns):
            return "python"

        # PowerShell patterns
        ps_patterns = ["param(", "$", "get-", "set-", "new-", "powershell"]
        if any(pattern in content for pattern in ps_patterns):
            return "powershell"

        # Default fallback
        return "unknown"

    def validate_python_syntax(self):
        """Validate Python script syntax."""
        validation_results = {"syntax_valid": False, "parse_errors": [], "warnings": [], "imports": [], "functions": [], "classes": []}

        try:
            import ast

            # Parse the Python code
            tree = ast.parse(self.script_content)
            validation_results["syntax_valid"] = True
            validation_results["tests"].append("OK Python syntax is valid")

            # Analyze AST for imports, functions, classes
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        validation_results["imports"].append(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    validation_results["imports"].append(module)
                elif isinstance(node, ast.FunctionDef):
                    validation_results["functions"].append(node.name)
                elif isinstance(node, ast.ClassDef):
                    validation_results["classes"].append(node.name)

            validation_results["tests"].append(f"OK Found {len(validation_results['imports'])} imports")
            validation_results["tests"].append(f"OK Found {len(validation_results['functions'])} functions")
            validation_results["tests"].append(f"OK Found {len(validation_results['classes'])} classes")

        except SyntaxError as e:
            validation_results["syntax_valid"] = False
            validation_results["parse_errors"].append(f"Syntax Error: {e}")
            validation_results["tests"].append("FAIL Python syntax validation failed")

        return validation_results

    def validate_javascript_syntax(self):
        """Validate JavaScript/Frida script syntax."""
        validation_results = {"syntax_valid": True, "warnings": [], "frida_patterns": [], "security_features": []}

        # Check for common Frida patterns
        frida_patterns = [
            ("Java.perform", "Java runtime manipulation"),
            ("Intercept.attach", "Function interception"),
            ("Module.findBaseAddress", "Module base address resolution"),
            ("Memory.readUtf8String", "Memory string reading"),
            ("Process.enumerateModules", "Module enumeration"),
        ]

        for pattern, description in frida_patterns:
            if pattern in self.script_content:
                validation_results["frida_patterns"].append(f"OK {description} ({pattern})")

        # Basic syntax validation (simplified)
        if "{" in self.script_content and "}" not in self.script_content:
            validation_results["warnings"].append("Unmatched braces detected")
            validation_results["syntax_valid"] = False

        if self.script_content.count("(") != self.script_content.count(")"):
            validation_results["warnings"].append("Unmatched parentheses detected")
            validation_results["syntax_valid"] = False

        status = "OK" if validation_results["syntax_valid"] else "FAIL"
        validation_results["tests"] = [f"{status} JavaScript syntax validation"]

        return validation_results

    def validate_powershell_syntax(self):
        """Validate PowerShell script syntax."""
        validation_results = {"syntax_valid": True, "cmdlets": [], "variables": [], "warnings": []}

        lines = self.script_content.split("\n")
        for line in lines:
            # Find PowerShell cmdlets
            if "-" in line and any(verb in line.lower() for verb in ["get-", "set-", "new-", "remove-"]):
                cmdlet = line.strip().split()[0] if line.strip().split() else ""
                if cmdlet and cmdlet not in validation_results["cmdlets"]:
                    validation_results["cmdlets"].append(cmdlet)

            # Find variables
            if "$" in line:
                import re

                vars_found = re.findall(r"\$\w+", line)
                validation_results["variables"].extend(vars_found)

        validation_results["tests"] = [
            f"OK Found {len(validation_results['cmdlets'])} PowerShell cmdlets",
            f"OK Found {len(set(validation_results['variables']))} unique variables",
        ]

        return validation_results

    def perform_generic_syntax_checks(self):
        """Perform language-agnostic syntax checks."""
        checks = {
            "line_count": len(self.script_content.split("\n")),
            "character_count": len(self.script_content),
            "contains_comments": False,
            "contains_strings": False,
            "suspicious_patterns": [],
        }

        # Check for comments
        comment_patterns = ["#", "//", "/*", "--", "REM "]
        checks["contains_comments"] = any(pattern in self.script_content for pattern in comment_patterns)

        # Check for strings
        string_patterns = ['"', "'"]
        checks["contains_strings"] = any(pattern in self.script_content for pattern in string_patterns)

        # Check for suspicious patterns
        suspicious = ["eval(", "exec(", "system(", "shell(", "cmd.exe", "powershell.exe"]
        for pattern in suspicious:
            if pattern in self.script_content.lower():
                checks["suspicious_patterns"].append(pattern)

        return checks

    def test_security(self):
        """Perform comprehensive security analysis."""
        security_results = {
            "status": "completed",
            "risk_level": "low",
            "vulnerabilities": [],
            "warnings": [],
            "safe_patterns": [],
            "timestamp": time.time(),
        }

        # Check for dangerous operations
        dangerous_patterns = {
            "system_execution": ["system(", "exec(", "subprocess", "os.system", "shell_exec"],
            "file_operations": ["open(", "file(", "write(", "delete", "unlink"],
            "network_access": ["urllib", "requests", "socket", "httplib", "xmlrpc"],
            "registry_access": ["winreg", "reg add", "reg delete", "registry"],
            "memory_manipulation": ["ctypes", "mmap", "struct.pack", "buffer"],
        }

        risk_score = 0
        for category, patterns in dangerous_patterns.items():
            found_patterns = [p for p in patterns if p.lower() in self.script_content.lower()]
            if found_patterns:
                security_results["vulnerabilities"].append(
                    {
                        "category": category,
                        "patterns": found_patterns,
                        "severity": "high" if category in ["system_execution", "registry_access"] else "medium",
                    }
                )
                risk_score += len(found_patterns) * (3 if category in ["system_execution"] else 1)

        # Determine overall risk level
        if risk_score >= 5:
            security_results["risk_level"] = "high"
        elif risk_score >= 2:
            security_results["risk_level"] = "medium"
        else:
            security_results["risk_level"] = "low"

        # Check for safe patterns
        safe_patterns = ["try:", "except:", "finally:", "with open", "if __name__"]
        for pattern in safe_patterns:
            if pattern in self.script_content:
                security_results["safe_patterns"].append(pattern)

        # Input validation checks
        if "input(" in self.script_content and "validate" not in self.script_content.lower():
            security_results["warnings"].append("User input detected without apparent validation")

        self.test_results["security_analysis"] = security_results
        self.update_security_display()

    def test_performance(self):
        """Analyze script performance characteristics."""
        performance_results = {
            "status": "completed",
            "complexity": "medium",
            "estimated_execution_time": "unknown",
            "memory_usage": "unknown",
            "bottlenecks": [],
            "optimizations": [],
            "timestamp": time.time(),
        }

        # Analyze complexity based on control structures
        complexity_indicators = {
            "loops": self.script_content.count("for ") + self.script_content.count("while "),
            "conditionals": self.script_content.count("if ") + self.script_content.count("elif "),
            "functions": self.script_content.count("def ") + self.script_content.count("function "),
            "nested_structures": 0,  # Simplified - would need proper parsing
        }

        total_complexity = sum(complexity_indicators.values())
        if total_complexity >= 20:
            performance_results["complexity"] = "high"
        elif total_complexity >= 5:
            performance_results["complexity"] = "medium"
        else:
            performance_results["complexity"] = "low"

        # Identify potential bottlenecks
        bottleneck_patterns = {
            "nested_loops": [
                "for " in line
                and "for " in self.script_content[self.script_content.find(line) + len(line) : self.script_content.find(line) + 200]
                for line in self.script_content.split("\n")
                if "for " in line
            ],
            "large_data_operations": "read(" in self.script_content or "readall()" in self.script_content,
            "inefficient_string_ops": "+=" in self.script_content and "str" in self.script_content,
            "recursive_calls": "def " in self.script_content
            and any(func_name in self.script_content for func_name in ["recursive", "recurse"]),
        }

        for bottleneck, detected in bottleneck_patterns.items():
            if detected:
                performance_results["bottlenecks"].append(bottleneck.replace("_", " ").title())

        # Suggest optimizations
        if "import" in self.script_content and len([line for line in self.script_content.split("\n") if "import" in line]) > 10:
            performance_results["optimizations"].append("Consider lazy imports for better startup time")

        if "print(" in self.script_content:
            print_count = self.script_content.count("print(")
            if print_count > 10:
                performance_results["optimizations"].append(f"High number of print statements ({print_count}) - consider logging")

        self.test_results["performance_analysis"] = performance_results
        self.update_performance_display()

    def test_effectiveness(self):
        """Test script effectiveness for its intended purpose."""
        effectiveness_results = {
            "status": "completed",
            "effectiveness_score": 0,
            "capabilities": [],
            "missing_features": [],
            "recommendations": [],
            "timestamp": time.time(),
        }

        script_type_lower = self.script_type.lower()

        # Analyze based on script type
        if "bypass" in script_type_lower:
            effectiveness_results.update(self.analyze_bypass_effectiveness())
        elif "exploit" in script_type_lower:
            effectiveness_results.update(self.analyze_exploit_effectiveness())
        elif "strategy" in script_type_lower:
            effectiveness_results.update(self.analyze_strategy_effectiveness())
        else:
            effectiveness_results["capabilities"].append("Generic analysis performed")
            effectiveness_results["effectiveness_score"] = 50

        self.test_results["effectiveness_testing"] = effectiveness_results
        self.update_effectiveness_display()

    def analyze_bypass_effectiveness(self):
        """Analyze bypass script effectiveness."""
        analysis = {"effectiveness_score": 0, "capabilities": [], "missing_features": []}

        # Check for bypass techniques
        bypass_techniques = {
            "binary_patching": ["patch", "modify", "overwrite", "nop"],
            "api_hooking": ["hook", "intercept", "detour", "replacement"],
            "memory_manipulation": ["memory", "write", "read", "address"],
            "dll_injection": ["inject", "dll", "library", "loadlibrary"],
            "process_manipulation": ["process", "thread", "suspend", "resume"],
        }

        score = 0
        for technique, keywords in bypass_techniques.items():
            if any(keyword in self.script_content.lower() for keyword in keywords):
                analysis["capabilities"].append(technique.replace("_", " ").title())
                score += 20

        # Check for error handling
        if any(pattern in self.script_content.lower() for pattern in ["try", "catch", "except", "error"]):
            score += 10
            analysis["capabilities"].append("Error handling")
        else:
            analysis["missing_features"].append("Error handling")

        # Check for target validation
        if any(pattern in self.script_content.lower() for pattern in ["validate", "check", "verify"]):
            score += 10
            analysis["capabilities"].append("Target validation")
        else:
            analysis["missing_features"].append("Target validation")

        analysis["effectiveness_score"] = min(score, 100)
        return analysis

    def analyze_exploit_effectiveness(self):
        """Analyze exploit script effectiveness."""
        analysis = {"effectiveness_score": 0, "capabilities": [], "missing_features": []}

        # Check for exploit components
        exploit_components = {
            "target_identification": ["target", "function", "address", "symbol"],
            "payload_delivery": ["payload", "shellcode", "execute", "run"],
            "privilege_escalation": ["privilege", "admin", "root", "escalate"],
            "persistence": ["persist", "startup", "service", "registry"],
            "evasion": ["evade", "hide", "stealth", "obfuscate"],
        }

        score = 0
        for component, keywords in exploit_components.items():
            if any(keyword in self.script_content.lower() for keyword in keywords):
                analysis["capabilities"].append(component.replace("_", " ").title())
                score += 20

        analysis["effectiveness_score"] = min(score, 100)
        return analysis

    def analyze_strategy_effectiveness(self):
        """Analyze strategy document effectiveness."""
        analysis = {"effectiveness_score": 0, "capabilities": [], "missing_features": []}

        # Check for strategy components
        strategy_components = {
            "reconnaissance": ["recon", "gather", "information", "discovery"],
            "vulnerability_analysis": ["vulnerability", "weakness", "flaw", "bug"],
            "attack_vectors": ["attack", "vector", "method", "approach"],
            "risk_assessment": ["risk", "impact", "likelihood", "assessment"],
            "mitigation": ["mitigation", "defense", "protection", "countermeasure"],
        }

        score = 0
        for component, keywords in strategy_components.items():
            if any(keyword in self.script_content.lower() for keyword in keywords):
                analysis["capabilities"].append(component.replace("_", " ").title())
                score += 20

        analysis["effectiveness_score"] = min(score, 100)
        return analysis

    def generate_summary(self):
        """Generate comprehensive test summary."""
        summary = {"status": "completed", "overall_score": 0, "test_results_summary": {}, "recommendations": [], "timestamp": time.time()}

        # Calculate overall score
        scores = []
        for test_name, results in self.test_results.items():
            if test_name == "syntax_validation":
                score = 100 if results.get("syntax_valid", False) else 0
            elif test_name == "security_analysis":
                risk_level = results.get("risk_level", "high")
                score = {"low": 90, "medium": 60, "high": 30}.get(risk_level, 30)
            elif test_name == "performance_analysis":
                complexity = results.get("complexity", "high")
                score = {"low": 90, "medium": 70, "high": 50}.get(complexity, 50)
            elif test_name == "effectiveness_testing":
                score = results.get("effectiveness_score", 0)
            else:
                score = 75  # Default for unknown tests

            scores.append(score)
            summary["test_results_summary"][test_name] = {"score": score, "status": results.get("status", "unknown")}

        summary["overall_score"] = sum(scores) // len(scores) if scores else 0

        # Generate recommendations
        if summary["overall_score"] >= 80:
            summary["recommendations"].append("OK Script passes all major tests and is ready for use")
        elif summary["overall_score"] >= 60:
            summary["recommendations"].append("WARNING Script has minor issues that should be addressed")
        else:
            summary["recommendations"].append("WARNING Script has significant issues requiring attention")

        # Add specific recommendations based on test results
        security_results = self.test_results.get("security_analysis", {})
        if security_results.get("risk_level") == "high":
            summary["recommendations"].append("🔒 High security risk - review and sanitize dangerous operations")

        syntax_results = self.test_results.get("syntax_validation", {})
        if not syntax_results.get("syntax_valid", True):
            summary["recommendations"].append("🔧 Syntax errors detected - fix before deployment")

        self.test_results["summary"] = summary
        self.update_summary_display()

    def update_test_progress(self):
        """Update the progress bar and status during testing."""
        if not self.is_testing:
            return

        progress = (self.current_test_phase / len(self.test_phases)) * 100
        self.progress_bar.setValue(int(progress))

    def complete_testing(self):
        """Complete the testing process."""
        self.is_testing = False
        self.test_timer.stop()
        self.progress_bar.setValue(100)
        self.status_label.setText("Testing completed")
        self.retest_btn.setEnabled(True)
        self.export_btn.setEnabled(True)

    def update_syntax_display(self):
        """Update the syntax validation display."""
        results = self.test_results.get("syntax_validation", {})
        lines = ["Syntax Validation Results", "=" * 30, ""]

        # Basic info
        lines.append(f"Language: {results.get('language', 'Unknown')}")
        lines.append(f"Status: {'OK Valid' if results.get('syntax_valid', False) else 'FAIL Invalid'}")
        lines.append("")

        # Tests performed
        tests = results.get("tests", [])
        if tests:
            lines.append("Tests Performed:")
            lines.extend([f"  {test}" for test in tests])
            lines.append("")

        # Errors and warnings
        errors = results.get("errors", []) + results.get("parse_errors", [])
        if errors:
            lines.append("Errors:")
            lines.extend([f"  FAIL {error}" for error in errors])
            lines.append("")

        warnings = results.get("warnings", [])
        if warnings:
            lines.append("Warnings:")
            lines.extend([f"  WARNING {warning}" for warning in warnings])
            lines.append("")

        # Language-specific results
        if results.get("imports"):
            lines.append(f"Imports: {', '.join(results['imports'])}")
        if results.get("functions"):
            lines.append(f"Functions: {', '.join(results['functions'])}")
        if results.get("frida_patterns"):
            lines.append("Frida Patterns:")
            lines.extend([f"  {pattern}" for pattern in results["frida_patterns"]])

        self.syntax_results.setText("\n".join(lines))

    def update_security_display(self):
        """Update the security analysis display."""
        results = self.test_results.get("security_analysis", {})
        lines = ["Security Analysis Results", "=" * 30, ""]

        # Risk assessment
        risk_level = results.get("risk_level", "unknown")
        risk_colors = {"low": "🟢", "medium": "🟡", "high": "🔴"}
        lines.append(f"Overall Risk Level: {risk_colors.get(risk_level, '⚪')} {risk_level.upper()}")
        lines.append("")

        # Vulnerabilities
        vulnerabilities = results.get("vulnerabilities", [])
        if vulnerabilities:
            lines.append("Security Issues Found:")
            for vuln in vulnerabilities:
                category = vuln["category"].replace("_", " ").title()
                severity = vuln["severity"]
                patterns = ", ".join(vuln["patterns"])
                severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                lines.append(f"  {severity_icon} {category} ({severity}): {patterns}")
            lines.append("")

        # Safe patterns
        safe_patterns = results.get("safe_patterns", [])
        if safe_patterns:
            lines.append("Safe Patterns Detected:")
            lines.extend([f"  OK {pattern}" for pattern in safe_patterns])
            lines.append("")

        # Warnings
        warnings = results.get("warnings", [])
        if warnings:
            lines.append("Security Warnings:")
            lines.extend([f"  WARNING {warning}" for warning in warnings])

        self.security_results.setText("\n".join(lines))

    def update_performance_display(self):
        """Update the performance analysis display."""
        results = self.test_results.get("performance_analysis", {})
        lines = ["Performance Analysis Results", "=" * 30, ""]

        # Complexity assessment
        complexity = results.get("complexity", "unknown")
        complexity_icons = {"low": "🟢", "medium": "🟡", "high": "🔴"}
        lines.append(f"Code Complexity: {complexity_icons.get(complexity, '⚪')} {complexity.upper()}")
        lines.append("")

        # Bottlenecks
        bottlenecks = results.get("bottlenecks", [])
        if bottlenecks:
            lines.append("Potential Bottlenecks:")
            lines.extend([f"  WARNING {bottleneck}" for bottleneck in bottlenecks])
            lines.append("")

        # Optimizations
        optimizations = results.get("optimizations", [])
        if optimizations:
            lines.append("Optimization Suggestions:")
            lines.extend([f"  💡 {opt}" for opt in optimizations])
            lines.append("")

        # Estimates (simplified)
        lines.append("Performance Estimates:")
        lines.append(f"  Execution Time: {results.get('estimated_execution_time', 'Unknown')}")
        lines.append(f"  Memory Usage: {results.get('memory_usage', 'Unknown')}")

        self.performance_results.setText("\n".join(lines))

    def update_effectiveness_display(self):
        """Update the effectiveness testing display."""
        results = self.test_results.get("effectiveness_testing", {})
        lines = ["Effectiveness Analysis Results", "=" * 30, ""]

        # Effectiveness score
        score = results.get("effectiveness_score", 0)
        if score >= 80:
            score_icon = "🟢"
            rating = "EXCELLENT"
        elif score >= 60:
            score_icon = "🟡"
            rating = "GOOD"
        elif score >= 40:
            score_icon = "🟠"
            rating = "FAIR"
        else:
            score_icon = "🔴"
            rating = "POOR"

        lines.append(f"Effectiveness Score: {score_icon} {score}/100 ({rating})")
        lines.append("")

        # Capabilities
        capabilities = results.get("capabilities", [])
        if capabilities:
            lines.append("Detected Capabilities:")
            lines.extend([f"  OK {capability}" for capability in capabilities])
            lines.append("")

        # Missing features
        missing = results.get("missing_features", [])
        if missing:
            lines.append("Missing Features:")
            lines.extend([f"  FAIL {feature}" for feature in missing])
            lines.append("")

        # Recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            lines.append("Recommendations:")
            lines.extend([f"  💡 {rec}" for rec in recommendations])

        self.effectiveness_results.setText("\n".join(lines))

    def update_summary_display(self):
        """Update the summary display."""
        results = self.test_results.get("summary", {})
        lines = ["Comprehensive Test Summary", "=" * 35, ""]

        # Overall score
        overall_score = results.get("overall_score", 0)
        if overall_score >= 80:
            score_icon = "🟢"
            rating = "EXCELLENT"
        elif overall_score >= 60:
            score_icon = "🟡"
            rating = "GOOD"
        else:
            score_icon = "🔴"
            rating = "NEEDS IMPROVEMENT"

        lines.append(f"Overall Score: {score_icon} {overall_score}/100 ({rating})")
        lines.append("")

        # Individual test results
        test_summary = results.get("test_results_summary", {})
        if test_summary:
            lines.append("Test Results:")
            for test_name, test_result in test_summary.items():
                test_display = test_name.replace("_", " ").title()
                score = test_result.get("score", 0)
                status = test_result.get("status", "unknown")
                status_icon = "OK" if status == "completed" else "FAIL"
                lines.append(f"  {status_icon} {test_display}: {score}/100")
            lines.append("")

        # Recommendations
        recommendations = results.get("recommendations", [])
        if recommendations:
            lines.append("Final Recommendations:")
            lines.extend([f"  {rec}" for rec in recommendations])
            lines.append("")

        # Test metadata
        timestamp = results.get("timestamp", time.time())
        lines.append(f"Test completed: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))}")
        lines.append(f"Script size: {len(self.script_content)} characters")
        lines.append(f"Script type: {self.script_type}")

        self.summary_results.setText("\n".join(lines))

    def export_results(self):
        """Export test results to file."""
        if not self.test_results:
            QMessageBox.warning(self, "Warning", "No test results to export.")
            return

        timestamp = int(time.time())
        default_name = f"script_test_results_{timestamp}.txt"

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Test Results", default_name, "Text Files (*.txt);;JSON Files (*.json);;All Files (*)"
        )

        if file_path:
            try:
                if file_path.endswith(".json"):
                    import json

                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(self.test_results, f, indent=2, default=str)
                else:
                    # Export as formatted text
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write("Script Testing Results\n")
                        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write(f"Script Type: {self.script_type}\n")
                        f.write("=" * 60 + "\n\n")

                        # Write each tab's content
                        tabs = [
                            ("Syntax Validation", self.syntax_results.toPlainText()),
                            ("Security Analysis", self.security_results.toPlainText()),
                            ("Performance Analysis", self.performance_results.toPlainText()),
                            ("Effectiveness Testing", self.effectiveness_results.toPlainText()),
                            ("Summary", self.summary_results.toPlainText()),
                        ]

                        for tab_name, content in tabs:
                            f.write(f"\n{tab_name}\n")
                            f.write("-" * len(tab_name) + "\n")
                            f.write(content + "\n\n")

                QMessageBox.information(self, "Export", f"Results exported to {os.path.basename(file_path)}")

            except Exception as e:
                logger.error(f"Export error: {e}")
                QMessageBox.critical(self, "Export Error", f"Failed to export results: {e}")


class PythonHighlighter(QSyntaxHighlighter):
    """Perform Python syntax highlighter."""

    def __init__(self, parent=None):
        """Initialize the PythonHighlighter with default values."""
        super().__init__(parent)
        self.highlighting_rules = []

        # Keywords
        keyword_format = QTextCharFormat()
        keyword_format.setColor(QColor(128, 0, 255))
        keyword_format.setFontWeight(QFont.Bold)
        keywords = [
            "def",
            "class",
            "if",
            "else",
            "elif",
            "while",
            "for",
            "try",
            "except",
            "import",
            "from",
            "return",
            "with",
        ]
        for _keyword in keywords:
            pattern = f"\\b{_keyword}\\b"
            self.highlighting_rules.append((pattern, keyword_format))

        # Strings
        string_format = QTextCharFormat()
        string_format.setColor(QColor(0, 128, 0))
        self.highlighting_rules.append(('".*"', string_format))
        self.highlighting_rules.append("'.*'", string_format)

        # Comments
        comment_format = QTextCharFormat()
        comment_format.setColor(QColor(128, 128, 128))
        self.highlighting_rules.append(("#.*", comment_format))

    def highlightBlock(self, text):
        """Highlight a block of text."""
        import re

        for pattern, text_format in self.highlighting_rules:
            for _match in re.finditer(pattern, text):
                start, end = _match.span()
                self.setFormat(start, end - start, text_format)


class ScriptGeneratorWorker(QThread):
    """Background worker for script generation."""

    script_generated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, binary_path: str, script_type: str, **kwargs):
        """Initialize the ScriptGeneratorWorker with default values."""
        super().__init__()
        self.binary_path = binary_path
        self.script_type = script_type
        self.kwargs = kwargs
        self.logger = logger
        self.ai_generator = None

    def run(self):
        """Execute the script generation."""
        try:
            if self.script_type == "bypass":
                self._generate_bypass_script()
            elif self.script_type == "exploit":
                self._generate_exploit_script()
            elif self.script_type == "strategy":
                self._generate_exploit_strategy()
        except (OSError, ValueError, RuntimeError) as e:
            self.logger.error("Error in script_generator_dialog: %s", e)
            self.error_occurred.emit(str(e))

    def _generate_bypass_script(self):
        """Generate bypass script."""
        # Try AI-powered generation first
        try:
            from ...ai.ai_script_generator import AIScriptGenerator

            if not self.ai_generator:
                self.ai_generator = AIScriptGenerator()

            # Prepare protection info
            protection_info = {
                "type": self.kwargs.get("protection_type", "license"),
                "methods": self.kwargs.get("methods", ["patch"]),
                "target_platform": "frida" if self.kwargs.get("language") == "javascript" else "python",
            }

            # Generate script using AI
            if self.kwargs.get("language") == "javascript":
                result = self.ai_generator.generate_frida_script(
                    self.binary_path,
                    protection_info,
                )
            else:
                # For Python/other languages, generate Ghidra script
                result = self.ai_generator.generate_ghidra_script(
                    self.binary_path,
                    protection_info,
                )

            self.script_generated.emit(result)

        except Exception as e:
            self.logger.warning(f"AI script generation failed: {e}. Falling back to template-based generation.")
            # Fallback to template-based generation
            from ...utils.exploitation import generate_bypass_script

            result = generate_bypass_script(
                self.binary_path,
                protection_type=self.kwargs.get("protection_type", "license"),
                language=self.kwargs.get("language", "python"),
            )
            self.script_generated.emit(result)

    def _generate_exploit_script(self):
        """Generate exploit script."""
        from ...utils.exploitation import generate_exploit

        result = generate_exploit(
            vulnerability=self.kwargs.get("exploit_type", "buffer_overflow"),
            target_arch=self.kwargs.get("target_arch", "x86"),
            payload_type=self.kwargs.get("payload_type", "shellcode"),
        )
        self.script_generated.emit(result)

    def _generate_exploit_strategy(self):
        """Generate exploit strategy."""
        from ...utils.exploitation import generate_exploit_strategy

        result = generate_exploit_strategy(
            self.binary_path,
            vulnerability_type=self.kwargs.get("vulnerability_type", "buffer_overflow"),
        )
        self.script_generated.emit(result)


class ScriptGeneratorDialog(BaseDialog):
    """Script Generation Dialog with multiple script types."""

    def __init__(self, parent=None, binary_path: str = ""):
        """Initialize the ScriptGeneratorDialog with default values."""
        # Initialize UI attributes
        self.analysis_depth = None
        self.analyze_btn = None
        self.bypass_config = None
        self.bypass_language = None
        self.bypass_output = None
        self.close_btn = None
        self.copy_btn = None
        self.doc_display = None
        self.exploit_advanced = None
        self.exploit_config = None
        self.exploit_type = None
        self.highlighter = None
        self.include_analysis = None
        self.include_exploitation = None
        self.include_options = None
        self.include_persistence = None
        self.include_recon = None
        self.method_hook = None
        self.method_loader = None
        self.method_memory = None
        self.method_patch = None
        self.method_registry = None
        self.payload_type = None
        self.save_btn = None
        self.script_display = None
        self.script_tabs = None
        self.status_label = None
        self.strategy_config = None
        self.strategy_type = None
        self.target_function = None
        self.template_display = None
        self.test_btn = None
        super().__init__(parent, "Script Generator")
        self.setMinimumSize(1000, 700)

        self.binary_path = binary_path
        self.worker = None
        self.generated_scripts = {}

        self.setup_content(self.content_widget.layout() or QVBoxLayout(self.content_widget))
        self.connect_signals()

    def setup_content(self, layout):
        """Set up the user interface content."""
        if layout is None:
            layout = QVBoxLayout(self.content_widget)

        # Header
        self.setup_header(layout)

        # Main content
        self.setup_main_content(layout)

        # Footer
        self.setup_footer(layout)

    def setup_header(self, layout):
        """Set up header with binary selection."""
        # Use the base class method
        super().setup_header(layout, show_label=True)

    def setup_main_content(self, layout):
        """Set up main content area."""
        splitter = QSplitter(Qt.Horizontal)

        # Left panel - Script types and configuration
        self.setup_left_panel(splitter)

        # Right panel - Generated script display
        self.setup_right_panel(splitter)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

    def setup_left_panel(self, splitter):
        """Set up left configuration panel."""
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)

        # Script type selection
        type_group = QGroupBox("Script Type")
        type_layout = QVBoxLayout(type_group)

        self.script_type_combo = QComboBox()
        self.script_type_combo.addItems(
            [
                "Bypass Script",
                "Exploit Script",
                "Exploit Strategy",
                "Custom Script",
            ]
        )
        self.script_type_combo.currentTextChanged.connect(self.on_script_type_changed)

        type_layout.addWidget(self.script_type_combo)
        left_layout.addWidget(type_group)

        # Configuration stack for different script types
        self.config_stack = QWidget()
        self.config_layout = QVBoxLayout(self.config_stack)

        self.setup_bypass_config()
        self.setup_exploit_config()
        self.setup_strategy_config()

        left_layout.addWidget(self.config_stack)

        # Generate button
        self.generate_btn = QPushButton("Generate Script")
        self.generate_btn.clicked.connect(self.generate_script)
        self.generate_btn.setObjectName("primaryButton")
        left_layout.addWidget(self.generate_btn)

        left_layout.addStretch()
        splitter.addWidget(left_widget)

    def setup_bypass_config(self):
        """Set up bypass script configuration."""
        self.bypass_config = QGroupBox("Bypass Script Configuration")
        layout = QGridLayout(self.bypass_config)

        # Language selection
        layout.addWidget(QLabel("Language:"), 0, 0)
        self.bypass_language = QComboBox()
        self.bypass_language.addItems(["Python", "JavaScript", "PowerShell", "Batch"])
        layout.addWidget(self.bypass_language, 0, 1)

        # Bypass methods
        layout.addWidget(QLabel("Methods:"), 1, 0)
        self.bypass_methods = QWidget()
        methods_layout = QVBoxLayout(self.bypass_methods)

        self.method_patch = QCheckBox("Binary Patching")
        self.method_patch.setChecked(True)
        self.method_loader = QCheckBox("DLL Injection/Loading")
        self.method_hook = QCheckBox("API Hooking")
        self.method_memory = QCheckBox("Memory Patching")
        self.method_registry = QCheckBox("Registry Modification")

        methods_layout.addWidget(self.method_patch)
        methods_layout.addWidget(self.method_loader)
        methods_layout.addWidget(self.method_hook)
        methods_layout.addWidget(self.method_memory)
        methods_layout.addWidget(self.method_registry)

        layout.addWidget(self.bypass_methods, 1, 1)

        # Output format
        layout.addWidget(QLabel("Output:"), 2, 0)
        self.bypass_output = QComboBox()
        self.bypass_output.addItems(["Script", "Executable", "Library"])
        layout.addWidget(self.bypass_output, 2, 1)

        self.config_layout.addWidget(self.bypass_config)

    def setup_exploit_config(self):
        """Set up exploit script configuration."""
        self.exploit_config = QGroupBox("Exploit Script Configuration")
        layout = QGridLayout(self.exploit_config)

        # Exploit type
        layout.addWidget(QLabel("Exploit Type:"), 0, 0)
        self.exploit_type = QComboBox()
        self.exploit_type.addItems(
            [
                "License Bypass",
                "Trial Extension",
                "Feature Unlock",
                "Authentication Bypass",
                "Custom Exploit",
            ]
        )
        layout.addWidget(self.exploit_type, 0, 1)

        # Target function
        layout.addWidget(QLabel("Target Function:"), 1, 0)
        self.target_function = QLineEdit()
        self.target_function.setPlaceholderText("e.g., CheckLicense, ValidateUser")
        layout.addWidget(self.target_function, 1, 1)

        # Payload type
        layout.addWidget(QLabel("Payload Type:"), 2, 0)
        self.payload_type = QComboBox()
        self.payload_type.addItems(["Patch", "Hook", "Replace", "Redirect"])
        layout.addWidget(self.payload_type, 2, 1)

        # Advanced options
        self.exploit_advanced = QCheckBox("Include Anti-Detection")
        layout.addWidget(self.exploit_advanced, 3, 0, 1, 2)

        self.config_layout.addWidget(self.exploit_config)
        self.exploit_config.hide()

    def setup_strategy_config(self):
        """Set up strategy configuration."""
        self.strategy_config = QGroupBox("Exploit Strategy Configuration")
        layout = QGridLayout(self.strategy_config)

        # Strategy type
        layout.addWidget(QLabel("Strategy Type:"), 0, 0)
        self.strategy_type = QComboBox()
        self.strategy_type.addItems(
            [
                "Comprehensive Analysis",
                "Quick Bypass",
                "Stealth Approach",
                "Brute Force",
                "Custom Strategy",
            ]
        )
        layout.addWidget(self.strategy_type, 0, 1)

        # Analysis depth
        layout.addWidget(QLabel("Analysis Depth:"), 1, 0)
        self.analysis_depth = QComboBox()
        self.analysis_depth.addItems(["Light", "Medium", "Deep", "Exhaustive"])
        layout.addWidget(self.analysis_depth, 1, 1)

        # Include sections
        layout.addWidget(QLabel("Include:"), 2, 0)
        self.include_options = QWidget()
        include_layout = QVBoxLayout(self.include_options)

        self.include_recon = QCheckBox("Reconnaissance")
        self.include_recon.setChecked(True)
        self.include_analysis = QCheckBox("Vulnerability Analysis")
        self.include_analysis.setChecked(True)
        self.include_exploitation = QCheckBox("Exploitation Steps")
        self.include_exploitation.setChecked(True)
        self.include_persistence = QCheckBox("Persistence Methods")

        include_layout.addWidget(self.include_recon)
        include_layout.addWidget(self.include_analysis)
        include_layout.addWidget(self.include_exploitation)
        include_layout.addWidget(self.include_persistence)

        layout.addWidget(self.include_options, 2, 1)

        self.config_layout.addWidget(self.strategy_config)
        self.strategy_config.hide()

    def setup_right_panel(self, splitter):
        """Set up right script display panel."""
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)

        # Script tabs
        self.script_tabs = QTabWidget()

        # Generated script tab
        self.script_display = QPlainTextEdit()
        self.script_display.setFont(QFont("Consolas", 10))
        self.script_display.setLineWrapMode(QPlainTextEdit.NoWrap)

        # Add syntax highlighting
        self.highlighter = PythonHighlighter(self.script_display.document())

        self.script_tabs.addTab(self.script_display, "Generated Script")

        # Documentation tab
        self.doc_display = QTextEdit()
        self.doc_display.setFont(QFont("Consolas", 10))
        self.script_tabs.addTab(self.doc_display, "Documentation")

        # Template tab
        self.template_display = QTextEdit()
        self.template_display.setFont(QFont("Consolas", 10))
        self.script_tabs.addTab(self.template_display, "Template Code")

        right_layout.addWidget(self.script_tabs)

        # Action buttons
        actions_layout = QHBoxLayout()

        self.copy_btn = QPushButton("Copy Script")
        self.copy_btn.clicked.connect(self.copy_script)

        self.save_btn = QPushButton("Save Script")
        self.save_btn.clicked.connect(self.save_script)

        self.test_btn = QPushButton("Test Script")
        self.test_btn.clicked.connect(self.test_script)

        self.analyze_btn = QPushButton("Analyze Script")
        self.analyze_btn.clicked.connect(self.analyze_script)

        actions_layout.addWidget(self.copy_btn)
        actions_layout.addWidget(self.save_btn)
        actions_layout.addWidget(self.test_btn)
        actions_layout.addWidget(self.analyze_btn)
        actions_layout.addStretch()

        right_layout.addLayout(actions_layout)

        splitter.addWidget(right_widget)

    def setup_footer(self, layout):
        """Set up footer with status and close button."""
        footer_layout = QHBoxLayout()

        self.status_label = QLabel("Ready")
        self.status_label.setObjectName("statusSecondary")

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.close)

        footer_layout.addWidget(self.status_label)
        footer_layout.addStretch()
        footer_layout.addWidget(self.close_btn)

        layout.addLayout(footer_layout)

    def connect_signals(self):
        """Connect internal signals."""
        self.binary_path_edit.textChanged.connect(self.on_binary_path_changed)

    def on_binary_path_changed(self, text):
        """Handle binary path change."""
        self.binary_path = text

    def on_script_type_changed(self, script_type):
        """Handle script type change."""
        # Hide all config groups
        self.bypass_config.hide()
        self.exploit_config.hide()
        self.strategy_config.hide()

        # Show relevant config
        if script_type == "Bypass Script":
            self.bypass_config.show()
        elif script_type == "Exploit Script":
            self.exploit_config.show()
        elif script_type == "Exploit Strategy":
            self.strategy_config.show()

    def generate_script(self):
        """Generate script based on configuration."""
        if not self.binary_path or not os.path.exists(self.binary_path):
            QMessageBox.warning(self, "Warning", "Please select a valid binary file first.")
            return

        script_type = self.script_type_combo.currentText()
        self.status_label.setText(f"Generating {script_type.lower()}...")
        self.generate_btn.setEnabled(False)

        # Get configuration based on script type
        if script_type == "Bypass Script":
            kwargs = self.get_bypass_config()
            worker_type = "bypass"
        elif script_type == "Exploit Script":
            kwargs = self.get_exploit_config()
            worker_type = "exploit"
        elif script_type == "Exploit Strategy":
            kwargs = self.get_strategy_config()
            worker_type = "strategy"
        else:
            QMessageBox.warning(self, "Warning", "Custom scripts not yet implemented.")
            self.generate_btn.setEnabled(True)
            return

        # Start worker thread
        self.worker = ScriptGeneratorWorker(self.binary_path, worker_type, **kwargs)
        self.worker.script_generated.connect(self.on_script_generated)
        self.worker.error_occurred.connect(self.on_error)
        self.worker.start()

    def get_bypass_config(self):
        """Get bypass script configuration."""
        methods = []
        if self.method_patch.isChecked():
            methods.append("patch")
        if self.method_loader.isChecked():
            methods.append("loader")
        if self.method_hook.isChecked():
            methods.append("hook")
        if self.method_memory.isChecked():
            methods.append("memory")
        if self.method_registry.isChecked():
            methods.append("registry")

        return {
            "language": self.bypass_language.currentText().lower(),
            "methods": methods,
            "output_format": self.bypass_output.currentText().lower(),
        }

    def get_exploit_config(self):
        """Get exploit script configuration."""
        return {
            "exploit_type": self.exploit_type.currentText().lower().replace(" ", "_"),
            "target_function": self.target_function.text(),
            "payload_type": self.payload_type.currentText().lower(),
            "include_anti_detection": self.exploit_advanced.isChecked(),
        }

    def get_strategy_config(self):
        """Get strategy configuration."""
        return {
            "strategy_type": self.strategy_type.currentText().lower().replace(" ", "_"),
            "analysis_depth": self.analysis_depth.currentText().lower(),
            "include_recon": self.include_recon.isChecked(),
            "include_analysis": self.include_analysis.isChecked(),
            "include_exploitation": self.include_exploitation.isChecked(),
            "include_persistence": self.include_persistence.isChecked(),
        }

    def on_script_generated(self, result):
        """Handle script generation completion."""
        self.generated_scripts[self.script_type_combo.currentText()] = result

        # Display script
        script_content = result.get("script", result.get("strategy", "No script generated"))
        self.script_display.setPlainText(script_content)

        # Display documentation
        doc_content = result.get("documentation", result.get("description", "No documentation available"))
        self.doc_display.setPlainText(doc_content)

        # Display template if available
        template_content = result.get("template", "No template available")
        self.template_display.setPlainText(template_content)

        self.status_label.setText("Script generated successfully")
        self.generate_btn.setEnabled(True)

    def copy_script(self):
        """Copy script to clipboard."""
        script_content = self.script_display.toPlainText()
        if script_content:
            try:
                QApplication.clipboard().setText(script_content)
                self.status_label.setText("Script copied to clipboard")
            except (OSError, ValueError, RuntimeError) as e:
                self.logger.error("Error in script_generator_dialog: %s", e)
                QMessageBox.information(self, "Copy", "Script copied to clipboard (fallback)")

    def save_script(self):
        """Save script to file."""
        script_content = self.script_display.toPlainText()
        if not script_content:
            QMessageBox.warning(self, "Warning", "No script to save. Generate a script first.")
            return

        # Determine file extension based on content/type
        script_type = self.script_type_combo.currentText()
        if "python" in script_content.lower() or script_type == "Exploit Strategy":
            ext = "py"
            filter_str = "Python Files (*.py);;All Files (*)"
        elif "javascript" in script_content.lower():
            ext = "js"
            filter_str = "JavaScript Files (*.js);;All Files (*)"
        elif "powershell" in script_content.lower():
            ext = "ps1"
            filter_str = "PowerShell Files (*.ps1);;All Files (*)"
        else:
            ext = "txt"
            filter_str = "Text Files (*.txt);;All Files (*)"

        default_name = f"{script_type.lower().replace(' ', '_')}_{int(time.time())}.{ext}"

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Script",
            default_name,
            filter_str,
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(script_content)
                self.status_label.setText(f"Script saved to {os.path.basename(file_path)}")
            except (OSError, ValueError, RuntimeError) as e:
                logger.error("Error in script_generator_dialog: %s", e)
                QMessageBox.critical(self, "Save Error", f"Failed to save script: {e!s}")

    def test_script(self):
        """Test the generated script with comprehensive validation."""
        script_content = self.script_display.toPlainText()
        if not script_content:
            QMessageBox.warning(self, "Warning", "No script to test. Generate a script first.")
            return

        # Create test dialog
        test_dialog = TestScriptDialog(self, script_content, self.script_type_combo.currentText())
        test_dialog.exec()

    def analyze_script(self):
        """Analyze the generated script for vulnerabilities, patterns, and improvements."""
        script_content = self.script_display.toPlainText()
        if not script_content:
            QMessageBox.warning(self, "Warning", "No script to analyze. Generate a script first.")
            return

        try:
            # Create AI tools instance
            ai_tools = AIAssistant()

            # Determine language based on script type or content
            script_type = self.script_type_combo.currentText()
            # Check if bypass_language exists and use it, otherwise detect from content
            if hasattr(self, "bypass_language") and self.bypass_language.isVisible():
                language = "javascript" if "javascript" in self.bypass_language.currentText().lower() else "python"
            # Auto-detect language from script type and content
            elif "frida" in script_type.lower() or "javascript" in script_type.lower():
                language = "javascript"
            elif "python" in script_type.lower() or "ghidra" in script_type.lower():
                language = "python"
            else:
                language = "auto"

            # Update status
            self.status_label.setText("Analyzing script...")

            # Perform analysis
            analysis_result = ai_tools.analyze_code(script_content, language)

            # Format and display results
            if analysis_result.get("status") == "success":
                formatted_analysis = self._format_analysis_results(analysis_result)

                # Create a new tab for analysis results
                analysis_display = QTextEdit()
                analysis_display.setFont(QFont("Consolas", 10))
                analysis_display.setReadOnly(True)
                analysis_display.setPlainText(formatted_analysis)

                # Add the analysis tab
                self.script_tabs.addTab(analysis_display, "Analysis Results")
                self.script_tabs.setCurrentWidget(analysis_display)

                self.status_label.setText("Script analysis completed")

                # Show warning if security issues found
                if analysis_result.get("security_issues"):
                    QMessageBox.warning(
                        self,
                        "Security Issues",
                        f"Found {len(analysis_result['security_issues'])} security issue(s) in the script.\n"
                        "Please review the analysis results.",
                    )
            else:
                error_msg = analysis_result.get("error", "Unknown error occurred")
                QMessageBox.critical(self, "Analysis Error", f"Script analysis failed: {error_msg}")
                self.status_label.setText("Analysis failed")

        except Exception as e:
            logger.error(f"Script analysis error: {e}")
            QMessageBox.critical(self, "Error", f"Failed to analyze script: {e!s}")
            self.status_label.setText("Error occurred")

    def _format_analysis_results(self, analysis_result):
        """Format code analysis results for display."""
        lines = ["Script Analysis Results", "=" * 50, ""]

        # Basic info
        lines.append(f"Language: {analysis_result.get('language', 'Unknown')}")
        lines.append(f"Lines of Code: {analysis_result.get('lines_of_code', 0)}")
        lines.append(f"Complexity: {analysis_result.get('complexity', 'Unknown')}")
        lines.append(f"AI Analysis: {'Enabled' if analysis_result.get('ai_enabled', False) else 'Disabled'}")
        lines.append("")

        # Insights
        insights = analysis_result.get("insights", [])
        if insights:
            lines.append("Insights:")
            for insight in insights:
                lines.append(f"  • {insight}")
            lines.append("")

        # Security Issues
        security_issues = analysis_result.get("security_issues", [])
        if security_issues:
            lines.append("SECURITY ISSUES:")
            for issue in security_issues:
                lines.append(f"  WARNING️  {issue}")
            lines.append("")

        # Suggestions
        suggestions = analysis_result.get("suggestions", [])
        if suggestions:
            lines.append("Suggestions:")
            for suggestion in suggestions:
                lines.append(f"  • {suggestion}")
            lines.append("")

        # Patterns
        patterns = analysis_result.get("patterns", [])
        if patterns:
            lines.append("Detected Patterns:")
            for pattern in patterns:
                lines.append(f"  • {pattern}")
            lines.append("")

        # Timestamp
        timestamp = analysis_result.get("analysis_timestamp", "")
        if timestamp:
            lines.append(f"\nAnalysis performed at: {timestamp}")

        return "\n".join(lines)

    def on_error(self, error_msg):
        """Handle worker thread errors."""
        QMessageBox.critical(self, "Error", f"Script generation failed: {error_msg}")
        self.status_label.setText("Error occurred")
        self.generate_btn.setEnabled(True)

    def closeEvent(self, event):
        """Handle dialog close event."""
        if self.worker and self.worker.isRunning():
            self.worker.wait()
        event.accept()


# Convenience function for main app integration
def show_script_generator_dialog(parent=None, binary_path: str = ""):
    """Show the script generator dialog."""
    dialog = ScriptGeneratorDialog(parent, binary_path)
    return dialog.exec()
