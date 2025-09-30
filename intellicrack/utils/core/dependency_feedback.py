"""This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

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

Comprehensive dependency feedback system for missing libraries and tools.

This module provides user-friendly feedback when dependencies are missing,
including installation instructions, alternative suggestions, and graceful degradation.
"""

import platform
from typing import Dict, List

from intellicrack.utils.logger import logger


class DependencyFeedback:
    """Provides comprehensive user feedback for missing dependencies."""

    DEPENDENCY_INFO = {
        "frida": {
            "name": "Frida",
            "description": "Dynamic instrumentation and binary analysis framework",
            "install_commands": {
                "Windows": ["pip install frida-tools", "pip install frida"],
                "Linux": ["pip3 install frida-tools", "sudo apt-get install frida-dev"],
                "macOS": ["pip3 install frida-tools", "brew install frida"],
            },
            "alternatives": ["radare2", "gdb", "dynamic analysis"],
            "critical": True,
            "category": "dynamic_analysis",
        },
        "ghidra": {
            "name": "Ghidra",
            "description": "NSA's reverse engineering framework",
            "install_commands": {
                "Windows": ["Download from NSA GitHub releases", "Set GHIDRA_INSTALL_DIR environment variable"],
                "Linux": ["sudo apt-get install ghidra", "Download from NSA GitHub releases"],
                "macOS": ["brew install ghidra", "Download from NSA GitHub releases"],
            },
            "alternatives": ["radare2", "Binary Ninja"],
            "critical": True,
            "category": "static_analysis",
        },
        "pefile": {
            "name": "pefile",
            "description": "PE file format analysis library",
            "install_commands": {"Windows": ["pip install pefile"], "Linux": ["pip3 install pefile"], "macOS": ["pip3 install pefile"]},
            "alternatives": ["lief", "pyelftools for ELF files"],
            "critical": True,
            "category": "binary_analysis",
        },
        "lief": {
            "name": "LIEF",
            "description": "Library for Instrumentation of Executable Formats",
            "install_commands": {"Windows": ["pip install lief"], "Linux": ["pip3 install lief"], "macOS": ["pip3 install lief"]},
            "alternatives": ["pefile for PE files", "pyelftools for ELF files"],
            "critical": False,
            "category": "binary_analysis",
        },
        "capstone": {
            "name": "Capstone Engine",
            "description": "Multi-platform disassembly framework",
            "install_commands": {
                "Windows": ["pip install capstone"],
                "Linux": ["pip3 install capstone", "sudo apt-get install libcapstone-dev"],
                "macOS": ["pip3 install capstone", "brew install capstone"],
            },
            "alternatives": ["objdump", "radare2 disassembler"],
            "critical": True,
            "category": "disassembly",
        },
        "pyelftools": {
            "name": "pyelftools",
            "description": "Python library for parsing ELF files",
            "install_commands": {
                "Windows": ["pip install pyelftools"],
                "Linux": ["pip3 install pyelftools"],
                "macOS": ["pip3 install pyelftools"],
            },
            "alternatives": ["lief", "readelf command"],
            "critical": False,
            "category": "binary_analysis",
        },
        "psutil": {
            "name": "psutil",
            "description": "System and process monitoring library",
            "install_commands": {"Windows": ["pip install psutil"], "Linux": ["pip3 install psutil"], "macOS": ["pip3 install psutil"]},
            "alternatives": ["Built-in system tools", "manual process monitoring"],
            "critical": False,
            "category": "system_monitoring",
        },
        "matplotlib": {
            "name": "Matplotlib",
            "description": "Plotting and visualization library",
            "install_commands": {
                "Windows": ["pip install matplotlib"],
                "Linux": ["pip3 install matplotlib"],
                "macOS": ["pip3 install matplotlib"],
            },
            "alternatives": ["Text-based output", "export to CSV"],
            "critical": False,
            "category": "visualization",
        },
        "numpy": {
            "name": "NumPy",
            "description": "Numerical computing library",
            "install_commands": {"Windows": ["pip install numpy"], "Linux": ["pip3 install numpy"], "macOS": ["pip3 install numpy"]},
            "alternatives": ["Built-in Python math", "reduced functionality"],
            "critical": False,
            "category": "numerical",
        },
        "tensorflow": {
            "name": "TensorFlow",
            "description": "Machine learning framework for AI analysis",
            "install_commands": {
                "Windows": ["pip install tensorflow"],
                "Linux": ["pip3 install tensorflow"],
                "macOS": ["pip3 install tensorflow"],
            },
            "alternatives": ["PyTorch", "scikit-learn", "rule-based analysis"],
            "critical": False,
            "category": "machine_learning",
        },
        "pdfkit": {
            "name": "pdfkit",
            "description": "PDF generation library",
            "install_commands": {
                "Windows": ["pip install pdfkit", "Download wkhtmltopdf"],
                "Linux": ["pip3 install pdfkit", "sudo apt-get install wkhtmltopdf"],
                "macOS": ["pip3 install pdfkit", "brew install wkhtmltopdf"],
            },
            "alternatives": ["HTML reports", "text output"],
            "critical": False,
            "category": "reporting",
        },
        "radare2": {
            "name": "radare2",
            "description": "Reverse engineering framework",
            "install_commands": {
                "Windows": ["winget install radare.radare2", "Download from radare.org"],
                "Linux": ["sudo apt-get install radare2", "snap install radare2"],
                "macOS": ["brew install radare2"],
            },
            "alternatives": ["Ghidra", "objdump", "manual analysis"],
            "critical": True,
            "category": "reverse_engineering",
        },
    }

    def __init__(self):
        """Initialize dependency feedback system."""
        self.system = platform.system()
        self.missing_critical = []
        self.missing_optional = []
        self.available_alternatives = {}

    def get_dependency_status(self, dependency_name: str) -> Dict:
        """Get comprehensive status information for a dependency."""
        if dependency_name not in self.DEPENDENCY_INFO:
            return {"available": False, "info": None, "message": f"Unknown dependency: {dependency_name}", "alternatives": []}

        info = self.DEPENDENCY_INFO[dependency_name]

        try:
            # Check if dependency is available through import checks
            from intellicrack.utils.core.import_checks import (
                CAPSTONE_AVAILABLE,
                FRIDA_AVAILABLE,
                HAS_NUMPY,
                LIEF_AVAILABLE,
                MATPLOTLIB_AVAILABLE,
                PDFKIT_AVAILABLE,
                PEFILE_AVAILABLE,
                PSUTIL_AVAILABLE,
                PYELFTOOLS_AVAILABLE,
                TENSORFLOW_AVAILABLE,
            )

            availability_map = {
                "frida": FRIDA_AVAILABLE,
                "capstone": CAPSTONE_AVAILABLE,
                "pefile": PEFILE_AVAILABLE,
                "lief": LIEF_AVAILABLE,
                "pyelftools": PYELFTOOLS_AVAILABLE,
                "psutil": PSUTIL_AVAILABLE,
                "matplotlib": MATPLOTLIB_AVAILABLE,
                "numpy": HAS_NUMPY,
                "tensorflow": TENSORFLOW_AVAILABLE,
                "pdfkit": PDFKIT_AVAILABLE,
            }

            is_available = availability_map.get(dependency_name, False)

        except ImportError:
            is_available = False

        return {
            "available": is_available,
            "info": info,
            "message": self._generate_feedback_message(dependency_name, info, is_available),
            "alternatives": info["alternatives"],
        }

    def _generate_feedback_message(self, name: str, info: Dict, available: bool) -> str:
        """Generate comprehensive feedback message for a dependency."""
        if available:
            return f"✅ {info['name']} is available and ready to use."

        message_parts = []
        message_parts.append(f"❌ {info['name']} is not available.")
        message_parts.append(f"   Purpose: {info['description']}")

        # Installation instructions
        if self.system in info["install_commands"]:
            commands = info["install_commands"][self.system]
            message_parts.append(f"   Installation for {self.system}:")
            for cmd in commands:
                message_parts.append(f"     • {cmd}")

        # Alternatives
        if info["alternatives"]:
            message_parts.append("   Alternatives:")
            for alt in info["alternatives"]:
                message_parts.append(f"     • {alt}")

        # Criticality
        if info["critical"]:
            message_parts.append("   ⚠️  This is a CRITICAL dependency for core functionality.")
        else:
            message_parts.append("   ℹ️  This is an optional dependency - reduced functionality available.")

        return "\n".join(message_parts)

    def check_all_dependencies(self) -> Dict:
        """Check status of all known dependencies."""
        results = {
            "critical_missing": [],
            "optional_missing": [],
            "available": [],
            "total_checked": len(self.DEPENDENCY_INFO),
            "summary": "",
        }

        for dep_name, dep_info in self.DEPENDENCY_INFO.items():
            status = self.get_dependency_status(dep_name)

            if status["available"]:
                results["available"].append(dep_name)
            else:
                if dep_info["critical"]:
                    results["critical_missing"].append(dep_name)
                else:
                    results["optional_missing"].append(dep_name)

        # Generate summary
        total_available = len(results["available"])
        total_critical_missing = len(results["critical_missing"])
        total_optional_missing = len(results["optional_missing"])

        results["summary"] = (
            f"Dependencies: {total_available}/{results['total_checked']} available. "
            f"Missing: {total_critical_missing} critical, {total_optional_missing} optional."
        )

        return results

    def get_installation_batch_script(self, missing_deps: List[str]) -> str:
        """Generate batch installation script for missing dependencies."""
        if not missing_deps:
            return "# All dependencies are available!"

        script_lines = [
            f"# Intellicrack Dependency Installation Script - {self.system}",
            "# Run these commands to install missing dependencies",
            "",
        ]

        for dep_name in missing_deps:
            if dep_name in self.DEPENDENCY_INFO:
                info = self.DEPENDENCY_INFO[dep_name]
                script_lines.append(f"# Installing {info['name']} - {info['description']}")

                if self.system in info["install_commands"]:
                    for cmd in info["install_commands"][self.system]:
                        script_lines.append(cmd)
                    script_lines.append("")

        return "\n".join(script_lines)

    def get_category_alternatives(self, category: str) -> List[str]:
        """Get alternative tools for a specific category."""
        alternatives = []
        for _dep_name, dep_info in self.DEPENDENCY_INFO.items():
            if dep_info.get("category") == category:
                alternatives.extend(dep_info.get("alternatives", []))
        return list(set(alternatives))  # Remove duplicates

    def generate_missing_dependency_report(self, missing_deps: List[str]) -> str:
        """Generate comprehensive report for missing dependencies."""
        if not missing_deps:
            return "✅ All required dependencies are available!"

        report_lines = ["📋 MISSING DEPENDENCY REPORT", "=" * 50, ""]

        # Group by category and criticality
        critical_deps = []
        optional_deps = []

        for dep_name in missing_deps:
            if dep_name in self.DEPENDENCY_INFO:
                if self.DEPENDENCY_INFO[dep_name]["critical"]:
                    critical_deps.append(dep_name)
                else:
                    optional_deps.append(dep_name)

        # Critical dependencies
        if critical_deps:
            report_lines.append("🔴 CRITICAL MISSING DEPENDENCIES:")
            report_lines.append("These are required for core functionality.")
            report_lines.append("")

            for dep_name in critical_deps:
                status = self.get_dependency_status(dep_name)
                report_lines.append(status["message"])
                report_lines.append("")

        # Optional dependencies
        if optional_deps:
            report_lines.append("🟡 OPTIONAL MISSING DEPENDENCIES:")
            report_lines.append("These provide enhanced functionality.")
            report_lines.append("")

            for dep_name in optional_deps:
                status = self.get_dependency_status(dep_name)
                report_lines.append(status["message"])
                report_lines.append("")

        # Installation script
        report_lines.append("📜 BATCH INSTALLATION SCRIPT:")
        report_lines.append("-" * 40)
        report_lines.append(self.get_installation_batch_script(missing_deps))

        return "\n".join(report_lines)

    def suggest_alternatives(self, missing_dep: str, task_context: str = "") -> str:
        """Suggest alternatives for a specific missing dependency in context."""
        if missing_dep not in self.DEPENDENCY_INFO:
            return f"No alternatives found for unknown dependency: {missing_dep}"

        info = self.DEPENDENCY_INFO[missing_dep]
        alternatives = info["alternatives"]

        if not alternatives:
            return f"No alternatives available for {info['name']}."

        suggestion_lines = [
            f"💡 ALTERNATIVES FOR {info['name'].upper()}:",
            f"Since {info['name']} is not available" + (f" for {task_context}" if task_context else "") + ", try:",
        ]

        for alt in alternatives:
            suggestion_lines.append(f"  • {alt}")

        # Add category-specific alternatives
        category_alts = self.get_category_alternatives(info.get("category", ""))
        if category_alts:
            additional_alts = [alt for alt in category_alts if alt not in alternatives]
            if additional_alts:
                suggestion_lines.append("  Additional options in this category:")
                for alt in additional_alts[:3]:  # Limit to top 3
                    suggestion_lines.append(f"    ◦ {alt}")

        return "\n".join(suggestion_lines)

    def log_dependency_status(self, dep_name: str, context: str = ""):
        """Log dependency status with appropriate level."""
        status = self.get_dependency_status(dep_name)

        if status["available"]:
            logger.info(f"{dep_name} dependency available for {context}")
        else:
            info = status.get("info", {})
            if info and info.get("critical"):
                logger.error(f"Critical dependency {dep_name} missing for {context}")
            else:
                logger.warning(f"Optional dependency {dep_name} missing for {context}")

    def create_user_friendly_error(self, dep_name: str, operation: str, error: Exception) -> str:
        """Create user-friendly error message with helpful guidance."""
        status = self.get_dependency_status(dep_name)

        error_lines = [f"❌ ERROR in {operation}:", f"   {str(error)}", "", status["message"], ""]

        # Add quick fix suggestion
        if not status["available"]:
            alternatives = status.get("alternatives", [])
            if alternatives:
                error_lines.append(f"💡 QUICK FIX: Try using {alternatives[0]} instead")
                error_lines.append(f"   Or install {dep_name} using the commands above")

        return "\n".join(error_lines)


# Global instance for easy access
dependency_feedback = DependencyFeedback()


def check_dependency(name: str, context: str = "") -> bool:
    """Quick check if dependency is available with logging."""
    status = dependency_feedback.get_dependency_status(name)
    dependency_feedback.log_dependency_status(name, context)
    return status["available"]


def get_user_friendly_error(dep_name: str, operation: str, error: Exception) -> str:
    """Get user-friendly error message for missing dependency."""
    return dependency_feedback.create_user_friendly_error(dep_name, operation, error)


def suggest_alternatives(missing_dep: str, context: str = "") -> str:
    """Suggest alternatives for missing dependency."""
    return dependency_feedback.suggest_alternatives(missing_dep, context)
