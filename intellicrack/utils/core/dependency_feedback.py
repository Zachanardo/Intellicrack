"""Comprehensive dependency feedback system for missing libraries and tools.

This module provides user-friendly feedback when dependencies are missing,
including installation instructions, alternative suggestions, and graceful
degradation.

This file is part of Intellicrack.
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
"""

import platform

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
                "Windows": [
                    "Download from NSA GitHub releases",
                    "Set GHIDRA_INSTALL_DIR environment variable",
                ],
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
            "install_commands": {
                "Windows": ["pip install pefile"],
                "Linux": ["pip3 install pefile"],
                "macOS": ["pip3 install pefile"],
            },
            "alternatives": ["lief", "pyelftools for ELF files"],
            "critical": True,
            "category": "binary_analysis",
        },
        "lief": {
            "name": "LIEF",
            "description": "Library for Instrumentation of Executable Formats",
            "install_commands": {
                "Windows": ["pip install lief"],
                "Linux": ["pip3 install lief"],
                "macOS": ["pip3 install lief"],
            },
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
            "install_commands": {
                "Windows": ["pip install psutil"],
                "Linux": ["pip3 install psutil"],
                "macOS": ["pip3 install psutil"],
            },
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
            "install_commands": {
                "Windows": ["pip install numpy"],
                "Linux": ["pip3 install numpy"],
                "macOS": ["pip3 install numpy"],
            },
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

    def __init__(self) -> None:
        """Initialize the DependencyFeedback system."""
        self.system = platform.system()
        self.missing_critical: list[str] = []
        self.missing_optional: list[str] = []
        self.available_alternatives: dict[str, list[str]] = {}

    def get_dependency_status(self, dependency_name: str) -> dict[str, object]:
        """Get comprehensive status information for a dependency.

        Args:
            dependency_name: Name of the dependency to check.

        Returns:
            Dictionary containing availability status, metadata, feedback message,
            and alternatives.
        """
        if dependency_name not in self.DEPENDENCY_INFO:
            return {
                "available": False,
                "info": None,
                "message": f"Unknown dependency: {dependency_name}",
                "alternatives": [],
            }

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

    def _generate_feedback_message(self, name: str, info: dict[str, object], available: bool) -> str:
        """Generate comprehensive feedback message for a dependency.

        Args:
            name: Name of the dependency.
            info: Dependency information dictionary.
            available: Whether the dependency is currently available.

        Returns:
            User-friendly feedback message about the dependency status.
        """
        dep_name = info.get("name", name)
        if not isinstance(dep_name, str):
            dep_name = name

        if available:
            return f"OK {dep_name} is available and ready to use."

        description = info.get("description", "")
        if not isinstance(description, str):
            description = ""

        message_parts = [
            f"ERROR {dep_name} is not available.",
            f"   Purpose: {description}",
        ]

        install_commands = info.get("install_commands", {})
        if isinstance(install_commands, dict) and self.system in install_commands:
            commands = install_commands[self.system]
            if isinstance(commands, list):
                message_parts.append(f"   Installation for {self.system}:")
                message_parts.extend(f"      {cmd}" for cmd in commands if isinstance(cmd, str))

        alternatives = info.get("alternatives", [])
        if isinstance(alternatives, list) and alternatives:
            message_parts.append("   Alternatives:")
            message_parts.extend(f"      {alt}" for alt in alternatives if isinstance(alt, str))

        critical = info.get("critical", False)
        if critical:
            message_parts.append("   WARNING️  This is a CRITICAL dependency for core functionality.")
        else:
            message_parts.append("   i  This is an optional dependency - reduced functionality available.")

        return "\n".join(message_parts)

    def check_all_dependencies(self) -> dict[str, object]:
        """Check status of all known dependencies.

        Returns:
            Dictionary with critical_missing, optional_missing, available lists
            and summary information.
        """
        critical_missing: list[str] = []
        optional_missing: list[str] = []
        available: list[str] = []

        for dep_name, dep_info in self.DEPENDENCY_INFO.items():
            status = self.get_dependency_status(dep_name)

            if status["available"]:
                available.append(dep_name)
            elif dep_info["critical"]:
                critical_missing.append(dep_name)
            else:
                optional_missing.append(dep_name)

        total_available = len(available)
        total_critical_missing = len(critical_missing)
        total_optional_missing = len(optional_missing)
        total_checked = len(self.DEPENDENCY_INFO)

        summary = (
            f"Dependencies: {total_available}/{total_checked} available. "
            f"Missing: {total_critical_missing} critical, {total_optional_missing} optional."
        )

        results: dict[str, object] = {
            "critical_missing": critical_missing,
            "optional_missing": optional_missing,
            "available": available,
            "total_checked": total_checked,
            "summary": summary,
        }

        return results

    def get_installation_batch_script(self, missing_deps: list[str]) -> str:
        """Generate batch installation script for missing dependencies.

        Args:
            missing_deps: List of dependency names to install.

        Returns:
            Shell script content with installation commands.
        """
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
                name = info.get("name", "")
                description = info.get("description", "")
                if isinstance(name, str) and isinstance(description, str):
                    script_lines.append(f"# Installing {name} - {description}")

                install_commands = info.get("install_commands", {})
                if isinstance(install_commands, dict) and self.system in install_commands:
                    commands = install_commands[self.system]
                    if isinstance(commands, list):
                        script_lines.extend(str(cmd) for cmd in commands)
                        script_lines.append("")

        return "\n".join(script_lines)

    def get_category_alternatives(self, category: str) -> list[str]:
        """Get alternative tools for a specific category.

        Args:
            category: Category name to find alternatives for.

        Returns:
            List of alternative tool names in the specified category.
        """
        alternatives: list[str] = []
        for dep_info in self.DEPENDENCY_INFO.values():
            if dep_info.get("category") == category:
                alts = dep_info.get("alternatives", [])
                if isinstance(alts, list):
                    alternatives.extend(str(alt) for alt in alts)
        return list(set(alternatives))

    def generate_missing_dependency_report(self, missing_deps: list[str]) -> str:
        """Generate comprehensive report for missing dependencies.

        Args:
            missing_deps: List of missing dependency names.

        Returns:
            Formatted report with categorized missing dependencies and installation
            instructions.
        """
        if not missing_deps:
            return "OK All required dependencies are available!"

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

        if critical_deps:
            report_lines.append("🔴 CRITICAL MISSING DEPENDENCIES:")
            report_lines.append("These are required for core functionality.")
            report_lines.append("")
            for dep_name in critical_deps:
                status = self.get_dependency_status(dep_name)
                message = status.get("message", "")
                if isinstance(message, str):
                    report_lines.append(message)
                    report_lines.append("")

        if optional_deps:
            report_lines.append("🟡 OPTIONAL MISSING DEPENDENCIES:")
            report_lines.append("These provide enhanced functionality.")
            report_lines.append("")
            for dep_name in optional_deps:
                status = self.get_dependency_status(dep_name)
                message = status.get("message", "")
                if isinstance(message, str):
                    report_lines.append(message)
                    report_lines.append("")
        report_lines.append("📜 BATCH INSTALLATION SCRIPT:")
        report_lines.append("-" * 40)
        report_lines.append(self.get_installation_batch_script(missing_deps))
        return "\n".join(report_lines)

    def suggest_alternatives(self, missing_dep: str, task_context: str = "") -> str:
        """Suggest alternatives for a specific missing dependency in context.

        Args:
            missing_dep: Name of the missing dependency.
            task_context: Optional context about the task requiring the dependency.
                Defaults to empty string.

        Returns:
            Formatted list of alternative tools and suggestions.
        """
        if missing_dep not in self.DEPENDENCY_INFO:
            return f"No alternatives found for unknown dependency: {missing_dep}"

        info = self.DEPENDENCY_INFO[missing_dep]
        alternatives = info.get("alternatives", [])
        name = info.get("name", missing_dep)

        if not isinstance(alternatives, list) or not alternatives:
            if isinstance(name, str):
                return f"No alternatives available for {name}."
            return f"No alternatives available for {missing_dep}."

        if not isinstance(name, str):
            name = missing_dep

        suggestion_lines = [
            f" ALTERNATIVES FOR {name.upper()}:",
            f"Since {name} is not available" + (f" for {task_context}" if task_context else "") + ", try:",
        ]

        suggestion_lines.extend(f"   {alt}" for alt in alternatives if isinstance(alt, str))

        category = info.get("category", "")
        if isinstance(category, str):
            category_alts = self.get_category_alternatives(category)
            if category_alts:
                additional_alts = [alt for alt in category_alts if alt not in alternatives]
                if additional_alts:
                    suggestion_lines.append("  Additional options in this category:")
                    suggestion_lines.extend(f"    ◦ {alt}" for alt in additional_alts[:3])

        return "\n".join(suggestion_lines)

    def log_dependency_status(self, dep_name: str, context: str = "") -> None:
        """Log dependency status with appropriate level.

        Args:
            dep_name: Name of the dependency to log.
            context: Optional context about where dependency is needed.
                Defaults to empty string.
        """
        status = self.get_dependency_status(dep_name)

        if status.get("available"):
            logger.info("%s dependency available for %s", dep_name, context)
        else:
            info = status.get("info", {})
            if isinstance(info, dict):
                critical = info.get("critical", False)
                if critical:
                    logger.error("Critical dependency %s missing for %s", dep_name, context, exc_info=True)
                else:
                    logger.warning("Optional dependency %s missing for %s", dep_name, context)
            else:
                logger.warning("Optional dependency %s missing for %s", dep_name, context)

    def create_user_friendly_error(self, dep_name: str, operation: str, error: Exception) -> str:
        """Create user-friendly error message with helpful guidance.

        Args:
            dep_name: Name of the missing dependency.
            operation: Description of the operation that failed.
            error: Exception that was raised.

        Returns:
            User-friendly error message with installation and alternative suggestions.
        """
        status = self.get_dependency_status(dep_name)
        message = status.get("message", "")
        if not isinstance(message, str):
            message = ""

        error_lines: list[str] = [
            f"ERROR ERROR in {operation}:",
            f"   {error!s}",
            "",
            message,
            "",
        ]

        available = status.get("available", False)
        if not available:
            alternatives = status.get("alternatives", [])
            if isinstance(alternatives, list) and alternatives:
                first_alt = alternatives[0]
                if isinstance(first_alt, str):
                    error_lines.append(f" QUICK FIX: Try using {first_alt} instead")
                    error_lines.append(f"   Or install {dep_name} using the commands above")

        return "\n".join(error_lines)


# Global instance for easy access
dependency_feedback = DependencyFeedback()


def check_dependency(name: str, context: str = "") -> bool:
    """Quick check if dependency is available with logging.

    Args:
        name: Name of the dependency to check.
        context: Optional context about where dependency is needed.
            Defaults to empty string.

    Returns:
        True if the dependency is available, False otherwise.
    """
    status = dependency_feedback.get_dependency_status(name)
    dependency_feedback.log_dependency_status(name, context)
    available = status.get("available", False)
    return bool(available)


def get_user_friendly_error(dep_name: str, operation: str, error: Exception) -> str:
    """Get user-friendly error message for missing dependency.

    Args:
        dep_name: Name of the missing dependency.
        operation: Description of the operation that failed.
        error: Exception that was raised.

    Returns:
        User-friendly error message with helpful guidance.
    """
    return dependency_feedback.create_user_friendly_error(dep_name, operation, error)


def suggest_alternatives(missing_dep: str, context: str = "") -> str:
    """Suggest alternatives for missing dependency.

    Args:
        missing_dep: Name of the missing dependency.
        context: Optional context about the task requiring the dependency.
            Defaults to empty string.

    Returns:
        Formatted list of alternative tools and suggestions.
    """
    return dependency_feedback.suggest_alternatives(missing_dep, context)
