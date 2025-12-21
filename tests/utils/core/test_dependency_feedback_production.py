"""Production tests for dependency feedback system.

Tests validate real dependency detection, installation script generation,
and user-friendly feedback for missing dependencies.

Copyright (C) 2025 Zachary Flint
"""

import platform
import sys
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.core.dependency_feedback import (
    DependencyFeedback,
    check_dependency,
    dependency_feedback,
    get_user_friendly_error,
    suggest_alternatives,
)


class TestDependencyFeedbackBasic:
    """Test basic dependency detection functionality."""

    def test_dependency_feedback_initialization(self) -> None:
        """DependencyFeedback initializes with correct platform detection."""
        feedback = DependencyFeedback()

        assert feedback.system == platform.system()
        assert isinstance(feedback.cache, dict)
        assert isinstance(feedback.missing_critical, list)
        assert isinstance(feedback.missing_optional, list)
        assert feedback.system in ["Windows", "Linux", "Darwin"]

    def test_dependency_info_completeness(self) -> None:
        """All dependency entries have complete information."""
        feedback = DependencyFeedback()

        required_keys = {"name", "description", "install_commands", "alternatives", "critical", "category"}

        for dep_name, dep_info in feedback.DEPENDENCY_INFO.items():
            assert required_keys.issubset(
                dep_info.keys(),
            ), f"Dependency {dep_name} missing required keys"

            assert isinstance(dep_info["name"], str)
            assert isinstance(dep_info["description"], str)
            assert isinstance(dep_info["install_commands"], dict)
            assert isinstance(dep_info["alternatives"], list)
            assert isinstance(dep_info["critical"], bool)
            assert isinstance(dep_info["category"], str)

            for platform_name in ["Windows", "Linux", "macOS"]:
                assert platform_name in dep_info["install_commands"]
                assert isinstance(dep_info["install_commands"][platform_name], list)


class TestRealDependencyDetection:
    """Test real dependency availability detection."""

    def test_get_dependency_status_available_dependency(self) -> None:
        """Correctly identifies available Python dependencies."""
        feedback = DependencyFeedback()

        status = feedback.get_dependency_status("pefile")

        assert isinstance(status, dict)
        assert "available" in status
        assert "info" in status
        assert "message" in status
        assert "alternatives" in status
        assert isinstance(status["available"], bool)

        if status["available"]:
            assert "OK" in status["message"]
            assert "available and ready to use" in status["message"]
        else:
            assert "ERROR" in status["message"]
            assert "not available" in status["message"]

    def test_get_dependency_status_known_available(self) -> None:
        """Detect actually installed dependencies correctly."""
        feedback = DependencyFeedback()

        python_available_deps = []
        for dep in ["psutil", "numpy", "matplotlib", "pefile"]:
            try:
                __import__(dep)
                python_available_deps.append(dep)
            except ImportError:
                pass

        for dep in python_available_deps:
            if dep in feedback.DEPENDENCY_INFO:
                status = feedback.get_dependency_status(dep)
                assert status["available"] is True, f"Failed to detect installed dependency: {dep}"

    def test_get_dependency_status_nonexistent(self) -> None:
        """Handles requests for unknown dependencies gracefully."""
        feedback = DependencyFeedback()

        status = feedback.get_dependency_status("nonexistent_fake_dependency_xyz")

        assert status["available"] is False
        assert "Unknown dependency" in status["message"]
        assert status["info"] is None
        assert status["alternatives"] == []

    def test_check_all_dependencies_comprehensive(self) -> None:
        """Complete dependency check returns accurate results."""
        feedback = DependencyFeedback()

        results = feedback.check_all_dependencies()

        assert "critical_missing" in results
        assert "optional_missing" in results
        assert "available" in results
        assert "total_checked" in results
        assert "summary" in results

        assert isinstance(results["critical_missing"], list)
        assert isinstance(results["optional_missing"], list)
        assert isinstance(results["available"], list)

        total_deps = len(results["critical_missing"]) + len(results["optional_missing"]) + len(results["available"])
        assert total_deps == results["total_checked"]
        assert results["total_checked"] == len(feedback.DEPENDENCY_INFO)

        assert "Dependencies:" in results["summary"]
        assert "available" in results["summary"]
        assert "Missing:" in results["summary"]

    def test_check_all_dependencies_categorization(self) -> None:
        """Dependencies correctly categorized by criticality."""
        feedback = DependencyFeedback()

        results = feedback.check_all_dependencies()

        for dep_name in results["critical_missing"]:
            assert feedback.DEPENDENCY_INFO[dep_name]["critical"] is True

        for dep_name in results["optional_missing"]:
            assert feedback.DEPENDENCY_INFO[dep_name]["critical"] is False


class TestInstallationScriptGeneration:
    """Test installation script generation for different platforms."""

    def test_get_installation_batch_script_empty(self) -> None:
        """Empty dependency list returns appropriate message."""
        feedback = DependencyFeedback()

        script = feedback.get_installation_batch_script([])

        assert "All dependencies are available" in script

    def test_get_installation_batch_script_single_dependency(self) -> None:
        """Generate installation script for single dependency."""
        feedback = DependencyFeedback()

        script = feedback.get_installation_batch_script(["pefile"])

        assert "Intellicrack Dependency Installation Script" in script
        assert feedback.system in script
        assert "pefile" in script.lower()

        dep_info = feedback.DEPENDENCY_INFO["pefile"]
        if feedback.system in dep_info["install_commands"]:
            for cmd in dep_info["install_commands"][feedback.system]:
                assert cmd in script

    def test_get_installation_batch_script_multiple_dependencies(self) -> None:
        """Generate installation script for multiple dependencies."""
        feedback = DependencyFeedback()

        deps = ["frida", "ghidra", "radare2"]
        script = feedback.get_installation_batch_script(deps)

        assert "Intellicrack Dependency Installation Script" in script

        for dep in deps:
            if dep in feedback.DEPENDENCY_INFO:
                assert dep in script.lower() or feedback.DEPENDENCY_INFO[dep]["name"] in script

    def test_get_installation_batch_script_platform_specific(self) -> None:
        """Installation commands appropriate for current platform."""
        feedback = DependencyFeedback()

        script = feedback.get_installation_batch_script(["frida", "pefile"])

        if feedback.system == "Windows":
            assert "pip install" in script
        elif feedback.system == "Linux":
            assert "pip3 install" in script or "apt-get" in script
        elif feedback.system == "Darwin":
            assert "pip3 install" in script or "brew install" in script


class TestAlternativesSuggestion:
    """Test alternative tool suggestion functionality."""

    def test_suggest_alternatives_with_context(self) -> None:
        """Alternative suggestions include context information."""
        feedback = DependencyFeedback()

        suggestion = feedback.suggest_alternatives("frida", "dynamic instrumentation")

        assert "ALTERNATIVES FOR FRIDA" in suggestion.upper()
        assert "dynamic instrumentation" in suggestion
        assert "not available" in suggestion

        frida_info = feedback.DEPENDENCY_INFO["frida"]
        for alt in frida_info["alternatives"]:
            assert alt in suggestion

    def test_suggest_alternatives_no_context(self) -> None:
        """Alternative suggestions work without context."""
        feedback = DependencyFeedback()

        suggestion = feedback.suggest_alternatives("ghidra")

        assert "ALTERNATIVES FOR GHIDRA" in suggestion.upper()
        assert "not available" in suggestion

        ghidra_info = feedback.DEPENDENCY_INFO["ghidra"]
        for alt in ghidra_info["alternatives"]:
            assert alt in suggestion

    def test_suggest_alternatives_unknown_dependency(self) -> None:
        """Unknown dependency returns appropriate message."""
        feedback = DependencyFeedback()

        suggestion = feedback.suggest_alternatives("unknown_tool_xyz")

        assert "No alternatives found" in suggestion
        assert "unknown dependency" in suggestion.lower()

    def test_get_category_alternatives(self) -> None:
        """Category alternatives include all relevant tools."""
        feedback = DependencyFeedback()

        static_analysis_alts = feedback.get_category_alternatives("static_analysis")

        assert isinstance(static_analysis_alts, list)
        assert len(static_analysis_alts) > 0

        for dep_name, dep_info in feedback.DEPENDENCY_INFO.items():
            if dep_info["category"] == "static_analysis":
                for alt in dep_info["alternatives"]:
                    assert alt in static_analysis_alts


class TestUserFeedbackGeneration:
    """Test user-friendly feedback message generation."""

    def test_generate_feedback_message_available(self) -> None:
        """Available dependency shows success message."""
        feedback = DependencyFeedback()

        dep_info = feedback.DEPENDENCY_INFO["pefile"]
        message = feedback._generate_feedback_message("pefile", dep_info, available=True)

        assert "OK" in message
        assert dep_info["name"] in message
        assert "available and ready to use" in message

    def test_generate_feedback_message_missing_critical(self) -> None:
        """Missing critical dependency shows warning."""
        feedback = DependencyFeedback()

        dep_info = feedback.DEPENDENCY_INFO["frida"]
        message = feedback._generate_feedback_message("frida", dep_info, available=False)

        assert "ERROR" in message
        assert dep_info["name"] in message
        assert "not available" in message
        assert dep_info["description"] in message
        assert "CRITICAL" in message

        if feedback.system in dep_info["install_commands"]:
            assert "Installation" in message

        for alt in dep_info["alternatives"]:
            assert alt in message

    def test_generate_feedback_message_missing_optional(self) -> None:
        """Missing optional dependency shows informational message."""
        feedback = DependencyFeedback()

        dep_info = feedback.DEPENDENCY_INFO["matplotlib"]
        message = feedback._generate_feedback_message("matplotlib", dep_info, available=False)

        assert "ERROR" in message
        assert "not available" in message
        assert "optional dependency" in message
        assert "CRITICAL" not in message

    def test_generate_missing_dependency_report_complete(self) -> None:
        """Complete missing dependency report has all sections."""
        feedback = DependencyFeedback()

        results = feedback.check_all_dependencies()
        if (
            all_missing := results["critical_missing"]
            + results["optional_missing"]
        ):
            report = feedback.generate_missing_dependency_report(all_missing)

            assert "MISSING DEPENDENCY REPORT" in report

            if results["critical_missing"]:
                assert "CRITICAL MISSING DEPENDENCIES" in report

            if results["optional_missing"]:
                assert "OPTIONAL MISSING DEPENDENCIES" in report

            assert "BATCH INSTALLATION SCRIPT" in report

    def test_generate_missing_dependency_report_empty(self) -> None:
        """Empty missing list returns success message."""
        feedback = DependencyFeedback()

        report = feedback.generate_missing_dependency_report([])

        assert "OK" in report
        assert "All required dependencies are available" in report


class TestErrorHandling:
    """Test error handling and edge cases."""

    def test_create_user_friendly_error(self) -> None:
        """User-friendly error includes helpful guidance."""
        feedback = DependencyFeedback()

        error = ValueError("Module not found")
        friendly_error = feedback.create_user_friendly_error(
            "frida",
            "binary instrumentation",
            error,
        )

        assert "ERROR" in friendly_error
        assert "binary instrumentation" in friendly_error
        assert "Module not found" in friendly_error
        assert "QUICK FIX" in friendly_error or "install" in friendly_error.lower()

    def test_log_dependency_status_available(self, caplog: pytest.LogCaptureFixture) -> None:
        """Available dependency logged at info level."""
        feedback = DependencyFeedback()

        with caplog.at_level("INFO"):
            feedback.log_dependency_status("pefile", "PE analysis")

        if feedback.get_dependency_status("pefile")["available"]:
            assert any("available" in record.message.lower() for record in caplog.records)

    def test_log_dependency_status_missing_critical(self, caplog: pytest.LogCaptureFixture) -> None:
        """Missing critical dependency logged at error level."""
        feedback = DependencyFeedback()

        status = feedback.get_dependency_status("frida")
        if not status["available"]:
            with caplog.at_level("ERROR"):
                feedback.log_dependency_status("frida", "dynamic analysis")

            assert any("missing" in record.message.lower() for record in caplog.records)


class TestModuleLevelFunctions:
    """Test module-level convenience functions."""

    def test_check_dependency_function(self) -> None:
        """Module-level check_dependency works correctly."""
        result = check_dependency("pefile", "PE analysis")

        assert isinstance(result, bool)

    def test_get_user_friendly_error_function(self) -> None:
        """Module-level get_user_friendly_error works correctly."""
        error = ImportError("No module named 'test'")
        friendly = get_user_friendly_error("frida", "instrumentation", error)

        assert isinstance(friendly, str)
        assert "ERROR" in friendly
        assert "instrumentation" in friendly

    def test_suggest_alternatives_function(self) -> None:
        """Module-level suggest_alternatives works correctly."""
        suggestion = suggest_alternatives("ghidra", "reverse engineering")

        assert isinstance(suggestion, str)
        assert "ALTERNATIVES" in suggestion.upper()
        assert "reverse engineering" in suggestion

    def test_dependency_feedback_singleton(self) -> None:
        """Global dependency_feedback instance is properly initialized."""
        assert isinstance(dependency_feedback, DependencyFeedback)
        assert dependency_feedback.system == platform.system()


class TestPlatformSpecificBehavior:
    """Test platform-specific dependency handling."""

    def test_platform_specific_install_commands(self) -> None:
        """Install commands appropriate for each platform."""
        feedback = DependencyFeedback()

        for dep_name, dep_info in feedback.DEPENDENCY_INFO.items():
            for platform_name, commands in dep_info["install_commands"].items():
                assert isinstance(commands, list)
                assert len(commands) > 0

                if platform_name == "Windows":
                    assert any("pip install" in cmd or "Download" in cmd or "Set" in cmd for cmd in commands)
                elif platform_name == "Linux":
                    assert any("pip3 install" in cmd or "apt-get" in cmd or "Download" in cmd for cmd in commands)
                elif platform_name == "macOS":
                    assert any(
                        "pip3 install" in cmd or "brew install" in cmd or "Download" in cmd for cmd in commands
                    )

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_specific_paths(self) -> None:
        """Windows-specific installation paths in commands."""
        feedback = DependencyFeedback()

        assert feedback.system == "Windows"
        assert feedback.is_windows

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-specific test")
    def test_linux_specific_package_managers(self) -> None:
        """Linux installation uses appropriate package managers."""
        feedback = DependencyFeedback()

        assert feedback.system == "Linux"
        assert feedback.is_linux


class TestDependencyCategories:
    """Test dependency categorization system."""

    def test_all_dependencies_have_category(self) -> None:
        """All dependencies assigned to valid category."""
        feedback = DependencyFeedback()

        valid_categories = {
            "dynamic_analysis",
            "static_analysis",
            "binary_analysis",
            "disassembly",
            "system_monitoring",
            "visualization",
            "numerical",
            "machine_learning",
            "reporting",
            "reverse_engineering",
        }

        for dep_name, dep_info in feedback.DEPENDENCY_INFO.items():
            assert (
                dep_info["category"] in valid_categories
            ), f"Dependency {dep_name} has invalid category: {dep_info['category']}"

    def test_category_grouping_in_report(self) -> None:
        """Dependencies properly grouped by category in reports."""
        feedback = DependencyFeedback()

        categories_found = {
            dep_info["category"] for dep_info in feedback.DEPENDENCY_INFO.values()
        }
        assert len(categories_found) >= 5


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_complete_dependency_check_workflow(self) -> None:
        """Complete workflow from check to report generation."""
        feedback = DependencyFeedback()

        results = feedback.check_all_dependencies()

        assert "summary" in results

        if (
            all_missing := results["critical_missing"]
            + results["optional_missing"]
        ):
            report = feedback.generate_missing_dependency_report(all_missing)
            assert len(report) > 0
            assert "DEPENDENCY REPORT" in report

            script = feedback.get_installation_batch_script(all_missing)
            assert len(script) > 0

    def test_dependency_availability_consistency(self) -> None:
        """Dependency availability consistent across multiple checks."""
        feedback = DependencyFeedback()

        first_check = feedback.check_all_dependencies()
        second_check = feedback.check_all_dependencies()

        assert first_check["available"] == second_check["available"]
        assert first_check["critical_missing"] == second_check["critical_missing"]
        assert first_check["optional_missing"] == second_check["optional_missing"]

    def test_critical_dependencies_identified(self) -> None:
        """Critical dependencies properly marked and handled."""
        feedback = DependencyFeedback()

        critical_deps = {name for name, info in feedback.DEPENDENCY_INFO.items() if info["critical"]}

        assert "frida" in critical_deps
        assert "pefile" in critical_deps
        assert "capstone" in critical_deps

        assert len(critical_deps) >= 3

    def test_alternatives_available_for_critical_tools(self) -> None:
        """Critical tools have alternatives listed."""
        feedback = DependencyFeedback()

        for dep_name, dep_info in feedback.DEPENDENCY_INFO.items():
            if dep_info["critical"]:
                assert len(dep_info["alternatives"]) > 0, f"Critical dependency {dep_name} has no alternatives"
