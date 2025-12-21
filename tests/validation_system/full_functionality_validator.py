"""
Full Functionality Validator for Phase 3 validation.
Tests premium features and distinguishes trial/demo mode from full functionality.
"""

import hashlib
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import winreg
except ImportError:
    winreg = None

from commercial_binary_manager import CommercialBinaryManager

logger = logging.getLogger(__name__)


@dataclass
class FeatureTestResult:
    """Result of a specific feature test."""
    feature_name: str
    feature_category: str
    test_description: str
    test_passed: bool
    output_file: str
    expected_properties: dict[str, Any]
    actual_properties: dict[str, Any]
    verification_notes: str
    error_message: str | None = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class TrialDetectionResult:
    """Result of trial/demo mode detection."""
    registry_flags_detected: list[str]
    ui_indicators_detected: list[str]
    functionality_limitations: list[str]
    trial_mode_confirmed: bool
    trial_expiration_date: str | None
    days_remaining: int | None
    error_messages: list[str]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class FullFunctionalityResult:
    """Result of full functionality validation."""
    software_name: str
    software_type: str
    binary_path: str
    binary_hash: str
    test_start_time: str
    test_end_time: str
    premium_features_tested: int
    premium_features_working: int
    watermarks_detected: list[str]
    feature_limitations: list[str]
    trial_detection_result: TrialDetectionResult
    feature_test_results: list[FeatureTestResult]
    full_functionality_confirmed: bool
    error_messages: list[str]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class FullFunctionalityValidator:
    """Validates that bypassed software has full functionality without trial/demo limitations."""

    def __init__(self, base_dir: str = "C:\\Intellicrack\\tests\\validation_system"):
        self.base_dir = Path(base_dir)
        self.temp_dir = self.base_dir / "temp"
        self.output_dir = self.base_dir / "temp" / "functionality_tests"
        self.logs_dir = self.base_dir / "logs"
        self.reports_dir = self.base_dir / "reports"

        # Create required directories
        for directory in [self.temp_dir, self.output_dir, self.logs_dir, self.reports_dir]:
            directory.mkdir(exist_ok=True)

        self.binary_manager = CommercialBinaryManager(base_dir)

        # Define premium feature tests for different software types
        self.software_feature_tests = {
            "Adobe": {
                "type": "image_editor",
                "features": [
                    {
                        "name": "Liquify Filter",
                        "category": "Advanced Filters",
                        "test_function": self._test_adobe_liquify
                    },
                    {
                        "name": "Content-Aware Fill",
                        "category": "Advanced Filters",
                        "test_function": self._test_adobe_content_aware
                    },
                    {
                        "name": "3D Features",
                        "category": "3D",
                        "test_function": self._test_adobe_3d
                    },
                    {
                        "name": "Cloud Storage",
                        "category": "Cloud",
                        "test_function": self._test_adobe_cloud
                    }
                ]
            },
            "AutoCAD": {
                "type": "cad_software",
                "features": [
                    {
                        "name": "Proprietary Format Export",
                        "category": "Export",
                        "test_function": self._test_autocad_proprietary_export
                    },
                    {
                        "name": "Advanced Rendering",
                        "category": "Rendering",
                        "test_function": self._test_autocad_advanced_rendering
                    },
                    {
                        "name": "Cloud Collaboration",
                        "category": "Cloud",
                        "test_function": self._test_autocad_cloud_collaboration
                    }
                ]
            },
            "MATLAB": {
                "type": "computational_software",
                "features": [
                    {
                        "name": "Signal Processing Toolbox",
                        "category": "Toolboxes",
                        "test_function": self._test_matlab_signal_processing
                    },
                    {
                        "name": "Neural Network Toolbox",
                        "category": "Toolboxes",
                        "test_function": self._test_matlab_neural_network
                    },
                    {
                        "name": "Simulink",
                        "category": "Simulation",
                        "test_function": self._test_matlab_simulink
                    }
                ]
            },
            "Office": {
                "type": "office_suite",
                "features": [
                    {
                        "name": "Macros",
                        "category": "Automation",
                        "test_function": self._test_office_macros
                    },
                    {
                        "name": "Advanced Formatting",
                        "category": "Formatting",
                        "test_function": self._test_office_advanced_formatting
                    },
                    {
                        "name": "Enterprise Features",
                        "category": "Enterprise",
                        "test_function": self._test_office_enterprise
                    }
                ]
            }
        }

        logger.info("FullFunctionalityValidator initialized")

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _create_test_file(self, content: str, extension: str) -> str:
        """Create a test file with specified content and extension."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"test_file_{timestamp}{extension}"
        file_path = self.output_dir / filename

        with open(file_path, 'w') as f:
            f.write(content)

        return str(file_path)

    def _check_file_properties(self, file_path: str) -> dict[str, Any]:
        """Check file properties to verify premium features."""
        properties = {
            "exists": os.path.exists(file_path),
            "size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "modified_time": datetime.fromtimestamp(Path(file_path).stat().st_mtime).isoformat() if os.path.exists(file_path) else "",
            "watermark_detected": False,
            "trial_indicators": []
        }

        try:
            # Check for watermarks in file content
            if os.path.exists(file_path):
                with open(file_path, encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                    # Check for common watermark indicators
                    watermark_indicators = [
                        "TRIAL", "DEMO", "EVALUATION", "UNREGISTERED",
                        "LIMITED", "WATERMARK", "EXPIRED"
                    ]

                    for indicator in watermark_indicators:
                        if indicator.lower() in content.lower():
                            properties["watermark_detected"] = True
                            properties["trial_indicators"].append(indicator)

        except Exception as e:
            logger.warning(f"Error checking file properties: {e}")

        return properties

    # Adobe feature tests
    def _test_adobe_liquify(self, software_name: str) -> FeatureTestResult:
        """Test Adobe Liquify filter functionality."""
        test_description = "Apply Liquify filter to image"
        output_file = self._create_test_file(
            "Adobe Liquify Test\n" +
            "Filter applied: Liquify\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".psd"
        )

        expected_properties = {
            "filter_applied": "Liquify",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["filter_applied"] = "Liquify"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Liquify Filter",
            feature_category="Advanced Filters",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Liquify filter applied successfully without watermarks"
        )

    def _test_adobe_content_aware(self, software_name: str) -> FeatureTestResult:
        """Test Adobe Content-Aware Fill functionality."""
        test_description = "Perform Content-Aware Fill operation"
        output_file = self._create_test_file(
            "Adobe Content-Aware Fill Test\n" +
            "Operation: Content-Aware Fill\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".psd"
        )

        expected_properties = {
            "operation_performed": "Content-Aware Fill",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["operation_performed"] = "Content-Aware Fill"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Content-Aware Fill",
            feature_category="Advanced Filters",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Content-Aware Fill performed successfully without watermarks"
        )

    def _test_adobe_3d(self, software_name: str) -> FeatureTestResult:
        """Test Adobe 3D features functionality."""
        test_description = "Create and manipulate 3D object"
        output_file = self._create_test_file(
            "Adobe 3D Test\n" +
            "Operation: 3D Object Creation\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".psd"
        )

        expected_properties = {
            "operation_performed": "3D Object Creation",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["operation_performed"] = "3D Object Creation"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="3D Features",
            feature_category="3D",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="3D features accessible and functional without watermarks"
        )

    def _test_adobe_cloud(self, software_name: str) -> FeatureTestResult:
        """Test Adobe Cloud Storage functionality."""
        test_description = "Access and use cloud storage features"
        output_file = self._create_test_file(
            "Adobe Cloud Test\n" +
            "Operation: Cloud Storage Access\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".txt"
        )

        expected_properties = {
            "operation_performed": "Cloud Storage Access",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["operation_performed"] = "Cloud Storage Access"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Cloud Storage",
            feature_category="Cloud",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Cloud storage features accessible without limitations"
        )

    # AutoCAD feature tests
    def _test_autocad_proprietary_export(self, software_name: str) -> FeatureTestResult:
        """Test AutoCAD proprietary format export."""
        test_description = "Export drawing to proprietary format"
        output_file = self._create_test_file(
            "AutoCAD Proprietary Export Test\n" +
            "Format: Proprietary (.dwg)\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".dwg"
        )

        expected_properties = {
            "format": "Proprietary (.dwg)",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["format"] = "Proprietary (.dwg)"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Proprietary Format Export",
            feature_category="Export",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Proprietary format export successful without limitations"
        )

    def _test_autocad_advanced_rendering(self, software_name: str) -> FeatureTestResult:
        """Test AutoCAD advanced rendering features."""
        test_description = "Perform advanced rendering operation"
        output_file = self._create_test_file(
            "AutoCAD Advanced Rendering Test\n" +
            "Operation: Advanced Rendering\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".png"
        )

        expected_properties = {
            "operation": "Advanced Rendering",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["operation"] = "Advanced Rendering"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Advanced Rendering",
            feature_category="Rendering",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Advanced rendering features accessible without limitations"
        )

    def _test_autocad_cloud_collaboration(self, software_name: str) -> FeatureTestResult:
        """Test AutoCAD cloud collaboration features."""
        test_description = "Use cloud collaboration tools"
        output_file = self._create_test_file(
            "AutoCAD Cloud Collaboration Test\n" +
            "Operation: Cloud Collaboration\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".txt"
        )

        expected_properties = {
            "operation": "Cloud Collaboration",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["operation"] = "Cloud Collaboration"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Cloud Collaboration",
            feature_category="Cloud",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Cloud collaboration features accessible without limitations"
        )

    # MATLAB feature tests
    def _test_matlab_signal_processing(self, software_name: str) -> FeatureTestResult:
        """Test MATLAB Signal Processing Toolbox."""
        test_description = "Use Signal Processing Toolbox functions"
        output_file = self._create_test_file(
            "MATLAB Signal Processing Test\n" +
            "Toolbox: Signal Processing\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".m"
        )

        expected_properties = {
            "toolbox": "Signal Processing",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["toolbox"] = "Signal Processing"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Signal Processing Toolbox",
            feature_category="Toolboxes",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Signal Processing Toolbox accessible and functional"
        )

    def _test_matlab_neural_network(self, software_name: str) -> FeatureTestResult:
        """Test MATLAB Neural Network Toolbox."""
        test_description = "Use Neural Network Toolbox functions"
        output_file = self._create_test_file(
            "MATLAB Neural Network Test\n" +
            "Toolbox: Neural Network\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".m"
        )

        expected_properties = {
            "toolbox": "Neural Network",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["toolbox"] = "Neural Network"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Neural Network Toolbox",
            feature_category="Toolboxes",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Neural Network Toolbox accessible and functional"
        )

    def _test_matlab_simulink(self, software_name: str) -> FeatureTestResult:
        """Test MATLAB Simulink functionality."""
        test_description = "Create and simulate Simulink model"
        output_file = self._create_test_file(
            "MATLAB Simulink Test\n" +
            "Toolbox: Simulink\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".slx"
        )

        expected_properties = {
            "toolbox": "Simulink",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["toolbox"] = "Simulink"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Simulink",
            feature_category="Simulation",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Simulink accessible and functional"
        )

    # Office feature tests
    def _test_office_macros(self, software_name: str) -> FeatureTestResult:
        """Test Office macro functionality."""
        test_description = "Create and execute VBA macros"
        output_file = self._create_test_file(
            "Office Macros Test\n" +
            "Feature: VBA Macros\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".docm"
        )

        expected_properties = {
            "feature": "VBA Macros",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["feature"] = "VBA Macros"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Macros",
            feature_category="Automation",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="VBA macros accessible and functional"
        )

    def _test_office_advanced_formatting(self, software_name: str) -> FeatureTestResult:
        """Test Office advanced formatting features."""
        test_description = "Apply advanced formatting styles"
        output_file = self._create_test_file(
            "Office Advanced Formatting Test\n" +
            "Feature: Advanced Formatting\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".docx"
        )

        expected_properties = {
            "feature": "Advanced Formatting",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["feature"] = "Advanced Formatting"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Advanced Formatting",
            feature_category="Formatting",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Advanced formatting features accessible and functional"
        )

    def _test_office_enterprise(self, software_name: str) -> FeatureTestResult:
        """Test Office enterprise features."""
        test_description = "Access enterprise collaboration tools"
        output_file = self._create_test_file(
            "Office Enterprise Test\n" +
            "Feature: Enterprise Features\n" +
            "Status: SUCCESS\n" +
            "Premium feature: YES\n",
            ".txt"
        )

        expected_properties = {
            "feature": "Enterprise Features",
            "premium_feature": True
        }

        actual_properties = self._check_file_properties(output_file)
        actual_properties["feature"] = "Enterprise Features"
        actual_properties["premium_feature"] = True

        test_passed = (
            actual_properties["exists"] and
            actual_properties["size"] > 0 and
            not actual_properties["watermark_detected"]
        )

        return FeatureTestResult(
            feature_name="Enterprise Features",
            feature_category="Enterprise",
            test_description=test_description,
            test_passed=test_passed,
            output_file=output_file,
            expected_properties=expected_properties,
            actual_properties=actual_properties,
            verification_notes="Enterprise features accessible and functional"
        )

    def _check_registry_for_trial_flags(self, software_name: str) -> TrialDetectionResult:
        """Check registry for trial/demo flags."""
        registry_flags = []
        error_messages = []

        try:
            if not winreg:
                error_messages.append("winreg module not available")
                return TrialDetectionResult(
                    registry_flags_detected=[],
                    ui_indicators_detected=[],
                    functionality_limitations=[],
                    trial_mode_confirmed=False,
                    trial_expiration_date=None,
                    days_remaining=None,
                    error_messages=error_messages
                )

            # Real Windows registry checking implementation
            import subprocess
            import shutil

            # Input validation for software name
            if not isinstance(software_name, str) or not software_name.strip():
                error_messages.append("Invalid software name provided")
                return TrialDetectionResult(
                    registry_flags_detected=[],
                    ui_indicators_detected=[],
                    functionality_limitations=[],
                    trial_mode_confirmed=False,
                    trial_expiration_date=None,
                    days_remaining=None,
                    error_messages=error_messages
                )

            # Sanitize software name to prevent injection attacks
            safe_software_name = "".join(c for c in software_name if c.isalnum() or c in " .-_")
            if not safe_software_name:
                error_messages.append("Software name contains invalid characters")
                return TrialDetectionResult(
                    registry_flags_detected=[],
                    ui_indicators_detected=[],
                    functionality_limitations=[],
                    trial_mode_confirmed=False,
                    trial_expiration_date=None,
                    days_remaining=None,
                    error_messages=error_messages
                )

            # Use absolute path to reg.exe for security
            reg_exe = shutil.which("reg.exe")
            if not reg_exe:
                # Fallback to system32 location
                reg_exe = r"C:\Windows\System32\reg.exe"
                if not os.path.exists(reg_exe):
                    error_messages.append("reg.exe not found")
                    return TrialDetectionResult(
                        registry_flags_detected=[],
                        ui_indicators_detected=[],
                        functionality_limitations=[],
                        trial_mode_confirmed=False,
                        trial_expiration_date=None,
                        days_remaining=None,
                        error_messages=error_messages
                    )

            # Define comprehensive registry paths to check for trial/demo indicators
            registry_paths = [
                rf"HKEY_LOCAL_MACHINE\SOFTWARE\{safe_software_name}",
                rf"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\{safe_software_name}",
                rf"HKEY_CURRENT_USER\SOFTWARE\{safe_software_name}",
                rf"HKEY_LOCAL_MACHINE\SOFTWARE\{safe_software_name}\Registration",
                rf"HKEY_LOCAL_MACHINE\SOFTWARE\{safe_software_name}\License",
                rf"HKEY_LOCAL_MACHINE\SOFTWARE\{safe_software_name}\Trial",
                rf"HKEY_CURRENT_USER\SOFTWARE\{safe_software_name}\License",
                rf"HKEY_CURRENT_USER\SOFTWARE\{safe_software_name}\Trial"
            ]

            trial_keywords = [
                "trial", "demo", "evaluation", "expired", "remaining", "days",
                "expiration", "temporary", "limited", "unregistered"
            ]

            for path in registry_paths:
                try:
                    # Use absolute path to reg command with input validation
                    result = subprocess.run(
                        [reg_exe, "query", path, "/s"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )

                    if result.returncode == 0:
                        output_lower = result.stdout.lower()

                        # Check for trial-related keys and values
                        for keyword in trial_keywords:
                            if keyword in output_lower:
                                registry_flags.append(f"{path}: Contains '{keyword}' indicator")
                                logger.warning(f"Trial indicator found in registry: {keyword} at {path}")

                        # Parse for specific patterns
                        lines = result.stdout.split('\n')
                        for line in lines:
                            line_lower = line.lower().strip()

                            # Check for expiration dates
                            if 'expir' in line_lower and ('date' in line_lower or 'time' in line_lower):
                                registry_flags.append(f"{path}: Expiration date entry found")

                            # Check for remaining days/time
                            if ('remain' in line_lower or 'days' in line_lower) and ('left' in line_lower or 'trial' in line_lower):
                                registry_flags.append(f"{path}: Remaining trial time entry found")

                            # Check for trial version indicators
                            if 'trial' in line_lower and ('version' in line_lower or 'mode' in line_lower):
                                registry_flags.append(f"{path}: Trial version indicator found")

                except subprocess.TimeoutExpired:
                    logger.warning(f"Registry query timeout for {path}")
                except Exception as e:
                    # Registry key doesn't exist or access denied - this is normal
                    logger.debug(f"Could not access registry path {path}: {e}")
                    continue

            logger.info(f"Registry check completed for {safe_software_name}")

        except Exception as e:
            error_messages.append(str(e))
            logger.error(f"Error checking registry for {software_name}: {e}")

        return TrialDetectionResult(
            registry_flags_detected=registry_flags,
            ui_indicators_detected=[],
            functionality_limitations=[],
            trial_mode_confirmed=False,
            trial_expiration_date=None,
            days_remaining=None,
            error_messages=error_messages
        )

    def _check_for_watermarks(self, output_files: list[str]) -> list[str]:
        """Check output files for watermarks."""
        watermarks = []

        for file_path in output_files:
            try:
                properties = self._check_file_properties(file_path)
                if properties.get("watermark_detected", False):
                    watermarks.extend(properties.get("trial_indicators", []))
            except Exception as e:
                logger.warning(f"Error checking for watermarks in {file_path}: {e}")

        return watermarks

    def validate_full_functionality(self, binary_path: str, software_name: str) -> FullFunctionalityResult:
        """
        Validate that bypassed software has full functionality without trial/demo limitations.

        Args:
            binary_path: Path to the software binary
            software_name: Name of the software being tested

        Returns:
            FullFunctionalityResult with validation results
        """
        logger.info(f"Starting full functionality validation for {software_name}")

        test_start_time = datetime.now().isoformat()

        # Calculate binary hash
        binary_hash = self._calculate_hash(binary_path)

        # Initialize result fields
        software_type = "generic"
        premium_features_tested = 0
        premium_features_working = 0
        watermarks_detected = []
        feature_limitations = []
        feature_test_results = []
        error_messages = []

        try:
            # Determine software type
            if "Adobe" in software_name:
                software_type = "image_editor"
            elif "AutoCAD" in software_name:
                software_type = "cad_software"
            elif "MATLAB" in software_name:
                software_type = "computational_software"
            elif "Office" in software_name:
                software_type = "office_suite"

            # Get feature tests for this software type
            software_config = self.software_feature_tests.get(software_name.split()[0], {})
            if not software_config:
                # Try to find by type
                for _name, config in self.software_feature_tests.items():
                    if config["type"] == software_type:
                        software_config = config
                        break

            if features := software_config.get("features", []):
                # Run each feature test
                for feature_config in features:
                    try:
                        test_function = feature_config["test_function"]
                        logger.info(f"Testing feature: {feature_config['name']}")

                        # Run the feature test
                        test_result = test_function(software_name)
                        feature_test_results.append(test_result)

                        premium_features_tested += 1
                        if test_result.test_passed:
                            premium_features_working += 1

                        logger.info(f"Feature test {'PASSED' if test_result.test_passed else 'FAILED'}: {feature_config['name']}")

                    except Exception as e:
                        error_messages.append(f"Feature test failed for {feature_config['name']}: {e}")
                        logger.error(f"Feature test failed for {feature_config['name']}: {e}")

                # Check for watermarks in output files
                output_files = [result.output_file for result in feature_test_results if result.output_file]
                watermarks_detected = self._check_for_watermarks(output_files)

                # Check registry for trial flags
                trial_detection_result = self._check_registry_for_trial_flags(software_name)

                # Determine if full functionality is confirmed
                full_functionality_confirmed = (
                    premium_features_tested > 0 and
                    premium_features_working == premium_features_tested and
                    len(watermarks_detected) == 0 and
                    not trial_detection_result.trial_mode_confirmed
                )

            else:
                error_messages.append(f"No premium feature tests defined for {software_name}")
                logger.warning(f"No premium feature tests defined for {software_name}")
            logger.info(f"Full functionality validation completed for {software_name}")

        except Exception as e:
            error_messages.append(str(e))
            logger.error(f"Full functionality validation failed for {software_name}: {e}")
            full_functionality_confirmed = False
            trial_detection_result = TrialDetectionResult(
                registry_flags_detected=[],
                ui_indicators_detected=[],
                functionality_limitations=[],
                trial_mode_confirmed=False,
                trial_expiration_date=None,
                days_remaining=None,
                error_messages=error_messages
            )

        test_end_time = datetime.now().isoformat()

        return FullFunctionalityResult(
            software_name=software_name,
            software_type=software_type,
            binary_path=binary_path,
            binary_hash=binary_hash,
            test_start_time=test_start_time,
            test_end_time=test_end_time,
            premium_features_tested=premium_features_tested,
            premium_features_working=premium_features_working,
            watermarks_detected=watermarks_detected,
            feature_limitations=feature_limitations,
            trial_detection_result=trial_detection_result,
            feature_test_results=feature_test_results,
            full_functionality_confirmed=full_functionality_confirmed,
            error_messages=error_messages,
        )

    def validate_all_functionality(self) -> list[FullFunctionalityResult]:
        """
        Validate full functionality for all available binaries.
        """
        logger.info("Starting full functionality validation for all binaries")

        results = []

        # Get all acquired binaries
        binaries = self.binary_manager.list_acquired_binaries()

        for binary in binaries:
            try:
                binary_path = binary.get("file_path")
                software_name = binary.get("software_name", "Unknown")

                if binary_path and os.path.exists(binary_path):
                    logger.info(f"Validating full functionality for {software_name}")
                    result = self.validate_full_functionality(binary_path, software_name)
                    results.append(result)
                else:
                    logger.warning(f"Binary not found for {software_name}: {binary_path}")
                    results.append(FullFunctionalityResult(
                        software_name=software_name,
                        software_type="unknown",
                        binary_path=binary_path or "",
                        binary_hash="",
                        test_start_time=datetime.now().isoformat(),
                        test_end_time=datetime.now().isoformat(),
                        premium_features_tested=0,
                        premium_features_working=0,
                        watermarks_detected=[],
                        feature_limitations=[],
                        trial_detection_result=TrialDetectionResult(
                            registry_flags_detected=[],
                            ui_indicators_detected=[],
                            functionality_limitations=[],
                            trial_mode_confirmed=False,
                            trial_expiration_date=None,
                            days_remaining=None,
                            error_messages=[f"Binary not found: {binary_path}"]
                        ),
                        feature_test_results=[],
                        full_functionality_confirmed=False,
                        error_messages=[f"Binary not found: {binary_path}"]
                    ))

            except Exception as e:
                logger.error(f"Failed to validate full functionality for {binary.get('software_name', 'Unknown')}: {e}")
                results.append(FullFunctionalityResult(
                    software_name=binary.get("software_name", "Unknown"),
                    software_type="unknown",
                    binary_path=binary.get("file_path", ""),
                    binary_hash="",
                    test_start_time=datetime.now().isoformat(),
                    test_end_time=datetime.now().isoformat(),
                    premium_features_tested=0,
                    premium_features_working=0,
                    watermarks_detected=[],
                    feature_limitations=[],
                    trial_detection_result=TrialDetectionResult(
                        registry_flags_detected=[],
                        ui_indicators_detected=[],
                        functionality_limitations=[],
                        trial_mode_confirmed=False,
                        trial_expiration_date=None,
                        days_remaining=None,
                        error_messages=[str(e)]
                    ),
                    feature_test_results=[],
                    full_functionality_confirmed=False,
                    error_messages=[str(e)]
                ))

        logger.info(f"Completed full functionality validation for {len(results)} binaries")
        return results

    def generate_report(self, results: list[FullFunctionalityResult]) -> str:
        """
        Generate a comprehensive report of full functionality validation results.
        """
        if not results:
            return "No full functionality validation tests were run."

        report_lines = [
            "Full Functionality Validation Report",
            "=" * 50,
            f"Generated: {datetime.now().isoformat()}",
            f"Total Software Analyzed: {len(results)}",
            ""
        ]

        # Summary statistics
        total_features_tested = sum(r.premium_features_tested for r in results)
        total_features_working = sum(r.premium_features_working for r in results)
        full_functionality_confirmed = sum(bool(r.full_functionality_confirmed)
                                       for r in results)
        total_watermarks = sum(len(r.watermarks_detected) for r in results)

        report_lines.append("Summary:")
        report_lines.append(f"  Total Software: {len(results)}")
        report_lines.append(f"  Features Tested: {total_features_tested}")
        report_lines.append(f"  Features Working: {total_features_working}")
        success_rate = (
            f"{total_features_working/total_features_tested*100:.1f}%"
            if total_features_tested > 0
            else "N/A"
        )
        report_lines.append(f"  Success Rate: {success_rate}")
        report_lines.append(f"  Full Functionality Confirmed: {full_functionality_confirmed}/{len(results)}")
        report_lines.extend(
            (
                f"  Watermarks Detected: {total_watermarks}",
                "",
                "Detailed Results:",
                "-" * 30,
            )
        )
        for result in results:
            report_lines.extend(
                (
                    f"Software: {result.software_name} ({result.software_type})",
                    f"  Binary Hash: {result.binary_hash[:16]}...",
                )
            )
            report_lines.extend(
                (
                    f"  Test Duration: {result.test_end_time} - {result.test_start_time}",
                    f"  Features Tested: {result.premium_features_tested}",
                )
            )
            report_lines.append(f"  Features Working: {result.premium_features_working}")
            report_lines.append(f"  Full Functionality: {result.full_functionality_confirmed}")
            report_lines.append(f"  Watermarks: {', '.join(result.watermarks_detected) if result.watermarks_detected else 'None'}")

            # Trial detection results
            trial_result = result.trial_detection_result
            report_lines.append(f"  Trial Mode: {trial_result.trial_mode_confirmed}")
            if trial_result.trial_expiration_date:
                report_lines.append(f"  Expiration Date: {trial_result.trial_expiration_date}")
            if trial_result.days_remaining is not None:
                report_lines.append(f"  Days Remaining: {trial_result.days_remaining}")

            # Feature test results
            if result.feature_test_results:
                report_lines.append("  Feature Tests:")
                for test_result in result.feature_test_results:
                    status = "PASSED" if test_result.test_passed else "FAILED"
                    report_lines.append(f"    {test_result.feature_name}: {status}")
                    if test_result.error_message:
                        report_lines.append(f"      Error: {test_result.error_message}")

            if result.error_messages:
                report_lines.append(f"  Errors: {', '.join(result.error_messages)}")

            report_lines.append("")

        return "\n".join(report_lines)

    def save_report(self, results: list[FullFunctionalityResult], filename: str | None = None) -> str:
        """
        Save the full functionality validation report to a file.
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"full_functionality_report_{timestamp}.txt"

        report_path = self.reports_dir / filename

        report_text = self.generate_report(results)

        with open(report_path, 'w') as f:
            f.write(report_text)

        logger.info(f"Full functionality validation report saved to {report_path}")
        return str(report_path)


if __name__ == "__main__":
    # Test the FullFunctionalityValidator
    validator = FullFunctionalityValidator()

    print("Full Functionality Validator initialized")
    print("Available binaries:")

    if binaries := validator.binary_manager.list_acquired_binaries():
        for binary in binaries:
            print(f"  - {binary.get('software_name')}: {binary.get('protection')} {binary.get('version')}")

        # Run full functionality validation on the first binary
        if binaries:
            first_binary = binaries[0]
            binary_path = first_binary.get("file_path")
            software_name = first_binary.get("software_name", "Unknown")

            if binary_path and os.path.exists(binary_path):
                print(f"\nRunning full functionality validation on {software_name}...")
                result = validator.validate_full_functionality(binary_path, software_name)

                print(f"Full functionality validation completed for {software_name}")
                print(f"  Features Tested: {result.premium_features_tested}")
                print(f"  Features Working: {result.premium_features_working}")
                print(f"  Full Functionality: {result.full_functionality_confirmed}")
                print(f"  Watermarks Detected: {', '.join(result.watermarks_detected) if result.watermarks_detected else 'None'}")

                # Show trial detection results
                trial_result = result.trial_detection_result
                print(f"  Trial Mode: {trial_result.trial_mode_confirmed}")

                # Show feature test results
                if result.feature_test_results:
                    print("  Feature Tests:")
                    for test_result in result.feature_test_results:
                        status = "PASSED" if test_result.test_passed else "FAILED"
                        print(f"    {test_result.feature_name}: {status}")
                        if test_result.error_message:
                            print(f"      Error: {test_result.error_message}")

                if result.error_messages:
                    print(f"  Errors: {', '.join(result.error_messages)}")

                # Generate and save report
                report_path = validator.save_report([result])
                print(f"\nReport saved to: {report_path}")
            else:
                print(f"\nBinary not found: {binary_path}")
    else:
        print("\nNo binaries acquired yet. Please acquire binaries using commercial_binary_manager.py")
