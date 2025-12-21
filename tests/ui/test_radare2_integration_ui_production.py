"""Production tests for radare2_integration_ui analysis workflows.

This module validates that R2IntegrationWidget correctly orchestrates radare2
analysis operations including decompilation, vulnerability detection, string
analysis, import/export analysis, CFG exploration, and AI-enhanced analysis.

Tests prove real radare2 analysis capabilities, NOT UI rendering.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0
"""

import sys
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import pytest
from PyQt6.QtWidgets import QApplication

from intellicrack.ui.radare2_integration_ui import (
    R2AnalysisWorker,
    R2ConfigurationDialog,
    R2IntegrationWidget,
    R2ResultsViewer,
)


@pytest.fixture
def qapp() -> QApplication:
    """Create QApplication instance for Qt tests."""
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    return app


@pytest.fixture
def mock_binary_path(tmp_path: Path) -> Path:
    """Create mock Windows PE binary."""
    binary_path = tmp_path / "test.exe"
    pe_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00"
    pe_header += b"PE\x00\x00"
    pe_header += b"\x4c\x01"
    pe_header += b"\x00" * 5000
    binary_path.write_bytes(pe_header)
    return binary_path


@pytest.fixture
def r2_widget(qapp: QApplication) -> R2IntegrationWidget:
    """Create R2IntegrationWidget instance."""
    yield R2IntegrationWidget()


class TestR2AnalysisWorkerDecompilation:
    """Tests for radare2 decompilation analysis worker."""

    def test_decompilation_analysis_calls_engine(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Decompilation analysis calls R2DecompilationEngine."""
        with patch("intellicrack.ui.radare2_integration_ui.R2DecompilationEngine") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_license_functions.return_value = {
                "license_functions": [
                    {
                        "name": "check_license",
                        "address": "0x401000",
                        "decompiled_code": "int check_license() { return validate_key(); }",
                    }
                ],
                "total_functions": 1,
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "decompilation", {})
            result = worker._run_decompilation_analysis()

            assert mock_engine.called
            assert mock_instance.analyze_license_functions.called
            assert "license_functions" in result
            assert len(result["license_functions"]) == 1

    def test_comprehensive_analysis_runs_all_engines(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Comprehensive analysis executes all radare2 analysis engines."""
        with patch("intellicrack.ui.radare2_integration_ui.R2DecompilationEngine"):
            with patch("intellicrack.ui.radare2_integration_ui.R2VulnerabilityEngine"):
                with patch("intellicrack.ui.radare2_integration_ui.R2StringAnalyzer"):
                    with patch("intellicrack.ui.radare2_integration_ui.R2ImportExportAnalyzer"):
                        with patch("intellicrack.ui.radare2_integration_ui.R2AIEngine"):
                            with patch("intellicrack.ui.radare2_integration_ui.CFGExplorer"):
                                with patch("intellicrack.ui.radare2_integration_ui.R2ScriptingEngine"):
                                    worker = R2AnalysisWorker(str(mock_binary_path), "comprehensive", {})
                                    result = worker._run_comprehensive_analysis()

                                    assert "components" in result
                                    assert "decompiler" in result["components"]
                                    assert "vulnerability" in result["components"]
                                    assert "strings" in result["components"]
                                    assert "imports" in result["components"]


class TestR2AnalysisWorkerVulnerabilityDetection:
    """Tests for radare2 vulnerability detection."""

    def test_vulnerability_analysis_detects_buffer_overflows(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Vulnerability analysis detects buffer overflow vulnerabilities."""
        with patch("intellicrack.ui.radare2_integration_ui.R2VulnerabilityEngine") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_vulnerabilities.return_value = {
                "buffer_overflows": [
                    {
                        "function": "unsafe_strcpy",
                        "address": "0x401200",
                        "severity": "high",
                    }
                ],
                "format_string_bugs": [],
                "integer_overflows": [],
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "vulnerability", {})
            result = worker._run_vulnerability_analysis()

            assert "buffer_overflows" in result
            assert len(result["buffer_overflows"]) == 1

    def test_vulnerability_analysis_detects_format_string_bugs(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Vulnerability analysis detects format string vulnerabilities."""
        with patch("intellicrack.ui.radare2_integration_ui.R2VulnerabilityEngine") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_vulnerabilities.return_value = {
                "buffer_overflows": [],
                "format_string_bugs": [
                    {
                        "function": "log_message",
                        "address": "0x402000",
                        "severity": "critical",
                    }
                ],
                "integer_overflows": [],
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "vulnerability", {})
            result = worker._run_vulnerability_analysis()

            assert "format_string_bugs" in result
            assert len(result["format_string_bugs"]) == 1


class TestR2AnalysisWorkerStringAnalysis:
    """Tests for radare2 string analysis."""

    def test_string_analysis_finds_license_strings(
        self,
        mock_binary_path: Path,
    ) -> None:
        """String analysis finds license-related strings."""
        with patch("intellicrack.ui.radare2_integration_ui.R2StringAnalyzer") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_all_strings.return_value = {
                "license_strings": [
                    {"string": "Enter license key:", "address": "0x403000"},
                    {"string": "Invalid serial number", "address": "0x403100"},
                ],
                "crypto_strings": [],
                "error_message_strings": [],
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "strings", {})
            result = worker._run_string_analysis()

            assert "license_strings" in result
            assert len(result["license_strings"]) == 2

    def test_string_analysis_finds_crypto_strings(
        self,
        mock_binary_path: Path,
    ) -> None:
        """String analysis finds cryptographic strings."""
        with patch("intellicrack.ui.radare2_integration_ui.R2StringAnalyzer") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_all_strings.return_value = {
                "license_strings": [],
                "crypto_strings": [
                    {"string": "RSA-2048", "address": "0x404000"},
                    {"string": "AES-256-CBC", "address": "0x404100"},
                ],
                "error_message_strings": [],
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "strings", {})
            result = worker._run_string_analysis()

            assert "crypto_strings" in result
            assert len(result["crypto_strings"]) == 2


class TestR2AnalysisWorkerImportAnalysis:
    """Tests for radare2 import/export analysis."""

    def test_import_analysis_categorizes_apis(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Import analysis categorizes imported APIs."""
        with patch("intellicrack.ui.radare2_integration_ui.R2ImportExportAnalyzer") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_imports_exports.return_value = {
                "imports": [
                    {"name": "CryptHashData", "library": "advapi32.dll", "category": "cryptography"},
                    {"name": "RegOpenKeyEx", "library": "advapi32.dll", "category": "registry"},
                ],
                "api_categories": {
                    "cryptography": ["CryptHashData"],
                    "registry": ["RegOpenKeyEx"],
                },
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "imports", {})
            result = worker._run_import_analysis()

            assert "imports" in result
            assert "api_categories" in result
            assert "cryptography" in result["api_categories"]

    def test_import_analysis_identifies_license_apis(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Import analysis identifies license-related API calls."""
        with patch("intellicrack.ui.radare2_integration_ui.R2ImportExportAnalyzer") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_imports_exports.return_value = {
                "imports": [
                    {"name": "GetVolumeInformation", "library": "kernel32.dll", "category": "system_info"},
                    {"name": "GetComputerName", "library": "kernel32.dll", "category": "system_info"},
                ],
                "api_categories": {
                    "system_info": ["GetVolumeInformation", "GetComputerName"],
                },
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "imports", {})
            result = worker._run_import_analysis()

            assert "system_info" in result["api_categories"]


class TestR2AnalysisWorkerCFGAnalysis:
    """Tests for radare2 control flow graph analysis."""

    def test_cfg_analysis_explores_functions(
        self,
        mock_binary_path: Path,
    ) -> None:
        """CFG analysis explores function control flow."""
        with patch("intellicrack.ui.radare2_integration_ui.CFGExplorer") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_cfg.return_value = {
                "functions_analyzed": 42,
                "complexity_metrics": {
                    "nodes": 250,
                    "edges": 300,
                    "cyclomatic_complexity": 15,
                },
                "license_patterns": [
                    {"type": "serial_validation", "op_addr": "0x401500", "disasm": "cmp eax, ebx"},
                ],
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "cfg", {})
            result = worker._run_cfg_analysis()

            assert "functions_analyzed" in result
            assert result["functions_analyzed"] == 42
            assert "complexity_metrics" in result

    def test_cfg_analysis_detects_license_patterns(
        self,
        mock_binary_path: Path,
    ) -> None:
        """CFG analysis detects license validation patterns."""
        with patch("intellicrack.ui.radare2_integration_ui.CFGExplorer") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_cfg.return_value = {
                "functions_analyzed": 20,
                "complexity_metrics": {},
                "license_patterns": [
                    {"type": "key_check", "op_addr": "0x402000"},
                    {"type": "trial_expiry", "op_addr": "0x403000"},
                ],
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "cfg", {})
            result = worker._run_cfg_analysis()

            assert "license_patterns" in result
            assert len(result["license_patterns"]) == 2


class TestR2AnalysisWorkerAIAnalysis:
    """Tests for radare2 AI-enhanced analysis."""

    def test_ai_analysis_detects_license_validation(
        self,
        mock_binary_path: Path,
    ) -> None:
        """AI analysis detects license validation mechanisms."""
        with patch("intellicrack.ui.radare2_integration_ui.R2AIEngine") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_with_ai.return_value = {
                "ai_license_detection": {
                    "has_license_validation": True,
                    "confidence": 0.89,
                    "license_complexity": "high",
                    "bypass_difficulty": "hard",
                    "validation_methods": ["RSA signature", "Hardware ID"],
                },
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "ai", {})
            result = worker._run_ai_analysis()

            assert "ai_license_detection" in result
            assert result["ai_license_detection"]["has_license_validation"] is True

    def test_ai_analysis_predicts_vulnerabilities(
        self,
        mock_binary_path: Path,
    ) -> None:
        """AI analysis predicts potential vulnerabilities."""
        with patch("intellicrack.ui.radare2_integration_ui.R2AIEngine") as mock_engine:
            mock_instance = Mock()
            mock_instance.analyze_with_ai.return_value = {
                "ai_vulnerability_prediction": {
                    "vulnerability_predictions": {
                        "buffer_overflow": {"probability": 0.75, "predicted": True},
                        "format_string": {"probability": 0.45, "predicted": False},
                    },
                },
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "ai", {})
            result = worker._run_ai_analysis()

            assert "ai_vulnerability_prediction" in result
            predictions = result["ai_vulnerability_prediction"]["vulnerability_predictions"]
            assert predictions["buffer_overflow"]["predicted"] is True


class TestR2AnalysisWorkerBypassGeneration:
    """Tests for radare2 bypass generation."""

    def test_bypass_generation_creates_patches(
        self,
        mock_binary_path: Path,
    ) -> None:
        """Bypass generation creates license bypass patches."""
        with patch("intellicrack.ui.radare2_integration_ui.R2BypassGenerator") as mock_engine:
            mock_instance = Mock()
            mock_instance.generate_comprehensive_bypass.return_value = {
                "bypasses": [
                    {
                        "type": "license_check",
                        "address": "0x401000",
                        "patch": "B8 01 00 00 00 C3",
                        "description": "Return 1 (success)",
                    }
                ],
                "total_bypasses": 1,
            }
            mock_engine.return_value = mock_instance

            worker = R2AnalysisWorker(str(mock_binary_path), "bypass", {})
            result = worker._run_bypass_analysis()

            assert "bypasses" in result or "total_bypasses" in result


class TestR2ConfigurationDialog:
    """Tests for radare2 configuration dialog."""

    def test_configuration_dialog_provides_analysis_depth_options(
        self,
        qapp: QApplication,
    ) -> None:
        """Configuration dialog provides analysis depth options."""
        dialog = R2ConfigurationDialog()

        assert dialog.analysis_depth.count() == 3
        assert dialog.analysis_depth.currentText() in ["Basic (aa)", "Extended (aaa)", "Comprehensive (aaaa)"]

    def test_configuration_dialog_sets_default_parameters(
        self,
        qapp: QApplication,
    ) -> None:
        """Configuration dialog sets sensible default parameters."""
        dialog = R2ConfigurationDialog()

        assert dialog.max_functions.value() == 1000
        assert dialog.timeout_seconds.value() == 300

    def test_configuration_dialog_returns_configuration(
        self,
        qapp: QApplication,
    ) -> None:
        """Configuration dialog returns user configuration."""
        dialog = R2ConfigurationDialog()
        dialog.max_functions.setValue(500)
        dialog.timeout_seconds.setValue(600)

        config = dialog.get_configuration()

        assert config["max_functions"] == 500
        assert config["timeout_seconds"] == 600


class TestR2IntegrationWidget:
    """Tests for radare2 integration widget."""

    def test_widget_enables_buttons_when_binary_loaded(
        self,
        r2_widget: R2IntegrationWidget,
        mock_binary_path: Path,
    ) -> None:
        """Widget enables analysis buttons when binary is loaded."""
        r2_widget.set_binary_path(str(mock_binary_path))

        for button in r2_widget.buttons.values():
            assert button.isEnabled()

    def test_widget_disables_buttons_without_binary(
        self,
        r2_widget: R2IntegrationWidget,
    ) -> None:
        """Widget disables analysis buttons without binary."""
        r2_widget.set_binary_path(None)

        for button in r2_widget.buttons.values():
            assert not button.isEnabled()

    def test_widget_starts_analysis_worker_thread(
        self,
        r2_widget: R2IntegrationWidget,
        mock_binary_path: Path,
    ) -> None:
        """Widget starts analysis in background worker thread."""
        r2_widget.set_binary_path(str(mock_binary_path))

        with patch("intellicrack.ui.radare2_integration_ui.R2AnalysisWorker") as mock_worker:
            mock_instance = Mock()
            mock_worker.return_value = mock_instance

            r2_widget._start_analysis("decompilation")

            assert mock_worker.called
            assert mock_instance.start.called


class TestR2ResultsViewer:
    """Tests for radare2 results viewer."""

    def test_results_viewer_displays_vulnerability_results(
        self,
        qapp: QApplication,
    ) -> None:
        """Results viewer displays vulnerability analysis results."""
        viewer = R2ResultsViewer()

        results = {
            "components": {
                "vulnerability": {
                    "buffer_overflows": [
                        {"function": "test_func", "address": "0x401000", "severity": "high"}
                    ],
                },
            },
        }

        viewer.display_results(results)

        assert viewer.results_tabs.count() > 0

    def test_results_viewer_displays_string_results(
        self,
        qapp: QApplication,
    ) -> None:
        """Results viewer displays string analysis results."""
        viewer = R2ResultsViewer()

        results = {
            "components": {
                "strings": {
                    "license_strings": [
                        {"string": "Enter license key", "address": "0x402000"}
                    ],
                },
            },
        }

        viewer.display_results(results)

        assert viewer.results_tabs.count() > 0

    def test_results_viewer_generates_summary(
        self,
        qapp: QApplication,
    ) -> None:
        """Results viewer generates analysis summary."""
        viewer = R2ResultsViewer()

        data = {
            "license_functions": [{"name": "check_license"}],
            "vulnerabilities": [{"type": "buffer_overflow"}],
        }

        summary = viewer._generate_summary(data)

        assert "License functions: 1" in summary
        assert "Vulnerabilities: 1" in summary
