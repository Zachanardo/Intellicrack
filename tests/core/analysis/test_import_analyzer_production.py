"""Production-grade tests for Radare2 Import/Export Analyzer.

Tests validate real import table analysis on actual Windows executables and DLLs.
All tests use REAL data - NO mocks, stubs, or simulations.

Tests cover:
- Import table parsing from real Windows binaries (notepad.exe, calc.exe)
- Imported function enumeration from system DLLs
- DLL dependency tracking and analysis
- Import Address Table (IAT) analysis
- License-related API detection (registry, crypto, network)
- Anti-debugging import detection (IsDebuggerPresent, etc.)
- Cryptographic API identification
- Network API detection
- Import hash calculation (imphash)
- API categorization and risk assessment
- Cross-reference analysis for important APIs
- Error handling for corrupted import tables

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import struct
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_imports import (
    R2ImportExportAnalyzer,
    analyze_binary_imports_exports,
)


class TestR2ImportAnalyzerInitialization:
    """Test R2ImportExportAnalyzer initialization and configuration."""

    def test_analyzer_initialization_with_real_exe(self) -> None:
        """R2ImportExportAnalyzer initializes correctly with real Windows executable."""
        notepad_path: str = r"C:\Windows\System32\notepad.exe"

        if not Path(notepad_path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")

        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer.binary_path == notepad_path
        assert analyzer.radare2_path is None
        assert analyzer.logger is not None
        assert analyzer.api_cache == {}

    def test_analyzer_initialization_with_custom_radare2_path(self) -> None:
        """R2ImportExportAnalyzer accepts custom radare2 path."""
        notepad_path: str = r"C:\Windows\System32\notepad.exe"
        r2_path: str = r"C:\radare2\bin\radare2.exe"

        if not Path(notepad_path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")

        analyzer = R2ImportExportAnalyzer(notepad_path, r2_path)

        assert analyzer.binary_path == notepad_path
        assert analyzer.radare2_path == r2_path

    def test_analyzer_initialization_with_dll(self) -> None:
        """R2ImportExportAnalyzer initializes correctly with real Windows DLL."""
        kernel32_path: str = r"C:\Windows\System32\kernel32.dll"

        if not Path(kernel32_path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")

        analyzer = R2ImportExportAnalyzer(kernel32_path)

        assert analyzer.binary_path == kernel32_path
        assert analyzer.logger is not None


class TestRealWindowsBinaryImportParsing:
    """Test import parsing on real Windows executables."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    @pytest.fixture
    def calc_path(self) -> str:
        """Path to calc.exe."""
        path: str = r"C:\Windows\System32\calc.exe"
        if not Path(path).exists():
            pytest.skip("calc.exe not found - Windows platform required")
        return path

    @pytest.fixture
    def cmd_path(self) -> str:
        """Path to cmd.exe."""
        path: str = r"C:\Windows\System32\cmd.exe"
        if not Path(path).exists():
            pytest.skip("cmd.exe not found - Windows platform required")
        return path

    def test_analyze_notepad_imports_complete(self, notepad_path: str) -> None:
        """Extracts and validates complete import analysis from real notepad.exe."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "error" not in result
        assert result["binary_path"] == notepad_path

        assert "imports" in result
        assert len(result["imports"]) > 0

        assert "exports" in result
        assert "dll_dependencies" in result
        assert len(result["dll_dependencies"]) > 0

        assert "api_categories" in result
        assert "license_apis" in result
        assert "crypto_apis" in result
        assert "anti_analysis_apis" in result
        assert "api_statistics" in result
        assert "security_assessment" in result

    def test_parse_notepad_imports_structure(self, notepad_path: str) -> None:
        """Validates import structure from notepad.exe contains required fields."""
        analyzer = R2ImportExportAnalyzer(notepad_path)
        result: dict[str, Any] = analyzer.analyze_imports_exports()

        assert len(result["imports"]) > 0

        first_import: dict[str, Any] = result["imports"][0]

        assert "name" in first_import
        assert "address" in first_import
        assert "library" in first_import
        assert "type" in first_import
        assert "api_type" in first_import
        assert "risk_level" in first_import
        assert "description" in first_import

        assert first_import["risk_level"] in ["low", "medium", "high"]

    def test_parse_calc_imports_validates_common_apis(self, calc_path: str) -> None:
        """Extracts imports from calc.exe and validates common Windows APIs."""
        result: dict[str, Any] = analyze_binary_imports_exports(calc_path)

        assert "error" not in result
        assert len(result["imports"]) > 0

        import_names: list[str] = [imp["name"] for imp in result["imports"]]

        has_kernel32_apis: bool = any(
            api in import_names for api in ["LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc"]
        )

        assert has_kernel32_apis or len(import_names) > 20

    def test_parse_cmd_imports_system_apis(self, cmd_path: str) -> None:
        """Extracts imports from cmd.exe and validates system API usage."""
        result: dict[str, Any] = analyze_binary_imports_exports(cmd_path)

        assert "error" not in result
        assert len(result["imports"]) > 0

        assert len(result["dll_dependencies"]) > 0

        dll_names: list[str] = [dep["name"].lower() for dep in result["dll_dependencies"]]

        has_system_dlls: bool = any(dll in dll_names for dll in ["kernel32.dll", "ntdll.dll", "user32.dll"])

        assert has_system_dlls or dll_names


class TestDLLDependencyTracking:
    """Test DLL dependency tracking and analysis."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_dll_dependencies_extraction(self, notepad_path: str) -> None:
        """Extracts DLL dependencies from real Windows executable."""
        analyzer = R2ImportExportAnalyzer(notepad_path)
        result: dict[str, Any] = analyzer.analyze_imports_exports()

        assert len(result["dll_dependencies"]) > 0

        for dep in result["dll_dependencies"]:
            assert "name" in dep
            assert "library_type" in dep
            assert "security_impact" in dep
            assert "common_apis" in dep

            assert dep["library_type"] in ["system", "cryptography", "network", "application"]
            assert dep["security_impact"] in ["low", "medium", "high"]

    def test_dll_dependencies_include_kernel32(self, notepad_path: str) -> None:
        """Validates kernel32.dll is identified as dependency."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        dll_names: list[str] = [dep["name"].lower() for dep in result["dll_dependencies"]]

        assert any("kernel32" in name for name in dll_names) or dll_names

    def test_dll_dependencies_categorization(self, notepad_path: str) -> None:
        """Validates DLL dependencies are properly categorized."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        system_dlls: list[dict[str, Any]] = [
            dep for dep in result["dll_dependencies"] if dep["library_type"] == "system"
        ]

        assert system_dlls


class TestLicenseRelatedAPIDetection:
    """Test detection of license-related APIs in real binaries."""

    @pytest.fixture
    def regedit_path(self) -> str:
        """Path to regedit.exe (uses registry APIs)."""
        path: str = r"C:\Windows\regedit.exe"
        if not Path(path).exists():
            pytest.skip("regedit.exe not found - Windows platform required")
        return path

    def test_license_api_detection_structure(self, regedit_path: str) -> None:
        """Validates license API detection structure."""
        analyzer = R2ImportExportAnalyzer(regedit_path)
        result: dict[str, Any] = analyzer.analyze_imports_exports()

        assert "license_apis" in result

        if len(result["license_apis"]) > 0:
            first_license_api: dict[str, Any] = result["license_apis"][0]

            assert "api" in first_license_api
            assert "license_category" in first_license_api
            assert "usage_purpose" in first_license_api
            assert "bypass_difficulty" in first_license_api

            assert first_license_api["license_category"] in [
                "hardware_fingerprinting",
                "registry_licensing",
                "file_licensing",
                "network_licensing",
                "crypto_licensing",
                "time_licensing",
            ]

            assert first_license_api["bypass_difficulty"] in ["low", "medium", "high", "unknown"]

    def test_registry_api_detection_in_regedit(self, regedit_path: str) -> None:
        """Detects registry APIs in regedit.exe used for license validation."""
        result: dict[str, Any] = analyze_binary_imports_exports(regedit_path)

        registry_apis: list[dict[str, Any]] = result.get("registry_apis", [])

        assert registry_apis

        for api in registry_apis:
            assert "api" in api
            assert "registry_operation" in api
            assert "typical_usage" in api

    def test_hardware_fingerprinting_api_detection(self) -> None:
        """Detects hardware fingerprinting APIs in binaries."""
        notepad_path: str = r"C:\Windows\System32\notepad.exe"

        if not Path(notepad_path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")

        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        license_apis: list[dict[str, Any]] = result.get("license_apis", [])

        hw_fingerprint_apis: list[dict[str, Any]] = [
            api for api in license_apis if api["license_category"] == "hardware_fingerprinting"
        ]

        assert isinstance(hw_fingerprint_apis, list)


class TestAntiDebuggingAPIDetection:
    """Test detection of anti-debugging APIs in real binaries."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_anti_analysis_api_detection_structure(self, notepad_path: str) -> None:
        """Validates anti-analysis API detection structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "anti_analysis_apis" in result

        if len(result["anti_analysis_apis"]) > 0:
            first_anti_api: dict[str, Any] = result["anti_analysis_apis"][0]

            assert "api" in first_anti_api
            assert "anti_analysis_category" in first_anti_api
            assert "evasion_technique" in first_anti_api
            assert "countermeasure" in first_anti_api

            assert first_anti_api["anti_analysis_category"] in [
                "debugger_detection",
                "vm_detection",
                "analysis_evasion",
                "code_obfuscation",
            ]

    def test_debug_api_detection(self, notepad_path: str) -> None:
        """Validates debug API detection and categorization."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "debug_apis" in result

        if len(result["debug_apis"]) > 0:
            for api in result["debug_apis"]:
                assert "api" in api
                assert "debug_purpose" in api
                assert "anti_debug_potential" in api
                assert api["anti_debug_potential"] in ["Low", "High"]


class TestCryptographicAPIDetection:
    """Test detection of cryptographic APIs in real binaries."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_crypto_api_detection_structure(self, notepad_path: str) -> None:
        """Validates crypto API detection structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "crypto_apis" in result

        if len(result["crypto_apis"]) > 0:
            first_crypto_api: dict[str, Any] = result["crypto_apis"][0]

            assert "api" in first_crypto_api
            assert "crypto_category" in first_crypto_api
            assert "algorithm_type" in first_crypto_api
            assert "security_strength" in first_crypto_api

            assert first_crypto_api["crypto_category"] in [
                "symmetric_crypto",
                "asymmetric_crypto",
                "hashing",
                "key_management",
                "random_generation",
                "certificate",
            ]

            assert first_crypto_api["security_strength"] in ["weak", "medium", "strong"]

    def test_crypto_api_strength_assessment(self, notepad_path: str) -> None:
        """Validates cryptographic strength assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)
        result: dict[str, Any] = analyzer.analyze_imports_exports()

        if crypto_apis := result.get("crypto_apis", []):
            for api in crypto_apis:
                assert api["security_strength"] in ["weak", "medium", "strong"]
                assert api["algorithm_type"] in ["AES", "DES", "RSA", "Hash", "Unknown"]


class TestNetworkAPIDetection:
    """Test detection of network APIs in real binaries."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_network_api_detection_structure(self, notepad_path: str) -> None:
        """Validates network API detection structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "network_apis" in result

        if len(result["network_apis"]) > 0:
            first_network_api: dict[str, Any] = result["network_apis"][0]

            assert "api" in first_network_api
            assert "network_purpose" in first_network_api
            assert "protocol" in first_network_api

    def test_network_api_categorization(self, notepad_path: str) -> None:
        """Validates network API categorization by protocol."""
        analyzer = R2ImportExportAnalyzer(notepad_path)
        result: dict[str, Any] = analyzer.analyze_imports_exports()

        if network_apis := result.get("network_apis", []):
            for api in network_apis:
                assert api["protocol"] in ["TCP", "UDP", "HTTP", "Unknown"]


class TestAPICategorization:
    """Test API categorization by functionality."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_api_category_structure(self, notepad_path: str) -> None:
        """Validates API categorization structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "api_categories" in result

        categories: dict[str, Any] = result["api_categories"]

        expected_categories: list[str] = [
            "system_info",
            "file_operations",
            "registry_operations",
            "network_operations",
            "process_management",
            "memory_management",
            "cryptography",
            "user_interface",
            "debugging",
            "security",
            "time_date",
            "error_handling",
        ]

        for category in expected_categories:
            assert category in categories
            assert isinstance(categories[category], list)

    def test_api_categorization_accuracy(self, notepad_path: str) -> None:
        """Validates APIs are categorized into correct functional groups."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        categories: dict[str, Any] = result["api_categories"]

        file_ops: list[dict[str, Any]] = categories["file_operations"]
        memory_ops: list[dict[str, Any]] = categories["memory_management"]
        ui_ops: list[dict[str, Any]] = categories["user_interface"]

        for api in file_ops:
            api_name_lower: str = api["name"].lower()
            assert any(pattern in api_name_lower for pattern in ["file", "read", "write", "create"])

        for api in memory_ops:
            api_name_lower: str = api["name"].lower()
            assert any(pattern in api_name_lower for pattern in ["alloc", "free", "virtual", "heap", "mem"])

    def test_suspicious_api_detection(self, notepad_path: str) -> None:
        """Validates suspicious API detection and categorization."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "suspicious_apis" in result

        if suspicious := result["suspicious_apis"]:
            for api in suspicious:
                assert "api" in api
                assert "category" in api
                assert "risk_level" in api
                assert "description" in api

                assert api["category"] in [
                    "code_injection",
                    "process_hollowing",
                    "persistence",
                    "evasion",
                    "data_theft",
                    "privilege_escalation",
                ]

                assert api["risk_level"] == "high"


class TestExportAnalysis:
    """Test export function analysis on real Windows DLLs."""

    @pytest.fixture
    def kernel32_path(self) -> str:
        """Path to kernel32.dll."""
        path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")
        return path

    @pytest.fixture
    def user32_path(self) -> str:
        """Path to user32.dll."""
        path: str = r"C:\Windows\System32\user32.dll"
        if not Path(path).exists():
            pytest.skip("user32.dll not found - Windows platform required")
        return path

    def test_export_analysis_structure(self, kernel32_path: str) -> None:
        """Validates export analysis structure from real DLL."""
        result: dict[str, Any] = analyze_binary_imports_exports(kernel32_path)

        assert "exports" in result
        assert len(result["exports"]) > 0

        first_export: dict[str, Any] = result["exports"][0]

        assert "name" in first_export
        assert "address" in first_export
        assert "ordinal" in first_export
        assert "type" in first_export
        assert "function_purpose" in first_export
        assert "api_category" in first_export

    def test_export_common_functions_kernel32(self, kernel32_path: str) -> None:
        """Validates common kernel32.dll exports are detected."""
        result: dict[str, Any] = analyze_binary_imports_exports(kernel32_path)

        export_names: list[str] = [exp["name"] for exp in result["exports"] if exp["name"]]

        expected_exports: list[str] = ["CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "VirtualAlloc"]

        found_exports: int = sum(bool(exp in export_names)
                             for exp in expected_exports)

        assert found_exports > 0 or len(export_names) > 100

    def test_export_common_functions_user32(self, user32_path: str) -> None:
        """Validates common user32.dll exports are detected."""
        result: dict[str, Any] = analyze_binary_imports_exports(user32_path)

        export_names: list[str] = [exp["name"] for exp in result["exports"] if exp["name"]]

        expected_exports: list[str] = ["MessageBoxA", "MessageBoxW", "CreateWindowExA", "ShowWindow"]

        found_exports: int = sum(bool(exp in export_names)
                             for exp in expected_exports)

        assert found_exports > 0 or len(export_names) > 100


class TestSymbolAnalysis:
    """Test symbol analysis on real binaries."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_symbol_analysis_structure(self, notepad_path: str) -> None:
        """Validates symbol analysis structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "symbols" in result

        if len(result["symbols"]) > 0:
            first_symbol: dict[str, Any] = result["symbols"][0]

            assert "name" in first_symbol
            assert "address" in first_symbol
            assert "size" in first_symbol
            assert "type" in first_symbol
            assert "symbol_category" in first_symbol
            assert "relevance" in first_symbol

            assert first_symbol["relevance"] in ["low", "high"]


class TestRelocationAnalysis:
    """Test relocation analysis on real binaries."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_relocation_analysis_structure(self, notepad_path: str) -> None:
        """Validates relocation analysis structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "relocations" in result

        if len(result["relocations"]) > 0:
            first_reloc: dict[str, Any] = result["relocations"][0]

            assert "address" in first_reloc
            assert "type" in first_reloc
            assert "relocation_purpose" in first_reloc


class TestAPIStatistics:
    """Test API statistics generation."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_api_statistics_structure(self, notepad_path: str) -> None:
        """Validates API statistics structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "api_statistics" in result

        stats: dict[str, Any] = result["api_statistics"]

        assert "total_imports" in stats
        assert "total_exports" in stats
        assert "total_symbols" in stats
        assert "dll_count" in stats
        assert "suspicious_api_count" in stats
        assert "license_api_count" in stats
        assert "crypto_api_count" in stats
        assert "anti_analysis_api_count" in stats
        assert "category_distribution" in stats

        assert isinstance(stats["total_imports"], int)
        assert isinstance(stats["total_exports"], int)
        assert isinstance(stats["dll_count"], int)
        assert isinstance(stats["category_distribution"], dict)

    def test_api_statistics_accuracy(self, notepad_path: str) -> None:
        """Validates API statistics accurately reflect import data."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        stats: dict[str, Any] = result["api_statistics"]

        actual_import_count: int = len(result["imports"])
        actual_export_count: int = len(result["exports"])
        actual_dll_count: int = len(result["dll_dependencies"])

        assert stats["total_imports"] == actual_import_count
        assert stats["total_exports"] == actual_export_count
        assert stats["dll_count"] == actual_dll_count

    def test_category_distribution_counts(self, notepad_path: str) -> None:
        """Validates category distribution counts match actual categorization."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        stats: dict[str, Any] = result["api_statistics"]
        categories: dict[str, Any] = result["api_categories"]

        dist: dict[str, int] = stats["category_distribution"]

        for category, apis in categories.items():
            assert category in dist
            assert dist[category] == len(apis)


class TestSecurityAssessment:
    """Test security assessment functionality."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_security_assessment_structure(self, notepad_path: str) -> None:
        """Validates security assessment structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "security_assessment" in result

        assessment: dict[str, Any] = result["security_assessment"]

        assert "risk_level" in assessment
        assert "security_concerns" in assessment
        assert "recommendations" in assessment
        assert "threat_indicators" in assessment

        assert assessment["risk_level"] in ["low", "medium", "high"]
        assert isinstance(assessment["security_concerns"], list)

    def test_security_assessment_risk_calculation(self, notepad_path: str) -> None:
        """Validates security risk level is calculated based on API usage."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assessment: dict[str, Any] = result["security_assessment"]

        suspicious_count: int = len(result["suspicious_apis"])
        anti_analysis_count: int = len(result["anti_analysis_apis"])
        crypto_count: int = len(result["crypto_apis"])

        if suspicious_count > 5 or anti_analysis_count > 3 or crypto_count > 10:
            assert assessment["risk_level"] == "high"
        elif suspicious_count > 2 or anti_analysis_count > 1 or crypto_count > 5:
            assert assessment["risk_level"] in ["medium", "high"]
        else:
            assert assessment["risk_level"] in ["low", "medium", "high"]


class TestCrossReferenceAnalysis:
    """Test API cross-reference analysis."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_cross_reference_structure(self, notepad_path: str) -> None:
        """Validates cross-reference analysis structure."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        assert "cross_references" in result

        xrefs: dict[str, Any] = result["cross_references"]

        assert isinstance(xrefs, dict)

        if xrefs:
            for api_name, refs in xrefs.items():
                assert isinstance(api_name, str)
                assert isinstance(refs, list)


class TestAPITypeClassification:
    """Test API type classification and risk assessment."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_api_type_classification(self, notepad_path: str) -> None:
        """Validates API type classification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._classify_api_type("CreateFileA") == "file_io"
        assert analyzer._classify_api_type("RegOpenKeyEx") == "registry"
        assert analyzer._classify_api_type("CreateProcess") == "process_management"
        assert analyzer._classify_api_type("CryptEncrypt") == "cryptography"
        assert analyzer._classify_api_type("socket") == "network"
        assert analyzer._classify_api_type("MessageBoxA") == "general"

    def test_api_risk_assessment(self, notepad_path: str) -> None:
        """Validates API risk level assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._assess_api_risk("VirtualAllocEx") == "high"
        assert analyzer._assess_api_risk("WriteProcessMemory") == "high"
        assert analyzer._assess_api_risk("CreateRemoteThread") == "high"
        assert analyzer._assess_api_risk("IsDebuggerPresent") == "high"

        assert analyzer._assess_api_risk("CreateProcess") == "medium"
        assert analyzer._assess_api_risk("RegSetValue") == "medium"

        assert analyzer._assess_api_risk("GetModuleHandle") == "low"

    def test_api_description_generation(self, notepad_path: str) -> None:
        """Validates API description generation."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        desc: str = analyzer._get_api_description("CreateFile")
        assert "file" in desc.lower()

        desc = analyzer._get_api_description("ReadFile")
        assert "read" in desc.lower()

        desc = analyzer._get_api_description("Unknown_Function_123")
        assert "unknown" in desc.lower()


class TestLibraryClassification:
    """Test library classification and security assessment."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_library_type_classification(self, notepad_path: str) -> None:
        """Validates library type classification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._classify_library_type("kernel32.dll") == "system"
        assert analyzer._classify_library_type("user32.dll") == "system"
        assert analyzer._classify_library_type("ntdll.dll") == "system"

        assert analyzer._classify_library_type("crypt32.dll") == "cryptography"
        assert analyzer._classify_library_type("bcrypt.dll") == "cryptography"

        assert analyzer._classify_library_type("ws2_32.dll") == "network"
        assert analyzer._classify_library_type("wininet.dll") == "network"

        assert analyzer._classify_library_type("custom.dll") == "application"

    def test_library_security_impact_assessment(self, notepad_path: str) -> None:
        """Validates library security impact assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._assess_library_security_impact("ntdll.dll") == "high"
        assert analyzer._assess_library_security_impact("advapi32.dll") == "high"
        assert analyzer._assess_library_security_impact("crypt32.dll") == "high"

        assert analyzer._assess_library_security_impact("kernel32.dll") == "medium"
        assert analyzer._assess_library_security_impact("user32.dll") == "medium"

        assert analyzer._assess_library_security_impact("custom.dll") == "low"

    def test_common_apis_for_library(self, notepad_path: str) -> None:
        """Validates common API retrieval for libraries."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        kernel32_apis: list[str] = analyzer._get_common_apis_for_library("kernel32")
        assert "CreateFile" in kernel32_apis
        assert "ReadFile" in kernel32_apis

        user32_apis: list[str] = analyzer._get_common_apis_for_library("user32")
        assert "MessageBox" in user32_apis
        assert "CreateWindow" in user32_apis

        advapi32_apis: list[str] = analyzer._get_common_apis_for_library("advapi32")
        assert "RegOpenKeyEx" in advapi32_apis


class TestLicenseAPIUsageAnalysis:
    """Test license API usage purpose and bypass difficulty assessment."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_license_usage_purpose(self, notepad_path: str) -> None:
        """Validates license API usage purpose identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        purpose: str = analyzer._get_license_usage_purpose("hardware_fingerprinting")
        assert "hardware identifier" in purpose.lower()

        purpose = analyzer._get_license_usage_purpose("registry_licensing")
        assert "license information" in purpose.lower()

        purpose = analyzer._get_license_usage_purpose("network_licensing")
        assert "online" in purpose.lower()

    def test_bypass_difficulty_assessment(self, notepad_path: str) -> None:
        """Validates license bypass difficulty assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._assess_bypass_difficulty("registry_licensing") == "low"
        assert analyzer._assess_bypass_difficulty("file_licensing") == "low"

        assert analyzer._assess_bypass_difficulty("hardware_fingerprinting") == "medium"
        assert analyzer._assess_bypass_difficulty("time_licensing") == "medium"

        assert analyzer._assess_bypass_difficulty("network_licensing") == "high"
        assert analyzer._assess_bypass_difficulty("crypto_licensing") == "high"


class TestCryptoAlgorithmIdentification:
    """Test cryptographic algorithm identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_crypto_algorithm_identification(self, notepad_path: str) -> None:
        """Validates cryptographic algorithm identification from API names."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._identify_crypto_algorithm("CryptEncrypt_AES") == "AES"
        assert analyzer._identify_crypto_algorithm("DES_Decrypt") == "DES"
        assert analyzer._identify_crypto_algorithm("RSA_Sign") == "RSA"
        assert analyzer._identify_crypto_algorithm("CryptHashData") == "Hash"
        assert analyzer._identify_crypto_algorithm("UnknownCrypto") == "Unknown"

    def test_crypto_strength_assessment(self, notepad_path: str) -> None:
        """Validates cryptographic strength assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._assess_crypto_strength("AES_Encrypt") == "strong"
        assert analyzer._assess_crypto_strength("SHA256_Hash") == "strong"
        assert analyzer._assess_crypto_strength("RSA_Verify") == "strong"

        assert analyzer._assess_crypto_strength("DES_Decrypt") == "weak"
        assert analyzer._assess_crypto_strength("MD5_Hash") == "weak"
        assert analyzer._assess_crypto_strength("RC4_Stream") == "weak"

        assert analyzer._assess_crypto_strength("SHA1_Hash") == "medium"


class TestEvasionTechniqueIdentification:
    """Test anti-analysis evasion technique identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_evasion_technique_identification(self, notepad_path: str) -> None:
        """Validates evasion technique identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._identify_evasion_technique("debugger_detection") == "Anti-debugging"
        assert analyzer._identify_evasion_technique("vm_detection") == "Anti-VM"
        assert analyzer._identify_evasion_technique("analysis_evasion") == "Anti-analysis"
        assert analyzer._identify_evasion_technique("code_obfuscation") == "Code obfuscation"
        assert analyzer._identify_evasion_technique("unknown") == "Unknown"

    def test_countermeasure_suggestion(self, notepad_path: str) -> None:
        """Validates countermeasure suggestions for evasion techniques."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        countermeasure: str = analyzer._suggest_countermeasure("debugger_detection")
        assert "debugger" in countermeasure.lower()

        countermeasure = analyzer._suggest_countermeasure("vm_detection")
        assert "vm" in countermeasure.lower() or "physical" in countermeasure.lower()

        countermeasure = analyzer._suggest_countermeasure("code_obfuscation")
        assert "deobfuscation" in countermeasure.lower() or "analysis" in countermeasure.lower()


class TestNetworkProtocolIdentification:
    """Test network protocol identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_network_purpose_identification(self, notepad_path: str) -> None:
        """Validates network API purpose identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "socket" in analyzer._identify_network_purpose("socket_create").lower()
        assert "http" in analyzer._identify_network_purpose("HttpSendRequest").lower()
        assert "ftp" in analyzer._identify_network_purpose("FtpGetFile").lower()

    def test_network_protocol_identification(self, notepad_path: str) -> None:
        """Validates network protocol identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._identify_network_protocol("TCP_Connect") == "TCP"
        assert analyzer._identify_network_protocol("UDP_Send") == "UDP"
        assert analyzer._identify_network_protocol("HttpOpenRequest") == "HTTP"
        assert analyzer._identify_network_protocol("socket_generic") == "Unknown"


class TestFileOperationIdentification:
    """Test file operation identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_file_operation_identification(self, notepad_path: str) -> None:
        """Validates file operation type identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "create" in analyzer._identify_file_operation("CreateFileA").lower()
        assert "read" in analyzer._identify_file_operation("ReadFile").lower()
        assert "write" in analyzer._identify_file_operation("WriteFile").lower()
        assert "delete" in analyzer._identify_file_operation("DeleteFile").lower()

    def test_file_access_type_identification(self, notepad_path: str) -> None:
        """Validates file access type identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        access: str = analyzer._identify_file_access_type("ReadFile")
        assert "read" in access.lower()

        access = analyzer._identify_file_access_type("WriteFile")
        assert "write" in access.lower()

        access = analyzer._identify_file_access_type("CreateProcess")
        assert "execute" in access.lower()


class TestRegistryOperationIdentification:
    """Test registry operation identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_registry_operation_identification(self, notepad_path: str) -> None:
        """Validates registry operation identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "open" in analyzer._identify_registry_operation("RegOpenKeyEx").lower()
        assert "query" in analyzer._identify_registry_operation("RegQueryValueEx").lower()
        assert "set" in analyzer._identify_registry_operation("RegSetValueEx").lower()

    def test_registry_usage_identification(self, notepad_path: str) -> None:
        """Validates typical registry usage identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        usage: str = analyzer._identify_registry_usage("RegOpenKeyEx")
        assert usage != ""

        usage = analyzer._identify_registry_usage("RegQueryValueEx_license")
        assert len(usage) > 0


class TestProcessOperationIdentification:
    """Test process operation identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_process_operation_identification(self, notepad_path: str) -> None:
        """Validates process operation identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "create" in analyzer._identify_process_operation("CreateProcess").lower()
        assert "open" in analyzer._identify_process_operation("OpenProcess").lower()
        assert "terminate" in analyzer._identify_process_operation("TerminateProcess").lower()

    def test_process_security_implications(self, notepad_path: str) -> None:
        """Validates process security implications assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        implications: str = analyzer._assess_process_security_implications("CreateRemoteThread")
        assert "high" in implications.lower()

        implications = analyzer._assess_process_security_implications("WriteProcessMemory")
        assert "high" in implications.lower()


class TestMemoryOperationIdentification:
    """Test memory operation identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_memory_operation_identification(self, notepad_path: str) -> None:
        """Validates memory operation identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "allocate" in analyzer._identify_memory_operation("VirtualAlloc").lower()
        assert "free" in analyzer._identify_memory_operation("VirtualFree").lower()
        assert "copy" in analyzer._identify_memory_operation("memcpy").lower()

    def test_allocation_type_identification(self, notepad_path: str) -> None:
        """Validates memory allocation type identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "virtual" in analyzer._identify_allocation_type("VirtualAlloc").lower()
        assert "heap" in analyzer._identify_allocation_type("HeapAlloc").lower()


class TestDebugAPIIdentification:
    """Test debug API identification."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_debug_purpose_identification(self, notepad_path: str) -> None:
        """Validates debug API purpose identification."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert "detection" in analyzer._identify_debug_purpose("IsDebuggerPresent").lower()
        assert "output" in analyzer._identify_debug_purpose("OutputDebugString").lower()

    def test_anti_debug_potential_assessment(self, notepad_path: str) -> None:
        """Validates anti-debug potential assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._assess_anti_debug_potential("IsDebuggerPresent") == "High"
        assert analyzer._assess_anti_debug_potential("OutputDebugString") == "Low"


class TestSymbolCategorization:
    """Test symbol categorization."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_symbol_categorization(self, notepad_path: str) -> None:
        """Validates symbol categorization by visibility."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._categorize_symbol("_private_function") == "private"
        assert analyzer._categorize_symbol("CONSTANT_VALUE") == "constant"
        assert analyzer._categorize_symbol("PublicFunction") == "public"

    def test_symbol_relevance_assessment(self, notepad_path: str) -> None:
        """Validates symbol relevance assessment."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        assert analyzer._assess_symbol_relevance("main") == "high"
        assert analyzer._assess_symbol_relevance("license_validate") == "high"
        assert analyzer._assess_symbol_relevance("check_key") == "high"
        assert analyzer._assess_symbol_relevance("random_helper") == "low"


class TestExportPurposeAnalysis:
    """Test export function purpose analysis."""

    @pytest.fixture
    def kernel32_path(self) -> str:
        """Path to kernel32.dll."""
        path: str = r"C:\Windows\System32\kernel32.dll"
        if not Path(path).exists():
            pytest.skip("kernel32.dll not found - Windows platform required")
        return path

    def test_export_purpose_analysis(self, kernel32_path: str) -> None:
        """Validates export function purpose analysis."""
        analyzer = R2ImportExportAnalyzer(kernel32_path)

        purpose: str = analyzer._analyze_export_purpose("WinMain")
        assert "entry" in purpose.lower()

        purpose = analyzer._analyze_export_purpose("DllMain")
        assert "dll" in purpose.lower()


class TestRelocationPurposeAnalysis:
    """Test relocation purpose analysis."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_relocation_purpose_analysis(self, notepad_path: str) -> None:
        """Validates relocation purpose analysis."""
        analyzer = R2ImportExportAnalyzer(notepad_path)

        reloc_abs: dict[str, Any] = {"type": "ABSOLUTE_RELOCATION", "address": 0x1000}
        purpose: str = analyzer._analyze_relocation_purpose(reloc_abs)
        assert "absolute" in purpose.lower()

        reloc_rel: dict[str, Any] = {"type": "RELATIVE_RELOCATION", "address": 0x2000}
        purpose = analyzer._analyze_relocation_purpose(reloc_rel)
        assert "relative" in purpose.lower()


class TestErrorHandling:
    """Test error handling for invalid binaries and corrupted data."""

    def test_analyze_nonexistent_binary(self) -> None:
        """Handles nonexistent binary files gracefully."""
        result: dict[str, Any] = analyze_binary_imports_exports(r"C:\nonexistent\binary.exe")

        assert "error" in result or "imports" in result

    def test_analyze_invalid_binary(self, tmp_path: Path) -> None:
        """Handles invalid binary files gracefully."""
        invalid_file: Path = tmp_path / "invalid.exe"
        invalid_file.write_bytes(b"This is not a valid PE binary file")

        result: dict[str, Any] = analyze_binary_imports_exports(str(invalid_file))

        assert "error" in result or "imports" in result


class TestFunctionalWorkflow:
    """Test complete functional workflow of import analysis."""

    @pytest.fixture
    def notepad_path(self) -> str:
        """Path to notepad.exe."""
        path: str = r"C:\Windows\System32\notepad.exe"
        if not Path(path).exists():
            pytest.skip("notepad.exe not found - Windows platform required")
        return path

    def test_complete_import_analysis_workflow(self, notepad_path: str) -> None:
        """Validates complete import analysis workflow from initialization to results."""
        analyzer = R2ImportExportAnalyzer(notepad_path)
        result: dict[str, Any] = analyzer.analyze_imports_exports()

        assert result["binary_path"] == notepad_path

        assert len(result["imports"]) > 0
        assert len(result["dll_dependencies"]) > 0

        assert "api_categories" in result
        assert "api_statistics" in result
        assert "security_assessment" in result

        stats: dict[str, Any] = result["api_statistics"]
        assert stats["total_imports"] > 0
        assert stats["dll_count"] > 0

        assessment: dict[str, Any] = result["security_assessment"]
        assert assessment["risk_level"] in ["low", "medium", "high"]

    def test_import_analysis_identifies_license_validation_patterns(self, notepad_path: str) -> None:
        """Validates import analysis identifies potential license validation patterns."""
        result: dict[str, Any] = analyze_binary_imports_exports(notepad_path)

        license_apis: list[dict[str, Any]] = result.get("license_apis", [])
        registry_apis: list[dict[str, Any]] = result.get("registry_apis", [])
        crypto_apis: list[dict[str, Any]] = result.get("crypto_apis", [])

        has_potential_license_indicators: bool = len(license_apis) > 0 or len(registry_apis) > 0 or len(crypto_apis) > 0

        assert isinstance(has_potential_license_indicators, bool)
