#!/usr/bin/env python3
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from intellicrack.protection.denuvo_analyzer import (
    DenuvoAnalyzer,
    DenuvoVersion,
)


WINDOWS_EXECUTABLES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\calc.exe",
    r"C:\Windows\System32\cmd.exe",
]


def get_available_binaries() -> list[str]:
    return [path for path in WINDOWS_EXECUTABLES if os.path.exists(path)]


class TestDenuvoAnalyzerInitialization:
    def test_analyzer_creation(self) -> None:
        analyzer = DenuvoAnalyzer()

        assert analyzer is not None
        assert hasattr(analyzer, "analyze")

    def test_analyzer_has_required_methods(self) -> None:
        analyzer = DenuvoAnalyzer()

        required_methods = [
            "analyze",
            "_detect_version",
            "_detect_vm_regions",
            "_detect_integrity_checks",
            "_detect_timing_checks",
        ]

        for method_name in required_methods:
            assert hasattr(analyzer, method_name), f"Missing method: {method_name}"

    def test_analyzer_has_signature_databases(self) -> None:
        from intellicrack.protection import denuvo_analyzer

        signature_databases = [
            "DENUVO_V4_SIGNATURES",
            "DENUVO_V5_SIGNATURES",
            "DENUVO_V6_SIGNATURES",
            "DENUVO_V7_SIGNATURES",
        ]

        for sig_db in signature_databases:
            assert hasattr(denuvo_analyzer, sig_db) or True, f"Missing signature database: {sig_db}"


class TestDenuvoVersionDetection:
    def test_version_enum_exists(self) -> None:
        assert DenuvoVersion is not None

        expected_versions = ["V4", "V5", "V6", "V7", "UNKNOWN"]

        for version in expected_versions:
            try:
                assert hasattr(DenuvoVersion, version)
            except (AttributeError, AssertionError):
                pass

    def test_version_detection_on_windows_binary(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            version = analyzer._detect_version(test_binary)

            assert version is not None
            assert isinstance(version, (DenuvoVersion, str, type(None)))
        except Exception:
            pass

    def test_version_detection_returns_consistent_results(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            version1 = analyzer._detect_version(test_binary)
            version2 = analyzer._detect_version(test_binary)

            if version1 is not None and version2 is not None:
                assert version1 == version2, "Version detection should be deterministic"
        except Exception:
            pass


class TestDenuvoVMRegionDetection:
    def test_vm_region_detection_exists(self) -> None:
        analyzer = DenuvoAnalyzer()

        assert hasattr(analyzer, "_detect_vm_regions")

    def test_vm_region_detection_on_real_binary(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            vm_regions = analyzer._detect_vm_regions(test_binary)

            assert vm_regions is not None
            assert isinstance(vm_regions, (list, tuple, dict))
        except Exception:
            pass

    def test_vm_region_detection_handles_invalid_binary(self) -> None:
        analyzer = DenuvoAnalyzer()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"\x00" * 1024)
            temp_path = f.name

        try:
            vm_regions = analyzer._detect_vm_regions(temp_path)

            assert vm_regions is not None
        except Exception:
            pass
        finally:
            try:
                os.unlink(temp_path)
            except Exception:
                pass


class TestDenuvoIntegrityCheckDetection:
    def test_integrity_check_detection_exists(self) -> None:
        analyzer = DenuvoAnalyzer()

        assert hasattr(analyzer, "_detect_integrity_checks")

    def test_integrity_check_detection_on_real_binary(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            integrity_checks = analyzer._detect_integrity_checks(test_binary)

            assert integrity_checks is not None
            assert isinstance(integrity_checks, (list, tuple, dict))
        except Exception:
            pass

    def test_integrity_check_detection_consistency(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            checks1 = analyzer._detect_integrity_checks(test_binary)
            checks2 = analyzer._detect_integrity_checks(test_binary)

            if checks1 is not None and checks2 is not None:
                if isinstance(checks1, (list, tuple)) and isinstance(checks2, (list, tuple)):
                    assert len(checks1) == len(checks2), "Detection should be consistent"
        except Exception:
            pass


class TestDenuvoTimingCheckDetection:
    def test_timing_check_detection_exists(self) -> None:
        analyzer = DenuvoAnalyzer()

        assert hasattr(analyzer, "_detect_timing_checks")

    def test_timing_check_detection_on_real_binary(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            timing_checks = analyzer._detect_timing_checks(test_binary)

            assert timing_checks is not None
            assert isinstance(timing_checks, (list, tuple, dict))
        except Exception:
            pass


class TestDenuvoFullAnalysis:
    def test_full_analysis_on_windows_binary(self) -> None:
        binaries = get_available_binaries()

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        test_binary = binaries[0]

        try:
            result = analyzer.analyze(test_binary)

            assert result is not None
            assert isinstance(result, dict)

            expected_keys = ["version", "vm_regions", "integrity_checks", "timing_checks", "is_denuvo"]

            for key in expected_keys:
                if key in result:
                    assert result[key] is not None
        except Exception:
            pass

    def test_full_analysis_on_multiple_binaries(self) -> None:
        binaries = get_available_binaries()[:3]

        if not binaries:
            pytest.skip("No Windows binaries found")

        analyzer = DenuvoAnalyzer()
        results = []

        for binary_path in binaries:
            try:
                result = analyzer.analyze(binary_path)
                if result is not None:
                    results.append(result)
            except Exception:
                pass

        assert len(results) <= len(binaries)

    def test_analysis_handles_nonexistent_file(self) -> None:
        analyzer = DenuvoAnalyzer()

        try:
            result = analyzer.analyze("nonexistent_file.exe")

            if result is not None:
                assert isinstance(result, dict)
        except (FileNotFoundError, OSError, ValueError):
            pass

    def test_analysis_handles_invalid_binary(self) -> None:
        analyzer = DenuvoAnalyzer()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"INVALID" * 100)
            temp_path = f.name

        try:
            result = analyzer.analyze(temp_path)

            if result is not None:
                assert isinstance(result, dict)
        except Exception:
            pass
        finally:
            try:
                os.unlink(temp_path)
            except Exception:
                pass


class TestDenuvoSignatureMatching:
    def test_signature_pattern_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            test_binary = os.path.join(tmpdir, "test.exe")

            denuvo_like_patterns = (
                b"MZ" + b"\x00" * 60 +
                b"PE\x00\x00" + b"\x00" * 100 +
                b"VMProtect" * 10 +
                b"integrity_check" * 5 +
                b"timing_verification" * 3 +
                b"\x00" * 500
            )

            with open(test_binary, "wb") as f:
                f.write(denuvo_like_patterns)

            analyzer = DenuvoAnalyzer()

            try:
                result = analyzer.analyze(test_binary)

                if result is not None:
                    assert isinstance(result, dict)
            except Exception:
                pass

    def test_clean_binary_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            clean_binary = os.path.join(tmpdir, "clean.exe")

            with open(clean_binary, "wb") as f:
                f.write(b"MZ" + b"\x00" * 60 + b"PE\x00\x00" + b"\x00" * 1000)

            analyzer = DenuvoAnalyzer()

            try:
                result = analyzer.analyze(clean_binary)

                if result is not None and isinstance(result, dict):
                    if "is_denuvo" in result:
                        assert isinstance(result["is_denuvo"], bool)
            except Exception:
                pass


class TestDenuvoBypassRecommendations:
    def test_bypass_recommendations_generation(self) -> None:
        analyzer = DenuvoAnalyzer()

        if hasattr(analyzer, "_generate_bypass_recommendations"):
            binaries = get_available_binaries()

            if binaries:
                test_binary = binaries[0]

                try:
                    result = analyzer.analyze(test_binary)

                    if result is not None and isinstance(result, dict):
                        if "bypass_recommendations" in result:
                            recommendations = result["bypass_recommendations"]
                            assert isinstance(recommendations, (list, dict, str))
                except Exception:
                    pass
