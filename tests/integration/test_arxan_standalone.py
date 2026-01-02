"""Standalone test script for Arxan modules.

Tests Arxan detector, analyzer, and bypass without full framework import.
"""

import struct
import sys
import tempfile
from pathlib import Path


def create_test_pe_binary(test_dir: Path, arxan_sigs: list[bytes] | None = None) -> Path:
    """Create minimal PE binary with optional Arxan signatures."""
    dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack("<HHIIIHH", 0x014c, 1, 0, 0, 0, 0xe0, 0x010b)
    optional_header = b"\x0b\x01" + b"\x00" * 222

    section_header = (
        b".text\x00\x00\x00"
        + struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x600, 0x600, 0, 0, 0x60000020)
    )

    section_data = b"\x90" * 0x600

    if arxan_sigs:
        section_data = b""
        for sig in arxan_sigs:
            section_data += sig + b"\x90" * 50

        section_data = section_data[:0x600].ljust(0x600, b"\x00")

    binary = dos_header + pe_signature + coff_header + optional_header + section_header + section_data

    test_file = test_dir / "test.exe"
    with open(test_file, "wb") as f:
        f.write(binary)

    return test_file


def test_arxan_detector() -> None:
    """Test ArxanDetector."""
    print("\n=== Testing ArxanDetector ===")

    from intellicrack.core.protection_detection.arxan_detector import ArxanDetector

    detector = ArxanDetector()
    print("OK ArxanDetector initialized")

    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)

        clean_binary = create_test_pe_binary(test_dir)
        result = detector.detect(clean_binary)

        assert result.is_protected == False, "Clean binary should not be detected as protected"
        print("OK Clean binary detection works")

        arxan_sigs = [b"Arxan Technologies", b"TransformIT", b"GuardIT"]
        protected_binary = create_test_pe_binary(test_dir / "protected", arxan_sigs)
        protected_binary.parent.mkdir(exist_ok=True)
        protected_binary = create_test_pe_binary(protected_binary.parent, arxan_sigs)

        result = detector.detect(protected_binary)

        assert result.is_protected == True, "Arxan-protected binary should be detected"
        assert result.confidence > 0.5, f"Confidence should be > 0.5, got {result.confidence}"
        assert len(result.signatures_found) > 0, "Should find signatures"
        print(f"OK Arxan protection detected (confidence: {result.confidence:.2%})")
        print(f"OK Found {len(result.signatures_found)} signatures")

    print("OK All ArxanDetector tests passed\n")


def test_arxan_analyzer() -> None:
    """Test ArxanAnalyzer."""
    print("=== Testing ArxanAnalyzer ===")

    from intellicrack.core.analysis.arxan_analyzer import ArxanAnalyzer

    analyzer = ArxanAnalyzer()
    print("OK ArxanAnalyzer initialized")

    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)

        section_data = (
            b"Arxan TransformIT"
            + b"\x33\xd2\x8a\x10"
            + b"\x85\xc0\x75\x02" * 20
            + b"frida"
            + b"license"
        )

        test_file = test_dir / "test.exe"
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014c, 1, 0, 0, 0, 0xe0, 0x010b)
        optional_header = b"\x0b\x01" + b"\x00" * 222
        section_header = (
            b".text\x00\x00\x00"
            + struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x600, 0x600, 0, 0, 0x60000020)
        )

        section_data = section_data.ljust(0x600, b"\x00")
        binary = dos_header + pe_signature + coff_header + optional_header + section_header + section_data

        with open(test_file, "wb") as f:
            f.write(binary)

        result = analyzer.analyze(test_file)

        assert result is not None, "Analysis should return results"
        assert result.metadata.get("analysis_complete") == True, "Analysis should complete"
        print("OK Analysis completed successfully")
        print(f"OK Control flow obfuscation density: {result.control_flow.obfuscation_density:.2%}")

    print("OK All ArxanAnalyzer tests passed\n")


def test_arxan_bypass() -> None:
    """Test ArxanBypass."""
    print("=== Testing ArxanBypass ===")

    from intellicrack.core.protection_bypass.arxan_bypass import ArxanBypass

    bypass = ArxanBypass()
    print("OK ArxanBypass initialized")

    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)

        arxan_sigs = [b"Arxan", b"\x33\xd2\x8a\x10", b"license"]
        protected_binary = create_test_pe_binary(test_dir, arxan_sigs)

        result = bypass.bypass(protected_binary)

        assert result.success == True, "Bypass should succeed"
        assert result.patched_binary_path is not None, "Should create patched binary"
        assert Path(result.patched_binary_path).exists(), "Patched binary should exist"
        print("OK Bypass completed successfully")
        print(f"OK Patches applied: {len(result.patches_applied)}")
        print(f"OK Patched binary: {result.patched_binary_path}")

    print("OK All ArxanBypass tests passed\n")


def test_integration() -> None:
    """Test complete workflow."""
    print("=== Testing Complete Integration ===")

    from intellicrack.core.protection_detection.arxan_detector import ArxanDetector
    from intellicrack.core.analysis.arxan_analyzer import ArxanAnalyzer
    from intellicrack.core.protection_bypass.arxan_bypass import ArxanBypass

    with tempfile.TemporaryDirectory() as temp_dir:
        test_dir = Path(temp_dir)

        section_data = (
            b"Arxan Technologies Inc."
            + b"TransformIT 7.0"
            + b"\x64\xa1\x30\x00\x00\x00"
            + b"\x33\xd2\x8a\x10"
            + b"license_check"
            + b"frida"
        )

        test_file = test_dir / "arxan_protected.exe"
        dos_header = b"MZ" + b"\x90" * 58 + struct.pack("<I", 0x80)
        pe_signature = b"PE\x00\x00"
        coff_header = struct.pack("<HHIIIHH", 0x014c, 1, 0, 0, 0, 0xe0, 0x010b)
        optional_header = b"\x0b\x01" + b"\x00" * 222
        section_header = (
            b".text\x00\x00\x00"
            + struct.pack("<IIIIHHI", 0x1000, 0x1000, 0x600, 0x600, 0, 0, 0x60000020)
        )

        section_data = section_data.ljust(0x600, b"\x00")
        binary = dos_header + pe_signature + coff_header + optional_header + section_header + section_data

        with open(test_file, "wb") as f:
            f.write(binary)

        detector = ArxanDetector()
        detection_result = detector.detect(test_file)

        assert detection_result.is_protected == True, "Should detect Arxan protection"
        print(f"OK Detection: {detection_result.confidence:.2%} confidence")

        analyzer = ArxanAnalyzer()
        analysis_result = analyzer.analyze(test_file)

        assert analysis_result.metadata.get("analysis_complete") == True
        print("OK Analysis completed")

        bypass = ArxanBypass()
        bypass_result = bypass.bypass(test_file)

        assert bypass_result.success == True, "Bypass should succeed"
        print("OK Bypass completed")
        print(f"OK Patched binary created at: {bypass_result.patched_binary_path}")

    print("OK All integration tests passed\n")


def main() -> int:
    """Run all tests."""
    print("\n" + "=" * 60)
    print("Arxan TransformIT Support - Standalone Test Suite")
    print("=" * 60)

    try:
        test_arxan_detector()
        test_arxan_analyzer()
        test_arxan_bypass()
        test_integration()

        print("=" * 60)
        print("OKOKOK ALL TESTS PASSED OKOKOK")
        print("=" * 60)
        print("\nArxan support implementation successful!")
        print("- Detection: signature-based and heuristic analysis")
        print("- Analysis: tamper checks, RASP, license validation")
        print("- Bypass: integrity neutralization, license bypass")
        print("- Integration: complete workflow tested")

        return 0

    except Exception as e:
        print(f"\nFAIL TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
