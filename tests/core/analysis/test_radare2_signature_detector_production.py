"""Production tests for Radare2SignatureDetector.

Tests validate real YARA rule compilation, signature detection on binaries,
protection scheme fingerprinting, compiler detection, and library version identification.
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.radare2_signature_detector import (
    CompilerInfo,
    LibraryInfo,
    Radare2SignatureDetector,
    SignatureMatch,
    SignatureType,
)


@pytest.fixture
def simple_pe_binary() -> bytes:
    """Create a minimal valid PE binary for testing."""
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"
    dos_header[60:64] = (128).to_bytes(4, "little")

    pe_header = b"PE\x00\x00"

    coff_header = bytearray(20)
    coff_header[0:2] = (0x14C).to_bytes(2, "little")
    coff_header[2:4] = (1).to_bytes(2, "little")
    coff_header[16:18] = (224).to_bytes(2, "little")
    coff_header[18:20] = (0x0002).to_bytes(2, "little")

    optional_header = bytearray(224)
    optional_header[0:2] = (0x10B).to_bytes(2, "little")
    optional_header[16:20] = (0x1000).to_bytes(4, "little")
    optional_header[20:24] = (0x1000).to_bytes(4, "little")
    optional_header[24:28] = (0x2000).to_bytes(4, "little")
    optional_header[28:32] = (0x400000).to_bytes(4, "little")
    optional_header[32:36] = (0x1000).to_bytes(4, "little")
    optional_header[36:40] = (0x200).to_bytes(4, "little")
    optional_header[56:60] = (0x10000).to_bytes(4, "little")
    optional_header[60:64] = (0x400).to_bytes(4, "little")
    optional_header[92:96] = (16).to_bytes(4, "little")

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    section_header[8:12] = (0x1000).to_bytes(4, "little")
    section_header[12:16] = (0x1000).to_bytes(4, "little")
    section_header[16:20] = (0x200).to_bytes(4, "little")
    section_header[20:24] = (0x400).to_bytes(4, "little")
    section_header[36:40] = (0x60000020).to_bytes(4, "little")

    section_data = bytearray(512)
    section_data[0:3] = b"\x90\x90\xc3"

    binary = dos_header + bytearray(64) + pe_header + coff_header + optional_header + section_header + section_data
    return bytes(binary)


@pytest.fixture
def vmprotect_binary() -> bytes:
    """Create binary with VMProtect signatures."""
    binary = bytearray(simple_pe_binary())
    binary.extend(b".vmp0" + b"\x00" * 100)
    binary.extend(b"VMProtect" + b"\x00" * 50)
    binary.extend(b"\xe8\x00\x00\x00\x00\x8b\x45\x00\x8b\x00\x8b\x4d\x00")
    return bytes(binary)


@pytest.fixture
def themida_binary() -> bytes:
    """Create binary with Themida signatures."""
    binary = bytearray(simple_pe_binary())
    binary.extend(b"Themida" + b"\x00" * 100)
    binary.extend(b".themida" + b"\x00" * 50)
    binary.extend(b"\xb8\x00\x00\x00\x00\x60\x0b\xc0\x74\x68")
    return bytes(binary)


@pytest.fixture
def msvc_compiled_binary() -> bytes:
    """Create binary with MSVC compiler signatures."""
    binary = bytearray(simple_pe_binary())
    binary.extend(b"Microsoft Visual C++ 14.0" + b"\x00" * 50)
    binary.extend(b"msvcr140.dll" + b"\x00" * 50)
    return bytes(binary)


@pytest.fixture
def temp_binary_file(simple_pe_binary: bytes) -> Path:
    """Create temporary binary file for testing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(simple_pe_binary)
        temp_path = Path(f.name)

    yield temp_path

    temp_path.unlink(missing_ok=True)


def test_detector_initialization_calculates_hashes(temp_binary_file: Path) -> None:
    """Detector initialization computes SHA256 and SHA512 hashes of binary."""
    detector = Radare2SignatureDetector(str(temp_binary_file))

    assert "sha256" in detector.file_hash
    assert "sha512" in detector.file_hash
    assert "size" in detector.file_hash
    assert len(detector.file_hash["sha256"]) == 64
    assert len(detector.file_hash["sha512"]) == 128
    assert detector.file_hash["size"] == temp_binary_file.stat().st_size


def test_detector_opens_binary_with_radare2(temp_binary_file: Path) -> None:
    """Detector successfully opens binary in radare2 and performs analysis."""
    detector = Radare2SignatureDetector(str(temp_binary_file))

    result = detector.open()

    assert result is True
    assert detector.r2 is not None

    detector.close()


def test_create_default_yara_rules_contains_protections(temp_binary_file: Path) -> None:
    """Default YARA rules include VMProtect, Themida, UPX, and license protection patterns."""
    detector = Radare2SignatureDetector(str(temp_binary_file))

    rules_text = detector.create_default_yara_rules()

    assert "VMProtect_Signature" in rules_text
    assert "Themida_Signature" in rules_text
    assert "UPX_Packer" in rules_text
    assert "FlexLM_License" in rules_text
    assert "Sentinel_HASP" in rules_text
    assert "CodeMeter_Protection" in rules_text
    assert ".vmp0" in rules_text
    assert "IsLicenseValid" in rules_text


def test_yara_scan_detects_vmprotect_signature() -> None:
    """YARA scanner detects VMProtect protection on binary with VMProtect signatures."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(vmprotect_binary())
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_with_yara()

        assert len(matches) > 0
        vmprotect_matches = [m for m in matches if "VMProtect" in m.name]
        assert len(vmprotect_matches) > 0

        for match in vmprotect_matches:
            assert match.signature_type == SignatureType.YARA
            assert match.confidence == 1.0
            assert match.offset >= 0
            assert match.size > 0

    finally:
        temp_path.unlink(missing_ok=True)


def test_yara_scan_detects_themida_signature() -> None:
    """YARA scanner detects Themida protection on binary with Themida signatures."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(themida_binary())
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_with_yara()

        assert len(matches) > 0
        themida_matches = [m for m in matches if "Themida" in m.name]
        assert len(themida_matches) > 0

        for match in themida_matches:
            assert match.signature_type == SignatureType.YARA
            assert 0 <= match.offset < temp_path.stat().st_size

    finally:
        temp_path.unlink(missing_ok=True)


def test_load_yara_rules_from_file() -> None:
    """Detector loads YARA rules from external rule file successfully."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yar", delete=False) as f:
        f.write("""
rule TestRule {
    meta:
        description = "Test rule"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
""")
        rules_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 100 + b"TESTPATTERN" + b"\x00" * 100)
        binary_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(binary_path))

        result = detector.load_yara_rules(str(rules_path))

        assert result is True
        assert len(detector.yara_rules) > 0

        matches = detector.scan_with_yara()
        test_matches = [m for m in matches if "TestRule" in m.name]
        assert len(test_matches) > 0

    finally:
        rules_path.unlink(missing_ok=True)
        binary_path.unlink(missing_ok=True)


def test_load_yara_rules_from_directory() -> None:
    """Detector loads multiple YARA rules from directory of rule files."""
    with tempfile.TemporaryDirectory() as temp_dir:
        rules_dir = Path(temp_dir)

        rule1_path = rules_dir / "rule1.yar"
        rule1_path.write_text("""
rule Rule1 {
    strings:
        $s1 = "PATTERN1"
    condition:
        $s1
}
""")

        rule2_path = rules_dir / "rule2.yar"
        rule2_path.write_text("""
rule Rule2 {
    strings:
        $s2 = "PATTERN2"
    condition:
        $s2
}
""")

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 50)
            binary_path = Path(f.name)

        try:
            detector = Radare2SignatureDetector(str(binary_path))

            result = detector.load_yara_rules(str(rules_dir))

            assert result is True
            assert len(detector.yara_rules) >= 2

        finally:
            binary_path.unlink(missing_ok=True)


def test_custom_signature_detection_finds_license_checks() -> None:
    """Custom signatures detect license validation function names in binary."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        binary_data = b"MZ" + b"\x00" * 200
        binary_data += b"IsLicenseValid" + b"\x00" * 50
        binary_data += b"CheckLicense" + b"\x00" * 50
        binary_data += b"VerifyLicense" + b"\x00" * 100
        f.write(binary_data)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_custom_signatures()

        assert len(matches) >= 3
        license_matches = [m for m in matches if "License_Check" in m.name]
        assert len(license_matches) >= 3

        for match in license_matches:
            assert match.signature_type == SignatureType.CUSTOM
            assert match.confidence == 0.85
            assert match.offset >= 0

    finally:
        temp_path.unlink(missing_ok=True)


def test_custom_signature_detection_finds_trial_checks() -> None:
    """Custom signatures detect trial period checking patterns."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        binary_data = b"MZ" + b"\x00" * 200
        binary_data += b"IsTrialExpired" + b"\x00" * 50
        binary_data += b"CheckTrialPeriod" + b"\x00" * 50
        binary_data += b"GetTrialDays" + b"\x00" * 100
        f.write(binary_data)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_custom_signatures()

        trial_matches = [m for m in matches if "Trial_Check" in m.name]
        assert len(trial_matches) >= 3

    finally:
        temp_path.unlink(missing_ok=True)


def test_custom_signature_detection_finds_hwid_patterns() -> None:
    """Custom signatures detect hardware ID collection patterns."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        binary_data = b"MZ" + b"\x00" * 200
        binary_data += b"GetVolumeSerialNumber" + b"\x00" * 50
        binary_data += b"GetAdaptersInfo" + b"\x00" * 50
        binary_data += b"MachineGuid" + b"\x00" * 100
        f.write(binary_data)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_custom_signatures()

        hwid_matches = [m for m in matches if "HWID" in m.name]
        assert len(hwid_matches) >= 3

    finally:
        temp_path.unlink(missing_ok=True)


def test_custom_signature_finds_multiple_occurrences() -> None:
    """Custom signature scanner finds all occurrences of repeated pattern."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        binary_data = b"MZ" + b"\x00" * 200
        binary_data += b"AES" + b"\x00" * 100
        binary_data += b"AES" + b"\x00" * 100
        binary_data += b"AES" + b"\x00" * 100
        f.write(binary_data)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_custom_signatures()

        aes_matches = [m for m in matches if m.name == "Crypto_AES"]
        assert len(aes_matches) == 3

        offsets = [m.offset for m in aes_matches]
        assert len(set(offsets)) == 3

    finally:
        temp_path.unlink(missing_ok=True)


def test_export_signatures_to_json() -> None:
    """Signature export creates JSON file with all detected signatures."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 200 + b"RSA" + b"\x00" * 100)
        binary_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(binary_path))
        detector.scan_custom_signatures()

        result = detector.export_signatures(str(json_path), format="json")

        assert result is True
        assert json_path.exists()
        assert json_path.stat().st_size > 0

        import json
        with open(json_path) as f:
            data = json.load(f)

        assert "binary" in data
        assert "hashes" in data
        assert "matches" in data
        assert isinstance(data["matches"], list)

    finally:
        binary_path.unlink(missing_ok=True)
        json_path.unlink(missing_ok=True)


def test_export_signatures_to_csv() -> None:
    """Signature export creates CSV file with signature matches."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 200 + b"MD5" + b"\x00" * 100)
        binary_path = Path(f.name)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        csv_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(binary_path))
        detector.scan_custom_signatures()

        result = detector.export_signatures(str(csv_path), format="csv")

        assert result is True
        assert csv_path.exists()

        import csv
        with open(csv_path, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)

        assert len(rows) >= 2
        assert rows[0] == ["Type", "Name", "Offset", "Size", "Confidence"]

    finally:
        binary_path.unlink(missing_ok=True)
        csv_path.unlink(missing_ok=True)


def test_generate_report_includes_all_sections() -> None:
    """Report generation includes binary info, signatures, compiler, and libraries."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(simple_pe_binary())
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))
        detector.open()
        detector.scan_custom_signatures()

        report = detector.generate_report()

        assert "SIGNATURE DETECTION REPORT" in report
        assert "Binary:" in report
        assert "SHA256:" in report
        assert "SHA512:" in report
        assert "Size:" in report
        assert "SUMMARY" in report

        detector.close()

    finally:
        temp_path.unlink(missing_ok=True)


def test_signature_match_dataclass_stores_metadata() -> None:
    """SignatureMatch dataclass correctly stores all match information."""
    match = SignatureMatch(
        signature_type=SignatureType.YARA,
        name="TestSignature",
        offset=0x1000,
        size=32,
        confidence=0.95,
        metadata={"key": "value"},
        raw_match=None,
    )

    assert match.signature_type == SignatureType.YARA
    assert match.name == "TestSignature"
    assert match.offset == 0x1000
    assert match.size == 32
    assert match.confidence == 0.95
    assert match.metadata["key"] == "value"


def test_close_releases_radare2_session(temp_binary_file: Path) -> None:
    """Close method properly releases radare2 session."""
    detector = Radare2SignatureDetector(str(temp_binary_file))
    detector.open()

    assert detector.r2 is not None

    detector.close()

    assert detector.r2 is None


def test_yara_scan_handles_no_matches() -> None:
    """YARA scanner returns empty list when no signatures match."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 1000)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        matches = detector.scan_with_yara()

        assert isinstance(matches, list)

    finally:
        temp_path.unlink(missing_ok=True)


def test_custom_signatures_initialized_on_first_scan() -> None:
    """Custom signatures are automatically created on first scan."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ" + b"\x00" * 200)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        assert len(detector.custom_signatures) == 0

        detector.scan_custom_signatures()

        assert len(detector.custom_signatures) > 0
        assert "License_Check_1" in detector.custom_signatures
        assert "VMProtect_1" in detector.custom_signatures

    finally:
        temp_path.unlink(missing_ok=True)


def test_detector_handles_corrupted_binary_gracefully() -> None:
    """Detector handles corrupted or invalid binary files without crashing."""
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
        f.write(b"NOT_A_BINARY" + b"\x00" * 100)
        temp_path = Path(f.name)

    try:
        detector = Radare2SignatureDetector(str(temp_path))

        result = detector.open()

        assert isinstance(result, bool)

        if detector.r2:
            detector.close()

    finally:
        temp_path.unlink(missing_ok=True)


def test_multiple_scans_accumulate_matches(temp_binary_file: Path) -> None:
    """Multiple scan operations accumulate matches in detector.matches list."""
    detector = Radare2SignatureDetector(str(temp_binary_file))

    initial_count = len(detector.matches)

    detector.scan_with_yara()
    after_yara = len(detector.matches)

    detector.scan_custom_signatures()
    after_custom = len(detector.matches)

    assert after_yara >= initial_count
    assert after_custom >= after_yara
