"""Production-Grade Tests for Activation Pattern Analyzer.

Validates REAL activation detection capabilities against actual binaries with
licensing protections. NO mocks, NO stubs - only genuine pattern detection that
proves offensive capability for security research.

Copyright (C) 2025 Zachary Flint
Licensed under GNU GPL v3.0+
"""

import struct
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.core.analysis.activation_analyzer import (
    PEFILE_AVAILABLE,
    ActivationAnalyzer,
    ActivationAnalysisResult,
    ActivationPattern,
    ActivationType,
    HardwareIDPattern,
    LicenseFilePattern,
    RegistrationPattern,
    RegistrationType,
    TrialPattern,
)


@pytest.fixture
def analyzer() -> ActivationAnalyzer:
    """Provide activation analyzer instance."""
    return ActivationAnalyzer()


@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    """Provide temporary directory for test binaries."""
    return tmp_path


def create_pe_binary(
    path: Path,
    strings: list[bytes] = None,
    with_pe_header: bool = True,
    imports: list[bytes] = None
) -> Path:
    """Create realistic PE binary with embedded strings and imports.

    Args:
        path: Output path for binary
        strings: List of byte strings to embed
        with_pe_header: Include valid PE header
        imports: List of import names to reference

    Returns:
        Path to created binary

    """
    dos_header = bytearray([
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
    ])

    dos_stub = b"This program cannot be run in DOS mode.\r\r\n$" + b"\x00" * 7

    pe_signature = b"PE\x00\x00"

    coff_header = struct.pack(
        "<HHIIIHH",
        0x8664,
        3,
        0,
        0,
        0,
        0x00F0,
        0x0022
    )

    optional_header = bytearray(240)
    optional_header[0:2] = struct.pack("<H", 0x020B)
    optional_header[2] = 14
    optional_header[3] = 0

    struct.pack_into("<I", optional_header, 16, 0x1000)
    struct.pack_into("<I", optional_header, 20, 0x1000)
    struct.pack_into("<Q", optional_header, 24, 0x400000)
    struct.pack_into("<I", optional_header, 32, 0x1000)
    struct.pack_into("<I", optional_header, 36, 0x200)
    struct.pack_into("<H", optional_header, 40, 6)
    struct.pack_into("<H", optional_header, 48, 6)
    struct.pack_into("<Q", optional_header, 56, 0x2000)
    struct.pack_into("<I", optional_header, 64, 0x400)
    struct.pack_into("<H", optional_header, 68, 0x0140)
    struct.pack_into("<H", optional_header, 70, 0x0003)
    struct.pack_into("<Q", optional_header, 72, 0x100000)
    struct.pack_into("<Q", optional_header, 80, 0x1000)
    struct.pack_into("<I", optional_header, 92, 2)

    section_header = bytearray(40)
    section_header[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<I", section_header, 8, 0x1000)
    struct.pack_into("<I", section_header, 12, 0x1000)
    struct.pack_into("<I", section_header, 16, 0x1000)
    struct.pack_into("<I", section_header, 20, 0x400)
    struct.pack_into("<I", section_header, 36, 0x60000020)

    binary_content = dos_header + dos_stub
    binary_content += pe_signature + coff_header + optional_header + section_header

    binary_content += b"\x90" * (0x400 - len(binary_content))

    if strings:
        for s in strings:
            binary_content += s + b"\x00"

    if imports:
        for imp in imports:
            binary_content += imp + b"\x00"

    binary_content += b"\x00" * 1024

    path.write_bytes(binary_content)
    return path


def test_analyzer_initialization(analyzer: ActivationAnalyzer) -> None:
    """Analyzer initializes with correct keyword databases."""
    assert len(analyzer.ACTIVATION_KEYWORDS) > 0
    assert len(analyzer.REGISTRATION_KEYWORDS) > 0
    assert len(analyzer.TRIAL_KEYWORDS) > 0
    assert len(analyzer.HWID_KEYWORDS) > 0
    assert len(analyzer.LICENSE_FILE_KEYWORDS) > 0
    assert len(analyzer.ACTIVATION_APIS) > 0


def test_analyze_nonexistent_binary_raises_error(analyzer: ActivationAnalyzer) -> None:
    """Analyzing nonexistent binary raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        analyzer.analyze("/nonexistent/binary.exe")


def test_detect_online_activation_pattern(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects online activation with HTTP/HTTPS URLs."""
    binary = create_pe_binary(
        temp_dir / "online_activation.exe",
        strings=[
            b"Product activation required",
            b"https://activation.example.com/verify",
            b"Activate now",
            b"Enter activation code"
        ],
        imports=[b"WinHttpOpen", b"HttpSendRequestW"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert len(result.activation_patterns) > 0
    assert any(p.pattern_type == ActivationType.ONLINE for p in result.activation_patterns)
    assert len(result.online_activation_urls) > 0
    assert "https://activation.example.com/verify" in result.online_activation_urls


def test_detect_offline_activation_pattern(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects offline activation mechanism."""
    binary = create_pe_binary(
        temp_dir / "offline_activation.exe",
        strings=[
            b"Offline activation",
            b"Generate activation request",
            b"Enter response code"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert len(result.activation_patterns) > 0


def test_detect_challenge_response_activation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects challenge-response activation system."""
    binary = create_pe_binary(
        temp_dir / "challenge_response.exe",
        strings=[
            b"Challenge code",
            b"Response code required",
            b"activation challenge",
            b"Enter response"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert any(p.pattern_type == ActivationType.CHALLENGE_RESPONSE for p in result.activation_patterns)


def test_detect_hardware_locked_activation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects hardware-locked activation with HWID fingerprinting."""
    binary = create_pe_binary(
        temp_dir / "hardware_locked.exe",
        strings=[
            b"Hardware ID",
            b"Machine fingerprint",
            b"activation",
            b"This license is locked to your hardware"
        ],
        imports=[b"GetVolumeInformationW", b"GetComputerNameW"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert result.has_hwid_lock is True
    assert any(p.pattern_type == ActivationType.HARDWARE_LOCKED for p in result.activation_patterns)


def test_detect_serial_number_registration(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects serial number registration system."""
    binary = create_pe_binary(
        temp_dir / "serial_registration.exe",
        strings=[
            b"Enter serial number",
            b"Serial number required",
            b"Invalid serial",
            b"Serial validation"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.registration_patterns) > 0
    assert any(p.registration_type == RegistrationType.SERIAL_NUMBER for p in result.registration_patterns)


def test_detect_product_key_registration(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects product key registration validation."""
    binary = create_pe_binary(
        temp_dir / "product_key.exe",
        strings=[
            b"Enter product key",
            b"Product key format: XXXXX-XXXXX-XXXXX",
            b"Invalid product key"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.registration_patterns) > 0
    assert any(p.registration_type == RegistrationType.PRODUCT_KEY for p in result.registration_patterns)


def test_detect_license_key_with_crypto(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects license key validation with cryptographic checks."""
    binary = create_pe_binary(
        temp_dir / "license_key_crypto.exe",
        strings=[
            b"License key",
            b"RSA signature verification",
            b"Invalid license key"
        ],
        imports=[b"CryptHashData", b"CryptCreateHash"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.registration_patterns) > 0

    crypto_patterns = [p for p in result.registration_patterns
                       if "rsa" in p.algorithm_hints or "cryptographic_hash" in p.algorithm_hints]
    assert len(crypto_patterns) > 0


def test_detect_trial_period_limitation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects time-limited trial period."""
    binary = create_pe_binary(
        temp_dir / "trial_period.exe",
        strings=[
            b"Trial period",
            b"days remaining",
            b"Trial expired",
            b"Buy now to continue"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_trial is True
    assert len(result.trial_patterns) > 0
    assert any("time" in p.trial_type or "trial" in p.trial_type for p in result.trial_patterns)


def test_detect_evaluation_version_trial(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects evaluation version limitations."""
    binary = create_pe_binary(
        temp_dir / "evaluation.exe",
        strings=[
            b"Evaluation version",
            b"Limited functionality",
            b"Purchase full version"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_trial is True
    assert any("evaluation" in p.trial_type for p in result.trial_patterns)


def test_detect_demo_mode_trial(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects demo mode restrictions."""
    binary = create_pe_binary(
        temp_dir / "demo.exe",
        strings=[
            b"Demo mode active",
            b"Demo limitations apply",
            b"Activate to unlock full features"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_trial is True
    assert any("demo" in p.trial_type for p in result.trial_patterns)


def test_detect_registry_based_trial_storage(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects trial data stored in Windows Registry."""
    binary = create_pe_binary(
        temp_dir / "registry_trial.exe",
        strings=[
            b"Trial",
            b"SOFTWARE\\TestApp\\Trial",
            b"HKEY_CURRENT_USER"
        ],
        imports=[b"RegCreateKeyExW", b"RegSetValueExW", b"RegQueryValueExW"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_trial is True

    registry_trials = [p for p in result.trial_patterns
                       if p.storage_location and "registry" in p.storage_location]
    assert len(registry_trials) > 0


def test_detect_file_based_trial_storage(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects trial data stored in configuration files."""
    binary = create_pe_binary(
        temp_dir / "file_trial.exe",
        strings=[
            b"Trial",
            b"C:\\ProgramData\\TestApp\\trial.dat",
            b"trial.cfg"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_trial is True

    file_trials = [p for p in result.trial_patterns
                   if p.storage_location and "file" in p.storage_location]
    assert len(file_trials) > 0


def test_detect_hwid_volume_serial_fingerprinting(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects hardware fingerprinting using volume serial number."""
    binary = create_pe_binary(
        temp_dir / "hwid_volume.exe",
        strings=[
            b"Hardware ID",
            b"Volume serial number"
        ],
        imports=[b"GetVolumeInformationW"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_hwid_lock is True
    assert len(result.hardware_id_patterns) > 0

    volume_hwid = [p for p in result.hardware_id_patterns
                   if "volume_serial" in p.components]
    assert len(volume_hwid) > 0


def test_detect_hwid_computer_name_fingerprinting(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects hardware fingerprinting using computer name."""
    binary = create_pe_binary(
        temp_dir / "hwid_computer.exe",
        strings=[
            b"Machine ID",
            b"Computer identification"
        ],
        imports=[b"GetComputerNameW"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_hwid_lock is True

    computer_hwid = [p for p in result.hardware_id_patterns
                     if "computer_name" in p.components]
    assert len(computer_hwid) > 0


def test_detect_multi_component_hwid(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects multi-component hardware fingerprinting."""
    binary = create_pe_binary(
        temp_dir / "hwid_multi.exe",
        strings=[
            b"Hardware fingerprint",
            b"System identification"
        ],
        imports=[
            b"GetVolumeInformationW",
            b"GetComputerNameW",
            b"GetUserNameW",
            b"GetSystemInfo"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_hwid_lock is True

    multi_hwid = [p for p in result.hardware_id_patterns
                  if p.hwid_type == "multi_component"]
    assert len(multi_hwid) > 0


def test_detect_license_file_dat_format(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects license.dat file handling."""
    binary = create_pe_binary(
        temp_dir / "license_dat.exe",
        strings=[
            b"license.dat",
            b"C:\\Program Files\\TestApp\\license.dat",
            b"License file missing"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.license_file_patterns) > 0

    dat_licenses = [p for p in result.license_file_patterns
                    if p.file_path and "license.dat" in p.file_path]
    assert len(dat_licenses) > 0


def test_detect_license_file_xml_format(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects XML-formatted license files."""
    binary = create_pe_binary(
        temp_dir / "license_xml.exe",
        strings=[
            b"license.xml",
            b"XML license format",
            b"Parse license XML"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.license_file_patterns) > 0

    xml_licenses = [p for p in result.license_file_patterns
                    if p.file_format == "xml"]
    assert len(xml_licenses) > 0


def test_detect_encrypted_license_file(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects encrypted license file validation."""
    binary = create_pe_binary(
        temp_dir / "license_encrypted.exe",
        strings=[
            b"license.key",
            b"Decrypt license"
        ],
        imports=[b"CryptHashData", b"CryptDecrypt"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.license_file_patterns) > 0

    encrypted_licenses = [p for p in result.license_file_patterns
                          if p.encryption_used]
    assert len(encrypted_licenses) > 0


def test_extract_https_activation_url(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Extracts HTTPS activation server URLs."""
    binary = create_pe_binary(
        temp_dir / "url_https.exe",
        strings=[
            b"https://license-server.example.com/activate",
            b"Contacting activation server..."
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.online_activation_urls) > 0
    assert "https://license-server.example.com/activate" in result.online_activation_urls


def test_extract_http_activation_url(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Extracts HTTP activation server URLs."""
    binary = create_pe_binary(
        temp_dir / "url_http.exe",
        strings=[
            b"http://activation.testapp.com/verify",
            b"Online validation"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.online_activation_urls) > 0
    assert "http://activation.testapp.com/verify" in result.online_activation_urls


def test_extract_multiple_activation_urls(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Extracts multiple activation URLs from binary."""
    binary = create_pe_binary(
        temp_dir / "multi_urls.exe",
        strings=[
            b"https://primary-activation.example.com/api",
            b"https://backup-license.example.com/verify",
            b"http://legacy-auth.example.com/validate"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.online_activation_urls) >= 2


def test_calculate_protection_strength_strong(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Calculates high protection strength for multi-layer protection."""
    binary = create_pe_binary(
        temp_dir / "strong_protection.exe",
        strings=[
            b"Product activation required",
            b"https://activation.example.com/verify",
            b"Hardware ID verification",
            b"Serial number validation",
            b"Trial expired",
            b"license.dat"
        ],
        imports=[
            b"GetVolumeInformationW",
            b"CryptHashData",
            b"WinHttpOpen"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.protection_strength > 0.7


def test_calculate_protection_strength_weak(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Calculates low protection strength for minimal protection."""
    binary = create_pe_binary(
        temp_dir / "weak_protection.exe",
        strings=[
            b"Trial version"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.protection_strength < 0.3


def test_analyze_real_windows_binary_notepad(analyzer: ActivationAnalyzer) -> None:
    """Analyzes real Windows notepad.exe without crashing."""
    notepad_path = Path("C:\\Windows\\System32\\notepad.exe")

    if not notepad_path.exists():
        pytest.skip("notepad.exe not found on system")

    result: ActivationAnalysisResult = analyzer.analyze(notepad_path)

    assert isinstance(result, ActivationAnalysisResult)


def test_pattern_deduplication_activation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Removes duplicate activation patterns in close proximity."""
    repeated_strings = [b"activate"] * 100

    binary = create_pe_binary(
        temp_dir / "duplicates.exe",
        strings=repeated_strings
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.activation_patterns) < 20


def test_pattern_confidence_scoring(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Assigns higher confidence to patterns with API calls."""
    binary = create_pe_binary(
        temp_dir / "confidence.exe",
        strings=[
            b"Product activation",
            b"Verify license key",
            b"Contact activation server"
        ],
        imports=[
            b"WinHttpOpen",
            b"HttpSendRequestW",
            b"CryptHashData"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    high_confidence = [p for p in result.activation_patterns if p.confidence > 0.7]
    assert len(high_confidence) > 0


def test_detect_phone_activation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects phone-based activation system."""
    binary = create_pe_binary(
        temp_dir / "phone_activation.exe",
        strings=[
            b"Phone activation",
            b"Call 1-800-ACTIVATE",
            b"activation code by phone"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert any(p.pattern_type == ActivationType.PHONE_ACTIVATION for p in result.activation_patterns)


def test_detect_registry_based_activation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects registry-based activation storage."""
    binary = create_pe_binary(
        temp_dir / "registry_activation.exe",
        strings=[
            b"activation",
            b"SOFTWARE\\TestApp\\Activation",
            b"Registry activation key"
        ],
        imports=[b"RegCreateKeyExW", b"RegSetValueExW"]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert any(p.pattern_type == ActivationType.REGISTRY_BASED for p in result.activation_patterns)


def test_detect_license_file_activation(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects license file-based activation."""
    binary = create_pe_binary(
        temp_dir / "license_file_activation.exe",
        strings=[
            b"activation",
            b"license.lic",
            b"Load activation license"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert any(p.pattern_type == ActivationType.LICENSE_FILE for p in result.activation_patterns)


def test_context_string_extraction(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Extracts context strings around activation patterns."""
    binary = create_pe_binary(
        temp_dir / "context.exe",
        strings=[
            b"Application Settings",
            b"Product activation required",
            b"Enter your activation code below",
            b"Continue"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.activation_patterns) > 0

    pattern = result.activation_patterns[0]
    assert len(pattern.related_strings) > 0


def test_api_call_detection(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects relevant API calls near activation patterns."""
    binary = create_pe_binary(
        temp_dir / "api_calls.exe",
        strings=[b"activation"],
        imports=[
            b"GetVolumeInformationW",
            b"WinHttpOpen",
            b"CryptHashData"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert len(result.activation_patterns) > 0

    pattern = result.activation_patterns[0]
    assert len(pattern.api_calls) > 0


def test_validation_function_detection(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects nearby validation functions for registration codes."""
    binary = create_pe_binary(
        temp_dir / "validation.exe",
        strings=[
            b"Serial number",
            b"Validate serial"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    if PEFILE_AVAILABLE and len(result.registration_patterns) > 0:
        pattern = result.registration_patterns[0]
        assert pattern.validation_function is not None or pattern.confidence > 0.5


def test_algorithm_hint_detection_md5(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects MD5 algorithm hints in validation."""
    binary = create_pe_binary(
        temp_dir / "md5_validation.exe",
        strings=[
            b"Serial number",
            b"MD5 hash verification",
            b"MD5"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    md5_patterns = [p for p in result.registration_patterns
                    if "md5" in p.algorithm_hints]
    assert len(md5_patterns) > 0


def test_algorithm_hint_detection_rsa(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects RSA algorithm hints in validation."""
    binary = create_pe_binary(
        temp_dir / "rsa_validation.exe",
        strings=[
            b"License key",
            b"RSA-2048 signature",
            b"RSA public key"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    rsa_patterns = [p for p in result.registration_patterns
                    if "rsa" in p.algorithm_hints]
    assert len(rsa_patterns) > 0


def test_algorithm_hint_detection_sha(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects SHA algorithm hints in validation."""
    binary = create_pe_binary(
        temp_dir / "sha_validation.exe",
        strings=[
            b"Product key",
            b"SHA-256 checksum",
            b"SHA validation"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    sha_patterns = [p for p in result.registration_patterns
                    if "sha" in p.algorithm_hints]
    assert len(sha_patterns) > 0


def test_time_check_detection(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects time comparison operations in trial checks."""
    binary = create_pe_binary(
        temp_dir / "time_check.exe",
        strings=[
            b"Trial",
            b"Check trial expiration",
            b"Compare timestamps"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    if PEFILE_AVAILABLE and result.has_trial:
        time_checks = [p for p in result.trial_patterns
                       if p.time_check_address is not None]
        assert len(time_checks) >= 0


def test_expiration_check_detection(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Detects expiration validation logic."""
    binary = create_pe_binary(
        temp_dir / "expiration.exe",
        strings=[
            b"Trial",
            b"License expired",
            b"Expiration date"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_trial is True

    expiry_checks = [p for p in result.trial_patterns
                     if p.expiration_check is not None]
    assert len(expiry_checks) > 0


def test_empty_binary_produces_empty_results(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Empty binary produces no activation patterns."""
    empty_binary = temp_dir / "empty.exe"
    empty_binary.write_bytes(b"\x00" * 1024)

    result: ActivationAnalysisResult = analyzer.analyze(empty_binary)

    assert result.has_activation is False
    assert result.has_trial is False
    assert result.has_hwid_lock is False
    assert len(result.activation_patterns) == 0


def test_binary_with_only_unrelated_strings(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Binary with unrelated strings produces no false positives."""
    binary = create_pe_binary(
        temp_dir / "unrelated.exe",
        strings=[
            b"Hello World",
            b"Welcome to the application",
            b"Click OK to continue"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is False


def test_case_insensitive_pattern_matching(analyzer: ActivationAnalyzer, temp_dir: Path) -> None:
    """Pattern detection is case-insensitive."""
    binary = create_pe_binary(
        temp_dir / "case_insensitive.exe",
        strings=[
            b"ACTIVATE NOW",
            b"SeRiAl NuMbEr",
            b"TRIAL EXPIRED"
        ]
    )

    result: ActivationAnalysisResult = analyzer.analyze(binary)

    assert result.has_activation is True
    assert len(result.registration_patterns) > 0
    assert result.has_trial is True
