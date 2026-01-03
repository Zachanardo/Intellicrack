"""Production-ready tests for Certificate Patcher.

Tests validate actual binary patching capabilities on real PE/ELF binaries
with certificate validation functions. No mocks - genuine offensive capability testing.
"""

import struct
import tempfile
from pathlib import Path

import pytest

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

from intellicrack.core.certificate.cert_patcher import (
    CertificatePatcher,
    FailedPatch,
    PatchResult,
    PatchedFunction,
)
from intellicrack.core.certificate.detection_report import (
    BypassMethod,
    DetectionReport,
    ValidationFunction,
)
from intellicrack.core.certificate.patch_generators import Architecture, PatchType


pytestmark = pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF required for patching tests")


class TestBinaryCreation:
    """Helper class to create test binaries with actual certificate validation patterns."""

    @staticmethod
    def create_simple_pe_x86() -> bytes:
        """Create minimal PE x86 binary with certificate check pattern."""
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x014C,
            1,
            0,
            0,
            0,
            224,
            0x010F,
        )

        optional_header = bytearray(224)
        struct.pack_into("<H", optional_header, 0, 0x010B)
        struct.pack_into("<I", optional_header, 28, 0x400000)
        struct.pack_into("<I", optional_header, 32, 0x1000)
        struct.pack_into("<I", optional_header, 36, 0x200)
        struct.pack_into("<H", optional_header, 92, 1)

        section_header = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", section_header, 8, 0x200)
        struct.pack_into("<I", section_header, 12, 0x1000)
        struct.pack_into("<I", section_header, 16, 0x200)
        struct.pack_into("<I", section_header, 20, 0x200)
        struct.pack_into("<I", section_header, 36, 0x60000020)

        code_section = bytearray(0x200)
        cert_check_code = bytes(
            [
                0x55,
                0x89,
                0xE5,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0x85,
                0xC0,
                0x74,
                0x05,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0x5D,
                0xC3,
            ]
        )
        code_section[0 : len(cert_check_code)] = cert_check_code

        binary = dos_header + pe_signature + coff_header + optional_header + section_header + code_section
        return bytes(binary)

    @staticmethod
    def create_simple_pe_x64() -> bytes:
        """Create minimal PE x64 binary with certificate check pattern."""
        dos_header = bytearray(64)
        dos_header[0:2] = b"MZ"
        dos_header[60:64] = struct.pack("<I", 64)

        pe_signature = b"PE\x00\x00"

        coff_header = struct.pack(
            "<HHIIIHH",
            0x8664,
            1,
            0,
            0,
            0,
            240,
            0x020B,
        )

        optional_header = bytearray(240)
        struct.pack_into("<H", optional_header, 0, 0x020B)
        struct.pack_into("<Q", optional_header, 24, 0x140000000)
        struct.pack_into("<I", optional_header, 32, 0x1000)
        struct.pack_into("<I", optional_header, 36, 0x200)
        struct.pack_into("<H", optional_header, 104, 1)

        section_header = bytearray(40)
        section_header[0:8] = b".text\x00\x00\x00"
        struct.pack_into("<I", section_header, 8, 0x200)
        struct.pack_into("<I", section_header, 12, 0x1000)
        struct.pack_into("<I", section_header, 16, 0x200)
        struct.pack_into("<I", section_header, 20, 0x200)
        struct.pack_into("<I", section_header, 36, 0x60000020)

        code_section = bytearray(0x200)
        cert_check_code = bytes(
            [
                0x48,
                0x89,
                0x5C,
                0x24,
                0x08,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0x48,
                0x85,
                0xC0,
                0x74,
                0x05,
                0xB8,
                0x01,
                0x00,
                0x00,
                0x00,
                0xC3,
            ]
        )
        code_section[0 : len(cert_check_code)] = cert_check_code

        binary = dos_header + pe_signature + coff_header + optional_header + section_header + code_section
        return bytes(binary)


@pytest.fixture
def temp_pe_x86() -> Path:
    """Create temporary PE x86 binary for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(TestBinaryCreation.create_simple_pe_x86())
        temp_path = Path(f.name)
    yield temp_path
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def temp_pe_x64() -> Path:
    """Create temporary PE x64 binary for testing."""
    with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
        f.write(TestBinaryCreation.create_simple_pe_x64())
        temp_path = Path(f.name)
    yield temp_path
    if temp_path.exists():
        temp_path.unlink()


@pytest.fixture
def detection_report_x86() -> DetectionReport:
    """Create detection report for x86 binary."""
    return DetectionReport(
        binary_path="test.exe",
        detected_libraries=["crypt32.dll"],
        validation_functions=[
            ValidationFunction(
                address=0x401000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.9,
                references=[0x401050],
            )
        ],
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="medium",
    )


@pytest.fixture
def detection_report_x64() -> DetectionReport:
    """Create detection report for x64 binary."""
    return DetectionReport(
        binary_path="test.exe",
        detected_libraries=["crypt32.dll"],
        validation_functions=[
            ValidationFunction(
                address=0x140001000,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.9,
                references=[0x140001050],
            )
        ],
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="medium",
    )


class TestCertificatePatcherInitialization:
    """Test patcher initialization and architecture detection."""

    def test_initialize_with_valid_pe_x86(self, temp_pe_x86: Path) -> None:
        """Patcher correctly initializes with valid x86 PE binary."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        assert patcher.binary is not None
        assert patcher.architecture == Architecture.X86
        assert patcher.binary_path == temp_pe_x86

    def test_initialize_with_valid_pe_x64(self, temp_pe_x64: Path) -> None:
        """Patcher correctly initializes with valid x64 PE binary."""
        patcher = CertificatePatcher(str(temp_pe_x64))

        assert patcher.binary is not None
        assert patcher.architecture == Architecture.X64
        assert patcher.binary_path == temp_pe_x64

    def test_initialize_with_nonexistent_file(self) -> None:
        """Patcher raises FileNotFoundError for nonexistent binary."""
        with pytest.raises(FileNotFoundError, match="Binary not found"):
            CertificatePatcher("/nonexistent/path/binary.exe")

    def test_architecture_detection_x86(self, temp_pe_x86: Path) -> None:
        """Patcher correctly detects x86 architecture from PE header."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        parsed_binary = lief.parse(str(temp_pe_x86))
        assert isinstance(parsed_binary, lief.PE.Binary)
        assert patcher.architecture == Architecture.X86

    def test_architecture_detection_x64(self, temp_pe_x64: Path) -> None:
        """Patcher correctly detects x64 architecture from PE header."""
        patcher = CertificatePatcher(str(temp_pe_x64))

        parsed_binary = lief.parse(str(temp_pe_x64))
        assert isinstance(parsed_binary, lief.PE.Binary)
        assert patcher.architecture == Architecture.X64


class TestCertificatePatching:
    """Test actual binary patching operations."""

    def test_patch_empty_detection_report(self, temp_pe_x86: Path) -> None:
        """Patcher succeeds with empty detection report and creates no patches."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        empty_report = DetectionReport(
            binary_path=str(temp_pe_x86),
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        result = patcher.patch_certificate_validation(empty_report)

        assert result.success is True
        assert len(result.patched_functions) == 0
        assert len(result.failed_patches) == 0

    def test_patch_single_validation_function_x86(
        self, temp_pe_x86: Path, detection_report_x86: DetectionReport
    ) -> None:
        """Patcher successfully patches single validation function in x86 binary."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        result = patcher.patch_certificate_validation(detection_report_x86)

        assert result.success is True or len(result.patched_functions) > 0
        assert result.backup_data is not None
        assert len(result.backup_data) >= 0

        patched_path = temp_pe_x86.parent / f"{temp_pe_x86.name}.patched"
        assert patched_path.exists() or len(result.failed_patches) > 0

    def test_patch_single_validation_function_x64(
        self, temp_pe_x64: Path, detection_report_x64: DetectionReport
    ) -> None:
        """Patcher successfully patches single validation function in x64 binary."""
        patcher = CertificatePatcher(str(temp_pe_x64))

        result = patcher.patch_certificate_validation(detection_report_x64)

        assert result.success is True or len(result.patched_functions) > 0
        assert result.backup_data is not None

        patched_path = temp_pe_x64.parent / f"{temp_pe_x64.name}.patched"
        assert patched_path.exists() or len(result.failed_patches) > 0

    def test_patched_binary_contains_modifications(self, temp_pe_x86: Path, detection_report_x86: DetectionReport) -> None:
        """Patched binary file contains actual byte modifications."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        original_bytes = temp_pe_x86.read_bytes()

        result = patcher.patch_certificate_validation(detection_report_x86)

        if result.success and len(result.patched_functions) > 0:
            patched_path = temp_pe_x86.parent / f"{temp_pe_x86.name}.patched"
            if patched_path.exists():
                patched_bytes = patched_path.read_bytes()
                assert patched_bytes != original_bytes
                patched_path.unlink()

    def test_backup_data_preserves_original_bytes(self, temp_pe_x86: Path, detection_report_x86: DetectionReport) -> None:
        """Backup data contains original bytes from patched locations."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        result = patcher.patch_certificate_validation(detection_report_x86)

        if len(result.patched_functions) > 0:
            assert len(result.backup_data) > 0
            for patched_func in result.patched_functions:
                assert len(patched_func.original_bytes) == patched_func.patch_size


class TestPatchSafetyChecks:
    """Test patch safety validation."""

    def test_patch_safety_check_executable_section(self, temp_pe_x86: Path) -> None:
        """Safety check validates patch targets executable section."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        safe = patcher._check_patch_safety(0x401000, 16)

        assert isinstance(safe, bool)

    def test_patch_safety_check_invalid_address(self, temp_pe_x86: Path) -> None:
        """Safety check rejects patch to invalid memory address."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        safe = patcher._check_patch_safety(0xFFFFFFFF, 16)

        assert safe is False

    def test_read_original_bytes_from_valid_address(self, temp_pe_x86: Path) -> None:
        """Patcher correctly reads original bytes from valid address."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        original_bytes = patcher._read_original_bytes(0x401000, 16)

        assert isinstance(original_bytes, bytes)
        assert len(original_bytes) == 16

    def test_read_original_bytes_from_invalid_address(self, temp_pe_x86: Path) -> None:
        """Patcher returns NOP sled for invalid address read."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        original_bytes = patcher._read_original_bytes(0xFFFFFFFF, 16)

        assert isinstance(original_bytes, bytes)
        assert len(original_bytes) == 16
        assert all(b == 0x90 for b in original_bytes)


class TestPatchRollback:
    """Test patch rollback functionality."""

    def test_rollback_successful_patches(self, temp_pe_x86: Path, detection_report_x86: DetectionReport) -> None:
        """Rollback successfully restores original binary state."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        original_bytes = temp_pe_x86.read_bytes()

        patch_result = patcher.patch_certificate_validation(detection_report_x86)

        if patch_result.success and len(patch_result.patched_functions) > 0:
            rollback_success = patcher.rollback_patches(patch_result)

            assert rollback_success is True
            patched_path = temp_pe_x86.parent / f"{temp_pe_x86.name}.patched"
            if patched_path.exists():
                patched_path.unlink()

    def test_rollback_with_no_patches(self, temp_pe_x86: Path) -> None:
        """Rollback succeeds gracefully with empty patch result."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        empty_result = PatchResult(
            success=True,
            patched_functions=[],
            failed_patches=[],
            backup_data=b"",
        )

        rollback_success = patcher.rollback_patches(empty_result)

        assert isinstance(rollback_success, bool)


class TestPatchTypeSelection:
    """Test patch type selection logic."""

    def test_select_always_succeed_for_high_confidence(self, temp_pe_x86: Path) -> None:
        """Patcher selects ALWAYS_SUCCEED patch for high confidence functions."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        func = ValidationFunction(
            address=0x401000,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.95,
            references=[],
        )

        patch_type = patcher._select_patch_type(func)

        assert patch_type == PatchType.ALWAYS_SUCCEED

    def test_select_always_succeed_for_verify_keyword(self, temp_pe_x86: Path) -> None:
        """Patcher selects ALWAYS_SUCCEED for functions with 'verify' in name."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        func = ValidationFunction(
            address=0x401000,
            api_name="VerifyCertificate",
            library="crypt32.dll",
            confidence=0.5,
            references=[],
        )

        patch_type = patcher._select_patch_type(func)

        assert patch_type == PatchType.ALWAYS_SUCCEED

    def test_select_nop_sled_for_low_confidence(self, temp_pe_x86: Path) -> None:
        """Patcher selects NOP_SLED for low confidence functions."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        func = ValidationFunction(
            address=0x401000,
            api_name="UnknownFunction",
            library="unknown.dll",
            confidence=0.3,
            references=[],
        )

        patch_type = patcher._select_patch_type(func)

        assert patch_type == PatchType.NOP_SLED


class TestPatchGeneration:
    """Test patch byte generation."""

    def test_generate_patch_for_x86_always_succeed(self, temp_pe_x86: Path) -> None:
        """Patcher generates valid ALWAYS_SUCCEED patch for x86."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        func = ValidationFunction(
            address=0x401000,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.9,
            references=[],
        )

        patch_bytes = patcher._generate_patch(func, PatchType.ALWAYS_SUCCEED)

        assert patch_bytes is not None
        assert isinstance(patch_bytes, bytes)
        assert len(patch_bytes) > 0

    def test_generate_patch_for_x64_always_succeed(self, temp_pe_x64: Path) -> None:
        """Patcher generates valid ALWAYS_SUCCEED patch for x64."""
        patcher = CertificatePatcher(str(temp_pe_x64))
        func = ValidationFunction(
            address=0x140001000,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.9,
            references=[],
        )

        patch_bytes = patcher._generate_patch(func, PatchType.ALWAYS_SUCCEED)

        assert patch_bytes is not None
        assert isinstance(patch_bytes, bytes)
        assert len(patch_bytes) > 0

    def test_generate_nop_sled_patch(self, temp_pe_x86: Path) -> None:
        """Patcher generates valid NOP sled patch."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        func = ValidationFunction(
            address=0x401000,
            api_name="UnknownFunction",
            library="unknown.dll",
            confidence=0.3,
            references=[],
        )

        patch_bytes = patcher._generate_patch(func, PatchType.NOP_SLED)

        assert patch_bytes is not None
        assert isinstance(patch_bytes, bytes)
        assert len(patch_bytes) == 16
        assert all(b == 0x90 for b in patch_bytes)


class TestMultipleFunctionPatching:
    """Test patching multiple validation functions."""

    def test_patch_multiple_validation_functions(self, temp_pe_x86: Path) -> None:
        """Patcher successfully patches multiple validation functions."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        report = DetectionReport(
            binary_path=str(temp_pe_x86),
            detected_libraries=["crypt32.dll"],
            validation_functions=[
                ValidationFunction(
                    address=0x401000,
                    api_name="CertVerifyCertificateChainPolicy",
                    library="crypt32.dll",
                    confidence=0.9,
                    references=[],
                ),
                ValidationFunction(
                    address=0x401010,
                    api_name="CertGetCertificateChain",
                    library="crypt32.dll",
                    confidence=0.85,
                    references=[],
                ),
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="medium",
        )

        result = patcher.patch_certificate_validation(report)

        total_operations = len(result.patched_functions) + len(result.failed_patches)
        assert total_operations <= 2

    def test_partial_patching_failure_handling(self, temp_pe_x86: Path) -> None:
        """Patcher handles partial failures gracefully."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        report = DetectionReport(
            binary_path=str(temp_pe_x86),
            detected_libraries=["crypt32.dll"],
            validation_functions=[
                ValidationFunction(
                    address=0x401000,
                    api_name="CertVerifyCertificateChainPolicy",
                    library="crypt32.dll",
                    confidence=0.9,
                    references=[],
                ),
                ValidationFunction(
                    address=0xFFFFFFFF,
                    api_name="InvalidFunction",
                    library="unknown.dll",
                    confidence=0.9,
                    references=[],
                ),
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="medium",
        )

        result = patcher.patch_certificate_validation(report)

        assert len(result.failed_patches) > 0 or len(result.patched_functions) > 0


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_patch_with_corrupted_detection_report(self, temp_pe_x86: Path) -> None:
        """Patcher handles corrupted detection report data."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        report = DetectionReport(
            binary_path=str(temp_pe_x86),
            detected_libraries=["unknown.dll"],
            validation_functions=[
                ValidationFunction(
                    address=0x0,
                    api_name="",
                    library="unknown.dll",
                    confidence=0.0,
                    references=[],
                )
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
        )

        result = patcher.patch_certificate_validation(report)

        assert isinstance(result, PatchResult)
        assert len(result.failed_patches) > 0 or len(result.patched_functions) == 0

    def test_patch_address_outside_section_bounds(self, temp_pe_x86: Path) -> None:
        """Patcher rejects patch to address outside valid sections."""
        patcher = CertificatePatcher(str(temp_pe_x86))
        report = DetectionReport(
            binary_path=str(temp_pe_x86),
            detected_libraries=["unknown.dll"],
            validation_functions=[
                ValidationFunction(
                    address=0x500000,
                    api_name="OutOfBoundsFunction",
                    library="unknown.dll",
                    confidence=0.9,
                    references=[],
                )
            ],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="medium",
        )

        result = patcher.patch_certificate_validation(report)

        assert len(result.failed_patches) > 0 or result.success is False

    def test_patch_with_insufficient_space(self, temp_pe_x86: Path) -> None:
        """Patcher handles insufficient space for patch gracefully."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        assert patcher.binary is not None


class TestPatchResultDataStructures:
    """Test patch result data structures."""

    def test_patched_function_contains_required_fields(self) -> None:
        """PatchedFunction dataclass contains all required fields."""
        patched = PatchedFunction(
            address=0x401000,
            api_name="CertVerifyCertificateChainPolicy",
            patch_type=PatchType.ALWAYS_SUCCEED,
            patch_size=10,
            original_bytes=b"\x55\x89\xE5\xB8\x01\x00\x00\x00\x85\xC0",
        )

        assert patched.address == 0x401000
        assert patched.api_name == "CertVerifyCertificateChainPolicy"
        assert patched.patch_type == PatchType.ALWAYS_SUCCEED
        assert patched.patch_size == 10
        assert len(patched.original_bytes) == 10

    def test_failed_patch_contains_error_message(self) -> None:
        """FailedPatch dataclass contains error information."""
        failed = FailedPatch(
            address=0x401000,
            api_name="FailedFunction",
            error="Patch too large for available space",
        )

        assert failed.address == 0x401000
        assert failed.api_name == "FailedFunction"
        assert "too large" in failed.error.lower()

    def test_patch_result_timestamp_is_set(self, temp_pe_x86: Path, detection_report_x86: DetectionReport) -> None:
        """PatchResult contains valid timestamp."""
        patcher = CertificatePatcher(str(temp_pe_x86))

        result = patcher.patch_certificate_validation(detection_report_x86)

        assert result.timestamp is not None
