"""Unit tests for certificate patcher module.

This test suite validates the CertificatePatcher functionality with comprehensive
coverage of patching operations, safety checks, architecture detection, and rollback.
Tests use mocking to avoid dependencies on real binaries and LIEF.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, PropertyMock
from dataclasses import dataclass

from intellicrack.core.certificate.cert_patcher import (
    CertificatePatcher,
    PatchResult,
    PatchedFunction,
    FailedPatch,
)
from intellicrack.core.certificate.detection_report import (
    DetectionReport,
    ValidationFunction,
    BypassMethod,
)
from intellicrack.core.certificate.patch_generators import (
    Architecture,
    PatchType,
)


@pytest.fixture
def mock_lief_pe_binary():
    """Create mock LIEF PE binary."""
    binary = Mock()
    binary.header = Mock()
    binary.header.machine = 0x8664
    binary.optional_header = Mock()
    binary.optional_header.imagebase = 0x140000000

    section = Mock()
    section.virtual_address = 0x1000
    section.content = [0x90] * 1000
    section.characteristics = 0x60000020

    binary.section_from_rva = Mock(return_value=section)
    binary.write = Mock()
    return binary


@pytest.fixture
def mock_lief_elf_binary():
    """Create mock LIEF ELF binary."""
    binary = Mock()
    binary.header = Mock()
    binary.header.machine_type = 0x3E

    segment = Mock()
    segment.virtual_address = 0x401000
    segment.virtual_size = 0x1000
    segment.content = [0x90] * 1000

    binary.segments = [segment]
    binary.write = Mock()
    return binary


@pytest.fixture
def sample_detection_report():
    """Create sample detection report with validation functions."""
    from datetime import datetime

    functions = [
        ValidationFunction(
            address=0x140001234,
            api_name="WinHttpSetOption",
            library="winhttp.dll",
            confidence=0.9,
            context="license validation code",
            references=[0x140005000]
        ),
        ValidationFunction(
            address=0x140002345,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.85,
            context="certificate chain verification",
            references=[0x140006000]
        ),
    ]

    return DetectionReport(
        binary_path="test.exe",
        detected_libraries=["winhttp.dll", "crypt32.dll"],
        validation_functions=functions,
        recommended_method=BypassMethod.BINARY_PATCH,
        risk_level="low",
        timestamp=datetime.now()
    )


class TestPatcherInitialization:
    """Tests for patcher initialization and configuration."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_patcher_initializes_with_valid_binary(self, mock_lief, mock_path, mock_lief_pe_binary):
        """Test patcher initializes successfully with valid binary."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        mock_lief.ELF = Mock()
        mock_lief.ELF.Binary = type("DummyELF", (), {})

        patcher = CertificatePatcher("test.exe")

        assert patcher.binary_path == "test.exe"
        assert patcher.binary is not None
        assert patcher.architecture == Architecture.X64

    @patch("intellicrack.core.certificate.cert_patcher.Path")
    def test_patcher_raises_error_for_nonexistent_binary(self, mock_path):
        """Test patcher raises FileNotFoundError for non-existent binary."""
        mock_path.return_value.exists.return_value = False

        with pytest.raises(FileNotFoundError) as exc_info:
            CertificatePatcher("nonexistent.exe")

        assert "Binary not found" in str(exc_info.value)

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", False)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    def test_patcher_raises_error_without_lief(self, mock_path):
        """Test patcher raises RuntimeError when LIEF not available."""
        mock_path.return_value.exists.return_value = True

        with pytest.raises(RuntimeError) as exc_info:
            CertificatePatcher("test.exe")

        assert "LIEF library not available" in str(exc_info.value)


class TestArchitectureDetection:
    """Tests for binary architecture detection."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_detects_x86_pe_architecture(self, mock_lief, mock_path):
        """Test detection of x86 PE binary."""
        mock_path.return_value.exists.return_value = True

        binary = Mock()
        binary.header = Mock()
        binary.header.machine = 0x14C

        mock_lief.parse.return_value = binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.I386 = 0x14C

        mock_lief.ELF = Mock()
        mock_lief.ELF.Binary = type("DummyELF", (), {})

        patcher = CertificatePatcher("test.exe")

        assert patcher.architecture == Architecture.X86

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_detects_x64_elf_architecture(self, mock_lief, mock_path):
        """Test detection of x64 ELF binary."""
        mock_path.return_value.exists.return_value = True

        binary = Mock()
        binary.header = Mock()
        binary.header.machine_type = 0x3E

        mock_lief.parse.return_value = binary

        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type("DummyPE", (), {})

        mock_lief.ELF = Mock()
        mock_lief.ELF.Binary = type(binary)
        mock_lief.ELF.ARCH = Mock()
        mock_lief.ELF.ARCH.x86_64 = 0x3E

        patcher = CertificatePatcher("test")

        assert patcher.architecture == Architecture.X64

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_detects_arm64_architecture(self, mock_lief, mock_path):
        """Test detection of ARM64 architecture."""
        mock_path.return_value.exists.return_value = True

        binary = Mock()
        binary.header = Mock()
        binary.header.machine_type = 0xB7

        mock_lief.parse.return_value = binary

        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type("DummyPE", (), {})

        mock_lief.ELF = Mock()
        mock_lief.ELF.Binary = type(binary)
        mock_lief.ELF.ARCH = Mock()
        mock_lief.ELF.ARCH.AARCH64 = 0xB7

        patcher = CertificatePatcher("test")

        assert patcher.architecture == Architecture.ARM64


class TestPatchTypeSelection:
    """Tests for patch type selection logic."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_selects_always_succeed_for_high_confidence(
        self, mock_lief, mock_path, mock_lief_pe_binary
    ):
        """Test ALWAYS_SUCCEED selected for high confidence functions."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        patcher = CertificatePatcher("test.exe")

        high_conf_func = ValidationFunction(
            address=0x1234,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.95,
            context="",
            references=[]
        )

        patch_type = patcher._select_patch_type(high_conf_func)
        assert patch_type == PatchType.ALWAYS_SUCCEED

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_selects_always_succeed_for_verify_api(
        self, mock_lief, mock_path, mock_lief_pe_binary
    ):
        """Test ALWAYS_SUCCEED selected for verify/check APIs."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        patcher = CertificatePatcher("test.exe")

        verify_func = ValidationFunction(
            address=0x1234,
            api_name="VerifyCertificate",
            library="test.dll",
            confidence=0.5,
            context="",
            references=[]
        )

        patch_type = patcher._select_patch_type(verify_func)
        assert patch_type == PatchType.ALWAYS_SUCCEED


class TestPatchGeneration:
    """Tests for patch bytes generation."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    @patch("intellicrack.core.certificate.cert_patcher.select_template")
    def test_uses_template_when_available(
        self, mock_select_template, mock_lief, mock_path, mock_lief_pe_binary
    ):
        """Test patch generation uses template when available."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        template = Mock()
        template.name = "TEST_TEMPLATE"
        template.patch_bytes = b'\xb8\x01\x00\x00\x00\xc3'
        mock_select_template.return_value = template

        patcher = CertificatePatcher("test.exe")

        func = ValidationFunction(
            address=0x1234,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[]
        )

        patch_bytes = patcher._generate_patch(func, PatchType.ALWAYS_SUCCEED)

        assert patch_bytes == b'\xb8\x01\x00\x00\x00\xc3'
        mock_select_template.assert_called_once()

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    @patch("intellicrack.core.certificate.cert_patcher.select_template")
    @patch("intellicrack.core.certificate.cert_patcher.generate_always_succeed_x64")
    def test_generates_always_succeed_x64_without_template(
        self, mock_gen_x64, mock_select_template, mock_lief, mock_path, mock_lief_pe_binary
    ):
        """Test generates x64 always-succeed patch when no template."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        mock_select_template.return_value = None
        mock_gen_x64.return_value = b'\x48\xc7\xc0\x01\x00\x00\x00\xc3'

        patcher = CertificatePatcher("test.exe")

        func = ValidationFunction(
            address=0x1234,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[]
        )

        patch_bytes = patcher._generate_patch(func, PatchType.ALWAYS_SUCCEED)

        assert patch_bytes == b'\x48\xc7\xc0\x01\x00\x00\x00\xc3'
        mock_gen_x64.assert_called_once()


class TestPatchApplication:
    """Tests for patch application and safety checks."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_checks_patch_safety_for_executable_section(
        self, mock_lief, mock_path
    ):
        """Test safety check passes for executable sections."""
        mock_path.return_value.exists.return_value = True

        binary = Mock()
        binary.header = Mock()
        binary.header.machine = 0x8664
        binary.optional_header = Mock()
        binary.optional_header.imagebase = 0x140000000

        section = Mock()
        section.characteristics = 0x60000020
        binary.section_from_rva = Mock(return_value=section)

        mock_lief.parse.return_value = binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664
        mock_lief.PE.SECTION_CHARACTERISTICS = Mock()
        mock_lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE = 0x20000000

        patcher = CertificatePatcher("test.exe")

        assert patcher._check_patch_safety(0x140001234, 16)

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_reads_original_bytes_from_pe_binary(
        self, mock_lief, mock_path
    ):
        """Test reading original bytes from PE binary."""
        mock_path.return_value.exists.return_value = True

        binary = Mock()
        binary.header = Mock()
        binary.header.machine = 0x8664
        binary.optional_header = Mock()
        binary.optional_header.imagebase = 0x140000000

        section = Mock()
        section.virtual_address = 0x1000
        section.content = list(b'\x48\x8b\xec\x48\x83\xec' + b'\x00' * 994)
        binary.section_from_rva = Mock(return_value=section)

        mock_lief.parse.return_value = binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        patcher = CertificatePatcher("test.exe")

        original = patcher._read_original_bytes(0x140001234, 6)

        assert len(original) == 6


class TestPatchingWorkflow:
    """Tests for complete patching workflow."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    @patch("intellicrack.core.certificate.cert_patcher.select_template")
    def test_successful_patch_with_empty_report(
        self, mock_select_template, mock_lief, mock_path, mock_lief_pe_binary
    ):
        """Test patching with empty detection report."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        from datetime import datetime
        empty_report = DetectionReport(
            binary_path="test.exe",
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
            timestamp=datetime.now()
        )

        patcher = CertificatePatcher("test.exe")
        result = patcher.patch_certificate_validation(empty_report)

        assert result.success is True
        assert len(result.patched_functions) == 0
        assert len(result.failed_patches) == 0


class TestRollback:
    """Tests for patch rollback functionality."""

    @patch("intellicrack.core.certificate.cert_patcher.LIEF_AVAILABLE", True)
    @patch("intellicrack.core.certificate.cert_patcher.Path")
    @patch("intellicrack.core.certificate.cert_patcher.lief")
    def test_rollback_restores_original_bytes(
        self, mock_lief, mock_path, mock_lief_pe_binary
    ):
        """Test rollback restores original binary state."""
        mock_path.return_value.exists.return_value = True
        mock_lief.parse.return_value = mock_lief_pe_binary
        mock_lief.PE = Mock()
        mock_lief.PE.Binary = type(mock_lief_pe_binary)
        mock_lief.PE.MACHINE_TYPES = Mock()
        mock_lief.PE.MACHINE_TYPES.AMD64 = 0x8664

        patcher = CertificatePatcher("test.exe")

        patch_result = PatchResult(
            success=True,
            patched_functions=[
                PatchedFunction(
                    address=0x140001234,
                    api_name="TestAPI",
                    patch_type=PatchType.ALWAYS_SUCCEED,
                    patch_size=8,
                    original_bytes=b'\x48\x8b\xec\x48\x83\xec\x20\xc3'
                )
            ],
            failed_patches=[],
            backup_data=b'\x48\x8b\xec\x48\x83\xec\x20\xc3'
        )

        result = patcher.rollback_patches(patch_result)

        assert result is True
        mock_lief_pe_binary.write.assert_called()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
