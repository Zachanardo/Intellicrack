"""Real functional tests for certificate patcher module.

This test suite validates CertificatePatcher functionality with real binary operations,
actual LIEF manipulations, and genuine patching workflows. All tests operate on real
binaries and verify actual outputs - NO MOCKS, NO STUBS, NO SIMULATIONS.
"""

import shutil
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

try:
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
    from intellicrack.core.certificate.patch_generators import (
        Architecture,
        PatchType,
        generate_always_succeed_x64,
        generate_always_succeed_x86,
        generate_nop_sled,
    )

    MODULE_AVAILABLE = True
except ImportError:
    MODULE_AVAILABLE = False

pytestmark = [
    pytest.mark.skipif(not MODULE_AVAILABLE, reason="Certificate patcher module not available"),
    pytest.mark.skipif(not LIEF_AVAILABLE, reason="LIEF library not available"),
]


class TestBinaryGenerator:
    """Helper class to generate real test binaries with LIEF."""

    @staticmethod
    def create_simple_pe_x64(output_path: Path) -> Path:
        """Create a simple x64 PE binary using LIEF.

        Args:
            output_path: Path where to save the binary

        Returns:
            Path to created binary
        """
        binary = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32_PLUS)

        binary.optional_header.addressof_entrypoint = 0x1000
        binary.optional_header.imagebase = 0x140000000
        binary.optional_header.section_alignment = 0x1000
        binary.optional_header.file_alignment = 0x200

        text_section = lief.PE.Section(".text")
        text_section.virtual_address = 0x1000
        text_section.virtual_size = 0x2000
        text_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
            | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
            | lief.PE.SECTION_CHARACTERISTICS.CNT_CODE
        )

        code = bytearray(0x2000)
        code[0:8] = b"\x48\x8b\xec\x48\x83\xec\x20\xc3"
        code[0x234:0x240] = b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x57\xc3"
        code[0x345:0x350] = b"\x48\x83\xec\x28\xe8\x00\x00\x00\x00\x48\x83\xc4\x28\xc3"

        text_section.content = memoryview(bytes(code))
        binary.add_section(text_section)

        data_section = lief.PE.Section(".data")
        data_section.virtual_address = 0x3000
        data_section.virtual_size = 0x1000
        data_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
            | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
            | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
        )
        data_section.content = memoryview(bytes(0x1000))
        binary.add_section(data_section)

        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(str(output_path))

        return output_path

    @staticmethod
    def create_simple_pe_x86(output_path: Path) -> Path:
        """Create a simple x86 PE binary using LIEF.

        Args:
            output_path: Path where to save the binary

        Returns:
            Path to created binary
        """
        binary = lief.PE.Binary("test", lief.PE.PE_TYPE.PE32)

        binary.optional_header.addressof_entrypoint = 0x1000
        binary.optional_header.imagebase = 0x400000
        binary.optional_header.section_alignment = 0x1000
        binary.optional_header.file_alignment = 0x200

        text_section = lief.PE.Section(".text")
        text_section.virtual_address = 0x1000
        text_section.virtual_size = 0x2000
        text_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
            | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE
            | lief.PE.SECTION_CHARACTERISTICS.CNT_CODE
        )

        code = bytearray(0x2000)
        code[0:6] = b"\x55\x8b\xec\x5d\xc3\x90"
        code[0x100:0x106] = b"\xb8\x00\x00\x00\x00\xc3"
        code[0x200:0x206] = b"\x33\xc0\x40\xc3\x90\x90"

        text_section.content = memoryview(bytes(code))
        binary.add_section(text_section)

        data_section = lief.PE.Section(".data")
        data_section.virtual_address = 0x3000
        data_section.virtual_size = 0x1000
        data_section.characteristics = (
            lief.PE.SECTION_CHARACTERISTICS.MEM_READ
            | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
            | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
        )
        data_section.content = memoryview(bytes(0x1000))
        binary.add_section(data_section)

        builder = lief.PE.Builder(binary)
        builder.build()
        builder.write(str(output_path))

        return output_path

    @staticmethod
    def create_simple_elf_x64(output_path: Path) -> Path:
        """Create a simple x64 ELF binary using LIEF.

        Args:
            output_path: Path where to save the binary

        Returns:
            Path to created binary
        """
        binary = lief.ELF.Binary("test", lief.ELF.ELF_CLASS.ELFCLASS64)

        binary.header.machine_type = lief.ELF.ARCH.x86_64
        binary.header.entrypoint = 0x401000

        text_segment = lief.ELF.Segment()
        text_segment.type = lief.ELF.SEGMENT_TYPES.LOAD
        text_segment.flags = lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X
        text_segment.virtual_address = 0x401000
        text_segment.virtual_size = 0x2000
        text_segment.alignment = 0x1000

        code = bytearray(0x2000)
        code[0:8] = b"\x48\x8b\xec\x48\x83\xec\x20\xc3"
        code[0x500:0x508] = b"\x48\x31\xc0\x48\xff\xc0\xc3\x90"

        text_segment.content = memoryview(bytes(code))
        binary.add(text_segment)

        builder = lief.ELF.Builder(binary)
        builder.build()
        builder.write(str(output_path))

        return output_path


@pytest.fixture
def temp_binary_dir() -> Path:
    """Create temporary directory for test binaries."""
    temp_dir = Path(tempfile.mkdtemp(prefix="intellicrack_cert_patcher_test_"))
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def test_pe_x64_binary(temp_binary_dir: Path) -> Path:
    """Generate real x64 PE binary for testing."""
    binary_path = temp_binary_dir / "test_x64.exe"
    return TestBinaryGenerator.create_simple_pe_x64(binary_path)


@pytest.fixture
def test_pe_x86_binary(temp_binary_dir: Path) -> Path:
    """Generate real x86 PE binary for testing."""
    binary_path = temp_binary_dir / "test_x86.exe"
    return TestBinaryGenerator.create_simple_pe_x86(binary_path)


@pytest.fixture
def test_elf_x64_binary(temp_binary_dir: Path) -> Path:
    """Generate real x64 ELF binary for testing."""
    binary_path = temp_binary_dir / "test_elf"
    return TestBinaryGenerator.create_simple_elf_x64(binary_path)


@pytest.fixture
def fixtures_dir() -> Path:
    """Get path to fixtures directory with real protected binaries."""
    return Path(__file__).parent.parent.parent / "fixtures"


class TestPatcherInitialization:
    """Real tests for patcher initialization on actual binaries."""

    def test_patcher_initializes_with_real_x64_pe_binary(self, test_pe_x64_binary: Path) -> None:
        """Patcher successfully initializes with real x64 PE binary and detects architecture."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        assert patcher.binary_path == test_pe_x64_binary
        assert patcher.binary is not None
        assert isinstance(patcher.binary, lief.PE.Binary)
        assert patcher.architecture == Architecture.X64

    def test_patcher_initializes_with_real_x86_pe_binary(self, test_pe_x86_binary: Path) -> None:
        """Patcher successfully initializes with real x86 PE binary and detects architecture."""
        patcher = CertificatePatcher(str(test_pe_x86_binary))

        assert patcher.binary_path == test_pe_x86_binary
        assert patcher.binary is not None
        assert isinstance(patcher.binary, lief.PE.Binary)
        assert patcher.architecture == Architecture.X86

    def test_patcher_initializes_with_real_elf_binary(self, test_elf_x64_binary: Path) -> None:
        """Patcher successfully initializes with real ELF binary and detects architecture."""
        patcher = CertificatePatcher(str(test_elf_x64_binary))

        assert patcher.binary_path == test_elf_x64_binary
        assert patcher.binary is not None
        assert isinstance(patcher.binary, lief.ELF.Binary)
        assert patcher.architecture == Architecture.X64

    def test_patcher_raises_error_for_nonexistent_file(self, temp_binary_dir: Path) -> None:
        """Patcher raises FileNotFoundError when binary doesn't exist."""
        nonexistent_path = temp_binary_dir / "does_not_exist.exe"

        with pytest.raises(FileNotFoundError) as exc_info:
            CertificatePatcher(str(nonexistent_path))

        assert "Binary not found" in str(exc_info.value)
        assert str(nonexistent_path) in str(exc_info.value)

    def test_patcher_initializes_with_real_protected_binary(self, fixtures_dir: Path) -> None:
        """Patcher initializes with real commercial protected binary from fixtures."""
        protected_binaries = list((fixtures_dir / "binaries" / "pe" / "legitimate").glob("*.exe"))

        if not protected_binaries:
            pytest.skip("No real protected binaries in fixtures")

        test_binary = protected_binaries[0]
        patcher = CertificatePatcher(str(test_binary))

        assert patcher.binary is not None
        assert patcher.architecture in {Architecture.X86, Architecture.X64}


class TestArchitectureDetection:
    """Real tests for architecture detection on actual binaries."""

    def test_detects_x64_pe_architecture_from_real_binary(self, test_pe_x64_binary: Path) -> None:
        """Architecture detection correctly identifies x64 PE from real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        assert patcher.architecture == Architecture.X64
        assert patcher.binary.header.machine == lief.PE.MACHINE_TYPES.AMD64

    def test_detects_x86_pe_architecture_from_real_binary(self, test_pe_x86_binary: Path) -> None:
        """Architecture detection correctly identifies x86 PE from real binary."""
        patcher = CertificatePatcher(str(test_pe_x86_binary))

        assert patcher.architecture == Architecture.X86
        assert patcher.binary.header.machine == lief.PE.MACHINE_TYPES.I386

    def test_detects_x64_elf_architecture_from_real_binary(self, test_elf_x64_binary: Path) -> None:
        """Architecture detection correctly identifies x64 ELF from real binary."""
        patcher = CertificatePatcher(str(test_elf_x64_binary))

        assert patcher.architecture == Architecture.X64
        assert patcher.binary.header.machine_type == lief.ELF.ARCH.x86_64


class TestPatchTypeSelection:
    """Real tests for patch type selection logic."""

    def test_selects_always_succeed_for_high_confidence_function(self, test_pe_x64_binary: Path) -> None:
        """Patcher selects ALWAYS_SUCCEED patch type for high confidence validation functions."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        high_confidence_func = ValidationFunction(
            address=0x140001234,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.95,
            context="High confidence certificate validation",
            references=[0x140005000],
        )

        patch_type = patcher._select_patch_type(high_confidence_func)

        assert patch_type == PatchType.ALWAYS_SUCCEED

    def test_selects_always_succeed_for_verify_api_regardless_of_confidence(
        self, test_pe_x64_binary: Path
    ) -> None:
        """Patcher selects ALWAYS_SUCCEED for verify/check APIs even with low confidence."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        verify_func = ValidationFunction(
            address=0x140002345,
            api_name="VerifyCertificate",
            library="custom.dll",
            confidence=0.5,
            context="API name indicates verification",
            references=[],
        )

        patch_type = patcher._select_patch_type(verify_func)

        assert patch_type == PatchType.ALWAYS_SUCCEED

    def test_selects_nop_sled_for_low_confidence_non_verify_function(
        self, test_pe_x64_binary: Path
    ) -> None:
        """Patcher selects NOP_SLED for low confidence functions without verify/check in name."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        low_confidence_func = ValidationFunction(
            address=0x140003456,
            api_name="ProcessData",
            library="unknown.dll",
            confidence=0.4,
            context="Uncertain function",
            references=[],
        )

        patch_type = patcher._select_patch_type(low_confidence_func)

        assert patch_type == PatchType.NOP_SLED


class TestPatchGeneration:
    """Real tests for patch bytes generation."""

    def test_generates_real_always_succeed_x64_patch(self, test_pe_x64_binary: Path) -> None:
        """Patcher generates real x64 always-succeed patch bytes."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        func = ValidationFunction(
            address=0x140001000,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[],
        )

        patch_bytes = patcher._generate_patch(func, PatchType.ALWAYS_SUCCEED)

        assert patch_bytes is not None
        assert len(patch_bytes) >= 6
        expected_patch = generate_always_succeed_x64()
        assert patch_bytes == expected_patch

    def test_generates_real_always_succeed_x86_patch(self, test_pe_x86_binary: Path) -> None:
        """Patcher generates real x86 always-succeed patch bytes."""
        patcher = CertificatePatcher(str(test_pe_x86_binary))

        func = ValidationFunction(
            address=0x401000,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[],
        )

        patch_bytes = patcher._generate_patch(func, PatchType.ALWAYS_SUCCEED)

        assert patch_bytes is not None
        assert len(patch_bytes) == 6
        expected_patch = generate_always_succeed_x86()
        assert patch_bytes == expected_patch

    def test_generates_real_nop_sled_patch(self, test_pe_x64_binary: Path) -> None:
        """Patcher generates real NOP sled patch bytes."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        func = ValidationFunction(
            address=0x140001000,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.5,
            context="",
            references=[],
        )

        patch_bytes = patcher._generate_patch(func, PatchType.NOP_SLED)

        assert patch_bytes is not None
        assert len(patch_bytes) == 16
        expected_nops = generate_nop_sled(16, Architecture.X64)
        assert patch_bytes == expected_nops


class TestBinaryReading:
    """Real tests for reading binary content."""

    def test_reads_original_bytes_from_real_pe_binary(self, test_pe_x64_binary: Path) -> None:
        """Patcher correctly reads original bytes from real PE binary sections."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        address = 0x140001000
        size = 8

        original_bytes = patcher._read_original_bytes(address, size)

        assert original_bytes is not None
        assert len(original_bytes) == size
        assert original_bytes == b"\x48\x8b\xec\x48\x83\xec\x20\xc3"

    def test_reads_bytes_from_different_offsets(self, test_pe_x64_binary: Path) -> None:
        """Patcher reads correct bytes from different offsets in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        bytes_at_234 = patcher._read_original_bytes(0x140001234, 12)
        assert len(bytes_at_234) == 12
        assert bytes_at_234 == b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x57\xc3"

        bytes_at_345 = patcher._read_original_bytes(0x140001345, 14)
        assert len(bytes_at_345) == 14
        assert bytes_at_345[:6] == b"\x48\x83\xec\x28\xe8\x00"

    def test_reads_bytes_from_elf_binary(self, test_elf_x64_binary: Path) -> None:
        """Patcher correctly reads bytes from real ELF binary segments."""
        patcher = CertificatePatcher(str(test_elf_x64_binary))

        original_bytes = patcher._read_original_bytes(0x401000, 8)

        assert original_bytes is not None
        assert len(original_bytes) == 8
        assert original_bytes == b"\x48\x8b\xec\x48\x83\xec\x20\xc3"


class TestPatchSafetyChecks:
    """Real tests for patch safety validation."""

    def test_safety_check_passes_for_executable_section(self, test_pe_x64_binary: Path) -> None:
        """Safety check passes when patching executable section in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        address = 0x140001234
        size = 16

        is_safe = patcher._check_patch_safety(address, size)

        assert is_safe is True

    def test_safety_check_verifies_section_is_executable(self, test_pe_x64_binary: Path) -> None:
        """Safety check verifies section has execute permissions in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        text_section_addr = 0x140001000
        assert patcher._check_patch_safety(text_section_addr, 8) is True

        data_section_addr = 0x140003000
        is_data_safe = patcher._check_patch_safety(data_section_addr, 8)
        assert is_data_safe is False


class TestPatchApplication:
    """Real tests for applying patches to binaries."""

    def test_applies_patch_to_real_pe_binary(self, test_pe_x64_binary: Path) -> None:
        """Patcher successfully applies patch bytes to real PE binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        address = 0x140001234
        patch_bytes = generate_always_succeed_x64()

        original_bytes = patcher._read_original_bytes(address, len(patch_bytes))
        assert original_bytes != patch_bytes

        success = patcher._apply_patch(address, patch_bytes)

        assert success is True

        patched_bytes = patcher._read_original_bytes(address, len(patch_bytes))
        assert patched_bytes == patch_bytes

    def test_applies_multiple_patches_to_different_addresses(self, test_pe_x64_binary: Path) -> None:
        """Patcher applies multiple patches to different addresses in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        addr1 = 0x140001234
        patch1 = generate_always_succeed_x64()

        addr2 = 0x140001345
        patch2 = generate_nop_sled(14, Architecture.X64)

        success1 = patcher._apply_patch(addr1, patch1)
        success2 = patcher._apply_patch(addr2, patch2)

        assert success1 is True
        assert success2 is True

        result1 = patcher._read_original_bytes(addr1, len(patch1))
        result2 = patcher._read_original_bytes(addr2, len(patch2))

        assert result1 == patch1
        assert result2 == patch2

    def test_applies_patch_to_elf_binary(self, test_elf_x64_binary: Path) -> None:
        """Patcher successfully applies patch to real ELF binary."""
        patcher = CertificatePatcher(str(test_elf_x64_binary))

        address = 0x401500
        patch_bytes = generate_always_succeed_x64()

        success = patcher._apply_patch(address, patch_bytes)

        assert success is True

        patched_bytes = patcher._read_original_bytes(address, len(patch_bytes))
        assert patched_bytes == patch_bytes


class TestCompletePatchingWorkflow:
    """Real end-to-end tests for complete patching workflow."""

    def test_successful_patch_with_empty_detection_report(self, test_pe_x64_binary: Path) -> None:
        """Patcher handles empty detection report correctly."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        empty_report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=[],
            validation_functions=[],
            recommended_method=BypassMethod.NONE,
            risk_level="low",
            timestamp=datetime.now(),
        )

        result = patcher.patch_certificate_validation(empty_report)

        assert result.success is True
        assert len(result.patched_functions) == 0
        assert len(result.failed_patches) == 0
        assert result.backup_data == b""

    def test_patches_single_validation_function_successfully(self, test_pe_x64_binary: Path) -> None:
        """Patcher successfully patches single validation function in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        func = ValidationFunction(
            address=0x140001234,
            api_name="CertVerifyCertificateChainPolicy",
            library="crypt32.dll",
            confidence=0.95,
            context="Certificate validation routine",
            references=[0x140005000],
        )

        report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=["crypt32.dll"],
            validation_functions=[func],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
            timestamp=datetime.now(),
        )

        result = patcher.patch_certificate_validation(report)

        assert result.success is True
        assert len(result.patched_functions) == 1
        assert len(result.failed_patches) == 0

        patched_func = result.patched_functions[0]
        assert patched_func.address == func.address
        assert patched_func.api_name == func.api_name
        assert patched_func.patch_type == PatchType.ALWAYS_SUCCEED
        assert len(patched_func.original_bytes) > 0
        assert patched_func.patch_size >= 6

    def test_patches_multiple_validation_functions(self, test_pe_x64_binary: Path) -> None:
        """Patcher successfully patches multiple validation functions in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        functions = [
            ValidationFunction(
                address=0x140001234,
                api_name="CertVerifyCertificateChainPolicy",
                library="crypt32.dll",
                confidence=0.95,
                context="Primary cert validation",
                references=[0x140005000],
            ),
            ValidationFunction(
                address=0x140001345,
                api_name="WinHttpSetOption",
                library="winhttp.dll",
                confidence=0.85,
                context="TLS option configuration",
                references=[0x140006000],
            ),
        ]

        report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=["crypt32.dll", "winhttp.dll"],
            validation_functions=functions,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="medium",
            timestamp=datetime.now(),
        )

        result = patcher.patch_certificate_validation(report)

        assert result.success is True
        assert len(result.patched_functions) == 2
        assert len(result.failed_patches) == 0

        assert result.patched_functions[0].address == 0x140001234
        assert result.patched_functions[1].address == 0x140001345

    def test_saves_patched_binary_to_disk(
        self, test_pe_x64_binary: Path, temp_binary_dir: Path
    ) -> None:
        """Patcher saves patched binary to disk with .patched extension."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        func = ValidationFunction(
            address=0x140001234,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[],
        )

        report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=["test.dll"],
            validation_functions=[func],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
            timestamp=datetime.now(),
        )

        result = patcher.patch_certificate_validation(report)

        assert result.success is True

        patched_path = test_pe_x64_binary.parent / f"{test_pe_x64_binary.name}.patched"
        assert patched_path.exists()
        assert patched_path.stat().st_size > 0

        patched_binary = lief.parse(str(patched_path))
        assert patched_binary is not None


class TestPatchRollback:
    """Real tests for patch rollback functionality."""

    def test_rollback_restores_original_bytes_in_real_binary(self, test_pe_x64_binary: Path) -> None:
        """Rollback successfully restores original bytes in real binary."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        address = 0x140001234
        original_before_patch = patcher._read_original_bytes(address, 8)

        func = ValidationFunction(
            address=address,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[],
        )

        report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=["test.dll"],
            validation_functions=[func],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
            timestamp=datetime.now(),
        )

        patch_result = patcher.patch_certificate_validation(report)
        assert patch_result.success is True

        patched_bytes = patcher._read_original_bytes(address, 8)
        assert patched_bytes != original_before_patch

        rollback_success = patcher.rollback_patches(patch_result)

        assert rollback_success is True

        restored_bytes = patcher._read_original_bytes(address, 8)
        assert restored_bytes == original_before_patch

    def test_rollback_handles_multiple_patches(self, test_pe_x64_binary: Path) -> None:
        """Rollback successfully restores multiple patched functions."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        addr1 = 0x140001234
        addr2 = 0x140001345
        original1 = patcher._read_original_bytes(addr1, 8)
        original2 = patcher._read_original_bytes(addr2, 14)

        functions = [
            ValidationFunction(
                address=addr1,
                api_name="API1",
                library="lib1.dll",
                confidence=0.9,
                context="",
                references=[],
            ),
            ValidationFunction(
                address=addr2,
                api_name="API2",
                library="lib2.dll",
                confidence=0.85,
                context="",
                references=[],
            ),
        ]

        report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=["lib1.dll", "lib2.dll"],
            validation_functions=functions,
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
            timestamp=datetime.now(),
        )

        patch_result = patcher.patch_certificate_validation(report)
        assert len(patch_result.patched_functions) == 2

        rollback_success = patcher.rollback_patches(patch_result)

        assert rollback_success is True
        assert patcher._read_original_bytes(addr1, 8) == original1
        assert patcher._read_original_bytes(addr2, 14) == original2


class TestEdgeCases:
    """Real tests for edge cases and error conditions."""

    def test_handles_invalid_address_gracefully(self, test_pe_x64_binary: Path) -> None:
        """Patcher handles attempts to patch invalid addresses without crashing."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        invalid_address = 0x999999999
        patch_bytes = generate_always_succeed_x64()

        success = patcher._apply_patch(invalid_address, patch_bytes)

        assert success is False

    def test_handles_zero_size_patch(self, test_pe_x64_binary: Path) -> None:
        """Patcher handles zero-size patch attempt."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        address = 0x140001234
        empty_patch = b""

        success = patcher._apply_patch(address, empty_patch)

        assert success is True

    def test_patch_result_includes_backup_data(self, test_pe_x64_binary: Path) -> None:
        """Patch result contains backup data for all patched functions."""
        patcher = CertificatePatcher(str(test_pe_x64_binary))

        func = ValidationFunction(
            address=0x140001234,
            api_name="TestAPI",
            library="test.dll",
            confidence=0.9,
            context="",
            references=[],
        )

        report = DetectionReport(
            binary_path=str(test_pe_x64_binary),
            detected_libraries=["test.dll"],
            validation_functions=[func],
            recommended_method=BypassMethod.BINARY_PATCH,
            risk_level="low",
            timestamp=datetime.now(),
        )

        result = patcher.patch_certificate_validation(report)

        assert result.success is True
        assert len(result.backup_data) > 0
        assert result.backup_data == result.patched_functions[0].original_bytes


class TestRealProtectedBinaries:
    """Tests on real commercial protected binaries from fixtures."""

    def test_initializes_with_real_7zip_binary(self, fixtures_dir: Path) -> None:
        """Patcher initializes with real 7-Zip binary from fixtures."""
        binary_path = fixtures_dir / "binaries" / "pe" / "legitimate" / "7zip.exe"

        if not binary_path.exists():
            pytest.skip("7-Zip binary not in fixtures")

        patcher = CertificatePatcher(str(binary_path))

        assert patcher.binary is not None
        assert patcher.architecture in {Architecture.X86, Architecture.X64}

    def test_reads_bytes_from_real_firefox_binary(self, fixtures_dir: Path) -> None:
        """Patcher reads bytes from real Firefox binary."""
        binary_path = fixtures_dir / "binaries" / "pe" / "legitimate" / "firefox.exe"

        if not binary_path.exists():
            pytest.skip("Firefox binary not in fixtures")

        patcher = CertificatePatcher(str(binary_path))

        text_section = None
        for section in patcher.binary.sections:
            if section.name == ".text" or (section.characteristics & 0x20000000):
                text_section = section
                break

        if text_section:
            address = patcher.binary.optional_header.imagebase + text_section.virtual_address
            bytes_read = patcher._read_original_bytes(address, 16)

            assert len(bytes_read) == 16
            assert bytes_read != b"\x00" * 16


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
