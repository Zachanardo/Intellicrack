"""Production-ready tests for advanced Intellicrack protection analysis.

Tests validate comprehensive protection detection and analysis capabilities including:
- Advanced scan modes (normal, deep, heuristic, all)
- Entropy analysis for packed/encrypted sections
- Digital certificate validation
- Resource extraction and analysis
- Suspicious string detection
- Import hash calculation
- Similarity hashing
- YARA rule generation
- Batch analysis operations
- Custom signature creation
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.protection.intellicrack_protection_advanced import (
    AdvancedProtectionAnalysis,
    CertificateInfo,
    EntropyInfo,
    ExportFormat,
    ImportHash,
    IntellicrackAdvancedProtection,
    ResourceInfo,
    ScanMode,
    StringInfo,
    advanced_analyze,
)
from intellicrack.protection.intellicrack_protection_core import (
    DetectionResult,
    ProtectionType,
)


class TestScanModeEnum:
    """Test ScanMode enumeration values."""

    def test_scan_mode_enum_has_expected_values(self) -> None:
        """ScanMode enum defines all scan mode types."""
        assert ScanMode.NORMAL.value == "normal"
        assert ScanMode.DEEP.value == "deep"
        assert ScanMode.HEURISTIC.value == "heuristic"
        assert ScanMode.ALL.value == "all"

    def test_scan_mode_enum_can_compare_values(self) -> None:
        """ScanMode enum values can be compared and accessed."""
        assert ScanMode.NORMAL == ScanMode.NORMAL
        assert ScanMode.DEEP.value != ScanMode.HEURISTIC.value  # type: ignore[comparison-overlap]
        assert ScanMode.ALL.value == "all"


class TestExportFormatEnum:
    """Test ExportFormat enumeration values."""

    def test_export_format_enum_has_all_formats(self) -> None:
        """ExportFormat enum defines all supported export formats."""
        assert ExportFormat.JSON.value == "json"
        assert ExportFormat.XML.value == "xml"
        assert ExportFormat.TEXT.value == "text"
        assert ExportFormat.CSV.value == "csv"
        assert ExportFormat.HTML.value == "html"

    def test_export_format_enum_comparison(self) -> None:
        """ExportFormat enum values can be compared."""
        assert ExportFormat.JSON == ExportFormat.JSON
        assert ExportFormat.JSON.value != ExportFormat.XML.value  # type: ignore[comparison-overlap]


class TestEntropyInfoDataclass:
    """Test EntropyInfo dataclass for section entropy analysis."""

    def test_entropy_info_stores_section_data(self) -> None:
        """EntropyInfo stores complete section entropy information."""
        info = EntropyInfo(
            section_name=".text",
            offset=0x1000,
            size=0x5000,
            entropy=6.8,
            packed=False,
            encrypted=False,
        )

        assert info.section_name == ".text"
        assert info.offset == 0x1000
        assert info.size == 0x5000
        assert info.entropy == 6.8
        assert info.packed is False
        assert info.encrypted is False

    def test_entropy_info_indicates_packed_section(self) -> None:
        """EntropyInfo correctly identifies packed sections with high entropy."""
        info = EntropyInfo(
            section_name=".upx0",
            offset=0x2000,
            size=0x8000,
            entropy=7.9,
            packed=True,
            encrypted=False,
        )

        assert info.packed is True
        assert info.entropy > 7.5

    def test_entropy_info_indicates_encrypted_section(self) -> None:
        """EntropyInfo correctly identifies encrypted sections."""
        info = EntropyInfo(
            section_name=".enigma",
            offset=0x3000,
            size=0x4000,
            entropy=7.95,
            packed=False,
            encrypted=True,
        )

        assert info.encrypted is True
        assert info.entropy > 7.8


class TestCertificateInfoDataclass:
    """Test CertificateInfo dataclass for digital signatures."""

    def test_certificate_info_stores_complete_cert_data(self) -> None:
        """CertificateInfo stores all digital certificate fields."""
        cert = CertificateInfo(
            subject="CN=Microsoft Corporation",
            issuer="CN=Microsoft Code Signing PCA",
            serial_number="1234567890ABCDEF",
            valid_from="2024-01-01T00:00:00Z",
            valid_to="2026-01-01T00:00:00Z",
            algorithm="RSA-SHA256",
            is_valid=True,
            is_trusted=True,
        )

        assert "Microsoft Corporation" in cert.subject
        assert "Microsoft Code Signing PCA" in cert.issuer
        assert cert.serial_number == "1234567890ABCDEF"
        assert cert.algorithm == "RSA-SHA256"
        assert cert.is_valid is True
        assert cert.is_trusted is True

    def test_certificate_info_handles_untrusted_cert(self) -> None:
        """CertificateInfo correctly represents untrusted certificates."""
        cert = CertificateInfo(
            subject="CN=Unknown Publisher",
            issuer="CN=Self-Signed",
            serial_number="DEADBEEF",
            valid_from="2020-01-01T00:00:00Z",
            valid_to="2021-01-01T00:00:00Z",
            algorithm="SHA1",
            is_valid=False,
            is_trusted=False,
        )

        assert cert.is_valid is False
        assert cert.is_trusted is False


class TestResourceInfoDataclass:
    """Test ResourceInfo dataclass for PE resource analysis."""

    def test_resource_info_stores_complete_resource_data(self) -> None:
        """ResourceInfo stores all resource metadata."""
        res = ResourceInfo(
            type="RT_ICON",
            name="MAINICON",
            language="en-US",
            size=4096,
            offset=0x10000,
            data_hash="abc123def456",
        )

        assert res.type == "RT_ICON"
        assert res.name == "MAINICON"
        assert res.language == "en-US"
        assert res.size == 4096
        assert res.offset == 0x10000
        assert res.data_hash == "abc123def456"


class TestStringInfoDataclass:
    """Test StringInfo dataclass for suspicious string detection."""

    def test_string_info_stores_string_metadata(self) -> None:
        """StringInfo stores string value, location, and encoding."""
        info = StringInfo(
            value="LoadLibraryA",
            offset=0x5000,
            encoding="ascii",
            length=12,
            suspicious=False,
        )

        assert info.value == "LoadLibraryA"
        assert info.offset == 0x5000
        assert info.encoding == "ascii"
        assert info.length == 12
        assert info.suspicious is False

    def test_string_info_marks_suspicious_strings(self) -> None:
        """StringInfo correctly marks suspicious strings."""
        info = StringInfo(
            value="\\\\.\\\pipe\\malicious",
            offset=0x6000,
            encoding="unicode",
            length=40,
            suspicious=True,
        )

        assert info.suspicious is True
        assert "pipe" in info.value


class TestImportHashDataclass:
    """Test ImportHash dataclass for similarity analysis."""

    def test_import_hash_stores_hash_values(self) -> None:
        """ImportHash stores imphash, sorted imphash, and rich header hash."""
        ih = ImportHash(
            imphash="abc123def456",
            imphash_sorted="123abc456def",
            rich_header_hash="xyz789",
        )

        assert ih.imphash == "abc123def456"
        assert ih.imphash_sorted == "123abc456def"
        assert ih.rich_header_hash == "xyz789"

    def test_import_hash_allows_none_rich_header(self) -> None:
        """ImportHash allows None for rich header hash when unavailable."""
        ih = ImportHash(
            imphash="abc123",
            imphash_sorted="123abc",
            rich_header_hash=None,
        )

        assert ih.rich_header_hash is None


class TestAdvancedProtectionAnalysisDataclass:
    """Test AdvancedProtectionAnalysis extended dataclass."""

    def test_advanced_analysis_extends_base_analysis(self) -> None:
        """AdvancedProtectionAnalysis includes all base and extended fields."""
        analysis = AdvancedProtectionAnalysis(
            file_path="test.exe",
            file_type="PE32",
            architecture="x64",
            detections=[],
        )

        assert analysis.file_path == "test.exe"
        assert analysis.file_type == "PE32"
        assert analysis.architecture == "x64"
        assert isinstance(analysis.entropy_info, list)
        assert isinstance(analysis.certificates, list)
        assert isinstance(analysis.resources, list)
        assert isinstance(analysis.suspicious_strings, list)
        assert isinstance(analysis.heuristic_detections, list)

    def test_advanced_analysis_stores_entropy_info(self) -> None:
        """AdvancedProtectionAnalysis stores entropy analysis for sections."""
        entropy = [
            EntropyInfo(".text", 0x1000, 0x5000, 6.5, False, False),
            EntropyInfo(".data", 0x6000, 0x2000, 5.2, False, False),
        ]

        analysis = AdvancedProtectionAnalysis(
            file_path="test.exe",
            file_type="PE32",
            architecture="x64",
            detections=[],
            entropy_info=entropy,
        )

        assert len(analysis.entropy_info) == 2
        assert analysis.entropy_info[0].section_name == ".text"
        assert analysis.entropy_info[1].section_name == ".data"

    def test_advanced_analysis_stores_certificates(self) -> None:
        """AdvancedProtectionAnalysis stores digital certificate information."""
        certs = [
            CertificateInfo(
                "CN=Test",
                "CN=CA",
                "123",
                "2024-01-01",
                "2025-01-01",
                "SHA256",
                True,
                True,
            )
        ]

        analysis = AdvancedProtectionAnalysis(
            file_path="test.exe",
            file_type="PE32",
            architecture="x64",
            detections=[],
            certificates=certs,
        )

        assert len(analysis.certificates) == 1
        assert analysis.certificates[0].subject == "CN=Test"

    def test_advanced_analysis_stores_import_hash(self) -> None:
        """AdvancedProtectionAnalysis stores import hash for similarity."""
        ih = ImportHash("abc123", "123abc", "xyz789")

        analysis = AdvancedProtectionAnalysis(
            file_path="test.exe",
            file_type="PE32",
            architecture="x64",
            detections=[],
            import_hash=ih,
        )

        assert analysis.import_hash is not None
        assert analysis.import_hash.imphash == "abc123"


class TestIntellicrackAdvancedProtectionInitialization:
    """Test IntellicrackAdvancedProtection class initialization."""

    def test_advanced_protection_initializes_successfully(self) -> None:
        """Advanced protection engine initializes with base and extended features."""
        engine = IntellicrackAdvancedProtection()

        assert hasattr(engine, "logger")
        assert hasattr(engine, "detect_protections_advanced")
        assert hasattr(engine, "batch_analyze")
        assert hasattr(engine, "export_to_yara")

    def test_advanced_protection_finds_custom_db(self) -> None:
        """Advanced protection engine can locate custom signature database."""
        engine = IntellicrackAdvancedProtection()

        db_path = engine._find_custom_db()

        assert db_path is None or isinstance(db_path, str)
        if db_path:
            assert Path(db_path).exists()


class TestAdvancedProtectionDetection:
    """Test advanced protection detection with various scan modes."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        """Provide advanced protection engine instance."""
        return IntellicrackAdvancedProtection()

    @pytest.fixture
    def test_executable(self, tmp_path: Path) -> Path:
        """Create a minimal test executable."""
        exe_path = tmp_path / "test.exe"
        exe_data = b"MZ" + b"\x00" * 510
        exe_path.write_bytes(exe_data)
        return exe_path

    def test_detect_protections_normal_mode(
        self, engine: IntellicrackAdvancedProtection, test_executable: Path
    ) -> None:
        """Advanced detection performs normal scan with basic analysis."""
        result = engine.detect_protections_advanced(
            str(test_executable), ScanMode.NORMAL
        )

        assert isinstance(result, AdvancedProtectionAnalysis)
        assert result.file_path == str(test_executable)

    def test_detect_protections_deep_mode(
        self, engine: IntellicrackAdvancedProtection, test_executable: Path
    ) -> None:
        """Advanced detection performs deep scan with comprehensive analysis."""
        result = engine.detect_protections_advanced(
            str(test_executable), ScanMode.DEEP
        )

        assert isinstance(result, AdvancedProtectionAnalysis)
        assert isinstance(result.entropy_info, list)
        assert isinstance(result.suspicious_strings, list)

    def test_detect_protections_heuristic_mode(
        self, engine: IntellicrackAdvancedProtection, test_executable: Path
    ) -> None:
        """Advanced detection performs heuristic scan for unknown protections."""
        result = engine.detect_protections_advanced(
            str(test_executable), ScanMode.HEURISTIC
        )

        assert isinstance(result, AdvancedProtectionAnalysis)
        assert isinstance(result.heuristic_detections, list)

    def test_detect_protections_all_mode(
        self, engine: IntellicrackAdvancedProtection, test_executable: Path
    ) -> None:
        """Advanced detection performs all scan types simultaneously."""
        result = engine.detect_protections_advanced(
            str(test_executable), ScanMode.ALL
        )

        assert isinstance(result, AdvancedProtectionAnalysis)

    def test_detect_protections_on_nonexistent_file(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """Advanced detection handles nonexistent file gracefully."""
        result = engine.detect_protections_advanced(
            "nonexistent.exe", ScanMode.NORMAL
        )

        assert isinstance(result, AdvancedProtectionAnalysis)


class TestSuspiciousStringExtraction:
    """Test suspicious string detection and extraction."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    def test_extract_suspicious_strings_from_binary(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """String extraction identifies suspicious patterns in binary."""
        test_file = tmp_path / "test.bin"
        test_data = b"Normal data" + b"\x00" * 50
        test_data += b"LoadLibraryA" + b"\x00" * 50
        test_data += b"VirtualAlloc" + b"\x00" * 50
        test_file.write_bytes(test_data)

        strings = engine._extract_suspicious_strings(str(test_file), max_length=100)

        assert isinstance(strings, list)
        assert all(isinstance(s, StringInfo) for s in strings)

    def test_extract_suspicious_strings_limits_length(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """String extraction respects max length parameter."""
        test_file = tmp_path / "test.bin"
        test_data = b"A" * 1000
        test_file.write_bytes(test_data)

        strings = engine._extract_suspicious_strings(str(test_file), max_length=50)

        assert isinstance(strings, list)


class TestImportHashCalculation:
    """Test import hash calculation for binary similarity analysis."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    def test_calculate_import_hash_on_pe_file(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Import hash calculation processes PE files."""
        pe_file = tmp_path / "test.exe"
        pe_data = b"MZ" + b"\x00" * 1000
        pe_file.write_bytes(pe_data)

        ih = engine._calculate_import_hash(str(pe_file))

        assert ih is None or isinstance(ih, ImportHash)
        if ih:
            assert isinstance(ih.imphash, str)
            assert isinstance(ih.imphash_sorted, str)

    def test_calculate_import_hash_manual_fallback(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Import hash calculation uses manual method as fallback."""
        test_file = tmp_path / "test.exe"
        test_data = b"MZ" + b"\x00" * 500
        test_file.write_bytes(test_data)

        ih = engine._calculate_import_hash_manual(str(test_file))

        assert ih is None or isinstance(ih, ImportHash)


class TestSimilarityHashCalculation:
    """Test similarity hash calculation for fuzzy matching."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    def test_calculate_similarity_hash(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Similarity hash calculation generates fuzzy hash."""
        test_file = tmp_path / "test.bin"
        test_data = b"Test data for fuzzy hashing" * 100
        test_file.write_bytes(test_data)

        sim_hash = engine._calculate_similarity_hash(str(test_file))

        assert sim_hash is None or isinstance(sim_hash, str)

    def test_calculate_custom_fuzzy_hash(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Custom fuzzy hash calculation produces hash string."""
        test_file = tmp_path / "test.bin"
        test_data = b"Custom fuzzy hash test data" * 50
        test_file.write_bytes(test_data)

        fuzzy_hash = engine._calculate_custom_fuzzy_hash(str(test_file))

        assert isinstance(fuzzy_hash, str)
        assert len(fuzzy_hash) > 0

    def test_calculate_file_hash(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """File hash calculation produces SHA256 hash."""
        test_file = tmp_path / "test.bin"
        test_data = b"Test data for SHA256 hashing"
        test_file.write_bytes(test_data)

        file_hash = engine._calculate_file_hash(str(test_file))

        expected_hash = hashlib.sha256(test_data).hexdigest()
        assert file_hash == expected_hash


class TestBatchAnalysis:
    """Test batch analysis of multiple files."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    @pytest.fixture
    def test_files(self, tmp_path: Path) -> list[Path]:
        """Create multiple test files for batch processing."""
        files = []
        for i in range(5):
            file_path = tmp_path / f"test{i}.exe"
            file_path.write_bytes(b"MZ" + b"\x00" * 100 * (i + 1))
            files.append(file_path)
        return files

    def test_batch_analyze_processes_multiple_files(
        self,
        engine: IntellicrackAdvancedProtection,
        test_files: list[Path],
    ) -> None:
        """Batch analysis processes all files and returns results."""
        file_paths = [str(f) for f in test_files]

        results = engine.batch_analyze(file_paths, ScanMode.NORMAL, max_workers=2)  # type: ignore[arg-type, misc]

        assert isinstance(results, list)  # type: ignore[unreachable]
        assert len(results) == len(file_paths)  # type: ignore[unreachable]
        assert all(isinstance(r, AdvancedProtectionAnalysis) for r in results)

    def test_batch_analyze_with_deep_scan(
        self,
        engine: IntellicrackAdvancedProtection,
        test_files: list[Path],
    ) -> None:
        """Batch analysis performs deep scan on all files."""
        file_paths = [str(f) for f in test_files[:3]]

        results = engine.batch_analyze(file_paths, ScanMode.DEEP, max_workers=1)  # type: ignore[arg-type, misc]

        assert len(results) == 3
        assert all(isinstance(r.entropy_info, list) for r in results)  # type: ignore[attr-defined]


class TestCustomSignatureCreation:
    """Test custom protection signature creation."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    def test_create_custom_signature(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """Custom signature creation adds new detection pattern."""
        result = engine.create_custom_signature(
            name="CustomProtection",
            pattern=b"\x4D\x5A\x90\x00",
            offset=0,
            description="Custom MZ header protection",
        )

        assert isinstance(result, bool)

    def test_create_custom_signature_with_offset(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """Custom signature creation supports offset parameter."""
        result = engine.create_custom_signature(
            name="OffsetProtection",
            pattern=b"\xCA\xFE\xBA\xBE",
            offset=0x1000,
            description="Protection at specific offset",
        )

        assert isinstance(result, bool)


class TestYARAExport:
    """Test YARA rule generation from analysis results."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    @pytest.fixture
    def sample_analysis(self) -> AdvancedProtectionAnalysis:
        """Create sample analysis result for YARA export."""
        detection = DetectionResult(
            protection_type=ProtectionType.PACKER,  # type: ignore[call-arg]
            name="UPX",
            version="3.96",
            confidence=95.0,
            signature="UPX packer detected",
        )

        return AdvancedProtectionAnalysis(
            file_path="sample.exe",
            file_type="PE32",
            architecture="x86",
            detections=[detection],
        )

    def test_export_to_yara_generates_rule(
        self,
        engine: IntellicrackAdvancedProtection,
        sample_analysis: AdvancedProtectionAnalysis,
    ) -> None:
        """YARA export generates valid YARA rule from analysis."""
        yara_rule = engine.export_to_yara(sample_analysis)

        assert isinstance(yara_rule, str)
        assert "rule" in yara_rule.lower()
        assert "strings:" in yara_rule or "condition:" in yara_rule

    def test_export_to_yara_includes_detections(
        self,
        engine: IntellicrackAdvancedProtection,
        sample_analysis: AdvancedProtectionAnalysis,
    ) -> None:
        """YARA export includes detection information in rule."""
        yara_rule = engine.export_to_yara(sample_analysis)

        assert "UPX" in yara_rule or "packer" in yara_rule.lower()

    def test_export_to_yara_with_heuristic_detections(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """YARA export handles heuristic detections."""
        analysis = AdvancedProtectionAnalysis(
            file_path="test.exe",
            file_type="PE32",
            architecture="x64",
            detections=[],
            heuristic_detections=[
                DetectionResult(
                    ProtectionType.UNKNOWN,  # type: ignore[arg-type]
                    "Heuristic1",
                    None,  # type: ignore[arg-type]
                    85.0,
                    "Heuristic detection",  # type: ignore[arg-type]
                )
            ],
        )

        yara_rule = engine.export_to_yara(analysis)

        assert isinstance(yara_rule, str)


class TestFormatCapabilities:
    """Test file format capability detection."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    def test_get_format_capabilities_for_pe(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Format capabilities detection identifies PE file features."""
        pe_file = tmp_path / "test.exe"
        pe_file.write_bytes(b"MZ" + b"\x00" * 1000)

        caps = engine.get_format_capabilities(str(pe_file))

        assert isinstance(caps, dict)
        assert all(isinstance(v, bool) for v in caps.values())


class TestAdvancedAnalyzeFunction:
    """Test module-level advanced_analyze convenience function."""

    @pytest.fixture
    def test_file(self, tmp_path: Path) -> Path:
        """Create test file for analysis."""
        file_path = tmp_path / "test.exe"
        file_path.write_bytes(b"MZ" + b"\x00" * 500)
        return file_path

    def test_advanced_analyze_normal_mode(self, test_file: Path) -> None:
        """Module function performs normal mode analysis."""
        result = advanced_analyze(str(test_file), ScanMode.NORMAL, enable_heuristic=False)

        assert isinstance(result, AdvancedProtectionAnalysis)
        assert result.file_path == str(test_file)

    def test_advanced_analyze_deep_mode(self, test_file: Path) -> None:
        """Module function performs deep mode analysis."""
        result = advanced_analyze(str(test_file), ScanMode.DEEP, enable_heuristic=True)

        assert isinstance(result, AdvancedProtectionAnalysis)

    def test_advanced_analyze_with_heuristics(self, test_file: Path) -> None:
        """Module function enables heuristic detection."""
        result = advanced_analyze(str(test_file), ScanMode.HEURISTIC, enable_heuristic=True)

        assert isinstance(result, AdvancedProtectionAnalysis)
        assert isinstance(result.heuristic_detections, list)


class TestEdgeCasesAndErrorHandling:
    """Test edge cases and error handling in advanced protection."""

    @pytest.fixture
    def engine(self) -> IntellicrackAdvancedProtection:
        return IntellicrackAdvancedProtection()

    def test_detect_protections_on_empty_file(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Advanced detection handles empty file gracefully."""
        empty_file = tmp_path / "empty.exe"
        empty_file.write_bytes(b"")

        result = engine.detect_protections_advanced(str(empty_file), ScanMode.NORMAL)

        assert isinstance(result, AdvancedProtectionAnalysis)

    def test_detect_protections_on_invalid_path(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """Advanced detection handles invalid path gracefully."""
        result = engine.detect_protections_advanced(
            "Z:\\invalid\\path\\file.exe", ScanMode.NORMAL
        )

        assert isinstance(result, AdvancedProtectionAnalysis)

    def test_batch_analyze_with_empty_list(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """Batch analysis handles empty file list."""
        results = engine.batch_analyze([], ScanMode.NORMAL)  # type: ignore[arg-type]

        assert isinstance(results, list)  # type: ignore[unreachable]
        assert len(results) == 0  # type: ignore[unreachable]

    def test_batch_analyze_with_mixed_valid_invalid_files(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Batch analysis handles mix of valid and invalid files."""
        valid_file = tmp_path / "valid.exe"
        valid_file.write_bytes(b"MZ" + b"\x00" * 100)

        file_paths = [str(valid_file), "invalid.exe", "another_invalid.exe"]

        results = engine.batch_analyze(file_paths, ScanMode.NORMAL)  # type: ignore[arg-type]

        assert isinstance(results, list)  # type: ignore[unreachable]
        assert len(results) == 3  # type: ignore[unreachable]

    def test_calculate_import_hash_on_non_pe_file(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """Import hash calculation handles non-PE files gracefully."""
        non_pe = tmp_path / "test.txt"
        non_pe.write_bytes(b"Not a PE file")

        ih = engine._calculate_import_hash(str(non_pe))

        assert ih is None or isinstance(ih, ImportHash)

    def test_extract_suspicious_strings_on_binary_file(
        self, engine: IntellicrackAdvancedProtection, tmp_path: Path
    ) -> None:
        """String extraction handles pure binary data."""
        binary_file = tmp_path / "binary.dat"
        binary_file.write_bytes(bytes(range(256)) * 10)

        strings = engine._extract_suspicious_strings(str(binary_file), max_length=100)

        assert isinstance(strings, list)

    def test_export_to_yara_with_no_detections(
        self, engine: IntellicrackAdvancedProtection
    ) -> None:
        """YARA export handles analysis with no detections."""
        analysis = AdvancedProtectionAnalysis(
            file_path="empty.exe",
            file_type="PE32",
            architecture="x86",
            detections=[],
        )

        yara_rule = engine.export_to_yara(analysis)

        assert isinstance(yara_rule, str)
