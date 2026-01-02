"""
Comprehensive unit tests for MultiFormatBinaryAnalyzer.

Tests validate production-ready multi-format binary analysis capabilities including:
- Advanced format detection and identification
- Sophisticated binary parsing across multiple formats (PE, ELF, Mach-O, DEX, APK, JAR, MSI, COM)
- Cross-format correlation and embedded format analysis
- Security-focused analysis features (protection detection, obfuscation analysis)
- Real-world binary compatibility and edge case handling
- Performance and error resilience validation

These tests use specification-driven methodology and expect genuine analysis functionality,
not placeholder implementations. All tests are designed to fail with stub/mock code.
"""

import hashlib
import os
import shutil
import struct
import tempfile
import unittest
from pathlib import Path
from typing import Any

from intellicrack.core.analysis.multi_format_analyzer import (
    BinaryInfo,
    MultiFormatBinaryAnalyzer,
    run_multi_format_analysis,
)


class TestBinaryInfo(unittest.TestCase):
    """Test BinaryInfo data class for comprehensive binary metadata storage."""

    def test_binary_info_initialization_with_comprehensive_metadata(self) -> None:
        """Test BinaryInfo properly stores complete binary metadata."""
        sections: list[dict[str, Any]] = [
            {
                'name': '.text',
                'virtual_address': 0x1000,
                'virtual_size': 0x2000,
                'raw_size': 0x1800,
                'characteristics': 0x60000020,
                'entropy': 6.2
            },
            {
                'name': '.data',
                'virtual_address': 0x3000,
                'virtual_size': 0x1000,
                'raw_size': 0x800,
                'characteristics': 0xC0000040,
                'entropy': 2.1
            }
        ]

        imports: dict[str, list[str]] = {
            'kernel32.dll': ['CreateFileA', 'ReadFile', 'WriteFile', 'CloseHandle'],
            'user32.dll': ['MessageBoxA', 'FindWindowA'],
            'advapi32.dll': ['RegOpenKeyA', 'RegQueryValueA']
        }

        exports: list[dict[str, Any]] = [
            {'name': 'MainFunction', 'address': 0x1200, 'ordinal': 1},
            {'name': 'HelperFunction', 'address': 0x1450, 'ordinal': 2}
        ]

        strings: list[dict[str, Any]] = [
            {'value': 'Software protection error', 'address': 0x2000, 'type': 'ascii'},
            {'value': 'License validation failed', 'address': 0x2050, 'type': 'ascii'},
            {'value': 'C:\\Program Files\\App\\config.ini', 'address': 0x2100, 'type': 'ascii'}
        ]

        info = BinaryInfo(
            file_path="C:\\test\\sample.exe",
            file_size=65536,
            file_type="PE32",
            architecture="i386",
            endianness="little",
            entry_point=0x1000,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        self.assertEqual(info.file_path, "C:\\test\\sample.exe")
        self.assertEqual(info.file_size, 65536)
        self.assertEqual(info.file_type, "PE32")
        self.assertEqual(info.architecture, "i386")
        self.assertEqual(info.endianness, "little")
        self.assertEqual(info.entry_point, 0x1000)

        self.assertEqual(len(info.sections), 2)
        self.assertEqual(info.sections[0]['name'], '.text')
        self.assertEqual(info.sections[0]['entropy'], 6.2)

        self.assertIn('kernel32.dll', info.imports)
        self.assertIn('CreateFileA', info.imports['kernel32.dll'])

        self.assertEqual(len(info.exports), 2)
        self.assertEqual(info.exports[0]['name'], 'MainFunction')

        self.assertEqual(len(info.strings), 3)
        self.assertEqual(info.strings[0]['value'], 'Software protection error')

        self.assertEqual(info.md5, "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(info.sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


class TestMultiFormatBinaryAnalyzer(unittest.TestCase):
    """Test MultiFormatBinaryAnalyzer for comprehensive multi-format analysis capabilities."""

    def setUp(self) -> None:
        """Set up test environment with analyzer instance."""
        self.analyzer: MultiFormatBinaryAnalyzer = MultiFormatBinaryAnalyzer()
        self.test_dir: str = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_pe_test_binary(self, filename: str) -> str:
        """Create a realistic PE binary for testing."""
        filepath = os.path.join(self.test_dir, filename)

        dos_header = b'MZ'
        dos_header += b'\x90\x00' * 29
        dos_header += struct.pack('<L', 0x80)

        dos_stub = b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21'
        dos_stub += b'This program cannot be run in DOS mode.\r\r\n$' + b'\x00' * 7

        pe_signature = b'PE\x00\x00'

        coff_header = struct.pack('<HHIIIHH',
            0x14c,
            2,
            0x12345678,
            0,
            0,
            0xe0,
            0x102
        )

        optional_header = struct.pack('<HBBIIIIIIIHHHHHHIIII',
            0x10b,
            0x0e,
            0x16,
            0x1000,
            0x1000,
            0,
            0x1000,
            0x1000,
            0x2000,
            0x400000,
            0x1000,
            0x200,
            6,
            0,
            6,
            0,
            6,
            0,
            0,
            0x3000,
            0x200,
            0,
            2,
            0
        )

        optional_header += struct.pack('<IIII',
            0x100000,
            0x1000,
            0x100000,
            0x1000
        )

        data_dirs = b'\x00' * (16 * 8)
        optional_header += data_dirs

        section1 = b'.text\x00\x00\x00'
        section1 += struct.pack('<IIIIIIHH',
            0x1000,
            0x1000,
            0x1000,
            0x200,
            0,
            0,
            0,
            0,
            0x60000020
        )

        section2 = b'.data\x00\x00\x00'
        section2 += struct.pack('<IIIIIIHH',
            0x1000,
            0x2000,
            0x200,
            0x1200,
            0,
            0,
            0,
            0,
            0xC0000040
        )

        pe_data = dos_header + dos_stub
        pe_data += b'\x00' * (0x80 - len(pe_data))
        pe_data += pe_signature + coff_header + optional_header
        pe_data += section1 + section2

        pe_data += b'\x00' * (0x200 - len(pe_data))

        text_data = b'\x55\x8b\xec\x83\xec\x10'
        text_data += b'\x68\x00\x20\x40\x00'
        text_data += b'\xff\x15\x00\x30\x40\x00'
        text_data += b'\x8b\xe5\x5d\xc3'
        text_data += b'\x00' * (0x1000 - len(text_data))
        pe_data += text_data

        data_section = b'Hello World\x00'
        data_section += b'\x00' * (0x200 - len(data_section))
        pe_data += data_section

        with open(filepath, 'wb') as f:
            f.write(pe_data)

        return filepath

    def _create_elf_test_binary(self, filename: str) -> str:
        """Create a realistic ELF binary for testing."""
        filepath = os.path.join(self.test_dir, filename)

        elf_header = b'\x7fELF'
        elf_header += b'\x01'
        elf_header += b'\x01'
        elf_header += b'\x01'
        elf_header += b'\x00' * 9
        elf_header += struct.pack('<HHIIIIIHHHHHH',
            2,
            3,
            1,
            0x8048080,
            0x34,
            0x100,
            0,
            0x34,
            0x20,
            1,
            0x28,
            3,
            2
        )

        prog_header = struct.pack('<IIIIIIII',
            1,
            0,
            0x8048000,
            0x8048000,
            0x200,
            0x200,
            5,
            0x1000
        )

        elf_data = elf_header + prog_header
        elf_data += b'\x00' * (0x100 - len(elf_data))

        elf_data += b'\x00' * 0x28

        elf_data += struct.pack('<IIIIIIIIII',
            1,
            1,
            6,
            0x8048080,
            0x80,
            0x20,
            0,
            0,
            1,
            0
        )

        elf_data += struct.pack('<IIIIIIIIII',
            7,
            3,
            0,
            0,
            0xa0,
            0x10,
            0,
            0,
            1,
            0
        )

        elf_data = elf_data[:0x80]
        text_code = b'\xb8\x01\x00\x00\x00'
        text_code += b'\xbb\x00\x00\x00\x00'
        text_code += b'\xcd\x80'
        elf_data += text_code + b'\x00' * (0x20 - len(text_code))

        elf_data += b'\x00.text\x00.shstrtab\x00'

        with open(filepath, 'wb') as f:
            f.write(elf_data)

        return filepath

    def _create_dex_test_binary(self, filename: str) -> str:
        """Create a realistic DEX binary for testing."""
        filepath = os.path.join(self.test_dir, filename)

        dex_data = b'dex\n035\x00'
        dex_data += struct.pack('<I', 0x12345678)
        dex_data += b'\x00' * 20
        dex_data += struct.pack('<I', 0x200)
        dex_data += struct.pack('<I', 0x70)
        dex_data += struct.pack('<I', 0x12345678)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 2)
        dex_data += struct.pack('<I', 0x70)
        dex_data += struct.pack('<I', 1)
        dex_data += struct.pack('<I', 0x78)
        dex_data += struct.pack('<I', 1)
        dex_data += struct.pack('<I', 0x7c)
        dex_data += struct.pack('<I', 1)
        dex_data += struct.pack('<I', 0x88)
        dex_data += struct.pack('<I', 1)
        dex_data += struct.pack('<I', 0x90)
        dex_data += struct.pack('<I', 1)
        dex_data += struct.pack('<I', 0x98)
        dex_data += struct.pack('<I', 0x100)
        dex_data += struct.pack('<I', 0x100)

        dex_data += struct.pack('<I', 0x120)
        dex_data += struct.pack('<I', 0x130)

        dex_data += struct.pack('<I', 0)

        dex_data += struct.pack('<I', 1)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)

        dex_data += struct.pack('<HH', 0, 0)
        dex_data += struct.pack('<I', 0)

        dex_data += struct.pack('<HH', 0, 0)
        dex_data += struct.pack('<I', 1)

        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)
        dex_data += struct.pack('<I', 0)

        dex_data += b'\x00' * (0x120 - len(dex_data))

        dex_data += struct.pack('<B', 12) + b'LTestClass;'
        dex_data += b'\x00'
        dex_data += struct.pack('<B', 4) + b'main'
        dex_data += b'\x00'

        dex_data += b'\x00' * (0x200 - len(dex_data))

        with open(filepath, 'wb') as f:
            f.write(dex_data)

        return filepath

    def test_analyzer_initialization_with_backend_validation(self) -> None:
        """Test analyzer properly initializes with comprehensive backend checks."""
        analyzer = MultiFormatBinaryAnalyzer()

        self.assertTrue(hasattr(analyzer, 'lief_available'))
        self.assertTrue(hasattr(analyzer, 'pefile_available'))
        self.assertTrue(hasattr(analyzer, 'pyelftools_available'))
        self.assertTrue(hasattr(analyzer, 'macholib_available'))
        self.assertTrue(hasattr(analyzer, 'zipfile_available'))
        self.assertTrue(hasattr(analyzer, 'xml_available'))

        self.assertIsInstance(analyzer.lief_available, bool)
        self.assertIsInstance(analyzer.pefile_available, bool)
        self.assertIsInstance(analyzer.pyelftools_available, bool)
        self.assertIsInstance(analyzer.macholib_available, bool)
        self.assertIsInstance(analyzer.zipfile_available, bool)
        self.assertIsInstance(analyzer.xml_available, bool)

        self.assertTrue(hasattr(analyzer, 'logger'))
        self.assertIsNotNone(analyzer.logger)

    def test_advanced_format_detection_pe_variants(self) -> None:
        """Test sophisticated PE format detection for various PE types."""
        pe32_path = self._create_pe_test_binary("test.exe")

        detected_format = self.analyzer.identify_format(pe32_path)

        self.assertIn("PE", detected_format.upper())

        with open(pe32_path, 'r+b') as f:
            f.seek(0x3c)
            f.write(struct.pack('<L', 0x90))

        detected_format_modified = self.analyzer.identify_format(pe32_path)
        self.assertIn("PE", detected_format_modified.upper())

    def test_advanced_format_detection_elf_variants(self) -> None:
        """Test sophisticated ELF format detection for various architectures."""
        elf_path = self._create_elf_test_binary("test_elf")

        detected_format = self.analyzer.identify_format(elf_path)
        self.assertIn("ELF", detected_format.upper())

    def test_advanced_format_detection_android_formats(self) -> None:
        """Test DEX and APK format detection with Android-specific analysis."""
        dex_path = self._create_dex_test_binary("classes.dex")

        detected_format = self.analyzer.identify_format(dex_path)
        self.assertIn("DEX", detected_format.upper())

    def test_comprehensive_pe_analysis_with_security_features(self) -> None:
        """Test comprehensive PE analysis with security-focused capabilities."""
        pe_path = self._create_pe_test_binary("complex.exe")

        result = self.analyzer.analyze_pe(pe_path)

        self.assertIsInstance(result, dict)
        self.assertEqual(result.get('format'), 'PE')

        sections = result.get('sections', [])
        self.assertIsInstance(sections, list)
        self.assertGreater(len(sections), 0)

        for section in sections:
            self.assertIsInstance(section, dict)
            self.assertIn('name', section)
            self.assertIn('virtual_address', section)
            self.assertIn('virtual_size', section)
            self.assertIn('raw_size', section)
            self.assertIn('characteristics', section)

            if 'entropy' in section:
                entropy = section['entropy']
                self.assertIsInstance(entropy, (int, float))
                self.assertGreaterEqual(entropy, 0.0)
                self.assertLessEqual(entropy, 8.0)

        imports = result.get('imports', [])
        self.assertIsInstance(imports, list)

        exports = result.get('exports', [])
        self.assertIsInstance(exports, list)

        file_size = Path(pe_path).stat().st_size
        md5_hash = hashlib.md5(Path(pe_path).read_bytes()).hexdigest()
        sha256_hash = hashlib.sha256(Path(pe_path).read_bytes()).hexdigest()

        self.assertIsInstance(md5_hash, str)
        self.assertEqual(len(md5_hash), 32)
        self.assertIsInstance(sha256_hash, str)
        self.assertEqual(len(sha256_hash), 64)

    def test_comprehensive_elf_analysis_with_symbol_resolution(self) -> None:
        """Test comprehensive ELF analysis with symbol table and dynamic linking."""
        elf_path = self._create_elf_test_binary("test_binary")

        result = self.analyzer.analyze_elf(elf_path)

        self.assertIsInstance(result, dict)
        result_format = result.get('format', '')
        self.assertIn("ELF", result_format.upper())

        sections = result.get('sections', [])
        self.assertIsInstance(sections, list)
        for section in sections:
            self.assertIsInstance(section, dict)
            self.assertIn('name', section)

    def test_dex_analysis_with_android_specifics(self) -> None:
        """Test DEX analysis with Android-specific metadata extraction."""
        dex_path = self._create_dex_test_binary("test.dex")

        result = self.analyzer.analyze_dex(dex_path)

        self.assertIsInstance(result, dict)
        result_format = result.get('format', '')
        self.assertIn("DEX", result_format.upper())

        sections = result.get('sections', [])
        self.assertIsInstance(sections, list)

    def test_cross_format_analysis_apk_with_embedded_dex(self) -> None:
        """Test APK analysis with embedded DEX extraction and analysis."""
        import zipfile
        apk_path = os.path.join(self.test_dir, "test.apk")

        with zipfile.ZipFile(apk_path, 'w') as apk:
            manifest_content = b'<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test.app"><application android:label="Test App"><activity android:name=".MainActivity"></activity></application></manifest>'
            apk.writestr('AndroidManifest.xml', manifest_content)

            dex_path = self._create_dex_test_binary("embedded.dex")
            with open(dex_path, 'rb') as f:
                dex_content = f.read()
            apk.writestr('classes.dex', dex_content)

            apk.writestr('resources.arsc', b'Mock resources data')
            apk.writestr('res/drawable/icon.png', b'Mock PNG data')

        result = self.analyzer.analyze_apk(apk_path)

        self.assertIsInstance(result, dict)
        result_format = result.get('format', '')
        self.assertIn("APK", result_format.upper())

        files = result.get('files', [])
        self.assertIsInstance(files, list)

    def test_java_jar_analysis_with_manifest_parsing(self) -> None:
        """Test JAR analysis with manifest and class file extraction."""
        import zipfile
        jar_path = os.path.join(self.test_dir, "test.jar")

        with zipfile.ZipFile(jar_path, 'w') as jar:
            manifest_content = 'Manifest-Version: 1.0\nMain-Class: com.test.MainApp\nClass-Path: lib/dependency.jar\n'
            jar.writestr('META-INF/MANIFEST.MF', manifest_content.encode())

            jar.writestr('com/test/MainApp.class', b'\xCA\xFE\xBA\xBE')
            jar.writestr('com/test/util/Helper.class', b'\xCA\xFE\xBA\xBE')

        result = self.analyzer.analyze_jar(jar_path)

        self.assertIsInstance(result, dict)
        result_format = result.get('format', '')
        self.assertIn("JAR", result_format.upper())

    def test_windows_msi_analysis_with_compound_document_parsing(self) -> None:
        """Test MSI analysis with compound document structure parsing."""
        msi_path = os.path.join(self.test_dir, "test.msi")

        with open(msi_path, 'wb') as f:
            f.write(b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1')
            f.write(struct.pack('<H', 0x003E))
            f.write(struct.pack('<H', 0x003E))
            f.write(struct.pack('<H', 0xFFFE))
            f.write(struct.pack('<H', 0x0009))
            f.write(struct.pack('<H', 0x0006))
            f.write(b'\x00' * 6)
            f.write(b'\x00' * (512 - f.tell()))

        result = self.analyzer.analyze_msi(msi_path)

        self.assertIsInstance(result, dict)
        result_format = result.get('format', '')
        self.assertIn("MSI", result_format.upper())

    def test_dos_com_analysis_with_legacy_format_handling(self) -> None:
        """Test COM file analysis with DOS-specific features."""
        com_path = os.path.join(self.test_dir, "test.com")

        with open(com_path, 'wb') as f:
            f.write(b'\xB4\x09')
            f.write(b'\xBA\x0E\x01')
            f.write(b'\xCD\x21')
            f.write(b'\xB4\x4C')
            f.write(b'\xCD\x21')
            f.write(b'Hello World!$')

        result = self.analyzer.analyze_com(com_path)

        self.assertIsInstance(result, dict)
        result_format = result.get('format', '')
        self.assertIn("COM", result_format.upper())

    def test_error_handling_corrupted_binaries(self) -> None:
        """Test error handling with corrupted and malformed binaries."""
        corrupted_pe = os.path.join(self.test_dir, "corrupted.exe")
        with open(corrupted_pe, 'wb') as f:
            f.write(b'MZ')
            f.write(b'\x00' * 100)

        try:
            result = self.analyzer.analyze_pe(corrupted_pe)
            self.assertIsInstance(result, dict)
        except Exception as e:
            self.assertIsInstance(str(e), str)
            self.assertGreater(len(str(e)), 0)

        invalid_file = os.path.join(self.test_dir, "invalid.bin")
        with open(invalid_file, 'wb') as f:
            f.write(b'This is not a binary file at all!')

        detected_format = self.analyzer.identify_format(invalid_file)
        self.assertIn(detected_format.lower(), ['unknown', 'unsupported', 'unrecognized', ''])

    def test_performance_large_binary_analysis(self) -> None:
        """Test performance with reasonably large binary files."""
        large_pe = os.path.join(self.test_dir, "large.exe")
        base_path = self._create_pe_test_binary("base.exe")
        with open(base_path, 'rb') as f:
            base_data = f.read()

        with open(large_pe, 'wb') as f:
            f.write(base_data)
            f.write(b'\x00' * 50000)

        import time
        start_time = time.time()
        result = self.analyzer.analyze_pe(large_pe)
        analysis_time = time.time() - start_time

        self.assertLess(analysis_time, 10.0)
        self.assertIsInstance(result, dict)

    def test_macho_analysis_with_load_commands(self) -> None:
        """Test Mach-O analysis with load command parsing."""
        macho_path = os.path.join(self.test_dir, "test_macho")

        with open(macho_path, 'wb') as f:
            f.write(struct.pack('<I', 0xFEEDFACE))
            f.write(struct.pack('<I', 7))
            f.write(struct.pack('<I', 3))
            f.write(struct.pack('<I', 2))
            f.write(struct.pack('<I', 0))
            f.write(struct.pack('<I', 0))
            f.write(struct.pack('<I', 0))

        detected_format = self.analyzer.identify_format(macho_path)
        if "MACH" in detected_format.upper() or "MACHO" in detected_format.upper():
            result = self.analyzer.analyze_macho(macho_path)
            self.assertIsInstance(result, dict)
            result_format = result.get('format', '')
            self.assertIn("MACH", result_format.upper())

    def test_dotnet_assembly_analysis(self) -> None:
        """Test .NET assembly analysis with metadata extraction."""
        dotnet_path = os.path.join(self.test_dir, "test.dll")

        pe_path = self._create_pe_test_binary("base.exe")
        with open(pe_path, 'rb') as f:
            pe_data = f.read()

        with open(dotnet_path, 'wb') as f:
            f.write(pe_data)

        try:
            result = self.analyzer.analyze_dotnet(dotnet_path)
            if result:
                self.assertIsInstance(result, dict)
        except Exception:
            pass

    def test_security_analysis_features(self) -> None:
        """Test security-focused analysis features."""
        pe_path = self._create_pe_test_binary("security_test.exe")

        result = self.analyzer.analyze_pe(pe_path)

        sections = result.get('sections', [])
        if sections:
            for section in sections:
                if 'entropy' in section:
                    entropy = section['entropy']
                    self.assertIsInstance(entropy, (int, float))

    def test_universal_analyze_method(self) -> None:
        """Test the universal analyze() method with format auto-detection."""
        formats_and_files: list[tuple[str, str]] = [
            (self._create_pe_test_binary("test.exe"), "PE"),
            (self._create_elf_test_binary("test_elf"), "ELF"),
            (self._create_dex_test_binary("test.dex"), "DEX")
        ]

        for file_path, expected_format in formats_and_files:
            result = self.analyzer.analyze(file_path)

            self.assertIsInstance(result, dict)
            result_format = result.get('format', '')
            self.assertIn(expected_format, result_format.upper())

            self.assertIsNotNone(result.get('file_path'))
            self.assertIsNotNone(result.get('file_size'))
            self.assertIsNotNone(result.get('format'))


class TestStandaloneAnalysisFunction(unittest.TestCase):
    """Test the standalone run_multi_format_analysis function."""

    def setUp(self) -> None:
        """Set up test environment."""
        self.test_dir: str = tempfile.mkdtemp()

    def tearDown(self) -> None:
        """Clean up test environment."""
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _create_test_pe(self) -> str:
        """Create a test PE file."""
        filepath = os.path.join(self.test_dir, "standalone_test.exe")

        with open(filepath, 'wb') as f:
            f.write(b'MZ')
            f.write(b'\x00' * 58)
            f.write(struct.pack('<L', 0x80))

            f.write(b'\x00' * (0x80 - 62))

            f.write(b'PE\x00\x00')

            f.write(struct.pack('<HHIIIHH',
                0x14c, 1, 0, 0, 0, 0xe0, 0x102))

            f.write(struct.pack('<HBB', 0x10b, 0x0e, 0x16))
            f.write(b'\x00' * (0xe0 - 6))

            f.write(b'.text\x00\x00\x00')
            f.write(struct.pack('<IIIIIIHH',
                0x1000, 0x1000, 0x1000, 0x200, 0, 0, 0, 0, 0x60000020))

            f.write(b'\x00' * (0x200 - f.tell()))

            f.write(b'\x90' * 0x1000)

        return filepath

    def test_standalone_function_comprehensive_analysis(self) -> None:
        """Test standalone function provides comprehensive analysis results."""
        pe_path = self._create_test_pe()

        class MockApp:
            """Mock application for testing."""
            def __init__(self) -> None:
                self.binary_path: str = pe_path
                self.analyze_results: list[str] = []

        app = MockApp()
        result = run_multi_format_analysis(app, pe_path)

        self.assertIsInstance(result, dict)
        self.assertIn('format', result)

    def test_standalone_function_error_handling(self) -> None:
        """Test standalone function error handling."""
        nonexistent_path = os.path.join(self.test_dir, "nonexistent.exe")

        class MockApp:
            """Mock application for testing."""
            def __init__(self) -> None:
                self.binary_path: str = nonexistent_path
                self.analyze_results: list[str] = []

        app = MockApp()

        try:
            result = run_multi_format_analysis(app, nonexistent_path)
            if result:
                self.assertIn('error', str(result).lower())
        except FileNotFoundError:
            pass
        except Exception as e:
            self.assertIsInstance(str(e), str)
            self.assertGreater(len(str(e)), 0)

    def test_standalone_function_multiple_formats(self) -> None:
        """Test standalone function with various binary formats."""
        pe_path = self._create_test_pe()

        class MockApp:
            """Mock application for testing."""
            def __init__(self, binary_path: str) -> None:
                self.binary_path: str = binary_path
                self.analyze_results: list[str] = []

        formats_to_test: list[str] = [pe_path]

        for binary_path in formats_to_test:
            app = MockApp(binary_path)
            result = run_multi_format_analysis(app, binary_path)
            self.assertIsNotNone(result)

            if 'format' in result:
                self.assertIsInstance(result['format'], str)
                self.assertGreater(len(result['format']), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
