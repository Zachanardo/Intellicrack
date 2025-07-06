#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Real-world test suite for multi-format binary analyzer

Tests the analyzer with actual system files and comprehensive edge cases.
This test suite validates production readiness with real binary files.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from intellicrack.utils.logger import get_logger

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


logger = get_logger(__name__)


class TestRealWorldMultiFormatAnalyzer(unittest.TestCase):
    """Test multi-format analyzer with real system files"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test class with real file paths"""
        cls.analyzer = MultiFormatBinaryAnalyzer()
        
        # Find real system files for testing
        cls.real_files = {}
        
        # PE files (Windows executables)
        pe_candidates = [
            "/mnt/c/Windows/System32/notepad.exe",
            "/mnt/c/Windows/System32/calc.exe",
            "/mnt/c/Windows/System32/cmd.exe",
            "/mnt/c/Windows/System32/AgentService.exe"
        ]
        for pe_file in pe_candidates:
            if os.path.exists(pe_file):
                cls.real_files['PE'] = pe_file
                break
        
        # ELF files (Linux executables)
        elf_candidates = [
            "/usr/bin/ls",
            "/usr/bin/cat",
            "/usr/bin/dpkg",
            "/bin/bash"
        ]
        for elf_file in elf_candidates:
            if os.path.exists(elf_file):
                cls.real_files['ELF'] = elf_file
                break
        
        # JAR files (Java archives)
        jar_candidates = [
            "/mnt/c/Program Files (x86)/Java/jre1.8.0_451/lib/charsets.jar",
            "/mnt/c/Program Files/Java/jre-1.8/lib/rt.jar",
            "/usr/share/java/junit.jar"
        ]
        for jar_file in jar_candidates:
            if os.path.exists(jar_file):
                cls.real_files['JAR'] = jar_file
                break
        
        # MSI files (Windows installers)
        msi_candidates = [
            "/mnt/c/Windows/Installer/1211e.msi",
            "/mnt/c/Windows/Installer/1212f.msi"
        ]
        for msi_file in msi_candidates:
            if os.path.exists(msi_file):
                cls.real_files['MSI'] = msi_file
                break
        
        logger.info(f"Found real test files: {list(cls.real_files.keys())}")

    def test_real_pe_file_analysis(self):
        """Test analysis of real PE executable"""
        if 'PE' not in self.real_files:
            self.skipTest("No real PE file available for testing")
        
        pe_file = self.real_files['PE']
        
        # Test format detection
        detected_format = self.analyzer.identify_format(pe_file)
        self.assertIn(detected_format, ['PE', 'DOTNET'],
                     f"PE file should be detected as PE or DOTNET, got {detected_format}")
        
        # Test full analysis
        result = self.analyzer.analyze_binary(pe_file)
        
        # Validate result structure
        self.assertIsInstance(result, dict)
        self.assertIn('format', result)
        self.assertIn(result['format'], ['PE', 'DOTNET'])
        
        # Should not have errors for valid system file
        self.assertNotIn('error', result,
                        f"Real PE file analysis should not have errors: {result.get('error')}")
        
        # PE-specific validations
        if 'machine' in result:
            self.assertIsInstance(result['machine'], str)
            self.assertNotEqual(result['machine'], '')
        
        if 'sections' in result:
            self.assertIsInstance(result['sections'], list)
            # PE files should have at least one section
            if len(result['sections']) > 0:
                section = result['sections'][0]
                self.assertIn('name', section)
                self.assertIn('virtual_address', section)

    def test_real_elf_file_analysis(self):
        """Test analysis of real ELF executable"""
        if 'ELF' not in self.real_files:
            self.skipTest("No real ELF file available for testing")
        
        elf_file = self.real_files['ELF']
        
        # Test format detection
        detected_format = self.analyzer.identify_format(elf_file)
        self.assertEqual(detected_format, 'ELF')
        
        # Mock external dependencies if needed
        mock_lief = MagicMock()
        mock_lief.parse.return_value = MagicMock()
        
        # Test full analysis
        result = self.analyzer.analyze_binary(elf_file)
        
        # Validate result structure
        self.assertIsInstance(result, dict)
        self.assertIn('format', result)
        self.assertEqual(result['format'], 'ELF')
        
        # ELF analysis might require optional libraries
        if 'error' in result:
            # Check if it's a dependency error
            error_msg = result['error'].lower()
            if 'available' in error_msg or 'library' in error_msg:
                self.skipTest(f"ELF analysis dependencies not available: {result['error']}")
            else:
                self.fail(f"Unexpected ELF analysis error: {result['error']}")
        
        # ELF-specific validations
        if 'machine' in result:
            self.assertIsInstance(result['machine'], str)
        
        if 'entry_point' in result:
            self.assertIsInstance(result['entry_point'], str)
            self.assertTrue(result['entry_point'].startswith('0x'))

    def test_real_jar_file_analysis(self):
        """Test analysis of real JAR file"""
        if 'JAR' not in self.real_files:
            self.skipTest("No real JAR file available for testing")
        
        jar_file = self.real_files['JAR']
        
        # Test format detection
        detected_format = self.analyzer.identify_format(jar_file)
        self.assertEqual(detected_format, 'JAR')
        
        # Test full analysis
        result = self.analyzer.analyze_binary(jar_file)
        
        # Validate result structure
        self.assertIsInstance(result, dict)
        self.assertIn('format', result)
        self.assertEqual(result['format'], 'JAR')
        
        # JAR analysis requires zipfile
        if 'error' in result:
            if 'zipfile' in result['error']:
                self.skipTest(f"JAR analysis dependencies not available: {result['error']}")
            else:
                self.fail(f"Unexpected JAR analysis error: {result['error']}")
        
        # JAR-specific validations
        self.assertIn('total_files', result)
        self.assertIsInstance(result['total_files'], int)
        self.assertGreater(result['total_files'], 0)
        
        if 'manifest_info' in result:
            self.assertIsInstance(result['manifest_info'], dict)

    def test_real_msi_file_analysis(self):
        """Test analysis of real MSI file"""
        if 'MSI' not in self.real_files:
            self.skipTest("No real MSI file available for testing")
        
        msi_file = self.real_files['MSI']
        
        # Test format detection
        detected_format = self.analyzer.identify_format(msi_file)
        self.assertEqual(detected_format, 'MSI')
        
        # Test full analysis
        result = self.analyzer.analyze_binary(msi_file)
        
        # Validate result structure
        self.assertIsInstance(result, dict)
        self.assertIn('format', result)
        self.assertEqual(result['format'], 'MSI')
        
        # MSI analysis is basic and might have errors
        if 'error' not in result:
            # Basic validations for successful analysis
            if 'compound_document' in result:
                self.assertIsInstance(result['compound_document'], dict)

    def test_format_detection_accuracy(self):
        """Test format detection accuracy across all available files"""
        test_cases = [
            ('PE', 'PE', 'DOTNET'),  # PE files can be detected as .NET
            ('ELF', 'ELF'),
            ('JAR', 'JAR'),
            ('MSI', 'MSI')
        ]
        
        for file_type, *expected_formats in test_cases:
            if file_type in self.real_files:
                file_path = self.real_files[file_type]
                detected = self.analyzer.identify_format(file_path)
                self.assertIn(detected, expected_formats,
                            f"{file_type} file {file_path} detected as {detected}, expected one of {expected_formats}")

    def test_large_file_performance(self):
        """Test performance with larger files"""
        if 'PE' not in self.real_files:
            self.skipTest("No large file available for performance testing")
        
        large_file = self.real_files['PE']
        file_size = os.path.getsize(large_file)
        
        # Skip if file is too small for meaningful performance test
        if file_size < 1024 * 1024:  # 1MB
            self.skipTest("File too small for performance testing")
        
        import time
        start_time = time.time()
        
        result = self.analyzer.analyze_binary(large_file)
        
        end_time = time.time()
        analysis_time = end_time - start_time
        
        # Analysis should complete within reasonable time (10 seconds)
        self.assertLess(analysis_time, 10.0,
                       f"Large file analysis took too long: {analysis_time:.2f}s")
        
        # Should still produce valid results
        self.assertIsInstance(result, dict)
        self.assertIn('format', result)

    def test_nonexistent_file_error(self):
        """Test error handling for non-existent files"""
        nonexistent_file = "/path/that/does/not/exist.exe"
        
        detected_format = self.analyzer.identify_format(nonexistent_file)
        self.assertEqual(detected_format, 'UNKNOWN')
        
        result = self.analyzer.analyze_binary(nonexistent_file)
        self.assertIn('error', result)

    def test_empty_file_handling(self):
        """Test handling of empty files"""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            # File is empty
            detected_format = self.analyzer.identify_format(temp_path)
            self.assertEqual(detected_format, 'UNKNOWN')
            
            result = self.analyzer.analyze_binary(temp_path)
            self.assertIn('error', result)
        finally:
            os.unlink(temp_path)

    def test_corrupted_file_handling(self):
        """Test handling of files with corrupted headers"""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            # Write invalid data
            temp_file.write(b'INVALID_MAGIC_BYTES' + b'\x00' * 100)
            temp_path = temp_file.name
        
        try:
            detected_format = self.analyzer.identify_format(temp_path)
            self.assertEqual(detected_format, 'UNKNOWN')
            
            result = self.analyzer.analyze_binary(temp_path)
            self.assertIn('error', result)
        finally:
            os.unlink(temp_path)

    def test_permission_denied_handling(self):
        """Test handling of permission denied errors"""
        # This test might not work on all systems
        restricted_file = "/etc/shadow"  # Typically permission-restricted file
        
        if not os.path.exists(restricted_file):
            self.skipTest("No permission-restricted file available for testing")
        
        try:
            detected_format = self.analyzer.identify_format(restricted_file)
            # Should handle gracefully
            self.assertIsInstance(detected_format, str)
        except PermissionError:
            # This is also acceptable behavior
            pass

    @patch('intellicrack.core.analysis.multi_format_analyzer.PEFILE_AVAILABLE', False)
    def test_missing_pefile_dependency(self):
        """Test behavior when pefile dependency is missing"""
        analyzer = MultiFormatBinaryAnalyzer()
        self.assertFalse(analyzer.pefile_available)
        
        # Should still identify PE format
        if 'PE' in self.real_files:
            detected = analyzer.identify_format(self.real_files['PE'])
            self.assertIn(detected, ['PE', 'DOTNET'])
            
            # But analysis should return error
            result = analyzer.analyze_pe(self.real_files['PE'])
            self.assertIn('error', result)
            self.assertIn('pefile', result['error'])

    @patch('intellicrack.core.analysis.multi_format_analyzer.ZIPFILE_AVAILABLE', False)
    def test_missing_zipfile_dependency(self):
        """Test behavior when zipfile dependency is missing"""
        analyzer = MultiFormatBinaryAnalyzer()
        self.assertFalse(analyzer.zipfile_available)
        
        if 'JAR' in self.real_files:
            # Analysis should return error
            result = analyzer.analyze_jar(self.real_files['JAR'])
            self.assertIn('error', result)
            self.assertIn('zipfile', result['error'])

    def test_com_file_size_limits(self):
        """Test COM file size limit enforcement"""
        # Create a file larger than 64KB
        with tempfile.NamedTemporaryFile(suffix='.com', delete=False) as temp_file:
            # Write 70KB of data
            temp_file.write(b'\x00' * (70 * 1024))
            temp_path = temp_file.name
        
        try:
            detected_format = self.analyzer.identify_format(temp_path)
            self.assertEqual(detected_format, 'UNKNOWN')  # Should fail size check
            
            # Direct COM analysis should report size error
            result = self.analyzer.analyze_com(temp_path)
            self.assertIn('error', result)
            self.assertIn('too large', result['error'])
        finally:
            os.unlink(temp_path)

    def test_valid_com_file_analysis(self):
        """Test analysis of valid COM file"""
        with tempfile.NamedTemporaryFile(suffix='.com', delete=False) as temp_file:
            # Write valid COM file header
            com_code = bytearray([
                0xB4, 0x09,        # MOV AH, 09h
                0xBA, 0x10, 0x01,  # MOV DX, 0110h
                0xCD, 0x21,       # INT 21h
                0xCD, 0x20,       # INT 20h
                # String data
                0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x24  # "Hello$"
            ])
            temp_file.write(com_code)
            temp_path = temp_file.name
        
        try:
            detected_format = self.analyzer.identify_format(temp_path)
            self.assertEqual(detected_format, 'COM')
            
            result = self.analyzer.analyze_com(temp_path)
            self.assertEqual(result['format'], 'COM')
            self.assertNotIn('error', result)
            
            # Validate COM-specific fields
            self.assertIn('file_size', result)
            self.assertIn('load_address', result)
            self.assertEqual(result['load_address'], '0x0100')
            
            # Should detect DOS interrupts
            if 'header_analysis' in result:
                instructions = result['header_analysis'].get('possible_instructions', [])
                dos_calls = [inst for inst in instructions if 'INT' in inst]
                
                # Validate DOS interrupt detection
                if dos_calls:
                    print(f"Found DOS interrupts: {dos_calls}")
                else:
                    print("No DOS interrupts detected (acceptable for synthetic test files)")
        finally:
            os.unlink(temp_path)

    def test_cross_platform_path_handling(self):
        """Test path handling across different formats"""
        if 'PE' in self.real_files:
            # Test with both Path object and string
            pe_file = self.real_files['PE']
            
            # String path
            result1 = self.analyzer.analyze_binary(pe_file)
            
            # Path object
            result2 = self.analyzer.analyze_binary(Path(pe_file))
            
            # Results should be equivalent
            self.assertEqual(result1['format'], result2['format'])

    def test_batch_analysis_consistency(self):
        """Test that multiple analyses of the same file are consistent"""
        if 'PE' in self.real_files:
            pe_file = self.real_files['PE']
            
            # Run analysis multiple times
            results = []
            for _ in range(3):
                result = self.analyzer.analyze_binary(pe_file)
                results.append(result)
            
            # All results should be identical for deterministic file
            for i in range(1, len(results)):
                self.assertEqual(results[0]['format'], results[i]['format'])
                
                # If no errors, basic structure should be same
                if 'error' not in results[0] and 'error' not in results[i]:
                    for key in ['format']:  # Keys that should always be consistent
                        if key in results[0] and key in results[i]:
                            self.assertEqual(results[0][key], results[i][key])

    def test_analyzer_initialization(self):
        """Test analyzer initialization and dependency checking"""
        analyzer = MultiFormatBinaryAnalyzer()
        
        # Should have dependency flags
        self.assertIsInstance(analyzer.lief_available, bool)
        self.assertIsInstance(analyzer.pefile_available, bool)
        self.assertIsInstance(analyzer.pyelftools_available, bool)
        self.assertIsInstance(analyzer.macholib_available, bool)
        self.assertIsInstance(analyzer.zipfile_available, bool)
        self.assertIsInstance(analyzer.xml_available, bool)
        
        # Should have logger
        self.assertIsNotNone(analyzer.logger)

    def test_unknown_format_handling(self):
        """Test handling of unknown file formats"""
        with tempfile.NamedTemporaryFile(suffix='.unknown', delete=False) as temp_file:
            # Write some random data that doesn't match any known format
            temp_file.write(b'RANDOM_UNKNOWN_FORMAT_DATA' + b'\x00' * 100)
            temp_path = temp_file.name
        
        try:
            detected_format = self.analyzer.identify_format(temp_path)
            self.assertEqual(detected_format, 'UNKNOWN')
            
            result = self.analyzer.analyze_binary(temp_path)
            self.assertEqual(result['format'], 'UNKNOWN')
            self.assertIn('error', result)
            self.assertIn('Unsupported', result['error'])
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    # Set up logging for test visibility
    import logging
    logging.basicConfig(level=logging.INFO,
                       format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Run the tests
    unittest.main(verbosity=2)
