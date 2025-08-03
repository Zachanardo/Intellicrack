"""
Unit tests for MSI extraction functionality.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from intellicrack.utils.extraction.msi_extractor import MSIExtractor


class TestMSIExtractor(unittest.TestCase):
    """Test MSI extraction functionality."""

    def setUp(self):
        """Set up test environment."""
        self.extractor = MSIExtractor()
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment."""
        self.extractor.cleanup()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_validate_msi_valid(self):
        """Test MSI validation with valid file."""
        # Create a mock MSI file with proper signature
        test_msi = Path(self.test_dir) / "test.msi"
        with open(test_msi, 'wb') as f:
            # Write MSI signature (compound document)
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
            f.write(b'\x00' * 100)  # Padding
        
        is_valid, error = self.extractor.validate_msi(test_msi)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_validate_msi_invalid_signature(self):
        """Test MSI validation with invalid signature."""
        test_msi = Path(self.test_dir) / "test.msi"
        with open(test_msi, 'wb') as f:
            f.write(b'INVALID_SIGNATURE')
        
        is_valid, error = self.extractor.validate_msi(test_msi)
        self.assertFalse(is_valid)
        self.assertIn("Invalid MSI signature", error)

    def test_validate_msi_wrong_extension(self):
        """Test MSI validation with wrong extension."""
        test_file = Path(self.test_dir) / "test.exe"
        with open(test_file, 'wb') as f:
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
        
        is_valid, error = self.extractor.validate_msi(test_file)
        self.assertFalse(is_valid)
        self.assertIn("Invalid file extension", error)

    def test_validate_msi_not_found(self):
        """Test MSI validation with non-existent file."""
        test_msi = Path(self.test_dir) / "nonexistent.msi"
        
        is_valid, error = self.extractor.validate_msi(test_msi)
        self.assertFalse(is_valid)
        self.assertIn("File not found", error)

    @patch('subprocess.run')
    def test_extract_with_msiexec(self, mock_run):
        """Test extraction using msiexec."""
        # Only test on Windows
        if os.name != 'nt':
            self.skipTest("msiexec only available on Windows")
        
        # Create test MSI
        test_msi = Path(self.test_dir) / "test.msi"
        with open(test_msi, 'wb') as f:
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 100)
        
        # Mock successful extraction
        mock_run.return_value = Mock(returncode=0, stdout='', stderr='')
        
        result = self.extractor._extract_with_msiexec(test_msi, Path(self.test_dir))
        
        self.assertTrue(result['success'])
        self.assertEqual(result['method'], 'msiexec')
        mock_run.assert_called_once()

    @patch('shutil.which')
    @patch('subprocess.run')
    def test_extract_with_7zip(self, mock_run, mock_which):
        """Test extraction using 7-Zip."""
        # Mock 7z availability
        mock_which.return_value = '7z'
        mock_run.return_value = Mock(returncode=0, stdout='', stderr='')
        
        test_msi = Path(self.test_dir) / "test.msi"
        with open(test_msi, 'wb') as f:
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 100)
        
        result = self.extractor._extract_with_7zip(test_msi, Path(self.test_dir))
        
        self.assertTrue(result['success'])
        self.assertEqual(result['method'], '7zip')

    def test_analyze_extracted_contents(self):
        """Test analysis of extracted contents."""
        # Create test directory structure
        output_dir = Path(self.test_dir) / "extracted"
        output_dir.mkdir()
        
        # Create test files
        (output_dir / "app.exe").write_bytes(b'MZ' + b'\x00' * 100)
        (output_dir / "helper.dll").write_bytes(b'MZ' + b'\x00' * 50)
        (output_dir / "config.xml").write_text('<config>test</config>')
        (output_dir / "install.ps1").write_text('# Install script')
        (output_dir / "readme.txt").write_text('Readme')
        
        files = self.extractor._analyze_extracted_contents(output_dir)
        
        # Check categorization
        self.assertEqual(len(files), 5)
        
        # Check executables are high priority
        exe_files = [f for f in files if f['category'] == 'executable']
        self.assertEqual(len(exe_files), 2)
        self.assertTrue(all(f['analysis_priority'] == 'high' for f in exe_files))
        
        # Check config is medium priority
        config_files = [f for f in files if f['category'] == 'configuration']
        self.assertEqual(len(config_files), 1)
        self.assertEqual(config_files[0]['analysis_priority'], 'medium')
        
        # Check script is high priority
        script_files = [f for f in files if f['category'] == 'script']
        self.assertEqual(len(script_files), 1)
        self.assertEqual(script_files[0]['analysis_priority'], 'high')

    def test_find_main_executable(self):
        """Test finding main executable from extracted files."""
        extracted_files = [
            {
                'filename': 'setup.exe',
                'path': 'setup.exe',
                'size': 1000,
                'category': 'executable'
            },
            {
                'filename': 'app.exe',
                'path': 'app.exe',
                'size': 5000,
                'category': 'executable'
            },
            {
                'filename': 'helper.dll',
                'path': 'helper.dll',
                'size': 2000,
                'category': 'executable'
            }
        ]
        
        main_exe = self.extractor.find_main_executable(extracted_files)
        
        # Should find app.exe (not setup.exe)
        self.assertIsNotNone(main_exe)
        self.assertEqual(main_exe['filename'], 'app.exe')

    def test_cleanup(self):
        """Test cleanup of temporary directories."""
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        self.extractor._temp_dirs.append(temp_dir)
        
        # Create a file in it
        test_file = Path(temp_dir) / "test.txt"
        test_file.write_text("test")
        
        # Verify directory exists
        self.assertTrue(os.path.exists(temp_dir))
        
        # Clean up
        self.extractor.cleanup()
        
        # Verify directory is removed
        self.assertFalse(os.path.exists(temp_dir))
        self.assertEqual(len(self.extractor._temp_dirs), 0)

    @patch.object(MSIExtractor, '_extract_with_msiexec')
    @patch.object(MSIExtractor, '_extract_with_7zip')
    def test_extract_fallback(self, mock_7zip, mock_msiexec):
        """Test fallback between extraction methods."""
        # Create test MSI
        test_msi = Path(self.test_dir) / "test.msi"
        with open(test_msi, 'wb') as f:
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 100)
        
        # First method fails
        mock_msiexec.side_effect = Exception("msiexec failed")
        
        # Second method succeeds
        mock_7zip.return_value = {'success': True, 'method': '7zip'}
        
        # Create mock extracted file
        output_dir = Path(self.test_dir) / "output"
        output_dir.mkdir()
        (output_dir / "test.exe").write_bytes(b'MZ')
        
        result = self.extractor.extract(test_msi, output_dir)
        
        # Should succeed with 7zip
        self.assertTrue(result['success'])
        self.assertEqual(result['extraction_method'], '7zip')


if __name__ == '__main__':
    unittest.main()