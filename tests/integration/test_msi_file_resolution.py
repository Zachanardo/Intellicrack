"""
Integration tests for MSI extraction with file resolution.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from intellicrack.utils.system.file_resolution import file_resolver
from intellicrack.utils.extraction.msi_extractor import MSIExtractor


class TestMSIFileResolution(unittest.TestCase):
    """Test integration of MSI extraction with file resolution."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_msi = Path(self.test_dir) / "test_app.msi"
        
        # Create a mock MSI file with proper signature
        with open(self.test_msi, 'wb') as f:
            f.write(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')  # MSI signature
            f.write(b'\x00' * 1000)  # Padding
            
    def tearDown(self):
        """Clean up test environment."""
        file_resolver.cleanup_all_extracted_msi()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    @patch.object(MSIExtractor, 'extract')
    def test_resolve_msi_to_executable(self, mock_extract):
        """Test resolving MSI file to main executable."""
        # Mock successful extraction
        extracted_dir = Path(self.test_dir) / "extracted"
        extracted_dir.mkdir()
        
        # Create mock extracted files
        main_exe = extracted_dir / "TestApp.exe"
        main_exe.write_bytes(b'MZ' + b'\x00' * 100)
        
        helper_dll = extracted_dir / "helper.dll"
        helper_dll.write_bytes(b'MZ' + b'\x00' * 50)
        
        mock_extract.return_value = {
            'success': True,
            'msi_path': str(self.test_msi),
            'output_dir': str(extracted_dir),
            'extraction_method': 'mock',
            'file_count': 2,
            'extracted_files': [
                {
                    'filename': 'TestApp.exe',
                    'path': 'TestApp.exe',
                    'full_path': str(main_exe),
                    'size': 102,
                    'extension': '.exe',
                    'category': 'executable',
                    'analysis_priority': 'high'
                },
                {
                    'filename': 'helper.dll',
                    'path': 'helper.dll',
                    'full_path': str(helper_dll),
                    'size': 52,
                    'extension': '.dll',
                    'category': 'executable',
                    'analysis_priority': 'high'
                }
            ],
            'metadata': {
                'file_size': 1008,
                'file_name': 'test_app.msi',
                'properties': {
                    'ProductName': 'Test Application',
                    'ProductVersion': '1.0.0',
                    'Manufacturer': 'Test Corp'
                }
            }
        }
        
        # Resolve MSI
        resolved_path, metadata = file_resolver.resolve_file_path(self.test_msi)
        
        # Verify resolution
        self.assertEqual(resolved_path, str(main_exe))
        self.assertTrue(metadata.get('is_installer'))
        self.assertEqual(metadata['resolution_method'], 'msi_extraction')
        self.assertEqual(metadata['original_msi'], str(self.test_msi))
        self.assertEqual(metadata['total_files'], 2)
        
        # Check MSI metadata
        msi_meta = metadata.get('msi_metadata', {})
        self.assertEqual(msi_meta.get('properties', {}).get('ProductName'), 'Test Application')

    @patch.object(MSIExtractor, 'extract')
    def test_resolve_msi_extraction_failure(self, mock_extract):
        """Test handling of MSI extraction failure."""
        # Mock extraction failure
        mock_extract.return_value = {
            'success': False,
            'error': 'All extraction methods failed',
            'msi_path': str(self.test_msi)
        }
        
        # Resolve MSI
        resolved_path, metadata = file_resolver.resolve_file_path(self.test_msi)
        
        # Should return the MSI itself
        self.assertEqual(resolved_path, str(self.test_msi))
        self.assertTrue(metadata.get('msi_extraction_failed'))
        self.assertEqual(metadata.get('extraction_error'), 'All extraction methods failed')

    def test_resolve_non_msi_file(self):
        """Test that non-MSI files are resolved normally."""
        # Create a regular executable
        test_exe = Path(self.test_dir) / "test.exe"
        test_exe.write_bytes(b'MZ' + b'\x00' * 100)
        
        # Resolve executable
        resolved_path, metadata = file_resolver.resolve_file_path(test_exe)
        
        # Should return the exe itself
        self.assertEqual(resolved_path, str(test_exe))
        self.assertFalse(metadata.get('is_installer'))
        self.assertEqual(metadata['resolution_method'], 'direct')

    @patch.object(MSIExtractor, 'extract')
    def test_msi_cache_functionality(self, mock_extract):
        """Test MSI extraction caching."""
        # Mock successful extraction
        extracted_dir = Path(self.test_dir) / "cached_extract"
        extracted_dir.mkdir()
        
        main_exe = extracted_dir / "app.exe"
        main_exe.write_bytes(b'MZ' + b'\x00' * 100)
        
        mock_extract.return_value = {
            'success': True,
            'output_dir': str(extracted_dir),
            'extraction_method': 'mock',
            'file_count': 1,
            'extracted_files': [{
                'filename': 'app.exe',
                'path': 'app.exe',
                'full_path': str(main_exe),
                'size': 102,
                'extension': '.exe',
                'category': 'executable',
                'analysis_priority': 'high'
            }],
            'metadata': {}
        }
        
        # First resolution
        resolved_path1, metadata1 = file_resolver.resolve_file_path(self.test_msi)
        
        # Second resolution (should use cache)
        resolved_path2, metadata2 = file_resolver.resolve_file_path(self.test_msi)
        
        # Verify same result
        self.assertEqual(resolved_path1, resolved_path2)
        
        # Extract should only be called once
        mock_extract.assert_called_once()

    def test_cleanup_extracted_msi(self):
        """Test cleanup of extracted MSI contents."""
        # Create mock extraction directory
        extracted_dir = Path(self.test_dir) / "to_cleanup"
        extracted_dir.mkdir()
        test_file = extracted_dir / "test.exe"
        test_file.write_bytes(b'test')
        
        # Add to cache
        cache_key = str(self.test_msi.absolute())
        file_resolver._extracted_msi_cache[cache_key] = {
            'output_dir': str(extracted_dir)
        }
        
        # Verify directory exists
        self.assertTrue(extracted_dir.exists())
        
        # Cleanup
        file_resolver.cleanup_extracted_msi(self.test_msi)
        
        # Verify cleanup
        self.assertFalse(extracted_dir.exists())
        self.assertNotIn(cache_key, file_resolver._extracted_msi_cache)

    def test_file_type_info_for_msi(self):
        """Test file type information for MSI files."""
        file_info = file_resolver.get_file_type_info(self.test_msi)
        
        self.assertEqual(file_info.extension, '.msi')
        self.assertEqual(file_info.description, 'Windows Installer Package')
        self.assertEqual(file_info.category, 'installer')
        self.assertTrue(file_info.supported)
        self.assertEqual(file_info.analyzer_hint, 'msi')


if __name__ == '__main__':
    unittest.main()