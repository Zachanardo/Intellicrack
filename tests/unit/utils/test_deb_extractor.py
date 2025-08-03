"""
Unit tests for DEB package extraction functionality.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, call

from intellicrack.utils.extraction.deb_extractor import DEBExtractor


class TestDEBExtractor(unittest.TestCase):
    """Test cases for DEB extraction functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.extractor = DEBExtractor()
        self.test_dir = tempfile.mkdtemp()
        self.test_deb = Path(self.test_dir) / "test_package.deb"
        
    def tearDown(self):
        """Clean up test fixtures."""
        self.extractor.cleanup()
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_validate_deb_valid_file(self):
        """Test validation of a valid DEB file."""
        # Create a mock DEB file with proper ar signature
        with open(self.test_deb, 'wb') as f:
            f.write(b'!<arch>\n')
            f.write(b' ' * 100)  # Some dummy content
        
        is_valid, error = self.extractor.validate_deb(self.test_deb)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_validate_deb_invalid_signature(self):
        """Test validation fails for invalid signature."""
        # Create a file with wrong signature
        with open(self.test_deb, 'wb') as f:
            f.write(b'INVALID\n')
        
        is_valid, error = self.extractor.validate_deb(self.test_deb)
        self.assertFalse(is_valid)
        self.assertIn("Invalid DEB signature", error)

    def test_validate_deb_nonexistent_file(self):
        """Test validation fails for non-existent file."""
        fake_path = Path(self.test_dir) / "nonexistent.deb"
        is_valid, error = self.extractor.validate_deb(fake_path)
        self.assertFalse(is_valid)
        self.assertIn("File not found", error)

    def test_validate_deb_wrong_extension(self):
        """Test validation fails for wrong file extension."""
        wrong_file = Path(self.test_dir) / "test.txt"
        wrong_file.touch()
        
        is_valid, error = self.extractor.validate_deb(wrong_file)
        self.assertFalse(is_valid)
        self.assertIn("Invalid file extension", error)

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_extract_with_dpkg_deb(self, mock_which, mock_run):
        """Test extraction using dpkg-deb."""
        # Setup mocks
        mock_which.return_value = '/usr/bin/dpkg-deb'
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        # Create valid DEB file
        with open(self.test_deb, 'wb') as f:
            f.write(b'!<arch>\n')
            f.write(b' ' * 100)
        
        output_dir = Path(self.test_dir) / "output"
        
        # Mock the file analysis
        with patch.object(self.extractor, '_analyze_extracted_contents') as mock_analyze:
            mock_analyze.return_value = []
            
            result = self.extractor.extract(self.test_deb, output_dir)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['extraction_method'], 'dpkg-deb')
        
        # Verify dpkg-deb was called correctly
        calls = mock_run.call_args_list
        self.assertEqual(len(calls), 2)  # Main extraction + control extraction
        
        # Check main extraction call
        self.assertEqual(calls[0][0][0][:3], ['/usr/bin/dpkg-deb', '-x', str(self.test_deb)])
        
        # Check control extraction call
        self.assertEqual(calls[1][0][0][:3], ['/usr/bin/dpkg-deb', '-e', str(self.test_deb)])

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_extract_with_ar(self, mock_which, mock_run):
        """Test extraction using ar command."""
        # Setup mocks - dpkg-deb not found, but ar is available
        def which_side_effect(cmd):
            if cmd == 'dpkg-deb':
                return None
            elif cmd == 'ar':
                return '/usr/bin/ar'
            return None
        
        mock_which.side_effect = which_side_effect
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        # Create valid DEB file
        with open(self.test_deb, 'wb') as f:
            f.write(b'!<arch>\n')
            f.write(b' ' * 100)
        
        output_dir = Path(self.test_dir) / "output"
        
        # Mock component extraction
        with patch.object(self.extractor, '_extract_deb_components') as mock_components:
            with patch.object(self.extractor, '_analyze_extracted_contents') as mock_analyze:
                mock_analyze.return_value = []
                
                result = self.extractor.extract(self.test_deb, output_dir)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['extraction_method'], 'ar')
        
        # Verify ar was called
        mock_run.assert_called_once()
        ar_call = mock_run.call_args[0][0]
        self.assertEqual(ar_call[:2], ['/usr/bin/ar', 'x'])

    def test_extract_with_python_ar(self):
        """Test extraction using pure Python ar parser."""
        # Create a minimal valid ar archive with control.tar.gz and data.tar.gz
        ar_content = bytearray()
        ar_content.extend(b'!<arch>\n')
        
        # Add a dummy control.tar.gz entry
        control_name = b'control.tar.gz  '
        control_data = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x00'  # Minimal gzip header
        control_size = str(len(control_data)).encode().ljust(10)
        
        header = control_name + b'0     0     100644  ' + control_size + b'`\n'
        ar_content.extend(header)
        ar_content.extend(control_data)
        if len(control_data) % 2:
            ar_content.extend(b'\n')  # Padding
        
        # Write the ar archive
        with open(self.test_deb, 'wb') as f:
            f.write(ar_content)
        
        output_dir = Path(self.test_dir) / "output"
        
        # Mock methods that would fail without real archives
        with patch.object(self.extractor, '_extract_deb_components'):
            with patch.object(self.extractor, '_analyze_extracted_contents') as mock_analyze:
                mock_analyze.return_value = []
                
                # Force all other methods to fail so Python ar is used
                with patch.object(self.extractor, '_extract_with_dpkg_deb') as mock_dpkg:
                    with patch.object(self.extractor, '_extract_with_ar') as mock_ar:
                        with patch.object(self.extractor, '_extract_with_7zip') as mock_7z:
                            mock_dpkg.side_effect = Exception("dpkg-deb not available")
                            mock_ar.side_effect = Exception("ar not available")
                            mock_7z.side_effect = Exception("7zip not available")
                            
                            result = self.extractor.extract(self.test_deb, output_dir)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['extraction_method'], 'python_ar')

    def test_analyze_extracted_contents(self):
        """Test file categorization logic."""
        # Create test directory structure
        extract_dir = Path(self.test_dir) / "extracted"
        
        # Create various file types
        (extract_dir / "usr" / "bin").mkdir(parents=True)
        (extract_dir / "usr" / "lib").mkdir(parents=True)
        (extract_dir / "etc").mkdir(parents=True)
        (extract_dir / "usr" / "share" / "doc").mkdir(parents=True)
        
        # Create test files
        test_files = [
            ("usr/bin/myapp", "executable", 1024),
            ("usr/lib/libmyapp.so", "library", 2048),
            ("etc/myapp.conf", "configuration", 512),
            ("usr/bin/install.sh", "script", 256),
            ("usr/share/doc/README", "documentation", 128),
            ("usr/share/data.txt", "other", 64)
        ]
        
        for rel_path, expected_category, size in test_files:
            file_path = extract_dir / rel_path
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_bytes(b'x' * size)
            
            # Make scripts and binaries executable
            if expected_category in ['executable', 'script']:
                file_path.chmod(0o755)
        
        # Analyze the contents
        results = self.extractor._analyze_extracted_contents(extract_dir)
        
        # Verify categorization
        self.assertEqual(len(results), len(test_files))
        
        # Check each file was categorized correctly
        for result in results:
            # Find the corresponding test file
            for rel_path, expected_category, expected_size in test_files:
                if result['path'].replace('\\', '/') == rel_path:
                    self.assertEqual(result['category'], expected_category)
                    self.assertEqual(result['size'], expected_size)
                    break

    def test_extract_deb_metadata(self):
        """Test metadata extraction from control files."""
        # Create test control directory
        output_dir = Path(self.test_dir) / "output"
        control_dir = output_dir / "DEBIAN"
        control_dir.mkdir(parents=True)
        
        # Create control file
        control_content = """Package: test-package
Version: 1.0.0-1
Architecture: amd64
Maintainer: Test User <test@example.com>
Depends: libc6 (>= 2.17), libssl1.1
Description: Test package for unit tests
 This is a longer description
 that spans multiple lines.
"""
        
        control_file = control_dir / "control"
        control_file.write_text(control_content)
        
        # Create maintainer scripts
        (control_dir / "postinst").write_text("#!/bin/sh\necho 'Post install'")
        (control_dir / "prerm").write_text("#!/bin/sh\necho 'Pre remove'")
        
        # Create md5sums
        (control_dir / "md5sums").write_text("d41d8cd98f00b204e9800998ecf8427e  usr/bin/myapp")
        
        # Create conffiles
        (control_dir / "conffiles").write_text("/etc/myapp.conf\n/etc/myapp/settings.ini")
        
        # Extract metadata
        metadata = self.extractor._extract_deb_metadata(output_dir)
        
        # Verify control data
        self.assertEqual(metadata['control']['Package'], 'test-package')
        self.assertEqual(metadata['control']['Version'], '1.0.0-1')
        self.assertEqual(metadata['control']['Architecture'], 'amd64')
        self.assertIn("This is a longer description", metadata['control']['Description'])
        
        # Verify dependencies
        self.assertIn('depends', metadata['dependencies'])
        self.assertEqual(len(metadata['dependencies']['depends']), 2)
        
        # Verify scripts
        self.assertIn('postinst', metadata['scripts'])
        self.assertIn('prerm', metadata['scripts'])
        
        # Verify other metadata
        self.assertTrue(metadata['md5sums_present'])
        self.assertEqual(len(metadata['conffiles']), 2)

    def test_find_main_executable(self):
        """Test main executable identification."""
        # Create test file list
        files = [
            {'filename': 'test-app', 'path': 'usr/bin/test-app', 'category': 'executable', 'size': 2048},
            {'filename': 'test-app-helper', 'path': 'usr/bin/test-app-helper', 'category': 'executable', 'size': 1024},
            {'filename': 'libtest.so', 'path': 'usr/lib/libtest.so', 'category': 'library', 'size': 4096},
            {'filename': 'install.sh', 'path': 'usr/share/install.sh', 'category': 'script', 'size': 512}
        ]
        
        metadata = {
            'control': {
                'Package': 'test-app'
            }
        }
        
        # Find main executable
        main_exe = self.extractor.find_main_executable(files, metadata)
        
        self.assertIsNotNone(main_exe)
        self.assertEqual(main_exe['filename'], 'test-app')
        
        # Test without package name match
        metadata['control']['Package'] = 'different-name'
        main_exe = self.extractor.find_main_executable(files, metadata)
        
        # Should still find the non-helper executable
        self.assertIsNotNone(main_exe)
        self.assertEqual(main_exe['filename'], 'test-app')

    def test_cleanup(self):
        """Test temporary directory cleanup."""
        # Create some temp directories
        temp_dir1 = tempfile.mkdtemp()
        temp_dir2 = tempfile.mkdtemp()
        
        self.extractor._temp_dirs = [temp_dir1, temp_dir2]
        
        # Verify directories exist
        self.assertTrue(os.path.exists(temp_dir1))
        self.assertTrue(os.path.exists(temp_dir2))
        
        # Run cleanup
        self.extractor.cleanup()
        
        # Verify directories are removed
        self.assertFalse(os.path.exists(temp_dir1))
        self.assertFalse(os.path.exists(temp_dir2))
        self.assertEqual(len(self.extractor._temp_dirs), 0)


if __name__ == '__main__':
    unittest.main()