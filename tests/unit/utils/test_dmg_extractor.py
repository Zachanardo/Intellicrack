"""
Unit tests for DMG (Apple Disk Image) extraction functionality.

Tests the DMGExtractor class for extracting macOS disk images.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from intellicrack.utils.extraction import DMGExtractor


class TestDMGExtractor(unittest.TestCase):
    """Test cases for DMG extraction functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.extractor = DMGExtractor()
        self.test_dir = tempfile.mkdtemp()
        self.test_dmg = Path(self.test_dir) / "test.dmg"
        
        # Create a mock DMG file with UDIF trailer
        with open(self.test_dmg, 'wb') as f:
            # Write some dummy data
            f.write(b'\x00' * 1024)
            # Write UDIF trailer with 'koly' signature
            f.seek(-512, 2)
            f.write(b'\x00' * 200)
            f.write(b'koly')
            f.write(b'\x00' * 308)

    def tearDown(self):
        """Clean up test fixtures."""
        self.extractor.cleanup()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_validate_dmg_valid_file(self):
        """Test validation of a valid DMG file."""
        is_valid, error = self.extractor.validate_dmg(self.test_dmg)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_validate_dmg_missing_file(self):
        """Test validation of a missing DMG file."""
        missing_dmg = Path(self.test_dir) / "missing.dmg"
        is_valid, error = self.extractor.validate_dmg(missing_dmg)
        self.assertFalse(is_valid)
        self.assertIn("File not found", error)

    def test_validate_dmg_wrong_extension(self):
        """Test validation with wrong file extension."""
        wrong_file = Path(self.test_dir) / "test.txt"
        wrong_file.touch()
        is_valid, error = self.extractor.validate_dmg(wrong_file)
        self.assertFalse(is_valid)
        self.assertIn("Invalid file extension", error)

    def test_validate_dmg_encrypted(self):
        """Test validation of encrypted DMG."""
        encrypted_dmg = Path(self.test_dir) / "encrypted.dmg"
        with open(encrypted_dmg, 'wb') as f:
            f.write(b'encrcdsa' + b'\x00' * 504)
        
        is_valid, error = self.extractor.validate_dmg(encrypted_dmg)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_extract_with_hdiutil_success(self, mock_which, mock_run):
        """Test successful extraction using hdiutil."""
        mock_which.return_value = '/usr/bin/hdiutil'
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        with patch('tempfile.mkdtemp') as mock_mkdtemp:
            mount_point = Path(self.test_dir) / 'mount'
            mount_point.mkdir()
            mock_mkdtemp.return_value = str(mount_point)
            
            # Create mock app bundle
            app_dir = mount_point / 'TestApp.app'
            app_dir.mkdir()
            (app_dir / 'Contents').mkdir()
            (app_dir / 'Contents' / 'MacOS').mkdir()
            (app_dir / 'Contents' / 'MacOS' / 'TestApp').touch()
            
            with patch('shutil.copytree'), patch('shutil.copy2'):
                result = self.extractor.extract(self.test_dmg)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['extraction_method'], 'hdiutil')

    @patch('subprocess.run')
    @patch('shutil.which')
    @patch('os.path.exists')
    def test_extract_with_7zip_success(self, mock_exists, mock_which, mock_run):
        """Test successful extraction using 7-Zip."""
        mock_which.side_effect = lambda x: None if x == 'hdiutil' else None
        mock_exists.side_effect = lambda x: True if '7z.exe' in x else False
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        
        output_dir = Path(self.test_dir) / 'output'
        output_dir.mkdir()
        
        # Create mock extracted content
        (output_dir / 'TestApp.app').mkdir()
        
        result = self.extractor.extract(self.test_dmg, output_dir)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['extraction_method'], '7zip')

    def test_extract_all_methods_fail(self):
        """Test when all extraction methods fail."""
        with patch.object(self.extractor, '_extraction_methods', []):
            result = self.extractor.extract(self.test_dmg)
        
        self.assertFalse(result['success'])
        self.assertEqual(result['error'], 'All extraction methods failed')

    def test_analyze_app_bundle(self):
        """Test analyzing macOS app bundle structure."""
        app_path = Path(self.test_dir) / 'TestApp.app'
        contents = app_path / 'Contents'
        macos = contents / 'MacOS'
        macos.mkdir(parents=True)
        
        # Create Info.plist
        info_plist = contents / 'Info.plist'
        plist_content = b"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.TestApp</string>
    <key>CFBundleExecutable</key>
    <string>TestApp</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
</dict>
</plist>"""
        with open(info_plist, 'wb') as f:
            f.write(plist_content)
        
        # Create executable
        (macos / 'TestApp').touch()
        
        # Create frameworks
        frameworks = contents / 'Frameworks'
        frameworks.mkdir()
        (frameworks / 'TestFramework.framework').mkdir()
        
        app_info = self.extractor._analyze_app_bundle(app_path)
        
        self.assertIsNotNone(app_info)
        self.assertEqual(app_info['bundle_id'], 'com.example.TestApp')
        self.assertEqual(app_info['version'], '1.0.0')
        self.assertEqual(len(app_info['frameworks']), 1)

    def test_analyze_extracted_contents(self):
        """Test analyzing and categorizing extracted files."""
        output_dir = Path(self.test_dir) / 'output'
        output_dir.mkdir()
        
        # Create various file types
        (output_dir / 'TestApp.app').mkdir()
        (output_dir / 'binary').write_bytes(b'\xfe\xed\xfa\xcf' + b'\x00' * 100)  # Mach-O 64-bit
        (output_dir / 'library.dylib').touch()
        (output_dir / 'config.plist').touch()
        (output_dir / 'interface.nib').touch()
        (output_dir / 'resource.png').touch()
        
        files = self.extractor._analyze_extracted_contents(output_dir)
        
        # Check categorization
        categories = {f['category'] for f in files}
        self.assertIn('application_bundle', categories)
        self.assertIn('macho_executable', categories)
        self.assertIn('executable', categories)
        self.assertIn('configuration', categories)
        self.assertIn('interface', categories)
        self.assertIn('resource', categories)
        
        # Check priority ordering
        priorities = [f['analysis_priority'] for f in files]
        self.assertEqual(priorities[0], 'critical')  # App bundle should be first

    def test_find_main_executable(self):
        """Test finding the main executable."""
        files = [
            {
                'filename': 'TestApp',
                'path': 'TestApp.app/Contents/MacOS/TestApp',
                'full_path': '/test/TestApp.app/Contents/MacOS/TestApp',
                'size': 1000000,
                'category': 'macho_executable'
            },
            {
                'filename': 'helper',
                'path': 'TestApp.app/Contents/MacOS/helper',
                'full_path': '/test/TestApp.app/Contents/MacOS/helper',
                'size': 50000,
                'category': 'macho_executable'
            }
        ]
        
        app_bundles = [
            {
                'name': 'TestApp.app',
                'executable': '/test/TestApp.app/Contents/MacOS/TestApp'
            }
        ]
        
        main_exe = self.extractor.find_main_executable(files, app_bundles)
        
        self.assertIsNotNone(main_exe)
        self.assertEqual(main_exe['filename'], 'TestApp')

    def test_extract_dmg_metadata(self):
        """Test extracting metadata from DMG file."""
        # Test UDIF format
        metadata = self.extractor._extract_dmg_metadata(self.test_dmg)
        self.assertEqual(metadata['format'], 'UDIF')
        self.assertEqual(metadata['file_name'], 'test.dmg')
        self.assertGreater(metadata['file_size'], 0)
        
        # Test encrypted DMG
        encrypted_dmg = Path(self.test_dir) / 'encrypted.dmg'
        with open(encrypted_dmg, 'wb') as f:
            f.write(b'encrcdsa' + b'\x00' * 504)
        
        metadata = self.extractor._extract_dmg_metadata(encrypted_dmg)
        self.assertTrue(metadata['encrypted'])
        self.assertEqual(metadata['format'], 'encrypted')

    def test_consolidate_7zip_output(self):
        """Test consolidating 7-Zip numbered folder output."""
        output_dir = Path(self.test_dir) / 'output'
        output_dir.mkdir()
        
        # Create numbered directories like 7-Zip does
        (output_dir / '1').mkdir()
        (output_dir / '1' / 'TestApp.app').mkdir()
        (output_dir / '2').mkdir()
        (output_dir / '2' / 'README.txt').touch()
        
        self.extractor._consolidate_7zip_output(output_dir)
        
        # Check files were moved to root
        self.assertTrue((output_dir / 'TestApp.app').exists())
        self.assertTrue((output_dir / 'README.txt').exists())
        
        # Check numbered dirs were removed
        self.assertFalse((output_dir / '1').exists())
        self.assertFalse((output_dir / '2').exists())

    def test_python_parser_extraction(self):
        """Test pure Python DMG parser."""
        # Create a more realistic UDIF DMG
        with open(self.test_dmg, 'wb') as f:
            # Write data fork
            data_fork_offset = 512
            data_fork_content = b'Test data content'
            f.seek(data_fork_offset)
            f.write(data_fork_content)
            
            # Write UDIF trailer (koly block)
            f.seek(-512, 2)
            koly = bytearray(512)
            koly[0:4] = b'koly'
            
            # Set data fork offset and length (big-endian)
            import struct
            struct.pack_into('>Q', koly, 0x28, data_fork_offset)
            struct.pack_into('>Q', koly, 0x30, len(data_fork_content))
            
            f.write(koly)
        
        output_dir = Path(self.test_dir) / 'python_output'
        output_dir.mkdir()
        
        result = self.extractor._extract_with_python_parser(self.test_dmg, output_dir)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['method'], 'python_parser')
        self.assertTrue((output_dir / 'data_fork.bin').exists())

    def test_cleanup(self):
        """Test cleanup of temporary directories and mounted volumes."""
        # Add temp directory
        temp_dir = tempfile.mkdtemp()
        self.extractor._temp_dirs.append(temp_dir)
        
        # Add fake mounted volume
        self.extractor._mounted_volumes.append('/Volumes/TestDMG')
        
        with patch('subprocess.run'):  # Mock unmount commands
            self.extractor.cleanup()
        
        self.assertEqual(len(self.extractor._temp_dirs), 0)
        self.assertEqual(len(self.extractor._mounted_volumes), 0)
        self.assertFalse(os.path.exists(temp_dir))


if __name__ == '__main__':
    unittest.main()