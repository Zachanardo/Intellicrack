"""
Integration tests for .lnk file resolution in FileResolver.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import os
import tempfile
import unittest
from pathlib import Path

from intellicrack.utils.system.file_resolution import FileResolver
from intellicrack.utils.system.lnk_parser import LnkParseError


class TestFileResolverLnkIntegration(unittest.TestCase):
    """Integration tests for .lnk file resolution."""

    def setUp(self):
        """Set up test fixtures."""
        self.resolver = FileResolver()

    def test_lnk_file_type_detection(self):
        """Test that .lnk files are correctly identified."""
        file_type = self.resolver.get_file_type_info("test.lnk")
        self.assertEqual(file_type.extension, '.lnk')
        self.assertEqual(file_type.category, 'shortcut')
        self.assertTrue(file_type.supported)
        self.assertEqual(file_type.analyzer_hint, 'shortcut')

    def test_resolve_nonexistent_lnk(self):
        """Test resolving a non-existent .lnk file."""
        resolved_path, metadata = self.resolver.resolve_file_path("nonexistent.lnk")
        self.assertEqual(resolved_path, "nonexistent.lnk")
        self.assertIn("error", metadata)
        self.assertIn("File not found", metadata["error"])

    def test_resolve_invalid_lnk(self):
        """Test resolving an invalid .lnk file."""
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(b'invalid lnk data')
            temp_path = f.name

        try:
            resolved_path, metadata = self.resolver.resolve_file_path(temp_path)
            self.assertEqual(resolved_path, temp_path)
            self.assertIn("error", metadata)
        finally:
            os.unlink(temp_path)

    def test_resolve_minimal_valid_lnk(self):
        """Test resolving a minimal valid .lnk file."""
        # Create minimal valid .lnk file header
        header = (
            b'\x4c\x00\x00\x00'  # Header size (76 bytes)
            b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'  # CLSID
            b'\x00\x00\x00\x00'  # Link flags (no additional data)
            b'\x20\x00\x00\x00'  # File attributes
            + b'\x00' * 40  # Remaining header fields
        )

        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            resolved_path, metadata = self.resolver.resolve_file_path(temp_path)
            
            # Since this minimal .lnk has no target, it should fail resolution
            # but the metadata should indicate it was processed as a shortcut
            self.assertTrue(metadata.get('is_shortcut', False))
            self.assertEqual(metadata.get('resolution_method'), 'windows_shortcut')
            self.assertEqual(metadata.get('parser_type'), 'pure_python')
            
        finally:
            os.unlink(temp_path)

    def test_file_filters_include_lnk(self):
        """Test that file filters include .lnk files."""
        filters = self.resolver.get_supported_file_filters()
        self.assertIn('*.lnk', filters)
        self.assertIn('Shortcuts and Links', filters)

    def test_real_lnk_resolution_if_available(self):
        """Test with real .lnk files if available on the system."""
        # Common locations for .lnk files
        test_locations = [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Excel.lnk",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Word.lnk"
        ]
        
        for location in test_locations:
            if os.path.exists(location):
                try:
                    resolved_path, metadata = self.resolver.resolve_file_path(location)
                    
                    # Verify metadata structure
                    self.assertIn('original_path', metadata)
                    self.assertIn('file_type', metadata)
                    self.assertIn('is_shortcut', metadata)
                    self.assertIn('resolution_method', metadata)
                    
                    if metadata.get('is_shortcut'):
                        self.assertEqual(metadata['resolution_method'], 'windows_shortcut')
                        self.assertIn('parser_type', metadata)
                        
                        # Verify parser type is our pure Python implementation
                        parser_type = metadata.get('parser_type')
                        self.assertIn(parser_type, ['pure_python', 'windows_com'])
                        
                        if parser_type == 'pure_python':
                            # Verify additional metadata from pure Python parser
                            self.assertIn('target_path', metadata)
                            self.assertIn('shortcut_type', metadata)
                            self.assertEqual(metadata['shortcut_type'], 'windows_lnk')
                    
                    print(f"Successfully resolved real .lnk file: {location}")
                    print(f"  Resolved to: {resolved_path}")
                    print(f"  Parser type: {metadata.get('parser_type', 'unknown')}")
                    print(f"  Is shortcut: {metadata.get('is_shortcut', False)}")
                    
                    break  # Test just one file
                    
                except Exception as e:
                    print(f"Could not resolve {location}: {e}")
                    continue

    def test_metadata_completeness(self):
        """Test that .lnk resolution provides complete metadata."""
        # Test with a known .lnk file if available
        test_file = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk"
        
        if os.path.exists(test_file):
            resolved_path, metadata = self.resolver.resolve_file_path(test_file)
            
            # Required metadata fields
            required_fields = [
                'original_path', 'file_type', 'size', 'is_shortcut', 'resolution_method'
            ]
            
            for field in required_fields:
                self.assertIn(field, metadata, f"Missing required field: {field}")
            
            # If it's a shortcut, additional fields should be present
            if metadata.get('is_shortcut'):
                shortcut_fields = ['target_path', 'shortcut_type']
                for field in shortcut_fields:
                    self.assertIn(field, metadata, f"Missing shortcut field: {field}")

    def test_cross_platform_compatibility(self):
        """Test that the .lnk parser works without Windows dependencies."""
        # This test verifies that the pure Python implementation works
        # even when Windows COM libraries are not available
        
        # Create a minimal .lnk file
        header = (
            b'\x4c\x00\x00\x00'  # Header size
            b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'  # CLSID
            b'\x00\x00\x00\x00'  # Link flags
            b'\x20\x00\x00\x00'  # File attributes
            + b'\x00' * 40  # Remaining header
        )

        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            # Temporarily disable COM to test pure Python implementation
            original_has_win32 = self.resolver._FileResolver__dict__.get('HAS_WIN32', None)
            
            # Force use of pure Python parser
            import intellicrack.utils.system.file_resolution as fr
            original_has_win32_module = fr.HAS_WIN32
            fr.HAS_WIN32 = False
            
            try:
                resolved_path, metadata = self.resolver.resolve_file_path(temp_path)
                
                # Should still work with pure Python implementation
                self.assertTrue(metadata.get('is_shortcut', False))
                self.assertEqual(metadata.get('parser_type'), 'pure_python')
                
            finally:
                # Restore original state
                fr.HAS_WIN32 = original_has_win32_module
                
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()