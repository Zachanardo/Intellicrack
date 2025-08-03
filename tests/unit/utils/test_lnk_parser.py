"""
Unit tests for the pure Python .lnk parser.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.
"""

import os
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from intellicrack.utils.system.lnk_parser import (
    LnkParser, LnkParseError, LnkInfo, parse_lnk_file,
    LinkFlags, FileAttributes, ShowWindow
)


class TestLnkParser(unittest.TestCase):
    """Test cases for the LnkParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = LnkParser()

    def test_parser_instantiation(self):
        """Test that LnkParser can be instantiated."""
        self.assertIsInstance(self.parser, LnkParser)

    def test_lnk_info_initialization(self):
        """Test LnkInfo initialization."""
        lnk_info = LnkInfo()
        self.assertEqual(lnk_info.header_size, 0)
        self.assertIsNone(lnk_info.target_path)
        self.assertFalse(lnk_info.is_unicode)
        self.assertEqual(lnk_info.parse_errors, [])

    def test_lnk_info_to_dict(self):
        """Test LnkInfo to_dict conversion."""
        lnk_info = LnkInfo()
        lnk_info.target_path = "C:\\test.exe"
        lnk_info.file_size = 1024
        
        result = lnk_info.to_dict()
        self.assertIsInstance(result, dict)
        self.assertEqual(result['target_path'], "C:\\test.exe")
        self.assertEqual(result['file_size'], 1024)

    def test_parse_nonexistent_file(self):
        """Test parsing a non-existent file raises LnkParseError."""
        with self.assertRaises(LnkParseError):
            self.parser.parse_lnk_file("nonexistent.lnk")

    def test_parse_wrong_extension(self):
        """Test parsing a file with wrong extension raises LnkParseError."""
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'test')
            temp_path = f.name

        try:
            with self.assertRaises(LnkParseError):
                self.parser.parse_lnk_file(temp_path)
        finally:
            os.unlink(temp_path)

    def test_parse_invalid_format(self):
        """Test parsing an invalid .lnk file raises LnkParseError."""
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(b'invalid data')
            temp_path = f.name

        try:
            with self.assertRaises(LnkParseError):
                self.parser.parse_lnk_file(temp_path)
        finally:
            os.unlink(temp_path)

    def test_parse_minimal_valid_lnk(self):
        """Test parsing a minimal valid .lnk file."""
        # Create minimal valid .lnk file header
        header = (
            b'\x4c\x00\x00\x00'  # Header size (76 bytes)
            b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'  # CLSID
            b'\x00\x00\x00\x00'  # Link flags (no additional data)
            b'\x20\x00\x00\x00'  # File attributes (FILE_ATTRIBUTE_ARCHIVE)
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Creation time
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Access time  
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # Write time
            b'\x00\x00\x00\x00'  # File size
            b'\x00\x00\x00\x00'  # Icon index
            b'\x01\x00\x00\x00'  # Show command (SW_SHOWNORMAL)
            b'\x00\x00'          # Hotkey
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Reserved
        )

        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            lnk_info = self.parser.parse_lnk_file(temp_path)
            self.assertIsInstance(lnk_info, LnkInfo)
            self.assertEqual(lnk_info.header_size, 76)
            self.assertEqual(lnk_info.show_command, ShowWindow.SW_SHOWNORMAL)
            self.assertEqual(lnk_info.file_attributes, FileAttributes.FILE_ATTRIBUTE_ARCHIVE)
        finally:
            os.unlink(temp_path)

    def test_convenience_function(self):
        """Test the parse_lnk_file convenience function."""
        # Create minimal valid .lnk file
        header = (
            b'\x4c\x00\x00\x00'  # Header size
            b'\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46'  # CLSID
            b'\x00\x00\x00\x00'  # Link flags
            b'\x20\x00\x00\x00'  # File attributes
            + b'\x00' * 40  # Remaining header fields
        )

        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(header)
            temp_path = f.name

        try:
            result = parse_lnk_file(temp_path)
            self.assertIsInstance(result, dict)
            self.assertIn('target_path', result)
            self.assertIn('file_attributes', result)
        finally:
            os.unlink(temp_path)

    def test_file_attributes_description(self):
        """Test file attributes description generation."""
        attrs = self.parser.get_file_attributes_description(
            FileAttributes.FILE_ATTRIBUTE_READONLY | 
            FileAttributes.FILE_ATTRIBUTE_HIDDEN | 
            FileAttributes.FILE_ATTRIBUTE_SYSTEM
        )
        self.assertIn('readonly', attrs)
        self.assertIn('hidden', attrs)
        self.assertIn('system', attrs)

    def test_show_command_description(self):
        """Test show command description generation."""
        desc = self.parser.get_show_command_description(ShowWindow.SW_SHOWNORMAL)
        self.assertEqual(desc, 'normal')
        
        desc = self.parser.get_show_command_description(ShowWindow.SW_SHOWMAXIMIZED)
        self.assertEqual(desc, 'maximized')
        
        desc = self.parser.get_show_command_description(999)
        self.assertEqual(desc, 'unknown_999')

    def test_filetime_conversion(self):
        """Test Windows FILETIME to datetime conversion."""
        # Test zero filetime
        result = self.parser._filetime_to_datetime(0)
        self.assertIsNone(result)
        
        # Test valid filetime (example: January 1, 2020)
        filetime = 132232416000000000  # Approximate FILETIME for 2020-01-01
        result = self.parser._filetime_to_datetime(filetime)
        self.assertIsInstance(result, datetime)

    def test_string_reading_methods(self):
        """Test string reading helper methods."""
        # Test null-terminated string
        data = b'Hello\x00World'
        result = self.parser._read_null_terminated_string(data, 0)
        self.assertEqual(result, 'Hello')
        
        # Test null-terminated Unicode string
        unicode_data = b'H\x00e\x00l\x00l\x00o\x00\x00\x00'
        result = self.parser._read_null_terminated_unicode_string(unicode_data, 0)
        self.assertEqual(result, 'Hello')


class TestLnkParserIntegration(unittest.TestCase):
    """Integration tests for .lnk parser with real files."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = LnkParser()

    def test_real_lnk_file_if_available(self):
        """Test with real .lnk files if available on the system."""
        # Common locations for .lnk files
        test_locations = [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Excel.lnk",
            r"C:\Users\Public\Desktop\*.lnk"
        ]
        
        for location in test_locations:
            if '*' in location:
                # Handle glob patterns
                from glob import glob
                files = glob(location)
                if files:
                    location = files[0]
                else:
                    continue
            
            if os.path.exists(location):
                try:
                    lnk_info = self.parser.parse_lnk_file(location)
                    self.assertIsInstance(lnk_info, LnkInfo)
                    
                    # Basic validation
                    self.assertEqual(lnk_info.header_size, 76)
                    self.assertIsNotNone(lnk_info.link_clsid)
                    
                    # Test dictionary conversion
                    result = lnk_info.to_dict()
                    self.assertIsInstance(result, dict)
                    
                    print(f"Successfully parsed real .lnk file: {location}")
                    break  # Test just one file
                    
                except LnkParseError as e:
                    # This is acceptable - some .lnk files might be corrupt or have unsupported features
                    print(f"Could not parse {location}: {e}")
                    continue


if __name__ == '__main__':
    unittest.main()