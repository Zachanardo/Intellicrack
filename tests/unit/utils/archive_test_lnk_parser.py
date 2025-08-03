"""
Test script for the pure Python .lnk parser implementation.

This script tests the .lnk parser functionality and compares it with
existing shortcut resolution methods.
"""

import os
import sys
import tempfile
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from intellicrack.utils.system.lnk_parser import LnkParser, LnkParseError, parse_lnk_file
from intellicrack.utils.system.file_resolution import FileResolver


def create_test_lnk_file() -> Path:
    """Create a test .lnk file for testing purposes."""
    # This would create a minimal valid .lnk file for testing
    # For now, we'll look for existing .lnk files on the system
    
    # Common locations for .lnk files on Windows
    common_lnk_locations = [
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs"),
        "C:/ProgramData/Microsoft/Windows/Start Menu/Programs",
        "C:/Users/Public/Desktop"
    ]
    
    for location in common_lnk_locations:
        if os.path.exists(location):
            for file_path in Path(location).rglob("*.lnk"):
                if file_path.is_file():
                    print(f"Found test .lnk file: {file_path}")
                    return file_path
    
    return None


def test_lnk_parser():
    """Test the pure Python .lnk parser."""
    print("Testing Pure Python .lnk Parser")
    print("=" * 50)
    
    # Find a test .lnk file
    test_lnk = create_test_lnk_file()
    
    if not test_lnk:
        print("No .lnk files found for testing. Creating a synthetic test...")
        # Create a minimal test by examining existing shortcuts
        return test_synthetic_lnk()
    
    try:
        # Test the standalone parser
        print(f"\nTesting file: {test_lnk}")
        
        parser = LnkParser()
        lnk_info = parser.parse_lnk_file(test_lnk)
        
        print(f"✓ Successfully parsed .lnk file")
        print(f"  Target Path: {lnk_info.target_path}")
        print(f"  Working Directory: {lnk_info.working_directory}")
        print(f"  Arguments: {lnk_info.command_line_arguments}")
        print(f"  Name: {lnk_info.name}")
        print(f"  Icon Location: {lnk_info.icon_location}")
        print(f"  Is Unicode: {lnk_info.is_unicode}")
        print(f"  File Size: {lnk_info.file_size}")
        print(f"  Creation Time: {lnk_info.creation_time}")
        print(f"  Show Command: {parser.get_show_command_description(lnk_info.show_command)}")
        
        if lnk_info.file_attributes:
            attrs = parser.get_file_attributes_description(lnk_info.file_attributes)
            print(f"  File Attributes: {', '.join(attrs)}")
        
        if lnk_info.parse_errors:
            print(f"  Parse Errors: {lnk_info.parse_errors}")
        
        # Test the convenience function
        lnk_dict = parse_lnk_file(test_lnk)
        print(f"✓ Convenience function works")
        
        # Test integration with FileResolver
        print(f"\nTesting integration with FileResolver...")
        resolver = FileResolver()
        resolved_path, metadata = resolver.resolve_file_path(test_lnk)
        
        print(f"✓ FileResolver integration works")
        print(f"  Resolved Path: {resolved_path}")
        print(f"  Is Shortcut: {metadata.get('is_shortcut', False)}")
        print(f"  Resolution Method: {metadata.get('resolution_method', 'unknown')}")
        print(f"  Parser Type: {metadata.get('parser_type', 'unknown')}")
        
        if metadata.get('arguments'):
            print(f"  Arguments: {metadata.get('arguments')}")
        
        if metadata.get('working_directory'):
            print(f"  Working Directory: {metadata.get('working_directory')}")
        
        return True
        
    except LnkParseError as e:
        print(f"✗ LnkParseError: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_synthetic_lnk():
    """Test with a synthetic .lnk file structure."""
    print("\nTesting with synthetic data...")
    
    # Create minimal .lnk file header for testing
    # This is a simplified version - real .lnk files are more complex
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
    
    try:
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(header)
            temp_lnk_path = f.name
        
        parser = LnkParser()
        lnk_info = parser.parse_lnk_file(temp_lnk_path)
        
        print(f"✓ Successfully parsed synthetic .lnk file")
        print(f"  Header Size: {lnk_info.header_size}")
        print(f"  Show Command: {parser.get_show_command_description(lnk_info.show_command)}")
        
        # Clean up
        os.unlink(temp_lnk_path)
        
        return True
        
    except Exception as e:
        print(f"✗ Error with synthetic test: {e}")
        return False


def test_error_handling():
    """Test error handling for invalid files."""
    print("\nTesting error handling...")
    
    try:
        # Test with non-existent file
        parser = LnkParser()
        try:
            parser.parse_lnk_file("nonexistent.lnk")
            print("✗ Should have raised LnkParseError for non-existent file")
            return False
        except LnkParseError:
            print("✓ Correctly handles non-existent file")
        
        # Test with invalid file format
        with tempfile.NamedTemporaryFile(suffix='.lnk', delete=False) as f:
            f.write(b'invalid data')
            temp_path = f.name
        
        try:
            parser.parse_lnk_file(temp_path)
            print("✗ Should have raised LnkParseError for invalid format")
            return False
        except LnkParseError:
            print("✓ Correctly handles invalid file format")
        finally:
            os.unlink(temp_path)
        
        # Test with wrong extension
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'test')
            temp_path = f.name
        
        try:
            parser.parse_lnk_file(temp_path)
            print("✗ Should have raised LnkParseError for wrong extension")
            return False
        except LnkParseError:
            print("✓ Correctly handles wrong file extension")
        finally:
            os.unlink(temp_path)
        
        return True
        
    except Exception as e:
        print(f"✗ Unexpected error in error handling test: {e}")
        return False


def main():
    """Run all tests."""
    print("Pure Python .lnk Parser Test Suite")
    print("=" * 50)
    
    tests_passed = 0
    total_tests = 3
    
    # Test basic parsing
    if test_lnk_parser():
        tests_passed += 1
    
    # Test error handling
    if test_error_handling():
        tests_passed += 1
    
    # Test file type detection
    print(f"\nTesting file type detection...")
    resolver = FileResolver()
    lnk_type = resolver.get_file_type_info("test.lnk")
    if lnk_type.extension == '.lnk' and lnk_type.category == 'shortcut':
        print("✓ .lnk file type correctly detected")
        tests_passed += 1
    else:
        print("✗ .lnk file type detection failed")
    
    # Summary
    print(f"\nTest Results: {tests_passed}/{total_tests} tests passed")
    
    if tests_passed == total_tests:
        print("🎉 All tests passed! Pure Python .lnk parser is working correctly.")
        return True
    else:
        print("❌ Some tests failed. Check the implementation.")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)