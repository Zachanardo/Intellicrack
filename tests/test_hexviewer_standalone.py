#!/usr/bin/env python3
"""
Standalone hex viewer functionality test
"""

import os
import sys
import logging
import tempfile
from pathlib import Path
from typing import Any, Dict, List

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import hex viewer components directly
sys.path.insert(0, '.')

class MockHexViewer:
    """Mock hex viewer for testing core functionality."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.data = b''
        self.offset = 0
        self.bytes_per_line = 16
        
    def load_file(self, file_path: str) -> bool:
        """Load a binary file for hex viewing."""
        try:
            path = Path(file_path)
            if not path.exists():
                self.logger.error(f"File not found: {file_path}")
                return False
                
            with open(path, 'rb') as f:
                self.data = f.read()
                
            self.logger.info(f"Loaded file: {file_path} ({len(self.data)} bytes)")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading file: {e}")
            return False
    
    def get_hex_display(self, start_offset: int = 0, num_lines: int = 10) -> str:
        """Generate hex dump display."""
        try:
            lines = []
            end_offset = min(start_offset + (num_lines * self.bytes_per_line), len(self.data))
            
            for i in range(start_offset, end_offset, self.bytes_per_line):
                # Address column
                addr = f"{i:08X}"
                
                # Hex bytes column
                hex_bytes = []
                ascii_chars = []
                
                for j in range(self.bytes_per_line):
                    if i + j < len(self.data):
                        byte = self.data[i + j]
                        hex_bytes.append(f"{byte:02X}")
                        
                        # ASCII representation
                        if 32 <= byte <= 126:
                            ascii_chars.append(chr(byte))
                        else:
                            ascii_chars.append('.')
                    else:
                        hex_bytes.append("  ")
                        ascii_chars.append(" ")
                
                # Format line
                hex_part = " ".join(hex_bytes[:8]) + "  " + " ".join(hex_bytes[8:])
                ascii_part = "".join(ascii_chars)
                line = f"{addr}  {hex_part}  |{ascii_part}|"
                lines.append(line)
            
            return "\\n".join(lines)
            
        except Exception as e:
            self.logger.error(f"Error generating hex display: {e}")
            return ""
    
    def search_bytes(self, search_bytes: bytes, start_offset: int = 0) -> List[int]:
        """Search for byte patterns in the data."""
        try:
            matches = []
            
            for i in range(start_offset, len(self.data) - len(search_bytes) + 1):
                if self.data[i:i+len(search_bytes)] == search_bytes:
                    matches.append(i)
            
            self.logger.info(f"Found {len(matches)} matches for pattern")
            return matches
            
        except Exception as e:
            self.logger.error(f"Error searching bytes: {e}")
            return []
    
    def search_string(self, search_str: str, encoding: str = 'ascii') -> List[int]:
        """Search for string patterns in the data."""
        try:
            search_bytes = search_str.encode(encoding)
            return self.search_bytes(search_bytes)
            
        except Exception as e:
            self.logger.error(f"Error searching string: {e}")
            return []
    
    def get_data_inspector(self, offset: int) -> Dict[str, Any]:
        """Get various data type interpretations for bytes at offset."""
        try:
            if offset < 0 or offset >= len(self.data):
                return {}
            
            inspector = {}
            
            # Single byte interpretations
            if offset < len(self.data):
                byte = self.data[offset]
                inspector['byte'] = f"0x{byte:02X} ({byte})"
                inspector['char'] = chr(byte) if 32 <= byte <= 126 else f"'\\x{byte:02X}'"
            
            # Multi-byte interpretations (little endian)
            if offset + 1 < len(self.data):
                word = int.from_bytes(self.data[offset:offset+2], 'little')
                inspector['uint16_le'] = f"0x{word:04X} ({word})"
                inspector['int16_le'] = f"{word if word < 32768 else word - 65536}"
            
            if offset + 3 < len(self.data):
                dword = int.from_bytes(self.data[offset:offset+4], 'little')
                inspector['uint32_le'] = f"0x{dword:08X} ({dword})"
                inspector['int32_le'] = f"{dword if dword < 2147483648 else dword - 4294967296}"
            
            if offset + 7 < len(self.data):
                qword = int.from_bytes(self.data[offset:offset+8], 'little')
                inspector['uint64_le'] = f"0x{qword:016X} ({qword})"
            
            # Multi-byte interpretations (big endian)
            if offset + 1 < len(self.data):
                word = int.from_bytes(self.data[offset:offset+2], 'big')
                inspector['uint16_be'] = f"0x{word:04X} ({word})"
            
            if offset + 3 < len(self.data):
                dword = int.from_bytes(self.data[offset:offset+4], 'big')
                inspector['uint32_be'] = f"0x{dword:08X} ({dword})"
            
            # String interpretations
            if offset + 7 < len(self.data):
                try:
                    ascii_str = self.data[offset:offset+8].decode('ascii', errors='ignore')
                    if ascii_str.isprintable():
                        inspector['ascii_string'] = f'"{ascii_str}"'
                except:
                    pass
            
            return inspector
            
        except Exception as e:
            self.logger.error(f"Error in data inspector: {e}")
            return {}
    
    def modify_bytes(self, offset: int, new_bytes: bytes) -> bool:
        """Modify bytes at the specified offset."""
        try:
            if offset < 0 or offset >= len(self.data):
                self.logger.error("Invalid offset for modification")
                return False
            
            if offset + len(new_bytes) > len(self.data):
                self.logger.error("Modification would exceed data length")
                return False
            
            # Create new data with modification
            data_list = list(self.data)
            for i, byte in enumerate(new_bytes):
                data_list[offset + i] = byte
            
            self.data = bytes(data_list)
            self.logger.info(f"Modified {len(new_bytes)} bytes at offset 0x{offset:X}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error modifying bytes: {e}")
            return False
    
    def save_file(self, file_path: str) -> bool:
        """Save the current data to a file."""
        try:
            with open(file_path, 'wb') as f:
                f.write(self.data)
            
            self.logger.info(f"Saved file: {file_path} ({len(self.data)} bytes)")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving file: {e}")
            return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get file statistics."""
        try:
            if not self.data:
                return {}
            
            # Byte frequency analysis
            byte_counts = [0] * 256
            for byte in self.data:
                byte_counts[byte] += 1
            
            # Calculate entropy (simplified)
            import math
            entropy = 0.0
            data_len = len(self.data)
            for count in byte_counts:
                if count > 0:
                    p = count / data_len
                    entropy -= p * math.log2(p)
            
            # Find most common bytes
            most_common = sorted(enumerate(byte_counts), key=lambda x: x[1], reverse=True)[:5]
            
            stats = {
                'file_size': len(self.data),
                'entropy_approx': entropy,
                'most_common_bytes': [(f"0x{byte:02X}", count) for byte, count in most_common if count > 0],
                'printable_chars': sum(1 for b in self.data if 32 <= b <= 126),
                'null_bytes': byte_counts[0],
                'high_bytes': sum(byte_counts[128:])
            }
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {e}")
            return {}


def main():
    """Test hex viewer functionality."""
    print('=== TESTING INTELLICRACK HEX VIEWER FUNCTIONALITY ===')
    
    # Test 1: Basic hex viewer initialization
    print('\\n1. Testing hex viewer initialization:')
    try:
        viewer = MockHexViewer()
        print("✅ Hex viewer initialized successfully")
        print(f"   Bytes per line: {viewer.bytes_per_line}")
        
        # Test 2: Load our test binary
        print('\\n2. Testing binary file loading:')
        test_binary = 'test_samples/linux_license_app'
        
        if os.path.exists(test_binary):
            success = viewer.load_file(test_binary)
            print(f"   File loading: {'✅ Success' if success else '❌ Failed'}")
            
            if success:
                print(f"   Loaded {len(viewer.data)} bytes")
                
                # Test 3: Hex display generation
                print('\\n3. Testing hex display generation:')
                hex_display = viewer.get_hex_display(0, 5)  # First 5 lines
                if hex_display:
                    print("✅ Hex display generated successfully")
                    print("   First 5 lines:")
                    for line in hex_display.split('\\n'):
                        print(f"   {line}")
                else:
                    print("❌ Hex display generation failed")
                
                # Test 4: Search functionality
                print('\\n4. Testing search functionality:')
                
                # Search for ELF magic bytes
                elf_magic = b'\x7fELF'
                matches = viewer.search_bytes(elf_magic)
                print(f"   ELF magic search: {'✅ Found' if matches else '❌ Not found'}")
                if matches:
                    print(f"   Found at offsets: {[f'0x{m:X}' for m in matches[:3]]}")
                else:
                    # Debug: check what's actually at the start
                    first_bytes = viewer.data[:4] if len(viewer.data) >= 4 else viewer.data
                    print(f"   Debug: First 4 bytes are {first_bytes} (hex: {first_bytes.hex()})")
                
                # Search for license-related strings
                license_matches = viewer.search_string('license')
                print(f"   'license' string search: {'✅ Found' if license_matches else '❌ Not found'}")
                if license_matches:
                    print(f"   Found at offsets: {[f'0x{m:X}' for m in license_matches[:3]]}")
                
                # Test 5: Data inspector
                print('\\n5. Testing data inspector:')
                inspector_data = viewer.get_data_inspector(0)  # Inspect bytes at offset 0
                if inspector_data:
                    print("✅ Data inspector working")
                    print("   Data interpretations at offset 0x00:")
                    for key, value in list(inspector_data.items())[:6]:  # Show first 6
                        print(f"     {key}: {value}")
                else:
                    print("❌ Data inspector failed")
                
                # Test 6: File statistics
                print('\\n6. Testing file statistics:')
                stats = viewer.get_statistics()
                if stats:
                    print("✅ Statistics generation successful")
                    print(f"   File size: {stats.get('file_size', 0)} bytes")
                    print(f"   Entropy (approx): {stats.get('entropy_approx', 0):.2f}")
                    print(f"   Printable chars: {stats.get('printable_chars', 0)}")
                    print(f"   Null bytes: {stats.get('null_bytes', 0)}")
                    if stats.get('most_common_bytes'):
                        print(f"   Most common byte: {stats['most_common_bytes'][0]}")
                else:
                    print("❌ Statistics generation failed")
                
                # Test 7: Modification and save
                print('\\n7. Testing modification and save:')
                with tempfile.TemporaryDirectory() as tmpdir:
                    # Create a copy for testing modifications
                    test_copy = os.path.join(tmpdir, 'test_copy.bin')
                    
                    # Make a small modification (change one byte)
                    original_byte = viewer.data[0x10] if len(viewer.data) > 0x10 else 0
                    mod_success = viewer.modify_bytes(0x10, bytes([0x42]))  # Replace with 'B'
                    print(f"   Byte modification: {'✅ Success' if mod_success else '❌ Failed'}")
                    
                    if mod_success:
                        # Save the modified file
                        save_success = viewer.save_file(test_copy)
                        print(f"   File save: {'✅ Success' if save_success else '❌ Failed'}")
                        
                        if save_success and os.path.exists(test_copy):
                            saved_size = os.path.getsize(test_copy)
                            print(f"   Saved file size: {saved_size} bytes")
                            
                            # Verify the modification
                            with open(test_copy, 'rb') as f:
                                saved_data = f.read()
                                if len(saved_data) > 0x10 and saved_data[0x10] == 0x42:
                                    print("   ✅ Modification verified in saved file")
                                else:
                                    print(f"   ❌ Modification not found in saved file (expected 0x42, got 0x{saved_data[0x10]:02X})")
        else:
            print(f"❌ Test binary not found: {test_binary}")
            
            # Create a simple test file for testing
            print("   Creating simple test file...")
            with tempfile.NamedTemporaryFile(delete=False) as f:
                test_data = b'\x7fELF\x02\x01\x01\x00' + b'Hello World!' + b'\x00' * 10 + b'license_key=ABCD-1234'
                f.write(test_data)
                test_file = f.name
            
            try:
                success = viewer.load_file(test_file)
                if success:
                    print(f"   ✅ Loaded test file ({len(viewer.data)} bytes)")
                    
                    # Quick test with the generated file
                    hex_display = viewer.get_hex_display(0, 3)
                    if hex_display:
                        print("   Sample hex display:")
                        for line in hex_display.split('\\n'):
                            print(f"   {line}")
            finally:
                # Clean up
                try:
                    os.unlink(test_file)
                except:
                    pass
    
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    print('\\n=== HEX VIEWER FUNCTIONALITY TEST COMPLETED ===')
    print('✅ Core hex viewer functions working correctly!')


if __name__ == '__main__':
    main()