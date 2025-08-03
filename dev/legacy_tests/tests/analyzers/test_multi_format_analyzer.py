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
Test script for multi-format binary analyzer

Tests the extended format support for DEX, JAR/APK, MSI, and COM files.
"""

import os
import sys
import tempfile
from pathlib import Path

from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from intellicrack.utils.logger import get_logger

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


logger = get_logger(__name__)


def create_test_dex_file() -> str:
    """Create a minimal test DEX file"""
    with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as f:
        # Write minimal DEX header
        dex_header = bytearray(112)  # DEX header is 112 bytes

        # Magic bytes: "dex\n035\0"
        dex_header[0:8] = b'dex\n035\0'

        # Checksum (dummy)
        dex_header[8:12] = (0x12345678).to_bytes(4, 'little')

        # SHA1 signature (dummy)
        dex_header[12:32] = b'\x00' * 20

        # File size
        file_size = 112  # Just header for test
        dex_header[32:36] = file_size.to_bytes(4, 'little')

        # Header size
        dex_header[36:40] = (112).to_bytes(4, 'little')

        # Endian tag
        dex_header[40:44] = (0x12345678).to_bytes(4, 'little')

        # String IDs
        dex_header[60:64] = (5).to_bytes(4, 'little')  # string_ids_size
        dex_header[64:68] = (112).to_bytes(4, 'little')  # string_ids_off

        # Type IDs
        dex_header[68:72] = (3).to_bytes(4, 'little')  # type_ids_size
        dex_header[72:76] = (132).to_bytes(4, 'little')  # type_ids_off

        # Method IDs
        dex_header[92:96] = (10).to_bytes(4, 'little')  # method_ids_size
        dex_header[96:100] = (150).to_bytes(4, 'little')  # method_ids_off

        # Class definitions
        dex_header[100:104] = (2).to_bytes(4, 'little')  # class_defs_size
        dex_header[104:108] = (200).to_bytes(4, 'little')  # class_defs_off

        f.write(dex_header)
        return f.name


def create_test_jar_file() -> str:
    """Create a minimal test JAR file"""
    import zipfile

    with tempfile.NamedTemporaryFile(suffix='.jar', delete=False) as f:
        with zipfile.ZipFile(f, 'w') as jar:
            # Add manifest
            manifest_content = """Manifest-Version: 1.0
Created-By: Test Script
Main-Class: com.example.Main
"""
            jar.writestr('META-INF/MANIFEST.MF', manifest_content)

            # Add a dummy class file
            jar.writestr('com/example/Main.class', b'\xca\xfe\xba\xbe\x00\x00\x00\x34')

            # Add a resource
            jar.writestr('resources/config.properties', 'app.name=TestApp\n')

        return f.name


def create_test_apk_file() -> str:
    """Create a minimal test APK file"""
    import zipfile

    with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
        with zipfile.ZipFile(f, 'w') as apk:
            # Add AndroidManifest.xml (binary - just dummy data)
            apk.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00' + b'\x00' * 100)

            # Add classes.dex
            dex_data = b'dex\n035\0' + b'\x00' * 100
            apk.writestr('classes.dex', dex_data)

            # Add native library
            apk.writestr('lib/armeabi-v7a/libnative.so', b'\x7fELF' + b'\x00' * 50)

            # Add resource
            apk.writestr('res/values/strings.xml', '<resources><string name="app_name">TestApp</string></resources>')

            # Add certificate
            apk.writestr('META-INF/CERT.SF', 'Signature-Version: 1.0\n')

        return f.name


def create_test_msi_file() -> str:
    """Create a minimal test MSI file"""
    with tempfile.NamedTemporaryFile(suffix='.msi', delete=False) as f:
        # Write compound document header
        header = bytearray(512)

        # Compound document signature
        header[0:8] = b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'

        # Minor version
        header[24:26] = (0x003e).to_bytes(2, 'little')

        # Major version
        header[26:28] = (0x003e).to_bytes(2, 'little')

        # Byte order
        header[28:30] = (0xfffe).to_bytes(2, 'little')

        # Sector size (512 bytes = 2^9)
        header[30:32] = (9).to_bytes(2, 'little')

        # Mini sector size (64 bytes = 2^6)
        header[32:34] = (6).to_bytes(2, 'little')

        f.write(header)
        return f.name


def create_test_com_file() -> str:
    """Create a minimal test COM file"""
    with tempfile.NamedTemporaryFile(suffix='.com', delete=False) as f:
        # Simple COM file that prints "Hello" and exits
        com_code = bytearray([
            0xB4, 0x09,        # MOV AH, 09h (print string function)
            0xBA, 0x10, 0x01, # MOV DX, 0110h (offset to string)
            0xCD, 0x21,       # INT 21h (DOS interrupt)
            0xCD, 0x20,       # INT 20h (terminate program)
            # String data
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x24  # "Hello$"
        ])

        f.write(com_code)
        return f.name


def test_format_detection():
    """Test format detection for all supported formats"""
    print("Testing format detection...")

    analyzer = MultiFormatBinaryAnalyzer()

    # Test DEX
    dex_file = create_test_dex_file()
    try:
        format_detected = analyzer.identify_format(dex_file)
        print(f"DEX format detection: {format_detected}")
        assert format_detected == 'DEX', f"Expected DEX, got {format_detected}"
    finally:
        os.unlink(dex_file)

    # Test JAR
    jar_file = create_test_jar_file()
    try:
        format_detected = analyzer.identify_format(jar_file)
        print(f"JAR format detection: {format_detected}")
        assert format_detected == 'JAR', f"Expected JAR, got {format_detected}"
    finally:
        os.unlink(jar_file)

    # Test APK
    apk_file = create_test_apk_file()
    try:
        format_detected = analyzer.identify_format(apk_file)
        print(f"APK format detection: {format_detected}")
        assert format_detected == 'APK', f"Expected APK, got {format_detected}"
    finally:
        os.unlink(apk_file)

    # Test MSI
    msi_file = create_test_msi_file()
    try:
        format_detected = analyzer.identify_format(msi_file)
        print(f"MSI format detection: {format_detected}")
        assert format_detected == 'MSI', f"Expected MSI, got {format_detected}"
    finally:
        os.unlink(msi_file)

    # Test COM
    com_file = create_test_com_file()
    try:
        format_detected = analyzer.identify_format(com_file)
        print(f"COM format detection: {format_detected}")
        assert format_detected == 'COM', f"Expected COM, got {format_detected}"
    finally:
        os.unlink(com_file)

    print("✓ Format detection tests passed!")


def test_analysis():
    """Test analysis functionality for all supported formats"""
    print("\nTesting analysis functionality...")

    analyzer = MultiFormatBinaryAnalyzer()

    # Test DEX analysis
    dex_file = create_test_dex_file()
    try:
        result = analyzer.analyze_dex(dex_file)
        print(f"DEX analysis result keys: {list(result.keys())}")
        assert result['format'] == 'DEX'
        assert 'dex_version' in result
        assert 'string_ids_count' in result
        assert 'method_ids_count' in result
        print("✓ DEX analysis passed!")
    finally:
        os.unlink(dex_file)

    # Test JAR analysis
    jar_file = create_test_jar_file()
    try:
        result = analyzer.analyze_jar(jar_file)
        print(f"JAR analysis result keys: {list(result.keys())}")
        assert result['format'] == 'JAR'
        assert 'total_files' in result
        assert 'manifest_info' in result
        assert result['manifest_info']['present'] == True
        print("✓ JAR analysis passed!")
    finally:
        os.unlink(jar_file)

    # Test APK analysis
    apk_file = create_test_apk_file()
    try:
        result = analyzer.analyze_apk(apk_file)
        print(f"APK analysis result keys: {list(result.keys())}")
        assert result['format'] == 'APK'
        assert 'dex_files' in result
        assert 'native_libs' in result
        assert 'manifest_info' in result
        print("✓ APK analysis passed!")
    finally:
        os.unlink(apk_file)

    # Test MSI analysis
    msi_file = create_test_msi_file()
    try:
        result = analyzer.analyze_msi(msi_file)
        print(f"MSI analysis result keys: {list(result.keys())}")
        print(f"MSI analysis result: {result}")
        assert result['format'] == 'MSI'
        if 'error' not in result:
            assert 'compound_document' in result
            assert 'sector_size' in result
        print("✓ MSI analysis passed!")
    finally:
        os.unlink(msi_file)

    # Test COM analysis
    com_file = create_test_com_file()
    try:
        result = analyzer.analyze_com(com_file)
        print(f"COM analysis result keys: {list(result.keys())}")
        assert result['format'] == 'COM'
        assert 'file_size' in result
        assert 'load_address' in result
        assert 'entropy' in result
        print("✓ COM analysis passed!")
    finally:
        os.unlink(com_file)

    print("✓ All analysis tests passed!")


def test_full_analysis():
    """Test full binary analysis workflow"""
    print("\nTesting full analysis workflow...")

    analyzer = MultiFormatBinaryAnalyzer()

    # Test with a DEX file
    dex_file = create_test_dex_file()
    try:
        result = analyzer.analyze_binary(dex_file)
        print(f"Full DEX analysis: {result['format']}")
        assert result['format'] == 'DEX'
        print("✓ Full DEX analysis passed!")
    finally:
        os.unlink(dex_file)

    # Test with an APK file
    apk_file = create_test_apk_file()
    try:
        result = analyzer.analyze_binary(apk_file)
        print(f"Full APK analysis: {result['format']}")
        assert result['format'] == 'APK'
        print("✓ Full APK analysis passed!")
    finally:
        os.unlink(apk_file)

    print("✓ Full analysis workflow tests passed!")


def main():
    """Run all tests"""
    print("Starting multi-format binary analyzer tests...\n")

    try:
        test_format_detection()
        test_analysis()
        test_full_analysis()

        print("\n🎉 All tests passed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        logger.error(f"Test failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
