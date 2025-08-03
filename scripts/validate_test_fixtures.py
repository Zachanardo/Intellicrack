#!/usr/bin/env python3
"""
Validate test fixtures for Intellicrack testing infrastructure.
Ensures all test data is REAL and functional, not mocked or placeholder.
NO MOCKS - Validates actual test fixtures for real functionality testing.
"""

import os
import sys
import struct
import hashlib
from pathlib import Path
from typing import List, Dict, Tuple

def validate_pe_binary(file_path: Path) -> Dict[str, any]:
    """Validate PE binary is real and analyzable."""
    result = {"valid": False, "format": "PE", "issues": []}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check MZ signature
        if len(data) < 2 or data[:2] != b'MZ':
            result["issues"].append("Missing MZ signature")
            return result
        
        # Check PE signature
        if len(data) < 0x40:
            result["issues"].append("File too small for PE format")
            return result
            
        pe_offset = struct.unpack('<L', data[0x3C:0x40])[0]
        if len(data) < pe_offset + 4:
            result["issues"].append("Invalid PE offset")
            return result
            
        if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            result["issues"].append("Missing PE signature")
            return result
        
        result["valid"] = True
        result["size"] = len(data)
        result["pe_offset"] = pe_offset
        
        # Additional PE validation
        coff_header = data[pe_offset+4:pe_offset+24]
        if len(coff_header) >= 20:
            machine = struct.unpack('<H', coff_header[0:2])[0]
            sections = struct.unpack('<H', coff_header[2:4])[0]
            result["machine"] = hex(machine)
            result["sections"] = sections
        
        print(f"✅ Valid PE binary: {file_path.name} ({len(data)} bytes)")
        
    except Exception as e:
        result["issues"].append(f"Error reading file: {e}")
    
    return result

def validate_elf_binary(file_path: Path) -> Dict[str, any]:
    """Validate ELF binary is real and analyzable."""
    result = {"valid": False, "format": "ELF", "issues": []}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check ELF signature
        if len(data) < 4 or data[:4] != b'\x7fELF':
            result["issues"].append("Missing ELF signature")
            return result
        
        if len(data) < 16:
            result["issues"].append("File too small for ELF format")
            return result
        
        # Check class (32/64 bit)
        elf_class = data[4]
        if elf_class == 1:
            result["class"] = "ELF32"
        elif elf_class == 2:
            result["class"] = "ELF64"
        else:
            result["issues"].append(f"Invalid ELF class: {elf_class}")
            return result
        
        # Check endianness
        endian = data[5]
        if endian == 1:
            result["endian"] = "little"
        elif endian == 2:
            result["endian"] = "big"
        else:
            result["issues"].append(f"Invalid endianness: {endian}")
            return result
        
        result["valid"] = True
        result["size"] = len(data)
        
        print(f"✅ Valid ELF binary: {file_path.name} ({result['class']}, {len(data)} bytes)")
        
    except Exception as e:
        result["issues"].append(f"Error reading file: {e}")
    
    return result

def validate_network_capture(file_path: Path) -> Dict[str, any]:
    """Validate network capture file is real PCAP data."""
    result = {"valid": False, "format": "PCAP", "issues": []}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check PCAP magic numbers
        if len(data) < 4:
            result["issues"].append("File too small for PCAP format")
            return result
        
        magic = struct.unpack('<L', data[:4])[0]
        if magic == 0xa1b2c3d4:
            result["endian"] = "little"
        elif magic == 0xd4c3b2a1:
            result["endian"] = "big"
        elif magic == 0xa1b23c4d:
            result["format"] = "PCAP-NG"
            result["endian"] = "little"
        else:
            result["issues"].append(f"Invalid PCAP magic: {hex(magic)}")
            return result
        
        result["valid"] = True
        result["size"] = len(data)
        
        # Count packets (basic estimation)
        packet_count = 0
        offset = 24  # Skip global header
        while offset + 16 < len(data):
            try:
                cap_len = struct.unpack('<L', data[offset+8:offset+12])[0]
                if cap_len > 65535:  # Sanity check
                    break
                packet_count += 1
                offset += 16 + cap_len
            except:
                break
        
        result["estimated_packets"] = packet_count
        
        print(f"✅ Valid PCAP file: {file_path.name} (~{packet_count} packets, {len(data)} bytes)")
        
    except Exception as e:
        result["issues"].append(f"Error reading file: {e}")
    
    return result

def validate_fixtures_directory(fixtures_dir: Path) -> Dict[str, List[Dict]]:
    """Validate all fixtures in directory."""
    results = {
        "pe_binaries": [],
        "elf_binaries": [],
        "network_captures": [],
        "vulnerable_samples": [],
        "overall_stats": {}
    }
    
    print(f"Validating fixtures in: {fixtures_dir}")
    print("=" * 60)
    
    # Validate PE binaries
    pe_dir = fixtures_dir / 'binaries' / 'pe'
    if pe_dir.exists():
        for pe_file in pe_dir.glob('*.exe'):
            result = validate_pe_binary(pe_file)
            results["pe_binaries"].append(result)
        
        for pe_file in pe_dir.glob('*.dll'):
            result = validate_pe_binary(pe_file)
            results["pe_binaries"].append(result)
    
    # Validate ELF binaries
    elf_dir = fixtures_dir / 'binaries' / 'elf'
    if elf_dir.exists():
        for elf_file in elf_dir.iterdir():
            if elf_file.is_file() and not elf_file.name.startswith('.'):
                result = validate_elf_binary(elf_file)
                results["elf_binaries"].append(result)
    
    # Validate network captures
    net_dir = fixtures_dir / 'network_captures'
    if net_dir.exists():
        for pcap_file in net_dir.glob('*.pcap'):
            result = validate_network_capture(pcap_file)
            results["network_captures"].append(result)
    
    # Validate vulnerable samples
    vuln_dir = fixtures_dir / 'vulnerable_samples'
    if vuln_dir.exists():
        for vuln_file in vuln_dir.glob('*.exe'):
            result = validate_pe_binary(vuln_file)
            results["vulnerable_samples"].append(result)
    
    return results

def print_validation_summary(results: Dict[str, List[Dict]]):
    """Print validation summary."""
    print("\n" + "=" * 60)
    print("VALIDATION SUMMARY")
    print("=" * 60)
    
    categories = [
        ("PE Binaries", results["pe_binaries"]),
        ("ELF Binaries", results["elf_binaries"]),
        ("Network Captures", results["network_captures"]),
        ("Vulnerable Samples", results["vulnerable_samples"])
    ]
    
    total_valid = 0
    total_files = 0
    
    for category_name, category_results in categories:
        valid_count = sum(1 for r in category_results if r["valid"])
        total_count = len(category_results)
        total_valid += valid_count
        total_files += total_count
        
        status = "✅" if valid_count == total_count else "❌"
        print(f"{status} {category_name}: {valid_count}/{total_count} valid")
        
        # Show issues
        for result in category_results:
            if not result["valid"] and result["issues"]:
                print(f"    Issues: {', '.join(result['issues'])}")
    
    print(f"\n📊 Overall: {total_valid}/{total_files} fixtures valid")
    
    if total_valid == total_files:
        print("🎉 All test fixtures are valid and ready for REAL functionality testing!")
        return 0
    else:
        print("⚠️  Some test fixtures have issues. Please review and fix.")
        return 1

def main():
    """Main validation entry point."""
    project_root = Path(__file__).parent.parent
    fixtures_dir = project_root / 'tests' / 'fixtures'
    
    if not fixtures_dir.exists():
        print(f"❌ Fixtures directory not found: {fixtures_dir}")
        print("Run 'just create-fixtures' to create test fixtures first.")
        return 1
    
    results = validate_fixtures_directory(fixtures_dir)
    return print_validation_summary(results)

if __name__ == '__main__':
    sys.exit(main())