"""
DEB integration example showing how to analyze extracted binaries.

This example demonstrates the full workflow of extracting a DEB package
and analyzing the binaries within using Intellicrack's analysis capabilities.

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

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.extraction import DEBExtractor
from intellicrack.core.analysis.multi_format_analyzer import MultiFormatBinaryAnalyzer
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer


def analyze_deb_package(deb_path: Path):
    """Extract and analyze a DEB package."""
    print(f"\n{'='*60}")
    print(f"Analyzing DEB Package: {deb_path.name}")
    print(f"{'='*60}")
    
    # Step 1: Extract the DEB package
    print("\n[Step 1] Extracting DEB package...")
    extractor = DEBExtractor()
    
    # Validate DEB
    is_valid, error = extractor.validate_deb(deb_path)
    if not is_valid:
        print(f"[!] Invalid DEB: {error}")
        return
    
    # Extract contents
    extraction_result = extractor.extract(deb_path)
    
    if not extraction_result['success']:
        print(f"[!] Extraction failed: {extraction_result.get('error')}")
        return
    
    print(f"[+] Extracted {extraction_result['file_count']} files")
    print(f"[+] Output directory: {extraction_result['output_dir']}")
    
    # Display package info
    metadata = extraction_result['metadata']
    if metadata.get('control'):
        control = metadata['control']
        print(f"\n[*] Package: {control.get('Package', 'Unknown')}")
        print(f"[*] Version: {control.get('Version', 'Unknown')}")
        print(f"[*] Architecture: {control.get('Architecture', 'Unknown')}")
    
    # Step 2: Analyze extracted binaries
    print("\n[Step 2] Analyzing extracted binaries...")
    
    # Get executables and libraries
    executables = extractor.get_files_by_category(extraction_result['extracted_files'], 'executable')
    libraries = extractor.get_files_by_category(extraction_result['extracted_files'], 'library')
    
    print(f"\n[*] Found {len(executables)} executables and {len(libraries)} libraries")
    
    # Initialize analyzers
    multi_format_analyzer = MultiFormatBinaryAnalyzer()
    binary_analyzer = BinaryAnalyzer()
    
    # Analyze main executable
    main_exe = extractor.find_main_executable(extraction_result['extracted_files'], metadata)
    if main_exe:
        print(f"\n[*] Analyzing main executable: {main_exe['filename']}")
        analyze_binary(main_exe['full_path'], multi_format_analyzer, binary_analyzer)
    
    # Analyze other executables (limit to first 3)
    other_exes = [exe for exe in executables if exe != main_exe][:3]
    for exe in other_exes:
        print(f"\n[*] Analyzing executable: {exe['filename']}")
        analyze_binary(exe['full_path'], multi_format_analyzer, binary_analyzer)
    
    # Step 3: Security analysis summary
    print(f"\n[Step 3] Security Analysis Summary")
    print("="*40)
    
    # Check for SUID/SGID binaries
    suid_files = []
    for file_info in extraction_result['extracted_files']:
        if file_info['category'] == 'executable':
            try:
                file_path = Path(file_info['full_path'])
                if file_path.exists():
                    mode = file_path.stat().st_mode
                    if mode & 0o4000:  # SUID
                        suid_files.append((file_info, 'SUID'))
                    elif mode & 0o2000:  # SGID
                        suid_files.append((file_info, 'SGID'))
            except:
                pass
    
    if suid_files:
        print("\n[!] Found privileged binaries:")
        for file_info, perm_type in suid_files:
            print(f"    - {file_info['path']} ({perm_type})")
    
    # Check maintainer scripts
    if metadata.get('scripts'):
        print(f"\n[*] Package contains {len(metadata['scripts'])} maintainer scripts:")
        for script in metadata['scripts']:
            print(f"    - {script}")
        print("    [!] Review these scripts for security implications")
    
    # Check for interesting paths
    interesting_paths = ['/etc/', '/usr/sbin/', '/lib/systemd/', '/usr/lib/systemd/']
    interesting_files = []
    
    for file_info in extraction_result['extracted_files']:
        path_str = file_info['path'].replace('\\', '/')
        if any(path_str.startswith(p) for p in interesting_paths):
            interesting_files.append(file_info)
    
    if interesting_files:
        print(f"\n[*] Found {len(interesting_files)} files in sensitive locations")
    
    # Cleanup
    print(f"\n[*] Analysis complete. Extracted files remain at: {extraction_result['output_dir']}")
    print("[*] Remember to clean up with: extractor.cleanup()")
    
    return extractor, extraction_result


def analyze_binary(binary_path: str, multi_format_analyzer, binary_analyzer):
    """Analyze a single binary file."""
    binary_path = Path(binary_path)
    
    if not binary_path.exists():
        print(f"    [!] File not found: {binary_path}")
        return
    
    # Identify format
    binary_format = multi_format_analyzer.identify_format(binary_path)
    print(f"    Format: {binary_format}")
    
    if binary_format == 'ELF':
        # Analyze ELF binary
        result = multi_format_analyzer.analyze_elf(binary_path)
        
        if 'error' not in result:
            print(f"    Machine: {result.get('machine', 'Unknown')}")
            print(f"    Type: {result.get('type', 'Unknown')}")
            print(f"    Entry Point: {result.get('entry_point', 'Unknown')}")
            
            # Check for security features
            if 'sections' in result:
                has_nx = any('.nx' in s.get('name', '').lower() for s in result['sections'])
                has_relro = any('relro' in s.get('name', '').lower() for s in result['sections'])
                
                security_features = []
                if has_nx:
                    security_features.append("NX")
                if has_relro:
                    security_features.append("RELRO")
                
                if security_features:
                    print(f"    Security Features: {', '.join(security_features)}")
            
            # Check symbols
            if 'symbols' in result and result['symbols']:
                dangerous_symbols = ['system', 'exec', 'popen', 'strcpy', 'gets', 'sprintf']
                found_dangerous = [s['name'] for s in result['symbols'] 
                                 if any(d in s['name'].lower() for d in dangerous_symbols)]
                
                if found_dangerous:
                    print(f"    Potentially dangerous functions: {', '.join(found_dangerous[:5])}")
    
    else:
        print(f"    [!] Unexpected format in DEB: {binary_format}")


def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python deb_integration_example.py <path_to_deb_file>")
        print("\nExample:")
        print("  python deb_integration_example.py /var/cache/apt/archives/curl_7.68.0-1ubuntu2_amd64.deb")
        return
    
    deb_path = Path(sys.argv[1])
    
    if not deb_path.exists():
        print(f"[!] Error: File not found: {deb_path}")
        return
    
    try:
        extractor, result = analyze_deb_package(deb_path)
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during analysis: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()