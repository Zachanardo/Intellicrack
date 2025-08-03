"""
DEB extraction demonstration for Intellicrack.

This script demonstrates how to extract and analyze DEB packages
using Intellicrack's DEB extraction capabilities.

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

import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.extraction import DEBExtractor


def demonstrate_deb_extraction():
    """Demonstrate DEB extraction capabilities."""
    print("=" * 60)
    print("DEB Extraction Demo for Intellicrack")
    print("=" * 60)
    
    # Create extractor instance
    extractor = DEBExtractor()
    print("\n[+] DEBExtractor initialized")
    
    # Example DEB files to try
    example_debs = [
        "/var/cache/apt/archives/*.deb",  # Ubuntu/Debian cache
        "~/Downloads/*.deb",               # Common download location
        "./test_package.deb"               # Local test file
    ]
    
    print("\n[*] Looking for DEB files...")
    print(f"[*] Search locations: {', '.join(example_debs)}")
    
    # Find a DEB file
    deb_path = None
    for pattern in example_debs:
        path = Path(pattern).expanduser()
        if path.exists() and path.suffix == '.deb':
            deb_path = path
            break
        elif path.parent.exists():
            # Try glob pattern
            matches = list(path.parent.glob(path.name))
            if matches:
                deb_path = matches[0]
                break
    
    if not deb_path:
        print("\n[!] No DEB files found. Please provide a DEB file path.")
        print("\n[*] Example usage:")
        print("    python deb_extraction_demo.py /path/to/package.deb")
        
        if len(sys.argv) > 1:
            deb_path = Path(sys.argv[1])
            if not deb_path.exists():
                print(f"\n[!] Error: File not found: {deb_path}")
                return
        else:
            return
    
    print(f"\n[+] Found DEB file: {deb_path}")
    
    # Validate DEB
    print("\n[*] Validating DEB file...")
    is_valid, error = extractor.validate_deb(deb_path)
    
    if not is_valid:
        print(f"[!] Invalid DEB file: {error}")
        return
    
    print("[+] DEB file is valid")
    
    # Extract DEB
    print(f"\n[*] Extracting DEB file...")
    result = extractor.extract(deb_path)
    
    if not result['success']:
        print(f"[!] Extraction failed: {result.get('error', 'Unknown error')}")
        return
    
    print(f"[+] Successfully extracted using method: {result['extraction_method']}")
    print(f"[+] Output directory: {result['output_dir']}")
    print(f"[+] Total files extracted: {result['file_count']}")
    
    # Display metadata
    metadata = result['metadata']
    if metadata.get('control'):
        print("\n[*] Package Information:")
        for key, value in metadata['control'].items():
            if key in ['Package', 'Version', 'Architecture', 'Maintainer', 'Description']:
                if '\n' in str(value):
                    print(f"    {key}:")
                    for line in str(value).split('\n'):
                        print(f"        {line}")
                else:
                    print(f"    {key}: {value}")
    
    # Display dependencies
    if metadata.get('dependencies'):
        print("\n[*] Dependencies:")
        for dep_type, deps in metadata['dependencies'].items():
            print(f"    {dep_type.title()}: {', '.join(deps)}")
    
    # Display scripts
    if metadata.get('scripts'):
        print("\n[*] Maintainer Scripts:")
        for script, info in metadata['scripts'].items():
            print(f"    {script}: Present (size: {info['size']} bytes)")
    
    # Categorize extracted files
    print("\n[*] File Categories:")
    categories = {}
    for file_info in result['extracted_files']:
        category = file_info['category']
        if category not in categories:
            categories[category] = []
        categories[category].append(file_info)
    
    for category, files in categories.items():
        print(f"\n    {category.title()} ({len(files)} files):")
        # Show first 5 files of each category
        for file_info in files[:5]:
            print(f"        {file_info['path']} ({file_info['size']} bytes)")
        if len(files) > 5:
            print(f"        ... and {len(files) - 5} more")
    
    # Find main executable
    main_exe = extractor.find_main_executable(result['extracted_files'], metadata)
    if main_exe:
        print(f"\n[*] Identified main executable: {main_exe['path']}")
        print(f"    Size: {main_exe['size']} bytes")
        print(f"    Full path: {main_exe['full_path']}")
    
    # Analysis recommendations
    print("\n[*] Analysis Recommendations:")
    
    executables = extractor.get_files_by_category(result['extracted_files'], 'executable')
    libraries = extractor.get_files_by_category(result['extracted_files'], 'library')
    scripts = extractor.get_files_by_category(result['extracted_files'], 'script')
    configs = extractor.get_files_by_category(result['extracted_files'], 'configuration')
    
    if executables:
        print(f"    - Found {len(executables)} executable(s) for binary analysis")
    if libraries:
        print(f"    - Found {len(libraries)} shared libraries for dependency analysis")
    if scripts:
        print(f"    - Found {len(scripts)} scripts for security review")
    if configs:
        print(f"    - Found {len(configs)} configuration files for settings analysis")
    
    # Save extraction report
    report_path = Path(result['output_dir']) / 'extraction_report.json'
    report = {
        'deb_file': str(deb_path),
        'extraction_method': result['extraction_method'],
        'file_count': result['file_count'],
        'metadata': metadata,
        'categories': {cat: len(files) for cat, files in categories.items()},
        'main_executable': main_exe['path'] if main_exe else None
    }
    
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n[+] Extraction report saved to: {report_path}")
    
    # Cleanup option
    print(f"\n[*] Extracted files are in: {result['output_dir']}")
    print("[*] Run extractor.cleanup() to remove temporary files")
    
    return extractor, result


def main():
    """Main function."""
    try:
        extractor, result = demonstrate_deb_extraction()
        
        # Optional: Analyze specific files
        if extractor and result and result['success']:
            print("\n" + "=" * 60)
            print("Additional Analysis Options:")
            print("=" * 60)
            print("\n[*] You can now:")
            print("    1. Analyze executables with Intellicrack's binary analyzer")
            print("    2. Check for protection mechanisms")
            print("    3. Extract strings and symbols")
            print("    4. Perform dynamic analysis")
            
            # Example: Get paths for further analysis
            main_exe = extractor.find_main_executable(result['extracted_files'], result['metadata'])
            if main_exe:
                print(f"\n[*] Suggested next step:")
                print(f"    intellicrack analyze {main_exe['full_path']}")
    
    except KeyboardInterrupt:
        print("\n\n[!] Demo interrupted by user")
    except Exception as e:
        print(f"\n[!] Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()