"""
Demonstration of MSI extraction functionality.

This script shows how to use Intellicrack's MSI extraction capabilities
to analyze Windows Installer packages.

Copyright (C) 2025 Zachary Flint
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.extraction import MSIExtractor
from intellicrack.utils.system.file_resolution import file_resolver


def demonstrate_msi_extraction():
    """Demonstrate MSI extraction capabilities."""
    print("=== MSI Extraction Demo ===\n")
    
    # Example MSI paths (update these with actual MSI files)
    example_msis = [
        r"C:\Downloads\example_installer.msi",
        r"C:\Windows\Installer\*.msi",  # System MSI cache
    ]
    
    extractor = MSIExtractor()
    
    # Find first available MSI for demo
    msi_path = None
    for path_pattern in example_msis:
        if '*' in path_pattern:
            # Handle wildcards
            from glob import glob
            matches = glob(path_pattern)
            if matches:
                msi_path = Path(matches[0])
                break
        else:
            path = Path(path_pattern)
            if path.exists():
                msi_path = path
                break
    
    if not msi_path:
        print("No MSI files found. Please update example_msis with actual MSI paths.")
        print("\nTo test with a real MSI:")
        print("1. Download any MSI installer")
        print("2. Update the example_msis list with its path")
        print("3. Run this script again")
        return
    
    print(f"Found MSI: {msi_path}\n")
    
    # Validate MSI
    print("1. Validating MSI file...")
    is_valid, error = extractor.validate_msi(msi_path)
    if is_valid:
        print("   ✓ Valid MSI file")
    else:
        print(f"   ✗ Invalid MSI: {error}")
        return
    
    # Extract MSI
    print("\n2. Extracting MSI contents...")
    result = extractor.extract(msi_path)
    
    if result['success']:
        print(f"   ✓ Extraction successful using {result['extraction_method']}")
        print(f"   ✓ Extracted to: {result['output_dir']}")
        print(f"   ✓ Total files: {result['file_count']}")
        
        # Show metadata
        metadata = result.get('metadata', {})
        if metadata.get('properties'):
            print("\n3. MSI Metadata:")
            for key, value in metadata['properties'].items():
                print(f"   - {key}: {value}")
        
        # Categorize files
        print("\n4. Extracted Files by Category:")
        categories = {}
        for file_info in result['extracted_files']:
            category = file_info['category']
            if category not in categories:
                categories[category] = []
            categories[category].append(file_info)
        
        for category, files in categories.items():
            print(f"\n   {category.upper()} ({len(files)} files):")
            # Show top 5 files per category
            for file_info in files[:5]:
                size_kb = file_info['size'] / 1024
                print(f"   - {file_info['filename']} ({size_kb:.1f} KB)")
            if len(files) > 5:
                print(f"   ... and {len(files) - 5} more")
        
        # Find main executable
        print("\n5. Main Executable Detection:")
        main_exe = extractor.find_main_executable(result['extracted_files'])
        if main_exe:
            print(f"   ✓ Found: {main_exe['filename']}")
            print(f"   - Path: {main_exe['path']}")
            print(f"   - Size: {main_exe['size'] / 1024:.1f} KB")
        else:
            print("   ✗ No main executable found")
        
        # Cleanup option
        print("\n6. Cleanup:")
        print(f"   Temporary files at: {result['output_dir']}")
        print("   Run extractor.cleanup() to remove")
        
    else:
        print(f"   ✗ Extraction failed: {result.get('error', 'Unknown error')}")


def demonstrate_file_resolver_integration():
    """Demonstrate file resolver integration with MSI support."""
    print("\n\n=== File Resolver MSI Integration Demo ===\n")
    
    # Example: Resolve MSI to executable
    msi_path = r"C:\Downloads\example.msi"  # Update with actual MSI
    
    if not Path(msi_path).exists():
        print("No MSI file found for file resolver demo.")
        print("Update msi_path with an actual MSI file path.")
        return
    
    print(f"Resolving MSI: {msi_path}")
    
    resolved_path, metadata = file_resolver.resolve_file_path(msi_path)
    
    if metadata.get('is_installer'):
        print("\n✓ MSI successfully resolved to executable:")
        print(f"  - Executable: {resolved_path}")
        print(f"  - Original MSI: {metadata['original_msi']}")
        print(f"  - Extraction Dir: {metadata['extraction_dir']}")
        print(f"  - Total Files: {metadata['total_files']}")
        
        if metadata.get('msi_metadata', {}).get('properties'):
            print("\n  MSI Properties:")
            for key, value in metadata['msi_metadata']['properties'].items():
                print(f"    - {key}: {value}")
    else:
        print("\n✗ Failed to resolve MSI")
        if metadata.get('msi_extraction_failed'):
            print(f"  Error: {metadata.get('extraction_error')}")


if __name__ == '__main__':
    try:
        demonstrate_msi_extraction()
        demonstrate_file_resolver_integration()
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user.")
    except Exception as e:
        print(f"\n\nError during demo: {e}")
        import traceback
        traceback.print_exc()