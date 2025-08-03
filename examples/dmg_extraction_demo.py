"""
DMG (Apple Disk Image) extraction demonstration.

This script demonstrates how to use the DMGExtractor to extract
and analyze macOS disk images across different platforms.

Copyright (C) 2025 Zachary Flint
"""

import json
import logging
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.utils.extraction import DMGExtractor


def setup_logging():
    """Configure logging for the demo."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def demonstrate_dmg_extraction(dmg_path: str):
    """
    Demonstrate DMG extraction capabilities.
    
    Args:
        dmg_path: Path to a DMG file
    """
    dmg_path = Path(dmg_path)
    
    if not dmg_path.exists():
        print(f"Error: DMG file not found: {dmg_path}")
        return
    
    print(f"\n{'='*60}")
    print(f"DMG Extraction Demo: {dmg_path.name}")
    print(f"{'='*60}\n")
    
    # Create extractor
    extractor = DMGExtractor()
    
    try:
        # Validate DMG
        print("1. Validating DMG file...")
        is_valid, error = extractor.validate_dmg(dmg_path)
        if not is_valid:
            print(f"   ❌ Invalid DMG: {error}")
            return
        print("   ✓ Valid DMG file")
        
        # Extract contents
        print("\n2. Extracting DMG contents...")
        result = extractor.extract(dmg_path)
        
        if not result['success']:
            print(f"   ❌ Extraction failed: {result.get('error', 'Unknown error')}")
            return
        
        print(f"   ✓ Extraction successful using {result['extraction_method']}")
        print(f"   ✓ Output directory: {result['output_dir']}")
        print(f"   ✓ Files extracted: {result['file_count']}")
        
        # Show metadata
        print("\n3. DMG Metadata:")
        metadata = result['metadata']
        print(f"   • Format: {metadata.get('format', 'Unknown')}")
        print(f"   • Size: {metadata['file_size']:,} bytes")
        print(f"   • Encrypted: {metadata.get('encrypted', False)}")
        print(f"   • Compressed: {metadata.get('compressed', False)}")
        if 'variant' in metadata:
            print(f"   • Variant: {metadata['variant']}")
        
        # Show app bundles
        if result.get('app_bundles'):
            print(f"\n4. Application Bundles Found: {len(result['app_bundles'])}")
            for i, app in enumerate(result['app_bundles'], 1):
                print(f"\n   App {i}: {app['name']}")
                print(f"   • Bundle ID: {app.get('bundle_id', 'N/A')}")
                print(f"   • Version: {app.get('version', 'N/A')}")
                print(f"   • Executable: {app.get('executable', 'N/A')}")
                print(f"   • Frameworks: {len(app.get('frameworks', []))}")
                print(f"   • Plugins: {len(app.get('plugins', []))}")
                if app.get('minimum_os'):
                    print(f"   • Minimum OS: {app['minimum_os']}")
        
        # Analyze file categories
        print("\n5. File Categories:")
        categories = {}
        for file in result['extracted_files']:
            cat = file['category']
            categories[cat] = categories.get(cat, 0) + 1
        
        for cat, count in sorted(categories.items()):
            print(f"   • {cat}: {count} files")
        
        # Find main executable
        print("\n6. Main Executable:")
        main_exe = extractor.find_main_executable(
            result['extracted_files'], 
            result.get('app_bundles', [])
        )
        if main_exe:
            print(f"   • File: {main_exe['filename']}")
            print(f"   • Path: {main_exe['path']}")
            print(f"   • Size: {main_exe['size']:,} bytes")
        else:
            print("   • No main executable identified")
        
        # Show high-priority files
        print("\n7. High Priority Files for Analysis:")
        high_priority = [f for f in result['extracted_files'] 
                        if f['analysis_priority'] in ['critical', 'high']][:10]
        
        for file in high_priority:
            print(f"   • {file['filename']} ({file['category']}) - {file['size']:,} bytes")
        
        # Export results
        output_json = Path(result['output_dir']) / 'extraction_results.json'
        with open(output_json, 'w') as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\n8. Results exported to: {output_json}")
        
    except Exception as e:
        print(f"\n❌ Error during extraction: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Cleanup
        extractor.cleanup()
        print("\n✓ Cleanup completed")


def demonstrate_cross_platform_extraction():
    """Demonstrate cross-platform DMG extraction capabilities."""
    print("\n" + "="*60)
    print("Cross-Platform DMG Extraction Methods")
    print("="*60 + "\n")
    
    extractor = DMGExtractor()
    
    print("Available extraction methods (in order of preference):")
    for i, method in enumerate(extractor._extraction_methods, 1):
        method_name = method.__name__.replace('_extract_with_', '')
        print(f"{i}. {method_name}")
        
        # Check availability
        if method_name == 'hdiutil':
            print("   • Platform: macOS only")
            print("   • Status: Native macOS tool")
        elif method_name == '7zip':
            print("   • Platform: Windows, Linux, macOS")
            print("   • Status: Cross-platform, handles most DMG formats")
        elif method_name == 'dmg2img':
            print("   • Platform: Linux, Unix")
            print("   • Status: Converts DMG to mountable format")
        elif method_name == 'python_parser':
            print("   • Platform: All")
            print("   • Status: Pure Python fallback for simple DMGs")
    
    print("\nNotes:")
    print("• On Windows: 7-Zip is the recommended method")
    print("• On Linux: dmg2img + mount or 7-Zip")
    print("• On macOS: hdiutil (native) is preferred")
    print("• Python parser: Limited to uncompressed UDIF format")


def main():
    """Main demonstration function."""
    setup_logging()
    
    print("Intellicrack DMG Extraction Demo")
    print("================================\n")
    
    # Show cross-platform capabilities
    demonstrate_cross_platform_extraction()
    
    # Check command line arguments
    if len(sys.argv) > 1:
        dmg_path = sys.argv[1]
        demonstrate_dmg_extraction(dmg_path)
    else:
        print("\nUsage: python dmg_extraction_demo.py <path_to_dmg>")
        print("\nExample DMGs to test:")
        print("• Application installer: /path/to/app_installer.dmg")
        print("• Compressed DMG: /path/to/compressed.dmg")
        print("• Encrypted DMG: /path/to/encrypted.dmg")
        
        # Try to find example DMGs
        example_paths = [
            Path.home() / "Downloads",
            Path("/Applications"),
            Path("C:\\Downloads"),
        ]
        
        print("\nSearching for DMG files...")
        dmg_found = False
        for path in example_paths:
            if path.exists():
                dmgs = list(path.glob("*.dmg"))
                if dmgs:
                    print(f"\nFound DMG files in {path}:")
                    for dmg in dmgs[:5]:  # Show first 5
                        print(f"  • {dmg}")
                    dmg_found = True
        
        if not dmg_found:
            print("No DMG files found in common locations.")


if __name__ == "__main__":
    main()