#!/usr/bin/env python3
"""
Test script for enhanced installation directory discovery.

This script tests the new installation discovery functionality with real
directories to validate marker detection and confidence scoring.
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from intellicrack.utils.system.installation_discovery import installation_discovery_engine

def test_installation_discovery():
    """Test the installation discovery functionality."""
    print("Testing Installation Directory Discovery")
    print("=" * 50)
    
    # Test with common Windows installation directories
    test_paths = []
    
    if sys.platform.startswith('win'):
        test_paths = [
            r"C:\Program Files",
            r"C:\Program Files (x86)",
            r"C:\ProgramData",
        ]
    else:
        test_paths = [
            "/opt",
            "/usr/local",
            "/Applications" if sys.platform.startswith('darwin') else "/usr/share",
        ]
    
    for test_path in test_paths:
        if os.path.exists(test_path):
            print(f"\nTesting path: {test_path}")
            print("-" * 30)
            
            try:
                # Test marker analysis
                markers, marker_confidence = installation_discovery_engine.analyze_installation_markers(test_path)
                print(f"Found {len(markers)} installation markers (confidence: {marker_confidence:.1f})")
                
                for marker in markers[:3]:  # Show first 3
                    print(f"  - {marker.description} ({marker.marker_type})")
                
                # Test directory structure analysis
                structures, struct_confidence = installation_discovery_engine.analyze_directory_structure(test_path)
                print(f"Found {len(structures)} key directory structures (confidence: {struct_confidence:.1f})")
                
                for structure in structures[:3]:  # Show first 3
                    print(f"  - {structure.description} ({structure.structure_type})")
                
                # Test full discovery (limited depth for performance)
                candidates = installation_discovery_engine.discover_installation_roots(
                    test_path, include_subdirs=False
                )
                
                if candidates:
                    best = candidates[0]
                    print(f"Installation confidence: {best.confidence_score:.1f}/100")
                    print(f"Files: {best.file_count}, Executables: {best.executable_count}")
                else:
                    print("No installation candidates found")
                    
            except Exception as e:
                print(f"Error testing {test_path}: {e}")
        else:
            print(f"Path does not exist: {test_path}")

def test_specific_installation():
    """Test with a specific known installation if available."""
    print("\n" + "=" * 50)
    print("Testing Specific Installation")
    print("=" * 50)
    
    # Try to find a real installation to test
    specific_paths = []
    
    if sys.platform.startswith('win'):
        # Common Windows applications
        potential_paths = [
            r"C:\Program Files\7-Zip",
            r"C:\Program Files\Notepad++",
            r"C:\Program Files (x86)\Notepad++",
            r"C:\Program Files\Git",
            r"C:\Program Files\Mozilla Firefox",
            r"C:\Program Files (x86)\Mozilla Firefox",
        ]
        specific_paths = [p for p in potential_paths if os.path.exists(p)]
    else:
        # Common Unix applications
        potential_paths = [
            "/opt/google/chrome",
            "/usr/local/bin",
            "/Applications/Firefox.app" if sys.platform.startswith('darwin') else "/usr/share/firefox",
        ]
        specific_paths = [p for p in potential_paths if os.path.exists(p)]
    
    if not specific_paths:
        print("No known installations found for detailed testing")
        return
        
    test_path = specific_paths[0]
    print(f"Testing installation: {test_path}")
    print("-" * 30)
    
    try:
        # Full discovery analysis
        candidates = installation_discovery_engine.discover_installation_roots(
            test_path, include_subdirs=True
        )
        
        if candidates:
            best = candidates[0]
            print(f"Installation Analysis Results:")
            print(f"  Path: {best.path}")
            print(f"  Confidence Score: {best.confidence_score:.1f}/100")
            print(f"  File Count: {best.file_count}")
            print(f"  Executable Count: {best.executable_count}")
            print(f"  Total Size: {best.total_size / (1024*1024):.1f} MB")
            
            if best.markers_found:
                print(f"  Installation Markers Found:")
                for marker in best.markers_found:
                    print(f"    - {marker.description} (type: {marker.marker_type}, weight: {marker.weight})")
                    
            if best.directories_found:
                print(f"  Key Directory Structures:")
                for structure in best.directories_found:
                    print(f"    - {structure.description} (type: {structure.structure_type})")
                    
            # Test key subdirectory identification
            key_subdirs = installation_discovery_engine.identify_key_subdirectories(test_path)
            print(f"  Key Subdirectories by Category:")
            for category, paths in key_subdirs.items():
                if paths:
                    print(f"    {category}: {len(paths)} directories")
                    
        else:
            print("No installation candidates found")
            
    except Exception as e:
        print(f"Error during detailed testing: {e}")

if __name__ == "__main__":
    try:
        test_installation_discovery()
        test_specific_installation()
        
        print("\n" + "=" * 50)
        print("Installation Discovery Test Complete")
        print("=" * 50)
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
    except Exception as e:
        print(f"Test failed with error: {e}")
        sys.exit(1)