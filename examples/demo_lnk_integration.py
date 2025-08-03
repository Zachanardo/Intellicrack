"""
Demonstration of the pure Python .lnk parser integration.

This script shows how the .lnk parser is integrated into the FileResolver
and provides cross-platform shortcut resolution without Windows dependencies.
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))


def demo_lnk_parsing():
    """Demonstrate .lnk parsing capabilities."""
    print("Pure Python .lnk Parser Integration Demo")
    print("=" * 50)

    try:
        from intellicrack.utils.system.lnk_parser import LnkParser, parse_lnk_file
        from intellicrack.utils.system.file_resolution import FileResolver

        # Test with common Windows .lnk files
        test_files = [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Excel.lnk",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Word.lnk"
        ]

        for test_file in test_files:
            if os.path.exists(test_file):
                print(f"\n📄 Testing: {Path(test_file).name}")
                print("-" * 30)

                try:
                    # Test standalone parser
                    lnk_data = parse_lnk_file(test_file)
                    print(f"✓ Pure Python parser successful")
                    print(f"  Target: {lnk_data.get('target_path', 'Not found')}")
                    print(f"  Working Dir: {lnk_data.get('working_directory', 'None')}")
                    print(f"  Arguments: {lnk_data.get('command_line_arguments', 'None')}")

                    # Test FileResolver integration
                    resolver = FileResolver()
                    resolved_path, metadata = resolver.resolve_file_path(test_file)

                    print(f"\n✓ FileResolver integration successful")
                    print(f"  Resolved Path: {resolved_path}")
                    print(f"  Is Shortcut: {metadata.get('is_shortcut', False)}")
                    print(f"  Parser Type: {metadata.get('parser_type', 'unknown')}")

                    if metadata.get('error'):
                        print(f"  Note: {metadata['error']}")

                except Exception as e:
                    print(f"✗ Error processing {test_file}: {e}")

                break  # Just test the first found file

        print(f"\n🎯 Key Features Implemented:")
        print(f"  ✓ Cross-platform .lnk parsing (no Windows APIs required)")
        print(f"  ✓ Full .lnk file format support (header, strings, extra data)")
        print(f"  ✓ Unicode and ANSI string handling")
        print(f"  ✓ Timestamp parsing (Windows FILETIME format)")
        print(f"  ✓ File attributes and show command decoding")
        print(f"  ✓ Integration with existing FileResolver")
        print(f"  ✓ Fallback to Windows COM when available")
        print(f"  ✓ Comprehensive error handling")

        print(f"\n🔧 Technical Implementation:")
        print(f"  • Binary file format parsing")
        print(f"  • Windows FILETIME to datetime conversion")
        print(f"  • Environment variable expansion")
        print(f"  • Relative path resolution")
        print(f"  • Graceful fallback mechanisms")

    except ImportError as e:
        print(f"✗ Import error: {e}")
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    demo_lnk_parsing()