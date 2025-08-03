"""Simple test for .lnk parser."""

import sys
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.utils.system.lnk_parser import LnkParser, LnkParseError
    print("✓ Successfully imported LnkParser")
    
    from intellicrack.utils.system.file_resolution import FileResolver
    print("✓ Successfully imported FileResolver")
    
    # Test basic instantiation
    parser = LnkParser()
    print("✓ Successfully created LnkParser instance")
    
    resolver = FileResolver()
    print("✓ Successfully created FileResolver instance")
    
    # Test file type detection
    lnk_type = resolver.get_file_type_info("test.lnk")
    if lnk_type.extension == '.lnk' and lnk_type.category == 'shortcut':
        print("✓ .lnk file type correctly detected")
    else:
        print(f"✗ .lnk file type detection failed: {lnk_type.extension}, {lnk_type.category}")
    
    print("\n🎉 All basic tests passed!")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)