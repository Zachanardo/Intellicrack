"""
Simple test runner for ASLR bypass tests.
"""
import sys
import os

try:
    from intellicrack.core.mitigation_bypass.aslr_bypass import ASLRBypass
    MODULE_AVAILABLE = True
except ImportError:
    ASLRBypass = None
    MODULE_AVAILABLE = False

try:
    import pytest
    pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")
except ImportError:
    pass

def test_basic_functionality() -> None:
    """Test basic ASLR bypass instantiation and methods."""
    print("Testing ASLRBypass instantiation...")

    try:
        # Create instance
        aslr = ASLRBypass()
        print("OK ASLRBypass instance created")

        # Check attributes
        assert hasattr(aslr, 'techniques'), "Missing techniques attribute"
        print(f"OK Found {len(aslr.techniques)} bypass techniques")

        # Test recommendation method
        result = aslr.get_recommended_technique(
            binary_path="test.exe",
            has_info_leak=True,
            has_write_primitive=True
        )
        assert result is not None, "get_recommended_technique returned None"
        print(f"OK Recommended technique: {result.get('technique', 'Unknown')}")

        # Test analysis method
        analysis = aslr.analyze_aslr_bypass(
            binary_path="test.exe",
            process=None
        )
        assert analysis is not None, "analyze_aslr_bypass returned None"
        print(f"OK Analysis completed with difficulty: {analysis.get('difficulty_score', 'Unknown')}")

        print("\nAll basic tests passed!")
        return True

    except Exception as e:
        print(f"FAIL Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_basic_functionality()
    sys.exit(0 if success else 1)
