"""Validation script for bypass_engine.py scope enforcement fix.

This script validates that:
1. REVERSE_SHELL, BIND_SHELL, STAGED_PAYLOAD are removed from PayloadType enum
2. All remaining payload types are licensing-related
3. PayloadType can be imported correctly
4. The enum values are correct
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))


def validate_payload_type_enum() -> bool:
    """Validate PayloadType enum has only licensing-related types.

    Returns:
        bool: True if validation passes, False otherwise.
    """
    try:
        from intellicrack.core.exploitation.bypass_engine import PayloadType

        # Expected licensing-only payload types
        expected_types = {
            "LICENSE_CHECK_BYPASS",
            "TRIAL_EXTENSION",
            "ACTIVATION_BYPASS",
            "SERIAL_VALIDATION_BYPASS",
            "HARDWARE_ID_SPOOF",
        }

        # Get actual types
        actual_types = {member.name for member in PayloadType}

        # Check for removed types
        removed_types = {"REVERSE_SHELL", "BIND_SHELL", "STAGED_PAYLOAD"}
        found_removed = actual_types & removed_types

        if found_removed:
            print(f"❌ FAIL: Found removed shell payload types: {found_removed}")
            return False

        # Check all expected types are present
        missing_types = expected_types - actual_types
        if missing_types:
            print(f"❌ FAIL: Missing expected licensing types: {missing_types}")
            return False

        # Check for unexpected types
        unexpected_types = actual_types - expected_types
        if unexpected_types:
            print(f"❌ FAIL: Found unexpected payload types: {unexpected_types}")
            return False

        print("✅ PASS: PayloadType enum contains only licensing-related types")
        print(f"   Found types: {sorted(actual_types)}")
        return True

    except ImportError as e:
        print(f"❌ FAIL: Could not import PayloadType: {e}")
        return False


def validate_cli_import() -> bool:
    """Validate CLI can import PayloadType correctly.

    Returns:
        bool: True if validation passes, False otherwise.
    """
    try:
        from intellicrack.core.exploitation.bypass_engine import BypassEngine, PayloadType

        if PayloadType is None:
            print("❌ FAIL: PayloadType imported as None")
            return False

        # Test enum access
        test_type = PayloadType.LICENSE_CHECK_BYPASS
        if test_type.value != "license_check_bypass":
            print(f"❌ FAIL: Unexpected enum value: {test_type.value}")
            return False

        print("✅ PASS: CLI import pattern works correctly")
        print(f"   BypassEngine: {BypassEngine}")
        print(f"   PayloadType: {PayloadType}")
        return True

    except ImportError as e:
        print(f"❌ FAIL: Could not import from bypass_engine: {e}")
        return False
    except AttributeError as e:
        print(f"❌ FAIL: Attribute error accessing PayloadType: {e}")
        return False


def validate_bypass_engine() -> bool:
    """Validate BypassEngine class has correct docstrings.

    Returns:
        bool: True if validation passes, False otherwise.
    """
    try:
        from intellicrack.core.exploitation.bypass_engine import BypassEngine

        # Check class docstring mentions licensing scope
        class_doc = BypassEngine.__doc__
        if class_doc is None:
            print("❌ FAIL: BypassEngine missing docstring")
            return False

        if "licensing" not in class_doc.lower():
            print("❌ FAIL: BypassEngine docstring doesn't mention 'licensing'")
            return False

        if "EXCLUSIVELY" not in class_doc or "SOLELY" not in class_doc:
            print("❌ FAIL: BypassEngine docstring doesn't emphasize exclusive licensing scope")
            return False

        print("✅ PASS: BypassEngine has proper scope documentation")
        return True

    except ImportError as e:
        print(f"❌ FAIL: Could not import BypassEngine: {e}")
        return False


def main() -> int:
    """Run all validation tests.

    Returns:
        int: 0 if all tests pass, 1 otherwise.
    """
    print("=" * 70)
    print("BYPASS ENGINE SCOPE ENFORCEMENT VALIDATION")
    print("=" * 70)
    print()

    tests = [
        ("PayloadType Enum", validate_payload_type_enum),
        ("CLI Import Pattern", validate_cli_import),
        ("BypassEngine Documentation", validate_bypass_engine),
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n{'─' * 70}")
        print(f"Testing: {test_name}")
        print("─" * 70)
        result = test_func()
        results.append(result)

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Tests passed: {passed}/{total}")

    if all(results):
        print("\n✅ ALL VALIDATIONS PASSED - Scope enforcement is correct!")
        return 0
    else:
        print("\n❌ SOME VALIDATIONS FAILED - Please review the errors above")
        return 1


if __name__ == "__main__":
    sys.exit(main())
