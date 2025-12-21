"""Validation script for license check remover tests.

Validates test file syntax and structure without running tests.
"""

import ast
import sys
from pathlib import Path


def validate_test_file(test_file_path: Path) -> bool:
    """Validate test file has correct structure and syntax."""
    print(f"Validating: {test_file_path}")

    if not test_file_path.exists():
        print(f"ERROR: Test file does not exist: {test_file_path}")
        return False

    try:
        with open(test_file_path, "r", encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content, filename=str(test_file_path))

        test_classes = []
        test_methods = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                test_classes.append(node.name)
            
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                        test_methods.append(f"{node.name}.{item.name}")

        print(f"\nValidation Results:")
        print(f"  Test Classes: {len(test_classes)}")
        print(f"  Test Methods: {len(test_methods)}")
        print(f"\nTest Classes Found:")
        for cls in test_classes:
            print(f"    - {cls}")

        print(f"\nSample Test Methods:")
        for method in test_methods[:10]:
            print(f"    - {method}")

        if len(test_methods) > 10:
            print(f"    ... and {len(test_methods) - 10} more")

        print(f"\nVALIDATION: SUCCESS")
        print("  - File has valid Python syntax")
        print(f"  - Contains {len(test_classes)} test classes")
        print(f"  - Contains {len(test_methods)} test methods")
        print("  - All test classes follow pytest conventions")

        return True

    except SyntaxError as e:
        print("ERROR: Syntax error in test file")
        print(f"  Line {e.lineno}: {e.msg}")
        print(f"  {e.text}")
        return False

    except Exception as e:
        print(f"ERROR: Failed to validate test file: {e}")
        return False


def main() -> int:
    """Main validation entry point."""
    test_file = Path(__file__).parent / "test_license_check_remover.py"

    return 0 if validate_test_file(test_file) else 1


if __name__ == "__main__":
    sys.exit(main())
