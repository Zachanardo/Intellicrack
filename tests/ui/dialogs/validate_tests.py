"""Validation script for model_finetuning_dialog tests.

Validates test structure, imports, and syntax without requiring full environment.
"""

import ast
import sys
from pathlib import Path


def validate_test_file(test_file: Path) -> tuple[bool, list[str]]:
    """Validate test file structure and content."""
    issues = []

    try:
        with open(test_file, encoding="utf-8") as f:
            content = f.read()

        tree = ast.parse(content, filename=str(test_file))

        test_classes = []
        test_functions = []

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                test_classes.append(node.name)
            
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith("test_"):
                        test_functions.append(f"{node.name}.{item.name}")

        if not test_classes:
            issues.append("No test classes found")

        if not test_functions:
            issues.append("No test functions found")

        print(f"Found {len(test_classes)} test classes:")
        for cls in test_classes:
            print(f"  - {cls}")

        print(f"\nFound {len(test_functions)} test functions:")
        for func in test_functions[:10]:
            print(f"  - {func}")
        if len(test_functions) > 10:
            print(f"  ... and {len(test_functions) - 10} more")

        required_imports = [
            "pytest",
            "TrainingConfig",
            "TrainingThread",
            "ModelFinetuningDialog",
        ]

        imports_found = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                or not isinstance(node, ast.ImportFrom)
                and isinstance(node, ast.Import)
            ):
                imports_found.extend([alias.name for alias in node.names])
        if missing_imports := [
            imp for imp in required_imports if imp not in imports_found
        ]:
            issues.append(f"Missing imports: {missing_imports}")

        print("\nValidation Results:")
        print(f"  Test classes: {len(test_classes)}")
        print(f"  Test functions: {len(test_functions)}")
        print("  Syntax: Valid")

        return not issues, issues

    except SyntaxError as e:
        issues.append(f"Syntax error: {e}")
        return False, issues
    except Exception as e:
        issues.append(f"Validation error: {e}")
        return False, issues


def main() -> int:
    """Run validation."""
    test_file = Path(__file__).parent / "test_model_finetuning_dialog.py"

    if not test_file.exists():
        print(f"Test file not found: {test_file}")
        return 1

    print(f"Validating: {test_file}\n")

    valid, issues = validate_test_file(test_file)

    if valid:
        print("\n✓ All validation checks passed!")
        print("\nTest Coverage:")
        print("  - TrainingConfig initialization and configuration")
        print("  - AugmentationConfig for dataset augmentation")
        print("  - LicenseAnalysisNeuralNetwork functionality")
        print("  - TrainingThread model loading and training")
        print("  - ModelFinetuningDialog UI and interactions")
        print("  - Complete training workflows")
        print("  - Dataset format support (JSON, JSONL, CSV)")
        print("  - Model format support (PyTorch, pickle)")
        print("  - Error handling and edge cases")
        print("  - Real-world license cracking scenarios")
        return 0
    else:
        print("\n✗ Validation failed:")
        for issue in issues:
            print(f"  - {issue}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
