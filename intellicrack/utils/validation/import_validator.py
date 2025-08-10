"""Import validation utilities for plugin development.

Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import ast
import importlib

from intellicrack.logger import logger


class ImportValidator:
    """Utility class for validating Python imports in code files."""

    @staticmethod
    def validate_imports_from_code(code: str) -> tuple[bool, list[str]]:
        """Check if imports are available from code string.

        Args:
            code: Python code as string

        Returns:
            Tuple of (success, warnings/errors)

        """
        warnings = []
        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        try:
                            importlib.import_module(alias.name)
                        except ImportError as e:
                            logger.error("Import error in import_validator: %s", e)
                            warnings.append(f"Module not found: {alias.name}")

                elif isinstance(node, ast.ImportFrom):
                    if node.module:  # Skip relative imports without module
                        try:
                            importlib.import_module(node.module)
                        except ImportError as e:
                            logger.error("Import error in import_validator: %s", e)
                            warnings.append(f"Module not found: {node.module}")

            return True, warnings

        except Exception as e:
            logger.error("Exception in import_validator: %s", e)
            return False, [f"Import validation error: {e!s}"]

    @staticmethod
    def validate_imports_from_file(file_path: str) -> dict[str, list[str] | bool]:
        """Check imports from a file path.

        Args:
            file_path: Path to Python file

        Returns:
            Dictionary with 'missing' list and optionally 'success' boolean

        """
        missing = []

        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            success, warnings = ImportValidator.validate_imports_from_code(code)

            # Extract just the missing module names from warnings
            for warning in warnings:
                if warning.startswith("Module not found: "):
                    missing.append(warning.replace("Module not found: ", ""))

            return {"missing": missing, "success": success}

        except Exception as e:
            logger.error("Exception in import_validator: %s", e)
            return {"missing": missing, "success": False}

    @staticmethod
    def get_import_nodes(code: str) -> list[dict[str, str | list[str]]]:
        """Extract all import nodes from code.

        Args:
            code: Python code as string

        Returns:
            List of import information dictionaries

        """
        imports = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(
                            {
                                "type": "import",
                                "module": alias.name,
                                "alias": alias.asname,
                                "line": node.lineno,
                            },
                        )

                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        names = [alias.name for alias in node.names]
                        imports.append(
                            {
                                "type": "from_import",
                                "module": node.module,
                                "names": names,
                                "level": node.level,
                                "line": node.lineno,
                            },
                        )

        except Exception as e:
            logger.error("Exception in import_validator: %s", e)

        return imports

    @staticmethod
    def check_import_availability(module_name: str) -> bool:
        """Check if a specific module is available.

        Args:
            module_name: Name of module to check

        Returns:
            True if module is available, False otherwise

        """
        try:
            importlib.import_module(module_name)
            return True
        except ImportError as e:
            logger.error("Import error in import_validator: %s", e)
            return False

    @staticmethod
    def suggest_alternatives(module_name: str) -> list[str]:
        """Suggest alternative modules for common missing imports.

        Args:
            module_name: Name of missing module

        Returns:
            List of suggested alternatives

        """
        alternatives = {
            "cv2": ["opencv-python", "opencv-contrib-python"],
            "sklearn": ["scikit-learn"],
            "PIL": ["Pillow"],
            "yaml": ["PyYAML"],
            "bs4": ["beautifulsoup4"],
            "requests": ["urllib3"],
            "numpy": ["array"],
            "pandas": ["csv"],
            "matplotlib": ["plotly"],
            "torch": ["tensorflow"],
            "tensorflow": ["torch"],
            "lxml": ["xml.etree.ElementTree"],
            "psutil": ["os", "subprocess"],
        }

        return alternatives.get(module_name, [])


class PluginStructureValidator:
    """Utility class for validating plugin structure and AST patterns."""

    @staticmethod
    def validate_structure_from_code(
        code: str,
        required_methods: set[str] | None = None,
    ) -> tuple[bool, list[str]]:
        """Validate plugin structure requirements from code string.

        Args:
            code: Python code as string
            required_methods: Set of required method names (defaults to {'run'})

        Returns:
            Tuple of (success, errors)

        """
        if required_methods is None:
            required_methods = {"run"}

        errors = []
        found_methods = set()

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if node.name in required_methods:
                        found_methods.add(node.name)
                elif isinstance(node, ast.ClassDef):
                    # Check methods in classes
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef) and item.name in required_methods:
                            found_methods.add(item.name)

            # Check for missing required methods
            missing_methods = required_methods - found_methods
            for method in missing_methods:
                errors.append(f"Missing required '{method}' method")

            return len(errors) == 0, errors

        except Exception as e:
            logger.error("Exception in import_validator: %s", e)
            errors.append(f"Structure validation error: {e!s}")
            return False, errors

    @staticmethod
    def validate_structure_from_file(
        file_path: str,
        required_methods: set[str] | None = None,
    ) -> dict[str, bool | list[str]]:
        """Check plugin structure from a file path.

        Args:
            file_path: Path to Python file
            required_methods: Set of required method names (defaults to {'run'})

        Returns:
            Dictionary with 'valid' boolean and 'errors' list

        """
        try:
            with open(file_path, encoding="utf-8") as f:
                code = f.read()

            is_valid, errors = PluginStructureValidator.validate_structure_from_code(
                code,
                required_methods,
            )

            return {"valid": is_valid, "errors": errors}

        except Exception as e:
            logger.error("Exception in import_validator: %s", e)
            return {"valid": False, "errors": [str(e)]}

    @staticmethod
    def get_function_definitions(code: str) -> list[dict[str, str | int]]:
        """Extract all function definitions from code.

        Args:
            code: Python code as string

        Returns:
            List of function information dictionaries

        """
        functions = []

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Get function arguments
                    args = []
                    for arg in node.args.args:
                        args.append(arg.arg)

                    functions.append(
                        {
                            "name": node.name,
                            "line": node.lineno,
                            "args": args,
                            "type": "function",
                        }
                    )
                elif isinstance(node, ast.ClassDef):
                    # Get methods from classes
                    for item in node.body:
                        if isinstance(item, ast.FunctionDef):
                            args = []
                            for arg in item.args.args:
                                args.append(arg.arg)

                            functions.append(
                                {
                                    "name": item.name,
                                    "line": item.lineno,
                                    "args": args,
                                    "type": "method",
                                    "class": node.name,
                                }
                            )

        except Exception as e:
            logger.error("Exception in import_validator: %s", e)

        return functions

    @staticmethod
    def validate_combined(
        code: str,
        required_methods: set[str] | None = None,
    ) -> dict[str, bool | list[str]]:
        """Validate both imports and structure in one call.

        Args:
            code: Python code as string
            required_methods: Set of required method names

        Returns:
            Dictionary with validation results

        """
        # Validate imports
        import_success, import_warnings = ImportValidator.validate_imports_from_code(code)

        # Validate structure
        struct_success, struct_errors = PluginStructureValidator.validate_structure_from_code(
            code,
            required_methods,
        )

        return {
            "valid": import_success and struct_success,
            "import_warnings": import_warnings,
            "structure_errors": struct_errors,
            "import_success": import_success,
            "structure_success": struct_success,
        }


# Convenience functions for backward compatibility
def validate_imports(code: str) -> tuple[bool, list[str]]:
    """Backward compatibility function for validate_imports.

    Args:
        code: Python code as string

    Returns:
        Tuple of (success, warnings)

    """
    return ImportValidator.validate_imports_from_code(code)


def validate_structure(code: str) -> tuple[bool, list[str]]:
    """Backward compatibility function for validate_structure.

    Args:
        code: Python code as string

    Returns:
        Tuple of (success, errors)

    """
    return PluginStructureValidator.validate_structure_from_code(code)
