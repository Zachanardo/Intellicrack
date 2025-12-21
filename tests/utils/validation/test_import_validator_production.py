"""Production tests for import validator.

Tests validate real Python import validation and AST analysis for plugin development.
NO mocks - validates actual module imports and code structure.

Copyright (C) 2025 Zachary Flint
"""

import tempfile
from pathlib import Path
from typing import Any

import pytest

from intellicrack.utils.validation.import_validator import ImportValidator, PluginStructureValidator, validate_imports, validate_structure


class TestImportValidation:
    """Test import validation from code strings."""

    def test_validates_successful_imports(self) -> None:
        """Validates code with available imports."""
        code = """
import os
import sys
import json
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert success is True
        assert len(warnings) == 0

    def test_detects_missing_imports(self) -> None:
        """Detects unavailable module imports."""
        code = """
import nonexistent_module_12345
import another_fake_module_67890
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert len(warnings) > 0
        assert any("nonexistent_module_12345" in w for w in warnings)

    def test_validates_from_imports(self) -> None:
        """Validates from...import statements."""
        code = """
from pathlib import Path
from typing import List, Dict
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert success is True
        assert len(warnings) == 0

    def test_detects_missing_from_imports(self) -> None:
        """Detects missing modules in from imports."""
        code = """
from fake_module_xyz import something
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert len(warnings) > 0
        assert any("fake_module_xyz" in w for w in warnings)

    def test_handles_import_aliases(self) -> None:
        """Handles imports with aliases."""
        code = """
import numpy as np
import pandas as pd
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        if success:
            assert len(warnings) == 0
        else:
            assert any("numpy" in w or "pandas" in w for w in warnings)

    def test_handles_multi_line_imports(self) -> None:
        """Handles multi-line import statements."""
        code = """
from typing import (
    List,
    Dict,
    Optional,
    Any
)
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert success is True

    def test_handles_relative_imports(self) -> None:
        """Handles relative imports without errors."""
        code = """
from . import module
from .. import parent_module
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert isinstance(success, bool)

    def test_handles_syntax_errors(self) -> None:
        """Handles code with syntax errors gracefully."""
        code = """
import os
def broken function syntax
"""
        success, warnings = ImportValidator.validate_imports_from_code(code)

        assert success is False
        assert len(warnings) > 0


class TestImportValidationFromFile:
    """Test import validation from file paths."""

    def test_validates_imports_from_file(self) -> None:
        """Validates imports from Python file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
import os
import sys
import json
""")
            f.flush()
            filepath = f.name

        try:
            result = ImportValidator.validate_imports_from_file(filepath)

            assert "missing" in result
            assert "success" in result
            assert result["success"] is True
            assert len(result["missing"]) == 0
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_detects_missing_imports_from_file(self) -> None:
        """Detects missing imports in file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
import nonexistent_test_module
""")
            f.flush()
            filepath = f.name

        try:
            result = ImportValidator.validate_imports_from_file(filepath)

            assert len(result["missing"]) > 0
            assert "nonexistent_test_module" in result["missing"]
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_handles_file_not_found(self) -> None:
        """Handles non-existent file paths."""
        result = ImportValidator.validate_imports_from_file("/nonexistent/file.py")

        assert "missing" in result
        assert "success" in result
        assert result["success"] is False


class TestImportNodeExtraction:
    """Test extraction of import nodes from code."""

    def test_extracts_simple_imports(self) -> None:
        """Extracts simple import statements."""
        code = """
import os
import sys
"""
        imports = ImportValidator.get_import_nodes(code)

        assert len(imports) >= 2
        import_modules = [imp["module"] for imp in imports if imp["type"] == "import"]
        assert "os" in import_modules
        assert "sys" in import_modules

    def test_extracts_from_imports(self) -> None:
        """Extracts from...import statements."""
        code = """
from pathlib import Path, PurePath
"""
        imports = ImportValidator.get_import_nodes(code)

        from_imports = [imp for imp in imports if imp["type"] == "from_import"]
        assert len(from_imports) >= 1
        assert any(imp["module"] == "pathlib" for imp in from_imports)

    def test_extracts_import_line_numbers(self) -> None:
        """Extracts line numbers for imports."""
        code = """
import os
import sys
from pathlib import Path
"""
        imports = ImportValidator.get_import_nodes(code)

        assert all("line" in imp for imp in imports)
        assert all(imp["line"] > 0 for imp in imports)

    def test_extracts_import_aliases(self) -> None:
        """Extracts import aliases."""
        code = """
import numpy as np
"""
        imports = ImportValidator.get_import_nodes(code)

        numpy_import = next((imp for imp in imports if imp.get("module") == "numpy"), None)
        if numpy_import:
            assert numpy_import.get("alias") == "np"

    def test_extracts_from_import_names(self) -> None:
        """Extracts specific names from from imports."""
        code = """
from typing import List, Dict, Optional
"""
        imports = ImportValidator.get_import_nodes(code)

        typing_import = next((imp for imp in imports if imp.get("module") == "typing"), None)
        assert typing_import is not None
        assert "List" in typing_import["names"]
        assert "Dict" in typing_import["names"]


class TestModuleAvailabilityCheck:
    """Test module availability checking."""

    def test_detects_available_module(self) -> None:
        """Detects available standard library modules."""
        assert ImportValidator.check_import_availability("os") is True
        assert ImportValidator.check_import_availability("sys") is True

    def test_detects_unavailable_module(self) -> None:
        """Detects unavailable modules."""
        assert ImportValidator.check_import_availability("nonexistent_xyz_module") is False

    def test_handles_nested_module_names(self) -> None:
        """Handles nested module names."""
        result = ImportValidator.check_import_availability("os.path")
        assert isinstance(result, bool)


class TestAlternativeSuggestions:
    """Test alternative module suggestions."""

    def test_suggests_alternatives_for_common_modules(self) -> None:
        """Suggests alternatives for commonly misnamed modules."""
        alternatives = ImportValidator.suggest_alternatives("cv2")
        assert len(alternatives) > 0
        assert any("opencv" in alt.lower() for alt in alternatives)

    def test_suggests_alternatives_for_sklearn(self) -> None:
        """Suggests scikit-learn for sklearn."""
        alternatives = ImportValidator.suggest_alternatives("sklearn")
        assert "scikit-learn" in alternatives

    def test_returns_empty_for_unknown_modules(self) -> None:
        """Returns empty list for unknown modules."""
        alternatives = ImportValidator.suggest_alternatives("completely_unknown_module")
        assert alternatives == []

    def test_suggests_pil_alternative(self) -> None:
        """Suggests Pillow for PIL."""
        alternatives = ImportValidator.suggest_alternatives("PIL")
        assert "Pillow" in alternatives


class TestPluginStructureValidation:
    """Test plugin structure validation."""

    def test_validates_plugin_with_run_method(self) -> None:
        """Validates plugin code with required run method."""
        code = """
def run():
    pass
"""
        is_valid, errors = PluginStructureValidator.validate_structure_from_code(code)

        assert is_valid is True
        assert len(errors) == 0

    def test_detects_missing_run_method(self) -> None:
        """Detects missing run method in plugin."""
        code = """
def other_function():
    pass
"""
        is_valid, errors = PluginStructureValidator.validate_structure_from_code(code)

        assert is_valid is False
        assert any("run" in err for err in errors)

    def test_validates_class_with_run_method(self) -> None:
        """Validates class-based plugin with run method."""
        code = """
class Plugin:
    def run(self):
        pass
"""
        is_valid, errors = PluginStructureValidator.validate_structure_from_code(code)

        assert is_valid is True
        assert len(errors) == 0

    def test_accepts_custom_required_methods(self) -> None:
        """Accepts custom required method names."""
        code = """
def analyze():
    pass

def execute():
    pass
"""
        is_valid, errors = PluginStructureValidator.validate_structure_from_code(
            code,
            required_methods={"analyze", "execute"}
        )

        assert is_valid is True

    def test_detects_missing_custom_methods(self) -> None:
        """Detects missing custom required methods."""
        code = """
def analyze():
    pass
"""
        is_valid, errors = PluginStructureValidator.validate_structure_from_code(
            code,
            required_methods={"analyze", "execute"}
        )

        assert is_valid is False
        assert any("execute" in err for err in errors)


class TestPluginStructureValidationFromFile:
    """Test plugin structure validation from files."""

    def test_validates_structure_from_file(self) -> None:
        """Validates plugin structure from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
def run():
    pass
""")
            f.flush()
            filepath = f.name

        try:
            result = PluginStructureValidator.validate_structure_from_file(filepath)

            assert "valid" in result
            assert "errors" in result
            assert result["valid"] is True
        finally:
            Path(filepath).unlink(missing_ok=True)

    def test_detects_invalid_structure_from_file(self) -> None:
        """Detects invalid structure from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("""
def other_method():
    pass
""")
            f.flush()
            filepath = f.name

        try:
            result = PluginStructureValidator.validate_structure_from_file(filepath)

            assert result["valid"] is False
            assert len(result["errors"]) > 0
        finally:
            Path(filepath).unlink(missing_ok=True)


class TestFunctionDefinitionExtraction:
    """Test function definition extraction."""

    def test_extracts_function_definitions(self) -> None:
        """Extracts function definitions from code."""
        code = """
def function1():
    pass

def function2(arg1, arg2):
    pass
"""
        functions = PluginStructureValidator.get_function_definitions(code)

        assert len(functions) >= 2
        names = [f["name"] for f in functions]
        assert "function1" in names
        assert "function2" in names

    def test_extracts_function_arguments(self) -> None:
        """Extracts function argument names."""
        code = """
def analyze(binary_path, options):
    pass
"""
        functions = PluginStructureValidator.get_function_definitions(code)

        analyze_func = next((f for f in functions if f["name"] == "analyze"), None)
        assert analyze_func is not None
        assert "binary_path" in analyze_func["args"]
        assert "options" in analyze_func["args"]

    def test_extracts_class_methods(self) -> None:
        """Extracts methods from classes."""
        code = """
class LicenseCracker:
    def analyze(self):
        pass

    def crack(self):
        pass
"""
        functions = PluginStructureValidator.get_function_definitions(code)

        methods = [f for f in functions if f["type"] == "method"]
        assert len(methods) >= 2
        assert any(m["name"] == "analyze" for m in methods)
        assert any(m["name"] == "crack" for m in methods)

    def test_extracts_method_class_names(self) -> None:
        """Extracts class names for methods."""
        code = """
class Plugin:
    def run(self):
        pass
"""
        functions = PluginStructureValidator.get_function_definitions(code)

        run_method = next((f for f in functions if f["name"] == "run"), None)
        assert run_method is not None
        assert run_method.get("class") == "Plugin"


class TestCombinedValidation:
    """Test combined import and structure validation."""

    def test_validates_both_imports_and_structure(self) -> None:
        """Validates both imports and structure together."""
        code = """
import os
import sys

def run():
    os.path.exists('test')
"""
        result = PluginStructureValidator.validate_combined(code)

        assert "valid" in result
        assert "import_success" in result
        assert "structure_success" in result
        assert result["import_success"] is True
        assert result["structure_success"] is True
        assert result["valid"] is True

    def test_detects_combined_failures(self) -> None:
        """Detects both import and structure failures."""
        code = """
import nonexistent_module

def other_function():
    pass
"""
        result = PluginStructureValidator.validate_combined(code)

        assert result["import_success"] is True
        assert len(result["import_warnings"]) > 0
        assert result["structure_success"] is False
        assert result["valid"] is False


class TestBackwardCompatibility:
    """Test backward compatibility functions."""

    def test_validate_imports_function(self) -> None:
        """Tests backward compatible validate_imports function."""
        code = "import os"
        success, warnings = validate_imports(code)

        assert isinstance(success, bool)
        assert isinstance(warnings, list)

    def test_validate_structure_function(self) -> None:
        """Tests backward compatible validate_structure function."""
        code = "def run(): pass"
        success, errors = validate_structure(code)

        assert isinstance(success, bool)
        assert isinstance(errors, list)
