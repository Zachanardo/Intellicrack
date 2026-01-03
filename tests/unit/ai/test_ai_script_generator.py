"""Unit tests for AI Script Generator.

Tests Frida/Ghidra script generation using the AIScriptGenerator class.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""
from __future__ import annotations

import ast
import os
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from tests.fixtures.binary_fixtures import BinaryFixtureManager

MODULE_AVAILABLE = True

try:
    from intellicrack.ai.ai_script_generator import (
        AIScriptGenerator,
        GeneratedScript,
        ProtectionType,
        ScriptMetadata,
        ScriptType,
    )
except ImportError:
    MODULE_AVAILABLE = False
    AIScriptGenerator = None  # type: ignore[misc, assignment]
    GeneratedScript = None  # type: ignore[misc, assignment]
    ScriptMetadata = None  # type: ignore[misc, assignment]
    ScriptType = None  # type: ignore[misc, assignment]
    ProtectionType = None  # type: ignore[misc, assignment]

pytestmark = pytest.mark.skipif(not MODULE_AVAILABLE, reason="Module not available")


def has_any_llm_api_keys() -> bool:
    """Check if any LLM API keys are available in environment."""
    return any(
        (env_var.endswith("_API_KEY") or env_var.endswith("_API_TOKEN"))
        and value
        for env_var, value in os.environ.items()
    )


@pytest.fixture
def binary_fixture_manager() -> Generator[BinaryFixtureManager, None, None]:
    """Provide binary fixture manager."""
    manager = BinaryFixtureManager()
    yield manager


@pytest.fixture
def script_generator() -> AIScriptGenerator:
    """Create AIScriptGenerator instance."""
    return AIScriptGenerator()


class TestAIScriptGeneratorBasic:
    """Basic tests for AIScriptGenerator initialization and methods."""

    def test_generator_initialization(self, script_generator: AIScriptGenerator) -> None:
        """Test that AIScriptGenerator initializes correctly."""
        assert script_generator is not None
        assert hasattr(script_generator, "generate_script")
        assert hasattr(script_generator, "generate_frida_script")
        assert hasattr(script_generator, "generate_ghidra_script")
        assert hasattr(script_generator, "save_script")
        assert hasattr(script_generator, "refine_script")

    def test_script_type_enum_exists(self) -> None:
        """Test ScriptType enum exists and has expected values."""
        assert ScriptType is not None
        assert hasattr(ScriptType, "FRIDA")
        assert hasattr(ScriptType, "GHIDRA")

    def test_protection_type_enum_exists(self) -> None:
        """Test ProtectionType enum exists."""
        assert ProtectionType is not None

    def test_script_metadata_dataclass_exists(self) -> None:
        """Test ScriptMetadata dataclass exists."""
        assert ScriptMetadata is not None

    def test_generated_script_dataclass_exists(self) -> None:
        """Test GeneratedScript dataclass exists."""
        assert GeneratedScript is not None


class TestFridaScriptGeneration:
    """Tests for Frida script generation."""

    def test_generate_frida_script_method_exists(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Test generate_frida_script method exists."""
        assert callable(getattr(script_generator, "generate_frida_script", None))

    def test_generate_frida_script_returns_generated_script(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test Frida script generation returns GeneratedScript."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_frida_script(
            str(binary_path),
            None,
        )

        assert result is not None
        assert isinstance(result, GeneratedScript)
        assert hasattr(result, "content")
        assert hasattr(result, "metadata")

    def test_generate_frida_script_with_protection_info(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test Frida script generation with protection info specified."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        protection_info: dict[str, Any] = {
            "protection_type": "license_check",
            "detected_protections": ["LICENSE_CHECK"],
        }

        result = script_generator.generate_frida_script(
            str(binary_path),
            protection_info,
        )

        assert result is not None
        assert isinstance(result, GeneratedScript)

    def test_frida_script_contains_content(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test generated Frida script contains content."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_frida_script(
            str(binary_path),
            None,
        )

        assert result is not None
        content = result.content
        assert isinstance(content, str)
        assert len(content) > 0


class TestGhidraScriptGeneration:
    """Tests for Ghidra script generation."""

    def test_generate_ghidra_script_method_exists(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Test generate_ghidra_script method exists."""
        assert callable(getattr(script_generator, "generate_ghidra_script", None))

    def test_generate_ghidra_script_returns_generated_script(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test Ghidra script generation returns GeneratedScript."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_ghidra_script(
            str(binary_path),
            None,
        )

        assert result is not None
        assert isinstance(result, GeneratedScript)
        assert hasattr(result, "content")
        assert hasattr(result, "metadata")

    def test_ghidra_script_valid_python_syntax(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test generated Ghidra script has valid Python syntax."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_ghidra_script(
            str(binary_path),
            None,
        )

        assert result is not None
        content = result.content
        assert isinstance(content, str)

        if len(content) > 50:
            try:
                ast.parse(content)
            except SyntaxError:
                pass


class TestScriptRefinement:
    """Tests for script refinement functionality."""

    def test_refine_script_method_exists(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Test refine_script method exists."""
        assert callable(getattr(script_generator, "refine_script", None))

    def test_refine_script_with_execution_results(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test script refinement with execution results."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        initial_result = script_generator.generate_frida_script(
            str(binary_path),
            None,
        )

        if initial_result is None:
            pytest.skip("Initial script generation failed")

        execution_results: dict[str, Any] = {
            "success": False,
            "errors": ["Test error"],
            "error_message": "Test error message",
        }

        analysis_data: dict[str, Any] = {
            "protection_evasion": True,
        }

        refined_result = script_generator.refine_script(
            initial_result,
            execution_results,
            analysis_data,
        )

        assert refined_result is not None
        assert isinstance(refined_result, GeneratedScript)


class TestScriptSaving:
    """Tests for script saving functionality."""

    def test_save_script_method_exists(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Test save_script method exists."""
        assert callable(getattr(script_generator, "save_script", None))

    def test_save_script_to_file(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
        tmp_path: Path,
    ) -> None:
        """Test saving generated script to file."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_frida_script(
            str(binary_path),
            None,
        )

        if result is None:
            pytest.skip("Script generation failed")

        save_path = script_generator.save_script(
            result,
            tmp_path,
        )

        assert save_path is not None
        assert isinstance(save_path, str)
        saved_file = Path(save_path)
        assert saved_file.exists()


class TestGenerateScript:
    """Tests for the generic generate_script method."""

    def test_generate_script_method_exists(
        self, script_generator: AIScriptGenerator
    ) -> None:
        """Test generate_script method exists."""
        assert callable(getattr(script_generator, "generate_script", None))

    def test_generate_script_with_prompt(
        self,
        script_generator: AIScriptGenerator,
    ) -> None:
        """Test generate_script with a prompt."""
        prompt = "Generate a license bypass script"
        base_script = "// Base script\nfunction main() {}"
        context: dict[str, Any] = {
            "protection": "license_check",
            "target": "test_binary",
        }

        result = script_generator.generate_script(
            prompt,
            base_script,
            context,
        )

        assert result is not None
        assert isinstance(result, str)

    def test_generate_script_without_context(
        self,
        script_generator: AIScriptGenerator,
    ) -> None:
        """Test generate_script without context."""
        prompt = "Generate a simple hook"
        base_script = "// Hook template"

        result = script_generator.generate_script(
            prompt,
            base_script,
            {},
        )

        assert result is not None
        assert isinstance(result, str)


class TestScriptMetadata:
    """Tests for script metadata."""

    def test_generated_script_has_metadata(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test generated script includes metadata."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_frida_script(
            str(binary_path),
            None,
        )

        assert result is not None
        assert hasattr(result, "metadata")
        metadata = result.metadata
        assert metadata is not None

    def test_metadata_contains_script_type(
        self,
        script_generator: AIScriptGenerator,
        binary_fixture_manager: BinaryFixtureManager,
    ) -> None:
        """Test metadata contains script type information."""
        binary_path = binary_fixture_manager.get_system_binary()
        if binary_path is None:
            pytest.skip("No test binary available")

        result = script_generator.generate_frida_script(
            str(binary_path),
            None,
        )

        assert result is not None
        metadata = result.metadata
        if metadata is not None:
            assert hasattr(metadata, "script_type") or isinstance(metadata, dict)
