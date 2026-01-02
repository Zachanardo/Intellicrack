#!/usr/bin/env python3
"""Simple test for AI script generation classes."""

import pytest


class TestAIImportSimple:
    """Test basic AI imports and functionality."""

    def test_core_imports(self) -> None:
        """Test that core AI classes can be imported successfully."""
        from intellicrack.ai.ai_script_generator import (
            ScriptGenerationResult,
            ScriptType,
            DynamicScriptGenerator
        )

        # Basic import test passes if we get here without ImportError
        assert ScriptGenerationResult is not None
        assert ScriptType is not None
        assert DynamicScriptGenerator is not None

    def test_script_type_enum(self) -> None:
        """Test that ScriptType enum works correctly."""
        from intellicrack.ai.ai_script_generator import ScriptType

        script_type = ScriptType.FRIDA
        assert script_type.value is not None
        assert isinstance(script_type.value, str)

    def test_script_generation_result(self) -> None:
        """Test that ScriptGenerationResult can be created."""
        from intellicrack.ai.ai_script_generator import ScriptGenerationResult

        result = ScriptGenerationResult(success=True, content="test")
        assert result.success is True
        assert result.content == "test"

    def test_dynamic_script_generator_creation(self) -> None:
        """Test that DynamicScriptGenerator can be instantiated."""
        from intellicrack.ai.ai_script_generator import DynamicScriptGenerator

        generator = DynamicScriptGenerator()
        assert generator is not None
