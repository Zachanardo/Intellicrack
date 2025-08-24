#!/usr/bin/env python3
"""Simple test for AI script generation classes."""

import pytest
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class TestAIImportSimple:
    """Test basic AI imports and functionality."""

    def test_core_imports(self):
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

    def test_script_type_enum(self):
        """Test that ScriptType enum works correctly."""
        from intellicrack.ai.ai_script_generator import ScriptType
        
        script_type = ScriptType.FRIDA
        assert script_type.value is not None
        assert isinstance(script_type.value, str)

    def test_script_generation_result(self):
        """Test that ScriptGenerationResult can be created."""
        from intellicrack.ai.ai_script_generator import ScriptGenerationResult
        
        result = ScriptGenerationResult(success=True, content="test")
        assert result.success is True
        assert result.content == "test"

    def test_dynamic_script_generator_creation(self):
        """Test that DynamicScriptGenerator can be instantiated."""
        from intellicrack.ai.ai_script_generator import DynamicScriptGenerator
        
        generator = DynamicScriptGenerator()
        assert generator is not None
