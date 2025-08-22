#!/usr/bin/env python3
"""Simple test for AI script generation classes."""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    print("Testing imports...")

    # Test basic import
    from intellicrack.ai.ai_script_generator import (
        ScriptGenerationResult,
        ScriptType,
        DynamicScriptGenerator
    )
    print("✅ Core classes imported successfully")

    # Test creating instances
    script_type = ScriptType.FRIDA
    print(f"✅ ScriptType.FRIDA = {script_type.value}")

    result = ScriptGenerationResult(success=True, content="test")
    print(f"✅ ScriptGenerationResult created: success={result.success}")

    generator = DynamicScriptGenerator()
    print("✅ DynamicScriptGenerator created successfully")

    print("\n🎉 All imports and basic functionality working!")

except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Unexpected error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
