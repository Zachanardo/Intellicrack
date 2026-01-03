#!/usr/bin/env python3
"""Test dynamic AI script generation functionality."""

import sys
from typing import Any, cast


def test_frida_generation() -> bool:
    """Test Frida script generation from natural language prompt."""
    print("Testing dynamic Frida script generation...")

    try:
        from intellicrack.ai.ai_script_generator import AIScriptGenerator

        generator = AIScriptGenerator()

        result = generator.generate_frida_script(
            binary_path_or_analysis="test_binary.exe",
            protection_info={"type": "license_check", "hooks": ["CreateFileW"]},
        )

        if result is not None:
            print("OK Script generated successfully!")
            if result.content:
                print(f" Content preview:\n{result.content[:500]}...")
            return True
        else:
            print("FAIL Generation returned None")
            return False

    except Exception as e:
        print(f"FAIL Exception during generation: {e}")
        return False


def test_ghidra_generation() -> bool:
    """Test Ghidra script generation from natural language prompt."""
    print("\nTesting dynamic Ghidra script generation...")

    try:
        from intellicrack.ai.ai_script_generator import AIScriptGenerator

        generator = AIScriptGenerator()

        result = generator.generate_ghidra_script(
            binary_path_or_analysis="test_binary.exe",
            protection_info={"analysis_goals": ["License validation pattern detection"]},
        )

        if result is not None:
            print("OK Ghidra script generated successfully!")
            if result.content:
                print(f" Content preview:\n{result.content[:500]}...")
            return True
        else:
            print("FAIL Generation returned None")
            return False

    except Exception as e:
        print(f"FAIL Exception during generation: {e}")
        return False

def main() -> bool:
    """Run all tests."""
    print(" Testing Dynamic AI Script Generation System")
    print("=" * 50)

    try:
        from intellicrack.core.config_manager import get_config
        config = get_config()
        ai_config_raw = config.get("ai_script_generation", {})
        if isinstance(ai_config_raw, dict):
            ai_config = cast(dict[str, Any], ai_config_raw)
            default_backend = ai_config.get("default_backend", "openai")
            models = ai_config.get("models", {})
            model_name = models.get("openai", "gpt-4") if isinstance(models, dict) else "gpt-4"
            print(f"LLM Backend: {default_backend}")
            print(f"Model: {model_name}")
        else:
            print("Config: ai_script_generation not configured as dict")
    except Exception as e:
        print(f"WARNING Config warning: {e}")

    print()

    # Run tests
    frida_success = test_frida_generation()
    ghidra_success = test_ghidra_generation()

    print("\n" + "=" * 50)
    print(" Test Results:")
    print(f"Frida Generation: {'OK PASS' if frida_success else 'FAIL FAIL'}")
    print(f"Ghidra Generation: {'OK PASS' if ghidra_success else 'FAIL FAIL'}")

    if frida_success and ghidra_success:
        print("\n🎉 All tests passed! Dynamic AI script generation is working.")
        return True
    else:
        print("\nWARNING Some tests failed. Check configuration and LLM backend.")
        return False

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⏹️ Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFAIL Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
