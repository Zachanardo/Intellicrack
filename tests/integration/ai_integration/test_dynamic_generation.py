#!/usr/bin/env python3
"""Test dynamic AI script generation functionality."""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_frida_generation():
    """Test Frida script generation from natural language prompt."""
    print("🧪 Testing dynamic Frida script generation...")

    try:
        from intellicrack.ai.ai_script_generator import DynamicScriptGenerator, ScriptType

        # Create generator instance
        generator = DynamicScriptGenerator()

        # Test prompt for license bypass
        prompt = "Create a Frida script that hooks CreateFileW API calls and logs all file access attempts. Focus on detecting license file reads."

        # Generate script
        result = generator.generate_from_prompt(
            prompt=prompt,
            script_type=ScriptType.FRIDA,
            binary_path=None  # Generic script, no specific binary
        )

        if result.success:
            print(f"OK Script generated successfully!")
            print(f" Saved to: {result.file_path}")
            print(f" Content preview:\n{result.content[:500]}...")
            return True
        else:
            print(f"FAIL Generation failed: {result.error}")
            return False

    except Exception as e:
        print(f"FAIL Exception during generation: {e}")
        return False

def test_ghidra_generation():
    """Test Ghidra script generation from natural language prompt."""
    print("\n🧪 Testing dynamic Ghidra script generation...")

    try:
        from intellicrack.ai.ai_script_generator import DynamicScriptGenerator, ScriptType

        generator = DynamicScriptGenerator()

        prompt = "Generate a Ghidra script that scans for string patterns related to license validation. Look for keywords like 'license', 'serial', 'activation', and 'trial'."

        result = generator.generate_from_prompt(
            prompt=prompt,
            script_type=ScriptType.GHIDRA,
            binary_path=None
        )

        if result.success:
            print(f"OK Ghidra script generated successfully!")
            print(f" Saved to: {result.file_path}")
            print(f" Content preview:\n{result.content[:500]}...")
            return True
        else:
            print(f"FAIL Generation failed: {result.error}")
            return False

    except Exception as e:
        print(f"FAIL Exception during generation: {e}")
        return False

def main():
    """Run all tests."""
    print(" Testing Dynamic AI Script Generation System")
    print("=" * 50)

    # Test configuration
    try:
        from intellicrack.core.config_manager import get_config
        config = get_config()
        ai_config = config.get("ai_script_generation", {})
        print(f"📋 LLM Backend: {ai_config.get('default_backend', 'openai')}")
        print(f"📋 Model: {ai_config.get('models', {}).get('openai', 'gpt-4')}")
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
