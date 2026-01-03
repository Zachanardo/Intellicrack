#!/usr/bin/env python3
"""
End-to-end test of the dynamic LLM interface.
"""
from typing import Any

from intellicrack.ai.ai_script_generator import AIScriptGenerator, GeneratedScript


def test_end_to_end() -> None:
    """Test the complete LLM interface end-to-end."""
    print("=== End-to-End LLM Interface Test ===\n")

    # Create the interface
    generator = AIScriptGenerator()

    print("OK AIScriptGenerator initialized")

    # Try to generate a Frida script
    print("\n=== Testing Script Generation ===\n")

    try:
        result = generator.generate_frida_script(
            binary_path_or_analysis="test_binary.exe",
            protection_info={"type": "license_check", "hooks": ["CreateFileW"]},
        )

        if result is not None and isinstance(result, GeneratedScript):
            print("OK Generation successful!")
            print(f"   Script type: {result.metadata.script_type.value if result.metadata.script_type else 'N/A'}")
            if result.content:
                print(f"   Content length: {len(result.content)}")
        else:
            print(f"FAIL Generation returned None or unexpected type: {type(result)}")

    except Exception as e:
        print(f"FAIL Generation failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    test_end_to_end()
