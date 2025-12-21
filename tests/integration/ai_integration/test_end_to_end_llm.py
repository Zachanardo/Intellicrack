#!/usr/bin/env python3
"""
End-to-end test of the dynamic LLM interface.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from intellicrack.ai.ai_script_generator import LLMScriptInterface, ScriptGenerationRequest

def test_end_to_end():
    """Test the complete LLM interface end-to-end."""

    print("=== End-to-End LLM Interface Test ===\n")

    # Create the interface
    interface = LLMScriptInterface()

    if not interface.llm_backend:
        print("FAIL No LLM backend initialized")
        print("   Set OPENAI_API_KEY or ANTHROPIC_API_KEY to test")
        return

    print("OK LLM backend initialized")
    print(f"   Backend info: {interface.llm_backend}")

    # Check if it's a properly wrapped backend
    if isinstance(interface.llm_backend, dict):
        backend_type = interface.llm_backend.get("type")
        provider = interface.llm_backend.get("provider")

        print(f"   Type: {backend_type}")
        print(f"   Provider: {provider}")

        if "client" in interface.llm_backend:
            client = interface.llm_backend["client"]
            print(f"   Client type: {type(client)}")
            print(f"   Client is real object: {client is not None and not isinstance(client, dict)}")

    # Try to generate something
    print("\n=== Testing Script Generation ===\n")

    try:
        request = ScriptGenerationRequest(
            prompt="Write a simple Python script that prints 'Hello World'",
            script_type="python",
            binary_path=None
        )

        prompt = """Generate a Python script that prints 'Hello World'.

        Return your response as JSON with these fields:
        {
            "script_content": "the actual script code",
            "file_extension": "py"
        }"""

        result = interface.generate_script(request, prompt)
        print("OK Generation successful!")
        print(f"   Result type: {type(result)}")
        print(f"   Script content length: {len(result[0]) if isinstance(result, tuple) else 'N/A'}")
        print(f"   File extension: {result[1] if isinstance(result, tuple) and len(result) > 1 else 'N/A'}")

    except Exception as e:
        print(f"FAIL Generation failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_end_to_end()
