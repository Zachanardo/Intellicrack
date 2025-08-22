#!/usr/bin/env python3
"""
Test the actual generation flow to find where it breaks.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def _try_anthropic_style(client, prompt: str, model, max_tokens: int, temp: float):
    """Exact copy of the _try_anthropic_style method."""
    if hasattr(client, 'messages') and hasattr(client.messages, 'create'):
        try:
            response = client.messages.create(
                model=model or "claude-3-opus-20240229",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temp
            )
            return response.content[0].text
        except Exception as e:
            print(f"   Exception in _try_anthropic_style: {e}")
            return None
    return None

def test_actual_flow():
    """Test the actual generation flow."""

    print("=== Testing Actual Generation Flow ===\n")

    # Create the backend like _try_initialize_provider does
    import anthropic
    api_key = os.environ.get("ANTHROPIC_API_KEY", "test-key")

    # First, test the module import and client creation
    module = anthropic
    client = anthropic.Anthropic(api_key=api_key)

    backend = {
        "type": "dynamic",
        "provider": "anthropic",
        "client": client,
        "module": module
    }

    print(f"Backend created: {backend['type']}, {backend['provider']}")
    print(f"Client type: {type(backend['client'])}")

    # Now test generation like _call_dynamic_provider does
    prompt = "Say 'Hello World' in Python"
    model = None
    max_tokens = 100
    temperature = 0.3

    print("\nTrying _try_anthropic_style:")
    result = _try_anthropic_style(backend["client"], prompt, model, max_tokens, temperature)

    if result:
        print(f"✅ Generation successful: {result[:100]}...")
    else:
        print(f"❌ Generation returned None")

    # Test with a valid API key if available
    if os.environ.get("ANTHROPIC_API_KEY") and os.environ.get("ANTHROPIC_API_KEY") != "test-key":
        print("\n=== With Real API Key ===")
        real_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        result = _try_anthropic_style(real_client, prompt, model, max_tokens, temperature)
        if result:
            print(f"✅ Generation successful: {result[:100]}...")
        else:
            print(f"❌ Generation returned None even with real API key")

if __name__ == "__main__":
    test_actual_flow()
