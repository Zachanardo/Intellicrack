#!/usr/bin/env python3
"""
Test if the Anthropic client generation pattern works.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_anthropic_generation():
    """Test if we can generate with Anthropic using the pattern in _try_anthropic_style."""

    print("=== Testing Anthropic Generation Pattern ===\n")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("FAIL No ANTHROPIC_API_KEY set")
        return

    import anthropic
    client = anthropic.Anthropic(api_key=api_key)

    print(f"OK Client created: {type(client)}")
    print(f"   Has messages: {hasattr(client, 'messages')}")
    print(f"   Has messages.create: {hasattr(client, 'messages') and hasattr(client.messages, 'create')}")

    # Test actual generation
    try:
        response = client.messages.create(
            model="claude-3-opus-20240229",
            messages=[{"role": "user", "content": "Say 'Hello World' in Python"}],
            max_tokens=100,
            temperature=0.3
        )
        print(f"\nOK Generation successful!")
        print(f"   Response type: {type(response)}")
        print(f"   Has content: {hasattr(response, 'content')}")

        if hasattr(response, 'content') and response.content:
            text = response.content[0].text
            print(f"   Text: {text[:100]}...")
    except Exception as e:
        print(f"\nFAIL Generation failed: {e}")

if __name__ == "__main__":
    test_anthropic_generation()
