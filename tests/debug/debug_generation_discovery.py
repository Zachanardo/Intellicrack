#!/usr/bin/env python3
"""
Debug why generation method discovery fails.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def debug_generation_discovery():
    """Debug the generation method discovery process."""

    print("=== Debugging Generation Method Discovery ===\n")

    # Simulate what happens in _call_dynamic_provider
    import anthropic
    api_key = os.environ.get("ANTHROPIC_API_KEY", "test-key")
    client = anthropic.Anthropic(api_key=api_key)

    print(f"Client type: {type(client)}")

    # Test _try_anthropic_style pattern
    print("\n1. Testing Anthropic-style pattern:")
    print(f"   Has messages: {hasattr(client, 'messages')}")
    print(f"   Has messages.create: {hasattr(client.messages, 'create') if hasattr(client, 'messages') else False}")

    # This is what _try_anthropic_style checks
    if hasattr(client, 'messages') and hasattr(client.messages, 'create'):
        print("   ✅ Should work with _try_anthropic_style")
    else:
        print("   ❌ Won't work with _try_anthropic_style")

    # Test _try_openai_style pattern
    print("\n2. Testing OpenAI-style pattern:")
    print(f"   Has chat: {hasattr(client, 'chat')}")
    print(f"   Has chat.completions: {hasattr(client.chat, 'completions') if hasattr(client, 'chat') else False}")

    # Test other patterns
    print("\n3. Testing other patterns:")
    print(f"   Has chat method: {hasattr(client, 'chat')}")
    print(f"   Has generate method: {hasattr(client, 'generate')}")
    print(f"   Has complete method: {hasattr(client, 'complete')}")

    # Test with OpenAI too
    print("\n=== Testing OpenAI Client ===\n")
    try:
        import openai
        openai_key = os.environ.get("OPENAI_API_KEY", "test-key")
        openai_client = openai.OpenAI(api_key=openai_key)

        print(f"Client type: {type(openai_client)}")
        print(f"Has chat: {hasattr(openai_client, 'chat')}")
        print(f"Has chat.completions: {hasattr(openai_client.chat, 'completions') if hasattr(openai_client, 'chat') else False}")

        if hasattr(openai_client, 'chat') and hasattr(openai_client.chat, 'completions'):
            print("✅ Should work with _try_openai_style")
    except ImportError:
        print("OpenAI not installed")

if __name__ == "__main__":
    debug_generation_discovery()
