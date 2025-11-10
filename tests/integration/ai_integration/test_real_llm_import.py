#!/usr/bin/env python3
"""
Test script to verify that the dynamic LLM provider import actually works
with real LLM libraries.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_real_provider_import():
    """Test if we can actually import and initialize real LLM providers."""

    print("=== Testing Real LLM Provider Import ===\n")

    # Test OpenAI import
    try:
        import openai
        print("OK OpenAI module imported successfully")
        if os.environ.get("OPENAI_API_KEY"):
            client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
            print(f"   Client type: {type(client)}")
            print(f"   Has chat.completions: {hasattr(client, 'chat') and hasattr(client.chat, 'completions')}")
    except ImportError:
        print("FAIL OpenAI module not installed")
    except Exception as e:
        print(f"WARNING OpenAI import succeeded but initialization failed: {e}")

    # Test Anthropic import
    try:
        import anthropic
        print("\nOK Anthropic module imported successfully")
        if os.environ.get("ANTHROPIC_API_KEY"):
            client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
            print(f"   Client type: {type(client)}")
            print(f"   Has messages.create: {hasattr(client, 'messages') and hasattr(client.messages, 'create')}")
    except ImportError:
        print("\nFAIL Anthropic module not installed")
    except Exception as e:
        print(f"\nWARNING Anthropic import succeeded but initialization failed: {e}")

    # Test dynamic import pattern used in _try_initialize_provider
    print("\n=== Testing Dynamic Import Pattern ===\n")

    test_providers = ["openai", "anthropic", "groq", "together"]

    for provider_name in test_providers:
        print(f"Testing {provider_name}:")

        # This mimics what _try_initialize_provider does
        import_attempts = [
            provider_name,
            f"{provider_name}_sdk",
            f"{provider_name}ai",
            provider_name.replace("_", ""),
            provider_name.replace("-", "_"),
        ]

        imported = False
        for module_name in import_attempts:
            try:
                module = __import__(module_name)
                print(f"  OK Imported as '{module_name}'")
                print(f"     Module type: {type(module)}")

                # Check for client creation methods
                has_client = hasattr(module, 'Client')
                has_titled_client = hasattr(module, f'{provider_name.title()}Client')
                has_api_client = hasattr(module, 'APIClient')

                print(f"     Has Client: {has_client}")
                print(f"     Has {provider_name.title()}Client: {has_titled_client}")
                print(f"     Has APIClient: {has_api_client}")

                imported = True
                break
            except ImportError:
                continue

        if not imported:
            print(f"  FAIL Could not import {provider_name} with any pattern")
        print()

if __name__ == "__main__":
    test_real_provider_import()
