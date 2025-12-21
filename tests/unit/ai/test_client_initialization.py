#!/usr/bin/env python3
"""
Test script to verify that the client initialization patterns work correctly.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_client_initialization():
    """Test if client initialization patterns match real LLM libraries."""

    print("=== Testing Client Initialization Patterns ===\n")

    # Test OpenAI
    try:
        import openai
        print("Testing OpenAI client initialization:")

        # Pattern 1: getattr(module, 'Client')(api_key=api_key)
        try:
            ClientClass = getattr(openai, 'Client')
            print(f"  FAIL Has 'Client' attribute but it's: {ClientClass}")
        except AttributeError:
            print("  OK No 'Client' attribute (correct)")

        # Check actual pattern for OpenAI
        if hasattr(openai, 'OpenAI'):
            print("  OK Has 'OpenAI' class (actual client class)")
            if os.environ.get("OPENAI_API_KEY"):
                client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
                print(f"  OK Successfully created client: {type(client)}")

    except ImportError:
        print("OpenAI not installed")

    print()

    # Test Anthropic
    try:
        import anthropic
        print("Testing Anthropic client initialization:")

        # Pattern 1: getattr(module, 'Client')(api_key=api_key)
        try:
            ClientClass = getattr(anthropic, 'Client')
            print(f"  FAIL Has 'Client' attribute but it's: {ClientClass}")
        except AttributeError:
            print("  OK No 'Client' attribute (correct)")

        # Check actual pattern for Anthropic
        if hasattr(anthropic, 'Anthropic'):
            print("  OK Has 'Anthropic' class (actual client class)")
            if os.environ.get("ANTHROPIC_API_KEY"):
                client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
                print(f"  OK Successfully created client: {type(client)}")

    except ImportError:
        print("Anthropic not installed")

    print("\n=== Issue Identified ===")
    print("The _try_initialize_provider method looks for 'Client' class,")
    print("but real providers use 'OpenAI' and 'Anthropic' as class names.")
    print("This needs to be fixed for proper initialization!")

if __name__ == "__main__":
    test_client_initialization()
