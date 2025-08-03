#!/usr/bin/env python3
"""Check pydantic installation and version."""

try:
    import pydantic
    print(f"Pydantic version: {pydantic.__version__}")
    
    try:
        from pydantic_settings import BaseSettings
        print("✓ pydantic_settings available")
    except ImportError:
        print("✗ pydantic_settings not available, using pydantic BaseSettings")
        from pydantic import BaseSettings
    
    print("✓ Pydantic imports successful")
    
except ImportError as e:
    print(f"✗ Pydantic import failed: {e}")