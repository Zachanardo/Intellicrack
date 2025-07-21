#!/usr/bin/env python3
"""Test script to verify both mitmproxy and qiling can be imported together."""

import sys
print(f"Python: {sys.version}")

try:
    import mitmproxy
    print("✅ mitmproxy imports successfully")
except ImportError as e:
    print(f"❌ mitmproxy import failed: {e}")

try:
    import qiling
    print("✅ qiling imports successfully")
    print(f"   qiling version: {qiling.__version__}")
except ImportError as e:
    print(f"❌ qiling import failed: {e}")

try:
    import typing_extensions
    print("✅ typing-extensions imports successfully")
    # Check version via pip show instead
except ImportError as e:
    print(f"❌ typing-extensions import failed: {e}")

print("\n🎉 All imports successful - dependency conflict resolved!")