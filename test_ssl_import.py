"""Test script to validate ssl_interceptor.py imports and syntax."""

import sys
import traceback

def test_imports():
    """Test that the module can be imported."""
    try:
        print("Testing import of ssl_interceptor module...")
        from intellicrack.core.network import ssl_interceptor
        print("✓ Module imported successfully")

        print("\nTesting class instantiation...")
        print("  - JWTTokenModifier")
        jwt_mod = ssl_interceptor.JWTTokenModifier()
        print("    ✓ JWTTokenModifier instantiated")

        print("  - SSLTLSInterceptor")
        interceptor = ssl_interceptor.SSLTLSInterceptor()
        print("    ✓ SSLTLSInterceptor instantiated")

        print("\n✓ All basic tests passed")
        return True

    except Exception as e:
        print(f"\n✗ Error during testing: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_imports()
    sys.exit(0 if success else 1)
