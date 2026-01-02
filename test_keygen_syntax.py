"""Quick syntax validation for keygen_generator.py."""

import sys
from pathlib import Path

try:
    import py_compile

    file_path = Path(__file__).parent / "intellicrack" / "core" / "exploitation" / "keygen_generator.py"

    print(f"Checking syntax of {file_path}...")
    py_compile.compile(str(file_path), doraise=True)
    print("✓ Syntax check passed!")

    print("\nAttempting import test...")
    sys.path.insert(0, str(Path(__file__).parent))

    from intellicrack.core.exploitation.keygen_generator import BinaryKeyValidator

    print("✓ Import successful!")
    print(f"✓ BinaryKeyValidator class available: {BinaryKeyValidator.__name__}")
    print(f"✓ BinaryKeyValidator methods: {[m for m in dir(BinaryKeyValidator) if not m.startswith('_')]}")

except SyntaxError as e:
    print(f"✗ Syntax error: {e}")
    sys.exit(1)
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"✗ Unexpected error: {e}")
    sys.exit(1)

print("\nAll checks passed!")
