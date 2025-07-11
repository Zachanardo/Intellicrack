#!/usr/bin/env python3
import sys

# Block tensorflow import temporarily
class FakeModule:
    def __getattr__(self, name):
        return self

sys.modules['tensorflow'] = FakeModule()
sys.modules['tf'] = FakeModule()

print("Starting test with TensorFlow blocked...")

try:
    from intellicrack.ui.main_app import launch
    print("Launch imported successfully")
    result = launch()
    print(f"Launch returned: {result}")
except Exception as e:
    print(f"ERROR: {e}")
    import traceback
    traceback.print_exc()