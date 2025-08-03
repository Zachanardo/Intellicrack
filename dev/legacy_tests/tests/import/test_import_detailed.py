#!/usr/bin/env python
"""Detailed import test with verbose tracing"""

import sys
import os

# Configure TensorFlow to prevent GPU initialization issues
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

# Enable import tracing
import importlib.util
import types

class ImportTracer:
    def __init__(self):
        self.depth = 0
        self.imports = []

    def find_spec(self, name, path, target=None):
        indent = "  " * self.depth
        print(f"{indent}→ Importing: {name}", flush=True)
        self.imports.append((self.depth, name))
        self.depth += 1
        return None

    def find_module(self, name, path=None):
        return None

tracer = ImportTracer()
sys.meta_path.insert(0, tracer)

print("[TRACE] Starting detailed import trace...")
print("[TRACE] This will show every module being imported...")
print("-" * 60)

try:
    import intellicrack
    print("\n[TRACE] Successfully imported intellicrack base package")
except Exception as e:
    print(f"\n[TRACE] Failed at intellicrack import: {e}")
    sys.exit(1)

print("\n[TRACE] Now attempting to import intellicrack.ui...")
try:
    import intellicrack.ui
    print("\n[TRACE] Successfully imported intellicrack.ui")
except Exception as e:
    print(f"\n[TRACE] Failed at intellicrack.ui import: {e}")

print("\n[TRACE] Last 10 imports before failure/success:")
for depth, name in tracer.imports[-10:]:
    print(f"  {'  ' * depth}{name}")
