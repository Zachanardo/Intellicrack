#!/usr/bin/env python
"""Test to identify which import is causing the hang"""

import sys
import os

# Configure TensorFlow to prevent GPU initialization issues
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

def test_import(module_path, description):
    """Test importing a module and report success/failure"""
    print(f"\n[IMPORT TEST] {description}")
    print(f"[IMPORT TEST] Importing {module_path}...", flush=True)
    try:
        if '.' in module_path:
            parts = module_path.split('.')
            module = __import__(module_path, fromlist=[parts[-1]])
        else:
            module = __import__(module_path)
        print(f"[IMPORT TEST] ✓ Successfully imported {module_path}")
        return True
    except Exception as e:
        print(f"[IMPORT TEST] ✗ Failed to import {module_path}: {e}")
        import traceback
        traceback.print_exc()
        return False

print("[IMPORT TEST] Starting import chain test...")

# Test core imports
test_import("intellicrack", "Base package")
test_import("intellicrack.utils", "Utils package")
test_import("intellicrack.utils.core", "Core utils")
test_import("intellicrack.utils.core.common_imports", "Common imports")

# Test UI imports
test_import("intellicrack.ui", "UI package")

print("\n[IMPORT TEST] Testing specific UI modules...")
test_import("intellicrack.ui.common_imports", "UI common imports")
test_import("intellicrack.ui.widgets", "UI widgets")
test_import("intellicrack.ui.dialogs", "UI dialogs")
test_import("intellicrack.ui.tabs", "UI tabs")

print("\n[IMPORT TEST] Testing main_app import...")
test_import("intellicrack.ui.main_app", "Main app module")

print("\n[IMPORT TEST] Test complete!")