#!/usr/bin/env python3
"""Debug import issues"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

def test_import(module_name, import_statement):
    """Test an import and report results"""
    try:
        print(f"Testing: {import_statement}")
        exec(import_statement)
        print(f"✓ SUCCESS: {module_name}")
        return True
    except Exception as e:
        print(f"✗ FAILED: {module_name} - {e}")
        return False

def main():
    """Test imports step by step"""
    print("Testing DIE JSON wrapper imports step by step...\n")
    
    imports_to_test = [
        ("basic imports", "import json, logging, time, os"),
        ("pathlib", "from pathlib import Path"),
        ("dataclasses", "from dataclasses import dataclass, field"),
        ("enum", "from enum import Enum"),
        ("typing", "from typing import Any, Dict, List, Optional, Union"),
        ("audit logger", "from intellicrack.core.logging.audit_logger import get_audit_logger"),
        ("DIE enums", "from intellicrack.core.analysis.die_json_wrapper import DIEScanMode"),
        ("DIE classes", "from intellicrack.core.analysis.die_json_wrapper import DIEDetection, DIEAnalysisResult"),
        ("DIE wrapper", "from intellicrack.core.analysis.die_json_wrapper import DIEJSONWrapper"),
        ("structured logger", "from intellicrack.core.analysis.die_structured_logger import get_die_structured_logger"),
    ]
    
    results = []
    for name, import_stmt in imports_to_test:
        result = test_import(name, import_stmt)
        results.append((name, result))
        print()
    
    print("=" * 50)
    print("Import Test Summary:")
    
    for name, success in results:
        status = "PASS" if success else "FAIL"
        print(f"  {name}: {status}")
    
    all_passed = all(result[1] for result in results)
    print(f"\nOverall: {'PASS' if all_passed else 'FAIL'}")

if __name__ == "__main__":
    main()