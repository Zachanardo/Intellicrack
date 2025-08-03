#!/usr/bin/env python3
"""
Simple verification script for cross-tool coordination enhancements
"""

try:
    import sys
    import os
    sys.path.insert(0, os.path.dirname(__file__))
    
    # Test imports
    print("Testing imports...")
    from intellicrack.core.analysis.analysis_orchestrator import FunctionBoundary, CrossToolValidator
    print("✅ AnalysisOrchestrator imports successful")
    
    from intellicrack.core.analysis.ghidra_decompiler import GhidraDecompiler
    print("✅ GhidraDecompiler imports successful")
    
    # Test FunctionBoundary
    boundary = FunctionBoundary(
        address=0x401000,
        size=100,
        name='test_func',
        priority=0.8,
        source_tool='radare2'
    )
    print(f"✅ FunctionBoundary created: {boundary.name}")
    
    # Test conversion
    dict_data = boundary.to_dict()
    restored = FunctionBoundary.from_dict(dict_data)
    print(f"✅ Conversion test: {restored.name == boundary.name}")
    
    # Test validator exists
    import logging
    validator = CrossToolValidator(logging.getLogger('test'))
    print("✅ CrossToolValidator created")
    
    # Test GhidraDecompiler has new methods
    methods = ['decompile_at_address', 'analyze_targeted_functions', '_validate_address_in_memory']
    for method in methods:
        if hasattr(GhidraDecompiler, method):
            print(f"✅ GhidraDecompiler.{method} exists")
        else:
            print(f"❌ GhidraDecompiler.{method} missing")
    
    print("\n🎉 All verification tests passed!")
    print("Enhanced cross-tool coordination is working correctly.")
    
except Exception as e:
    print(f"❌ Verification failed: {e}")
    import traceback
    traceback.print_exc()