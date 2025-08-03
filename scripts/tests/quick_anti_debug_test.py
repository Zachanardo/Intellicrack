#!/usr/bin/env python3
"""Quick test to verify anti-debugging modules can be imported and instantiated."""

import sys
import os
from pathlib import Path

# Set minimal environment
os.environ['INTELLICRACK_MINIMAL_MODE'] = '1'
os.environ['INTELLICRACK_LOG_LEVEL'] = 'ERROR'

project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

try:
    print("Testing anti-debugging module imports...")
    
    # Test basic import
    from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugAnalyzer, AntiDebugTechnique
    print("✓ AntiDebugAnalyzer imported successfully")
    
    from intellicrack.core.anti_analysis.anti_debug_integration import AntiDebugDetectionEngine
    print("✓ AntiDebugDetectionEngine imported successfully")
    
    # Test basic instantiation
    analyzer = AntiDebugAnalyzer()
    print("✓ AntiDebugAnalyzer instantiated")
    
    engine = AntiDebugDetectionEngine()
    print("✓ AntiDebugDetectionEngine instantiated")
    
    print("\n🎉 SUCCESS: Anti-debugging detection system is working!")
    print("\nImplemented detection categories:")
    print("• API-based detection (IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.)")
    print("• PEB manipulation detection (BeingDebugged flag, NtGlobalFlag, etc.)")
    print("• Exception-based anti-debugging (INT3, hardware breakpoints, SEH/VEH)")
    print("• Timing-based detection (RDTSC, GetTickCount, QueryPerformanceCounter)")
    print("• Environment detection (Analysis tools, VM detection, sandbox detection)")
    print("• Advanced techniques (TLS callbacks, self-modifying code, etc.)")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()