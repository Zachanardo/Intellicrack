#!/usr/bin/env python3
import sys
sys.path.insert(0, r'C:\Intellicrack')

try:
    # Simple import test
    import intellicrack.core.anti_analysis.anti_debug_analyzer
    print("SUCCESS: anti_debug_analyzer module found and imported")
    
    import intellicrack.core.anti_analysis.anti_debug_integration  
    print("SUCCESS: anti_debug_integration module found and imported")
    
    # Test basic class instantiation
    from intellicrack.core.anti_analysis.anti_debug_analyzer import AntiDebugAnalyzer
    analyzer = AntiDebugAnalyzer()
    print("SUCCESS: AntiDebugAnalyzer instantiated")
    
except ImportError as e:
    print(f"Import Error: {e}")
except Exception as e:
    print(f"Error: {e}")