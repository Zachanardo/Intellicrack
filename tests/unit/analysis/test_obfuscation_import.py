#!/usr/bin/env python3
"""Test import of obfuscation pattern analyzer"""

try:
    from intellicrack.core.analysis.obfuscation_pattern_analyzer import ObfuscationPatternAnalyzer
    print("✓ Successfully imported ObfuscationPatternAnalyzer")
    
    from intellicrack.core.analysis.obfuscation_detectors.control_flow_detector import ControlFlowObfuscationDetector
    print("✓ Successfully imported ControlFlowObfuscationDetector")
    
    from intellicrack.core.analysis.obfuscation_detectors.string_obfuscation_detector import StringObfuscationDetector
    print("✓ Successfully imported StringObfuscationDetector")
    
    from intellicrack.core.analysis.obfuscation_detectors.api_obfuscation_detector import APIObfuscationDetector
    print("✓ Successfully imported APIObfuscationDetector")
    
    from intellicrack.core.analysis.obfuscation_detectors.virtualization_detector import VirtualizationDetector
    print("✓ Successfully imported VirtualizationDetector")
    
    from intellicrack.core.analysis.obfuscation_detectors.ml_obfuscation_classifier import MLObfuscationClassifier
    print("✓ Successfully imported MLObfuscationClassifier")
    
    print("\n🎉 All obfuscation pattern analyzer modules imported successfully!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    import traceback
    traceback.print_exc()
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()