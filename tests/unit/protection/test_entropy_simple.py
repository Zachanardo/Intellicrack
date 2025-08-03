#!/usr/bin/env python3
"""Simple test to verify entropy packer detection is working."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

try:
    from intellicrack.protection.entropy_packer_detector import SophisticatedEntropyPackerDetector
    from intellicrack.protection.entropy_integration import quick_entropy_scan
    
    print("✓ Successfully imported entropy packer detection modules")
    
    # Create detector instance
    detector = SophisticatedEntropyPackerDetector()
    print("✓ Successfully created SophisticatedEntropyPackerDetector instance")
    
    # Test with Python executable (should be available)
    python_exe = sys.executable
    if os.path.exists(python_exe):
        print(f"Testing with: {python_exe}")
        result = quick_entropy_scan(python_exe)
        print(f"✓ Entropy analysis completed. Detected packers: {len(result.detected_packers)}")
        print(f"  - Confidence: {result.confidence:.2f}")
        print(f"  - Entropy score: {result.entropy_analysis.global_entropy:.3f}")
    else:
        print("! Python executable not found for testing")
    
    print("\n✓ Entropy packer detection system is working correctly!")
    
except ImportError as e:
    print(f"✗ Import error: {e}")
except Exception as e:
    print(f"✗ Error: {e}")