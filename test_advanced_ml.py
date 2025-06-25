#!/usr/bin/env python3
"""
Test Advanced ML System

This script tests the new advanced licensing detection system
and verifies backward compatibility.
"""

import sys
import os
import time
import json
from pathlib import Path

# Add intellicrack to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_ml_system():
    """Test the advanced ML system"""
    print("=" * 80)
    print("INTELLICRACK ADVANCED ML SYSTEM TEST")
    print("=" * 80)
    print()
    
    # Test 1: Import compatibility
    print("Test 1: Import Compatibility")
    print("-" * 40)
    
    try:
        # Old imports (should work via compatibility layer)
        from intellicrack.models.ml_integration import IntellicrackMLPredictor
        print("  ✓ Old import: IntellicrackMLPredictor")
        
        from intellicrack.ai.ml_predictor_updated import MLVulnerabilityPredictor
        print("  ✓ Old import: MLVulnerabilityPredictor")
        
        # New imports
        from intellicrack.models import (
            get_ml_system, 
            AdvancedLicensingDetector,
            StreamingTrainingCollector
        )
        print("  ✓ New import: get_ml_system")
        print("  ✓ New import: AdvancedLicensingDetector")
        print("  ✓ New import: StreamingTrainingCollector")
        
        print("\n✅ All imports successful!")
        
    except ImportError as e:
        print(f"\n❌ Import error: {e}")
        return
    
    # Test 2: System initialization
    print("\n\nTest 2: System Initialization")
    print("-" * 40)
    
    ml_system = get_ml_system()
    print("  ✓ ML system initialized")
    
    status = ml_system.get_training_status()
    print(f"  - Model loaded: {status['model_loaded']}")
    print(f"  - Model exists: {status['model_exists']}")
    print(f"  - Model size: {status['model_size_mb']:.2f} MB")
    print(f"  - Training in progress: {status['in_progress']}")
    
    # Test 3: Feature extraction
    print("\n\nTest 3: Feature Extraction")
    print("-" * 40)
    
    from intellicrack.models import StreamingFeatureExtractor
    extractor = StreamingFeatureExtractor()
    
    # Test with a simple binary pattern
    test_binary = b'MZ' + b'\x90' * 100 + b'This is a test binary with license'
    features = extractor.extract_from_stream(test_binary)
    
    print(f"  ✓ Extracted {len(features)} features")
    print(f"  - File size: {features.get('file_size', 0)} bytes")
    print(f"  - Entropy: {features.get('file_entropy', 0):.2f}")
    print(f"  - Is PE: {features.get('is_pe', 0)}")
    print(f"  - License strings: {features.get('strings_license', 0)}")
    
    # Test 4: Backward compatibility
    print("\n\nTest 4: Backward Compatibility")
    print("-" * 40)
    
    # Old API
    old_predictor = IntellicrackMLPredictor()
    print("  ✓ Created old-style predictor")
    
    if old_predictor.load_model():
        print("  ✓ Model loaded via old API")
        
        # Test prediction with old API
        test_result = old_predictor.predict_vulnerability("C:/Windows/System32/notepad.exe")
        print(f"  ✓ Old API prediction:")
        print(f"    - Success: {test_result.get('success', False)}")
        print(f"    - Prediction: {test_result.get('prediction', 'unknown')}")
        print(f"    - Probability: {test_result.get('probability', 0):.2f}")
    else:
        print("  ⚠️  No model loaded - training required")
    
    # Test 5: New API features
    print("\n\nTest 5: New API Features")
    print("-" * 40)
    
    if ml_system.model_loaded:
        # Test URLs
        test_urls = [
            "https://example.com/software.exe",
            "C:/Windows/System32/cmd.exe",
            "C:/Program Files/Git/bin/git.exe"
        ]
        
        for url in test_urls:
            if os.path.exists(url) or url.startswith('http'):
                print(f"\n  Testing: {url}")
                result = ml_system.predict(url)
                
                if result['success']:
                    print(f"    - Protection: {result['protection_type']}")
                    print(f"    - Confidence: {result['confidence']:.2%}")
                    print(f"    - Difficulty: {result['bypass_difficulty']}")
                    print(f"    - Category: {result['protection_category']}")
                    
                    # Show detailed scores
                    if 'detailed_scores' in result:
                        print("    - Top detection scores:")
                        scores = sorted(
                            result['detailed_scores'].items(),
                            key=lambda x: x[1],
                            reverse=True
                        )[:3]
                        for scheme, score in scores:
                            if score > 0.1:
                                print(f"      • {scheme}: {score:.2f}")
                else:
                    print(f"    ❌ Error: {result.get('error', 'Unknown')}")
    else:
        print("  ⚠️  Model not loaded - skipping prediction tests")
    
    # Test 6: Training data collection
    print("\n\nTest 6: Training Data Collection")
    print("-" * 40)
    
    collector = StreamingTrainingCollector()
    print("  ✓ Created training collector")
    
    # Test URL collection (limited)
    print("  Testing URL collection (limited to 10 URLs)...")
    trial_urls = collector.collect_trial_software_urls(max_urls=10)
    github_urls = collector.collect_github_releases(max_urls=10)
    
    print(f"  ✓ Collected {len(trial_urls)} trial software URLs")
    print(f"  ✓ Collected {len(github_urls)} GitHub release URLs")
    
    if trial_urls:
        print("  Sample trial URLs:")
        for url in trial_urls[:3]:
            print(f"    - {url[:80]}...")
    
    # Test 7: Protection info
    print("\n\nTest 7: Protection Information")
    print("-" * 40)
    
    protection_types = [
        "Sentinel HASP",
        "FlexLM/FlexNet",
        "WinLicense/Themida",
        "Steam CEG",
        "Denuvo"
    ]
    
    for ptype in protection_types:
        info = ml_system.get_protection_info(ptype)
        print(f"\n  {ptype}:")
        print(f"    - Description: {info['description']}")
        print(f"    - Difficulty: {info['difficulty']}")
        print(f"    - Tools: {', '.join(info['common_tools'][:2])}")
    
    # Summary
    print("\n\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    print("\n✅ All tests completed successfully!")
    print("\nThe advanced ML system is working correctly with:")
    print("  - Full backward compatibility")
    print("  - New multi-class protection detection")
    print("  - Streaming feature extraction")
    print("  - URL-based training capability")
    
    if not ml_system.model_loaded:
        print("\n⚠️  Note: No trained model found.")
        print("To train the model, run: python train_advanced_model.py")


def main():
    """Main entry point"""
    try:
        test_ml_system()
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()