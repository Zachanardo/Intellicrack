#!/usr/bin/env python3
"""
ML System Demo - Showcase Advanced Licensing Detection

This script demonstrates all features of the new ML system with real examples.
"""

import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from intellicrack.models import (
    get_ml_system,
    get_current_model_info,
    AdvancedLicensingDetector,
    StreamingTrainingCollector,
    ProtectionScheme
)
from intellicrack.models.protection_knowledge_base import get_protection_knowledge_base


def print_banner(title: str):
    """Print a formatted banner"""
    print("\n" + "=" * 80)
    print(f" {title} ".center(80, "="))
    print("=" * 80 + "\n")


def demo_feature_extraction():
    """Demonstrate feature extraction capabilities"""
    print_banner("FEATURE EXTRACTION DEMO")
    
    from intellicrack.models import StreamingFeatureExtractor
    extractor = StreamingFeatureExtractor()
    
    # Create test binaries with different characteristics
    test_cases = [
        {
            "name": "Simple PE",
            "data": b'MZ' + b'\x90' * 100 + b'This program cannot be run in DOS mode',
            "expected": "Basic PE file"
        },
        {
            "name": "With License Strings",
            "data": b'MZ' + b'\x90' * 100 + b'License Key: XXXX-XXXX-XXXX-XXXX\nSerial Number Required',
            "expected": "License protected"
        },
        {
            "name": "With Protection Signatures",
            "data": b'MZ' + b'\x90' * 100 + b'hasp_login\x00hasplms.exe\x00Sentinel HASP',
            "expected": "Sentinel HASP protected"
        },
        {
            "name": "High Entropy (Packed)",
            "data": b'MZ' + os.urandom(1000),  # Random data = high entropy
            "expected": "Possibly packed/encrypted"
        }
    ]
    
    for test in test_cases:
        print(f"\nTest: {test['name']}")
        print("-" * 40)
        
        features = extractor.extract_from_stream(test['data'])
        
        print(f"Expected: {test['expected']}")
        print(f"Results:")
        print(f"  - File size: {features['file_size']} bytes")
        print(f"  - Entropy: {features['file_entropy']:.2f}")
        print(f"  - Is PE: {'Yes' if features['is_pe'] else 'No'}")
        print(f"  - License strings: {features.get('strings_license', 0)}")
        print(f"  - High entropy: {'Yes' if features.get('high_entropy', 0) else 'No'}")
        
        # Check protection detection
        protection_scores = {
            k.replace('scheme_', '').replace('_score', ''): v
            for k, v in features.items()
            if k.startswith('scheme_') and v > 0
        }
        
        if protection_scores:
            print(f"  - Detected protections:")
            for scheme, score in sorted(protection_scores.items(), key=lambda x: x[1], reverse=True):
                print(f"    • {scheme}: {score:.2f}")


def demo_protection_detection():
    """Demonstrate protection detection on real files"""
    print_banner("PROTECTION DETECTION DEMO")
    
    ml_system = get_ml_system()
    
    # Test files (Windows system files as examples)
    test_files = [
        {
            "path": "C:/Windows/System32/notepad.exe",
            "expected": "No protection (system utility)"
        },
        {
            "path": "C:/Windows/System32/cmd.exe",
            "expected": "No protection (system utility)"
        },
        {
            "path": "C:/Program Files/Git/bin/git.exe",
            "expected": "No protection (open source)"
        }
    ]
    
    print("Testing protection detection on real files:\n")
    
    for test_file in test_files:
        if os.path.exists(test_file['path']):
            print(f"File: {test_file['path']}")
            print(f"Expected: {test_file['expected']}")
            
            if ml_system.model_loaded:
                result = ml_system.predict(test_file['path'])
                
                if result['success']:
                    print(f"Detected:")
                    print(f"  - Protection: {result['protection_type']}")
                    print(f"  - Confidence: {result['confidence']:.2%}")
                    print(f"  - Category: {result['protection_category']}")
                    print(f"  - Bypass Difficulty: {result['bypass_difficulty']}")
                    
                    if result.get('detailed_scores'):
                        print(f"  - Top candidates:")
                        scores = sorted(
                            result['detailed_scores'].items(),
                            key=lambda x: x[1],
                            reverse=True
                        )[:3]
                        for scheme, score in scores:
                            if score > 0.1:
                                print(f"    • {scheme}: {score:.2f}")
                else:
                    print(f"  Error: {result.get('error', 'Unknown')}")
            else:
                print("  (Model not loaded - showing expected result)")
            
            print("-" * 60)
        else:
            print(f"File not found: {test_file['path']}")
            print("-" * 60)


def demo_knowledge_base():
    """Demonstrate protection knowledge base"""
    print_banner("PROTECTION KNOWLEDGE BASE DEMO")
    
    kb = get_protection_knowledge_base()
    
    # Show information about popular protection schemes
    protection_schemes = [
        "Sentinel HASP",
        "FlexLM",
        "WinLicense",
        "Steam CEG",
        "Denuvo"
    ]
    
    for scheme_name in protection_schemes:
        info = kb.get_protection_info(scheme_name)
        if info:
            print(f"\n{info.name}")
            print("=" * len(info.name))
            print(f"Vendor: {info.vendor}")
            print(f"Category: {info.category.value}")
            print(f"Difficulty: {info.bypass_difficulty.value}")
            print(f"\nDescription:")
            print(f"  {info.description}")
            print(f"\nCommon Applications:")
            for app in info.common_applications[:5]:
                print(f"  • {app}")
            print(f"\nBypass Techniques:")
            for technique in info.bypass_techniques[:2]:
                print(f"  • {technique.name}")
                print(f"    - Difficulty: {technique.difficulty.value}")
                print(f"    - Success Rate: {technique.success_rate:.0%}")
                print(f"    - Time: {technique.time_estimate}")
            
            # Estimate bypass time
            for skill in ["beginner", "intermediate", "expert"]:
                time_est = kb.estimate_bypass_time(scheme_name, skill)
                print(f"\nEstimated bypass time ({skill}): {time_est}")
            
            print("\n" + "-" * 80)


def demo_streaming_collection():
    """Demonstrate streaming URL collection"""
    print_banner("STREAMING DATA COLLECTION DEMO")
    
    collector = StreamingTrainingCollector()
    
    print("Demonstrating URL collection from legitimate sources:\n")
    
    # Collect a small sample
    print("1. Collecting trial software URLs (limited sample)...")
    trial_urls = collector.collect_trial_software_urls(max_urls=5)
    
    print(f"\nFound {len(trial_urls)} trial software URLs:")
    for i, url in enumerate(trial_urls[:3], 1):
        print(f"  {i}. {url[:80]}...")
    
    print("\n2. Collecting GitHub release URLs (limited sample)...")
    github_urls = collector.collect_github_releases(max_urls=5)
    
    print(f"\nFound {len(github_urls)} GitHub release URLs:")
    for i, url in enumerate(github_urls[:3], 1):
        print(f"  {i}. {url[:80]}...")
    
    # Show how labeling works
    print("\n3. Automatic labeling example:")
    
    test_urls = [
        "https://www.adobe.com/products/photoshop/trial.exe",
        "https://github.com/microsoft/vscode/releases/vscode-win32.exe",
        "https://store.steampowered.com/app/730/counter-strike.exe",
        "https://download.oracle.com/java/jdk-17.exe"
    ]
    
    all_urls = {"test": test_urls}
    labeled_urls, labels = collector.create_labeled_dataset(all_urls)
    
    print("\nURL -> Label mapping:")
    for url, label in zip(test_urls, labels[:len(test_urls)]):
        protection_map = {
            0: "No Protection",
            1: "Sentinel HASP",
            2: "FlexLM/FlexNet",
            6: "Steam CEG",
            8: "Microsoft Activation",
            9: "Custom/Unknown"
        }
        print(f"  • {url.split('/')[-1]}")
        print(f"    Label: {label} ({protection_map.get(label, 'Unknown')})")


def demo_backward_compatibility():
    """Demonstrate backward compatibility"""
    print_banner("BACKWARD COMPATIBILITY DEMO")
    
    print("Testing that old code still works with new system:\n")
    
    # Old-style import and usage
    print("1. Old import style:")
    print("   from intellicrack.models.ml_integration import IntellicrackMLPredictor")
    
    from intellicrack.models.ml_integration import IntellicrackMLPredictor
    old_predictor = IntellicrackMLPredictor()
    print("   ✓ Import successful")
    
    print("\n2. Old API usage:")
    print("   predictor.load_model()")
    loaded = old_predictor.load_model()
    print(f"   ✓ Model loaded: {loaded}")
    
    if loaded:
        print("\n3. Old prediction method:")
        print("   result = predictor.predict_vulnerability('test.exe')")
        
        # Test with a dummy path
        result = old_predictor.predict_vulnerability("C:/Windows/System32/calc.exe")
        
        print("   ✓ Prediction returned:")
        print(f"     - Success: {result.get('success', False)}")
        print(f"     - Prediction: {result.get('prediction', 'unknown')}")
        print(f"     - Vulnerability Type: {result.get('vulnerability_type', 'unknown')}")
    
    print("\n4. New API with enhanced features:")
    from intellicrack.models import get_ml_system
    ml_system = get_ml_system()
    
    print("   ml_system = get_ml_system()")
    print("   ✓ New system initialized")
    
    if ml_system.model_loaded:
        print("\n   Enhanced prediction:")
        result = ml_system.predict("C:/Windows/System32/calc.exe")
        print(f"     - Protection Type: {result.get('protection_type', 'Unknown')}")
        print(f"     - Confidence: {result.get('confidence', 0):.2%}")
        print(f"     - Bypass Difficulty: {result.get('bypass_difficulty', 'Unknown')}")
        print(f"     - Category: {result.get('protection_category', 'unknown')}")


def demo_model_info():
    """Show current model information"""
    print_banner("CURRENT MODEL INFORMATION")
    
    model_info = get_current_model_info()
    
    print(f"Model Type: {model_info['type']}")
    print(f"Status: {'Loaded' if model_info['loaded'] else 'Not Loaded'}")
    print(f"Exists: {'Yes' if model_info['exists'] else 'No'}")
    print(f"Size: {model_info['size_mb']:.2f} MB")
    
    print("\nCapabilities:")
    for capability in model_info['capabilities']:
        print(f"  ✓ {capability}")
    
    ml_system = get_ml_system()
    status = ml_system.get_training_status()
    
    print(f"\nTraining Status:")
    print(f"  - In Progress: {status['in_progress']}")
    print(f"  - Model Loaded: {status['model_loaded']}")
    
    if ml_system.model_loaded:
        # Show feature importance
        print("\nTop Important Features:")
        importance = ml_system.get_feature_importance()
        
        if importance:
            for i, (feature, score) in enumerate(list(importance.items())[:10], 1):
                print(f"  {i}. {feature}: {score:.4f}")


def main():
    """Run all demos"""
    print("=" * 80)
    print(" INTELLICRACK ADVANCED ML SYSTEM DEMONSTRATION ".center(80))
    print("=" * 80)
    
    demos = [
        ("Model Information", demo_model_info),
        ("Feature Extraction", demo_feature_extraction),
        ("Protection Detection", demo_protection_detection),
        ("Knowledge Base", demo_knowledge_base),
        ("Streaming Collection", demo_streaming_collection),
        ("Backward Compatibility", demo_backward_compatibility)
    ]
    
    for i, (name, demo_func) in enumerate(demos, 1):
        print(f"\n[{i}/{len(demos)}] Running: {name}")
        try:
            demo_func()
        except Exception as e:
            print(f"\nError in {name} demo: {e}")
            import traceback
            traceback.print_exc()
    
    print_banner("DEMONSTRATION COMPLETE")
    
    print("The advanced ML system provides:")
    print("  • Multi-class protection classification (10+ types)")
    print("  • 200+ advanced features including code analysis")
    print("  • Streaming training without local storage")
    print("  • Comprehensive protection knowledge base")
    print("  • Full backward compatibility")
    print("  • Production-ready performance")
    
    print("\nTo train the model, run: python train_advanced_model.py")
    print("To run benchmarks, run: python -m intellicrack.models.ml_benchmark")


if __name__ == "__main__":
    main()