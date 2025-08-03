#!/usr/bin/env python3
"""Test script for the Predictive Intelligence system."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

try:
    from intellicrack.ai.predictive_intelligence import (
        PredictiveIntelligenceEngine,
        BinaryFeatures,
        predict_protection_type,
        predict_vulnerabilities,
        recommend_bypass_strategy,
        detect_anomalies,
        PredictionType,
        PredictionConfidence,
        ProtectionFamily,
        VulnerabilityClass,
        BypassStrategy
    )
    
    print("✅ All imports successful!")
    
    # Test BinaryFeatures creation
    features = BinaryFeatures(
        file_size=1024000,
        entropy=7.5,
        section_count=8,
        import_count=150,
        export_count=20,
        string_count=500,
        packed=True,
        signed=False,
        architecture="x64",
        compiler="msvc",
        protection_indicators=["vmp0", "vmp1"],
        api_calls=["VirtualProtect", "VirtualAlloc", "CreateThread"],
        suspicious_strings=["VMProtect", "AntiDebug"],
        control_flow_complexity=0.8,
        code_obfuscation_level=0.9
    )
    print("✅ BinaryFeatures created successfully!")
    
    # Test protection type prediction
    try:
        protection_result = predict_protection_type(features)
        print(f"✅ Protection prediction: {protection_result.predicted_value} (confidence: {protection_result.confidence.value})")
    except Exception as e:
        print(f"❌ Protection prediction failed: {e}")
    
    # Test vulnerability prediction
    try:
        vuln_result = predict_vulnerabilities(features)
        print(f"✅ Vulnerability prediction: {vuln_result.predicted_value} (confidence: {vuln_result.confidence_score:.3f})")
    except Exception as e:
        print(f"❌ Vulnerability prediction failed: {e}")
    
    # Test bypass strategy recommendation
    try:
        bypass_result = recommend_bypass_strategy("vmprotect", features)
        print(f"✅ Bypass strategy: {bypass_result.predicted_value} (confidence: {bypass_result.confidence.value})")
    except Exception as e:
        print(f"❌ Bypass strategy failed: {e}")
    
    # Test anomaly detection
    try:
        anomaly_result = detect_anomalies(features)
        print(f"✅ Anomaly detection: {anomaly_result.predicted_value} (confidence: {anomaly_result.confidence.value})")
    except Exception as e:
        print(f"❌ Anomaly detection failed: {e}")
    
    # Test comprehensive analysis
    try:
        engine = PredictiveIntelligenceEngine()
        comprehensive_results = engine.analyze_binary_comprehensive("/test/binary.exe", features)
        print(f"✅ Comprehensive analysis completed with {len(comprehensive_results)} predictions")
        
        for pred_type, result in comprehensive_results.items():
            print(f"   - {pred_type}: {result.predicted_value} (conf: {result.confidence_score:.3f})")
    except Exception as e:
        print(f"❌ Comprehensive analysis failed: {e}")
    
    print("\n🎉 Predictive Intelligence system verification completed!")
    
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Test failed: {e}")
    sys.exit(1)