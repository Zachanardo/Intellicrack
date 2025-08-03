#!/usr/bin/env python3
"""Example demonstrating integration of Predictive Intelligence with AI Script Generator.

This example shows how the predictive intelligence system enhances script generation
by providing protection type prediction, vulnerability assessment, and bypass strategy
recommendations before script generation begins.

Copyright (C) 2025 Zachary Flint
"""

import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from intellicrack.ai.predictive_intelligence import (
    BinaryFeatures,
    PredictiveIntelligenceEngine,
    analyze_binary_comprehensive,
    predict_protection_type,
    recommend_bypass_strategy
)
from intellicrack.ai.ai_script_generator import AIScriptGenerator, ScriptType


def enhanced_script_generation_workflow(binary_path: str, binary_features: BinaryFeatures):
    """Demonstrate enhanced script generation with predictive intelligence."""
    
    print("🔮 Enhanced AI Script Generation with Predictive Intelligence")
    print("=" * 60)
    
    # Initialize components
    predictor = PredictiveIntelligenceEngine()
    script_generator = AIScriptGenerator()
    
    # Step 1: Comprehensive Predictive Analysis
    print("\n1. Performing comprehensive predictive analysis...")
    
    predictions = analyze_binary_comprehensive(binary_path, binary_features)
    
    for prediction_type, result in predictions.items():
        print(f"   {prediction_type}: {result.predicted_value}")
        print(f"   Confidence: {result.confidence.value} ({result.confidence_score:.3f})")
        print(f"   Reasoning: {result.reasoning}")
        if result.recommendations:
            print(f"   Recommendations: {', '.join(result.recommendations[:2])}")
        print()
    
    # Step 2: Extract Key Predictions
    protection_type = predictions.get('protection_type', {}).predicted_value or 'unknown'
    vulnerability_info = predictions.get('vulnerabilities', {})
    bypass_strategy = predictions.get('bypass_strategy', {}).predicted_value or 'static_analysis'
    threat_level = predictions.get('threat_intelligence', {}).threat_level or 'medium'
    
    print(f"2. Key Predictions Summary:")
    print(f"   Protection Type: {protection_type}")
    print(f"   Primary Vulnerability: {vulnerability_info.predicted_value if vulnerability_info else 'Unknown'}")
    print(f"   Recommended Strategy: {bypass_strategy}")
    print(f"   Threat Level: {threat_level}")
    
    # Step 3: Generate Enhanced Analysis Context
    analysis_context = {
        "binary_path": binary_path,
        "predicted_protection": protection_type,
        "bypass_strategy": bypass_strategy,
        "threat_level": threat_level,
        "vulnerability_likelihood": vulnerability_info.confidence_score if vulnerability_info else 0.5,
        "analysis_depth": "comprehensive" if threat_level in ['high', 'critical'] else "standard",
        "special_considerations": []
    }
    
    # Add special considerations based on predictions
    if predictions.get('anomaly_detection', {}).predicted_value == 'anomalous':
        analysis_context["special_considerations"].append("anomalous_protection_detected")
    
    if threat_level in ['high', 'critical']:
        analysis_context["special_considerations"].append("high_threat_level")
    
    if binary_features.code_obfuscation_level > 0.8:
        analysis_context["special_considerations"].append("heavy_obfuscation")
    
    print(f"\n3. Enhanced Analysis Context:")
    print(f"   Analysis Depth: {analysis_context['analysis_depth']}")
    print(f"   Special Considerations: {', '.join(analysis_context['special_considerations']) or 'None'}")
    
    # Step 4: Generate Predictive-Enhanced Scripts
    print(f"\n4. Generating enhanced scripts based on predictions...")
    
    # Generate Frida script with predictive enhancements
    frida_context = {
        **analysis_context,
        "script_type": "frida",
        "target_apis": _get_target_apis_for_protection(protection_type),
        "bypass_techniques": _get_bypass_techniques_for_strategy(bypass_strategy),
        "protection_specific_hooks": _get_protection_specific_hooks(protection_type)
    }
    
    print(f"   Frida Script Context:")
    print(f"     Target APIs: {', '.join(frida_context['target_apis'][:3])}...")
    print(f"     Bypass Techniques: {', '.join(frida_context['bypass_techniques'][:2])}...")
    
    # Generate Ghidra script with predictive enhancements
    ghidra_context = {
        **analysis_context,
        "script_type": "ghidra",
        "analysis_functions": _get_analysis_functions_for_protection(protection_type),
        "deobfuscation_priority": binary_features.code_obfuscation_level > 0.7,
        "vulnerability_focus_areas": _get_vulnerability_focus_areas(vulnerability_info.predicted_value if vulnerability_info else 'safe')
    }
    
    print(f"   Ghidra Script Context:")
    print(f"     Analysis Functions: {', '.join(ghidra_context['analysis_functions'][:2])}...")
    print(f"     Deobfuscation Priority: {ghidra_context['deobfuscation_priority']}")
    
    # Step 5: Generate Scripts with Enhanced Context
    try:
        # This would normally generate actual scripts using the AI script generator
        # For this example, we'll show the enhanced context that would be used
        
        enhanced_frida_script = generate_enhanced_frida_script(frida_context)
        enhanced_ghidra_script = generate_enhanced_ghidra_script(ghidra_context)
        
        print(f"\n5. Generated Enhanced Scripts:")
        print(f"   Frida Script: {len(enhanced_frida_script)} lines")
        print(f"   Ghidra Script: {len(enhanced_ghidra_script)} lines")
        
        # Step 6: Predictive Success Estimation
        success_prediction = predictor.success_predictor.predict_success_probability(
            "script_generation", analysis_context
        )
        
        print(f"\n6. Success Prediction:")
        print(f"   Estimated Success Rate: {success_prediction.predicted_value:.1%}")
        print(f"   Confidence: {success_prediction.confidence.value}")
        print(f"   Key Factors: {', '.join(list(success_prediction.factors.keys())[:3])}")
        
        return {
            "predictions": predictions,
            "enhanced_context": analysis_context,
            "frida_script": enhanced_frida_script,
            "ghidra_script": enhanced_ghidra_script,
            "success_prediction": success_prediction
        }
        
    except Exception as e:
        print(f"   ❌ Error generating scripts: {e}")
        return None


def generate_enhanced_frida_script(context: dict) -> list:
    """Generate enhanced Frida script based on predictive context."""
    script_lines = [
        "// Enhanced Frida Script Generated with Predictive Intelligence",
        f"// Target Protection: {context['predicted_protection']}",
        f"// Bypass Strategy: {context['bypass_strategy']}",
        f"// Threat Level: {context['threat_level']}",
        "",
        "Java.perform(function() {",
        "    console.log('[+] Enhanced Frida script loaded');",
        ""
    ]
    
    # Add protection-specific hooks
    for hook in context['protection_specific_hooks']:
        script_lines.extend([
            f"    // {hook} protection bypass",
            f"    try {{",
            f"        // Hook implementation for {hook}",
            f"        console.log('[+] {hook} hook installed');",
            f"    }} catch(e) {{",
            f"        console.log('[-] Failed to hook {hook}');",
            f"    }}",
            ""
        ])
    
    # Add bypass techniques
    for technique in context['bypass_techniques']:
        script_lines.extend([
            f"    // {technique} bypass implementation",
            f"    // ... technique-specific code ...",
            ""
        ])
    
    script_lines.append("});")
    
    return script_lines


def generate_enhanced_ghidra_script(context: dict) -> list:
    """Generate enhanced Ghidra script based on predictive context."""
    script_lines = [
        "# Enhanced Ghidra Script Generated with Predictive Intelligence",
        f"# Target Protection: {context['predicted_protection']}",
        f"# Analysis Depth: {context['analysis_depth']}",
        f"# Deobfuscation Priority: {context['deobfuscation_priority']}",
        "",
        "from ghidra.program.model.symbol import *",
        "from ghidra.program.model.listing import *",
        "",
        "def enhanced_analysis():",
        '    print("[+] Starting enhanced analysis")'
    ]
    
    # Add analysis functions
    for func in context['analysis_functions']:
        script_lines.extend([
            f"    # {func} analysis",
            f"    perform_{func}_analysis()",
            ""
        ])
    
    # Add vulnerability focus areas
    for area in context['vulnerability_focus_areas']:
        script_lines.extend([
            f"    # Focus on {area} vulnerabilities",
            f"    analyze_{area}_patterns()",
            ""
        ])
    
    script_lines.extend([
        "",
        "if __name__ == '__main__':",
        "    enhanced_analysis()"
    ])
    
    return script_lines


def _get_target_apis_for_protection(protection_type: str) -> list:
    """Get target APIs based on protection type."""
    api_map = {
        'vmprotect': ['VirtualProtect', 'VirtualAlloc', 'CreateThread', 'GetProcAddress'],
        'themida': ['CreateMutex', 'GetTickCount', 'QueryPerformanceCounter'],
        'denuvo': ['GetSystemTimeAsFileTime', 'QueryPerformanceCounter', 'GetVolumeInformation'],
        'upx': ['LoadLibrary', 'GetProcAddress', 'VirtualProtect'],
        'unknown': ['VirtualProtect', 'LoadLibrary', 'CreateProcess', 'RegOpenKey']
    }
    return api_map.get(protection_type, api_map['unknown'])


def _get_bypass_techniques_for_strategy(strategy: str) -> list:
    """Get bypass techniques based on strategy."""
    technique_map = {
        'memory_patching': ['runtime_patching', 'breakpoint_injection'],
        'api_hooking': ['function_interception', 'return_value_modification'],
        'debugger_evasion': ['anti_anti_debug', 'stealth_debugging'],
        'static_analysis': ['disassembly_analysis', 'control_flow_mapping'],
        'virtualization_bypass': ['vm_detection', 'devirtualization']
    }
    return technique_map.get(strategy, technique_map['static_analysis'])


def _get_protection_specific_hooks(protection_type: str) -> list:
    """Get protection-specific hooks."""
    hook_map = {
        'vmprotect': ['vm_entry_detection', 'handler_analysis'],
        'themida': ['anti_debug_bypass', 'license_check_hook'],
        'denuvo': ['hardware_id_spoof', 'time_check_bypass'],
        'upx': ['unpacker_detection', 'original_entry_point'],
        'unknown': ['generic_protection_bypass', 'license_validation']
    }
    return hook_map.get(protection_type, hook_map['unknown'])


def _get_analysis_functions_for_protection(protection_type: str) -> list:
    """Get analysis functions based on protection type."""
    function_map = {
        'vmprotect': ['vm_handler_analysis', 'control_flow_reconstruction'],
        'themida': ['mutation_pattern_analysis', 'anti_debug_detection'],
        'denuvo': ['license_validation_analysis', 'hardware_binding_check'],
        'upx': ['unpacking_analysis', 'entry_point_detection'],
        'unknown': ['generic_protection_analysis', 'pattern_recognition']
    }
    return function_map.get(protection_type, function_map['unknown'])


def _get_vulnerability_focus_areas(vulnerability_type: str) -> list:
    """Get vulnerability focus areas."""
    area_map = {
        'buffer_overflow': ['stack_analysis', 'input_validation'],
        'use_after_free': ['memory_lifecycle', 'pointer_analysis'],
        'integer_overflow': ['arithmetic_operations', 'size_calculations'],
        'format_string': ['format_function_analysis', 'user_input_tracing'],
        'code_injection': ['dynamic_code_paths', 'execution_flow'],
        'safe': ['general_security_patterns', 'best_practices_validation']
    }
    return area_map.get(vulnerability_type, area_map['safe'])


def main():
    """Main demonstration function."""
    
    # Example binary features (would normally come from actual binary analysis)
    example_features = BinaryFeatures(
        file_size=2048000,  # 2MB
        entropy=7.6,        # High entropy suggesting protection
        section_count=10,   # Multiple sections
        import_count=200,   # Many imports
        export_count=15,    # Some exports
        string_count=800,   # Many strings
        packed=True,        # Appears packed
        signed=False,       # Not signed
        architecture="x64", # 64-bit
        compiler="msvc",    # MSVC compiler
        protection_indicators=["vmp0", "vmp1", ".themida"],
        api_calls=[
            "VirtualProtect", "VirtualAlloc", "CreateThread", "LoadLibrary",
            "GetProcAddress", "CreateMutex", "GetTickCount"
        ],
        suspicious_strings=[
            "VMProtect", "Themida", "AntiDebug", "LicenseCheck", "TrialExpired"
        ],
        control_flow_complexity=0.85,  # High complexity
        code_obfuscation_level=0.9     # Heavy obfuscation
    )
    
    # Run the enhanced workflow
    binary_path = "/path/to/protected/binary.exe"
    
    result = enhanced_script_generation_workflow(binary_path, example_features)
    
    if result:
        print(f"\n✅ Enhanced script generation completed successfully!")
        print(f"\nSummary:")
        print(f"  - Generated {len(result['predictions'])} predictions")
        print(f"  - Created {len(result['frida_script'])} line Frida script")
        print(f"  - Created {len(result['ghidra_script'])} line Ghidra script")
        print(f"  - Predicted success rate: {result['success_prediction'].predicted_value:.1%}")
    else:
        print(f"\n❌ Enhanced script generation failed")


if __name__ == "__main__":
    main()