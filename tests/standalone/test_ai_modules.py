"""Standalone tests for AI modules"""
import os
import sys
import json
import time
from pathlib import Path

# Disable GPU initialization
os.environ['INTELLICRACK_NO_GPU'] = '1'
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'

# Add project to path
sys.path.insert(0, 'C:\\Intellicrack')

def run_test_llm_backends():
    """Test LLM backend functionality"""
    print("\n=== Running LLM Backend Test ===")

    try:
        from intellicrack.ai.llm_backends import LLMBackend

        # Create backend instance
        backend = LLMBackend()

        # Test initialization
        assert backend is not None, "Backend creation failed"
        print("LLM backend created successfully")

        # Test model listing
        models = backend.list_models()
        assert models is not None, "Model listing returned None"
        assert isinstance(models, (list, dict)), "Models must be list or dict"
        print(f"Available models: {len(models) if isinstance(models, list) else 'multiple categories'}")

        # Test prompt formatting
        test_prompt = "Analyze this code for vulnerabilities"
        formatted = backend.format_prompt(test_prompt)
        assert formatted is not None, "Prompt formatting returned None"
        assert len(formatted) > 0, "Empty formatted prompt"
        print("Prompt formatting working")

        # Test backend capabilities
        capabilities = backend.get_capabilities()
        assert capabilities is not None, "Capabilities returned None"
        assert isinstance(capabilities, dict), "Capabilities must be dict"
        print(f"Backend capabilities: {list(capabilities.keys())}")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_pattern_library():
    """Test pattern library functionality"""
    print("\n=== Running Pattern Library Test ===")

    try:
        from intellicrack.ai.pattern_library import PatternLibrary

        # Create library instance
        library = PatternLibrary()

        # Test pattern categories
        categories = library.get_categories()
        assert categories is not None, "Categories returned None"
        assert isinstance(categories, (list, dict)), "Categories must be list or dict"
        print(f"Pattern categories available: {len(categories) if isinstance(categories, list) else 'multiple'}")

        # Test pattern search
        test_patterns = ['anti_debug', 'license', 'packing']
        for pattern_name in test_patterns:
            results = library.search_patterns(pattern_name)
            print(f"  Search '{pattern_name}': {len(results) if results else 0} results")

        # Test pattern matching
        test_code = "IsDebuggerPresent()"
        matches = library.find_matches(test_code)
        assert matches is not None, "Pattern matching returned None"
        print(f"Pattern matches for test code: {len(matches) if matches else 0}")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_learning_engine():
    """Test AI learning engine"""
    print("\n=== Running Learning Engine Test ===")

    try:
        from intellicrack.ai.learning_engine import AILearningEngine, get_learning_engine

        engine = get_learning_engine()

        assert engine is not None, "Engine creation failed"
        print("Learning engine created successfully")

        assert hasattr(engine, 'learning_enabled'), "Missing learning_enabled attribute"
        assert hasattr(engine, 'database'), "Missing database attribute"
        print("Engine has required attributes")

        insights = engine.get_learning_insights()
        assert insights is not None, "Failed to get learning insights"
        assert 'total_records' in insights, "Missing total_records in insights"
        print(f"Got learning insights with {insights.get('total_records', 0)} records")

        record_id = engine.record_experience(
            task_type="anti_debug_bypass",
            input_data={"protection": "IsDebuggerPresent"},
            output_data={"bypassed": True},
            success=True,
            confidence=0.85,
            execution_time=2.5,
            memory_usage=1024000,
        )
        print("Successfully recorded experience")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_script_generation():
    """Test AI script generation"""
    print("\n=== Running Script Generation Test ===")

    try:
        from intellicrack.ai.ai_script_generator import AIScriptGenerator

        # Create generator
        generator = AIScriptGenerator()

        # Test Frida script generation
        frida_request = {
            'type': 'frida',
            'target': 'function_hook',
            'function_name': 'CheckLicense',
            'action': 'bypass'
        }

        frida_script = generator.generate_frida_script(frida_request)
        assert frida_script is not None, "Frida script generation failed"
        assert len(frida_script) > 0, "Empty Frida script"
        assert 'Interceptor' in frida_script or 'hook' in frida_script.lower(), "Invalid Frida script"
        print(f"Generated Frida script: {len(frida_script)} chars")

        # Test Ghidra script generation
        ghidra_request = {
            'type': 'ghidra',
            'analysis_type': 'find_crypto',
            'target': 'all_functions'
        }

        ghidra_script = generator.generate_ghidra_script(ghidra_request)
        assert ghidra_script is not None, "Ghidra script generation failed"
        assert len(ghidra_script) > 0, "Empty Ghidra script"
        print(f"Generated Ghidra script: {len(ghidra_script)} chars")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_llm_config():
    """Test LLM configuration management"""
    print("\n=== Running LLM Config Test ===")

    try:
        from intellicrack.ai.llm_config_manager import LLMConfigManager

        # Create config manager
        config_mgr = LLMConfigManager()

        # Test default config
        default_config = config_mgr.get_default_config()
        assert default_config is not None, "Default config returned None"
        assert isinstance(default_config, dict), "Config must be dict"
        print(f"Default config sections: {list(default_config.keys())}")

        # Test model configurations
        model_configs = config_mgr.get_model_configs()
        assert model_configs is not None, "Model configs returned None"
        print(f"Configured models: {len(model_configs) if isinstance(model_configs, dict) else 'unknown'}")

        # Test API key management (without exposing keys)
        has_openai = config_mgr.has_api_key('openai')
        has_anthropic = config_mgr.has_api_key('anthropic')
        print(f"API keys configured - OpenAI: {has_openai}, Anthropic: {has_anthropic}")

        # Test temperature settings
        temps = config_mgr.get_temperature_presets()
        assert temps is not None, "Temperature presets returned None"
        print(f"Temperature presets: {list(temps.keys()) if isinstance(temps, dict) else 'default'}")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_ai_tools():
    """Test AI tools functionality"""
    print("\n=== Running AI Tools Test ===")

    try:
        from intellicrack.ai.code_analysis_tools import AITools

        # Create tools instance
        tools = AITools()

        # Test tool listing
        available_tools = tools.list_tools()
        assert available_tools is not None, "Tool listing returned None"
        assert isinstance(available_tools, (list, dict)), "Tools must be list or dict"
        print(f"Available AI tools: {len(available_tools) if isinstance(available_tools, list) else 'multiple categories'}")

        # Test code analysis tool
        test_code = """
        BOOL CheckSerial(char* serial) {
            DWORD sum = 0;
            for(int i = 0; i < strlen(serial); i++) {
                sum += serial[i] ^ 0x55;
            }
            return sum == 0x1337;
        }
        """

        analysis = tools.analyze_code(test_code, language='c')
        assert analysis is not None, "Code analysis returned None"
        print(f"Code analysis completed: {len(str(analysis)) if analysis else 0} chars")

        # Test vulnerability detection
        vulns = tools.detect_vulnerabilities(test_code)
        assert vulns is not None, "Vulnerability detection returned None"
        print(f"Vulnerabilities found: {len(vulns) if isinstance(vulns, list) else 'analysis complete'}")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_model_performance():
    """Test model performance monitoring"""
    print("\n=== Running Model Performance Test ===")

    try:
        from intellicrack.ai.model_performance_monitor import ModelPerformanceMonitor

        # Create monitor
        monitor = ModelPerformanceMonitor()

        # Test metric recording
        test_metric = {
            'model': 'gpt-3.5-turbo',
            'task': 'code_analysis',
            'duration': 2.5,
            'tokens_used': 1500,
            'success': True
        }

        monitor.record_metric(test_metric)
        print("Performance metric recorded")

        # Test statistics retrieval
        stats = monitor.get_statistics()
        assert stats is not None, "Statistics returned None"
        assert isinstance(stats, dict), "Statistics must be dict"
        print(f"Performance stats available: {list(stats.keys())}")

        # Test performance recommendations
        recommendations = monitor.get_optimization_recommendations()
        assert recommendations is not None, "Recommendations returned None"
        print(f"Optimization recommendations: {len(recommendations) if isinstance(recommendations, list) else 'available'}")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_test_ai_integration():
    """Test AI integration components"""
    print("\n=== Running AI Integration Test ===")

    try:
        # Test multiple AI components working together
        from intellicrack.ai.ai_script_generator import AIScriptGenerator
        from intellicrack.ai.pattern_library import PatternLibrary

        generator = AIScriptGenerator()
        library = PatternLibrary()

        # Find anti-debug patterns
        patterns = library.search_patterns('anti_debug')
        assert patterns is not None, "Pattern search failed"

        # Generate script based on patterns
        if patterns and len(patterns) > 0:
            pattern = patterns[0] if isinstance(patterns, list) else patterns

            script_request = {
                'type': 'frida',
                'pattern': pattern,
                'action': 'bypass'
            }

            script = generator.generate_from_pattern(script_request)
            assert script is not None, "Script generation from pattern failed"
            print("Successfully integrated pattern library with script generation")
        else:
            print("No patterns found, but integration test structure validated")

        print("OK Test PASSED!")
        return True

    except Exception as e:
        print(f"FAIL Test FAILED: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all AI module tests"""
    print("Starting AI module standalone tests...")

    tests = [
        run_test_llm_backends,
        run_test_pattern_library,
        run_test_learning_engine,
        run_test_script_generation,
        run_test_llm_config,
        run_test_ai_tools,
        run_test_model_performance,
        run_test_ai_integration
    ]

    passed = 0
    failed = 0

    for test in tests:
        result = test()
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\n{'='*50}")
    print("AI Module Test Results:")
    print(f"  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total: {len(tests)}")
    print(f"{'='*50}")

    return failed == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
