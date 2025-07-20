"""
Unit tests for AI Script Generator with REAL model integration.
Tests REAL Frida/Ghidra script generation using actual LLM APIs.
NO MOCKS - ALL TESTS USE REAL MODELS AND PRODUCE REAL SCRIPTS.
"""

import pytest
import ast
import re
import json
from pathlib import Path

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.ai.llm_backends import LLMBackend
from tests.base_test import BaseIntellicrackTest


class TestAIScriptGenerator(BaseIntellicrackTest):
    """Test AI script generation with REAL models and REAL binaries."""
    
    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary):
        """Set up test with real binary and AI generator."""
        self.generator = AIScriptGenerator()
        self.test_binary = real_pe_binary
        
    @pytest.mark.skipif(not LLMBackend.has_api_keys(), reason="No LLM API keys available")
    def test_frida_script_generation_real(self):
        """Test REAL Frida script generation with actual LLM."""
        # Generate Frida script for real binary
        script_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'functions_to_hook': ['CreateFileW', 'RegOpenKeyW'],
            'objectives': ['Monitor file operations', 'Track registry access']
        }
        
        script_result = self.generator.generate_frida_script(script_request)
        
        # Validate real script generation
        self.assert_real_output(script_result)
        assert 'script_code' in script_result
        assert 'metadata' in script_result
        assert 'quality_score' in script_result
        
        # Validate JavaScript syntax
        script_code = script_result['script_code']
        assert isinstance(script_code, str)
        assert len(script_code) > 100  # Real scripts are substantial
        
        # Check for Frida API usage
        assert 'Interceptor.attach' in script_code
        assert 'Module.findExportByName' in script_code or 'Module.getExportByName' in script_code
        
        # Validate target functions are hooked
        assert 'CreateFileW' in script_code
        assert 'RegOpenKeyW' in script_code
        
        # Check for proper logging/monitoring
        assert 'console.log' in script_code or 'send(' in script_code
        
        # Validate metadata
        metadata = script_result['metadata']
        assert 'model_used' in metadata
        assert 'generation_time' in metadata
        assert 'token_usage' in metadata
        assert metadata['generation_time'] > 0
        
    @pytest.mark.skipif(not LLMBackend.has_api_keys(), reason="No LLM API keys available")
    def test_ghidra_script_generation_real(self):
        """Test REAL Ghidra script generation with actual LLM."""
        # Generate Ghidra script for real binary
        script_request = {
            'type': 'ghidra_analysis',
            'target_binary': self.test_binary,
            'analysis_type': 'string_extraction',
            'objectives': ['Extract all strings', 'Identify encryption patterns']
        }
        
        script_result = self.generator.generate_ghidra_script(script_request)
        
        # Validate real script generation
        self.assert_real_output(script_result)
        assert 'script_code' in script_result
        assert 'metadata' in script_result
        
        # Validate Python syntax
        script_code = script_result['script_code']
        try:
            ast.parse(script_code)  # Will raise if invalid Python
        except SyntaxError:
            pytest.fail(f"Generated Ghidra script has syntax errors: {script_code}")
            
        # Check for Ghidra API usage
        assert 'currentProgram' in script_code or 'getCurrentProgram' in script_code
        assert 'getMemory()' in script_code or 'memory' in script_code.lower()
        
        # Check for string extraction logic
        assert 'string' in script_code.lower()
        assert 'byte' in script_code.lower() or 'data' in script_code.lower()
        
    def test_script_validation_real(self):
        """Test REAL script validation with actual syntax checking."""
        # Valid Frida script
        valid_frida = '''
        Java.perform(function() {
            var MainActivity = Java.use("com.example.MainActivity");
            MainActivity.onCreate.implementation = function(savedInstanceState) {
                console.log("onCreate called");
                this.onCreate(savedInstanceState);
            };
        });
        '''
        
        validation_result = self.generator.validate_script(valid_frida, 'frida')
        
        # Validate real validation results
        self.assert_real_output(validation_result)
        assert validation_result['valid'] == True
        assert validation_result['syntax_errors'] == []
        assert 'quality_metrics' in validation_result
        
        # Invalid script
        invalid_frida = '''
        Java.perform(function() {
            var MainActivity = Java.use("com.example.MainActivity"
            // Missing closing parenthesis and semicolon
        '''
        
        invalid_result = self.generator.validate_script(invalid_frida, 'frida')
        assert invalid_result['valid'] == False
        assert len(invalid_result['syntax_errors']) > 0
        
    @pytest.mark.skipif(not LLMBackend.has_api_keys(), reason="No LLM API keys available")
    def test_context_aware_generation_real(self):
        """Test REAL context-aware script generation based on binary analysis."""
        # Analyze binary first to get context
        from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
        analyzer = BinaryAnalyzer()
        binary_info = analyzer.analyze(self.test_binary)
        
        # Generate context-aware script
        script_request = {
            'type': 'frida_bypass',
            'target_binary': self.test_binary,
            'binary_info': binary_info,
            'protection_type': 'anti_debug',
            'objectives': ['Bypass IsDebuggerPresent checks']
        }
        
        script_result = self.generator.generate_context_aware_script(script_request)
        
        # Validate context awareness
        self.assert_real_output(script_result)
        script_code = script_result['script_code']
        
        # Should reference specific binary characteristics
        if binary_info.get('architecture') == 'x64':
            assert 'x64' in script_code or '64' in script_code
        
        # Should include anti-debug bypass techniques
        assert 'IsDebuggerPresent' in script_code or 'debugger' in script_code.lower()
        
    def test_script_optimization_real(self):
        """Test REAL script optimization and quality improvement."""
        # Basic unoptimized script
        basic_script = '''
        Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateFileW"), {
            onEnter: function(args) {
                console.log("CreateFileW called");
                console.log("Filename: " + Memory.readUtf16String(args[0]));
            }
        });
        '''
        
        optimized_result = self.generator.optimize_script(basic_script, 'frida')
        
        # Validate real optimization
        self.assert_real_output(optimized_result)
        assert 'optimized_script' in optimized_result
        assert 'improvements' in optimized_result
        assert 'performance_gain' in optimized_result
        
        optimized_script = optimized_result['optimized_script']
        
        # Check for real optimizations
        assert len(optimized_script) >= len(basic_script)  # Should be enhanced
        assert 'error' in optimized_script.lower()  # Should add error handling
        
    @pytest.mark.skipif(not LLMBackend.has_api_keys(), reason="No LLM API keys available")
    def test_multi_model_comparison_real(self):
        """Test REAL multi-model script generation and comparison."""
        script_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'functions_to_hook': ['CreateFileW'],
            'objectives': ['Monitor file access']
        }
        
        # Generate with multiple models
        comparison_result = self.generator.compare_models(script_request, models=['gpt-4', 'claude-3'])
        
        # Validate real comparison
        self.assert_real_output(comparison_result)
        assert 'model_results' in comparison_result
        assert 'best_model' in comparison_result
        assert 'quality_comparison' in comparison_result
        
        # Check that models produced different but valid results
        model_results = comparison_result['model_results']
        assert len(model_results) >= 2
        
        scripts = [result['script_code'] for result in model_results.values()]
        assert len(set(scripts)) > 1  # Different models should produce different scripts
        
        # All scripts should be valid
        for model, result in model_results.items():
            validation = self.generator.validate_script(result['script_code'], 'frida')
            assert validation['valid'], f"Script from {model} is invalid"
            
    def test_custom_template_integration_real(self):
        """Test REAL integration with custom script templates."""
        # Define custom template
        custom_template = {
            'name': 'file_monitor_template',
            'type': 'frida',
            'base_code': '''
            var fileOps = [];
            Interceptor.attach(Module.findExportByName("kernel32.dll", "CreateFileW"), {
                onEnter: function(args) {
                    fileOps.push({
                        operation: "create",
                        filename: Memory.readUtf16String(args[0]),
                        timestamp: Date.now()
                    });
                }
            });
            ''',
            'customization_points': ['additional_apis', 'filter_logic', 'output_format']
        }
        
        # Generate script using template
        result = self.generator.generate_from_template(custom_template, {
            'additional_apis': ['WriteFile', 'ReadFile'],
            'filter_logic': 'only .exe files',
            'output_format': 'JSON'
        })
        
        # Validate template integration
        self.assert_real_output(result)
        assert 'WriteFile' in result['script_code']
        assert 'ReadFile' in result['script_code']
        assert '.exe' in result['script_code']
        
    @pytest.mark.skipif(not LLMBackend.has_api_keys(), reason="No LLM API keys available")  
    def test_error_handling_and_recovery_real(self):
        """Test REAL error handling when LLM fails or returns invalid code."""
        # Request that might cause issues
        problematic_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'functions_to_hook': ['NonExistentFunction123'],
            'objectives': ['Do impossible things'],
            'constraints': ['Must be under 10 characters']  # Impossible constraint
        }
        
        result = self.generator.generate_frida_script(problematic_request)
        
        # Should handle gracefully
        assert isinstance(result, dict)
        if result.get('success', True):
            # If successful, validate the result
            self.assert_real_output(result)
        else:
            # If failed, should have proper error info
            assert 'error' in result
            assert 'fallback_script' in result or 'suggestions' in result
            
    def test_performance_monitoring_real(self):
        """Test REAL performance monitoring during script generation."""
        # Enable performance monitoring
        self.generator.enable_performance_monitoring()
        
        script_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'functions_to_hook': ['CreateFileW'],
            'objectives': ['Monitor file access']
        }
        
        result = self.generator.generate_frida_script(script_request)
        performance_metrics = self.generator.get_performance_metrics()
        
        # Validate real performance data
        self.assert_real_output(performance_metrics)
        assert 'generation_time' in performance_metrics
        assert 'token_usage' in performance_metrics
        assert 'api_calls' in performance_metrics
        assert 'memory_usage' in performance_metrics
        
        # Check realistic values
        assert performance_metrics['generation_time'] > 0
        assert performance_metrics['token_usage'] > 0
        
    def test_script_effectiveness_scoring_real(self):
        """Test REAL script effectiveness scoring and quality assessment."""
        # Generate script
        script_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'functions_to_hook': ['CreateFileW'],
            'objectives': ['Monitor file access']
        }
        
        script_result = self.generator.generate_frida_script(script_request)
        
        # Score effectiveness
        effectiveness_score = self.generator.score_script_effectiveness(
            script_result['script_code'], 
            script_request
        )
        
        # Validate real scoring
        self.assert_real_output(effectiveness_score)
        assert 'overall_score' in effectiveness_score
        assert 'coverage_score' in effectiveness_score
        assert 'robustness_score' in effectiveness_score
        assert 'maintainability_score' in effectiveness_score
        
        # Check score ranges
        assert 0 <= effectiveness_score['overall_score'] <= 100
        assert 0 <= effectiveness_score['coverage_score'] <= 100