"""
Unit tests for AI Script Generator with REAL model integration.
Tests REAL Frida/Ghidra script generation using actual LLM APIs.
NO MOCKS - ALL TESTS USE REAL MODELS AND PRODUCE REAL SCRIPTS.
"""

import pytest
import ast
import re
import json
import os
from pathlib import Path

from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.ai.llm_backends import LLMBackend
from intellicrack.core.config_manager import get_config
from tests.base_test import BaseIntellicrackTest
from tests.fixtures.binary_fixtures import real_pe_binary, binary_fixture_dir


def has_any_llm_api_keys():
    """Check if any LLM API keys are available."""
    # Check configured API keys
    config = get_config()
    script_gen_config = config.get("ai_models", {}).get("script_generation", {})
    api_keys = script_gen_config.get("api_keys", {})

    # Check if any configured API key is present
    for provider, key in api_keys.items():
        if key:
            return True

    # Check environment variables for any LLM API keys
    for env_var in os.environ:
        if (env_var.endswith("_API_KEY") or env_var.endswith("_API_TOKEN")) and os.environ[env_var]:
            return True

    return False


class TestAIScriptGenerator(BaseIntellicrackTest):
    """Test AI script generation with REAL models and REAL binaries."""

    @pytest.fixture(autouse=True)
    def setup(self, real_pe_binary):
        """Set up test with real binary and AI generator."""
        self.generator = AIScriptGenerator()
        self.test_binary = real_pe_binary

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_frida_script_generation_real(self):
        """Test REAL Frida script generation with actual LLM."""
        # Generate Frida script for real binary
        script_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'functions_to_hook': ['CreateFileW', 'RegOpenKeyW'],
            'objectives': ['Monitor file operations', 'Track registry access']
        }

        script_result = self.generator.generate_script_from_prompt(prompt=script_request['objectives'][0], script_type='frida', binary_path=self.test_binary)

        # Validate real script generation
        assert script_result is not None, "Script generation returned None"
        assert isinstance(script_result, dict), "Script result should be a dictionary"
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

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_ghidra_script_generation_real(self):
        """Test REAL Ghidra script generation with actual LLM."""
        # Generate Ghidra script for real binary
        script_request = {
            'type': 'ghidra_analysis',
            'target_binary': self.test_binary,
            'analysis_type': 'string_extraction',
            'objectives': ['Extract all strings', 'Identify encryption patterns']
        }

        script_result = self.generator.generate_script_from_prompt(prompt=script_request['objectives'][0], script_type='ghidra', binary_path=self.test_binary)

        # Validate real script generation
        assert script_result is not None, "Script generation returned None"
        assert isinstance(script_result, dict), "Script result should be a dictionary"
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
        assert validation_result is not None, "Validation returned None"
        assert isinstance(validation_result, dict), "Validation result should be a dictionary"
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

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
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
        assert script_result is not None, "Script generation returned None"
        assert isinstance(script_result, dict), "Script result should be a dictionary"
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
        assert optimized_result is not None, "Optimization returned None"
        assert isinstance(optimized_result, dict), "Optimization result should be a dictionary"
        assert 'optimized_script' in optimized_result
        assert 'improvements' in optimized_result
        assert 'performance_gain' in optimized_result

        optimized_script = optimized_result['optimized_script']

        # Check for real optimizations
        assert len(optimized_script) >= len(basic_script)  # Should be enhanced
        assert 'error' in optimized_script.lower()  # Should add error handling

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
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
        assert comparison_result is not None, "Comparison returned None"
        assert isinstance(comparison_result, dict), "Comparison result should be a dictionary"
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



    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
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

        result = self.generator.generate_script_from_prompt(prompt=problematic_request['objectives'][0], script_type='frida', binary_path=self.test_binary)

        # Should handle gracefully
        assert isinstance(result, dict)
        if result.get('success', True):
            # If successful, validate the result
            assert result is not None, "Result returned None"
            assert isinstance(result, dict), "Result should be a dictionary"
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

        result = self.generator.generate_script_from_prompt(prompt=script_request['objectives'][0], script_type='frida', binary_path=self.test_binary)
        performance_metrics = self.generator.get_performance_metrics()

        # Validate real performance data
        assert performance_metrics is not None, "Performance metrics returned None"
        assert isinstance(performance_metrics, dict), "Performance metrics should be a dictionary"
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

        script_result = self.generator.generate_script_from_prompt(prompt=script_request['objectives'][0], script_type='frida', binary_path=self.test_binary)

        # Score effectiveness
        effectiveness_score = self.generator.score_script_effectiveness(
            script_result['script_code'],
            script_request
        )

        # Validate real scoring
        assert effectiveness_score is not None, "Effectiveness score returned None"
        assert isinstance(effectiveness_score, (dict, float)), "Effectiveness score should be dict or float"
        assert 'overall_score' in effectiveness_score
        assert 'coverage_score' in effectiveness_score
        assert 'robustness_score' in effectiveness_score
        assert 'maintainability_score' in effectiveness_score

        # Check score ranges
        assert 0 <= effectiveness_score['overall_score'] <= 100
        assert 0 <= effectiveness_score['coverage_score'] <= 100

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_qemu_script_execution_real(self):
        """Test REAL script execution in QEMU virtual machine."""
        from intellicrack.ai.qemu_manager import QEMUManager
        from intellicrack.ai.script_editor import ScriptTester

        # Generate a Frida script
        script_request = {
            'type': 'frida_hook',
            'target_binary': self.test_binary,
            'objectives': ['Hook process creation APIs', 'Monitor network connections']
        }

        script_result = self.generator.generate_script_from_prompt(
            prompt=script_request['objectives'][0],
            script_type='frida',
            binary_path=self.test_binary
        )

        assert script_result is not None
        assert 'script_code' in script_result

        # Test the script in QEMU
        tester = ScriptTester()
        qemu_result = tester.test_script_execution(
            script_content=script_result['script_code'],
            script_type='frida',
            binary_path=self.test_binary,
            timeout=60
        )

        # Validate QEMU execution results
        assert qemu_result is not None, "QEMU test returned None"
        assert isinstance(qemu_result, dict), "QEMU result should be a dictionary"
        assert 'success' in qemu_result
        assert 'output' in qemu_result
        assert 'errors' in qemu_result
        assert 'performance' in qemu_result

        # If execution failed, check error details
        if not qemu_result['success']:
            assert qemu_result.get('error') or qemu_result.get('errors'), "Failed execution should have error details"

        # Check performance metrics
        if qemu_result.get('performance'):
            perf = qemu_result['performance']
            assert 'runtime_ms' in perf or 'execution_time' in perf
            assert 'exit_code' in perf or 'return_code' in perf

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_diverse_script_types(self):
        """Test generation of diverse script types beyond Frida/Ghidra."""
        script_types_and_prompts = [
            ('python', 'Create a Python script to analyze PE file headers and extract version information'),
            ('radare2', 'Generate r2 commands to disassemble main function and find crypto routines'),
            ('javascript', 'Create a browser DevTools script to intercept and log WebSocket messages'),
            ('powershell', 'Generate PowerShell script to extract embedded resources from .NET assemblies'),
            ('lua', 'Write a Lua script for Wireshark to parse custom protocol packets'),
            ('c', 'Create a C program using ptrace to monitor system calls'),
            ('shell', 'Generate a bash script to automate binary unpacking with UPX'),
        ]

        for script_type, prompt in script_types_and_prompts:
            script_result = self.generator.generate_script_from_prompt(
                prompt=prompt,
                script_type=script_type,
                binary_path=self.test_binary if 'binary' in prompt.lower() else None
            )

            # Validate generation
            assert script_result is not None, f"Failed to generate {script_type} script"
            assert isinstance(script_result, dict), f"{script_type} result should be dictionary"
            assert 'script_code' in script_result, f"{script_type} missing script_code"
            assert len(script_result['script_code']) > 50, f"{script_type} script too short"

            # Validate script contains relevant content
            code = script_result['script_code'].lower()
            if script_type == 'python':
                assert 'def ' in code or 'import ' in code or 'class ' in code
            elif script_type == 'radare2':
                assert any(cmd in code for cmd in ['pdf', 'aa', 's ', 'afl', 'iz'])
            elif script_type == 'powershell':
                assert '$' in script_result['script_code'] or 'param' in code
            elif script_type == 'shell':
                assert '#!/bin/' in script_result['script_code'] or 'echo' in code or '$' in script_result['script_code']

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_complex_multi_objective_prompts(self):
        """Test generation with complex, multi-objective prompts."""
        complex_prompts = [
            """Create a comprehensive Frida script that:
            1. Hooks all file I/O operations (CreateFile, ReadFile, WriteFile)
            2. Monitors registry access (RegOpenKey, RegSetValue)
            3. Intercepts network connections (connect, send, recv)
            4. Logs process creation (CreateProcess)
            5. Detects anti-debugging techniques
            6. Dumps strings from memory
            7. Provides real-time statistics
            """,

            """Generate a Ghidra script to:
            1. Identify all crypto/hashing functions
            2. Find and label all string references
            3. Detect packers and protectors
            4. Map out the call graph
            5. Identify potential vulnerabilities
            6. Export findings to JSON report
            """,

            """Write a multi-stage exploitation script that:
            1. Performs reconnaissance on the target
            2. Identifies the protection mechanisms
            3. Finds suitable gadgets for ROP chain
            4. Constructs the payload
            5. Handles ASLR and DEP bypasses
            6. Achieves code execution
            7. Maintains persistence
            """
        ]

        for i, prompt in enumerate(complex_prompts):
            # Determine appropriate script type from prompt content
            if 'frida' in prompt.lower():
                script_type = 'frida'
            elif 'ghidra' in prompt.lower():
                script_type = 'ghidra'
            else:
                script_type = 'python'  # Default to Python for exploitation scripts

            script_result = self.generator.generate_script_from_prompt(
                prompt=prompt,
                script_type=script_type,
                binary_path=self.test_binary
            )

            # Validate complex script generation
            assert script_result is not None, f"Failed complex prompt {i+1}"
            assert 'script_code' in script_result
            assert len(script_result['script_code']) > 200, f"Complex script {i+1} too short"

            # Check that script addresses multiple objectives
            code = script_result['script_code'].lower()

            # Count how many objectives are addressed (rough heuristic)
            objectives_found = 0
            keywords = ['hook', 'monitor', 'intercept', 'log', 'detect', 'dump',
                       'identify', 'find', 'map', 'export', 'recon', 'gadget',
                       'payload', 'bypass', 'execute', 'persist']

            for keyword in keywords:
                if keyword in code:
                    objectives_found += 1

            # Complex scripts should address multiple objectives
            assert objectives_found >= 3, f"Complex script {i+1} doesn't address enough objectives"

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_iterative_improvement_with_qemu(self):
        """Test iterative script improvement using QEMU feedback."""
        from intellicrack.ai.script_editor import AIScriptEditor
        import tempfile
        import os

        # Generate initial script
        initial_prompt = "Create a Frida script to hook and log all API calls"
        script_result = self.generator.generate_script_from_prompt(
            prompt=initial_prompt,
            script_type='frida',
            binary_path=self.test_binary
        )

        assert script_result is not None
        assert 'script_code' in script_result

        # Save script to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(script_result['script_code'])
            script_path = f.name

        try:
            # Test iterative improvement
            editor = AIScriptEditor()
            improvement_result = editor.iterative_improve(
                script_path=script_path,
                improvement_goals=[
                    "Ensure the script runs without errors",
                    "Add performance optimization",
                    "Include error handling"
                ],
                max_iterations=3,
                test_binary=self.test_binary
            )

            # Validate improvement results
            assert improvement_result is not None
            assert 'iterations' in improvement_result
            assert 'final_success' in improvement_result
            assert 'qemu_feedback' in improvement_result

            # Check that iterations were performed
            assert len(improvement_result['iterations']) > 0

            # Check QEMU feedback was collected
            assert len(improvement_result['qemu_feedback']) > 0

            # Verify each iteration has required fields
            for iteration in improvement_result['iterations']:
                assert 'iteration' in iteration
                assert 'result' in iteration
                assert 'qemu_result' in iteration or 'goals_achieved' in iteration

            # Check final QEMU result if available
            if 'final_qemu_result' in improvement_result:
                final_result = improvement_result['final_qemu_result']
                assert isinstance(final_result, dict)
                assert 'success' in final_result

        finally:
            # Clean up temp file
            if os.path.exists(script_path):
                os.unlink(script_path)

    @pytest.mark.skipif(not has_any_llm_api_keys(), reason="No LLM API keys available")
    def test_edge_case_prompts(self):
        """Test generation with edge case and unusual prompts."""
        edge_cases = [
            # Very short prompt
            ("frida", "hook"),

            # Very long technical prompt
            ("ghidra", "Analyze the binary to identify all instances of dynamic memory allocation including malloc, calloc, realloc, and new operations, trace their usage patterns throughout the program execution flow, identify potential memory leaks, buffer overflows, use-after-free vulnerabilities, and generate a comprehensive report with memory usage statistics, vulnerability risk scores, and recommended patches using secure coding practices"),

            # Non-English characters in prompt
            ("python", "Create a script to find strings with Unicode characters like 你好世界 and émojis 🔒🔑"),

            # Prompt with code snippets
            ("frida", "Hook the function at address 0x401000 that has signature: int process_data(char* buffer, size_t len)"),

            # Contradictory requirements
            ("javascript", "Create a synchronous script that performs asynchronous operations without using async/await or promises"),

            # Domain-specific jargon
            ("radare2", "Implement ROP gadget discovery using semantic analysis of epilogue sequences with stack pivoting"),
        ]

        for script_type, prompt in edge_cases:
            script_result = self.generator.generate_script_from_prompt(
                prompt=prompt,
                script_type=script_type,
                binary_path=self.test_binary if script_type in ['frida', 'ghidra'] else None
            )

            # Even edge cases should generate something
            assert script_result is not None, f"Failed on edge case: {prompt[:50]}..."
            assert 'script_code' in script_result

            # Script should have some content
            assert len(script_result.get('script_code', '')) > 10, f"Edge case generated empty script: {prompt[:50]}..."

            # Should not contain obvious error messages in the script itself
            code = script_result['script_code'].lower()
            assert 'error:' not in code, f"Script contains error for: {prompt[:50]}..."
            assert 'exception:' not in code, f"Script contains exception for: {prompt[:50]}..."
