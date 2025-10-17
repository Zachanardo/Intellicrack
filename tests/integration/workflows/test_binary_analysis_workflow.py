"""
Integration tests for Intellicrack's binary analysis workflows.

This module contains comprehensive integration tests for binary analysis end-to-end workflows in Intellicrack,
including complete binary analysis workflows, binary to radare2 analysis workflows,
protection detection to bypass generation workflows, analysis results to AI script
generation workflows, end-to-end analysis with error handling, concurrent analysis
workflow performance, analysis result persistence and retrieval, plugin integration
with analysis workflows, analysis workflows under memory constraints, and workflow
configuration validation. These tests ensure the binary analysis components work
effectively together in real-world scenarios.
"""

import pytest
import tempfile
import os
import time
from pathlib import Path

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.core.analysis.radare2_enhanced_integration import Radare2EnhancedIntegration
from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.core.analysis.analysis_orchestrator import AnalysisOrchestrator
from intellicrack.core.app_context import AppContext


class TestBinaryAnalysisWorkflow:
    """Integration tests for REAL binary analysis end-to-end workflows."""

    @pytest.fixture
    def test_pe_file(self):
        """Create REAL PE file for workflow testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            section_data = b'\x2e\x74\x65\x78\x74\x00\x00\x00'
            section_data += b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00'
            section_data += b'\x00' * 16
            section_data += b'\x20\x00\x00\x60'

            code_section = b'\x55\x8b\xec\x83\xec\x08\x53\x56\x57'
            code_section += b'\x8b\x75\x08\x33\xdb\x83\xfe\xff'
            code_section += b'\x74\x0a\x8b\x0e\x83\xc6\x04\x85\xc9'
            code_section += b'\x75\xf9\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3'
            code_section += b'\x90' * (256 - len(code_section))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header + section_data + code_section)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except:
            pass

    @pytest.fixture
    def app_context(self):
        """Create REAL application context for testing."""
        context = AppContext()
        context.initialize()
        return context

    def test_complete_binary_analysis_workflow(self, test_pe_file, app_context):
        """Test REAL complete binary analysis workflow from file to results."""
        orchestrator = AnalysisOrchestrator(app_context)

        analysis_config = {
            'file_path': test_pe_file,
            'analysis_type': 'comprehensive',
            'enable_ai': True,
            'generate_scripts': True,
            'detect_protections': True
        }

        start_time = time.time()

        results = orchestrator.run_analysis(analysis_config)

        end_time = time.time()

        assert results is not None, "Analysis workflow must return results"
        assert 'binary_info' in results, "Results must contain binary information"
        assert 'protection_analysis' in results, "Results must contain protection analysis"
        assert 'ai_insights' in results, "Results must contain AI insights"
        assert 'generated_scripts' in results, "Results must contain generated scripts"

        assert end_time - start_time < 30.0, "Complete workflow should complete under 30 seconds"

        assert results['binary_info']['file_type'] == 'PE', "Must correctly identify PE file"
        assert len(results['binary_info']['sections']) > 0, "Must identify file sections"

        assert isinstance(results['protection_analysis']['protections'], list), "Protections must be a list"

        assert len(results['generated_scripts']) > 0, "Must generate at least one script"
        for script in results['generated_scripts']:
            assert 'script_type' in script, "Each script must have a type"
            assert 'content' in script, "Each script must have content"
            assert len(script['content']) > 0, "Script content must not be empty"

    def test_binary_to_radare2_workflow(self, test_pe_file):
        """Test REAL binary loading to radare2 analysis workflow."""
        analyzer = BinaryAnalyzer()
        radare2 = Radare2EnhancedIntegration()

        binary_info = analyzer.analyze_file(test_pe_file)
        assert binary_info is not None, "Binary analysis must succeed"

        r2_session = radare2.create_session(test_pe_file)
        assert r2_session is not None, "Radare2 session creation must succeed"

        try:
            functions = radare2.analyze_functions(r2_session)
            assert functions is not None, "Function analysis must return results"
            assert isinstance(functions, list), "Functions must be a list"

            if len(functions) > 0:
                function_info = radare2.get_function_info(r2_session, functions[0]['name'])
                assert function_info is not None, "Function info must be available"
                assert 'address' in function_info, "Function info must contain address"
                assert 'size' in function_info, "Function info must contain size"

            disassembly = radare2.disassemble_function(r2_session, 'main')
            if disassembly is not None:
                assert isinstance(disassembly, list), "Disassembly must be a list"
                if len(disassembly) > 0:
                    assert 'opcode' in disassembly[0], "Each instruction must have opcode"

        finally:
            radare2.close_session(r2_session)

    def test_protection_detection_to_bypass_workflow(self, test_pe_file):
        """Test REAL protection detection to bypass generation workflow."""
        detector = ProtectionDetector()

        protection_results = detector.analyze_file(test_pe_file)
        assert protection_results is not None, "Protection detection must return results"
        assert 'protections' in protection_results, "Results must contain protections list"

        detected_protections = protection_results['protections']

        if len(detected_protections) > 0:
            for protection in detected_protections:
                bypass_strategies = detector.generate_bypass_strategies(protection)
                assert bypass_strategies is not None, "Bypass strategies must be generated"
                assert isinstance(bypass_strategies, list), "Strategies must be a list"

                for strategy in bypass_strategies:
                    assert 'method' in strategy, "Each strategy must have a method"
                    assert 'confidence' in strategy, "Each strategy must have confidence"
                    assert 'description' in strategy, "Each strategy must have description"
        else:
            assert True, "No protections detected - valid result for test binary"

    def test_analysis_to_ai_script_generation_workflow(self, test_pe_file, app_context):
        """Test REAL analysis results to AI script generation workflow."""
        analyzer = BinaryAnalyzer()
        ai_generator = AIScriptGenerator(app_context)

        analysis_results = analyzer.analyze_file(test_pe_file)
        assert analysis_results is not None, "Binary analysis must succeed"

        script_requests = [
            {
                'type': 'frida',
                'target': 'function_hooking',
                'binary_info': analysis_results
            },
            {
                'type': 'ghidra',
                'target': 'structure_analysis',
                'binary_info': analysis_results
            }
        ]

        for request in script_requests:
            script_result = ai_generator.generate_script(request)
            assert script_result is not None, f"Script generation failed for {request['type']}"
            assert 'script' in script_result, "Result must contain generated script"
            assert 'metadata' in script_result, "Result must contain metadata"

            script_content = script_result['script']
            assert len(script_content) > 0, "Generated script must not be empty"
            assert script_content != "TODO: Implement script", "Script must not be placeholder"

            if request['type'] == 'frida':
                assert 'Java.perform' in script_content or 'Interceptor.attach' in script_content, \
                    "Frida script must contain valid Frida API calls"
            elif request['type'] == 'ghidra':
                assert 'import' in script_content and 'def' in script_content, \
                    "Ghidra script must contain valid Python structure"

    def test_end_to_end_analysis_with_error_handling(self, app_context):
        """Test REAL end-to-end workflow with error handling."""
        orchestrator = AnalysisOrchestrator(app_context)

        invalid_file_configs = [
            {'file_path': '/nonexistent/file.exe', 'analysis_type': 'basic'},
            {'file_path': '', 'analysis_type': 'comprehensive'},
            {'file_path': None, 'analysis_type': 'basic'}
        ]

        for config in invalid_file_configs:
            try:
                results = orchestrator.run_analysis(config)
                if results is not None:
                    assert 'error' in results, "Invalid file should produce error result"
                    assert 'error_type' in results, "Error result should specify type"
            except Exception as e:
                assert "file" in str(e).lower() or "path" in str(e).lower(), \
                    "Exception should be related to file/path issues"

    def test_concurrent_analysis_workflow(self, test_pe_file, app_context):
        """Test REAL concurrent analysis workflow performance."""
        import threading

        orchestrator = AnalysisOrchestrator(app_context)
        results = []
        errors = []

        def run_analysis(thread_id):
            try:
                config = {
                    'file_path': test_pe_file,
                    'analysis_type': 'basic',
                    'enable_ai': False,
                    'thread_id': thread_id
                }
                result = orchestrator.run_analysis(config)
                results.append((thread_id, result))
            except Exception as e:
                errors.append((thread_id, str(e)))

        threads = []
        start_time = time.time()

        for i in range(3):
            thread = threading.Thread(target=run_analysis, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=60.0)

        end_time = time.time()

        assert len(errors) == 0, f"Concurrent analysis errors: {errors}"
        assert len(results) == 3, f"Expected 3 results, got {len(results)}"
        assert end_time - start_time < 45.0, "Concurrent analysis should complete under 45 seconds"

        for thread_id, result in results:
            assert result is not None, f"Thread {thread_id} returned None"
            assert 'binary_info' in result, f"Thread {thread_id} missing binary info"

    def test_analysis_result_persistence_workflow(self, test_pe_file, app_context):
        """Test REAL analysis result persistence and retrieval workflow."""
        orchestrator = AnalysisOrchestrator(app_context)

        config = {
            'file_path': test_pe_file,
            'analysis_type': 'comprehensive',
            'save_results': True,
            'result_id': f'test_analysis_{int(time.time())}'
        }

        original_results = orchestrator.run_analysis(config)
        assert original_results is not None, "Analysis must return results"

        result_id = original_results.get('result_id')
        assert result_id is not None, "Results must have an ID"

        retrieved_results = orchestrator.load_analysis_results(result_id)
        assert retrieved_results is not None, "Must be able to retrieve saved results"

        assert retrieved_results['binary_info'] == original_results['binary_info'], \
            "Retrieved binary info must match original"
        assert retrieved_results['protection_analysis'] == original_results['protection_analysis'], \
            "Retrieved protection analysis must match original"

        cleanup_success = orchestrator.delete_analysis_results(result_id)
        assert cleanup_success, "Must be able to clean up saved results"

    def test_plugin_integration_workflow(self, test_pe_file, app_context):
        """Test REAL plugin integration with analysis workflow."""
        orchestrator = AnalysisOrchestrator(app_context)

        available_plugins = orchestrator.get_available_plugins()
        assert isinstance(available_plugins, list), "Available plugins must be a list"

        if len(available_plugins) > 0:
            plugin_config = {
                'file_path': test_pe_file,
                'analysis_type': 'basic',
                'enabled_plugins': available_plugins[:2]
            }

            results = orchestrator.run_analysis(plugin_config)
            assert results is not None, "Plugin-enabled analysis must return results"
            assert 'plugin_results' in results, "Results must contain plugin outputs"

            plugin_results = results['plugin_results']
            assert isinstance(plugin_results, dict), "Plugin results must be a dictionary"

            for plugin_name in plugin_config['enabled_plugins']:
                if plugin_name in plugin_results:
                    plugin_output = plugin_results[plugin_name]
                    assert plugin_output is not None, f"Plugin {plugin_name} must produce output"

    def test_analysis_workflow_with_memory_constraints(self, test_pe_file, app_context):
        """Test REAL analysis workflow under memory constraints."""
        import psutil

        process = psutil.Process()
        initial_memory = process.memory_info().rss

        orchestrator = AnalysisOrchestrator(app_context)

        config = {
            'file_path': test_pe_file,
            'analysis_type': 'comprehensive',
            'memory_limit': 512 * 1024 * 1024,
            'enable_memory_monitoring': True
        }

        results = orchestrator.run_analysis(config)
        assert results is not None, "Memory-constrained analysis must return results"

        final_memory = process.memory_info().rss
        memory_increase = final_memory - initial_memory

        assert memory_increase < 300 * 1024 * 1024, "Memory increase should be under 300MB"

        if 'memory_stats' in results:
            memory_stats = results['memory_stats']
            assert 'peak_usage' in memory_stats, "Memory stats must include peak usage"
            assert 'limit_exceeded' in memory_stats, "Memory stats must include limit status"

    def test_workflow_configuration_validation(self, app_context):
        """Test REAL workflow configuration validation."""
        orchestrator = AnalysisOrchestrator(app_context)

        valid_configs = [
            {
                'file_path': '/valid/path/file.exe',
                'analysis_type': 'basic'
            },
            {
                'file_path': '/valid/path/file.dll',
                'analysis_type': 'comprehensive',
                'enable_ai': True,
                'generate_scripts': True
            }
        ]

        for config in valid_configs:
            validation_result = orchestrator.validate_configuration(config)
            assert validation_result['valid'] is True, f"Config should be valid: {config}"
            assert 'errors' not in validation_result or len(validation_result['errors']) == 0, \
                "Valid config should have no errors"

        invalid_configs = [
            {},
            {'analysis_type': 'basic'},
            {'file_path': '/path/file.exe'},
            {'file_path': '/path/file.exe', 'analysis_type': 'invalid_type'}
        ]

        for config in invalid_configs:
            validation_result = orchestrator.validate_configuration(config)
            assert validation_result['valid'] is False, f"Config should be invalid: {config}"
            assert 'errors' in validation_result, "Invalid config should have errors"
            assert len(validation_result['errors']) > 0, "Invalid config should have error details"
