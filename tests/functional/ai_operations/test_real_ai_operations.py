"""
Functional tests for Intellicrack's AI operations.

This module contains comprehensive tests for the AI functionality in Intellicrack,
including LLM backends, semantic code analysis, pattern recognition, multi-agent
collaboration, learning engines, and predictive intelligence. These tests verify
real AI operations with actual model operations and ensure the AI components work
as expected in production scenarios.
"""

import pytest
import tempfile
import os
import json
import time
from pathlib import Path

from intellicrack.ai.interactive_assistant import IntellicrackAIAssistant
from intellicrack.ai.llm_backends import LLMManager
from intellicrack.ai.model_manager_module import ModelManager
from intellicrack.ai.multi_agent_system import MultiAgentSystem
from intellicrack.ai.learning_engine import AILearningEngine
from intellicrack.ai.predictive_intelligence import PredictiveIntelligenceEngine
from intellicrack.ai.semantic_code_analyzer import SemanticCodeAnalyzer
from intellicrack.ai.pattern_library import AdvancedPatternLibrary
from intellicrack.ai.performance_monitor import PerformanceMonitor
from intellicrack.core.app_context import AppContext


class TestRealAIOperations:
    """Functional tests for REAL AI operations with actual model operations."""

    @pytest.fixture
    def test_code_sample(self):
        """Create REAL code sample for AI analysis."""
        return '''
#include <windows.h>
#include <stdio.h>

// License check function
BOOL CheckLicense(const char* key) {
    // Simple XOR check
    DWORD checksum = 0;
    for (int i = 0; key[i]; i++) {
        checksum ^= key[i] << (i % 4);
    }

    // Compare with hardcoded value
    if (checksum == 0xDEADBEEF) {
        return TRUE;
    }

    return FALSE;
}

// Anti-debug check
BOOL IsDebuggerPresent() {
    __asm {
        mov eax, fs:[0x30]
        movzx eax, byte ptr [eax+2]
        test eax, eax
        jnz debugger_detected
    }
    return FALSE;

debugger_detected:
    return TRUE;
}

int main() {
    // Check for debugger
    if (IsDebuggerPresent()) {
        MessageBox(NULL, "Debugger detected!", "Error", MB_OK);
        return 1;
    }

    // Check license
    char license_key[256];
    printf("Enter license key: ");
    scanf("%s", license_key);

    if (CheckLicense(license_key)) {
        printf("License valid! Welcome!\n");
        // Main program logic here
    } else {
        printf("Invalid license key!\n");
        return 1;
    }

    return 0;
}
'''

    @pytest.fixture
    def app_context(self):
        """Create REAL application context."""
        context = AppContext()
        context.initialize()
        return context

    @pytest.fixture
    def test_binary_metadata(self):
        """Create REAL binary metadata for AI analysis."""
        return {
            'file_name': 'test_app.exe',
            'file_size': 524288,
            'file_type': 'PE32',
            'architecture': 'x86',
            'sections': [
                {'name': '.text', 'size': 4096, 'entropy': 6.2},
                {'name': '.data', 'size': 2048, 'entropy': 3.5},
                {'name': '.rdata', 'size': 1024, 'entropy': 4.1}
            ],
            'imports': [
                {'dll': 'kernel32.dll', 'functions': ['CreateFileA', 'ReadFile', 'WriteFile']},
                {'dll': 'user32.dll', 'functions': ['MessageBoxA', 'GetWindowTextA']},
                {'dll': 'advapi32.dll', 'functions': ['RegOpenKeyExA', 'RegQueryValueExA']}
            ],
            'strings': [
                'Enter license key:',
                'License valid! Welcome!',
                'Invalid license key!',
                'Debugger detected!'
            ]
        }

    def test_real_llm_backend_operations(self, app_context):
        """Test REAL LLM backend operations and model switching."""
        llm_backends = LLMManager(app_context)

        # Test backend initialization
        available_backends = llm_backends.get_available_backends()
        assert available_backends is not None, "Must return available backends"
        assert isinstance(available_backends, list), "Available backends must be a list"

        # Test model listing
        models = llm_backends.list_available_models()
        assert models is not None, "Must return available models"
        assert isinstance(models, dict), "Models must be a dictionary"

        # Test prompt generation
        test_prompt = {
            'task': 'analyze_code',
            'code': 'if (checksum == 0xDEADBEEF) return TRUE;',
            'context': 'license validation'
        }

        formatted_prompt = llm_backends.format_prompt(test_prompt)
        assert formatted_prompt is not None, "Must format prompt"
        assert len(formatted_prompt) > 0, "Formatted prompt must not be empty"
        assert 'analyze' in formatted_prompt.lower(), "Prompt must contain task"
        assert 'license' in formatted_prompt.lower(), "Prompt must contain context"

    def test_real_semantic_code_analysis(self, test_code_sample, app_context):
        """Test REAL semantic code analysis functionality."""
        analyzer = SemanticCodeAnalyzer(app_context)

        # Analyze code structure
        analysis_result = analyzer.analyze_code(test_code_sample, language='c')
        assert analysis_result is not None, "Code analysis must return results"
        assert 'functions' in analysis_result, "Must identify functions"
        assert 'security_issues' in analysis_result, "Must identify security issues"
        assert 'patterns' in analysis_result, "Must identify code patterns"

        functions = analysis_result['functions']
        assert len(functions) >= 3, "Must find at least 3 functions"

        # Check function detection
        function_names = [f.get('name', '') for f in functions]
        assert 'CheckLicense' in function_names, "Must find CheckLicense function"
        assert 'IsDebuggerPresent' in function_names, "Must find IsDebuggerPresent function"
        assert 'main' in function_names, "Must find main function"

        # Check security issue detection
        security_issues = analysis_result['security_issues']
        assert len(security_issues) > 0, "Must identify security issues"

        issue_types = [issue.get('type', '') for issue in security_issues]
        assert any('hardcoded' in t.lower() for t in issue_types), "Must detect hardcoded values"
        assert any('buffer' in t.lower() or 'scanf' in t.lower() for t in issue_types), "Must detect unsafe input"

    def test_real_pattern_library_operations(self, app_context):
        """Test REAL pattern library functionality."""
        pattern_lib = AdvancedPatternLibrary(app_context)

        # Test pattern categories
        categories = pattern_lib.get_pattern_categories()
        assert categories is not None, "Must return pattern categories"
        assert 'protection' in categories, "Must have protection patterns"
        assert 'exploitation' in categories, "Must have exploitation patterns"
        assert 'obfuscation' in categories, "Must have obfuscation patterns"

        # Test pattern retrieval
        protection_patterns = pattern_lib.get_patterns_by_category('protection')
        assert protection_patterns is not None, "Must return protection patterns"
        assert len(protection_patterns) > 0, "Must have protection patterns"

        for pattern in protection_patterns:
            assert 'name' in pattern, "Each pattern must have name"
            assert 'description' in pattern, "Each pattern must have description"
            assert 'signature' in pattern or 'code' in pattern, "Pattern must have signature or code"

        # Test pattern matching
        test_code = "mov eax, fs:[0x30]"
        matches = pattern_lib.find_matching_patterns(test_code)
        assert matches is not None, "Pattern matching must return results"

        if len(matches) > 0:
            for match in matches:
                assert 'pattern_name' in match, "Match must identify pattern"
                assert 'confidence' in match, "Match must have confidence score"
                assert match['confidence'] > 0, "Confidence must be positive"

    def test_real_multi_agent_collaboration(self, test_code_sample, test_binary_metadata, app_context):
        """Test REAL multi-agent system collaboration."""
        multi_agent = MultiAgentSystem(app_context)

        # Create analysis task
        task = {
            'id': f'task_{int(time.time())}',
            'type': 'comprehensive_analysis',
            'targets': {
                'code': test_code_sample,
                'metadata': test_binary_metadata
            },
            'agents': ['code_analyzer', 'security_auditor', 'exploit_researcher']
        }

        # Execute multi-agent analysis
        result = multi_agent.execute_collaborative_task(task)
        assert result is not None, "Multi-agent task must return results"
        assert 'task_id' in result, "Result must contain task ID"
        assert 'agent_outputs' in result, "Result must contain agent outputs"
        assert 'consensus' in result, "Result must contain consensus"

        agent_outputs = result['agent_outputs']
        assert isinstance(agent_outputs, dict), "Agent outputs must be dictionary"

        # Verify each agent contributed
        for agent in task['agents']:
            assert agent in agent_outputs, f"Agent {agent} must provide output"
            agent_output = agent_outputs[agent]
            assert 'analysis' in agent_output, f"Agent {agent} must provide analysis"
            assert 'confidence' in agent_output, f"Agent {agent} must provide confidence"

    def test_real_learning_engine_operations(self, app_context):
        """Test REAL learning engine functionality."""
        learning_engine = AILearningEngine(app_context)

        # Test knowledge base operations
        knowledge_stats = learning_engine.get_knowledge_statistics()
        assert knowledge_stats is not None, "Must return knowledge statistics"
        assert 'total_entries' in knowledge_stats, "Must track total entries"
        assert 'categories' in knowledge_stats, "Must track categories"

        # Test learning from analysis
        analysis_data = {
            'binary_hash': 'abc123def456',
            'protections_found': ['anti_debug', 'packing', 'obfuscation'],
            'successful_bypasses': ['anti_debug'],
            'failed_attempts': ['packing'],
            'time_taken': 45.2,
            'techniques_used': ['dynamic_analysis', 'static_analysis']
        }

        learning_result = learning_engine.learn_from_analysis(analysis_data)
        assert learning_result is not None, "Learning must return result"
        assert learning_result.get('learned', False), "Must indicate learning success"
        assert 'knowledge_updated' in learning_result, "Must show knowledge updates"

        # Test pattern extraction
        patterns = learning_engine.extract_success_patterns()
        assert patterns is not None, "Must extract success patterns"
        assert isinstance(patterns, list), "Patterns must be a list"

    def test_real_predictive_intelligence(self, test_binary_metadata, app_context):
        """Test REAL predictive intelligence functionality."""
        predictive = PredictiveIntelligenceEngine(app_context)

        # Test protection prediction
        protection_prediction = predictive.predict_protections(test_binary_metadata)
        assert protection_prediction is not None, "Must predict protections"
        assert 'predicted_protections' in protection_prediction, "Must contain predictions"
        assert 'confidence_scores' in protection_prediction, "Must contain confidence scores"

        predictions = protection_prediction['predicted_protections']
        assert isinstance(predictions, list), "Predictions must be a list"

        for prediction in predictions:
            assert 'protection_type' in prediction, "Prediction must specify type"
            assert 'probability' in prediction, "Prediction must have probability"
            assert 0 <= prediction['probability'] <= 1, "Probability must be between 0 and 1"

        # Test bypass strategy prediction
        bypass_prediction = predictive.predict_bypass_strategy(predictions)
        assert bypass_prediction is not None, "Must predict bypass strategy"
        assert 'recommended_approach' in bypass_prediction, "Must recommend approach"
        assert 'success_probability' in bypass_prediction, "Must estimate success probability"
        assert 'estimated_time' in bypass_prediction, "Must estimate time required"

    def test_real_ai_performance_monitoring(self, app_context):
        """Test REAL AI performance monitoring."""
        monitor = PerformanceMonitor()

        # Start monitoring session
        session_id = monitor.start_monitoring_session('ai_operations')
        assert session_id is not None, "Must create monitoring session"

        # Simulate AI operations
        operation_metrics = []
        for i in range(5):
            start = time.time()

            # Simulate operation
            time.sleep(0.1)

            end = time.time()

            metric = {
                'operation': f'ai_task_{i}',
                'duration': end - start,
                'memory_used': 50 + i * 10,  # MB
                'tokens_processed': 100 + i * 50
            }

            monitor.record_metric(session_id, metric)
            operation_metrics.append(metric)

        # Get monitoring results
        results = monitor.get_session_results(session_id)
        assert results is not None, "Must return monitoring results"
        assert 'session_id' in results, "Results must contain session ID"
        assert 'metrics' in results, "Results must contain metrics"
        assert 'summary' in results, "Results must contain summary"

        summary = results['summary']
        assert 'total_operations' in summary, "Summary must count operations"
        assert summary['total_operations'] == 5, "Must track all operations"
        assert 'average_duration' in summary, "Summary must calculate average duration"
        assert 'total_tokens' in summary, "Summary must sum tokens"

    def test_real_ai_model_management(self, app_context):
        """Test REAL AI model management operations."""
        model_manager = ModelManager(app_context)

        # Test model discovery
        available_models = model_manager.discover_models()
        assert available_models is not None, "Must discover models"
        assert isinstance(available_models, dict), "Models must be dictionary"

        # Test model capabilities
        for model_type, models in available_models.items():
            for model in models:
                capabilities = model_manager.get_model_capabilities(model)
                assert capabilities is not None, f"Must return capabilities for {model}"
                assert 'supported_tasks' in capabilities, "Must list supported tasks"
                assert 'context_window' in capabilities, "Must specify context window"
                assert 'performance_profile' in capabilities, "Must include performance profile"

        # Test model selection
        task_requirements = {
            'task_type': 'code_analysis',
            'input_size': 2048,
            'required_capabilities': ['syntax_understanding', 'security_analysis'],
            'performance_requirement': 'balanced'
        }

        selected_model = model_manager.select_optimal_model(task_requirements)
        assert selected_model is not None, "Must select a model"
        assert 'model_name' in selected_model, "Must specify model name"
        assert 'reasoning' in selected_model, "Must explain selection"

    def test_real_ai_script_generation_workflow(self, test_code_sample, app_context):
        """Test REAL AI script generation workflow."""
        ai_assistant = IntellicrackAIAssistant(app_context)

        # Generate Frida script
        frida_request = {
            'script_type': 'frida',
            'target_code': test_code_sample,
            'objectives': [
                'hook_license_check',
                'bypass_debugger_detection',
                'log_function_calls'
            ]
        }

        frida_script = ai_assistant.generate_analysis_script(frida_request)
        assert frida_script is not None, "Must generate Frida script"
        assert 'script' in frida_script, "Result must contain script"
        assert 'metadata' in frida_script, "Result must contain metadata"

        script_content = frida_script['script']
        assert len(script_content) > 0, "Script must not be empty"
        assert 'Interceptor.attach' in script_content, "Frida script must use Interceptor"
        assert 'CheckLicense' in script_content, "Script must target license check"
        assert 'IsDebuggerPresent' in script_content, "Script must target debugger detection"

        # Generate Ghidra script
        ghidra_request = {
            'script_type': 'ghidra',
            'analysis_goals': [
                'identify_crypto_constants',
                'find_anti_analysis_code',
                'extract_strings'
            ]
        }

        ghidra_script = ai_assistant.generate_analysis_script(ghidra_request)
        assert ghidra_script is not None, "Must generate Ghidra script"
        assert 'script' in ghidra_script, "Result must contain script"

        ghidra_content = ghidra_script['script']
        assert 'currentProgram' in ghidra_content, "Ghidra script must reference program"
        assert any(api in ghidra_content for api in ['getFunction', 'getInstruction', 'getMemory']), \
            "Script must use Ghidra APIs"

    def test_real_ai_context_awareness(self, test_binary_metadata, app_context):
        """Test REAL AI context awareness and memory."""
        ai_assistant = IntellicrackAIAssistant(app_context)

        # First interaction - establish context
        initial_request = {
            'action': 'analyze_binary',
            'data': test_binary_metadata,
            'session_id': f'session_{int(time.time())}'
        }

        first_response = ai_assistant.process_with_context(initial_request)
        assert first_response is not None, "First response must succeed"
        assert 'analysis' in first_response, "Response must contain analysis"
        assert 'context_stored' in first_response, "Must indicate context storage"

        # Second interaction - use previous context
        followup_request = {
            'action': 'suggest_bypasses',
            'session_id': initial_request['session_id'],
            'reference_previous': True
        }

        second_response = ai_assistant.process_with_context(followup_request)
        assert second_response is not None, "Followup response must succeed"
        assert 'bypasses' in second_response, "Response must contain bypasses"
        assert 'context_used' in second_response, "Must indicate context usage"
        assert second_response['context_used'], "Must actually use previous context"

        # Verify context continuity
        if 'referenced_data' in second_response:
            assert 'file_name' in second_response['referenced_data'], \
                "Should reference original file name from context"

    def test_real_ai_error_recovery(self, app_context):
        """Test REAL AI error handling and recovery."""
        ai_assistant = IntellicrackAIAssistant(app_context)

        # Test with malformed input
        error_cases = [
            {'action': 'analyze', 'data': None},
            {'action': 'unknown_action', 'data': {}},
            {'action': 'analyze', 'data': {'corrupted': b'\xff\xfe\xfd'}},
            {'action': 'generate_script', 'script_type': 'invalid_type'}
        ]

        for error_case in error_cases:
            result = ai_assistant.handle_with_recovery(error_case)
            assert result is not None, "Must return result even for errors"
            assert 'status' in result, "Result must have status"

            if result['status'] == 'error':
                assert 'error_type' in result, "Error must specify type"
                assert 'recovery_attempted' in result, "Must indicate recovery attempt"
                assert 'suggestion' in result, "Must provide suggestion"

    def test_real_ai_optimization_strategies(self, test_code_sample, app_context):
        """Test REAL AI optimization strategies."""
        ai_assistant = IntellicrackAIAssistant(app_context)

        # Test different optimization modes
        optimization_modes = ['speed', 'accuracy', 'balanced']

        for mode in optimization_modes:
            request = {
                'action': 'analyze_code',
                'code': test_code_sample,
                'optimization_mode': mode
            }

            result = ai_assistant.process_optimized(request)
            assert result is not None, f"Must return result for {mode} mode"
            assert 'optimization_applied' in result, "Must indicate optimization"
            assert result['optimization_applied'] == mode, f"Must apply {mode} optimization"
            assert 'performance_metrics' in result, "Must include performance metrics"

            metrics = result['performance_metrics']
            if mode == 'speed':
                assert 'execution_time' in metrics, "Speed mode must track time"
            elif mode == 'accuracy':
                assert 'accuracy_score' in metrics, "Accuracy mode must track accuracy"
            elif mode == 'balanced':
                assert 'efficiency_ratio' in metrics, "Balanced mode must track efficiency"

    def test_real_ai_batch_processing(self, app_context):
        """Test REAL AI batch processing capabilities."""
        ai_assistant = IntellicrackAIAssistant(app_context)

        # Create batch of analysis tasks
        batch_tasks = []
        for i in range(5):
            task = {
                'id': f'task_{i}',
                'type': 'pattern_analysis',
                'data': {
                    'code_snippet': f'function_{i}() {{ return {i}; }}',
                    'priority': 'high' if i < 2 else 'normal'
                }
            }
            batch_tasks.append(task)

        # Process batch
        batch_result = ai_assistant.process_batch(batch_tasks, parallel=True)
        assert batch_result is not None, "Batch processing must return results"
        assert 'completed_tasks' in batch_result, "Must track completed tasks"
        assert 'failed_tasks' in batch_result, "Must track failed tasks"
        assert 'processing_time' in batch_result, "Must track processing time"

        completed = batch_result['completed_tasks']
        assert len(completed) == len(batch_tasks), "All tasks should complete"

        # Verify task results
        for task_result in completed:
            assert 'task_id' in task_result, "Result must have task ID"
            assert 'result' in task_result, "Result must have output"
            assert 'processing_time' in task_result, "Result must track individual time"

    def test_real_ai_confidence_scoring(self, test_code_sample, app_context):
        """Test REAL AI confidence scoring system."""
        ai_assistant = IntellicrackAIAssistant(app_context)
        semantic_analyzer = SemanticCodeAnalyzer(app_context)

        # Analyze with confidence tracking
        analysis_request = {
            'code': test_code_sample,
            'analysis_depth': 'comprehensive',
            'include_confidence': True
        }

        result = semantic_analyzer.analyze_with_confidence(analysis_request)
        assert result is not None, "Analysis must return result"
        assert 'findings' in result, "Must contain findings"
        assert 'overall_confidence' in result, "Must have overall confidence"

        findings = result['findings']
        for finding in findings:
            assert 'description' in finding, "Finding must have description"
            assert 'confidence' in finding, "Finding must have confidence score"
            assert 0 <= finding['confidence'] <= 1, "Confidence must be between 0 and 1"
            assert 'evidence' in finding, "Finding must provide evidence"

        overall_confidence = result['overall_confidence']
        assert 0 <= overall_confidence <= 1, "Overall confidence must be between 0 and 1"

        # Test confidence factors
        if 'confidence_factors' in result:
            factors = result['confidence_factors']
            assert 'code_clarity' in factors, "Should assess code clarity"
            assert 'pattern_matches' in factors, "Should assess pattern matches"
            assert 'analysis_coverage' in factors, "Should assess coverage"
