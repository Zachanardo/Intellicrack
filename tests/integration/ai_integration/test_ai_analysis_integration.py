"""
Integration tests for Intellicrack's AI analysis capabilities.

This module contains comprehensive integration tests for AI-driven analysis workflows in Intellicrack,
including binary analysis feeding into AI insights generation, protection detection to AI bypass
generation, multi-agent AI coordination for complex analysis, AI orchestrator managing complex
workflows, AI learning from analysis results, AI script generation with context awareness,
AI error handling and recovery mechanisms, AI performance optimization during workflows,
and AI collaborative analysis with multiple models. These tests ensure the AI components
work effectively together in real-world analysis scenarios.
"""

import pytest
import tempfile
import os
import time
from pathlib import Path
from typing import Any, Generator

from intellicrack.ai.interactive_assistant import AIAssistantEnhanced  # type: ignore[attr-defined]
from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.ai.coordination_layer import CoordinationLayer  # type: ignore[attr-defined]
from intellicrack.ai.multi_agent_system import MultiAgentSystem
from intellicrack.ai.orchestrator import Orchestrator  # type: ignore[attr-defined]
from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.protection.protection_detector import ProtectionDetector
from intellicrack.core.app_context import AppContext


class TestAIAnalysisIntegration:
    """Integration tests for REAL AI-driven analysis workflows."""

    @pytest.fixture
    def test_binary_file(self) -> Generator[str, None, None]:
        """Create REAL binary file for AI analysis testing."""
        with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as temp_file:
            dos_header = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00'
            dos_header += b'\xb8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00'
            dos_header += b'\x00' * 40
            dos_header += b'\x80\x00\x00\x00'
            dos_header += b'\x00' * 60

            pe_signature = b'PE\x00\x00'
            coff_header = b'\x4c\x01\x03\x00' + b'\x00' * 16
            optional_header = b'\x0b\x01\x0e\x00' + b'\x00' * 220

            section_text = b'\x2e\x74\x65\x78\x74\x00\x00\x00'
            section_text += b'\x00\x10\x00\x00\x00\x10\x00\x00\x00\x10\x00\x00\x00\x04\x00\x00'
            section_text += b'\x00' * 16
            section_text += b'\x20\x00\x00\x60'

            section_data = b'\x2e\x64\x61\x74\x61\x00\x00\x00'
            section_data += b'\x00\x20\x00\x00\x00\x20\x00\x00\x00\x10\x00\x00\x00\x14\x00\x00'
            section_data += b'\x00' * 16
            section_data += b'\x40\x00\x00\xc0'

            code_section = b'\x55\x8b\xec\x83\xec\x08'
            code_section += b'\x68\x00\x40\x00\x00'
            code_section += b'\xff\x15\x00\x20\x00\x00'
            code_section += b'\x33\xc0\x8b\xe5\x5d\xc3'
            code_section += b'\x90' * (256 - len(code_section))

            data_section = b'Hello World\x00\x00\x00\x00\x00'
            data_section += b'\x41\x64\x6f\x62\x65\x00\x00\x00'
            data_section += b'\x00' * (256 - len(data_section))

            temp_file.write(dos_header + pe_signature + coff_header + optional_header +
                          section_text + section_data + code_section + data_section)
            temp_file.flush()
            yield temp_file.name

        try:
            os.unlink(temp_file.name)
        except Exception:
            pass

    @pytest.fixture
    def app_context(self) -> AppContext:
        """Create REAL application context for AI testing."""
        context = AppContext()
        context.initialize()  # type: ignore[attr-defined]
        return context

    def test_binary_analysis_to_ai_insights_workflow(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL binary analysis feeding into AI insight generation."""
        analyzer = BinaryAnalyzer()
        ai_assistant = AIAssistantEnhanced(app_context)

        binary_results = analyzer.analyze_file(test_binary_file)  # type: ignore[attr-defined]
        assert binary_results is not None, "Binary analysis must return results"
        assert 'sections' in binary_results, "Analysis must identify sections"
        assert 'imports' in binary_results, "Analysis must identify imports"

        ai_request = {
            'task': 'analyze_binary_structure',
            'input_data': binary_results,
            'analysis_depth': 'comprehensive'
        }

        ai_insights = ai_assistant.generate_insights(ai_request)
        assert ai_insights is not None, "AI must generate insights"
        assert 'analysis' in ai_insights, "AI insights must contain analysis"
        assert 'recommendations' in ai_insights, "AI insights must contain recommendations"
        assert 'confidence' in ai_insights, "AI insights must contain confidence score"

        analysis_content = ai_insights['analysis']
        assert len(analysis_content) > 0, "AI analysis must not be empty"
        assert analysis_content != "TODO: Analyze binary", "AI analysis must not be placeholder"

        recommendations = ai_insights['recommendations']
        assert isinstance(recommendations, list), "Recommendations must be a list"
        if len(recommendations) > 0:
            for rec in recommendations:
                assert 'action' in rec, "Each recommendation must have an action"
                assert 'rationale' in rec, "Each recommendation must have rationale"

    def test_protection_detection_to_ai_bypass_generation(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL protection detection feeding into AI bypass generation."""
        detector = ProtectionDetector()
        ai_generator = AIScriptGenerator(app_context)  # type: ignore[call-arg]

        protection_results = detector.analyze_file(test_binary_file)  # type: ignore[attr-defined]
        assert protection_results is not None, "Protection detection must return results"

        detected_protections = protection_results.get('protections', [])

        if len(detected_protections) > 0:
            for protection in detected_protections:
                bypass_request = {
                    'protection_type': protection.get('type', 'unknown'),
                    'protection_details': protection,
                    'target_binary': test_binary_file,
                    'bypass_method': 'dynamic_analysis'
                }

                ai_bypass = ai_generator.generate_bypass_script(bypass_request)  # type: ignore[attr-defined]
                assert ai_bypass is not None, f"AI must generate bypass for {protection.get('type')}"
                assert 'script' in ai_bypass, "Bypass must contain script"
                assert 'method' in ai_bypass, "Bypass must contain method"
                assert 'confidence' in ai_bypass, "Bypass must contain confidence"

                script_content = ai_bypass['script']
                assert len(script_content) > 0, "Bypass script must not be empty"
                assert script_content != "# TODO: Implement bypass", "Script must not be placeholder"
        else:
            ai_bypass = ai_generator.generate_generic_analysis_script({'target': test_binary_file})  # type: ignore[attr-defined]
            assert ai_bypass is not None, "AI must generate generic analysis script"
            assert 'script' in ai_bypass, "Generic script must be generated"

    def test_multi_agent_coordination_workflow(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL multi-agent AI coordination for complex analysis."""
        coordination = CoordinationLayer(app_context)
        multi_agent = MultiAgentSystem(app_context)  # type: ignore[arg-type]

        analysis_task = {
            'task_id': f'multi_analysis_{int(time.time())}',
            'target_file': test_binary_file,
            'agents': ['binary_analyzer', 'protection_detector', 'exploit_generator'],
            'coordination_mode': 'sequential'
        }

        task_result = coordination.coordinate_analysis(analysis_task)
        assert task_result is not None, "Coordination must return results"
        assert 'task_id' in task_result, "Result must contain task ID"
        assert 'agent_results' in task_result, "Result must contain agent results"
        assert 'coordination_summary' in task_result, "Result must contain coordination summary"

        agent_results = task_result['agent_results']
        assert isinstance(agent_results, dict), "Agent results must be a dictionary"

        for agent_name in analysis_task['agents']:
            if agent_name in agent_results:
                agent_result = agent_results[agent_name]
                assert agent_result is not None, f"Agent {agent_name} must produce results"
                assert 'status' in agent_result, f"Agent {agent_name} must report status"
                assert 'output' in agent_result, f"Agent {agent_name} must provide output"

    def test_ai_orchestrator_workflow_management(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL AI orchestrator managing complex workflows."""
        orchestrator = Orchestrator(app_context)

        workflow_config = {
            'workflow_type': 'comprehensive_analysis',
            'target': test_binary_file,
            'stages': [
                {'stage': 'binary_analysis', 'priority': 'high'},
                {'stage': 'protection_detection', 'priority': 'high'},
                {'stage': 'vulnerability_analysis', 'priority': 'medium'},
                {'stage': 'exploit_generation', 'priority': 'low'}
            ],
            'ai_assistance': True,
            'generate_reports': True
        }

        start_time = time.time()

        workflow_result = orchestrator.execute_workflow(workflow_config)

        end_time = time.time()

        assert workflow_result is not None, "Orchestrator must return workflow results"
        assert 'workflow_id' in workflow_result, "Result must contain workflow ID"
        assert 'stage_results' in workflow_result, "Result must contain stage results"
        assert 'final_report' in workflow_result, "Result must contain final report"

        assert end_time - start_time < 60.0, "Workflow should complete under 60 seconds"

        stage_results = workflow_result['stage_results']
        assert isinstance(stage_results, dict), "Stage results must be a dictionary"

        for stage in workflow_config['stages']:  # type: ignore[attr-defined]
            stage_name = stage['stage']
            if stage_name in stage_results:
                stage_result = stage_results[stage_name]
                assert 'status' in stage_result, f"Stage {stage_name} must report status"
                assert 'duration' in stage_result, f"Stage {stage_name} must report duration"

    def test_ai_learning_from_analysis_results(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL AI learning and adaptation from analysis results."""
        ai_assistant = AIAssistantEnhanced(app_context)

        initial_analysis = {
            'file_path': test_binary_file,
            'task_type': 'binary_analysis',
            'user_feedback': None
        }

        first_result = ai_assistant.perform_analysis(initial_analysis)
        assert first_result is not None, "First analysis must return results"
        assert 'insights' in first_result, "First analysis must contain insights"

        feedback = {
            'result_id': first_result.get('result_id'),
            'accuracy_rating': 8,
            'helpful_suggestions': ['focus_on_imports', 'analyze_strings'],
            'corrections': []
        }

        learning_result = ai_assistant.incorporate_feedback(feedback)
        assert learning_result is not None, "AI must process feedback"
        assert learning_result.get('feedback_processed', False), "Feedback must be processed"

        improved_analysis = {
            'file_path': test_binary_file,
            'task_type': 'binary_analysis',
            'apply_learned_improvements': True
        }

        second_result = ai_assistant.perform_analysis(improved_analysis)
        assert second_result is not None, "Improved analysis must return results"
        assert 'insights' in second_result, "Improved analysis must contain insights"

        if 'improvement_applied' in second_result:
            assert second_result['improvement_applied'], "Improvements should be applied"

    def test_ai_script_generation_with_context_awareness(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL AI script generation with context awareness."""
        analyzer = BinaryAnalyzer()
        ai_generator = AIScriptGenerator(app_context)  # type: ignore[call-arg]

        binary_context = analyzer.analyze_file(test_binary_file)  # type: ignore[attr-defined]
        assert binary_context is not None, "Binary analysis must provide context"

        script_requests = [
            {
                'type': 'frida',
                'purpose': 'function_hooking',
                'target_functions': ['main', 'MessageBoxA'],
                'context': binary_context
            },
            {
                'type': 'ghidra',
                'purpose': 'structure_analysis',
                'focus_areas': ['imports', 'strings', 'functions'],
                'context': binary_context
            }
        ]

        for request in script_requests:
            script_result = ai_generator.generate_context_aware_script(request)  # type: ignore[attr-defined]
            assert script_result is not None, f"Context-aware script generation failed for {request['type']}"
            assert 'script' in script_result, "Result must contain generated script"
            assert 'context_utilized' in script_result, "Result must show context utilization"
            assert 'adaptation_notes' in script_result, "Result must contain adaptation notes"

            script_content = script_result['script']
            assert len(script_content) > 0, "Generated script must not be empty"

            context_utilized = script_result['context_utilized']
            assert isinstance(context_utilized, list), "Context utilization must be a list"

            if request['type'] == 'frida':
                assert any('function' in item.lower() for item in context_utilized), \
                    "Frida script should utilize function context"
            elif request['type'] == 'ghidra':
                assert any('structure' in item.lower() or 'import' in item.lower() for item in context_utilized), \
                    "Ghidra script should utilize structural context"

    def test_ai_error_handling_and_recovery(self, app_context: AppContext) -> None:
        """Test REAL AI error handling and recovery mechanisms."""
        ai_assistant = AIAssistantEnhanced(app_context)

        error_scenarios = [
            {'task': 'analyze_binary', 'input_data': None},
            {'task': 'analyze_binary', 'input_data': {}},
            {'task': 'invalid_task_type', 'input_data': {'file': 'test.exe'}},
            {'task': 'analyze_binary', 'input_data': {'file': '/nonexistent/file.exe'}}
        ]

        for scenario in error_scenarios:
            try:
                result = ai_assistant.handle_request(scenario)

                if result is not None:
                    assert 'error' in result or 'status' in result, \
                        "Invalid requests should produce error or status information"

                    if 'error' in result:
                        assert 'error_type' in result, "Error should specify type"
                        assert 'recovery_suggestion' in result, "Error should include recovery suggestion"

            except Exception as e:
                assert 'input' in str(e).lower() or 'invalid' in str(e).lower(), \
                    "Exceptions should be related to input validation"

    def test_ai_performance_optimization_workflow(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL AI performance optimization during workflows."""
        orchestrator = Orchestrator(app_context)

        performance_config = {
            'target': test_binary_file,
            'optimization_mode': 'speed',
            'resource_constraints': {
                'max_memory': '512MB',
                'max_cpu_time': '30s',
                'parallel_agents': 2
            },
            'quality_threshold': 0.8
        }

        start_time = time.time()

        optimized_result = orchestrator.execute_optimized_workflow(performance_config)

        end_time = time.time()

        assert optimized_result is not None, "Optimized workflow must return results"
        assert 'performance_metrics' in optimized_result, "Result must contain performance metrics"
        assert 'quality_score' in optimized_result, "Result must contain quality score"
        assert 'optimization_applied' in optimized_result, "Result must show optimization details"

        performance_metrics = optimized_result['performance_metrics']
        assert 'execution_time' in performance_metrics, "Metrics must include execution time"
        assert 'memory_usage' in performance_metrics, "Metrics must include memory usage"
        assert 'cpu_utilization' in performance_metrics, "Metrics must include CPU utilization"

        quality_score = optimized_result['quality_score']
        assert isinstance(quality_score, (int, float)), "Quality score must be numeric"
        assert quality_score >= performance_config['quality_threshold'], "Quality score must meet threshold"  # type: ignore[operator]

        assert end_time - start_time <= 35.0, "Optimized workflow should respect time constraints"

    def test_ai_collaborative_analysis_workflow(self, test_binary_file: str, app_context: AppContext) -> None:
        """Test REAL AI collaborative analysis with multiple models."""
        coordination = CoordinationLayer(app_context)

        collaborative_config = {
            'analysis_target': test_binary_file,
            'models': ['primary_analyzer', 'secondary_validator', 'expert_reviewer'],
            'collaboration_mode': 'consensus',
            'consensus_threshold': 0.7
        }

        collaborative_result = coordination.run_collaborative_analysis(collaborative_config)
        assert collaborative_result is not None, "Collaborative analysis must return results"
        assert 'consensus_result' in collaborative_result, "Result must contain consensus"
        assert 'model_contributions' in collaborative_result, "Result must show model contributions"
        assert 'confidence_score' in collaborative_result, "Result must contain confidence score"

        model_contributions = collaborative_result['model_contributions']
        assert isinstance(model_contributions, dict), "Contributions must be a dictionary"

        for model_name in collaborative_config['models']:  # type: ignore[attr-defined]
            if model_name in model_contributions:
                contribution = model_contributions[model_name]
                assert 'analysis' in contribution, f"Model {model_name} must provide analysis"
                assert 'confidence' in contribution, f"Model {model_name} must provide confidence"

        consensus_result = collaborative_result['consensus_result']
        assert 'final_analysis' in consensus_result, "Consensus must contain final analysis"
        assert 'agreement_level' in consensus_result, "Consensus must show agreement level"

        confidence_score = collaborative_result['confidence_score']
        assert isinstance(confidence_score, (int, float)), "Confidence must be numeric"
        assert confidence_score >= collaborative_config['consensus_threshold'], "Confidence must meet consensus threshold"  # type: ignore[operator]
