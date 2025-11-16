"""Intellicrack AI Package.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging

logger = logging.getLogger(__name__)
logger.debug("AI module loaded")

_lazy_imports = {}


def __getattr__(name: str):
    """Lazy load AI module attributes to prevent circular imports."""
    if name in _lazy_imports:
        return _lazy_imports[name]

    import_map = {
        'AIAssistant': ('code_analysis_tools', 'AIAssistant'),
        'CodeAnalyzer': ('code_analysis_tools', 'CodeAnalyzer'),
        'analyze_with_ai': ('code_analysis_tools', 'analyze_with_ai'),
        'explain_code': ('code_analysis_tools', 'explain_code'),
        'get_ai_suggestions': ('code_analysis_tools', 'get_ai_suggestions'),
        'ModelBackend': ('model_manager_module', 'ModelBackend'),
        'ModelManager': ('model_manager_module', 'ModelManager'),
        'ONNXBackend': ('model_manager_module', 'ONNXBackend'),
        'PyTorchBackend': ('model_manager_module', 'PyTorchBackend'),
        'SklearnBackend': ('model_manager_module', 'SklearnBackend'),
        'TensorFlowBackend': ('model_manager_module', 'TensorFlowBackend'),
        'configure_ai_provider': ('model_manager_module', 'configure_ai_provider'),
        'list_available_models': ('model_manager_module', 'list_available_models'),
        'load_model': ('model_manager_module', 'load_model'),
        'save_model': ('model_manager_module', 'save_model'),
        'LLMBackend': ('llm_backends', 'LLMBackend'),
        'LLMConfig': ('llm_backends', 'LLMConfig'),
        'LLMManager': ('llm_backends', 'LLMManager'),
        'LLMMessage': ('llm_backends', 'LLMMessage'),
        'LLMProvider': ('llm_backends', 'LLMProvider'),
        'LLMResponse': ('llm_backends', 'LLMResponse'),
        'create_anthropic_config': ('llm_backends', 'create_anthropic_config'),
        'create_gguf_config': ('llm_backends', 'create_gguf_config'),
        'create_ollama_config': ('llm_backends', 'create_ollama_config'),
        'create_openai_config': ('llm_backends', 'create_openai_config'),
        'get_llm_manager': ('llm_backends', 'get_llm_manager'),
        'shutdown_llm_manager': ('llm_backends', 'shutdown_llm_manager'),
        'AnthropicProviderClient': ('api_provider_clients', 'AnthropicProviderClient'),
        'BaseProviderClient': ('api_provider_clients', 'BaseProviderClient'),
        'LMStudioProviderClient': ('api_provider_clients', 'LMStudioProviderClient'),
        'LocalProviderClient': ('api_provider_clients', 'LocalProviderClient'),
        'ModelInfo': ('api_provider_clients', 'ModelInfo'),
        'OllamaProviderClient': ('api_provider_clients', 'OllamaProviderClient'),
        'OpenAIProviderClient': ('api_provider_clients', 'OpenAIProviderClient'),
        'ProviderManager': ('api_provider_clients', 'ProviderManager'),
        'get_provider_manager': ('api_provider_clients', 'get_provider_manager'),
        'ModelDiscoveryService': ('model_discovery_service', 'ModelDiscoveryService'),
        'get_model_discovery_service': ('model_discovery_service', 'get_model_discovery_service'),
        'LLMConfigManager': ('llm_config_manager', 'LLMConfigManager'),
        'get_llm_config_manager': ('llm_config_manager', 'get_llm_config_manager'),
        'AIEventBus': ('orchestrator', 'AIEventBus'),
        'AIOrchestrator': ('orchestrator', 'AIOrchestrator'),
        'AIResult': ('orchestrator', 'AIResult'),
        'AISharedContext': ('orchestrator', 'AISharedContext'),
        'AITask': ('orchestrator', 'AITask'),
        'AITaskType': ('orchestrator', 'AITaskType'),
        'AnalysisComplexity': ('orchestrator', 'AnalysisComplexity'),
        'get_orchestrator': ('orchestrator', 'get_orchestrator'),
        'shutdown_orchestrator': ('orchestrator', 'shutdown_orchestrator'),
        'AICoordinationLayer': ('coordination_layer', 'AICoordinationLayer'),
        'AnalysisRequest': ('coordination_layer', 'AnalysisRequest'),
        'AnalysisStrategy': ('coordination_layer', 'AnalysisStrategy'),
        'CoordinatedResult': ('coordination_layer', 'CoordinatedResult'),
        'comprehensive_analysis': ('coordination_layer', 'comprehensive_analysis'),
        'quick_vulnerability_scan': ('coordination_layer', 'quick_vulnerability_scan'),
        'IntellicrackAIAssistant': ('interactive_assistant', 'IntellicrackAIAssistant'),
        'Tool': ('interactive_assistant', 'Tool'),
        'ToolCategory': ('interactive_assistant', 'ToolCategory'),
        'ResponseLineParser': ('parsing_utils', 'ResponseLineParser'),
        'LicensingProtectionAnalyzer': ('vulnerability_research_integration', 'LicensingProtectionAnalyzer'),
        'AILearningEngine': ('learning_engine_simple', 'AILearningEngine'),
        'FailureAnalysis': ('learning_engine_simple', 'FailureAnalysis'),
        'LearningRecord': ('learning_engine_simple', 'LearningRecord'),
        'PatternRule': ('learning_engine_simple', 'PatternRule'),
        'get_learning_engine': ('learning_engine_simple', 'get_learning_engine'),
        'AgentMessage': ('multi_agent_system', 'AgentMessage'),
        'AgentRole': ('multi_agent_system', 'AgentRole'),
        'AgentTask': ('multi_agent_system', 'AgentTask'),
        'MessageType': ('multi_agent_system', 'MessageType'),
        'MultiAgentSystem': ('multi_agent_system', 'MultiAgentSystem'),
        'TaskPriority': ('multi_agent_system', 'TaskPriority'),
        'AdaptationRule': ('realtime_adaptation_engine', 'AdaptationRule'),
        'AdaptationType': ('realtime_adaptation_engine', 'AdaptationType'),
        'RealTimeAdaptationEngine': ('realtime_adaptation_engine', 'RealTimeAdaptationEngine'),
        'RuntimeMetric': ('realtime_adaptation_engine', 'RuntimeMetric'),
        'TriggerCondition': ('realtime_adaptation_engine', 'TriggerCondition'),
        'BusinessLogicPattern': ('semantic_code_analyzer', 'BusinessLogicPattern'),
        'SemanticCodeAnalyzer': ('semantic_code_analyzer', 'SemanticCodeAnalyzer'),
        'SemanticIntent': ('semantic_code_analyzer', 'SemanticIntent'),
        'SemanticNode': ('semantic_code_analyzer', 'SemanticNode'),
        'SemanticRelationship': ('semantic_code_analyzer', 'SemanticRelationship'),
        'CacheManager': ('performance_optimization_layer', 'CacheManager'),
        'OptimizationStrategy': ('performance_optimization_layer', 'OptimizationStrategy'),
        'ParallelExecutor': ('performance_optimization_layer', 'ParallelExecutor'),
        'PerformanceOptimizationLayer': ('performance_optimization_layer', 'PerformanceOptimizationLayer'),
        'PerformanceOptimizer': ('performance_optimization_layer', 'PerformanceOptimizer'),
        'ResourceManager': ('performance_optimization_layer', 'ResourceManager'),
        'ResourceType': ('performance_optimization_layer', 'ResourceType'),
        'performance_optimization_layer': ('performance_optimization_layer', 'performance_optimization_layer'),
        'AnalyticsEngine': ('visualization_analytics', 'AnalyticsEngine'),
        'ChartData': ('visualization_analytics', 'ChartData'),
        'ChartGenerator': ('visualization_analytics', 'ChartGenerator'),
        'ChartType': ('visualization_analytics', 'ChartType'),
        'Dashboard': ('visualization_analytics', 'Dashboard'),
        'DashboardManager': ('visualization_analytics', 'DashboardManager'),
        'MetricType': ('visualization_analytics', 'MetricType'),
        'VisualizationAnalytics': ('visualization_analytics', 'VisualizationAnalytics'),
        'visualization_analytics': ('visualization_analytics', 'visualization_analytics'),
        'ExecutionTimePredictor': ('predictive_intelligence', 'ExecutionTimePredictor'),
        'PredictionConfidence': ('predictive_intelligence', 'PredictionConfidence'),
        'PredictionResult': ('predictive_intelligence', 'PredictionResult'),
        'PredictionType': ('predictive_intelligence', 'PredictionType'),
        'PredictiveIntelligenceEngine': ('predictive_intelligence', 'PredictiveIntelligenceEngine'),
        'SuccessProbabilityPredictor': ('predictive_intelligence', 'SuccessProbabilityPredictor'),
        'VulnerabilityPredictor': ('predictive_intelligence', 'VulnerabilityPredictor'),
        'predictive_intelligence': ('predictive_intelligence', 'predictive_intelligence'),
        'FailureType': ('system_monitor', 'FailureType'),
        'HealthMonitor': ('system_monitor', 'HealthMonitor'),
        'HealthStatus': ('system_monitor', 'HealthStatus'),
        'RecoveryStrategy': ('system_monitor', 'RecoveryStrategy'),
        'RecoverySystem': ('system_monitor', 'RecoverySystem'),
        'ResilienceSelfHealingSystem': ('system_monitor', 'ResilienceSelfHealingSystem'),
        'StateManager': ('system_monitor', 'StateManager'),
        'resilience_system': ('system_monitor', 'resilience_system'),
        'AIScriptGenerator': ('ai_script_generator', 'AIScriptGenerator'),
        'ScriptType': ('ai_script_generator', 'ScriptType'),
        'AIAgent': ('script_generation_agent', 'AIAgent'),
        'ChangeStatus': ('intelligent_code_modifier', 'ChangeStatus'),
        'CodeChange': ('intelligent_code_modifier', 'CodeChange'),
        'IntelligentCodeModifier': ('intelligent_code_modifier', 'IntelligentCodeModifier'),
        'ModificationRequest': ('intelligent_code_modifier', 'ModificationRequest'),
        'ModificationType': ('intelligent_code_modifier', 'ModificationType'),
        'QEMUManager': ('qemu_manager', 'QEMUManager'),
        'IntegrationManager': ('integration_manager', 'IntegrationManager'),
        'IntegrationTask': ('integration_manager', 'IntegrationTask'),
        'WorkflowResult': ('integration_manager', 'WorkflowResult'),
        'PerformanceMetric': ('performance_monitor', 'PerformanceMetric'),
        'PerformanceMonitor': ('performance_monitor', 'PerformanceMonitor'),
        'PerformanceProfile': ('performance_monitor', 'PerformanceProfile'),
        'monitor_memory_usage': ('performance_monitor', 'monitor_memory_usage'),
        'performance_monitor': ('performance_monitor', 'performance_monitor'),
        'profile_ai_operation': ('performance_monitor', 'profile_ai_operation'),
        'OptimizationManager': ('optimization_config', 'OptimizationManager'),
        'OptimizationRule': ('optimization_config', 'OptimizationRule'),
        'PerformanceConfig': ('optimization_config', 'PerformanceConfig'),
        'benchmark_ai_optimizations': ('optimization_config', 'benchmark_ai_optimizations'),
        'get_performance_recommendations': ('optimization_config', 'get_performance_recommendations'),
        'optimization_manager': ('optimization_config', 'optimization_manager'),
        'optimize_ai_performance': ('optimization_config', 'optimize_ai_performance'),
    }

    special_cases = {
        'QemuTestManager': ('qemu_manager', 'QEMUManager'),
        'learning_engine': ('learning_engine_simple', 'get_learning_engine'),
    }

    if name in {'MLVulnerabilityPredictor', 'VulnerabilityPredictor'}:
        _lazy_imports[name] = None
        return None
    if name in ('ml_predictor', 'predict_vulnerabilities', 'train_model', 'evaluate_model'):
        _lazy_imports[name] = None
        return None

    if name in special_cases:
        module_name, attr_name = special_cases[name]
        try:
            module = __import__(f'{__name__}.{module_name}', fromlist=[attr_name])
            result = getattr(module, attr_name)
            _lazy_imports[name] = result
            return result
        except (ImportError, AttributeError) as e:
            logger.warning(f"Failed to import {name} from {module_name}: {e}")
            _lazy_imports[name] = None
            return None

    if name in import_map:
        module_name, attr_name = import_map[name]
        try:
            module = __import__(f'{__name__}.{module_name}', fromlist=[attr_name])
            result = getattr(module, attr_name)
            _lazy_imports[name] = result
            return result
        except (ImportError, AttributeError) as e:
            logger.warning(f"Failed to import {name} from {module_name}: {e}")
            _lazy_imports[name] = None
            return None

    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")


__all__ = [
    "AdaptationRule",
    "AdaptationType",
    "AgentMessage",
    "AgentRole",
    "AgentTask",
    "AIAssistant",
    "AICoordinationLayer",
    "AIEventBus",
    "AIOrchestrator",
    "AIScriptGenerator",
    "AISharedContext",
    "AIResult",
    "AITask",
    "AITaskType",
    "AnalysisComplexity",
    "AnalysisRequest",
    "AnalysisStrategy",
    "AnthropicProviderClient",
    "BaseProviderClient",
    "benchmark_ai_optimizations",
    "BusinessLogicPattern",
    "ChangeStatus",
    "CodeAnalyzer",
    "CodeChange",
    "comprehensive_analysis",
    "configure_ai_provider",
    "create_anthropic_config",
    "create_gguf_config",
    "create_ollama_config",
    "create_openai_config",
    "explain_code",
    "FailureAnalysis",
    "get_ai_suggestions",
    "get_llm_config_manager",
    "get_llm_manager",
    "get_model_discovery_service",
    "get_orchestrator",
    "get_performance_recommendations",
    "get_provider_manager",
    "IntelligentCodeModifier",
    "IntellicrackAIAssistant",
    "IntegrationManager",
    "IntegrationTask",
    "LicensingProtectionAnalyzer",
    "LLMBackend",
    "LLMConfig",
    "LLMConfigManager",
    "LLMManager",
    "LLMMessage",
    "LLMProvider",
    "LLMResponse",
    "learning_engine",
    "LearningRecord",
    "list_available_models",
    "load_model",
    "LocalProviderClient",
    "LMStudioProviderClient",
    "MessageType",
    "ModelBackend",
    "ModelDiscoveryService",
    "ModelInfo",
    "ModelManager",
    "monitor_memory_usage",
    "MultiAgentSystem",
    "ONNXBackend",
    "OllamaProviderClient",
    "OpenAIProviderClient",
    "optimization_manager",
    "OptimizationManager",
    "OptimizationRule",
    "optimize_ai_performance",
    "performance_monitor",
    "PerformanceConfig",
    "PerformanceMetric",
    "PerformanceMonitor",
    "PerformanceProfile",
    "PatternRule",
    "profile_ai_operation",
    "ProviderManager",
    "PyTorchBackend",
    "QemuTestManager",
    "quick_vulnerability_scan",
    "RealTimeAdaptationEngine",
    "ResponseLineParser",
    "RuntimeMetric",
    "ScriptType",
    "SemanticCodeAnalyzer",
    "SemanticIntent",
    "SemanticNode",
    "SemanticRelationship",
    "shutdown_llm_manager",
    "shutdown_orchestrator",
    "SklearnBackend",
    "TaskPriority",
    "TensorFlowBackend",
    "Tool",
    "ToolCategory",
    "TriggerCondition",
    "WorkflowResult",
    "analyze_with_ai",
    "save_model",
]

__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
