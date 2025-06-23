"""
Intellicrack AI Package

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""


import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import AI modules with error handling - explicit imports to avoid F403/F405
try:
    from .ai_tools import (
        AIAssistant,
        CodeAnalyzer,
        analyze_with_ai,
        explain_code,
        get_ai_suggestions,
    )
except ImportError as e:
    logger.warning("Failed to import ai_tools: %s", e)
    AIAssistant = CodeAnalyzer = analyze_with_ai = None
    get_ai_suggestions = explain_code = None

try:
    from .ml_predictor import (
        MLPredictor,
        MLVulnerabilityPredictor,
        VulnerabilityPredictor,
        evaluate_model,
        predict_vulnerabilities,
        train_model,
    )
except ImportError as e:
    logger.warning("Failed to import ml_predictor: %s", e)
    MLVulnerabilityPredictor = MLPredictor = VulnerabilityPredictor = None
    predict_vulnerabilities = train_model = evaluate_model = None

try:
    from .model_manager_module import (
        ModelBackend,
        ModelManager,
        ONNXBackend,
        PyTorchBackend,
        SklearnBackend,
        TensorFlowBackend,
        configure_ai_provider,
        list_available_models,
        load_model,
        save_model,
    )
except ImportError as e:
    logger.warning("Failed to import model_manager_module: %s", e)
    ModelManager = ModelBackend = PyTorchBackend = TensorFlowBackend = ONNXBackend = SklearnBackend = None
    load_model = save_model = list_available_models = configure_ai_provider = None


try:
    from .llm_backends import (
        LLMBackend,
        LLMConfig,
        LLMManager,
        LLMMessage,
        LLMProvider,
        LLMResponse,
        create_anthropic_config,
        create_gguf_config,
        create_ollama_config,
        create_openai_config,
        get_llm_manager,
        shutdown_llm_manager,
    )
except ImportError as e:
    logger.warning("Failed to import llm_backends: %s", e)
    LLMManager = LLMBackend = LLMConfig = LLMProvider = None
    LLMMessage = LLMResponse = None
    get_llm_manager = shutdown_llm_manager = None
    create_openai_config = create_anthropic_config = create_gguf_config = create_ollama_config = None

try:
    from .orchestrator import (
        AIEventBus,
        AIOrchestrator,
        AIResult,
        AISharedContext,
        AITask,
        AITaskType,
        AnalysisComplexity,
        get_orchestrator,
        shutdown_orchestrator,
    )
except ImportError as e:
    logger.warning("Failed to import orchestrator: %s", e)
    AIOrchestrator = AISharedContext = AIEventBus = AITask = AIResult = None
    AITaskType = AnalysisComplexity = get_orchestrator = shutdown_orchestrator = None

try:
    from .coordination_layer import (
        AICoordinationLayer,
        AnalysisRequest,
        AnalysisStrategy,
        CoordinatedResult,
        comprehensive_analysis,
        quick_vulnerability_scan,
    )
except ImportError as e:
    logger.warning("Failed to import coordination_layer: %s", e)
    CoordinatedResult = quick_vulnerability_scan = comprehensive_analysis = None

try:
    from .ai_assistant_enhanced import IntellicrackAIAssistant, Tool, ToolCategory
except ImportError as e:
    logger.warning("Failed to import ai_assistant_enhanced: %s", e)
    IntellicrackAIAssistant = Tool = ToolCategory = None

try:
    from .parsing_utils import ResponseLineParser
except ImportError as e:
    logger.warning("Failed to import parsing_utils: %s", e)
    ResponseLineParser = None

# Import new exploitation AI modules
try:
    from .vulnerability_research_integration import VulnerabilityResearchAI
except ImportError as e:
    logger.warning("Failed to import vulnerability_research_integration: %s", e)
    VulnerabilityResearchAI = None

try:
    from .exploitation_orchestrator import ExploitationOrchestrator
except ImportError as e:
    logger.warning("Failed to import exploitation_orchestrator: %s", e)
    ExploitationOrchestrator = None

# Import advanced AI system components
try:
    from .learning_engine import (
        AILearningEngine,
        FailureAnalysis,
        LearningRecord,
        PatternRule,
        learning_engine,
    )
except ImportError as e:
    logger.warning("Failed to import learning_engine: %s", e)
    AILearningEngine = LearningRecord = PatternRule = FailureAnalysis = learning_engine = None

try:
    from .multi_agent_system import (
        AgentMessage,
        AgentRole,
        AgentTask,
        MessageType,
        MultiAgentSystem,
        TaskPriority,
    )
except ImportError as e:
    logger.warning("Failed to import multi_agent_system: %s", e)
    MultiAgentSystem = AgentRole = AgentMessage = AgentTask = TaskPriority = MessageType = None

try:
    from .realtime_adaptation_engine import (
        AdaptationRule,
        AdaptationType,
        RealTimeAdaptationEngine,
        RuntimeMetric,
        TriggerCondition,
    )
except ImportError as e:
    logger.warning("Failed to import realtime_adaptation_engine: %s", e)
    RealTimeAdaptationEngine = AdaptationType = TriggerCondition = AdaptationRule = RuntimeMetric = None

try:
    from .semantic_code_analyzer import (
        BusinessLogicPattern,
        SemanticCodeAnalyzer,
        SemanticIntent,
        SemanticNode,
        SemanticRelationship,
    )
except ImportError as e:
    logger.warning("Failed to import semantic_code_analyzer: %s", e)
    SemanticCodeAnalyzer = SemanticIntent = BusinessLogicPattern = SemanticNode = SemanticRelationship = None

try:
    from .exploit_chain_builder import (
        AutomatedExploitChainBuilder,
        ChainComplexity,
        ExploitChain,
        ExploitChainFramework,
        ExploitPrimitive,
        ExploitPrimitiveLibrary,
        ExploitStep,
        ExploitType,
        SafetyVerificationSystem,
        Vulnerability,
        exploit_chain_builder,
    )
except ImportError as e:
    logger.warning("Failed to import exploit_chain_builder: %s", e)
    AutomatedExploitChainBuilder = ExploitChainFramework = ExploitPrimitiveLibrary = SafetyVerificationSystem = None
    Vulnerability = ExploitType = ExploitPrimitive = ExploitStep = ExploitChain = ChainComplexity = exploit_chain_builder = None

try:
    from .performance_optimization_layer import (
        CacheManager,
        OptimizationStrategy,
        ParallelExecutor,
        PerformanceOptimizationLayer,
        PerformanceOptimizer,
        ResourceManager,
        ResourceType,
        performance_optimization_layer,
    )
except ImportError as e:
    logger.warning("Failed to import performance_optimization_layer: %s", e)
    PerformanceOptimizationLayer = PerformanceOptimizer = ResourceManager = ParallelExecutor = CacheManager = None
    OptimizationStrategy = ResourceType = performance_optimization_layer = None

try:
    from .visualization_analytics import (
        AnalyticsEngine,
        ChartData,
        ChartGenerator,
        ChartType,
        Dashboard,
        DashboardManager,
        MetricType,
        VisualizationAnalytics,
        visualization_analytics,
    )
except ImportError as e:
    logger.warning("Failed to import visualization_analytics: %s", e)
    VisualizationAnalytics = DashboardManager = ChartGenerator = AnalyticsEngine = None
    ChartType = MetricType = Dashboard = ChartData = visualization_analytics = None

try:
    from .predictive_intelligence import (
        ExecutionTimePredictor,
        PredictionConfidence,
        PredictionResult,
        PredictionType,
        PredictiveIntelligenceEngine,
        SuccessProbabilityPredictor,
        VulnerabilityPredictor,
        predictive_intelligence,
    )
except ImportError as e:
    logger.warning("Failed to import predictive_intelligence: %s", e)
    PredictiveIntelligenceEngine = SuccessProbabilityPredictor = ExecutionTimePredictor = VulnerabilityPredictor = None
    PredictionType = PredictionConfidence = PredictionResult = predictive_intelligence = None

try:
    from .resilience_self_healing import (
        FailureType,
        HealthMonitor,
        HealthStatus,
        RecoveryStrategy,
        RecoverySystem,
        ResilienceSelfHealingSystem,
        StateManager,
        resilience_system,
    )
except ImportError as e:
    logger.warning("Failed to import resilience_self_healing: %s", e)
    ResilienceSelfHealingSystem = HealthMonitor = RecoverySystem = StateManager = None
    FailureType = RecoveryStrategy = HealthStatus = resilience_system = None

# Import AI script generation system components
try:
    from .ai_script_generator import AIScriptGenerator, ScriptGenerationResult, ScriptType
except ImportError as e:
    logger.warning("Failed to import ai_script_generator: %s", e)
    AIScriptGenerator = ScriptType = ScriptGenerationResult = None

try:
    from .autonomous_agent import AutonomousAgent
except ImportError as e:
    logger.warning("Failed to import autonomous_agent: %s", e)
    AutonomousAgent = None

try:
    from .intelligent_code_modifier import (
        ChangeStatus,
        CodeChange,
        IntelligentCodeModifier,
        ModificationRequest,
        ModificationType,
    )
except ImportError as e:
    logger.warning("Failed to import intelligent_code_modifier: %s", e)
    IntelligentCodeModifier = CodeChange = ModificationRequest = None
    ModificationType = ChangeStatus = None

try:
    from .qemu_test_manager import QEMUTestManager
    QemuTestManager = QEMUTestManager  # For backward compatibility
except ImportError as e:
    logger.warning("Failed to import qemu_test_manager: %s", e)
    QemuTestManager = QEMUTestManager = None

try:
    from .integration_manager import IntegrationManager, IntegrationTask, WorkflowResult
except ImportError as e:
    logger.warning("Failed to import integration_manager: %s", e)
    IntegrationManager = IntegrationTask = WorkflowResult = None

try:
    from .performance_monitor import (
        PerformanceMetric,
        PerformanceMonitor,
        PerformanceProfile,
        monitor_memory_usage,
        performance_monitor,
        profile_ai_operation,
    )
except ImportError as e:
    logger.warning("Failed to import performance_monitor: %s", e)
    PerformanceMonitor = PerformanceMetric = PerformanceProfile = None
    performance_monitor = profile_ai_operation = monitor_memory_usage = None

try:
    from .optimization_config import (
        OptimizationManager,
        OptimizationRule,
        PerformanceConfig,
        benchmark_ai_optimizations,
        get_performance_recommendations,
        optimization_manager,
        optimize_ai_performance,
    )
except ImportError as e:
    logger.warning("Failed to import optimization_config: %s", e)
    OptimizationManager = OptimizationRule = PerformanceConfig = None
    optimization_manager = optimize_ai_performance = None
    get_performance_recommendations = benchmark_ai_optimizations = None

# Define package exports
__all__ = [
    # From ai_tools
    'AIAssistant',
    'CodeAnalyzer',
    'analyze_with_ai',
    'get_ai_suggestions',
    'explain_code',

    # From ml_predictor
    'MLPredictor',
    'VulnerabilityPredictor',
    'MLVulnerabilityPredictor',
    'predict_vulnerabilities',
    'train_model',
    'evaluate_model',

    # From model_manager_module
    'ModelManager',
    'ModelBackend',
    'ONNXBackend',
    'PyTorchBackend',
    'SklearnBackend',
    'TensorFlowBackend',
    'load_model',
    'save_model',
    'list_available_models',
    'configure_ai_provider',

    # From orchestrator (Agentic AI System)
    'AIOrchestrator',
    'AISharedContext',
    'AIEventBus',
    'AITask',
    'AIResult',
    'AITaskType',
    'AnalysisComplexity',
    'get_orchestrator',
    'shutdown_orchestrator',

    # From coordination_layer (Intelligent Coordination)
    'AICoordinationLayer',
    'AnalysisRequest',
    'CoordinatedResult',
    'AnalysisStrategy',
    'quick_vulnerability_scan',
    'comprehensive_analysis',

    # From ai_assistant_enhanced
    'IntellicrackAIAssistant',
    'Tool',
    'ToolCategory',

    # From exploitation modules
    'VulnerabilityResearchAI',
    'ExploitationOrchestrator',

    # From advanced AI system components
    'AILearningEngine',
    'LearningRecord',
    'PatternRule',
    'FailureAnalysis',
    'learning_engine',
    'MultiAgentSystem',
    'AgentRole',
    'AgentMessage',
    'AgentTask',
    'TaskPriority',
    'MessageType',
    'RealTimeAdaptationEngine',
    'AdaptationType',
    'TriggerCondition',
    'AdaptationRule',
    'RuntimeMetric',
    'SemanticCodeAnalyzer',
    'SemanticIntent',
    'BusinessLogicPattern',
    'SemanticNode',
    'SemanticRelationship',
    'AutomatedExploitChainBuilder',
    'ExploitChainFramework',
    'ExploitPrimitiveLibrary',
    'SafetyVerificationSystem',
    'Vulnerability',
    'ExploitType',
    'ExploitPrimitive',
    'ExploitStep',
    'ExploitChain',
    'ChainComplexity',
    'exploit_chain_builder',

    # From AI script generation system
    'AIScriptGenerator',
    'ScriptType',
    'ScriptGenerationResult',
    'AutonomousAgent',
    'IntelligentCodeModifier',
    'CodeChange',
    'ModificationRequest',
    'ModificationType',
    'ChangeStatus',
    'QemuTestManager',
    'IntegrationManager',
    'IntegrationTask',
    'WorkflowResult',
    'PerformanceMonitor',
    'PerformanceMetric',
    'PerformanceProfile',
    'performance_monitor',
    'profile_ai_operation',
    'monitor_memory_usage',
    'OptimizationManager',
    'OptimizationRule',
    'PerformanceConfig',
    'optimization_manager',
    'optimize_ai_performance',
    'get_performance_recommendations',
    'benchmark_ai_optimizations',

    # From llm_backends (GGUF and API Support)
    'LLMManager',
    'LLMBackend',
    'LLMConfig',
    'LLMProvider',
    'LLMMessage',
    'LLMResponse',
    'get_llm_manager',
    'shutdown_llm_manager',
    'create_openai_config',
    'create_anthropic_config',
    'create_gguf_config',
    'create_ollama_config',

    # From parsing_utils
    'ResponseLineParser',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
