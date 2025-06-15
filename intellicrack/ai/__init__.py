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
