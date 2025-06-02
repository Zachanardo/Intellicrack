"""
Intellicrack AI Package

This package provides artificial intelligence and machine learning capabilities for the
Intellicrack framework. It includes tools for AI-assisted analysis, ML-based predictions,
model management, and a sophisticated coordination system that creates a truly agentic environment.

Modules:
    - ai_tools: General AI tools and utilities for analysis assistance
    - ml_predictor: Machine learning prediction models for vulnerability detection
    - model_manager_module: Management and deployment of AI/ML models
    - orchestrator: Central AI coordination system for agentic workflows
    - coordination_layer: Intelligent coordination between fast ML and smart LLMs

Key Features:
    - AI-powered code analysis with agentic coordination
    - Fast ML vulnerability prediction with intelligent escalation
    - Comprehensive model management for multiple AI backends
    - Event-driven communication between AI components
    - Shared context and memory across AI workflows
    - Adaptive analysis strategies (ML-first, LLM-first, parallel)
    - Pattern recognition capabilities
    - Model fine-tuning and management
    - Integration with multiple AI providers
    - Automated analysis suggestions
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import AI modules with error handling
try:
    from .ai_tools import *
except ImportError as e:
    logger.warning(f"Failed to import ai_tools: {e}")

try:
    from .ml_predictor import *
except ImportError as e:
    logger.warning(f"Failed to import ml_predictor: {e}")

try:
    from .model_manager_module import *
except ImportError as e:
    logger.warning(f"Failed to import model_manager_module: {e}")

try:
    from .orchestrator import *
except ImportError as e:
    logger.warning(f"Failed to import orchestrator: {e}")

try:
    from .coordination_layer import *
except ImportError as e:
    logger.warning(f"Failed to import coordination_layer: {e}")

try:
    from .ai_assistant_enhanced import *
except ImportError as e:
    logger.warning(f"Failed to import ai_assistant_enhanced: {e}")

try:
    from .llm_backends import *
except ImportError as e:
    logger.warning(f"Failed to import llm_backends: {e}")

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
    
    # From llm_backends (GGUF and API Support)
    'LLMManager',
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
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
