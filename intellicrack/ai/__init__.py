"""
Intellicrack AI Package

This package provides artificial intelligence and machine learning capabilities for the
Intellicrack framework. It includes tools for AI-assisted analysis, ML-based predictions,
and model management for enhancing binary analysis workflows.

Modules:
    - ai_tools: General AI tools and utilities for analysis assistance
    - ml_predictor: Machine learning prediction models for vulnerability detection
    - model_manager_module: Management and deployment of AI/ML models

Key Features:
    - AI-powered code analysis
    - Vulnerability prediction models
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
    'predict_vulnerabilities',
    'train_model',
    'evaluate_model',
    
    # From model_manager_module
    'ModelManager',
    'load_model',
    'save_model',
    'list_available_models',
    'configure_ai_provider',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
