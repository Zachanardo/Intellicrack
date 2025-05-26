"""
Intellicrack UI Dialogs Package

This package provides specialized dialog windows for the Intellicrack user interface.
It includes configuration dialogs, wizards, editors, and managers for various aspects
of the application's functionality.

Modules:
    - distributed_config_dialog: Configuration for distributed processing
    - guided_workflow_wizard: Step-by-step workflow guidance
    - model_finetuning_dialog: AI model fine-tuning interface
    - plugin_manager_dialog: Plugin management interface
    - report_manager_dialog: Report generation and management
    - similarity_search_dialog: Binary similarity search interface
    - splash_screen: Application startup splash screen
    - text_editor_dialog: Built-in text editor
    - visual_patch_editor: Visual binary patching interface

Key Features:
    - Intuitive configuration interfaces
    - Guided workflows for complex tasks
    - Visual editing capabilities
    - Plugin and model management
    - Integrated reporting tools
"""

import logging

# Set up package logger
logger = logging.getLogger(__name__)

# Import dialog modules with error handling
try:
    from .distributed_config_dialog import *
except ImportError as e:
    logger.warning(f"Failed to import distributed_config_dialog: {e}")

try:
    from .guided_workflow_wizard import *
except ImportError as e:
    logger.warning(f"Failed to import guided_workflow_wizard: {e}")

try:
    from .model_finetuning_dialog import *
except ImportError as e:
    logger.warning(f"Failed to import model_finetuning_dialog: {e}")

# Temporarily disabled due to indentation issues
# try:
#     from .plugin_manager_dialog import *
# except ImportError as e:
#     logger.warning(f"Failed to import plugin_manager_dialog: {e}")

try:
    from .report_manager_dialog import *
except ImportError as e:
    logger.warning(f"Failed to import report_manager_dialog: {e}")

try:
    from .similarity_search_dialog import *
except ImportError as e:
    logger.warning(f"Failed to import similarity_search_dialog: {e}")

try:
    from .splash_screen import *
except ImportError as e:
    logger.warning(f"Failed to import splash_screen: {e}")

try:
    from .text_editor_dialog import *
except ImportError as e:
    logger.warning(f"Failed to import text_editor_dialog: {e}")

try:
    from .visual_patch_editor import *
except ImportError as e:
    logger.warning(f"Failed to import visual_patch_editor: {e}")

# Define package exports
__all__ = [
    # From distributed_config_dialog
    'DistributedConfigDialog',
    'configure_distributed_processing',
    
    # From guided_workflow_wizard
    'GuidedWorkflowWizard',
    'create_workflow_wizard',
    
    # From model_finetuning_dialog
    'ModelFinetuningDialog',
    'open_model_finetuning',
    
    # From plugin_manager_dialog
    'PluginManagerDialog',
    'manage_plugins',
    
    # From report_manager_dialog
    'ReportManagerDialog',
    'manage_reports',
    
    # From similarity_search_dialog
    'SimilaritySearchDialog',
    'search_similar_binaries',
    
    # From splash_screen
    'SplashScreen',
    'show_splash_screen',
    
    # From text_editor_dialog
    'TextEditorDialog',
    'open_text_editor',
    
    # From visual_patch_editor
    'VisualPatchEditor',
    'open_patch_editor',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
