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
    logger.warning("Failed to import distributed_config_dialog: %s", e)

try:
    from .guided_workflow_wizard import *
except ImportError as e:
    logger.warning("Failed to import guided_workflow_wizard: %s", e)

try:
    from .model_finetuning_dialog import *
except ImportError as e:
    logger.warning("Failed to import model_finetuning_dialog: %s", e)

try:
    from .plugin_manager_dialog import *
except ImportError as e:
    logger.warning("Failed to import plugin_manager_dialog: %s", e)

try:
    from .report_manager_dialog import *
except ImportError as e:
    logger.warning("Failed to import report_manager_dialog: %s", e)

try:
    from .similarity_search_dialog import *
except ImportError as e:
    logger.warning("Failed to import similarity_search_dialog: %s", e)

try:
    from .splash_screen import *
except ImportError as e:
    logger.warning("Failed to import splash_screen: %s", e)

try:
    from .text_editor_dialog import *
except ImportError as e:
    logger.warning("Failed to import text_editor_dialog: %s", e)

try:
    from .visual_patch_editor import *
except ImportError as e:
    logger.warning("Failed to import visual_patch_editor: %s", e)

# Define package exports
__all__ = [
    # From distributed_config_dialog
    'DistributedProcessingConfigDialog',
    'create_distributed_config_dialog',

    # From guided_workflow_wizard
    'GuidedWorkflowWizard',
    'create_guided_workflow_wizard',

    # From model_finetuning_dialog
    'ModelFinetuningDialog',
    'TrainingConfig',
    'AugmentationConfig',
    'TrainingThread',
    'create_model_finetuning_dialog',

    # From plugin_manager_dialog
    'PluginManagerDialog',
    'PluginInstallThread',

    # From report_manager_dialog
    'ReportManagerDialog',
    'ReportGenerationThread',

    # From similarity_search_dialog
    'BinarySimilaritySearchDialog',
    'create_similarity_search_dialog',

    # From splash_screen
    'SplashScreen',
    'create_progress_splash_screen',
    'IntellicrackApp',

    # From text_editor_dialog
    'TextEditorDialog',
    'PythonSyntaxHighlighter',
    'FindReplaceDialog',

    # From visual_patch_editor
    'VisualPatchEditorDialog',
    'create_visual_patch_editor',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
