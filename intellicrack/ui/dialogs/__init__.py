"""Intellicrack UI Dialogs Package.

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


logger: logging.Logger = logging.getLogger(__name__)

# Import dialog modules with error handling
# Only set attributes when imports succeed
try:
    from .distributed_config_dialog import DistributedProcessingConfigDialog
except ImportError as e:
    logger.warning("Failed to import distributed_config_dialog: %s", e)

try:
    from .guided_workflow_wizard import GuidedWorkflowWizard
except ImportError as e:
    logger.warning("Failed to import guided_workflow_wizard: %s", e)

try:
    from .model_finetuning_dialog import AugmentationConfig, ModelFinetuningDialog, TrainingConfig, TrainingThread
except ImportError as e:
    logger.warning("Failed to import model_finetuning_dialog: %s", e)

try:
    from .plugin_manager_dialog import PluginManagerDialog
except (ImportError, SyntaxError) as e:
    logger.warning("Failed to import plugin_manager_dialog: %s", e)

try:
    from .report_manager_dialog import ReportGenerationThread, ReportManagerDialog
except ImportError as e:
    logger.warning("Failed to import report_manager_dialog: %s", e)

try:
    from .similarity_search_dialog import BinarySimilaritySearchDialog
except ImportError as e:
    logger.warning("Failed to import similarity_search_dialog: %s", e)

# BaseTemplateDialog and BinarySelectionDialog don't exist in base_dialog
# Don't set them to None

try:
    from .splash_screen import SplashScreen
except ImportError as e:
    logger.warning("Failed to import splash_screen: %s", e)

try:
    from .text_editor_dialog import FindReplaceDialog, PythonSyntaxHighlighter, TextEditorDialog
except ImportError as e:
    logger.warning("Failed to import text_editor_dialog: %s", e)

try:
    from .visual_patch_editor import VisualPatchEditorDialog
except ImportError as e:
    logger.warning("Failed to import visual_patch_editor: %s", e)

try:
    from .frida_manager_dialog import FridaManagerDialog
except ImportError as e:
    logger.warning("Failed to import frida_manager_dialog: %s", e)

try:
    from .plugin_creation_wizard import PluginCreationWizard
except ImportError as e:
    logger.warning("Failed to import plugin_creation_wizard: %s", e)

try:
    from .plugin_editor_dialog import PluginEditorDialog
except ImportError as e:
    logger.warning("Failed to import plugin_editor_dialog: %s", e)

try:
    from .test_generator_dialog import TestGeneratorDialog
except ImportError as e:
    logger.warning("Failed to import test_generator_dialog: %s", e)

try:
    from .ci_cd_dialog import CICDDialog
except ImportError as e:
    logger.warning("Failed to import ci_cd_dialog: %s", e)

try:
    from .debugger_dialog import DebuggerDialog
except ImportError as e:
    logger.warning("Failed to import debugger_dialog: %s", e)

try:
    from .program_selector_dialog import ProgramSelectorDialog, show_program_selector, show_smart_program_selector
except ImportError as e:
    logger.warning("Failed to import program_selector_dialog: %s", e)

# Define package exports - only include successfully imported items
__all__: list[str] = []

# Add successfully imported classes to __all__
if "DistributedProcessingConfigDialog" in locals():
    __all__.append("DistributedProcessingConfigDialog")

if "GuidedWorkflowWizard" in locals():
    __all__.append("GuidedWorkflowWizard")

if "ModelFinetuningDialog" in locals():
    __all__.extend(["AugmentationConfig", "ModelFinetuningDialog", "TrainingConfig", "TrainingThread"])

if "PluginManagerDialog" in locals():
    __all__.append("PluginManagerDialog")

if "ReportManagerDialog" in locals():
    __all__.extend(["ReportGenerationThread", "ReportManagerDialog"])

if "BinarySimilaritySearchDialog" in locals():
    __all__.append("BinarySimilaritySearchDialog")

if "BinarySelectionDialog" in locals() and "BaseTemplateDialog" in locals():
    __all__.extend(["BaseTemplateDialog", "BinarySelectionDialog"])

if "SplashScreen" in locals():
    __all__.append("SplashScreen")

if "TextEditorDialog" in locals():
    __all__.extend(["FindReplaceDialog", "PythonSyntaxHighlighter", "TextEditorDialog"])

if "VisualPatchEditorDialog" in locals():
    __all__.append("VisualPatchEditorDialog")

if "FridaManagerDialog" in locals():
    __all__.append("FridaManagerDialog")

if "PluginCreationWizard" in locals():
    __all__.append("PluginCreationWizard")

if "PluginEditorDialog" in locals():
    __all__.append("PluginEditorDialog")

if "TestGeneratorDialog" in locals():
    __all__.append("TestGeneratorDialog")

if "CICDDialog" in locals():
    __all__.append("CICDDialog")

if "DebuggerDialog" in locals():
    __all__.append("DebuggerDialog")

if "ProgramSelectorDialog" in locals():
    __all__.extend(["ProgramSelectorDialog", "show_program_selector", "show_smart_program_selector"])

# Package metadata
__version__: str = "0.1.0"
__author__: str = "Intellicrack Development Team"
