"""Intellicrack UI Dialogs Package

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

# Import dialog modules with error handling
try:
    from .distributed_config_dialog import DistributedProcessingConfigDialog
except ImportError as e:
    logger.warning("Failed to import distributed_config_dialog: %s", e)
    DistributedProcessingConfigDialog = None

try:
    from .guided_workflow_wizard import GuidedWorkflowWizard
except ImportError as e:
    logger.warning("Failed to import guided_workflow_wizard: %s", e)
    GuidedWorkflowWizard = None

try:
    from .model_finetuning_dialog import (
        AugmentationConfig,
        ModelFinetuningDialog,
        TrainingConfig,
        TrainingThread,
    )
except ImportError as e:
    logger.warning("Failed to import model_finetuning_dialog: %s", e)
    ModelFinetuningDialog = None
    TrainingConfig = None
    AugmentationConfig = None
    TrainingThread = None

try:
    from .plugin_manager_dialog import PluginManagerDialog
except ImportError as e:
    logger.warning("Failed to import plugin_manager_dialog: %s", e)
    PluginManagerDialog = None

try:
    from .report_manager_dialog import ReportGenerationThread, ReportManagerDialog
except ImportError as e:
    logger.warning("Failed to import report_manager_dialog: %s", e)
    ReportManagerDialog = None
    ReportGenerationThread = None

try:
    from .similarity_search_dialog import BinarySimilaritySearchDialog
except ImportError as e:
    logger.warning("Failed to import similarity_search_dialog: %s", e)
    BinarySimilaritySearchDialog = None

try:
    from .base_dialog import BaseTemplateDialog, BinarySelectionDialog
except ImportError as e:
    logger.warning("Failed to import base_dialog: %s", e)
    BinarySelectionDialog = None
    BaseTemplateDialog = None

try:
    from .splash_screen import SplashScreen
except ImportError as e:
    logger.warning("Failed to import splash_screen: %s", e)
    SplashScreen = None

try:
    from .text_editor_dialog import FindReplaceDialog, PythonSyntaxHighlighter, TextEditorDialog
except ImportError as e:
    logger.warning("Failed to import text_editor_dialog: %s", e)
    TextEditorDialog = None
    PythonSyntaxHighlighter = None
    FindReplaceDialog = None

try:
    from .visual_patch_editor import VisualPatchEditorDialog
except ImportError as e:
    logger.warning("Failed to import visual_patch_editor: %s", e)
    VisualPatchEditorDialog = None

try:
    from .payload_generator_dialog import PayloadGeneratorDialog
except ImportError as e:
    logger.warning("Failed to import payload_generator_dialog: %s", e)
    PayloadGeneratorDialog = None

try:
    from .c2_management_dialog import C2ManagementDialog
except ImportError as e:
    logger.warning("Failed to import c2_management_dialog: %s", e)
    C2ManagementDialog = None

try:
    from .frida_manager_dialog import FridaManagerDialog
except ImportError as e:
    logger.warning("Failed to import frida_manager_dialog: %s", e)
    FridaManagerDialog = None

try:
    from .plugin_creation_wizard import PluginCreationWizard
except ImportError as e:
    logger.warning("Failed to import plugin_creation_wizard: %s", e)
    PluginCreationWizard = None

try:
    from .plugin_editor_dialog import PluginEditorDialog
except ImportError as e:
    logger.warning("Failed to import plugin_editor_dialog: %s", e)
    PluginEditorDialog = None

try:
    from .test_generator_dialog import TestGeneratorDialog
except ImportError as e:
    logger.warning("Failed to import test_generator_dialog: %s", e)
    TestGeneratorDialog = None

try:
    from .ci_cd_dialog import CICDDialog
except ImportError as e:
    logger.warning("Failed to import ci_cd_dialog: %s", e)
    CICDDialog = None

try:
    from .debugger_dialog import DebuggerDialog
except ImportError as e:
    logger.warning("Failed to import debugger_dialog: %s", e)
    DebuggerDialog = None

try:
    from .program_selector_dialog import (
        ProgramSelectorDialog,
        show_program_selector,
        show_smart_program_selector,
    )
except ImportError as e:
    logger.warning("Failed to import program_selector_dialog: %s", e)
    ProgramSelectorDialog = None
    show_program_selector = None
    show_smart_program_selector = None

# Define package exports - only include successfully imported items
__all__ = []

# Add successfully imported classes to __all__
if DistributedProcessingConfigDialog is not None:
    __all__.append("DistributedProcessingConfigDialog")

if GuidedWorkflowWizard is not None:
    __all__.append("GuidedWorkflowWizard")

if ModelFinetuningDialog is not None:
    __all__.extend(["AugmentationConfig", "ModelFinetuningDialog", "TrainingConfig", "TrainingThread"])

if PluginManagerDialog is not None:
    __all__.append("PluginManagerDialog")

if ReportManagerDialog is not None:
    __all__.extend(["ReportGenerationThread", "ReportManagerDialog"])

if BinarySimilaritySearchDialog is not None:
    __all__.append("BinarySimilaritySearchDialog")

if BinarySelectionDialog is not None and BaseTemplateDialog is not None:
    __all__.extend(["BaseTemplateDialog", "BinarySelectionDialog"])

if SplashScreen is not None:
    __all__.append("SplashScreen")

if TextEditorDialog is not None:
    __all__.extend(["FindReplaceDialog", "PythonSyntaxHighlighter", "TextEditorDialog"])

if VisualPatchEditorDialog is not None:
    __all__.append("VisualPatchEditorDialog")

if PayloadGeneratorDialog is not None:
    __all__.append("PayloadGeneratorDialog")

if C2ManagementDialog is not None:
    __all__.append("C2ManagementDialog")

if FridaManagerDialog is not None:
    __all__.append("FridaManagerDialog")

if PluginCreationWizard is not None:
    __all__.append("PluginCreationWizard")

if PluginEditorDialog is not None:
    __all__.append("PluginEditorDialog")

if TestGeneratorDialog is not None:
    __all__.append("TestGeneratorDialog")

if CICDDialog is not None:
    __all__.append("CICDDialog")

if DebuggerDialog is not None:
    __all__.append("DebuggerDialog")

if ProgramSelectorDialog is not None:
    __all__.extend(["ProgramSelectorDialog", "show_program_selector", "show_smart_program_selector"])

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
