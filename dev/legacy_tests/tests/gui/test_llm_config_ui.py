#!/usr/bin/env python3
"""Test LLM Configuration Dialog functionality."""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from PyQt6.QtWidgets import QApplication
from intellicrack.ui.dialogs.llm_config_dialog import LLMConfigDialog
from intellicrack.config import CONFIG

def test_llm_config_dialog():
    """Test the LLM configuration dialog."""
    app = QApplication(sys.argv)

    # Create and show dialog
    dialog = LLMConfigDialog()

    # Test that all tabs are present
    tab_widget = dialog.tabs
    print(f"Number of tabs: {tab_widget.count()}")

    # Print tab names
    for i in range(tab_widget.count()):
        print(f"Tab {i}: {tab_widget.tabText(i)}")

    # Check for Local Models tab
    local_models_index = -1
    for i in range(tab_widget.count()):
        if tab_widget.tabText(i) == "Local Models":
            local_models_index = i
            break

    if local_models_index >= 0:
        print("✓ Local Models tab found")

        # Switch to Local Models tab
        tab_widget.setCurrentIndex(local_models_index)

        # Check for required widgets
        if hasattr(dialog, 'local_models_list'):
            print("✓ Local models list widget found")
        if hasattr(dialog, 'local_import_gguf_btn'):
            print("✓ Import GGUF button found")
        if hasattr(dialog, 'local_model_info'):
            print("✓ Model info display found")
        if hasattr(dialog, 'add_gguf_model_direct'):
            print("✓ Direct model add methods found")
    else:
        print("✗ Local Models tab not found!")

    # Test model discovery functionality
    print("\nTesting model discovery:")

    # Check OpenAI tab for refresh button
    for i in range(tab_widget.count()):
        if tab_widget.tabText(i) == "OpenAI":
            tab_widget.setCurrentIndex(i)
            if hasattr(dialog, 'openai_refresh_btn'):
                print("✓ OpenAI refresh button found")
            break

    # Check Anthropic tab for refresh button
    for i in range(tab_widget.count()):
        if tab_widget.tabText(i) == "Anthropic":
            tab_widget.setCurrentIndex(i)
            if hasattr(dialog, 'anthropic_refresh_btn'):
                print("✓ Anthropic refresh button found")
            break

    # Show dialog briefly
    dialog.show()

    # Process events to ensure UI is rendered
    app.processEvents()

    print("\nLLM Configuration Dialog test completed!")

    # Close dialog
    dialog.close()

    return 0

if __name__ == "__main__":
    sys.exit(test_llm_config_dialog())
