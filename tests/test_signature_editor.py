#!/usr/bin/env python3
"""
Test script for the ICP Signature Editor Dialog

This script tests the signature editor functionality independently.
"""

import os
import sys

from PyQt5.QtWidgets import QApplication

from intellicrack.ui.dialogs.signature_editor_dialog import SignatureEditorDialog

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))



def main():
    """Test the signature editor dialog"""
    app = QApplication(sys.argv)
    
    # Create and show the signature editor
    editor = SignatureEditorDialog()
    editor.show()
    
    # Run the application
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
