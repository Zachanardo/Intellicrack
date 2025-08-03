#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Test script for the ICP Signature Editor Dialog

This script tests the signature editor functionality independently.
"""

import os
import sys

from PyQt6.QtWidgets import QApplication

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
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
