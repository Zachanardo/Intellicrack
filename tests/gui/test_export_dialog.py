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
Test script for the Export Dialog

This script tests the export functionality independently.
"""

import os
import sys

from PyQt6.QtWidgets import QApplication

from intellicrack.ui.dialogs.export_dialog import ExportDialog

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))



def create_mock_results():
    """Create mock analysis results for testing"""
    class MockDetection:
        def __init__(self, name, det_type, confidence, version=""):
            self.name = name
            self.type = det_type
            self.confidence = confidence
            self.version = version
    
    class MockICPAnalysis:
        def __init__(self):
            self.file_type = "PE32"
            self.architecture = "x86-64"
            self.is_protected = True
            self.all_detections = [
                MockDetection("UPX", "Packer", 0.95, "3.96"),
                MockDetection("VMProtect", "Protector", 0.78, "3.5"),
                MockDetection("Anti-Debug", "Protector", 0.65),
                MockDetection("Themida", "Protector", 0.42, "3.1"),
                MockDetection("Custom Cryptor", "Cryptor", 0.30)
            ]
    
    return {
        "file_info": {
            "file_path": "/test/sample.exe",
            "file_size": 1024000,
            "file_name": "sample.exe",
            "md5": "abc123def456...",
            "sha256": "def456abc123...",
            "created_date": "2025-01-01 12:00:00",
            "modified_date": "2025-01-01 12:30:00"
        },
        "icp_analysis": MockICPAnalysis(),
        "protections": [
            {"name": "UPX", "type": "Packer", "confidence": 95.0, "source": "ICP"},
            {"name": "VMProtect", "type": "Protector", "confidence": 78.0, "source": "ICP"}
        ],
        "file_type": "PE32",
        "architecture": "x86-64",
        "is_protected": True
    }


def main():
    """Test the export dialog"""
    app = QApplication(sys.argv)
    
    # Create mock results
    mock_results = create_mock_results()
    
    # Create and show the export dialog
    dialog = ExportDialog(mock_results)
    dialog.show()
    
    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
