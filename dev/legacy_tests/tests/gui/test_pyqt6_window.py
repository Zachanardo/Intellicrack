#!/usr/bin/env python3
"""Test basic PyQt6 window display"""
import sys
import os
os.environ['MKL_THREADING_LAYER'] = 'GNU'

from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel
from PyQt6.QtCore import Qt

def test_window():
    app = QApplication(sys.argv)

    window = QMainWindow()
    window.setWindowTitle("PyQt6 Test Window")
    window.setGeometry(100, 100, 400, 300)

    label = QLabel("PyQt6 is working!", window)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    window.setCentralWidget(label)

    window.show()

    print("Window should be visible now")
    print("Close the window to exit")

    sys.exit(app.exec())

if __name__ == "__main__":
    test_window()
