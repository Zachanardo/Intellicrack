"""Minimal Qt test to isolate crash."""
from __future__ import annotations

import sys


def main() -> int:
    """Test minimal Qt window."""
    print("Testing minimal PyQt6 window...")

    from PyQt6.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QWidget

    app = QApplication(sys.argv)

    window = QMainWindow()
    window.setWindowTitle("Minimal Qt Test")
    window.setMinimumSize(400, 300)

    central = QWidget()
    layout = QVBoxLayout(central)

    button = QPushButton("Click Me")
    button.clicked.connect(lambda: print("Button clicked!"))
    layout.addWidget(button)

    window.setCentralWidget(central)
    window.show()

    print("Window shown - try clicking the button...")
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
