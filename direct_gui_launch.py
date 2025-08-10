#!/usr/bin/env python
"""Direct GUI launch bypassing normal imports."""

import sys
import os
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.absolute()
sys.path.insert(0, str(project_root))

print("Attempting direct GUI launch...")

try:
    print("1. Setting up environment...")
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    os.environ.setdefault("MKL_NUM_THREADS", "1")
    os.environ.setdefault("NUMEXPR_NUM_THREADS", "1")
    
    print("2. Importing PyQt6...")
    from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
    from PyQt6.QtCore import Qt
    
    print("3. Creating application...")
    app = QApplication(sys.argv)
    
    print("4. Creating main window...")
    window = QMainWindow()
    window.setWindowTitle("Intellicrack - Test Launch")
    window.setGeometry(100, 100, 800, 600)
    
    central_widget = QWidget()
    layout = QVBoxLayout()
    
    label = QLabel("Intellicrack GUI Test Launch Successful!")
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    label.setStyleSheet("font-size: 20px; color: green; margin: 50px;")
    
    layout.addWidget(label)
    central_widget.setLayout(layout)
    window.setCentralWidget(central_widget)
    
    print("5. Showing window...")
    window.show()
    
    print("6. Starting event loop...")
    print("✅ GUI launched successfully! Close the window to exit.")
    
    # Run for a short time then exit
    from PyQt6.QtCore import QTimer
    timer = QTimer()
    timer.singleShot(3000, app.quit)  # Close after 3 seconds
    
    app.exec()
    
except Exception as e:
    import traceback
    print(f"\n❌ Error: {e}")
    print("\nFull traceback:")
    traceback.print_exc()
    sys.exit(1)