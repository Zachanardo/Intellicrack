#!/usr/bin/env python3
"""Minimal Intellicrack launch to bypass all complex initialization."""

import os
import sys

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_ANGLE_PLATFORM'] = 'warp'
os.environ['QT_D3D_ADAPTER_INDEX'] = '1'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'

def main():
    """Launch minimal Intellicrack."""
    try:
        print("Starting minimal Intellicrack...")
        
        from PyQt6.QtWidgets import QApplication, QMainWindow, QTabWidget, QLabel, QVBoxLayout, QWidget
        from PyQt6.QtCore import Qt
        
        app = QApplication(sys.argv)
        
        # Create main window
        window = QMainWindow()
        window.setWindowTitle("Intellicrack - Minimal Mode (Intel Arc B580)")
        window.setGeometry(100, 100, 1200, 800)
        
        # Set dark theme
        app.setStyle("Fusion")
        app.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
            }
            QTabWidget::pane {
                border: 1px solid #444;
                background-color: #353535;
            }
            QTabBar::tab {
                background-color: #2b2b2b;
                color: white;
                padding: 8px 16px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #454545;
            }
            QLabel {
                color: white;
                padding: 20px;
            }
        """)
        
        # Create tab widget
        tabs = QTabWidget()
        
        # Add placeholder tabs
        for name in ["Dashboard", "Analysis", "Tools", "Exploitation", "AI Assistant", "Project", "Settings"]:
            widget = QWidget()
            layout = QVBoxLayout(widget)
            label = QLabel(f"""
<h2>{name} Tab</h2>
<p>This tab is running in minimal mode for Intel Arc B580 compatibility.</p>
<p>Full functionality will be enabled in a future update.</p>
            """)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(label)
            tabs.addTab(widget, name)
        
        window.setCentralWidget(tabs)
        
        # Show window
        window.show()
        
        print("✓ Intellicrack launched successfully in minimal mode!")
        print("✓ Application is running. Close the window to exit.")
        
        return app.exec()
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())