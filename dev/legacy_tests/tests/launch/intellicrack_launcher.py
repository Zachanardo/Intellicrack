#!/usr/bin/env python3
"""
Intellicrack Launcher - Optimized for Intel Arc B580
"""

import os
import sys
import signal
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Intel Arc B580 compatibility settings
os.environ['DISABLE_TENSORFLOW'] = '1'
os.environ['QT_OPENGL'] = 'software'
os.environ['QT_ANGLE_PLATFORM'] = 'warp'
os.environ['QT_D3D_ADAPTER_INDEX'] = '1'
os.environ['QT_QUICK_BACKEND'] = 'software'
os.environ['QT_QPA_PLATFORM'] = 'windows'
os.environ['PYTHONUNBUFFERED'] = '1'

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    logger.info("Shutting down Intellicrack...")
    sys.exit(0)

def main():
    """Launch Intellicrack with proper error handling."""
    signal.signal(signal.SIGINT, signal_handler)

    try:
        logger.info("Starting Intellicrack...")
        logger.info("Intel Arc B580 compatibility mode enabled")

        # Try to import and run the main application
        try:
            from intellicrack.main import main
            logger.info("Main module imported successfully")

            result = main()
            logger.info(f"Application exited with code: {result}")
            return result

        except ImportError as e:
            logger.error(f"Failed to import main module: {e}")

            # Fallback to minimal UI
            logger.info("Attempting minimal UI fallback...")
            from PyQt6.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget
            from PyQt6.QtCore import Qt

            app = QApplication(sys.argv)

            window = QMainWindow()
            window.setWindowTitle("Intellicrack - Recovery Mode")
            window.setGeometry(100, 100, 800, 600)

            central = QWidget()
            layout = QVBoxLayout(central)

            label = QLabel("""
<h1>Intellicrack - Recovery Mode</h1>
<p>The application encountered an error during startup.</p>
<p>Error: """ + str(e) + """</p>
<p>Please check the logs for more information.</p>
            """)
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(label)

            window.setCentralWidget(central)
            window.show()

            return app.exec()

    except Exception as e:
        logger.error(f"Critical error: {e}")
        import traceback
        traceback.print_exc()

        # Show error dialog if possible
        try:
            from PyQt6.QtWidgets import QApplication, QMessageBox

            if not QApplication.instance():
                app = QApplication(sys.argv)

            QMessageBox.critical(
                None,
                "Intellicrack Error",
                f"Failed to start Intellicrack:\n\n{str(e)}\n\nPlease check the console for details."
            )
        except:
            pass

        return 1

if __name__ == "__main__":
    sys.exit(main())
