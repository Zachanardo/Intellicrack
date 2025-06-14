#!/usr/bin/env python3
"""
Intellicrack Launcher

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

import sys
import os
import warnings
import subprocess

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Fix siphash
try:
    import siphash24
except ImportError:
    from utils import siphash24_replacement
    sys.modules['siphash24'] = siphash24_replacement

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)
os.environ['QT_LOGGING_RULES'] = '*.debug=false;qt.qpa.*=false'

# Import Qt FIRST before anything else
from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

logger.info("Creating QApplication...")
app = QApplication(sys.argv)

# Set up simple logging AFTER QApplication is created
import logging
from datetime import datetime

# Create logs directory
log_dir = os.path.join(os.path.dirname(__file__), 'logs')
os.makedirs(log_dir, exist_ok=True)

# Set up basic logging
log_file = os.path.join(log_dir, f'intellicrack_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
# Set up logging with proper encoding handling
import sys
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

# Handle encoding errors gracefully on Windows
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except (AttributeError, IOError):
        pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        stream_handler
    ]
)

logger = logging.getLogger('Intellicrack')
logger.info("="*60)
logger.info("Intellicrack Starting Up")
logger.info(f"Log file: {log_file}")
logger.info("="*60)

# Run setup verification before launch
setup_verification_script = os.path.join(os.path.dirname(__file__), 'tools', 'setup', 'verify_setup.bat')
if os.path.exists(setup_verification_script):
    logger.info("Running setup verification...")
    try:
        result = subprocess.run([setup_verification_script], 
                              capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.warning("Setup verification suggested running full setup")
        else:
            logger.info("Setup verification passed")
    except Exception as e:
        logger.warning(f"Setup verification failed: {e}")
else:
    logger.warning("Setup verification script not found")

# Set application icon
icon_path = os.path.join(os.path.dirname(__file__), 'assets', 'icon.ico')
if os.path.exists(icon_path):
    app.setWindowIcon(QIcon(icon_path))
    logger.info("Application icon set")

# Import splash screen and main app
from intellicrack.ui.dialogs.splash_screen import SplashScreen
from intellicrack.ui.main_app import IntellicrackApp

# Show splash screen
splash_image_path = os.path.join(os.path.dirname(__file__), 'assets', 'splash.png')
if os.path.exists(splash_image_path):
    logger.info("Showing splash screen...")
    splash = SplashScreen(splash_image_path)
    splash.show()
    app.processEvents()
else:
    logger.warning(f"Splash image not found at: {splash_image_path}")
    splash = None

# Small delay for splash visibility
import time
if splash:
    time.sleep(2)  # Show splash for 2 seconds

logger.info("Creating main window...")
window = IntellicrackApp()

logger.info("Showing main window...")
window.show()

# Close splash screen
if splash:
    splash.finish(window)
    logger.info("Splash screen closed")

logger.info(f"Window visible: {window.isVisible()}")

# Start event loop
logger.info("Starting Qt event loop...")
sys.exit(app.exec_())