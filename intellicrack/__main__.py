"""Entry point for running Intellicrack as a module.

This module enables execution of Intellicrack using Python's -m flag,
providing a standard entry point for package execution. It handles
environment setup for various display configurations and ensures
proper initialization across different platforms.

Usage:
    python -m intellicrack [args]

Environment Variables:
    DISPLAY: X11 display identifier (automatically detected)
    QT_QPA_PLATFORM: Qt platform plugin (set to 'offscreen' for headless)

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


import os
import sys

# Configure TensorFlow to prevent GPU initialization issues with Intel Arc B580
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress TensorFlow warnings
os.environ['CUDA_VISIBLE_DEVICES'] = '-1'  # Disable GPU for TensorFlow
os.environ['MKL_THREADING_LAYER'] = 'GNU'  # Fix PyTorch + TensorFlow import conflict

from .main import main

# Set Qt to offscreen mode for WSL/headless environments if no display
# This prevents Qt initialization errors when running without a GUI environment
if 'DISPLAY' not in os.environ and 'QT_QPA_PLATFORM' not in os.environ:
    os.environ['QT_QPA_PLATFORM'] = 'offscreen'


if __name__ == "__main__":
    sys.exit(main())
