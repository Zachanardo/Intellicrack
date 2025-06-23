"""
Intellicrack CLI Module 

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


try:
    from .ai_wrapper import IntellicrackAIInterface
except ImportError:
    IntellicrackAIInterface = None

try:
    from .config_profiles import ConfigProfileManager
except ImportError:
    ConfigProfileManager = None

try:
    from .enhanced_runner import EnhancedRunner
except ImportError:
    EnhancedRunner = None

try:
    from .interactive_mode import InteractiveMode
except ImportError:
    InteractiveMode = None

from .main import main as cli_main

try:
    from .pipeline import Pipeline
except ImportError:
    Pipeline = None

from .progress_manager import ProgressManager

__all__ = [
    'cli_main',
    'IntellicrackAIInterface',
    'Pipeline',
    'InteractiveMode',
    'ProgressManager',
    'ConfigProfileManager',
    'EnhancedRunner'
]

__version__ = '1.0.0'
