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


from .main import main as cli_main
from .ai_wrapper import AIWrapper
from .pipeline import Pipeline, PipelineProcessor
from .interactive_mode import InteractiveMode
from .progress_manager import ProgressManager
from .config_profiles import ConfigProfileManager
from .enhanced_runner import EnhancedRunner

__all__ = [
    'cli_main',
    'AIWrapper',
    'Pipeline',
    'PipelineProcessor',
    'InteractiveMode',
    'ProgressManager',
    'ConfigProfileManager',
    'EnhancedRunner'
]

__version__ = '1.0.0'