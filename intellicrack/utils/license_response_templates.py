"""
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

# Import all functions from the templates module
from .templates.license_response_templates import *

__all__ = ['get_common_license_response', 'get_adobe_response_templates',
           'get_autodesk_response_templates', 'get_jetbrains_response_templates',
           'get_microsoft_response_templates', 'get_generic_response_templates',
           'get_all_response_templates']
