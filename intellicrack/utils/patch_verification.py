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

# Import all functions from the patching patch_verification module
from .patching.patch_verification import (
    verify_patches,
    simulate_patch_and_verify,
    apply_parsed_patch_instructions_with_validation,
    rewrite_license_functions_with_parsing
)

__all__ = ['verify_patches', 'simulate_patch_and_verify',
           'apply_parsed_patch_instructions_with_validation',
           'rewrite_license_functions_with_parsing']
