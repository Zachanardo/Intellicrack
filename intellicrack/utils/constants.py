"""Constants for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.

Shared constants for Intellicrack.

This module contains constants that are used across multiple modules
to avoid code duplication.
"""

# Common file size formatting breakpoints
SIZE_UNITS = [
    (1024**3, "GB"),
    (1024**2, "MB"),
    (1024, "KB"),
    (1, "B"),
]
