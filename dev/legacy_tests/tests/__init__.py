"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Tests package for Intellicrack.

This package contains all unit tests, integration tests, and test utilities
for the Intellicrack binary analysis framework.
"""

# Test configuration
TEST_DATA_DIR = "tests/data"
TEST_BINARY_DIR = "tests/binaries"
TEST_OUTPUT_DIR = "tests/output"

# Test runner configuration
DEFAULT_TEST_TIMEOUT = 300  # 5 minutes
ENABLE_INTEGRATION_TESTS = True
ENABLE_SLOW_TESTS = False

__version__ = "0.1.0"
