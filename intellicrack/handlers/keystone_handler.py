"""Keystone Assembler Engine Handler.

This module provides a centralized handler for the Keystone assembler engine,
ensuring that it is imported safely and that appropriate fallbacks are in place
if it is not available.

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
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""

import logging

logger = logging.getLogger(__name__)

try:
    from keystone import (
        KS_ARCH_ARM,
        KS_ARCH_ARM64,
        KS_ARCH_X86,
        KS_MODE_32,
        KS_MODE_64,
        KS_MODE_ARM,
        KS_MODE_THUMB,
        Ks,
    )

    KEYSTONE_AVAILABLE = True
    logger.info("Keystone assembler engine initialized successfully")

except ImportError:
    logger.warning("Keystone assembler engine not found. Some features may be disabled.")
    KEYSTONE_AVAILABLE = False
    KS_ARCH_X86 = None
    KS_ARCH_ARM = None
    KS_ARCH_ARM64 = None
    KS_MODE_32 = None
    KS_MODE_64 = None
    KS_MODE_ARM = None
    KS_MODE_THUMB = None
    Ks = None
