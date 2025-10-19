"""Security module for Intellicrack VM and script execution hardening.

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
along with Intellicrack. If not, see <https://www.gnu.org/licenses/>.
"""

import logging

logger = logging.getLogger(__name__)

# Import security modules with error handling
try:
    from .vm_security import ResourceMonitor, VMSecurityManager, secure_vm_execution
except ImportError as e:
    logger.warning("Failed to import vm_security: %s", e)
    ResourceMonitor = None
    VMSecurityManager = None
    secure_vm_execution = None

# Also try to import from parent security modules
try:
    from ..security_enforcement import *
except ImportError as e:
    logger.warning("Failed to import security_enforcement: %s", e)

try:
    from ..security_utils import *
except ImportError as e:
    logger.warning("Failed to import security_utils: %s", e)

__all__ = []

if VMSecurityManager is not None:
    __all__.extend(["VMSecurityManager", "ResourceMonitor", "secure_vm_execution"])

# Add other security modules to __all__ if available
try:
    from .. import security_enforcement

    if hasattr(security_enforcement, "__all__"):
        __all__.extend(security_enforcement.__all__)
except (ImportError, AttributeError):
    pass

try:
    from .. import security_utils

    if hasattr(security_utils, "__all__"):
        __all__.extend(security_utils.__all__)
except (ImportError, AttributeError):
    pass
