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

This module provides security hardening capabilities for virtual machine execution
and script-based analysis, including resource monitoring and VM security management.
"""

import logging
from typing import Any


logger: logging.Logger = logging.getLogger(__name__)

ResourceMonitor: Any = None
VMSecurityManager: Any = None
secure_vm_execution: Any = None

try:
    from .vm_security import ResourceMonitor, VMSecurityManager, secure_vm_execution
except ImportError as e:
    logger.warning("Failed to import vm_security: %s", e)
    ResourceMonitor = None
    VMSecurityManager = None
    secure_vm_execution = None

try:
    from ..security_enforcement import *
except ImportError as e:
    logger.warning("Failed to import security_enforcement: %s", e)

try:
    from ..security_utils import *
except ImportError as e:
    logger.warning("Failed to import security_utils: %s", e)

__all__: list[str] = []

if VMSecurityManager is not None:
    __all__.extend(["ResourceMonitor", "VMSecurityManager", "secure_vm_execution"])

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
