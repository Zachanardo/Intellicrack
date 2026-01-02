"""Resource management package for Intellicrack.

This package provides context managers and automatic cleanup utilities for
managing system resources including processes, virtual machines, containers,
and temporary files. Resources are tracked and cleaned up automatically,
even when errors occur.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import contextlib


with contextlib.suppress(ImportError):
    from .resource_manager import (
        ManagedResource,
        ProcessResource,
        ResourceManager,
        ResourceState,
        ResourceType,
        VMResource,
        get_resource_manager,
    )

__all__ = [
    "ManagedResource",
    "ProcessResource",
    "ResourceManager",
    "ResourceState",
    "ResourceType",
    "VMResource",
    "get_resource_manager",
]

# Filter out items that are not available
__all__ = [item for item in __all__ if item in locals()]
