"""Resource Management Package.

Provides context managers and automatic cleanup for system resources.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

try:
    from .resource_manager import (
        ManagedResource,
        ProcessResource,
        ResourceManager,
        ResourceState,
        ResourceType,
        VMResource,
        get_resource_manager,
    )
except ImportError:
    # Don't set variables if import fails
    pass

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
