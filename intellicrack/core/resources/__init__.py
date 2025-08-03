"""
Resource Management Package

Provides context managers and automatic cleanup for system resources.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from .resource_manager import (
    ContainerResource,
    ManagedResource,
    ProcessResource,
    ResourceManager,
    ResourceState,
    ResourceType,
    VMResource,
    get_resource_manager,
)

__all__ = [
    "ResourceManager",
    "ResourceType",
    "ResourceState",
    "ManagedResource",
    "ProcessResource",
    "VMResource",
    "ContainerResource",
    "get_resource_manager"
]
