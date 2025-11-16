"""OpenCL handler for Intellicrack.

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
"""

from intellicrack.utils.logger import logger

"""
OpenCL Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for OpenCL imports.
When OpenCL is not available, it provides fallback implementations.
"""

# OpenCL availability detection and import handling
try:
    import pyopencl as cl

    # Import basic classes
    from pyopencl import (
        Buffer,
        Context,
        Device,
        Platform,
        Program,
        create_some_context,
        get_platforms,
    )

    # Try to import Queue - it may be CommandQueue in some versions
    try:
        from pyopencl import Queue
    except ImportError:
        try:
            from pyopencl import CommandQueue as Queue
        except ImportError:
            # Create fallback if neither exists
            Queue = None

    HAS_OPENCL = True
    OPENCL_AVAILABLE = True
    OPENCL_VERSION = getattr(cl, "VERSION_TEXT", "unknown")

except ImportError as e:
    logger.error("OpenCL not available, using fallback implementations: %s", e)
    HAS_OPENCL = False
    OPENCL_AVAILABLE = False
    OPENCL_VERSION = None

    # Fallback implementations
    class FallbackContext:
        """Fallback OpenCL context."""


    class FallbackDevice:
        """Fallback OpenCL device."""


    class FallbackBuffer:
        """Fallback OpenCL buffer."""


    class FallbackProgram:
        """Fallback OpenCL program."""


    class FallbackQueue:
        """Fallback OpenCL command queue."""


    class FallbackPlatform:
        """Fallback OpenCL platform."""


    # Assign fallback objects
    cl = None
    Context = FallbackContext
    Device = FallbackDevice
    Buffer = FallbackBuffer
    Program = FallbackProgram
    Queue = FallbackQueue
    Platform = FallbackPlatform

    def create_some_context() -> FallbackContext:
        """Fallback context creation."""
        return FallbackContext()

    def get_platforms() -> list:
        """Fallback platform enumeration."""
        return []


# Export all OpenCL objects and availability flag
__all__ = [
    # Availability flags
    "HAS_OPENCL",
    "OPENCL_AVAILABLE",
    "OPENCL_VERSION",
    # Main module
    "cl",
    # Classes
    "Context",
    "Device",
    "Buffer",
    "Program",
    "Queue",
    "Platform",
    # Functions
    "create_some_context",
    "get_platforms",
]
