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

from typing import Any

from intellicrack.utils.logger import logger


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


HAS_OPENCL = False
OPENCL_AVAILABLE = False
OPENCL_VERSION: str | None = None

try:
    import pyopencl as cl_module
    from pyopencl import (
        Buffer as OpenCLBuffer,
        Context as OpenCLContext,
        Device as OpenCLDevice,
        Platform as OpenCLPlatform,
        Program as OpenCLProgram,
        create_some_context as opencl_create_some_context,
        get_platforms as opencl_get_platforms,
    )

    try:
        from pyopencl import CommandQueue as OpenCLQueue
    except ImportError:
        from pyopencl import Queue as OpenCLQueue

    HAS_OPENCL = True
    OPENCL_AVAILABLE = True
    OPENCL_VERSION = getattr(cl_module, "VERSION_TEXT", "unknown")

    cl: Any = cl_module
    Context: type[Any] = OpenCLContext
    Device: type[Any] = OpenCLDevice
    Buffer: type[Any] = OpenCLBuffer
    Program: type[Any] = OpenCLProgram
    Queue: type[Any] = OpenCLQueue
    Platform: type[Any] = OpenCLPlatform

    def create_some_context(interactive: bool | None = None, answers: list[str] | None = None) -> Any:
        """Create OpenCL context with optional interactivity control.

        Args:
            interactive: bool | None. Enable interactive mode for device selection if True.
                Defaults to None for automatic selection.
            answers: list[str] | None. Preset answers for interactive device selection.
                Defaults to None if no preset answers are provided.

        Returns:
            Any: OpenCL context object created by pyopencl with the specified
                parameters or fallback context if OpenCL is unavailable.
        """
        return opencl_create_some_context(interactive=interactive, answers=answers)

    def get_platforms() -> list[Any]:
        """Get available OpenCL platforms.

        Returns:
            list[Any]: List of available OpenCL platform objects from pyopencl,
                each supporting device enumeration and context creation.
        """
        return list(opencl_get_platforms())

except ImportError as e:
    logger.error("OpenCL not available, using fallback implementations: %s", e)
    HAS_OPENCL = False
    OPENCL_AVAILABLE = False
    OPENCL_VERSION = None

    cl = None
    Context = FallbackContext
    Device = FallbackDevice
    Buffer = FallbackBuffer
    Program = FallbackProgram
    Queue = FallbackQueue
    Platform = FallbackPlatform

    def create_some_context(interactive: bool | None = None, answers: list[str] | None = None) -> Any:
        """Fallback context creation.

        Args:
            interactive: bool | None. Enable interactive mode for device selection if True.
                Defaults to None for automatic selection.
            answers: list[str] | None. Preset answers for interactive device selection.
                Defaults to None if no preset answers are provided.

        Returns:
            Any: Fallback OpenCL context object when pyopencl is unavailable,
                providing a compatibility implementation for graceful degradation.
        """
        return FallbackContext()

    def get_platforms() -> list[Any]:
        """Fallback platform enumeration.

        Returns:
            list[Any]: Empty list when OpenCL is not available, allowing code
                to gracefully handle the absence of GPU platforms while maintaining
                compatibility with the standard OpenCL interface.
        """
        return []


__all__ = [
    "Buffer",
    "Context",
    "Device",
    "HAS_OPENCL",
    "OPENCL_AVAILABLE",
    "OPENCL_VERSION",
    "Platform",
    "Program",
    "Queue",
    "cl",
    "create_some_context",
    "get_platforms",
]
