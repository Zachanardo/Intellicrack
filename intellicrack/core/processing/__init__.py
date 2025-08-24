"""Intellicrack Core Processing Package.

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

# Set up package logger
logger = logging.getLogger(__name__)

# Import processing modules with error handling
try:
    from .distributed_manager import DistributedProcessingManager, create_distributed_manager
except ImportError as e:
    logger.warning("Failed to import distributed_manager: %s", e)

try:
    from .gpu_accelerator import (
        GPUAccelerationManager,
        GPUAccelerator,
        create_gpu_acceleration_manager,
        create_gpu_accelerator,
        is_gpu_acceleration_available,
    )
except ImportError as e:
    logger.warning("Failed to import gpu_accelerator: %s", e)

try:
    from .memory_optimizer import MemoryOptimizer, create_memory_optimizer
except ImportError as e:
    logger.warning("Failed to import memory_optimizer: %s", e)

try:
    from .memory_loader import MemoryOptimizedBinaryLoader, create_memory_loader
except ImportError as e:
    logger.warning("Failed to import memory_loader: %s", e)

try:
    from .qiling_emulator import QILING_AVAILABLE, QilingEmulator, run_qiling_emulation
except ImportError as e:
    logger.warning("Failed to import qiling_emulator: %s", e)

# QEMU emulator removed during VM framework consolidation
# QEMUSystemEmulator and run_qemu_analysis functionality moved to QEMUManager
QEMUSystemEmulator = None
run_qemu_analysis = None

# Define package exports
__all__ = [
    # From distributed_manager
    "DistributedProcessingManager",
    "create_distributed_manager",
    # From gpu_accelerator
    "GPUAccelerationManager",
    "GPUAccelerator",
    "create_gpu_acceleration_manager",
    "create_gpu_accelerator",
    "is_gpu_acceleration_available",
    # From memory_optimizer
    "MemoryOptimizer",
    "create_memory_optimizer",
    # From memory_loader
    "MemoryOptimizedBinaryLoader",
    "create_memory_loader",
    # From qiling_emulator
    "QilingEmulator",
    "run_qiling_emulation",
    "QILING_AVAILABLE",
    # From qemu_emulator
    "QEMUSystemEmulator",
    "run_qemu_analysis",
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
