"""
Intellicrack Core Processing Package

This package provides high-performance processing capabilities for the Intellicrack framework.
It includes distributed processing, GPU acceleration, and memory optimization features for
handling large-scale binary analysis tasks efficiently.

Modules:
    - distributed_manager: Manage distributed processing across multiple nodes
    - gpu_accelerator: GPU-accelerated processing for intensive computations
    - memory_optimizer: Memory management and optimization utilities

Key Features:
    - Distributed task management
    - GPU acceleration support
    - Memory-efficient processing
    - Multi-threaded analysis
    - Resource optimization
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
    from .qiling_emulator import QilingEmulator, run_qiling_emulation, QILING_AVAILABLE
except ImportError as e:
    logger.warning("Failed to import qiling_emulator: %s", e)

try:
    from .qemu_emulator import QEMUSystemEmulator, run_qemu_analysis
except ImportError as e:
    logger.warning("Failed to import qemu_emulator: %s", e)

# Define package exports
__all__ = [
    # From distributed_manager
    'DistributedProcessingManager',
    'create_distributed_manager',

    # From gpu_accelerator
    'GPUAccelerationManager',
    'GPUAccelerator',
    'create_gpu_acceleration_manager',
    'create_gpu_accelerator',
    'is_gpu_acceleration_available',

    # From memory_optimizer
    'MemoryOptimizer',
    'create_memory_optimizer',

    # From memory_loader
    'MemoryOptimizedBinaryLoader',
    'create_memory_loader',

    # From qiling_emulator
    'QilingEmulator',
    'run_qiling_emulation',
    'QILING_AVAILABLE',

    # From qemu_emulator
    'QEMUSystemEmulator',
    'run_qemu_analysis',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
