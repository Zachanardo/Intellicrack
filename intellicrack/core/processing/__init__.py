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
    from .distributed_manager import *
except ImportError as e:
    logger.warning(f"Failed to import distributed_manager: {e}")

try:
    from .gpu_accelerator import *
except ImportError as e:
    logger.warning(f"Failed to import gpu_accelerator: {e}")

try:
    from .memory_optimizer import *
except ImportError as e:
    logger.warning(f"Failed to import memory_optimizer: {e}")

# Define package exports
__all__ = [
    # From distributed_manager
    'DistributedManager',
    'TaskDistributor',
    'NodeManager',
    'distribute_analysis',
    
    # From gpu_accelerator
    'GPUAccelerator',
    'CUDAProcessor',
    'accelerate_computation',
    'gpu_available',
    
    # From memory_optimizer
    'MemoryOptimizer',
    'optimize_memory',
    'profile_memory_usage',
    'clear_cache',
]

# Package metadata
__version__ = "0.1.0"
__author__ = "Intellicrack Development Team"
