"""
Simple performance monitor to replace the complex one temporarily.
"""

import logging
from typing import Callable

logger = logging.getLogger(__name__)


def profile_ai_operation(operation_name: str = None):
    """Decorator for profiling AI operations."""
    def decorator(func: Callable) -> Callable:
        # Simplified version to avoid initialization issues
        return func
    return decorator


def get_performance_monitor():
    """Get a dummy performance monitor."""
    return None


def get_async_monitor():
    """Get a dummy async monitor."""
    return None
