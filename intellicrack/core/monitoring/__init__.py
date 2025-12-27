"""Real-time License Monitoring System.

Production-ready monitoring infrastructure for detecting and analyzing
software licensing operations across multiple channels: API calls, registry
operations, file I/O, network traffic, and memory patterns.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import logging
from typing import TYPE_CHECKING, Any


logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .base_monitor import BaseMonitor, MonitorEvent
    from .event_aggregator import EventAggregator
    from .frida_server_manager import FridaServerManager
    from .monitoring_session import MonitoringSession
else:
    BaseMonitor: type[Any] | None = None
    MonitorEvent: type[Any] | None = None
    EventAggregator: type[Any] | None = None
    FridaServerManager: type[Any] | None = None
    MonitoringSession: type[Any] | None = None

    try:
        from .base_monitor import BaseMonitor, MonitorEvent
    except ImportError as e:
        logger.warning("Failed to import base_monitor: %s", e)
        BaseMonitor = None
        MonitorEvent = None

    try:
        from .event_aggregator import EventAggregator
    except ImportError as e:
        logger.warning("Failed to import event_aggregator: %s", e)
        EventAggregator = None

    try:
        from .frida_server_manager import FridaServerManager
    except ImportError as e:
        logger.warning("Failed to import frida_server_manager: %s", e)
        FridaServerManager = None

    try:
        from .monitoring_session import MonitoringSession
    except ImportError as e:
        logger.warning("Failed to import monitoring_session: %s", e)
        MonitoringSession = None

__all__ = [
    "BaseMonitor",
    "EventAggregator",
    "FridaServerManager",
    "MonitorEvent",
    "MonitoringSession",
]

if not TYPE_CHECKING:
    __all__ = [item for item in __all__ if locals().get(item) is not None]
