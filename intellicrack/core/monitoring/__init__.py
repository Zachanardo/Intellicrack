"""Real-time License Monitoring System.

Production-ready monitoring infrastructure for detecting and analyzing
software licensing operations across multiple channels: API calls, registry
operations, file I/O, network traffic, and memory patterns.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from intellicrack.core.monitoring.base_monitor import BaseMonitor, MonitorEvent
from intellicrack.core.monitoring.event_aggregator import EventAggregator
from intellicrack.core.monitoring.frida_server_manager import FridaServerManager
from intellicrack.core.monitoring.monitoring_session import MonitoringSession

__all__ = [
    "BaseMonitor",
    "MonitorEvent",
    "EventAggregator",
    "FridaServerManager",
    "MonitoringSession",
]
