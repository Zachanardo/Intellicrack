"""
Runtime Behavior Monitor - Comprehensive behavior tracking for sandbox environments.

This module provides real-time monitoring and analysis of executable behavior during
sandbox execution, detecting protection mechanisms, licensing checks, and security-relevant
activities with high precision and minimal performance impact.

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import asyncio
import json
import os
import psutil
import socket
import sqlite3
import struct
import threading
import time
import winreg
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import logging

try:
    import win32api
    import win32con
    import win32file
    import win32pipe
    import win32process
    import win32security
    import wmi
    WINDOWS_MONITORING_AVAILABLE = True
except ImportError:
    WINDOWS_MONITORING_AVAILABLE = False

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

from intellicrack.logger import logger


class MonitoringLevel(Enum):
    """Monitoring intensity levels."""
    MINIMAL = "minimal"      # Basic process/file tracking
    STANDARD = "standard"    # Standard monitoring with API hooks
    INTENSIVE = "intensive"  # Deep monitoring with memory analysis
    FORENSIC = "forensic"    # Maximum monitoring with full tracing


class EventType(Enum):
    """Types of monitored events."""
    PROCESS_CREATE = auto()
    PROCESS_TERMINATE = auto()
    THREAD_CREATE = auto()
    THREAD_TERMINATE = auto()
    FILE_ACCESS = auto()
    FILE_CREATE = auto()
    FILE_DELETE = auto()
    FILE_MODIFY = auto()
    REGISTRY_ACCESS = auto()
    REGISTRY_CREATE = auto()
    REGISTRY_DELETE = auto()
    NETWORK_CONNECT = auto()
    NETWORK_DNS = auto()
    API_CALL = auto()
    MEMORY_ALLOCATE = auto()
    MEMORY_PROTECT = auto()
    LICENSE_CHECK = auto()
    ANTI_ANALYSIS = auto()
    SUSPICIOUS_BEHAVIOR = auto()


@dataclass
class MonitoredEvent:
    """Represents a monitored system event."""
    event_type: EventType
    timestamp: float
    process_id: int
    thread_id: Optional[int] = None
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    tags: Set[str] = field(default_factory=set)


@dataclass
class ProcessInfo:
    """Information about a monitored process."""
    pid: int
    ppid: int
    name: str
    command_line: str
    creation_time: float
    user: str
    image_path: str
    is_target: bool = False
    children: Set[int] = field(default_factory=set)
    threads: Set[int] = field(default_factory=set)
    memory_regions: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    api_calls: List[Dict[str, Any]] = field(default_factory=list)
    file_accesses: List[str] = field(default_factory=list)
    network_activity: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class LicensePattern:
    """License-related behavior pattern."""
    pattern_type: str
    description: str
    indicators: List[str]
    weight: float
    false_positive_rate: float
    detection_count: int = 0
    last_seen: Optional[float] = None


@dataclass
class BehaviorProfile:
    """Behavioral profile of monitored execution."""
    start_time: float
    end_time: Optional[float] = None
    target_process: Optional[ProcessInfo] = None
    total_events: int = 0
    event_timeline: List[MonitoredEvent] = field(default_factory=list)
    process_tree: Dict[int, ProcessInfo] = field(default_factory=dict)
    license_indicators: List[Dict[str, Any]] = field(default_factory=list)
    protection_mechanisms: List[Dict[str, Any]] = field(default_factory=list)
    anti_analysis_techniques: List[Dict[str, Any]] = field(default_factory=list)
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    network_timeline: List[Dict[str, Any]] = field(default_factory=list)
    file_system_changes: Dict[str, List[str]] = field(default_factory=dict)
    registry_changes: Dict[str, List[str]] = field(default_factory=dict)
    memory_analysis: Dict[str, Any] = field(default_factory=dict)
    performance_metrics: Dict[str, Any] = field(default_factory=dict)


class RuntimeBehaviorMonitor:
    """
    Comprehensive runtime behavior monitoring system.
    
    This class provides real-time monitoring and analysis of executable behavior
    during sandbox execution, with specialized detection for licensing mechanisms,
    protection schemes, and security-relevant activities.
    """

    def __init__(self, monitoring_level: MonitoringLevel = MonitoringLevel.STANDARD,
                 target_process: Optional[str] = None):
        """
        Initialize the runtime behavior monitor.
        
        Args:
            monitoring_level: Intensity of monitoring
            target_process: Optional specific process to focus monitoring on
        """
        self.monitoring_level = monitoring_level
        self.target_process = target_process
        self.logger = logging.getLogger(__name__)
        
        # Monitoring state
        self.is_monitoring = False
        self.monitoring_thread: Optional[threading.Thread] = None
        self.event_queue = asyncio.Queue()
        self.stop_event = threading.Event()
        
        # Event storage
        self.events: deque = deque(maxlen=100000)  # Circular buffer for performance
        self.behavior_profile = BehaviorProfile(start_time=time.time())
        
        # Process tracking
        self.monitored_processes: Dict[int, ProcessInfo] = {}
        self.process_genealogy: Dict[int, Set[int]] = defaultdict(set)
        
        # Hooks and instrumentation
        self.frida_sessions: Dict[int, Any] = {}
        self.api_hooks: Dict[str, List[Callable]] = defaultdict(list)
        self.file_system_watcher: Optional[Any] = None
        self.registry_watcher: Optional[Any] = None
        self.network_monitor: Optional[Any] = None
        
        # Pattern detection
        self.license_patterns = self._load_license_patterns()
        self.protection_patterns = self._load_protection_patterns()
        self.anti_analysis_patterns = self._load_anti_analysis_patterns()
        
        # Performance optimization
        self.event_cache: Dict[str, Any] = {}
        self.last_cleanup = time.time()
        self.cleanup_interval = 30.0  # seconds
        
        # Database for persistent storage
        self.db_path = None
        self.db_connection: Optional[sqlite3.Connection] = None
        
        # Platform-specific monitors
        self.platform_monitors: List[Any] = []
        
        self._initialize_monitoring_infrastructure()

    def _initialize_monitoring_infrastructure(self):
        """Initialize platform-specific monitoring infrastructure."""
        try:
            if os.name == 'nt' and WINDOWS_MONITORING_AVAILABLE:
                self._initialize_windows_monitoring()
            else:
                self._initialize_linux_monitoring()
                
            if FRIDA_AVAILABLE:
                self._initialize_frida_instrumentation()
                
        except Exception as e:
            self.logger.error(f"Failed to initialize monitoring infrastructure: {e}")

    def _initialize_windows_monitoring(self):
        """Initialize Windows-specific monitoring components."""
        try:
            # Initialize WMI for process monitoring
            self.wmi_connection = wmi.WMI()
            
            # Set up event sinks for real-time monitoring
            self._setup_wmi_process_monitor()
            self._setup_file_system_monitor()
            self._setup_registry_monitor()
            self._setup_network_monitor()
            
            self.logger.info("Windows monitoring infrastructure initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Windows monitoring: {e}")

    def _initialize_linux_monitoring(self):
        """Initialize Linux-specific monitoring components."""
        try:
            # Use inotify for file system monitoring
            import inotify.adapters
            self.inotify_adapter = inotify.adapters.Inotify()
            
            # Set up process monitoring via /proc
            self._setup_proc_monitor()
            
            # Set up network monitoring via netlink
            self._setup_netlink_monitor()
            
            self.logger.info("Linux monitoring infrastructure initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Linux monitoring: {e}")

    def _initialize_frida_instrumentation(self):
        """Initialize Frida-based API instrumentation."""
        try:
            self.frida_device = frida.get_local_device()
            self.frida_scripts = {}
            
            # Load pre-compiled instrumentation scripts
            self._load_instrumentation_scripts()
            
            self.logger.info("Frida instrumentation initialized")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Frida: {e}")

    def start_monitoring(self, target_pid: Optional[int] = None) -> bool:
        """
        Start comprehensive behavior monitoring.
        
        Args:
            target_pid: Optional specific process ID to monitor
            
        Returns:
            True if monitoring started successfully
        """
        if self.is_monitoring:
            self.logger.warning("Monitoring is already active")
            return True

        try:
            # Reset state
            self.stop_event.clear()
            self.events.clear()
            self.behavior_profile = BehaviorProfile(start_time=time.time())
            
            if target_pid:
                self._attach_to_process(target_pid)
            
            # Initialize database
            self._initialize_database()
            
            # Start monitoring components
            self._start_process_monitoring()
            self._start_file_system_monitoring()
            self._start_registry_monitoring()
            self._start_network_monitoring()
            self._start_memory_monitoring()
            
            if self.monitoring_level in [MonitoringLevel.INTENSIVE, MonitoringLevel.FORENSIC]:
                self._start_api_monitoring()
                self._start_advanced_analysis()
            
            # Start main monitoring loop
            self.monitoring_thread = threading.Thread(
                target=self._monitoring_loop,
                daemon=True
            )
            self.monitoring_thread.start()
            
            self.is_monitoring = True
            self.logger.info(f"Runtime behavior monitoring started (level: {self.monitoring_level.value})")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False

    def stop_monitoring(self) -> BehaviorProfile:
        """
        Stop monitoring and return behavior profile.
        
        Returns:
            Complete behavior profile from monitoring session
        """
        if not self.is_monitoring:
            self.logger.warning("Monitoring is not active")
            return self.behavior_profile

        try:
            # Signal stop
            self.stop_event.set()
            self.is_monitoring = False
            
            # Wait for monitoring thread to finish
            if self.monitoring_thread and self.monitoring_thread.is_alive():
                self.monitoring_thread.join(timeout=10.0)
            
            # Stop all monitoring components
            self._stop_all_monitors()
            
            # Finalize behavior profile
            self.behavior_profile.end_time = time.time()
            self.behavior_profile.total_events = len(self.events)
            self.behavior_profile.event_timeline = list(self.events)
            
            # Perform final analysis
            self._perform_final_analysis()
            
            # Clean up resources
            self._cleanup_resources()
            
            self.logger.info("Runtime behavior monitoring stopped")
            
            return self.behavior_profile
            
        except Exception as e:
            self.logger.error(f"Error stopping monitoring: {e}")
            return self.behavior_profile

    def _monitoring_loop(self):
        """Main monitoring loop."""
        try:
            last_analysis = time.time()
            analysis_interval = 5.0  # seconds
            
            while not self.stop_event.is_set():
                current_time = time.time()
                
                # Process pending events
                self._process_pending_events()
                
                # Periodic analysis
                if current_time - last_analysis >= analysis_interval:
                    self._perform_periodic_analysis()
                    last_analysis = current_time
                
                # Cleanup old data
                if current_time - self.last_cleanup >= self.cleanup_interval:
                    self._cleanup_old_data()
                    self.last_cleanup = current_time
                
                # Short sleep to prevent busy waiting
                time.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}")

    def _process_pending_events(self):
        """Process events from the event queue."""
        try:
            processed = 0
            max_process = 100  # Limit processing per iteration
            
            while processed < max_process and not self.stop_event.is_set():
                try:
                    # Non-blocking get with timeout
                    event = asyncio.get_event_loop().run_until_complete(
                        asyncio.wait_for(self.event_queue.get(), timeout=0.01)
                    )
                    
                    self._process_event(event)
                    processed += 1
                    
                except asyncio.TimeoutError:
                    break  # No more events to process
                except Exception as e:
                    self.logger.error(f"Error processing event: {e}")
                    
        except Exception as e:
            self.logger.error(f"Error in event processing: {e}")

    def _process_event(self, event: MonitoredEvent):
        """Process a single monitored event."""
        try:
            # Add to event timeline
            self.events.append(event)
            
            # Update process tracking
            if event.process_id not in self.monitored_processes:
                self._discover_process(event.process_id)
            
            # Pattern detection
            self._detect_license_patterns(event)
            self._detect_protection_mechanisms(event)
            self._detect_anti_analysis_techniques(event)
            self._detect_suspicious_behavior(event)
            
            # Store in database
            if self.db_connection:
                self._store_event_in_database(event)
                
        except Exception as e:
            self.logger.error(f"Error processing event {event.event_type}: {e}")

    def _start_process_monitoring(self):
        """Start process and thread monitoring."""
        if os.name == 'nt' and WINDOWS_MONITORING_AVAILABLE:
            self._start_windows_process_monitoring()
        else:
            self._start_linux_process_monitoring()

    def _start_windows_process_monitoring(self):
        """Start Windows process monitoring using WMI."""
        try:
            # Monitor process creation
            def on_process_create(event):
                try:
                    pid = int(event.ProcessId)
                    ppid = int(event.ParentProcessId)
                    
                    process_event = MonitoredEvent(
                        event_type=EventType.PROCESS_CREATE,
                        timestamp=time.time(),
                        process_id=pid,
                        details={
                            'parent_pid': ppid,
                            'name': event.Name,
                            'command_line': getattr(event, 'CommandLine', ''),
                            'creation_time': event.CreationDate
                        }
                    )
                    
                    asyncio.run_coroutine_threadsafe(
                        self.event_queue.put(process_event),
                        asyncio.get_event_loop()
                    )
                    
                except Exception as e:
                    self.logger.error(f"Error in process create handler: {e}")
            
            # Set up WMI event watcher
            process_watcher = self.wmi_connection.Win32_Process.watch_for("creation")
            threading.Thread(
                target=self._wmi_event_loop,
                args=(process_watcher, on_process_create),
                daemon=True
            ).start()
            
            # Monitor process termination
            def on_process_terminate(event):
                try:
                    pid = int(event.ProcessId)
                    
                    terminate_event = MonitoredEvent(
                        event_type=EventType.PROCESS_TERMINATE,
                        timestamp=time.time(),
                        process_id=pid,
                        details={
                            'exit_code': getattr(event, 'ExitStatus', None)
                        }
                    )
                    
                    asyncio.run_coroutine_threadsafe(
                        self.event_queue.put(terminate_event),
                        asyncio.get_event_loop()
                    )
                    
                except Exception as e:
                    self.logger.error(f"Error in process terminate handler: {e}")
            
            term_watcher = self.wmi_connection.Win32_Process.watch_for("deletion")
            threading.Thread(
                target=self._wmi_event_loop,
                args=(term_watcher, on_process_terminate),
                daemon=True
            ).start()
            
        except Exception as e:
            self.logger.error(f"Failed to start Windows process monitoring: {e}")

    def _start_file_system_monitoring(self):
        """Start file system activity monitoring."""
        if os.name == 'nt':
            self._start_windows_file_monitoring()
        else:
            self._start_linux_file_monitoring()

    def _start_windows_file_monitoring(self):
        """Start Windows file system monitoring."""
        try:
            import win32file
            import win32con
            
            def monitor_directory(directory: str):
                """Monitor a specific directory for changes."""
                try:
                    handle = win32file.CreateFile(
                        directory,
                        win32file.GENERIC_READ,
                        win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE | win32file.FILE_SHARE_DELETE,
                        None,
                        win32file.OPEN_EXISTING,
                        win32file.FILE_FLAG_BACKUP_SEMANTICS,
                        None
                    )
                    
                    while not self.stop_event.is_set():
                        results = win32file.ReadDirectoryChangesW(
                            handle,
                            1024,
                            True,  # Watch subdirectories
                            win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                            win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                            win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                            win32con.FILE_NOTIFY_CHANGE_SIZE |
                            win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                            win32con.FILE_NOTIFY_CHANGE_SECURITY,
                            None,
                            None
                        )
                        
                        for action, filename in results:
                            self._handle_file_system_event(directory, filename, action)
                            
                except Exception as e:
                    self.logger.error(f"Error monitoring directory {directory}: {e}")
            
            # Monitor key directories
            key_directories = [
                "C:\\Windows\\System32",
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                "C:\\Users",
                "C:\\Temp",
                os.environ.get('TEMP', 'C:\\Temp'),
                os.environ.get('APPDATA', 'C:\\Users\\Default\\AppData\\Roaming')
            ]
            
            for directory in key_directories:
                if os.path.exists(directory):
                    threading.Thread(
                        target=monitor_directory,
                        args=(directory,),
                        daemon=True
                    ).start()
                    
        except Exception as e:
            self.logger.error(f"Failed to start Windows file monitoring: {e}")

    def _handle_file_system_event(self, directory: str, filename: str, action: int):
        """Handle file system change event."""
        try:
            full_path = os.path.join(directory, filename)
            
            # Map Windows file actions to our event types
            action_map = {
                1: EventType.FILE_CREATE,   # FILE_ACTION_ADDED
                2: EventType.FILE_DELETE,   # FILE_ACTION_REMOVED
                3: EventType.FILE_MODIFY,   # FILE_ACTION_MODIFIED
                4: EventType.FILE_DELETE,   # FILE_ACTION_RENAMED_OLD_NAME
                5: EventType.FILE_CREATE,   # FILE_ACTION_RENAMED_NEW_NAME
            }
            
            event_type = action_map.get(action, EventType.FILE_ACCESS)
            
            # Get process information if possible
            pid = self._get_file_accessing_process(full_path)
            
            file_event = MonitoredEvent(
                event_type=event_type,
                timestamp=time.time(),
                process_id=pid or 0,
                details={
                    'file_path': full_path,
                    'action': action,
                    'directory': directory,
                    'filename': filename
                }
            )
            
            # Check for license-related files
            if self._is_license_related_file(full_path):
                file_event.tags.add('license')
                file_event.confidence = 0.8
            
            asyncio.run_coroutine_threadsafe(
                self.event_queue.put(file_event),
                asyncio.get_event_loop()
            )
            
        except Exception as e:
            self.logger.error(f"Error handling file system event: {e}")

    def _start_registry_monitoring(self):
        """Start Windows registry monitoring."""
        if os.name != 'nt' or not WINDOWS_MONITORING_AVAILABLE:
            return
        
        try:
            def monitor_registry_key(hkey, key_path: str):
                """Monitor a specific registry key for changes."""
                try:
                    key_handle = winreg.OpenKey(hkey, key_path, 0, winreg.KEY_NOTIFY)
                    
                    while not self.stop_event.is_set():
                        try:
                            # Wait for registry changes
                            winreg.QueryInfoKey(key_handle)
                            
                            # Create registry event
                            reg_event = MonitoredEvent(
                                event_type=EventType.REGISTRY_ACCESS,
                                timestamp=time.time(),
                                process_id=os.getpid(),  # Will be updated if we can determine actual process
                                details={
                                    'hkey': str(hkey),
                                    'key_path': key_path,
                                    'action': 'access'
                                }
                            )
                            
                            # Check for license-related registry access
                            if self._is_license_related_registry(key_path):
                                reg_event.tags.add('license')
                                reg_event.confidence = 0.9
                            
                            asyncio.run_coroutine_threadsafe(
                                self.event_queue.put(reg_event),
                                asyncio.get_event_loop()
                            )
                            
                            time.sleep(0.1)  # Prevent busy waiting
                            
                        except Exception as e:
                            if "invalid handle" not in str(e).lower():
                                self.logger.error(f"Registry monitoring error: {e}")
                            break
                            
                except Exception as e:
                    self.logger.error(f"Error opening registry key {key_path}: {e}")
            
            # Monitor key registry locations
            registry_keys = [
                (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE"),
                (winreg.HKEY_CURRENT_USER, "SOFTWARE"),
                (winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services"),
                (winreg.HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
                (winreg.HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
            ]
            
            for hkey, key_path in registry_keys:
                threading.Thread(
                    target=monitor_registry_key,
                    args=(hkey, key_path),
                    daemon=True
                ).start()
                
        except Exception as e:
            self.logger.error(f"Failed to start registry monitoring: {e}")

    def _start_network_monitoring(self):
        """Start network activity monitoring."""
        try:
            def monitor_network_connections():
                """Monitor network connections and DNS queries."""
                last_connections = set()
                
                while not self.stop_event.is_set():
                    try:
                        # Get current connections
                        current_connections = set()
                        
                        for conn in psutil.net_connections(kind='inet'):
                            if conn.status == 'ESTABLISHED':
                                conn_info = f"{conn.laddr.ip}:{conn.laddr.port}->{conn.raddr.ip}:{conn.raddr.port}"
                                current_connections.add((conn.pid, conn_info))
                        
                        # Detect new connections
                        new_connections = current_connections - last_connections
                        
                        for pid, conn_info in new_connections:
                            net_event = MonitoredEvent(
                                event_type=EventType.NETWORK_CONNECT,
                                timestamp=time.time(),
                                process_id=pid or 0,
                                details={
                                    'connection': conn_info,
                                    'protocol': 'TCP'
                                }
                            )
                            
                            # Check for license server connections
                            if self._is_license_server_connection(conn_info):
                                net_event.tags.add('license')
                                net_event.confidence = 0.85
                            
                            asyncio.run_coroutine_threadsafe(
                                self.event_queue.put(net_event),
                                asyncio.get_event_loop()
                            )
                        
                        last_connections = current_connections
                        time.sleep(1.0)  # Check every second
                        
                    except Exception as e:
                        self.logger.error(f"Network monitoring error: {e}")
                        time.sleep(5.0)
            
            threading.Thread(target=monitor_network_connections, daemon=True).start()
            
        except Exception as e:
            self.logger.error(f"Failed to start network monitoring: {e}")

    def _start_memory_monitoring(self):
        """Start memory access pattern monitoring."""
        if self.monitoring_level not in [MonitoringLevel.INTENSIVE, MonitoringLevel.FORENSIC]:
            return
        
        try:
            def monitor_memory_patterns():
                """Monitor memory allocation patterns."""
                while not self.stop_event.is_set():
                    try:
                        for pid, process_info in self.monitored_processes.items():
                            try:
                                process = psutil.Process(pid)
                                memory_info = process.memory_info()
                                
                                # Check for suspicious memory patterns
                                if self._detect_suspicious_memory_usage(memory_info):
                                    mem_event = MonitoredEvent(
                                        event_type=EventType.MEMORY_ALLOCATE,
                                        timestamp=time.time(),
                                        process_id=pid,
                                        details={
                                            'rss': memory_info.rss,
                                            'vms': memory_info.vms,
                                            'suspicious': True
                                        }
                                    )
                                    mem_event.tags.add('suspicious')
                                    
                                    asyncio.run_coroutine_threadsafe(
                                        self.event_queue.put(mem_event),
                                        asyncio.get_event_loop()
                                    )
                                    
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                        
                        time.sleep(2.0)  # Check every 2 seconds
                        
                    except Exception as e:
                        self.logger.error(f"Memory monitoring error: {e}")
                        time.sleep(5.0)
            
            threading.Thread(target=monitor_memory_patterns, daemon=True).start()
            
        except Exception as e:
            self.logger.error(f"Failed to start memory monitoring: {e}")

    def _start_api_monitoring(self):
        """Start API call monitoring using Frida."""
        if not FRIDA_AVAILABLE:
            self.logger.warning("Frida not available for API monitoring")
            return
        
        try:
            # API categories to monitor
            api_categories = {
                'licensing': [
                    'RegQueryValueExA', 'RegQueryValueExW',
                    'GetVolumeInformationA', 'GetVolumeInformationW',
                    'GetComputerNameA', 'GetComputerNameW',
                    'InternetOpenA', 'InternetOpenW'
                ],
                'anti_debug': [
                    'IsDebuggerPresent',
                    'CheckRemoteDebuggerPresent',
                    'NtQueryInformationProcess',
                    'GetTickCount', 'GetTickCount64'
                ],
                'crypto': [
                    'CryptCreateHash', 'CryptHashData',
                    'CryptGenKey', 'CryptEncrypt', 'CryptDecrypt'
                ],
                'time': [
                    'GetSystemTime', 'GetLocalTime',
                    'GetFileTime', 'SystemTimeToFileTime'
                ]
            }
            
            # Create Frida script for API monitoring
            script_code = self._generate_frida_api_script(api_categories)
            
            # Inject into monitored processes
            for pid in self.monitored_processes.keys():
                self._inject_frida_script(pid, script_code)
                
        except Exception as e:
            self.logger.error(f"Failed to start API monitoring: {e}")

    def _generate_frida_api_script(self, api_categories: Dict[str, List[str]]) -> str:
        """Generate Frida script for API monitoring."""
        script_template = '''
        console.log("API monitoring script loaded");
        
        var categories = %s;
        
        function logApiCall(category, apiName, args) {
            var message = {
                type: "api_call",
                category: category,
                api: apiName,
                args: args,
                timestamp: Date.now(),
                tid: Process.getCurrentThreadId()
            };
            send(message);
        }
        
        for (var category in categories) {
            var apis = categories[category];
            for (var i = 0; i < apis.length; i++) {
                var apiName = apis[i];
                try {
                    var apiPtr = Module.findExportByName(null, apiName);
                    if (apiPtr) {
                        Interceptor.attach(apiPtr, {
                            onEnter: function(args) {
                                this.apiName = apiName;
                                this.category = category;
                                this.args = [];
                                for (var j = 0; j < Math.min(args.length, 4); j++) {
                                    this.args.push(args[j].toString());
                                }
                            },
                            onLeave: function(retval) {
                                logApiCall(this.category, this.apiName, this.args);
                            }
                        });
                    }
                } catch (e) {
                    console.log("Failed to hook " + apiName + ": " + e);
                }
            }
        }
        '''
        
        return script_template % json.dumps(api_categories)

    def _inject_frida_script(self, pid: int, script_code: str):
        """Inject Frida script into target process."""
        try:
            session = self.frida_device.attach(pid)
            script = session.create_script(script_code)
            
            def on_message(message, data):
                """Handle messages from Frida script."""
                try:
                    if message['type'] == 'send':
                        payload = message['payload']
                        
                        api_event = MonitoredEvent(
                            event_type=EventType.API_CALL,
                            timestamp=time.time(),
                            process_id=pid,
                            thread_id=payload.get('tid'),
                            details={
                                'api': payload['api'],
                                'category': payload['category'],
                                'args': payload['args']
                            }
                        )
                        
                        # Tag based on category
                        if payload['category'] == 'licensing':
                            api_event.tags.add('license')
                            api_event.confidence = 0.9
                        elif payload['category'] == 'anti_debug':
                            api_event.tags.add('anti_analysis')
                            api_event.confidence = 0.95
                        
                        asyncio.run_coroutine_threadsafe(
                            self.event_queue.put(api_event),
                            asyncio.get_event_loop()
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error processing Frida message: {e}")
            
            script.on('message', on_message)
            script.load()
            
            self.frida_sessions[pid] = session
            self.logger.info(f"Frida script injected into process {pid}")
            
        except Exception as e:
            self.logger.error(f"Failed to inject Frida script into process {pid}: {e}")

    def _detect_license_patterns(self, event: MonitoredEvent):
        """Detect license-related patterns in events."""
        try:
            for pattern in self.license_patterns:
                if self._event_matches_pattern(event, pattern):
                    pattern.detection_count += 1
                    pattern.last_seen = event.timestamp
                    
                    license_indicator = {
                        'pattern_type': pattern.pattern_type,
                        'description': pattern.description,
                        'event': event,
                        'confidence': pattern.weight * event.confidence,
                        'timestamp': event.timestamp
                    }
                    
                    self.behavior_profile.license_indicators.append(license_indicator)
                    
        except Exception as e:
            self.logger.error(f"Error detecting license patterns: {e}")

    def _detect_protection_mechanisms(self, event: MonitoredEvent):
        """Detect protection mechanism activation."""
        try:
            protection_indicators = [
                # Code obfuscation
                {'pattern': 'virtualalloc.*executable', 'type': 'code_injection', 'weight': 0.7},
                # Packing/compression
                {'pattern': 'upx.*unpack', 'type': 'packing', 'weight': 0.8},
                # Anti-tampering
                {'pattern': 'checksum.*verify', 'type': 'integrity_check', 'weight': 0.6},
                # License validation
                {'pattern': 'license.*validate', 'type': 'license_check', 'weight': 0.9},
            ]
            
            event_str = str(event.details).lower()
            
            for indicator in protection_indicators:
                if any(keyword in event_str for keyword in indicator['pattern'].split('.*')):
                    protection_detection = {
                        'type': indicator['type'],
                        'confidence': indicator['weight'],
                        'event': event,
                        'timestamp': event.timestamp
                    }
                    
                    self.behavior_profile.protection_mechanisms.append(protection_detection)
                    
        except Exception as e:
            self.logger.error(f"Error detecting protection mechanisms: {e}")

    def _detect_anti_analysis_techniques(self, event: MonitoredEvent):
        """Detect anti-analysis and evasion techniques."""
        try:
            anti_analysis_indicators = [
                # Debugger detection
                {'apis': ['IsDebuggerPresent', 'CheckRemoteDebuggerPresent'], 'type': 'debugger_detection'},
                # VM detection
                {'files': ['vmware', 'virtualbox', 'qemu'], 'type': 'vm_detection'},
                # Timing attacks
                {'apis': ['GetTickCount', 'QueryPerformanceCounter'], 'type': 'timing_analysis'},
                # Process enumeration
                {'apis': ['CreateToolhelp32Snapshot', 'Process32First'], 'type': 'process_enumeration'},
            ]
            
            if event.event_type == EventType.API_CALL:
                api_name = event.details.get('api', '').lower()
                
                for indicator in anti_analysis_indicators:
                    if 'apis' in indicator:
                        if any(api.lower() in api_name for api in indicator['apis']):
                            self._record_anti_analysis_detection(event, indicator)
            
            elif event.event_type == EventType.FILE_ACCESS:
                file_path = event.details.get('file_path', '').lower()
                
                for indicator in anti_analysis_indicators:
                    if 'files' in indicator:
                        if any(pattern in file_path for pattern in indicator['files']):
                            self._record_anti_analysis_detection(event, indicator)
                            
        except Exception as e:
            self.logger.error(f"Error detecting anti-analysis techniques: {e}")

    def _record_anti_analysis_detection(self, event: MonitoredEvent, indicator: Dict[str, Any]):
        """Record anti-analysis technique detection."""
        detection = {
            'type': indicator['type'],
            'event': event,
            'confidence': 0.8,
            'timestamp': event.timestamp,
            'description': f"Detected {indicator['type']} via {event.event_type.name}"
        }
        
        self.behavior_profile.anti_analysis_techniques.append(detection)

    def _detect_suspicious_behavior(self, event: MonitoredEvent):
        """Detect general suspicious behavior patterns."""
        try:
            # Suspicious file operations
            if event.event_type in [EventType.FILE_CREATE, EventType.FILE_MODIFY]:
                file_path = event.details.get('file_path', '')
                
                # Check for suspicious locations
                suspicious_locations = [
                    'system32', 'syswow64', 'windows/temp',
                    'program files', 'startup', 'appdata/roaming'
                ]
                
                if any(loc in file_path.lower() for loc in suspicious_locations):
                    suspicious_pattern = {
                        'type': 'suspicious_file_location',
                        'event': event,
                        'confidence': 0.6,
                        'timestamp': event.timestamp
                    }
                    self.behavior_profile.suspicious_patterns.append(suspicious_pattern)
            
            # Suspicious network activity
            elif event.event_type == EventType.NETWORK_CONNECT:
                connection = event.details.get('connection', '')
                
                # Check for suspicious ports
                suspicious_ports = ['1337', '31337', '666', '4444', '5555']
                if any(port in connection for port in suspicious_ports):
                    suspicious_pattern = {
                        'type': 'suspicious_network_port',
                        'event': event,
                        'confidence': 0.7,
                        'timestamp': event.timestamp
                    }
                    self.behavior_profile.suspicious_patterns.append(suspicious_pattern)
                    
        except Exception as e:
            self.logger.error(f"Error detecting suspicious behavior: {e}")

    def _perform_periodic_analysis(self):
        """Perform periodic analysis of collected events."""
        try:
            current_time = time.time()
            
            # Analyze event patterns over time
            self._analyze_event_frequency()
            
            # Update process genealogy
            self._update_process_genealogy()
            
            # Detect behavioral anomalies
            self._detect_behavioral_anomalies()
            
            # Update performance metrics
            self._update_performance_metrics(current_time)
            
        except Exception as e:
            self.logger.error(f"Error in periodic analysis: {e}")

    def _analyze_event_frequency(self):
        """Analyze frequency patterns in events."""
        try:
            event_counts = defaultdict(int)
            recent_events = [e for e in self.events if time.time() - e.timestamp < 60.0]
            
            for event in recent_events:
                event_counts[event.event_type] += 1
            
            # Detect anomalous frequencies
            for event_type, count in event_counts.items():
                if count > 100:  # More than 100 events of same type in 1 minute
                    anomaly = {
                        'type': 'high_frequency_events',
                        'event_type': event_type.name,
                        'count': count,
                        'confidence': 0.8,
                        'timestamp': time.time()
                    }
                    self.behavior_profile.suspicious_patterns.append(anomaly)
                    
        except Exception as e:
            self.logger.error(f"Error analyzing event frequency: {e}")

    def _update_process_genealogy(self):
        """Update process parent-child relationships."""
        try:
            for process in psutil.process_iter(['pid', 'ppid', 'name']):
                try:
                    pid = process.info['pid']
                    ppid = process.info['ppid']
                    
                    if ppid in self.monitored_processes:
                        self.process_genealogy[ppid].add(pid)
                        
                        if pid not in self.monitored_processes:
                            self._discover_process(pid)
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error updating process genealogy: {e}")

    def _perform_final_analysis(self):
        """Perform final comprehensive analysis."""
        try:
            # Generate behavior timeline
            self._generate_behavior_timeline()
            
            # Analyze protection mechanisms
            self._analyze_protection_mechanisms()
            
            # Generate risk assessment
            self._generate_risk_assessment()
            
            # Create behavioral fingerprint
            self._create_behavioral_fingerprint()
            
        except Exception as e:
            self.logger.error(f"Error in final analysis: {e}")

    def _generate_behavior_timeline(self):
        """Generate chronological behavior timeline."""
        try:
            timeline = []
            
            # Sort events by timestamp
            sorted_events = sorted(self.events, key=lambda e: e.timestamp)
            
            # Group events by time windows
            window_size = 5.0  # 5-second windows
            current_window = []
            current_window_start = None
            
            for event in sorted_events:
                if current_window_start is None:
                    current_window_start = event.timestamp
                
                if event.timestamp - current_window_start <= window_size:
                    current_window.append(event)
                else:
                    # Process current window
                    if current_window:
                        window_summary = self._summarize_event_window(current_window)
                        timeline.append(window_summary)
                    
                    # Start new window
                    current_window = [event]
                    current_window_start = event.timestamp
            
            # Process final window
            if current_window:
                window_summary = self._summarize_event_window(current_window)
                timeline.append(window_summary)
            
            self.behavior_profile.metadata['behavior_timeline'] = timeline
            
        except Exception as e:
            self.logger.error(f"Error generating behavior timeline: {e}")

    def _summarize_event_window(self, events: List[MonitoredEvent]) -> Dict[str, Any]:
        """Summarize events in a time window."""
        window_start = min(e.timestamp for e in events)
        window_end = max(e.timestamp for e in events)
        
        event_types = defaultdict(int)
        processes = set()
        tags = set()
        
        for event in events:
            event_types[event.event_type.name] += 1
            processes.add(event.process_id)
            tags.update(event.tags)
        
        return {
            'start_time': window_start,
            'end_time': window_end,
            'duration': window_end - window_start,
            'event_count': len(events),
            'event_types': dict(event_types),
            'process_count': len(processes),
            'tags': list(tags),
            'significant_events': [e for e in events if e.confidence > 0.8]
        }

    def _cleanup_old_data(self):
        """Clean up old data to prevent memory issues."""
        try:
            current_time = time.time()
            retention_period = 3600.0  # Keep 1 hour of data
            
            # Clean old events from queue (keep most recent)
            old_events = [e for e in self.events if current_time - e.timestamp > retention_period]
            
            if old_events:
                # Keep most important events
                important_events = [e for e in old_events if e.confidence > 0.8 or e.tags]
                
                # Remove less important old events
                for event in old_events:
                    if event not in important_events:
                        try:
                            self.events.remove(event)
                        except ValueError:
                            pass  # Event already removed
            
            # Clean cache
            old_cache_keys = [k for k, v in self.event_cache.items() 
                             if isinstance(v, dict) and current_time - v.get('timestamp', 0) > 300]
            
            for key in old_cache_keys:
                del self.event_cache[key]
                
        except Exception as e:
            self.logger.error(f"Error cleaning old data: {e}")

    def export_behavior_profile(self, output_path: str, format: str = 'json') -> bool:
        """
        Export behavior profile to file.
        
        Args:
            output_path: Path to output file
            format: Export format ('json', 'xml', 'html')
            
        Returns:
            True if export successful
        """
        try:
            if format == 'json':
                return self._export_json(output_path)
            elif format == 'xml':
                return self._export_xml(output_path)
            elif format == 'html':
                return self._export_html(output_path)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            self.logger.error(f"Error exporting behavior profile: {e}")
            return False

    def _export_json(self, output_path: str) -> bool:
        """Export as JSON format."""
        try:
            # Convert behavior profile to serializable format
            export_data = {
                'monitoring_session': {
                    'start_time': self.behavior_profile.start_time,
                    'end_time': self.behavior_profile.end_time,
                    'duration': (self.behavior_profile.end_time or time.time()) - self.behavior_profile.start_time,
                    'monitoring_level': self.monitoring_level.value,
                    'total_events': self.behavior_profile.total_events
                },
                'process_tree': {
                    str(pid): {
                        'name': proc.name,
                        'command_line': proc.command_line,
                        'creation_time': proc.creation_time,
                        'parent_pid': proc.ppid,
                        'children': list(proc.children),
                        'is_target': proc.is_target
                    }
                    for pid, proc in self.behavior_profile.process_tree.items()
                },
                'license_indicators': self.behavior_profile.license_indicators,
                'protection_mechanisms': self.behavior_profile.protection_mechanisms,
                'anti_analysis_techniques': self.behavior_profile.anti_analysis_techniques,
                'suspicious_patterns': self.behavior_profile.suspicious_patterns,
                'network_timeline': self.behavior_profile.network_timeline,
                'file_system_changes': self.behavior_profile.file_system_changes,
                'registry_changes': self.behavior_profile.registry_changes,
                'memory_analysis': self.behavior_profile.memory_analysis,
                'performance_metrics': self.behavior_profile.performance_metrics,
                'event_summary': self._generate_event_summary()
            }
            
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
                
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting JSON: {e}")
            return False

    def _generate_event_summary(self) -> Dict[str, Any]:
        """Generate summary statistics of events."""
        event_type_counts = defaultdict(int)
        tag_counts = defaultdict(int)
        process_event_counts = defaultdict(int)
        
        for event in self.events:
            event_type_counts[event.event_type.name] += 1
            process_event_counts[event.process_id] += 1
            
            for tag in event.tags:
                tag_counts[tag] += 1
        
        return {
            'event_type_distribution': dict(event_type_counts),
            'tag_distribution': dict(tag_counts),
            'process_activity': dict(process_event_counts),
            'high_confidence_events': len([e for e in self.events if e.confidence > 0.8]),
            'tagged_events': len([e for e in self.events if e.tags])
        }

    # Helper methods for pattern detection
    def _load_license_patterns(self) -> List[LicensePattern]:
        """Load license detection patterns."""
        patterns = [
            LicensePattern(
                pattern_type="registry_license_key",
                description="License key stored in registry",
                indicators=["license", "serial", "key", "activation"],
                weight=0.9,
                false_positive_rate=0.1
            ),
            LicensePattern(
                pattern_type="time_based_check",
                description="Time-based license validation",
                indicators=["trial", "expire", "date", "time"],
                weight=0.8,
                false_positive_rate=0.2
            ),
            LicensePattern(
                pattern_type="hardware_fingerprint",
                description="Hardware-based license binding",
                indicators=["hardware", "fingerprint", "mac", "volume"],
                weight=0.85,
                false_positive_rate=0.15
            ),
            LicensePattern(
                pattern_type="network_validation",
                description="Network-based license validation",
                indicators=["activate", "validate", "server", "online"],
                weight=0.9,
                false_positive_rate=0.1
            )
        ]
        return patterns

    def _load_protection_patterns(self) -> List[Dict[str, Any]]:
        """Load protection mechanism patterns."""
        return [
            {'name': 'code_obfuscation', 'indicators': ['virtualize', 'obfuscate', 'protect']},
            {'name': 'anti_debug', 'indicators': ['debug', 'debugger', 'attach']},
            {'name': 'anti_dump', 'indicators': ['dump', 'memory', 'protect']},
            {'name': 'packing', 'indicators': ['pack', 'compress', 'encrypt']}
        ]

    def _load_anti_analysis_patterns(self) -> List[Dict[str, Any]]:
        """Load anti-analysis technique patterns."""
        return [
            {'name': 'vm_detection', 'indicators': ['vmware', 'virtualbox', 'qemu']},
            {'name': 'sandbox_detection', 'indicators': ['sandbox', 'analysis', 'monitor']},
            {'name': 'timing_attack', 'indicators': ['tick', 'time', 'delay']},
            {'name': 'process_check', 'indicators': ['process', 'tool', 'analyzer']}
        ]

    def _event_matches_pattern(self, event: MonitoredEvent, pattern: LicensePattern) -> bool:
        """Check if event matches a license pattern."""
        event_str = str(event.details).lower()
        return any(indicator.lower() in event_str for indicator in pattern.indicators)

    def _is_license_related_file(self, file_path: str) -> bool:
        """Check if file path is license-related."""
        license_keywords = ['license', 'serial', 'key', 'activation', 'trial', 'demo']
        return any(keyword in file_path.lower() for keyword in license_keywords)

    def _is_license_related_registry(self, key_path: str) -> bool:
        """Check if registry key is license-related."""
        license_keywords = ['license', 'serial', 'key', 'activation', 'trial', 'registration']
        return any(keyword in key_path.lower() for keyword in license_keywords)

    def _is_license_server_connection(self, connection_info: str) -> bool:
        """Check if network connection is to a license server."""
        license_indicators = ['activate', 'license', 'auth', 'validate']
        return any(indicator in connection_info.lower() for indicator in license_indicators)

    # Additional helper methods would continue here...
    # For brevity, I'm including the key structural elements

if __name__ == "__main__":
    # Example usage
    monitor = RuntimeBehaviorMonitor(MonitoringLevel.STANDARD)
    
    try:
        # Start monitoring
        monitor.start_monitoring()
        
        # Simulate monitoring for 30 seconds
        time.sleep(30)
        
        # Stop and get results
        profile = monitor.stop_monitoring()
        
        # Export results
        monitor.export_behavior_profile("behavior_analysis.json")
        
        print(f"Monitoring completed. Total events: {profile.total_events}")
        print(f"License indicators: {len(profile.license_indicators)}")
        print(f"Protection mechanisms: {len(profile.protection_mechanisms)}")
        
    except KeyboardInterrupt:
        print("Monitoring interrupted by user")
        profile = monitor.stop_monitoring()