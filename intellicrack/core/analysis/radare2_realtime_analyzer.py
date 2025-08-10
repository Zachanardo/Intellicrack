"""Radare2 real-time analysis module for dynamic binary monitoring.

Copyright (C) 2025 Zachary Flint

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

import hashlib
import os
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from intellicrack.logger import logger

from ...utils.logger import get_logger
from .radare2_error_handler import get_error_handler, r2_error_context
from .radare2_json_standardizer import standardize_r2_result
from .radare2_performance_optimizer import OptimizationStrategy, create_performance_optimizer

"""
Real-time Radare2 Analysis with Live Updating Capabilities

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellirack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellirack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


try:
    import r2pipe
except ImportError as e:
    logger.error("Import error in radare2_realtime_analyzer: %s", e)
    r2pipe = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    WATCHDOG_AVAILABLE = True
except ImportError as e:
    logger.error("Import error in radare2_realtime_analyzer: %s", e)
    WATCHDOG_AVAILABLE = False


logger = get_logger(__name__)
error_handler = get_error_handler()


class AnalysisEvent(Enum):
    """Types of analysis events"""

    FILE_MODIFIED = "file_modified"
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_FAILED = "analysis_failed"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    LICENSE_PATTERN_FOUND = "license_pattern_found"
    IMPORT_CHANGED = "import_changed"
    STRING_ANALYSIS_UPDATED = "string_analysis_updated"
    PERFORMANCE_ALERT = "performance_alert"
    ERROR_DETECTED = "error_detected"


class UpdateMode(Enum):
    """Real-time update modes"""

    CONTINUOUS = "continuous"  # Continuous monitoring
    INTERVAL = "interval"  # Periodic updates
    ON_CHANGE = "on_change"  # Only when file changes
    HYBRID = "hybrid"  # Combination of interval and on_change


@dataclass
class AnalysisUpdate:
    """Real-time analysis update"""

    timestamp: datetime
    event_type: AnalysisEvent
    binary_path: str
    data: dict[str, Any]
    confidence: float = 1.0
    severity: str = "info"
    analysis_id: str = ""
    source_component: str = ""
    related_updates: list[str] = field(default_factory=list)


class BinaryFileWatcher(FileSystemEventHandler):
    """File system watcher for binary file changes"""

    def __init__(self, callback: Callable, watched_files: set[str]):
        """Initialize the binary file watcher with callback and file monitoring."""
        self.callback = callback
        self.watched_files = watched_files
        self.logger = logger

        # Debouncing to prevent multiple events for same change
        self.last_modified = {}
        self.debounce_delay = 1.0  # 1 second  # 1 second

    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return

        file_path = os.path.abspath(event.src_path)

        # Check if this is a watched file
        if file_path not in self.watched_files:
            return

        # Debounce rapid modifications
        current_time = time.time()
        if file_path in self.last_modified:
            if current_time - self.last_modified[file_path] < self.debounce_delay:
                return

        self.last_modified[file_path] = current_time

        try:
            self.callback(file_path, AnalysisEvent.FILE_MODIFIED)
        except Exception as e:
            self.logger.error(f"Error in file watcher callback: {e}")


class R2RealtimeAnalyzer:
    """Real-time radare2 analyzer with live updating capabilities.

    This class provides:
    - Real-time binary analysis with live updates
    - File system monitoring for automatic re-analysis
    - Streaming analysis results
    - Performance monitoring and optimization
    - Event-driven architecture
    - Multiple update modes
    - Intelligent caching and incremental analysis
    """

    def __init__(
        self,
        update_mode: UpdateMode = UpdateMode.HYBRID,
        update_interval: float = 30.0,
        max_concurrent_analyses: int = 3,
    ):
        """Initialize the Radare2 real-time analyzer.

        Args:
            update_mode: The update strategy for real-time analysis.
            update_interval: The interval in seconds between analysis updates.
            max_concurrent_analyses: Maximum number of concurrent analysis operations.

        """
        self.update_mode = update_mode
        self.update_interval = update_interval
        self.max_concurrent_analyses = max_concurrent_analyses

        self.logger = logger
        self.error_handler = error_handler

        # Analysis state
        self.watched_binaries: dict[str, dict[str, Any]] = {}
        self.active_analyses: dict[str, threading.Thread] = {}
        self.analysis_queue = queue.Queue(maxsize=100)

        # Event system
        self.event_callbacks: dict[AnalysisEvent, list[Callable]] = {
            event: [] for event in AnalysisEvent
        }

        # File watching
        self.file_observer = None
        self.file_watcher = None

        # Real-time state
        self.running = False
        self.worker_threads: list[threading.Thread] = []
        self.update_thread = None

        # Performance optimization
        self.performance_optimizer = create_performance_optimizer(
            OptimizationStrategy.SPEED_OPTIMIZED
        )

        # Results storage
        self.latest_results: dict[str, dict[str, Any]] = {}
        self.result_history: dict[str, list[AnalysisUpdate]] = {}

        # Incremental analysis tracking
        self.file_hashes: dict[str, str] = {}
        self.analysis_cache: dict[str, dict[str, Any]] = {}

        self.logger.info(f"R2RealtimeAnalyzer initialized with {update_mode.value} mode")

    def add_binary(self, binary_path: str, analysis_config: dict[str, Any] | None = None) -> bool:
        """Add binary for real-time analysis.

        Args:
            binary_path: Path to binary file
            analysis_config: Optional analysis configuration

        Returns:
            bool: True if successfully added

        """
        try:
            if not os.path.exists(binary_path):
                self.logger.error(f"Binary file not found: {binary_path}")
                return False

            binary_path = os.path.abspath(binary_path)

            # Calculate initial file hash
            file_hash = self._calculate_file_hash(binary_path)
            self.file_hashes[binary_path] = file_hash

            # Get optimized configuration
            if not analysis_config:
                analysis_config = self.performance_optimizer.optimize_for_binary(binary_path)

            # Store binary information
            self.watched_binaries[binary_path] = {
                "config": analysis_config,
                "last_analysis": None,
                "analysis_count": 0,
                "file_hash": file_hash,
                "watch_enabled": True,
                "priority": "normal",
            }

            # Initialize result storage
            self.latest_results[binary_path] = {}
            self.result_history[binary_path] = []

            # Trigger initial analysis
            self._schedule_analysis(binary_path, AnalysisEvent.ANALYSIS_STARTED, priority="high")

            self.logger.info(f"Added binary for real-time analysis: {binary_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to add binary {binary_path}: {e}")
            return False

    def remove_binary(self, binary_path: str) -> bool:
        """Remove binary from real-time analysis.

        Args:
            binary_path: Path to binary file

        Returns:
            bool: True if successfully removed

        """
        try:
            binary_path = os.path.abspath(binary_path)

            if binary_path in self.watched_binaries:
                # Stop any active analysis
                if binary_path in self.active_analyses:
                    thread = self.active_analyses[binary_path]
                    if thread.is_alive():
                        # Note: We can't force stop threads, but we can mark them for cleanup
                        pass
                    del self.active_analyses[binary_path]

                # Clean up stored data
                del self.watched_binaries[binary_path]
                if binary_path in self.latest_results:
                    del self.latest_results[binary_path]
                if binary_path in self.result_history:
                    del self.result_history[binary_path]
                if binary_path in self.file_hashes:
                    del self.file_hashes[binary_path]
                if binary_path in self.analysis_cache:
                    del self.analysis_cache[binary_path]

                self.logger.info(f"Removed binary from real-time analysis: {binary_path}")
                return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to remove binary {binary_path}: {e}")
            return False

    def start_realtime_analysis(self):
        """Start real-time analysis system"""
        if self.running:
            self.logger.warning("Real-time analysis already running")
            return

        try:
            self.running = True

            # Start worker threads for analysis processing
            for i in range(self.max_concurrent_analyses):
                worker = threading.Thread(
                    target=self._analysis_worker,
                    name=f"R2RealtimeWorker-{i}",
                    daemon=True,
                )
                worker.start()
                self.worker_threads.append(worker)

            # Start file system monitoring if available and needed
            if WATCHDOG_AVAILABLE and self.update_mode in [UpdateMode.ON_CHANGE, UpdateMode.HYBRID]:
                self._start_file_monitoring()

            # Start interval-based updates if needed
            if self.update_mode in [UpdateMode.INTERVAL, UpdateMode.HYBRID, UpdateMode.CONTINUOUS]:
                self.update_thread = threading.Thread(
                    target=self._update_loop,
                    name="R2RealtimeUpdater",
                    daemon=True,
                )
                self.update_thread.start()

            # Start performance monitoring
            self.performance_optimizer.start_monitoring()

            self.logger.info("Real-time analysis system started")

        except Exception as e:
            self.logger.error(f"Failed to start real-time analysis: {e}")
            self.running = False

    def stop_realtime_analysis(self):
        """Stop real-time analysis system"""
        if not self.running:
            return

        try:
            self.running = False

            # Stop file monitoring
            self._stop_file_monitoring()

            # Stop performance monitoring
            self.performance_optimizer.stop_monitoring()

            # Wait for worker threads to finish current work
            for worker in self.worker_threads:
                worker.join(timeout=10)

            if self.update_thread:
                self.update_thread.join(timeout=5)

            # Clear active analyses
            self.active_analyses.clear()

            # Clear analysis queue
            while not self.analysis_queue.empty():
                try:
                    self.analysis_queue.get_nowait()
                except queue.Empty as e:
                    logger.error("queue.Empty in radare2_realtime_analyzer: %s", e)
                    break

            self.worker_threads.clear()
            self.update_thread = None

            self.logger.info("Real-time analysis system stopped")

        except Exception as e:
            self.logger.error(f"Failed to stop real-time analysis: {e}")

    def _start_file_monitoring(self):
        """Start file system monitoring"""
        try:
            if not WATCHDOG_AVAILABLE:
                self.logger.warning("Watchdog not available for file monitoring")
                return

            watched_files = set(self.watched_binaries.keys())
            if not watched_files:
                return

            self.file_watcher = BinaryFileWatcher(
                callback=self._on_file_changed,
                watched_files=watched_files,
            )

            self.file_observer = Observer()

            # Watch directories containing the binaries
            watched_dirs = set()
            for binary_path in watched_files:
                directory = os.path.dirname(binary_path)
                if directory not in watched_dirs:
                    self.file_observer.schedule(self.file_watcher, directory, recursive=False)
                    watched_dirs.add(directory)

            self.file_observer.start()
            self.logger.info(f"File monitoring started for {len(watched_dirs)} directories")

        except Exception as e:
            self.logger.error(f"Failed to start file monitoring: {e}")

    def _stop_file_monitoring(self):
        """Stop file system monitoring"""
        try:
            if self.file_observer:
                self.file_observer.stop()
                self.file_observer.join(timeout=5)
                self.file_observer = None

            self.file_watcher = None
            self.logger.info("File monitoring stopped")

        except Exception as e:
            self.logger.error(f"Failed to stop file monitoring: {e}")

    def _on_file_changed(self, file_path: str, event_type: AnalysisEvent):
        """Handle file change events"""
        try:
            # Check if file hash actually changed
            current_hash = self._calculate_file_hash(file_path)
            previous_hash = self.file_hashes.get(file_path)

            if current_hash != previous_hash:
                self.file_hashes[file_path] = current_hash

                # Clear cache for this file
                if file_path in self.analysis_cache:
                    del self.analysis_cache[file_path]

                # Schedule re-analysis
                self._schedule_analysis(file_path, event_type, priority="high")

                # Emit file change event
                self._emit_event(
                    AnalysisUpdate(
                        timestamp=datetime.now(),
                        event_type=event_type,
                        binary_path=file_path,
                        data={"file_hash": current_hash, "previous_hash": previous_hash},
                        source_component="file_watcher",
                    )
                )

                self.logger.info(f"File change detected: {file_path}")

        except Exception as e:
            self.logger.error(f"Error handling file change for {file_path}: {e}")

    def _schedule_analysis(
        self, binary_path: str, event_type: AnalysisEvent, priority: str = "normal"
    ):
        """Schedule analysis for binary"""
        try:
            # Check if analysis is already running for this binary
            if binary_path in self.active_analyses:
                thread = self.active_analyses[binary_path]
                if thread.is_alive():
                    self.logger.debug(f"Analysis already running for {binary_path}")
                    return

            # Add to queue
            analysis_task = {
                "binary_path": binary_path,
                "event_type": event_type,
                "priority": priority,
                "timestamp": time.time(),
            }

            try:
                if priority == "high":
                    # For high priority, try to add to front of queue
                    # This is a simplified approach; a proper priority queue would be better
                    temp_items = []

                    # Extract all items
                    while not self.analysis_queue.empty():
                        try:
                            temp_items.append(self.analysis_queue.get_nowait())
                        except queue.Empty as e:
                            logger.error("queue.Empty in radare2_realtime_analyzer: %s", e)
                            break

                    # Add high priority item first
                    self.analysis_queue.put(analysis_task, timeout=1)

                    # Re-add other items
                    for item in temp_items:
                        try:
                            self.analysis_queue.put(item, timeout=0.1)
                        except queue.Full as e:
                            logger.error("queue.Full in radare2_realtime_analyzer: %s", e)
                            break  # Queue is full, drop oldest items
                else:
                    self.analysis_queue.put(analysis_task, timeout=1)

            except queue.Full:
                self.logger.warning(f"Analysis queue full, dropping task for {binary_path}")

        except Exception as e:
            self.logger.error(f"Failed to schedule analysis for {binary_path}: {e}")

    def _analysis_worker(self):
        """Worker thread for processing analysis tasks"""
        while self.running:
            try:
                # Get task from queue with timeout
                try:
                    task = self.analysis_queue.get(timeout=5)
                except queue.Empty as e:
                    self.logger.error("queue.Empty in radare2_realtime_analyzer: %s", e)
                    continue

                binary_path = task["binary_path"]
                event_type = task["event_type"]

                # Check if binary is still being watched
                if binary_path not in self.watched_binaries:
                    continue

                # Mark analysis as active
                analysis_thread = threading.current_thread()
                self.active_analyses[binary_path] = analysis_thread

                try:
                    # Perform analysis
                    self._perform_incremental_analysis(binary_path, event_type)
                finally:
                    # Remove from active analyses
                    if binary_path in self.active_analyses:
                        del self.active_analyses[binary_path]

            except Exception as e:
                self.logger.error(f"Analysis worker error: {e}")
                time.sleep(1)  # Prevent tight error loops

    def _perform_incremental_analysis(self, binary_path: str, trigger_event: AnalysisEvent):
        """Perform incremental analysis on binary"""
        try:
            start_time = time.time()

            # Emit analysis started event
            self._emit_event(
                AnalysisUpdate(
                    timestamp=datetime.now(),
                    event_type=AnalysisEvent.ANALYSIS_STARTED,
                    binary_path=binary_path,
                    data={"trigger_event": trigger_event.value},
                    source_component="realtime_analyzer",
                )
            )

            # Get configuration
            binary_config = self.watched_binaries[binary_path]
            config = binary_config["config"]

            # Determine what analysis to perform based on trigger and cache
            analysis_components = self._determine_analysis_components(binary_path, trigger_event)

            results = {}
            analysis_id = f"rt_{int(time.time())}_{hash(binary_path) % 10000}"

            # Perform analysis using r2
            with r2_error_context("realtime_analysis", binary_path=binary_path):
                with r2pipe.open(binary_path, flags=config.get("r2_flags", [])) as r2:
                    # Apply optimizations
                    self.performance_optimizer.optimize_r2_session(r2, config)

                    # Perform initial analysis if needed
                    if not self._is_analysis_cached(binary_path, "basic"):
                        r2.cmd(config.get("analysis_level", "aa"))
                        self._cache_analysis_result(binary_path, "basic", {"completed": True})

                    # Run specific analysis components
                    for component in analysis_components:
                        try:
                            component_result = self._run_analysis_component(
                                r2, component, binary_path
                            )
                            if component_result:
                                results[component] = component_result

                                # Check for significant findings
                                self._check_for_significant_findings(
                                    binary_path, component, component_result
                                )

                        except Exception as e:
                            self.logger.error(
                                f"Component {component} failed for {binary_path}: {e}"
                            )
                            results[component] = {"error": str(e)}

            # Calculate analysis duration
            duration = time.time() - start_time

            # Update latest results
            self.latest_results[binary_path].update(results)

            # Update binary statistics
            binary_config["last_analysis"] = datetime.now()
            binary_config["analysis_count"] += 1

            # Standardize results
            standardized_results = standardize_r2_result(
                "realtime",
                {
                    "components": results,
                    "analysis_id": analysis_id,
                    "trigger_event": trigger_event.value,
                    "duration": duration,
                    "incremental": True,
                },
                binary_path,
                {"realtime_analysis": True},
            )

            # Emit analysis completed event
            self._emit_event(
                AnalysisUpdate(
                    timestamp=datetime.now(),
                    event_type=AnalysisEvent.ANALYSIS_COMPLETED,
                    binary_path=binary_path,
                    data=standardized_results,
                    analysis_id=analysis_id,
                    source_component="realtime_analyzer",
                )
            )

            self.logger.info(f"Real-time analysis completed for {binary_path} in {duration:.2f}s")

        except Exception as e:
            self.logger.error(f"Real-time analysis failed for {binary_path}: {e}")

            # Emit analysis failed event
            self._emit_event(
                AnalysisUpdate(
                    timestamp=datetime.now(),
                    event_type=AnalysisEvent.ANALYSIS_FAILED,
                    binary_path=binary_path,
                    data={"error": str(e)},
                    severity="error",
                    source_component="realtime_analyzer",
                )
            )

    def _determine_analysis_components(
        self, binary_path: str, trigger_event: AnalysisEvent
    ) -> list[str]:
        """Determine which analysis components to run based on binary characteristics"""
        # Base components for different triggers
        base_components = ["strings", "imports"]

        # Analyze binary path and file characteristics
        file_name = os.path.basename(binary_path).lower()
        file_size = 0
        file_extension = os.path.splitext(file_name)[1].lower()

        try:
            file_size = os.path.getsize(binary_path)
        except Exception as e:
            self.logger.error("Exception in radare2_realtime_analyzer: %s", e)

        # Check if this binary has been analyzed before
        is_initial_analysis = (
            binary_path not in self.latest_results or not self.latest_results[binary_path]
        )

        # Determine components based on file type and characteristics
        components = []

        # Always include base components
        components.extend(base_components)

        # Add components based on trigger event
        if trigger_event == AnalysisEvent.FILE_MODIFIED:
            # Full re-analysis on file modification
            components.extend(["functions", "vulnerabilities", "basic_info"])

            # Check what changed based on cached data
            if binary_path in self.analysis_cache:
                # If we have previous analysis, we can be more selective
                prev_hash = self.watched_binaries.get(binary_path, {}).get("file_hash", "")
                curr_hash = self.file_hashes.get(binary_path, "")

                # If only small change, focus on specific components
                if prev_hash and curr_hash:
                    components.append("patch_detection")

        elif trigger_event == AnalysisEvent.ANALYSIS_STARTED or is_initial_analysis:
            # Initial analysis - comprehensive scan
            components.extend(["functions", "basic_info", "vulnerabilities"])

            # Add extra components for executables
            if file_extension in [".exe", ".dll", ".so", ".dylib", ""]:
                components.extend(["headers", "sections", "relocations"])

        # Add components based on file characteristics
        # Large files get optimized analysis
        if file_size > 50 * 1024 * 1024:  # > 50MB
            # Remove some heavy components for large files
            if "functions" in components and file_size > 100 * 1024 * 1024:
                components.remove("functions")
                components.append("functions_summary")  # Lighter alternative

        # Packed/encrypted binaries
        if binary_path in self.latest_results:
            prev_results = self.latest_results[binary_path]
            if prev_results.get("basic_info", {}).get("packed", False):
                components.append("unpacking_analysis")

        # Add components based on file extension
        if file_extension == ".dll":
            components.append("exports")
            components.append("dll_characteristics")
        elif file_extension == ".so":
            components.append("elf_analysis")
            components.append("symbols")
        elif file_extension == ".dylib":
            components.append("macho_analysis")
        elif file_extension in [".sys", ".drv"]:
            components.append("driver_analysis")

        # Add components based on filename patterns
        license_patterns = ["license", "auth", "serial", "key", "activate", "trial"]
        if any(pattern in file_name for pattern in license_patterns):
            components.append("license_analysis")
            components.append("crypto_detection")

        network_patterns = ["net", "sock", "http", "tcp", "udp", "comm"]
        if any(pattern in file_name for pattern in network_patterns):
            components.append("network_analysis")

        security_patterns = ["crypt", "secure", "auth", "protect", "guard"]
        if any(pattern in file_name for pattern in security_patterns):
            components.append("crypto_detection")
            components.append("security_features")

        # Based on previous analysis results, adapt components
        if self.result_history.get(binary_path):
            recent_events = self.result_history[binary_path][-5:]  # Last 5 events

            # If vulnerabilities were found before, prioritize vulnerability scanning
            if any(
                event.event_type == AnalysisEvent.VULNERABILITY_DETECTED for event in recent_events
            ):
                if "vulnerabilities" not in components:
                    components.append("vulnerabilities")
                components.append("exploit_detection")

            # If license patterns were found, add detailed license analysis
            if any(
                event.event_type == AnalysisEvent.LICENSE_PATTERN_FOUND for event in recent_events
            ):
                if "license_analysis" not in components:
                    components.append("license_analysis")
                components.append("string_analysis_deep")

        # Performance optimization based on current system load
        if hasattr(self.performance_optimizer, "get_current_load"):
            system_load = self.performance_optimizer.get_current_load()
            if system_load > 0.8:  # High system load
                # Remove heavy analysis components
                heavy_components = ["functions", "vulnerabilities", "unpacking_analysis"]
                components = [c for c in components if c not in heavy_components]

        # Remove duplicates while preserving order
        seen = set()
        unique_components = []
        for component in components:
            if component not in seen:
                seen.add(component)
                unique_components.append(component)

        return unique_components

    def _run_analysis_component(
        self, r2, component: str, binary_path: str
    ) -> dict[str, Any] | None:
        """Run specific analysis component with context awareness"""
        try:
            # Get binary context information
            file_name = os.path.basename(binary_path).lower()
            file_size = os.path.getsize(binary_path) if os.path.exists(binary_path) else 0
            file_extension = os.path.splitext(file_name)[1].lower()

            # Check cache first for some components
            if self._is_analysis_cached(binary_path, component):
                cached_result = self.analysis_cache[binary_path][component].get("result")
                if cached_result:
                    return cached_result

            result = None

            if component == "strings":
                # Context-aware string extraction
                strings = r2.cmdj("izzj") or []

                # Filter strings based on binary context
                if "license" in file_name or "auth" in file_name:
                    # Focus on license-related strings
                    filtered_strings = [
                        s
                        for s in strings
                        if any(
                            keyword in s.get("string", "").lower()
                            for keyword in ["license", "key", "serial", "activation", "trial"]
                        )
                    ]
                    result = {"strings": strings, "filtered_strings": filtered_strings}
                else:
                    result = {"strings": strings}

            elif component == "imports":
                imports = r2.cmdj("iij") or []
                exports = r2.cmdj("iEj") or []

                # Add context-specific import analysis
                suspicious_imports = []
                if file_extension in [".exe", ".dll"]:
                    # Windows-specific suspicious imports
                    suspicious_patterns = [
                        "VirtualAllocEx",
                        "WriteProcessMemory",
                        "CreateRemoteThread",
                    ]
                    suspicious_imports = [
                        imp
                        for imp in imports
                        if any(pattern in imp.get("name", "") for pattern in suspicious_patterns)
                    ]

                result = {
                    "imports": imports,
                    "exports": exports,
                    "suspicious_imports": suspicious_imports,
                    "import_count": len(imports),
                    "export_count": len(exports),
                }

            elif component == "functions":
                functions = r2.cmdj("aflj") or []

                # For large binaries, provide summary instead
                if file_size > 100 * 1024 * 1024:  # > 100MB
                    result = {
                        "function_count": len(functions),
                        "main_functions": [f for f in functions[:20]],  # First 20 functions
                        "large_file": True,
                    }
                else:
                    # Analyze functions based on binary type
                    entry_points = [f for f in functions if "entry" in f.get("name", "").lower()]
                    suspicious_funcs = [
                        f
                        for f in functions
                        if any(
                            pattern in f.get("name", "").lower()
                            for pattern in ["decrypt", "unpack", "inject", "hook"]
                        )
                    ]

                    result = {
                        "functions": functions,
                        "entry_points": entry_points,
                        "suspicious_functions": suspicious_funcs,
                        "function_count": len(functions),
                    }

            elif component == "functions_summary":
                # Lightweight function analysis for large files
                func_count = r2.cmd("afl~?")
                result = {
                    "function_count": int(func_count.strip()) if func_count else 0,
                    "summary_only": True,
                }

            elif component == "basic_info":
                info = r2.cmdj("ij") or {}

                # Add binary path context to info
                info["analyzed_path"] = binary_path
                info["file_name"] = file_name
                info["file_size"] = file_size

                # Check for packing based on entropy
                sections = r2.cmdj("iSj") or []
                high_entropy_sections = [s for s in sections if s.get("entropy", 0) > 7.0]
                info["likely_packed"] = len(high_entropy_sections) > 0

                result = {"info": info}

            elif component == "vulnerabilities":
                # Context-aware vulnerability detection
                imports = r2.cmdj("iij") or []

                # Expand vulnerability patterns based on binary type
                vuln_patterns = ["strcpy", "sprintf", "gets", "scanf", "strcat"]
                if file_extension == ".dll":
                    vuln_patterns.extend(["LoadLibrary", "GetProcAddress"])
                elif "net" in file_name or "sock" in file_name:
                    vuln_patterns.extend(["recv", "recvfrom"])

                vuln_imports = [
                    imp
                    for imp in imports
                    if any(vuln in imp.get("name", "").lower() for vuln in vuln_patterns)
                ]

                # Check for specific vulnerability patterns in functions
                functions = r2.cmdj("aflj") or []
                vuln_functions = []
                for func in functions[:100]:  # Check first 100 functions
                    func_name = func.get("name", "").lower()
                    if any(
                        pattern in func_name for pattern in ["overflow", "vulnerable", "exploit"]
                    ):
                        vuln_functions.append(func)

                result = {
                    "potential_vulnerabilities": vuln_imports,
                    "vulnerable_functions": vuln_functions,
                    "vulnerability_score": len(vuln_imports) + len(vuln_functions),
                }

            elif component == "license_analysis":
                # Specialized license analysis based on binary path
                strings = r2.cmdj("izzj") or []
                imports = r2.cmdj("iij") or []

                license_strings = [
                    s
                    for s in strings
                    if any(
                        keyword in s.get("string", "").lower()
                        for keyword in ["license", "serial", "activation", "trial", "expire"]
                    )
                ]

                license_imports = [
                    imp
                    for imp in imports
                    if any(
                        api in imp.get("name", "").lower()
                        for api in ["regquery", "regopen", "getvolume", "getsystem"]
                    )
                ]

                result = {
                    "license_strings": license_strings,
                    "license_apis": license_imports,
                    "has_licensing": len(license_strings) > 0 or len(license_imports) > 0,
                }

            elif component == "network_analysis":
                # Network-specific analysis
                imports = r2.cmdj("iij") or []
                network_imports = [
                    imp
                    for imp in imports
                    if any(
                        api in imp.get("name", "").lower()
                        for api in ["socket", "connect", "send", "recv", "internet", "http"]
                    )
                ]

                strings = r2.cmdj("izzj") or []
                url_strings = [
                    s
                    for s in strings
                    if any(
                        pattern in s.get("string", "")
                        for pattern in ["http://", "https://", "ftp://", "tcp://", "udp://"]
                    )
                ]

                result = {
                    "network_apis": network_imports,
                    "urls": url_strings,
                    "has_network": len(network_imports) > 0 or len(url_strings) > 0,
                }

            elif component == "crypto_detection":
                # Cryptography detection
                imports = r2.cmdj("iij") or []
                crypto_imports = [
                    imp
                    for imp in imports
                    if any(
                        api in imp.get("name", "").lower()
                        for api in ["crypt", "hash", "aes", "rsa", "encrypt", "decrypt"]
                    )
                ]

                strings = r2.cmdj("izzj") or []
                crypto_strings = [
                    s
                    for s in strings
                    if any(
                        pattern in s.get("string", "").lower()
                        for pattern in ["aes", "rsa", "sha", "md5", "encrypt"]
                    )
                ]

                result = {
                    "crypto_apis": crypto_imports,
                    "crypto_strings": crypto_strings,
                    "uses_crypto": len(crypto_imports) > 0 or len(crypto_strings) > 0,
                }

            elif component == "headers":
                # File headers analysis
                headers = r2.cmdj("ihj") or []
                result = {"headers": headers}

            elif component == "sections":
                # Section analysis with context
                sections = r2.cmdj("iSj") or []

                # Analyze sections for anomalies
                anomalous_sections = []
                for section in sections:
                    # Check for suspicious section names
                    name = section.get("name", "").lower()
                    if (
                        any(pattern in name for pattern in ["upx", "pack", ".0", "crypt"])
                        or section.get("entropy", 0) > 7.5
                    ):
                        anomalous_sections.append(section)

                result = {
                    "sections": sections,
                    "anomalous_sections": anomalous_sections,
                    "section_count": len(sections),
                }

            else:
                # Generic component handler
                self.logger.debug(f"Running generic handler for component: {component}")
                return None

            # Cache the result
            if result:
                self._cache_analysis_result(binary_path, component, result)

            return result

        except Exception as e:
            self.logger.error(f"Analysis component {component} failed for {binary_path}: {e}")
            return None

    def _check_for_significant_findings(
        self, binary_path: str, component: str, result: dict[str, Any]
    ):
        """Check analysis results for significant findings and emit events"""
        try:
            if component == "vulnerabilities" and result.get("potential_vulnerabilities"):
                self._emit_event(
                    AnalysisUpdate(
                        timestamp=datetime.now(),
                        event_type=AnalysisEvent.VULNERABILITY_DETECTED,
                        binary_path=binary_path,
                        data=result,
                        severity="high",
                        source_component=component,
                    )
                )

            elif component == "strings":
                strings = result.get("strings", [])
                license_keywords = ["license", "copyright", "patent", "proprietary"]

                license_strings = [
                    s
                    for s in strings
                    if any(keyword in s.get("string", "").lower() for keyword in license_keywords)
                ]

                if license_strings:
                    self._emit_event(
                        AnalysisUpdate(
                            timestamp=datetime.now(),
                            event_type=AnalysisEvent.LICENSE_PATTERN_FOUND,
                            binary_path=binary_path,
                            data={"license_strings": license_strings},
                            severity="medium",
                            source_component=component,
                        )
                    )

        except Exception as e:
            self.logger.error(f"Error checking findings for {component}: {e}")

    def _is_analysis_cached(self, binary_path: str, analysis_type: str) -> bool:
        """Check if analysis result is cached"""
        if binary_path not in self.analysis_cache:
            return False

        cache_entry = self.analysis_cache[binary_path].get(analysis_type)
        if not cache_entry:
            return False

        # Check if cache is still valid (5 minutes)
        cache_time = cache_entry.get("timestamp", 0)
        return time.time() - cache_time < 300

    def _cache_analysis_result(self, binary_path: str, analysis_type: str, result: dict[str, Any]):
        """Cache analysis result"""
        if binary_path not in self.analysis_cache:
            self.analysis_cache[binary_path] = {}

        self.analysis_cache[binary_path][analysis_type] = {
            "result": result,
            "timestamp": time.time(),
        }

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate file hash for change detection"""
        try:
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                # Read file in chunks to handle large files
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to calculate hash for {file_path}: {e}")
            return str(time.time())  # Fallback to timestamp

    def _update_loop(self):
        """Main update loop for interval-based updates"""
        while self.running:
            try:
                # Schedule updates for all watched binaries
                for binary_path in list(self.watched_binaries.keys()):
                    if not self.running:
                        break

                    binary_config = self.watched_binaries[binary_path]

                    # Check if enough time has passed since last analysis
                    last_analysis = binary_config.get("last_analysis")
                    if last_analysis:
                        time_since_last = datetime.now() - last_analysis
                        if time_since_last.total_seconds() < self.update_interval:
                            continue

                    # Schedule analysis
                    self._schedule_analysis(binary_path, AnalysisEvent.ANALYSIS_STARTED)

                # Wait for next update cycle
                time.sleep(self.update_interval)

            except Exception as e:
                self.logger.error(f"Update loop error: {e}")
                time.sleep(10)  # Wait longer on error

    def register_event_callback(self, event_type: AnalysisEvent, callback: Callable):
        """Register callback for analysis events"""
        if event_type not in self.event_callbacks:
            self.event_callbacks[event_type] = []

        self.event_callbacks[event_type].append(callback)
        self.logger.debug(f"Registered callback for {event_type.value}")

    def unregister_event_callback(self, event_type: AnalysisEvent, callback: Callable):
        """Unregister callback for analysis events"""
        if event_type in self.event_callbacks:
            try:
                self.event_callbacks[event_type].remove(callback)
                self.logger.debug(f"Unregistered callback for {event_type.value}")
            except ValueError as e:
                self.logger.error("Value error in radare2_realtime_analyzer: %s", e)

    def _emit_event(self, update: AnalysisUpdate):
        """Emit analysis event to registered callbacks"""
        try:
            # Store in history
            if update.binary_path not in self.result_history:
                self.result_history[update.binary_path] = []

            self.result_history[update.binary_path].append(update)

            # Keep only last 100 updates
            if len(self.result_history[update.binary_path]) > 100:
                self.result_history[update.binary_path] = self.result_history[update.binary_path][
                    -100:
                ]

            # Call registered callbacks
            callbacks = self.event_callbacks.get(update.event_type, [])
            for callback in callbacks:
                try:
                    callback(update)
                except Exception as e:
                    self.logger.error(f"Event callback error: {e}")

        except Exception as e:
            self.logger.error(f"Failed to emit event: {e}")

    def get_latest_results(self, binary_path: str) -> dict[str, Any] | None:
        """Get latest analysis results for binary"""
        return self.latest_results.get(binary_path)

    def get_result_history(self, binary_path: str, limit: int = 50) -> list[AnalysisUpdate]:
        """Get analysis result history for binary"""
        history = self.result_history.get(binary_path, [])
        return history[-limit:] if limit else history

    def get_status(self) -> dict[str, Any]:
        """Get real-time analyzer status"""
        return {
            "running": self.running,
            "update_mode": self.update_mode.value,
            "watched_binaries": len(self.watched_binaries),
            "active_analyses": len(self.active_analyses),
            "queue_size": self.analysis_queue.qsize(),
            "worker_threads": len(self.worker_threads),
            "file_monitoring": self.file_observer is not None,
            "performance_stats": self.performance_optimizer.get_performance_report(),
        }

    def cleanup(self):
        """Cleanup resources"""
        try:
            self.stop_realtime_analysis()

            # Clear all data
            self.watched_binaries.clear()
            self.latest_results.clear()
            self.result_history.clear()
            self.file_hashes.clear()
            self.analysis_cache.clear()

            # Cleanup performance optimizer
            self.performance_optimizer.cleanup()

            self.logger.info("R2RealtimeAnalyzer cleanup completed")

        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")


def create_realtime_analyzer(
    update_mode: UpdateMode = UpdateMode.HYBRID,
    update_interval: float = 30.0,
    max_concurrent_analyses: int = 3,
) -> R2RealtimeAnalyzer:
    """Create real-time analyzer instance"""
    return R2RealtimeAnalyzer(update_mode, update_interval, max_concurrent_analyses)


__all__ = [
    "AnalysisEvent",
    "AnalysisUpdate",
    "R2RealtimeAnalyzer",
    "UpdateMode",
    "create_realtime_analyzer",
]
