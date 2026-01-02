"""Frida Stalker Integration for Dynamic Code Tracing and Coverage Analysis.

This module provides comprehensive Stalker-based tracing capabilities for analyzing
software licensing protections, including instruction-level tracing, API monitoring,
code coverage collection, and licensing validation flow analysis.

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
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import json
import os
import time
import types
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    import frida.core


frida: types.ModuleType | None
try:
    import frida
except ImportError:
    frida = None


@dataclass
class TraceEvent:
    """Represents a single trace event from Stalker."""

    event_type: str
    address: str
    module: str | None = None
    offset: str | None = None
    timestamp: int | None = None
    thread_id: int | None = None
    depth: int | None = None
    backtrace: list[str] = field(default_factory=list)


@dataclass
class APICallEvent:
    """Represents an API call intercepted during tracing."""

    api_name: str
    module: str
    timestamp: int
    thread_id: int
    backtrace: list[str] = field(default_factory=list)
    is_licensing_related: bool = False


@dataclass
class CoverageEntry:
    """Represents a code coverage entry."""

    module: str
    offset: str
    address: str
    hit_count: int
    is_licensing: bool = False


@dataclass
class StalkerStats:
    """Statistics collected during Stalker tracing."""

    total_instructions: int = 0
    unique_blocks: int = 0
    coverage_entries: int = 0
    licensing_routines: int = 0
    api_calls: int = 0
    trace_duration: float = 0.0


class StalkerSession:
    """Manages a Frida Stalker tracing session.

    Provides comprehensive dynamic analysis capabilities including instruction
    tracing, API monitoring, code coverage analysis, and licensing flow tracking.
    """

    def __init__(
        self,
        binary_path: str,
        output_dir: str | None = None,
        message_callback: Callable[[str], None] | None = None,
    ) -> None:
        """Initialize Stalker session.

        Args:
            binary_path: Path to target binary
            output_dir: Directory for trace output files
            message_callback: Optional callback for status messages

        Raises:
            ImportError: If Frida is not installed.

        """
        if frida is None:
            raise ImportError("Frida is not installed. Install with: pip install frida-tools")

        self.binary_path = binary_path
        self.output_dir = output_dir or os.path.join(os.path.dirname(binary_path), "stalker_output")
        self.message_callback = message_callback or print

        os.makedirs(self.output_dir, exist_ok=True)

        self.device: Any | None = None
        self.session: Any | None = None
        self.script: Any | None = None
        self.pid: int | None = None

        self.trace_events: list[TraceEvent] = []
        self.api_calls: list[APICallEvent] = []
        self.coverage_data: dict[str, CoverageEntry] = {}
        self.licensing_routines: set[str] = set()

        self.stats = StalkerStats()
        self.start_time: float | None = None

        self._is_active = False

    def _log(self, message: str) -> None:
        """Log message via callback.

        Args:
            message: Message to log.

        Returns:
            None

        """
        self.message_callback(f"[StalkerSession] {message}")

    def _on_message(
        self,
        message: frida.core.ScriptPayloadMessage | frida.core.ScriptErrorMessage,
        data: bytes | None,
    ) -> None:
        """Handle messages from Frida script.

        Args:
            message: Message payload from Frida script containing status or error
                information.
            data: Optional binary data attached to message.

        """
        message_dict = cast("dict[str, Any]", message)
        try:
            if message_dict.get("type") == "send":
                payload = cast("dict[str, Any]", message_dict.get("payload", {}))
                msg_type = payload.get("type", "unknown")

                if msg_type == "status":
                    self._log(f"Status: {payload.get('message', '')}")

                elif msg_type == "ready":
                    self._log(f"Stalker ready: {payload.get('message', '')}")
                    capabilities = payload.get("capabilities", [])
                    self._log(f"Capabilities: {', '.join(capabilities)}")

                elif msg_type == "api_call":
                    self._handle_api_call(payload)

                elif msg_type == "licensing_event":
                    self._handle_licensing_event(payload)

                elif msg_type == "progress":
                    self._handle_progress(payload)

                elif msg_type == "trace_complete":
                    self._handle_trace_complete(payload)

                elif msg_type == "function_trace_complete":
                    self._handle_function_trace(payload)

                elif msg_type == "module_coverage_complete":
                    self._handle_module_coverage(payload)

                elif msg_type == "error":
                    self._log(f"Error: {payload.get('message', 'Unknown error')}")

            elif message_dict.get("type") == "error":
                stack = message_dict.get("stack", "No stack trace")
                self._log(f"Script Error: {stack}")

        except Exception as e:
            self._log(f"Message handler error: {e}")

    def _handle_api_call(self, payload: dict[str, Any]) -> None:
        """Process API call event.

        Args:
            payload: Event payload containing API call data.

        Returns:
            None

        """
        data = payload.get("data", {})
        api_call = APICallEvent(
            api_name=data.get("api", "unknown"),
            module=data.get("api", "").split("!")[0] if "!" in data.get("api", "") else "unknown",
            timestamp=data.get("timestamp", 0),
            thread_id=data.get("tid", 0),
            backtrace=data.get("backtrace", []),
            is_licensing_related=payload.get("licensing", False),
        )
        self.api_calls.append(api_call)

    def _handle_licensing_event(self, payload: dict[str, Any]) -> None:
        """Process licensing-related event.

        Args:
            payload: Event payload containing licensing event data.

        Returns:
            None

        """
        data = payload.get("data", {})
        caller = data.get("caller", {})
        key = f"{caller.get('module', 'unknown')}:{caller.get('offset', '0x0')}"
        self.licensing_routines.add(key)
        self._log(f"Licensing event: {data.get('api', '')} from {key}")

    def _handle_progress(self, payload: dict[str, Any]) -> None:
        """Process progress update.

        Args:
            payload: Event payload containing progress data.

        Returns:
            None

        """
        instructions = payload.get("instructions", 0)
        blocks = payload.get("blocks", 0)
        coverage = payload.get("coverage_entries", 0)
        licensing = payload.get("licensing_routines", 0)

        self.stats.total_instructions = instructions
        self.stats.unique_blocks = blocks
        self.stats.coverage_entries = coverage
        self.stats.licensing_routines = licensing

        self._log(
            f"Progress: {instructions} instructions, {blocks} blocks, {coverage} coverage entries, {licensing} licensing routines",
        )

    def _handle_trace_complete(self, payload: dict[str, Any]) -> None:
        """Process complete trace data.

        Args:
            payload: Event payload containing trace completion data.

        Returns:
            None

        """
        data = payload.get("data", {})

        self.stats.total_instructions = data.get("total_instructions", 0)
        self.stats.unique_blocks = data.get("unique_blocks", 0)
        self.stats.coverage_entries = data.get("coverage_entries", 0)
        self.stats.licensing_routines = data.get("licensing_routines", 0)
        self.stats.api_calls = data.get("api_calls", 0)

        coverage_list = data.get("coverage", [])
        for entry in coverage_list:
            key = entry.get("key", "")
            self.coverage_data[key] = CoverageEntry(
                module=entry.get("module", ""),
                offset=entry.get("offset", ""),
                address=entry.get("address", ""),
                hit_count=entry.get("hitCount", 0),
                is_licensing=entry.get("licensing", False),
            )

        licensing_funcs = data.get("licensing_functions", [])
        self.licensing_routines.update(licensing_funcs)

        self._log(f"Trace complete: {self.stats.total_instructions} instructions traced")
        self._save_trace_results(data)

    def _handle_function_trace(self, payload: dict[str, Any]) -> None:
        """Process function trace data.

        Args:
            payload: Event payload containing function trace data.

        Returns:
            None

        """
        function = payload.get("function", "unknown")
        trace_length = payload.get("trace_length", 0)
        trace_data = payload.get("trace", [])

        self._log(f"Function trace complete: {function} ({trace_length} events)")

        for event in trace_data:
            trace_event = TraceEvent(
                event_type=event.get("type", "unknown"),
                address=event.get("address", "0x0"),
                module=event.get("module"),
                offset=event.get("offset"),
                timestamp=event.get("timestamp"),
                thread_id=event.get("thread"),
                depth=event.get("depth"),
                backtrace=event.get("backtrace", []),
            )
            self.trace_events.append(trace_event)

        output_file = os.path.join(self.output_dir, f"function_trace_{function.replace('!', '_')}.json")
        self._save_json(output_file, {"function": function, "trace": trace_data})

    def _handle_module_coverage(self, payload: dict[str, Any]) -> None:
        """Process module coverage data.

        Args:
            payload: Event payload containing module coverage data.

        Returns:
            None

        """
        module = payload.get("module", "unknown")
        blocks_covered = payload.get("blocks_covered", 0)
        coverage_pct = payload.get("coverage_percentage", 0.0)

        self._log(f"Module coverage: {module} - {blocks_covered} blocks ({coverage_pct:.2f}%)")

        output_file = os.path.join(self.output_dir, f"coverage_{module}.json")
        self._save_json(output_file, payload)

    def _save_trace_results(self, data: dict[str, Any]) -> None:
        """Save complete trace results to file.

        Args:
            data: Trace results to save.

        Returns:
            None

        """
        output_file = os.path.join(self.output_dir, "trace_results.json")
        self._save_json(output_file, data)
        self._log(f"Trace results saved to {output_file}")

    def _save_json(self, filepath: str, data: object) -> None:
        """Save data to JSON file.

        Args:
            filepath: Path to output JSON file.
            data: Data to serialize and save.

        Returns:
            None

        """
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self._log(f"Failed to save JSON to {filepath}: {e}")

    def start(self) -> bool:
        """Start Stalker session and attach to process.

        Returns:
            True if successfully started, False otherwise.

        Raises:
            ImportError: If Frida is not installed.

        """
        try:
            self._log(f"Starting Stalker session for {os.path.basename(self.binary_path)}")

            script_path = Path(__file__).parent.parent.parent / "scripts" / "frida" / "stalker_tracer.js"
            if not script_path.exists():
                self._log(f"Stalker script not found: {script_path}")
                return False

            with open(script_path, encoding="utf-8") as f:
                script_source = f.read()

            self.device = frida.get_local_device()
            self.pid = self.device.spawn([self.binary_path])
            self.session = self.device.attach(self.pid)

            self._log(f"Attached to PID {self.pid}")

            self.script = self.session.create_script(script_source)
            self.script.on("message", self._on_message)
            self.script.load()

            self.device.resume(self.pid)

            self.start_time = time.time()
            self._is_active = True

            self._log("Stalker session started successfully")
            return True

        except Exception as e:
            self._log(f"Failed to start Stalker session: {e}")
            self.cleanup()
            return False

    def trace_function(self, module_name: str, function_name: str) -> bool:
        """Trace execution of a specific function.

        Args:
            module_name: Name of module containing function.
            function_name: Name of function to trace.

        Returns:
            True if trace started successfully, False otherwise.

        """
        if not self._is_active or not self.script:
            self._log("Session not active")
            return False

        try:
            self._log(f"Starting function trace: {module_name}!{function_name}")
            self.script.exports_sync.trace_function(module_name, function_name)
            return True
        except Exception as e:
            self._log(f"Failed to trace function: {e}")
            return False

    def collect_module_coverage(self, module_name: str) -> bool:
        """Collect code coverage for specific module.

        Args:
            module_name: Name of module to analyze.

        Returns:
            True if coverage collection started, False otherwise.

        """
        if not self._is_active or not self.script:
            self._log("Session not active")
            return False

        try:
            self._log(f"Collecting coverage for module: {module_name}")
            self.script.exports_sync.collect_module_coverage(module_name)
            return True
        except Exception as e:
            self._log(f"Failed to collect module coverage: {e}")
            return False

    def start_stalking(self) -> bool:
        """Start Stalker tracing on current thread.

        Returns:
            True if stalking started successfully, False otherwise.

        """
        if not self._is_active or not self.script:
            self._log("Session not active")
            return False

        try:
            self._log("Starting Stalker tracing")
            self.script.exports_sync.start_stalking()
            return True
        except Exception as e:
            self._log(f"Failed to start stalking: {e}")
            return False

    def stop_stalking(self) -> bool:
        """Stop Stalker tracing and collect results.

        Returns:
            True if stalking stopped successfully, False otherwise.

        """
        if not self._is_active or not self.script:
            self._log("Session not active")
            return False

        try:
            self._log("Stopping Stalker tracing")
            self.script.exports_sync.stop_stalking()

            if self.start_time:
                self.stats.trace_duration = time.time() - self.start_time

            return True
        except Exception as e:
            self._log(f"Failed to stop stalking: {e}")
            return False

    def get_stats(self) -> StalkerStats:
        """Get current tracing statistics.

        Returns:
            Current tracing statistics object containing instruction count, block
                count, coverage entries, licensing routine count, and API call count.

        """
        if self._is_active and self.script:
            try:
                remote_stats = self.script.exports_sync.get_stats()
                self.stats.total_instructions = remote_stats.get("totalInstructions", 0)
                self.stats.unique_blocks = remote_stats.get("uniqueBlocks", 0)
                self.stats.coverage_entries = remote_stats.get("coverageEntries", 0)
                self.stats.licensing_routines = remote_stats.get("licensingRoutines", 0)
                self.stats.api_calls = remote_stats.get("apiCalls", 0)
            except Exception as e:
                self._log(f"Failed to get remote stats: {e}")

        return self.stats

    def set_config(self, config: dict[str, Any]) -> bool:
        """Update Stalker configuration.

        Args:
            config: Configuration dictionary with Stalker settings.

        Returns:
            True if configuration updated successfully, False otherwise.

        """
        if not self._is_active or not self.script:
            self._log("Session not active")
            return False

        try:
            self.script.exports_sync.set_config(config)
            return True
        except Exception as e:
            self._log(f"Failed to set config: {e}")
            return False

    def get_licensing_routines(self) -> list[str]:
        """Get list of identified licensing-related routines.

        Returns:
            List of licensing routine identifiers extracted from traced execution.

        """
        return list(self.licensing_routines)

    def get_coverage_summary(self) -> dict[str, Any]:
        """Get summary of code coverage data.

        Returns:
            Dictionary containing total coverage entries, licensing entries count,
                top hotspot blocks, and licensing-specific hotspots with hit counts.

        """
        if not self.coverage_data:
            return {"total_entries": 0, "top_hotspots": []}

        sorted_coverage = sorted(
            self.coverage_data.values(),
            key=lambda x: x.hit_count,
            reverse=True,
        )

        licensing_coverage = [c for c in sorted_coverage if c.is_licensing]

        return {
            "total_entries": len(self.coverage_data),
            "licensing_entries": len(licensing_coverage),
            "top_hotspots": [
                {
                    "module": c.module,
                    "offset": c.offset,
                    "hit_count": c.hit_count,
                    "is_licensing": c.is_licensing,
                }
                for c in sorted_coverage[:20]
            ],
            "licensing_hotspots": [
                {
                    "module": c.module,
                    "offset": c.offset,
                    "hit_count": c.hit_count,
                }
                for c in licensing_coverage[:10]
            ],
        }

    def get_api_summary(self) -> dict[str, Any]:
        """Get summary of API calls.

        Returns:
            Dictionary containing total API calls, unique API count, licensing
                related calls, and top API list with call counts.

        """
        if not self.api_calls:
            return {"total_calls": 0, "unique_apis": 0, "top_apis": []}

        api_counts: dict[str, int] = {}
        licensing_calls = 0

        for call in self.api_calls:
            api_counts[call.api_name] = api_counts.get(call.api_name, 0) + 1
            if call.is_licensing_related:
                licensing_calls += 1

        sorted_apis = sorted(api_counts.items(), key=lambda x: x[1], reverse=True)

        return {
            "total_calls": len(self.api_calls),
            "unique_apis": len(api_counts),
            "licensing_calls": licensing_calls,
            "top_apis": [{"api": api, "count": count} for api, count in sorted_apis[:20]],
        }

    def export_results(self, output_path: str | None = None) -> str:
        """Export all collected results to JSON file.

        Args:
            output_path: Optional custom output path for results. If not provided,
                a timestamped file will be created in the output directory.

        Returns:
            Absolute path to the exported JSON file containing all tracing results.

        """
        if output_path is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(
                self.output_dir,
                f"stalker_results_{timestamp}.json",
            )

        results = {
            "binary": os.path.basename(self.binary_path),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "stats": {
                "total_instructions": self.stats.total_instructions,
                "unique_blocks": self.stats.unique_blocks,
                "coverage_entries": self.stats.coverage_entries,
                "licensing_routines": self.stats.licensing_routines,
                "api_calls": self.stats.api_calls,
                "trace_duration": self.stats.trace_duration,
            },
            "coverage_summary": self.get_coverage_summary(),
            "api_summary": self.get_api_summary(),
            "licensing_routines": list(self.licensing_routines),
        }

        self._save_json(output_path, results)
        self._log(f"Results exported to {output_path}")
        return output_path

    def cleanup(self) -> None:
        """Clean up session resources.

        Detaches from the Frida session and sets the session to inactive state.

        Returns:
            None

        """
        if self.session and not self.session.is_detached:
            try:
                self.session.detach()
            except Exception as e:
                self._log(f"Error detaching session: {e}")

        self._is_active = False
        self._log("Session cleaned up")

    def __enter__(self) -> "StalkerSession":
        """Context manager entry.

        Returns:
            The session instance for use within context manager block.

        """
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Context manager exit.

        Args:
            exc_type: Exception type if an exception occurred in the context.
            exc_val: Exception value if an exception occurred in the context.
            exc_tb: Exception traceback if an exception occurred in the context.

        Returns:
            None

        """
        if self._is_active:
            self.stop_stalking()
        self.cleanup()
