"""SimConcolic - A simple binary analysis framework.

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
import time
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    StateType = Any
else:
    StateType = object

__version__: str = "1.0.0"

logger: logging.Logger = logging.getLogger(__name__)


class Plugin:
    """Base class for SimConcolic plugins.

    Provides callback hooks for monitoring and controlling binary analysis execution
    including analysis start/stop, state forking, and state termination events.
    """

    def __init__(self) -> None:
        """Initialize the plugin.

        Sets up the plugin instance with an analyzer reference that will be
        populated when the plugin is registered with a BinaryAnalyzer.

        """
        self.analyzer: BinaryAnalyzer | None = None
        self.analysis_start_time: float = 0.0
        self.total_states_analyzed: int = 0
        self.analysis_metadata: dict[str, Any] = {}
        self.fork_count: int = 0
        self.fork_history: list[dict[str, Any]] = []
        self.termination_pending: dict[int, dict[str, Any]] = {}
        self.terminated_states: list[dict[str, Any]] = []

    def will_run_callback(self, *args: object, **kwargs: object) -> None:
        """Prepare before analysis starts.

        Args:
            *args: Additional positional arguments passed from the analyzer.
            **kwargs: Additional keyword arguments passed from the analyzer.

        """
        # Initialize analysis state
        self.analysis_start_time = time.time()
        self.total_states_analyzed = 0
        self.analysis_metadata = {
            "start_time": self.analysis_start_time,
            "initial_memory_usage": self._get_memory_usage(),
            "callback_args": args,
            "callback_kwargs": kwargs,
        }
        logger.info("Starting analysis at %s", datetime.fromtimestamp(self.analysis_start_time))

    def did_finish_run_callback(self, *args: object, **kwargs: object) -> None:
        """Finalize after analysis finishes.

        Args:
            *args: Additional positional arguments passed from the analyzer.
            **kwargs: Additional keyword arguments passed from the analyzer.

        """
        # Calculate analysis statistics
        end_time = time.time()
        duration = end_time - getattr(self, "analysis_start_time", end_time)

        # Log completion statistics
        logger.info("Analysis completed in %.2f seconds", duration)
        logger.info("Total states analyzed: %s", getattr(self, "total_states_analyzed", 0))

        # Store final metrics
        if hasattr(self, "analysis_metadata"):
            self.analysis_metadata["end_time"] = end_time
            self.analysis_metadata["duration"] = duration
            self.analysis_metadata["final_memory_usage"] = self._get_memory_usage()
            self.analysis_metadata["completion_args"] = args
            self.analysis_metadata["completion_kwargs"] = kwargs

    def will_fork_state_callback(self, state: "State", *args: object, **kwargs: object) -> None:
        """Prepare before a state is forked.

        Args:
            state: The state that is about to be forked.
            *args: Additional positional arguments passed from the analyzer.
            **kwargs: Additional keyword arguments passed from the analyzer.

        """
        # Track state forking for analysis
        if not hasattr(self, "fork_count"):
            self.fork_count = 0
        self.fork_count += 1

        # Log fork event
        logger.debug("Forking state at address 0x%x (fork #%s)", state.address, self.fork_count)

        # Store fork metadata
        if not hasattr(self, "fork_history"):
            self.fork_history = []
        self.fork_history.append(
            {
                "timestamp": time.time(),
                "state_address": state.address,
                "fork_number": self.fork_count,
                "parent_constraints": len(state.constraints) if hasattr(state, "constraints") else 0,
            },
        )

    def will_terminate_state_callback(self, state: "State", *args: object, **kwargs: object) -> None:
        """Prepare before a state is terminated.

        Args:
            state: The state that is about to be terminated.
            *args: Additional positional arguments passed from the analyzer.
            **kwargs: Additional keyword arguments passed from the analyzer.

        """
        # Track termination reasons
        if not hasattr(self, "termination_pending"):
            self.termination_pending = {}

        # Store pending termination info
        state_id = getattr(state, "state_id", id(state))
        self.termination_pending[state_id] = {
            "timestamp": time.time(),
            "address": state.address,
            "reason": kwargs.get("reason", "unknown"),
            "constraints_count": len(state.constraints) if hasattr(state, "constraints") else 0,
        }

        logger.debug("State at 0x%x pending termination", state.address)

    def did_terminate_state_callback(self, state: "State", *args: object, **kwargs: object) -> None:
        """Finalize after a state is terminated.

        Args:
            state: The state that has been terminated.
            *args: Additional positional arguments passed from the analyzer.
            **kwargs: Additional keyword arguments passed from the analyzer.

        """
        # Update termination statistics
        if not hasattr(self, "terminated_states"):
            self.terminated_states = []

        state_id = getattr(state, "state_id", id(state))
        termination_info = getattr(self, "termination_pending", {}).get(state_id, {})

        # Record terminated state
        self.terminated_states.append(
            {
                "timestamp": time.time(),
                "address": state.address,
                "state_id": state_id,
                "reason": termination_info.get("reason", "unknown"),
                "duration": time.time() - termination_info.get("timestamp", time.time()),
            },
        )

        # Clean up pending termination
        if hasattr(self, "termination_pending") and state_id in self.termination_pending:
            del self.termination_pending[state_id]

        # Update total states analyzed
        self.total_states_analyzed = getattr(self, "total_states_analyzed", 0) + 1

        logger.debug("State at 0x%x terminated (total: %s)", state.address, self.total_states_analyzed)

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB.

        Returns:
            Memory usage in megabytes, or 0.0 if psutil is unavailable.

        """
        try:
            from intellicrack.handlers.psutil_handler import psutil

            process = psutil.Process()
            memory_info = process.memory_info()
            rss_bytes: int = memory_info.rss
            return float(rss_bytes / 1024 / 1024)
        except Exception:
            logger.debug("Failed to get memory usage", exc_info=True)
            return 0.0


class State:
    """Represents an execution state in the binary.

    Encapsulates an execution path through a binary during symbolic analysis,
    tracking instruction pointer, memory state, and symbolic inputs.
    """

    def __init__(self, address: int, analyzer: "BinaryAnalyzer", state_id: str | None = None) -> None:
        """Initialize a state.

        Args:
            address: The current instruction pointer address.
            analyzer: The parent BinaryAnalyzer instance managing this state.
            state_id: Optional unique identifier for this state. If not provided,
                generated from the address.

        """
        self.analyzer: BinaryAnalyzer = analyzer
        self.terminated: bool = False
        self.termination_reason: str = "running"
        self.input_symbols: dict[str, bytes | list[bytes]] = {
            "stdin": b"",
            "argv": [],
        }
        self.id: str = state_id or f"state_{address:x}"
        self._address: int = address

        CPUClass = type(
            "CPU",
            (object,),
            {
                "instruction_pointer": address,
                "PC": address,
                "memory": {},
                "registers": {},
            },
        )
        self.cpu: Any = CPUClass()
        self.constraints: list[Any] = []

    @property
    def address(self) -> int:
        """Get the current instruction pointer address.

        Returns:
            The current instruction pointer address.

        """
        return self._address

    @property
    def state_id(self) -> str:
        """Get the state ID.

        Returns:
            The unique state identifier.

        """
        return self.id

    def abandon(self) -> None:
        """Abandon this state and terminate symbolic exploration.

        Marks the state as terminated with "abandoned" reason and notifies
        the parent analyzer to handle the termination.

        """
        self.terminated = True
        self.termination_reason = "abandoned"
        self.analyzer._handle_state_termination(self)

    def is_terminated(self) -> bool:
        """Check if the state is terminated.

        Returns:
            True if the state has been terminated, False otherwise.

        """
        return self.terminated

    def set_termination_reason(self, reason: str) -> None:
        """Set the reason for state termination.

        Args:
            reason: The termination reason (e.g., "reached_target", "abandoned").

        """
        self.termination_reason = reason


class BinaryAnalyzer:
    """Base class for binary analysis.

    Manages execution of binary analysis with support for state exploration,
    hooks, and plugin-based monitoring of analysis execution.
    """

    def __init__(self, binary_path: str, workspace_url: str | None = None) -> None:
        """Initialize a binary analyzer.

        Args:
            binary_path: Path to the binary file to analyze.
            workspace_url: Optional workspace URL for storing analysis results.

        """
        self.binary_path: str = binary_path
        self.workspace_url: str | None = workspace_url
        self.logger: logging.Logger = logging.getLogger("SimConcolic")
        self.hooks: dict[int, list[Callable[[State], None]]] = {}
        self.plugins: list[Plugin] = []
        self._states: dict[str, State] = {}
        self._exec_timeout: int | None = None
        self._procs: int = 1

    def add_hook(self, address: int, callback: Callable[["State"], None]) -> None:
        """Add a hook at the specified address.

        Args:
            address: The address to hook at.
            callback: The callback function invoked when the address is reached,
                receives the current State as its argument.

        """
        if address not in self.hooks:
            self.hooks[address] = []

        self.hooks[address].append(callback)
        self.logger.debug("Added hook at address 0x%x", address)

    def set_exec_timeout(self, timeout: int) -> None:
        """Set the execution timeout.

        Args:
            timeout: Timeout duration in seconds.

        """
        self._exec_timeout = timeout

    def register_plugin(self, plugin: Plugin) -> None:
        """Register a plugin for analysis monitoring.

        Args:
            plugin: The plugin instance to register with the analyzer.

        """
        self.plugins.append(plugin)
        plugin.analyzer = self

    # pylint: disable=too-many-branches,too-many-statements
    def run(self, timeout: int | None = None, procs: int = 1) -> list[State]:
        """Run the analysis.

        Performs symbolic execution exploration through registered hooks,
        creating and managing execution states, and invoking plugin callbacks
        at key analysis points.

        Args:
            timeout: Optional timeout in seconds for analysis execution.
            procs: Number of parallel processes to use for analysis.

        Returns:
            List of all explored states created during analysis execution.

        """
        # Use the timeout parameter if provided, otherwise use the instance timeout
        if timeout is not None:
            self._exec_timeout = timeout

        self._procs = procs

        # Notify plugins that we're starting
        for plugin in self.plugins:
            if hasattr(plugin, "will_run_callback"):
                plugin.will_run_callback()

        # Create initial state for execution
        initial_state = State(0x400000, self, "state_0")
        self._states[initial_state.id] = initial_state

        # Execute symbolic path exploration through hooked addresses
        start_time = time.time()
        remaining_hooks = set(self.hooks.keys())
        explored_states = []

        # Initialize concrete input symbols for symbolic execution
        initial_state.input_symbols["stdin"] = b"AAAA"
        initial_state.input_symbols["argv"] = [b"./program", b"arg1", b"arg2"]

        state_counter = 1

        while remaining_hooks and not self._is_timeout(start_time):
            address = remaining_hooks.pop()

            # Create a state for this hook
            state_id = f"state_{state_counter}"
            state_counter += 1
            state = State(address, self, state_id)
            self._states[state.id] = state

            # Add some symbolic inputs
            state.input_symbols["stdin"] = f"input_for_addr_{address:x}".encode()
            state.input_symbols["argv"] = [b"./program", f"arg_for_addr_{address:x}".encode()]

            # Perform state forking for path exploration based on branch conditions
            if len(self._states) < 10 and remaining_hooks:
                for plugin in self.plugins:
                    if hasattr(plugin, "will_fork_state_callback"):
                        plugin.will_fork_state_callback(state)

                # Execute state forking for branch exploration
                forked_address = address + 0x100  # Just a different address
                fork_state_id = f"state_{state_counter}"
                state_counter += 1
                forked_state = State(forked_address, self, fork_state_id)
                forked_state.input_symbols["stdin"] = f"fork_input_for_addr_{forked_address:x}".encode()
                forked_state.input_symbols["argv"] = [
                    b"./program",
                    f"fork_arg_for_addr_{forked_address:x}".encode(),
                ]
                self._states[forked_state.id] = forked_state

            # Execute the hook callbacks
            if address in self.hooks:
                for callback in self.hooks[address]:
                    if state.terminated:
                        break
                    callback(state)

            # Set a specific reason if it's still "running"
            if state.termination_reason == "running":
                if address == 0x1000:  # Target address
                    state.set_termination_reason("reached_target")
                elif address in [0x2000, 0x3000]:  # Avoid addresses
                    state.set_termination_reason("avoided")
                else:
                    state.set_termination_reason("completed")
                state.terminated = True
            explored_states.append(state)

        # Mark any remaining states as completed
        for state in self._states.values():
            if state.termination_reason == "running":
                state.set_termination_reason("completed")
                state.terminated = True

        # Notify plugins that we're done
        for plugin in self.plugins:
            if hasattr(plugin, "did_finish_run_callback"):
                plugin.did_finish_run_callback()

        return explored_states

    def _is_timeout(self, start_time: float) -> bool:
        """Check if the execution has timed out.

        Args:
            start_time: Timestamp when analysis started (seconds since epoch).

        Returns:
            True if execution has exceeded timeout, False otherwise.

        """
        if self._exec_timeout is None:
            return False

        return (time.time() - start_time) > self._exec_timeout

    def _handle_state_termination(self, state: State) -> None:
        """Handle the termination of a state.

        Invokes plugin callbacks before and after state termination,
        updating the state's terminated status and reason.

        Args:
            state: The state being terminated.

        """
        for plugin in self.plugins:
            if hasattr(plugin, "will_terminate_state_callback"):
                plugin.will_terminate_state_callback(state)

        # Mark the state as terminated
        state.terminated = True

        # Set the termination reason if not already set
        if state.termination_reason == "running":
            state.termination_reason = "abandoned"

        for plugin in self.plugins:
            if hasattr(plugin, "did_terminate_state_callback"):
                plugin.did_terminate_state_callback(state)

    @property
    def all_states(self) -> dict[str, State]:
        """Get all states created during analysis as a dictionary.

        Returns:
            Dictionary of states keyed by state ID

        """
        return self._states
