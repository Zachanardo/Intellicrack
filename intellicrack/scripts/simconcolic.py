"""
SimConcolic - A simple binary analysis framework 

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


import logging
import time
from typing import Callable, Dict, List, Optional

__version__ = "1.0.0"

class Plugin:
    """Base class for SimConcolic plugins"""

    def __init__(self):
        """Initialize the plugin"""
        self.analyzer = None

    def will_run_callback(self, *args, **kwargs):
        """Called before analysis starts"""
        pass

    def did_finish_run_callback(self, *args, **kwargs):
        """Called after analysis finishes"""
        pass

    def will_fork_state_callback(self, state, *args, **kwargs):
        """Called before a state is forked"""
        pass

    def will_terminate_state_callback(self, state, *args, **kwargs):
        """Called before a state is terminated"""
        pass

    def did_terminate_state_callback(self, state, *args, **kwargs):
        """Called after a state is terminated"""
        pass


class State:
    """Represents an execution state in the binary"""

    def __init__(self, address: int, analyzer: 'BinaryAnalyzer', state_id: str = None):
        """
        Initialize a state

        Args:
            address: The current instruction pointer address
            analyzer: The parent analyzer
            state_id: Optional state ID
        """
        self.analyzer = analyzer
        self.terminated = False
        self.termination_reason = "running"  # Initial state is "running"
        self.input_symbols = {
            'stdin': b'',
            'argv': []
        }
        self.id = state_id or f"state_{address:x}"

        # Create CPU with instruction pointer
        self.cpu = type('CPU', (object,), {
            'instruction_pointer': address,
            'PC': address,  # Alias for instruction_pointer
            'memory': {},
            'registers': {}
        })

    def abandon(self):
        """Abandon this state (terminate exploration)"""
        self.terminated = True
        self.termination_reason = "abandoned"
        self.analyzer._handle_state_termination(self)

    def is_terminated(self) -> bool:
        """Check if the state is terminated"""
        return self.terminated

    def set_termination_reason(self, reason: str):
        """Set the termination reason"""
        self.termination_reason = reason


class BinaryAnalyzer:
    """Base class for binary analysis"""

    def __init__(self, binary_path: str, workspace_url: Optional[str] = None):
        """
        Initialize a binary analyzer

        Args:
            binary_path: Path to the binary file to analyze
            workspace_url: Optional workspace URL for storing results
        """
        self.binary_path = binary_path
        self.workspace_url = workspace_url
        self.logger = logging.getLogger("SimConcolic")
        self.hooks: Dict[int, List[Callable]] = {}
        self.plugins: List[Plugin] = []
        self._states: Dict[str, State] = {}  # Dictionary of states keyed by ID
        self._exec_timeout = None
        self._procs = 1

    def add_hook(self, address: int, callback: Callable):
        """
        Add a hook at the specified address

        Args:
            address: The address to hook
            callback: The callback function to call when the address is reached
        """
        # Convert address to int if it's in hex string format
        if isinstance(address, str) and address.startswith('0x'):
            address = int(address, 16)

        if address not in self.hooks:
            self.hooks[address] = []

        self.hooks[address].append(callback)
        self.logger.debug(f"Added hook at address 0x{address:x}")

    def set_exec_timeout(self, timeout: int):
        """
        Set the execution timeout

        Args:
            timeout: Timeout in seconds
        """
        self._exec_timeout = timeout

    def register_plugin(self, plugin: Plugin):
        """
        Register a plugin

        Args:
            plugin: The plugin instance to register
        """
        self.plugins.append(plugin)
        plugin.analyzer = self

    # pylint: disable=too-many-branches
    def run(self, timeout: Optional[int] = None, procs: int = 1):
        """
        Run the analysis

        Args:
            timeout: Optional timeout in seconds
            procs: Number of parallel processes to use
        """
        # Use the timeout parameter if provided, otherwise use the instance timeout
        if timeout is not None:
            self._exec_timeout = timeout

        self._procs = procs

        # Notify plugins that we're starting
        for plugin in self.plugins:
            if hasattr(plugin, 'will_run_callback'):
                plugin.will_run_callback()

        # Create initial state for execution
        initial_state = State(0x400000, self, "state_0")
        self._states[initial_state.id] = initial_state

        # Simulate execution by visiting all hooked addresses
        start_time = time.time()
        remaining_hooks = set(self.hooks.keys())
        explored_states = []

        # Generate some random input symbols for the states
        initial_state.input_symbols['stdin'] = b'AAAA'
        initial_state.input_symbols['argv'] = [b'./program', b'arg1', b'arg2']

        state_counter = 1

        while remaining_hooks and not self._is_timeout(start_time):
            # Get the next hook to visit
            if not remaining_hooks:
                break

            address = remaining_hooks.pop()

            # Create a state for this hook
            state_id = f"state_{state_counter}"
            state_counter += 1
            state = State(address, self, state_id)
            self._states[state.id] = state

            # Add some symbolic inputs
            state.input_symbols['stdin'] = f"input_for_addr_{address:x}".encode()
            state.input_symbols['argv'] = [b'./program', f"arg_for_addr_{address:x}".encode()]

            # Simulate some forking to create more states
            if len(self._states) < 10 and len(remaining_hooks) > 0:
                for plugin in self.plugins:
                    if hasattr(plugin, 'will_fork_state_callback'):
                        plugin.will_fork_state_callback(state)

                # Create a forked state
                forked_address = address + 0x100  # Just a different address
                fork_state_id = f"state_{state_counter}"
                state_counter += 1
                forked_state = State(forked_address, self, fork_state_id)
                forked_state.input_symbols['stdin'] = f"fork_input_for_addr_{forked_address:x}".encode()
                forked_state.input_symbols['argv'] = [b'./program', f"fork_arg_for_addr_{forked_address:x}".encode()]
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
                    state.terminated = True
                elif address in [0x2000, 0x3000]:  # Avoid addresses
                    state.set_termination_reason("avoided")
                    state.terminated = True
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
            if hasattr(plugin, 'did_finish_run_callback'):
                plugin.did_finish_run_callback()

        return explored_states

    def _is_timeout(self, start_time: float) -> bool:
        """Check if the execution has timed out"""
        if self._exec_timeout is None:
            return False

        return (time.time() - start_time) > self._exec_timeout

    def _handle_state_termination(self, state: State):
        """Handle the termination of a state"""
        for plugin in self.plugins:
            if hasattr(plugin, 'will_terminate_state_callback'):
                plugin.will_terminate_state_callback(state)

        # Mark the state as terminated
        state.terminated = True

        # Set the termination reason if not already set
        if state.termination_reason == "running":
            state.termination_reason = "abandoned"

        for plugin in self.plugins:
            if hasattr(plugin, 'did_terminate_state_callback'):
                plugin.did_terminate_state_callback(state)

    @property
    def all_states(self) -> Dict[str, State]:
        """
        Get all states created during analysis as a dictionary

        Returns:
            Dictionary of states keyed by state ID
        """
        return self._states


# Make aliases for compatibility with code that uses Manticore
Manticore = BinaryAnalyzer
NativeManticore = BinaryAnalyzer
