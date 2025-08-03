"""Plugin debugger for testing and debugging Intellicrack plugins."""
from intellicrack.logger import logger

"""
Advanced Plugin Debugger with Breakpoint Support for Intellicrack.

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

import ast
import linecache
import os
import queue
import sys
import threading
import traceback
import types
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class BreakpointType(Enum):
    """Types of breakpoints"""
    LINE = "line"
    FUNCTION = "function"
    CONDITIONAL = "conditional"
    EXCEPTION = "exception"


@dataclass
class Breakpoint:
    """Represents a breakpoint"""
    id: int
    type: BreakpointType
    file: str
    line: Optional[int] = None
    function: Optional[str] = None
    condition: Optional[str] = None
    enabled: bool = True
    hit_count: int = 0
    ignore_count: int = 0


@dataclass
class StackFrame:
    """Represents a stack frame"""
    filename: str
    lineno: int
    function: str
    locals: Dict[str, Any]
    globals: Dict[str, Any]
    code: str


class DebuggerState(Enum):
    """Debugger states"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STEPPING = "stepping"
    TERMINATED = "terminated"


class PluginDebugger:
    """Advanced debugger for Intellicrack plugins"""

    def __init__(self):
        """Initialize plugin debugger with state tracking, breakpoints, and trace monitoring."""
        self.logger = logger  # Use the imported logger from line 1
        self.breakpoints: Dict[int, Breakpoint] = {}
        self.next_breakpoint_id = 1
        self.state = DebuggerState.IDLE
        self.current_frame = None
        self.stack_frames = []
        self.step_mode = None
        self.command_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.watched_variables = {}
        self.call_stack = []
        self.exception_breakpoint = False
        self.plugin_module = None

        # Enhanced trace data tracking
        self.call_history = []
        self.return_history = []
        self.exception_history = []
        self.verbose = False
        self.trace_calls = False
        self.trace_returns = False
        self.watched_returns = []
        self.exception_filters = []

    def load_plugin(self, plugin_path: str):
        """Load a plugin for debugging"""
        # Read plugin code
        with open(plugin_path, "r") as f:
            code = f.read()

        # Compile with debugging info
        tree = ast.parse(code, plugin_path, "exec")
        compiled = compile(tree, plugin_path, "exec")

        # Create module
        module_name = os.path.basename(plugin_path).replace(".py", "")
        self.plugin_module = types.ModuleType(module_name)
        self.plugin_module.__file__ = plugin_path

        # Store for later execution
        self._plugin_code = compiled
        self._plugin_path = plugin_path

    def add_breakpoint(self, file: str, line: int = None, function: str = None,
                      condition: str = None, type: BreakpointType = BreakpointType.LINE) -> int:
        """Add a breakpoint"""
        bp = Breakpoint(
            id=self.next_breakpoint_id,
            type=type,
            file=file,
            line=line,
            function=function,
            condition=condition
        )

        self.breakpoints[bp.id] = bp
        self.next_breakpoint_id += 1

        return bp.id

    def remove_breakpoint(self, bp_id: int):
        """Remove a breakpoint"""
        if bp_id in self.breakpoints:
            del self.breakpoints[bp_id]

    def enable_breakpoint(self, bp_id: int):
        """Enable a breakpoint"""
        if bp_id in self.breakpoints:
            self.breakpoints[bp_id].enabled = True

    def disable_breakpoint(self, bp_id: int):
        """Disable a breakpoint"""
        if bp_id in self.breakpoints:
            self.breakpoints[bp_id].enabled = False

    def set_exception_breakpoint(self, enabled: bool):
        """Enable/disable break on exceptions"""
        self.exception_breakpoint = enabled

    def run(self, binary_path: str = None, options: Dict[str, Any] = None):
        """Run the plugin with debugging"""
        self.state = DebuggerState.RUNNING

        # Set up trace function
        sys.settrace(self._trace_dispatch)

        try:
            # Prepare globals
            globals_dict = {
                "__name__": "__main__",
                "__file__": self._plugin_path,
                "binary_path": binary_path,
                "options": options or {}
            }

            # Execute plugin
            exec(self._plugin_code, globals_dict, globals_dict)

            # Call run function if exists
            if "run" in globals_dict:
                result = globals_dict["run"](binary_path, options)
                self.output_queue.put(("result", result))

        except Exception as e:
            logger.error("Exception in plugin_debugger: %s", e)
            if self.exception_breakpoint:
                self._handle_exception(e)
            else:
                self.output_queue.put(("exception", e))
        finally:
            sys.settrace(None)
            self.state = DebuggerState.TERMINATED

    def _trace_dispatch(self, frame, event, arg):
        """Main trace dispatch function"""
        if self.state == DebuggerState.TERMINATED:
            return None

        # Check for commands
        try:
            command = self.command_queue.get_nowait()
            self._handle_command(command)
        except queue.Empty:
            logger.debug("No commands in queue")

        # Handle different events
        if event == "line":
            return self._trace_line(frame, arg)
        elif event == "call":
            return self._trace_call(frame, arg)
        elif event == "return":
            return self._trace_return(frame, arg)
        elif event == "exception":
            return self._trace_exception(frame, arg)

        return self._trace_dispatch

    def _trace_line(self, frame, arg):
        """Handle line event"""
        filename = frame.f_code.co_filename
        lineno = frame.f_lineno

        # Use arg to enhance trace information
        if arg is not None:
            # Log trace data if verbose mode
            if hasattr(self, "verbose") and self.verbose:
                self.output_queue.put(("trace", {
                    "event": "line",
                    "filename": filename,
                    "lineno": lineno,
                    "arg": str(arg)
                }))

        # Check breakpoints
        for bp in self.breakpoints.values():
            if not bp.enabled:
                continue

            if bp.type == BreakpointType.LINE:
                if bp.file == filename and bp.line == lineno:
                    if bp.ignore_count > 0:
                        bp.ignore_count -= 1
                    else:
                        bp.hit_count += 1
                        self._pause_at_breakpoint(frame, bp)
                        break

            elif bp.type == BreakpointType.CONDITIONAL:
                if bp.file == filename and bp.line == lineno:
                    try:
                        # Evaluate condition in frame context
                        if eval(bp.condition, frame.f_globals, frame.f_locals):
                            bp.hit_count += 1
                            self._pause_at_breakpoint(frame, bp)
                            break
                    except Exception as e:
                        logger.debug("Failed to evaluate breakpoint condition: %s", e)

        # Handle stepping
        if self.state == DebuggerState.STEPPING:
            if self.step_mode == "over":
                # Step over - pause at next line in same frame
                if len(self.call_stack) <= 1:
                    self._pause_execution(frame)
            elif self.step_mode == "into":
                # Step into - pause at any line
                self._pause_execution(frame)
            elif self.step_mode == "out":
                # Step out - handled in return event
                pass

        return self._trace_dispatch

    def _trace_call(self, frame, arg):
        """Handle call event"""
        self.call_stack.append(frame)

        # Use arg to track function call information
        if arg is not None:
            # Store call information for analysis
            call_info = {
                "function": frame.f_code.co_name,
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "args": arg if isinstance(arg, (list, tuple, dict)) else str(arg),
                "timestamp": getattr(self, "_get_timestamp", lambda: 0)()
            }
            if hasattr(self, "call_history"):
                self.call_history.append(call_info)

            # Emit call event if in trace mode
            if hasattr(self, "trace_calls") and self.trace_calls:
                self.output_queue.put(("call_trace", call_info))

        # Check function breakpoints
        func_name = frame.f_code.co_name
        filename = frame.f_code.co_filename

        for bp in self.breakpoints.values():
            if not bp.enabled:
                continue

            if bp.type == BreakpointType.FUNCTION:
                if bp.function == func_name and bp.file == filename:
                    bp.hit_count += 1
                    self._pause_at_breakpoint(frame, bp)
                    break

        return self._trace_dispatch

    def _trace_return(self, frame, arg):
        """Handle return event"""
        if self.call_stack and self.call_stack[-1] == frame:
            self.call_stack.pop()

        # Use arg to capture return values
        if arg is not None:
            return_info = {
                "function": frame.f_code.co_name,
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "return_value": repr(arg) if not isinstance(arg, (bytes, bytearray)) else f"<{type(arg).__name__}: {len(arg)} bytes>",
                "type": type(arg).__name__
            }

            # Track return values for analysis
            if hasattr(self, "return_history"):
                self.return_history.append(return_info)

            # Emit return event if tracing returns
            if hasattr(self, "trace_returns") and self.trace_returns:
                self.output_queue.put(("return_trace", return_info))

            # Check for watched return values
            if hasattr(self, "watched_returns"):
                for pattern in self.watched_returns:
                    if pattern in str(arg) or pattern == frame.f_code.co_name:
                        self.output_queue.put(("watched_return", {
                            "pattern": pattern,
                            "value": return_info
                        }))

        # Handle step out
        if self.state == DebuggerState.STEPPING and self.step_mode == "out":
            if len(self.call_stack) == 0:
                self._pause_execution(frame)

        return self._trace_dispatch

    def _trace_exception(self, frame, arg):
        """Handle exception event"""
        # Use arg to get detailed exception information
        if arg is not None:
            exc_type, exc_value, exc_tb = arg

            # Create comprehensive exception info
            exception_info = {
                "type": exc_type.__name__ if exc_type else "Unknown",
                "value": str(exc_value),
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "function": frame.f_code.co_name,
                "traceback": traceback.format_tb(exc_tb) if exc_tb else []
            }

            # Track exception history
            if hasattr(self, "exception_history"):
                self.exception_history.append(exception_info)

            # Check exception filters
            if hasattr(self, "exception_filters"):
                for filter_type in self.exception_filters:
                    if isinstance(exc_value, filter_type):
                        self.output_queue.put(("filtered_exception", exception_info))
                        break

            # Handle exception breakpoint
            if self.exception_breakpoint:
                self._handle_exception(exc_value, frame)
                # Also provide the full exception info
                self.output_queue.put(("exception_detail", exception_info))

        return self._trace_dispatch

    def _pause_at_breakpoint(self, frame, breakpoint: Breakpoint):
        """Pause execution at breakpoint"""
        self.output_queue.put(("breakpoint", {
            "id": breakpoint.id,
            "type": breakpoint.type.value,
            "file": breakpoint.file,
            "line": breakpoint.line,
            "function": breakpoint.function,
            "hit_count": breakpoint.hit_count
        }))

        self._pause_execution(frame)

    def _pause_execution(self, frame):
        """Pause execution and wait for commands"""
        self.state = DebuggerState.PAUSED
        self.current_frame = frame
        self._update_stack_frames()
        self._update_watched_variables()

        # Send pause notification
        self.output_queue.put(("paused", {
            "file": frame.f_code.co_filename,
            "line": frame.f_lineno,
            "function": frame.f_code.co_name
        }))

        # Wait for continue command
        while self.state == DebuggerState.PAUSED:
            try:
                command = self.command_queue.get(timeout=0.1)
                self._handle_command(command)
            except queue.Empty:
                logger.debug("No commands in queue during pause")
                continue

    def _handle_command(self, command: Dict[str, Any]):
        """Handle debugger command"""
        cmd_type = command.get("type")

        if cmd_type == "continue":
            self.state = DebuggerState.RUNNING
            self.step_mode = None

        elif cmd_type == "step_over":
            self.state = DebuggerState.STEPPING
            self.step_mode = "over"

        elif cmd_type == "step_into":
            self.state = DebuggerState.STEPPING
            self.step_mode = "into"

        elif cmd_type == "step_out":
            self.state = DebuggerState.STEPPING
            self.step_mode = "out"

        elif cmd_type == "pause":
            self.state = DebuggerState.PAUSED

        elif cmd_type == "terminate":
            self.state = DebuggerState.TERMINATED

        elif cmd_type == "evaluate":
            expression = command.get("expression")
            self._evaluate_expression(expression)

        elif cmd_type == "set_variable":
            name = command.get("name")
            value = command.get("value")
            self._set_variable(name, value)

        elif cmd_type == "watch":
            expression = command.get("expression")
            self._add_watch(expression)

        elif cmd_type == "unwatch":
            expression = command.get("expression")
            self._remove_watch(expression)

    def _update_stack_frames(self):
        """Update stack frames"""
        self.stack_frames = []

        frame = self.current_frame
        while frame:
            # Get source code
            filename = frame.f_code.co_filename
            lineno = frame.f_lineno

            if os.path.exists(filename):
                line = linecache.getline(filename, lineno).strip()
            else:
                line = "<source not available>"

            stack_frame = StackFrame(
                filename=filename,
                lineno=lineno,
                function=frame.f_code.co_name,
                locals=dict(frame.f_locals),
                globals=dict(frame.f_globals),
                code=line
            )

            self.stack_frames.append(stack_frame)
            frame = frame.f_back

        # Send stack frames
        self.output_queue.put(("stack", [
            {
                "filename": sf.filename,
                "lineno": sf.lineno,
                "function": sf.function,
                "code": sf.code
            }
            for sf in self.stack_frames
        ]))

    def _update_watched_variables(self):
        """Update watched variables"""
        if not self.current_frame:
            return

        watched_values = {}

        for expr in self.watched_variables:
            try:
                value = eval(expr, self.current_frame.f_globals, self.current_frame.f_locals)
                watched_values[expr] = self._serialize_value(value)
            except Exception as e:
                self.logger.error("Exception in plugin_debugger: %s", e)
                watched_values[expr] = f"<error: {str(e)}>"

        self.output_queue.put(("watches", watched_values))

    def _evaluate_expression(self, expression: str):
        """Evaluate expression in current context"""
        if not self.current_frame:
            self.output_queue.put(("eval_result", {
                "expression": expression,
                "error": "No active frame"
            }))
            return

        try:
            result = eval(expression, self.current_frame.f_globals, self.current_frame.f_locals)
            self.output_queue.put(("eval_result", {
                "expression": expression,
                "value": self._serialize_value(result)
            }))
        except Exception as e:
            self.logger.error("Exception in plugin_debugger: %s", e)
            self.output_queue.put(("eval_result", {
                "expression": expression,
                "error": str(e)
            }))

    def _set_variable(self, name: str, value: str):
        """Set variable value in current context"""
        if not self.current_frame:
            return

        try:
            # Parse value
            parsed_value = eval(value)

            # Set in locals first, then globals
            if name in self.current_frame.f_locals:
                self.current_frame.f_locals[name] = parsed_value
            else:
                self.current_frame.f_globals[name] = parsed_value

            self.output_queue.put(("variable_set", {
                "name": name,
                "value": self._serialize_value(parsed_value)
            }))

            # Update watches
            self._update_watched_variables()

        except Exception as e:
            logger.error("Exception in plugin_debugger: %s", e)
            self.output_queue.put(("error", f"Failed to set variable: {str(e)}"))

    def _add_watch(self, expression: str):
        """Add watch expression"""
        self.watched_variables[expression] = None
        self._update_watched_variables()

    def _remove_watch(self, expression: str):
        """Remove watch expression"""
        if expression in self.watched_variables:
            del self.watched_variables[expression]
            self._update_watched_variables()

    def _handle_exception(self, exception: Exception, frame=None):
        """Handle exception breakpoint"""
        tb = traceback.format_exc()

        self.output_queue.put(("exception_break", {
            "type": type(exception).__name__,
            "message": str(exception),
            "traceback": tb
        }))

        if frame:
            self._pause_execution(frame)

    def _serialize_value(self, value: Any) -> Any:
        """Serialize value for transmission"""
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        elif isinstance(value, (list, tuple)):
            return [self._serialize_value(v) for v in value[:100]]  # Limit size
        elif isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in list(value.items())[:100]}
        else:
            return repr(value)

    def get_source_code(self, filename: str, start_line: int = 1, end_line: int = None) -> List[str]:
        """Get source code lines"""
        lines = []

        if os.path.exists(filename):
            with open(filename, "r") as f:
                all_lines = f.readlines()

            if end_line is None:
                end_line = len(all_lines)

            for i in range(max(0, start_line - 1), min(len(all_lines), end_line)):
                lines.append({
                    "line": i + 1,
                    "code": all_lines[i].rstrip(),
                    "breakpoint": any(
                        bp.file == filename and bp.line == i + 1 and bp.enabled
                        for bp in self.breakpoints.values()
                    )
                })

        return lines

    def get_variables(self, frame_index: int = 0) -> Dict[str, Any]:
        """Get variables for a specific frame"""
        if frame_index >= len(self.stack_frames):
            return {}

        frame = self.stack_frames[frame_index]

        # Combine locals and globals, preferring locals
        variables = {}

        # Add globals first
        for name, value in frame.globals.items():
            if not name.startswith("__"):
                variables[name] = {
                    "value": self._serialize_value(value),
                    "type": type(value).__name__,
                    "scope": "global"
                }

        # Override with locals
        for name, value in frame.locals.items():
            variables[name] = {
                "value": self._serialize_value(value),
                "type": type(value).__name__,
                "scope": "local"
            }

        return variables


class DebuggerThread(threading.Thread):
    """Thread for running debugger"""

    def __init__(self, debugger: PluginDebugger, plugin_path: str,
                 binary_path: str = None, options: Dict[str, Any] = None):
        """Initialize debugger thread with plugin path, binary path, and execution options."""
        super().__init__()
        self.debugger = debugger
        self.plugin_path = plugin_path
        self.binary_path = binary_path
        self.options = options

    def run(self):
        """Run the debugger"""
        self.debugger.load_plugin(self.plugin_path)
        self.debugger.run(self.binary_path, self.options)
