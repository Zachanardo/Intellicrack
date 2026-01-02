"""Plugin debugger for testing and debugging Intellicrack plugins.

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
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

from __future__ import annotations

import linecache
import logging
import os
import queue
import sys
import threading
import traceback
import types
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


class BreakpointType(Enum):
    """Enumeration of breakpoint types for the plugin debugger.

    Attributes:
        LINE: Line-based breakpoints that trigger on specific line numbers.
        FUNCTION: Function-based breakpoints that trigger on function entry.
        CONDITIONAL: Conditional breakpoints that trigger when an expression evaluates to true.
        EXCEPTION: Exception breakpoints that trigger when exceptions are raised.
    """

    LINE = "line"
    FUNCTION = "function"
    CONDITIONAL = "conditional"
    EXCEPTION = "exception"


@dataclass
class Breakpoint:
    """Represents a debugger breakpoint configuration.

    This dataclass stores all metadata and state associated with a single breakpoint,
    including its type, location, conditional expression, and hit tracking.

    Attributes:
        id: Unique identifier for the breakpoint.
        type: The type of breakpoint (line, function, conditional, or exception).
        file: Path to the file where the breakpoint is set.
        line: Line number for line-based breakpoints.
        function: Function name for function-based breakpoints.
        condition: Python expression that must evaluate to true for conditional breakpoints.
        enabled: Whether the breakpoint is currently active.
        hit_count: Number of times this breakpoint has been hit.
        ignore_count: Number of times to ignore hits before breaking.
    """

    id: int
    type: BreakpointType
    file: str
    line: int | None = None
    function: str | None = None
    condition: str | None = None
    enabled: bool = True
    hit_count: int = 0
    ignore_count: int = 0


@dataclass
class StackFrame:
    """Represents a single frame in the call stack during debugging.

    This dataclass captures the state of a single frame in the execution stack,
    including local and global variables, source code, and location information.

    Attributes:
        filename: Path to the source file of the frame.
        lineno: Line number where the frame is currently executing.
        function: Name of the function executing in this frame.
        locals: Dictionary of local variables in this frame.
        globals: Dictionary of global variables accessible to this frame.
        code: Source code line being executed in this frame.
    """

    filename: str
    lineno: int
    function: str
    locals: dict[str, Any]
    globals: dict[str, Any]
    code: str


class DebuggerState(Enum):
    """Enumeration of debugger execution states.

    Attributes:
        IDLE: Initial state before any debugging begins.
        RUNNING: Debugger is executing code without pausing.
        PAUSED: Debugger has paused execution at a breakpoint or command.
        STEPPING: Debugger is in single-step mode (step into, over, or out).
        TERMINATED: Debugging session has ended.
    """

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STEPPING = "stepping"
    TERMINATED = "terminated"


TraceFunction = Callable[[types.FrameType, str, Any], "TraceFunction | None"] | None


class PluginDebugger:
    """Advanced debugger for analyzing and debugging Intellicrack plugins.

    Provides comprehensive debugging capabilities including breakpoints (line, function, conditional, exception),
    single-stepping, watch expressions, variable inspection, and call history tracking. Integrates with
    sys.settrace for real-time execution monitoring.
    """

    def __init__(self) -> None:
        """Initialize the plugin debugger with state tracking, breakpoints, and trace monitoring.

        Sets up initial debugger state (IDLE), empty breakpoint registry, command and output queues,
        history tracking for calls/returns/exceptions, and configuration for watch expressions and
        exception filtering.
        """
        self._logger = logging.getLogger(__name__)
        self.breakpoints: dict[int, Breakpoint] = {}
        self.next_breakpoint_id: int = 1
        self.state: DebuggerState = DebuggerState.IDLE
        self.current_frame: types.FrameType | None = None
        self.stack_frames: list[StackFrame] = []
        self.step_mode: str | None = None
        self.command_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.output_queue: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.watched_variables: dict[str, Any] = {}
        self.call_stack: list[types.FrameType] = []
        self.exception_breakpoint: bool = False
        self.plugin_module: types.ModuleType | None = None

        self.call_history: list[dict[str, Any]] = []
        self.return_history: list[dict[str, Any]] = []
        self.exception_history: list[dict[str, Any]] = []
        self.verbose: bool = False
        self.trace_calls: bool = False
        self.trace_returns: bool = False
        self.watched_returns: list[str] = []
        self.exception_filters: list[type[BaseException]] = []

        self._plugin_code: types.CodeType | None = None
        self._plugin_path: str = ""

    def load_plugin(self, plugin_path: str) -> None:
        """Load and compile a plugin file for debugging.

        Reads the plugin source code, parses it into an AST, compiles it to bytecode,
        and creates a module object to hold the plugin's namespace during execution.

        Args:
            plugin_path: Absolute path to the plugin Python file to load.
        """
        import ast

        with open(plugin_path, encoding="utf-8") as f:
            code = f.read()

        tree = ast.parse(code, plugin_path, "exec")
        compiled = compile(tree, plugin_path, "exec")

        module_name = os.path.basename(plugin_path).replace(".py", "")
        self.plugin_module = types.ModuleType(module_name)
        self.plugin_module.__file__ = plugin_path

        self._plugin_code = compiled
        self._plugin_path = plugin_path

    def add_breakpoint(
        self,
        file: str,
        line: int | None = None,
        function: str | None = None,
        condition: str | None = None,
        type: BreakpointType = BreakpointType.LINE,
    ) -> int:
        """Create and register a new breakpoint with the debugger.

        Creates a breakpoint object with the specified parameters and adds it to the
        breakpoint registry with a unique identifier. The breakpoint is enabled by default.

        Args:
            file: Path to the file where the breakpoint applies.
            line: Line number for line-based breakpoints.
            function: Function name for function-based breakpoints.
            condition: Python expression for conditional breakpoints.
            type: Type of breakpoint (LINE, FUNCTION, CONDITIONAL, or EXCEPTION).

        Returns:
            int: Unique identifier assigned to the breakpoint.
        """
        bp = Breakpoint(
            id=self.next_breakpoint_id,
            type=type,
            file=file,
            line=line,
            function=function,
            condition=condition,
        )

        self.breakpoints[bp.id] = bp
        self.next_breakpoint_id += 1

        return bp.id

    def remove_breakpoint(self, bp_id: int) -> None:
        """Remove a breakpoint from the debugger by its identifier.

        Args:
            bp_id: Unique identifier of the breakpoint to remove.
        """
        if bp_id in self.breakpoints:
            del self.breakpoints[bp_id]

    def enable_breakpoint(self, bp_id: int) -> None:
        """Enable a previously disabled breakpoint by its identifier.

        Args:
            bp_id: Unique identifier of the breakpoint to enable.
        """
        if bp_id in self.breakpoints:
            self.breakpoints[bp_id].enabled = True

    def disable_breakpoint(self, bp_id: int) -> None:
        """Disable an enabled breakpoint without removing it.

        Args:
            bp_id: Unique identifier of the breakpoint to disable.
        """
        if bp_id in self.breakpoints:
            self.breakpoints[bp_id].enabled = False

    def set_exception_breakpoint(self, enabled: bool) -> None:
        """Enable or disable breaking on all unhandled exceptions.

        Args:
            enabled: True to break on exceptions, False to ignore them.
        """
        self.exception_breakpoint = enabled

    def run(self, binary_path: str | None = None, options: dict[str, Any] | None = None) -> None:
        """Execute the loaded plugin with full debugging support enabled.

        Installs the trace function via sys.settrace, executes the plugin bytecode in a
        controlled namespace, and manages exception handling. Output is sent to the output
        queue for retrieval by the debugger client.

        Args:
            binary_path: Optional path to a binary file for the plugin to analyze.
            options: Optional dictionary of configuration options for the plugin.
        """
        self.state = DebuggerState.RUNNING

        sys.settrace(self._trace_dispatch)

        try:
            globals_dict: dict[str, Any] = {
                "__name__": "__main__",
                "__file__": self._plugin_path,
                "binary_path": binary_path,
                "options": options or {},
            }

            if self._plugin_code is not None:
                exec(self._plugin_code, globals_dict, globals_dict)

            if "run" in globals_dict:
                result = globals_dict["run"](binary_path, options)
                self.output_queue.put(("result", result))

        except Exception as e:
            self._logger.error("Exception in plugin_debugger: %s", e)
            if self.exception_breakpoint:
                self._handle_exception(e)
            else:
                self.output_queue.put(("exception", e))
        finally:
            sys.settrace(None)
            self.state = DebuggerState.TERMINATED

    def _trace_dispatch(
        self, frame: types.FrameType, event: str, arg: Any
    ) -> TraceFunction:
        """Route trace events to appropriate handlers based on event type.

        Dispatches events from sys.settrace to specific handlers for lines, function calls,
        returns, and exceptions. Processes pending debugger commands from the command queue
        between trace events.

        Args:
            frame: The stack frame where the event occurred.
            event: Event type: "line", "call", "return", "exception", etc.
            arg: Event-specific argument (varies by event type).

        Returns:
            TraceFunction: The trace function to use for subsequent events.
        """
        if self.state == DebuggerState.TERMINATED:
            return None

        try:
            command = self.command_queue.get_nowait()
            self._handle_command(command)
        except queue.Empty:
            pass

        if event == "line":
            return self._trace_line(frame, arg)
        elif event == "call":
            return self._trace_call(frame, arg)
        elif event == "return":
            return self._trace_return(frame, arg)
        elif event == "exception":
            return self._trace_exception(frame, arg)

        return self._trace_dispatch

    def _trace_line(self, frame: types.FrameType, arg: Any) -> TraceFunction:
        """Handle line execution events and check breakpoints.

        Checks for line and conditional breakpoints at the current location. Handles
        single-stepping in "step into" mode. Outputs trace information if verbose mode
        is enabled.

        Args:
            frame: The stack frame executing the line.
            arg: Event argument (unused for line events but included for trace signature).

        Returns:
            TraceFunction: The trace function to use for subsequent events.
        """
        filename = frame.f_code.co_filename
        lineno = frame.f_lineno

        if arg is not None and self.verbose:
            self.output_queue.put(
                (
                    "trace",
                    {"event": "line", "filename": filename, "lineno": lineno, "arg": str(arg)},
                )
            )

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
                if bp.file == filename and bp.line == lineno and bp.condition is not None:
                    try:
                        if eval(bp.condition, frame.f_globals, frame.f_locals):
                            bp.hit_count += 1
                            self._pause_at_breakpoint(frame, bp)
                            break
                    except Exception as e:
                        self._logger.debug("Failed to evaluate breakpoint condition: %s", e)

        if self.state == DebuggerState.STEPPING and (
            (self.step_mode == "over" and len(self.call_stack) <= 1)
            or (self.step_mode != "over" and self.step_mode == "into")
        ):
            self._pause_execution(frame)

        return self._trace_dispatch

    def _trace_call(self, frame: types.FrameType, arg: Any) -> TraceFunction:
        """Handle function call events and check function breakpoints.

        Records function call information in call history, checks for function-based
        breakpoints at the entry point, and outputs trace information if call tracing
        is enabled.

        Args:
            frame: The stack frame of the called function.
            arg: Event argument (typically the function object or arguments).

        Returns:
            TraceFunction: The trace function to use for subsequent events.
        """
        self.call_stack.append(frame)

        if arg is not None:
            call_info: dict[str, Any] = {
                "function": frame.f_code.co_name,
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "args": arg if isinstance(arg, (list, tuple, dict)) else str(arg),
                "timestamp": 0,
            }
            self.call_history.append(call_info)

            if self.trace_calls:
                self.output_queue.put(("call_trace", call_info))

        func_name = frame.f_code.co_name
        filename = frame.f_code.co_filename

        for bp in self.breakpoints.values():
            if not bp.enabled:
                continue

            if bp.function == func_name and bp.file == filename and bp.type == BreakpointType.FUNCTION:
                bp.hit_count += 1
                self._pause_at_breakpoint(frame, bp)
                break

        return self._trace_dispatch

    def _trace_return(self, frame: types.FrameType, arg: Any) -> TraceFunction:
        """Handle function return events and track return values.

        Records return values and types in return history, checks for watched return
        patterns, removes the frame from the call stack, and handles "step out"
        single-stepping.

        Args:
            frame: The stack frame of the returning function.
            arg: The return value from the function.

        Returns:
            TraceFunction: The trace function to use for subsequent events.
        """
        if self.call_stack and self.call_stack[-1] == frame:
            self.call_stack.pop()

        if arg is not None:
            return_value_str: str
            if isinstance(arg, (bytes, bytearray)):
                return_value_str = f"<{type(arg).__name__}: {len(arg)} bytes>"
            else:
                return_value_str = repr(arg)

            return_info: dict[str, Any] = {
                "function": frame.f_code.co_name,
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "return_value": return_value_str,
                "type": type(arg).__name__,
            }

            self.return_history.append(return_info)

            if self.trace_returns:
                self.output_queue.put(("return_trace", return_info))

            for pattern in self.watched_returns:
                if pattern in str(arg) or pattern == frame.f_code.co_name:
                    self.output_queue.put(("watched_return", {"pattern": pattern, "value": return_info}))

        if self.state == DebuggerState.STEPPING and self.step_mode == "out" and len(self.call_stack) == 0:
            self._pause_execution(frame)

        return self._trace_dispatch

    def _trace_exception(self, frame: types.FrameType, arg: Any) -> TraceFunction:
        """Handle exception events and filter by type.

        Records exception information in exception history, applies exception filters,
        and triggers exception breakpoint handling if enabled.

        Args:
            frame: The stack frame where the exception occurred.
            arg: Tuple of (exception_type, exception_value, traceback).

        Returns:
            TraceFunction: The trace function to use for subsequent events.
        """
        if arg is not None:
            exc_type, exc_value, exc_tb = arg

            exception_info: dict[str, Any] = {
                "type": exc_type.__name__ if exc_type else "Unknown",
                "value": str(exc_value),
                "file": frame.f_code.co_filename,
                "line": frame.f_lineno,
                "function": frame.f_code.co_name,
                "traceback": traceback.format_tb(exc_tb) if exc_tb else [],
            }

            self.exception_history.append(exception_info)

            for filter_type in self.exception_filters:
                if isinstance(exc_value, filter_type):
                    self.output_queue.put(("filtered_exception", exception_info))
                    break

            if self.exception_breakpoint:
                self._handle_exception(exc_value, frame)
                self.output_queue.put(("exception_detail", exception_info))

        return self._trace_dispatch

    def _pause_at_breakpoint(self, frame: types.FrameType, breakpoint: Breakpoint) -> None:
        """Notify about a breakpoint hit and pause execution.

        Queues breakpoint information and delegates to _pause_execution to wait for
        debugger commands.

        Args:
            frame: The stack frame where the breakpoint was hit.
            breakpoint: The breakpoint object that was triggered.
        """
        self.output_queue.put(
            (
                "breakpoint",
                {
                    "id": breakpoint.id,
                    "type": breakpoint.type.value,
                    "file": breakpoint.file,
                    "line": breakpoint.line,
                    "function": breakpoint.function,
                    "hit_count": breakpoint.hit_count,
                },
            )
        )

        self._pause_execution(frame)

    def _pause_execution(self, frame: types.FrameType) -> None:
        """Pause execution and block until debugger commands resume execution.

        Updates the debugger state to PAUSED, captures the current stack frames and
        watched variables, and blocks in a loop waiting for commands from the command
        queue. Processes commands until the state changes to RUNNING, STEPPING, or
        TERMINATED.

        Args:
            frame: The current stack frame where execution is paused.
        """
        self.state = DebuggerState.PAUSED
        self.current_frame = frame
        self._update_stack_frames()
        self._update_watched_variables()

        self.output_queue.put(
            (
                "paused",
                {
                    "file": frame.f_code.co_filename,
                    "line": frame.f_lineno,
                    "function": frame.f_code.co_name,
                },
            )
        )

        while self.state == DebuggerState.PAUSED:
            try:
                command = self.command_queue.get(timeout=0.1)
                self._handle_command(command)
            except queue.Empty:
                continue

    def _handle_command(self, command: dict[str, Any]) -> None:
        """Process a debugger command and update debugger state accordingly.

        Interprets commands such as continue, step_into, step_over, step_out, pause,
        terminate, evaluate, set_variable, watch, and unwatch. Updates the debugger
        state and delegates to appropriate handlers for complex commands.

        Args:
            command: Dictionary with "type" key specifying the command, plus additional
                keys for command-specific arguments.
        """
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
            if isinstance(expression, str):
                self._evaluate_expression(expression)

        elif cmd_type == "set_variable":
            name = command.get("name")
            value = command.get("value")
            if isinstance(name, str) and isinstance(value, str):
                self._set_variable(name, value)

        elif cmd_type == "watch":
            expression = command.get("expression")
            if isinstance(expression, str):
                self._add_watch(expression)

        elif cmd_type == "unwatch":
            expression = command.get("expression")
            if isinstance(expression, str):
                self._remove_watch(expression)

    def _update_stack_frames(self) -> None:
        """Capture and update the current call stack frames.

        Walks the frame chain from the current frame, extracting location information,
        source code lines, and frame metadata. Queues the updated stack information
        for transmission to the debugger client.
        """
        self.stack_frames = []

        frame: types.FrameType | None = self.current_frame
        while frame is not None:
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
                code=line,
            )

            self.stack_frames.append(stack_frame)
            frame = frame.f_back

        self.output_queue.put(
            (
                "stack",
                [
                    {
                        "filename": sf.filename,
                        "lineno": sf.lineno,
                        "function": sf.function,
                        "code": sf.code,
                    }
                    for sf in self.stack_frames
                ],
            )
        )

    def _update_watched_variables(self) -> None:
        """Evaluate and update values of all watched expressions.

        Evaluates each watched expression in the context of the current frame,
        serializes the results, and queues the updated watch values for transmission
        to the debugger client.
        """
        if not self.current_frame:
            return

        watched_values: dict[str, Any] = {}

        for expr in self.watched_variables:
            try:
                value = eval(expr, self.current_frame.f_globals, self.current_frame.f_locals)
                watched_values[expr] = self._serialize_value(value)
            except Exception as e:
                self._logger.error("Exception in plugin_debugger: %s", e)
                watched_values[expr] = f"<error: {e!s}>"

        self.output_queue.put(("watches", watched_values))

    def _evaluate_expression(self, expression: str) -> None:
        """Evaluate a Python expression in the context of the current frame.

        Evaluates the expression string in the local and global scope of the current
        execution frame and queues the result for transmission to the client.

        Args:
            expression: Python expression string to evaluate.
        """
        if not self.current_frame:
            self.output_queue.put(("eval_result", {"expression": expression, "error": "No active frame"}))
            return

        try:
            result = eval(expression, self.current_frame.f_globals, self.current_frame.f_locals)
            self.output_queue.put(("eval_result", {"expression": expression, "value": self._serialize_value(result)}))
        except Exception as e:
            self._logger.error("Exception in plugin_debugger: %s", e)
            self.output_queue.put(("eval_result", {"expression": expression, "error": str(e)}))

    def _set_variable(self, name: str, value: str) -> None:
        """Set a variable's value in the current execution frame.

        Parses the value string as Python code, evaluates it, and assigns it to the
        named variable in either the local or global scope of the current frame.

        Args:
            name: Name of the variable to set.
            value: Python expression string representing the new value.
        """
        if not self.current_frame:
            return

        try:
            parsed_value = eval(value)

            if name in self.current_frame.f_locals:
                self.current_frame.f_locals[name] = parsed_value
            else:
                self.current_frame.f_globals[name] = parsed_value

            self.output_queue.put(("variable_set", {"name": name, "value": self._serialize_value(parsed_value)}))

            self._update_watched_variables()

        except Exception as e:
            self._logger.error("Exception in plugin_debugger: %s", e)
            self.output_queue.put(("error", f"Failed to set variable: {e!s}"))

    def _add_watch(self, expression: str) -> None:
        """Add a watch expression for continuous monitoring.

        Registers a Python expression to be evaluated and displayed whenever execution
        pauses. Updates the watched variables immediately.

        Args:
            expression: Python expression string to watch.
        """
        self.watched_variables[expression] = None
        self._update_watched_variables()

    def _remove_watch(self, expression: str) -> None:
        """Remove a watch expression from monitoring.

        Unregisters a previously added watch expression and updates the watched
        variables display.

        Args:
            expression: Python expression string to stop watching.
        """
        if expression in self.watched_variables:
            del self.watched_variables[expression]
            self._update_watched_variables()

    def _handle_exception(
        self, exception: Exception, frame: types.FrameType | None = None
    ) -> None:
        """Handle an exception by pausing and queuing exception details.

        Formats a traceback of the exception and optionally pauses execution at the
        specified frame to allow inspection of the exception context.

        Args:
            exception: The exception instance to handle.
            frame: Optional stack frame where exception occurred. If provided, execution
                is paused at this frame.
        """
        tb = traceback.format_exc()

        self.output_queue.put(
            (
                "exception_break",
                {"type": type(exception).__name__, "message": str(exception), "traceback": tb},
            )
        )

        if frame:
            self._pause_execution(frame)

    def _serialize_value(self, value: Any) -> Any:
        """Serialize a Python value for transmission to the debugger client.

        Converts values to JSON-serializable forms: primitives are returned unchanged,
        collections are recursively serialized (limited to first 100 items), and other
        objects are converted to their string representation.

        Args:
            value: The Python value to serialize.

        Returns:
            Serialized form of the value suitable for transmission.
        """
        if isinstance(value, (str, int, float, bool, type(None))):
            return value
        elif isinstance(value, (list, tuple)):
            return [self._serialize_value(v) for v in value[:100]]
        elif isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in list(value.items())[:100]}
        else:
            return repr(value)

    def get_source_code(
        self, filename: str, start_line: int = 1, end_line: int | None = None
    ) -> list[dict[str, Any]]:
        """Retrieve source code lines with breakpoint information.

        Reads source code lines from a file within the specified range and annotates
        each line with its number and whether an enabled breakpoint is set on that line.

        Args:
            filename: Path to the source file.
            start_line: Starting line number (1-indexed, default 1).
            end_line: Ending line number (1-indexed), defaults to end of file.

        Returns:
            list[dict[str, Any]]: List of dictionaries with keys "line" (number),
                "code" (source text), and "breakpoint" (bool).
        """
        lines: list[dict[str, Any]] = []

        if os.path.exists(filename):
            with open(filename, encoding="utf-8") as f:
                all_lines = f.readlines()

            if end_line is None:
                end_line = len(all_lines)

            lines.extend(
                {
                    "line": i + 1,
                    "code": all_lines[i].rstrip(),
                    "breakpoint": any(
                        bp.file == filename and bp.line == i + 1 and bp.enabled
                        for bp in self.breakpoints.values()
                    ),
                }
                for i in range(
                    max(0, start_line - 1), min(len(all_lines), end_line)
                )
            )
        return lines

    def get_variables(self, frame_index: int = 0) -> dict[str, Any]:
        """Retrieve all variables (local and global) from a specific stack frame.

        Returns a dictionary containing all variables from the specified frame's local
        and global scopes. Each variable entry includes its serialized value, type name,
        and scope designation.

        Args:
            frame_index: Index into the stack_frames list (0 = most recent frame).

        Returns:
            dict[str, Any]: Dictionary mapping variable names to metadata dicts with
                keys "value" (serialized), "type" (type name), and "scope" ("local" or "global").
        """
        if frame_index >= len(self.stack_frames):
            return {}

        frame = self.stack_frames[frame_index]

        variables: dict[str, Any] = {
            name: {
                "value": self._serialize_value(value),
                "type": type(value).__name__,
                "scope": "global",
            }
            for name, value in frame.globals.items()
            if not name.startswith("__")
        }

        for name, value in frame.locals.items():
            variables[name] = {
                "value": self._serialize_value(value),
                "type": type(value).__name__,
                "scope": "local",
            }

        return variables


class DebuggerThread(threading.Thread):
    """Thread for executing plugin debugging in a separate execution context.

    Extends threading.Thread to run the PluginDebugger in a separate thread, allowing
    asynchronous execution of plugins while the main thread monitors and controls
    execution via queues.
    """

    def __init__(
        self,
        debugger: PluginDebugger,
        plugin_path: str,
        binary_path: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        """Initialize the debugger thread with plugin and execution parameters.

        Args:
            debugger: The PluginDebugger instance to execute.
            plugin_path: Path to the plugin Python file to debug.
            binary_path: Optional path to a binary file for the plugin to analyze.
            options: Optional dictionary of configuration options for the plugin.
        """
        super().__init__()
        self.debugger = debugger
        self.plugin_path = plugin_path
        self.binary_path = binary_path
        self.options = options

    def run(self) -> None:
        """Load the plugin and execute it with full debugging support.

        Loads the plugin from the file path and begins execution with the configured
        binary path and options. This method is called when the thread is started via
        the start() method inherited from threading.Thread.
        """
        self.debugger.load_plugin(self.plugin_path)
        self.debugger.run(self.binary_path, self.options)
