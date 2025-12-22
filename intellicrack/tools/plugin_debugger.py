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
    """Types of breakpoints."""

    LINE = "line"
    FUNCTION = "function"
    CONDITIONAL = "conditional"
    EXCEPTION = "exception"


@dataclass
class Breakpoint:
    """Represents a breakpoint."""

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
    """Represents a stack frame."""

    filename: str
    lineno: int
    function: str
    locals: dict[str, Any]
    globals: dict[str, Any]
    code: str


class DebuggerState(Enum):
    """Debugger states."""

    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STEPPING = "stepping"
    TERMINATED = "terminated"


TraceFunction = Callable[[types.FrameType, str, Any], "TraceFunction | None"] | None


class PluginDebugger:
    """Advanced debugger for Intellicrack plugins."""

    def __init__(self) -> None:
        """Initialize plugin debugger with state tracking, breakpoints, and trace monitoring."""
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
        """Load a plugin for debugging."""
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
        """Add a breakpoint."""
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
        """Remove a breakpoint."""
        if bp_id in self.breakpoints:
            del self.breakpoints[bp_id]

    def enable_breakpoint(self, bp_id: int) -> None:
        """Enable a breakpoint."""
        if bp_id in self.breakpoints:
            self.breakpoints[bp_id].enabled = True

    def disable_breakpoint(self, bp_id: int) -> None:
        """Disable a breakpoint."""
        if bp_id in self.breakpoints:
            self.breakpoints[bp_id].enabled = False

    def set_exception_breakpoint(self, enabled: bool) -> None:
        """Enable/disable break on exceptions."""
        self.exception_breakpoint = enabled

    def run(self, binary_path: str | None = None, options: dict[str, Any] | None = None) -> None:
        """Run the plugin with debugging."""
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
        """Run trace dispatch function."""
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
        """Handle line event."""
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
        """Handle call event."""
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
        """Handle return event."""
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
        """Handle exception event."""
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
        """Pause execution at breakpoint."""
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
        """Pause execution and wait for commands."""
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
        """Handle debugger command."""
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
        """Update stack frames."""
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
        """Update watched variables."""
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
        """Evaluate expression in current context."""
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
        """Set variable value in current context."""
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
        """Add watch expression."""
        self.watched_variables[expression] = None
        self._update_watched_variables()

    def _remove_watch(self, expression: str) -> None:
        """Remove watch expression."""
        if expression in self.watched_variables:
            del self.watched_variables[expression]
            self._update_watched_variables()

    def _handle_exception(
        self, exception: Exception, frame: types.FrameType | None = None
    ) -> None:
        """Handle exception breakpoint."""
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
        """Serialize value for transmission."""
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
        """Get source code lines."""
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
        """Get variables for a specific frame."""
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
    """Thread for running debugger."""

    def __init__(
        self,
        debugger: PluginDebugger,
        plugin_path: str,
        binary_path: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        """Initialize debugger thread with plugin path, binary path, and execution options."""
        super().__init__()
        self.debugger = debugger
        self.plugin_path = plugin_path
        self.binary_path = binary_path
        self.options = options

    def run(self) -> None:
        """Run the debugger."""
        self.debugger.load_plugin(self.plugin_path)
        self.debugger.run(self.binary_path, self.options)
