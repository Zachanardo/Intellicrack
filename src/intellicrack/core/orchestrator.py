"""Main AI agent orchestrator for Intellicrack.

This module provides the central orchestration layer that coordinates
between the user, LLM providers, and tool bridges to execute
reverse engineering workflows.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

from .logging import get_logger
from .types import (
    BinaryInfo,
    ConfirmationLevel,
    Message,
    PatchInfo,
    ProviderName,
    ToolCall,
    ToolDefinition,
    ToolName,
    ToolResult,
)


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from ..providers.base import LLMProvider
    from ..providers.registry import ProviderRegistry
    from .session import Session, SessionManager
    from .tools import ToolRegistry


_logger = get_logger("core.orchestrator")

OrchestratorState = Literal["idle", "processing", "waiting_confirmation", "cancelled"]


@dataclass
class OrchestratorConfig:
    """Configuration for the orchestrator.

    Attributes:
        confirmation_level: When to ask for user confirmation.
        max_iterations: Maximum tool call iterations per request.
        timeout_seconds: Timeout for LLM requests.
        temperature: LLM temperature setting.
        max_tokens: Maximum tokens in LLM response.
        stream_responses: Whether to stream LLM responses.
        stream_mode: Streaming mode ("auto", "always", "never").
    """

    confirmation_level: ConfirmationLevel = ConfirmationLevel.DESTRUCTIVE
    max_iterations: int = 20
    timeout_seconds: int = 120
    temperature: float = 0.7
    max_tokens: int = 4096
    stream_responses: bool = True
    stream_mode: Literal["auto", "always", "never"] = "auto"


@dataclass
class PendingConfirmation:
    """A tool call waiting for user confirmation.

    Attributes:
        call: The tool call awaiting confirmation.
        future: Future to resolve when confirmation received.
    """

    call: ToolCall
    future: asyncio.Future[bool]


@dataclass
class OrchestratorStats:
    """Statistics for orchestrator operations.

    Attributes:
        total_requests: Total user requests processed.
        total_tool_calls: Total tool calls executed.
        successful_tool_calls: Successful tool call count.
        failed_tool_calls: Failed tool call count.
        total_tokens_used: Approximate tokens used.
        average_response_time_ms: Average response time.
    """

    total_requests: int = 0
    total_tool_calls: int = 0
    successful_tool_calls: int = 0
    failed_tool_calls: int = 0
    total_tokens_used: int = 0
    average_response_time_ms: float = 0.0
    _response_times: list[float] = field(default_factory=list)

    def record_response_time(self, time_ms: float) -> None:
        """Record a response time and update average.

        Args:
            time_ms: Response time in milliseconds.
        """
        self._response_times.append(time_ms)
        self.average_response_time_ms = sum(self._response_times) / len(
            self._response_times
        )


class Orchestrator:
    """Main AI agent orchestrator.

    Manages the conversation loop between the user, LLM, and tools.
    Coordinates tool execution and handles confirmations.

    Attributes:
        _providers: Registry of LLM providers.
        _tools: Registry of tool bridges.
        _sessions: Session state manager.
        _config: Orchestrator configuration.
        _current_session: Currently active session.
        _state: Current orchestrator state.
        _stats: Operation statistics.
    """

    DESTRUCTIVE_PATTERNS: tuple[str, ...] = (
        "write",
        "patch",
        "modify",
        "delete",
        "remove",
        "set_",
        "assemble",
        "inject",
        "intercept_return",
        "hook",
        "replace",
        "overwrite",
    )

    def __init__(
        self,
        provider_registry: ProviderRegistry,
        tool_registry: ToolRegistry,
        session_manager: SessionManager,
        config: OrchestratorConfig | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            provider_registry: Registry of LLM providers.
            tool_registry: Registry of tool bridges.
            session_manager: Session state manager.
            config: Optional configuration override.
        """
        self._providers = provider_registry
        self._tools = tool_registry
        self._sessions = session_manager
        self._config = config or OrchestratorConfig()

        self._current_session: Session | None = None
        self._state: OrchestratorState = "idle"
        self._stats = OrchestratorStats()
        self._pending_confirmation: PendingConfirmation | None = None
        self._cancel_event = asyncio.Event()

        self._on_message: Callable[[Message], None] | None = None
        self._on_tool_call: Callable[[ToolCall], None] | None = None
        self._on_tool_result: Callable[[ToolResult], None] | None = None
        self._on_stream_chunk: Callable[[str], None] | None = None
        self._confirmation_callback: Callable[[ToolCall], bool] | None = None
        self._async_confirmation_callback: (
            Callable[[ToolCall], asyncio.Future[bool]] | None
        ) = None

    @property
    def state(self) -> OrchestratorState:
        """Get current orchestrator state.

        Returns:
            Current state.
        """
        return self._state

    @property
    def current_session(self) -> Session | None:
        """Get current session.

        Returns:
            Current session or None.
        """
        return self._current_session

    @property
    def stats(self) -> OrchestratorStats:
        """Get orchestrator statistics.

        Returns:
            Statistics instance.
        """
        return self._stats

    async def start_session(
        self,
        provider: str | ProviderName,
        model: str,
        binary_path: Path | None = None,
    ) -> Session:
        """Start a new session.

        Args:
            provider: LLM provider to use.
            model: Model ID to use.
            binary_path: Optional binary to load.

        Returns:
            New session instance.

        Raises:
            ValueError: If provider not available.
        """
        if isinstance(provider, str):
            provider = ProviderName(provider.lower())

        provider_instance = self._providers.get(provider)
        if provider_instance is None or not provider_instance.is_connected:
            error_message = f"Provider not available: {provider.value}"
            raise ValueError(error_message)

        session = await self._sessions.create(
            provider=provider,
            model=model,
        )

        if binary_path is not None:
            binary_info = await self._load_binary(binary_path)
            session.binaries.append(binary_info)
            session.active_binary_index = 0

        self._current_session = session
        self._state = "idle"

        _logger.info(
            "Started session %s with provider %s model %s",
            session.id,
            provider.value,
            model,
        )

        return session

    async def load_session(self, session_id: str) -> Session:
        """Load an existing session.

        Args:
            session_id: ID of session to load.

        Returns:
            Loaded session.

        Raises:
            ValueError: If session not found.
        """
        session = await self._sessions.get(session_id)
        if session is None:
            error_message = f"Session not found: {session_id}"
            raise ValueError(error_message)

        self._current_session = session
        self._state = "idle"

        _logger.info("Loaded session %s", session_id)
        return session

    async def _load_binary(self, path: Path) -> BinaryInfo:
        """Load a binary file for analysis.

        Args:
            path: Path to the binary.

        Returns:
            Binary information.
        """
        binary_bridge = self._tools.get_binary_bridge()
        return await binary_bridge.load_file(path)

    async def process_user_input(self, text: str) -> None:
        """Process user input and generate response.

        This is the main agent loop:
        1. Add user message to session
        2. Send to LLM with tool definitions
        3. If LLM returns tool calls, execute them
        4. Send tool results back to LLM
        5. Repeat until LLM returns final text response
        6. Add assistant message to session

        Args:
            text: User's natural language input.

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        self._state = "processing"
        self._cancel_event.clear()
        self._stats.total_requests += 1
        start_time = time.time()

        user_message = Message(
            role="user",
            content=text,
            timestamp=datetime.now(),
        )
        self._current_session.messages.append(user_message)

        if self._on_message:
            self._on_message(user_message)

        try:
            await self._run_agent_loop()
        except asyncio.CancelledError:
            _logger.info("Request cancelled")
            self._state = "cancelled"
        finally:
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.record_response_time(elapsed_ms)

            if self._state != "cancelled":
                self._state = "idle"

            if self._current_session is not None:
                await self._sessions.update(self._current_session)

    async def _run_agent_loop(self) -> None:
        """Run the main agent loop until completion or cancellation.

        Raises:
            RuntimeError: If provider is not available.
            CancelledError: If the operation is cancelled.
        """
        if self._current_session is None:
            return

        provider = self._providers.get(self._current_session.provider)
        if provider is None:
            error_message = "Provider not available"
            raise RuntimeError(error_message)

        tool_definitions = self._tools.get_tool_definitions()
        iteration = 0

        while iteration < self._config.max_iterations:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError()

            iteration += 1
            _logger.debug("Agent loop iteration %d", iteration)

            messages = self._build_messages()

            response, tool_calls = await self._call_llm(
                provider=provider,
                messages=messages,
                tools=tool_definitions,
                is_final_response=self._is_final_response_expected(),
            )

            if response.content:
                self._current_session.messages.append(response)
                if self._on_message:
                    self._on_message(response)

            if not tool_calls:
                _logger.debug("No tool calls, agent loop complete")
                break

            tool_results = await self._execute_tool_calls(tool_calls)

            tool_message = Message(
                role="tool",
                content="",
                tool_results=tool_results,
                timestamp=datetime.now(),
            )
            self._current_session.messages.append(tool_message)

            if all(not r.success for r in tool_results):
                _logger.warning("All tool calls failed, stopping iteration")
                break

        if iteration >= self._config.max_iterations:
            _logger.warning("Reached maximum iterations (%d)", self._config.max_iterations)

    def _is_final_response_expected(self) -> bool:
        """Determine whether a final response is expected.

        Returns:
            True if the next response is likely final.
        """
        if self._current_session is None:
            return False
        if not self._current_session.messages:
            return False
        return self._current_session.messages[-1].role == "tool"

    def _build_messages(self) -> list[Message]:
        """Build message list for LLM including system prompt.

        Returns:
            List of messages with system prompt prepended.
        """
        if self._current_session is None:
            return []

        system_prompt = self._generate_system_prompt()
        system_message = Message(
            role="system",
            content=system_prompt,
            timestamp=datetime.now(),
        )

        return [system_message, *self._current_session.messages]

    def _generate_system_prompt(self) -> str:
        """Generate system prompt for the LLM.

        Returns:
            System prompt describing available tools and capabilities.
        """
        if self._current_session is None:
            return ""

        prompt_parts = [
            "You are Intellicrack, an advanced AI-powered reverse engineering assistant "
            "specialized in analyzing software licensing protections.",
            "",
            "Your capabilities include:",
            "- Static analysis via Ghidra (decompilation, disassembly, cross-references)",
            "- Dynamic analysis via Frida (hooking, memory manipulation, tracing)",
            "- Debugging via x64dbg (breakpoints, stepping, register manipulation)",
            "- Binary analysis via radare2 (disassembly, analysis, patching)",
            "- Process control (memory reading/writing, DLL injection)",
            "- Binary operations (loading, parsing, patching)",
            "",
            "When analyzing software:",
            "1. First understand the protection mechanism through static analysis",
            "2. Use dynamic analysis to observe runtime behavior",
            "3. Identify key validation functions and decision points",
            "4. Propose bypass strategies (patching, hooking, keygen)",
            "5. Implement the bypass with appropriate tools",
            "",
            "Always explain your reasoning and findings clearly.",
            "Use tools iteratively to build understanding before making changes.",
        ]

        if self._current_session.binaries:
            active_binary = self._current_session.binaries[
                self._current_session.active_binary_index
            ]
            prompt_parts.extend([
                "",
                f"Current binary: {active_binary.name}",
                f"Path: {active_binary.path}",
                f"Type: {active_binary.file_type}",
                f"Architecture: {active_binary.architecture}",
                f"Entry point: 0x{active_binary.entry_point:X}",
            ])

        if self._current_session.patches:
            prompt_parts.extend([
                "",
                "Applied patches:",
            ])
            for patch in self._current_session.patches:
                status = "applied" if patch.applied else "pending"
                prompt_parts.append(
                    f"- 0x{patch.address:X}: {patch.description} ({status})"
                )

        return "\n".join(prompt_parts)

    async def _call_llm(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
        is_final_response: bool = False,
    ) -> tuple[Message, list[ToolCall] | None]:
        """Call the LLM and handle response.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.
            is_final_response: Whether a final response is expected.

        Returns:
            Tuple of (response message, tool calls if any).

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        tools_available = bool(tools)
        if self._should_use_streaming(
            tools_available=tools_available,
            is_final_response=is_final_response,
        ):
            return await self._stream_response(
                provider=provider,
                messages=messages,
                tools=tools,
            )

        return await self._non_stream_response(
            provider=provider,
            messages=messages,
            tools=tools,
        )

    def _should_use_streaming(
        self,
        tools_available: bool,
        is_final_response: bool,
    ) -> bool:
        """Decide whether to use streaming mode.

        Args:
            tools_available: Whether tools are available for this request.
            is_final_response: Whether a final response is expected.

        Returns:
            True if streaming should be used.
        """
        if not self._config.stream_responses:
            return False
        if self._on_stream_chunk is None:
            return False

        mode = self._config.stream_mode
        if mode == "never":
            return False
        if mode == "always":
            return True
        return not (tools_available and not is_final_response)

    async def _stream_response(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
    ) -> tuple[Message, None]:
        """Stream a response from the LLM.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.

        Returns:
            Tuple of (response message, None).

        Raises:
            RuntimeError: If no active session.
            CancelledError: If the operation is cancelled.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        content_parts: list[str] = []

        async for chunk in provider.chat_stream(
            messages=messages,
            model=self._current_session.model,
            tools=tools,
            temperature=self._config.temperature,
            max_tokens=self._config.max_tokens,
        ):
            if self._cancel_event.is_set():
                raise asyncio.CancelledError()

            content_parts.append(chunk)
            if self._on_stream_chunk:
                self._on_stream_chunk(chunk)

        content = "".join(content_parts)
        return Message(
            role="assistant",
            content=content,
            timestamp=datetime.now(),
        ), None

    async def _non_stream_response(
        self,
        provider: LLMProvider,
        messages: list[Message],
        tools: list[ToolDefinition],
    ) -> tuple[Message, list[ToolCall] | None]:
        """Request a non-streaming response from the LLM.

        Args:
            provider: LLM provider to use.
            messages: Conversation messages.
            tools: Available tool definitions.

        Returns:
            Tuple of (response message, tool calls if any).

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        response, tool_calls = await provider.chat(
            messages=messages,
            model=self._current_session.model,
            tools=tools,
            temperature=self._config.temperature,
            max_tokens=self._config.max_tokens,
        )

        return response, tool_calls

    async def _execute_tool_calls(
        self,
        tool_calls: list[ToolCall],
    ) -> list[ToolResult]:
        """Execute a list of tool calls.

        Args:
            tool_calls: Tool calls to execute.

        Returns:
            List of tool results.

        Raises:
            CancelledError: If the operation is cancelled.
        """
        results: list[ToolResult] = []

        for call in tool_calls:
            if self._cancel_event.is_set():
                raise asyncio.CancelledError()

            if self._on_tool_call:
                self._on_tool_call(call)

            if await self._should_confirm(call):
                confirmed = await self._request_confirmation(call)
                if not confirmed:
                    result = ToolResult(
                        call_id=call.id,
                        success=False,
                        result=None,
                        error="User declined confirmation",
                        duration_ms=0,
                    )
                    results.append(result)
                    continue

            result = await self._execute_single_tool_call(call)
            results.append(result)

            if self._on_tool_result:
                self._on_tool_result(result)

        return results

    async def _execute_single_tool_call(self, call: ToolCall) -> ToolResult:
        """Execute a single tool call.

        Args:
            call: The tool call to execute.

        Returns:
            Result of the tool execution.
        """
        start_time = time.time()
        self._stats.total_tool_calls += 1

        try:
            result = await self._tools.execute_tool_call(
                tool_name=call.tool_name,
                function_name=call.function_name,
                arguments=call.arguments,
            )

            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.successful_tool_calls += 1

            _logger.info(
                "Tool call %s.%s succeeded in %.1fms",
                call.tool_name,
                call.function_name,
                elapsed_ms,
            )

            return ToolResult(
                call_id=call.id,
                success=True,
                result=result,
                error=None,
                duration_ms=elapsed_ms,
            )

        except Exception as e:
            elapsed_ms = (time.time() - start_time) * 1000
            self._stats.failed_tool_calls += 1

            _logger.exception(
                "Tool call %s.%s failed",
                call.tool_name,
                call.function_name,
            )

            return ToolResult(
                call_id=call.id,
                success=False,
                result=None,
                error=str(e),
                duration_ms=elapsed_ms,
            )

    async def _should_confirm(self, call: ToolCall) -> bool:
        """Check if tool call requires user confirmation.

        Args:
            call: The tool call to check.

        Returns:
            True if confirmation needed.
        """
        if self._config.confirmation_level == ConfirmationLevel.NONE:
            return False
        if self._config.confirmation_level == ConfirmationLevel.ALL:
            return True
        return self._is_destructive_operation(call)

    def _is_destructive_operation(self, call: ToolCall) -> bool:
        """Check if a tool call is destructive.

        Destructive operations include:
        - Writing to memory or files
        - Patching binaries
        - Executing code in target
        - Any modification operations

        Args:
            call: The tool call to check.

        Returns:
            True if operation is destructive.
        """
        function_lower = call.function_name.lower()
        return any(pattern in function_lower for pattern in self.DESTRUCTIVE_PATTERNS)

    async def _request_confirmation(self, call: ToolCall) -> bool:
        """Request user confirmation for a tool call.

        Args:
            call: The tool call requiring confirmation.

        Returns:
            True if user confirmed, False otherwise.
        """
        self._state = "waiting_confirmation"

        if self._async_confirmation_callback:
            future = self._async_confirmation_callback(call)
            self._pending_confirmation = PendingConfirmation(call=call, future=future)

            try:
                return await future
            finally:
                self._pending_confirmation = None
                self._state = "processing"

        if self._confirmation_callback:
            result = await asyncio.to_thread(self._confirmation_callback, call)
            self._state = "processing"
            return result

        _logger.warning("No confirmation callback set, auto-declining")
        self._state = "processing"
        return False

    def confirm_pending(self, confirmed: bool) -> None:
        """Confirm or decline a pending operation.

        Args:
            confirmed: True to confirm, False to decline.
        """
        if (
            self._pending_confirmation is not None
            and not self._pending_confirmation.future.done()
        ):
            self._pending_confirmation.future.set_result(confirmed)

    async def cancel(self) -> None:
        """Cancel current operation."""
        _logger.info("Cancelling current operation")
        self._cancel_event.set()

        provider = (
            self._providers.get(self._current_session.provider)
            if self._current_session
            else None
        )
        if provider:
            await provider.cancel_request()

        if (
            self._pending_confirmation
            and not self._pending_confirmation.future.done()
        ):
            self._pending_confirmation.future.set_result(False)

    async def add_binary(self, path: Path) -> BinaryInfo:
        """Add a binary to the current session.

        Args:
            path: Path to the binary.

        Returns:
            Binary information.

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        binary_info = await self._load_binary(path)
        self._current_session.binaries.append(binary_info)
        self._current_session.active_binary_index = (
            len(self._current_session.binaries) - 1
        )

        await self._sessions.update(self._current_session)
        return binary_info

    async def set_active_binary(self, index: int) -> None:
        """Set the active binary by index.

        Args:
            index: Index of binary to activate.

        Raises:
            RuntimeError: If no active session.
            IndexError: If index out of range.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        if index < 0 or index >= len(self._current_session.binaries):
            error_message = f"Binary index out of range: {index}"
            raise IndexError(error_message)

        self._current_session.active_binary_index = index
        await self._sessions.update(self._current_session)

    async def add_patch(self, patch: PatchInfo) -> None:
        """Add a patch to the current session.

        Args:
            patch: Patch information.

        Raises:
            RuntimeError: If no active session.
        """
        if self._current_session is None:
            error_message = "No active session"
            raise RuntimeError(error_message)

        self._current_session.patches.append(patch)
        await self._sessions.update(self._current_session)

    def set_message_callback(self, callback: Callable[[Message], None]) -> None:
        """Set callback for new messages.

        Args:
            callback: Function to call with each new message.
        """
        self._on_message = callback

    def set_tool_call_callback(self, callback: Callable[[ToolCall], None]) -> None:
        """Set callback for tool calls.

        Args:
            callback: Function to call when tool is called.
        """
        self._on_tool_call = callback

    def set_tool_result_callback(self, callback: Callable[[ToolResult], None]) -> None:
        """Set callback for tool results.

        Args:
            callback: Function to call when tool returns result.
        """
        self._on_tool_result = callback

    def set_stream_callback(self, callback: Callable[[str], None]) -> None:
        """Set callback for streaming response chunks.

        Args:
            callback: Function to call with each text chunk.
        """
        self._on_stream_chunk = callback

    def set_confirmation_callback(
        self,
        callback: Callable[[ToolCall], bool],
    ) -> None:
        """Set synchronous callback for confirmation requests.

        Args:
            callback: Function to call for confirmation, returns True to proceed.
        """
        self._confirmation_callback = callback

    def set_async_confirmation_callback(
        self,
        callback: Callable[[ToolCall], asyncio.Future[bool]],
    ) -> None:
        """Set async callback for confirmation requests.

        Args:
            callback: Function returning a Future that resolves to True/False.
        """
        self._async_confirmation_callback = callback

    async def get_tool_status(self) -> list[dict[str, Any]]:
        """Get status of all tools.

        Returns:
            List of tool status dictionaries.
        """
        statuses = await self._tools.get_all_status()
        return [
            {
                "name": status.name.value,
                "available": status.available,
                "connected": status.connected,
                "version": status.version,
                "path": str(status.path) if status.path else None,
                "error": status.error,
            }
            for status in statuses
        ]

    async def initialize_tool(self, tool_name: str | ToolName) -> bool:
        """Initialize a specific tool.

        Args:
            tool_name: Name of the tool to initialize.

        Returns:
            True if initialization succeeded.
        """
        if isinstance(tool_name, str):
            tool_name = ToolName(tool_name.lower())

        return await self._tools.initialize_tool(tool_name)

    async def shutdown(self) -> None:
        """Shutdown the orchestrator and cleanup resources."""
        _logger.info("Shutting down orchestrator")

        await self.cancel()
        await self._tools.shutdown()

        if self._current_session:
            await self._sessions.update(self._current_session)

        self._current_session = None
        self._state = "idle"
