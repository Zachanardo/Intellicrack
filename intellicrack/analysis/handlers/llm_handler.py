"""LLM Integration Handler.

Manages the integration between protection analysis results and LLM tools,
allowing AI models to answer questions about detected protections.

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

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol


if TYPE_CHECKING:
    from collections.abc import Callable

    from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal

    from ...protection.unified_protection_engine import UnifiedProtectionResult

    PYQT6_AVAILABLE = True
else:
    try:
        from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal

        PYQT6_AVAILABLE = True
    except ImportError:

        class QObject:
            """Fallback QObject class when PyQt6 is not available."""

            def __init__(self, parent: QObject | None = None) -> None:
                """Initialize QObject with optional parent.

                Args:
                    parent: Optional parent QObject instance, defaults to None.

                Returns:
                    None

                """
                pass

        class QRunnable:
            """Fallback QRunnable class when PyQt6 is not available."""

            def run(self) -> None:
                """Execute the runnable task."""
                pass

        class QThreadPool:
            """Fallback QThreadPool class when PyQt6 is not available."""

            @staticmethod
            def globalInstance() -> QThreadPool | None:
                """Return the global thread pool instance.

                Args:
                    No arguments.

                Returns:
                    QThreadPool | None: The global thread pool instance or None
                        if unavailable.

                """
                return None

            def start(self, runnable: QRunnable) -> None:
                """Start a runnable in the thread pool.

                Args:
                    runnable: The QRunnable task to execute in the thread pool.

                Returns:
                    None

                """
                pass

        def pyqtSignal(*args: Any, **kwargs: Any) -> Callable[..., Any]:
            """Fallback pyqtSignal function when PyQt6 is not available.

            Args:
                *args: Positional arguments for the signal definition.
                **kwargs: Keyword arguments for the signal definition.

            Returns:
                Callable[..., Any]: A decorator function that wraps signal
                    definitions.

            """

            def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
                return func

            return decorator

        PYQT6_AVAILABLE = False


class LLMManagerProtocol(Protocol):
    """Protocol for LLM Manager interface."""

    @staticmethod
    def get_instance() -> LLMManagerProtocol:
        """Get the singleton instance of LLM manager."""
        ...

    def query(self, prompt: str) -> Any:
        """Query the LLM with a prompt.

        Args:
            prompt: The prompt string to send to the LLM for processing.

        Returns:
            Any: The response from the LLM backend.

        """
        ...


try:
    from ...ai.llm_backends import LLMManager as _LLMManager

    LLMManager: type[LLMManagerProtocol] | None = _LLMManager
except ImportError:
    LLMManager = None

try:
    from ...llm.tools.intellicrack_protection_analysis_tool import DIEAnalysisTool as _DIEAnalysisTool

    DIEAnalysisTool: type[Any] | None = _DIEAnalysisTool
except ImportError:
    DIEAnalysisTool = None

try:
    from ...utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name: str | None = None) -> logging.Logger:
        """Create a logger instance with the given name.

        Args:
            name: The name for the logger instance

        Returns:
            A logging.Logger instance

        """
        return logging.getLogger(name or __name__)


logger = get_logger(__name__)


class LLMWorkerSignals(QObject):
    """Signals for LLM worker thread."""

    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(str)


class LLMAnalysisWorker(QRunnable):
    """Worker thread for LLM analysis operations."""

    def __init__(self, operation: str, analysis_result: UnifiedProtectionResult, **kwargs: object) -> None:
        """Initialize the LLM analysis worker.

        Args:
            operation: The type of LLM operation to perform.
            analysis_result: The unified protection result to analyze.
            **kwargs: Additional keyword arguments for the operation.

        """
        super().__init__()
        self.operation = operation
        self.analysis_result = analysis_result
        self.kwargs = kwargs
        self.signals = LLMWorkerSignals()

    def run(self) -> None:
        """Execute the LLM operation."""
        try:
            self.signals.progress.emit(f"Processing {self.operation}...")

            result: dict[str, Any]
            if self.operation == "register_context":
                context = self._build_llm_context(self.analysis_result)
                result = {"success": True, "context": context}

            elif self.operation == "generate_summary":
                if LLMManager is None:
                    result = {"success": False, "error": "LLM Manager not available"}
                else:
                    llm_manager = LLMManager.get_instance()
                    prompt = self._build_summary_prompt(self.analysis_result)
                    response = llm_manager.query(prompt)
                    result = {"success": True, "summary": response}

            elif self.operation == "suggest_bypass":
                if LLMManager is None:
                    result = {"success": False, "error": "LLM Manager not available"}
                else:
                    llm_manager = LLMManager.get_instance()
                    prompt = self._build_bypass_prompt(self.analysis_result)
                    response = llm_manager.query(prompt)
                    result = {"success": True, "suggestions": response}

            else:
                result = {"success": False, "error": f"Unknown operation: {self.operation}"}

            self.signals.result.emit(result)

        except Exception as e:
            logger.exception("Exception in llm_handler: %s", e)
            import traceback

            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()

    def _build_llm_context(self, result: UnifiedProtectionResult) -> dict[str, object]:
        """Build context dictionary for LLM.

        Args:
            result: The unified protection analysis result to convert to
                context.

        Returns:
            dict[str, object]: A dictionary containing the protection analysis
                context for the LLM.

        """
        context = {
            "file_path": result.file_path,
            "file_type": result.file_type,
            "architecture": result.architecture,
            "protections": [
                {
                    "name": p["name"],
                    "type": p["type"],
                    "confidence": p.get("confidence", 0),
                }
                for p in result.protections
            ],
            "is_packed": result.is_packed,
            "is_protected": result.is_protected,
            "has_anti_debug": result.has_anti_debug,
            "has_anti_vm": result.has_anti_vm,
            "has_licensing": result.has_licensing,
            "protection_count": len(result.protections),
            "confidence_score": result.confidence_score,
        }

        # Add bypass strategies if available
        if result.bypass_strategies:
            context["bypass_strategies"] = [
                {
                    "name": s["name"],
                    "difficulty": s.get("difficulty", "Unknown"),
                }
                for s in result.bypass_strategies
            ]

        return context

    def _build_summary_prompt(self, result: UnifiedProtectionResult) -> str:
        """Build prompt for protection summary.

        Args:
            result: The unified protection analysis result to analyze.

        Returns:
            str: A formatted string prompt for the LLM to generate a summary.

        """
        prompt = f"""Analyze the following protection analysis results and provide a concise summary:

File: {result.file_path}
Type: {result.file_type}
Architecture: {result.architecture}

Protections detected ({len(result.protections)}):
"""
        for p in result.protections:
            prompt += f"- {p['name']} ({p['type']}) - Confidence: {p.get('confidence', 0)}%\n"

        prompt += f"""
Overall confidence: {result.confidence_score}%
Packed: {result.is_packed}
Anti-debug: {result.has_anti_debug}
Anti-VM: {result.has_anti_vm}
Licensing: {result.has_licensing}

Please provide:
1. A brief summary of the protection scheme
2. The likely purpose of these protections
3. The difficulty level of bypassing these protections
4. Any notable observations
"""
        return prompt

    def _build_bypass_prompt(self, result: UnifiedProtectionResult) -> str:
        """Build prompt for bypass suggestions.

        Args:
            result: The unified protection analysis result to analyze.

        Returns:
            str: A formatted string prompt for the LLM to suggest bypass
                strategies.

        """
        prompt = """Based on the following protection analysis, suggest bypass strategies:

Protections:
"""
        for p in result.protections:
            prompt += f"- {p['name']} ({p['type']})\n"

        prompt += """
Please provide:
1. Step-by-step bypass approach for each protection
2. Tools that would be helpful
3. Potential challenges
4. Code snippets or scripts if applicable
"""
        return prompt


class LLMHandler(QObject):
    """Handle LLM integration with protection analysis results.

    This handler manages the interaction between protection analysis
    and LLM tools, enabling AI-powered insights and suggestions.
    """

    # Signals
    #: Signal emitted when LLM operation results are ready (type: dict)
    llm_result_ready = pyqtSignal(dict)
    #: Signal emitted when an LLM error occurs (type: str)
    llm_error = pyqtSignal(str)
    #: Signal emitted to report LLM operation progress (type: str)
    llm_progress = pyqtSignal(str)

    def __init__(self, parent: QObject | None = None) -> None:
        """Initialize the LLM handler.

        Args:
            parent: Optional parent widget for Qt integration.

        """
        super().__init__(parent)
        self.thread_pool: QThreadPool | None = QThreadPool.globalInstance()
        self.current_result: UnifiedProtectionResult | None = None
        self.die_tool: Any = None
        if DIEAnalysisTool is not None:
            self.die_tool = DIEAnalysisTool()

        self._register_llm_tool()

    def _register_llm_tool(self) -> None:
        """Register the DIE analysis tool with LLM manager."""
        try:
            if LLMManager is None or self.die_tool is None:
                logger.warning("LLM Manager or DIE tool not available")
                return

            llm_manager = LLMManager.get_instance()
            self.die_tool._llm_handler = self
            logger.info("Retrieved LLM manager instance: %s", llm_manager)
            logger.info("Registered DIE analysis tool with LLM manager")
        except Exception as e:
            logger.exception("Failed to register LLM tool: %s", e)

    def on_analysis_complete(self, result: UnifiedProtectionResult) -> None:
        """Handle slot when protection analysis completes.

        This method runs in the main thread and kicks off background
        LLM operations.

        Args:
            result: The protection analysis result to process.

        Returns:
            None

        """
        self.current_result = result
        logger.info("LLM handler received analysis for: %s", result.file_path)

        if self.thread_pool is None:
            logger.error("Thread pool not available")
            return

        worker = LLMAnalysisWorker("register_context", result)
        worker.signals.result.connect(self._on_context_registered)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.llm_progress.emit)

        self.thread_pool.start(worker)

    def generate_summary(self) -> None:
        """Generate an AI summary of the current protection analysis.

        Returns:
            None

        """
        if not self.current_result:
            self.llm_error.emit("No analysis result available")
            return

        if self.thread_pool is None:
            self.llm_error.emit("Thread pool not available")
            return

        worker = LLMAnalysisWorker("generate_summary", self.current_result)
        worker.signals.result.connect(self._on_summary_ready)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.llm_progress.emit)

        self.thread_pool.start(worker)

    def suggest_bypass_strategies(self) -> None:
        """Get AI suggestions for bypassing detected protections.

        Returns:
            None

        """
        if not self.current_result:
            self.llm_error.emit("No analysis result available")
            return

        if self.thread_pool is None:
            self.llm_error.emit("Thread pool not available")
            return

        worker = LLMAnalysisWorker("suggest_bypass", self.current_result)
        worker.signals.result.connect(self._on_bypass_suggestions_ready)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.llm_progress.emit)

        self.thread_pool.start(worker)

    def get_cached_result(self) -> UnifiedProtectionResult | None:
        """Get the current cached analysis result.

        Returns:
            UnifiedProtectionResult | None: The cached protection analysis result
                or None if no result is available.

        """
        return self.current_result

    def _on_context_registered(self, result: dict[str, Any]) -> None:
        """Handle context registration completion.

        Args:
            result: The result dictionary from the context registration
                operation.

        Returns:
            None

        """
        if result.get("success"):
            logger.info("Protection analysis context registered with LLM")
            self.llm_result_ready.emit(
                {
                    "type": "context_registered",
                    "context": result.get("context"),
                },
            )
        else:
            error_msg = result.get("error")
            if isinstance(error_msg, str):
                self.llm_error.emit(error_msg)
            else:
                self.llm_error.emit("Unknown error")

    def _on_summary_ready(self, result: dict[str, Any]) -> None:
        """Handle summary generation completion.

        Args:
            result: The result dictionary from the summary generation
                operation.

        Returns:
            None

        """
        if result.get("success"):
            self.llm_result_ready.emit(
                {
                    "type": "summary",
                    "content": result.get("summary"),
                },
            )
        else:
            error_msg = result.get("error")
            if isinstance(error_msg, str):
                self.llm_error.emit(error_msg)
            else:
                self.llm_error.emit("Unknown error")

    def _on_bypass_suggestions_ready(self, result: dict[str, Any]) -> None:
        """Handle bypass suggestions completion.

        Args:
            result: The result dictionary from the bypass suggestions
                operation.

        Returns:
            None

        """
        if result.get("success"):
            self.llm_result_ready.emit(
                {
                    "type": "bypass_suggestions",
                    "content": result.get("suggestions"),
                },
            )
        else:
            error_msg = result.get("error")
            if isinstance(error_msg, str):
                self.llm_error.emit(error_msg)
            else:
                self.llm_error.emit("Unknown error")

    def _on_worker_error(self, error_tuple: tuple[type[BaseException], BaseException, str]) -> None:
        """Handle worker thread errors.

        Args:
            error_tuple: A tuple containing the exception type, value, and
                traceback.

        Returns:
            None

        """
        _exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"LLM operation failed: {exc_value}"
        logger.error("%s\n%s", error_msg, exc_traceback)
        self.llm_error.emit(error_msg)
