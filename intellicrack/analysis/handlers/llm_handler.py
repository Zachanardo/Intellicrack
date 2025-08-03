"""
LLM Integration Handler

Manages the integration between protection analysis results and LLM tools,
allowing AI models to answer questions about detected protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

from typing import Any, Dict, Optional

from PyQt6.QtCore import QObject, QRunnable, QThreadPool, pyqtSignal

try:
    from ...ai.llm_backends import LLMManager
except ImportError:
    LLMManager = None

try:
    from ...llm.tools.intellicrack_protection_analysis_tool import DIEAnalysisTool
except ImportError:
    DIEAnalysisTool = None

try:
    from ...protection.unified_protection_engine import UnifiedProtectionResult
except ImportError:
    UnifiedProtectionResult = None

try:
    from ...utils.logger import get_logger
except ImportError:
    import logging

    def get_logger(name):
        """Create a logger instance with the given name.

        Args:
            name: The name for the logger instance

        Returns:
            A logging.Logger instance
        """
        return logging.getLogger(name)

logger = get_logger(__name__)


class LLMWorkerSignals(QObject):
    """Signals for LLM worker thread"""
    finished = pyqtSignal()
    error = pyqtSignal(tuple)
    result = pyqtSignal(object)
    progress = pyqtSignal(str)


class LLMAnalysisWorker(QRunnable):
    """Worker thread for LLM analysis operations"""

    def __init__(self, operation: str, analysis_result: UnifiedProtectionResult, **kwargs):
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

    def run(self):
        """Execute the LLM operation"""
        try:
            self.signals.progress.emit(f"Processing {self.operation}...")

            if self.operation == "register_context":
                # Register the analysis result as context for LLM
                context = self._build_llm_context(self.analysis_result)
                result = {"success": True, "context": context}

            elif self.operation == "generate_summary":
                # Generate an AI summary of the protections
                llm_manager = LLMManager.get_instance()
                prompt = self._build_summary_prompt(self.analysis_result)
                response = llm_manager.query(prompt)
                result = {"success": True, "summary": response}

            elif self.operation == "suggest_bypass":
                # Get AI suggestions for bypassing protections
                llm_manager = LLMManager.get_instance()
                prompt = self._build_bypass_prompt(self.analysis_result)
                response = llm_manager.query(prompt)
                result = {"success": True, "suggestions": response}

            else:
                result = {"success": False,
                          "error": f"Unknown operation: {self.operation}"}

            self.signals.result.emit(result)

        except Exception as e:
            logger.error("Exception in llm_handler: %s", e)
            import traceback
            self.signals.error.emit((type(e), e, traceback.format_exc()))
        finally:
            self.signals.finished.emit()

    def _build_llm_context(self, result: UnifiedProtectionResult) -> Dict[str, Any]:
        """Build context dictionary for LLM"""
        context = {
            "file_path": result.file_path,
            "file_type": result.file_type,
            "architecture": result.architecture,
            "protections": [
                {
                    "name": p["name"],
                    "type": p["type"],
                    "confidence": p.get("confidence", 0)
                }
                for p in result.protections
            ],
            "is_packed": result.is_packed,
            "is_protected": result.is_protected,
            "has_anti_debug": result.has_anti_debug,
            "has_anti_vm": result.has_anti_vm,
            "has_licensing": result.has_licensing,
            "protection_count": len(result.protections),
            "confidence_score": result.confidence_score
        }

        # Add bypass strategies if available
        if result.bypass_strategies:
            context["bypass_strategies"] = [
                {
                    "name": s["name"],
                    "difficulty": s.get("difficulty", "Unknown")
                }
                for s in result.bypass_strategies
            ]

        return context

    def _build_summary_prompt(self, result: UnifiedProtectionResult) -> str:
        """Build prompt for protection summary"""
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
        """Build prompt for bypass suggestions"""
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
    """
    Handler for LLM integration with protection analysis results.

    This handler manages the interaction between protection analysis
    and LLM tools, enabling AI-powered insights and suggestions.
    """

    # Signals
    llm_result_ready = pyqtSignal(dict)  # Emits LLM operation results
    llm_error = pyqtSignal(str)
    llm_progress = pyqtSignal(str)

    def __init__(self, parent=None):
        """Initialize the LLM handler.

        Args:
            parent: Optional parent widget for Qt integration.
        """
        super().__init__(parent)
        self.thread_pool = QThreadPool.globalInstance()
        self.current_result: Optional[UnifiedProtectionResult] = None
        self.die_tool = DIEAnalysisTool()

        # Register the tool with LLM manager
        self._register_llm_tool()

    def _register_llm_tool(self):
        """Register the DIE analysis tool with LLM manager"""
        try:
            llm_manager = LLMManager.get_instance()
            # Store reference to this handler in the tool
            self.die_tool._llm_handler = self
            logger.info("Retrieved LLM manager instance: %s", llm_manager)
            logger.info("Registered DIE analysis tool with LLM manager")
        except Exception as e:
            logger.error(f"Failed to register LLM tool: {e}")

    def on_analysis_complete(self, result: UnifiedProtectionResult):
        """
        Main slot called when protection analysis completes.

        This method runs in the main thread and kicks off background
        LLM operations.
        """
        self.current_result = result
        logger.info(f"LLM handler received analysis for: {result.file_path}")

        # Register context with LLM in background
        worker = LLMAnalysisWorker("register_context", result)
        worker.signals.result.connect(self._on_context_registered)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.llm_progress.emit)

        self.thread_pool.start(worker)

    def generate_summary(self):
        """Generate an AI summary of the current protection analysis"""
        if not self.current_result:
            self.llm_error.emit("No analysis result available")
            return

        worker = LLMAnalysisWorker("generate_summary", self.current_result)
        worker.signals.result.connect(self._on_summary_ready)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.llm_progress.emit)

        self.thread_pool.start(worker)

    def suggest_bypass_strategies(self):
        """Get AI suggestions for bypassing detected protections"""
        if not self.current_result:
            self.llm_error.emit("No analysis result available")
            return

        worker = LLMAnalysisWorker("suggest_bypass", self.current_result)
        worker.signals.result.connect(self._on_bypass_suggestions_ready)
        worker.signals.error.connect(self._on_worker_error)
        worker.signals.progress.connect(self.llm_progress.emit)

        self.thread_pool.start(worker)

    def get_cached_result(self) -> Optional[UnifiedProtectionResult]:
        """Get the current cached analysis result"""
        return self.current_result

    def _on_context_registered(self, result: dict):
        """Handle context registration completion"""
        if result["success"]:
            logger.info("Protection analysis context registered with LLM")
            self.llm_result_ready.emit({
                "type": "context_registered",
                "context": result["context"]
            })
        else:
            self.llm_error.emit(result.get("error", "Unknown error"))

    def _on_summary_ready(self, result: dict):
        """Handle summary generation completion"""
        if result["success"]:
            self.llm_result_ready.emit({
                "type": "summary",
                "content": result["summary"]
            })
        else:
            self.llm_error.emit(result.get("error", "Unknown error"))

    def _on_bypass_suggestions_ready(self, result: dict):
        """Handle bypass suggestions completion"""
        if result["success"]:
            self.llm_result_ready.emit({
                "type": "bypass_suggestions",
                "content": result["suggestions"]
            })
        else:
            self.llm_error.emit(result.get("error", "Unknown error"))

    def _on_worker_error(self, error_tuple):
        """Handle worker thread errors"""
        exc_type, exc_value, exc_traceback = error_tuple
        error_msg = f"LLM operation failed: {exc_value}"
        logger.error(f"{error_msg}\n{exc_traceback}")
        self.llm_error.emit(error_msg)
