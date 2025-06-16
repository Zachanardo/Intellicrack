"""
AI Coordination Layer for Intellicrack 

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


import hashlib
import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

# Local imports
try:
    from ..utils.logger import get_logger
    from .ml_predictor import MLVulnerabilityPredictor
    from .model_manager_module import ModelManager
    from .orchestrator import AIEventBus, AISharedContext
except ImportError:
    # Fallback for testing
    MLVulnerabilityPredictor = None
    ModelManager = None
    AISharedContext = None
    AIEventBus = None


logger = get_logger(__name__)


class AnalysisStrategy(Enum):
    """Strategy for coordinating ML and LLM analysis."""
    ML_FIRST = "ml_first"              # Start with ML, escalate if needed
    LLM_FIRST = "llm_first"            # Start with LLM, use ML for validation
    PARALLEL = "parallel"              # Run both simultaneously
    ML_ONLY = "ml_only"               # Use only fast ML models
    LLM_ONLY = "llm_only"             # Use only intelligent LLMs
    ADAPTIVE = "adaptive"              # Choose strategy based on task complexity


@dataclass
class AnalysisRequest:
    """Request for coordinated analysis."""
    binary_path: str
    analysis_type: str
    strategy: AnalysisStrategy = AnalysisStrategy.ADAPTIVE
    confidence_threshold: float = 0.7
    max_processing_time: float = 30.0  # seconds
    use_cache: bool = True
    context: Dict[str, Any] = None


@dataclass
class CoordinatedResult:
    """Result from coordinated analysis."""
    ml_results: Optional[Dict[str, Any]] = None
    llm_results: Optional[Dict[str, Any]] = None
    combined_confidence: float = 0.0
    strategy_used: AnalysisStrategy = AnalysisStrategy.ML_FIRST
    processing_time: float = 0.0
    escalated: bool = False
    cache_hit: bool = False
    recommendations: List[str] = None


class AICoordinationLayer:
    """
    Coordination layer between fast ML models and intelligent LLMs.

    This class orchestrates the interaction between:
    - MLVulnerabilityPredictor: Fast, specific vulnerability detection
    - ModelManager: Intelligent LLM reasoning and complex analysis

    It maintains the performance characteristics of each while enabling
    intelligent workflows that leverage both capabilities.
    """

    def __init__(self, shared_context: Optional[AISharedContext] = None,
                 event_bus: Optional[AIEventBus] = None):
        """Initialize the coordination layer."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing AI Coordination Layer...")

        self.shared_context = shared_context or AISharedContext()
        self.event_bus = event_bus or AIEventBus()

        # Initialize components
        self.ml_predictor = None
        self.model_manager = None
        self._llm_manager = None
        self._initialize_components()

        # Performance tracking
        self.performance_stats = {
            "ml_calls": 0,
            "llm_calls": 0,
            "escalations": 0,
            "cache_hits": 0,
            "avg_ml_time": 0.0,
            "avg_llm_time": 0.0
        }

        # Analysis cache for performance optimization
        self.analysis_cache = {}
        self.cache_ttl = timedelta(hours=1)  # Cache results for 1 hour

        logger.info("AI Coordination Layer initialized")

    def _initialize_components(self):
        """Initialize ML and LLM components."""
        # Initialize ML predictor
        try:
            if MLVulnerabilityPredictor:
                self.ml_predictor = MLVulnerabilityPredictor()
                logger.info("ML Predictor initialized in coordination layer")
            else:
                logger.warning("ML Predictor not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize ML Predictor: %s", e)

        # Initialize model manager
        try:
            if ModelManager:
                self.model_manager = ModelManager()
                logger.info("Model Manager initialized in coordination layer")
            else:
                logger.warning("Model Manager not available")
        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Failed to initialize Model Manager: %s", e)

    def _get_cache_key(self, request: AnalysisRequest) -> str:
        """Generate cache key for analysis request."""
        key_data = f"{request.binary_path}_{request.analysis_type}_{request.strategy}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        """Check if cache entry is still valid."""
        cached_time = cache_entry.get("timestamp", datetime.min)
        return datetime.now() - cached_time < self.cache_ttl

    def _cache_result(self, cache_key: str, result: CoordinatedResult):
        """Cache analysis result."""
        self.analysis_cache[cache_key] = {
            "result": result,
            "timestamp": datetime.now()
        }

    def _choose_strategy(self, request: AnalysisRequest) -> AnalysisStrategy:
        """Choose analysis strategy based on request characteristics."""
        if request.strategy != AnalysisStrategy.ADAPTIVE:
            return request.strategy

        # Adaptive strategy selection
        binary_path = request.binary_path

        # Check file size (larger files might benefit from ML first)
        try:
            import os
            file_size = os.path.getsize(binary_path)

            if file_size > 50 * 1024 * 1024:  # > 50MB
                return AnalysisStrategy.ML_FIRST  # Start with fast analysis
            elif file_size < 1024 * 1024:  # < 1MB
                return AnalysisStrategy.PARALLEL  # Small files can handle both
            else:
                return AnalysisStrategy.ML_FIRST  # Default to ML first

        except (OSError, ValueError, RuntimeError):
            return AnalysisStrategy.ML_FIRST

    def analyze_vulnerabilities(self, request: AnalysisRequest) -> CoordinatedResult:
        """
        Coordinate vulnerability analysis between ML and LLM components.

        This method intelligently combines fast ML prediction with deep
        LLM reasoning to provide comprehensive vulnerability analysis.
        """
        start_time = time.time()
        strategy = self._choose_strategy(request)

        logger.info("Starting coordinated vulnerability analysis with strategy: %s", strategy)

        # Check cache first
        cache_key = self._get_cache_key(request)
        if request.use_cache and cache_key in self.analysis_cache:
            cache_entry = self.analysis_cache[cache_key]
            if self._is_cache_valid(cache_entry):
                logger.info("Returning cached analysis result")
                result = cache_entry["result"]
                result.cache_hit = True
                self.performance_stats["cache_hits"] += 1
                return result

        # Initialize result
        result = CoordinatedResult(strategy_used=strategy)

        try:
            # Execute based on chosen strategy
            if strategy == AnalysisStrategy.ML_FIRST:
                result = self._ml_first_analysis(request, result)
            elif strategy == AnalysisStrategy.LLM_FIRST:
                result = self._llm_first_analysis(request, result)
            elif strategy == AnalysisStrategy.PARALLEL:
                result = self._parallel_analysis(request, result)
            elif strategy == AnalysisStrategy.ML_ONLY:
                result = self._ml_only_analysis(request, result)
            elif strategy == AnalysisStrategy.LLM_ONLY:
                result = self._llm_only_analysis(request, result)

            # Calculate processing time
            result.processing_time = time.time() - start_time

            # Cache the result
            if request.use_cache:
                self._cache_result(cache_key, result)

            # Emit completion event
            self.event_bus.emit("coordinated_analysis_complete", {
                "strategy": strategy,
                "processing_time": result.processing_time,
                "confidence": result.combined_confidence,
                "escalated": result.escalated
            }, "coordination_layer")

            logger.info("Coordinated analysis complete in %fs", result.processing_time)
            return result

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("Error in coordinated analysis: %s", e)
            result.processing_time = time.time() - start_time
            return result

    def _ml_first_analysis(self, request: AnalysisRequest, result: CoordinatedResult) -> CoordinatedResult:
        """Execute ML-first analysis strategy."""
        logger.debug("Executing ML-first analysis strategy")

        # Step 1: Fast ML analysis
        if self.ml_predictor:
            ml_start = time.time()
            try:
                # Check if method exists, fallback to alternative
                if hasattr(self.ml_predictor, 'predict_vulnerabilities'):
                    ml_results = self.ml_predictor.predict_vulnerabilities(request.binary_path)
                elif hasattr(self.ml_predictor, 'predict'):
                    ml_results = self.ml_predictor.predict(request.binary_path)
                else:
                    raise AttributeError("No prediction method available")
                result.ml_results = ml_results

                ml_time = time.time() - ml_start
                self.performance_stats["ml_calls"] += 1
                self.performance_stats["avg_ml_time"] = (
                    (self.performance_stats["avg_ml_time"] * (self.performance_stats["ml_calls"] - 1) + ml_time) /
                    self.performance_stats["ml_calls"]
                )

                # Check if escalation to LLM is needed
                ml_confidence = ml_results.get("confidence", 0.0)
                vulnerability_count = len(ml_results.get("vulnerabilities", []))

                should_escalate = (
                    ml_confidence < request.confidence_threshold or
                    vulnerability_count > 5 or  # Many vulnerabilities need deeper analysis
                    any(_vuln.get("severity") == "critical" for _vuln in ml_results.get("vulnerabilities", []))
                )

                if should_escalate and self.model_manager:
                    logger.info("Escalating to LLM analysis (ML confidence: %f)", ml_confidence)
                    result = self._add_llm_analysis(request, result)
                    result.escalated = True
                    self.performance_stats["escalations"] += 1
                else:
                    result.combined_confidence = ml_confidence

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("ML analysis failed: %s", e)
                if self.model_manager:
                    # Fallback to LLM analysis
                    result = self._add_llm_analysis(request, result)
                    result.escalated = True

        return result

    def _llm_first_analysis(self, request: AnalysisRequest, result: CoordinatedResult) -> CoordinatedResult:
        """Execute LLM-first analysis strategy."""
        logger.debug("Executing LLM-first analysis strategy")

        # Step 1: Deep LLM analysis
        if self.model_manager:
            result = self._add_llm_analysis(request, result)

            # Step 2: Use ML for validation/augmentation
            if self.ml_predictor and result.llm_results:
                try:
                    # Check if method exists, fallback to alternative
                    if hasattr(self.ml_predictor, 'predict_vulnerabilities'):
                        ml_results = self.ml_predictor.predict_vulnerabilities(request.binary_path)
                    elif hasattr(self.ml_predictor, 'predict'):
                        ml_results = self.ml_predictor.predict(request.binary_path)
                    else:
                        raise AttributeError("No prediction method available")
                    result.ml_results = ml_results

                    # Combine confidences (weighted toward LLM)
                    llm_confidence = result.llm_results.get("confidence", 0.8)
                    ml_confidence = ml_results.get("confidence", 0.0)
                    result.combined_confidence = 0.7 * llm_confidence + 0.3 * ml_confidence

                except (OSError, ValueError, RuntimeError) as e:
                    logger.error("ML validation failed: %s", e)

        return result

    def _parallel_analysis(self, request: AnalysisRequest, result: CoordinatedResult) -> CoordinatedResult:
        """Execute parallel analysis strategy."""
        logger.debug("Executing parallel analysis strategy")

        import queue

        # Create and start analysis threads
        ml_queue = queue.Queue()
        llm_queue = queue.Queue()
        threads = self._start_parallel_threads(request, ml_queue, llm_queue)

        # Collect results with timeout
        self._collect_parallel_results(request, result, ml_queue, llm_queue)

        # Ensure threads complete
        self._cleanup_threads(threads)

        return result

    def _start_parallel_threads(self, request: AnalysisRequest, ml_queue, llm_queue):
        """Start ML and LLM analysis threads."""
        ml_thread_obj = threading.Thread(target=self._ml_thread_worker, args=(request, ml_queue))  # pylint: disable=redefined-outer-name
        llm_thread_obj = threading.Thread(target=self._llm_thread_worker, args=(request, llm_queue))  # pylint: disable=redefined-outer-name

        ml_thread_obj.start()
        llm_thread_obj.start()

        return ml_thread_obj, llm_thread_obj

    def _ml_thread_worker(self, request: AnalysisRequest, ml_queue):
        """Worker function for ML analysis thread."""
        if self.ml_predictor:
            try:
                # Check if method exists, fallback to alternative
                if hasattr(self.ml_predictor, 'predict_vulnerabilities'):
                    ml_results = self.ml_predictor.predict_vulnerabilities(request.binary_path)
                elif hasattr(self.ml_predictor, 'predict'):
                    ml_results = self.ml_predictor.predict(request.binary_path)
                else:
                    raise AttributeError("No prediction method available")
                ml_queue.put(("success", ml_results))
            except (OSError, ValueError, RuntimeError) as e:
                ml_queue.put(("error", str(e)))
        else:
            ml_queue.put(("unavailable", None))

    def _llm_thread_worker(self, request: AnalysisRequest, llm_queue):
        """Worker function for LLM analysis thread."""
        if self.model_manager:
            try:
                llm_results = self._perform_llm_analysis(request)
                llm_queue.put(("success", llm_results))
            except (OSError, ValueError, RuntimeError) as e:
                llm_queue.put(("error", str(e)))
        else:
            llm_queue.put(("unavailable", None))

    def _collect_parallel_results(self, request: AnalysisRequest, result: CoordinatedResult, ml_queue, llm_queue):
        """Collect results from parallel analysis threads."""
        import queue

        try:
            # Get ML results
            ml_status, ml_data = ml_queue.get(timeout=request.max_processing_time / 2)
            if ml_status == "success":
                result.ml_results = ml_data

            # Get LLM results
            llm_status, llm_data = llm_queue.get(timeout=request.max_processing_time / 2)
            if llm_status == "success":
                result.llm_results = llm_data

            # Combine results
            self._combine_parallel_results(result)

        except queue.Empty:
            logger.warning("Parallel analysis timed out")

    def _combine_parallel_results(self, result: CoordinatedResult):
        """Combine ML and LLM results with confidence scoring."""
        if result.ml_results and result.llm_results:
            ml_conf = result.ml_results.get("confidence", 0.0)
            llm_conf = result.llm_results.get("confidence", 0.0)
            result.combined_confidence = max(ml_conf, llm_conf)
        elif result.ml_results:
            result.combined_confidence = result.ml_results.get("confidence", 0.0)
        elif result.llm_results:
            result.combined_confidence = result.llm_results.get("confidence", 0.0)

    def _cleanup_threads(self, threads):
        """Ensure all threads complete gracefully."""
        ml_thread_obj, llm_thread_obj = threads
        ml_thread_obj.join(timeout=1)
        llm_thread_obj.join(timeout=1)

    def _ml_only_analysis(self, request: AnalysisRequest, result: CoordinatedResult) -> CoordinatedResult:
        """Execute ML-only analysis strategy."""
        logger.debug("Executing ML-only analysis strategy")

        if self.ml_predictor:
            try:
                # Check if method exists, fallback to alternative
                if hasattr(self.ml_predictor, 'predict_vulnerabilities'):
                    ml_results = self.ml_predictor.predict_vulnerabilities(request.binary_path)
                elif hasattr(self.ml_predictor, 'predict'):
                    ml_results = self.ml_predictor.predict(request.binary_path)
                else:
                    raise AttributeError("No prediction method available")
                result.ml_results = ml_results
                result.combined_confidence = ml_results.get("confidence", 0.0)
                self.performance_stats["ml_calls"] += 1

            except (OSError, ValueError, RuntimeError) as e:
                logger.error("ML-only analysis failed: %s", e)

        return result

    def _llm_only_analysis(self, request: AnalysisRequest, result: CoordinatedResult) -> CoordinatedResult:
        """Execute LLM-only analysis strategy."""
        logger.debug("Executing LLM-only analysis strategy")

        if self.model_manager:
            result = self._add_llm_analysis(request, result)

        return result

    def _add_llm_analysis(self, request: AnalysisRequest, result: CoordinatedResult) -> CoordinatedResult:
        """Add LLM analysis to the result."""
        if not self.model_manager:
            return result

        llm_start = time.time()
        try:
            llm_results = self._perform_llm_analysis(request)
            result.llm_results = llm_results

            llm_time = time.time() - llm_start
            self.performance_stats["llm_calls"] += 1
            self.performance_stats["avg_llm_time"] = (
                (self.performance_stats["avg_llm_time"] * (self.performance_stats["llm_calls"] - 1) + llm_time) /
                self.performance_stats["llm_calls"]
            )

            # Update combined confidence
            if result.ml_results:
                # Weighted combination (ML: 30%, LLM: 70%)
                ml_conf = result.ml_results.get("confidence", 0.0)
                llm_conf = llm_results.get("confidence", 0.0)
                result.combined_confidence = 0.3 * ml_conf + 0.7 * llm_conf
            else:
                result.combined_confidence = llm_results.get("confidence", 0.0)

        except (OSError, ValueError, RuntimeError) as e:
            logger.error("LLM analysis failed: %s", e)

        return result

    def _perform_llm_analysis(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Perform LLM-based analysis using available language models."""
        try:
            from .llm_backends import LLMManager, LLMMessage

            # Check if we have an LLM manager available
            llm_manager = getattr(self, '_llm_manager', None)
            if not llm_manager:
                # Create a temporary LLM manager if one doesn't exist
                llm_manager = LLMManager()
                self._llm_manager = llm_manager

            # Get available LLMs
            available_llms = llm_manager.get_available_llms()
            if not available_llms:
                self.logger.warning("No LLM backends available for analysis")
                return self._fallback_analysis(request)

            # Prepare binary analysis prompt
            analysis_prompt = self._create_binary_analysis_prompt(request)

            # Create messages for LLM
            messages = [
                LLMMessage(
                    role="system",
                    content="You are a cybersecurity expert specializing in binary analysis and vulnerability research. "
                           "Analyze the provided binary information and identify potential security vulnerabilities, "
                           "exploitation techniques, and recommend appropriate security measures."
                ),
                LLMMessage(
                    role="user",
                    content=analysis_prompt
                )
            ]

            # Perform LLM analysis
            response = llm_manager.chat(messages)

            if response and response.content:
                # Parse LLM response and structure it
                analysis_result = self._parse_llm_response(response.content, request)

                # Increment performance stats
                self.performance_stats["llm_calls"] += 1

                return analysis_result
            else:
                self.logger.warning("No response from LLM, using fallback analysis")
                return self._fallback_analysis(request)

        except Exception as e:
            self.logger.error("LLM analysis failed: %s", e)
            return self._fallback_analysis(request)

    def _create_binary_analysis_prompt(self, request: AnalysisRequest) -> str:
        """Create analysis prompt for LLM based on binary information."""
        # Read basic binary information
        binary_info = []

        try:
            import os

            if os.path.exists(request.binary_path):
                file_size = os.path.getsize(request.binary_path)
                binary_info.append(f"File size: {file_size} bytes")

                # Try to get binary format
                try:
                    from ..utils.analysis.binary_analysis import identify_binary_format
                    binary_format = identify_binary_format(request.binary_path)
                    binary_info.append(f"Binary format: {binary_format}")
                except (ImportError, AttributeError, OSError) as e:
                    logger.debug("Binary format identification failed: %s", e)
                    binary_info.append("Binary format: Unknown")

                # Try to get file type info
                try:
                    import subprocess
                    result = subprocess.run(['file', request.binary_path],
                                          capture_output=True, text=True, timeout=5, check=False)
                    if result.returncode == 0:
                        binary_info.append(f"File type: {result.stdout.strip()}")
                except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError) as e:
                    logger.debug("File type detection failed: %s", e)
                    binary_info.append("File type: Detection unavailable")

        except Exception as e:
            self.logger.debug("Error gathering binary info: %s", e)

        # Build comprehensive prompt
        prompt = f"""
        Analyze the following binary file for security vulnerabilities and potential attack vectors:
        
        Binary Path: {request.binary_path}
        Analysis Priority: {request.priority}
        
        Binary Information:
        {chr(10).join(binary_info)}
        
        Please provide a detailed security analysis including:
        1. Potential vulnerabilities (buffer overflows, format strings, etc.)
        2. Attack vectors and exploitation techniques
        3. Security mitigations present or missing
        4. Recommendations for further analysis
        5. Risk assessment and priority level
        
        Format your response as a structured analysis with clear sections.
        """

        return prompt

    def _parse_llm_response(self, response_content: str, request: AnalysisRequest) -> Dict[str, Any]:
        """Parse LLM response into structured analysis result."""
        # Extract key information from LLM response
        # Parse using common AI response parser
        from .response_parser import parse_attack_vector_response
        vulnerabilities, recommendations, attack_vectors = parse_attack_vector_response(response_content)

        # Calculate confidence based on response quality
        confidence = min(0.95, 0.6 + (len(vulnerabilities) * 0.1) + (len(recommendations) * 0.05))

        return {
            "analysis_type": "llm_vulnerability_analysis",
            "binary_path": request.binary_path,
            "confidence": confidence,
            "vulnerabilities": vulnerabilities[:10],  # Limit to top 10
            "attack_vectors": attack_vectors[:5],     # Limit to top 5
            "recommendations": recommendations[:8],    # Limit to top 8
            "complex_patterns": [],  # Would be populated by more advanced analysis
            "reasoning": "Deep analysis performed using Large Language Model reasoning and pattern recognition",
            "raw_response": response_content[:1000],  # Store first 1000 chars for debugging
            "analysis_timestamp": self._get_timestamp()
        }

    def _fallback_analysis(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Fallback analysis when LLM is not available."""
        return {
            "analysis_type": "fallback_static_analysis",
            "binary_path": request.binary_path,
            "confidence": 0.6,
            "vulnerabilities": [
                "Unable to perform advanced LLM analysis - basic static analysis only",
                "Recommend manual code review for comprehensive security assessment"
            ],
            "attack_vectors": [],
            "recommendations": [
                "Install and configure LLM backend for enhanced analysis",
                "Perform manual static analysis with specialized tools",
                "Consider dynamic analysis and fuzzing"
            ],
            "reasoning": "Fallback analysis due to LLM unavailability",
            "analysis_timestamp": self._get_timestamp()
        }

    def _get_timestamp(self) -> str:
        """Get current timestamp for analysis."""
        return datetime.now().isoformat()

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get coordination layer performance statistics."""
        return {
            "ml_calls": self.performance_stats["ml_calls"],
            "llm_calls": self.performance_stats["llm_calls"],
            "escalations": self.performance_stats["escalations"],
            "cache_hits": self.performance_stats["cache_hits"],
            "avg_ml_time": self.performance_stats["avg_ml_time"],
            "avg_llm_time": self.performance_stats["avg_llm_time"],
            "cache_size": len(self.analysis_cache),
            "components_available": {
                "ml_predictor": self.ml_predictor is not None,
                "model_manager": self.model_manager is not None
            }
        }

    def clear_cache(self):
        """Clear the analysis cache."""
        self.analysis_cache.clear()
        logger.info("Analysis cache cleared")

    def suggest_strategy(self, binary_path: str, analysis_type: str) -> AnalysisStrategy:
        """Suggest the best analysis strategy for a given binary."""
        try:
            import os
            file_size = os.path.getsize(binary_path)

            # Strategy suggestions based on file characteristics
            if file_size > 100 * 1024 * 1024:  # > 100MB
                return AnalysisStrategy.ML_FIRST  # Large files benefit from fast initial scan
            if file_size < 512 * 1024:  # < 512KB
                return AnalysisStrategy.PARALLEL  # Small files can handle both
            elif analysis_type in ["license_analysis", "complex_patterns"]:
                return AnalysisStrategy.LLM_FIRST  # These need reasoning
            elif analysis_type in ["vulnerability_scan", "quick_check"]:
                return AnalysisStrategy.ML_FIRST  # These benefit from speed
            else:
                return AnalysisStrategy.ADAPTIVE  # Let the system decide

        except (OSError, ValueError, RuntimeError):
            return AnalysisStrategy.ADAPTIVE


# Convenience functions for _easy integration
def quick_vulnerability_scan(binary_path: str, confidence_threshold: float = 0.7) -> CoordinatedResult:
    """Quick vulnerability scan using coordination layer."""
    coordinator = AICoordinationLayer()
    request = AnalysisRequest(
        binary_path=binary_path,
        analysis_type="vulnerability_scan",
        strategy=AnalysisStrategy.ML_FIRST,
        confidence_threshold=confidence_threshold
    )
    return coordinator.analyze_vulnerabilities(request)


def comprehensive_analysis(binary_path: str) -> CoordinatedResult:
    """Comprehensive analysis using all available AI resources."""
    coordinator = AICoordinationLayer()
    request = AnalysisRequest(
        binary_path=binary_path,
        analysis_type="comprehensive",
        strategy=AnalysisStrategy.PARALLEL,
        confidence_threshold=0.8,
        max_processing_time=60.0
    )
    return coordinator.analyze_vulnerabilities(request)
