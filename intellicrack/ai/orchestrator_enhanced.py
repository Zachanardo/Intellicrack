"""
Enhanced Exploitation Orchestrator

Integrates all Phase 3 AI components for advanced automation and intelligent
script generation with multi-model consensus and continuous learning.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.analysis.unified_model.model import ProtectionInfo, UnifiedBinaryModel
from ..utils.logger import get_logger
from .ai_script_generator import ProtectionType, ScriptType
from .ai_script_generator_v2 import AIScriptGeneratorV2
from .architecture_translator import Architecture, ArchitectureTranslator, ScriptLanguage, TranslationContext
from .bypass_strategy_engine import BypassStrategyEngine
from .consensus_engine import ConsensusMode, ConsensusQuery, ModelExpertise, MultiModelConsensusEngine
from .domain_model_manager import DomainModelManager, ProtectionDomain
from .exploitation_orchestrator import ExploitationOrchestrator
from .feedback_loop_engine import ExecutionStatus, FeedbackLoopEngine, ScriptExecutionResult
from .script_testing_sandbox import ScriptTestingSandbox, SandboxConfig, ValidationResult

logger = get_logger(__name__)


@dataclass
class OrchestrationConfig:
    """Configuration for enhanced orchestration"""
    use_consensus: bool = True
    consensus_mode: ConsensusMode = ConsensusMode.EXPERT_PRIORITY
    minimum_consensus_models: int = 3
    use_domain_models: bool = True
    enable_feedback_loop: bool = True
    translate_scripts: bool = True
    target_architectures: List[Architecture] = None
    script_testing_enabled: bool = True
    max_retry_attempts: int = 3
    sandbox_config: Optional[SandboxConfig] = None
    validate_before_execution: bool = True
    
    def __post_init__(self):
        if self.target_architectures is None:
            self.target_architectures = [Architecture.X86, Architecture.X64]
        if self.sandbox_config is None:
            self.sandbox_config = SandboxConfig()


class EnhancedExploitationOrchestrator(ExploitationOrchestrator):
    """Enhanced orchestrator with Phase 3 AI capabilities"""
    
    def __init__(self, ai_model=None):
        super().__init__(ai_model)
        
        # Initialize Phase 3 components
        self.consensus_engine = MultiModelConsensusEngine()
        self.script_generator_v2 = AIScriptGeneratorV2()
        self.bypass_engine = BypassStrategyEngine()
        self.architecture_translator = ArchitectureTranslator()
        self.feedback_loop = FeedbackLoopEngine()
        self.domain_manager = DomainModelManager()
        self.script_sandbox = None  # Initialize on demand
        
        # Enhanced state tracking
        self.script_cache: Dict[str, Any] = {}
        self.translation_cache: Dict[str, Any] = {}
        self.bypass_strategies: Dict[str, Any] = {}
        self.validation_reports: Dict[str, Any] = {}
        
        logger.info("Enhanced orchestrator initialized with Phase 3 components")
    
    def orchestrate_with_phase3(self, target_info: Dict[str, Any], 
                               unified_model: UnifiedBinaryModel,
                               config: Optional[OrchestrationConfig] = None) -> Dict[str, Any]:
        """Execute orchestration with Phase 3 enhancements"""
        
        if not config:
            config = OrchestrationConfig()
        
        orchestration_id = f"enhanced_{int(time.time())}"
        
        result = {
            "orchestration_id": orchestration_id,
            "success": False,
            "target_info": target_info,
            "phases": {},
            "generated_scripts": [],
            "bypass_strategies": [],
            "consensus_results": [],
            "translations": [],
            "validation_reports": [],
            "feedback_applied": False,
            "errors": [],
            "warnings": [],
            "timeline": [],
            "metrics": {}
        }
        
        try:
            start_time = time.time()
            
            # Phase 1: Protection Analysis with Domain Models
            logger.info(f"[{orchestration_id}] Starting protection analysis")
            protection_phase = self._analyze_protections_with_domain_models(
                unified_model, config
            )
            result["phases"]["protection_analysis"] = protection_phase
            result["timeline"].append({
                "phase": "protection_analysis",
                "timestamp": time.time() - start_time,
                "status": "completed" if protection_phase["success"] else "failed"
            })
            
            if not protection_phase["success"]:
                result["errors"].append(f"Protection analysis failed: {protection_phase.get('error')}")
                return result
            
            # Phase 2: Generate Bypass Strategies
            logger.info(f"[{orchestration_id}] Generating bypass strategies")
            bypass_phase = self._generate_bypass_strategies(
                unified_model, protection_phase["protections"], config
            )
            result["phases"]["bypass_generation"] = bypass_phase
            result["bypass_strategies"] = bypass_phase["strategies"]
            result["timeline"].append({
                "phase": "bypass_generation",
                "timestamp": time.time() - start_time,
                "status": "completed" if bypass_phase["success"] else "failed"
            })
            
            # Phase 3: Generate Scripts with Consensus
            logger.info(f"[{orchestration_id}] Generating scripts with consensus")
            script_phase = self._generate_scripts_with_consensus(
                unified_model, bypass_phase["strategies"], config
            )
            result["phases"]["script_generation"] = script_phase
            result["generated_scripts"] = script_phase["scripts"]
            result["consensus_results"] = script_phase["consensus_results"]
            result["timeline"].append({
                "phase": "script_generation",
                "timestamp": time.time() - start_time,
                "status": "completed" if script_phase["success"] else "failed"
            })
            
            # Phase 4: Script Validation
            if config.validate_before_execution and script_phase["success"]:
                logger.info(f"[{orchestration_id}] Validating generated scripts in sandbox")
                validation_phase = self._validate_scripts_in_sandbox(
                    script_phase["scripts"], unified_model, config
                )
                result["phases"]["script_validation"] = validation_phase
                result["validation_reports"] = validation_phase["validation_reports"]
                result["timeline"].append({
                    "phase": "script_validation",
                    "timestamp": time.time() - start_time,
                    "status": "completed" if validation_phase["success"] else "failed"
                })
                
                # Filter out scripts that failed validation
                if validation_phase["success"]:
                    validated_scripts = []
                    for i, script in enumerate(script_phase["scripts"]):
                        if i < len(validation_phase["validation_reports"]):
                            report = validation_phase["validation_reports"][i]
                            if report["validation_result"] in ["passed", "warning"]:
                                validated_scripts.append(script)
                            else:
                                result["warnings"].append(f"Script filtered due to validation failure: {report['script_id']}")
                    
                    # Update scripts list with validated scripts only
                    script_phase["scripts"] = validated_scripts
                    result["generated_scripts"] = validated_scripts
            
            # Phase 5: Architecture Translation
            if config.translate_scripts and script_phase["success"]:
                logger.info(f"[{orchestration_id}] Translating scripts for target architectures")
                translation_phase = self._translate_scripts_for_architectures(
                    script_phase["scripts"], unified_model, config
                )
                result["phases"]["translation"] = translation_phase
                result["translations"] = translation_phase["translations"]
                result["timeline"].append({
                    "phase": "translation",
                    "timestamp": time.time() - start_time,
                    "status": "completed" if translation_phase["success"] else "failed"
                })
            
            # Phase 6: Apply Feedback Loop Learning
            if config.enable_feedback_loop:
                logger.info(f"[{orchestration_id}] Applying feedback loop enhancements")
                feedback_phase = self._apply_feedback_loop_enhancements(
                    script_phase["scripts"], unified_model
                )
                result["phases"]["feedback_enhancement"] = feedback_phase
                result["feedback_applied"] = feedback_phase["success"]
                result["timeline"].append({
                    "phase": "feedback_enhancement",
                    "timestamp": time.time() - start_time,
                    "status": "completed" if feedback_phase["success"] else "failed"
                })
            
            # Phase 7: Execute Traditional Orchestration
            logger.info(f"[{orchestration_id}] Executing traditional exploitation phases")
            traditional_result = super().orchestrate_full_exploitation(
                target_info, 
                {
                    "enhanced_scripts": result["generated_scripts"],
                    "bypass_strategies": result["bypass_strategies"],
                    "ai_insights": protection_phase.get("ai_insights", {})
                }
            )
            
            # Merge results
            result["phases"]["traditional_exploitation"] = traditional_result
            result["success"] = traditional_result["success"]
            
            # Phase 8: Record Execution Results for Learning
            if config.enable_feedback_loop and result["success"]:
                self._record_execution_feedback(
                    result["generated_scripts"],
                    traditional_result,
                    unified_model
                )
            
            # Calculate final metrics
            result["metrics"] = self._calculate_enhanced_metrics(result, time.time() - start_time)
            
            logger.info(f"[{orchestration_id}] Enhanced orchestration completed - Success: {result['success']}")
            
        except Exception as e:
            logger.error(f"[{orchestration_id}] Enhanced orchestration failed: {e}")
            result["errors"].append(str(e))
            result["success"] = False
        
        return result
    
    def _analyze_protections_with_domain_models(self, unified_model: UnifiedBinaryModel,
                                              config: OrchestrationConfig) -> Dict[str, Any]:
        """Analyze protections using domain-specific models"""
        
        result = {
            "success": False,
            "protections": [],
            "domain_analyses": {},
            "ai_insights": {},
            "error": None
        }
        
        try:
            # Get all detected protections
            protections = list(unified_model.protection_analysis.protections.values())
            result["protections"] = protections
            
            # Use domain models if enabled
            if config.use_domain_models:
                for protection in protections:
                    domain_analysis = self.domain_manager.analyze_with_domain_model(
                        protection, unified_model
                    )
                    result["domain_analyses"][protection.name] = domain_analysis
                    
                    # Extract AI insights
                    if "findings" in domain_analysis:
                        result["ai_insights"][protection.name] = domain_analysis["findings"]
            
            # Use consensus for overall protection assessment
            if config.use_consensus:
                consensus_query = ConsensusQuery(
                    query_id=f"protection_assessment_{int(time.time())}",
                    prompt=f"Assess the overall protection scheme for binary with {len(protections)} protections",
                    query_type="protection_analysis",
                    context_data={
                        "protections": [p.__dict__ for p in protections],
                        "binary_info": unified_model.metadata.__dict__
                    },
                    required_expertise={ModelExpertise.REVERSE_ENGINEERING, ModelExpertise.MALWARE_ANALYSIS},
                    minimum_models=config.minimum_consensus_models,
                    consensus_mode=config.consensus_mode
                )
                
                consensus_result = asyncio.run(
                    self.consensus_engine.process_consensus_query(consensus_query)
                )
                
                result["ai_insights"]["consensus_assessment"] = {
                    "confidence": consensus_result.consensus_confidence,
                    "agreement": consensus_result.agreement_score,
                    "content": consensus_result.consensus_content
                }
            
            result["success"] = True
            
        except Exception as e:
            logger.error(f"Protection analysis with domain models failed: {e}")
            result["error"] = str(e)
        
        return result
    
    def _generate_bypass_strategies(self, unified_model: UnifiedBinaryModel,
                                   protections: List[ProtectionInfo],
                                   config: OrchestrationConfig) -> Dict[str, Any]:
        """Generate bypass strategies for detected protections"""
        
        result = {
            "success": False,
            "strategies": [],
            "error": None
        }
        
        try:
            for protection in protections:
                # Generate bypass strategy
                bypass_strategy = self.bypass_engine.create_bypass_strategy(
                    protection, unified_model
                )
                
                # Get domain-specific strategy if available
                domain_strategy = self.domain_manager.generate_domain_bypass_strategy(
                    protection, unified_model
                )
                
                # Merge strategies
                if domain_strategy and domain_strategy.get("steps"):
                    bypass_strategy.alternative_approaches.append({
                        "name": f"Domain-specific approach ({domain_strategy['domain']})",
                        "steps": domain_strategy["steps"],
                        "confidence": domain_strategy.get("success_probability", 0.7)
                    })
                
                result["strategies"].append(bypass_strategy)
            
            result["success"] = len(result["strategies"]) > 0
            
        except Exception as e:
            logger.error(f"Bypass strategy generation failed: {e}")
            result["error"] = str(e)
        
        return result
    
    def _generate_scripts_with_consensus(self, unified_model: UnifiedBinaryModel,
                                       bypass_strategies: List[Any],
                                       config: OrchestrationConfig) -> Dict[str, Any]:
        """Generate scripts using consensus and context-aware generation"""
        
        result = {
            "success": False,
            "scripts": [],
            "consensus_results": [],
            "error": None
        }
        
        try:
            # Determine script types to generate
            script_types = [ScriptType.FRIDA, ScriptType.GHIDRA, ScriptType.IDA_PYTHON]
            
            for script_type in script_types:
                # Determine primary protection to target
                primary_protection = None
                if bypass_strategies:
                    # Use the highest complexity protection
                    primary_strategy = max(
                        bypass_strategies, 
                        key=lambda s: s.complexity_score
                    )
                    primary_protection = self._map_to_protection_type(
                        primary_strategy.protection_info
                    )
                
                # Generate script with context
                generation_result = self.script_generator_v2.generate_script_with_context(
                    unified_model=unified_model,
                    script_type=script_type,
                    target_protection=primary_protection
                )
                
                if generation_result.success and generation_result.scripts:
                    script = generation_result.scripts[0]
                    script.metadata["generation_method"] = "enhanced_v2"
                    script.metadata["has_context"] = True
                    result["scripts"].append(script)
                    
                    # Store consensus metadata
                    if "consensus_agreement" in generation_result.metadata:
                        result["consensus_results"].append({
                            "script_type": script_type.value,
                            "agreement": generation_result.metadata["consensus_agreement"],
                            "confidence": generation_result.ai_confidence,
                            "models_used": generation_result.metadata.get("models_used", 0)
                        })
            
            result["success"] = len(result["scripts"]) > 0
            
        except Exception as e:
            logger.error(f"Script generation with consensus failed: {e}")
            result["error"] = str(e)
        
        return result
    
    def _validate_scripts_in_sandbox(self, scripts: List[Any],
                                   unified_model: UnifiedBinaryModel,
                                   config: OrchestrationConfig) -> Dict[str, Any]:
        """Validate scripts in sandbox environment"""
        
        result = {
            "success": False,
            "validation_reports": [],
            "passed_scripts": 0,
            "failed_scripts": 0,
            "error": None
        }
        
        try:
            # Initialize sandbox if not already done
            if not self.script_sandbox:
                self.script_sandbox = ScriptTestingSandbox(config.sandbox_config)
            
            # Validate each script
            validation_reports = self.script_sandbox.batch_validate_scripts(
                scripts, unified_model
            )
            
            # Convert validation reports to serializable format
            for report in validation_reports:
                report_dict = {
                    "script_id": report.script_id,
                    "script_type": report.script_type.value,
                    "validation_result": report.validation_result.value,
                    "risk_level": report.security_analysis.risk_level.value,
                    "safe_to_execute": report.security_analysis.safe_to_execute,
                    "detected_risks": report.security_analysis.detected_risks,
                    "syntax_errors": report.syntax_errors,
                    "runtime_errors": report.runtime_errors,
                    "warnings": report.warnings,
                    "validation_time": report.validation_time,
                    "timestamp": report.timestamp
                }
                
                # Add performance metrics if available
                if report.performance_metrics:
                    report_dict["performance_metrics"] = {
                        "execution_time": report.performance_metrics.execution_time,
                        "peak_memory_usage": report.performance_metrics.peak_memory_usage,
                        "average_cpu_usage": report.performance_metrics.average_cpu_usage,
                        "peak_cpu_usage": report.performance_metrics.peak_cpu_usage
                    }
                
                result["validation_reports"].append(report_dict)
                
                # Count results
                if report.validation_result == ValidationResult.PASSED:
                    result["passed_scripts"] += 1
                else:
                    result["failed_scripts"] += 1
            
            # Store validation reports for future reference
            for report_dict in result["validation_reports"]:
                self.validation_reports[report_dict["script_id"]] = report_dict
            
            result["success"] = True
            
        except Exception as e:
            logger.error(f"Script validation in sandbox failed: {e}")
            result["error"] = str(e)
        
        return result
    
    def _translate_scripts_for_architectures(self, scripts: List[Any],
                                           unified_model: UnifiedBinaryModel,
                                           config: OrchestrationConfig) -> Dict[str, Any]:
        """Translate scripts for different target architectures"""
        
        result = {
            "success": False,
            "translations": [],
            "error": None
        }
        
        try:
            source_arch = self._get_architecture_enum(unified_model.metadata.architecture)
            
            for script in scripts:
                for target_arch in config.target_architectures:
                    if target_arch != source_arch:
                        # Create translation context
                        context = TranslationContext(
                            source_script=script.content,
                            source_language=self._map_script_type_to_language(script.script_type),
                            source_arch=source_arch,
                            target_arch=target_arch,
                            unified_model=unified_model,
                            optimize_for_target=True
                        )
                        
                        # Perform translation
                        translation_result = self.architecture_translator.translate_script(context)
                        
                        if translation_result.success:
                            result["translations"].append({
                                "original_script_type": script.script_type.value,
                                "source_arch": source_arch.value,
                                "target_arch": target_arch.value,
                                "translated_script": translation_result.translated_script,
                                "confidence": translation_result.confidence,
                                "warnings": translation_result.warnings
                            })
            
            result["success"] = True
            
        except Exception as e:
            logger.error(f"Script translation failed: {e}")
            result["error"] = str(e)
        
        return result
    
    def _apply_feedback_loop_enhancements(self, scripts: List[Any],
                                         unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Apply feedback loop learning to enhance scripts"""
        
        result = {
            "success": False,
            "enhanced_count": 0,
            "error": None
        }
        
        try:
            for script in scripts:
                # Enhance script with learned patterns
                enhanced_script = self.feedback_loop.enhance_script_with_knowledge(
                    script, unified_model
                )
                
                if enhanced_script.metadata.get("knowledge_enhanced"):
                    result["enhanced_count"] += 1
            
            result["success"] = True
            
        except Exception as e:
            logger.error(f"Feedback loop enhancement failed: {e}")
            result["error"] = str(e)
        
        return result
    
    def _record_execution_feedback(self, scripts: List[Any], 
                                 execution_result: Dict[str, Any],
                                 unified_model: UnifiedBinaryModel):
        """Record execution results for continuous learning"""
        
        try:
            for script in scripts:
                # Create execution result
                exec_result = ScriptExecutionResult(
                    script_id=script.metadata.get("script_id", "unknown"),
                    script_type=script.script_type,
                    target_protection=script.target_protection,
                    execution_status=ExecutionStatus.SUCCESS if execution_result["success"] else ExecutionStatus.FAILURE,
                    execution_time=execution_result.get("metrics", {}).get("total_time", 0.0),
                    output=str(execution_result.get("phases", {})),
                    protection_bypassed=execution_result["success"],
                    binary_hash=unified_model.metadata.sha256,
                    architecture=unified_model.metadata.architecture
                )
                
                # Record feedback
                self.feedback_loop.record_execution_result(script, exec_result)
                
        except Exception as e:
            logger.error(f"Failed to record execution feedback: {e}")
    
    def _calculate_enhanced_metrics(self, result: Dict[str, Any], total_time: float) -> Dict[str, Any]:
        """Calculate enhanced orchestration metrics"""
        
        metrics = {
            "total_execution_time": total_time,
            "phases_completed": len([p for p in result["phases"].values() if p.get("success", False)]),
            "total_phases": len(result["phases"]),
            "scripts_generated": len(result["generated_scripts"]),
            "bypass_strategies": len(result["bypass_strategies"]),
            "translations_performed": len(result["translations"]),
            "consensus_average_agreement": 0.0,
            "consensus_average_confidence": 0.0,
            "feedback_enhancements": result["phases"].get("feedback_enhancement", {}).get("enhanced_count", 0)
        }
        
        # Calculate consensus metrics
        if result["consensus_results"]:
            metrics["consensus_average_agreement"] = sum(
                c["agreement"] for c in result["consensus_results"]
            ) / len(result["consensus_results"])
            
            metrics["consensus_average_confidence"] = sum(
                c["confidence"] for c in result["consensus_results"]
            ) / len(result["consensus_results"])
        
        return metrics
    
    def _map_to_protection_type(self, protection_info: ProtectionInfo) -> Optional[ProtectionType]:
        """Map ProtectionInfo to ProtectionType enum"""
        
        type_mapping = {
            "license": ProtectionType.LICENSE_CHECK,
            "trial": ProtectionType.TRIAL_TIMER,
            "hardware": ProtectionType.HARDWARE_LOCK,
            "network": ProtectionType.NETWORK_AUTH,
            "vm": ProtectionType.VM_DETECTION,
            "debug": ProtectionType.ANTI_DEBUG,
            "obfuscation": ProtectionType.OBFUSCATION,
            "crypto": ProtectionType.CRYPTOGRAPHIC
        }
        
        for key, prot_type in type_mapping.items():
            if key in protection_info.type.lower():
                return prot_type
        
        return None
    
    def _get_architecture_enum(self, arch_str: str) -> Architecture:
        """Convert architecture string to enum"""
        
        arch_lower = arch_str.lower()
        
        if "x64" in arch_lower or "amd64" in arch_lower or "x86_64" in arch_lower:
            return Architecture.X64
        elif "x86" in arch_lower or "i386" in arch_lower:
            return Architecture.X86
        elif "arm64" in arch_lower or "aarch64" in arch_lower:
            return Architecture.ARM64
        elif "arm" in arch_lower:
            return Architecture.ARM
        elif "mips64" in arch_lower:
            return Architecture.MIPS64
        elif "mips" in arch_lower:
            return Architecture.MIPS
        else:
            return Architecture.X86  # Default
    
    def _map_script_type_to_language(self, script_type: ScriptType) -> ScriptLanguage:
        """Map ScriptType to ScriptLanguage"""
        
        mapping = {
            ScriptType.FRIDA: ScriptLanguage.FRIDA,
            ScriptType.GHIDRA: ScriptLanguage.GHIDRA,
            ScriptType.IDA_PYTHON: ScriptLanguage.IDA_PYTHON,
            ScriptType.RADARE2: ScriptLanguage.RADARE2
        }
        
        return mapping.get(script_type, ScriptLanguage.FRIDA)
    
    def get_phase3_statistics(self) -> Dict[str, Any]:
        """Get statistics from all Phase 3 components"""
        
        stats = {
            "consensus_engine": self.consensus_engine.get_model_performance_stats(),
            "domain_models": self.domain_manager.get_domain_statistics(),
            "feedback_loop": self.feedback_loop.generate_performance_report(),
            "script_cache_size": len(self.script_cache),
            "translation_cache_size": len(self.translation_cache),
            "bypass_strategies_cached": len(self.bypass_strategies),
            "validation_reports_cached": len(self.validation_reports)
        }
        
        # Add sandbox statistics if available
        if self.script_sandbox:
            stats["sandbox_statistics"] = self.script_sandbox.get_validation_statistics()
        
        return stats
    
    def optimize_models(self):
        """Optimize all AI models based on performance"""
        
        # Optimize consensus model selection
        self.consensus_engine.optimize_model_selection()
        
        # Process feedback buffer
        self.feedback_loop._process_feedback_buffer()
        
        logger.info("AI models optimized based on performance metrics")
    
    def cleanup_resources(self):
        """Clean up all Phase 3 resources"""
        
        # Cleanup sandbox
        if self.script_sandbox:
            self.script_sandbox.cleanup_sandbox()
            self.script_sandbox = None
        
        # Clear caches
        self.script_cache.clear()
        self.translation_cache.clear()
        self.bypass_strategies.clear()
        self.validation_reports.clear()
        
        logger.info("Phase 3 resources cleaned up")
    
    def __del__(self):
        """Cleanup on destruction"""
        try:
            self.cleanup_resources()
        except Exception:
            pass