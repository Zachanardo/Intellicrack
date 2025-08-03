"""
AI-Driven Protection Bypass Advisor

Intelligent recommendation system for protection bypass strategies.
Provides context-aware bypass suggestions based on detected protections,
generates step-by-step bypass procedures with confidence ratings,
and supports defensive research to help developers strengthen their protections.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import hashlib
import json
import time
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.analysis.unified_model.model import (
    UnifiedBinaryModel, ProtectionInfo, FunctionInfo, ImportInfo, 
    ExportInfo, SectionInfo, StringInfo
)
from ..utils.logger import get_logger
from .bypass_strategy_engine import (
    BypassStrategy, BypassTechnique, BypassComplexity, 
    BypassRisk, BypassStep, BypassStrategyEngine
)
from .predictive_intelligence import PredictiveIntelligenceEngine, PredictionType
from .multi_agent_system import MultiAgentSystem

logger = get_logger(__name__)

try:
    from .llm_backends import get_llm_manager
    from .ai_script_generator import AIScriptGenerator, ProtectionType, ScriptType
    LLM_AVAILABLE = True
except ImportError:
    logger.warning("LLM backends not available - using rule-based recommendations only")
    get_llm_manager = None
    LLM_AVAILABLE = False


class RecommendationType(Enum):
    """Types of bypass recommendations"""
    IMMEDIATE_BYPASS = "immediate_bypass"
    STRATEGIC_ANALYSIS = "strategic_analysis"  
    VULNERABILITY_EXPLOITATION = "vulnerability_exploitation"
    TOOL_RECOMMENDATION = "tool_recommendation"
    EDUCATIONAL_GUIDANCE = "educational_guidance"
    DEFENSIVE_ASSESSMENT = "defensive_assessment"


class ConfidenceLevel(Enum):
    """Confidence levels for recommendations"""
    VERY_LOW = 0.1
    LOW = 0.3
    MEDIUM = 0.5
    HIGH = 0.7
    VERY_HIGH = 0.9


class RecommendationPriority(Enum):
    """Priority levels for recommendations"""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFORMATIONAL = 5


@dataclass
class BypassRecommendation:
    """A single bypass recommendation with detailed guidance"""
    recommendation_id: str
    title: str
    description: str
    type: RecommendationType
    priority: RecommendationPriority
    confidence: ConfidenceLevel
    
    # Target information
    target_protection: ProtectionInfo
    target_functions: List[str] = field(default_factory=list)
    target_imports: List[str] = field(default_factory=list)
    
    # Implementation details
    technique: BypassTechnique
    implementation_steps: List[str] = field(default_factory=list)
    code_example: Optional[str] = None
    script_template: Optional[str] = None
    
    # Requirements and tools
    prerequisites: List[str] = field(default_factory=list)
    tools_required: List[str] = field(default_factory=list)
    skill_level: str = "Intermediate"
    
    # Risk and success assessment
    risk_level: BypassRisk = BypassRisk.MEDIUM
    success_probability: float = 0.5
    estimated_time: str = "Unknown"
    
    # Educational context
    educational_notes: List[str] = field(default_factory=list)
    security_implications: List[str] = field(default_factory=list)
    mitigation_advice: List[str] = field(default_factory=list)
    
    # Metadata
    generation_timestamp: float = field(default_factory=time.time)
    ai_model_used: Optional[str] = None
    related_cves: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert recommendation to dictionary format"""
        return {
            "recommendation_id": self.recommendation_id,
            "title": self.title,
            "description": self.description,
            "type": self.type.value,
            "priority": self.priority.value,
            "confidence": self.confidence.value,
            "target_protection": {
                "name": self.target_protection.name,
                "type": self.target_protection.type,
                "confidence": self.target_protection.confidence
            },
            "target_functions": self.target_functions,
            "target_imports": self.target_imports,
            "technique": self.technique.value,
            "implementation_steps": self.implementation_steps,
            "code_example": self.code_example,
            "script_template": self.script_template,
            "prerequisites": self.prerequisites,
            "tools_required": self.tools_required,
            "skill_level": self.skill_level,
            "risk_level": self.risk_level.value,
            "success_probability": self.success_probability,
            "estimated_time": self.estimated_time,
            "educational_notes": self.educational_notes,
            "security_implications": self.security_implications,
            "mitigation_advice": self.mitigation_advice,
            "generation_timestamp": self.generation_timestamp,
            "ai_model_used": self.ai_model_used,
            "related_cves": self.related_cves
        }


@dataclass
class BypassAnalysisResult:
    """Result of comprehensive bypass analysis"""
    binary_hash: str
    analysis_timestamp: float
    total_protections: int
    
    # Recommendations by category
    immediate_bypasses: List[BypassRecommendation] = field(default_factory=list)
    strategic_recommendations: List[BypassRecommendation] = field(default_factory=list)
    vulnerability_exploits: List[BypassRecommendation] = field(default_factory=list)
    tool_suggestions: List[BypassRecommendation] = field(default_factory=list)
    educational_content: List[BypassRecommendation] = field(default_factory=list)
    
    # Overall assessment
    overall_bypass_difficulty: BypassComplexity = BypassComplexity.MODERATE
    overall_success_probability: float = 0.5
    recommended_approach: str = ""
    
    # Defensive insights
    protection_strengths: List[str] = field(default_factory=list)
    protection_weaknesses: List[str] = field(default_factory=list)
    improvement_suggestions: List[str] = field(default_factory=list)
    
    def get_all_recommendations(self) -> List[BypassRecommendation]:
        """Get all recommendations sorted by priority"""
        all_recs = (
            self.immediate_bypasses + 
            self.strategic_recommendations + 
            self.vulnerability_exploits + 
            self.tool_suggestions + 
            self.educational_content
        )
        return sorted(all_recs, key=lambda r: (r.priority.value, -r.confidence.value))
    
    def get_high_confidence_recommendations(self, min_confidence: float = 0.7) -> List[BypassRecommendation]:
        """Get recommendations above confidence threshold"""
        return [r for r in self.get_all_recommendations() 
                if r.confidence.value >= min_confidence]


class ProtectionBypassAdvisor:
    """
    AI-driven protection bypass advisor that provides intelligent recommendations
    for bypass strategies, vulnerability exploitation, and defensive assessment.
    """
    
    def __init__(self):
        """Initialize the bypass advisor with AI components"""
        self.bypass_strategy_engine = BypassStrategyEngine()
        self.predictive_engine = PredictiveIntelligenceEngine()
        self.multi_agent_system = MultiAgentSystem()
        
        # AI components (loaded on demand)
        self._llm_manager = None
        self._script_generator = None
        
        # Knowledge bases
        self.protection_knowledge = self._load_protection_knowledge()
        self.bypass_patterns = self._load_bypass_patterns()
        self.vulnerability_database = self._load_vulnerability_database()
        
        # Recommendation cache
        self.recommendation_cache: Dict[str, BypassAnalysisResult] = {}
        self.learning_history: List[Dict[str, Any]] = []
        
        # Success tracking for learning
        self.success_tracker = defaultdict(list)
        self.performance_metrics = defaultdict(float)
        
        logger.info("Protection Bypass Advisor initialized")
    
    @property
    def llm_manager(self):
        """Lazy load LLM manager"""
        if self._llm_manager is None and LLM_AVAILABLE:
            self._llm_manager = get_llm_manager()
        return self._llm_manager
    
    @property
    def script_generator(self):
        """Lazy load script generator"""
        if self._script_generator is None:
            try:
                self._script_generator = AIScriptGenerator()
            except Exception as e:
                logger.warning(f"Failed to initialize script generator: {e}")
        return self._script_generator
    
    def analyze_and_recommend(self, binary_model: UnifiedBinaryModel) -> BypassAnalysisResult:
        """
        Perform comprehensive bypass analysis and generate recommendations
        
        Args:
            binary_model: Unified binary model from analysis
            
        Returns:
            Comprehensive bypass analysis result with categorized recommendations
        """
        start_time = time.time()
        logger.info(f"Starting bypass analysis for {binary_model.metadata.filename}")
        
        # Check cache first
        cache_key = self._generate_cache_key(binary_model)
        if cache_key in self.recommendation_cache:
            cached_result = self.recommendation_cache[cache_key]
            logger.info("Returning cached bypass analysis")
            return cached_result
        
        # Initialize result
        result = BypassAnalysisResult(
            binary_hash=binary_model.metadata.sha256,
            analysis_timestamp=start_time,
            total_protections=len(binary_model.protection_analysis.detected_protections)
        )
        
        # Analyze each detected protection
        for protection in binary_model.protection_analysis.detected_protections:
            self._analyze_single_protection(protection, binary_model, result)
        
        # Generate strategic recommendations
        self._generate_strategic_recommendations(binary_model, result)
        
        # Assess vulnerability exploitation opportunities
        self._analyze_vulnerability_opportunities(binary_model, result)
        
        # Recommend tools and techniques
        self._recommend_tools_and_techniques(binary_model, result)
        
        # Generate educational content
        self._generate_educational_content(binary_model, result)
        
        # Perform overall assessment
        self._perform_overall_assessment(binary_model, result)
        
        # Generate defensive insights
        self._generate_defensive_insights(binary_model, result)
        
        # Cache result
        self.recommendation_cache[cache_key] = result
        
        analysis_time = time.time() - start_time
        logger.info(f"Bypass analysis completed in {analysis_time:.2f}s - "
                   f"Generated {len(result.get_all_recommendations())} recommendations")
        
        return result
    
    def _analyze_single_protection(self, protection: ProtectionInfo, 
                                 binary_model: UnifiedBinaryModel,
                                 result: BypassAnalysisResult):
        """Analyze a single protection and generate specific recommendations"""
        
        logger.debug(f"Analyzing protection: {protection.name} ({protection.type})")
        
        # Generate bypass strategy using strategy engine
        strategy = self.bypass_strategy_engine.create_bypass_strategy(protection, binary_model)
        
        # Convert strategy to immediate bypass recommendations
        if strategy and strategy.success_probability > 0.3:
            immediate_rec = self._strategy_to_recommendation(
                strategy, protection, RecommendationType.IMMEDIATE_BYPASS
            )
            result.immediate_bypasses.append(immediate_rec)
        
        # Analyze protection-specific patterns
        self._analyze_protection_patterns(protection, binary_model, result)
        
        # Use AI for advanced analysis if available
        if self.llm_manager:
            self._ai_enhanced_analysis(protection, binary_model, result)
    
    def _strategy_to_recommendation(self, strategy: BypassStrategy, 
                                  protection: ProtectionInfo,
                                  rec_type: RecommendationType) -> BypassRecommendation:
        """Convert bypass strategy to recommendation format"""
        
        # Determine priority based on success probability and complexity
        if strategy.success_probability > 0.8 and strategy.complexity in [BypassComplexity.TRIVIAL, BypassComplexity.SIMPLE]:
            priority = RecommendationPriority.HIGH
        elif strategy.success_probability > 0.6:
            priority = RecommendationPriority.MEDIUM
        else:
            priority = RecommendationPriority.LOW
        
        # Map complexity to confidence
        confidence_mapping = {
            BypassComplexity.TRIVIAL: ConfidenceLevel.VERY_HIGH,
            BypassComplexity.SIMPLE: ConfidenceLevel.HIGH,
            BypassComplexity.MODERATE: ConfidenceLevel.MEDIUM,
            BypassComplexity.COMPLEX: ConfidenceLevel.LOW,
            BypassComplexity.ADVANCED: ConfidenceLevel.VERY_LOW
        }
        confidence = confidence_mapping.get(strategy.complexity, ConfidenceLevel.MEDIUM)
        
        # Extract implementation details
        implementation_steps = [step.description for step in strategy.steps]
        code_example = self._generate_code_example(strategy)
        
        # Create recommendation
        rec = BypassRecommendation(
            recommendation_id=f"rec_{strategy.strategy_id}",
            title=strategy.name,
            description=strategy.description,
            type=rec_type,
            priority=priority,
            confidence=confidence,
            target_protection=protection,
            technique=strategy.steps[0].technique if strategy.steps else BypassTechnique.DYNAMIC_HOOKING,
            implementation_steps=implementation_steps,
            code_example=code_example,
            prerequisites=strategy.prerequisites,
            tools_required=list(strategy.tools_required),
            risk_level=strategy.steps[0].risk_level if strategy.steps else BypassRisk.MEDIUM,
            success_probability=strategy.success_probability,
            estimated_time=strategy.estimated_time,
            ai_model_used="BypassStrategyEngine"
        )
        
        # Add educational context
        rec.educational_notes = self._generate_educational_notes(strategy, protection)
        rec.security_implications = self._generate_security_implications(strategy, protection)
        rec.mitigation_advice = self._generate_mitigation_advice(strategy, protection)
        
        return rec
    
    def _analyze_protection_patterns(self, protection: ProtectionInfo,
                                   binary_model: UnifiedBinaryModel,
                                   result: BypassAnalysisResult):
        """Analyze protection-specific patterns and generate targeted recommendations"""
        
        protection_type = protection.type.lower()
        
        # License protection patterns
        if "license" in protection_type or "serial" in protection_type:
            self._analyze_license_protection(protection, binary_model, result)
        
        # Trial/time-based protection patterns  
        elif "trial" in protection_type or "time" in protection_type:
            self._analyze_trial_protection(protection, binary_model, result)
        
        # Hardware-based protection patterns
        elif "hardware" in protection_type or "hwid" in protection_type:
            self._analyze_hardware_protection(protection, binary_model, result)
        
        # Anti-debug protection patterns
        elif "debug" in protection_type or "anti" in protection_type:
            self._analyze_antidebug_protection(protection, binary_model, result)
        
        # VM protection patterns
        elif "vm" in protection_type or "virtual" in protection_type:
            self._analyze_vm_protection(protection, binary_model, result)
        
        # Network-based protection patterns
        elif "network" in protection_type or "online" in protection_type:
            self._analyze_network_protection(protection, binary_model, result)
        
        # Packer/obfuscation patterns
        elif "pack" in protection_type or "obfus" in protection_type:
            self._analyze_packer_protection(protection, binary_model, result)
    
    def _analyze_license_protection(self, protection: ProtectionInfo,
                                  binary_model: UnifiedBinaryModel,
                                  result: BypassAnalysisResult):
        """Analyze license-based protection and generate specific recommendations"""
        
        # Look for license validation functions
        license_functions = [
            func for func in binary_model.function_analysis.functions.values()
            if any(keyword in func.name.lower() 
                  for keyword in ["license", "serial", "key", "valid", "register", "activate"])
        ]
        
        if license_functions:
            # Recommend static analysis approach
            rec = BypassRecommendation(
                recommendation_id=f"license_static_{protection.name}_{int(time.time())}",
                title="Static License Function Analysis",
                description="Analyze license validation functions to identify bypass points",
                type=RecommendationType.STRATEGIC_ANALYSIS,
                priority=RecommendationPriority.HIGH,
                confidence=ConfidenceLevel.HIGH,
                target_protection=protection,
                target_functions=[func.name for func in license_functions[:5]],
                technique=BypassTechnique.STATIC_PATCHING,
                implementation_steps=[
                    "Open binary in disassembler (IDA Pro, Ghidra, or Radare2)",
                    "Navigate to license validation functions",
                    "Analyze conditional jumps and comparison operations",
                    "Identify success/failure branches",
                    "Patch conditional jumps to always take success branch",
                    "Test with invalid license to verify bypass"
                ],
                tools_required=["IDA Pro", "Ghidra", "Radare2", "Hex Editor"],
                success_probability=0.75,
                estimated_time="30-60 minutes",
                skill_level="Intermediate"
            )
            
            rec.educational_notes = [
                "License validation typically involves string comparison or checksum verification",
                "Look for patterns like 'cmp', 'test', 'jz', 'jnz' near license functions",
                "Success branches often continue execution while failure branches exit or show error"
            ]
            
            rec.security_implications = [
                "Static patching modifies the binary permanently",
                "May be detected by integrity checks",
                "Could affect software updates"
            ]
            
            rec.mitigation_advice = [
                "Implement multiple validation points throughout the application",
                "Use cryptographic signatures to verify license integrity",
                "Perform runtime integrity checks on validation code",
                "Implement server-side validation when possible"
            ]
            
            result.strategic_recommendations.append(rec)
        
        # Look for hardcoded license keys or validation strings
        license_strings = [
            string for string in binary_model.symbol_db.strings.values()
            if (len(string.value) > 8 and 
                any(keyword in string.value.lower() 
                    for keyword in ["license", "serial", "key", "valid", "trial"]))
        ]
        
        if license_strings:
            rec = BypassRecommendation(
                recommendation_id=f"license_strings_{protection.name}_{int(time.time())}",
                title="Hardcoded License String Analysis",
                description="Examine hardcoded license-related strings for potential keys or validation data",
                type=RecommendationType.VULNERABILITY_EXPLOITATION,
                priority=RecommendationPriority.MEDIUM,
                confidence=ConfidenceLevel.MEDIUM,
                target_protection=protection,
                technique=BypassTechnique.STATIC_PATCHING,
                implementation_steps=[
                    "Extract all license-related strings from binary",
                    "Test each string as potential license key",
                    "Analyze string usage in validation functions",
                    "Try variations and transformations of found strings"
                ],
                tools_required=["Strings utility", "Hex editor", "Debugger"],
                success_probability=0.4,
                estimated_time="15-30 minutes",
                skill_level="Beginner"
            )
            
            rec.educational_notes = [
                "Developers sometimes leave test keys or validation strings in binaries",
                "Look for patterns like serial number formats or license templates",
                "Try common transformations like base64 encoding/decoding"
            ]
            
            result.vulnerability_exploits.append(rec)
    
    def _analyze_trial_protection(self, protection: ProtectionInfo,
                                binary_model: UnifiedBinaryModel,
                                result: BypassAnalysisResult):
        """Analyze trial/time-based protection"""
        
        # Look for time-related API calls
        time_imports = [
            imp for imp in binary_model.symbol_db.imports.values()
            if any(api in imp.name.lower() 
                  for api in ["time", "clock", "date", "getsystemtime", "gettickcount"])
        ]
        
        if time_imports:
            rec = BypassRecommendation(
                recommendation_id=f"trial_time_hook_{protection.name}_{int(time.time())}",
                title="Time API Hooking",
                description="Hook time-related API calls to manipulate trial period",
                type=RecommendationType.IMMEDIATE_BYPASS,
                priority=RecommendationPriority.HIGH,
                confidence=ConfidenceLevel.HIGH,
                target_protection=protection,
                target_imports=[imp.name for imp in time_imports[:3]],
                technique=BypassTechnique.API_REDIRECTION,
                implementation_steps=[
                    "Identify time-related API calls used by application",
                    "Create DLL proxy or use API hooking framework",
                    "Redirect time calls to return controlled values",
                    "Set time to installation date or desired trial period",
                    "Test application with extended trial time"
                ],
                tools_required=["API Monitor", "Detours", "DLL Proxy Generator"],
                success_probability=0.8,
                estimated_time="20-40 minutes",
                skill_level="Intermediate"
            )
            
            # Generate Frida script for time hooking
            rec.script_template = self._generate_time_hook_script(time_imports)
            
            rec.educational_notes = [
                "Many trial applications use system time to track usage",
                "Hooking APIs allows dynamic control without modifying binary",
                "Consider both absolute time and relative time measurements"
            ]
            
            result.immediate_bypasses.append(rec)
        
        # Registry/file-based trial data
        rec = BypassRecommendation(
            recommendation_id=f"trial_data_{protection.name}_{int(time.time())}",
            title="Trial Data Manipulation",
            description="Locate and manipulate stored trial information",
            type=RecommendationType.STRATEGIC_ANALYSIS,
            priority=RecommendationPriority.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            target_protection=protection,
            technique=BypassTechnique.STATIC_PATCHING,
            implementation_steps=[
                "Monitor file and registry access during trial check",
                "Use Process Monitor to track data storage locations",
                "Backup original trial data",
                "Modify or delete trial timestamp data",
                "Test application restart with reset trial",
                "Automate trial reset with script if needed"
            ],
            tools_required=["Process Monitor", "Registry Editor", "File Monitor"],
            success_probability=0.6,
            estimated_time="15-30 minutes",
            skill_level="Beginner"
        )
        
        result.strategic_recommendations.append(rec)
    
    def _analyze_hardware_protection(self, protection: ProtectionInfo,
                                   binary_model: UnifiedBinaryModel,
                                   result: BypassAnalysisResult):
        """Analyze hardware-based protection"""
        
        hardware_imports = [
            imp for imp in binary_model.symbol_db.imports.values()
            if any(api in imp.name.lower() 
                  for api in ["getvolumeinformation", "deviceiocontrol", "wmi", "cpuid"])
        ]
        
        if hardware_imports:
            rec = BypassRecommendation(
                recommendation_id=f"hwid_spoof_{protection.name}_{int(time.time())}",
                title="Hardware ID Spoofing",
                description="Spoof hardware identifiers to bypass hardware-based protection",
                type=RecommendationType.IMMEDIATE_BYPASS,
                priority=RecommendationPriority.HIGH,
                confidence=ConfidenceLevel.MEDIUM,
                target_protection=protection,
                target_imports=[imp.name for imp in hardware_imports],
                technique=BypassTechnique.HARDWARE_SPOOFING,
                implementation_steps=[
                    "Identify hardware APIs used for fingerprinting",
                    "Hook hardware identification functions",
                    "Return consistent fake hardware IDs",
                    "Use virtual machine with controlled hardware profile",
                    "Test with different hardware ID combinations"
                ],
                tools_required=["API Monitor", "VirtualBox", "VMware", "Registry Editor"],
                success_probability=0.7,
                estimated_time="45-90 minutes",
                skill_level="Advanced"
            )
            
            result.immediate_bypasses.append(rec)
    
    def _analyze_antidebug_protection(self, protection: ProtectionInfo,
                                    binary_model: UnifiedBinaryModel,
                                    result: BypassAnalysisResult):
        """Analyze anti-debugging protection"""
        
        debug_imports = [
            imp for imp in binary_model.symbol_db.imports.values()
            if any(api in imp.name.lower() 
                  for api in ["isdebuggerpresent", "checkremotedebugger", "ntquerysystem"])
        ]
        
        if debug_imports:
            rec = BypassRecommendation(
                recommendation_id=f"antidebug_bypass_{protection.name}_{int(time.time())}",
                title="Anti-Debug Bypass",
                description="Bypass anti-debugging mechanisms to enable analysis",
                type=RecommendationType.IMMEDIATE_BYPASS,
                priority=RecommendationPriority.HIGH,
                confidence=ConfidenceLevel.HIGH,
                target_protection=protection,
                target_imports=[imp.name for imp in debug_imports],
                technique=BypassTechnique.DEBUGGER_HIDING,
                implementation_steps=[
                    "Identify anti-debug API calls",
                    "Hook APIs to return false (no debugger detected)",
                    "Use debugger plugins that hide debugger presence",
                    "Patch anti-debug checks directly in memory",
                    "Use advanced debuggers with stealth capabilities"
                ],
                tools_required=["x64dbg", "OllyDbg", "Cheat Engine", "Detours"],
                success_probability=0.85,
                estimated_time="20-45 minutes",
                skill_level="Intermediate"
            )
            
            rec.script_template = self._generate_antidebug_bypass_script(debug_imports)
            
            result.immediate_bypasses.append(rec)
    
    def _analyze_vm_protection(self, protection: ProtectionInfo,
                             binary_model: UnifiedBinaryModel,
                             result: BypassAnalysisResult):
        """Analyze VM detection protection"""
        
        rec = BypassRecommendation(
            recommendation_id=f"vm_evasion_{protection.name}_{int(time.time())}",
            title="VM Detection Evasion",
            description="Configure environment to evade virtual machine detection",
            type=RecommendationType.STRATEGIC_ANALYSIS,
            priority=RecommendationPriority.MEDIUM,
            confidence=ConfidenceLevel.MEDIUM,
            target_protection=protection,
            technique=BypassTechnique.VM_ESCAPE,
            implementation_steps=[
                "Use VM with anti-detection features",
                "Modify VM artifacts (registry, files, processes)",
                "Spoof hardware characteristics",
                "Use bare metal system if detection is strong",
                "Hook VM detection APIs to return false"
            ],
            tools_required=["VirtualBox", "VMware", "Registry Editor", "Process Monitor"],
            success_probability=0.6,
            estimated_time="60-120 minutes",
            skill_level="Advanced"
        )
        
        result.strategic_recommendations.append(rec)
    
    def _analyze_network_protection(self, protection: ProtectionInfo,
                                  binary_model: UnifiedBinaryModel,
                                  result: BypassAnalysisResult):
        """Analyze network-based protection"""
        
        network_imports = [
            imp for imp in binary_model.symbol_db.imports.values()
            if any(api in imp.name.lower() 
                  for api in ["wininet", "winhttp", "socket", "connect"])
        ]
        
        if network_imports:
            rec = BypassRecommendation(
                recommendation_id=f"network_intercept_{protection.name}_{int(time.time())}",
                title="Network Traffic Interception",
                description="Intercept and modify network communications for protection bypass",
                type=RecommendationType.STRATEGIC_ANALYSIS,
                priority=RecommendationPriority.MEDIUM,
                confidence=ConfidenceLevel.MEDIUM,
                target_protection=protection,
                target_imports=[imp.name for imp in network_imports[:3]],
                technique=BypassTechnique.NETWORK_INTERCEPTION,
                implementation_steps=[
                    "Monitor network traffic during license validation",
                    "Analyze authentication protocols and data formats",
                    "Set up local proxy or mock server",
                    "Redirect network calls to controlled server",
                    "Craft valid responses for bypass"
                ],
                tools_required=["Wireshark", "Fiddler", "Burp Suite", "Python"],
                success_probability=0.65,
                estimated_time="90-180 minutes",
                skill_level="Advanced"
            )
            
            result.strategic_recommendations.append(rec)
    
    def _analyze_packer_protection(self, protection: ProtectionInfo,
                                 binary_model: UnifiedBinaryModel,
                                 result: BypassAnalysisResult):
        """Analyze packer/obfuscation protection"""
        
        if binary_model.metadata.is_packed:
            rec = BypassRecommendation(
                recommendation_id=f"unpacking_{protection.name}_{int(time.time())}",
                title="Binary Unpacking",
                description="Unpack the binary to reveal original code for analysis",
                type=RecommendationType.STRATEGIC_ANALYSIS,
                priority=RecommendationPriority.HIGH,
                confidence=ConfidenceLevel.HIGH,
                target_protection=protection,
                technique=BypassTechnique.STATIC_PATCHING,
                implementation_steps=[
                    "Identify packer type using detection tools",
                    "Use appropriate unpacker if available",
                    "Manually unpack using debugger if needed",
                    "Dump unpacked memory to file",
                    "Fix import table and relocations",
                    "Analyze unpacked binary for protection mechanisms"
                ],
                tools_required=["PEiD", "Detect It Easy", "x64dbg", "Import REConstructor"],
                success_probability=0.7,
                estimated_time="60-120 minutes",
                skill_level="Advanced"
            )
            
            result.strategic_recommendations.append(rec)
    
    def _ai_enhanced_analysis(self, protection: ProtectionInfo,
                            binary_model: UnifiedBinaryModel,
                            result: BypassAnalysisResult):
        """Use AI for enhanced bypass analysis"""
        
        if not self.llm_manager:
            return
        
        try:
            # Prepare context for AI analysis
            context = {
                "protection_name": protection.name,
                "protection_type": protection.type,
                "confidence": protection.confidence,
                "binary_format": binary_model.metadata.file_format,
                "architecture": binary_model.metadata.architecture,
                "is_packed": binary_model.metadata.is_packed,
                "has_debug_info": binary_model.metadata.has_debug_info,
                "function_count": len(binary_model.function_analysis.functions),
                "import_count": len(binary_model.symbol_db.imports)
            }
            
            # Generate AI-powered recommendations
            ai_recommendations = self._generate_ai_recommendations(context, protection)
            
            # Add AI recommendations to result
            for ai_rec in ai_recommendations:
                ai_rec.ai_model_used = "LLM_Enhanced"
                result.strategic_recommendations.append(ai_rec)
                
        except Exception as e:
            logger.warning(f"AI-enhanced analysis failed: {e}")
    
    def _generate_ai_recommendations(self, context: Dict[str, Any], 
                                   protection: ProtectionInfo) -> List[BypassRecommendation]:
        """Generate AI-powered bypass recommendations"""
        
        recommendations = []
        
        if not self.llm_manager:
            return recommendations
        
        try:
            prompt = self._build_ai_analysis_prompt(context, protection)
            
            # Get AI response
            response = self.llm_manager.chat(
                messages=[{"role": "user", "content": prompt}],
                model="gpt-4"  # Use best available model
            )
            
            if response and response.get("content"):
                ai_analysis = response["content"]
                
                # Parse AI response into structured recommendations
                parsed_recs = self._parse_ai_response(ai_analysis, protection)
                recommendations.extend(parsed_recs)
                
        except Exception as e:
            logger.warning(f"AI recommendation generation failed: {e}")
        
        return recommendations
    
    def _build_ai_analysis_prompt(self, context: Dict[str, Any], 
                                protection: ProtectionInfo) -> str:
        """Build prompt for AI analysis"""
        
        prompt = f"""
Analyze the following software protection mechanism and provide bypass recommendations for defensive security research:

Protection Details:
- Name: {protection.name}
- Type: {protection.type}
- Confidence: {protection.confidence}

Binary Context:
- Format: {context['binary_format']}
- Architecture: {context['architecture']}
- Packed: {context['is_packed']}
- Debug Info: {context['has_debug_info']}
- Functions: {context['function_count']}
- Imports: {context['import_count']}

Please provide:
1. Assessment of protection strength and bypass difficulty
2. Recommended bypass techniques with implementation guidance
3. Tools and skills required for bypass
4. Success probability estimate
5. Educational insights about the protection mechanism
6. Mitigation advice for developers to strengthen the protection

Focus on educational content for defensive security research and responsible disclosure.
"""
        
        return prompt
    
    def _parse_ai_response(self, ai_response: str, 
                         protection: ProtectionInfo) -> List[BypassRecommendation]:
        """Parse AI response into structured recommendations"""
        
        recommendations = []
        
        try:
            # Simple parsing - in production, use more sophisticated NLP
            lines = ai_response.split('\n')
            current_rec = None
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                # Look for recommendation sections
                if any(keyword in line.lower() for keyword in ['recommend', 'technique', 'approach']):
                    if current_rec:
                        recommendations.append(current_rec)
                    
                    current_rec = BypassRecommendation(
                        recommendation_id=f"ai_rec_{int(time.time())}",
                        title=line[:100],
                        description=line,
                        type=RecommendationType.STRATEGIC_ANALYSIS,
                        priority=RecommendationPriority.MEDIUM,
                        confidence=ConfidenceLevel.MEDIUM,
                        target_protection=protection,
                        technique=BypassTechnique.DYNAMIC_HOOKING,
                        success_probability=0.5,
                        skill_level="Intermediate"
                    )
                elif current_rec:
                    # Add to current recommendation
                    if 'implement' in line.lower():
                        current_rec.implementation_steps.append(line)
                    elif 'tool' in line.lower():
                        current_rec.tools_required.append(line)
                    elif 'education' in line.lower() or 'learn' in line.lower():
                        current_rec.educational_notes.append(line)
            
            # Add last recommendation
            if current_rec:
                recommendations.append(current_rec)
                
        except Exception as e:
            logger.warning(f"AI response parsing failed: {e}")
        
        return recommendations
    
    def _generate_strategic_recommendations(self, binary_model: UnifiedBinaryModel,
                                          result: BypassAnalysisResult):
        """Generate high-level strategic recommendations"""
        
        # Comprehensive analysis approach
        rec = BypassRecommendation(
            recommendation_id=f"strategic_analysis_{int(time.time())}",
            title="Comprehensive Protection Analysis",
            description="Perform systematic analysis of all protection mechanisms",
            type=RecommendationType.STRATEGIC_ANALYSIS,
            priority=RecommendationPriority.HIGH,
            confidence=ConfidenceLevel.HIGH,
            target_protection=result.get_all_recommendations()[0].target_protection if result.get_all_recommendations() else None,
            technique=BypassTechnique.STATIC_PATCHING,
            implementation_steps=[
                "Map all protection mechanisms in the binary",
                "Identify interdependencies between protections",
                "Prioritize bypass targets based on impact",
                "Develop layered bypass strategy",
                "Test bypass effectiveness incrementally"
            ],
            tools_required=["IDA Pro", "Ghidra", "x64dbg", "Frida"],
            success_probability=0.8,
            estimated_time="2-4 hours",
            skill_level="Advanced"
        )
        
        rec.educational_notes = [
            "Complex protections often have multiple layers that must be bypassed in order",
            "Understanding protection architecture is key to successful bypass",
            "Start with the weakest protection layer and work progressively"
        ]
        
        result.strategic_recommendations.append(rec)
    
    def _analyze_vulnerability_opportunities(self, binary_model: UnifiedBinaryModel,
                                           result: BypassAnalysisResult):
        """Analyze potential vulnerability exploitation opportunities"""
        
        # Look for obvious vulnerabilities
        vulns_found = 0
        
        # Check for buffer overflow opportunities
        dangerous_functions = ["strcpy", "sprintf", "gets", "scanf"]
        for imp in binary_model.symbol_db.imports.values():
            if any(func in imp.name.lower() for func in dangerous_functions):
                vulns_found += 1
                
                rec = BypassRecommendation(
                    recommendation_id=f"vuln_exploit_{imp.name}_{int(time.time())}",
                    title=f"Potential Buffer Overflow - {imp.name}",
                    description=f"Dangerous function {imp.name} may be exploitable for bypass",
                    type=RecommendationType.VULNERABILITY_EXPLOITATION,
                    priority=RecommendationPriority.HIGH,
                    confidence=ConfidenceLevel.MEDIUM,
                    target_protection=None,
                    target_imports=[imp.name],
                    technique=BypassTechnique.MEMORY_MANIPULATION,
                    implementation_steps=[
                        f"Locate usage of {imp.name} in binary",
                        "Analyze input validation and buffer sizes",
                        "Craft exploit payload for buffer overflow",
                        "Test exploit in controlled environment",
                        "Use exploit to bypass protection checks"
                    ],
                    tools_required=["Debugger", "Exploit Development Kit", "Fuzzer"],
                    risk_level=BypassRisk.HIGH,
                    success_probability=0.4,
                    estimated_time="2-6 hours",
                    skill_level="Expert"
                )
                
                rec.security_implications = [
                    "Buffer overflow exploits can lead to arbitrary code execution",
                    "May cause application crashes or system instability",
                    "Should only be used in controlled testing environments"
                ]
                
                result.vulnerability_exploits.append(rec)
        
        # Check for weak cryptographic implementations
        weak_crypto = ["xor", "rot", "simple", "custom"]
        for func in binary_model.function_analysis.functions.values():
            if (func.is_crypto_related and 
                any(weak in func.name.lower() for weak in weak_crypto)):
                
                rec = BypassRecommendation(
                    recommendation_id=f"weak_crypto_{func.name}_{int(time.time())}",
                    title=f"Weak Cryptography - {func.name}",
                    description="Potentially weak cryptographic implementation detected",
                    type=RecommendationType.VULNERABILITY_EXPLOITATION,
                    priority=RecommendationPriority.MEDIUM,
                    confidence=ConfidenceLevel.MEDIUM,
                    target_protection=None,
                    target_functions=[func.name],
                    technique=BypassTechnique.CRYPTO_BYPASS,
                    implementation_steps=[
                        "Analyze cryptographic algorithm implementation",
                        "Test with known weak keys or patterns",
                        "Develop key recovery or bypass method",
                        "Validate bypass effectiveness"
                    ],
                    tools_required=["Disassembler", "Crypto Analysis Tools", "Python"],
                    success_probability=0.6,
                    estimated_time="1-3 hours",
                    skill_level="Advanced"
                )
                
                result.vulnerability_exploits.append(rec)
    
    def _recommend_tools_and_techniques(self, binary_model: UnifiedBinaryModel,
                                      result: BypassAnalysisResult):
        """Recommend appropriate tools and techniques"""
        
        # Static analysis tools
        static_rec = BypassRecommendation(
            recommendation_id=f"tools_static_{int(time.time())}",
            title="Static Analysis Tool Selection",
            description="Recommended tools for static binary analysis",
            type=RecommendationType.TOOL_RECOMMENDATION,
            priority=RecommendationPriority.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            target_protection=None,
            technique=BypassTechnique.STATIC_PATCHING,
            implementation_steps=[
                "Use IDA Pro for comprehensive disassembly and analysis",
                "Use Ghidra for free alternative with decompilation",
                "Use Radare2 for scripting and automation",
                "Use Detect It Easy for packer and protection identification",
                "Use strings utility for quick text analysis"
            ],
            tools_required=["IDA Pro", "Ghidra", "Radare2", "Detect It Easy"],
            success_probability=1.0,
            estimated_time="Tool setup: 30 minutes",
            skill_level="Beginner"
        )
        
        result.tool_suggestions.append(static_rec)
        
        # Dynamic analysis tools
        dynamic_rec = BypassRecommendation(
            recommendation_id=f"tools_dynamic_{int(time.time())}",
            title="Dynamic Analysis Tool Selection", 
            description="Recommended tools for dynamic analysis and debugging",
            type=RecommendationType.TOOL_RECOMMENDATION,
            priority=RecommendationPriority.MEDIUM,
            confidence=ConfidenceLevel.HIGH,
            target_protection=None,
            technique=BypassTechnique.DYNAMIC_HOOKING,
            implementation_steps=[
                "Use x64dbg for Windows binary debugging",
                "Use Frida for dynamic instrumentation and hooking",
                "Use Process Monitor for file/registry monitoring",
                "Use API Monitor for API call tracing",
                "Use Cheat Engine for memory manipulation"
            ],
            tools_required=["x64dbg", "Frida", "Process Monitor", "API Monitor"],
            success_probability=1.0,
            estimated_time="Tool setup: 45 minutes",
            skill_level="Intermediate"
        )
        
        result.tool_suggestions.append(dynamic_rec)
    
    def _generate_educational_content(self, binary_model: UnifiedBinaryModel,
                                    result: BypassAnalysisResult):
        """Generate educational content about protections and bypass techniques"""
        
        educational_rec = BypassRecommendation(
            recommendation_id=f"education_{int(time.time())}",
            title="Understanding Software Protection Mechanisms",
            description="Educational overview of common protection types and bypass principles",
            type=RecommendationType.EDUCATIONAL_GUIDANCE,
            priority=RecommendationPriority.LOW,
            confidence=ConfidenceLevel.VERY_HIGH,
            target_protection=None,
            technique=BypassTechnique.STATIC_PATCHING,
            implementation_steps=[
                "Study protection mechanism documentation and whitepapers",
                "Practice on intentionally vulnerable applications",
                "Join security research communities and forums",
                "Follow responsible disclosure guidelines",
                "Focus on defensive applications of bypass knowledge"
            ],
            tools_required=["Documentation", "Practice Labs", "Research Papers"],
            success_probability=1.0,
            estimated_time="Ongoing learning",
            skill_level="All Levels"
        )
        
        educational_rec.educational_notes = [
            "Protection bypass is a legitimate security research technique",
            "Always obtain proper authorization before testing",
            "Use knowledge to improve security, not exploit vulnerabilities",
            "Consider the ethical implications of your research",
            "Share findings responsibly with the security community"
        ]
        
        result.educational_content.append(educational_rec)
    
    def _perform_overall_assessment(self, binary_model: UnifiedBinaryModel,
                                  result: BypassAnalysisResult):
        """Perform overall bypass difficulty assessment"""
        
        # Calculate overall difficulty based on protection complexity
        difficulty_factors = []
        
        for protection in binary_model.protection_analysis.detected_protections:
            if protection.is_vm_protection:
                difficulty_factors.append(4)
            elif protection.is_encryption:
                difficulty_factors.append(3)
            elif protection.is_anti_debug:
                difficulty_factors.append(2)
            else:
                difficulty_factors.append(1)
        
        if binary_model.metadata.is_packed:
            difficulty_factors.append(2)
        
        if not binary_model.metadata.has_debug_info:
            difficulty_factors.append(1)
        
        avg_difficulty = sum(difficulty_factors) / max(len(difficulty_factors), 1)
        
        # Map to complexity enum
        if avg_difficulty >= 3.5:
            result.overall_bypass_difficulty = BypassComplexity.ADVANCED
        elif avg_difficulty >= 2.5:
            result.overall_bypass_difficulty = BypassComplexity.COMPLEX
        elif avg_difficulty >= 1.5:
            result.overall_bypass_difficulty = BypassComplexity.MODERATE
        elif avg_difficulty >= 1.0:
            result.overall_bypass_difficulty = BypassComplexity.SIMPLE
        else:
            result.overall_bypass_difficulty = BypassComplexity.TRIVIAL
        
        # Calculate overall success probability
        high_conf_recs = result.get_high_confidence_recommendations(0.6)
        if high_conf_recs:
            result.overall_success_probability = sum(r.success_probability for r in high_conf_recs) / len(high_conf_recs)
        else:
            result.overall_success_probability = 0.3
        
        # Generate recommended approach
        if result.immediate_bypasses:
            result.recommended_approach = "Start with immediate bypass techniques for quick wins"
        elif result.strategic_recommendations:
            result.recommended_approach = "Focus on strategic analysis and gradual bypass development"
        else:
            result.recommended_approach = "Begin with tool-assisted analysis and vulnerability research"
    
    def _generate_defensive_insights(self, binary_model: UnifiedBinaryModel,
                                   result: BypassAnalysisResult):
        """Generate insights for defensive security improvement"""
        
        # Analyze protection strengths
        strengths = []
        weaknesses = []
        improvements = []
        
        protection_count = len(binary_model.protection_analysis.detected_protections)
        
        if protection_count > 3:
            strengths.append("Multiple layered protection mechanisms")
        if binary_model.metadata.is_packed:
            strengths.append("Binary packing complicates static analysis")
        if not binary_model.metadata.has_debug_info:
            strengths.append("No debug symbols to aid reverse engineering")
        
        # Identify weaknesses based on recommendations
        immediate_bypasses = len(result.immediate_bypasses)
        if immediate_bypasses > 2:
            weaknesses.append("Multiple immediate bypass opportunities available")
        
        vuln_exploits = len(result.vulnerability_exploits)
        if vuln_exploits > 0:
            weaknesses.append("Exploitable vulnerabilities detected")
        
        # Generate improvement suggestions
        if immediate_bypasses > 0:
            improvements.append("Implement runtime integrity checking")
            improvements.append("Add multiple validation layers")
        
        if vuln_exploits > 0:
            improvements.append("Conduct security code review")
            improvements.append("Implement input validation")
        
        if protection_count < 2:
            improvements.append("Add additional protection layers")
        
        improvements.append("Implement server-side validation")
        improvements.append("Use cryptographic signatures for integrity")
        improvements.append("Regular security assessments and updates")
        
        result.protection_strengths = strengths
        result.protection_weaknesses = weaknesses
        result.improvement_suggestions = improvements
    
    def _generate_cache_key(self, binary_model: UnifiedBinaryModel) -> str:
        """Generate cache key for binary model"""
        key_data = f"{binary_model.metadata.sha256}_{len(binary_model.protection_analysis.detected_protections)}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _generate_code_example(self, strategy: BypassStrategy) -> Optional[str]:
        """Generate code example for bypass strategy"""
        
        if not strategy.steps:
            return None
        
        first_step = strategy.steps[0]
        
        if first_step.technique == BypassTechnique.DYNAMIC_HOOKING:
            return self._generate_frida_hook_example(strategy)
        elif first_step.technique == BypassTechnique.STATIC_PATCHING:
            return self._generate_patch_example(strategy)
        elif first_step.technique == BypassTechnique.API_REDIRECTION:
            return self._generate_api_redirect_example(strategy)
        
        return None
    
    def _generate_frida_hook_example(self, strategy: BypassStrategy) -> str:
        """Generate Frida hooking example"""
        
        return f"""
// Frida script for {strategy.name}
Java.perform(function() {{
    // Hook target function
    var targetModule = Process.findModuleByName("target.exe");
    var targetFunction = targetModule.findExportByName("TargetFunction");
    
    if (targetFunction) {{
        Interceptor.attach(targetFunction, {{
            onEnter: function(args) {{
                console.log("[+] Hooked function called");
                // Modify arguments or behavior
            }},
            onLeave: function(retval) {{
                console.log("[+] Function returning: " + retval);
                // Modify return value for bypass
                retval.replace(1); // Return success
            }}
        }});
    }}
}});
"""
    
    def _generate_patch_example(self, strategy: BypassStrategy) -> str:
        """Generate static patching example"""
        
        return f"""
# Python script for {strategy.name}
import struct

def patch_binary(filepath):
    with open(filepath, 'r+b') as f:
        # Locate target address (example: 0x1000)
        target_offset = 0x1000
        f.seek(target_offset)
        
        # Patch conditional jump to NOP (0x90)
        # Original: JZ (0x74 0x05) -> NOP NOP (0x90 0x90)
        f.write(b'\\x90\\x90')
        
    print("Binary patched successfully")

# Usage
patch_binary("target.exe")
"""
    
    def _generate_api_redirect_example(self, strategy: BypassStrategy) -> str:
        """Generate API redirection example"""
        
        return f"""
// DLL Proxy for {strategy.name}
#include <windows.h>

// Original function pointer
typedef BOOL (*OriginalFunction)(VOID);
OriginalFunction original_func = NULL;

// Hooked function
BOOL HookedFunction(VOID) {{
    // Always return success instead of calling original
    return TRUE;
}}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {{
    if (reason == DLL_PROCESS_ATTACH) {{
        // Set up hook
        original_func = (OriginalFunction)GetProcAddress(
            GetModuleHandle("original.dll"), "TargetFunction");
        // Install hook using Detours or similar
    }}
    return TRUE;
}}
"""
    
    def _generate_time_hook_script(self, time_imports: List[ImportInfo]) -> str:
        """Generate Frida script for time API hooking"""
        
        script = "// Frida script for time manipulation\n"
        script += "var kernel32 = Module.findExportByName('kernel32.dll', 'GetSystemTime');\n"
        script += "if (kernel32) {\n"
        script += "    Interceptor.attach(kernel32, {\n"
        script += "        onEnter: function(args) {\n"
        script += "            console.log('[+] GetSystemTime hooked');\n"
        script += "        },\n"
        script += "        onLeave: function(retval) {\n"
        script += "            // Modify time to extend trial\n"
        script += "            // Set to installation date or desired time\n"
        script += "        }\n"
        script += "    });\n"
        script += "}\n"
        
        return script
    
    def _generate_antidebug_bypass_script(self, debug_imports: List[ImportInfo]) -> str:
        """Generate anti-debug bypass script"""
        
        script = "// Frida script for anti-debug bypass\n"
        
        for imp in debug_imports:
            if "isdebuggerpresent" in imp.name.lower():
                script += f"""
var {imp.name} = Module.findExportByName('kernel32.dll', '{imp.name}');
if ({imp.name}) {{
    Interceptor.attach({imp.name}, {{
        onLeave: function(retval) {{
            console.log('[+] {imp.name} bypassed');
            retval.replace(0); // Return FALSE (no debugger)
        }}
    }});
}}
"""
        
        return script
    
    def _generate_educational_notes(self, strategy: BypassStrategy, 
                                  protection: ProtectionInfo) -> List[str]:
        """Generate educational notes for strategy"""
        
        notes = [
            f"This bypass targets {protection.type} protection mechanisms",
            f"Success probability is estimated at {strategy.success_probability:.1%}",
            f"Complexity level: {strategy.complexity.name}"
        ]
        
        if strategy.complexity in [BypassComplexity.COMPLEX, BypassComplexity.ADVANCED]:
            notes.append("This is an advanced technique requiring significant reverse engineering skills")
        
        if any(step.risk_level in [BypassRisk.HIGH, BypassRisk.CRITICAL] for step in strategy.steps):
            notes.append("Some steps involve high-risk operations - use in controlled environments only")
        
        return notes
    
    def _generate_security_implications(self, strategy: BypassStrategy,
                                      protection: ProtectionInfo) -> List[str]:
        """Generate security implications for strategy"""
        
        implications = [
            "This technique modifies software behavior and should only be used on authorized systems",
            "Use in controlled testing environments to avoid unintended consequences"
        ]
        
        if any(step.technique == BypassTechnique.MEMORY_MANIPULATION for step in strategy.steps):
            implications.append("Memory manipulation may cause application instability")
        
        if any(step.technique == BypassTechnique.STATIC_PATCHING for step in strategy.steps):
            implications.append("Static patching permanently modifies the binary file")
        
        return implications
    
    def _generate_mitigation_advice(self, strategy: BypassStrategy,
                                  protection: ProtectionInfo) -> List[str]:
        """Generate mitigation advice for developers"""
        
        advice = []
        
        for step in strategy.steps:
            if step.technique == BypassTechnique.STATIC_PATCHING:
                advice.extend([
                    "Implement runtime integrity checking to detect binary modifications",
                    "Use code signing and signature verification"
                ])
            elif step.technique == BypassTechnique.DYNAMIC_HOOKING:
                advice.extend([
                    "Implement anti-hooking mechanisms",
                    "Use multiple validation points throughout execution"
                ])
            elif step.technique == BypassTechnique.TIME_MANIPULATION:
                advice.extend([
                    "Use server-side time validation",
                    "Implement multiple time sources and cross-validation"
                ])
            elif step.technique == BypassTechnique.HARDWARE_SPOOFING:
                advice.extend([
                    "Use multiple hardware fingerprinting methods",
                    "Implement server-side hardware validation"
                ])
        
        # Remove duplicates
        return list(set(advice))
    
    def _load_protection_knowledge(self) -> Dict[str, Any]:
        """Load protection knowledge base"""
        
        return {
            "license_patterns": [
                {"pattern": "serial.*check", "confidence": 0.8},
                {"pattern": "license.*valid", "confidence": 0.9},
                {"pattern": "registration.*key", "confidence": 0.7}
            ],
            "trial_patterns": [
                {"pattern": "trial.*expire", "confidence": 0.9},
                {"pattern": "days.*remaining", "confidence": 0.8},
                {"pattern": "evaluation.*period", "confidence": 0.7}
            ],
            "antidebug_patterns": [
                {"pattern": "isdebuggerpresent", "confidence": 0.95},
                {"pattern": "checkremotedebugger", "confidence": 0.9},
                {"pattern": "debugbreak", "confidence": 0.8}
            ]
        }
    
    def _load_bypass_patterns(self) -> Dict[str, Any]:
        """Load bypass pattern knowledge"""
        
        return {
            "static_patches": {
                "conditional_jumps": ["jz", "jnz", "je", "jne", "jl", "jg"],
                "comparisons": ["cmp", "test", "sub"],
                "calls": ["call", "ret"]
            },
            "api_hooks": {
                "time_apis": ["GetSystemTime", "GetTickCount", "time", "clock"],
                "debug_apis": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
                "hardware_apis": ["GetVolumeInformation", "DeviceIoControl"]
            },
            "memory_patterns": {
                "license_storage": ["registry", "files", "memory"],
                "trial_data": ["timestamps", "counters", "flags"]
            }
        }
    
    def _load_vulnerability_database(self) -> Dict[str, Any]:
        """Load vulnerability database"""
        
        return {
            "buffer_overflows": [
                {"function": "strcpy", "risk": "high"},
                {"function": "sprintf", "risk": "high"},
                {"function": "gets", "risk": "critical"}
            ],
            "format_strings": [
                {"function": "printf", "risk": "medium"},
                {"function": "fprintf", "risk": "medium"}
            ],
            "weak_crypto": [
                {"algorithm": "xor", "risk": "high"},
                {"algorithm": "rot13", "risk": "high"},
                {"algorithm": "simple_substitution", "risk": "medium"}
            ]
        }
    
    def report_bypass_success(self, recommendation_id: str, success: bool, 
                            details: Optional[str] = None):
        """Report success/failure of bypass attempt for learning"""
        
        self.success_tracker[recommendation_id].append({
            "success": success,
            "timestamp": time.time(),
            "details": details
        })
        
        # Update performance metrics
        rec_type = recommendation_id.split('_')[0]
        current_rate = self.performance_metrics.get(rec_type, 0.5)
        
        # Simple learning rate adjustment
        if success:
            self.performance_metrics[rec_type] = min(0.95, current_rate + 0.05)
        else:
            self.performance_metrics[rec_type] = max(0.05, current_rate - 0.05)
        
        logger.info(f"Bypass success reported: {recommendation_id} = {success}")
    
    def get_learning_insights(self) -> Dict[str, Any]:
        """Get insights from bypass success tracking"""
        
        insights = {
            "total_attempts": sum(len(attempts) for attempts in self.success_tracker.values()),
            "success_rates": {},
            "top_techniques": [],
            "recommendations": []
        }
        
        # Calculate success rates by technique
        technique_stats = defaultdict(lambda: {"success": 0, "total": 0})
        
        for rec_id, attempts in self.success_tracker.items():
            technique = rec_id.split('_')[0]
            for attempt in attempts:
                technique_stats[technique]["total"] += 1
                if attempt["success"]:
                    technique_stats[technique]["success"] += 1
        
        for technique, stats in technique_stats.items():
            if stats["total"] > 0:
                rate = stats["success"] / stats["total"]
                insights["success_rates"][technique] = rate
        
        # Identify top techniques
        sorted_techniques = sorted(
            insights["success_rates"].items(),
            key=lambda x: x[1],
            reverse=True
        )
        insights["top_techniques"] = sorted_techniques[:5]
        
        # Generate recommendations
        if insights["top_techniques"]:
            best_technique = insights["top_techniques"][0]
            insights["recommendations"].append(
                f"Focus on {best_technique[0]} techniques (success rate: {best_technique[1]:.1%})"
            )
        
        return insights
    
    def export_recommendations(self, result: BypassAnalysisResult, 
                             format: str = "json") -> str:
        """Export recommendations in various formats"""
        
        if format == "json":
            return self._export_json_recommendations(result)
        elif format == "markdown":
            return self._export_markdown_recommendations(result)
        elif format == "html":
            return self._export_html_recommendations(result)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _export_json_recommendations(self, result: BypassAnalysisResult) -> str:
        """Export recommendations as JSON"""
        
        export_data = {
            "analysis_summary": {
                "binary_hash": result.binary_hash,
                "analysis_timestamp": result.analysis_timestamp,
                "total_protections": result.total_protections,
                "overall_difficulty": result.overall_bypass_difficulty.name,
                "success_probability": result.overall_success_probability,
                "recommended_approach": result.recommended_approach
            },
            "recommendations": {
                "immediate_bypasses": [rec.to_dict() for rec in result.immediate_bypasses],
                "strategic_recommendations": [rec.to_dict() for rec in result.strategic_recommendations],
                "vulnerability_exploits": [rec.to_dict() for rec in result.vulnerability_exploits],
                "tool_suggestions": [rec.to_dict() for rec in result.tool_suggestions],
                "educational_content": [rec.to_dict() for rec in result.educational_content]
            },
            "defensive_insights": {
                "strengths": result.protection_strengths,
                "weaknesses": result.protection_weaknesses,
                "improvements": result.improvement_suggestions
            }
        }
        
        return json.dumps(export_data, indent=2)
    
    def _export_markdown_recommendations(self, result: BypassAnalysisResult) -> str:
        """Export recommendations as Markdown"""
        
        md = f"# Protection Bypass Analysis Report\n\n"
        md += f"**Analysis Date:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.analysis_timestamp))}\n"
        md += f"**Binary Hash:** {result.binary_hash}\n"
        md += f"**Total Protections:** {result.total_protections}\n"
        md += f"**Overall Difficulty:** {result.overall_bypass_difficulty.name}\n"
        md += f"**Success Probability:** {result.overall_success_probability:.1%}\n\n"
        
        md += f"## Recommended Approach\n{result.recommended_approach}\n\n"
        
        # Add recommendations by category
        categories = [
            ("Immediate Bypasses", result.immediate_bypasses),
            ("Strategic Recommendations", result.strategic_recommendations),
            ("Vulnerability Exploits", result.vulnerability_exploits),
            ("Tool Suggestions", result.tool_suggestions),
            ("Educational Content", result.educational_content)
        ]
        
        for category_name, recommendations in categories:
            if recommendations:
                md += f"## {category_name}\n\n"
                for i, rec in enumerate(recommendations, 1):
                    md += f"### {i}. {rec.title}\n"
                    md += f"**Priority:** {rec.priority.name}\n"
                    md += f"**Confidence:** {rec.confidence.name}\n"
                    md += f"**Success Rate:** {rec.success_probability:.1%}\n\n"
                    md += f"{rec.description}\n\n"
                    
                    if rec.implementation_steps:
                        md += "**Implementation Steps:**\n"
                        for step in rec.implementation_steps:
                            md += f"1. {step}\n"
                        md += "\n"
                    
                    if rec.tools_required:
                        md += f"**Required Tools:** {', '.join(rec.tools_required)}\n\n"
        
        # Add defensive insights
        md += "## Defensive Security Insights\n\n"
        
        if result.protection_strengths:
            md += "### Protection Strengths\n"
            for strength in result.protection_strengths:
                md += f"- {strength}\n"
            md += "\n"
        
        if result.protection_weaknesses:
            md += "### Protection Weaknesses\n"
            for weakness in result.protection_weaknesses:
                md += f"- {weakness}\n"
            md += "\n"
        
        if result.improvement_suggestions:
            md += "### Improvement Suggestions\n"
            for suggestion in result.improvement_suggestions:
                md += f"- {suggestion}\n"
            md += "\n"
        
        return md
    
    def _export_html_recommendations(self, result: BypassAnalysisResult) -> str:
        """Export recommendations as HTML"""
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Protection Bypass Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .recommendation {{ margin: 15px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .priority-HIGH {{ border-left: 5px solid #dc3545; }}
        .priority-MEDIUM {{ border-left: 5px solid #ffc107; }}
        .priority-LOW {{ border-left: 5px solid #28a745; }}
        .confidence {{ color: #6c757d; font-size: 0.9em; }}
        pre {{ background: #f8f9fa; padding: 10px; overflow-x: auto; }}
        .defensive-insights {{ background: #e7f3ff; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Protection Bypass Analysis Report</h1>
    
    <div class="summary">
        <h2>Analysis Summary</h2>
        <p><strong>Binary Hash:</strong> {result.binary_hash}</p>
        <p><strong>Analysis Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.analysis_timestamp))}</p>
        <p><strong>Total Protections:</strong> {result.total_protections}</p>
        <p><strong>Overall Difficulty:</strong> {result.overall_bypass_difficulty.name}</p>
        <p><strong>Success Probability:</strong> {result.overall_success_probability:.1%}</p>
        <p><strong>Recommended Approach:</strong> {result.recommended_approach}</p>
    </div>
"""
        
        # Add recommendations
        all_recs = result.get_all_recommendations()
        if all_recs:
            html += "<h2>Recommendations</h2>\n"
            for i, rec in enumerate(all_recs, 1):
                html += f'''
    <div class="recommendation priority-{rec.priority.name}">
        <h3>{i}. {rec.title}</h3>
        <p class="confidence">Priority: {rec.priority.name} | Confidence: {rec.confidence.name} | Success Rate: {rec.success_probability:.1%}</p>
        <p>{rec.description}</p>
'''
                if rec.implementation_steps:
                    html += "<h4>Implementation Steps:</h4><ol>"
                    for step in rec.implementation_steps:
                        html += f"<li>{step}</li>"
                    html += "</ol>"
                
                if rec.code_example:
                    html += f"<h4>Code Example:</h4><pre>{rec.code_example}</pre>"
                
                html += "</div>\n"
        
        # Add defensive insights
        html += '''
    <div class="defensive-insights">
        <h2>Defensive Security Insights</h2>
'''
        
        if result.protection_strengths:
            html += "<h3>Protection Strengths</h3><ul>"
            for strength in result.protection_strengths:
                html += f"<li>{strength}</li>"
            html += "</ul>"
        
        if result.protection_weaknesses:
            html += "<h3>Protection Weaknesses</h3><ul>"
            for weakness in result.protection_weaknesses:
                html += f"<li>{weakness}</li>"
            html += "</ul>"
        
        if result.improvement_suggestions:
            html += "<h3>Improvement Suggestions</h3><ul>"
            for suggestion in result.improvement_suggestions:
                html += f"<li>{suggestion}</li>"
            html += "</ul>"
        
        html += '''
    </div>
</body>
</html>
'''
        
        return html


# Global instance for easy access
_protection_bypass_advisor = None

def get_protection_bypass_advisor() -> ProtectionBypassAdvisor:
    """Get global protection bypass advisor instance"""
    global _protection_bypass_advisor
    if _protection_bypass_advisor is None:
        _protection_bypass_advisor = ProtectionBypassAdvisor()
    return _protection_bypass_advisor