"""
Automated Bypass Strategy Creator

Analyzes protection mechanisms and creates comprehensive bypass strategies
with step-by-step implementation guidance and alternative approaches.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.analysis.unified_model.model import (
    ProtectionInfo,
    UnifiedBinaryModel,
    FunctionInfo,
    ImportInfo
)
from ..utils.logger import get_logger
from .consensus_engine import ConsensusResult, ModelExpertise, MultiModelConsensusEngine
from .ai_script_generator import ProtectionType, ScriptType

logger = get_logger(__name__)


class BypassTechnique(Enum):
    """Bypass technique categories"""
    STATIC_PATCHING = "static_patching"
    DYNAMIC_HOOKING = "dynamic_hooking"
    MEMORY_MANIPULATION = "memory_manipulation"
    API_REDIRECTION = "api_redirection"
    TIME_MANIPULATION = "time_manipulation"
    HARDWARE_SPOOFING = "hardware_spoofing"
    NETWORK_INTERCEPTION = "network_interception"
    CRYPTO_BYPASS = "crypto_bypass"
    VM_ESCAPE = "vm_escape"
    DEBUGGER_HIDING = "debugger_hiding"
    
    
class BypassComplexity(Enum):
    """Bypass complexity levels"""
    TRIVIAL = 1
    SIMPLE = 2
    MODERATE = 3
    COMPLEX = 4
    ADVANCED = 5


class BypassRisk(Enum):
    """Risk levels for bypass techniques"""
    MINIMAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class BypassStep:
    """Individual step in a bypass strategy"""
    step_number: int
    description: str
    technique: BypassTechnique
    implementation: str  # Code or detailed instructions
    tools_required: List[str] = field(default_factory=list)
    risk_level: BypassRisk = BypassRisk.MEDIUM
    alternatives: List[str] = field(default_factory=list)
    verification: str = ""  # How to verify this step worked
    rollback: Optional[str] = None  # How to undo if needed
    

@dataclass
class BypassStrategy:
    """Complete bypass strategy for a protection"""
    strategy_id: str
    target_protection: ProtectionInfo
    name: str
    description: str
    complexity: BypassComplexity
    success_probability: float  # 0.0 to 1.0
    steps: List[BypassStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)
    tools_required: Set[str] = field(default_factory=set)
    estimated_time: str = "Unknown"
    
    # Alternative strategies
    alternatives: List['BypassStrategy'] = field(default_factory=list)
    
    # Metadata
    ai_confidence: float = 0.0
    generation_timestamp: float = field(default_factory=time.time)
    tested: bool = False
    test_results: Optional[Dict[str, Any]] = None
    

@dataclass
class BypassAnalysisContext:
    """Context for bypass strategy analysis"""
    protection: ProtectionInfo
    binary_model: UnifiedBinaryModel
    target_functions: List[FunctionInfo] = field(default_factory=list)
    target_imports: List[ImportInfo] = field(default_factory=list)
    vulnerability_points: List[Dict[str, Any]] = field(default_factory=list)
    environmental_factors: Dict[str, Any] = field(default_factory=dict)
    

class BypassStrategyEngine:
    """Engine for creating automated bypass strategies"""
    
    def __init__(self):
        self.consensus_engine = MultiModelConsensusEngine()
        self.strategy_cache: Dict[str, BypassStrategy] = {}
        self.technique_patterns = self._initialize_technique_patterns()
        
    def _initialize_technique_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize bypass technique patterns"""
        return {
            "license_check": {
                "techniques": [BypassTechnique.STATIC_PATCHING, BypassTechnique.DYNAMIC_HOOKING],
                "patterns": ["cmp", "test", "jz", "jnz", "call", "ret"],
                "targets": ["license", "serial", "key", "validate", "check"]
            },
            "trial_timer": {
                "techniques": [BypassTechnique.TIME_MANIPULATION, BypassTechnique.API_REDIRECTION],
                "patterns": ["GetSystemTime", "time", "clock", "timer"],
                "targets": ["expire", "trial", "days", "remaining"]
            },
            "hardware_lock": {
                "techniques": [BypassTechnique.HARDWARE_SPOOFING, BypassTechnique.API_REDIRECTION],
                "patterns": ["GetVolumeInformation", "DeviceIoControl", "WMI"],
                "targets": ["hardware", "machine", "device", "serial"]
            },
            "anti_debug": {
                "techniques": [BypassTechnique.DEBUGGER_HIDING, BypassTechnique.MEMORY_MANIPULATION],
                "patterns": ["IsDebuggerPresent", "CheckRemoteDebugger", "int3"],
                "targets": ["debug", "breakpoint", "trace"]
            },
            "vm_detection": {
                "techniques": [BypassTechnique.VM_ESCAPE, BypassTechnique.HARDWARE_SPOOFING],
                "patterns": ["CPUID", "SIDT", "SGDT", "VMX"],
                "targets": ["virtual", "vmware", "vbox", "hypervisor"]
            },
            "crypto": {
                "techniques": [BypassTechnique.CRYPTO_BYPASS, BypassTechnique.MEMORY_MANIPULATION],
                "patterns": ["CryptDecrypt", "AES", "RSA", "hash"],
                "targets": ["encrypt", "decrypt", "cipher", "hash"]
            }
        }
        
    def create_bypass_strategy(self, protection: ProtectionInfo, 
                             binary_model: UnifiedBinaryModel) -> BypassStrategy:
        """Create comprehensive bypass strategy for a protection"""
        
        # Build analysis context
        context = self._build_analysis_context(protection, binary_model)
        
        # Use consensus engine for strategy generation
        consensus_result = self.consensus_engine.create_bypass_strategy_with_consensus(
            protection_info=protection,
            binary_context={
                "format": binary_model.metadata.file_format,
                "architecture": binary_model.metadata.architecture,
                "protection_level": binary_model.protection_analysis.protection_level
            }
        )
        
        # Parse consensus result into structured strategy
        strategy = self._parse_consensus_to_strategy(consensus_result, protection, context)
        
        # Enhance strategy with technical analysis
        strategy = self._enhance_strategy_with_analysis(strategy, context)
        
        # Generate alternatives
        strategy.alternatives = self._generate_alternative_strategies(protection, context)
        
        # Cache the strategy
        cache_key = f"{protection.name}_{protection.type}_{binary_model.metadata.sha256}"
        self.strategy_cache[cache_key] = strategy
        
        logger.info(f"Created bypass strategy for {protection.name} - Complexity: {strategy.complexity.name}")
        
        return strategy
        
    def _build_analysis_context(self, protection: ProtectionInfo, 
                              binary_model: UnifiedBinaryModel) -> BypassAnalysisContext:
        """Build comprehensive analysis context"""
        
        context = BypassAnalysisContext(
            protection=protection,
            binary_model=binary_model
        )
        
        # Find protection-related functions
        protection_keywords = self._get_protection_keywords(protection.type)
        
        for func in binary_model.function_analysis.functions.values():
            if any(keyword in func.name.lower() for keyword in protection_keywords):
                context.target_functions.append(func)
            elif any(keyword in api.lower() for api in func.api_calls for keyword in protection_keywords):
                context.target_functions.append(func)
                
        # Find relevant imports
        for imp in binary_model.symbol_db.imports.values():
            if any(keyword in imp.name.lower() for keyword in protection_keywords):
                context.target_imports.append(imp)
                
        # Identify vulnerability points
        context.vulnerability_points = self._identify_vulnerabilities(protection, binary_model)
        
        # Collect environmental factors
        context.environmental_factors = {
            "has_debug_symbols": binary_model.metadata.has_debug_info,
            "is_packed": binary_model.metadata.is_packed,
            "architecture": binary_model.metadata.architecture,
            "platform": binary_model.metadata.file_format,
            "code_sections": len([s for s in binary_model.section_analysis.sections.values() if s.is_executable])
        }
        
        return context
        
    def _get_protection_keywords(self, protection_type: str) -> List[str]:
        """Get keywords associated with protection type"""
        
        type_keywords = {
            "license": ["license", "serial", "key", "validate", "register", "activate"],
            "trial": ["trial", "expire", "days", "time", "period", "evaluation"],
            "hardware": ["hardware", "hwid", "machine", "device", "volume", "cpu"],
            "network": ["connect", "auth", "server", "verify", "online", "http"],
            "anti_debug": ["debug", "break", "trace", "detect", "IsDebugger"],
            "vm": ["virtual", "vm", "vbox", "vmware", "qemu", "hypervisor"],
            "packer": ["unpack", "decompress", "stub", "loader", "entry"],
            "obfuscator": ["obfuscate", "encrypt", "decode", "transform"],
            "crypto": ["crypt", "aes", "rsa", "hash", "cipher", "encrypt"]
        }
        
        # Find matching keywords
        for key, keywords in type_keywords.items():
            if key in protection_type.lower():
                return keywords
                
        # Default keywords
        return ["protect", "check", "verify", "validate"]
        
    def _identify_vulnerabilities(self, protection: ProtectionInfo, 
                                binary_model: UnifiedBinaryModel) -> List[Dict[str, Any]]:
        """Identify potential vulnerability points"""
        
        vulnerabilities = []
        
        # Check for unprotected comparison points
        for func in binary_model.function_analysis.functions.values():
            if func.is_license_related or protection.name.lower() in func.name.lower():
                # Look for conditional jumps in disassembly
                if func.disassembly and any(instr in func.disassembly for instr in ["jz", "jnz", "je", "jne"]):
                    vulnerabilities.append({
                        "type": "conditional_jump",
                        "location": f"{func.name} @ 0x{func.address:x}",
                        "description": "Conditional jump that may control protection flow",
                        "exploitation": "Patch jump to always take desired branch"
                    })
                    
        # Check for time-based vulnerabilities
        time_imports = ["GetSystemTime", "time", "clock_gettime", "GetTickCount"]
        for imp in binary_model.symbol_db.imports.values():
            if any(t in imp.name for t in time_imports):
                vulnerabilities.append({
                    "type": "time_dependency",
                    "location": f"Import: {imp.name}",
                    "description": "Time-based function that can be hooked",
                    "exploitation": "Hook API to return controlled time values"
                })
                
        # Check for weak crypto implementations
        if protection.is_encryption:
            weak_patterns = ["xor", "simple", "custom", "roll"]
            for func in binary_model.function_analysis.functions.values():
                if func.is_crypto_related and any(p in func.name.lower() for p in weak_patterns):
                    vulnerabilities.append({
                        "type": "weak_crypto",
                        "location": f"{func.name} @ 0x{func.address:x}",
                        "description": "Potentially weak cryptographic implementation",
                        "exploitation": "Analyze and reverse custom crypto algorithm"
                    })
                    
        # Check for hardcoded values
        for string in binary_model.symbol_db.strings.values():
            if string.is_license_related and len(string.value) > 10:
                vulnerabilities.append({
                    "type": "hardcoded_value",
                    "location": f"String @ 0x{string.address:x}" if string.address else "Data section",
                    "description": f"Hardcoded string: {string.value[:50]}...",
                    "exploitation": "Use hardcoded value directly or patch comparisons"
                })
                
        return vulnerabilities
        
    def _parse_consensus_to_strategy(self, consensus_result: ConsensusResult, 
                                   protection: ProtectionInfo,
                                   context: BypassAnalysisContext) -> BypassStrategy:
        """Parse consensus result into structured bypass strategy"""
        
        # Create base strategy
        strategy = BypassStrategy(
            strategy_id=f"bypass_{protection.name}_{int(time.time())}",
            target_protection=protection,
            name=f"{protection.name} Bypass Strategy",
            description=f"Automated bypass strategy for {protection.type} protection",
            complexity=self._assess_complexity(protection, context),
            success_probability=consensus_result.consensus_confidence,
            ai_confidence=consensus_result.consensus_confidence
        )
        
        # Parse steps from consensus content
        steps = self._extract_steps_from_consensus(consensus_result.consensus_content)
        
        # Convert to structured bypass steps
        for i, step_data in enumerate(steps):
            bypass_step = BypassStep(
                step_number=i + 1,
                description=step_data.get("description", ""),
                technique=self._determine_technique(step_data, protection),
                implementation=step_data.get("implementation", ""),
                tools_required=step_data.get("tools", []),
                risk_level=self._assess_step_risk(step_data),
                verification=step_data.get("verification", "Check if protection is bypassed"),
                alternatives=step_data.get("alternatives", [])
            )
            strategy.steps.append(bypass_step)
            
        # Extract prerequisites
        strategy.prerequisites = self._extract_prerequisites(consensus_result.consensus_content)
        
        # Collect all required tools
        for step in strategy.steps:
            strategy.tools_required.update(step.tools_required)
            
        # Estimate time
        strategy.estimated_time = self._estimate_bypass_time(strategy)
        
        return strategy
        
    def _extract_steps_from_consensus(self, consensus_content: str) -> List[Dict[str, Any]]:
        """Extract structured steps from consensus content"""
        
        steps = []
        current_step = {}
        
        lines = consensus_content.split("\n")
        in_step = False
        step_number = 0
        
        for line in lines:
            # Detect step markers
            if any(marker in line.lower() for marker in ["step", "phase", "stage"]) and any(c.isdigit() for c in line):
                if current_step:
                    steps.append(current_step)
                step_number += 1
                current_step = {
                    "number": step_number,
                    "description": line.strip(),
                    "details": []
                }
                in_step = True
            elif in_step and line.strip():
                # Categorize step content
                line_lower = line.lower()
                if any(tool in line_lower for tool in ["frida", "ghidra", "x64dbg", "ida", "radare2"]):
                    if "tools" not in current_step:
                        current_step["tools"] = []
                    current_step["tools"].append(line.strip())
                elif "implement" in line_lower or "code" in line_lower:
                    if "implementation" not in current_step:
                        current_step["implementation"] = ""
                    current_step["implementation"] += line + "\n"
                elif "verify" in line_lower or "check" in line_lower:
                    current_step["verification"] = line.strip()
                elif "alternative" in line_lower or "instead" in line_lower:
                    if "alternatives" not in current_step:
                        current_step["alternatives"] = []
                    current_step["alternatives"].append(line.strip())
                else:
                    current_step["details"].append(line.strip())
                    
        # Add last step
        if current_step:
            steps.append(current_step)
            
        # If no structured steps found, create generic ones
        if not steps:
            steps = self._create_generic_steps(consensus_content)
            
        return steps
        
    def _create_generic_steps(self, content: str) -> List[Dict[str, Any]]:
        """Create generic steps from unstructured content"""
        
        # Split content into logical sections
        sections = content.split("\n\n")
        steps = []
        
        for i, section in enumerate(sections):
            if section.strip():
                steps.append({
                    "number": i + 1,
                    "description": f"Bypass Phase {i + 1}",
                    "implementation": section.strip(),
                    "tools": ["Frida", "Python"],  # Default tools
                    "verification": "Verify protection is bypassed"
                })
                
        return steps
        
    def _determine_technique(self, step_data: Dict[str, Any], 
                           protection: ProtectionInfo) -> BypassTechnique:
        """Determine bypass technique from step data"""
        
        step_text = (step_data.get("description", "") + " " + 
                    step_data.get("implementation", "")).lower()
        
        # Check for technique indicators
        if any(word in step_text for word in ["patch", "modify", "nop", "change bytes"]):
            return BypassTechnique.STATIC_PATCHING
        elif any(word in step_text for word in ["hook", "intercept", "attach", "frida"]):
            return BypassTechnique.DYNAMIC_HOOKING
        elif any(word in step_text for word in ["memory", "writeprocessmemory", "virtualprotect"]):
            return BypassTechnique.MEMORY_MANIPULATION
        elif any(word in step_text for word in ["redirect", "detour", "import"]):
            return BypassTechnique.API_REDIRECTION
        elif any(word in step_text for word in ["time", "clock", "date", "timer"]):
            return BypassTechnique.TIME_MANIPULATION
        elif any(word in step_text for word in ["hardware", "serial", "hwid", "device"]):
            return BypassTechnique.HARDWARE_SPOOFING
        elif any(word in step_text for word in ["network", "socket", "http", "packet"]):
            return BypassTechnique.NETWORK_INTERCEPTION
        elif any(word in step_text for word in ["decrypt", "cipher", "key", "crypto"]):
            return BypassTechnique.CRYPTO_BYPASS
        elif any(word in step_text for word in ["vm", "virtual", "hypervisor"]):
            return BypassTechnique.VM_ESCAPE
        elif any(word in step_text for word in ["debug", "anti", "detect"]):
            return BypassTechnique.DEBUGGER_HIDING
        else:
            # Default based on protection type
            protection_defaults = {
                "license": BypassTechnique.STATIC_PATCHING,
                "trial": BypassTechnique.TIME_MANIPULATION,
                "hardware": BypassTechnique.HARDWARE_SPOOFING,
                "network": BypassTechnique.NETWORK_INTERCEPTION,
                "anti_debug": BypassTechnique.DEBUGGER_HIDING,
                "vm": BypassTechnique.VM_ESCAPE,
                "crypto": BypassTechnique.CRYPTO_BYPASS
            }
            
            for key, technique in protection_defaults.items():
                if key in protection.type.lower():
                    return technique
                    
            return BypassTechnique.DYNAMIC_HOOKING  # Default
            
    def _assess_step_risk(self, step_data: Dict[str, Any]) -> BypassRisk:
        """Assess risk level of a bypass step"""
        
        step_text = str(step_data).lower()
        
        # High risk indicators
        if any(word in step_text for word in ["kernel", "driver", "system", "ring0"]):
            return BypassRisk.CRITICAL
        elif any(word in step_text for word in ["memory", "inject", "patch executable"]):
            return BypassRisk.HIGH
        elif any(word in step_text for word in ["hook", "detour", "redirect"]):
            return BypassRisk.MEDIUM
        elif any(word in step_text for word in ["config", "file", "registry"]):
            return BypassRisk.LOW
        else:
            return BypassRisk.MINIMAL
            
    def _extract_prerequisites(self, content: str) -> List[str]:
        """Extract prerequisites from strategy content"""
        
        prerequisites = []
        
        # Common prerequisites patterns
        prereq_patterns = [
            "require", "need", "must have", "prerequisite", "before", "ensure"
        ]
        
        lines = content.split("\n")
        for line in lines:
            if any(pattern in line.lower() for pattern in prereq_patterns):
                prerequisites.append(line.strip())
                
        # Add default prerequisites based on content
        if "admin" in content.lower() or "administrator" in content.lower():
            prerequisites.append("Administrator/root privileges required")
        if "frida" in content.lower():
            prerequisites.append("Frida framework installed and configured")
        if "kernel" in content.lower():
            prerequisites.append("Kernel-level access may be required")
            
        return prerequisites
        
    def _assess_complexity(self, protection: ProtectionInfo, 
                         context: BypassAnalysisContext) -> BypassComplexity:
        """Assess overall bypass complexity"""
        
        score = 0
        
        # Protection characteristics
        if protection.is_vm_protection:
            score += 3
        if protection.is_encryption:
            score += 2
        if protection.is_anti_debug:
            score += 1
        if protection.is_anti_vm:
            score += 1
            
        # Binary characteristics
        if context.binary_model.metadata.is_packed:
            score += 2
        if not context.binary_model.metadata.has_debug_info:
            score += 1
        if context.binary_model.protection_analysis.protection_level in ["heavy", "extreme"]:
            score += 2
            
        # Target complexity
        if len(context.target_functions) == 0:
            score += 2  # No clear targets
        if len(context.vulnerability_points) == 0:
            score += 1  # No obvious vulnerabilities
            
        # Map score to complexity
        if score >= 8:
            return BypassComplexity.ADVANCED
        elif score >= 6:
            return BypassComplexity.COMPLEX
        elif score >= 4:
            return BypassComplexity.MODERATE
        elif score >= 2:
            return BypassComplexity.SIMPLE
        else:
            return BypassComplexity.TRIVIAL
            
    def _estimate_bypass_time(self, strategy: BypassStrategy) -> str:
        """Estimate time required for bypass"""
        
        base_time = {
            BypassComplexity.TRIVIAL: 5,
            BypassComplexity.SIMPLE: 15,
            BypassComplexity.MODERATE: 60,
            BypassComplexity.COMPLEX: 240,
            BypassComplexity.ADVANCED: 480
        }
        
        minutes = base_time.get(strategy.complexity, 120)
        
        # Adjust based on steps
        minutes += len(strategy.steps) * 10
        
        # Format time estimate
        if minutes < 60:
            return f"{minutes} minutes"
        elif minutes < 480:
            hours = minutes // 60
            mins = minutes % 60
            return f"{hours} hours {mins} minutes"
        else:
            days = minutes // (60 * 8)  # Assuming 8 hour work days
            return f"{days} days"
            
    def _enhance_strategy_with_analysis(self, strategy: BypassStrategy,
                                      context: BypassAnalysisContext) -> BypassStrategy:
        """Enhance strategy with technical analysis"""
        
        # Add specific targets to steps
        for step in strategy.steps:
            if step.technique == BypassTechnique.STATIC_PATCHING:
                # Add specific patch locations
                patch_targets = []
                for func in context.target_functions:
                    patch_targets.append(f"Patch function {func.name} at 0x{func.address:x}")
                if patch_targets:
                    step.implementation += "\n\nSpecific targets:\n" + "\n".join(patch_targets)
                    
            elif step.technique == BypassTechnique.DYNAMIC_HOOKING:
                # Add specific hook points
                hook_targets = []
                for imp in context.target_imports:
                    hook_targets.append(f"Hook {imp.name} from {imp.library}")
                if hook_targets:
                    step.implementation += "\n\nHook points:\n" + "\n".join(hook_targets)
                    
        # Add vulnerability-specific guidance
        if context.vulnerability_points:
            vuln_step = BypassStep(
                step_number=0,  # Will be renumbered
                description="Exploit identified vulnerabilities",
                technique=BypassTechnique.STATIC_PATCHING,
                implementation=self._format_vulnerability_exploits(context.vulnerability_points),
                tools_required=["Hex editor", "Disassembler"],
                risk_level=BypassRisk.LOW
            )
            strategy.steps.insert(0, vuln_step)
            
            # Renumber steps
            for i, step in enumerate(strategy.steps):
                step.step_number = i + 1
                
        return strategy
        
    def _format_vulnerability_exploits(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Format vulnerability exploitation instructions"""
        
        exploit_text = "Identified vulnerabilities and exploitation methods:\n\n"
        
        for vuln in vulnerabilities:
            exploit_text += f"## {vuln['type'].upper()}\n"
            exploit_text += f"Location: {vuln['location']}\n"
            exploit_text += f"Description: {vuln['description']}\n"
            exploit_text += f"Exploitation: {vuln['exploitation']}\n\n"
            
        return exploit_text
        
    def _generate_alternative_strategies(self, protection: ProtectionInfo,
                                       context: BypassAnalysisContext) -> List[BypassStrategy]:
        """Generate alternative bypass strategies"""
        
        alternatives = []
        
        # Generate technique-based alternatives
        protection_type = protection.type.lower()
        
        if "license" in protection_type or "serial" in protection_type:
            # Alternative 1: Keygen approach
            keygen_strategy = BypassStrategy(
                strategy_id=f"keygen_{protection.name}_{int(time.time())}",
                target_protection=protection,
                name="Keygen Creation Strategy",
                description="Reverse engineer validation algorithm and create key generator",
                complexity=BypassComplexity.COMPLEX,
                success_probability=0.7,
                steps=[
                    BypassStep(
                        step_number=1,
                        description="Analyze license validation algorithm",
                        technique=BypassTechnique.CRYPTO_BYPASS,
                        implementation="Use debugger to trace validation flow and identify algorithm",
                        tools_required=["IDA Pro", "x64dbg"],
                        risk_level=BypassRisk.LOW
                    ),
                    BypassStep(
                        step_number=2,
                        description="Reverse engineer key generation",
                        technique=BypassTechnique.CRYPTO_BYPASS,
                        implementation="Implement validation algorithm in reverse",
                        tools_required=["Python", "Crypto libraries"],
                        risk_level=BypassRisk.MINIMAL
                    )
                ]
            )
            alternatives.append(keygen_strategy)
            
        elif "trial" in protection_type or "time" in protection_type:
            # Alternative: Registry/file manipulation
            file_strategy = BypassStrategy(
                strategy_id=f"file_manip_{protection.name}_{int(time.time())}",
                target_protection=protection,
                name="Trial Data Manipulation",
                description="Manipulate stored trial data to reset or extend trial",
                complexity=BypassComplexity.SIMPLE,
                success_probability=0.6,
                steps=[
                    BypassStep(
                        step_number=1,
                        description="Locate trial data storage",
                        technique=BypassTechnique.MEMORY_MANIPULATION,
                        implementation="Monitor file/registry access during trial check",
                        tools_required=["Process Monitor", "RegShot"],
                        risk_level=BypassRisk.LOW
                    ),
                    BypassStep(
                        step_number=2,
                        description="Modify trial data",
                        technique=BypassTechnique.STATIC_PATCHING,
                        implementation="Reset trial timestamps or counters",
                        tools_required=["Registry Editor", "Hex Editor"],
                        risk_level=BypassRisk.LOW
                    )
                ]
            )
            alternatives.append(file_strategy)
            
        elif "hardware" in protection_type:
            # Alternative: Virtual environment
            vm_strategy = BypassStrategy(
                strategy_id=f"vm_bypass_{protection.name}_{int(time.time())}",
                target_protection=protection,
                name="Virtual Environment Bypass",
                description="Use VM with controlled hardware IDs",
                complexity=BypassComplexity.MODERATE,
                success_probability=0.5,
                steps=[
                    BypassStep(
                        step_number=1,
                        description="Setup VM with custom hardware IDs",
                        technique=BypassTechnique.VM_ESCAPE,
                        implementation="Configure VM to report specific hardware serials",
                        tools_required=["VMware", "VirtualBox"],
                        risk_level=BypassRisk.MINIMAL
                    )
                ]
            )
            alternatives.append(vm_strategy)
            
        return alternatives
        
    def create_multi_protection_strategy(self, protections: List[ProtectionInfo],
                                       binary_model: UnifiedBinaryModel) -> BypassStrategy:
        """Create unified strategy for multiple protections"""
        
        # Create individual strategies
        individual_strategies = []
        for protection in protections:
            strategy = self.create_bypass_strategy(protection, binary_model)
            individual_strategies.append(strategy)
            
        # Merge into unified strategy
        unified = BypassStrategy(
            strategy_id=f"unified_{int(time.time())}",
            target_protection=protections[0],  # Primary protection
            name="Unified Multi-Protection Bypass",
            description=f"Comprehensive bypass for {len(protections)} protections",
            complexity=BypassComplexity.ADVANCED,
            success_probability=min(s.success_probability for s in individual_strategies)
        )
        
        # Combine and order steps
        all_steps = []
        for strategy in individual_strategies:
            for step in strategy.steps:
                # Clone step with protection prefix
                new_step = BypassStep(
                    step_number=len(all_steps) + 1,
                    description=f"[{strategy.target_protection.name}] {step.description}",
                    technique=step.technique,
                    implementation=step.implementation,
                    tools_required=step.tools_required,
                    risk_level=step.risk_level,
                    verification=step.verification
                )
                all_steps.append(new_step)
                
        # Order steps by risk (low risk first) and technique
        all_steps.sort(key=lambda s: (s.risk_level.value, s.technique.value))
        
        # Renumber
        for i, step in enumerate(all_steps):
            step.step_number = i + 1
            
        unified.steps = all_steps
        
        # Combine prerequisites and tools
        for strategy in individual_strategies:
            unified.prerequisites.extend(strategy.prerequisites)
            unified.tools_required.update(strategy.tools_required)
            
        # Remove duplicates
        unified.prerequisites = list(set(unified.prerequisites))
        
        return unified
        
    def export_strategy(self, strategy: BypassStrategy, format: str = "markdown") -> str:
        """Export strategy to various formats"""
        
        if format == "markdown":
            return self._export_markdown(strategy)
        elif format == "json":
            return self._export_json(strategy)
        elif format == "html":
            return self._export_html(strategy)
        else:
            raise ValueError(f"Unsupported export format: {format}")
            
    def _export_markdown(self, strategy: BypassStrategy) -> str:
        """Export strategy as markdown"""
        
        md = f"# {strategy.name}\n\n"
        md += f"**Target Protection:** {strategy.target_protection.name} ({strategy.target_protection.type})\n"
        md += f"**Complexity:** {strategy.complexity.name}\n"
        md += f"**Success Probability:** {strategy.success_probability:.1%}\n"
        md += f"**Estimated Time:** {strategy.estimated_time}\n"
        md += f"**AI Confidence:** {strategy.ai_confidence:.1%}\n\n"
        
        md += f"## Description\n{strategy.description}\n\n"
        
        if strategy.prerequisites:
            md += "## Prerequisites\n"
            for prereq in strategy.prerequisites:
                md += f"- {prereq}\n"
            md += "\n"
            
        if strategy.tools_required:
            md += "## Required Tools\n"
            for tool in sorted(strategy.tools_required):
                md += f"- {tool}\n"
            md += "\n"
            
        md += "## Bypass Steps\n\n"
        for step in strategy.steps:
            md += f"### Step {step.step_number}: {step.description}\n"
            md += f"**Technique:** {step.technique.value}\n"
            md += f"**Risk Level:** {step.risk_level.name}\n\n"
            md += f"**Implementation:**\n```\n{step.implementation}\n```\n\n"
            
            if step.verification:
                md += f"**Verification:** {step.verification}\n\n"
                
            if step.alternatives:
                md += "**Alternatives:**\n"
                for alt in step.alternatives:
                    md += f"- {alt}\n"
                md += "\n"
                
        if strategy.alternatives:
            md += "## Alternative Strategies\n\n"
            for alt in strategy.alternatives:
                md += f"### {alt.name}\n"
                md += f"- Complexity: {alt.complexity.name}\n"
                md += f"- Success Rate: {alt.success_probability:.1%}\n"
                md += f"- Steps: {len(alt.steps)}\n\n"
                
        return md
        
    def _export_json(self, strategy: BypassStrategy) -> str:
        """Export strategy as JSON"""
        
        data = {
            "strategy_id": strategy.strategy_id,
            "name": strategy.name,
            "description": strategy.description,
            "target_protection": {
                "name": strategy.target_protection.name,
                "type": strategy.target_protection.type,
                "confidence": strategy.target_protection.confidence
            },
            "complexity": strategy.complexity.name,
            "success_probability": strategy.success_probability,
            "ai_confidence": strategy.ai_confidence,
            "estimated_time": strategy.estimated_time,
            "prerequisites": strategy.prerequisites,
            "tools_required": list(strategy.tools_required),
            "steps": [
                {
                    "number": step.step_number,
                    "description": step.description,
                    "technique": step.technique.value,
                    "implementation": step.implementation,
                    "tools": step.tools_required,
                    "risk": step.risk_level.name,
                    "verification": step.verification,
                    "alternatives": step.alternatives
                }
                for step in strategy.steps
            ],
            "generation_timestamp": strategy.generation_timestamp
        }
        
        return json.dumps(data, indent=2)
        
    def _export_html(self, strategy: BypassStrategy) -> str:
        """Export strategy as HTML"""
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>{strategy.name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .metadata {{ background: #f0f0f0; padding: 10px; border-radius: 5px; }}
        .step {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .risk-MINIMAL {{ border-color: #28a745; }}
        .risk-LOW {{ border-color: #17a2b8; }}
        .risk-MEDIUM {{ border-color: #ffc107; }}
        .risk-HIGH {{ border-color: #fd7e14; }}
        .risk-CRITICAL {{ border-color: #dc3545; }}
        pre {{ background: #f8f9fa; padding: 10px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>{strategy.name}</h1>
    
    <div class="metadata">
        <p><strong>Target:</strong> {strategy.target_protection.name}</p>
        <p><strong>Complexity:</strong> {strategy.complexity.name}</p>
        <p><strong>Success Rate:</strong> {strategy.success_probability:.1%}</p>
        <p><strong>Time Required:</strong> {strategy.estimated_time}</p>
    </div>
    
    <h2>Steps</h2>
"""
        
        for step in strategy.steps:
            html += f"""
    <div class="step risk-{step.risk_level.name}">
        <h3>Step {step.step_number}: {step.description}</h3>
        <p><strong>Technique:</strong> {step.technique.value}</p>
        <p><strong>Risk:</strong> {step.risk_level.name}</p>
        <pre>{step.implementation}</pre>
        <p><strong>Verification:</strong> {step.verification}</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        
        return html