"""
Enhanced AI Script Generator V2

Context-aware script generation that integrates with the unified binary model
from Phase 2 for more intelligent and targeted script creation.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from ..core.analysis.unified_model.model import (
    FunctionInfo,
    ImportInfo,
    ProtectionInfo,
    SectionInfo,
    StringInfo,
    UnifiedBinaryModel
)
from ..utils.logger import get_logger
from .ai_script_generator import (
    AIScriptGenerator,
    GeneratedScript,
    ProtectionType,
    ScriptGenerationResult,
    ScriptType
)
from .consensus_engine import ConsensusResult, ModelExpertise, MultiModelConsensusEngine

logger = get_logger(__name__)


@dataclass
class EnhancedScriptContext:
    """Enhanced context for script generation with unified model integration"""
    binary_model: UnifiedBinaryModel
    target_functions: List[FunctionInfo] = field(default_factory=list)
    target_imports: List[ImportInfo] = field(default_factory=list)
    relevant_strings: List[StringInfo] = field(default_factory=list)
    protection_targets: List[ProtectionInfo] = field(default_factory=list)
    code_sections: List[SectionInfo] = field(default_factory=list)
    
    # AI-enhanced attributes
    ai_confidence: float = 0.0
    ai_insights: Dict[str, Any] = field(default_factory=dict)
    recommended_approaches: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary for AI consumption"""
        return {
            "binary_metadata": {
                "format": self.binary_model.metadata.file_format,
                "architecture": self.binary_model.metadata.architecture,
                "file_size": self.binary_model.metadata.file_size,
                "is_packed": self.binary_model.metadata.is_packed,
                "has_debug_info": self.binary_model.metadata.has_debug_info
            },
            "target_functions": [
                {
                    "name": f.name,
                    "address": f"0x{f.address:x}",
                    "size": f.size,
                    "is_license_related": f.is_license_related,
                    "is_crypto_related": f.is_crypto_related,
                    "api_calls": f.api_calls,
                    "has_decompiled_code": bool(f.decompiled_code)
                }
                for f in self.target_functions
            ],
            "target_imports": [
                {
                    "name": i.name,
                    "library": i.library,
                    "address": f"0x{i.address:x}" if i.address else None
                }
                for i in self.target_imports
            ],
            "relevant_strings": [
                {
                    "value": s.value[:100],  # Truncate long strings
                    "is_license_related": s.is_license_related,
                    "section": s.section
                }
                for s in self.relevant_strings[:20]  # Limit to top 20
            ],
            "protections": [
                {
                    "name": p.name,
                    "type": p.type,
                    "confidence": p.confidence,
                    "is_vm_protection": p.is_vm_protection,
                    "is_encryption": p.is_encryption
                }
                for p in self.protection_targets
            ],
            "code_sections": [
                {
                    "name": s.name,
                    "address": f"0x{s.address:x}",
                    "size": s.size,
                    "entropy": s.entropy,
                    "is_executable": s.is_executable,
                    "is_packed": s.is_packed
                }
                for s in self.code_sections
            ],
            "ai_insights": self.ai_insights,
            "recommended_approaches": self.recommended_approaches
        }


class AIScriptGeneratorV2(AIScriptGenerator):
    """Enhanced AI Script Generator with unified binary model integration"""
    
    def __init__(self):
        super().__init__()
        self.consensus_engine = MultiModelConsensusEngine()
        self._context_cache: Dict[str, EnhancedScriptContext] = {}
        
    def generate_script_with_context(self, 
                                   unified_model: UnifiedBinaryModel,
                                   script_type: ScriptType,
                                   target_protection: Optional[ProtectionType] = None,
                                   custom_prompt: Optional[str] = None) -> ScriptGenerationResult:
        """Generate script using unified binary model context"""
        
        # Build enhanced context from unified model
        context = self._build_enhanced_context(unified_model, target_protection)
        
        # Cache context for reuse
        cache_key = f"{unified_model.metadata.sha256}_{script_type.value}_{target_protection.value if target_protection else 'all'}"
        self._context_cache[cache_key] = context
        
        # Prepare generation prompt
        if custom_prompt:
            prompt = custom_prompt
        else:
            prompt = self._create_intelligent_prompt(context, script_type, target_protection)
        
        # Use consensus engine for generation
        required_expertise = self._determine_required_expertise(context, target_protection)
        
        consensus_result = self.consensus_engine.generate_script_with_consensus(
            prompt=prompt,
            script_type=script_type.value,
            context_data=context.to_dict(),
            required_expertise=required_expertise
        )
        
        # Extract and validate generated script
        generated_script = self._extract_script_from_consensus(consensus_result, script_type)
        
        # Enhance with context-specific optimizations
        enhanced_script = self._enhance_script_with_context(generated_script, context)
        
        # Create result
        result = ScriptGenerationResult(
            scripts=[enhanced_script],
            success=True,
            errors=[],
            warnings=[],
            ai_confidence=consensus_result.consensus_confidence,
            generation_time=consensus_result.processing_time,
            metadata={
                "consensus_agreement": consensus_result.agreement_score,
                "models_used": len(consensus_result.individual_responses),
                "context_enhanced": True,
                "unified_model_version": unified_model.version
            }
        )
        
        # Log generation
        logger.info(f"Generated {script_type.value} script with context - Confidence: {result.ai_confidence:.2f}")
        
        return result
    
    def _build_enhanced_context(self, unified_model: UnifiedBinaryModel, 
                              target_protection: Optional[ProtectionType]) -> EnhancedScriptContext:
        """Build enhanced context from unified binary model"""
        
        context = EnhancedScriptContext(binary_model=unified_model)
        
        # Extract target functions based on protection type
        if target_protection:
            context.target_functions = self._find_protection_related_functions(
                unified_model, target_protection
            )
        else:
            # Get all interesting functions
            context.target_functions = [
                f for f in unified_model.function_analysis.functions.values()
                if f.is_license_related or f.is_crypto_related or f.is_exported
            ]
        
        # Extract relevant imports
        context.target_imports = self._find_relevant_imports(unified_model, target_protection)
        
        # Extract relevant strings
        context.relevant_strings = unified_model.symbol_db.get_license_related_strings()
        
        # Extract protection information
        context.protection_targets = list(unified_model.protection_analysis.protections.values())
        
        # Extract executable sections
        context.code_sections = [
            s for s in unified_model.section_analysis.sections.values()
            if s.is_executable or s.contains_code
        ]
        
        # Generate AI insights
        context.ai_insights = self._generate_ai_insights(unified_model)
        
        # Generate recommended approaches
        context.recommended_approaches = self._generate_approach_recommendations(
            unified_model, target_protection
        )
        
        # Calculate overall confidence
        context.ai_confidence = self._calculate_context_confidence(context)
        
        return context
    
    def _find_protection_related_functions(self, unified_model: UnifiedBinaryModel,
                                         protection_type: ProtectionType) -> List[FunctionInfo]:
        """Find functions related to specific protection type"""
        
        related_functions = []
        
        # Define patterns for each protection type
        protection_patterns = {
            ProtectionType.LICENSE_CHECK: [
                "license", "serial", "key", "validate", "register", "activation", "unlock"
            ],
            ProtectionType.TRIAL_TIMER: [
                "trial", "expire", "timer", "days", "remaining", "evaluation", "period"
            ],
            ProtectionType.HARDWARE_LOCK: [
                "hardware", "hwid", "machine", "fingerprint", "device", "cpu", "disk"
            ],
            ProtectionType.NETWORK_AUTH: [
                "auth", "connect", "server", "network", "verify", "online", "remote"
            ],
            ProtectionType.VM_DETECTION: [
                "vm", "virtual", "detect", "sandbox", "emulator", "hypervisor"
            ],
            ProtectionType.ANTI_DEBUG: [
                "debug", "debugger", "breakpoint", "trace", "detect", "anti"
            ],
            ProtectionType.OBFUSCATION: [
                "obfuscate", "encrypt", "decode", "unpack", "decrypt", "deobfuscate"
            ],
            ProtectionType.CRYPTOGRAPHIC: [
                "crypt", "hash", "aes", "rsa", "encrypt", "decrypt", "cipher"
            ]
        }
        
        patterns = protection_patterns.get(protection_type, [])
        
        # Search functions by name patterns
        for func in unified_model.function_analysis.functions.values():
            func_name_lower = func.name.lower()
            
            # Check name patterns
            if any(pattern in func_name_lower for pattern in patterns):
                related_functions.append(func)
                continue
            
            # Check API calls
            for api_call in func.api_calls:
                if any(pattern in api_call.lower() for pattern in patterns):
                    related_functions.append(func)
                    break
            
            # Check if already marked as protection-related
            if protection_type == ProtectionType.LICENSE_CHECK and func.is_license_related:
                related_functions.append(func)
            elif protection_type == ProtectionType.CRYPTOGRAPHIC and func.is_crypto_related:
                related_functions.append(func)
        
        # Sort by relevance (prioritize exported and larger functions)
        related_functions.sort(
            key=lambda f: (f.is_exported, f.size or 0, len(f.api_calls)),
            reverse=True
        )
        
        return related_functions[:10]  # Return top 10 most relevant
    
    def _find_relevant_imports(self, unified_model: UnifiedBinaryModel,
                             target_protection: Optional[ProtectionType]) -> List[ImportInfo]:
        """Find imports relevant to protection bypass"""
        
        relevant_imports = []
        
        # Common protection-related API patterns
        protection_apis = {
            ProtectionType.LICENSE_CHECK: [
                "RegQueryValue", "GetVolumeInformation", "CryptHash", "InternetOpen",
                "GetWindowText", "MessageBox", "CreateFile", "ReadFile"
            ],
            ProtectionType.TRIAL_TIMER: [
                "GetSystemTime", "GetLocalTime", "GetTickCount", "QueryPerformanceCounter",
                "SystemTimeToFileTime", "CompareFileTime", "time", "gettimeofday"
            ],
            ProtectionType.HARDWARE_LOCK: [
                "GetVolumeInformation", "GetComputerName", "GetSystemInfo", "DeviceIoControl",
                "WMI", "GetAdaptersInfo", "CPUID", "GetSystemFirmwareTable"
            ],
            ProtectionType.NETWORK_AUTH: [
                "InternetOpen", "InternetConnect", "HttpSendRequest", "WinHttpOpen",
                "WSAStartup", "connect", "send", "recv", "SSL_", "curl_"
            ],
            ProtectionType.VM_DETECTION: [
                "GetSystemInfo", "CPUID", "NtQuerySystemInformation", "EnumProcesses",
                "GetModuleFileName", "RegOpenKey", "CreateToolhelp32Snapshot"
            ],
            ProtectionType.ANTI_DEBUG: [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                "OutputDebugString", "GetTickCount", "SetUnhandledExceptionFilter"
            ],
            ProtectionType.CRYPTOGRAPHIC: [
                "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptDecrypt",
                "BCryptOpenAlgorithmProvider", "AES_", "RSA_", "SHA", "MD5"
            ]
        }
        
        # Get relevant API patterns
        if target_protection:
            patterns = protection_apis.get(target_protection, [])
        else:
            # Get all protection patterns
            patterns = []
            for api_list in protection_apis.values():
                patterns.extend(api_list)
        
        # Find matching imports
        for import_info in unified_model.symbol_db.imports.values():
            import_name_lower = import_info.name.lower()
            
            for pattern in patterns:
                if pattern.lower() in import_name_lower:
                    relevant_imports.append(import_info)
                    break
        
        return relevant_imports
    
    def _generate_ai_insights(self, unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Generate AI insights from unified model analysis"""
        
        insights = {
            "protection_complexity": self._assess_protection_complexity(unified_model),
            "bypass_difficulty": unified_model.protection_analysis.bypass_difficulty,
            "recommended_strategy": self._recommend_bypass_strategy(unified_model),
            "key_targets": self._identify_key_targets(unified_model),
            "potential_weaknesses": self._identify_weaknesses(unified_model),
            "architecture_considerations": self._get_architecture_considerations(unified_model)
        }
        
        return insights
    
    def _assess_protection_complexity(self, unified_model: UnifiedBinaryModel) -> str:
        """Assess overall protection complexity"""
        
        score = 0
        
        # Check for multiple protections
        protection_count = len(unified_model.protection_analysis.protections)
        score += min(protection_count * 2, 10)
        
        # Check for VM protection
        if any(p.is_vm_protection for p in unified_model.protection_analysis.protections.values()):
            score += 5
        
        # Check for encryption
        if any(p.is_encryption for p in unified_model.protection_analysis.protections.values()):
            score += 3
        
        # Check for anti-debug
        if unified_model.protection_analysis.has_anti_debug:
            score += 2
        
        # Check for code obfuscation
        if unified_model.protection_analysis.is_obfuscated:
            score += 4
        
        # Map score to complexity level
        if score >= 15:
            return "extreme"
        elif score >= 10:
            return "high"
        elif score >= 5:
            return "moderate"
        elif score > 0:
            return "low"
        else:
            return "minimal"
    
    def _recommend_bypass_strategy(self, unified_model: UnifiedBinaryModel) -> str:
        """Recommend primary bypass strategy based on analysis"""
        
        # Check for dominant protection type
        protections = unified_model.protection_analysis.protections
        
        if not protections:
            return "direct_patching"
        
        # Prioritize based on protection characteristics
        if any(p.is_vm_protection for p in protections.values()):
            return "vm_escape_and_hook"
        elif any(p.is_encryption for p in protections.values()):
            return "runtime_decryption_hook"
        elif unified_model.protection_analysis.has_anti_debug:
            return "anti_debug_bypass_first"
        elif unified_model.protection_analysis.is_packed:
            return "unpack_then_patch"
        else:
            return "targeted_function_hook"
    
    def _identify_key_targets(self, unified_model: UnifiedBinaryModel) -> List[Dict[str, Any]]:
        """Identify key targets for bypass"""
        
        targets = []
        
        # Find license check functions
        for func in unified_model.function_analysis.functions.values():
            if func.is_license_related:
                targets.append({
                    "type": "function",
                    "name": func.name,
                    "address": f"0x{func.address:x}",
                    "reason": "license_check_function"
                })
        
        # Find critical imports
        critical_imports = ["IsDebuggerPresent", "CryptDecrypt", "InternetConnect", "GetVolumeInformation"]
        for imp in unified_model.symbol_db.imports.values():
            if any(crit in imp.name for crit in critical_imports):
                targets.append({
                    "type": "import",
                    "name": imp.name,
                    "library": imp.library,
                    "reason": "critical_api_call"
                })
        
        # Find encrypted sections
        for section in unified_model.section_analysis.sections.values():
            if section.is_packed or (section.entropy and section.entropy > 7.5):
                targets.append({
                    "type": "section",
                    "name": section.name,
                    "address": f"0x{section.address:x}",
                    "reason": "high_entropy_packed"
                })
        
        return targets[:5]  # Return top 5 targets
    
    def _identify_weaknesses(self, unified_model: UnifiedBinaryModel) -> List[str]:
        """Identify potential weaknesses in protection"""
        
        weaknesses = []
        
        # Check for debug information
        if unified_model.metadata.has_debug_info:
            weaknesses.append("debug_symbols_present")
        
        # Check for unprotected exports
        unprotected_exports = [
            e for e in unified_model.symbol_db.exports.values()
            if not any(p in e.name.lower() for p in ["check", "verify", "validate"])
        ]
        if unprotected_exports:
            weaknesses.append("unprotected_exported_functions")
        
        # Check for hardcoded strings
        license_strings = unified_model.symbol_db.get_license_related_strings()
        if len(license_strings) > 5:
            weaknesses.append("excessive_license_strings_exposed")
        
        # Check for standard protection patterns
        standard_protections = ["UPX", "ASPack", "PECompact", "Themida", "VMProtect"]
        for protection in unified_model.protection_analysis.protections.values():
            if any(std in protection.name for std in standard_protections):
                weaknesses.append(f"standard_protection_{protection.name.lower()}")
        
        # Check for incomplete anti-debug
        if unified_model.protection_analysis.has_anti_debug:
            # Look for common anti-debug imports
            anti_debug_imports = ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"]
            found_imports = [i for i in unified_model.symbol_db.imports.keys() 
                           if any(api in i for api in anti_debug_imports)]
            if len(found_imports) < 3:
                weaknesses.append("incomplete_anti_debug_coverage")
        
        return weaknesses
    
    def _get_architecture_considerations(self, unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Get architecture-specific considerations"""
        
        arch = unified_model.metadata.architecture.lower()
        
        considerations = {
            "architecture": arch,
            "pointer_size": 8 if "64" in arch else 4,
            "calling_convention": "fastcall" if "64" in arch else "stdcall",
            "register_set": "extended" if "64" in arch else "standard"
        }
        
        # Architecture-specific bypass techniques
        if "64" in arch:
            considerations["techniques"] = [
                "RIP-relative addressing hooks",
                "Extended register manipulation",
                "64-bit syscall interception"
            ]
        elif "arm" in arch:
            considerations["techniques"] = [
                "Thumb mode considerations",
                "ARM/Thumb interworking",
                "Conditional execution bypass"
            ]
        else:
            considerations["techniques"] = [
                "Stack-based parameter passing",
                "SEH chain manipulation",
                "32-bit calling convention hooks"
            ]
        
        return considerations
    
    def _generate_approach_recommendations(self, unified_model: UnifiedBinaryModel,
                                         target_protection: Optional[ProtectionType]) -> List[str]:
        """Generate specific approach recommendations"""
        
        recommendations = []
        
        # Base recommendations on protection analysis
        if unified_model.protection_analysis.is_packed:
            recommendations.append("unpack_binary_first_using_dynamic_analysis")
        
        if unified_model.protection_analysis.has_anti_debug:
            recommendations.append("use_kernel_mode_bypass_or_hypervisor")
        
        if unified_model.protection_analysis.has_anti_vm:
            recommendations.append("use_hardware_assisted_virtualization_bypass")
        
        # Target-specific recommendations
        if target_protection == ProtectionType.LICENSE_CHECK:
            recommendations.extend([
                "hook_license_validation_functions",
                "patch_conditional_jumps_in_verification",
                "redirect_license_file_operations"
            ])
        elif target_protection == ProtectionType.TRIAL_TIMER:
            recommendations.extend([
                "freeze_time_related_api_calls",
                "manipulate_system_time_queries",
                "patch_date_comparison_logic"
            ])
        elif target_protection == ProtectionType.HARDWARE_LOCK:
            recommendations.extend([
                "spoof_hardware_identifiers",
                "hook_wmi_queries",
                "redirect_device_enumeration"
            ])
        
        # Add dynamic vs static approach recommendation
        if unified_model.protection_analysis.protection_level in ["heavy", "extreme"]:
            recommendations.append("prefer_dynamic_runtime_hooks_over_static_patches")
        else:
            recommendations.append("static_binary_patching_feasible")
        
        return recommendations
    
    def _calculate_context_confidence(self, context: EnhancedScriptContext) -> float:
        """Calculate confidence score for the context"""
        
        confidence = 0.5  # Base confidence
        
        # Boost for identified functions
        if context.target_functions:
            confidence += min(len(context.target_functions) * 0.05, 0.2)
        
        # Boost for relevant imports
        if context.target_imports:
            confidence += min(len(context.target_imports) * 0.03, 0.15)
        
        # Boost for protection identification
        if context.protection_targets:
            confidence += min(len(context.protection_targets) * 0.1, 0.3)
        
        # Penalty for high complexity
        complexity = context.ai_insights.get("protection_complexity", "moderate")
        if complexity == "extreme":
            confidence *= 0.7
        elif complexity == "high":
            confidence *= 0.85
        
        # Cap confidence
        return min(confidence, 0.95)
    
    def _create_intelligent_prompt(self, context: EnhancedScriptContext,
                                 script_type: ScriptType,
                                 target_protection: Optional[ProtectionType]) -> str:
        """Create intelligent prompt using context"""
        
        prompt_parts = [
            f"Generate a production-ready {script_type.value} script for binary analysis.",
            f"\nTarget Binary Information:",
            f"- Format: {context.binary_model.metadata.file_format}",
            f"- Architecture: {context.binary_model.metadata.architecture}",
            f"- Protection Level: {context.binary_model.protection_analysis.protection_level}",
            f"- Bypass Difficulty: {context.binary_model.protection_analysis.bypass_difficulty}"
        ]
        
        if target_protection:
            prompt_parts.append(f"\nTarget Protection: {target_protection.value}")
        
        if context.protection_targets:
            prompt_parts.append("\nDetected Protections:")
            for prot in context.protection_targets[:3]:
                prompt_parts.append(f"- {prot.name} ({prot.type}) - Confidence: {prot.confidence:.2f}")
        
        if context.target_functions:
            prompt_parts.append("\nKey Target Functions:")
            for func in context.target_functions[:5]:
                prompt_parts.append(f"- {func.name} at 0x{func.address:x}")
        
        if context.recommended_approaches:
            prompt_parts.append("\nRecommended Approaches:")
            for approach in context.recommended_approaches[:3]:
                prompt_parts.append(f"- {approach}")
        
        prompt_parts.extend([
            "\nRequirements:",
            "1. Generate complete, working code with no placeholders",
            "2. Include proper error handling and logging",
            "3. Target the specific protections identified",
            "4. Use architecture-appropriate techniques",
            "5. Include detailed comments explaining bypass logic"
        ])
        
        return "\n".join(prompt_parts)
    
    def _determine_required_expertise(self, context: EnhancedScriptContext,
                                    target_protection: Optional[ProtectionType]) -> Set[ModelExpertise]:
        """Determine required AI expertise based on context"""
        
        expertise = {ModelExpertise.REVERSE_ENGINEERING}  # Always needed
        
        # Add expertise based on protections
        for protection in context.protection_targets:
            if protection.is_vm_protection:
                expertise.add(ModelExpertise.VM_DETECTION)
            if protection.is_encryption:
                expertise.add(ModelExpertise.CRYPTOGRAPHY)
            if protection.is_anti_debug:
                expertise.add(ModelExpertise.ANTI_DEBUGGING)
        
        # Add expertise based on target protection
        if target_protection:
            if target_protection == ProtectionType.LICENSE_CHECK:
                expertise.add(ModelExpertise.LICENSE_SYSTEMS)
            elif target_protection == ProtectionType.NETWORK_AUTH:
                expertise.add(ModelExpertise.NETWORK_PROTOCOLS)
            elif target_protection == ProtectionType.CRYPTOGRAPHIC:
                expertise.add(ModelExpertise.CRYPTOGRAPHY)
        
        return expertise
    
    def _extract_script_from_consensus(self, consensus_result: ConsensusResult,
                                     script_type: ScriptType) -> GeneratedScript:
        """Extract script from consensus result"""
        
        # Extract script content from consensus
        script_content = consensus_result.consensus_content
        
        # Clean up any markdown formatting
        if "```" in script_content:
            # Extract code block
            lines = script_content.split("\n")
            in_code = False
            code_lines = []
            
            for line in lines:
                if line.startswith("```"):
                    in_code = not in_code
                    continue
                if in_code:
                    code_lines.append(line)
            
            script_content = "\n".join(code_lines)
        
        # Create generated script
        return GeneratedScript(
            script_type=script_type,
            content=script_content,
            target_protection=None,  # Will be set by caller if needed
            confidence=consensus_result.consensus_confidence,
            metadata={
                "consensus_agreement": consensus_result.agreement_score,
                "generation_method": "consensus_ai",
                "model_count": len(consensus_result.individual_responses)
            }
        )
    
    def _enhance_script_with_context(self, script: GeneratedScript,
                                   context: EnhancedScriptContext) -> GeneratedScript:
        """Enhance script with context-specific optimizations"""
        
        enhanced_content = script.content
        
        # Add context-aware header
        header = f"""// Enhanced with binary context analysis
// Target: {context.binary_model.metadata.file_format} {context.binary_model.metadata.architecture}
// Protection Level: {context.binary_model.protection_analysis.protection_level}
// Generated with confidence: {context.ai_confidence:.2f}

"""
        
        # Add target function addresses
        if context.target_functions and script.script_type == ScriptType.FRIDA:
            function_hooks = "\n// Target function hooks\n"
            for func in context.target_functions[:5]:
                function_hooks += f"const {func.name}_addr = ptr('0x{func.address:x}');\n"
            
            enhanced_content = header + function_hooks + "\n" + enhanced_content
        else:
            enhanced_content = header + enhanced_content
        
        # Add architecture-specific optimizations
        if "64" in context.binary_model.metadata.architecture:
            enhanced_content = enhanced_content.replace(
                "Process.pointerSize === 4",
                "Process.pointerSize === 8"
            )
        
        # Update script object
        script.content = enhanced_content
        script.metadata["context_enhanced"] = True
        script.metadata["target_function_count"] = len(context.target_functions)
        
        return script
    
    def analyze_and_generate_bypass(self, unified_model: UnifiedBinaryModel) -> ScriptGenerationResult:
        """Analyze unified model and generate comprehensive bypass script"""
        
        # First, analyze protections with consensus engine
        protection_analysis = self.consensus_engine.analyze_protection_with_consensus(
            binary_data={
                "file_path": unified_model.metadata.file_path,
                "file_size": unified_model.metadata.file_size,
                "protections": len(unified_model.protection_analysis.protections)
            },
            unified_model=unified_model
        )
        
        # Determine primary protection to target
        primary_protection = self._identify_primary_protection(unified_model)
        
        # Generate targeted bypass script
        result = self.generate_script_with_context(
            unified_model=unified_model,
            script_type=ScriptType.FRIDA,  # Default to Frida for runtime bypass
            target_protection=primary_protection
        )
        
        # Add analysis insights to result metadata
        result.metadata["protection_analysis"] = {
            "consensus_confidence": protection_analysis.consensus_confidence,
            "primary_target": primary_protection.value if primary_protection else "general",
            "total_protections": len(unified_model.protection_analysis.protections)
        }
        
        return result
    
    def _identify_primary_protection(self, unified_model: UnifiedBinaryModel) -> Optional[ProtectionType]:
        """Identify primary protection to target"""
        
        # Map protection types to our enum
        type_mapping = {
            "license": ProtectionType.LICENSE_CHECK,
            "trial": ProtectionType.TRIAL_TIMER,
            "hardware": ProtectionType.HARDWARE_LOCK,
            "network": ProtectionType.NETWORK_AUTH,
            "vm": ProtectionType.VM_DETECTION,
            "debug": ProtectionType.ANTI_DEBUG,
            "obfuscator": ProtectionType.OBFUSCATION,
            "crypto": ProtectionType.CRYPTOGRAPHIC
        }
        
        # Find highest confidence protection
        highest_confidence = 0.0
        primary_type = None
        
        for protection in unified_model.protection_analysis.protections.values():
            for key, prot_type in type_mapping.items():
                if key in protection.type.lower() and protection.confidence > highest_confidence:
                    highest_confidence = protection.confidence
                    primary_type = prot_type
        
        return primary_type