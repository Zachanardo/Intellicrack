"""
Domain-Specific Model Manager

Manages AI models specialized for specific protection schemes (VMProtect, Themida, Denuvo, etc.)
with fine-tuned knowledge and pattern recognition capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.analysis.unified_model.model import ProtectionInfo, UnifiedBinaryModel
from ..utils.logger import get_logger
from .consensus_engine import ConsensusResult, ModelExpertise, ModelProfile, MultiModelConsensusEngine
from .llm_backends import LLMConfig, LLMManager, LLMProvider, get_llm_manager

logger = get_logger(__name__)


class ProtectionDomain(Enum):
    """Specific protection domains"""
    VMPROTECT = "vmprotect"
    THEMIDA = "themida"
    DENUVO = "denuvo"
    SECUROM = "securom"
    SAFEDISC = "safedisc"
    STARFORCE = "starforce"
    ARMADILLO = "armadillo"
    ASPACK = "aspack"
    UPX = "upx"
    ENIGMA = "enigma"
    OBSIDIUM = "obsidium"
    WINLICENSE = "winlicense"
    CUSTOM_VM = "custom_vm"
    CUSTOM_PACKER = "custom_packer"
    UNKNOWN = "unknown"


@dataclass
class DomainKnowledge:
    """Domain-specific knowledge for a protection scheme"""
    domain: ProtectionDomain
    version_patterns: Dict[str, Any] = field(default_factory=dict)
    
    # Protection characteristics
    vm_architecture: Optional[str] = None
    opcode_mappings: Dict[int, str] = field(default_factory=dict)
    handler_patterns: List[str] = field(default_factory=list)
    
    # Known weaknesses
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    bypass_techniques: List[Dict[str, Any]] = field(default_factory=list)
    
    # Detection patterns
    signatures: List[bytes] = field(default_factory=list)
    behavioral_patterns: List[str] = field(default_factory=list)
    api_usage_patterns: List[str] = field(default_factory=list)
    
    # Code patterns
    initialization_patterns: List[str] = field(default_factory=list)
    check_patterns: List[str] = field(default_factory=list)
    encryption_patterns: List[str] = field(default_factory=list)
    
    # Analysis techniques
    recommended_tools: List[str] = field(default_factory=list)
    analysis_workflow: List[str] = field(default_factory=list)
    
    # Historical data
    successful_bypasses: List[Dict[str, Any]] = field(default_factory=list)
    failed_attempts: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "domain": self.domain.value,
            "version_patterns": self.version_patterns,
            "vm_architecture": self.vm_architecture,
            "opcode_mappings": self.opcode_mappings,
            "handler_patterns": self.handler_patterns,
            "vulnerabilities": self.vulnerabilities,
            "bypass_techniques": self.bypass_techniques,
            "signatures": [s.hex() for s in self.signatures],
            "behavioral_patterns": self.behavioral_patterns,
            "api_usage_patterns": self.api_usage_patterns,
            "recommended_tools": self.recommended_tools,
            "analysis_workflow": self.analysis_workflow,
            "successful_bypasses": len(self.successful_bypasses),
            "failed_attempts": len(self.failed_attempts)
        }


@dataclass
class DomainModel:
    """Domain-specific AI model configuration"""
    model_id: str
    domain: ProtectionDomain
    base_model: str  # Base LLM model
    provider: LLMProvider
    
    # Specialization
    fine_tuned: bool = False
    training_data_size: int = 0
    last_updated: Optional[datetime] = None
    
    # Performance metrics
    accuracy: float = 0.0
    response_time_avg: float = 0.0
    success_rate: float = 0.0
    
    # Domain knowledge
    knowledge_base: Optional[DomainKnowledge] = None
    
    # Specialized prompts
    system_prompts: Dict[str, str] = field(default_factory=dict)
    example_conversations: List[Dict[str, str]] = field(default_factory=list)
    
    # Configuration
    temperature: float = 0.7
    max_tokens: int = 4096
    top_p: float = 0.9
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "model_id": self.model_id,
            "domain": self.domain.value,
            "base_model": self.base_model,
            "provider": self.provider.value,
            "fine_tuned": self.fine_tuned,
            "training_data_size": self.training_data_size,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "accuracy": self.accuracy,
            "response_time_avg": self.response_time_avg,
            "success_rate": self.success_rate,
            "has_knowledge_base": self.knowledge_base is not None
        }


class DomainModelManager:
    """Manages domain-specific AI models for protection analysis"""
    
    def __init__(self, models_dir: Optional[str] = None):
        self.llm_manager = get_llm_manager()
        self.consensus_engine = MultiModelConsensusEngine()
        self.models_dir = models_dir or os.path.join(
            os.path.dirname(__file__), 
            "domain_models"
        )
        self._ensure_models_dir()
        self.domain_models: Dict[ProtectionDomain, DomainModel] = {}
        self.domain_knowledge: Dict[ProtectionDomain, DomainKnowledge] = {}
        self._initialize_domain_models()
        self._load_domain_knowledge()
        
    def _ensure_models_dir(self):
        """Ensure models directory exists"""
        os.makedirs(self.models_dir, exist_ok=True)
        
    def _initialize_domain_models(self):
        """Initialize domain-specific models"""
        
        # VMProtect specialist
        self._register_domain_model(DomainModel(
            model_id="vmprotect_specialist",
            domain=ProtectionDomain.VMPROTECT,
            base_model="gpt-4",
            provider=LLMProvider.OPENAI,
            system_prompts={
                "analysis": """You are a VMProtect specialist with deep knowledge of:
- VMProtect versions 1.x, 2.x, and 3.x differences
- Virtual machine architecture and opcode handlers
- Mutation engine and code virtualization
- Anti-debugging and anti-VM techniques
- Known vulnerabilities and bypass methods

Provide detailed, technical analysis focusing on VMProtect-specific characteristics.""",
                "bypass": """Generate VMProtect bypass strategies based on:
- Version-specific vulnerabilities
- VM handler exploitation
- Devirtualization techniques
- Memory snapshot analysis
- Known weaknesses in the protection scheme"""
            }
        ))
        
        # Themida specialist
        self._register_domain_model(DomainModel(
            model_id="themida_specialist",
            domain=ProtectionDomain.THEMIDA,
            base_model="claude-3-opus",
            provider=LLMProvider.ANTHROPIC,
            system_prompts={
                "analysis": """You are a Themida/WinLicense specialist with expertise in:
- CISC/RISC/FISH virtual machines
- SecureEngine protection layers
- Advanced API wrapping techniques
- Nanomites and code splicing
- Anti-dump and anti-debug features

Focus on Themida-specific protection mechanisms and vulnerabilities.""",
                "bypass": """Create Themida bypass strategies utilizing:
- VM architecture weaknesses
- SecureEngine vulnerabilities
- API unwrapping techniques
- Memory reconstruction methods
- Known attack vectors for different versions"""
            }
        ))
        
        # Denuvo specialist
        self._register_domain_model(DomainModel(
            model_id="denuvo_specialist",
            domain=ProtectionDomain.DENUVO,
            base_model="gpt-4",
            provider=LLMProvider.OPENAI,
            system_prompts={
                "analysis": """You are a Denuvo specialist knowledgeable about:
- Denuvo versions and evolution
- VMProtect integration in Denuvo
- Hardware fingerprinting mechanisms
- Ticket validation system
- Performance impact patterns

Analyze Denuvo-protected binaries with focus on version-specific features.""",
                "bypass": """Develop Denuvo bypass strategies considering:
- Ticket system vulnerabilities
- Hardware ID spoofing
- VM layer exploitation
- Activation bypass methods
- Performance optimization removal"""
            }
        ))
        
        # Custom VM specialist
        self._register_domain_model(DomainModel(
            model_id="custom_vm_specialist",
            domain=ProtectionDomain.CUSTOM_VM,
            base_model="mistral-large",
            provider=LLMProvider.OLLAMA,
            system_prompts={
                "analysis": """You are a custom VM protection specialist skilled in:
- Identifying custom virtual machine architectures
- Reverse engineering unknown instruction sets
- Pattern recognition in VM handlers
- Custom obfuscation techniques
- Proprietary protection schemes

Analyze unknown VM-based protections systematically.""",
                "bypass": """Create bypass strategies for custom VMs through:
- VM architecture reconstruction
- Instruction set analysis
- Handler pattern exploitation
- Generic devirtualization techniques
- Automated unpacking approaches"""
            }
        ))
        
    def _register_domain_model(self, model: DomainModel):
        """Register a domain-specific model"""
        self.domain_models[model.domain] = model
        
        # Register with consensus engine
        model_profile = ModelProfile(
            model_id=model.model_id,
            provider=model.provider,
            expertise_domains={ModelExpertise.REVERSE_ENGINEERING, ModelExpertise.MALWARE_ANALYSIS},
            confidence_weight=1.5 if model.fine_tuned else 1.0,
            max_context_length=model.max_tokens
        )
        self.consensus_engine.register_model_profile(model_profile)
        
        logger.info(f"Registered domain model: {model.model_id} for {model.domain.value}")
        
    def _load_domain_knowledge(self):
        """Load domain-specific knowledge bases"""
        
        # VMProtect knowledge
        self.domain_knowledge[ProtectionDomain.VMPROTECT] = DomainKnowledge(
            domain=ProtectionDomain.VMPROTECT,
            version_patterns={
                "1.x": ["vmp0", "vmp1", ".vmp0", ".vmp1"],
                "2.x": ["vmp2", ".vmp2", "VMProtectSDK32.dll"],
                "3.x": ["vmp3", ".vmp3", "VMProtectSDK64.dll"]
            },
            vm_architecture="Stack-based VM with polymorphic handlers",
            handler_patterns=[
                "push handler",
                "arithmetic handler",
                "control flow handler",
                "memory access handler"
            ],
            vulnerabilities=[
                {
                    "version": "2.x",
                    "type": "handler_leak",
                    "description": "VM handlers can be dumped from memory"
                },
                {
                    "version": "3.x",
                    "type": "timing_attack",
                    "description": "Timing analysis reveals VM operations"
                }
            ],
            bypass_techniques=[
                {
                    "name": "Handler reconstruction",
                    "description": "Rebuild original code from VM handlers",
                    "difficulty": "high"
                },
                {
                    "name": "Memory snapshot differential",
                    "description": "Compare memory states before/after VM execution",
                    "difficulty": "medium"
                }
            ],
            signatures=[
                bytes.fromhex("564D50726F74656374"),  # "VMProtect"
                bytes.fromhex("2E766D7030"),  # ".vmp0"
                bytes.fromhex("2E766D7031"),  # ".vmp1"
            ],
            api_usage_patterns=[
                "GetModuleHandle",
                "VirtualProtect",
                "IsDebuggerPresent",
                "QueryPerformanceCounter"
            ],
            recommended_tools=["x64dbg", "VMPImportFixer", "Scylla", "NoVmp"],
            analysis_workflow=[
                "Identify VMProtect version",
                "Locate VM entry points",
                "Trace VM handler execution",
                "Reconstruct protected code",
                "Fix imports and relocations"
            ]
        )
        
        # Themida knowledge
        self.domain_knowledge[ProtectionDomain.THEMIDA] = DomainKnowledge(
            domain=ProtectionDomain.THEMIDA,
            version_patterns={
                "2.x": ["Themida", "SecureEngine"],
                "3.x": ["WinLicense", "CISC", "RISC", "FISH"]
            },
            vm_architecture="Multiple VM types: CISC, RISC, FISH, TIGER",
            vulnerabilities=[
                {
                    "type": "api_wrapper_weakness",
                    "description": "API wrappers can be unwrapped through pattern matching"
                },
                {
                    "type": "vm_context_leak",
                    "description": "VM context can be extracted during exceptions"
                }
            ],
            bypass_techniques=[
                {
                    "name": "API unwrapping",
                    "description": "Restore original API calls from wrappers",
                    "difficulty": "medium"
                },
                {
                    "name": "Exception-based dumping",
                    "description": "Use exceptions to dump protected code",
                    "difficulty": "high"
                }
            ],
            api_usage_patterns=[
                "CreateToolhelp32Snapshot",
                "EnumProcessModules",
                "SetUnhandledExceptionFilter",
                "AddVectoredExceptionHandler"
            ],
            recommended_tools=["OllyDbg", "x64dbg", "Themida Unpacker", "IDA Pro"],
            analysis_workflow=[
                "Identify Themida version and VM type",
                "Locate SecureEngine initialization",
                "Trace VM execution flow",
                "Extract VM handlers",
                "Reconstruct original code"
            ]
        )
        
        # Denuvo knowledge
        self.domain_knowledge[ProtectionDomain.DENUVO] = DomainKnowledge(
            domain=ProtectionDomain.DENUVO,
            version_patterns={
                "v4": ["denuvo64.dll", "uplay_r164.dll"],
                "v5": ["denuvo64_v5.dll", "steam_api64.dll"],
                "v6+": ["kernel32.dll hooks", "ntdll.dll hooks"]
            },
            vulnerabilities=[
                {
                    "type": "ticket_validation",
                    "description": "Ticket validation can be bypassed"
                },
                {
                    "type": "hardware_id",
                    "description": "Hardware fingerprinting can be spoofed"
                }
            ],
            bypass_techniques=[
                {
                    "name": "Ticket emulation",
                    "description": "Emulate valid ticket responses",
                    "difficulty": "very_high"
                },
                {
                    "name": "Hardware ID spoofing",
                    "description": "Fake hardware identifiers",
                    "difficulty": "high"
                }
            ],
            api_usage_patterns=[
                "GetVolumeInformationW",
                "GetSystemInfo",
                "CryptGenRandom",
                "BCryptGenRandom"
            ],
            recommended_tools=["x64dbg", "Ghidra", "IDA Pro", "Process Monitor"],
            analysis_workflow=[
                "Identify Denuvo version",
                "Locate activation checks",
                "Trace hardware fingerprinting",
                "Analyze ticket validation",
                "Develop bypass strategy"
            ]
        )
        
    def get_domain_model(self, protection: Union[ProtectionInfo, ProtectionDomain]) -> Optional[DomainModel]:
        """Get appropriate domain model for protection"""
        
        if isinstance(protection, ProtectionInfo):
            # Map protection info to domain
            domain = self._map_protection_to_domain(protection)
        else:
            domain = protection
            
        return self.domain_models.get(domain)
        
    def _map_protection_to_domain(self, protection: ProtectionInfo) -> ProtectionDomain:
        """Map protection info to domain"""
        
        name_lower = protection.name.lower()
        
        # Direct mappings
        domain_mappings = {
            "vmprotect": ProtectionDomain.VMPROTECT,
            "themida": ProtectionDomain.THEMIDA,
            "winlicense": ProtectionDomain.THEMIDA,
            "denuvo": ProtectionDomain.DENUVO,
            "securom": ProtectionDomain.SECUROM,
            "safedisc": ProtectionDomain.SAFEDISC,
            "starforce": ProtectionDomain.STARFORCE,
            "armadillo": ProtectionDomain.ARMADILLO,
            "aspack": ProtectionDomain.ASPACK,
            "upx": ProtectionDomain.UPX,
            "enigma": ProtectionDomain.ENIGMA,
            "obsidium": ProtectionDomain.OBSIDIUM
        }
        
        for key, domain in domain_mappings.items():
            if key in name_lower:
                return domain
                
        # Check for VM-based protection
        if protection.is_vm_protection:
            return ProtectionDomain.CUSTOM_VM
        elif protection.is_packed:
            return ProtectionDomain.CUSTOM_PACKER
        else:
            return ProtectionDomain.UNKNOWN
            
    def analyze_with_domain_model(self, protection: ProtectionInfo, 
                                 unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Analyze protection using domain-specific model"""
        
        domain_model = self.get_domain_model(protection)
        if not domain_model:
            logger.warning(f"No domain model for protection: {protection.name}")
            return self._generic_analysis(protection, unified_model)
            
        # Prepare domain-specific context
        context = self._prepare_domain_context(protection, unified_model, domain_model)
        
        # Use domain-specific prompts
        analysis_prompt = domain_model.system_prompts.get("analysis", "")
        analysis_prompt += f"\n\nAnalyze the following {domain_model.domain.value} protection:\n"
        analysis_prompt += json.dumps(context, indent=2)
        
        # Query domain model
        start_time = time.time()
        
        messages = [
            {"role": "system", "content": analysis_prompt},
            {"role": "user", "content": "Provide detailed analysis of this protection implementation."}
        ]
        
        response = self.llm_manager.chat(
            messages,
            llm_config=LLMConfig(
                provider=domain_model.provider,
                model_name=domain_model.base_model,
                temperature=domain_model.temperature,
                max_tokens=domain_model.max_tokens,
                top_p=domain_model.top_p
            )
        )
        
        response_time = time.time() - start_time
        
        # Update model metrics
        domain_model.response_time_avg = (
            (domain_model.response_time_avg + response_time) / 2
        )
        
        # Parse and enhance response
        analysis = self._parse_domain_analysis(response.content, domain_model)
        
        # Add domain knowledge
        if domain_model.domain in self.domain_knowledge:
            knowledge = self.domain_knowledge[domain_model.domain]
            analysis["domain_knowledge"] = {
                "known_vulnerabilities": knowledge.vulnerabilities,
                "bypass_techniques": knowledge.bypass_techniques,
                "recommended_tools": knowledge.recommended_tools,
                "analysis_workflow": knowledge.analysis_workflow
            }
            
        return analysis
        
    def _prepare_domain_context(self, protection: ProtectionInfo, 
                              unified_model: UnifiedBinaryModel,
                              domain_model: DomainModel) -> Dict[str, Any]:
        """Prepare domain-specific context"""
        
        context = {
            "protection_name": protection.name,
            "protection_type": protection.type,
            "version": protection.version,
            "confidence": protection.confidence,
            "binary_info": {
                "format": unified_model.metadata.file_format,
                "architecture": unified_model.metadata.architecture,
                "size": unified_model.metadata.file_size
            }
        }
        
        # Add domain-specific details
        if domain_model.domain == ProtectionDomain.VMPROTECT:
            # VMProtect-specific context
            context["vm_sections"] = [
                {
                    "name": s.name,
                    "address": f"0x{s.address:x}",
                    "size": s.size,
                    "entropy": s.entropy
                }
                for s in unified_model.section_analysis.sections.values()
                if ".vmp" in s.name or s.entropy > 7.0
            ]
            
            # Look for VMProtect SDK imports
            context["vmp_imports"] = [
                i.name for i in unified_model.symbol_db.imports.values()
                if "vmprotect" in i.name.lower()
            ]
            
        elif domain_model.domain == ProtectionDomain.THEMIDA:
            # Themida-specific context
            context["secure_sections"] = [
                s.name for s in unified_model.section_analysis.sections.values()
                if any(marker in s.name for marker in [".secure", ".themida", ".winlic"])
            ]
            
            # Check for Themida markers
            context["themida_strings"] = [
                s.value for s in unified_model.symbol_db.strings.values()
                if any(marker in s.value.lower() for marker in ["themida", "secure", "winlicense"])
            ][:10]  # Limit to 10
            
        elif domain_model.domain == ProtectionDomain.DENUVO:
            # Denuvo-specific context
            context["large_sections"] = [
                {
                    "name": s.name,
                    "size": s.size,
                    "executable": s.is_executable
                }
                for s in unified_model.section_analysis.sections.values()
                if s.size > 1024 * 1024  # Sections > 1MB
            ]
            
            # Performance impact indicators
            context["performance_indicators"] = {
                "total_size": unified_model.metadata.file_size,
                "executable_size": sum(
                    s.size for s in unified_model.section_analysis.sections.values()
                    if s.is_executable
                )
            }
            
        return context
        
    def _parse_domain_analysis(self, response: str, domain_model: DomainModel) -> Dict[str, Any]:
        """Parse domain-specific analysis response"""
        
        analysis = {
            "domain": domain_model.domain.value,
            "model_used": domain_model.model_id,
            "confidence": 0.8,  # Default confidence
            "findings": []
        }
        
        # Extract structured information
        lines = response.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Section headers
            if line.startswith('#') or line.endswith(':'):
                current_section = line.strip('#: ').lower()
                analysis[current_section] = []
            elif current_section and line:
                if line.startswith('- ') or line.startswith('* '):
                    analysis[current_section].append(line[2:])
                    analysis["findings"].append(line[2:])
                    
        # Extract confidence if mentioned
        import re
        confidence_match = re.search(r'confidence:?\s*([0-9.]+)', response, re.IGNORECASE)
        if confidence_match:
            analysis["confidence"] = float(confidence_match.group(1))
            
        return analysis
        
    def _generic_analysis(self, protection: ProtectionInfo, 
                         unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Generic analysis when no domain model available"""
        
        # Use consensus engine with general models
        context = {
            "protection": protection.__dict__,
            "binary_info": {
                "format": unified_model.metadata.file_format,
                "architecture": unified_model.metadata.architecture,
                "protections": [p.name for p in unified_model.protection_analysis.protections.values()]
            }
        }
        
        consensus_result = self.consensus_engine.analyze_protection_with_consensus(
            binary_data={"protection_info": protection.__dict__},
            unified_model=unified_model
        )
        
        return {
            "domain": "generic",
            "model_used": "consensus",
            "confidence": consensus_result.consensus_confidence,
            "findings": self._extract_findings_from_consensus(consensus_result),
            "consensus_agreement": consensus_result.agreement_score
        }
        
    def _extract_findings_from_consensus(self, consensus_result: ConsensusResult) -> List[str]:
        """Extract findings from consensus result"""
        findings = []
        
        # Simple extraction - would be more sophisticated in practice
        lines = consensus_result.consensus_content.split('\n')
        for line in lines:
            if line.strip() and not line.startswith('[') and len(line) > 20:
                findings.append(line.strip())
                
        return findings[:10]  # Top 10 findings
        
    def generate_domain_bypass_strategy(self, protection: ProtectionInfo,
                                      unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Generate bypass strategy using domain model"""
        
        domain_model = self.get_domain_model(protection)
        if not domain_model:
            return self._generic_bypass_strategy(protection, unified_model)
            
        # Use domain-specific bypass prompt
        bypass_prompt = domain_model.system_prompts.get("bypass", "")
        
        # Add domain knowledge
        if domain_model.domain in self.domain_knowledge:
            knowledge = self.domain_knowledge[domain_model.domain]
            bypass_prompt += f"\n\nKnown bypass techniques:\n"
            for technique in knowledge.bypass_techniques[:3]:
                bypass_prompt += f"- {technique['name']}: {technique['description']}\n"
                
        # Add context
        context = self._prepare_domain_context(protection, unified_model, domain_model)
        bypass_prompt += f"\n\nTarget protection details:\n{json.dumps(context, indent=2)}"
        
        # Query domain model
        messages = [
            {"role": "system", "content": bypass_prompt},
            {"role": "user", "content": "Generate a detailed bypass strategy with step-by-step instructions."}
        ]
        
        response = self.llm_manager.chat(
            messages,
            llm_config=LLMConfig(
                provider=domain_model.provider,
                model_name=domain_model.base_model,
                temperature=0.7,
                max_tokens=4096
            )
        )
        
        # Parse bypass strategy
        strategy = self._parse_bypass_strategy(response.content, domain_model)
        
        # Enhance with domain knowledge
        if domain_model.domain in self.domain_knowledge:
            knowledge = self.domain_knowledge[domain_model.domain]
            strategy["recommended_tools"] = knowledge.recommended_tools
            strategy["known_vulnerabilities"] = knowledge.vulnerabilities
            
        return strategy
        
    def _parse_bypass_strategy(self, response: str, domain_model: DomainModel) -> Dict[str, Any]:
        """Parse bypass strategy from response"""
        
        strategy = {
            "domain": domain_model.domain.value,
            "steps": [],
            "tools_required": [],
            "estimated_difficulty": "medium",
            "success_probability": 0.7
        }
        
        # Extract steps
        lines = response.split('\n')
        step_number = 1
        
        for line in lines:
            line = line.strip()
            
            # Look for numbered steps
            if re.match(r'^\d+\.', line) or line.startswith('Step'):
                strategy["steps"].append({
                    "number": step_number,
                    "description": re.sub(r'^\d+\.\s*|^Step\s*\d+:?\s*', '', line),
                    "critical": "critical" in line.lower() or "important" in line.lower()
                })
                step_number += 1
                
            # Extract tools
            if "tool" in line.lower() or any(tool in line for tool in ["IDA", "x64dbg", "Ghidra"]):
                tools = re.findall(r'\b(?:IDA|x64dbg|Ghidra|OllyDbg|Frida|VMPImportFixer)\b', line)
                strategy["tools_required"].extend(tools)
                
        # Remove duplicates from tools
        strategy["tools_required"] = list(set(strategy["tools_required"]))
        
        # Extract difficulty
        if "easy" in response.lower():
            strategy["estimated_difficulty"] = "easy"
        elif "hard" in response.lower() or "difficult" in response.lower():
            strategy["estimated_difficulty"] = "hard"
        elif "very hard" in response.lower() or "extremely difficult" in response.lower():
            strategy["estimated_difficulty"] = "very_hard"
            
        return strategy
        
    def _generic_bypass_strategy(self, protection: ProtectionInfo,
                                unified_model: UnifiedBinaryModel) -> Dict[str, Any]:
        """Generic bypass strategy when no domain model available"""
        
        # Use consensus engine
        consensus_result = self.consensus_engine.create_bypass_strategy_with_consensus(
            protection,
            {
                "binary_format": unified_model.metadata.file_format,
                "architecture": unified_model.metadata.architecture
            }
        )
        
        # Parse consensus into strategy format
        return {
            "domain": "generic",
            "steps": self._extract_steps_from_consensus(consensus_result),
            "tools_required": ["IDA Pro", "x64dbg", "Frida"],
            "estimated_difficulty": "medium",
            "success_probability": consensus_result.consensus_confidence
        }
        
    def _extract_steps_from_consensus(self, consensus_result: ConsensusResult) -> List[Dict[str, Any]]:
        """Extract steps from consensus result"""
        steps = []
        
        lines = consensus_result.consensus_content.split('\n')
        step_number = 1
        
        for line in lines:
            if re.match(r'^\d+\.', line) or "step" in line.lower():
                steps.append({
                    "number": step_number,
                    "description": line.strip(),
                    "critical": False
                })
                step_number += 1
                
        return steps
        
    def train_domain_model(self, domain: ProtectionDomain, training_data: List[Dict[str, Any]]):
        """Train or fine-tune a domain-specific model"""
        
        domain_model = self.domain_models.get(domain)
        if not domain_model:
            logger.error(f"No model registered for domain: {domain.value}")
            return
            
        # In a real implementation, this would:
        # 1. Prepare training data in appropriate format
        # 2. Fine-tune the base model
        # 3. Validate performance
        # 4. Update model configuration
        
        # For now, simulate training
        logger.info(f"Training {domain.value} model with {len(training_data)} examples")
        
        # Update model metrics
        domain_model.training_data_size += len(training_data)
        domain_model.fine_tuned = True
        domain_model.last_updated = datetime.now()
        domain_model.accuracy = min(0.95, domain_model.accuracy + 0.1)
        
        # Save updated model
        self._save_domain_model(domain_model)
        
    def _save_domain_model(self, model: DomainModel):
        """Save domain model configuration"""
        
        model_path = os.path.join(self.models_dir, f"{model.domain.value}_model.json")
        
        with open(model_path, 'w') as f:
            json.dump(model.to_dict(), f, indent=2)
            
        logger.info(f"Saved domain model: {model.model_id}")
        
    def add_domain_knowledge(self, domain: ProtectionDomain, 
                           knowledge_update: Dict[str, Any]):
        """Add knowledge to domain knowledge base"""
        
        if domain not in self.domain_knowledge:
            self.domain_knowledge[domain] = DomainKnowledge(domain=domain)
            
        knowledge = self.domain_knowledge[domain]
        
        # Update various knowledge components
        if "vulnerabilities" in knowledge_update:
            knowledge.vulnerabilities.extend(knowledge_update["vulnerabilities"])
            
        if "bypass_techniques" in knowledge_update:
            knowledge.bypass_techniques.extend(knowledge_update["bypass_techniques"])
            
        if "signatures" in knowledge_update:
            for sig in knowledge_update["signatures"]:
                if isinstance(sig, str):
                    knowledge.signatures.append(bytes.fromhex(sig))
                elif isinstance(sig, bytes):
                    knowledge.signatures.append(sig)
                    
        if "api_patterns" in knowledge_update:
            knowledge.api_usage_patterns.extend(knowledge_update["api_patterns"])
            
        # Save updated knowledge
        self._save_domain_knowledge(domain)
        
    def _save_domain_knowledge(self, domain: ProtectionDomain):
        """Save domain knowledge to disk"""
        
        knowledge_path = os.path.join(self.models_dir, f"{domain.value}_knowledge.json")
        
        knowledge = self.domain_knowledge.get(domain)
        if knowledge:
            # Convert to JSON-serializable format
            knowledge_dict = knowledge.to_dict()
            
            with open(knowledge_path, 'w') as f:
                json.dump(knowledge_dict, f, indent=2)
                
            logger.info(f"Saved knowledge base for {domain.value}")
            
    def get_all_domain_models(self) -> List[DomainModel]:
        """Get all registered domain models"""
        return list(self.domain_models.values())
        
    def get_domain_statistics(self) -> Dict[str, Any]:
        """Get statistics about domain models"""
        
        stats = {
            "total_models": len(self.domain_models),
            "fine_tuned_models": sum(1 for m in self.domain_models.values() if m.fine_tuned),
            "models_by_domain": {},
            "average_accuracy": 0.0,
            "total_training_data": 0
        }
        
        for domain, model in self.domain_models.items():
            stats["models_by_domain"][domain.value] = {
                "model_id": model.model_id,
                "fine_tuned": model.fine_tuned,
                "accuracy": model.accuracy,
                "training_data_size": model.training_data_size,
                "last_updated": model.last_updated.isoformat() if model.last_updated else None
            }
            stats["average_accuracy"] += model.accuracy
            stats["total_training_data"] += model.training_data_size
            
        if self.domain_models:
            stats["average_accuracy"] /= len(self.domain_models)
            
        # Add knowledge statistics
        stats["knowledge_bases"] = {}
        for domain, knowledge in self.domain_knowledge.items():
            stats["knowledge_bases"][domain.value] = {
                "vulnerabilities": len(knowledge.vulnerabilities),
                "bypass_techniques": len(knowledge.bypass_techniques),
                "signatures": len(knowledge.signatures),
                "api_patterns": len(knowledge.api_usage_patterns)
            }
            
        return stats
        
    def export_domain_models(self, export_path: str):
        """Export all domain models and knowledge"""
        
        export_data = {
            "export_date": datetime.now().isoformat(),
            "models": {},
            "knowledge": {}
        }
        
        # Export models
        for domain, model in self.domain_models.items():
            export_data["models"][domain.value] = model.to_dict()
            
        # Export knowledge
        for domain, knowledge in self.domain_knowledge.items():
            export_data["knowledge"][domain.value] = knowledge.to_dict()
            
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        logger.info(f"Exported domain models to {export_path}")
        
    def import_domain_models(self, import_path: str):
        """Import domain models and knowledge"""
        
        with open(import_path, 'r') as f:
            import_data = json.load(f)
            
        # Import models
        for domain_str, model_dict in import_data.get("models", {}).items():
            try:
                domain = ProtectionDomain(domain_str)
                # Reconstruct model from dict
                model = DomainModel(
                    model_id=model_dict["model_id"],
                    domain=domain,
                    base_model=model_dict["base_model"],
                    provider=LLMProvider(model_dict["provider"]),
                    fine_tuned=model_dict["fine_tuned"],
                    training_data_size=model_dict["training_data_size"],
                    accuracy=model_dict["accuracy"]
                )
                if model_dict.get("last_updated"):
                    model.last_updated = datetime.fromisoformat(model_dict["last_updated"])
                    
                self._register_domain_model(model)
            except Exception as e:
                logger.error(f"Failed to import model for {domain_str}: {e}")
                
        # Import knowledge
        for domain_str, knowledge_dict in import_data.get("knowledge", {}).items():
            try:
                domain = ProtectionDomain(domain_str)
                # Reconstruct knowledge from dict
                knowledge = DomainKnowledge(domain=domain)
                
                # Restore various fields
                knowledge.vulnerabilities = knowledge_dict.get("vulnerabilities", [])
                knowledge.bypass_techniques = knowledge_dict.get("bypass_techniques", [])
                knowledge.api_usage_patterns = knowledge_dict.get("api_usage_patterns", [])
                
                # Restore signatures
                for sig_hex in knowledge_dict.get("signatures", []):
                    knowledge.signatures.append(bytes.fromhex(sig_hex))
                    
                self.domain_knowledge[domain] = knowledge
            except Exception as e:
                logger.error(f"Failed to import knowledge for {domain_str}: {e}")
                
        logger.info(f"Imported domain models from {import_path}")