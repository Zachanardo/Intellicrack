"""
Cross-Architecture Script Translator

Converts scripts between different architectures (x86/x64/ARM/MIPS/PowerPC) while
maintaining functionality and adapting to architecture-specific requirements.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.analysis.unified_model.model import UnifiedBinaryModel
from ..utils.logger import get_logger
from .consensus_engine import ConsensusResult, ModelExpertise, MultiModelConsensusEngine

logger = get_logger(__name__)


class Architecture(Enum):
    """Supported architectures for translation"""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    POWERPC = "powerpc"
    POWERPC64 = "powerpc64"
    RISCV = "riscv"
    RISCV64 = "riscv64"


class ScriptLanguage(Enum):
    """Script languages that can be translated"""
    FRIDA = "frida"
    GHIDRA = "ghidra"
    IDA_PYTHON = "ida_python"
    RADARE2 = "radare2"
    ASSEMBLY = "assembly"
    C_CODE = "c_code"


@dataclass
class ArchitectureMapping:
    """Maps constructs between architectures"""
    source_arch: Architecture
    target_arch: Architecture
    register_map: Dict[str, str] = field(default_factory=dict)
    instruction_map: Dict[str, str] = field(default_factory=dict)
    calling_convention: Dict[str, Any] = field(default_factory=dict)
    pointer_size: int = 4
    endianness: str = "little"
    stack_direction: str = "down"  # Stack grows down or up
    
    # Architecture-specific features
    has_delay_slots: bool = False  # MIPS, some RISC
    has_condition_codes: bool = True  # x86, ARM
    has_predication: bool = False  # ARM, IA-64
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert mapping to dictionary"""
        return {
            "source_arch": self.source_arch.value,
            "target_arch": self.target_arch.value,
            "register_map": self.register_map,
            "instruction_map": self.instruction_map,
            "calling_convention": self.calling_convention,
            "pointer_size": self.pointer_size,
            "endianness": self.endianness,
            "stack_direction": self.stack_direction,
            "has_delay_slots": self.has_delay_slots,
            "has_condition_codes": self.has_condition_codes,
            "has_predication": self.has_predication
        }


@dataclass
class TranslationContext:
    """Context for script translation"""
    source_script: str
    source_language: ScriptLanguage
    source_arch: Architecture
    target_arch: Architecture
    target_language: Optional[ScriptLanguage] = None
    preserve_comments: bool = True
    optimize_for_target: bool = True
    strict_mode: bool = False  # Fail on untranslatable constructs
    
    # Optional unified model for context-aware translation
    unified_model: Optional[UnifiedBinaryModel] = None
    
    # Translation hints
    hints: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert context to dictionary"""
        return {
            "source_language": self.source_language.value,
            "source_arch": self.source_arch.value,
            "target_arch": self.target_arch.value,
            "target_language": self.target_language.value if self.target_language else None,
            "script_preview": self.source_script[:500] + "..." if len(self.source_script) > 500 else self.source_script,
            "preserve_comments": self.preserve_comments,
            "optimize_for_target": self.optimize_for_target,
            "strict_mode": self.strict_mode,
            "has_unified_model": self.unified_model is not None,
            "hints": self.hints
        }


@dataclass
class TranslationResult:
    """Result of script translation"""
    success: bool
    translated_script: str
    source_arch: Architecture
    target_arch: Architecture
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    translation_notes: List[str] = field(default_factory=list)
    confidence: float = 0.0
    
    # Mapping information used
    architecture_mapping: Optional[ArchitectureMapping] = None
    
    # Performance considerations
    estimated_performance_impact: str = "neutral"  # faster, neutral, slower
    
    # Verification suggestions
    verification_steps: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "success": self.success,
            "source_arch": self.source_arch.value,
            "target_arch": self.target_arch.value,
            "warnings": self.warnings,
            "errors": self.errors,
            "translation_notes": self.translation_notes,
            "confidence": self.confidence,
            "estimated_performance_impact": self.estimated_performance_impact,
            "verification_steps": self.verification_steps,
            "script_size": len(self.translated_script)
        }


class ArchitectureTranslator:
    """Translates scripts between different architectures"""
    
    def __init__(self):
        self.consensus_engine = MultiModelConsensusEngine()
        self._architecture_mappings = self._initialize_architecture_mappings()
        self._translation_cache: Dict[str, TranslationResult] = {}
        
    def _initialize_architecture_mappings(self) -> Dict[Tuple[Architecture, Architecture], ArchitectureMapping]:
        """Initialize architecture mapping database"""
        mappings = {}
        
        # x86 to x64 mapping
        mappings[(Architecture.X86, Architecture.X64)] = ArchitectureMapping(
            source_arch=Architecture.X86,
            target_arch=Architecture.X64,
            register_map={
                "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
                "esi": "rsi", "edi": "rdi", "esp": "rsp", "ebp": "rbp",
                "ax": "ax", "bx": "bx", "cx": "cx", "dx": "dx",
                "al": "al", "bl": "bl", "cl": "cl", "dl": "dl",
                "ah": "ah", "bh": "bh", "ch": "ch", "dh": "dh"
            },
            instruction_map={
                "pushad": "push rax; push rcx; push rdx; push rbx; push rsp; push rbp; push rsi; push rdi",
                "popad": "pop rdi; pop rsi; pop rbp; pop rsp; pop rbx; pop rdx; pop rcx; pop rax",
                "cdq": "cqo",
                "pushfd": "pushfq",
                "popfd": "popfq"
            },
            calling_convention={
                "x86": ["stack", "stack", "stack"],  # All params on stack
                "x64": ["rcx", "rdx", "r8", "r9", "stack"]  # First 4 in registers (Windows)
            },
            pointer_size=8,
            endianness="little"
        )
        
        # x64 to x86 mapping (reverse)
        mappings[(Architecture.X64, Architecture.X86)] = ArchitectureMapping(
            source_arch=Architecture.X64,
            target_arch=Architecture.X86,
            register_map={
                "rax": "eax", "rbx": "ebx", "rcx": "ecx", "rdx": "edx",
                "rsi": "esi", "rdi": "edi", "rsp": "esp", "rbp": "ebp",
                "r8": "eax", "r9": "ecx", "r10": "edx", "r11": "ebx",  # Map extended regs
                "r12": "esi", "r13": "edi", "r14": "ebp", "r15": "esp"
            },
            instruction_map={
                "cqo": "cdq",
                "pushfq": "pushfd",
                "popfq": "popfd",
                "movsxd": "movsx"  # Sign extend differs
            },
            calling_convention={
                "x64": ["rcx", "rdx", "r8", "r9", "stack"],
                "x86": ["stack", "stack", "stack"]
            },
            pointer_size=4,
            endianness="little"
        )
        
        # x86/x64 to ARM mapping
        mappings[(Architecture.X86, Architecture.ARM)] = ArchitectureMapping(
            source_arch=Architecture.X86,
            target_arch=Architecture.ARM,
            register_map={
                "eax": "r0", "ebx": "r1", "ecx": "r2", "edx": "r3",
                "esi": "r4", "edi": "r5", "esp": "sp", "ebp": "fp",
                "eip": "pc"
            },
            instruction_map={
                "mov": "mov",
                "add": "add",
                "sub": "sub",
                "push": "str [sp, #-4]!",
                "pop": "ldr [sp], #4",
                "call": "bl",
                "ret": "bx lr",
                "jmp": "b",
                "je": "beq",
                "jne": "bne"
            },
            calling_convention={
                "x86": ["stack", "stack", "stack"],
                "arm": ["r0", "r1", "r2", "r3", "stack"]
            },
            pointer_size=4,
            endianness="little",
            has_delay_slots=False,
            has_condition_codes=True,
            has_predication=True  # ARM conditional execution
        )
        
        # ARM to ARM64 mapping
        mappings[(Architecture.ARM, Architecture.ARM64)] = ArchitectureMapping(
            source_arch=Architecture.ARM,
            target_arch=Architecture.ARM64,
            register_map={
                "r0": "x0", "r1": "x1", "r2": "x2", "r3": "x3",
                "r4": "x4", "r5": "x5", "r6": "x6", "r7": "x7",
                "r8": "x8", "r9": "x9", "r10": "x10", "r11": "x11",
                "r12": "x12", "sp": "sp", "lr": "x30", "pc": "pc",
                "fp": "x29"
            },
            instruction_map={
                "mov": "mov",
                "add": "add",
                "sub": "sub",
                "bl": "bl",
                "bx lr": "ret",
                "push": "str [sp, #-16]!",  # 64-bit push
                "pop": "ldr [sp], #16"
            },
            calling_convention={
                "arm": ["r0", "r1", "r2", "r3", "stack"],
                "arm64": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "stack"]
            },
            pointer_size=8,
            endianness="little",
            has_predication=False  # ARM64 removed most conditional execution
        )
        
        # x86 to MIPS mapping
        mappings[(Architecture.X86, Architecture.MIPS)] = ArchitectureMapping(
            source_arch=Architecture.X86,
            target_arch=Architecture.MIPS,
            register_map={
                "eax": "$v0", "ebx": "$s0", "ecx": "$a0", "edx": "$a1",
                "esi": "$s1", "edi": "$s2", "esp": "$sp", "ebp": "$fp"
            },
            instruction_map={
                "mov": "move",
                "add": "add",
                "sub": "sub",
                "push": "addiu $sp, $sp, -4; sw",
                "pop": "lw; addiu $sp, $sp, 4",
                "call": "jal",
                "ret": "jr $ra",
                "jmp": "j",
                "je": "beq",
                "jne": "bne"
            },
            calling_convention={
                "x86": ["stack", "stack", "stack"],
                "mips": ["$a0", "$a1", "$a2", "$a3", "stack"]
            },
            pointer_size=4,
            endianness="big",  # MIPS can be either, but traditionally big
            has_delay_slots=True,  # MIPS branch delay slots
            has_condition_codes=False
        )
        
        return mappings
    
    def translate_script(self, context: TranslationContext) -> TranslationResult:
        """Translate script between architectures"""
        
        # Check cache first
        cache_key = self._get_cache_key(context)
        if cache_key in self._translation_cache:
            logger.info(f"Using cached translation for {context.source_arch} to {context.target_arch}")
            return self._translation_cache[cache_key]
        
        # Get architecture mapping
        mapping = self._get_architecture_mapping(context.source_arch, context.target_arch)
        if not mapping:
            # Use AI for unsupported direct mappings
            return self._ai_assisted_translation(context)
        
        # Perform translation based on script language
        if context.source_language == ScriptLanguage.ASSEMBLY:
            result = self._translate_assembly(context, mapping)
        elif context.source_language == ScriptLanguage.FRIDA:
            result = self._translate_frida_script(context, mapping)
        elif context.source_language == ScriptLanguage.GHIDRA:
            result = self._translate_ghidra_script(context, mapping)
        elif context.source_language == ScriptLanguage.C_CODE:
            result = self._translate_c_code(context, mapping)
        else:
            result = self._generic_translation(context, mapping)
        
        # Cache successful translations
        if result.success:
            self._translation_cache[cache_key] = result
        
        return result
    
    def _get_cache_key(self, context: TranslationContext) -> str:
        """Generate cache key for translation"""
        import hashlib
        
        key_parts = [
            context.source_language.value,
            context.source_arch.value,
            context.target_arch.value,
            hashlib.md5(context.source_script.encode()).hexdigest()[:8]
        ]
        
        return "_".join(key_parts)
    
    def _get_architecture_mapping(self, source: Architecture, target: Architecture) -> Optional[ArchitectureMapping]:
        """Get architecture mapping if available"""
        return self._architecture_mappings.get((source, target))
    
    def _translate_assembly(self, context: TranslationContext, mapping: ArchitectureMapping) -> TranslationResult:
        """Translate assembly code between architectures"""
        
        translated_lines = []
        warnings = []
        errors = []
        
        # Parse assembly line by line
        lines = context.source_script.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip empty lines and comments
            if not line.strip() or line.strip().startswith(';') or line.strip().startswith('#'):
                if context.preserve_comments:
                    translated_lines.append(line)
                continue
            
            # Translate the line
            try:
                translated_line = self._translate_assembly_line(line, mapping)
                translated_lines.append(translated_line)
            except Exception as e:
                if context.strict_mode:
                    errors.append(f"Line {line_num}: {str(e)}")
                    translated_lines.append(f"; ERROR: {line}")
                else:
                    warnings.append(f"Line {line_num}: Could not translate '{line}' - {str(e)}")
                    translated_lines.append(f"; UNTRANSLATED: {line}")
        
        # Join translated lines
        translated_script = '\n'.join(translated_lines)
        
        # Add architecture-specific adjustments
        if mapping.has_delay_slots and not context.source_arch in [Architecture.MIPS, Architecture.MIPS64]:
            warnings.append("Target architecture has delay slots - manual verification required")
            translated_script = self._add_delay_slot_nops(translated_script)
        
        # Calculate confidence based on translation success
        total_lines = len([l for l in lines if l.strip() and not l.strip().startswith(';')])
        translated_count = len(translated_lines) - len(errors) - len(warnings)
        confidence = translated_count / total_lines if total_lines > 0 else 0.0
        
        # Generate verification steps
        verification_steps = [
            f"Test on {mapping.target_arch.value} hardware or emulator",
            "Verify calling convention translations",
            "Check endianness conversions if applicable",
            "Validate register mapping correctness"
        ]
        
        if mapping.pointer_size != self._architecture_mappings.get((context.source_arch, context.source_arch), mapping).pointer_size:
            verification_steps.append("Verify pointer arithmetic and addressing modes")
        
        return TranslationResult(
            success=len(errors) == 0,
            translated_script=translated_script,
            source_arch=context.source_arch,
            target_arch=context.target_arch,
            warnings=warnings,
            errors=errors,
            translation_notes=[
                f"Translated {translated_count}/{total_lines} instructions",
                f"Register mapping: {len(mapping.register_map)} registers mapped",
                f"Instruction mapping: {len(mapping.instruction_map)} instructions mapped"
            ],
            confidence=confidence,
            architecture_mapping=mapping,
            estimated_performance_impact=self._estimate_performance_impact(mapping),
            verification_steps=verification_steps
        )
    
    def _translate_assembly_line(self, line: str, mapping: ArchitectureMapping) -> str:
        """Translate a single assembly line"""
        
        # Parse instruction and operands
        parts = line.strip().split(None, 1)
        if not parts:
            return line
        
        instruction = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""
        
        # Translate instruction
        if instruction in mapping.instruction_map:
            translated_inst = mapping.instruction_map[instruction]
        else:
            translated_inst = instruction  # Keep original if no mapping
        
        # Translate registers in operands
        translated_operands = operands
        for src_reg, tgt_reg in mapping.register_map.items():
            # Use word boundaries to avoid partial matches
            translated_operands = re.sub(r'\b' + re.escape(src_reg) + r'\b', tgt_reg, translated_operands)
        
        # Handle pointer size differences
        if mapping.pointer_size == 8 and "dword" in translated_operands:
            translated_operands = translated_operands.replace("dword", "qword")
        elif mapping.pointer_size == 4 and "qword" in translated_operands:
            translated_operands = translated_operands.replace("qword", "dword")
        
        # Combine translated parts
        if translated_operands:
            return f"{translated_inst} {translated_operands}"
        else:
            return translated_inst
    
    def _translate_frida_script(self, context: TranslationContext, mapping: ArchitectureMapping) -> TranslationResult:
        """Translate Frida script between architectures"""
        
        translated_script = context.source_script
        warnings = []
        translation_notes = []
        
        # Update pointer size references
        if mapping.pointer_size == 8:
            translated_script = translated_script.replace("Process.pointerSize === 4", "Process.pointerSize === 8")
            translated_script = translated_script.replace("ptr(0x", "ptr('0x")  # Ensure 64-bit addresses work
        else:
            translated_script = translated_script.replace("Process.pointerSize === 8", "Process.pointerSize === 4")
        
        # Update register references in Frida API calls
        for src_reg, tgt_reg in mapping.register_map.items():
            # Handle context register access
            translated_script = re.sub(
                rf"context\.{src_reg}\b",
                f"context.{tgt_reg}",
                translated_script
            )
            
            # Handle register string references
            translated_script = re.sub(
                rf"['\"]({src_reg})['\"]",
                f"'{tgt_reg}'",
                translated_script
            )
        
        # Update architecture-specific Frida APIs
        if context.target_arch in [Architecture.ARM, Architecture.ARM64]:
            # ARM-specific Frida adjustments
            translated_script = self._adjust_frida_for_arm(translated_script, mapping)
            translation_notes.append("Adjusted Frida APIs for ARM architecture")
        elif context.target_arch in [Architecture.MIPS, Architecture.MIPS64]:
            # MIPS-specific adjustments
            translated_script = self._adjust_frida_for_mips(translated_script, mapping)
            translation_notes.append("Adjusted Frida APIs for MIPS architecture")
            if mapping.has_delay_slots:
                warnings.append("MIPS delay slots require careful handling in hooks")
        
        # Handle calling convention differences
        if context.optimize_for_target:
            translated_script = self._optimize_calling_convention(translated_script, mapping)
            translation_notes.append("Optimized calling conventions for target architecture")
        
        # Add architecture check
        arch_check = self._generate_architecture_check(context.target_arch)
        if "Process.arch" not in translated_script:
            translated_script = arch_check + "\n\n" + translated_script
            translation_notes.append("Added architecture verification")
        
        return TranslationResult(
            success=True,
            translated_script=translated_script,
            source_arch=context.source_arch,
            target_arch=context.target_arch,
            warnings=warnings,
            errors=[],
            translation_notes=translation_notes,
            confidence=0.85,  # High confidence for Frida translations
            architecture_mapping=mapping,
            estimated_performance_impact="neutral",
            verification_steps=[
                f"Test with Frida on {context.target_arch.value} process",
                "Verify register context access works correctly",
                "Check memory read/write operations",
                "Validate function hooking behavior"
            ]
        )
    
    def _adjust_frida_for_arm(self, script: str, mapping: ArchitectureMapping) -> str:
        """Adjust Frida script for ARM architectures"""
        
        # Handle Thumb mode for 32-bit ARM
        if mapping.target_arch == Architecture.ARM:
            # Add Thumb mode handling
            thumb_check = """
// ARM Thumb mode handling
function isThumbMode(address) {
    return (address.toInt32() & 1) === 1;
}

function makeThumbAddress(address) {
    return address.or(1);
}
"""
            if "isThumbMode" not in script:
                script = thumb_check + script
            
            # Adjust function pointers for Thumb
            script = re.sub(
                r"Interceptor\.attach\(ptr\(([^)]+)\)",
                r"Interceptor.attach(makeThumbAddress(ptr(\1))",
                script
            )
        
        # Handle ARM64 specific features
        if mapping.target_arch == Architecture.ARM64:
            # PAC (Pointer Authentication) handling
            pac_strip = """
// ARM64 PAC stripping
function stripPAC(ptr) {
    // Strip pointer authentication code
    return ptr.and(0x0000FFFFFFFFFFFF);
}
"""
            if "stripPAC" not in script and "PAC" in script.upper():
                script = pac_strip + script
        
        return script
    
    def _adjust_frida_for_mips(self, script: str, mapping: ArchitectureMapping) -> str:
        """Adjust Frida script for MIPS architectures"""
        
        # Add delay slot warning
        delay_slot_warning = """
// WARNING: MIPS delay slots active
// Branches and jumps execute the following instruction
// Be careful when placing hooks on branch instructions
"""
        
        if "delay slot" not in script.lower():
            script = delay_slot_warning + script
        
        # Adjust endianness if needed
        if mapping.endianness == "big":
            # Add endianness conversion helpers
            endian_helpers = """
// MIPS big-endian helpers
function swapEndian32(value) {
    return ((value & 0xFF) << 24) |
           ((value & 0xFF00) << 8) |
           ((value & 0xFF0000) >>> 8) |
           ((value & 0xFF000000) >>> 24);
}
"""
            if "swapEndian" not in script:
                script = endian_helpers + script
        
        return script
    
    def _optimize_calling_convention(self, script: str, mapping: ArchitectureMapping) -> str:
        """Optimize script for target calling convention"""
        
        source_cc = mapping.calling_convention.get(mapping.source_arch.value, [])
        target_cc = mapping.calling_convention.get(mapping.target_arch.value, [])
        
        if not source_cc or not target_cc:
            return script
        
        # Generate calling convention mapping code
        cc_mapping = self._generate_calling_convention_map(source_cc, target_cc, mapping)
        
        # Insert before first function hook
        hook_pattern = r"Interceptor\.attach\("
        match = re.search(hook_pattern, script)
        if match:
            insert_pos = match.start()
            script = script[:insert_pos] + cc_mapping + "\n\n" + script[insert_pos:]
        
        return script
    
    def _generate_calling_convention_map(self, source_cc: List[str], target_cc: List[str], 
                                       mapping: ArchitectureMapping) -> str:
        """Generate calling convention mapping code"""
        
        cc_map = """// Calling convention helper
function getArgument(context, index) {
"""
        
        if mapping.target_arch in [Architecture.X86]:
            # x86 - all args on stack
            cc_map += """    // x86: All arguments on stack
    var sp = context.esp;
    return Memory.readPointer(sp.add((index + 1) * 4)); // +1 for return address
"""
        elif mapping.target_arch in [Architecture.X64]:
            # x64 - first 4 in registers (Windows), first 6 (Linux)
            cc_map += """    // x64: First 4 args in registers (Windows)
    switch(index) {
        case 0: return context.rcx;
        case 1: return context.rdx;
        case 2: return context.r8;
        case 3: return context.r9;
        default:
            var sp = context.rsp;
            return Memory.readPointer(sp.add((index - 4 + 5) * 8)); // +5 for shadow space
    }
"""
        elif mapping.target_arch in [Architecture.ARM, Architecture.ARM64]:
            # ARM - first 4/8 in registers
            reg_count = 4 if mapping.target_arch == Architecture.ARM else 8
            cc_map += f"""    // {mapping.target_arch.value}: First {reg_count} args in registers
    switch(index) {{
"""
            for i in range(reg_count):
                reg = f"r{i}" if mapping.target_arch == Architecture.ARM else f"x{i}"
                cc_map += f"        case {i}: return context.{reg};\n"
            
            cc_map += f"""        default:
            var sp = context.sp;
            return Memory.readPointer(sp.add((index - {reg_count}) * {mapping.pointer_size}));
    }}
"""
        
        cc_map += "}\n"
        return cc_map
    
    def _generate_architecture_check(self, arch: Architecture) -> str:
        """Generate architecture verification code"""
        
        arch_name = arch.value
        return f"""// Architecture verification
if (Process.arch !== '{arch_name}') {{
    throw new Error('Script expects {arch_name} but running on ' + Process.arch);
}}
"""
    
    def _translate_ghidra_script(self, context: TranslationContext, mapping: ArchitectureMapping) -> TranslationResult:
        """Translate Ghidra script between architectures"""
        
        translated_script = context.source_script
        warnings = []
        translation_notes = []
        
        # Update processor references
        processor_map = {
            Architecture.X86: "x86:LE:32:default",
            Architecture.X64: "x86:LE:64:default",
            Architecture.ARM: "ARM:LE:32:v7",
            Architecture.ARM64: "AARCH64:LE:64:v8A",
            Architecture.MIPS: "MIPS:BE:32:default",
            Architecture.MIPS64: "MIPS:BE:64:default"
        }
        
        source_proc = processor_map.get(context.source_arch, "")
        target_proc = processor_map.get(context.target_arch, "")
        
        if source_proc and target_proc:
            translated_script = translated_script.replace(source_proc, target_proc)
            translation_notes.append(f"Updated processor from {source_proc} to {target_proc}")
        
        # Update register references in Ghidra API
        for src_reg, tgt_reg in mapping.register_map.items():
            # getCurrentProgram().getRegister("regname")
            translated_script = re.sub(
                rf'getRegister\(["\']({src_reg})["\']\)',
                f'getRegister("{tgt_reg}")',
                translated_script
            )
            
            # Direct register access
            translated_script = re.sub(
                rf'\.{src_reg}\b',
                f'.{tgt_reg}',
                translated_script
            )
        
        # Update address size references
        if mapping.pointer_size == 8:
            translated_script = translated_script.replace("toAddr(0x", "toAddr(\"0x")
            translated_script = translated_script.replace(".getInt(", ".getLong(")
            translated_script = translated_script.replace("4-byte", "8-byte")
        else:
            translated_script = translated_script.replace(".getLong(", ".getInt(")
            translated_script = translated_script.replace("8-byte", "4-byte")
        
        # Add architecture-specific imports if needed
        if context.target_arch in [Architecture.ARM, Architecture.ARM64]:
            arm_imports = """
# ARM-specific imports
from ghidra.program.model.lang import OperandType
from ghidra.app.util import Option
"""
            if "OperandType" not in translated_script and context.target_arch == Architecture.ARM:
                translated_script = arm_imports + "\n" + translated_script
                translation_notes.append("Added ARM-specific imports")
        
        return TranslationResult(
            success=True,
            translated_script=translated_script,
            source_arch=context.source_arch,
            target_arch=context.target_arch,
            warnings=warnings,
            errors=[],
            translation_notes=translation_notes,
            confidence=0.8,
            architecture_mapping=mapping,
            estimated_performance_impact="neutral",
            verification_steps=[
                f"Load in Ghidra with {target_proc} processor",
                "Verify register mappings in decompiler",
                "Check address calculations",
                "Test with sample binary of target architecture"
            ]
        )
    
    def _translate_c_code(self, context: TranslationContext, mapping: ArchitectureMapping) -> TranslationResult:
        """Translate C code with inline assembly between architectures"""
        
        translated_script = context.source_script
        warnings = []
        errors = []
        translation_notes = []
        
        # Find and translate inline assembly blocks
        asm_pattern = r'__asm__\s*\((.*?)\);|asm\s*\((.*?)\);|__asm\s*{(.*?)}'
        
        def translate_asm_block(match):
            asm_code = match.group(1) or match.group(2) or match.group(3)
            if not asm_code:
                return match.group(0)
            
            # Create mini context for assembly translation
            asm_context = TranslationContext(
                source_script=asm_code,
                source_language=ScriptLanguage.ASSEMBLY,
                source_arch=context.source_arch,
                target_arch=context.target_arch
            )
            
            asm_result = self._translate_assembly(asm_context, mapping)
            
            if asm_result.success:
                return match.group(0).replace(asm_code, asm_result.translated_script)
            else:
                warnings.extend(asm_result.warnings)
                errors.extend(asm_result.errors)
                return match.group(0) + " /* TRANSLATION FAILED */"
        
        translated_script = re.sub(asm_pattern, translate_asm_block, translated_script, flags=re.DOTALL)
        
        # Update architecture-specific types
        if mapping.pointer_size == 8:
            translated_script = re.sub(r'\buint32_t\s+(\w+_ptr)\b', r'uint64_t \1', translated_script)
            translated_script = re.sub(r'\buintptr_t', 'uint64_t', translated_script)
            translated_script = translated_script.replace("(uint32_t)", "(uint64_t)")
        else:
            translated_script = re.sub(r'\buint64_t\s+(\w+_ptr)\b', r'uint32_t \1', translated_script)
            translated_script = re.sub(r'\buintptr_t', 'uint32_t', translated_script)
            translated_script = translated_script.replace("(uint64_t)", "(uint32_t)")
        
        # Add architecture detection macro
        arch_macro = self._generate_c_architecture_macro(context.target_arch)
        if "#ifdef" not in translated_script or context.target_arch.value.upper() not in translated_script:
            translated_script = arch_macro + "\n" + translated_script
            translation_notes.append("Added architecture detection macros")
        
        # Update calling convention attributes
        if context.target_arch == Architecture.X86:
            translated_script = translated_script.replace("__fastcall", "__stdcall")
        elif context.target_arch == Architecture.X64:
            translated_script = translated_script.replace("__stdcall", "__fastcall")
        
        return TranslationResult(
            success=len(errors) == 0,
            translated_script=translated_script,
            source_arch=context.source_arch,
            target_arch=context.target_arch,
            warnings=warnings,
            errors=errors,
            translation_notes=translation_notes,
            confidence=0.75 if len(errors) == 0 else 0.4,
            architecture_mapping=mapping,
            estimated_performance_impact="neutral",
            verification_steps=[
                f"Compile with {context.target_arch.value} compiler",
                "Test inline assembly translations",
                "Verify pointer arithmetic",
                "Check structure padding and alignment"
            ]
        )
    
    def _generate_c_architecture_macro(self, arch: Architecture) -> str:
        """Generate C preprocessor macros for architecture detection"""
        
        macros = {
            Architecture.X86: """
#if !defined(__i386__) && !defined(_M_IX86)
    #error "This code requires x86 architecture"
#endif
""",
            Architecture.X64: """
#if !defined(__x86_64__) && !defined(_M_X64) && !defined(__amd64__)
    #error "This code requires x64 architecture"
#endif
""",
            Architecture.ARM: """
#if !defined(__arm__) && !defined(_M_ARM)
    #error "This code requires ARM architecture"
#endif
""",
            Architecture.ARM64: """
#if !defined(__aarch64__) && !defined(_M_ARM64)
    #error "This code requires ARM64 architecture"
#endif
""",
            Architecture.MIPS: """
#if !defined(__mips__) && !defined(__MIPS__)
    #error "This code requires MIPS architecture"
#endif
"""
        }
        
        return macros.get(arch, "")
    
    def _generic_translation(self, context: TranslationContext, mapping: ArchitectureMapping) -> TranslationResult:
        """Generic translation using pattern matching and AI assistance"""
        
        # Use consensus engine for complex translations
        return self._ai_assisted_translation(context)
    
    def _ai_assisted_translation(self, context: TranslationContext) -> TranslationResult:
        """Use AI consensus for complex translations"""
        
        prompt = f"""Translate the following {context.source_language.value} script from {context.source_arch.value} to {context.target_arch.value} architecture.

Source Architecture: {context.source_arch.value}
Target Architecture: {context.target_arch.value}
Script Language: {context.source_language.value}

Key Requirements:
1. Maintain functional equivalence
2. Adapt register names and sizes
3. Handle calling convention differences
4. Adjust memory addressing for pointer size
5. Account for architecture-specific features

Source Script:
```
{context.source_script}
```

Provide:
1. Complete translated script
2. List of changes made
3. Warnings about potential issues
4. Confidence score (0-1)
"""
        
        # Query consensus engine
        consensus_result = self.consensus_engine.generate_script_with_consensus(
            prompt=prompt,
            script_type=f"{context.source_language.value}_translation",
            context_data=context.to_dict(),
            required_expertise={ModelExpertise.REVERSE_ENGINEERING}
        )
        
        # Parse AI response
        translated_script, warnings, confidence = self._parse_ai_translation_response(
            consensus_result.consensus_content
        )
        
        return TranslationResult(
            success=True,
            translated_script=translated_script,
            source_arch=context.source_arch,
            target_arch=context.target_arch,
            warnings=warnings,
            errors=[],
            translation_notes=[
                "AI-assisted translation",
                f"Consensus confidence: {consensus_result.consensus_confidence:.2f}",
                f"Models consulted: {len(consensus_result.individual_responses)}"
            ],
            confidence=confidence,
            architecture_mapping=None,
            estimated_performance_impact="unknown",
            verification_steps=[
                "Thoroughly test translated script",
                "Verify all architecture-specific adaptations",
                "Compare behavior with original script",
                "Monitor for unexpected side effects"
            ]
        )
    
    def _parse_ai_translation_response(self, response: str) -> Tuple[str, List[str], float]:
        """Parse AI translation response"""
        
        # Extract translated script
        script_match = re.search(r'```[\w]*\n(.*?)\n```', response, re.DOTALL)
        translated_script = script_match.group(1) if script_match else response
        
        # Extract warnings
        warnings = []
        warning_section = re.search(r'Warnings?:(.*?)(?=Confidence|$)', response, re.DOTALL | re.IGNORECASE)
        if warning_section:
            warning_lines = warning_section.group(1).strip().split('\n')
            warnings = [w.strip('- *').strip() for w in warning_lines if w.strip()]
        
        # Extract confidence
        confidence_match = re.search(r'[Cc]onfidence:?\s*([0-9.]+)', response)
        confidence = float(confidence_match.group(1)) if confidence_match else 0.7
        
        return translated_script, warnings, confidence
    
    def _add_delay_slot_nops(self, script: str) -> str:
        """Add NOPs for delay slot architectures"""
        
        # Add NOP after branch instructions
        branch_instructions = ['j', 'jal', 'jr', 'beq', 'bne', 'blt', 'bgt', 'ble', 'bge']
        
        lines = script.split('\n')
        adjusted_lines = []
        
        for i, line in enumerate(lines):
            adjusted_lines.append(line)
            
            # Check if line contains branch instruction
            for branch in branch_instructions:
                if re.search(r'\b' + branch + r'\b', line, re.IGNORECASE):
                    # Add NOP if next line isn't already a NOP
                    if i + 1 < len(lines) and 'nop' not in lines[i + 1].lower():
                        adjusted_lines.append('    nop  ; Delay slot')
                    break
        
        return '\n'.join(adjusted_lines)
    
    def _estimate_performance_impact(self, mapping: ArchitectureMapping) -> str:
        """Estimate performance impact of translation"""
        
        # Simple heuristic based on architecture characteristics
        if mapping.source_arch in [Architecture.X86, Architecture.X64] and \
           mapping.target_arch in [Architecture.ARM, Architecture.ARM64]:
            return "faster"  # ARM often more efficient
        elif mapping.source_arch in [Architecture.ARM, Architecture.ARM64] and \
             mapping.target_arch in [Architecture.X86, Architecture.X64]:
            return "slower"  # x86 often has more overhead
        elif mapping.pointer_size < 8 and mapping.target_arch in [Architecture.X64, Architecture.ARM64]:
            return "faster"  # 64-bit can be more efficient
        else:
            return "neutral"
    
    def batch_translate(self, scripts: List[TranslationContext]) -> Dict[str, TranslationResult]:
        """Translate multiple scripts in batch"""
        
        results = {}
        
        for context in scripts:
            script_id = f"{context.source_language.value}_{context.source_arch.value}_to_{context.target_arch.value}"
            logger.info(f"Translating script: {script_id}")
            
            try:
                result = self.translate_script(context)
                results[script_id] = result
            except Exception as e:
                logger.error(f"Failed to translate {script_id}: {e}")
                results[script_id] = TranslationResult(
                    success=False,
                    translated_script="",
                    source_arch=context.source_arch,
                    target_arch=context.target_arch,
                    errors=[str(e)],
                    confidence=0.0
                )
        
        return results
    
    def validate_translation(self, original: str, translated: str, 
                           source_arch: Architecture, target_arch: Architecture) -> Dict[str, Any]:
        """Validate translation maintains functionality"""
        
        validation = {
            "structure_preserved": True,
            "api_calls_mapped": True,
            "logic_intact": True,
            "issues": []
        }
        
        # Check basic structure preservation
        original_lines = len([l for l in original.split('\n') if l.strip()])
        translated_lines = len([l for l in translated.split('\n') if l.strip()])
        
        if abs(original_lines - translated_lines) > original_lines * 0.5:
            validation["structure_preserved"] = False
            validation["issues"].append("Significant line count difference")
        
        # Check function/API preservation
        api_pattern = r'\b\w+\s*\('
        original_apis = set(re.findall(api_pattern, original))
        translated_apis = set(re.findall(api_pattern, translated))
        
        if len(original_apis - translated_apis) > len(original_apis) * 0.2:
            validation["api_calls_mapped"] = False
            validation["issues"].append("Missing API calls in translation")
        
        # Architecture-specific validation
        if target_arch in [Architecture.MIPS, Architecture.MIPS64]:
            if not any(word in translated.lower() for word in ['delay', 'nop', 'slot']):
                validation["issues"].append("No delay slot handling for MIPS")
        
        return validation